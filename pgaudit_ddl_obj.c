/*------------------------------------------------------------------------------
 * pgaudit_ddl_obj.c
 *
 * DDL auditing via object_access_hook for WHPG6 (PG9.4).
 * Provides object type/name resolution for DDL audit logs since
 * pg_event_trigger_ddl_commands() doesn't exist in PG9.4.
 *
 * OIDs are captured per-stack-item in the object_access_hook (pgaudit.c)
 * and resolved here when the audit log is emitted, after ProcessUtility
 * completes and the catalog is consistent.
 *
 * For some catalog classes (e.g. pg_proc, pg_conversion), newly created
 * entries may not be visible through the syscache at resolution time.
 * In those cases we do a direct heap scan using SnapshotSelf, which
 * always sees the current transaction's tuples regardless of command ID.
 *
 * Copyright (c) 2014-2024, PostgreSQL Global Development Group
 *------------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/indexing.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_class.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_trigger.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/tqual.h"

#include "pgaudit_ddl_obj.h"

/*
 * Scan a catalog by OID using SnapshotSelf to find tuples that may
 * not yet be visible through the syscache.  Returns a heap-copied
 * tuple (caller must heap_freetuple) or NULL.  The relation is
 * returned open via *relp; caller must heap_close it.
 */
static HeapTuple
fetch_catalog_tuple_self(Oid catalogId, Oid indexId, Oid objectId,
						 Relation *relp)
{
	SysScanDesc scan;
	ScanKeyData key;
	HeapTuple	tuple;
	HeapTuple	result = NULL;

	*relp = heap_open(catalogId, AccessShareLock);

	ScanKeyInit(&key,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(objectId));

	scan = systable_beginscan(*relp, indexId, true,
							  SnapshotSelf, 1, &key);
	tuple = systable_getnext(scan);

	if (HeapTupleIsValid(tuple))
		result = heap_copytuple(tuple);

	systable_endscan(scan);
	return result;
}

/*
 * Resolve an object's type description for audit logging.
 * Returns an uppercased string like "TABLE", "INDEX", "FUNCTION", etc.
 * Returns NULL on failure.
 */
const char *
pgaudit_ddl_resolve_object_type(Oid classId, Oid objectId, int subId)
{
	/*
	 * For pg_proc entries, distinguish AGGREGATE from FUNCTION via direct
	 * scan — the syscache may not yet see newly created entries.
	 */
	if (classId == ProcedureRelationId)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(ProcedureRelationId,
									   ProcedureOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_proc proc = (Form_pg_proc) GETSTRUCT(tup);
			const char *type = proc->proisagg ? "AGGREGATE" : "FUNCTION";

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return pstrdup(type);
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/*
	 * For pg_trigger entries, use direct scan — same visibility issue.
	 */
	if (classId == TriggerRelationId)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(TriggerRelationId,
									   TriggerOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return pstrdup("TRIGGER");
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/*
	 * For pg_class entries (subId=0), use direct scan to bypass stale
	 * syscache after RENAME or SET SCHEMA.
	 */
	if (classId == RelationRelationId && subId == 0)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(RelationRelationId,
									   ClassOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tup);
			const char *type;

			switch (classForm->relkind)
			{
				case RELKIND_RELATION:
					type = "TABLE";
					break;
				case RELKIND_INDEX:
					type = "INDEX";
					break;
				case RELKIND_SEQUENCE:
					type = "SEQUENCE";
					break;
				case RELKIND_VIEW:
					type = "VIEW";
					break;
				case RELKIND_MATVIEW:
					type = "MATERIALIZED VIEW";
					break;
				case RELKIND_COMPOSITE_TYPE:
					type = "TYPE";
					break;
				case RELKIND_FOREIGN_TABLE:
					type = "FOREIGN TABLE";
					break;
				default:
					type = "RELATION";
					break;
			}

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return pstrdup(type);
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/* For all other catalog classes, use the standard syscache path. */
	{
		ObjectAddress addr;
		char	   *type;

		addr.classId = classId;
		addr.objectId = objectId;
		addr.objectSubId = subId;

		type = getObjectTypeDescription(&addr);
		if (type != NULL)
		{
			char *p;
			for (p = type; *p; p++)
				*p = pg_toupper((unsigned char) *p);
		}

		return type;
	}
}

/*
 * Resolve an object's identity (fully qualified name) for audit logging.
 * Returns a string like "public.my_table", "public.my_func(integer)", etc.
 * Returns NULL on failure.
 */
const char *
pgaudit_ddl_resolve_object_name(Oid classId, Oid objectId, int subId)
{
	/*
	 * For pg_proc entries, build schema.name(argtypes) via direct scan.
	 */
	if (classId == ProcedureRelationId)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(ProcedureRelationId,
									   ProcedureOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_proc proc = (Form_pg_proc) GETSTRUCT(tup);
			char	   *proname = NameStr(proc->proname);
			char	   *nspname = get_namespace_name(proc->pronamespace);
			StringInfoData buf;
			int			i;

			initStringInfo(&buf);

			if (nspname)
				appendStringInfo(&buf, "%s.%s(", nspname, proname);
			else
				appendStringInfo(&buf, "%s(", proname);

			for (i = 0; i < proc->pronargs; i++)
			{
				if (i > 0)
					appendStringInfoChar(&buf, ',');
				appendStringInfoString(&buf,
					format_type_be(proc->proargtypes.values[i]));
			}
			appendStringInfoChar(&buf, ')');

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return buf.data;
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/*
	 * For pg_conversion entries, build schema.name via direct scan.
	 */
	if (classId == ConversionRelationId)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(ConversionRelationId,
									   ConversionOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_conversion conv = (Form_pg_conversion) GETSTRUCT(tup);
			char	   *conname = NameStr(conv->conname);
			char	   *nspname = get_namespace_name(conv->connamespace);
			char	   *result;

			if (nspname)
				result = psprintf("%s.%s", nspname, conname);
			else
				result = pstrdup(conname);

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return result;
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/*
	 * For pg_trigger entries, build "tgname on schema.relname" via direct scan.
	 */
	if (classId == TriggerRelationId)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(TriggerRelationId,
									   TriggerOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_trigger trig = (Form_pg_trigger) GETSTRUCT(tup);
			char	   *tgname = NameStr(trig->tgname);
			Oid			relid = trig->tgrelid;
			char	   *relname = get_rel_name(relid);
			char	   *nspname = get_namespace_name(get_rel_namespace(relid));
			char	   *result;

			if (nspname && relname)
				result = psprintf("%s on %s.%s", tgname, nspname, relname);
			else if (relname)
				result = psprintf("%s on %s", tgname, relname);
			else
				result = pstrdup(tgname);

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return result;
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/*
	 * For pg_class entries (subId=0), use direct scan to bypass stale
	 * syscache after RENAME or SET SCHEMA.
	 */
	if (classId == RelationRelationId && subId == 0)
	{
		Relation	rel;
		HeapTuple	tup;

		tup = fetch_catalog_tuple_self(RelationRelationId,
									   ClassOidIndexId,
									   objectId, &rel);
		if (HeapTupleIsValid(tup))
		{
			Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tup);
			char	   *relname = NameStr(classForm->relname);
			char	   *nspname = get_namespace_name(classForm->relnamespace);
			char	   *result;

			if (nspname)
				result = psprintf("%s.%s", nspname, relname);
			else
				result = pstrdup(relname);

			heap_freetuple(tup);
			heap_close(rel, AccessShareLock);
			return result;
		}

		heap_close(rel, AccessShareLock);
		return NULL;
	}

	/* For all other catalog classes, use the standard syscache path. */
	{
		ObjectAddress addr;

		addr.classId = classId;
		addr.objectId = objectId;
		addr.objectSubId = subId;

		return getObjectIdentity(&addr);
	}
}

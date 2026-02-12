/*------------------------------------------------------------------------------
 * pgaudit_ddl_obj.c
 *
 * DDL object resolution for audit logging in WHPG6 (PG9.4).
 *
 * Exports pgaudit_ddl_resolve_object() which resolves object OIDs to
 * human-readable type descriptions (e.g., "TABLE") and fully-qualified
 * names (e.g., "public.my_table") for DDL audit logs.
 *
 * This is needed because pg_event_trigger_ddl_commands() doesn't exist
 * in PG9.4. OIDs are captured in the object_access_hook (pgaudit.c)
 * and resolved here after ProcessUtility completes.
 *
 * We use direct heap scans with SnapshotSelf instead of syscache to:
 * 1. See in-transaction tuples that may not be visible through syscache
 * 2. Avoid resource leaks that occur when syscache lookups fail mid-execution
 *
 * Copyright (c) 2014-2026, EnterpriseDB Corporation. All Rights Reserved.
 *------------------------------------------------------------------------------
 */
#include "pgaudit_ddl_obj.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_cast.h"
#include "catalog/pg_class.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_opclass.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_rewrite.h"
#include "catalog/pg_trigger.h"
#include "catalog/pg_type.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/tqual.h"

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
 * Safe wrappers for lsyscache functions that may throw errors.
 * These catch errors and return fallback values, preventing resource
 * leaks when called while holding open relations.
 */
static char *
safe_format_type_be(Oid typid)
{
	char *result;

	PG_TRY();
	{
		result = format_type_be(typid);
	}
	PG_CATCH();
	{
		FlushErrorState();
		result = psprintf("%u", typid);
	}
	PG_END_TRY();

	return result;
}

static char *
safe_get_namespace_name(Oid nspid)
{
	char *result;

	PG_TRY();
	{
		result = get_namespace_name(nspid);
	}
	PG_CATCH();
	{
		FlushErrorState();
		result = NULL;
	}
	PG_END_TRY();

	return result;
}

static char *
safe_get_rel_name(Oid relid)
{
	char *result;

	PG_TRY();
	{
		result = get_rel_name(relid);
	}
	PG_CATCH();
	{
		FlushErrorState();
		result = NULL;
	}
	PG_END_TRY();

	return result;
}

static Oid
safe_get_rel_namespace(Oid relid)
{
	Oid result;

	PG_TRY();
	{
		result = get_rel_namespace(relid);
	}
	PG_CATCH();
	{
		FlushErrorState();
		result = InvalidOid;
	}
	PG_END_TRY();

	return result;
}

static char *
safe_get_attname(Oid relid, AttrNumber attnum)
{
	char *result;

	PG_TRY();
	{
		result = get_attname(relid, attnum);
	}
	PG_CATCH();
	{
		FlushErrorState();
		result = NULL;
	}
	PG_END_TRY();

	return result;
}

/*
 * Resolve an object's type description and identity for audit logging.
 * Refer to getObjectIdentity() for the implementation of this function.
 *
 * objectType: uppercased string like "TABLE", "INDEX", "FUNCTION", etc.
 * objectName: fully qualified name like "public.my_table", "public.my_func(integer)"
 *
 * Returns true on success.
 */
bool
pgaudit_ddl_resolve_object(Oid classId, Oid objectId, int subId,
                           const char **objectType, const char **objectName)
{
	Assert(objectType);
	Assert(objectName);
	Assert(*objectType == NULL);
	Assert(*objectName == NULL);

	ObjectAddress addr;
	ObjectClass objclass;
	Relation	rel;
	HeapTuple	tup;

	addr.classId = classId;
	addr.objectId = objectId;
	addr.objectSubId = subId;

	objclass = getObjectClass(&addr);

	switch (objclass)
	{
		case OCLASS_CLASS:
			{
				tup = fetch_catalog_tuple_self(RelationRelationId,
											   ClassOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_class classForm = (Form_pg_class) GETSTRUCT(tup);
					const char *type;
					char	   *relname = NameStr(classForm->relname);
					char	   *nspname = safe_get_namespace_name(classForm->relnamespace);

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
					*objectType = pstrdup(type);

					if (subId != 0)
					{
						char *attname = safe_get_attname(objectId, subId);
						if (nspname && attname)
							*objectName = psprintf("%s.%s.%s", nspname, relname, attname);
						else if (attname)
							*objectName = psprintf("%s.%s", relname, attname);
						else
							*objectName = pstrdup(relname);
					}
					else
					{
						if (nspname)
							*objectName = psprintf("%s.%s", nspname, relname);
						else
							*objectName = pstrdup(relname);
					}

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_PROC:
			{
				tup = fetch_catalog_tuple_self(ProcedureRelationId,
											   ProcedureOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_proc proc = (Form_pg_proc) GETSTRUCT(tup);
					char	   *proname = NameStr(proc->proname);
					char	   *nspname = safe_get_namespace_name(proc->pronamespace);
					StringInfoData buf;
					int			i;

					*objectType = pstrdup(proc->proisagg ? "AGGREGATE" : "FUNCTION");

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
							safe_format_type_be(proc->proargtypes.values[i]));
					}
					appendStringInfoChar(&buf, ')');
					*objectName = buf.data;

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_TYPE:
			{
				tup = fetch_catalog_tuple_self(TypeRelationId,
											   TypeOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_type typeForm = (Form_pg_type) GETSTRUCT(tup);
					char	   *typname = NameStr(typeForm->typname);
					char	   *nspname = safe_get_namespace_name(typeForm->typnamespace);

					*objectType = pstrdup("TYPE");
					if (nspname)
						*objectName = psprintf("%s.%s", nspname, typname);
					else
						*objectName = pstrdup(typname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_CAST:
			{
				tup = fetch_catalog_tuple_self(CastRelationId,
											   CastOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_cast castForm = (Form_pg_cast) GETSTRUCT(tup);

					*objectType = pstrdup("CAST");
					*objectName = psprintf("(%s AS %s)",
								  safe_format_type_be(castForm->castsource),
								  safe_format_type_be(castForm->casttarget));

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_COLLATION:
			{
				tup = fetch_catalog_tuple_self(CollationRelationId,
											   CollationOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_collation collForm = (Form_pg_collation) GETSTRUCT(tup);
					char	   *collname = NameStr(collForm->collname);
					char	   *nspname = safe_get_namespace_name(collForm->collnamespace);

					*objectType = pstrdup("COLLATION");
					if (nspname)
						*objectName = psprintf("%s.%s", nspname, collname);
					else
						*objectName = pstrdup(collname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_CONSTRAINT:
			{
				tup = fetch_catalog_tuple_self(ConstraintRelationId,
											   ConstraintOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_constraint conForm = (Form_pg_constraint) GETSTRUCT(tup);
					char	   *conname = NameStr(conForm->conname);
					Oid			conrelid = conForm->conrelid;
					Oid			contypid = conForm->contypid;

					*objectType = pstrdup("CONSTRAINT");

					if (OidIsValid(conrelid))
					{
						char *relname = safe_get_rel_name(conrelid);
						char *nspname = safe_get_namespace_name(safe_get_rel_namespace(conrelid));
						if (nspname && relname)
							*objectName = psprintf("%s on %s.%s", conname, nspname, relname);
						else if (relname)
							*objectName = psprintf("%s on %s", conname, relname);
						else
							*objectName = pstrdup(conname);
					}
					else if (OidIsValid(contypid))
					{
						*objectName = psprintf("%s on %s", conname,
											   safe_format_type_be(contypid));
					}
					else
					{
						*objectName = pstrdup(conname);
					}

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_CONVERSION:
			{
				tup = fetch_catalog_tuple_self(ConversionRelationId,
											   ConversionOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_conversion convForm = (Form_pg_conversion) GETSTRUCT(tup);
					char	   *convname = NameStr(convForm->conname);
					char	   *nspname = safe_get_namespace_name(convForm->connamespace);

					*objectType = pstrdup("CONVERSION");
					if (nspname)
						*objectName = psprintf("%s.%s", nspname, convname);
					else
						*objectName = pstrdup(convname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_LANGUAGE:
			{
				tup = fetch_catalog_tuple_self(LanguageRelationId,
											   LanguageOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_language langForm = (Form_pg_language) GETSTRUCT(tup);

					*objectType = pstrdup("LANGUAGE");
					*objectName = pstrdup(NameStr(langForm->lanname));

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_OPERATOR:
			{
				tup = fetch_catalog_tuple_self(OperatorRelationId,
											   OperatorOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_operator oprForm = (Form_pg_operator) GETSTRUCT(tup);
					char	   *oprname = NameStr(oprForm->oprname);
					char	   *nspname = safe_get_namespace_name(oprForm->oprnamespace);

					*objectType = pstrdup("OPERATOR");
					if (nspname)
						*objectName = psprintf("%s.%s(%s,%s)", nspname, oprname,
								safe_format_type_be(oprForm->oprleft),
								safe_format_type_be(oprForm->oprright));
					else
						*objectName = psprintf("%s(%s,%s)", oprname,
								safe_format_type_be(oprForm->oprleft),
								safe_format_type_be(oprForm->oprright));

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_OPCLASS:
			{
				tup = fetch_catalog_tuple_self(OperatorClassRelationId,
											   OpclassOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_opclass opcForm = (Form_pg_opclass) GETSTRUCT(tup);
					char	   *opcname = NameStr(opcForm->opcname);
					char	   *nspname = safe_get_namespace_name(opcForm->opcnamespace);

					*objectType = pstrdup("OPERATOR CLASS");
					if (nspname)
						*objectName = psprintf("%s.%s", nspname, opcname);
					else
						*objectName = pstrdup(opcname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_OPFAMILY:
			{
				tup = fetch_catalog_tuple_self(OperatorFamilyRelationId,
											   OpfamilyOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_opfamily opfForm = (Form_pg_opfamily) GETSTRUCT(tup);
					char	   *opfname = NameStr(opfForm->opfname);
					char	   *nspname = safe_get_namespace_name(opfForm->opfnamespace);

					*objectType = pstrdup("OPERATOR FAMILY");
					if (nspname)
						*objectName = psprintf("%s.%s", nspname, opfname);
					else
						*objectName = pstrdup(opfname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_REWRITE:
			{
				tup = fetch_catalog_tuple_self(RewriteRelationId,
											   RewriteOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_rewrite ruleForm = (Form_pg_rewrite) GETSTRUCT(tup);
					char	   *rulename = NameStr(ruleForm->rulename);
					Oid			relid = ruleForm->ev_class;
					char	   *relname = safe_get_rel_name(relid);
					char	   *nspname = safe_get_namespace_name(safe_get_rel_namespace(relid));

					*objectType = pstrdup("RULE");
					if (nspname && relname)
						*objectName = psprintf("%s on %s.%s", rulename, nspname, relname);
					else if (relname)
						*objectName = psprintf("%s on %s", rulename, relname);
					else
						*objectName = pstrdup(rulename);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_TRIGGER:
			{
				tup = fetch_catalog_tuple_self(TriggerRelationId,
											   TriggerOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_trigger trigForm = (Form_pg_trigger) GETSTRUCT(tup);
					char	   *tgname = NameStr(trigForm->tgname);
					Oid			relid = trigForm->tgrelid;
					char	   *relname = safe_get_rel_name(relid);
					char	   *nspname = safe_get_namespace_name(safe_get_rel_namespace(relid));

					*objectType = pstrdup("TRIGGER");
					if (nspname && relname)
						*objectName = psprintf("%s on %s.%s", tgname, nspname, relname);
					else if (relname)
						*objectName = psprintf("%s on %s", tgname, relname);
					else
						*objectName = pstrdup(tgname);

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		case OCLASS_SCHEMA:
			{
				tup = fetch_catalog_tuple_self(NamespaceRelationId,
											   NamespaceOidIndexId,
											   objectId, &rel);
				if (HeapTupleIsValid(tup))
				{
					Form_pg_namespace nspForm = (Form_pg_namespace) GETSTRUCT(tup);

					*objectType = pstrdup("SCHEMA");
					*objectName = pstrdup(NameStr(nspForm->nspname));

					heap_freetuple(tup);
					heap_close(rel, AccessShareLock);
					return true;
				}
				heap_close(rel, AccessShareLock);
				return false;
			}

		/*
		 * For unhandled object classes, return empty strings.
		 * This is acceptable as we avoid the resource leak issue.
		 */
		default:
			*objectType = pstrdup("");
			*objectName = pstrdup("");
			return true;
	}

	/* Should not reach here */
	return false;
}

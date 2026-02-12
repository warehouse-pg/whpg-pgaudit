/*------------------------------------------------------------------------------
 * pgaudit_ddl_obj.h
 *
 * DDL auditing via object_access_hook for WHPG6 (PG9.4).
 *
 * Copyright (c) 2014-2024, PostgreSQL Global Development Group
 *------------------------------------------------------------------------------
 */
#ifndef PGAUDIT_DDL_OBJ_H
#define PGAUDIT_DDL_OBJ_H

#include "postgres.h"

/* Resolve object OIDs to type description (e.g., "TABLE", "INDEX") */
extern const char *pgaudit_ddl_resolve_object_type(Oid classId, Oid objectId, int subId);

/* Resolve object OIDs to identity (e.g., "public.my_table") */
extern const char *pgaudit_ddl_resolve_object_name(Oid classId, Oid objectId, int subId);

#endif /* PGAUDIT_DDL_OBJ_H */

/*------------------------------------------------------------------------------
 * pgaudit_ddl_obj.h
 *
 * Copyright (c) 2014-2026, EnterpriseDB Corporation. All Rights Reserved.
 *------------------------------------------------------------------------------
 */
#ifndef PGAUDIT_DDL_OBJ_H
#define PGAUDIT_DDL_OBJ_H

#include "postgres.h"

/*
 * Resolve object OIDs to type description (e.g., "TABLE", "INDEX") and
 * identity (e.g., "public.my_table").  Output pointers may be NULL if
 * not needed.  Returns true on success, false if resolution failed.
 */
extern bool pgaudit_ddl_resolve_object(Oid classId, Oid objectId, int subId,
                                       const char **objectType,
                                       const char **objectName);

#endif /* PGAUDIT_DDL_OBJ_H */

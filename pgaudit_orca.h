/*------------------------------------------------------------------------------
 * pgaudit_orca.h
 *
 * ORCA compatibility layer for pgaudit. Handles proper audit logging when
 * ORCA optimizer is used.
 *
 * Copyright (c) 2014-2026, EnterpriseDB Corporation. All Rights Reserved.
 *------------------------------------------------------------------------------
 */
#ifndef PGAUDIT_ORCA_H
#define PGAUDIT_ORCA_H

#include "postgres.h"
#include "nodes/pg_list.h"

extern void orca_init(void);
extern bool orca_in_planner(void);
extern List *orca_resolve_rtable(List *rtables);

#endif /* PGAUDIT_ORCA_H */

/*------------------------------------------------------------------------------
 * pgaudit_orca.h
 *
 * ORCA compatibility layer for pgaudit. Handles proper audit logging when
 * ORCA optimizer is used.
 *
 * Copyright (c) 2026, EnterpriseDB Corporation
 *------------------------------------------------------------------------------
 */
#ifndef PGAUDIT_ORCA_H
#define PGAUDIT_ORCA_H

#include "postgres.h"
#include "nodes/pg_list.h"

extern void orca_init(void);
extern bool orca_in_planner(void);

/*
 * Called from ExecutorCheckPerms_hook.
 *
 *   During planning  : merges the perm data seen on each permission check into
 *                      a captured set; returns false (nothing usable yet).
 *   During execution : on a cache hit hands back the richer planning-time data
 *                      via the out params and returns true; on a miss returns
 *                      false and the caller keeps the executor-supplied data.
 */
extern bool orca_resolve_rtable(List *rtables, List *rtePermInfos,
                                 List **out_rtable, List **out_perminfos);

#endif /* PGAUDIT_ORCA_H */

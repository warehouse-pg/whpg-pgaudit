/*------------------------------------------------------------------------------
 * pgaudit_orca.h
 *
 * ORCA compatibility layer for pgaudit. Handles proper audit logging when
 * ORCA optimizer is used.
 *
 * Supports both WHPG7 (PostgreSQL 12 base) and WHPG19 (PostgreSQL 19 base).
 * PG16 moved the per-relation permission fields out of RangeTblEntry into a
 * parallel RTEPermissionInfo list, so on PG16+ the resolver exchanges BOTH the
 * range table and the matching perminfo list; before PG16 it exchanges just
 * the range table (whose RTEs carry the perm fields).
 *
 * Copyright (c) 2014-2026, EnterpriseDB Corporation. All Rights Reserved.
 *------------------------------------------------------------------------------
 */
#ifndef PGAUDIT_ORCA_H
#define PGAUDIT_ORCA_H

#include "postgres.h"
#include "nodes/pg_list.h"
#include "nodes/parsenodes.h"

/*
 * Structural adapter for the PG16 permission-info split.
 *
 * PG16 moved the per-relation permission fields out of RangeTblEntry into a
 * parallel RTEPermissionInfo list reached through rte->perminfoindex.  Both
 * structs expose the same field names (requiredPerms, selectedCols,
 * insertedCols, updatedCols), so once the correct struct for an RTE has been
 * resolved the consuming code is version independent.
 *
 *   PgaPermInfo                    type carrying the permission fields
 *   PGA_GET_PERMINFO(rte, perms)   resolve the PgaPermInfo for rte (NULL if none)
 *   PGA_PERMINFOS_PARAM            extra ", List *rtePermInfos" formal parameter
 *   PGA_PERMINFOS_ARG              matching ", rtePermInfos" call argument
 *
 * Before PG16 the fields live on the RangeTblEntry itself and the perminfo
 * list does not exist, so PGA_GET_PERMINFO yields the RTE and the parameter
 * macros collapse to nothing.  This lets a single function body serve both
 * versions instead of being duplicated under #if.
 */
#if PG_VERSION_NUM >= 160000
#include "parser/parse_relation.h"	/* getRTEPermissionInfo */

typedef RTEPermissionInfo PgaPermInfo;
#define PGA_GET_PERMINFO(rte, perminfos) \
	((rte)->perminfoindex != 0 ? getRTEPermissionInfo((perminfos), (rte)) : NULL)
#define PGA_PERMINFOS_PARAM	, List *rtePermInfos
#define PGA_PERMINFOS_ARG	, rtePermInfos
#else
typedef RangeTblEntry PgaPermInfo;
#define PGA_GET_PERMINFO(rte, perminfos) (rte)
#define PGA_PERMINFOS_PARAM
#define PGA_PERMINFOS_ARG
#endif

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
 *
 * PG16+ exchanges both the range table and its perminfo list; before PG16 the
 * RTEs carry the perm fields so only the range table is exchanged.
 */
#if PG_VERSION_NUM >= 160000
extern bool orca_resolve_rtable(List *rtables, List *rtePermInfos,
								 List **out_rtable, List **out_perminfos);
#else
extern bool orca_resolve_rtable(List *rtables, List **out_rtable);
#endif

#endif /* PGAUDIT_ORCA_H */
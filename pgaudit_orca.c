/*------------------------------------------------------------------------------
 * pgaudit_orca.c
 *
 * ORCA compatibility layer for pgaudit. Handles proper audit logging when
 * ORCA optimizer is used.
 *
 * Problem: ORCA calls ExecCheckRTPerms during planning (not execution) in
 * CTranslatorQueryToDXL::TranslateSelectQueryToDXL(). The new RTEs only
 * contain base tables, and lose track of views and fields like relkind,
 * selectedCols, etc. pgaudit needs to start auditing in ExecutorStart_hook,
 * but ORCA's first ExecutorCheckPerms_hook call happens before that.
 *
 * Flow comparison (ExecutorCheckPerms_hook perspective):
 *
 *   Standard Planner                    ORCA Optimizer
 *   ================                    ==============
 *
 *   planner_hook                        planner_hook
 *        |                                   |
 *        v                                   v
 *   standard_planner()                  standard_planner()
 *        |                                   |
 *        |                                   v
 *        |                              optimize_query() [ORCA]
 *        |                                   |
 *        |                                   v
 *        |                           +---> ExecCheckRTPerms() [1st call, e.g. TABLE+VIEW]
 *        |                           |      |
 *        |                           |      v
 *        |                           +---> ExecCheckRTPerms() [2nd call, e.g. VIEW's base table]
 *        |                           |      |
 *        |                           |---> ...  (may be called multiple times)
 *        |                                  |
 *        |                                  v
 *        |                              [returns PlannedStmt with simplified rtable (DXLToQuery)]
 *        v                                   v
 *   ExecutorStart_hook                  ExecutorStart_hook
 *        |                                   |
 *        v                                   v
 *   ExecCheckRTPerms()                  ExecCheckRTPerms() [final call during execution]
 *        |                                   |
 *        v                                   v
 *   [audit with full RTE info]          [audit with cached RTEs from planning]
 *
 * Solution:
 * 1. Maintain a context stack tracking PLANNER vs EXECUTOR phase.
 * 2. During planning: capture and merge RTEs from each ExecCheckRTPerms call.
 * 3. Cache merged rtable keyed by content hash when planner finishes.
 * 4. During execution: look up cached rtable by hash for auditing.
 * 5. Skip audit logging during PLANNER phase (orca_in_planner() == true).
 *
 * Copyright (c) 2014-2026, EnterpriseDB Corporation. All Rights Reserved.
 *------------------------------------------------------------------------------
 */
#include "pgaudit_orca.h"

#include "executor/executor.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "nodes/plannodes.h"
#include "optimizer/planner.h"
#if PG_VERSION_NUM >= 160000
#include "parser/parse_relation.h"	/* getRTEPermissionInfo (PG16+) */
#endif
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/guc.h"

/* Context types for the stack */
typedef enum
{
    CONTEXT_PLANNER,
    CONTEXT_EXECUTOR
} ContextType;

/* Context entry with type and captured rtable */
typedef struct ContextEntry
{
    ContextType type;
    /* Captured during planning-time perm check. Will be NULL for execution
     * stage */
    List *captured;
} ContextEntry;

/* Cache for range tables before QueryToDXL, keyed by the PlannedStmt.rtable
 * content hash */
typedef struct RTableCacheEntry
{
	uint32 hash_key; /* hash of rtable content */
    List *rtable;    /* copy of the augmented rtable */
#if PG_VERSION_NUM >= 160000
	List *perminfos;
#endif
} RTableCacheEntry;

/*
 * One captured relation seen during a planning-time permission check.  Holds
 * identity/kind from the RTE and access bits/columns from its perminfo.  This
 * version independent form is rebuilt into the layout the running executor
 * expects (see build_cached_lists).
 */
typedef struct CapturedPerm
{
	Oid	relid;
	char relkind;
	RTEKind	rtekind;
	AclMode	requiredPerms;
	Bitmapset *selectedCols;
	Bitmapset *insertedCols;
	Bitmapset *updatedCols;
} CapturedPerm;

/* Extra ", List **out_perminfos" out parameter, present only on PG16+. */
#if PG_VERSION_NUM >= 160000
#define PGA_PERMINFOS_OUTPARAM	, List **out_perminfos
#else
#define PGA_PERMINFOS_OUTPARAM
#endif

static inline uint32 compute_rtable_hash(List *list);
static inline void push_context(ContextType type);
static inline ContextEntry *pop_context(void);
static inline ContextEntry *top_context(void);
static void rtable_cache_reset(void *arg);
static void init_rtable_cache(void);
static inline RTableCacheEntry *lookup_entry(uint32 hash_key);

static void cache_rtable(uint32 hash_key, List *rtable PGA_PERMINFOS_PARAM);
static List *merge_perms(List *captured, List *rtable PGA_PERMINFOS_PARAM);
static void build_cached_lists(List *captured, List **out_rtable
							   PGA_PERMINFOS_OUTPARAM);
#if PG_VERSION_NUM >= 190000
static PlannedStmt *pgaudit_orca_planner_hook(Query *parse,
											  const char *query_string,
											  int cursorOptions,
											  ParamListInfo boundParams,
											  ExplainState *es);
#else
static PlannedStmt *pgaudit_orca_planner_hook(Query *parse, int cursorOptions,
											  ParamListInfo boundParams);
#endif

static void pgaudit_orca_executor_start_hook(QueryDesc *queryDesc, int eflags);

static List *context_stack = NIL;
static HTAB *rtable_cache = NULL;
static MemoryContext rtable_cache_context = NULL;

static planner_hook_type prev_planner_hook = NULL;
static ExecutorStart_hook_type prev_executor_start_hook = NULL;

static MemoryContextCallback rtable_cache_callback = {
    .func = rtable_cache_reset,
    .arg = NULL,
};

/*
 * Compute a hash of rtable content based on relid and requiredPerms.
 *
 * The rtable should be the one in PlannedStmt.rtable which won't be changed
 * when planner creates the PlannedStmt, or be used by the executor.
 */
static inline uint32
compute_rtable_hash(List *list)
{
	uint32		hash = list_length(list);
	ListCell   *lc;

	foreach(lc, list)
	{
		PgaPermInfo *pi = (PgaPermInfo *) lfirst(lc);

#if PG_VERSION_NUM < 160000
		/* Pre-PG16 hashes the range table; skip non-relation RTEs. */
		if (pi->rtekind != RTE_RELATION)
			continue;
#endif
		hash = hash * 31 + (uint32) pi->relid;
		hash = hash * 31 + (uint32) pi->requiredPerms;
	}

	return hash;
}

static inline void
push_context(ContextType type)
{
	MemoryContext oldcxt;
	ContextEntry *entry;

	if (rtable_cache_context == NULL)
		return;

	oldcxt = MemoryContextSwitchTo(rtable_cache_context);
	entry = palloc(sizeof(ContextEntry));
	entry->type = type;
	entry->captured = NIL;
	context_stack = lcons(entry, context_stack);
	MemoryContextSwitchTo(oldcxt);
}

static inline ContextEntry *
pop_context(void)
{
    ContextEntry *entry;

    if (context_stack == NIL)
        return NULL;

    entry = linitial(context_stack);
    context_stack = list_delete_first(context_stack);
    return entry;
}

static inline ContextEntry *
top_context(void)
{
    if (context_stack == NIL)
        return NULL;
    return linitial(context_stack);
}

/* Callback to reset cache when transaction context is destroyed */
static void
rtable_cache_reset(void *arg)
{
    rtable_cache = NULL;
    rtable_cache_context = NULL;
    context_stack = NIL;
}

/*
 * Initialize the rtable cache if needed.
 * Uses TopTransactionContext as parent so cache is auto-cleaned on txn end.
 */
static void
init_rtable_cache(void)
{
    HASHCTL hashctl;

    if (rtable_cache != NULL)
        return;

    rtable_cache_context = AllocSetContextCreate(
        TopTransactionContext, "pgaudit rtable cache", ALLOCSET_DEFAULT_SIZES);

    memset(&hashctl, 0, sizeof(hashctl));
    hashctl.keysize = sizeof(uint32);
    hashctl.entrysize = sizeof(RTableCacheEntry);
    hashctl.hcxt = rtable_cache_context;

    rtable_cache = hash_create("pgaudit rtable cache", 128, &hashctl,
                               HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);

    MemoryContextRegisterResetCallback(TopTransactionContext,
                                       &rtable_cache_callback);
}

/*
 * Look up (and remove) a cached entry by hash. Removing is fine: the entry is
 * consumed once per execution. On a hash collision a later audit event may
 * miss the richer data, which is not critical.
 */
static inline RTableCacheEntry *
lookup_entry(uint32 hash_key)
{
	RTableCacheEntry *entry;

	if (hash_key == 0 || rtable_cache == NULL)
		return NULL;

	entry = hash_search(rtable_cache, &hash_key, HASH_REMOVE, NULL);
	if (entry != NULL)
		elog(DEBUG1, "pgaudit: lookup_entry FOUND hash=%u entries=%d",
			 hash_key, list_length(entry->rtable));
	else
		elog(DEBUG1, "pgaudit: lookup_entry NOT FOUND hash=%u", hash_key);

	return entry;
}

/*
 * Capture/merge helpers.
 *
 * Permission data is always gathered into the version independent CapturedPerm
 * set during planning, then rebuilt into the layout the executor expects.  The
 * PGA_* adapters (see pgaudit_orca.h) hide the PG16 perminfo split so a single
 * implementation serves both WHPG 7 and WHPG 19.
 */
static void
cache_rtable(uint32 hash_key, List *rtable PGA_PERMINFOS_PARAM)
{
	RTableCacheEntry *entry;
	bool		found;

	Assert(rtable_cache_context);

	if (hash_key == 0 || rtable == NULL)
		return;

	entry = hash_search(rtable_cache, &hash_key, HASH_ENTER, &found);
	if (!found)
	{
		entry->hash_key = hash_key;
		entry->rtable = rtable;
#if PG_VERSION_NUM >= 160000
		entry->perminfos = rtePermInfos;
#endif
		elog(DEBUG1, "pgaudit: cache_rtable STORED hash=%u entries=%d",
			 hash_key, list_length(rtable));
	}
}

static inline CapturedPerm *
find_captured_by_relid(List *captured, Oid relid)
{
	ListCell   *lc;

	foreach(lc, captured)
	{
		CapturedPerm *cp = (CapturedPerm *) lfirst(lc);

		if (cp->relid == relid)
			return cp;
	}
	return NULL;
}

/*
 * Merge the relations of one permission check into the captured set. Only
 * relations carrying required permissions are kept. The perm fields are read
 * through PGA_GET_PERMINFO so the same code serves both layouts. Caller must
 * run this in rtable_cache_context.
 */
static List *
merge_perms(List *captured, List *rtable PGA_PERMINFOS_PARAM)
{
	ListCell   *lc;

	foreach(lc, rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);
		PgaPermInfo *pi;
		CapturedPerm *existing;

		if (rte->rtekind != RTE_RELATION)
			continue;

		pi = PGA_GET_PERMINFO(rte, rtePermInfos);
		if (pi == NULL || pi->requiredPerms == 0)
			continue;

		existing = find_captured_by_relid(captured, rte->relid);

		if (existing == NULL)
		{
			CapturedPerm *cp = (CapturedPerm *) palloc0(sizeof(CapturedPerm));

			cp->relid = rte->relid;
			cp->relkind = rte->relkind;
			cp->rtekind = rte->rtekind;
			cp->requiredPerms = pi->requiredPerms;
			cp->selectedCols = bms_copy(pi->selectedCols);
			cp->insertedCols = bms_copy(pi->insertedCols);
			cp->updatedCols = bms_copy(pi->updatedCols);
			captured = lappend(captured, cp);
		}
		else
		{
			existing->requiredPerms |= pi->requiredPerms;
			if (pi->selectedCols)
				existing->selectedCols =
					bms_union(existing->selectedCols, pi->selectedCols);
			if (pi->insertedCols)
				existing->insertedCols =
					bms_union(existing->insertedCols, pi->insertedCols);
			if (pi->updatedCols)
				existing->updatedCols =
					bms_union(existing->updatedCols, pi->updatedCols);
		}
	}

	return captured;
}

/*
 * Rebuild a thin range table from the captured set so the executor can consume
 * it. On PG16+ the perm fields go into a matching perminfo list linked by
 * perminfoindex; before PG16 they live directly on the rebuilt RTEs. Caller
 * runs this in rtable_cache_context.
 */
static void
build_cached_lists(List *captured, List **out_rtable PGA_PERMINFOS_OUTPARAM)
{
	List	   *rtable = NIL;
#if PG_VERSION_NUM >= 160000
	List	   *perminfos = NIL;
	int			idx = 0;
#endif
	ListCell   *lc;

	foreach(lc, captured)
	{
		CapturedPerm *cp = (CapturedPerm *) lfirst(lc);
		RangeTblEntry *rte = makeNode(RangeTblEntry);

		rte->rtekind = cp->rtekind;
		rte->relid = cp->relid;
		rte->relkind = cp->relkind;

#if PG_VERSION_NUM >= 160000
		{
			RTEPermissionInfo *pi = makeNode(RTEPermissionInfo);

			rte->perminfoindex = ++idx;		/* 1-based index into perminfos */

			pi->relid = cp->relid;
			pi->inh = false;
			pi->requiredPerms = cp->requiredPerms;
			pi->checkAsUser = InvalidOid;
			pi->selectedCols = cp->selectedCols;
			pi->insertedCols = cp->insertedCols;
			pi->updatedCols = cp->updatedCols;
			perminfos = lappend(perminfos, pi);
		}
#else
		rte->requiredPerms = cp->requiredPerms;
		rte->selectedCols = cp->selectedCols;
		rte->insertedCols = cp->insertedCols;
		rte->updatedCols = cp->updatedCols;
#endif

		rtable = lappend(rtable, rte);
	}

	*out_rtable = rtable;
#if PG_VERSION_NUM >= 160000
	*out_perminfos = perminfos;
#endif
}

/*
* Planner hook - push PLANNER context, cache rtable on exit.
*/
#if PG_VERSION_NUM >= 190000
#define PGAUDIT_DO_PLAN(fn) \
	(fn)(parse, query_string, cursorOptions, boundParams, es)
#else
#define PGAUDIT_DO_PLAN(fn) \
	(fn)(parse, cursorOptions, boundParams)
#endif

/*
 * Planner hook - push PLANNER context, cache captured perms on exit.
 */
static PlannedStmt *
#if PG_VERSION_NUM >= 190000
pgaudit_orca_planner_hook(Query *parse, const char *query_string,
						  int cursorOptions, ParamListInfo boundParams,
						  ExplainState *es)
#else
pgaudit_orca_planner_hook(Query *parse, int cursorOptions,
						  ParamListInfo boundParams)
#endif
{
	PlannedStmt *result;
	ContextEntry *ctx;

	if (!optimizer)
	{
		/* Do nothing if it is not orca */
		if (prev_planner_hook)
			result = PGAUDIT_DO_PLAN(prev_planner_hook);
		else
			result = PGAUDIT_DO_PLAN(standard_planner);
		return result;
	}

	init_rtable_cache();
	push_context(CONTEXT_PLANNER);

	PG_TRY();
	{
		if (prev_planner_hook)
			result = PGAUDIT_DO_PLAN(prev_planner_hook);
		else
			result = PGAUDIT_DO_PLAN(standard_planner);
	}
	PG_CATCH();
	{
		pop_context();
		PG_RE_THROW();
	}
	PG_END_TRY();

	ctx = pop_context();

	/* Cache the captured perms if this was an ORCA plan */
	if (ctx != NULL && ctx->captured != NIL &&
		result->planGen == PLANGEN_OPTIMIZER)
	{
		/* The hash must be computed over whatever the executor will hand us. */
#if PG_VERSION_NUM >= 160000
		uint32		hash = compute_rtable_hash(result->permInfos);
#else
		uint32		hash = compute_rtable_hash(result->rtable);
#endif

		if (hash != 0)
		{
			MemoryContext oldcxt = MemoryContextSwitchTo(rtable_cache_context);
			List	   *crt = NIL;
#if PG_VERSION_NUM >= 160000
			List	   *cpi = NIL;

			build_cached_lists(ctx->captured, &crt, &cpi);
			cache_rtable(hash, crt, cpi);
#else
			build_cached_lists(ctx->captured, &crt);
			cache_rtable(hash, crt);
#endif
			MemoryContextSwitchTo(oldcxt);
		}
		ctx->captured = NIL;
	}

	return result;
}

/*
 * ExecutorStart hook - push EXECUTOR context.
 */
static void
pgaudit_orca_executor_start_hook(QueryDesc *queryDesc, int eflags)
{
    push_context(CONTEXT_EXECUTOR);

    PG_TRY();
    {
        if (prev_executor_start_hook)
            prev_executor_start_hook(queryDesc, eflags);
        else
            standard_ExecutorStart(queryDesc, eflags);
    }
    PG_CATCH();
    {
        pop_context();
        PG_RE_THROW();
    }
    PG_END_TRY();

    pop_context();
}

/*
 * Initialize ORCA compatibility layer.
 */
void
orca_init(void)
{
    prev_planner_hook = planner_hook;
    planner_hook = pgaudit_orca_planner_hook;

    prev_executor_start_hook = ExecutorStart_hook;
    ExecutorStart_hook = pgaudit_orca_executor_start_hook;
}

/*
 * Check if we're in ORCA planner context (should skip logging).
 * Returns true only when in PLANNER context.
 * Returns false for executor context, empty stack, or non-ORCA path.
 */
bool
orca_in_planner(void)
{
    ContextEntry *ctx = top_context();
    return ctx != NULL && ctx->type == CONTEXT_PLANNER;
}

/*
 * Called from ExecutorCheckPerms_hook.
 * - During planning: capture and merge perms from all permission checks.
 * - During execution: hand back the cached data via the out params on a hit.
 *
 * The signature differs only in the perminfo list/out param that PG16+ adds;
 * the body is shared through the PGA_* adapters.
 */
#if PG_VERSION_NUM >= 160000
bool
orca_resolve_rtable(List *rtables, List *rtePermInfos,
					List **out_rtable, List **out_perminfos)
#else
bool
orca_resolve_rtable(List *rtables, List **out_rtable)
#endif
{
	ContextEntry *ctx = top_context();

	if (ctx == NULL)
		return false;

	if (ctx->type == CONTEXT_PLANNER)
	{
		MemoryContext oldcxt = MemoryContextSwitchTo(rtable_cache_context);

		ctx->captured = merge_perms(ctx->captured, rtables PGA_PERMINFOS_ARG);
		MemoryContextSwitchTo(oldcxt);
		return false;			/* nothing to return during planning */
	}
	else
	{
#if PG_VERSION_NUM >= 160000
		uint32		hash = compute_rtable_hash(rtePermInfos);
#else
		uint32		hash = compute_rtable_hash(rtables);
#endif
		RTableCacheEntry *entry = lookup_entry(hash);

		if (entry != NULL)
		{
			*out_rtable = entry->rtable;
#if PG_VERSION_NUM >= 160000
			*out_perminfos = entry->perminfos;
#endif
			return true;
		}
		return false;
	}
}
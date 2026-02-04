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
    List *captured_rtable;
} ContextEntry;

/* Cache for range tables before QueryToDXL, keyed by the PlannedStmt.rtable
 * content hash */
typedef struct RTableCacheEntry
{
    uint32 hash_key; /* hash of rtable content */
    List *rtable;    /* copy of the augmented rtable */
} RTableCacheEntry;

static inline uint32 compute_rtable_hash(List *rtable);
static inline void push_context(ContextType type);
static inline ContextEntry *pop_context(void);
static inline ContextEntry *top_context(void);
static void rtable_cache_reset(void *arg);
static void init_rtable_cache(void);
static void cache_rtable(uint32 hash_key, List *rtable);
static inline List *lookup_rtable(uint32 hash_key);
static inline RangeTblEntry *copy_rte(RangeTblEntry *src);
static inline RangeTblEntry *find_rte_by_relid(List *rtable, Oid relid);
static inline List *merge_rtable(List *captured, List *new_rtable);
static PlannedStmt *pgaudit_orca_planner_hook(Query *parse, int cursorOptions,
                                              ParamListInfo boundParams);
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
compute_rtable_hash(List *rtable)
{
    uint32 hash = list_length(rtable);
    ListCell *lc;

    foreach (lc, rtable)
    {
        RangeTblEntry *rte = lfirst(lc);

        if (rte->rtekind == RTE_RELATION)
        {
            hash = hash * 31 + rte->relid;
            hash = hash * 31 + rte->requiredPerms;
        }
    }

    return hash;
}

static inline void
push_context(ContextType type)
{
    if (rtable_cache_context == NULL)
        return;

    MemoryContext oldcxt = MemoryContextSwitchTo(rtable_cache_context);
    ContextEntry *entry = palloc(sizeof(ContextEntry));
    entry->type = type;
    entry->captured_rtable = NIL;
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
 * Cache the rtable keyed by content hash.
 * The rtable must already be allocated in rtable_cache_context.
 */
static void
cache_rtable(uint32 hash_key, List *rtable)
{
    RTableCacheEntry *entry;
    bool found;

    Assert(rtable_cache_context);

    if (hash_key == 0 || rtable == NULL)
        return;

    entry = hash_search(rtable_cache, &hash_key, HASH_ENTER, &found);
    if (!found)
    {
        entry->hash_key = hash_key;
        entry->rtable = rtable;
        elog(DEBUG1, "pgaudit: cache_rtable STORED hash=%u entries=%d",
             hash_key, list_length(rtable));
    }
    else
    {
        elog(DEBUG1, "pgaudit: cache_rtable EXISTS hash=%u", hash_key);
    }
}

/*
 * Look up cached rtable by hash.
 */
static inline List *
lookup_rtable(uint32 hash_key)
{
    RTableCacheEntry *entry;

    if (hash_key == 0 || rtable_cache == NULL)
    {
        elog(DEBUG1, "pgaudit: lookup_rtable hash=%u cache=%s", hash_key,
             rtable_cache ? "exists" : "NULL");
        return NULL;
    }

    /* Find and remove the cache entry. It should not be needed anymore.
     * If we are unlucky and there is a hash collision, the next audit event
     * may not have full information, which is not a critical issue. */
    entry = hash_search(rtable_cache, &hash_key, HASH_REMOVE, NULL);
    if (entry != NULL)
    {
        elog(DEBUG1, "pgaudit: lookup_rtable FOUND hash=%u entries=%d",
             hash_key, list_length(entry->rtable));
        return entry->rtable;
    }

    elog(DEBUG1, "pgaudit: lookup_rtable NOT FOUND hash=%u", hash_key);
    return NULL;
}

/*
 * Copy only the RTE fields that pgaudit needs for audit logging.
 * copyObject() does a deep copy and we don't need most of the fields.
 */
static inline RangeTblEntry *
copy_rte(RangeTblEntry *src)
{
    RangeTblEntry *dst = makeNode(RangeTblEntry);

    dst->rtekind = src->rtekind;
    dst->relid = src->relid;
    dst->relkind = src->relkind;
    dst->requiredPerms = src->requiredPerms;
    dst->selectedCols = bms_copy(src->selectedCols);
    dst->insertedCols = bms_copy(src->insertedCols);
    dst->updatedCols = bms_copy(src->updatedCols);

    return dst;
}

static inline RangeTblEntry *
find_rte_by_relid(List *rtable, Oid relid)
{
    ListCell *lc;

    foreach (lc, rtable)
    {
        RangeTblEntry *rte = lfirst(lc);
        if (rte->relid == relid)
            return rte;
    }
    return NULL;
}

/*
 * Merge RTEs from new rtable into existing captured rtable.
 * Only adds RTEs with requiredPerms > 0.
 * Returns merged list (may be newly created or the original).
 */
static inline List *
merge_rtable(List *captured, List *new_rtable)
{
    ListCell *lc;

    foreach (lc, new_rtable)
    {
        RangeTblEntry *new_rte = lfirst(lc);

        /* Only interested in relations with permissions to check */
        if (new_rte->rtekind != RTE_RELATION || new_rte->requiredPerms == 0)
            continue;

        /* Check if we already have this relation */
        RangeTblEntry *existing = find_rte_by_relid(captured, new_rte->relid);

        if (existing == NULL)
        {
            /* New relation - copy and add it */
            RangeTblEntry *copy = copy_rte(new_rte);
            captured = lappend(captured, copy);
        }
        else
        {
            /* Existing relation - merge permissions */
            existing->requiredPerms |= new_rte->requiredPerms;
            /* Also merge column bitmaps if available */
            if (new_rte->selectedCols)
                existing->selectedCols =
                    bms_union(existing->selectedCols, new_rte->selectedCols);
            if (new_rte->insertedCols)
                existing->insertedCols =
                    bms_union(existing->insertedCols, new_rte->insertedCols);
            if (new_rte->updatedCols)
                existing->updatedCols =
                    bms_union(existing->updatedCols, new_rte->updatedCols);
        }
    }

    return captured;
}

/*
 * Planner hook - push PLANNER context, cache rtable on exit.
 */
static PlannedStmt *
pgaudit_orca_planner_hook(Query *parse, int cursorOptions,
                          ParamListInfo boundParams)
{
    PlannedStmt *result;
    if (!optimizer)
    {
        /* Do nothing if it is not orca */
        if (prev_planner_hook)
            result = prev_planner_hook(parse, cursorOptions, boundParams);
        else
            result = standard_planner(parse, cursorOptions, boundParams);
        return result;
    }

    init_rtable_cache();
    push_context(CONTEXT_PLANNER);

    PG_TRY();
    {
        if (prev_planner_hook)
            result = prev_planner_hook(parse, cursorOptions, boundParams);
        else
            result = standard_planner(parse, cursorOptions, boundParams);
    }
    PG_CATCH();
    {
        pop_context();
        PG_RE_THROW();
    }
    PG_END_TRY();

    ContextEntry *ctx = pop_context();

    /* Cache the captured rtable if this was an ORCA plan */
    if (ctx != NULL && ctx->captured_rtable != NIL &&
        result->planGen == PLANGEN_OPTIMIZER)
    {
        uint32 hash = compute_rtable_hash(result->rtable);
        if (hash != 0)
            cache_rtable(hash, ctx->captured_rtable);
        ctx->captured_rtable = NIL;
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
 * - During planning: capture and merge RTEs from all permission checks
 * - During execution: return the cached rtable
 */
List *
orca_resolve_rtable(List *rtables)
{
    ContextEntry *ctx;
    uint32 hash;

    ctx = top_context();
    if (ctx == NULL)
        return NULL;

    if (ctx->type == CONTEXT_PLANNER)
    {
        /*
         * During planning: merge RTEs from this permission check into captured
         * list. ORCA may call permission check multiple times with different
         * RTEs, for example "SELECT * FROM some_table, someview":
         * - First call might have TABLE and SUBQUERY with SELECT permission
         * - Second call might extract the SUBQUERY and have VIEW and the base
         *   table with SELECT permission
         * We need to collect all RTEs with requiredPerms > 0.
         *
         * Allocate in rtable_cache_context so it survives until execution.
         */
        MemoryContext oldcxt = MemoryContextSwitchTo(rtable_cache_context);
        ctx->captured_rtable = merge_rtable(ctx->captured_rtable, rtables);
        MemoryContextSwitchTo(oldcxt);
        return NULL; /* Don't return anything during planning */
    }
    else
    {
        /* During execution: look up cached rtable */
        hash = compute_rtable_hash(rtables);
        return lookup_rtable(hash);
    }
}

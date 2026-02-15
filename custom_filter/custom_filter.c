

#include "postgres.h"
#include "fmgr.h"

#include <float.h>     
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>

#include "optimizer/paths.h"      
#include "optimizer/planner.h"
#include "nodes/extensible.h"      
#include "nodes/pathnodes.h"       
#include "nodes/plannodes.h"       
#include "executor/executor.h"     
#include "executor/tuptable.h"     
#include "commands/explain.h"      
#include "portability/instr_time.h"
#include "utils/guc.h"            
#include "nodes/bitmapset.h"
#include "parser/parsetree.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "catalog/pg_type.h"
#include "catalog/namespace.h"
#include "access/htup_details.h"   
#include "access/htup.h"
#include "access/table.h"
#include "storage/itemptr.h"      
#include "utils/memutils.h"       
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "lib/stringinfo.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "utils/hsearch.h"
#include "utils/array.h"
#include "storage/fd.h"
#include "utils/wait_event.h"
#include "common/md5.h"

#include "policy_evaluator.h"
#include "policy_spec.h"
#include "tcop/utility.h"
PG_MODULE_MAGIC;


struct CfExec;
typedef struct TableFilterState TableFilterState;
typedef struct PolicyQueryState PolicyQueryState;

typedef struct PolicyArtifactC {
    const char *name;
    const void *data;
    size_t len;
} PolicyArtifactC;

typedef struct PolicyTableAllowC {
    const char *table;
    uint8 *allow_bits;
    uint32 n_rows;
} PolicyTableAllowC;

typedef struct PolicyAllowListC {
    int count;
    PolicyTableAllowC *items;
} PolicyAllowListC;

typedef struct PolicyRunProfileC {
    double artifact_parse_ms;
    double atoms_ms;
    double presence_ms;
    double project_ms;
    double stamp_ms;
    double bin_ms;
    double local_sat_ms;
    double fill_ms;
    double prop_ms;
    int prop_iters;
    double decode_ms;
    double policy_total_ms;
} PolicyRunProfileC;

typedef struct PolicyRunHandle PolicyRunHandle;
extern PolicyRunHandle *policy_run(const PolicyArtifactC *arts, int art_count,
                                   const PolicyEngineInputC *in);
extern const PolicyAllowListC *policy_run_allow_list(const PolicyRunHandle *h);
extern const PolicyRunProfileC *policy_run_profile(const PolicyRunHandle *h);

#define CF_TRACE_LOG(fmt, ...) \
    do { \
        if (cf_trace_enabled()) \
            elog(NOTICE, fmt, ##__VA_ARGS__); \
    } while (0)

#define CF_RESCAN_LOG(fmt, ...) \
    do { \
        if (cf_profile_rescan) \
            elog(NOTICE, "rescan_profile: " fmt, ##__VA_ARGS__); \
    } while (0)

#define CF_DEBUG_IDS_LOG(fmt, ...) \
    do { \
        if (cf_debug_ids) \
            elog(NOTICE, "CF_ID " fmt, ##__VA_ARGS__); \
    } while (0)

#define CF_DEBUG_QS_LOG(fmt, ...) \
    do { \
        if (cf_debug_ids) \
            elog(NOTICE, "CF_QS " fmt, ##__VA_ARGS__); \
    } while (0)

#define CF_DEBUG_SUBPLAN_LOG(fmt, ...) \
    do { \
        if (cf_debug_ids) \
            elog(NOTICE, "CF_SUBPLAN " fmt, ##__VA_ARGS__); \
    } while (0)

static uint32
cf_popcount_allow(const uint8 *bits, uint32 n_rows)
{
    if (!bits) return 0;
    uint32 cnt = 0;
    for (uint32 r = 0; r < n_rows; r++) {
        if (bits[r >> 3] & (uint8)(1u << (r & 7)))
            cnt++;
    }
    return cnt;
}

static long
cf_rss_kb_now(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "VmRSS:", 6) == 0)
        {
            char *p = line + 6;
            while (*p && (*p < '0' || *p > '9'))
                p++;
            kb = atol(p);
            break;
        }
    }
    fclose(f);
    return kb;
}

static long
cf_peak_rss_kb(void)
{
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0)
        return -1;
    return (long) ru.ru_maxrss;
}

static bool
cf_memory_context_contains(MemoryContext parent, MemoryContext child)
{
    for (MemoryContext cur = child; cur != NULL; cur = cur->parent)
    {
        if (cur == parent)
            return true;
    }
    return false;
}

static void
cf_contract_assert_chunk(const char *label, const char *relname, void *ptr, MemoryContext qctx)
{
    if (!ptr || !qctx)
        return;
    MemoryContext mctx = GetMemoryChunkContext(ptr);
    bool ok = cf_memory_context_contains(qctx, mctx);
    CF_TRACE_LOG(
         "custom_filter: memctx label=%s rel=%s ptr=%p mctx=%p qctx=%p ok=%s",
         label ? label : "<null>",
         relname ? relname : "<global>",
         ptr,
         (void *) mctx,
         (void *) qctx,
         ok ? "true" : "false");
    if (!ok)
        ereport(ERROR,
                (errmsg("custom_filter[memctx_violation]: allocation escaped query context (label=%s rel=%s)",
                        label ? label : "<null>",
                        relname ? relname : "<global>")));
}

static bool
cf_atom_equal(const PolicyAtomC *a, const PolicyAtomC *b)
{
    if (!a || !b) return false;
    if (a->canon_key && b->canon_key)
        return strcmp(a->canon_key, b->canon_key) == 0;
    if (a->kind != b->kind) return false;
    if (a->join_class_id != b->join_class_id) return false;
    if ((a->lhs_schema_key && !b->lhs_schema_key) || (!a->lhs_schema_key && b->lhs_schema_key)) return false;
    if ((a->rhs_schema_key && !b->rhs_schema_key) || (!a->rhs_schema_key && b->rhs_schema_key)) return false;
    if (a->lhs_schema_key && b->lhs_schema_key && strcmp(a->lhs_schema_key, b->lhs_schema_key) != 0) return false;
    if (a->rhs_schema_key && b->rhs_schema_key && strcmp(a->rhs_schema_key, b->rhs_schema_key) != 0) return false;
    if (a->op != b->op) return false;
    if (a->const_count != b->const_count) return false;
    for (int i = 0; i < a->const_count; i++) {
        const char *av = a->const_values ? a->const_values[i] : NULL;
        const char *bv = b->const_values ? b->const_values[i] : NULL;
        if ((av && !bv) || (!av && bv)) return false;
        if (av && bv && strcmp(av, bv) != 0) return false;
    }
    return true;
}

static void
cf_log_atom(const char *prefix, const PolicyAtomC *a)
{
    if (!a) return;
    StringInfoData buf;
    initStringInfo(&buf);
    appendStringInfo(&buf, "%s id=%d kind=%d lhs=%s rhs=%s op=%d jc=%d",
                     prefix,
                     a->atom_id,
                     a->kind,
                     a->lhs_schema_key ? a->lhs_schema_key : "<null>",
                     a->rhs_schema_key ? a->rhs_schema_key : "<null>",
                     a->op,
                     a->join_class_id);
    if (a->canon_key)
        appendStringInfo(&buf, " key=%s", a->canon_key);
    if (a->const_count > 0) {
        appendStringInfoString(&buf, " vals=[");
        for (int i = 0; i < a->const_count; i++) {
            if (i > 0) appendStringInfoString(&buf, ",");
            appendStringInfoString(&buf, a->const_values[i] ? a->const_values[i] : "");
        }
        appendStringInfoString(&buf, "]");
    }
    CF_TRACE_LOG( "%s", buf.data);
}

static char *
cf_rewrite_ast_global(const char *ast, const int *map, int map_len, int global_max)
{
    if (!ast || !map || map_len <= 0) return ast ? pstrdup(ast) : NULL;
    StringInfoData out;
    initStringInfo(&out);
    const char *p = ast;
    while (*p) {
        if (*p == 'y') {
            const char *q = p + 1;
            int id = 0;
            while (*q >= '0' && *q <= '9') {
                id = id * 10 + (*q - '0');
                q++;
            }
            if (q > p + 1) {
                if (id <= 0 || id >= map_len)
                    ereport(ERROR,
                            (errmsg("custom_filter: ast var y%d out of local range 1..%d",
                                    id, map_len - 1)));
                int gid = map[id];
                if (gid <= 0 || gid > global_max)
                    ereport(ERROR,
                            (errmsg("custom_filter: ast var y%d maps to invalid global y%d (max=%d)",
                                    id, gid, global_max)));
                appendStringInfo(&out, "y%d", gid);
                p = q;
                continue;
            }
        }
        appendStringInfoChar(&out, *p);
        p++;
    }
    return out.data;
}

static void
cf_log_mapping_error(const char *target, int bundle_idx,
                     const PolicyBundleC *b,
                     const PolicyEvalResultC *eval_res,
                     const int *local_to_global,
                     const char *ast_global,
                     const char *reason)
{
    CF_TRACE_LOG( "policy_contract: mapping_error target=%s bundle_index=%d reason=%s",
         target ? target : "<null>", bundle_idx, reason ? reason : "<unknown>");
    if (b) {
        for (int j = 0; j < b->atom_count; j++) {
            const PolicyAtomC *ba = &b->atoms[j];
            cf_log_atom("policy_contract: local_atom", ba);
            if (local_to_global && ba->atom_id > 0 && ba->atom_id < b->atom_count + 1) {
                CF_TRACE_LOG( "policy_contract: local_map y%d -> global_y%d",
                     ba->atom_id, local_to_global[ba->atom_id]);
            }
        }
        if (b->ast && b->ast[0])
            CF_TRACE_LOG( "policy_contract: bundle_ast target=%s ast=%s",
                 target ? target : "<null>", b->ast);
    }
    if (eval_res && eval_res->atom_count > 0) {
        for (int g = 0; g < eval_res->atom_count; g++) {
            const PolicyAtomC *ga = &eval_res->atoms[g];
            cf_log_atom("policy_contract: global_atom", ga);
        }
    }
    if (ast_global)
        CF_TRACE_LOG( "policy_contract: bundle_ast_global target=%s ast=%s",
             target ? target : "<null>", ast_global);
}

static void
cf_validate_ast_vars(const char *ast, const int *map, int map_len, int global_max,
                     const PolicyBundleC *b, const PolicyEvalResultC *eval_res,
                     int bundle_idx)
{
    if (!ast || !map || map_len <= 0) return;
    const char *p = ast;
    while (*p) {
        if (*p == 'y') {
            const char *q = p + 1;
            int id = 0;
            while (*q >= '0' && *q <= '9') {
                id = id * 10 + (*q - '0');
                q++;
            }
            if (q > p + 1) {
                if (id <= 0 || id >= map_len) {
                    cf_log_mapping_error(b ? b->target_table : NULL, bundle_idx,
                                         b, eval_res, map, NULL, "ast var out of local range");
                    ereport(ERROR,
                            (errmsg("custom_filter: ast var y%d out of local range 1..%d",
                                    id, map_len - 1)));
                }
                int gid = map[id];
                if (gid <= 0 || gid > global_max) {
                    cf_log_mapping_error(b ? b->target_table : NULL, bundle_idx,
                                         b, eval_res, map, NULL, "ast var maps to invalid global");
                    ereport(ERROR,
                            (errmsg("custom_filter: ast var y%d maps to invalid global y%d (max=%d)",
                                    id, gid, global_max)));
                }
                p = q;
                continue;
            }
        }
        p++;
    }
}


bool cf_enabled = false;
static int cf_debug_mode = 0;
static bool cf_contract_mode = false;
static bool cf_debug_ids = false;
static char *cf_policy_path = NULL;
static int cf_profile_k = 0;
static char *cf_profile_query = NULL;
static bool cf_profile_rescan = false;

bool
cf_trace_enabled(void)
{
    return cf_debug_mode == 2;
}

bool
cf_debug_enabled(void)
{
    return cf_debug_mode != 0;
}

bool
cf_contract_enabled(void)
{
    return cf_contract_mode || cf_debug_mode == 1;
}


bool cf_in_internal_query = false;
/* True while we're inside standard_ExecutorStart() initializing plan states. */
static bool cf_in_executor_start_init = false;


set_rel_pathlist_hook_type prev_set_rel_pathlist_hook = NULL;
planner_hook_type prev_planner_hook = NULL;
ExecutorStart_hook_type prev_ExecutorStart_hook = NULL;


void cf_rel_pathlist_hook(PlannerInfo *root, RelOptInfo *rel, Index rti, RangeTblEntry *rte);
static PlannedStmt *cf_planner_hook(Query *parse, const char *query_string,
                                    int cursorOptions, ParamListInfo boundParams);
static void cf_executor_start(QueryDesc *queryDesc, int eflags);

Plan *cf_plan_path(PlannerInfo *root, RelOptInfo *rel,struct CustomPath *best_path,List *tlist, List *clauses, List *custom_plans);

Node *cf_create_state(CustomScan *cscan);
void cf_begin(CustomScanState *node, EState *estate, int eflags);
TupleTableSlot *cf_exec(CustomScanState *node);
void cf_end(CustomScanState *node);
void cf_explain(CustomScanState *node, List *ancestors, ExplainState *es);
void cf_rescan(CustomScanState *node);
bool cf_child_is_scan(PlanState *node);
TupleTableSlot *cf_return_tuple(CustomScanState *node);
void cf_accum_validation_time(struct CfExec *st, instr_time *start_time);

static const char *cf_path_type_name(Path *path);
static const char *cf_debug_mode_name(int mode);

static void
cf_log_policy_identity(const char *path)
{
    if (!path || !path[0])
        return;

    struct stat st;
    if (stat(path, &st) != 0)
    {
        CF_TRACE_LOG( "policy_contract: policy_path=%s (stat failed)", path);
        return;
    }

    CF_TRACE_LOG( "policy_contract: policy_path=%s size=%lld",
         path, (long long) st.st_size);

    size_t sz = (size_t) st.st_size;
    char *buf = (char *) palloc(sz > 0 ? sz : 1);

    File fd = PathNameOpenFile(path, O_RDONLY | PG_BINARY);
    if (fd < 0)
    {
        CF_TRACE_LOG( "policy_contract: policy_path=%s md5=ERROR(open)", path);
        pfree(buf);
        return;
    }

    int nread = FileRead(fd, buf, sz, 0, WAIT_EVENT_DATA_FILE_READ);
    FileClose(fd);
    if (nread < 0 || (size_t)nread != sz)
    {
        CF_TRACE_LOG( "policy_contract: policy_path=%s md5=ERROR(read)", path);
        pfree(buf);
        return;
    }

    char md5buf[MD5_DIGEST_LENGTH * 2 + 1];
    const char *err = NULL;
    if (pg_md5_hash(buf, sz, md5buf, &err))
    {
        md5buf[MD5_DIGEST_LENGTH * 2] = '\0';
        CF_TRACE_LOG( "policy_contract: policy_path=%s md5=%s", path, md5buf);
    }
    else
    {
        CF_TRACE_LOG( "policy_contract: policy_path=%s md5=ERROR(hash)", path);
    }
    pfree(buf);
}
static PolicyQueryState *cf_build_query_state(EState *estate, const char *query_str);
static TableFilterState *cf_find_filter(PolicyQueryState *qs, Oid relid, bool log_on_miss);
static int32 cf_ctid_to_rid(TableFilterState *tf, BlockNumber blk, OffsetNumber off);
static TupleTableSlot *cf_store_slot(CustomScanState *node, TupleTableSlot *slot);
static bool cf_table_wrapped(PolicyQueryState *qs, const char *name);
static const char *cf_plan_find_scan_type(Plan *plan, PlannedStmt *pstmt, Oid relid);
static bool cf_plan_scan_relid(Plan *plan, Index *out_relid);
static bool cf_relid_is_relation(PlannedStmt *pstmt, Index scanrelid, Oid *out_relid);
typedef enum CfTidSource
{
    CF_TID_NONE = 0,
    CF_TID_TTS = 1,
    CF_TID_SYSATTR = 2,
    CF_TID_MAT_TTS = 3,
    CF_TID_HEAPTUPLE = 4
} CfTidSource;

static const char *cf_tid_source_name(CfTidSource src);
static bool cf_slot_get_ctid(TupleTableSlot *slot, ItemPointerData *out, CfTidSource *src);
static TupleTableSlot *cf_scan_slot(PlanState *child, TupleTableSlot *fallback);
static void cf_collect_scanned_tables(EState *estate, MemoryContext mcxt,
                                      char ***out_names, int *out_count,
                                      char ***out_wrapped, int *out_wrapped_count,
                                      int *out_main_rel_count, int *out_total_rel_count);
static bool cf_table_in_list(const char *name, char **list, int count);
static int cf_eval_target_index(const PolicyEvalResultC *res, const char *name);
static void cf_parse_query_targets(const char *query_str, MemoryContext mcxt, char ***out_tables, int *out_count);
static bool cf_table_should_filter(PolicyQueryState *qs, const char *name);
static bool cf_table_scanned(PolicyQueryState *qs, const char *name);
static bool cf_rel_is_policy_target(PlannerInfo *root, Oid relid);
static void cf_clear_plan_eval_cache(void);
static const PolicyEvalResultC *cf_get_plan_eval(Query *parse);


CustomPathMethods CFPathMethods = {
    .CustomName     = "custom_filter",
    .PlanCustomPath = cf_plan_path,
};

CustomScanMethods CFPlanMethods = {
    .CustomName            = "custom_filter",
    .CreateCustomScanState = cf_create_state,
};

CustomExecMethods CFExecMethods = {
    .BeginCustomScan   = cf_begin,
    .ExecCustomScan    = cf_exec,
    .EndCustomScan     = cf_end,
    .ReScanCustomScan  = cf_rescan,
    .ExplainCustomScan = cf_explain,
};


void _PG_init(void);
void _PG_fini(void);

void
_PG_init(void)
{
    DefineCustomBoolVariable("custom_filter.enabled",
                             "",
                             NULL,
                             &cf_enabled,
                             false,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    static const struct config_enum_entry debug_mode_options[] = {
        {"off", 0, false},
        {"contract", 1, false},
        {"trace", 2, false},
        {NULL, 0, false}
    };

    DefineCustomEnumVariable("custom_filter.debug_mode",
                             "",
                             NULL,
                             &cf_debug_mode,
                             0,
                             debug_mode_options,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    DefineCustomBoolVariable("custom_filter.contract_mode",
                             "",
                             NULL,
                             &cf_contract_mode,
                             false,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    DefineCustomBoolVariable("custom_filter.debug_ids",
                             "Emit executor identity / binding debug NOTICE lines (temporary; off by default).",
                             NULL,
                             &cf_debug_ids,
                             false,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    DefineCustomIntVariable("custom_filter.profile_k",
                            "",
                            NULL,
                            &cf_profile_k,
                            0,
                            0,
                            1000000,
                            PGC_SUSET,
                            0,
                            NULL, NULL, NULL);

    DefineCustomStringVariable("custom_filter.profile_query",
                               "",
                               NULL,
                               &cf_profile_query,
                               "",
                               PGC_SUSET,
                               0,
                               NULL, NULL, NULL);

    DefineCustomStringVariable("custom_filter.policy_path",
                               "",
                               NULL,
                               &cf_policy_path,
                               NULL,
                               PGC_SUSET,
                               0,
                               NULL, NULL, NULL);

    DefineCustomBoolVariable("custom_filter.profile_rescan",
                             "",
                             NULL,
                             &cf_profile_rescan,
                             false,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    prev_planner_hook = planner_hook;
    planner_hook = cf_planner_hook;

    prev_set_rel_pathlist_hook = set_rel_pathlist_hook;
    set_rel_pathlist_hook = cf_rel_pathlist_hook;

    prev_ExecutorStart_hook = ExecutorStart_hook;
    ExecutorStart_hook = cf_executor_start;

    RegisterCustomScanMethods(&CFPlanMethods);
}

void
_PG_fini(void)
{
    planner_hook = prev_planner_hook;
    set_rel_pathlist_hook = prev_set_rel_pathlist_hook;
    ExecutorStart_hook = prev_ExecutorStart_hook;
    cf_clear_plan_eval_cache();
}

typedef struct PlannerEvalCache
{
    const Query *parse;
    char *policy_path;
    uint64 rtable_sig;
    char **scanned_tables;
    int n_scanned_tables;
    PolicyEvalResultC *eval_res;
} PlannerEvalCache;

static PlannerEvalCache cf_plan_eval_cache = {0};

static uint64
cf_rtable_signature(Query *parse)
{
    if (!parse || !parse->rtable)
        return 0;
    /* FNV-1a over relation OIDs (order-sensitive). */
    uint64 h = 1469598103934665603ULL;
    ListCell *lc;
    foreach (lc, parse->rtable)
    {
        RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
        if (!rte || rte->rtekind != RTE_RELATION)
            continue;
        Oid relid = rte->relid;
        const unsigned char *p = (const unsigned char *) &relid;
        for (size_t i = 0; i < sizeof(relid); i++)
        {
            h ^= (uint64) p[i];
            h *= 1099511628211ULL;
        }
    }
    return h;
}

static void
cf_collect_parse_tables(Query *parse, MemoryContext mcxt, char ***out_tables, int *out_count)
{
    *out_tables = NULL;
    *out_count = 0;
    if (!parse || !parse->rtable)
        return;

    int count = 0;
    ListCell *lc;
    foreach (lc, parse->rtable)
    {
        RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
        if (rte && rte->rtekind == RTE_RELATION)
            count++;
    }
    if (count <= 0)
        return;

    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    char **tables = (char **) palloc0(sizeof(char *) * count);
    MemoryContextSwitchTo(oldctx);

    int idx = 0;
    foreach (lc, parse->rtable)
    {
        RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
        if (!rte || rte->rtekind != RTE_RELATION)
            continue;
        const char *rn = get_rel_name(rte->relid);
        if (!rn)
            continue;
        oldctx = MemoryContextSwitchTo(mcxt);
        tables[idx++] = pstrdup(rn);
        MemoryContextSwitchTo(oldctx);
    }

    *out_tables = tables;
    *out_count = idx;
}

static void
cf_clear_plan_eval_cache(void)
{
    if (cf_plan_eval_cache.eval_res)
        free_policy_eval_result(cf_plan_eval_cache.eval_res);
    if (cf_plan_eval_cache.scanned_tables)
    {
        for (int i = 0; i < cf_plan_eval_cache.n_scanned_tables; i++)
        {
            if (cf_plan_eval_cache.scanned_tables[i])
                pfree(cf_plan_eval_cache.scanned_tables[i]);
        }
        pfree(cf_plan_eval_cache.scanned_tables);
    }
    if (cf_plan_eval_cache.policy_path)
        pfree(cf_plan_eval_cache.policy_path);
    memset(&cf_plan_eval_cache, 0, sizeof(cf_plan_eval_cache));
}

static const PolicyEvalResultC *
cf_get_plan_eval(Query *parse)
{
    if (!parse || !cf_policy_path || cf_policy_path[0] == '\0')
        return NULL;

    uint64 sig = cf_rtable_signature(parse);
    if (cf_plan_eval_cache.parse == parse &&
        cf_plan_eval_cache.policy_path &&
        strcmp(cf_plan_eval_cache.policy_path, cf_policy_path) == 0 &&
        cf_plan_eval_cache.rtable_sig == sig)
        return cf_plan_eval_cache.eval_res;

    cf_clear_plan_eval_cache();

    MemoryContext oldctx = MemoryContextSwitchTo(TopMemoryContext);
    cf_plan_eval_cache.parse = parse;
    cf_plan_eval_cache.policy_path = pstrdup(cf_policy_path);
    cf_plan_eval_cache.rtable_sig = sig;
    MemoryContextSwitchTo(oldctx);

    cf_collect_parse_tables(parse, TopMemoryContext,
                            &cf_plan_eval_cache.scanned_tables,
                            &cf_plan_eval_cache.n_scanned_tables);
    if (cf_plan_eval_cache.n_scanned_tables <= 0)
        return NULL;

    oldctx = MemoryContextSwitchTo(TopMemoryContext);
    cf_plan_eval_cache.eval_res =
        evaluate_policies_scanned(cf_policy_path,
                                  cf_plan_eval_cache.scanned_tables,
                                  cf_plan_eval_cache.n_scanned_tables);
    MemoryContextSwitchTo(oldctx);
    return cf_plan_eval_cache.eval_res;
}

static bool
cf_query_has_policy_targets(Query *parse)
{
    const PolicyEvalResultC *eval = cf_get_plan_eval(parse);
    return (eval && eval->target_count > 0);
}

static PlannedStmt *
cf_planner_hook(Query *parse, const char *query_string,
                int cursorOptions, ParamListInfo boundParams)
{
    cf_clear_plan_eval_cache();
    if (cf_enabled && !cf_in_internal_query && cf_query_has_policy_targets(parse))
    {
        SetConfigOption("enable_indexonlyscan", "off", PGC_USERSET, PGC_S_SESSION);
        if (cf_contract_enabled())
        {
            SetConfigOption("enable_indexscan", "off", PGC_USERSET, PGC_S_SESSION);
            SetConfigOption("enable_bitmapscan", "off", PGC_USERSET, PGC_S_SESSION);
            SetConfigOption("enable_seqscan", "on", PGC_USERSET, PGC_S_SESSION);
        }
    }

    PlannedStmt *res = NULL;
    if (prev_planner_hook)
        res = prev_planner_hook(parse, query_string, cursorOptions, boundParams);
    else
        res = standard_planner(parse, query_string, cursorOptions, boundParams);
    cf_clear_plan_eval_cache();
    return res;
}

void
cf_rel_pathlist_hook(PlannerInfo *root, RelOptInfo *rel,
                     Index rti, RangeTblEntry *rte)
{
    if (prev_set_rel_pathlist_hook)
        prev_set_rel_pathlist_hook(root, rel, rti, rte);

    
    if (!cf_enabled || cf_in_internal_query)
        return;

    if (rel->reloptkind != RELOPT_BASEREL || rte == NULL || rte->rtekind != RTE_RELATION)
        return;

    Relation relobj = table_open(rte->relid, NoLock);
    if (relobj->rd_rel->relkind != RELKIND_RELATION)
    {
        table_close(relobj, NoLock);
        return;
    }
    table_close(relobj, NoLock);

    /* Only wrap when there is provably something to enforce. */
    if (!cf_query_has_policy_targets(root ? root->parse : NULL))
        return;
    if (!cf_rel_is_policy_target(root, rte->relid))
        return;

    /*
     * Wrap only policy-target base relations.
     *
     * This is safe because we invalidate the planner eval cache if the parse
     * range-table changes (e.g., pulled-up relations), ensuring target detection
     * stays in sync with planning transformations.
     */

    const char *relname = rte ? get_rel_name(rte->relid) : NULL;
    List *orig_paths = rel->pathlist;
    List *wrapped_paths = NIL;
    Path *best_total = NULL;
    Path *best_startup = NULL;
    ListCell *lc;

    foreach (lc, orig_paths)
    {
        Path *child = (Path *) lfirst(lc);
        CustomPath *cp = makeNode(CustomPath);
        cp->methods = &CFPathMethods;
        cp->path.pathtype = T_CustomScan;
        cp->path.parent = rel;
        cp->path.pathtarget = rel->reltarget;
        cp->path.param_info = child->param_info;
        cp->path.rows = child->rows;
        cp->path.startup_cost = child->startup_cost;
        cp->path.total_cost = child->total_cost;
        cp->flags = 0;
        cp->custom_paths = list_make1(child);
        cp->custom_private = NIL;

        wrapped_paths = lappend(wrapped_paths, &cp->path);
        if (!best_total || cp->path.total_cost < best_total->total_cost)
            best_total = &cp->path;
        if (!best_startup || cp->path.startup_cost < best_startup->startup_cost)
            best_startup = &cp->path;
    }

    if (wrapped_paths == NIL)
        return;

    CF_TRACE_LOG( "custom_filter: wrap rel=%s oid=%u paths=%d",
         relname ? relname : "<unknown>",
         rte ? rte->relid : InvalidOid,
         list_length(wrapped_paths));

    rel->pathlist = wrapped_paths;
    rel->cheapest_total_path = best_total;
    rel->cheapest_startup_path = best_startup;
}

static const char *
cf_path_type_name(Path *path)
{
    if (!path)
        return "<null>";
    switch (path->pathtype)
    {
        case T_SeqScan:
            return "SeqScan";
        case T_SampleScan:
            return "SampleScan";
        case T_IndexScan:
            return "IndexScan";
        case T_IndexOnlyScan:
            return "IndexOnlyScan";
        case T_BitmapHeapPath:
            return "BitmapHeapScan";
        case T_TidPath:
            return "TidScan";
        case T_TidRangePath:
            return "TidRangeScan";
        case T_ForeignPath:
            return "ForeignScan";
        case T_FunctionScan:
            return "FunctionScan";
        case T_TableFuncScan:
            return "TableFuncScan";
        case T_ValuesScan:
            return "ValuesScan";
        case T_CteScan:
            return "CteScan";
        case T_WorkTableScan:
            return "WorkTableScan";
        default:
            return "OtherPath";
    }
}

static const char *
cf_debug_mode_name(int mode)
{
    switch (mode)
    {
        case 0:
            return "off";
        case 1:
            return "contract";
        case 2:
            return "trace";
        default:
            return "off";
    }
}

static bool
cf_rel_is_policy_target(PlannerInfo *root, Oid relid)
{
    if (!root || relid == InvalidOid)
        return false;
    if (!cf_policy_path || cf_policy_path[0] == '\0')
        return false;

    bool should_wrap = false;
    const PolicyEvalResultC *eval = cf_get_plan_eval(root->parse);
    if (!eval)
        return false;

    const char *relname = get_rel_name(relid);
    if (relname && eval->target_count > 0)
    {
        for (int i = 0; i < eval->target_count; i++)
        {
            const char *t = eval->target_tables[i];
            if (t && strcmp(t, relname) == 0)
            {
                should_wrap = true;
                break;
            }
        }
    }
    return should_wrap;
}

static const char *
cf_scan_state_name(PlanState *node)
{
    if (!node)
        return "<null>";
    switch (nodeTag(node))
    {
        case T_SeqScanState:
            return "SeqScan";
        case T_SampleScanState:
            return "SampleScan";
        case T_IndexScanState:
            return "IndexScan";
        case T_IndexOnlyScanState:
            return "IndexOnlyScan";
        case T_BitmapHeapScanState:
            return "BitmapHeapScan";
        case T_TidScanState:
            return "TidScan";
        case T_TidRangeScanState:
            return "TidRangeScan";
        case T_ForeignScanState:
            return "ForeignScan";
        case T_FunctionScanState:
            return "FunctionScan";
        case T_TableFuncScanState:
            return "TableFuncScan";
        case T_ValuesScanState:
            return "ValuesScan";
        case T_CteScanState:
            return "CteScan";
        case T_WorkTableScanState:
            return "WorkTableScan";
        default:
            return "OtherScan";
    }
}


Plan *
cf_plan_path(PlannerInfo *root, RelOptInfo *rel,
             CustomPath *best_path,
             List *tlist, List *clauses, List *custom_plans)
{
    CustomScan *cscan = makeNode(CustomScan);
    cscan->methods = &CFPlanMethods;

    
    cscan->scan.scanrelid       = rel->relid;
    Plan *child_plan = (custom_plans && custom_plans != NIL)
                           ? (Plan *) linitial(custom_plans)
                           : NULL;
    if (child_plan && child_plan->targetlist)
        cscan->scan.plan.targetlist = child_plan->targetlist;
    else
        cscan->scan.plan.targetlist = tlist;
    cscan->scan.plan.qual       = NIL;   

    cscan->custom_scan_tlist = cscan->scan.plan.targetlist;
    cscan->custom_exprs      = NIL;

    cscan->custom_plans = custom_plans;

    cscan->custom_relids = bms_copy(rel->relids);

    return &cscan->scan.plan;
}


typedef struct CfExec
{
    CustomScanState css;

    PlanState *child_plan;
    double data_transfer_ms;
    double policy_build_ms;
    double row_validation_ms;
    double child_exec_ms;
    double ctid_extract_ms;
    double ctid_to_rid_ms;
    double allow_check_ms;
    double projection_ms;

    uint64 tuples_seen;
    uint64 tuples_passed;
    uint64 misses;
    Oid relid;
    char relname[NAMEDATALEN];
    uint32 seq_rid;
    const char *scan_type;
    bool tid_logged;

    struct TableFilterState *filter;
    bool need_filter_rebind;
    uint64 bound_build_seq;
    bool attempted_filter_rebuild;
    uint64 rescan_calls;
    bool exec_logged;
    bool debug_exec_logged;
} CfExec;

typedef struct BlockIndex
{
    uint32 start_rid;
    uint32 end_rid;
    uint32 max_off;
    uint16 *off2delta;
    bool present;
} BlockIndex;

typedef struct TableFilterState
{
    Oid relid;
    char relname[NAMEDATALEN];
    uint32 n_rows;
    uint8 *allow_bits;
    size_t allow_nbytes;
    uint32 allow_popcount;
    uint32 *ctid_pairs;
    uint32 ctid_pairs_len;
    size_t ctid_bytes;
    BlockIndex *blk_index;
    uint32 n_blocks;
    size_t blk_index_bytes;
    uint64 seen;
    uint64 passed;
    uint64 misses;
} TableFilterState;

#define CF_ALLOW_CANARY_BYTES 8
static const uint8 cf_allow_canary[CF_ALLOW_CANARY_BYTES] = {
    0xA5, 0x5A, 0xC3, 0x3C, 0x9E, 0xE9, 0x77, 0x88
};

typedef struct PolicyQueryState
{
    bool ready;
    bool metrics_logged;
    int n_filters;
    TableFilterState *filters;
    /* Debug-only corruption guard for qs->filters (set at ready, checked later). */
    uint64 filters_guard_hash;
    bool filters_guard_set;
    bool filters_guard_reported;
    const char *filters_guard_last_ok_phase;
    /* Debug-only: where the filters array was allocated (CurrentMemoryContext at alloc time). */
    MemoryContext filters_alloc_mctx;
    MemoryContext qctx;
    char **needed_files;
    int n_needed_files;
    char **policy_targets;
    int n_policy_targets;
    char **closure_tables;
    int n_closure_tables;
    char **query_targets;
    int n_query_targets;
    char **scanned_tables;
    int n_scanned_tables;
    char **wrapped_tables;
    int n_wrapped_tables;
    size_t bytes_allow;
    size_t bytes_ctid;
    size_t bytes_blk_index;
    size_t bytes_artifacts_loaded;
    double eval_ms;
    double artifact_load_ms;
    double artifact_parse_ms;
    double atoms_ms;
    double presence_ms;
    double project_ms;
    double stamp_ms;
    double bin_ms;
    double local_sat_ms;
    double fill_ms;
    double prop_ms;
    int prop_iters;
    double decode_ms;
    double policy_total_ms;
    double ctid_map_ms;
    double filter_ms;
    double child_exec_ms;
    double ctid_extract_ms;
    double ctid_to_rid_ms;
    double allow_check_ms;
    double projection_ms;
    uint64 rows_seen;
    uint64 rows_passed;
    uint64 ctid_misses;
    long rss_kb_before_eval;
    long rss_kb_after_eval;
    long rss_kb_after_load;
    long rss_kb_after_engine;
    long rss_kb_after_ctid;
    long rss_kb_end;
    long peak_rss_kb_end;

    /* Rescan profiling (debug only). */
    uint64 build_seq;
    uint64 policy_eval_calls;
    uint64 artifact_load_calls;
    uint64 policy_run_calls;
    uint64 allow_build_calls;
    uint64 blk_index_build_calls;
} PolicyQueryState;

/*
 * Debug-only corruption guard for qs->filters[].
 *
 * We hash a subset of TableFilterState fields that should be stable for the
 * lifetime of a single statement, excluding runtime counters (seen/passed/misses)
 * to avoid false positives.
 */
static inline uint64
cf_fnv1a64_update(uint64 h, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *) data;
    while (len--)
    {
        h ^= (uint64) (*p++);
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64
cf_filters_guard_compute_hash(const PolicyQueryState *qs)
{
    /* FNV-1a 64-bit offset basis. */
    uint64 h = 1469598103934665603ULL;
    if (!qs)
        return h;

    h = cf_fnv1a64_update(h, &qs->n_filters, sizeof(qs->n_filters));
    if (!qs->filters || qs->n_filters <= 0)
        return h;

    for (int i = 0; i < qs->n_filters; i++)
    {
        const TableFilterState *tf = &qs->filters[i];
        h = cf_fnv1a64_update(h, &tf->relid, sizeof(tf->relid));
        size_t rn = strnlen(tf->relname, NAMEDATALEN);
        h = cf_fnv1a64_update(h, &rn, sizeof(rn));
        if (rn > 0)
            h = cf_fnv1a64_update(h, tf->relname, rn);
        h = cf_fnv1a64_update(h, &tf->n_rows, sizeof(tf->n_rows));
        h = cf_fnv1a64_update(h, &tf->allow_bits, sizeof(tf->allow_bits));
        h = cf_fnv1a64_update(h, &tf->allow_nbytes, sizeof(tf->allow_nbytes));
        h = cf_fnv1a64_update(h, &tf->allow_popcount, sizeof(tf->allow_popcount));
        h = cf_fnv1a64_update(h, &tf->ctid_pairs, sizeof(tf->ctid_pairs));
        h = cf_fnv1a64_update(h, &tf->ctid_pairs_len, sizeof(tf->ctid_pairs_len));
        h = cf_fnv1a64_update(h, &tf->ctid_bytes, sizeof(tf->ctid_bytes));
        h = cf_fnv1a64_update(h, &tf->blk_index, sizeof(tf->blk_index));
        h = cf_fnv1a64_update(h, &tf->n_blocks, sizeof(tf->n_blocks));
        h = cf_fnv1a64_update(h, &tf->blk_index_bytes, sizeof(tf->blk_index_bytes));
    }

    return h;
}

static const char *
cf_mctx_safe_name(MemoryContext mctx)
{
    if (!mctx)
        return "<null>";
    if (mctx->ident)
        return mctx->ident;
    if (mctx->name)
        return mctx->name;
    return "<unnamed>";
}

static void
cf_filters_guard_set(PolicyQueryState *qs, const char *phase)
{
    if (!qs)
        return;
    qs->filters_guard_hash = cf_filters_guard_compute_hash(qs);
    qs->filters_guard_set = true;
    qs->filters_guard_reported = false;
    qs->filters_guard_last_ok_phase = phase;
}

static void
cf_filters_guard_check(PolicyQueryState *qs, const char *phase)
{
    if (!cf_debug_ids || !qs || !qs->filters_guard_set)
        return;

    uint64 h = cf_filters_guard_compute_hash(qs);
    if (h == qs->filters_guard_hash)
    {
        qs->filters_guard_last_ok_phase = phase;
        return;
    }

    if (qs->filters_guard_reported)
        return;

    /* One-shot report of the first detected change. */
    qs->filters_guard_reported = true;

    uintptr_t start = (uintptr_t) qs->filters;
    uintptr_t end = start + (uintptr_t) qs->n_filters * (uintptr_t) sizeof(TableFilterState);

    StringInfoData msg;
    initStringInfo(&msg);
    appendStringInfo(&msg,
                     "CF_GUARD_CHANGED pid=%d qs=%p build_seq=%llu phase=%s last_ok=%s "
                     "filters_ptr=%p range=[0x%lx,0x%lx) n_filters=%d old_hash=%llu new_hash=%llu",
                     (int) getpid(),
                     (void *) qs,
                     (unsigned long long) qs->build_seq,
                     phase ? phase : "<null>",
                     qs->filters_guard_last_ok_phase ? qs->filters_guard_last_ok_phase : "<unset>",
                     (void *) qs->filters,
                     (unsigned long) start,
                     (unsigned long) end,
                     qs->n_filters,
                     (unsigned long long) qs->filters_guard_hash,
                     (unsigned long long) h);

    /* Dump filter entries inline (qs->n_filters is small in our workloads). */
    int lim = qs->n_filters;
    if (lim > 32)
        lim = 32;
    for (int i = 0; i < lim; i++)
    {
        const TableFilterState *tf = &qs->filters[i];
        appendStringInfo(&msg,
                         " f%d(tf=%p relid=%u rel=%s allow=%p nbytes=%zu rows=%u ctid=%p ctid_len=%u blk=%p nblk=%u)",
                         i,
                         (void *) tf,
                         (unsigned int) tf->relid,
                         tf->relname[0] ? tf->relname : "<unknown>",
                         (void *) tf->allow_bits,
                         tf->allow_nbytes,
                         tf->n_rows,
                         (void *) tf->ctid_pairs,
                         tf->ctid_pairs_len,
                         (void *) tf->blk_index,
                         tf->n_blocks);
    }
    if (qs->n_filters > lim)
        appendStringInfoString(&msg, " ...");

    elog(NOTICE, "%s", msg.data);
}

typedef struct LoadedArtifact
{
    char *name;
    bytea *data;
    size_t len;
    bool owned;
} LoadedArtifact;

typedef struct ArtifactNameIndexEntry
{
    char key[MAXPGPATH];
    int idx;
} ArtifactNameIndexEntry;

static bool
cf_find_ctid_rows(LoadedArtifact *arts, int art_count, const char *table, uint32 *out_rows)
{
    if (!arts || art_count <= 0 || !table || !out_rows)
        return false;
    size_t tlen = strlen(table);
    for (int i = 0; i < art_count; i++) {
        if (!arts[i].name || !arts[i].data)
            continue;
        size_t nlen = strlen(arts[i].name);
        if (nlen == tlen + 5 && memcmp(arts[i].name, table, tlen) == 0 &&
            strcmp(arts[i].name + tlen, "_ctid") == 0) {
            size_t bytes = (size_t) VARSIZE_ANY_EXHDR(arts[i].data);
            uint32 nrows = (uint32)(bytes / (sizeof(uint32) * 2));
            *out_rows = nrows;
            return true;
        }
    }
    return false;
}

static MemoryContext cf_query_cxt = NULL;
static PolicyQueryState *cf_query_state = NULL;
static PlannedStmt *cf_query_plannedstmt = NULL;
static uint64 cf_query_build_seq = 0;

static const char *
cf_rtekind_name(int k)
{
    switch (k)
    {
        case RTE_RELATION: return "RELATION";
        case RTE_SUBQUERY: return "SUBQUERY";
        case RTE_JOIN: return "JOIN";
        case RTE_FUNCTION: return "FUNCTION";
        case RTE_TABLEFUNC: return "TABLEFUNC";
        case RTE_VALUES: return "VALUES";
        case RTE_CTE: return "CTE";
        case RTE_NAMEDTUPLESTORE: return "NAMEDTUPLESTORE";
        case RTE_RESULT: return "RESULT";
        default: break;
    }
    return "OTHER";
}

static void
cf_debug_log_scan_ids(const char *event, CfExec *st, CustomScanState *node)
{
    if (!cf_debug_ids || !event || !st || !node)
        return;

    CustomScan *cscan = (CustomScan *) node->ss.ps.plan;
    EState *estate = node->ss.ps.state;

    Index scanrelid = 0;
    const char *rtekind = "<none>";
    Oid rte_relid_oid = InvalidOid;
    const char *rte_relname = "<none>";
    if (cscan)
        scanrelid = cscan->scan.scanrelid;
    if (estate && scanrelid > 0)
    {
        RangeTblEntry *rte = rt_fetch(scanrelid, estate->es_range_table);
        if (rte)
        {
            rtekind = cf_rtekind_name((int) rte->rtekind);
            rte_relid_oid = rte->relid;
            if (rte_relid_oid != InvalidOid)
            {
                const char *rn = get_rel_name(rte_relid_oid);
                if (rn)
                    rte_relname = rn;
            }
        }
    }

    PolicyQueryState *qs = cf_query_state;
    bool should_filter = false;
    bool in_targets = false;
    bool scanned = false;
    bool wrapped = false;
    if (qs && st->relname[0])
    {
        in_targets = cf_table_in_list(st->relname, qs->policy_targets, qs->n_policy_targets);
        scanned = cf_table_scanned(qs, st->relname);
        should_filter = cf_table_should_filter(qs, st->relname);
        wrapped = cf_table_wrapped(qs, st->relname);
    }

    CF_DEBUG_IDS_LOG("pid=%d build_seq=%llu qs=%p node=%p plan=%p event=%s "
                     "scanrelid=%d rtekind=%s rte_relid_oid=%u rte_relname=%s "
                     "st_relid=%u st_relname=%s st_scan=%s "
                     "need_rebind=%d bound_build_seq=%llu "
                     "should_filter=%d in_policy_targets=%d scanned=%d wrapped=%d "
                     "filter_ptr=%p filter_allow_bits=%p filter_found=%d",
                     (int) getpid(),
                     (unsigned long long) (qs ? qs->build_seq : 0),
                     (void *) qs,
                     (void *) st,
                     (void *) node->ss.ps.plan,
                     event,
                     (int) scanrelid,
                     rtekind,
                     rte_relid_oid,
                     rte_relname,
                     st->relid,
                     st->relname[0] ? st->relname : "<unknown>",
                     st->scan_type ? st->scan_type : "<unknown>",
                     st->need_filter_rebind ? 1 : 0,
                     (unsigned long long) st->bound_build_seq,
                     should_filter ? 1 : 0,
                     in_targets ? 1 : 0,
                     scanned ? 1 : 0,
                     wrapped ? 1 : 0,
                     (void *) st->filter,
                     (void *) (st->filter ? st->filter->allow_bits : NULL),
                     st->filter ? 1 : 0);
}

static bool
cf_query_context_related(MemoryContext lhs, MemoryContext rhs)
{
    if (!lhs || !rhs)
        return false;
    if (lhs == rhs)
        return true;
    return cf_memory_context_contains(lhs, rhs) ||
           cf_memory_context_contains(rhs, lhs);
}

static PolicyQueryState *
cf_ensure_query_state(EState *estate, const char *query_str, PlannedStmt *pstmt)
{
    if (!estate || !estate->es_query_cxt)
        return cf_query_state;

    MemoryContext qctx = estate->es_query_cxt;
    /*
     * IMPORTANT: query-state must live in a context that outlives all plan
     * fragments that will execute (including initplans/CTEs/subplans).
     *
     * During ExecutorStart(), Postgres can initialize CustomScan nodes that live
     * under subplans with their own es_query_cxt. If we build query-state in a
     * short-lived child context, it may be reset mid-query, leaving stale
     * filter pointers (and NULL allow_bits).
     *
     * So: reuse only when the existing context CONTAINS the current one (i.e.,
     * existing is an ancestor). If the current context contains the existing
     * one, rebuild upward into the longer-lived context.
     */
    if (cf_query_state && cf_query_cxt &&
        (cf_query_cxt == qctx || cf_memory_context_contains(cf_query_cxt, qctx)))
        return cf_query_state;

    cf_query_state = cf_build_query_state(estate, query_str);
    cf_query_cxt = qctx;
    cf_query_plannedstmt = pstmt ? pstmt : estate->es_plannedstmt;
    return cf_query_state;
}

static PolicyQueryState *
cf_force_rebuild_query_state(EState *estate, const char *query_str, PlannedStmt *pstmt)
{
    if (!estate || !estate->es_query_cxt)
        return cf_query_state;
    if (cf_in_internal_query)
        return cf_query_state;
    cf_query_state = cf_build_query_state(estate, query_str);
    cf_query_cxt = estate->es_query_cxt;
    cf_query_plannedstmt = pstmt ? pstmt : estate->es_plannedstmt;
    return cf_query_state;
}

static void
cf_executor_start(QueryDesc *queryDesc, int eflags)
{
    PlannedStmt *pstmt = NULL;

    /*
     * standard_ExecutorStart() will ExecInitNode() the plan tree, which invokes
     * our CustomScan Begin callback (cf_begin). We want to avoid building/binding
     * per-query policy state from those early callbacks, because they can run
     * under subplan contexts (CTEs/initplans) that are shorter-lived than the
     * top-level query context.
     *
     * Instead, delay query-state construction until after standard_ExecutorStart
     * completes (we'll build it below from queryDesc->estate).
     */
    cf_in_executor_start_init = true;
    PG_TRY();
    {
        if (prev_ExecutorStart_hook)
            prev_ExecutorStart_hook(queryDesc, eflags);
        else
            standard_ExecutorStart(queryDesc, eflags);
    }
    PG_FINALLY();
    {
        cf_in_executor_start_init = false;
    }
    PG_END_TRY();

    if (!cf_enabled || cf_in_internal_query || !queryDesc || !queryDesc->estate)
        return;

    pstmt = queryDesc->plannedstmt;
    if (!pstmt || pstmt->commandType != CMD_SELECT)
        return;

    (void) cf_ensure_query_state(queryDesc->estate,
                                 queryDesc->sourceText ? queryDesc->sourceText : debug_query_string,
                                 pstmt);
}

static void
cf_log_query_metrics(PolicyQueryState *qs)
{
    if (!qs)
        return;
    elog(NOTICE,
         "policy_profile: eval_ms=%.3f artifact_load_ms=%.3f artifact_parse_ms=%.3f atoms_ms=%.3f presence_ms=%.3f project_ms=%.3f "
         "stamp_ms=%.3f bin_ms=%.3f local_sat_ms=%.3f fill_ms=%.3f prop_ms=%.3f prop_iters=%d "
         "decode_ms=%.3f policy_total_ms=%.3f ctid_map_ms=%.3f filter_ms=%.3f "
         "child_exec_ms=%.3f ctid_extract_ms=%.3f ctid_to_rid_ms=%.3f allow_check_ms=%.3f projection_ms=%.3f "
         "n_scanned_tables=%d n_policy_targets=%d n_filters=%d "
         "bytes_artifacts_loaded=%zu bytes_allow=%zu bytes_ctid=%zu bytes_blk_index=%zu "
         "rows_seen=%llu rows_passed=%llu ctid_misses=%llu "
         "rss_kb_before_eval=%ld rss_kb_after_eval=%ld rss_kb_after_load=%ld "
         "rss_kb_after_engine=%ld rss_kb_after_ctid=%ld rss_kb_end=%ld peak_rss_kb_end=%ld",
         qs->eval_ms,
         qs->artifact_load_ms,
         qs->artifact_parse_ms,
         qs->atoms_ms,
         qs->presence_ms,
         qs->project_ms,
         qs->stamp_ms,
         qs->bin_ms,
         qs->local_sat_ms,
         qs->fill_ms,
         qs->prop_ms,
         qs->prop_iters,
         qs->decode_ms,
         qs->policy_total_ms,
         qs->ctid_map_ms,
         qs->filter_ms,
         qs->child_exec_ms,
         qs->ctid_extract_ms,
         qs->ctid_to_rid_ms,
         qs->allow_check_ms,
         qs->projection_ms,
         qs->n_scanned_tables,
         qs->n_policy_targets,
         qs->n_filters,
         qs->bytes_artifacts_loaded,
         qs->bytes_allow,
         qs->bytes_ctid,
         qs->bytes_blk_index,
         (unsigned long long) qs->rows_seen,
         (unsigned long long) qs->rows_passed,
         (unsigned long long) qs->ctid_misses,
         qs->rss_kb_before_eval,
         qs->rss_kb_after_eval,
         qs->rss_kb_after_load,
         qs->rss_kb_after_engine,
         qs->rss_kb_after_ctid,
         qs->rss_kb_end,
         qs->peak_rss_kb_end);
}

static void
cf_query_state_reset_callback(void *arg)
{
    PolicyQueryState *qs = (PolicyQueryState *) arg;
    if (qs && !qs->metrics_logged)
    {
        if (cf_trace_enabled())
        {
            qs->rss_kb_end = cf_rss_kb_now();
            qs->peak_rss_kb_end = cf_peak_rss_kb();
        }
        cf_log_query_metrics(qs);
        qs->metrics_logged = true;
    }
    if (cf_query_state == qs)
    {
        cf_query_state = NULL;
        cf_query_cxt = NULL;
        cf_query_plannedstmt = NULL;
    }
}

static bool
cf_has_suffix(const char *name, const char *suffix)
{
    if (!name || !suffix)
        return false;
    size_t nlen = strlen(name);
    size_t slen = strlen(suffix);
    if (nlen < slen)
        return false;
    return strcmp(name + (nlen - slen), suffix) == 0;
}

static bool
cf_load_artifacts_batch(char **needed_files, int needed_count,
                        MemoryContext mcxt, LoadedArtifact *arts,
                        StringInfo missing)
{
    if (!needed_files || needed_count <= 0 || !arts)
        return true;

    HASHCTL ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.keysize = MAXPGPATH;
    ctl.entrysize = sizeof(ArtifactNameIndexEntry);
    ctl.hcxt = mcxt;
    HTAB *name_to_idx = hash_create("custom_filter artifact index",
                                    needed_count,
                                    &ctl,
                                    HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);

    for (int i = 0; i < needed_count; i++)
    {
        bool found = false;
        ArtifactNameIndexEntry *ent =
            (ArtifactNameIndexEntry *) hash_search(name_to_idx, needed_files[i], HASH_ENTER, &found);
        if (ent)
            ent->idx = i;
    }

    Datum *arr_elems = (Datum *) palloc0(sizeof(Datum) * needed_count);
    for (int i = 0; i < needed_count; i++)
        arr_elems[i] = CStringGetTextDatum(needed_files[i]);

    ArrayType *name_arr = construct_array(arr_elems,
                                          needed_count,
                                          TEXTOID,
                                          -1,
                                          false,
                                          TYPALIGN_INT);

    const char *sql =
        "SELECT name, file "
        "FROM public.files "
        "WHERE name = ANY($1::text[])";
    Oid argtypes[1];
    Datum values[1];
    char nulls[1] = { ' ' };
    argtypes[0] = get_array_type(TEXTOID);
    if (!OidIsValid(argtypes[0]))
        ereport(ERROR, (errmsg("custom_filter: could not resolve text[] type oid")));

    values[0] = PointerGetDatum(name_arr);
    int spi_rc = SPI_execute_with_args(sql, 1, argtypes, values, nulls, true, 0);
    if (spi_rc != SPI_OK_SELECT)
        ereport(ERROR,
                (errmsg("custom_filter: batch artifact load failed (spi_rc=%d)", spi_rc)));

    TupleDesc tupdesc = SPI_tuptable->tupdesc;
    for (uint64 row = 0; row < SPI_processed; row++)
    {
        HeapTuple tup = SPI_tuptable->vals[row];
        bool isnull_name = false;
        Datum name_d = SPI_getbinval(tup, tupdesc, 1, &isnull_name);
        if (isnull_name)
            continue;
        char *name = TextDatumGetCString(name_d);

        bool found = false;
        ArtifactNameIndexEntry *ent =
            (ArtifactNameIndexEntry *) hash_search(name_to_idx, name, HASH_FIND, &found);
        if (!found || !ent)
        {
            pfree(name);
            continue;
        }

        bool isnull_file = false;
        Datum file_d = SPI_getbinval(tup, tupdesc, 2, &isnull_file);
        if (isnull_file)
        {
            pfree(name);
            continue;
        }

        bytea *payload = NULL;
        bool owned = false;
        if (cf_has_suffix(name, "_ctid"))
        {
            MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
            payload = (bytea *) PG_DETOAST_DATUM_COPY(file_d);
            MemoryContextSwitchTo(oldctx);
            owned = true;
        }
        else
        {
            payload = (bytea *) PG_DETOAST_DATUM(file_d);
            owned = false;
        }

        arts[ent->idx].data = payload;
        arts[ent->idx].len = (size_t) VARSIZE_ANY_EXHDR(payload);
        arts[ent->idx].owned = owned;
        pfree(name);
    }

    bool ok = true;
    for (int i = 0; i < needed_count; i++)
    {
        if (arts[i].data)
            continue;
        if (missing && missing->len > 0)
            appendStringInfoString(missing, ", ");
        if (missing)
            appendStringInfoString(missing, needed_files[i]);
        ok = false;
    }
    return ok;
}

static void
cf_build_blk_index(TableFilterState *tf, MemoryContext mcxt)
{
    if (!tf || !tf->ctid_pairs || tf->ctid_pairs_len < 2)
        return;
    uint32 n_rows = tf->ctid_pairs_len / 2;
    uint32 max_blk = 0;
    for (uint32 r = 0; r < n_rows; r++)
    {
        uint32 blk = tf->ctid_pairs[2 * r];
        if (blk > max_blk)
            max_blk = blk;
    }
    uint32 n_blocks = max_blk + 1;

    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    tf->blk_index = (BlockIndex *) palloc0(sizeof(BlockIndex) * n_blocks);
    MemoryContextSwitchTo(oldctx);
    tf->n_blocks = n_blocks;
    tf->blk_index_bytes = (size_t) n_blocks * sizeof(BlockIndex);

    for (uint32 r = 0; r < n_rows; r++)
    {
        uint32 blk = tf->ctid_pairs[2 * r];
        uint32 off = tf->ctid_pairs[2 * r + 1];
        BlockIndex *bi = &tf->blk_index[blk];
        if (!bi->present)
        {
            bi->present = true;
            bi->start_rid = r;
            bi->end_rid = r;
            bi->max_off = off;
        }
        else
        {
            bi->end_rid = r;
            if (off > bi->max_off)
                bi->max_off = off;
        }
    }

    for (uint32 blk = 0; blk < n_blocks; blk++)
    {
        BlockIndex *bi = &tf->blk_index[blk];
        if (!bi->present)
            continue;

        size_t off_entries = (size_t) bi->max_off + 1;
        oldctx = MemoryContextSwitchTo(mcxt);
        bi->off2delta = (uint16 *) palloc(off_entries * sizeof(uint16));
        MemoryContextSwitchTo(oldctx);
        memset(bi->off2delta, 0xFF, off_entries * sizeof(uint16));
        tf->blk_index_bytes += off_entries * sizeof(uint16);

        if ((bi->end_rid - bi->start_rid) >= (uint32) 0xFFFF)
            ereport(ERROR,
                    (errmsg("custom_filter: block rid span exceeds uint16 delta rel=%s blk=%u span=%u",
                            tf->relname[0] ? tf->relname : "<unknown>",
                            blk,
                            (bi->end_rid - bi->start_rid))));
    }

    for (uint32 r = 0; r < n_rows; r++)
    {
        uint32 blk = tf->ctid_pairs[2 * r];
        uint32 off = tf->ctid_pairs[2 * r + 1];
        BlockIndex *bi = &tf->blk_index[blk];
        uint32 delta = r - bi->start_rid;
        if (delta >= (uint32) 0xFFFF)
            ereport(ERROR,
                    (errmsg("custom_filter: delta overflow rel=%s blk=%u rid=%u start=%u",
                            tf->relname[0] ? tf->relname : "<unknown>",
                            blk, r, bi->start_rid)));
        if (off > bi->max_off)
            ereport(ERROR,
                    (errmsg("custom_filter: offset overflow rel=%s blk=%u off=%u max_off=%u",
                            tf->relname[0] ? tf->relname : "<unknown>",
                            blk, off, bi->max_off)));
        if (bi->off2delta[off] != (uint16) 0xFFFF)
            ereport(ERROR,
                    (errmsg("custom_filter: duplicate CTID key rel=%s blk=%u off=%u",
                            tf->relname[0] ? tf->relname : "<unknown>",
                            blk, off)));
        bi->off2delta[off] = (uint16) delta;
    }

    if (cf_trace_enabled())
    {
        for (uint32 r = 0; r < n_rows && r < 5; r++)
        {
            uint32 blk = tf->ctid_pairs[2 * r];
            uint32 off = tf->ctid_pairs[2 * r + 1];
            CF_TRACE_LOG( "custom_filter: ctid_map[%u]=(%u,%u)->%u", r, blk, off, r);
        }
    }
}

static int32
cf_ctid_to_rid(TableFilterState *tf, BlockNumber blk, OffsetNumber off)
{
    if (!tf || !tf->blk_index || tf->n_blocks == 0)
        return -1;
    if ((uint32) blk >= tf->n_blocks)
        return -1;

    BlockIndex *bi = &tf->blk_index[(uint32) blk];
    if (!bi->present || !bi->off2delta)
        return -1;
    if ((uint32) off > bi->max_off)
        return -1;
    uint16 delta = bi->off2delta[(uint32) off];
    if (delta == (uint16) 0xFFFF)
        return -1;

    uint32 rid = bi->start_rid + (uint32) delta;
    if (rid < bi->start_rid || rid > bi->end_rid || rid >= tf->n_rows)
        ereport(ERROR,
                (errmsg("custom_filter[engine_error]: off2delta rid invalid rel=%s blk=%u off=%u rid=%u start=%u end=%u rows=%u",
                        tf->relname[0] ? tf->relname : "<unknown>",
                        (uint32) blk,
                        (uint32) off,
                        rid,
                        bi->start_rid,
                        bi->end_rid,
                        tf->n_rows)));
    return (int32) rid;
}

static TableFilterState *
cf_find_filter(PolicyQueryState *qs, Oid relid, bool log_on_miss)
{
    if (!qs || !qs->filters)
        return NULL;
    for (int i = 0; i < qs->n_filters; i++)
    {
        if (qs->filters[i].relid == relid)
            return &qs->filters[i];
    }
    if (cf_debug_ids && log_on_miss)
    {
        int n = qs->n_filters;
        if (n < 0) n = 0;
        int lim = n < 8 ? n : 8;
        StringInfoData buf;
        initStringInfo(&buf);
        appendStringInfo(&buf,
                         "CF_FIND_NULL qs=%p qs_build_seq=%llu needle_relid=%u n_filters=%d filters_ptr=%p",
                         (void *) qs,
                         (unsigned long long) qs->build_seq,
                         (unsigned int) relid,
                         qs->n_filters,
                         (void *) qs->filters);
        for (int i = 0; i < lim; i++)
        {
            TableFilterState *f = &qs->filters[i];
            appendStringInfo(&buf,
                             " f%d(relid=%u,name=%s,allow=%p,rows=%u)",
                             i,
                             (unsigned int) f->relid,
                             f->relname[0] ? f->relname : "<unknown>",
                             (void *) f->allow_bits,
                             f->n_rows);
        }
        elog(NOTICE, "%s", buf.data);
    }
    return NULL;
}

static PolicyQueryState *
cf_build_query_state(EState *estate, const char *query_str)
{
    MemoryContext qctx = estate && estate->es_query_cxt ? estate->es_query_cxt : CurrentMemoryContext;
    MemoryContext oldctx = MemoryContextSwitchTo(qctx);
    if (CurrentMemoryContext != qctx)
        ereport(ERROR,
                (errmsg("custom_filter: query state allocated outside query context"),
                 errdetail("qctx=%p(%s) current=%p(%s)",
                           (void *) qctx, cf_mctx_safe_name(qctx),
                           (void *) CurrentMemoryContext, cf_mctx_safe_name(CurrentMemoryContext))));

    PolicyQueryState *qs = (PolicyQueryState *) palloc0(sizeof(PolicyQueryState));
    qs->build_seq = ++cf_query_build_seq;
    qs->qctx = qctx;
    CF_RESCAN_LOG("event=query_state_begin pid=%d build_seq=%llu qs=%p qctx=%p",
                  (int) getpid(),
                  (unsigned long long) qs->build_seq,
                  (void *) qs,
                  (void *) qctx);
    bool profile_trace = (cf_trace_enabled());
    qs->rss_kb_before_eval = -1;
    qs->rss_kb_after_eval = -1;
    qs->rss_kb_after_load = -1;
    qs->rss_kb_after_engine = -1;
    qs->rss_kb_after_ctid = -1;
    qs->rss_kb_end = -1;
    qs->peak_rss_kb_end = -1;

    const char *policy_path = cf_policy_path && cf_policy_path[0] ? cf_policy_path : NULL;
    if (!policy_path)
        ereport(ERROR, (errmsg("custom_filter.policy_path is not set")));
    if (cf_contract_enabled())
        cf_log_policy_identity(policy_path);

    if (cf_debug_ids && estate && estate->es_plannedstmt)
    {
        int spcnt = estate->es_plannedstmt->subplans ? list_length(estate->es_plannedstmt->subplans) : 0;
        CF_DEBUG_SUBPLAN_LOG("pid=%d build_seq=%llu pstmt=%p subplans_count=%d walk_subplans=1",
                             (int) getpid(),
                             (unsigned long long) qs->build_seq,
                             (void *) estate->es_plannedstmt,
                             spcnt);
        if (estate->es_plannedstmt->subplans)
        {
            int idx = 0;
            ListCell *lc;
            foreach (lc, estate->es_plannedstmt->subplans)
            {
                Plan *sp = (Plan *) lfirst(lc);
                CF_DEBUG_SUBPLAN_LOG("pid=%d build_seq=%llu subplan_idx=%d walk=1 tag=%d ptr=%p",
                                     (int) getpid(),
                                     (unsigned long long) qs->build_seq,
                                     idx++,
                                     sp ? (int) nodeTag(sp) : -1,
                                     (void *) sp);
            }
        }
    }

    int main_rel_count = 0;
    int total_rel_count = 0;
    cf_collect_scanned_tables(estate, qctx,
                              &qs->scanned_tables, &qs->n_scanned_tables,
                              &qs->wrapped_tables, &qs->n_wrapped_tables,
                              &main_rel_count, &total_rel_count);
    if (cf_debug_ids)
    {
        CF_DEBUG_SUBPLAN_LOG("pid=%d build_seq=%llu scans_main=%d scans_total=%d scans_subplans_added=%d",
                             (int) getpid(),
                             (unsigned long long) qs->build_seq,
                             main_rel_count,
                             total_rel_count,
                             (total_rel_count >= main_rel_count) ? (total_rel_count - main_rel_count) : 0);
    }

    instr_time eval_start, eval_end;
    if (profile_trace)
        qs->rss_kb_before_eval = cf_rss_kb_now();
    INSTR_TIME_SET_CURRENT(eval_start);
    qs->policy_eval_calls++;
    PolicyEvalResultC *eval_res = evaluate_policies_scanned(policy_path,
                                                            qs->scanned_tables,
                                                            qs->n_scanned_tables);
    INSTR_TIME_SET_CURRENT(eval_end);
    qs->eval_ms = INSTR_TIME_GET_MILLISEC(eval_end) - INSTR_TIME_GET_MILLISEC(eval_start);
    if (profile_trace)
        qs->rss_kb_after_eval = cf_rss_kb_now();
    if (!eval_res)
    {
        MemoryContextSwitchTo(oldctx);
        return qs;
    }

    qs->n_needed_files = eval_res->needed_count;
    if (qs->n_needed_files > 0)
    {
        qs->needed_files = (char **) palloc0(sizeof(char *) * qs->n_needed_files);
        for (int i = 0; i < qs->n_needed_files; i++)
            qs->needed_files[i] = pstrdup(eval_res->needed_files[i]);
        StringInfoData nf;
        initStringInfo(&nf);
        appendStringInfoChar(&nf, '[');
        for (int i = 0; i < qs->n_needed_files; i++)
        {
            if (i > 0)
                appendStringInfoString(&nf, ", ");
            appendStringInfoString(&nf, qs->needed_files[i]);
        }
        appendStringInfoChar(&nf, ']');
        CF_TRACE_LOG( "custom_filter: needed_files = %s", nf.data);
    }
    qs->n_policy_targets = eval_res->target_count;
    if (qs->n_policy_targets > 0)
    {
        qs->policy_targets = (char **) palloc0(sizeof(char *) * qs->n_policy_targets);
        for (int i = 0; i < qs->n_policy_targets; i++)
            qs->policy_targets[i] = pstrdup(eval_res->target_tables[i]);
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < qs->n_policy_targets; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, qs->policy_targets[i]);
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "custom_filter: policy_targets = %s", st.data);
    }
    if (eval_res->target_count > 0)
    {
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < eval_res->target_count; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, eval_res->target_tables[i] ? eval_res->target_tables[i] : "<null>");
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "policy_eval: target_tables=%s", st.data);
        for (int i = 0; i < eval_res->target_count; i++)
        {
            CF_TRACE_LOG( "policy_eval: combined_ast target=%s ast=%s",
                 eval_res->target_tables[i] ? eval_res->target_tables[i] : "<null>",
                 (eval_res->target_asts && eval_res->target_asts[i]) ? eval_res->target_asts[i] : "");
        }
    }
    qs->n_closure_tables = eval_res->closure_count;
    if (qs->n_closure_tables > 0)
    {
        qs->closure_tables = (char **) palloc0(sizeof(char *) * qs->n_closure_tables);
        for (int i = 0; i < qs->n_closure_tables; i++)
            qs->closure_tables[i] = pstrdup(eval_res->closure_tables[i]);
    }
    if (cf_contract_enabled() && qs->n_closure_tables > 0)
    {
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < qs->n_closure_tables; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, qs->closure_tables[i]);
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "custom_filter: closure_tables = %s", st.data);
    }
    cf_parse_query_targets(query_str ? query_str : "", qctx,
                           &qs->query_targets, &qs->n_query_targets);
    if (qs->n_query_targets > 0)
    {
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < qs->n_query_targets; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, qs->query_targets[i]);
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "custom_filter: query_targets = %s", st.data);
    }
    if (qs->n_scanned_tables > 0)
    {
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < qs->n_scanned_tables; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, qs->scanned_tables[i]);
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "custom_filter: scanned_tables = %s", st.data);
        for (int i = 0; i < qs->n_scanned_tables; i++)
        {
            const char *tbl = qs->scanned_tables[i];
            bool filtered = cf_table_should_filter(qs, tbl);
            CF_TRACE_LOG( "custom_filter: table=%s filter=%s",
                 tbl ? tbl : "<null>", filtered ? "on" : "off");
            if (cf_contract_enabled() && !filtered)
                CF_TRACE_LOG( "custom_filter: not_wrapping scan table=%s reason=no_policy_target",
                     tbl ? tbl : "<null>");
        }
    }

    if (eval_res && eval_res->target_joinclass_counts &&
        eval_res->target_joinclass_offsets && eval_res->target_joinclass_ids)
    {
        if (cf_contract_enabled())
        {
            for (int i = 0; i < eval_res->target_count; i++)
            {
                int cnt = eval_res->target_joinclass_counts[i];
                int off = eval_res->target_joinclass_offsets[i];
                StringInfoData list;
                initStringInfo(&list);
                for (int j = 0; j < cnt; j++)
                {
                    if (j > 0)
                        appendStringInfoString(&list, ", ");
                    appendStringInfo(&list, "%d", eval_res->target_joinclass_ids[off + j]);
                }
                CF_TRACE_LOG( "custom_filter: target=%s joinclass_count=%d joinclasses=[%s]",
                     (eval_res->target_tables && eval_res->target_tables[i]) ? eval_res->target_tables[i] : "<null>",
                     cnt, list.data);
            }
        }
        for (int i = 0; i < qs->n_scanned_tables; i++)
        {
            const char *tbl = qs->scanned_tables[i];
            if (!tbl || !cf_table_should_filter(qs, tbl))
                continue;
            int idx = cf_eval_target_index(eval_res, tbl);
            if (idx < 0)
                continue;
            int cnt = eval_res->target_joinclass_counts[idx];
            if (cnt > 1)
            {
                int off = eval_res->target_joinclass_offsets[idx];
                StringInfoData list;
                initStringInfo(&list);
                for (int j = 0; j < cnt; j++)
                {
                    if (j > 0)
                        appendStringInfoString(&list, ", ");
                    appendStringInfo(&list, "%d", eval_res->target_joinclass_ids[off + j]);
                }
                if (cf_contract_enabled()) {
                    CF_TRACE_LOG(
                         "custom_filter: multi-join-class policy detected (table=%s join_classes=[%s])",
                         tbl, list.data);
                }
            }
        }
    }

    if (estate && estate->es_plannedstmt && estate->es_plannedstmt->parallelModeNeeded)
    {
        for (int i = 0; i < qs->n_scanned_tables; i++)
        {
            const char *tbl = qs->scanned_tables[i];
            if (tbl && cf_table_should_filter(qs, tbl))
            {
                ereport(ERROR,
                        (errmsg("custom_filter: parallel plans not supported for policy enforcement (table=%s)",
                                tbl),
                         errhint("disable parallelism (max_parallel_workers_per_gather=0)")));
            }
        }
    }

    if (qs->n_wrapped_tables > 0 && cf_contract_enabled())
    {
        StringInfoData st;
        initStringInfo(&st);
        appendStringInfoChar(&st, '[');
        for (int i = 0; i < qs->n_wrapped_tables; i++)
        {
            if (i > 0)
                appendStringInfoString(&st, ", ");
            appendStringInfoString(&st, qs->wrapped_tables[i]);
        }
        appendStringInfoChar(&st, ']');
        CF_TRACE_LOG( "custom_filter: wrapped_tables = %s", st.data);
    }

    if (qs->n_policy_targets > 0 && qs->n_scanned_tables > 0)
    {
        for (int i = 0; i < qs->n_policy_targets; i++)
        {
            const char *tbl = qs->policy_targets[i];
            if (!tbl)
                continue;
            if (!cf_table_scanned(qs, tbl))
                continue;
            Oid nsp = get_namespace_oid("public", true);
            Oid relid = InvalidOid;
            if (OidIsValid(nsp))
                relid = get_relname_relid(tbl, nsp);
            if (!OidIsValid(relid))
                relid = get_relname_relid(tbl, InvalidOid);
            const char *stype = cf_plan_find_scan_type(estate->es_plannedstmt->planTree,
                                                       estate->es_plannedstmt,
                                                       relid);
            if (stype && strcmp(stype, "IndexOnlyScan") == 0)
            {
                ereport(ERROR,
                        (errmsg("custom_filter: IndexOnlyScan unsupported for policy-required table (table=%s scan=%s)",
                                tbl, stype),
                         errhint("disable indexonlyscan or force heap scan")));
            }
            if (cf_table_wrapped(qs, tbl))
                continue;
            ereport(ERROR,
                    (errmsg("custom_filter: policy enforcement required but scan type not wrapped (table=%s scan=%s)",
                            tbl, stype ? stype : "<unknown>"),
                     errhint("disable index/bitmap/tid scans or add wrapper support")));
        }
    }

    if (qs->n_policy_targets == 0 || qs->n_needed_files == 0)
    {
        free_policy_eval_result(eval_res);
        eval_res = NULL;
        goto finalize;
    }

    cf_in_internal_query = true;
    if (SPI_connect() != SPI_OK_CONNECT)
    {
        cf_in_internal_query = false;
        free_policy_eval_result(eval_res);
        MemoryContextSwitchTo(oldctx);
        return qs;
    }

    /*
     * SPI_connect() switches CurrentMemoryContext to SPI Proc.
     * Query-state data must NOT live there; bind-time executor reads it long after
     * SPI calls return. Force all qs-owned allocations into qctx.
     */
    MemoryContextSwitchTo(qctx);
    if (cf_debug_ids)
    {
        CF_DEBUG_QS_LOG("pid=%d build_seq=%llu post_SPI_connect cur_mctx=%p(%s) qctx=%p(%s)",
                        (int) getpid(),
                        (unsigned long long) qs->build_seq,
                        (void *) CurrentMemoryContext,
                        cf_mctx_safe_name(CurrentMemoryContext),
                        (void *) qctx,
                        cf_mctx_safe_name(qctx));
    }

    LoadedArtifact *arts = qs->n_needed_files > 0
                               ? (LoadedArtifact *) palloc0(sizeof(LoadedArtifact) * qs->n_needed_files)
                               : NULL;
    StringInfoData missing;
    initStringInfo(&missing);
    instr_time load_start;
    INSTR_TIME_SET_CURRENT(load_start);

    for (int i = 0; i < qs->n_needed_files; i++)
    {
        arts[i].name = pstrdup(qs->needed_files[i]);
    }

    qs->artifact_load_calls++;
    if (!cf_load_artifacts_batch(qs->needed_files, qs->n_needed_files, qctx, arts, &missing))
    {
        /* SPI calls may have changed CurrentMemoryContext; reset before exits/cleanup. */
        MemoryContextSwitchTo(qctx);
        SPI_finish();
        cf_in_internal_query = false;
        free_policy_eval_result(eval_res);
        MemoryContextSwitchTo(oldctx);
        ereport(ERROR,
                (errmsg("custom_filter: missing artifacts: %s", missing.data)));
    }
    /* Defensive: SPI_execute* can leave us in SPI Proc context. */
    MemoryContextSwitchTo(qctx);

    for (int i = 0; i < qs->n_needed_files; i++)
    {
        if (!arts[i].data)
            continue;
        qs->bytes_artifacts_loaded += arts[i].len;
        if (cf_contract_enabled())
            cf_contract_assert_chunk("artifact_blob", NULL, arts[i].data, qctx);
    }
    instr_time load_end;
    INSTR_TIME_SET_CURRENT(load_end);
    double load_ms = INSTR_TIME_GET_MILLISEC(load_end) - INSTR_TIME_GET_MILLISEC(load_start);
    CF_TRACE_LOG( "custom_filter: artifact_load_ms=%.3f", load_ms);
    qs->artifact_load_ms = load_ms;
    if (profile_trace)
        qs->rss_kb_after_load = cf_rss_kb_now();
    if (cf_contract_enabled()) {
        for (int i = 0; i < qs->n_needed_files; i++) {
            if (arts[i].name && arts[i].data) {
                CF_TRACE_LOG( "custom_filter: artifact %s bytes=%zu",
                     arts[i].name, arts[i].len);
            }
        }
    }

    PolicyArtifactC *policy_arts = qs->n_needed_files > 0
                                       ? (PolicyArtifactC *) palloc0(sizeof(PolicyArtifactC) * qs->n_needed_files)
                                       : NULL;
    int policy_art_count = 0;
    for (int i = 0; i < qs->n_needed_files; i++)
    {
        if (!arts[i].name || !arts[i].data)
            continue;
        policy_arts[policy_art_count].name = arts[i].name;
        policy_arts[policy_art_count].data = (const void *) VARDATA_ANY(arts[i].data);
        policy_arts[policy_art_count].len = (size_t) VARSIZE_ANY_EXHDR(arts[i].data);
        policy_art_count++;
    }

    PolicyRunHandle *run_handle = NULL;
    const PolicyAllowListC *allow_list = NULL;
    if (policy_art_count > 0 && eval_res->target_count > 0)
    {
        PolicyEngineInputC in;
        in.target_count = eval_res->target_count;
        in.target_tables = eval_res->target_tables;
        in.target_asts = eval_res->target_asts;
        in.target_perm_asts = eval_res->target_perm_asts;
        in.target_rest_asts = eval_res->target_rest_asts;
        in.atom_count = eval_res->atom_count;
        in.atoms = eval_res->atoms;
        CF_TRACE_LOG( "custom_filter: calling policy_run once target_count=%d atom_count=%d",
             in.target_count, in.atom_count);
        MemoryContext old_policy_ctx = MemoryContextSwitchTo(qctx);
        qs->policy_run_calls++;
        run_handle = policy_run(policy_arts, policy_art_count, &in);
        MemoryContextSwitchTo(old_policy_ctx);
        if (!run_handle)
            ereport(ERROR,
                    (errmsg("custom_filter: policy_run failed (target_count=%d atom_count=%d)",
                            in.target_count, in.atom_count)));
        const PolicyRunProfileC *pp = policy_run_profile(run_handle);
        if (pp) {
            qs->artifact_parse_ms += pp->artifact_parse_ms;
            qs->atoms_ms += pp->atoms_ms;
            qs->presence_ms += pp->presence_ms;
            qs->project_ms += pp->project_ms;
            qs->stamp_ms += pp->stamp_ms;
            qs->bin_ms += pp->bin_ms;
            qs->local_sat_ms += pp->local_sat_ms;
            qs->fill_ms += pp->fill_ms;
            qs->prop_ms += pp->prop_ms;
            qs->prop_iters += pp->prop_iters;
            qs->decode_ms += pp->decode_ms;
            qs->policy_total_ms += pp->policy_total_ms;
        }
        allow_list = policy_run_allow_list(run_handle);
        if (!allow_list)
            ereport(ERROR,
                    (errmsg("custom_filter: policy_run returned NULL allow list")));
        if (profile_trace)
            qs->rss_kb_after_engine = cf_rss_kb_now();
        for (int i = 0; i < allow_list->count; i++)
        {
            const PolicyTableAllowC *it = &allow_list->items[i];
            const char *tname = (it && it->table) ? it->table : "<null>";
            uint32 rows = it ? it->n_rows : 0;
            uint32 cnt = 0;
            if (it && it->allow_bits)
                cnt = cf_popcount_allow(it->allow_bits, rows);
            CF_TRACE_LOG( "custom_filter: allow_%s count=%u/%u", tname, cnt, rows);
        }
    }

    int n_filters = 0;
    for (int i = 0; i < qs->n_needed_files; i++)
    {
        if (arts[i].name && cf_has_suffix(arts[i].name, "_ctid"))
        {
            size_t nlen = strlen(arts[i].name);
            if (nlen <= 5) continue;
            char tblname[NAMEDATALEN];
            size_t tlen = nlen - 5;
            if (tlen >= sizeof(tblname))
                tlen = sizeof(tblname) - 1;
            memcpy(tblname, arts[i].name, tlen);
            tblname[tlen] = '\0';
            if (cf_table_should_filter(qs, tblname))
                n_filters++;
        }
    }

    /*
     * Ensure query-state allocations are always under qctx, even if SPI internals
     * changed CurrentMemoryContext during SPI_execute* calls.
     */
    MemoryContextSwitchTo(qctx);

    qs->n_filters = n_filters;
    if (n_filters > 0)
    {
        /*
         * Regression guard: filters must be allocated under qctx (or its child),
         * never in SPI Proc context.
         */
        if (CurrentMemoryContext != qctx)
            ereport(ERROR,
                    (errmsg("custom_filter: qs->filters allocated outside query context"),
                     errdetail("qctx=%p(%s) current=%p(%s)",
                               (void *) qctx, cf_mctx_safe_name(qctx),
                               (void *) CurrentMemoryContext, cf_mctx_safe_name(CurrentMemoryContext))));
        qs->filters_alloc_mctx = CurrentMemoryContext;
        if (cf_debug_ids)
        {
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu filters_alloc_site cur_mctx=%p(%s) qctx=%p(%s)",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            (void *) CurrentMemoryContext,
                            cf_mctx_safe_name(CurrentMemoryContext),
                            (void *) qctx,
                            cf_mctx_safe_name(qctx));
        }
        qs->filters = (TableFilterState *) palloc0(sizeof(TableFilterState) * n_filters);
    }

    int fidx = 0;
    for (int i = 0; i < qs->n_needed_files; i++)
    {
        if (!arts[i].name)
            continue;
        size_t nlen = strlen(arts[i].name);
        if (nlen <= 5 || !cf_has_suffix(arts[i].name, "_ctid"))
            continue;

        char tblname[NAMEDATALEN];
        size_t tlen = nlen - 5;
        if (tlen >= sizeof(tblname))
            tlen = sizeof(tblname) - 1;
        memcpy(tblname, arts[i].name, tlen);
        tblname[tlen] = '\0';

        if (!cf_table_should_filter(qs, tblname))
            continue;

        TableFilterState *tf = &qs->filters[fidx++];
        qs->allow_build_calls++;
        memset(tf, 0, sizeof(TableFilterState));
        strlcpy(tf->relname, tblname, sizeof(tf->relname));
        Oid nsp = get_namespace_oid("public", true);
        if (OidIsValid(nsp))
            tf->relid = get_relname_relid(tblname, nsp);
        if (!OidIsValid(tf->relid))
            tf->relid = get_relname_relid(tblname, InvalidOid);

        if (!arts[i].data)
            ereport(ERROR,
                    (errmsg("custom_filter[missing_artifact]: NULL _ctid payload for %s",
                            tblname)));
        size_t ctid_payload_bytes = (size_t) VARSIZE_ANY_EXHDR(arts[i].data);
        if ((ctid_payload_bytes % sizeof(uint32)) != 0)
            ereport(ERROR,
                    (errmsg("custom_filter[missing_artifact]: malformed _ctid payload for %s (bytes=%zu not multiple of %zu)",
                            tblname, ctid_payload_bytes, sizeof(uint32))));
        size_t ctid_words = ctid_payload_bytes / sizeof(uint32);
        if ((ctid_words & 1u) != 0)
            ereport(ERROR,
                    (errmsg("custom_filter[missing_artifact]: malformed _ctid payload for %s (len=%zu not even)",
                            tblname, ctid_words)));
        if (ctid_words > (size_t) UINT32_MAX)
            ereport(ERROR,
                    (errmsg("custom_filter[missing_artifact]: _ctid payload too large for %s (len=%zu)",
                            tblname, ctid_words)));

        tf->ctid_pairs = (uint32 *) VARDATA_ANY(arts[i].data);
        tf->ctid_pairs_len = (uint32) ctid_words;
        if ((tf->ctid_pairs_len & 1u) != 0)
            ereport(ERROR,
                    (errmsg("custom_filter[missing_artifact]: malformed _ctid payload for %s (len=%u not even)",
                            tblname, tf->ctid_pairs_len)));
        tf->n_rows = tf->ctid_pairs_len / 2;
        tf->ctid_bytes = ctid_payload_bytes;
        tf->allow_nbytes = (size_t) ((tf->n_rows + 7) / 8);
        if (cf_contract_enabled())
            cf_contract_assert_chunk("ctid_blob", tblname, arts[i].data, qctx);

        bool found_allow = false;
        uint32 found_allow_rows = 0;
        uint8 *found_allow_bits = NULL;
        int allow_count = allow_list ? allow_list->count : 0;
        for (int j = 0; j < allow_count; j++)
        {
            if (strcmp(allow_list->items[j].table, tblname) == 0)
            {
                found_allow_bits = allow_list->items[j].allow_bits;
                found_allow_rows = allow_list->items[j].n_rows;
                found_allow = true;
                break;
            }
        }
        if (!found_allow)
        {
            size_t bytes = tf->allow_nbytes;
            MemoryContext old_allow_ctx = MemoryContextSwitchTo(qctx);
            tf->allow_bits = (uint8 *) palloc0(bytes + CF_ALLOW_CANARY_BYTES);
            MemoryContextSwitchTo(old_allow_ctx);
            memset(tf->allow_bits, 0xFF, bytes);
            memcpy(tf->allow_bits + bytes, cf_allow_canary, CF_ALLOW_CANARY_BYTES);
            tf->allow_popcount = tf->n_rows;
            if (cf_contract_enabled() && eval_res && eval_res->target_joinclass_counts)
            {
                int tidx = cf_eval_target_index(eval_res, tblname);
                if (tidx >= 0 && eval_res->target_joinclass_counts[tidx] > 1)
                {
                    CF_TRACE_LOG( "custom_filter: multi-join contract mode, skip allow bits for %s (allow-all)",
                         tblname);
                }
                else
                {
                    elog(WARNING, "custom_filter: allow bits not found for %s, default allow-all", tblname);
                }
            }
            else
            {
                elog(WARNING, "custom_filter: allow bits not found for %s, default allow-all", tblname);
            }
        }
        else
        {
            if (!found_allow_bits)
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: allow_bits pointer missing for %s",
                                tblname)));
            if (found_allow_rows != tf->n_rows)
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: allow rows mismatch for %s allow_rows=%u ctid_rows=%u",
                                tblname, found_allow_rows, tf->n_rows)));
            /* Defensive copy of allow_bits into query context to avoid aliasing. */
            size_t bytes = tf->allow_nbytes;
            MemoryContext old_allow_ctx = MemoryContextSwitchTo(qctx);
            uint8 *copy_bits = (uint8 *) palloc0(bytes + CF_ALLOW_CANARY_BYTES);
            MemoryContextSwitchTo(old_allow_ctx);
            memcpy(copy_bits, found_allow_bits, bytes);
            memcpy(copy_bits + bytes, cf_allow_canary, CF_ALLOW_CANARY_BYTES);
            tf->allow_bits = copy_bits;
            uint32 allow_cnt = 0;
            for (uint32 r = 0; r < tf->n_rows; r++)
            {
                size_t byte_idx = (size_t) (r >> 3);
                if (byte_idx >= tf->allow_nbytes)
                    ereport(ERROR,
                            (errmsg("custom_filter[engine_error]: allow_bits length mismatch rel=%s rid=%u bytes=%zu",
                                    tf->relname, r, tf->allow_nbytes)));
                if (tf->allow_bits[byte_idx] & (uint8)(1u << (r & 7)))
                    allow_cnt++;
            }
            tf->allow_popcount = allow_cnt;
            CF_TRACE_LOG( "custom_filter: allow_%s popcount=%u/%u", tblname, allow_cnt, tf->n_rows);
        }

        instr_time blk_start, blk_end;
        INSTR_TIME_SET_CURRENT(blk_start);
        qs->blk_index_build_calls++;
        cf_build_blk_index(tf, qctx);
        if (tf->n_rows > 0 && (!tf->blk_index || tf->n_blocks == 0))
            ereport(ERROR,
                    (errmsg("custom_filter[engine_error]: failed to build ctid index for rel=%s rows=%u",
                            tf->relname, tf->n_rows)));
        if (cf_contract_enabled()) {
            cf_contract_assert_chunk("allow_bits", tf->relname, tf->allow_bits, qctx);
            if (tf->blk_index)
                cf_contract_assert_chunk("blk_index", tf->relname, tf->blk_index, qctx);
        }
        INSTR_TIME_SET_CURRENT(blk_end);
        double blk_ms = INSTR_TIME_GET_MILLISEC(blk_end) - INSTR_TIME_GET_MILLISEC(blk_start);
        CF_TRACE_LOG( "custom_filter: ctid_index_ms=%.3f rel=%s", blk_ms, tf->relname);
        qs->ctid_map_ms += blk_ms;
        if (cf_trace_enabled() && tf->ctid_pairs)
        {
            for (uint32 r = 0; r < tf->n_rows && r < 100; r++) {
                uint32 blk = tf->ctid_pairs[2 * r];
                uint32 off = tf->ctid_pairs[2 * r + 1];
                int32 rid2 = cf_ctid_to_rid(tf, blk, off);
                if (rid2 != (int32)r) {
                    CF_TRACE_LOG( "custom_filter: ctid_map_mismatch rel=%s r=%u -> %d (blk=%u off=%u)",
                         tf->relname, r, rid2, blk, off);
                    break;
                }
            }
        }

        size_t allow_bytes = tf->allow_nbytes;
        qs->bytes_allow += allow_bytes;
        qs->bytes_ctid += tf->ctid_bytes;
        qs->bytes_blk_index += tf->blk_index_bytes;

        if (tf->ctid_pairs && tf->ctid_pairs_len >= 10)
        {
            CF_TRACE_LOG( "custom_filter: %s_ctid head [%u,%u %u,%u %u,%u %u,%u %u,%u]",
                 tf->relname,
                 tf->ctid_pairs[0], tf->ctid_pairs[1],
                 tf->ctid_pairs[2], tf->ctid_pairs[3],
                 tf->ctid_pairs[4], tf->ctid_pairs[5],
                 tf->ctid_pairs[6], tf->ctid_pairs[7],
                 tf->ctid_pairs[8], tf->ctid_pairs[9]);
        }

        CF_TRACE_LOG( "custom_filter: retain rel=%s allow=%zuB ctid=%zuB blk_index=%zuB",
             tf->relname, allow_bytes,
             tf->ctid_bytes,
             tf->blk_index_bytes);

        CF_RESCAN_LOG("event=filter_built pid=%d build_seq=%llu rel=%s relid=%u rows=%u allow_bytes=%zu blk_index_bytes=%zu",
                      (int) getpid(),
                      (unsigned long long) qs->build_seq,
                      tf->relname,
                      tf->relid,
                      tf->n_rows,
                      allow_bytes,
                      tf->blk_index_bytes);

        if (!cf_trace_enabled() && arts[i].owned && arts[i].data)
        {
            pfree(arts[i].data);
            arts[i].data = NULL;
            arts[i].len = 0;
            arts[i].owned = false;
            tf->ctid_pairs = NULL;
            tf->ctid_pairs_len = 0;
        }
    }

    qs->n_filters = fidx;
    if (profile_trace)
        qs->rss_kb_after_ctid = cf_rss_kb_now();

    for (int i = 0; i < qs->n_needed_files; i++)
    {
        if (!arts[i].name || !arts[i].data)
            continue;
        if (!arts[i].owned)
            continue;
        size_t nlen = strlen(arts[i].name);
        if (nlen > 5 && cf_has_suffix(arts[i].name, "_ctid"))
            continue;
        pfree(arts[i].data);
        arts[i].data = NULL;
        arts[i].len = 0;
        arts[i].owned = false;
    }

    CF_TRACE_LOG( "custom_filter: retain total allow=%zuB ctid=%zuB blk_index=%zuB",
         qs->bytes_allow, qs->bytes_ctid, qs->bytes_blk_index);
    if (cf_contract_enabled() && qs->n_filters > 0)
    {
        for (int i = 0; i < qs->n_filters; i++)
        {
            TableFilterState *tf = &qs->filters[i];
            if (tf->allow_bits)
            {
                uint32 cnt = cf_popcount_allow(tf->allow_bits, tf->n_rows);
                size_t bytes = tf->allow_nbytes;
                bool canary_ok = (memcmp(tf->allow_bits + bytes,
                                         cf_allow_canary,
                                         CF_ALLOW_CANARY_BYTES) == 0);
                MemoryContext mctx = GetMemoryChunkContext(tf->allow_bits);
                CF_TRACE_LOG(
                     "custom_filter: allow_bits pre_exec rel=%s count=%u/%u ptr=%p canary=%s mctx=%p qctx=%p qs=%p",
                     tf->relname, cnt, tf->n_rows, (void *) tf->allow_bits,
                     canary_ok ? "ok" : "BAD", (void *) mctx,
                     (void *) qctx, (void *) qs);
            }
        }
    }

    /*
     * Guard baseline must be set while qs->filters memory is still in its
     * allocated state. If filters were accidentally allocated under SPI Proc
     * context, SPI_finish() can reset that context and mutate/free qs->filters.
     */
    if (cf_debug_ids)
        cf_filters_guard_set(qs, "pre_SPI_finish");

    SPI_finish();
    if (cf_debug_ids)
        cf_filters_guard_check(qs, "post_SPI_finish");
    cf_in_internal_query = false;
    free_policy_eval_result(eval_res);

finalize:
    qs->ready = true;
    if (qctx)
    {
        MemoryContextCallback *cb = (MemoryContextCallback *) MemoryContextAlloc(qctx, sizeof(MemoryContextCallback));
        cb->func = cf_query_state_reset_callback;
        cb->arg = qs;
        MemoryContextRegisterResetCallback(qctx, cb);
    }
    MemoryContextSwitchTo(oldctx);
    if (cf_debug_ids)
    {
        CF_DEBUG_QS_LOG("pid=%d build_seq=%llu qs=%p ready=%d n_filters=%d n_policy_targets=%d n_scanned_tables=%d n_wrapped_tables=%d",
                        (int) getpid(),
                        (unsigned long long) qs->build_seq,
                        (void *) qs,
                        qs->ready ? 1 : 0,
                        qs->n_filters,
                        qs->n_policy_targets,
                        qs->n_scanned_tables,
                        qs->n_wrapped_tables);
        for (int i = 0; i < qs->n_policy_targets; i++)
        {
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu target[%d]=%s",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            i,
                            (qs->policy_targets && qs->policy_targets[i]) ? qs->policy_targets[i] : "<null>");
        }
        for (int i = 0; i < qs->n_scanned_tables; i++)
        {
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu scanned[%d]=%s",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            i,
                            (qs->scanned_tables && qs->scanned_tables[i]) ? qs->scanned_tables[i] : "<null>");
        }
        for (int i = 0; i < qs->n_filters; i++)
        {
            TableFilterState *tf = &qs->filters[i];
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu filter[%d] key_relid=%u rel=%s allow_bits=%p allow_nbytes=%zu blk_index=%p n_blocks=%u ctid_pairs=%p ctid_pairs_len=%u n_rows=%u",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            i,
                            tf->relid,
                            tf->relname[0] ? tf->relname : "<unknown>",
                            (void *) tf->allow_bits,
                            tf->allow_nbytes,
                            (void *) tf->blk_index,
                            tf->n_blocks,
                            (void *) tf->ctid_pairs,
                            tf->ctid_pairs_len,
                            tf->n_rows);
        }

        /* Memory context ownership snapshot (safe: chunk-start pointers only). */
        MemoryContext qs_mctx = GetMemoryChunkContext(qs);
        CF_DEBUG_QS_LOG("pid=%d build_seq=%llu memctx qctx=%p(%s) qs=%p qs_mctx=%p(%s) filters_ptr=%p filters_alloc_mctx=%p(%s) cur_mctx=%p(%s)",
                        (int) getpid(),
                        (unsigned long long) qs->build_seq,
                        (void *) qctx,
                        cf_mctx_safe_name(qctx),
                        (void *) qs,
                        (void *) qs_mctx,
                        cf_mctx_safe_name(qs_mctx),
                        (void *) qs->filters,
                        (void *) qs->filters_alloc_mctx,
                        cf_mctx_safe_name(qs->filters_alloc_mctx),
                        (void *) CurrentMemoryContext,
                        cf_mctx_safe_name(CurrentMemoryContext));
        for (int i = 0; i < qs->n_filters; i++)
        {
            TableFilterState *tf = &qs->filters[i];
            MemoryContext allow_mctx = tf->allow_bits ? GetMemoryChunkContext(tf->allow_bits) : NULL;
            MemoryContext blk_mctx = tf->blk_index ? GetMemoryChunkContext(tf->blk_index) : NULL;
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu memctx rel=%s relid=%u allow=%p mctx=%p(%s) blk=%p mctx=%p(%s)",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            tf->relname[0] ? tf->relname : "<unknown>",
                            (unsigned int) tf->relid,
                            (void *) tf->allow_bits,
                            (void *) allow_mctx,
                            cf_mctx_safe_name(allow_mctx),
                            (void *) tf->blk_index,
                            (void *) blk_mctx,
                            cf_mctx_safe_name(blk_mctx));
        }
    }
    CF_RESCAN_LOG("event=query_state_ready pid=%d build_seq=%llu eval_calls=%llu load_calls=%llu policy_run_calls=%llu allow_build_calls=%llu blk_index_build_calls=%llu n_filters=%d",
                  (int) getpid(),
                  (unsigned long long) qs->build_seq,
                  (unsigned long long) qs->policy_eval_calls,
                  (unsigned long long) qs->artifact_load_calls,
                  (unsigned long long) qs->policy_run_calls,
                  (unsigned long long) qs->allow_build_calls,
                  (unsigned long long) qs->blk_index_build_calls,
                  qs->n_filters);
    return qs;
}

static TupleTableSlot *
cf_store_slot(CustomScanState *node, TupleTableSlot *slot)
{
    if (!node || !node->ss.ss_ScanTupleSlot || slot == node->ss.ss_ScanTupleSlot)
        return slot;
    return ExecCopySlot(node->ss.ss_ScanTupleSlot, slot);
}

static bool
cf_slot_get_ctid(TupleTableSlot *slot, ItemPointerData *out, CfTidSource *src)
{
    if (src)
        *src = CF_TID_NONE;
    if (ItemPointerIsValid(&slot->tts_tid))
    {
        *out = slot->tts_tid;
        if (src) *src = CF_TID_TTS;
        return true;
    }

    if (slot->tts_ops && slot->tts_ops->getsysattr)
    {
        bool isnull = false;
        Datum d = slot_getsysattr(slot, SelfItemPointerAttributeNumber, &isnull);
        if (!isnull)
        {
            ItemPointer ip = DatumGetItemPointer(d);
            if (ItemPointerIsValid(ip))
            {
                *out = *ip;
                if (src) *src = CF_TID_SYSATTR;
                return true;
            }
        }
    }

    bool should_free = false;
    HeapTuple htup = ExecFetchSlotHeapTuple(slot, false, &should_free);
    if (htup)
    {
        *out = htup->t_self;
        if (should_free)
            heap_freetuple(htup);
        if (src) *src = CF_TID_HEAPTUPLE;
        return ItemPointerIsValid(out);
    }

    return false;
}

static TupleTableSlot *
cf_scan_slot(PlanState *child, TupleTableSlot *fallback)
{
    if (!child)
        return fallback;

    switch (nodeTag(child))
    {
        case T_SeqScanState:
        case T_SampleScanState:
        case T_IndexScanState:
        case T_IndexOnlyScanState:
        case T_BitmapHeapScanState:
        case T_TidScanState:
        case T_TidRangeScanState:
        case T_ForeignScanState:
        case T_FunctionScanState:
        case T_TableFuncScanState:
        case T_ValuesScanState:
        case T_CteScanState:
        case T_WorkTableScanState:
            {
                ScanState *ss = (ScanState *) child;
                if (ss->ss_ScanTupleSlot)
                    return ss->ss_ScanTupleSlot;
            }
            break;
        default:
            break;
    }

    return fallback;
}

static const char *
cf_tid_source_name(CfTidSource src)
{
    switch (src)
    {
        case CF_TID_TTS: return "tts_tid";
        case CF_TID_SYSATTR: return "sysattr";
        case CF_TID_MAT_TTS: return "materialized_tts_tid";
        case CF_TID_HEAPTUPLE: return "heaptuple";
        default: return "none";
    }
}

typedef struct ScannedCtx
{
    PlannedStmt *pstmt;
    List *relids;
    List *wrapped_relids;
} ScannedCtx;

static bool
cf_plan_scan_relid(Plan *plan, Index *out_relid)
{
    if (!plan || !out_relid)
        return false;
    switch (nodeTag(plan))
    {
        case T_SeqScan:
        case T_SampleScan:
        case T_IndexScan:
        case T_IndexOnlyScan:
        case T_BitmapHeapScan:
        case T_TidScan:
        case T_TidRangeScan:
        case T_ForeignScan:
        case T_FunctionScan:
        case T_TableFuncScan:
        case T_ValuesScan:
        case T_CteScan:
        case T_WorkTableScan:
            *out_relid = ((Scan *) plan)->scanrelid;
            return true;
        default:
            break;
    }
    return false;
}

static bool
cf_relid_is_relation(PlannedStmt *pstmt, Index scanrelid, Oid *out_relid)
{
    if (!pstmt || scanrelid <= 0)
        return false;
    RangeTblEntry *rte = rt_fetch(scanrelid, pstmt->rtable);
    if (!rte || rte->rtekind != RTE_RELATION)
        return false;
    if (out_relid)
        *out_relid = rte->relid;
    return true;
}

static void
cf_plan_walk(Plan *plan, ScannedCtx *ctx)
{
    if (!plan)
        return;

    if (IsA(plan, CustomScan))
    {
        CustomScan *cs = (CustomScan *) plan;
        if (cs->scan.scanrelid > 0 && ctx->pstmt)
        {
            Oid relid = InvalidOid;
            if (cf_relid_is_relation(ctx->pstmt, cs->scan.scanrelid, &relid))
            {
                if (!list_member_oid(ctx->relids, relid))
                    ctx->relids = lappend_oid(ctx->relids, relid);
                if (!list_member_oid(ctx->wrapped_relids, relid))
                    ctx->wrapped_relids = lappend_oid(ctx->wrapped_relids, relid);
            }
        }
        if (cs->custom_plans)
        {
            ListCell *lc;
            foreach (lc, cs->custom_plans)
                cf_plan_walk((Plan *) lfirst(lc), ctx);
        }
    }

    {
        Index scanrelid = 0;
        if (cf_plan_scan_relid(plan, &scanrelid) && ctx->pstmt)
        {
            Oid relid = InvalidOid;
            if (cf_relid_is_relation(ctx->pstmt, scanrelid, &relid))
            {
                if (!list_member_oid(ctx->relids, relid))
                    ctx->relids = lappend_oid(ctx->relids, relid);
            }
        }
    }

    if (plan->lefttree)
        cf_plan_walk(plan->lefttree, ctx);
    if (plan->righttree)
        cf_plan_walk(plan->righttree, ctx);

    switch (nodeTag(plan))
    {
        case T_Append:
            {
                Append *a = (Append *) plan;
                ListCell *lc;
                foreach (lc, a->appendplans)
                    cf_plan_walk((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_MergeAppend:
            {
                MergeAppend *ma = (MergeAppend *) plan;
                ListCell *lc;
                foreach (lc, ma->mergeplans)
                    cf_plan_walk((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_BitmapAnd:
            {
                BitmapAnd *ba = (BitmapAnd *) plan;
                ListCell *lc;
                foreach (lc, ba->bitmapplans)
                    cf_plan_walk((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_BitmapOr:
            {
                BitmapOr *bo = (BitmapOr *) plan;
                ListCell *lc;
                foreach (lc, bo->bitmapplans)
                    cf_plan_walk((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_SubqueryScan:
            {
                SubqueryScan *sq = (SubqueryScan *) plan;
                cf_plan_walk(sq->subplan, ctx);
            }
            break;
        case T_ModifyTable:
            break;
        default:
            break;
    }
}

static void
cf_collect_scanned_tables(EState *estate, MemoryContext mcxt,
                          char ***out_names, int *out_count,
                          char ***out_wrapped, int *out_wrapped_count,
                          int *out_main_rel_count, int *out_total_rel_count)
{
    if (!estate || !estate->es_plannedstmt)
    {
        *out_names = NULL;
        *out_count = 0;
        if (out_wrapped)
            *out_wrapped = NULL;
        if (out_wrapped_count)
            *out_wrapped_count = 0;
        if (out_main_rel_count)
            *out_main_rel_count = 0;
        if (out_total_rel_count)
            *out_total_rel_count = 0;
        return;
    }
    ScannedCtx ctx;
    ctx.pstmt = estate->es_plannedstmt;
    ctx.relids = NIL;
    ctx.wrapped_relids = NIL;
    cf_plan_walk(estate->es_plannedstmt->planTree, &ctx);
    int main_rel_count = list_length(ctx.relids);
    /*
     * Collect base relations that appear only inside subplans (CTEs/initplans/
     * scalar subqueries). These scans are not reachable from planTree via
     * SubqueryScan::subplan, so we must also walk plannedstmt->subplans.
     *
     * This matters for correctness on TPC-H q15 (WITH/CTE) and queries with
     * initplans that scan protected tables.
     */
    if (estate->es_plannedstmt->subplans)
    {
        ListCell *lc;
        foreach (lc, estate->es_plannedstmt->subplans)
            cf_plan_walk((Plan *) lfirst(lc), &ctx);
    }

    int count = list_length(ctx.relids);
    if (out_main_rel_count)
        *out_main_rel_count = main_rel_count;
    if (out_total_rel_count)
        *out_total_rel_count = count;
    if (count == 0)
    {
        *out_names = NULL;
        *out_count = 0;
        if (out_wrapped)
            *out_wrapped = NULL;
        if (out_wrapped_count)
            *out_wrapped_count = 0;
        if (out_main_rel_count)
            *out_main_rel_count = main_rel_count;
        if (out_total_rel_count)
            *out_total_rel_count = 0;
        return;
    }

    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    char **names = (char **) palloc0(sizeof(char *) * count);
    int idx = 0;
    ListCell *lc;
    foreach (lc, ctx.relids)
    {
        Oid relid = lfirst_oid(lc);
        const char *rn = get_rel_name(relid);
        if (rn)
            names[idx++] = pstrdup(rn);
    }
    MemoryContextSwitchTo(oldctx);

    *out_names = names;
    *out_count = idx;

    if (out_wrapped && out_wrapped_count)
    {
        int wcount = list_length(ctx.wrapped_relids);
        if (wcount > 0)
        {
            MemoryContext oldctx2 = MemoryContextSwitchTo(mcxt);
            char **wnames = (char **) palloc0(sizeof(char *) * wcount);
            int widx = 0;
            ListCell *wc;
            foreach (wc, ctx.wrapped_relids)
            {
                Oid relid = lfirst_oid(wc);
                const char *rn = get_rel_name(relid);
                if (rn)
                    wnames[widx++] = pstrdup(rn);
            }
            MemoryContextSwitchTo(oldctx2);
            *out_wrapped = wnames;
            *out_wrapped_count = widx;
        }
        else
        {
            *out_wrapped = NULL;
            *out_wrapped_count = 0;
        }
    }
}

static bool
cf_table_in_list(const char *name, char **list, int count)
{
    if (!name || !list || count <= 0)
        return false;
    for (int i = 0; i < count; i++)
    {
        if (list[i] && strcmp(list[i], name) == 0)
            return true;
    }
    return false;
}

static int
cf_eval_target_index(const PolicyEvalResultC *res, const char *name)
{
    if (!res || !name || !res->target_tables || res->target_count <= 0)
        return -1;
    for (int i = 0; i < res->target_count; i++) {
        if (res->target_tables[i] && strcmp(res->target_tables[i], name) == 0)
            return i;
    }
    return -1;
}

static void
cf_parse_query_targets(const char *query_str, MemoryContext mcxt,
                       char ***out_tables, int *out_count)
{
    *out_tables = NULL;
    *out_count = 0;
    if (!query_str)
        return;

    const char *s = query_str;
    size_t len = strlen(s);
    size_t i = 0;
    while (i + 3 < len)
    {
        if ((i == 0 || !isalnum((unsigned char)s[i - 1])) &&
            tolower((unsigned char)s[i]) == 'f' &&
            tolower((unsigned char)s[i + 1]) == 'r' &&
            tolower((unsigned char)s[i + 2]) == 'o' &&
            tolower((unsigned char)s[i + 3]) == 'm' &&
            (i + 4 == len || !isalnum((unsigned char)s[i + 4])))
        {
            i += 4;
            break;
        }
        i++;
    }
    if (i >= len)
        return;

    while (i < len && isspace((unsigned char)s[i]))
        i++;
    if (i >= len)
        return;

    size_t start = i;
    while (i < len && (isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '.'))
        i++;
    if (i <= start)
        return;

    size_t toklen = i - start;
    char *tok = (char *) palloc(toklen + 1);
    for (size_t j = 0; j < toklen; j++)
        tok[j] = (char) tolower((unsigned char) s[start + j]);
    tok[toklen] = '\0';
    char *dot = strrchr(tok, '.');
    const char *tbl = dot ? dot + 1 : tok;

    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    char **tables = (char **) palloc0(sizeof(char *));
    tables[0] = pstrdup(tbl);
    MemoryContextSwitchTo(oldctx);

    *out_tables = tables;
    *out_count = 1;
}

static const char *
cf_plan_find_scan_type(Plan *plan, PlannedStmt *pstmt, Oid relid)
{
    if (!plan || !pstmt || relid == InvalidOid)
        return NULL;

    if (IsA(plan, CustomScan))
    {
        CustomScan *cs = (CustomScan *) plan;
        if (cs->custom_plans)
        {
            ListCell *lc;
            foreach (lc, cs->custom_plans)
            {
                const char *t = cf_plan_find_scan_type((Plan *) lfirst(lc), pstmt, relid);
                if (t)
                    return t;
            }
        }
    }

    {
        Index scanrelid = 0;
        if (cf_plan_scan_relid(plan, &scanrelid))
        {
            Oid plan_relid = InvalidOid;
            if (cf_relid_is_relation(pstmt, scanrelid, &plan_relid) && plan_relid == relid)
            {
                switch (nodeTag(plan))
                {
                    case T_SeqScan: return "SeqScan";
                    case T_SampleScan: return "SampleScan";
                    case T_IndexScan: return "IndexScan";
                    case T_IndexOnlyScan: return "IndexOnlyScan";
                    case T_BitmapHeapScan: return "BitmapHeapScan";
                    case T_TidScan: return "TidScan";
                    case T_TidRangeScan: return "TidRangeScan";
                    case T_ForeignScan: return "ForeignScan";
                    case T_FunctionScan: return "FunctionScan";
                    case T_TableFuncScan: return "TableFuncScan";
                    case T_ValuesScan: return "ValuesScan";
                    case T_CteScan: return "CteScan";
                    case T_WorkTableScan: return "WorkTableScan";
                    default: break;
                }
                return "OtherScan";
            }
        }
    }

    if (plan->lefttree)
    {
        const char *t = cf_plan_find_scan_type(plan->lefttree, pstmt, relid);
        if (t)
            return t;
    }
    if (plan->righttree)
    {
        const char *t = cf_plan_find_scan_type(plan->righttree, pstmt, relid);
        if (t)
            return t;
    }

    switch (nodeTag(plan))
    {
        case T_Append:
            {
                Append *a = (Append *) plan;
                ListCell *lc;
                foreach (lc, a->appendplans)
                {
                    const char *t = cf_plan_find_scan_type((Plan *) lfirst(lc), pstmt, relid);
                    if (t)
                        return t;
                }
            }
            break;
        case T_MergeAppend:
            {
                MergeAppend *ma = (MergeAppend *) plan;
                ListCell *lc;
                foreach (lc, ma->mergeplans)
                {
                    const char *t = cf_plan_find_scan_type((Plan *) lfirst(lc), pstmt, relid);
                    if (t)
                        return t;
                }
            }
            break;
        case T_BitmapAnd:
            {
                BitmapAnd *ba = (BitmapAnd *) plan;
                ListCell *lc;
                foreach (lc, ba->bitmapplans)
                {
                    const char *t = cf_plan_find_scan_type((Plan *) lfirst(lc), pstmt, relid);
                    if (t)
                        return t;
                }
            }
            break;
        case T_BitmapOr:
            {
                BitmapOr *bo = (BitmapOr *) plan;
                ListCell *lc;
                foreach (lc, bo->bitmapplans)
                {
                    const char *t = cf_plan_find_scan_type((Plan *) lfirst(lc), pstmt, relid);
                    if (t)
                        return t;
                }
            }
            break;
        case T_SubqueryScan:
            {
                SubqueryScan *sq = (SubqueryScan *) plan;
                const char *t = cf_plan_find_scan_type(sq->subplan, pstmt, relid);
                if (t)
                    return t;
            }
            break;
        default:
            break;
    }

    return NULL;
}

static bool
cf_table_should_filter(PolicyQueryState *qs, const char *name)
{
    if (!qs || !name)
        return false;
    if (!cf_table_in_list(name, qs->policy_targets, qs->n_policy_targets))
        return false;
    if (!cf_table_scanned(qs, name))
        return false;
    return true;
}

static bool
cf_table_scanned(PolicyQueryState *qs, const char *name)
{
    if (!qs || !name || qs->n_scanned_tables == 0 || !qs->scanned_tables)
        return true;
    for (int i = 0; i < qs->n_scanned_tables; i++)
    {
        if (qs->scanned_tables[i] && strcmp(qs->scanned_tables[i], name) == 0)
            return true;
    }
    return false;
}

static bool
cf_table_wrapped(PolicyQueryState *qs, const char *name)
{
    if (!qs || !name || qs->n_wrapped_tables == 0 || !qs->wrapped_tables)
        return false;
    for (int i = 0; i < qs->n_wrapped_tables; i++)
    {
        if (qs->wrapped_tables[i] && strcmp(qs->wrapped_tables[i], name) == 0)
            return true;
    }
    return false;
}
Node *
cf_create_state(CustomScan *cscan)
{
    CfExec *st = (CfExec *) palloc0(sizeof(CfExec));

    NodeSetTag(&st->css, T_CustomScanState);
    st->css.methods = &CFExecMethods;
    st->css.slotOps = &TTSOpsBufferHeapTuple;

    st->child_plan    = NULL;
    st->data_transfer_ms = 0.0;
    st->policy_build_ms = 0.0;
    st->row_validation_ms = 0.0;
    st->child_exec_ms = 0.0;
    st->ctid_extract_ms = 0.0;
    st->ctid_to_rid_ms = 0.0;
    st->allow_check_ms = 0.0;
    st->projection_ms = 0.0;
    st->tuples_seen = 0;
    st->tuples_passed = 0;
    st->misses = 0;
    st->relid = InvalidOid;
    st->relname[0] = '\0';
    st->seq_rid = 0;
    st->scan_type = NULL;
    st->tid_logged = false;
    st->filter = NULL;
    st->need_filter_rebind = true;
    st->bound_build_seq = 0;
    st->attempted_filter_rebuild = false;
    st->rescan_calls = 0;
    st->exec_logged = false;
    st->debug_exec_logged = false;

    return (Node *) st;
}


void
cf_begin(CustomScanState *node, EState *estate, int eflags)
{
    CfExec *st = (CfExec *) node;
    CustomScan *cscan = (CustomScan *) node->ss.ps.plan;
    if (estate && cscan->scan.scanrelid > 0)
    {
        RangeTblEntry *rte = rt_fetch(cscan->scan.scanrelid, estate->es_range_table);
        st->relid = rte ? rte->relid : InvalidOid;
        if (st->relid != InvalidOid)
        {
            const char *rn = get_rel_name(st->relid);
            if (rn)
                strlcpy(st->relname, rn, sizeof(st->relname));
        }
    }
    if (estate && !cf_in_executor_start_init)
    {
        /*
         * Query-state is built in cf_executor_start() in the top-level query's
         * es_query_cxt. Some subplans (e.g., SubPlan/SubqueryScan) can have their
         * own EState with an unrelated es_query_cxt. Rebuilding query-state into
         * those shorter-lived contexts is unsafe (it can be reset mid-statement,
         * leaving stale TableFilterState pointers).
         *
         * Only rebuild upward if the current context contains the existing one.
         */
        if (cf_query_state == NULL ||
            (cf_query_cxt && estate->es_query_cxt &&
             cf_memory_context_contains(estate->es_query_cxt, cf_query_cxt)))
        {
            (void) cf_ensure_query_state(estate, debug_query_string, estate->es_plannedstmt);
        }
    }
    /*
     * During ExecutorStart init, leave filter binding to cf_exec() after the
     * top-level query-state has been constructed in cf_executor_start().
     */
    st->filter = cf_in_executor_start_init ? NULL : cf_find_filter(cf_query_state, st->relid, false);
    st->need_filter_rebind = true;
    st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
    st->attempted_filter_rebuild = false;

    st->child_plan = ExecInitNode((Plan *) linitial(cscan->custom_plans),
                                  estate,
                                  eflags);
    st->scan_type = cf_scan_state_name(st->child_plan);
    cf_debug_log_scan_ids("BeginCustomScan", st, node);
    if (cf_profile_rescan && st->relid != InvalidOid)
    {
        CF_RESCAN_LOG("event=BeginCustomScan pid=%d build_seq=%llu node=%p plan=%p rel=%s relid=%u scan=%s filter=%s",
                      (int) getpid(),
                      (unsigned long long) (cf_query_state ? cf_query_state->build_seq : 0),
                      (void *) st,
                      (void *) node->ss.ps.plan,
                      st->relname[0] ? st->relname : "<unknown>",
                      st->relid,
                      st->scan_type ? st->scan_type : "<unknown>",
                      st->filter ? "on" : "off");
    }
    if (!cf_child_is_scan(st->child_plan))
    {
        if (st->filter)
            ereport(ERROR,
                    (errmsg("custom_filter: unsupported scan node for policy-required table (rel=%s node=%s)",
                            st->relname[0] ? st->relname : "<unknown>",
                            st->scan_type ? st->scan_type : "<unknown>")));
        else
            elog(WARNING, "custom_filter: child plan is not a scan node");
    }
    if (cf_contract_enabled())
    {
        CF_TRACE_LOG( "custom_filter: scan rel=%s type=%s filter=%s",
             st->relname[0] ? st->relname : "<unknown>",
             st->scan_type ? st->scan_type : "<unknown>",
             st->filter ? "on" : "off");
    }
    node->custom_ps = list_make1(st->child_plan);
}

TupleTableSlot *
cf_exec(CustomScanState *node)
{
    CfExec    *st    = (CfExec *) node;
    PlanState *child = st->child_plan;
    instr_time validation_start;

    INSTR_TIME_SET_CURRENT(validation_start);

    if (cf_query_state && st->bound_build_seq != cf_query_state->build_seq)
        st->need_filter_rebind = true;

    if (st->need_filter_rebind)
    {
        if (cf_query_state)
        {
            bool should_filter = false;
            bool in_policy_targets = false;
            if (st->relname[0])
            {
                should_filter = cf_table_should_filter(cf_query_state, st->relname);
                in_policy_targets = cf_table_in_list(st->relname,
                                                     cf_query_state->policy_targets,
                                                     cf_query_state->n_policy_targets);
            }
            bool expect_filter = should_filter || in_policy_targets;
            cf_filters_guard_check(cf_query_state, "BindFilter");
            /*
             * Always rebind the filter pointer from the current query-state.
             * If query-state is rebuilt mid-query (e.g., due to subplan contexts),
             * old pointers can become stale and appear "valid" while holding
             * corrupted metadata (ctid_pairs_len/n_rows/etc).
             */
            st->filter = cf_find_filter(cf_query_state, st->relid, expect_filter);
            if (cf_debug_ids && cf_query_state && !st->filter)
            {
                if (expect_filter)
                {
                    CustomScan *cscan = (CustomScan *) node->ss.ps.plan;
                    EState *estate = node->ss.ps.state;
                    Index scanrelid = cscan ? cscan->scan.scanrelid : 0;
                    Oid rte_oid = InvalidOid;
                    if (estate && scanrelid > 0)
                    {
                        RangeTblEntry *rte = rt_fetch(scanrelid, estate->es_range_table);
                        if (rte)
                            rte_oid = rte->relid;
                    }
                    elog(NOTICE,
                         "CF_BIND_NULL pid=%d scanrelid=%d st_relid=%u st_relname=%s rte_oid=%u should_filter=%d in_policy_targets=%d qs_ptr=%p build_seq=%llu",
                         (int) getpid(),
                         (int) scanrelid,
                         (unsigned int) st->relid,
                         st->relname[0] ? st->relname : "<unknown>",
                         (unsigned int) rte_oid,
                         should_filter ? 1 : 0,
                         in_policy_targets ? 1 : 0,
                         (void *) cf_query_state,
                         (unsigned long long) cf_query_state->build_seq);
                }
            }

            /*
             * Guardrail: if a scan state captured a stale filter pointer (e.g. due
             * to query-state being rebuilt upward to a longer-lived context), rebind
             * it to the current query state's filter for this relid.
             */
            if (st->filter && !st->filter->allow_bits)
            {
                TableFilterState *reb = cf_find_filter(cf_query_state, st->relid, true);
                if (reb && reb->allow_bits)
                    st->filter = reb;
            }
            st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
            st->need_filter_rebind = false;

            cf_debug_log_scan_ids("BindFilter", st, node);
            if (!st->debug_exec_logged)
            {
                cf_debug_log_scan_ids("ExecCustomScan(first)", st, node);
                if (cf_query_state)
                    cf_filters_guard_check(cf_query_state, "ExecCustomScan(first)");
                st->debug_exec_logged = true;
            }

            if (cf_profile_rescan && !st->exec_logged && st->relid != InvalidOid)
            {
                CF_RESCAN_LOG("event=ExecCustomScan(first) pid=%d build_seq=%llu node=%p rel=%s relid=%u scan=%s filter=%s",
                              (int) getpid(),
                              (unsigned long long) cf_query_state->build_seq,
                              (void *) st,
                              st->relname[0] ? st->relname : "<unknown>",
                              st->relid,
                              st->scan_type ? st->scan_type : "<unknown>",
                              st->filter ? "on" : "off");
                st->exec_logged = true;
            }
        }
    }

    TableFilterState *tf = st->filter;

    for (;;)
    {
        instr_time child_start, child_end;
        INSTR_TIME_SET_CURRENT(child_start);
        TupleTableSlot *slot = ExecProcNode(child);
        INSTR_TIME_SET_CURRENT(child_end);
        st->child_exec_ms += INSTR_TIME_GET_MILLISEC(child_end) - INSTR_TIME_GET_MILLISEC(child_start);

        if (TupIsNull(slot))
        {
            cf_accum_validation_time(st, &validation_start);
            return ExecClearTuple(node->ss.ss_ScanTupleSlot);
        }
        st->tuples_seen++;

        bool allow = true;
        if (tf)
            tf->seen++;
allow_check:
        if (tf && tf->allow_bits)
        {
            if (tf->n_rows > 0 && tf->allow_nbytes == 0)
            {
                if (cf_query_state)
                    cf_filters_guard_check(cf_query_state, "engine_error/allow_nbytes_zero");
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: allow_nbytes is zero for rel=%s rows=%u",
                                st->relname[0] ? st->relname : "<unknown>",
                                tf->n_rows)));
            }
            if (tf->ctid_pairs)
            {
                if ((tf->ctid_pairs_len & 1u) != 0)
                {
                    if (cf_query_state)
                        cf_filters_guard_check(cf_query_state, "engine_error/ctid_pairs_len_odd");
                    ereport(ERROR,
                            (errmsg("custom_filter[engine_error]: malformed ctid_pairs_len for rel=%s len=%u",
                                    st->relname[0] ? st->relname : "<unknown>",
                                    tf->ctid_pairs_len)));
                }
                if ((uint64) tf->ctid_pairs_len != ((uint64) tf->n_rows * 2ull))
                {
                    if (cf_query_state)
                        cf_filters_guard_check(cf_query_state, "engine_error/ctid_len_mismatch");
                    ereport(ERROR,
                            (errmsg("custom_filter[engine_error]: ctid length mismatch for rel=%s len=%u rows=%u",
                                    st->relname[0] ? st->relname : "<unknown>",
                                    tf->ctid_pairs_len,
                                    tf->n_rows)));
                }
            }
            else if (tf->ctid_pairs_len != 0)
            {
                if (cf_query_state)
                    cf_filters_guard_check(cf_query_state, "engine_error/ctid_ptr_missing");
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: ctid_pairs pointer missing for rel=%s len=%u rows=%u",
                                st->relname[0] ? st->relname : "<unknown>",
                                tf->ctid_pairs_len,
                                tf->n_rows)));
            }
            if (tf->n_rows > 0 && (!tf->blk_index || tf->n_blocks == 0))
            {
                if (cf_query_state)
                    cf_filters_guard_check(cf_query_state, "engine_error/missing_blk_index");
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: missing ctid block index for rel=%s rows=%u",
                                st->relname[0] ? st->relname : "<unknown>",
                                tf->n_rows)));
            }
            size_t expected_allow_nbytes = (size_t) ((tf->n_rows + 7) / 8);
            if (tf->allow_nbytes != expected_allow_nbytes)
            {
                if (cf_query_state)
                    cf_filters_guard_check(cf_query_state, "engine_error/allow_nbytes_mismatch");
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: allow_nbytes mismatch for rel=%s bytes=%zu expected=%zu rows=%u",
                                st->relname[0] ? st->relname : "<unknown>",
                                tf->allow_nbytes,
                                expected_allow_nbytes,
                                tf->n_rows)));
            }
            TupleTableSlot *ctid_slot = slot;
            ItemPointerData tid_buf;
            CfTidSource tid_src = CF_TID_NONE;
            bool has_tid = false;
            instr_time ctid_extract_start, ctid_extract_end;
            INSTR_TIME_SET_CURRENT(ctid_extract_start);
            if (nodeTag(child) == T_BitmapHeapScanState)
            {
                if (ItemPointerIsValid(&ctid_slot->tts_tid))
                {
                    tid_buf = ctid_slot->tts_tid;
                    tid_src = CF_TID_TTS;
                    has_tid = true;
                }
            }
            else
            {
                has_tid = cf_slot_get_ctid(ctid_slot, &tid_buf, &tid_src);
            }
            if (!has_tid)
            {
                ctid_slot = cf_scan_slot(child, slot);
                if (nodeTag(child) == T_BitmapHeapScanState)
                {
                    if (ItemPointerIsValid(&ctid_slot->tts_tid))
                    {
                        tid_buf = ctid_slot->tts_tid;
                        tid_src = CF_TID_TTS;
                        has_tid = true;
                    }
                }
                else
                {
                    has_tid = cf_slot_get_ctid(ctid_slot, &tid_buf, &tid_src);
                }
            }
            INSTR_TIME_SET_CURRENT(ctid_extract_end);
            st->ctid_extract_ms += INSTR_TIME_GET_MILLISEC(ctid_extract_end) -
                                   INSTR_TIME_GET_MILLISEC(ctid_extract_start);
            if (!has_tid)
            {
                ereport(ERROR,
                        (errmsg("custom_filter: missing CTID/TID for policy-required table (rel=%s scan=%s)",
                                st->relname[0] ? st->relname : "<unknown>",
                                st->scan_type ? st->scan_type : "<unknown>")));
            }
            if (cf_contract_enabled() && !st->tid_logged)
            {
                CF_TRACE_LOG( "custom_filter: tid_source rel=%s scan=%s source=%s",
                     st->relname[0] ? st->relname : "<unknown>",
                     st->scan_type ? st->scan_type : "<unknown>",
                     cf_tid_source_name(tid_src));
                st->tid_logged = true;
            }
            int32 rid = -1;
            BlockNumber blk = 0;
            OffsetNumber off = 0;
            if (cf_contract_enabled() && nodeTag(child) == T_SeqScanState)
            {
                if (tf && tf->ctid_pairs && st->seq_rid < 100)
                {
                    size_t pair_idx = (size_t) st->seq_rid * 2;
                    if (pair_idx + 1 < (size_t) tf->ctid_pairs_len)
                    {
                        uint32 exp_blk = tf->ctid_pairs[pair_idx];
                        uint32 exp_off = tf->ctid_pairs[pair_idx + 1];
                        if (!has_tid)
                        {
                            CF_TRACE_LOG( "custom_filter: seqscan no tid for rid=%u", st->seq_rid);
                        }
                        else if ((uint32) ItemPointerGetBlockNumber(&tid_buf) != exp_blk ||
                                 (uint32) ItemPointerGetOffsetNumber(&tid_buf) != exp_off)
                        {
                            CF_TRACE_LOG( "custom_filter: seqscan ctid mismatch rid=%u got=(%u,%u) exp=(%u,%u)",
                                 st->seq_rid,
                                 (uint32) ItemPointerGetBlockNumber(&tid_buf),
                                 (uint32) ItemPointerGetOffsetNumber(&tid_buf),
                                 exp_blk, exp_off);
                        }
                    }
                }
                st->seq_rid++;
            }
            blk  = ItemPointerGetBlockNumber(&tid_buf);
            off = ItemPointerGetOffsetNumber(&tid_buf);
            instr_time rid_start, rid_end;
            INSTR_TIME_SET_CURRENT(rid_start);
            rid = cf_ctid_to_rid(tf, blk, off);
            INSTR_TIME_SET_CURRENT(rid_end);
            st->ctid_to_rid_ms += INSTR_TIME_GET_MILLISEC(rid_end) - INSTR_TIME_GET_MILLISEC(rid_start);
            if (rid < 0)
            {
                ereport(ERROR,
                        (errmsg("custom_filter: CTID->rid not found for policy-required table (rel=%s blk=%u off=%u)",
                                st->relname[0] ? st->relname : "<unknown>",
                                (uint32) blk, (uint32) off)));
            }
            else if ((uint32) rid >= tf->n_rows)
            {
                ereport(ERROR,
                        (errmsg("custom_filter: rid out of bounds for policy-required table (rel=%s rid=%d rows=%u)",
                                st->relname[0] ? st->relname : "<unknown>",
                                rid, tf->n_rows)));
            }
            else
            {
                instr_time allow_start, allow_end;
                INSTR_TIME_SET_CURRENT(allow_start);
                uint32 idx = (uint32) rid;
                size_t byte_idx = (size_t) (idx >> 3);
                if (byte_idx >= tf->allow_nbytes)
                {
                    ereport(ERROR,
                            (errmsg("custom_filter[rid_oob]: allow_bits index out of range (rel=%s rid=%u rows=%u allow_bytes=%zu ctid=(%u,%u))",
                                    st->relname[0] ? st->relname : "<unknown>",
                                    idx, tf->n_rows, tf->allow_nbytes,
                                    (uint32) blk, (uint32) off)));
                }
                uint8 byte = tf->allow_bits[byte_idx];
                uint8 mask = (uint8) (1u << (idx & 7));
                allow = (byte & mask) != 0;
                INSTR_TIME_SET_CURRENT(allow_end);
                st->allow_check_ms += INSTR_TIME_GET_MILLISEC(allow_end) -
                                      INSTR_TIME_GET_MILLISEC(allow_start);
            }
        }
        else if (tf && !tf->allow_bits)
        {
            /*
             * Robustness: if a scan state captured a stale filter pointer (e.g. due
             * to query-state being rebuilt), try to rebind and, if needed, force a
             * rebuild once so we either recover or fail with useful context.
             */
            TableFilterState *reb = cf_query_state ? cf_find_filter(cf_query_state, st->relid, true) : NULL;
            if (reb && reb->allow_bits)
            {
                st->filter = reb;
                st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
                tf = reb;
                goto allow_check;
            }

            EState *estate = node->ss.ps.state;
            if (!st->attempted_filter_rebuild && estate)
            {
                st->attempted_filter_rebuild = true;
                (void) cf_force_rebuild_query_state(estate,
                                                    debug_query_string ? debug_query_string : "",
                                                    estate->es_plannedstmt);
                reb = cf_query_state ? cf_find_filter(cf_query_state, st->relid, true) : NULL;
                if (reb && reb->allow_bits)
                {
                    st->filter = reb;
                    st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
                    tf = reb;
                    goto allow_check;
                }
            }

            if (cf_trace_enabled())
            {
                PolicyQueryState *qs = cf_query_state;
                const char *rn = st->relname[0] ? st->relname : "<unknown>";
                bool in_targets = false;
                bool scanned = false;
                bool should_filter = false;
                bool wrapped = false;
                if (qs && st->relname[0])
                {
                    in_targets = cf_table_in_list(st->relname, qs->policy_targets, qs->n_policy_targets);
                    scanned = cf_table_scanned(qs, st->relname);
                    should_filter = cf_table_should_filter(qs, st->relname);
                    wrapped = cf_table_wrapped(qs, st->relname);
                }
                elog(NOTICE,
                     "custom_filter: missing_allow_bits_debug qs=%p build_seq=%llu st=%p rel=%s relid=%u tf=%p "
                     "in_policy_targets=%d scanned=%d should_filter=%d wrapped=%d n_filters=%d n_policy_targets=%d n_scanned_tables=%d",
                     (void *) qs,
                     (unsigned long long) (qs ? qs->build_seq : 0),
                     (void *) st,
                     rn,
                     st->relid,
                     (void *) tf,
                     in_targets ? 1 : 0,
                     scanned ? 1 : 0,
                     should_filter ? 1 : 0,
                     wrapped ? 1 : 0,
                     qs ? qs->n_filters : 0,
                     qs ? qs->n_policy_targets : 0,
                     qs ? qs->n_scanned_tables : 0);
                if (qs && qs->filters)
                {
                    for (int i = 0; i < qs->n_filters; i++)
                    {
                        TableFilterState *k = &qs->filters[i];
                        elog(NOTICE,
                             "custom_filter: missing_allow_bits_debug key[%d] rel=%s relid=%u allow_bits=%p allow_nbytes=%zu blk_index=%p n_blocks=%u",
                             i,
                             k->relname[0] ? k->relname : "<unknown>",
                             k->relid,
                             (void *) k->allow_bits,
                             k->allow_nbytes,
                             (void *) k->blk_index,
                             k->n_blocks);
                    }
                }
            }

            if (cf_debug_ids)
            {
                cf_debug_log_scan_ids("MissingAllowBits", st, node);
                PolicyQueryState *qs = cf_query_state;
                if (qs)
                {
                    CF_DEBUG_IDS_LOG("pid=%d build_seq=%llu missing_allow_bits_state qs=%p n_filters=%d n_policy_targets=%d",
                                     (int) getpid(),
                                     (unsigned long long) qs->build_seq,
                                     (void *) qs,
                                     qs->n_filters,
                                     qs->n_policy_targets);
                    if (qs->filters)
                    {
                        for (int i = 0; i < qs->n_filters; i++)
                        {
                            TableFilterState *k = &qs->filters[i];
                            CF_DEBUG_IDS_LOG("pid=%d build_seq=%llu key[%d] rel=%s relid=%u allow_bits=%p allow_nbytes=%zu blk_index=%p n_blocks=%u ctid_pairs=%p ctid_pairs_len=%u n_rows=%u",
                                             (int) getpid(),
                                             (unsigned long long) qs->build_seq,
                                             i,
                                             k->relname[0] ? k->relname : "<unknown>",
                                             k->relid,
                                             (void *) k->allow_bits,
                                             k->allow_nbytes,
                                             (void *) k->blk_index,
                                             k->n_blocks,
                                             (void *) k->ctid_pairs,
                                             k->ctid_pairs_len,
                                             k->n_rows);
                        }
                    }
                }
            }

            ereport(ERROR,
                    (errmsg("custom_filter[engine_error]: missing allow_bits for policy-required table rel=%s",
                            st->relname[0] ? st->relname : "<unknown>")));
        }

        if (allow)
        {
            st->tuples_passed++;
            if (tf)
                tf->passed++;
            instr_time proj_start, proj_end;
            INSTR_TIME_SET_CURRENT(proj_start);
            TupleTableSlot *ret = cf_store_slot(node, slot);
            INSTR_TIME_SET_CURRENT(proj_end);
            st->projection_ms += INSTR_TIME_GET_MILLISEC(proj_end) - INSTR_TIME_GET_MILLISEC(proj_start);
            cf_accum_validation_time(st, &validation_start);
            return ret;
        }

    }
}

void
cf_end(CustomScanState *node)
{
    CfExec *st = (CfExec *) node;

    if (st->child_plan)
    {
        ExecEndNode(st->child_plan);
        st->child_plan = NULL;
    }

    if (cf_contract_enabled() && st->filter && st->filter->allow_bits)
    {
        TableFilterState *tf = st->filter;
        uint32 allow_cnt = 0;
        for (uint32 r = 0; r < tf->n_rows; r++)
        {
            size_t byte_idx = (size_t) (r >> 3);
            if (byte_idx >= tf->allow_nbytes)
                ereport(ERROR,
                        (errmsg("custom_filter[rid_oob]: end-phase allow_bits index out of range (rel=%s rid=%u rows=%u allow_bytes=%zu)",
                                st->relname[0] ? st->relname : "<unknown>",
                                r, tf->n_rows, tf->allow_nbytes)));
            if (tf->allow_bits[byte_idx] & (uint8)(1u << (r & 7)))
                allow_cnt++;
        }
        size_t bytes = tf->allow_nbytes;
        bool canary_ok = (memcmp(tf->allow_bits + bytes,
                                 cf_allow_canary,
                                 CF_ALLOW_CANARY_BYTES) == 0);
        if (!canary_ok)
        {
            CF_TRACE_LOG( "custom_filter: allow_bits canary BAD rel=%s ptr=%p n_rows=%u",
                 st->relname[0] ? st->relname : "<unknown>",
                 (void *) tf->allow_bits, tf->n_rows);
        }
        if (allow_cnt != tf->allow_popcount)
        {
            CF_TRACE_LOG( "custom_filter: allow_bits changed rel=%s before=%u after=%u",
                 st->relname[0] ? st->relname : "<unknown>",
                 tf->allow_popcount, allow_cnt);
        }
        if (st->tuples_passed != (uint64)allow_cnt)
        {
            CF_TRACE_LOG( "custom_filter: allow_bits mismatch rel=%s allow=%u passed=%llu",
                 st->relname[0] ? st->relname : "<unknown>",
                 allow_cnt,
                 (unsigned long long) st->tuples_passed);
        }
    }

    CF_TRACE_LOG( "custom_filter exec: rel=%s oid=%u seen=%llu passed=%llu misses=%llu mode=%s",
         st->relname[0] ? st->relname : "<unknown>",
         st->relid,
         (unsigned long long) st->tuples_seen,
         (unsigned long long) st->tuples_passed,
         (unsigned long long) st->misses,
         cf_debug_mode_name(cf_debug_mode));

    CF_TRACE_LOG( "custom_filter: row validation time = %.3f ms", st->row_validation_ms);

    if (cf_profile_rescan && st->relid != InvalidOid)
    {
        CF_RESCAN_LOG("event=EndCustomScan pid=%d build_seq=%llu node=%p rel=%s relid=%u scan=%s filter=%s rescans=%llu tuples_seen=%llu tuples_passed=%llu",
                      (int) getpid(),
                      (unsigned long long) (cf_query_state ? cf_query_state->build_seq : 0),
                      (void *) st,
                      st->relname[0] ? st->relname : "<unknown>",
                      st->relid,
                      st->scan_type ? st->scan_type : "<unknown>",
                      st->filter ? "on" : "off",
                      (unsigned long long) st->rescan_calls,
                      (unsigned long long) st->tuples_seen,
                      (unsigned long long) st->tuples_passed);
    }

    if (cf_query_state) {
        cf_query_state->filter_ms += st->row_validation_ms;
        cf_query_state->child_exec_ms += st->child_exec_ms;
        cf_query_state->ctid_extract_ms += st->ctid_extract_ms;
        cf_query_state->ctid_to_rid_ms += st->ctid_to_rid_ms;
        cf_query_state->allow_check_ms += st->allow_check_ms;
        cf_query_state->projection_ms += st->projection_ms;
        cf_query_state->rows_seen += st->tuples_seen;
        cf_query_state->rows_passed += st->tuples_passed;
        cf_query_state->ctid_misses += st->misses;
    }
}

void
cf_rescan(CustomScanState *node)
{
    CfExec *st = (CfExec *) node;

    if (cf_query_state)
        cf_filters_guard_check(cf_query_state, "ReScanCustomScan");

    if (st->child_plan)
        ExecReScan(st->child_plan);

    st->seq_rid = 0;
    st->need_filter_rebind = true;
    st->rescan_calls++;
    if (cf_profile_rescan && st->relid != InvalidOid)
    {
        uint64 n = st->rescan_calls;
        bool log_now = (n <= 4) || ((n & (n - 1)) == 0) || ((n % 1024) == 0);
        if (log_now)
        {
            CF_RESCAN_LOG("event=ReScanCustomScan pid=%d build_seq=%llu node=%p rel=%s relid=%u scan=%s filter=%s rescan_count=%llu",
                          (int) getpid(),
                          (unsigned long long) (cf_query_state ? cf_query_state->build_seq : 0),
                          (void *) st,
                          st->relname[0] ? st->relname : "<unknown>",
                          st->relid,
                          st->scan_type ? st->scan_type : "<unknown>",
                          st->filter ? "on" : "off",
                          (unsigned long long) n);
        }
    }
    if (cf_debug_ids && st->relid != InvalidOid)
    {
        uint64 n = st->rescan_calls;
        bool log_now = (n <= 4) || ((n & (n - 1)) == 0) || ((n % 1024) == 0);
        if (log_now)
            cf_debug_log_scan_ids("ReScanCustomScan", st, node);
    }
}



void
cf_explain(CustomScanState *node, List *ancestors, ExplainState *es)
{
    (void) node;
    (void) ancestors;
    ExplainPropertyText("custom_filter", "", es);
}

bool
cf_child_is_scan(PlanState *node)
{
    if (node == NULL)
        return false;

    switch (nodeTag(node))
    {
        case T_SeqScanState:
        case T_SampleScanState:
        case T_IndexScanState:
        case T_IndexOnlyScanState:
        case T_BitmapHeapScanState:
        case T_TidScanState:
        case T_TidRangeScanState:
        case T_ForeignScanState:
        case T_FunctionScanState:
        case T_TableFuncScanState:
        case T_ValuesScanState:
        case T_CteScanState:
        case T_WorkTableScanState:
            return true;
        default:
            break;
    }

    return false;
}

TupleTableSlot *
cf_return_tuple(CustomScanState *node)
{
    ProjectionInfo *projInfo = node->ss.ps.ps_ProjInfo;

    if (projInfo)
    {
        ExprContext *econtext = node->ss.ps.ps_ExprContext;
        econtext->ecxt_scantuple = node->ss.ss_ScanTupleSlot;
        return ExecProject(projInfo);
    }

    return node->ss.ss_ScanTupleSlot;
}

void
cf_accum_validation_time(CfExec *st, instr_time *start_time)
{
    instr_time stop;
    instr_time diff;

    INSTR_TIME_SET_CURRENT(stop);
    diff = stop;
    INSTR_TIME_SUBTRACT(diff, *start_time);
    st->row_validation_ms += INSTR_TIME_GET_MILLISEC(diff);
}

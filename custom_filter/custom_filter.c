

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
#include "access/tableam.h"
#include "storage/itemptr.h"      
#include "utils/memutils.h"       
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "lib/stringinfo.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "nodes/primnodes.h"
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

typedef enum CfScanMode
{
    CF_SCAN_MODE_FILTER = 0,
    CF_SCAN_MODE_TID = 1,
    CF_SCAN_MODE_EMPTY = 2
} CfScanMode;

typedef struct PolicyTableAllowC {
    const char *table;
    uint64 *block_words;
    uint32 *block_ids;
    uint32 blocks;
    uint32 total_blocks;
    uint32 n_rows;
} PolicyTableAllowC;

typedef struct PolicyAllowListC {
    int count;
    PolicyTableAllowC *items;
} PolicyAllowListC;

typedef struct TableFilterState TableFilterState;

typedef struct PolicyRunProfileC {
    double artifact_parse_ms;
    double atoms_ms;
    double propagate_ms;
    double project_ms;
    double project_mask_ms;
    double project_row_ms;
    size_t project_mask_bytes;
    int project_n_join_evals_max;
    int project_clause_words_max;
    double stamp_ms;
    double bin_ms;
    double local_sat_ms;
    double fill_ms;
    double prop_ms;
    int prop_iters;
    double decode_ms;
    double policy_total_ms;
    int clause_plan_count_max;
    uint64 prop_join_scans_total;
    int unique_join_struct_sigs_max;
    const char *prop_table_scans;
    uint64 signature_cache_hits;
    uint64 signature_cache_misses;
    uint64 term_code_scans;
    uint64 target_full_row_scans;
    size_t target_rid_bitmap_bytes;
    size_t signature_cache_bytes;
    uint64 active_sig_dense_count;
    uint64 active_sig_sparse_count;
    double active_sig_density_sum;
    uint64 domain_set_dense_count;
    uint64 domain_set_sparse_count;
    double domain_set_density_sum;
    uint64 block_words_blocks_allocated;
    uint64 block_words_total_blocks;
    size_t block_words_dense_bytes;
    uint64 block_words_nblocks;
    uint64 block_words_nwords_per_block;
    uint64 proj_sig_count;
    uint64 proj_sig_total;
    uint64 proj_sig_new;
    uint64 proj_sig_skipped;
    uint64 proj_mask_or_ops;
    uint64 proj_rid_iters;
    uint64 proj_rid_iters_scan_enforcement;
    uint64 proj_rid_iters_dependency;
    uint64 canon_term_map_cache_hits;
    uint64 canon_term_map_cache_misses;
    double canon_term_map_build_ms;
    size_t canon_term_map_bytes;
    double restrict_key_index_build_ms;
    uint64 restrict_key_index_entries;
    size_t restrict_key_index_bytes;
    double restrict_key_prune_ms;
    uint64 sigmask_cache_hits;
    uint64 sigmask_cache_misses;
    double sigmask_build_ms;
    size_t sigmask_bytes;
    size_t bytes_sig_ctid_masks;
    size_t bytes_block_words;
    size_t bytes_artifact_buffers_retained;
    size_t bytes_decoded_buffers_retained;
    uint64 qual_atoms_total;
    uint64 qual_atoms_applied;
    uint64 qual_pruned_sigs;
    double qual_prune_ms;
    uint64 restrict_sig_tables;
    uint64 restrict_sig_schema_cols_total;
    size_t restrict_sig_bytes_total;
    double restrict_sig_apply_ms;
    double restrict_term_apply_ms;
    uint64 restrict_term_sigs_kept;
    uint64 restrict_term_sigs_dropped;
    uint64 scan_mode_tid_tables;
    uint64 scan_mode_filter_tables;
    uint64 tid_blocks_visited;
    uint64 tid_tuples_fetched;
    double tid_fetch_ms;
    double tid_qual_ms;
} PolicyRunProfileC;

typedef struct PolicyRunHandle PolicyRunHandle;
extern PolicyRunHandle *policy_run(const PolicyArtifactC *arts, int art_count,
                                   const PolicyEngineInputC *in);
extern const PolicyAllowListC *policy_run_allow_list(const PolicyRunHandle *h);
extern const PolicyRunProfileC *policy_run_profile(const PolicyRunHandle *h);

/* Fixed per-block bitmap layout: offsets are 1-based in CTIDs, so we map off -> (off-1). */
#define CF_MAX_OFF 512u
#define CF_WORDS_PER_BLOCK ((CF_MAX_OFF + 63u) / 64u)

static inline bool
cf_allowed_ctid_words(const uint64 *words, const uint32 *block_ids, uint32 blocks, uint32 total_blocks, BlockNumber blk, OffsetNumber off)
{
    uint32 blk_u;
    uint32 off_u;
    uint32 off0;
    size_t word_idx;
    size_t flat;
    uint64 mask;

    if (!words || blocks == 0)
        return false;
    blk_u = (uint32) blk;
    if (block_ids) {
        uint32 lo = 0, hi = blocks;
        while (lo < hi) {
            uint32 mid = lo + (hi - lo) / 2u;
            uint32 v = block_ids[mid];
            if (v < blk_u)
                lo = mid + 1u;
            else
                hi = mid;
        }
        if (lo >= blocks || block_ids[lo] != blk_u)
            return false;
        blk_u = lo;
    } else {
        if (blk_u >= blocks)
            return false;
    }
    if (total_blocks > 0 && blk_u >= total_blocks && !block_ids)
        return false;
    if (off < 1)
        return false;
    off_u = (uint32) off;
    if (off_u > CF_MAX_OFF)
        return false;

    off0 = off_u - 1u;
    word_idx = (size_t) (off0 >> 6);
    flat = (size_t) blk_u * (size_t) CF_WORDS_PER_BLOCK + word_idx;
    mask = 1ULL << (off0 & 63u);
    return (words[flat] & mask) != 0;
}

static inline const uint64 *
cf_lookup_block_words(const uint64 *words,
                      const uint32 *block_ids,
                      uint32 blocks,
                      uint32 total_blocks,
                      BlockNumber blk)
{
    if (!words || blocks == 0)
        return NULL;
    uint32 blk_u = (uint32) blk;
    if (block_ids)
    {
        uint32 lo = 0, hi = blocks;
        while (lo < hi)
        {
            uint32 mid = lo + (hi - lo) / 2u;
            uint32 v = block_ids[mid];
            if (v < blk_u)
                lo = mid + 1u;
            else
                hi = mid;
        }
        if (lo >= blocks || block_ids[lo] != blk_u)
            return NULL;
        return words + (size_t) lo * (size_t) CF_WORDS_PER_BLOCK;
    }
    if (blk_u >= blocks)
        return NULL;
    if (total_blocks > 0 && blk_u >= total_blocks)
        return NULL;
    return words + (size_t) blk_u * (size_t) CF_WORDS_PER_BLOCK;
}

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

static uint64
cf_popcount_block_words(const uint64 *words, uint32 blocks)
{
    uint64 cnt = 0;
    if (!words || blocks == 0)
        return 0;
    size_t nwords = (size_t) blocks * (size_t) CF_WORDS_PER_BLOCK;
    for (size_t i = 0; i < nwords; i++)
        cnt += (uint64) __builtin_popcountll((unsigned long long) words[i]);
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
static bool cf_tidscan_seqscan = true;
static double cf_tidscan_density_threshold = 0.20;

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
ExecutorRun_hook_type prev_ExecutorRun_hook = NULL;


void cf_rel_pathlist_hook(PlannerInfo *root, RelOptInfo *rel, Index rti, RangeTblEntry *rte);
static PlannedStmt *cf_planner_hook(Query *parse, const char *query_string,
                                    int cursorOptions, ParamListInfo boundParams);
static void cf_executor_start(QueryDesc *queryDesc, int eflags);
static void cf_executor_run(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once);

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
static TupleTableSlot *cf_store_slot(CustomScanState *node, TupleTableSlot *slot);
static bool cf_table_wrapped(PolicyQueryState *qs, const char *name);
static const char *cf_plan_find_scan_type(Plan *plan, PlannedStmt *pstmt, Oid relid);
static bool cf_plan_scan_relid(Plan *plan, Index *out_relid);
static bool cf_relid_is_relation(PlannedStmt *pstmt, Index scanrelid, Oid *out_relid);
static void cf_log_wrapper_audit(PlannedStmt *pstmt);
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
static bool cf_runtime_strict_mode_enabled(void);
static bool cf_plan_inner_only_safe(Plan *plan, const char **reason_out);
static bool cf_query_has_empty_allow_set(const PolicyQueryState *qs, const char **table_out);
static void cf_update_scan_mode(struct CfExec *st, CustomScanState *node, TableFilterState *tf);
static bool cf_tid_iter_next(struct CfExec *st, TableFilterState *tf, ItemPointerData *out_tid);
static TupleTableSlot *cf_exec_seqscan_tid_mode(CustomScanState *node, struct CfExec *st, TableFilterState *tf);
static void cf_collect_seqscan_qual_atoms(EState *estate,
                                          const PolicyEvalResultC *eval_res,
                                          MemoryContext mcxt,
                                          PolicyScanQualAtomC **out_atoms,
                                          int *out_count);
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

    DefineCustomBoolVariable("custom_filter.tidscan_seqscan",
                             "Enable adaptive CTID-driven fetch mode for selective SeqScan targets.",
                             NULL,
                             &cf_tidscan_seqscan,
                             true,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    DefineCustomRealVariable("custom_filter.tidscan_density_threshold",
                             "Switch SeqScan to CTID-driven mode when allowed-block density is below this threshold.",
                             NULL,
                             &cf_tidscan_density_threshold,
                             0.20,
                             0.0,
                             1.0,
                             PGC_SUSET,
                             0,
                             NULL, NULL, NULL);

    prev_planner_hook = planner_hook;
    planner_hook = cf_planner_hook;

    prev_set_rel_pathlist_hook = set_rel_pathlist_hook;
    set_rel_pathlist_hook = cf_rel_pathlist_hook;

    prev_ExecutorStart_hook = ExecutorStart_hook;
    ExecutorStart_hook = cf_executor_start;
    prev_ExecutorRun_hook = ExecutorRun_hook;
    ExecutorRun_hook = cf_executor_run;

    RegisterCustomScanMethods(&CFPlanMethods);
}

void
_PG_fini(void)
{
    planner_hook = prev_planner_hook;
    set_rel_pathlist_hook = prev_set_rel_pathlist_hook;
    ExecutorStart_hook = prev_ExecutorStart_hook;
    ExecutorRun_hook = prev_ExecutorRun_hook;
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
    struct TableFilterState *validated_filter;
    uint64 validated_build_seq;
    bool need_filter_rebind;
    uint64 bound_build_seq;
    bool attempted_filter_rebuild;
    uint64 rescan_calls;
    bool exec_logged;
    bool debug_exec_logged;
    bool blk_cache_valid;
    BlockNumber blk_cache_blkno;
    bool blk_cache_present;
    const uint64 *blk_cache_words;
    uint64 blocks_seen;
    uint64 blocks_skipped;
    CfScanMode scan_mode;
    bool scan_mode_set;
    double scan_mode_density;
    bool scan_mode_logged;
    bool tid_iter_initialized;
    uint32 tid_iter_block_ord;
    uint32 tid_iter_word_idx;
    uint32 tid_iter_bit_min;
    uint64 tid_blocks_visited;
    uint64 tid_tuples_fetched;
    double tid_fetch_ms;
    double tid_qual_ms;
    bool empty_short_circuit_recorded;
    uint64 empty_short_circuit_calls;
    double empty_short_circuit_ms;
} CfExec;

typedef struct TableFilterState
{
    Oid relid;
    char relname[NAMEDATALEN];
    uint32 n_rows;
    uint64 *block_words;
    uint32 *block_ids;
    uint32 blocks;
    uint32 total_blocks;
    size_t block_words_nbytes;
    size_t block_ids_nbytes;
    uint64 allowed_rows;
    bool allow_is_empty;
    uint64 seen;
    uint64 passed;
    uint64 misses;
} TableFilterState;

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
    double propagate_ms;
    double project_ms;
    double project_mask_ms;
    double project_row_ms;
    size_t project_mask_bytes;
    int project_n_join_evals_max;
    int project_clause_words_max;
    int clause_plan_count_max;
    uint64 prop_join_scans_total;
    int unique_join_struct_sigs_max;
    char *prop_table_scans;
    uint64 signature_cache_hits;
    uint64 signature_cache_misses;
    uint64 term_code_scans;
    uint64 target_full_row_scans;
    size_t target_rid_bitmap_bytes;
    size_t signature_cache_bytes;
    uint64 active_sig_dense_count;
    uint64 active_sig_sparse_count;
    double active_sig_density_sum;
    uint64 domain_set_dense_count;
    uint64 domain_set_sparse_count;
    double domain_set_density_sum;
    uint64 block_words_blocks_allocated;
    uint64 block_words_total_blocks;
    size_t block_words_dense_bytes;
    uint64 block_words_nblocks;
    uint64 block_words_nwords_per_block;
    uint64 proj_sig_count;
    uint64 proj_sig_total;
    uint64 proj_sig_new;
    uint64 proj_sig_skipped;
    uint64 proj_mask_or_ops;
    uint64 proj_rid_iters;
    uint64 proj_rid_iters_scan_enforcement;
    uint64 proj_rid_iters_dependency;
    uint64 canon_term_map_cache_hits;
    uint64 canon_term_map_cache_misses;
    double canon_term_map_build_ms;
    size_t canon_term_map_bytes;
    double restrict_key_index_build_ms;
    uint64 restrict_key_index_entries;
    size_t restrict_key_index_bytes;
    double restrict_key_prune_ms;
    uint64 sigmask_cache_hits;
    uint64 sigmask_cache_misses;
    double sigmask_build_ms;
    size_t sigmask_bytes;
    size_t bytes_sig_ctid_masks;
    size_t bytes_block_words;
    size_t bytes_artifact_buffers_retained;
    size_t bytes_decoded_buffers_retained;
    uint64 qual_atoms_total;
    uint64 qual_atoms_applied;
    uint64 qual_pruned_sigs;
    double qual_prune_ms;
    uint64 restrict_sig_tables;
    uint64 restrict_sig_schema_cols_total;
    size_t restrict_sig_bytes_total;
    double restrict_sig_apply_ms;
    double restrict_term_apply_ms;
    uint64 restrict_term_sigs_kept;
    uint64 restrict_term_sigs_dropped;
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
    uint64 blocks_seen;
    uint64 blocks_skipped;
    uint64 scan_mode_tid_tables;
    uint64 scan_mode_filter_tables;
    uint64 scan_mode_empty_tables;
    uint64 tid_blocks_visited;
    uint64 tid_tuples_fetched;
    double tid_fetch_ms;
    double tid_qual_ms;
    uint64 empty_short_circuit_tables;
    double empty_short_circuit_ms;
    bool query_short_circuit_empty;
    bool query_short_circuit_decided;
    char query_short_circuit_reason[64];
    double query_short_circuit_ms;
    uint64 query_short_circuit_hits;
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
        h = cf_fnv1a64_update(h, &tf->block_words, sizeof(tf->block_words));
        h = cf_fnv1a64_update(h, &tf->block_ids, sizeof(tf->block_ids));
        h = cf_fnv1a64_update(h, &tf->blocks, sizeof(tf->blocks));
        h = cf_fnv1a64_update(h, &tf->total_blocks, sizeof(tf->total_blocks));
        h = cf_fnv1a64_update(h, &tf->block_words_nbytes, sizeof(tf->block_words_nbytes));
        h = cf_fnv1a64_update(h, &tf->block_ids_nbytes, sizeof(tf->block_ids_nbytes));
        h = cf_fnv1a64_update(h, &tf->allowed_rows, sizeof(tf->allowed_rows));
        h = cf_fnv1a64_update(h, &tf->allow_is_empty, sizeof(tf->allow_is_empty));
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
                         " f%d(tf=%p relid=%u rel=%s block_words=%p blocks=%u bytes=%zu rows=%u)",
                         i,
                         (void *) tf,
                         (unsigned int) tf->relid,
                         tf->relname[0] ? tf->relname : "<unknown>",
                         (void *) tf->block_words,
                         (unsigned int) tf->blocks,
                         tf->block_words_nbytes,
                         tf->n_rows);
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
                     "filter_ptr=%p filter_block_words=%p filter_found=%d",
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
                     (void *) (st->filter ? st->filter->block_words : NULL),
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

    PolicyQueryState *qs = cf_ensure_query_state(queryDesc->estate,
                                                 queryDesc->sourceText ? queryDesc->sourceText : debug_query_string,
                                                 pstmt);
    cf_log_wrapper_audit(pstmt);
    if (qs)
    {
        const char *reason = "none";
        const char *empty_rel = NULL;
        bool any_empty = cf_query_has_empty_allow_set(qs, &empty_rel);
        bool safe_plan = false;

        qs->query_short_circuit_empty = false;
        qs->query_short_circuit_decided = true;
        qs->query_short_circuit_reason[0] = '\0';

        if (!any_empty)
            reason = "no_empty_allow";
        else
        {
            safe_plan = cf_plan_inner_only_safe(pstmt->planTree, &reason);
            if (safe_plan)
            {
                qs->query_short_circuit_empty = true;
                reason = "inner_only_empty";
            }
        }

        strlcpy(qs->query_short_circuit_reason, reason, sizeof(qs->query_short_circuit_reason));
        if (cf_profile_query && cf_profile_query[0])
        {
            elog(NOTICE,
                 "query_short_circuit_decision: enabled=%d reason=%s empty_rel=%s",
                 qs->query_short_circuit_empty ? 1 : 0,
                 qs->query_short_circuit_reason[0] ? qs->query_short_circuit_reason : "none",
                 empty_rel ? empty_rel : "none");
        }
    }
}

static void
cf_executor_run(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
{
    bool do_short_circuit = false;

    if (cf_enabled &&
        !cf_in_internal_query &&
        queryDesc &&
        queryDesc->estate &&
        queryDesc->plannedstmt &&
        queryDesc->plannedstmt->commandType == CMD_SELECT &&
        cf_runtime_strict_mode_enabled() &&
        cf_query_state &&
        cf_query_state->ready &&
        cf_query_state->query_short_circuit_decided &&
        cf_query_state->query_short_circuit_empty)
    {
        do_short_circuit = true;
    }

    if (do_short_circuit)
    {
        instr_time t0, t1;
        INSTR_TIME_SET_CURRENT(t0);
        queryDesc->estate->es_processed = 0;
        cf_query_state->query_short_circuit_hits++;
        INSTR_TIME_SET_CURRENT(t1);
        cf_query_state->query_short_circuit_ms += INSTR_TIME_GET_MILLISEC(t1) - INSTR_TIME_GET_MILLISEC(t0);
        return;
    }

    if (prev_ExecutorRun_hook)
        prev_ExecutorRun_hook(queryDesc, direction, count, execute_once);
    else
        standard_ExecutorRun(queryDesc, direction, count, execute_once);
}

static void
cf_log_query_metrics(PolicyQueryState *qs)
{
    if (!qs)
        return;
    elog(NOTICE,
         "policy_profile: eval_ms=%.3f artifact_load_ms=%.3f artifact_parse_ms=%.3f atoms_ms=%.3f propagate_ms=%.3f project_ms=%.3f "
         "project_mask_ms=%.3f project_row_ms=%.3f project_mask_bytes=%zu project_n_join_evals_max=%d project_clause_words_max=%d clause_plan_count_max=%d "
         "prop_join_scans_total=%llu unique_join_struct_sigs_max=%d prop_table_scans=%s signature_cache_hits=%llu signature_cache_misses=%llu term_code_scans=%llu target_full_row_scans=%llu "
         "target_rid_bitmap_bytes=%zu signature_cache_bytes=%zu active_sig_dense_count=%llu active_sig_sparse_count=%llu active_sig_density_sum=%.6f "
         "domain_set_dense_count=%llu domain_set_sparse_count=%llu domain_set_density_sum=%.6f block_words_blocks_allocated=%llu block_words_total_blocks=%llu block_words_dense_bytes=%zu block_words_nblocks=%llu block_words_nwords_per_block=%llu "
         "proj_sig_count=%llu proj_sig_total=%llu proj_sig_new=%llu proj_sig_skipped=%llu proj_mask_or_ops=%llu proj_rid_iters=%llu proj_rid_iters_scan_enforcement=%llu proj_rid_iters_dependency=%llu "
         "canon_term_map_cache_hits=%llu canon_term_map_cache_misses=%llu canon_term_map_build_ms=%.3f canon_term_map_bytes=%zu "
         "restrict_key_index_build_ms=%.3f restrict_key_index_entries=%llu restrict_key_index_bytes=%zu restrict_key_prune_ms=%.3f "
         "sigmask_cache_hits=%llu sigmask_cache_misses=%llu sigmask_build_ms=%.3f sigmask_bytes=%zu "
         "bytes_sig_ctid_masks=%zu bytes_block_words=%zu bytes_artifact_buffers_retained=%zu bytes_decoded_buffers_retained=%zu "
         "qual_atoms_total=%llu qual_atoms_applied=%llu qual_pruned_sigs=%llu qual_prune_ms=%.3f "
         "restrict_sig_tables=%llu restrict_sig_schema_cols_total=%llu restrict_sig_bytes_total=%zu restrict_sig_apply_ms=%.3f restrict_term_apply_ms=%.3f restrict_term_sigs_kept=%llu restrict_term_sigs_dropped=%llu "
         "stamp_ms=%.3f bin_ms=%.3f local_sat_ms=%.3f fill_ms=%.3f prop_ms=%.3f prop_iters=%d "
         "decode_ms=%.3f policy_total_ms=%.3f ctid_map_ms=%.3f filter_ms=%.3f "
         "child_exec_ms=%.3f ctid_extract_ms=%.3f ctid_to_rid_ms=%.3f allow_check_ms=%.3f projection_ms=%.3f "
         "blocks_seen=%llu blocks_skipped=%llu block_skip_hit_rate=%.6f "
         "scan_mode_tid_tables=%llu scan_mode_filter_tables=%llu scan_mode_empty_tables=%llu "
         "empty_short_circuit_tables=%llu empty_short_circuit_ms=%.3f "
         "query_short_circuit_empty=%d query_short_circuit_reason=%s query_short_circuit_ms=%.3f query_short_circuit_hits=%llu "
         "tid_blocks_visited=%llu tid_tuples_fetched=%llu tid_fetch_ms=%.3f tid_qual_ms=%.3f "
         "n_scanned_tables=%d n_policy_targets=%d n_filters=%d "
         "bytes_artifacts_loaded=%zu bytes_allow=%zu bytes_ctid=%zu bytes_blk_index=%zu "
         "rows_seen=%llu rows_passed=%llu ctid_misses=%llu "
         "rss_kb_before_eval=%ld rss_kb_after_eval=%ld rss_kb_after_load=%ld "
         "rss_kb_after_engine=%ld rss_kb_after_ctid=%ld rss_kb_end=%ld peak_rss_kb_end=%ld",
         qs->eval_ms,
         qs->artifact_load_ms,
         qs->artifact_parse_ms,
         qs->atoms_ms,
         qs->propagate_ms,
         qs->project_ms,
         qs->project_mask_ms,
         qs->project_row_ms,
         qs->project_mask_bytes,
         qs->project_n_join_evals_max,
         qs->project_clause_words_max,
         qs->clause_plan_count_max,
         (unsigned long long) qs->prop_join_scans_total,
         qs->unique_join_struct_sigs_max,
         (qs->prop_table_scans && qs->prop_table_scans[0]) ? qs->prop_table_scans : "none",
         (unsigned long long) qs->signature_cache_hits,
         (unsigned long long) qs->signature_cache_misses,
         (unsigned long long) qs->term_code_scans,
         (unsigned long long) qs->target_full_row_scans,
         qs->target_rid_bitmap_bytes,
         qs->signature_cache_bytes,
         (unsigned long long) qs->active_sig_dense_count,
         (unsigned long long) qs->active_sig_sparse_count,
         qs->active_sig_density_sum,
         (unsigned long long) qs->domain_set_dense_count,
         (unsigned long long) qs->domain_set_sparse_count,
         qs->domain_set_density_sum,
         (unsigned long long) qs->block_words_blocks_allocated,
         (unsigned long long) qs->block_words_total_blocks,
         qs->block_words_dense_bytes,
         (unsigned long long) qs->block_words_nblocks,
         (unsigned long long) qs->block_words_nwords_per_block,
         (unsigned long long) qs->proj_sig_count,
         (unsigned long long) qs->proj_sig_total,
         (unsigned long long) qs->proj_sig_new,
         (unsigned long long) qs->proj_sig_skipped,
         (unsigned long long) qs->proj_mask_or_ops,
         (unsigned long long) qs->proj_rid_iters,
         (unsigned long long) qs->proj_rid_iters_scan_enforcement,
         (unsigned long long) qs->proj_rid_iters_dependency,
         (unsigned long long) qs->canon_term_map_cache_hits,
         (unsigned long long) qs->canon_term_map_cache_misses,
         qs->canon_term_map_build_ms,
         qs->canon_term_map_bytes,
         qs->restrict_key_index_build_ms,
         (unsigned long long) qs->restrict_key_index_entries,
         qs->restrict_key_index_bytes,
         qs->restrict_key_prune_ms,
         (unsigned long long) qs->sigmask_cache_hits,
         (unsigned long long) qs->sigmask_cache_misses,
         qs->sigmask_build_ms,
         qs->sigmask_bytes,
         qs->bytes_sig_ctid_masks,
         qs->bytes_block_words,
         qs->bytes_artifact_buffers_retained,
         qs->bytes_decoded_buffers_retained,
         (unsigned long long) qs->qual_atoms_total,
         (unsigned long long) qs->qual_atoms_applied,
         (unsigned long long) qs->qual_pruned_sigs,
         qs->qual_prune_ms,
         (unsigned long long) qs->restrict_sig_tables,
         (unsigned long long) qs->restrict_sig_schema_cols_total,
         qs->restrict_sig_bytes_total,
         qs->restrict_sig_apply_ms,
         qs->restrict_term_apply_ms,
         (unsigned long long) qs->restrict_term_sigs_kept,
         (unsigned long long) qs->restrict_term_sigs_dropped,
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
         (unsigned long long) qs->blocks_seen,
         (unsigned long long) qs->blocks_skipped,
         (qs->blocks_seen > 0 ? ((double) qs->blocks_skipped / (double) qs->blocks_seen) : 0.0),
         (unsigned long long) qs->scan_mode_tid_tables,
         (unsigned long long) qs->scan_mode_filter_tables,
         (unsigned long long) qs->scan_mode_empty_tables,
         (unsigned long long) qs->empty_short_circuit_tables,
         qs->empty_short_circuit_ms,
         qs->query_short_circuit_empty ? 1 : 0,
         (qs->query_short_circuit_reason[0] ? qs->query_short_circuit_reason : "none"),
         qs->query_short_circuit_ms,
         (unsigned long long) qs->query_short_circuit_hits,
         (unsigned long long) qs->tid_blocks_visited,
         (unsigned long long) qs->tid_tuples_fetched,
         qs->tid_fetch_ms,
         qs->tid_qual_ms,
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

static char *
cf_files_table_sql_ident(void)
{
    const char *cfg = GetConfigOption("custom_filter.files_table", true, false);
    const char *raw = (cfg && cfg[0]) ? cfg : "public.files";
    const char *dot = strchr(raw, '.');
    if (dot && strchr(dot + 1, '.') == NULL)
    {
        char *schema = pnstrdup(raw, dot - raw);
        char *table = pstrdup(dot + 1);
        char *q = quote_qualified_identifier(schema, table);
        pfree(schema);
        pfree(table);
        return q;
    }
    return pstrdup(quote_identifier(raw));
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

    char *files_table_sql = cf_files_table_sql_ident();
    char *sql = psprintf(
        "SELECT name, file "
        "FROM %s "
        "WHERE COALESCE(run_id,'') = COALESCE(current_setting('custom_filter.run_id', true), '') "
        "AND name = ANY($1::text[])",
        files_table_sql);
    Oid argtypes[1];
    Datum values[1];
    char nulls[1] = { ' ' };
    argtypes[0] = get_array_type(TEXTOID);
    if (!OidIsValid(argtypes[0]))
        ereport(ERROR, (errmsg("custom_filter: could not resolve text[] type oid")));

    values[0] = PointerGetDatum(name_arr);
    int spi_rc = SPI_execute_with_args(sql, 1, argtypes, values, nulls, true, 0);
    pfree(sql);
    pfree(files_table_sql);
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

/* Legacy CTID->RID/blk_index filtering removed: runtime checks use block_words directly. */

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
                             " f%d(relid=%u,name=%s,block_words=%p,rows=%u)",
                             i,
                             (unsigned int) f->relid,
                             f->relname[0] ? f->relname : "<unknown>",
                             (void *) f->block_words,
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
        PolicyScanQualAtomC *scan_qual_atoms = NULL;
        int scan_qual_atom_count = 0;
        cf_collect_seqscan_qual_atoms(estate, eval_res, qctx, &scan_qual_atoms, &scan_qual_atom_count);
        PolicyEngineInputC in;
        in.target_count = eval_res->target_count;
        in.target_tables = eval_res->target_tables;
        in.target_asts = eval_res->target_asts;
        in.target_perm_asts = eval_res->target_perm_asts;
        in.target_rest_asts = eval_res->target_rest_asts;
        in.atom_count = eval_res->atom_count;
        in.atoms = eval_res->atoms;
        in.bundle_count = eval_res->bundle_count;
        in.bundles = eval_res->bundles;
        in.scan_qual_atom_count = scan_qual_atom_count;
        in.scan_qual_atoms = scan_qual_atoms;
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
            qs->propagate_ms += pp->propagate_ms;
            qs->project_ms += pp->project_ms;
            qs->project_mask_ms += pp->project_mask_ms;
            qs->project_row_ms += pp->project_row_ms;
            qs->project_mask_bytes += pp->project_mask_bytes;
            if (pp->project_n_join_evals_max > qs->project_n_join_evals_max)
                qs->project_n_join_evals_max = pp->project_n_join_evals_max;
            if (pp->project_clause_words_max > qs->project_clause_words_max)
                qs->project_clause_words_max = pp->project_clause_words_max;
            if (pp->clause_plan_count_max > qs->clause_plan_count_max)
                qs->clause_plan_count_max = pp->clause_plan_count_max;
            qs->prop_join_scans_total += pp->prop_join_scans_total;
            if (pp->unique_join_struct_sigs_max > qs->unique_join_struct_sigs_max)
                qs->unique_join_struct_sigs_max = pp->unique_join_struct_sigs_max;
            qs->signature_cache_hits += pp->signature_cache_hits;
            qs->signature_cache_misses += pp->signature_cache_misses;
            qs->term_code_scans += pp->term_code_scans;
            qs->target_full_row_scans += pp->target_full_row_scans;
            qs->target_rid_bitmap_bytes += pp->target_rid_bitmap_bytes;
            qs->signature_cache_bytes += pp->signature_cache_bytes;
            qs->active_sig_dense_count += pp->active_sig_dense_count;
            qs->active_sig_sparse_count += pp->active_sig_sparse_count;
            qs->active_sig_density_sum += pp->active_sig_density_sum;
            qs->domain_set_dense_count += pp->domain_set_dense_count;
            qs->domain_set_sparse_count += pp->domain_set_sparse_count;
            qs->domain_set_density_sum += pp->domain_set_density_sum;
            qs->block_words_blocks_allocated += pp->block_words_blocks_allocated;
            qs->block_words_total_blocks += pp->block_words_total_blocks;
            qs->block_words_dense_bytes += pp->block_words_dense_bytes;
            qs->block_words_nblocks += pp->block_words_nblocks;
            if (pp->block_words_nwords_per_block > qs->block_words_nwords_per_block)
                qs->block_words_nwords_per_block = pp->block_words_nwords_per_block;
            qs->proj_sig_count += pp->proj_sig_count;
            qs->proj_sig_total += pp->proj_sig_total;
            qs->proj_sig_new += pp->proj_sig_new;
            qs->proj_sig_skipped += pp->proj_sig_skipped;
            qs->proj_mask_or_ops += pp->proj_mask_or_ops;
            qs->proj_rid_iters += pp->proj_rid_iters;
            qs->proj_rid_iters_scan_enforcement += pp->proj_rid_iters_scan_enforcement;
            qs->proj_rid_iters_dependency += pp->proj_rid_iters_dependency;
            qs->canon_term_map_cache_hits += pp->canon_term_map_cache_hits;
            qs->canon_term_map_cache_misses += pp->canon_term_map_cache_misses;
            qs->canon_term_map_build_ms += pp->canon_term_map_build_ms;
            qs->canon_term_map_bytes += pp->canon_term_map_bytes;
            qs->restrict_key_index_build_ms += pp->restrict_key_index_build_ms;
            qs->restrict_key_index_entries += pp->restrict_key_index_entries;
            qs->restrict_key_index_bytes += pp->restrict_key_index_bytes;
            qs->restrict_key_prune_ms += pp->restrict_key_prune_ms;
            qs->sigmask_cache_hits += pp->sigmask_cache_hits;
            qs->sigmask_cache_misses += pp->sigmask_cache_misses;
            qs->sigmask_build_ms += pp->sigmask_build_ms;
            qs->sigmask_bytes += pp->sigmask_bytes;
            qs->bytes_sig_ctid_masks += pp->bytes_sig_ctid_masks;
            qs->bytes_block_words += pp->bytes_block_words;
            qs->bytes_artifact_buffers_retained += pp->bytes_artifact_buffers_retained;
            qs->bytes_decoded_buffers_retained += pp->bytes_decoded_buffers_retained;
            qs->qual_atoms_total += pp->qual_atoms_total;
            qs->qual_atoms_applied += pp->qual_atoms_applied;
            qs->qual_pruned_sigs += pp->qual_pruned_sigs;
            qs->qual_prune_ms += pp->qual_prune_ms;
            qs->restrict_sig_tables += pp->restrict_sig_tables;
            qs->restrict_sig_schema_cols_total += pp->restrict_sig_schema_cols_total;
            qs->restrict_sig_bytes_total += pp->restrict_sig_bytes_total;
            qs->restrict_sig_apply_ms += pp->restrict_sig_apply_ms;
            qs->restrict_term_apply_ms += pp->restrict_term_apply_ms;
            qs->restrict_term_sigs_kept += pp->restrict_term_sigs_kept;
            qs->restrict_term_sigs_dropped += pp->restrict_term_sigs_dropped;
            if (pp->prop_table_scans && pp->prop_table_scans[0]) {
                if (!qs->prop_table_scans) {
                    qs->prop_table_scans = MemoryContextStrdup(qctx, pp->prop_table_scans);
                } else {
                    size_t old_len = strlen(qs->prop_table_scans);
                    size_t add_len = strlen(pp->prop_table_scans);
                    char *merged = (char *) MemoryContextAlloc(qctx, old_len + 1 + add_len + 1);
                    memcpy(merged, qs->prop_table_scans, old_len);
                    merged[old_len] = ';';
                    memcpy(merged + old_len + 1, pp->prop_table_scans, add_len);
                    merged[old_len + 1 + add_len] = '\0';
                    qs->prop_table_scans = merged;
                }
            }
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
            uint64 cnt = 0;
            if (it && it->block_words)
                cnt = cf_popcount_block_words(it->block_words, it->blocks);
            CF_TRACE_LOG( "custom_filter: allow_%s count=%llu/%u", tname, (unsigned long long) cnt, rows);
        }
    }

    /* Build filter states from the policy engine output (already a CTID bitmap). */
    int n_filters = 0;
    if (allow_list && allow_list->count > 0)
    {
        for (int i = 0; i < allow_list->count; i++)
        {
            const PolicyTableAllowC *it = &allow_list->items[i];
            const char *tname = (it && it->table) ? it->table : NULL;
            if (!tname)
                continue;
            if (cf_table_should_filter(qs, tname))
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
    if (allow_list && allow_list->count > 0)
    {
        for (int i = 0; i < allow_list->count; i++)
        {
            const PolicyTableAllowC *it = &allow_list->items[i];
            const char *tname = (it && it->table) ? it->table : NULL;
            if (!tname)
                continue;
            if (!cf_table_should_filter(qs, tname))
                continue;
            if (!it->block_words && it->blocks > 0)
                ereport(ERROR,
                        (errmsg("custom_filter[engine_error]: missing block_words for %s", tname)));

            TableFilterState *tf = &qs->filters[fidx++];
            qs->allow_build_calls++;
            memset(tf, 0, sizeof(TableFilterState));
            strlcpy(tf->relname, tname, sizeof(tf->relname));
            Oid nsp = get_namespace_oid("public", true);
            if (OidIsValid(nsp))
                tf->relid = get_relname_relid(tname, nsp);
            if (!OidIsValid(tf->relid))
                tf->relid = get_relname_relid(tname, InvalidOid);

            tf->n_rows = it->n_rows;
            tf->blocks = it->blocks;
            tf->total_blocks = it->total_blocks;
            tf->block_words_nbytes = (size_t)tf->blocks * (size_t)CF_WORDS_PER_BLOCK * sizeof(uint64);
            tf->block_ids_nbytes = (size_t)tf->blocks * sizeof(uint32);

            /* Defensive copy into query context to avoid aliasing. */
            MemoryContext old_allow_ctx = MemoryContextSwitchTo(qctx);
            uint64 *copy_words = tf->block_words_nbytes > 0 ? (uint64 *) palloc0(tf->block_words_nbytes) : NULL;
            uint32 *copy_ids = tf->block_ids_nbytes > 0 ? (uint32 *) palloc0(tf->block_ids_nbytes) : NULL;
            MemoryContextSwitchTo(old_allow_ctx);
            if (tf->block_words_nbytes > 0)
                memcpy(copy_words, it->block_words, tf->block_words_nbytes);
            if (tf->block_ids_nbytes > 0 && it->block_ids)
                memcpy(copy_ids, it->block_ids, tf->block_ids_nbytes);
            tf->block_words = copy_words;
            tf->block_ids = copy_ids;
            tf->allowed_rows = (tf->block_words && tf->blocks > 0) ? cf_popcount_block_words(tf->block_words, tf->blocks) : 0;
            tf->allow_is_empty = (tf->allowed_rows == 0);

            qs->bytes_allow += tf->block_words_nbytes + tf->block_ids_nbytes;

            CF_TRACE_LOG("custom_filter: allow_%s blocks_alloc=%u total_blocks=%u words_bytes=%zu ids_bytes=%zu",
                         tname, tf->blocks, tf->total_blocks, tf->block_words_nbytes, tf->block_ids_nbytes);
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
            if (tf->block_words)
            {
                MemoryContext mctx = GetMemoryChunkContext(tf->block_words);
                CF_TRACE_LOG(
                     "custom_filter: block_words pre_exec rel=%s count=%llu rows=%u ptr=%p blocks=%u bytes=%zu mctx=%p qctx=%p qs=%p",
                     tf->relname,
                     (unsigned long long) tf->allowed_rows,
                     tf->n_rows,
                     (void *) tf->block_words,
                     (unsigned int) tf->blocks,
                     tf->block_words_nbytes,
                     (void *) mctx,
                     (void *) qctx,
                     (void *) qs);
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
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu filter[%d] key_relid=%u rel=%s block_words=%p blocks=%u bytes=%zu n_rows=%u",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            i,
                            tf->relid,
                            tf->relname[0] ? tf->relname : "<unknown>",
                            (void *) tf->block_words,
                            (unsigned int) tf->blocks,
                            tf->block_words_nbytes,
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
            MemoryContext allow_mctx = tf->block_words ? GetMemoryChunkContext(tf->block_words) : NULL;
            CF_DEBUG_QS_LOG("pid=%d build_seq=%llu memctx rel=%s relid=%u block_words=%p mctx=%p(%s)",
                            (int) getpid(),
                            (unsigned long long) qs->build_seq,
                            tf->relname[0] ? tf->relname : "<unknown>",
                            (unsigned int) tf->relid,
                            (void *) tf->block_words,
                            (void *) allow_mctx,
                            cf_mctx_safe_name(allow_mctx));
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

    /*
     * Last resort: fetch CTID via sysattr. This can be slow; prefer tts_tid or
     * heap-tuple CTIDs above.
     */
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

static bool
cf_runtime_strict_mode_enabled(void)
{
    /*
     * Class-engine-only runtime: once the extension is enabled for a session,
     * strict routing is always active.
     */
    return true;
}

static bool
cf_query_has_empty_allow_set(const PolicyQueryState *qs, const char **table_out)
{
    if (table_out)
        *table_out = NULL;
    if (!qs || !qs->filters || qs->n_filters <= 0)
        return false;
    for (int i = 0; i < qs->n_filters; i++)
    {
        const TableFilterState *tf = &qs->filters[i];
        if (tf->allow_is_empty || tf->allowed_rows == 0 || tf->blocks == 0 || !tf->block_words)
        {
            if (table_out)
                *table_out = tf->relname[0] ? tf->relname : NULL;
            return true;
        }
    }
    return false;
}

static bool
cf_plan_inner_only_safe(Plan *plan, const char **reason_out)
{
    const char *reason = "ok";
    if (!plan)
    {
        if (reason_out)
            *reason_out = reason;
        return true;
    }

    switch (nodeTag(plan))
    {
        case T_NestLoop:
            if (((NestLoop *) plan)->join.jointype != JOIN_INNER)
            {
                reason = "not_safe_join";
                goto not_safe;
            }
            break;
        case T_MergeJoin:
            if (((MergeJoin *) plan)->join.jointype != JOIN_INNER)
            {
                reason = "not_safe_join";
                goto not_safe;
            }
            break;
        case T_HashJoin:
            if (((HashJoin *) plan)->join.jointype != JOIN_INNER)
            {
                reason = "not_safe_join";
                goto not_safe;
            }
            break;
        case T_Append:
            reason = "not_safe_append";
            goto not_safe;
        case T_MergeAppend:
            reason = "not_safe_append";
            goto not_safe;
        case T_RecursiveUnion:
            reason = "not_safe_setop";
            goto not_safe;
        case T_SetOp:
            reason = "not_safe_setop";
            goto not_safe;
        case T_SubqueryScan:
            reason = "not_safe_subquery";
            goto not_safe;
        case T_FunctionScan:
        case T_TableFuncScan:
        case T_WorkTableScan:
        case T_CteScan:
            reason = "not_safe_scan_type";
            goto not_safe;
        default:
            break;
    }

    if (!cf_plan_inner_only_safe(outerPlan(plan), reason_out))
        return false;
    if (!cf_plan_inner_only_safe(innerPlan(plan), reason_out))
        return false;

    switch (nodeTag(plan))
    {
        case T_Append:
            {
                Append *ap = (Append *) plan;
                ListCell *lc;
                foreach (lc, ap->appendplans)
                {
                    if (!cf_plan_inner_only_safe((Plan *) lfirst(lc), reason_out))
                        return false;
                }
            }
            break;
        case T_MergeAppend:
            {
                MergeAppend *ap = (MergeAppend *) plan;
                ListCell *lc;
                foreach (lc, ap->mergeplans)
                {
                    if (!cf_plan_inner_only_safe((Plan *) lfirst(lc), reason_out))
                        return false;
                }
            }
            break;
        case T_BitmapAnd:
            {
                BitmapAnd *ba = (BitmapAnd *) plan;
                ListCell *lc;
                foreach (lc, ba->bitmapplans)
                {
                    if (!cf_plan_inner_only_safe((Plan *) lfirst(lc), reason_out))
                        return false;
                }
            }
            break;
        case T_BitmapOr:
            {
                BitmapOr *bo = (BitmapOr *) plan;
                ListCell *lc;
                foreach (lc, bo->bitmapplans)
                {
                    if (!cf_plan_inner_only_safe((Plan *) lfirst(lc), reason_out))
                        return false;
                }
            }
            break;
        case T_CustomScan:
            {
                CustomScan *cs = (CustomScan *) plan;
                ListCell *lc;
                foreach (lc, cs->custom_plans)
                {
                    if (!cf_plan_inner_only_safe((Plan *) lfirst(lc), reason_out))
                        return false;
                }
            }
            break;
        default:
            break;
    }

    if (reason_out)
        *reason_out = reason;
    return true;

not_safe:
    if (reason_out)
        *reason_out = reason;
    return false;
}

static const char *
cf_scan_mode_name(CfScanMode m)
{
    switch (m)
    {
        case CF_SCAN_MODE_EMPTY:
            return "EMPTY";
        case CF_SCAN_MODE_TID:
            return "TID";
        case CF_SCAN_MODE_FILTER:
        default:
            return "FILTER";
    }
}

static void
cf_update_scan_mode(CfExec *st, CustomScanState *node, TableFilterState *tf)
{
    CfScanMode new_mode = CF_SCAN_MODE_FILTER;
    double density = 0.0;
    const char *reason = "no_filter";
    PlanState *child = st ? st->child_plan : NULL;

    if (tf)
    {
        if (tf->total_blocks > 0)
            density = (double) tf->blocks / (double) tf->total_blocks;
        else
            density = 0.0;

        if (tf->allow_is_empty || tf->allowed_rows == 0 || tf->blocks == 0 || !tf->block_words || tf->block_words_nbytes == 0)
        {
            new_mode = CF_SCAN_MODE_EMPTY;
            density = 0.0;
            reason = "empty_allow_set";
        }
        else if (!cf_tidscan_seqscan)
        {
            reason = "tidscan_disabled";
        }
        else if (!child)
        {
            reason = "no_child_plan";
        }
        else if (nodeTag(child) != T_SeqScanState)
        {
            reason = "child_not_seqscan";
        }
        else if (child->plan && child->plan->parallel_aware)
        {
            reason = "parallel_aware";
        }
        else if (tf->total_blocks == 0)
        {
            reason = "missing_total_blocks";
        }
        else if (density < cf_tidscan_density_threshold)
        {
            new_mode = CF_SCAN_MODE_TID;
            reason = "sparse_tid";
        }
        else
        {
            reason = "density_high";
        }
    }

    if (!st)
        return;

    if (!st->scan_mode_set || st->scan_mode != new_mode)
    {
        st->scan_mode = new_mode;
        st->scan_mode_set = true;
        st->tid_iter_initialized = false;
        st->tid_iter_block_ord = 0;
        st->tid_iter_word_idx = 0;
        st->tid_iter_bit_min = 0;
    }
    st->scan_mode_density = density;

    if (!st->scan_mode_logged && tf && cf_profile_query && cf_profile_query[0])
    {
        elog(NOTICE,
             "scan_mode_decision: rel=%s mode=%s allow_rows=%llu allow_blocks=%u relpages=%u density=%.6f reason=%s scan=%s",
             st->relname[0] ? st->relname : "<unknown>",
             cf_scan_mode_name(st->scan_mode),
             (unsigned long long) tf->allowed_rows,
             (unsigned int) tf->blocks,
             (unsigned int) tf->total_blocks,
             st->scan_mode_density,
             reason,
             st->scan_type ? st->scan_type : "<unknown>");
        st->scan_mode_logged = true;
    }
    (void) node;
}

static bool
cf_tid_iter_next(CfExec *st, TableFilterState *tf, ItemPointerData *out_tid)
{
    if (!st || !tf || !tf->block_words || !out_tid)
        return false;
    if (!st->tid_iter_initialized)
    {
        st->tid_iter_initialized = true;
        st->tid_iter_block_ord = 0;
        st->tid_iter_word_idx = 0;
        st->tid_iter_bit_min = 0;
    }

    while (st->tid_iter_block_ord < tf->blocks)
    {
        const uint64 *bw = tf->block_words + (size_t) st->tid_iter_block_ord * (size_t) CF_WORDS_PER_BLOCK;
        BlockNumber blk = (BlockNumber) (tf->block_ids ? tf->block_ids[st->tid_iter_block_ord] : st->tid_iter_block_ord);

        if (st->tid_iter_word_idx == 0 && st->tid_iter_bit_min == 0)
            st->tid_blocks_visited++;

        while (st->tid_iter_word_idx < CF_WORDS_PER_BLOCK)
        {
            uint64 w = bw[st->tid_iter_word_idx];
            if (st->tid_iter_bit_min > 0 && st->tid_iter_bit_min < 64)
                w &= ~((1ULL << st->tid_iter_bit_min) - 1ULL);
            else if (st->tid_iter_bit_min >= 64)
                w = 0;

            if (w != 0)
            {
                uint32 bit = (uint32) __builtin_ctzll(w);
                uint32 off0 = st->tid_iter_word_idx * 64u + bit;
                OffsetNumber off = (OffsetNumber) (off0 + 1u);
                ItemPointerSet(out_tid, blk, off);
                st->tid_iter_bit_min = bit + 1u;
                if (st->tid_iter_bit_min >= 64u)
                {
                    st->tid_iter_word_idx++;
                    st->tid_iter_bit_min = 0;
                }
                return true;
            }
            st->tid_iter_word_idx++;
            st->tid_iter_bit_min = 0;
        }

        st->tid_iter_block_ord++;
        st->tid_iter_word_idx = 0;
        st->tid_iter_bit_min = 0;
    }
    return false;
}

static TupleTableSlot *
cf_exec_seqscan_tid_mode(CustomScanState *node, CfExec *st, TableFilterState *tf)
{
    PlanState *child = st->child_plan;
    ScanState *ss = (ScanState *) child;
    TupleTableSlot *scan_slot = ss->ss_ScanTupleSlot;
    EState *estate = node->ss.ps.state;
    Snapshot snap = estate ? estate->es_snapshot : InvalidSnapshot;

    if (!ss->ss_currentRelation || !scan_slot || !snap)
        ereport(ERROR,
                (errmsg("custom_filter: SeqScan TID mode missing relation/slot/snapshot (rel=%s)",
                        st->relname[0] ? st->relname : "<unknown>")));

    for (;;)
    {
        ItemPointerData tid;
        instr_time fetch_start, fetch_end;
        instr_time qual_start, qual_end;
        TupleTableSlot *slot;
        ExprContext *econtext;
        bool qual_ok = true;

        if (!cf_tid_iter_next(st, tf, &tid))
            return ExecClearTuple(node->ss.ss_ScanTupleSlot);

        INSTR_TIME_SET_CURRENT(fetch_start);
        ExecClearTuple(scan_slot);
        if (!table_tuple_fetch_row_version(ss->ss_currentRelation, &tid, snap, scan_slot))
        {
            INSTR_TIME_SET_CURRENT(fetch_end);
            st->tid_fetch_ms += INSTR_TIME_GET_MILLISEC(fetch_end) - INSTR_TIME_GET_MILLISEC(fetch_start);
            continue;
        }
        INSTR_TIME_SET_CURRENT(fetch_end);
        st->tid_fetch_ms += INSTR_TIME_GET_MILLISEC(fetch_end) - INSTR_TIME_GET_MILLISEC(fetch_start);
        st->tid_tuples_fetched++;
        st->tuples_seen++;
        if (tf)
            tf->seen++;

        INSTR_TIME_SET_CURRENT(qual_start);
        econtext = child->ps_ExprContext;
        if (econtext)
            ResetExprContext(econtext);
        if (child->qual)
        {
            if (!econtext)
                econtext = CreateExprContext(child->state);
            econtext->ecxt_scantuple = scan_slot;
            qual_ok = ExecQual(child->qual, econtext);
        }
        if (!qual_ok)
        {
            INSTR_TIME_SET_CURRENT(qual_end);
            st->tid_qual_ms += INSTR_TIME_GET_MILLISEC(qual_end) - INSTR_TIME_GET_MILLISEC(qual_start);
            continue;
        }
        slot = scan_slot;
        if (child->ps_ProjInfo)
        {
            if (!econtext)
                econtext = child->ps_ExprContext;
            if (!econtext)
                econtext = CreateExprContext(child->state);
            econtext->ecxt_scantuple = scan_slot;
            slot = ExecProject(child->ps_ProjInfo);
        }
        INSTR_TIME_SET_CURRENT(qual_end);
        st->tid_qual_ms += INSTR_TIME_GET_MILLISEC(qual_end) - INSTR_TIME_GET_MILLISEC(qual_start);

        st->tuples_passed++;
        if (tf)
            tf->passed++;
        return slot;
    }
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

typedef struct WrapperAuditCtx
{
    PlannedStmt *pstmt;
    int total_wrappers;
    int main_wrappers;
    int subplan_wrappers;
    int detail_count;
    StringInfo details;
} WrapperAuditCtx;

static void
cf_wrapper_audit_append(WrapperAuditCtx *ctx, CustomScan *cs, bool in_subplan, int subplan_idx)
{
    if (!ctx || !cs || !ctx->pstmt)
        return;

    int scanrelid = (int) cs->scan.scanrelid;
    Oid relid = InvalidOid;
    const char *relname = "<none>";
    const char *alias = "<none>";

    if (scanrelid > 0)
    {
        RangeTblEntry *rte = rt_fetch((Index) scanrelid, ctx->pstmt->rtable);
        if (rte)
        {
            relid = rte->relid;
            if (relid != InvalidOid)
            {
                const char *rn = get_rel_name(relid);
                if (rn)
                    relname = rn;
            }
            if (rte->eref && rte->eref->aliasname)
                alias = rte->eref->aliasname;
        }
    }

    ctx->total_wrappers++;
    if (in_subplan)
        ctx->subplan_wrappers++;
    else
        ctx->main_wrappers++;

    if (ctx->detail_count < 128)
    {
        appendStringInfo(ctx->details,
                         "%s{scanrelid=%d relid=%u rel=%s alias=%s subplan=%d subplan_idx=%d}",
                         (ctx->detail_count == 0 ? "" : ";"),
                         scanrelid,
                         relid,
                         relname,
                         alias,
                         in_subplan ? 1 : 0,
                         subplan_idx);
        ctx->detail_count++;
    }
}

static void
cf_wrapper_audit_walk(Plan *plan, WrapperAuditCtx *ctx, bool in_subplan, int subplan_idx)
{
    if (!plan || !ctx)
        return;

    if (IsA(plan, CustomScan))
    {
        CustomScan *cs = (CustomScan *) plan;
        if (cs->methods && cs->methods->CustomName &&
            strcmp(cs->methods->CustomName, "CustomFilterScan") == 0)
        {
            cf_wrapper_audit_append(ctx, cs, in_subplan, subplan_idx);
        }
        if (cs->custom_plans)
        {
            ListCell *lc;
            foreach (lc, cs->custom_plans)
                cf_wrapper_audit_walk((Plan *) lfirst(lc), ctx, in_subplan, subplan_idx);
        }
    }

    if (plan->lefttree)
        cf_wrapper_audit_walk(plan->lefttree, ctx, in_subplan, subplan_idx);
    if (plan->righttree)
        cf_wrapper_audit_walk(plan->righttree, ctx, in_subplan, subplan_idx);

    switch (nodeTag(plan))
    {
        case T_Append:
            {
                Append *a = (Append *) plan;
                ListCell *lc;
                foreach (lc, a->appendplans)
                    cf_wrapper_audit_walk((Plan *) lfirst(lc), ctx, in_subplan, subplan_idx);
            }
            break;
        case T_MergeAppend:
            {
                MergeAppend *ma = (MergeAppend *) plan;
                ListCell *lc;
                foreach (lc, ma->mergeplans)
                    cf_wrapper_audit_walk((Plan *) lfirst(lc), ctx, in_subplan, subplan_idx);
            }
            break;
        case T_BitmapAnd:
            {
                BitmapAnd *ba = (BitmapAnd *) plan;
                ListCell *lc;
                foreach (lc, ba->bitmapplans)
                    cf_wrapper_audit_walk((Plan *) lfirst(lc), ctx, in_subplan, subplan_idx);
            }
            break;
        case T_BitmapOr:
            {
                BitmapOr *bo = (BitmapOr *) plan;
                ListCell *lc;
                foreach (lc, bo->bitmapplans)
                    cf_wrapper_audit_walk((Plan *) lfirst(lc), ctx, in_subplan, subplan_idx);
            }
            break;
        case T_SubqueryScan:
            {
                SubqueryScan *sq = (SubqueryScan *) plan;
                cf_wrapper_audit_walk(sq->subplan, ctx, in_subplan, subplan_idx);
            }
            break;
        case T_ModifyTable:
            break;
        default:
            break;
    }
}

static void
cf_log_wrapper_audit(PlannedStmt *pstmt)
{
    if (!cf_debug_ids || !pstmt || !pstmt->planTree)
        return;

    StringInfoData details;
    initStringInfo(&details);
    WrapperAuditCtx ctx;
    ctx.pstmt = pstmt;
    ctx.total_wrappers = 0;
    ctx.main_wrappers = 0;
    ctx.subplan_wrappers = 0;
    ctx.detail_count = 0;
    ctx.details = &details;

    cf_wrapper_audit_walk(pstmt->planTree, &ctx, false, -1);
    if (pstmt->subplans)
    {
        int spidx = 0;
        ListCell *lc;
        foreach (lc, pstmt->subplans)
        {
            cf_wrapper_audit_walk((Plan *) lfirst(lc), &ctx, true, spidx);
            spidx++;
        }
    }

    CF_DEBUG_SUBPLAN_LOG("wrapper_audit custom_scans=%d main=%d subplan=%d details=%s",
                         ctx.total_wrappers,
                         ctx.main_wrappers,
                         ctx.subplan_wrappers,
                         details.len > 0 ? details.data : "<none>");
    pfree(details.data);
}

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

typedef struct CfScanQualTmpAtom
{
    Oid relid;
    char *target_table;
    int kind;                /* PolicyScanQualKindC */
    char *lhs_schema_key;
    int op;                  /* PolicyConstOpC */
    char *rhs_schema_key;    /* same-table col-col only */
    char *const_value;       /* col-const only */
} CfScanQualTmpAtom;

typedef struct CfSeqQualEntry
{
    Oid relid;
    char *relname;
    int seqscan_count;
    List *atoms; /* CfScanQualTmpAtom* */
} CfSeqQualEntry;

typedef struct CfSeqQualCtx
{
    PlannedStmt *pstmt;
    MemoryContext mcxt;
    List *entries; /* CfSeqQualEntry* */
} CfSeqQualCtx;

static Node *
cf_strip_relabel_node(Node *n)
{
    for (;;)
    {
        if (n == NULL)
            return NULL;
        if (IsA(n, RelabelType))
        {
            n = (Node *) ((RelabelType *) n)->arg;
            continue;
        }
        return n;
    }
}

static int
cf_map_policy_op_from_name(const char *opname)
{
    if (!opname)
        return 0;
    if (strcmp(opname, "=") == 0)
        return POLICY_OP_EQ;
    if (strcmp(opname, "<>") == 0 || strcmp(opname, "!=") == 0)
        return POLICY_OP_NE;
    if (strcmp(opname, "<") == 0)
        return POLICY_OP_LT;
    if (strcmp(opname, "<=") == 0)
        return POLICY_OP_LE;
    if (strcmp(opname, ">") == 0)
        return POLICY_OP_GT;
    if (strcmp(opname, ">=") == 0)
        return POLICY_OP_GE;
    return 0;
}

static int
cf_flip_policy_op(int op)
{
    switch (op)
    {
        case POLICY_OP_LT: return POLICY_OP_GT;
        case POLICY_OP_LE: return POLICY_OP_GE;
        case POLICY_OP_GT: return POLICY_OP_LT;
        case POLICY_OP_GE: return POLICY_OP_LE;
        default: return op;
    }
}

static char *
cf_const_text_value(Const *c, MemoryContext mcxt)
{
    if (!c || c->constisnull)
        return NULL;
    Oid typoutput = InvalidOid;
    bool typisvarlena = false;
    getTypeOutputInfo(c->consttype, &typoutput, &typisvarlena);
    char *out = OidOutputFunctionCall(typoutput, c->constvalue);
    if (!out)
        return NULL;
    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    char *copy = pstrdup(out);
    MemoryContextSwitchTo(oldctx);
    return copy;
}

static bool
cf_var_schema_key(Var *v,
                  Index expected_scanrelid,
                  Oid expected_relid,
                  PlannedStmt *pstmt,
                  MemoryContext mcxt,
                  char **out_schema_key,
                  char **out_relname)
{
    Index vscan = 0;
    AttrNumber vatt = InvalidAttrNumber;
    if (!v || !pstmt || !out_schema_key)
        return false;
    if (v->varlevelsup != 0)
        return false;
    vscan = (Index) v->varno;
    if (vscan != expected_scanrelid)
    {
        if (v->varnosyn > 0 && (Index) v->varnosyn == expected_scanrelid)
            vscan = (Index) v->varnosyn;
        else
            return false;
    }
    vatt = v->varattno;
    if (vatt <= 0 && v->varattnosyn > 0)
        vatt = v->varattnosyn;
    if (vatt <= 0)
        return false;
    Oid relid = InvalidOid;
    if (!cf_relid_is_relation(pstmt, vscan, &relid))
        return false;
    if (expected_relid != InvalidOid && relid != expected_relid)
        return false;
    const char *rn = get_rel_name(relid);
    const char *att = get_attname(relid, vatt, false);
    if (!rn || !att)
        return false;
    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    *out_schema_key = psprintf("%s.%s", rn, att);
    if (out_relname)
        *out_relname = pstrdup(rn);
    MemoryContextSwitchTo(oldctx);
    return true;
}

static CfSeqQualEntry *
cf_seqqual_entry_get(CfSeqQualCtx *ctx, Oid relid, const char *relname)
{
    ListCell *lc;
    foreach (lc, ctx->entries)
    {
        CfSeqQualEntry *e = (CfSeqQualEntry *) lfirst(lc);
        if (e && e->relid == relid)
            return e;
    }
    MemoryContext oldctx = MemoryContextSwitchTo(ctx->mcxt);
    CfSeqQualEntry *e = (CfSeqQualEntry *) palloc0(sizeof(CfSeqQualEntry));
    e->relid = relid;
    e->relname = relname ? pstrdup(relname) : NULL;
    e->seqscan_count = 0;
    e->atoms = NIL;
    ctx->entries = lappend(ctx->entries, e);
    MemoryContextSwitchTo(oldctx);
    return e;
}

static void
cf_seqqual_append_atom(CfSeqQualEntry *entry, CfScanQualTmpAtom *atom)
{
    if (!entry || !atom)
        return;
    entry->atoms = lappend(entry->atoms, atom);
}

static void
cf_collect_seqscan_qual_expr(Node *expr,
                             CfSeqQualEntry *entry,
                             Index scanrelid,
                             Oid relid,
                             PlannedStmt *pstmt,
                             MemoryContext mcxt)
{
    if (!expr || !entry || !pstmt)
        return;

    expr = cf_strip_relabel_node(expr);
    if (!expr)
        return;

    if (IsA(expr, BoolExpr))
    {
        BoolExpr *b = (BoolExpr *) expr;
        if (b->boolop == AND_EXPR)
        {
            ListCell *lc;
            foreach (lc, b->args)
                cf_collect_seqscan_qual_expr((Node *) lfirst(lc), entry, scanrelid, relid, pstmt, mcxt);
        }
        return;
    }

    if (!IsA(expr, OpExpr))
        return;

    OpExpr *op = (OpExpr *) expr;
    if (list_length(op->args) != 2)
        return;
    const char *opname = get_opname(op->opno);
    int pop = cf_map_policy_op_from_name(opname);
    if (pop == 0)
        return;

    Node *a0 = cf_strip_relabel_node((Node *) linitial(op->args));
    Node *a1 = cf_strip_relabel_node((Node *) lsecond(op->args));
    if (!a0 || !a1)
        return;

    Var *v_lhs = NULL;
    Var *v_rhs = NULL;
    Const *c_lhs = NULL;
    Const *c_rhs = NULL;
    if (IsA(a0, Var)) v_lhs = (Var *) a0;
    if (IsA(a1, Var)) v_rhs = (Var *) a1;
    if (IsA(a0, Const)) c_lhs = (Const *) a0;
    if (IsA(a1, Const)) c_rhs = (Const *) a1;

    if (v_lhs && c_rhs)
    {
        char *lhs_key = NULL;
        if (!cf_var_schema_key(v_lhs, scanrelid, relid, pstmt, mcxt, &lhs_key, NULL))
            return;
        char *cval = cf_const_text_value(c_rhs, mcxt);
        if (!cval)
            return;
        MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
        CfScanQualTmpAtom *a = (CfScanQualTmpAtom *) palloc0(sizeof(CfScanQualTmpAtom));
        a->relid = relid;
        a->target_table = pstrdup(entry->relname);
        a->kind = POLICY_SCAN_QUAL_COL_CONST;
        a->lhs_schema_key = lhs_key;
        a->op = pop;
        a->const_value = cval;
        MemoryContextSwitchTo(oldctx);
        cf_seqqual_append_atom(entry, a);
        return;
    }
    if (c_lhs && v_rhs)
    {
        char *lhs_key = NULL;
        if (!cf_var_schema_key(v_rhs, scanrelid, relid, pstmt, mcxt, &lhs_key, NULL))
            return;
        char *cval = cf_const_text_value(c_lhs, mcxt);
        if (!cval)
            return;
        MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
        CfScanQualTmpAtom *a = (CfScanQualTmpAtom *) palloc0(sizeof(CfScanQualTmpAtom));
        a->relid = relid;
        a->target_table = pstrdup(entry->relname);
        a->kind = POLICY_SCAN_QUAL_COL_CONST;
        a->lhs_schema_key = lhs_key;
        a->op = cf_flip_policy_op(pop);
        a->const_value = cval;
        MemoryContextSwitchTo(oldctx);
        cf_seqqual_append_atom(entry, a);
        return;
    }
    if (v_lhs && v_rhs)
    {
        char *lhs_key = NULL;
        char *rhs_key = NULL;
        if (!cf_var_schema_key(v_lhs, scanrelid, relid, pstmt, mcxt, &lhs_key, NULL))
            return;
        if (!cf_var_schema_key(v_rhs, scanrelid, relid, pstmt, mcxt, &rhs_key, NULL))
            return;
        MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
        CfScanQualTmpAtom *a = (CfScanQualTmpAtom *) palloc0(sizeof(CfScanQualTmpAtom));
        a->relid = relid;
        a->target_table = pstrdup(entry->relname);
        a->kind = POLICY_SCAN_QUAL_COL_COL;
        a->lhs_schema_key = lhs_key;
        a->op = pop;
        a->rhs_schema_key = rhs_key;
        MemoryContextSwitchTo(oldctx);
        cf_seqqual_append_atom(entry, a);
        return;
    }
}

static void
cf_plan_collect_seqscan_quals(Plan *plan, CfSeqQualCtx *ctx)
{
    if (!plan || !ctx)
        return;

    if (IsA(plan, CustomScan))
    {
        CustomScan *cs = (CustomScan *) plan;
        if (cs->custom_plans)
        {
            ListCell *lc;
            foreach (lc, cs->custom_plans)
                cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), ctx);
        }
    }

    if (nodeTag(plan) == T_SeqScan)
    {
        Index scanrelid = ((Scan *) plan)->scanrelid;
        Oid relid = InvalidOid;
        if (cf_relid_is_relation(ctx->pstmt, scanrelid, &relid))
        {
            const char *rn = get_rel_name(relid);
            CfSeqQualEntry *entry = cf_seqqual_entry_get(ctx, relid, rn);
            entry->seqscan_count++;
            if (plan->qual)
            {
                ListCell *lc;
                foreach (lc, plan->qual)
                    cf_collect_seqscan_qual_expr((Node *) lfirst(lc),
                                                entry,
                                                scanrelid,
                                                relid,
                                                ctx->pstmt,
                                                ctx->mcxt);
            }
        }
    }

    if (plan->lefttree)
        cf_plan_collect_seqscan_quals(plan->lefttree, ctx);
    if (plan->righttree)
        cf_plan_collect_seqscan_quals(plan->righttree, ctx);

    switch (nodeTag(plan))
    {
        case T_Append:
            {
                Append *a = (Append *) plan;
                ListCell *lc;
                foreach (lc, a->appendplans)
                    cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_MergeAppend:
            {
                MergeAppend *ma = (MergeAppend *) plan;
                ListCell *lc;
                foreach (lc, ma->mergeplans)
                    cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_BitmapAnd:
            {
                BitmapAnd *ba = (BitmapAnd *) plan;
                ListCell *lc;
                foreach (lc, ba->bitmapplans)
                    cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_BitmapOr:
            {
                BitmapOr *bo = (BitmapOr *) plan;
                ListCell *lc;
                foreach (lc, bo->bitmapplans)
                    cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), ctx);
            }
            break;
        case T_SubqueryScan:
            {
                SubqueryScan *sq = (SubqueryScan *) plan;
                cf_plan_collect_seqscan_quals(sq->subplan, ctx);
            }
            break;
        default:
            break;
    }
}

static void
cf_collect_seqscan_qual_atoms(EState *estate,
                              const PolicyEvalResultC *eval_res,
                              MemoryContext mcxt,
                              PolicyScanQualAtomC **out_atoms,
                              int *out_count)
{
    if (out_atoms) *out_atoms = NULL;
    if (out_count) *out_count = 0;
    if (!estate || !estate->es_plannedstmt || !eval_res || eval_res->target_count <= 0 || !out_atoms || !out_count)
        return;

    CfSeqQualCtx ctx;
    ctx.pstmt = estate->es_plannedstmt;
    ctx.mcxt = mcxt;
    ctx.entries = NIL;
    cf_plan_collect_seqscan_quals(estate->es_plannedstmt->planTree, &ctx);
    if (estate->es_plannedstmt->subplans)
    {
        ListCell *lc;
        foreach (lc, estate->es_plannedstmt->subplans)
            cf_plan_collect_seqscan_quals((Plan *) lfirst(lc), &ctx);
    }

    int total = 0;
    ListCell *lc;
    foreach (lc, ctx.entries)
    {
        CfSeqQualEntry *e = (CfSeqQualEntry *) lfirst(lc);
        if (!e || !e->relname || e->seqscan_count != 1)
            continue;
        if (!cf_table_in_list(e->relname, eval_res->target_tables, eval_res->target_count))
            continue;
        total += list_length(e->atoms);
    }
    if (total <= 0)
        return;

    MemoryContext oldctx = MemoryContextSwitchTo(mcxt);
    PolicyScanQualAtomC *atoms = (PolicyScanQualAtomC *) palloc0(sizeof(PolicyScanQualAtomC) * total);
    MemoryContextSwitchTo(oldctx);

    int idx = 0;
    foreach (lc, ctx.entries)
    {
        CfSeqQualEntry *e = (CfSeqQualEntry *) lfirst(lc);
        if (!e || !e->relname || e->seqscan_count != 1)
            continue;
        if (!cf_table_in_list(e->relname, eval_res->target_tables, eval_res->target_count))
            continue;
        ListCell *la;
        foreach (la, e->atoms)
        {
            CfScanQualTmpAtom *a = (CfScanQualTmpAtom *) lfirst(la);
            if (!a || !a->target_table || !a->lhs_schema_key || a->op == 0)
                continue;
            atoms[idx].target_table = a->target_table;
            atoms[idx].kind = a->kind;
            atoms[idx].lhs_schema_key = a->lhs_schema_key;
            atoms[idx].op = a->op;
            atoms[idx].rhs_schema_key = a->rhs_schema_key;
            atoms[idx].const_value = a->const_value;
            idx++;
        }
    }
    *out_atoms = atoms;
    *out_count = idx;
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
    st->validated_filter = NULL;
    st->validated_build_seq = 0;
    st->need_filter_rebind = true;
    st->bound_build_seq = 0;
    st->attempted_filter_rebuild = false;
    st->rescan_calls = 0;
    st->exec_logged = false;
    st->debug_exec_logged = false;
    st->blk_cache_valid = false;
    st->blk_cache_blkno = InvalidBlockNumber;
    st->blk_cache_present = false;
    st->blk_cache_words = NULL;
    st->scan_mode_set = false;
    st->scan_mode_density = 1.0;
    st->scan_mode_logged = false;
    st->tid_iter_initialized = false;
    st->tid_iter_block_ord = 0;
    st->tid_iter_word_idx = 0;
    st->tid_iter_bit_min = 0;
    st->blocks_seen = 0;
    st->blocks_skipped = 0;
    st->scan_mode = CF_SCAN_MODE_FILTER;
    st->scan_mode_set = false;
    st->scan_mode_density = 1.0;
    st->scan_mode_logged = false;
    st->tid_iter_initialized = false;
    st->tid_iter_block_ord = 0;
    st->tid_iter_word_idx = 0;
    st->tid_iter_bit_min = 0;
    st->tid_blocks_visited = 0;
    st->tid_tuples_fetched = 0;
    st->tid_fetch_ms = 0.0;
    st->tid_qual_ms = 0.0;
    st->empty_short_circuit_recorded = false;
    st->empty_short_circuit_calls = 0;
    st->empty_short_circuit_ms = 0.0;

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
    st->validated_filter = NULL;
    st->validated_build_seq = 0;
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
    {
        st->need_filter_rebind = true;
        st->validated_filter = NULL;
        st->validated_build_seq = 0;
    }

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

            st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
            st->need_filter_rebind = false;
            st->blk_cache_valid = false;
            st->blk_cache_blkno = InvalidBlockNumber;
            st->blk_cache_present = false;
            st->blk_cache_words = NULL;
            st->scan_mode_set = false;
            st->scan_mode_density = 1.0;
            st->scan_mode_logged = false;
            st->tid_iter_initialized = false;
            st->tid_iter_block_ord = 0;
            st->tid_iter_word_idx = 0;
            st->tid_iter_bit_min = 0;

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
    if (tf)
        cf_update_scan_mode(st, node, tf);
    if (tf && st->scan_mode == CF_SCAN_MODE_EMPTY)
    {
        /*
         * Exact short-circuit: policy allow-set is empty for this relation.
         * No heap access is needed; this scan always returns no rows.
         */
        instr_time e0, e1;
        INSTR_TIME_SET_CURRENT(e0);
        st->empty_short_circuit_recorded = true;
        st->empty_short_circuit_calls++;
        INSTR_TIME_SET_CURRENT(e1);
        st->empty_short_circuit_ms += INSTR_TIME_GET_MILLISEC(e1) - INSTR_TIME_GET_MILLISEC(e0);
        cf_accum_validation_time(st, &validation_start);
        return ExecClearTuple(node->ss.ss_ScanTupleSlot);
    }

    if (tf && st->scan_mode == CF_SCAN_MODE_TID)
    {
        for (;;)
        {
            instr_time proj_start, proj_end;
            TupleTableSlot *slot = cf_exec_seqscan_tid_mode(node, st, tf);
            if (TupIsNull(slot))
            {
                cf_accum_validation_time(st, &validation_start);
                return ExecClearTuple(node->ss.ss_ScanTupleSlot);
            }
            INSTR_TIME_SET_CURRENT(proj_start);
            TupleTableSlot *ret = cf_store_slot(node, slot);
            INSTR_TIME_SET_CURRENT(proj_end);
            st->projection_ms += INSTR_TIME_GET_MILLISEC(proj_end) - INSTR_TIME_GET_MILLISEC(proj_start);
            cf_accum_validation_time(st, &validation_start);
            return ret;
        }
    }

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
        if (tf && tf->block_words)
        {
            TupleTableSlot *ctid_slot = slot;
            ItemPointerData tid_buf;
            CfTidSource tid_src = CF_TID_NONE;
            bool has_tid = false;
            instr_time ctid_extract_start, ctid_extract_end;
            INSTR_TIME_SET_CURRENT(ctid_extract_start);
            if (ItemPointerIsValid(&slot->tts_tid))
            {
                tid_buf = slot->tts_tid;
                tid_src = CF_TID_TTS;
                has_tid = true;
            }
            else if (nodeTag(child) == T_BitmapHeapScanState)
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
                if (ctid_slot && ItemPointerIsValid(&ctid_slot->tts_tid))
                {
                    tid_buf = ctid_slot->tts_tid;
                    tid_src = CF_TID_TTS;
                    has_tid = true;
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
            BlockNumber blk = 0;
            OffsetNumber off = 0;
            blk  = ItemPointerGetBlockNumber(&tid_buf);
            off = ItemPointerGetOffsetNumber(&tid_buf);
            instr_time allow_start, allow_end;
            INSTR_TIME_SET_CURRENT(allow_start);
            if (!st->blk_cache_valid || st->blk_cache_blkno != blk)
            {
                st->blk_cache_valid = true;
                st->blk_cache_blkno = blk;
                st->blk_cache_words = cf_lookup_block_words(tf->block_words,
                                                            tf->block_ids,
                                                            tf->blocks,
                                                            tf->total_blocks,
                                                            blk);
                st->blk_cache_present = (st->blk_cache_words != NULL);
                st->blocks_seen++;
                if (!st->blk_cache_present)
                    st->blocks_skipped++;
            }
            if (!st->blk_cache_present)
            {
                allow = false;
            }
            else if (off < 1 || off > CF_MAX_OFF)
            {
                allow = false;
            }
            else
            {
                uint32 off0 = (uint32) off - 1u;
                size_t word_idx = (size_t) (off0 >> 6);
                uint64 mask = 1ULL << (off0 & 63u);
                allow = (st->blk_cache_words[word_idx] & mask) != 0;
            }
            INSTR_TIME_SET_CURRENT(allow_end);
            st->allow_check_ms += INSTR_TIME_GET_MILLISEC(allow_end) -
                                  INSTR_TIME_GET_MILLISEC(allow_start);
        }
        else if (tf && !tf->block_words && tf->blocks > 0)
        {
            /*
             * Robustness: if a scan state captured a stale filter pointer (e.g. due
             * to query-state being rebuilt), try to rebind and, if needed, force a
             * rebuild once so we either recover or fail with useful context.
             */
            TableFilterState *reb = cf_query_state ? cf_find_filter(cf_query_state, st->relid, true) : NULL;
            if (reb && reb->block_words)
            {
                st->filter = reb;
                st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
                tf = reb;
                st->blk_cache_valid = false;
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
                if (reb && reb->block_words)
                {
                    st->filter = reb;
                    st->bound_build_seq = cf_query_state ? cf_query_state->build_seq : 0;
                    tf = reb;
                    st->blk_cache_valid = false;
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
                     "custom_filter: missing_block_words_debug qs=%p build_seq=%llu st=%p rel=%s relid=%u tf=%p "
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
                             "custom_filter: missing_block_words_debug key[%d] rel=%s relid=%u block_words=%p blocks=%u bytes=%zu rows=%u",
                             i,
                             k->relname[0] ? k->relname : "<unknown>",
                             k->relid,
                             (void *) k->block_words,
                             (unsigned int) k->blocks,
                             k->block_words_nbytes,
                             k->n_rows);
                    }
                }
            }

            if (cf_debug_ids)
            {
                cf_debug_log_scan_ids("MissingBlockWords", st, node);
                PolicyQueryState *qs = cf_query_state;
                if (qs)
                {
                    CF_DEBUG_IDS_LOG("pid=%d build_seq=%llu missing_block_words_state qs=%p n_filters=%d n_policy_targets=%d",
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
                            CF_DEBUG_IDS_LOG("pid=%d build_seq=%llu key[%d] rel=%s relid=%u block_words=%p blocks=%u bytes=%zu n_rows=%u",
                                             (int) getpid(),
                                             (unsigned long long) qs->build_seq,
                                             i,
                                             k->relname[0] ? k->relname : "<unknown>",
                                             k->relid,
                                             (void *) k->block_words,
                                             (unsigned int) k->blocks,
                                             k->block_words_nbytes,
                                             k->n_rows);
                        }
                    }
                }
            }

            ereport(ERROR,
                    (errmsg("custom_filter[engine_error]: missing block_words for policy-required table rel=%s",
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

    /* Contract-mode allow-bit canary checks removed (filter is now a CTID bitmap). */

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
        cf_query_state->blocks_seen += st->blocks_seen;
        cf_query_state->blocks_skipped += st->blocks_skipped;
        if (st->filter)
        {
            if (st->scan_mode == CF_SCAN_MODE_EMPTY)
                cf_query_state->scan_mode_empty_tables++;
            else if (st->scan_mode == CF_SCAN_MODE_TID)
                cf_query_state->scan_mode_tid_tables++;
            else
                cf_query_state->scan_mode_filter_tables++;
        }
        cf_query_state->tid_blocks_visited += st->tid_blocks_visited;
        cf_query_state->tid_tuples_fetched += st->tid_tuples_fetched;
        cf_query_state->tid_fetch_ms += st->tid_fetch_ms;
        cf_query_state->tid_qual_ms += st->tid_qual_ms;
        if (st->empty_short_circuit_recorded)
            cf_query_state->empty_short_circuit_tables++;
        cf_query_state->empty_short_circuit_ms += st->empty_short_circuit_ms;
    }
}

void
cf_rescan(CustomScanState *node)
{
    CfExec *st = (CfExec *) node;

    if (cf_query_state)
        cf_filters_guard_check(cf_query_state, "ReScanCustomScan");

    if (st->child_plan)
    {
        /*
         * If policy allow-set is empty for this table, this scan always returns
         * NULL. Avoid rescanning the child plan on every upstream rescan.
         */
        if (!(st->filter && st->filter->allow_is_empty))
            ExecReScan(st->child_plan);
    }

    st->seq_rid = 0;
    /*
     * EMPTY-mode scans are invariant under rescans while query-state build_seq
     * is unchanged. Keep bindings/mode stable to avoid per-rescan rebinding cost.
     */
    if (st->filter && st->filter->allow_is_empty &&
        cf_query_state && st->bound_build_seq == cf_query_state->build_seq)
    {
        st->scan_mode = CF_SCAN_MODE_EMPTY;
        st->scan_mode_set = true;
        st->scan_mode_density = 0.0;
        st->tid_iter_initialized = false;
        st->tid_iter_block_ord = 0;
        st->tid_iter_word_idx = 0;
        st->tid_iter_bit_min = 0;
        st->blk_cache_valid = false;
        st->blk_cache_blkno = InvalidBlockNumber;
        st->blk_cache_present = false;
        st->blk_cache_words = NULL;
        st->need_filter_rebind = false;
    }
    else
    {
        st->blk_cache_valid = false;
        st->blk_cache_blkno = InvalidBlockNumber;
        st->blk_cache_present = false;
        st->blk_cache_words = NULL;
        st->scan_mode_set = false;
        st->scan_mode_density = 1.0;
        st->scan_mode_logged = false;
        st->tid_iter_initialized = false;
        st->tid_iter_block_ord = 0;
        st->tid_iter_word_idx = 0;
        st->tid_iter_bit_min = 0;
        st->need_filter_rebind = true;
        st->validated_filter = NULL;
        st->validated_build_seq = 0;
    }
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

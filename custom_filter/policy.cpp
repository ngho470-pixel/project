#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <cvc5/cvc5.h>

extern "C" {
#include "postgres.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/palloc.h"
}

#include "policy_evaluator.h"

using Clock = std::chrono::steady_clock;
using Ms = std::chrono::duration<double, std::milli>;

namespace {

static constexpr uint32 kMaxOff = 512u;
static constexpr uint32 kWordsPerBlock = (kMaxOff + 63u) / 64u;

extern "C" {

typedef struct PolicyArtifactC {
    const char *name;
    const void *data;
    size_t len;
} PolicyArtifactC;

typedef struct PolicyTableAllowC {
    const char *table;
    uint64 *block_words;
    uint32 *block_ids;
    uint32 blocks;
    uint32 total_blocks;
    uint32 n_rows;
    uint64 allowed_rows;
    uint32 allowed_sids;
    uint32 total_sids;
    double hub_prop_ms;
    double sat_ms;
    double sid_build_ms;
    int mode_hint;
    const char *mode_reason;
} PolicyTableAllowC;

typedef struct PolicyAllowListC {
    int count;
    PolicyTableAllowC *items;
} PolicyAllowListC;

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
    double build_hubs_ms;
    double composite_stamp_ms;
    double build_context_ms;
    double signature_build_ms;
    double sat_ms;
    double project_allowset_ms;
    double prop_build_arcs_ms;
    double prop_ac_ms;
    double prop_scc_ms;
    double prop_bin_catalog_ms;
    double prop_witness_ms;
    double prop_cmp_ms;
    double semantic_dedup_ms;
    double candidate_prune_ms;
    double sig_const_fold_ms;
    uint64 allow_cache_hit;
    uint64 allow_cache_miss;
    double allow_cache_build_ms;
    uint64 bin_build_rows_scanned;
    uint64 bin_count_final;
    double bin_build_avg_probe_len;
    uint64 bin_build_max_probe_len;
    uint64 bin_build_rehash_count;
    uint64 bin_build_hub_count;
    uint64 bin_build_local_atom_count;
    uint64 bin_build_extra_count;
} PolicyRunProfileC;

enum PolicyModeHint {
    POLICY_MODE_HINT_FILTER = 0,
    POLICY_MODE_HINT_TID = 1,
    POLICY_MODE_HINT_EMPTY = 2,
    POLICY_MODE_HINT_ALL = 3
};

} // extern "C"

struct BuildProfile {
    double artifact_parse_ms = 0.0;
    double atoms_ms = 0.0;
    double stamp_ms = 0.0;
    double local_sat_ms = 0.0;
    double propagate_ms = 0.0;
    double project_ms = 0.0;
    double decode_ms = 0.0;
    double bin_ms = 0.0;
    double policy_total_ms = 0.0;
    double build_hubs_ms = 0.0;
    double composite_stamp_ms = 0.0;
    double build_context_ms = 0.0;
    double prop_build_arcs_ms = 0.0;
    double prop_ac_ms = 0.0;
    double prop_scc_ms = 0.0;
    double prop_bin_catalog_ms = 0.0;
    double prop_witness_ms = 0.0;
    double prop_cmp_ms = 0.0;
    double semantic_dedup_ms = 0.0;
    double candidate_prune_ms = 0.0;
    double sig_const_fold_ms = 0.0;
    double signature_build_ms = 0.0;
    double sat_ms = 0.0;
    double project_allowset_ms = 0.0;
    double allow_cache_build_ms = 0.0;
    double prop_index_build_ms = 0.0;
    double prop_rel_build_ms = 0.0;
    double prop_ac_delta_ms = 0.0;
    double prop_witness_frontier_ms = 0.0;
    double prop_cmp_summary_ms = 0.0;
    double target_sig_build_ms = 0.0;

    uint64 sat_calls = 0;
    uint64 sat_models_total = 0;
    uint64 sat_sid_count = 0;
    uint64 sat_check_calls = 0;
    uint64 sat_assumptions_total = 0;
    uint64 sat_unique_assignments = 0;
    uint64 sat_cache_hits = 0;
    uint64 sat_nogood_prunes = 0;
    uint64 sat_nogoods_added = 0;
    uint64 sat_core_terms_total = 0;
    uint64 sat_core_terms_max = 0;
    uint64 sat_subsumed_dropped = 0;
    uint64 terms_total = 0;
    uint64 allow_rows_total = 0;
    uint64 allow_cache_hit = 0;
    uint64 allow_cache_miss = 0;

    uint64 prop_join_scans_total = 0;
    int prop_iters = 0;
    int project_n_join_evals_max = 0;
    uint64 bin_build_rows_scanned = 0;
    uint64 bin_count_final = 0;
    uint64 bin_build_probe_steps = 0;
    uint64 bin_build_max_probe_len = 0;
    uint64 bin_build_rehash_count = 0;
    uint64 bin_build_hub_count = 0;
    uint64 bin_build_local_atom_count = 0;
    uint64 bin_build_extra_count = 0;
    uint64 rows_scanned_for_prop = 0;
    uint64 rows_scanned_for_cmp = 0;
    uint64 rows_scanned_for_target_sig = 0;
    uint64 pair_rel_count = 0;
    uint64 pair_rel_edges = 0;
    uint64 domain_token_deletions = 0;
    uint64 witness_frontier_steps = 0;
    uint64 query_local_cache_hits = 0;
    uint64 query_local_cache_misses = 0;

    size_t bytes_block_words = 0;
    size_t bytes_decoded_buffers_retained = 0;
};

struct BlobRef {
    const char *data = nullptr;
    size_t len = 0;
    bool ok() const { return data != nullptr; }
};

static std::string trim_copy(const std::string &s)
{
    size_t b = 0;
    while (b < s.size() && std::isspace((unsigned char)s[b]))
        b++;
    size_t e = s.size();
    while (e > b && std::isspace((unsigned char)s[e - 1]))
        e--;
    return s.substr(b, e - b);
}

static std::string to_lower_copy(std::string s)
{
    for (char &c : s)
        c = (char)std::tolower((unsigned char)c);
    return s;
}

static bool parse_bool_like(const std::string &v, bool defval)
{
    std::string s = to_lower_copy(trim_copy(v));
    if (s.empty())
        return defval;
    if (s == "1" || s == "on" || s == "true" || s == "yes")
        return true;
    if (s == "0" || s == "off" || s == "false" || s == "no")
        return false;
    return defval;
}

static bool cf_bool_guc(const char *name, bool defval)
{
    if (!name || !name[0])
        return defval;
    const char *raw = GetConfigOption(name, true, false);
    if (!raw)
        return defval;
    return parse_bool_like(raw, defval);
}

static std::string current_run_id_string()
{
    const char *raw = GetConfigOption("custom_filter.run_id", true, false);
    return (raw && raw[0]) ? std::string(raw) : std::string();
}

static bool read_i32(const char *data, size_t len, size_t *pos, int32 *out)
{
    if (!data || !pos || !out || *pos + sizeof(int32) > len)
        return false;
    int32 v = 0;
    std::memcpy(&v, data + *pos, sizeof(int32));
    *pos += sizeof(int32);
    *out = v;
    return true;
}

static std::vector<std::string> split_lines_blob(const BlobRef &b)
{
    std::vector<std::string> out;
    if (!b.ok() || b.len == 0)
        return out;
    std::string s(b.data, b.len);
    size_t p = 0;
    while (p < s.size()) {
        size_t q = s.find('\n', p);
        if (q == std::string::npos)
            q = s.size();
        std::string ln = s.substr(p, q - p);
        if (!ln.empty() && ln.back() == '\r')
            ln.pop_back();
        ln = trim_copy(ln);
        if (!ln.empty())
            out.push_back(ln);
        p = (q < s.size()) ? (q + 1) : s.size();
    }
    return out;
}

static std::string files_table_sql_ident()
{
    const char *raw = GetConfigOption("custom_filter.files_table", true, false);
    std::string t = (raw && raw[0]) ? raw : "public.files";
    size_t dot = t.find('.');
    if (dot != std::string::npos && dot > 0 && dot + 1 < t.size()) {
        std::string schema = t.substr(0, dot);
        std::string table = t.substr(dot + 1);
        char *q = quote_qualified_identifier(schema.c_str(), table.c_str());
        std::string out = q ? q : "public.files";
        if (q)
            pfree(q);
        return out;
    }
    const char *q = quote_identifier(t.c_str());
    return q ? q : "public.files";
}

class ArtifactResolver {
public:
    ArtifactResolver(const PolicyArtifactC *arts, int art_count)
    {
        if (!arts || art_count <= 0)
            return;
        by_name_.reserve((size_t)art_count * 2u + 1u);
        for (int i = 0; i < art_count; i++) {
            if (!arts[i].name || !arts[i].data || arts[i].len == 0)
                continue;
            by_name_[arts[i].name] = BlobRef{(const char *)arts[i].data, arts[i].len};
        }
    }

    bool get(const std::string &name, BlobRef *out)
    {
        auto it = by_name_.find(name);
        if (it != by_name_.end()) {
            if (out)
                *out = it->second;
            return true;
        }
        if (!load_from_db(name))
            return false;
        auto it2 = by_name_.find(name);
        if (it2 == by_name_.end())
            return false;
        if (out)
            *out = it2->second;
        return true;
    }

private:
    bool load_from_db(const std::string &name)
    {
        std::string sql =
            "SELECT file FROM " + files_table_sql_ident() +
            " WHERE COALESCE(run_id,'') = COALESCE(current_setting('custom_filter.run_id', true), '')"
            " AND name = $1 LIMIT 1";

        Oid argtypes[1] = {TEXTOID};
        Datum values[1] = {CStringGetTextDatum(name.c_str())};
        char nulls[1] = {' '};
        int rc = SPI_execute_with_args(sql.c_str(), 1, argtypes, values, nulls, true, 1);
        if (rc != SPI_OK_SELECT || SPI_processed == 0)
            return false;

        TupleDesc tupdesc = SPI_tuptable->tupdesc;
        HeapTuple tup = SPI_tuptable->vals[0];
        bool isnull = false;
        Datum d = SPI_getbinval(tup, tupdesc, 1, &isnull);
        if (isnull)
            return false;

        bytea *copy = (bytea *)PG_DETOAST_DATUM_COPY(d);
        if (!copy)
            return false;

        owned_.push_back(copy);
        by_name_[name] = BlobRef{(const char *)VARDATA_ANY(copy), (size_t)VARSIZE_ANY_EXHDR(copy)};
        return true;
    }

    std::unordered_map<std::string, BlobRef> by_name_;
    std::vector<bytea *> owned_;
};

class DenseBits {
public:
    DenseBits() = default;
    explicit DenseBits(uint32 n) { reset(n); }

    void reset(uint32 n)
    {
        nbits_ = n;
        words_.assign((size_t)((n + 63u) / 64u), 0ULL);
    }

    uint32 nbits() const { return nbits_; }

    void fill_all()
    {
        std::fill(words_.begin(), words_.end(), ~0ULL);
        trim_tail();
    }

    void clear_all()
    {
        std::fill(words_.begin(), words_.end(), 0ULL);
    }

    void set(uint32 i)
    {
        if (i >= nbits_)
            return;
        words_[(size_t)i >> 6] |= (1ULL << (i & 63u));
    }

    void unset(uint32 i)
    {
        if (i >= nbits_)
            return;
        words_[(size_t)i >> 6] &= ~(1ULL << (i & 63u));
    }

    bool test(uint32 i) const
    {
        if (i >= nbits_)
            return false;
        return (words_[(size_t)i >> 6] & (1ULL << (i & 63u))) != 0ULL;
    }

    bool any() const
    {
        for (uint64 w : words_) {
            if (w)
                return true;
        }
        return false;
    }

    uint64 count() const
    {
        uint64 c = 0;
        for (uint64 w : words_)
            c += (uint64)__builtin_popcountll((unsigned long long)w);
        return c;
    }

    uint64 hash64() const
    {
        uint64 h = 1469598103934665603ULL;
        for (uint64 w : words_) {
            h ^= w;
            h *= 1099511628211ULL;
        }
        h ^= (uint64)nbits_;
        h *= 1099511628211ULL;
        return h;
    }

    bool equals(const DenseBits &o) const
    {
        return nbits_ == o.nbits_ && words_ == o.words_;
    }

    void bit_and(const DenseBits &o)
    {
        size_t n = std::min(words_.size(), o.words_.size());
        for (size_t i = 0; i < n; i++)
            words_[i] &= o.words_[i];
        for (size_t i = n; i < words_.size(); i++)
            words_[i] = 0ULL;
    }

    void bit_or(const DenseBits &o)
    {
        size_t n = std::min(words_.size(), o.words_.size());
        for (size_t i = 0; i < n; i++)
            words_[i] |= o.words_[i];
    }

    bool intersect_with_changed(const DenseBits &o)
    {
        bool changed = false;
        size_t n = std::min(words_.size(), o.words_.size());
        for (size_t i = 0; i < n; i++) {
            uint64 before = words_[i];
            words_[i] &= o.words_[i];
            if (words_[i] != before)
                changed = true;
        }
        for (size_t i = n; i < words_.size(); i++) {
            if (words_[i] != 0ULL) {
                words_[i] = 0ULL;
                changed = true;
            }
        }
        return changed;
    }

    template <typename Fn>
    void for_each_set(Fn &&fn) const
    {
        for (size_t wi = 0; wi < words_.size(); wi++) {
            uint64 w = words_[wi];
            while (w) {
                uint64 lsb = w & (~w + 1ULL);
                unsigned bit = (unsigned)__builtin_ctzll((unsigned long long)w);
                uint32 idx = (uint32)(wi * 64u + bit);
                if (idx < nbits_)
                    fn(idx);
                w ^= lsb;
            }
        }
    }

private:
    void trim_tail()
    {
        if (nbits_ == 0 || words_.empty())
            return;
        uint32 r = nbits_ & 63u;
        if (r == 0)
            return;
        uint64 mask = (1ULL << r) - 1ULL;
        words_.back() &= mask;
    }

    uint32 nbits_ = 0;
    std::vector<uint64> words_;
};

struct ColRef {
    std::string table;
    std::string col;

    std::string key() const { return table + "." + col; }
};

static bool parse_schema_key(const char *raw, ColRef *out)
{
    if (!raw || !out)
        return false;
    std::string s = raw;
    if (s.rfind("join:", 0) == 0)
        s = s.substr(5);
    else if (s.rfind("const:", 0) == 0)
        s = s.substr(6);

    size_t cls = s.find(" class=");
    if (cls != std::string::npos)
        s = s.substr(0, cls);

    size_t dot = s.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= s.size())
        return false;

    out->table = to_lower_copy(s.substr(0, dot));
    out->col = to_lower_copy(s.substr(dot + 1));
    return true;
}

static int parse_scope_id_from_canon_key(const char *raw)
{
    if (!raw || !raw[0])
        return -1;
    std::string s(raw);
    size_t p = s.rfind("@p");
    if (p == std::string::npos || (p + 2u) >= s.size())
        return -1;
    const char *num = s.c_str() + p + 2;
    char *endp = nullptr;
    long v = std::strtol(num, &endp, 10);
    if (!endp || *endp != '\0' || v <= 0 || v > std::numeric_limits<int>::max())
        return -1;
    return (int)v;
}

struct AtomInfo {
    int atom_id = 0;
    int kind = 0;
    int op = 0;
    int join_class_id = -1;
    int scope_id = -1;
    ColRef lhs;
    ColRef rhs;
    std::vector<std::string> const_values;
};

struct CodeManifest {
    uint32 nrows = 0;
    uint32 chunk_rows = 0;
    uint32 ncols = 0;
    uint32 nchunks = 0;
};

struct DictData {
    std::string dtype;
    std::vector<std::string> values;
    std::unordered_map<std::string, int32> token_by_norm;
};

struct RankData {
    bool present = false;
    std::vector<int32> rank_by_tok;
};

struct TableArtifact {
    std::string name;
    CodeManifest manifest;
    std::vector<int32> ctid_blk;
    std::vector<int32> ctid_off;
    uint32 total_blocks = 0;

    std::vector<std::string> cols;
    std::unordered_map<std::string, int> col_idx;

    std::unordered_map<int, std::vector<int32>> col_tokens;
};

struct CanonicalTargetAst {
    std::vector<PolicyAstTokC> final_ast;
    std::vector<PolicyAstTokC> perm_ast;
    std::vector<PolicyAstTokC> rest_ast;
    bool has_perm_expr = false;
    bool has_rest_expr = false;
};

using ConjTerm = std::vector<int>;
using ConjTerms = std::vector<ConjTerm>;

static inline PolicyAstTokC make_ast_token(int kind, int value = 0)
{
    PolicyAstTokC tk;
    tk.kind = kind;
    tk.value = value;
    return tk;
}

static std::vector<PolicyAstTokC> literal_postfix_ast(bool v)
{
    std::vector<PolicyAstTokC> out;
    out.push_back(make_ast_token(v ? POLICY_AST_TOK_TRUE : POLICY_AST_TOK_FALSE, 0));
    return out;
}

static bool ast_postfix_equal(const std::vector<PolicyAstTokC> &a, const std::vector<PolicyAstTokC> &b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (a[i].kind != b[i].kind || a[i].value != b[i].value)
            return false;
    }
    return true;
}

static void normalize_conj_term(ConjTerm *term)
{
    if (!term)
        return;
    std::sort(term->begin(), term->end());
    term->erase(std::remove_if(term->begin(), term->end(), [](int v) { return v <= 0; }),
                term->end());
    term->erase(std::unique(term->begin(), term->end()), term->end());
}

static void dedup_conj_terms(ConjTerms *terms)
{
    if (!terms)
        return;
    for (ConjTerm &t : *terms)
        normalize_conj_term(&t);
    std::sort(terms->begin(), terms->end(),
              [](const ConjTerm &a, const ConjTerm &b) {
                  if (a.size() != b.size())
                      return a.size() < b.size();
                  return a < b;
              });
    terms->erase(std::unique(terms->begin(), terms->end()), terms->end());
}

static bool conj_term_is_subset(const ConjTerm &a, const ConjTerm &b)
{
    // Requires sorted unique terms.
    size_t i = 0;
    size_t j = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) {
            i++;
            j++;
        } else if (a[i] > b[j]) {
            j++;
        } else {
            return false;
        }
    }
    return i == a.size();
}

static size_t prune_subsumed_conj_terms(ConjTerms *terms)
{
    if (!terms)
        return 0u;
    dedup_conj_terms(terms);
    ConjTerms kept;
    kept.reserve(terms->size());
    size_t dropped = 0u;
    for (const ConjTerm &t : *terms) {
        bool subsumed = false;
        for (const ConjTerm &k : kept) {
            if (conj_term_is_subset(k, t)) {
                subsumed = true;
                break;
            }
        }
        if (subsumed) {
            dropped++;
            continue;
        }
        kept.push_back(t);
    }
    *terms = std::move(kept);
    return dropped;
}

static bool enumerate_exact_terms_postfix(const PolicyAstTokC *toks,
                                          int ntok,
                                          ConjTerms *out_terms,
                                          std::string *err)
{
    if (!out_terms)
        return false;
    out_terms->clear();
    if (err)
        err->clear();
    if (!toks || ntok <= 0) {
        // Empty formula is treated as TRUE at this helper boundary.
        out_terms->push_back(ConjTerm{});
        return true;
    }

    std::vector<ConjTerms> st;
    st.reserve((size_t)ntok);
    for (int i = 0; i < ntok; i++) {
        const PolicyAstTokC &tk = toks[i];
        if (tk.kind == POLICY_AST_TOK_TRUE) {
            st.push_back(ConjTerms{ConjTerm{}});
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_FALSE) {
            st.push_back(ConjTerms{});
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_VAR) {
            if (tk.value > 0)
                st.push_back(ConjTerms{ConjTerm{tk.value}});
            else
                st.push_back(ConjTerms{});
            continue;
        }
        if (tk.kind != POLICY_AST_TOK_AND && tk.kind != POLICY_AST_TOK_OR) {
            if (err)
                *err = "invalid token kind in exact term enumerator";
            return false;
        }
        if (st.size() < 2u) {
            if (err)
                *err = "postfix stack underflow in exact term enumerator";
            return false;
        }
        ConjTerms right = std::move(st.back());
        st.pop_back();
        ConjTerms left = std::move(st.back());
        st.pop_back();

        ConjTerms merged;
        if (tk.kind == POLICY_AST_TOK_OR) {
            merged = std::move(left);
            merged.insert(merged.end(), right.begin(), right.end());
            dedup_conj_terms(&merged);
        } else {
            if (!left.empty() && !right.empty()) {
                merged.reserve(left.size() * right.size());
                for (const ConjTerm &l : left) {
                    for (const ConjTerm &r : right) {
                        ConjTerm t = l;
                        t.insert(t.end(), r.begin(), r.end());
                        normalize_conj_term(&t);
                        merged.push_back(std::move(t));
                    }
                }
                dedup_conj_terms(&merged);
            } else {
                merged.clear();
            }
        }
        st.push_back(std::move(merged));
    }

    if (st.size() != 1u) {
        if (err)
            *err = "postfix final stack size != 1 in exact term enumerator";
        return false;
    }
    *out_terms = std::move(st.back());
    dedup_conj_terms(out_terms);
    return true;
}

static std::vector<PolicyAstTokC> build_or_postfix_ast_from_vars(uint32 nvars)
{
    if (nvars == 0u)
        return literal_postfix_ast(false);
    std::vector<PolicyAstTokC> out;
    out.reserve((size_t)nvars * 2u);
    for (uint32 i = 1; i <= nvars; i++) {
        out.push_back(make_ast_token(POLICY_AST_TOK_VAR, (int)i));
        if (i > 1u)
            out.push_back(make_ast_token(POLICY_AST_TOK_OR, 0));
    }
    return out;
}

/*
 * Canonical AST representation rules used by the evaluator:
 * - positive VAR values are atom ids only (y1 == atom 1, never literal true)
 * - boolean literals are represented by explicit TRUE/FALSE token kinds
 * - legacy VAR(<=0) is normalized to FALSE for backwards compatibility
 */
static bool canonicalize_postfix_ast(const PolicyAstTokC *in_toks,
                                     int in_ntok,
                                     std::vector<PolicyAstTokC> *out,
                                     std::string *err)
{
    if (!out)
        return false;
    out->clear();
    if (err)
        err->clear();
    if (!in_toks || in_ntok <= 0)
        return true;

    out->reserve((size_t)in_ntok);
    int depth = 0;
    for (int i = 0; i < in_ntok; i++) {
        const PolicyAstTokC &tk = in_toks[i];
        if (tk.kind == POLICY_AST_TOK_VAR) {
            if (tk.value > 0) {
                out->push_back(make_ast_token(POLICY_AST_TOK_VAR, tk.value));
            } else {
                out->push_back(make_ast_token(POLICY_AST_TOK_FALSE, 0));
            }
            depth++;
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_TRUE || tk.kind == POLICY_AST_TOK_FALSE) {
            out->push_back(make_ast_token(tk.kind, 0));
            depth++;
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_AND || tk.kind == POLICY_AST_TOK_OR) {
            if (depth < 2) {
                if (err)
                    *err = "postfix stack underflow";
                return false;
            }
            out->push_back(make_ast_token(tk.kind, 0));
            depth--;
            continue;
        }
        if (err)
            *err = "invalid token kind";
        return false;
    }
    if (depth != 1) {
        if (err)
            *err = "postfix final stack size != 1";
        return false;
    }
    return true;
}

static bool parse_infix_ast_to_postfix(const std::string &expr, std::vector<PolicyAstTokC> *out)
{
    if (!out)
        return false;
    out->clear();

    struct Parser {
        const std::string &s;
        size_t pos = 0;

        explicit Parser(const std::string &src)
            : s(src) {}

        void skip_ws()
        {
            while (pos < s.size() && std::isspace((unsigned char)s[pos]))
                pos++;
        }

        bool match_char(char c)
        {
            skip_ws();
            if (pos >= s.size() || s[pos] != c)
                return false;
            pos++;
            return true;
        }

        bool match_word(const std::string &w)
        {
            skip_ws();
            if (w.empty())
                return false;
            if (pos + w.size() > s.size())
                return false;
            for (size_t i = 0; i < w.size(); i++) {
                char a = s[pos + i];
                char b = w[i];
                if (std::tolower((unsigned char)a) != b)
                    return false;
            }
            size_t end = pos + w.size();
            if (end < s.size()) {
                char c = s[end];
                if (std::isalnum((unsigned char)c) || c == '_' || c == '.')
                    return false;
            }
            pos = end;
            return true;
        }

        bool parse_var_or_const(std::vector<PolicyAstTokC> &out)
        {
            skip_ws();
            if (pos >= s.size())
                return false;

            if (s[pos] == '(') {
                pos++;
                if (!parse_or_expr(out))
                    return false;
                if (!match_char(')'))
                    return false;
                return true;
            }

            if (match_word("true")) {
                out.push_back(make_ast_token(POLICY_AST_TOK_TRUE, 0));
                return true;
            }

            if (match_word("false")) {
                out.push_back(make_ast_token(POLICY_AST_TOK_FALSE, 0));
                return true;
            }

            if (pos >= s.size() || s[pos] != 'y')
                return false;
            pos++;
            bool neg = false;
            if (pos < s.size() && s[pos] == '-') {
                neg = true;
                pos++;
            }
            if (pos >= s.size() || !std::isdigit((unsigned char)s[pos]))
                return false;
            int val = 0;
            while (pos < s.size() && std::isdigit((unsigned char)s[pos])) {
                val = val * 10 + (s[pos] - '0');
                pos++;
            }
            if (neg)
                val = -val;
            if (val > 0)
                out.push_back(make_ast_token(POLICY_AST_TOK_VAR, val));
            else
                out.push_back(make_ast_token(POLICY_AST_TOK_FALSE, 0));
            return true;
        }

        bool parse_and_expr(std::vector<PolicyAstTokC> &out)
        {
            if (!parse_var_or_const(out))
                return false;
            while (true) {
                size_t save = pos;
                if (match_word("and")) {
                    if (!parse_var_or_const(out))
                        return false;
                    out.push_back(make_ast_token(POLICY_AST_TOK_AND, 0));
                    continue;
                }
                pos = save;
                return true;
            }
        }

        bool parse_or_expr(std::vector<PolicyAstTokC> &out)
        {
            if (!parse_and_expr(out))
                return false;
            while (true) {
                size_t save = pos;
                if (match_word("or")) {
                    if (!parse_and_expr(out))
                        return false;
                    out.push_back(make_ast_token(POLICY_AST_TOK_OR, 0));
                    continue;
                }
                pos = save;
                return true;
            }
        }
    };

    Parser p(expr);
    if (!p.parse_or_expr(*out))
        return false;
    p.skip_ws();
    return p.pos == p.s.size();
}

static bool parse_bool_ast_postfix(const std::string &expr, std::vector<PolicyAstTokC> *out)
{
    if (!out)
        return false;
    out->clear();
    std::string e = to_lower_copy(trim_copy(expr));
    if (e.empty())
        return false;
    std::vector<PolicyAstTokC> parsed;
    if (!parse_infix_ast_to_postfix(e, &parsed))
        return false;
    std::string err;
    return canonicalize_postfix_ast(parsed.data(), (int)parsed.size(), out, &err);
}

/*
 * Build one canonical AST source for a target and use it everywhere:
 * feature extraction, context derivation, candidate masking, and SAT.
 *
 * We preserve policy semantics explicitly:
 * final = (OR permissive) AND (AND restrictive).
 * If no permissive exists, final is FALSE (Postgres RLS contract).
 */
static bool build_canonical_target_ast(const PolicyEngineInputC *in,
                                       int target_idx,
                                       const PolicyAstTokC *legacy_final_toks,
                                       int legacy_final_ntok,
                                       CanonicalTargetAst *out,
                                       std::string *err)
{
    if (!out)
        return false;
    if (err)
        err->clear();
    out->final_ast.clear();
    out->perm_ast.clear();
    out->rest_ast.clear();
    out->has_perm_expr = false;
    out->has_rest_expr = false;

    std::vector<PolicyAstTokC> legacy_final_ast;
    if (legacy_final_toks && legacy_final_ntok > 0) {
        if (!canonicalize_postfix_ast(legacy_final_toks, legacy_final_ntok, &legacy_final_ast, err))
            return false;
    }

    std::vector<PolicyAstTokC> parsed_perm;
    std::vector<PolicyAstTokC> parsed_rest;
    if (target_idx >= 0 && in && target_idx < in->target_count) {
        if (in->target_perm_asts && in->target_perm_asts[target_idx]) {
            std::string perm_txt = trim_copy(in->target_perm_asts[target_idx]);
            if (!perm_txt.empty()) {
                if (!parse_bool_ast_postfix(perm_txt, &parsed_perm)) {
                    if (err)
                        *err = "malformed permissive AST";
                    return false;
                }
                out->has_perm_expr = true;
            }
        }
        if (in->target_rest_asts && in->target_rest_asts[target_idx]) {
            std::string rest_txt = trim_copy(in->target_rest_asts[target_idx]);
            if (!rest_txt.empty()) {
                if (!parse_bool_ast_postfix(rest_txt, &parsed_rest)) {
                    if (err)
                        *err = "malformed restrictive AST";
                    return false;
                }
                out->has_rest_expr = true;
            }
        }
    }

    const bool have_perm_rest_source = out->has_perm_expr || out->has_rest_expr;
    std::vector<PolicyAstTokC> perm_rest_final_ast;
    if (have_perm_rest_source) {
        out->perm_ast = out->has_perm_expr ? parsed_perm : literal_postfix_ast(false);
        out->rest_ast = out->has_rest_expr ? parsed_rest : literal_postfix_ast(true);
        if (!out->has_perm_expr) {
            // Postgres RLS contract: no permissive policy means deny-all.
            perm_rest_final_ast = literal_postfix_ast(false);
        } else if (!out->has_rest_expr) {
            perm_rest_final_ast = out->perm_ast;
        } else {
            perm_rest_final_ast = out->perm_ast;
            perm_rest_final_ast.insert(perm_rest_final_ast.end(),
                                       out->rest_ast.begin(), out->rest_ast.end());
            perm_rest_final_ast.push_back(make_ast_token(POLICY_AST_TOK_AND, 0));
        }
    }

    /*
     * Dual-source convergence:
     * when parsed permissive/restrictive ASTs exist, they are canonical.
     * legacy target_ast_toks is compatibility-only and may be stale.
     */
    if (!legacy_final_ast.empty() && !perm_rest_final_ast.empty() &&
        !ast_postfix_equal(legacy_final_ast, perm_rest_final_ast)) {
        const char *tname =
            (in && in->target_tables && target_idx >= 0 && target_idx < in->target_count &&
             in->target_tables[target_idx])
                ? in->target_tables[target_idx]
                : "<unknown>";
        elog(NOTICE,
             "policy: AST source mismatch target=%s; preferring parsed permissive/restrictive AST over legacy target_ast_toks",
             tname);
    }

    if (!perm_rest_final_ast.empty()) {
        out->final_ast = std::move(perm_rest_final_ast);
    } else if (!legacy_final_ast.empty()) {
        out->final_ast = std::move(legacy_final_ast);
        out->perm_ast = out->final_ast;
        out->rest_ast = literal_postfix_ast(true);
    } else {
        // Never emit empty final AST: missing policy expression is explicit deny-all.
        out->perm_ast = literal_postfix_ast(false);
        out->rest_ast = literal_postfix_ast(true);
        out->final_ast = literal_postfix_ast(false);
    }

    if (out->perm_ast.empty())
        out->perm_ast = literal_postfix_ast(false);
    if (out->rest_ast.empty())
        out->rest_ast = literal_postfix_ast(true);
    if (out->final_ast.empty())
        out->final_ast = literal_postfix_ast(false);
    return true;
}

static std::string normalize_numeric_string(const std::string &in)
{
    std::string s = trim_copy(in);
    if (s.empty())
        return s;

    size_t epos = s.find_first_of("eE");
    std::string mant = (epos == std::string::npos) ? s : s.substr(0, epos);
    std::string exp = (epos == std::string::npos) ? "" : s.substr(epos + 1);

    bool neg = false;
    if (!mant.empty() && (mant[0] == '+' || mant[0] == '-')) {
        neg = (mant[0] == '-');
        mant.erase(mant.begin());
    }

    size_t dot = mant.find('.');
    std::string intp = (dot == std::string::npos) ? mant : mant.substr(0, dot);
    std::string frac = (dot == std::string::npos) ? "" : mant.substr(dot + 1);

    size_t nz = intp.find_first_not_of('0');
    intp = (nz == std::string::npos) ? "0" : intp.substr(nz);
    while (!frac.empty() && frac.back() == '0')
        frac.pop_back();

    std::string out;
    if (neg && !(intp == "0" && frac.empty()))
        out.push_back('-');
    out += intp;
    if (!frac.empty()) {
        out.push_back('.');
        out += frac;
    }

    if (!exp.empty()) {
        std::string e = trim_copy(exp);
        bool eneg = false;
        if (!e.empty() && (e[0] == '+' || e[0] == '-')) {
            eneg = (e[0] == '-');
            e.erase(e.begin());
        }
        size_t enz = e.find_first_not_of('0');
        if (enz != std::string::npos) {
            out.push_back('e');
            if (eneg)
                out.push_back('-');
            out += e.substr(enz);
        }
    }

    if (out == "-0")
        out = "0";
    return out;
}

static bool eval_postfix_constant_ast(const PolicyAstTokC *ast_toks, int ast_ntok, bool *ok_out)
{
    if (ok_out)
        *ok_out = false;
    if (!ast_toks || ast_ntok <= 0) {
        if (ok_out)
            *ok_out = true;
        return true;
    }

    std::vector<uint8_t> st;
    st.reserve((size_t)ast_ntok);
    for (int i = 0; i < ast_ntok; i++) {
        const PolicyAstTokC &tk = ast_toks[i];
        if (tk.kind == POLICY_AST_TOK_TRUE) {
            st.push_back(1u);
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_FALSE) {
            st.push_back(0u);
            continue;
        }
        if (tk.kind == POLICY_AST_TOK_VAR) {
            // Legacy VAR(<=0) is false; positive ids are atoms (not constants).
            if (tk.value > 0)
                return false;
            st.push_back(0u);
            continue;
        }
        if (tk.kind != POLICY_AST_TOK_AND && tk.kind != POLICY_AST_TOK_OR)
            return false;
        if (st.size() < 2u)
            return false;
        uint8_t b = st.back();
        st.pop_back();
        uint8_t a = st.back();
        st.pop_back();
        st.push_back((tk.kind == POLICY_AST_TOK_AND) ? (uint8_t)(a && b) : (uint8_t)(a || b));
    }
    if (st.size() != 1u)
        return false;
    if (ok_out)
        *ok_out = true;
    return st[0] != 0u;
}

static std::string normalize_literal_for_type(const std::string &raw, const std::string &dtype)
{
    std::string t = trim_copy(raw);
    if (dtype == "numeric")
        return normalize_numeric_string(t);
    if (dtype == "bpchar") {
        while (!t.empty() && t.back() == ' ')
            t.pop_back();
        return t;
    }
    if (dtype == "int" || dtype == "date") {
        char *endp = nullptr;
        long long v = std::strtoll(t.c_str(), &endp, 10);
        if (endp && *endp == '\0')
            return std::to_string(v);
        return t;
    }
    if (dtype == "float") {
        char *endp = nullptr;
        long double v = std::strtold(t.c_str(), &endp);
        if (endp && *endp == '\0') {
            char buf[128];
            snprintf(buf, sizeof(buf), "%.17Lg", v);
            return std::string(buf);
        }
        return t;
    }
    return t;
}

static int cmp_by_type(const std::string &dtype, const std::string &lhs_raw, const std::string &rhs_raw)
{
    std::string lhs = normalize_literal_for_type(lhs_raw, dtype);
    std::string rhs = normalize_literal_for_type(rhs_raw, dtype);

    if (dtype == "int" || dtype == "date") {
        char *e1 = nullptr;
        char *e2 = nullptr;
        long long a = std::strtoll(lhs.c_str(), &e1, 10);
        long long b = std::strtoll(rhs.c_str(), &e2, 10);
        if (e1 && *e1 == '\0' && e2 && *e2 == '\0') {
            if (a < b) return -1;
            if (a > b) return 1;
            return 0;
        }
    }

    if (dtype == "float" || dtype == "numeric") {
        char *e1 = nullptr;
        char *e2 = nullptr;
        long double a = std::strtold(lhs.c_str(), &e1);
        long double b = std::strtold(rhs.c_str(), &e2);
        if (e1 && *e1 == '\0' && e2 && *e2 == '\0') {
            if (a < b) return -1;
            if (a > b) return 1;
            return 0;
        }
    }

    if (lhs < rhs) return -1;
    if (lhs > rhs) return 1;
    return 0;
}

static bool op_cmp_true(int op, int cmp)
{
    switch (op) {
        case POLICY_OP_EQ: return cmp == 0;
        case POLICY_OP_NE: return cmp != 0;
        case POLICY_OP_LT: return cmp < 0;
        case POLICY_OP_LE: return cmp <= 0;
        case POLICY_OP_GT: return cmp > 0;
        case POLICY_OP_GE: return cmp >= 0;
        default: return false;
    }
}

static int inverse_op(int op)
{
    switch (op) {
        case POLICY_OP_EQ: return POLICY_OP_EQ;
        case POLICY_OP_NE: return POLICY_OP_NE;
        case POLICY_OP_LT: return POLICY_OP_GT;
        case POLICY_OP_LE: return POLICY_OP_GE;
        case POLICY_OP_GT: return POLICY_OP_LT;
        case POLICY_OP_GE: return POLICY_OP_LE;
        default: return op;
    }
}

static uint64 hash_combine64(uint64 h, uint64 v)
{
    // 64-bit mix (splitmix-inspired).
    v += 0x9e3779b97f4a7c15ULL;
    v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ULL;
    v = (v ^ (v >> 27)) * 0x94d049bb133111ebULL;
    v = v ^ (v >> 31);
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

struct CompositeStamp {
    bool ready = false;
    uint32 ntokens = 0;
    std::vector<int32> left_rid_to_tok;
    std::vector<int32> right_rid_to_tok;
};

struct EqConstraint {
    std::string left_table;
    std::string right_table;
    std::vector<int> left_col_idxs;
    std::vector<int> right_col_idxs;

    int domain_id = -1;
    bool composite = false;

    CompositeStamp comp;
};

struct CmpSummary {
    bool any = false;
    uint64 nonnull_count = 0;
    int32 min_rank = std::numeric_limits<int32>::max();
    int32 max_rank = std::numeric_limits<int32>::min();
    int32 only_tok = -1;
    std::vector<uint8_t> support;
};

struct CmpConstraint {
    std::string left_table;
    std::string right_table;
    int left_col_idx = -1;
    int right_col_idx = -1;
    int op = 0;
    int domain_id = -1;

    int group_eq_idx = -1;
};

struct QualAtom {
    std::string table;
    int kind = 0;
    ColRef lhs;
    ColRef rhs;
    int op = 0;
    std::string const_value;
};

struct AllowCacheEntry {
    std::vector<uint64> block_words;
    std::vector<uint32> block_ids;
    DenseBits allow_mask;
    uint32 total_blocks = 0;
    uint32 n_rows = 0;
    uint64 allowed_rows = 0;
    uint32 allowed_sids = 0;
    uint32 total_sids = 0;
    double hub_prop_ms = 0.0;
    double sat_ms = 0.0;
    double sid_build_ms = 0.0;
    int mode_hint = POLICY_MODE_HINT_FILTER;
    std::string mode_reason;
};

static uint64 hash_cstr64(uint64 h, const char *s)
{
    if (!s)
        return hash_combine64(h, 0ULL);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        h = hash_combine64(h, (uint64)(*p));
    return hash_combine64(h, 0ULL);
}

static std::string make_allow_cache_key(const std::string &target,
                                        const PolicyEngineInputC *in,
                                        int target_idx,
                                        const PolicyAstTokC *ast_toks,
                                        int ast_ntok,
                                        uint32 target_nrows,
                                        uint32 target_total_blocks)
{
    uint64 h = 1469598103934665603ULL;
    h = hash_combine64(h, std::hash<std::string>{}(target));
    h = hash_combine64(h, (uint64)(uint32)std::max(0, target_idx));
    h = hash_combine64(h, (uint64)target_nrows);
    h = hash_combine64(h, (uint64)target_total_blocks);
    if (in) {
        h = hash_combine64(h, (uint64)(uint32)std::max(0, in->atom_count));
        h = hash_combine64(h, (uint64)(uint32)std::max(0, in->scan_qual_atom_count));
        if (target_idx >= 0 && target_idx < in->target_count) {
            if (in->target_asts)
                h = hash_cstr64(h, in->target_asts[target_idx]);
            if (in->target_perm_asts)
                h = hash_cstr64(h, in->target_perm_asts[target_idx]);
            if (in->target_rest_asts)
                h = hash_cstr64(h, in->target_rest_asts[target_idx]);
        }
    }
    for (int i = 0; i < ast_ntok; i++) {
        h = hash_combine64(h, (uint64)(uint32)ast_toks[i].kind);
        h = hash_combine64(h, (uint64)(uint32)ast_toks[i].value);
    }
    std::string key = current_run_id_string();
    key.push_back('|');
    key += target;
    key.push_back('|');
    key += std::to_string((unsigned long long)h);
    return key;
}

static void copy_allow_cache_entry_to_out(const std::string &target,
                                          const AllowCacheEntry &ce,
                                          PolicyTableAllowC *out)
{
    if (!out)
        return;
    out->table = pstrdup(target.c_str());
    out->blocks = (uint32)ce.block_ids.size();
    out->total_blocks = ce.total_blocks;
    out->n_rows = ce.n_rows;
    out->allowed_rows = ce.allowed_rows;
    out->allowed_sids = ce.allowed_sids;
    out->total_sids = ce.total_sids;
    out->hub_prop_ms = ce.hub_prop_ms;
    out->sat_ms = ce.sat_ms;
    out->sid_build_ms = ce.sid_build_ms;
    out->mode_hint = ce.mode_hint;
    out->mode_reason = pstrdup(ce.mode_reason.c_str());
    out->block_words = nullptr;
    out->block_ids = nullptr;
    if (!ce.block_words.empty()) {
        size_t bytes = ce.block_words.size() * sizeof(uint64);
        out->block_words = (uint64 *)palloc0(bytes);
        std::memcpy(out->block_words, ce.block_words.data(), bytes);
    }
    if (!ce.block_ids.empty()) {
        size_t bytes = ce.block_ids.size() * sizeof(uint32);
        out->block_ids = (uint32 *)palloc0(bytes);
        std::memcpy(out->block_ids, ce.block_ids.data(), bytes);
    }
}

static void put_allow_cache_entry(std::unordered_map<std::string, AllowCacheEntry> *cache,
                                  std::deque<std::string> *lru,
                                  size_t max_entries,
                                  const std::string &key,
                                  AllowCacheEntry &&entry)
{
    if (!cache || !lru || max_entries == 0u)
        return;
    auto it = cache->find(key);
    if (it == cache->end() && lru->size() >= max_entries) {
        const std::string evict = lru->front();
        lru->pop_front();
        cache->erase(evict);
    }
    if (it != cache->end()) {
        for (auto q = lru->begin(); q != lru->end(); ++q) {
            if (*q == key) {
                lru->erase(q);
                break;
            }
        }
    }
    lru->push_back(key);
    (*cache)[key] = std::move(entry);
}

class Engine {
public:
    Engine(const PolicyArtifactC *arts, int art_count, const PolicyEngineInputC *in, BuildProfile *profile)
        : resolver_(arts, art_count), in_(in), profile_(profile)
    {
        auto t0 = Clock::now();
        load_col_domain_meta();
        load_atoms();
        load_scan_qual_atoms();
        if (profile_)
            profile_->atoms_ms += Ms(Clock::now() - t0).count();
    }

    std::unordered_set<std::string> target_dependencies(const std::string &target) const
    {
        std::unordered_set<std::string> deps;
        int target_idx = target_index(target);
        if (target_idx < 0 || !in_ || target_idx >= in_->target_count)
            return deps;
        const PolicyAstTokC *legacy_ast_toks = nullptr;
        int legacy_ast_ntok = 0;
        if (in_->target_ast_toks && in_->target_ast_tok_offsets && in_->target_ast_tok_counts) {
            int off = in_->target_ast_tok_offsets[target_idx];
            int cnt = in_->target_ast_tok_counts[target_idx];
            if (off >= 0 && cnt >= 0 && (off + cnt) <= in_->target_ast_tok_len) {
                legacy_ast_toks = in_->target_ast_toks + off;
                legacy_ast_ntok = cnt;
            }
        }

        CanonicalTargetAst canonical;
        std::string ast_err;
        if (!build_canonical_target_ast(in_, target_idx,
                                        legacy_ast_toks, legacy_ast_ntok,
                                        &canonical, &ast_err)) {
            ereport(ERROR,
                    (errmsg("policy: malformed canonical AST for dependencies target=%s err=%s",
                            target.c_str(), ast_err.c_str())));
        }

        for (const PolicyAstTokC &tk : canonical.final_ast) {
            if (tk.kind != POLICY_AST_TOK_VAR || tk.value <= 0)
                continue;
            auto ait = atom_by_id_.find(tk.value);
            if (ait == atom_by_id_.end())
                continue;
            const AtomInfo &a = ait->second;
            if (!a.lhs.table.empty() && a.lhs.table != target)
                deps.insert(a.lhs.table);
            if (!a.rhs.table.empty() && a.rhs.table != target)
                deps.insert(a.rhs.table);
        }
        return deps;
    }

    bool build_target_allow(const std::string &target, PolicyTableAllowC *out)
    {
        if (!out)
            return false;
        std::memset(out, 0, sizeof(*out));

        TableArtifact *target_td = require_table(target);
        if (!target_td)
            return false;

        try {
            auto t_allow_build0 = Clock::now();

            int target_idx = target_index(target);
            const PolicyAstTokC *legacy_ast_toks = nullptr;
            int legacy_ast_ntok = 0;
            if (target_idx >= 0 && in_ &&
                in_->target_ast_toks && in_->target_ast_tok_offsets && in_->target_ast_tok_counts &&
                target_idx < in_->target_count) {
                int off = in_->target_ast_tok_offsets[target_idx];
                int cnt = in_->target_ast_tok_counts[target_idx];
                if (off >= 0 && cnt >= 0 && (off + cnt) <= in_->target_ast_tok_len) {
                    legacy_ast_toks = in_->target_ast_toks + off;
                    legacy_ast_ntok = cnt;
                }
            }

            CanonicalTargetAst canonical_ast;
            {
                std::string ast_err;
                if (!build_canonical_target_ast(in_, target_idx,
                                                legacy_ast_toks, legacy_ast_ntok,
                                                &canonical_ast, &ast_err))
                    ereport(ERROR,
                            (errmsg("policy: malformed AST target=%s err=%s",
                                    target.c_str(), ast_err.c_str())));
            }
            const PolicyAstTokC *ast_toks =
                canonical_ast.final_ast.empty() ? nullptr : canonical_ast.final_ast.data();
            int ast_ntok = (int)canonical_ast.final_ast.size();

            bool allow_cache_enabled = cf_bool_guc("custom_filter.enable_allow_cache", true);
            bool allow_cache_miss_recorded = false;
            std::string allow_cache_key;
            if (allow_cache_enabled) {
                allow_cache_key =
                    make_allow_cache_key(target, in_, target_idx, ast_toks, ast_ntok,
                                         target_td->manifest.nrows, target_td->total_blocks);
                auto acit = allow_cache_.find(allow_cache_key);
                if (acit != allow_cache_.end()) {
                    copy_allow_cache_entry_to_out(target, acit->second, out);
                    policy_allow_mask_cache_[target] = acit->second.allow_mask;
                    if (profile_) {
                        profile_->allow_cache_hit++;
                        profile_->allow_rows_total += acit->second.allowed_rows;
                    }
                    return true;
                }
                allow_cache_miss_recorded = true;
                if (profile_)
                    profile_->allow_cache_miss++;
            }

            auto note_allow_cache_build_time = [&]() {
                if (allow_cache_miss_recorded && profile_)
                    profile_->allow_cache_build_ms += Ms(Clock::now() - t_allow_build0).count();
            };

            auto maybe_store_allow_cache = [&](const DenseBits &allow_mask) {
                if (!allow_cache_enabled || allow_cache_key.empty())
                    return;
                AllowCacheEntry ce;
                ce.total_blocks = out->total_blocks;
                ce.n_rows = out->n_rows;
                ce.allowed_rows = out->allowed_rows;
                ce.allowed_sids = out->allowed_sids;
                ce.total_sids = out->total_sids;
                ce.hub_prop_ms = out->hub_prop_ms;
                ce.sat_ms = out->sat_ms;
                ce.sid_build_ms = out->sid_build_ms;
                ce.mode_hint = out->mode_hint;
                ce.mode_reason = out->mode_reason ? out->mode_reason : "";
                ce.allow_mask = allow_mask;
                if (out->blocks > 0 && out->block_ids)
                    ce.block_ids.assign(out->block_ids, out->block_ids + out->blocks);
                if (out->blocks > 0 && out->block_words) {
                    size_t nwords = (size_t)out->blocks * kWordsPerBlock;
                    ce.block_words.assign(out->block_words, out->block_words + nwords);
                }
                put_allow_cache_entry(&allow_cache_, &allow_cache_lru_, kAllowCacheMaxEntries,
                                      allow_cache_key, std::move(ce));
            };

            static constexpr size_t kExactTermHardCap = 4096u;
            auto guard_exact_term_cap = [&](size_t nterms, const char *stage) {
                if (nterms > kExactTermHardCap) {
                    ereport(ERROR,
                            (errmsg("policy: exact term cap exceeded target=%s target_idx=%d stage=%s terms=%zu cap=%zu",
                                    target.c_str(),
                                    target_idx,
                                    stage ? stage : "unknown",
                                    nterms,
                                    kExactTermHardCap)));
                }
            };

            ConjTerms perm_terms_raw;
            ConjTerms rest_terms_raw;
            ConjTerms final_terms_raw;
            ConjTerms final_terms_dedup;
            ConjTerms final_terms_pruned;

            {
                std::string terms_err;
                if (!enumerate_exact_terms_postfix(canonical_ast.perm_ast.data(),
                                                   (int)canonical_ast.perm_ast.size(),
                                                   &perm_terms_raw,
                                                   &terms_err))
                    ereport(ERROR,
                            (errmsg("policy: exact term enumeration failed target=%s side=perm err=%s",
                                    target.c_str(), terms_err.c_str())));
                if (!enumerate_exact_terms_postfix(canonical_ast.rest_ast.data(),
                                                   (int)canonical_ast.rest_ast.size(),
                                                   &rest_terms_raw,
                                                   &terms_err))
                    ereport(ERROR,
                            (errmsg("policy: exact term enumeration failed target=%s side=rest err=%s",
                                    target.c_str(), terms_err.c_str())));
            }

            // final = (OR perm_terms) AND (OR rest_terms)
            if (!perm_terms_raw.empty() && !rest_terms_raw.empty()) {
                final_terms_raw.reserve(perm_terms_raw.size() * rest_terms_raw.size());
                for (const ConjTerm &pt : perm_terms_raw) {
                    for (const ConjTerm &rt : rest_terms_raw) {
                        ConjTerm t = pt;
                        t.insert(t.end(), rt.begin(), rt.end());
                        normalize_conj_term(&t);
                        final_terms_raw.push_back(std::move(t));
                    }
                }
            } else {
                final_terms_raw.clear();
            }
            guard_exact_term_cap(final_terms_raw.size(), "raw");

            final_terms_dedup = final_terms_raw;
            dedup_conj_terms(&final_terms_dedup);
            guard_exact_term_cap(final_terms_dedup.size(), "dedup");

            final_terms_pruned = final_terms_dedup;
            size_t final_terms_subsumed_dropped = prune_subsumed_conj_terms(&final_terms_pruned);
            guard_exact_term_cap(final_terms_pruned.size(), "pruned");

            std::vector<int> feature_atom_ids;
            feature_atom_ids.reserve((size_t)std::max(16, (int)final_terms_pruned.size()));
            for (const ConjTerm &t : final_terms_pruned) {
                for (int aid : t) {
                    if (aid > 0)
                        feature_atom_ids.push_back(aid);
                }
            }
            std::sort(feature_atom_ids.begin(), feature_atom_ids.end());
            feature_atom_ids.erase(std::unique(feature_atom_ids.begin(), feature_atom_ids.end()),
                                   feature_atom_ids.end());

            if (feature_atom_ids.empty()) {
                bool allow_all = (!final_terms_pruned.empty() && final_terms_pruned[0].empty());

                uint32 total_blocks = target_td->total_blocks;
                std::vector<uint32> block_ids;
                std::vector<uint64> block_words;
                std::vector<uint64> dense((size_t)total_blocks * kWordsPerBlock, 0ULL);
                std::vector<uint8_t> touched(total_blocks, 0u);
                uint64 allowed_rows = 0;

                DenseBits allow_mask(target_td->manifest.nrows);
                if (allow_all)
                    allow_mask.fill_all();
                else
                    allow_mask.clear_all();

                if (allow_all) {
                    for (uint32 rid = 0; rid < target_td->manifest.nrows; rid++) {
                        int32 blk_i = target_td->ctid_blk[rid];
                        int32 off_i = target_td->ctid_off[rid];
                        if (blk_i < 0 || off_i < 1 || off_i > (int32)kMaxOff)
                            continue;
                        uint32 blk = (uint32)blk_i;
                        uint32 off0 = (uint32)off_i - 1u;
                        size_t base = (size_t)blk * kWordsPerBlock;
                        dense[base + (off0 >> 6)] |= (1ULL << (off0 & 63u));
                        if (!touched[blk]) {
                            touched[blk] = 1u;
                            block_ids.push_back(blk);
                        }
                        allowed_rows++;
                    }
                }
                std::sort(block_ids.begin(), block_ids.end());
                block_words.reserve(block_ids.size() * kWordsPerBlock);
                for (uint32 blk : block_ids) {
                    size_t base = (size_t)blk * kWordsPerBlock;
                    for (uint32 w = 0; w < kWordsPerBlock; w++)
                        block_words.push_back(dense[base + w]);
                }

                out->table = pstrdup(target.c_str());
                out->blocks = (uint32)block_ids.size();
                out->total_blocks = total_blocks;
                out->n_rows = target_td->manifest.nrows;
                out->allowed_rows = allowed_rows;
                out->allowed_sids = allow_all ? 1u : 0u;
                out->total_sids = 1u;
                out->hub_prop_ms = 0.0;
                out->sat_ms = 0.0;
                out->sid_build_ms = 0.0;
                out->mode_hint = allow_all ? POLICY_MODE_HINT_ALL : POLICY_MODE_HINT_EMPTY;
                out->mode_reason = pstrdup(allow_all ? "exact_terms_constant_true" : "exact_terms_constant_false");
                out->block_words = nullptr;
                out->block_ids = nullptr;
                if (!block_words.empty()) {
                    size_t bytes = block_words.size() * sizeof(uint64);
                    out->block_words = (uint64 *)palloc0(bytes);
                    std::memcpy(out->block_words, block_words.data(), bytes);
                }
                if (!block_ids.empty()) {
                    size_t bytes = block_ids.size() * sizeof(uint32);
                    out->block_ids = (uint32 *)palloc0(bytes);
                    std::memcpy(out->block_ids, block_ids.data(), bytes);
                }

                policy_allow_mask_cache_[target] = allow_mask;
                maybe_store_allow_cache(allow_mask);
                note_allow_cache_build_time();
                if (profile_)
                    profile_->allow_rows_total += allowed_rows;
                elog(NOTICE,
                     "policy_exact_terms: target=%s target_idx=%d final_terms_raw=%zu final_terms_dedup=%zu final_terms_pruned=%zu final_terms_subsumed=%zu constant=%d",
                     target.c_str(),
                     target_idx,
                     final_terms_raw.size(),
                     final_terms_dedup.size(),
                     final_terms_pruned.size(),
                     final_terms_subsumed_dropped,
                     allow_all ? 1 : 0);
                return true;
            }

            if (!cf_bool_guc("custom_filter.enable_token_rel_propagation", true))
                ereport(ERROR,
                        (errmsg("policy: token-domain propagation is required; set custom_filter.enable_token_rel_propagation=on")));

            auto t_prop0 = Clock::now();
            auto t_prop_index0 = t_prop0;

            // Query-local propagation substrate: build table base masks and
            // reusable eq/cmp structures once, then evaluate AST contexts via
            // a per-target context cache (no persisted hub artifacts).
            std::unordered_set<std::string> tables;
            tables.reserve(feature_atom_ids.size() * 2u + 4u);
            tables.insert(target);

            std::vector<const AtomInfo *> join_atoms;
            std::vector<const AtomInfo *> cross_cmp_atoms;
            std::unordered_map<int, const AtomInfo *> atom_ptr;
            atom_ptr.reserve(feature_atom_ids.size() * 2u + 1u);

            for (int aid : feature_atom_ids) {
                auto it = atom_by_id_.find(aid);
                if (it == atom_by_id_.end())
                    continue;
                const AtomInfo &a = it->second;
                atom_ptr.emplace(aid, &a);
                if (!a.lhs.table.empty())
                    tables.insert(a.lhs.table);
                if (!a.rhs.table.empty())
                    tables.insert(a.rhs.table);

                if (a.kind == POLICY_ATOM_JOIN_EQ && a.lhs.table != a.rhs.table)
                    join_atoms.push_back(&a);
                else if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table != a.rhs.table)
                    cross_cmp_atoms.push_back(&a);
            }

            std::unordered_map<std::string, DenseBits> base_rows;
            base_rows.reserve(tables.size() * 2u + 1u);
            for (const std::string &t : tables) {
                TableArtifact *td = require_table(t);
                DenseBits mask(td ? td->manifest.nrows : 0u);
                mask.fill_all();
                auto pit = policy_allow_mask_cache_.find(t);
                if (pit != policy_allow_mask_cache_.end() && pit->second.nbits() == mask.nbits())
                    mask.bit_and(pit->second);
                mask.bit_and(scan_qual_mask_for_table(t));
                base_rows.emplace(t, std::move(mask));
            }

            auto t_prop_rel0 = Clock::now();

            struct EqEntry {
                EqConstraint eq;
                int atom_id = 0;
            };
            std::vector<EqEntry> eq_entries;
            eq_entries.reserve(join_atoms.size());
            for (const AtomInfo *ap : join_atoms) {
                EqEntry e;
                e.atom_id = ap->atom_id;
                e.eq.left_table = ap->lhs.table;
                e.eq.right_table = ap->rhs.table;
                e.eq.left_col_idxs.push_back(require_col_idx(ap->lhs.table, ap->lhs.col));
                e.eq.right_col_idxs.push_back(require_col_idx(ap->rhs.table, ap->rhs.col));
                e.eq.domain_id = (ap->join_class_id >= 0) ? ap->join_class_id : domain_of_col(ap->lhs);
                e.eq.composite = false;
                eq_entries.push_back(std::move(e));
            }

            std::vector<EqConstraint> eqs;
            eqs.reserve(eq_entries.size());
            for (EqEntry &e : eq_entries)
                eqs.push_back(e.eq);

            struct CmpEntry {
                CmpConstraint cmp;
                int atom_id = 0;
            };
            std::vector<CmpEntry> cmp_entries;
            cmp_entries.reserve(cross_cmp_atoms.size());
            for (const AtomInfo *ap : cross_cmp_atoms) {
                CmpEntry ce;
                ce.atom_id = ap->atom_id;
                ce.cmp.left_table = ap->lhs.table;
                ce.cmp.right_table = ap->rhs.table;
                ce.cmp.left_col_idx = require_col_idx(ap->lhs.table, ap->lhs.col);
                ce.cmp.right_col_idx = require_col_idx(ap->rhs.table, ap->rhs.col);
                ce.cmp.op = ap->op;
                ce.cmp.domain_id = (ap->join_class_id >= 0) ? ap->join_class_id : domain_of_col(ap->lhs);
                ce.cmp.group_eq_idx = -1;
                for (size_t i = 0; i < eq_entries.size(); i++) {
                    const EqConstraint &e = eq_entries[i].eq;
                    if ((e.left_table == ce.cmp.left_table && e.right_table == ce.cmp.right_table) ||
                        (e.left_table == ce.cmp.right_table && e.right_table == ce.cmp.left_table)) {
                        ce.cmp.group_eq_idx = (int)i;
                        break;
                    }
                }
                cmp_entries.push_back(std::move(ce));
            }

            auto t_prop_rel1 = Clock::now();

            if (profile_)
                profile_->pair_rel_count += (uint64)eq_entries.size();

            std::vector<DenseBits> exact_term_masks;
            std::vector<PolicyAstTokC> sat_terms_ast;
            std::vector<int> sat_feature_ids;
            std::unordered_map<int, int> sat_var_alias;
            DenseBits all_target(target_td->manifest.nrows);
            all_target.clear_all();
            auto target_base_it = base_rows.find(target);
            if (target_base_it != base_rows.end())
                all_target = target_base_it->second;
            uint64 query_local_cache_hits_local = 0;
            uint64 query_local_cache_misses_local = 0;
            uint64 witness_frontier_steps_local = 0;
            uint64 contexts_total_local = 0;
            uint64 contexts_pruned_superset_local =
                (uint64)(final_terms_dedup.size() >= final_terms_pruned.size()
                             ? (final_terms_dedup.size() - final_terms_pruned.size())
                             : 0u);

            struct ContextEval {
                DenseBits target_mask;
                int iters = 0;
                int join_evals = 0;
            };
            std::unordered_map<std::string, ContextEval> context_cache;
            context_cache.reserve(feature_atom_ids.size() * 4u + 1u);
            std::unordered_map<int, std::vector<std::string>> tables_by_atom;
            tables_by_atom.reserve(feature_atom_ids.size() * 2u + 1u);
            for (int aid : feature_atom_ids) {
                auto ait = atom_ptr.find(aid);
                if (ait == atom_ptr.end())
                    continue;
                const AtomInfo &a = *(ait->second);
                std::vector<std::string> tabs;
                tabs.reserve(2u);
                if (!a.lhs.table.empty())
                    tabs.push_back(a.lhs.table);
                if (!a.rhs.table.empty() && a.rhs.table != a.lhs.table)
                    tabs.push_back(a.rhs.table);
                std::sort(tabs.begin(), tabs.end());
                tabs.erase(std::unique(tabs.begin(), tabs.end()), tabs.end());
                tables_by_atom.emplace(aid, std::move(tabs));
            }

            auto t_prop_ac0 = Clock::now();
            auto eval_context = [&](const std::vector<int> &required_raw) -> const ContextEval & {
                std::vector<int> required = required_raw;
                std::sort(required.begin(), required.end());
                required.erase(std::unique(required.begin(), required.end()), required.end());
                std::string key;
                for (size_t i = 0; i < required.size(); i++) {
                    if (i > 0)
                        key.push_back(',');
                    key += std::to_string(required[i]);
                }
                auto cit = context_cache.find(key);
                if (cit != context_cache.end()) {
                    query_local_cache_hits_local++;
                    return cit->second;
                }
                query_local_cache_misses_local++;

                std::unordered_map<std::string, DenseBits> active;
                std::unordered_set<int> required_set(required.begin(), required.end());
                std::unordered_set<std::string> required_tables;
                required_tables.reserve(required_set.size() * 2u + 2u);
                required_tables.insert(target);
                for (int aid : required) {
                    auto ait = tables_by_atom.find(aid);
                    if (ait == tables_by_atom.end())
                        continue;
                    for (const std::string &t : ait->second)
                        required_tables.insert(t);
                }
                if (required_tables.empty())
                    required_tables.insert(target);

                active.reserve(required_tables.size() * 2u + 1u);
                for (const std::string &t : required_tables) {
                    auto bitit = base_rows.find(t);
                    if (bitit != base_rows.end())
                        active.emplace(t, bitit->second);
                }

                for (int aid : required) {
                    auto ait = atom_ptr.find(aid);
                    if (ait == atom_ptr.end())
                        continue;
                    const AtomInfo &a = *(ait->second);
                    bool is_local =
                        (a.kind == POLICY_ATOM_COL_CONST) ||
                        (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table) ||
                        (a.kind == POLICY_ATOM_JOIN_EQ && a.lhs.table == a.rhs.table);
                    if (!is_local)
                        continue;
                    auto it = active.find(a.lhs.table);
                    if (it != active.end())
                        it->second.bit_and(local_mask_for_atom(a));
                }

                int iters = 0;
                int join_evals = 0;
                bool changed = true;
                while (changed && iters < 24) {
                    changed = false;
                    iters++;

                    for (size_t i = 0; i < eq_entries.size(); i++) {
                        if (required_set.find(eq_entries[i].atom_id) == required_set.end())
                            continue;
                        changed |= apply_eq_constraint(&eqs[i], &active, &join_evals);
                    }

                    for (const auto &kv : active) {
                        if (!kv.second.any()) {
                            changed = false;
                            goto done_fixpoint;
                        }
                    }

                    for (size_t i = 0; i < cmp_entries.size(); i++) {
                        if (required_set.find(cmp_entries[i].atom_id) == required_set.end())
                            continue;
                        CmpConstraint c = cmp_entries[i].cmp;
                        if (c.group_eq_idx >= 0) {
                            int ge = c.group_eq_idx;
                            if ((size_t)ge >= eq_entries.size() ||
                                required_set.find(eq_entries[(size_t)ge].atom_id) == required_set.end())
                                c.group_eq_idx = -1;
                        }
                        changed |= apply_cmp_constraint(c, eqs, &active);
                    }
                }
            done_fixpoint:
                ContextEval ce;
                ce.iters = iters;
                ce.join_evals = join_evals;
                auto tit = active.find(target);
                if (tit != active.end())
                    ce.target_mask = tit->second;
                else {
                    ce.target_mask = DenseBits(target_td->manifest.nrows);
                    ce.target_mask.clear_all();
                }
                witness_frontier_steps_local += (uint64)std::max(0, iters);
                auto ins = context_cache.emplace(key, std::move(ce));
                return ins.first->second;
            };

            std::unordered_map<std::string, std::vector<int>> required_by_key;
            std::unordered_map<std::string, DenseBits> target_mask_by_required_key;
            std::vector<std::string> key_by_term;
            required_by_key.reserve(final_terms_pruned.size() * 2u + 1u);
            target_mask_by_required_key.reserve(final_terms_pruned.size() * 2u + 1u);
            key_by_term.reserve(final_terms_pruned.size());

            auto term_key_from_req = [](const std::vector<int> &req) -> std::string {
                std::string key;
                for (size_t i = 0; i < req.size(); i++) {
                    if (i > 0)
                        key.push_back(',');
                    key += std::to_string(req[i]);
                }
                return key;
            };

            for (const ConjTerm &term : final_terms_pruned) {
                std::vector<int> req = term;
                normalize_conj_term(&req);
                std::string key = term_key_from_req(req);
                required_by_key.emplace(key, req);
                key_by_term.push_back(std::move(key));
            }

            for (const auto &kv : required_by_key) {
                const std::string &key = kv.first;
                const std::vector<int> &req = kv.second;
                const ContextEval &ce = eval_context(req);
                contexts_total_local++;
                target_mask_by_required_key.emplace(key, ce.target_mask);
            }

            exact_term_masks.clear();
            exact_term_masks.reserve(key_by_term.size());
            for (const std::string &key : key_by_term) {
                DenseBits mask(target_td->manifest.nrows);
                mask.clear_all();
                auto mit = target_mask_by_required_key.find(key);
                if (mit != target_mask_by_required_key.end())
                    mask = mit->second;
                exact_term_masks.push_back(std::move(mask));
            }

            sat_feature_ids.clear();
            sat_feature_ids.reserve(exact_term_masks.size());
            sat_var_alias.clear();
            sat_var_alias.reserve(exact_term_masks.size() * 2u + 1u);
            for (size_t i = 0; i < exact_term_masks.size(); i++) {
                int tid = (int)i + 1;
                sat_feature_ids.push_back(tid);
                sat_var_alias.emplace(tid, tid);
            }
            sat_terms_ast = build_or_postfix_ast_from_vars((uint32)exact_term_masks.size());

            auto t_prop_ac1 = Clock::now();

            auto t_candidate0 = Clock::now();
            DenseBits candidate_mask(target_td->manifest.nrows);
            candidate_mask.clear_all();
            for (const DenseBits &m : exact_term_masks)
                candidate_mask.bit_or(m);
            candidate_mask.bit_and(all_target);
            auto t_candidate1 = Clock::now();
            uint64 candidate_rows_pre_sig = candidate_mask.count();

            std::vector<DenseBits> term_masks = exact_term_masks;

            auto t_sig0 = Clock::now();
            std::vector<uint32> row_sid;
            std::vector<uint64> sid_words_flat;
            uint32 nbits = 0;
            uint32 nwords = 0;
            uint64 rows_scanned_sig_local = 0;
            build_row_signatures_subset(term_masks,
                                        candidate_mask,
                                        target_td->manifest.nrows,
                                        &row_sid,
                                        &sid_words_flat,
                                        &nbits,
                                        &nwords,
                                        &rows_scanned_sig_local);
            auto t_sig1 = Clock::now();

            std::unordered_map<int, bool> const_atom_values;
            std::vector<uint8_t> sid_allowed;
            auto t_sat0 = Clock::now();
            const PolicyAstTokC *sat_toks =
                sat_terms_ast.empty() ? nullptr : sat_terms_ast.data();
            int sat_ntok = (int)sat_terms_ast.size();
            // SAT is the final policy decider over signature assignments.
            // Candidate pruning only narrows rows/signatures; it does not replace SAT semantics.
            cvc5_allowed_sids_postfix(sat_toks,
                                      sat_ntok,
                                      sat_feature_ids,
                                      const_atom_values,
                                      sat_var_alias,
                                      sid_words_flat,
                                      nbits,
                                      nwords,
                                      &sid_allowed);
            auto t_sat1 = Clock::now();

            uint32 total_sids = (uint32)sid_allowed.size();
            uint32 allowed_sids = 0;
            for (uint8_t v : sid_allowed)
                allowed_sids += (v != 0u);

            auto t_proj0 = Clock::now();
            std::vector<uint32> block_ids;
            std::vector<uint64> block_words;
            uint64 allowed_rows = 0;
            project_allowed_rows(*target_td,
                                 row_sid,
                                 sid_allowed,
                                 &candidate_mask,
                                 &block_ids,
                                 &block_words,
                                 &allowed_rows);
            auto t_proj1 = Clock::now();

            DenseBits allow_mask(target_td->manifest.nrows);
            allow_mask.clear_all();
            candidate_mask.for_each_set([&](uint32 rid) {
                if ((size_t)rid >= row_sid.size())
                    return;
                uint32 sid = row_sid[(size_t)rid];
                if (sid == UINT32_MAX)
                    return;
                if (sid < sid_allowed.size() && sid_allowed[(size_t)sid] != 0u)
                    allow_mask.set(rid);
            });

            out->table = pstrdup(target.c_str());
            out->blocks = (uint32)block_ids.size();
            out->total_blocks = target_td->total_blocks;
            out->n_rows = target_td->manifest.nrows;
            out->allowed_rows = allowed_rows;
            out->allowed_sids = allowed_sids;
            out->total_sids = total_sids;
            out->hub_prop_ms = Ms(t_sig0 - t_prop0).count();
            out->sat_ms = Ms(t_sat1 - t_sat0).count();
            out->sid_build_ms = Ms(t_sig1 - t_sig0).count();

            int mode_hint = POLICY_MODE_HINT_FILTER;
            std::string mode_reason = "token_domain_filter";
            if (allowed_rows == 0u) {
                mode_hint = POLICY_MODE_HINT_EMPTY;
                mode_reason = "token_domain_empty";
            } else if (target_td->manifest.nrows > 0 && allowed_rows >= target_td->manifest.nrows) {
                mode_hint = POLICY_MODE_HINT_ALL;
                mode_reason = "token_domain_all";
            } else if (target_td->manifest.nrows > 0) {
                double density_tmp = (double)allowed_rows / (double)target_td->manifest.nrows;
                if (density_tmp <= 0.15) {
                    mode_hint = POLICY_MODE_HINT_TID;
                    mode_reason = "token_domain_sparse_tid";
                }
            }
            out->mode_hint = mode_hint;
            out->mode_reason = pstrdup(mode_reason.c_str());

            out->block_words = nullptr;
            out->block_ids = nullptr;
            if (!block_words.empty()) {
                size_t bytes = block_words.size() * sizeof(uint64);
                out->block_words = (uint64 *)palloc0(bytes);
                std::memcpy(out->block_words, block_words.data(), bytes);
            }
            if (!block_ids.empty()) {
                size_t bytes = block_ids.size() * sizeof(uint32);
                out->block_ids = (uint32 *)palloc0(bytes);
                std::memcpy(out->block_ids, block_ids.data(), bytes);
            }

            policy_allow_mask_cache_[target] = allow_mask;
            maybe_store_allow_cache(allow_mask);
            note_allow_cache_build_time();

            double prop_index_build_ms_local = Ms(t_prop_rel0 - t_prop_index0).count();
            double prop_rel_build_ms_local = Ms(t_prop_rel1 - t_prop_rel0).count();
            double prop_ac_delta_ms_local = Ms(t_prop_ac1 - t_prop_ac0).count();
            double candidate_prune_ms_local = Ms(t_candidate1 - t_candidate0).count();
            double target_sig_build_ms_local = Ms(t_sig1 - t_sig0).count();
            double sat_ms_local = Ms(t_sat1 - t_sat0).count();
            double project_allowset_ms_local = Ms(t_proj1 - t_proj0).count();
            double density =
                (target_td->manifest.nrows > 0)
                    ? ((double)allowed_rows / (double)target_td->manifest.nrows)
                    : 0.0;

            if (profile_) {
                profile_->build_hubs_ms += prop_index_build_ms_local;
                profile_->composite_stamp_ms += 0.0;
                profile_->build_context_ms += prop_rel_build_ms_local;
                profile_->prop_build_arcs_ms += 0.0;
                profile_->prop_ac_ms += prop_ac_delta_ms_local;
                profile_->prop_scc_ms += 0.0;
                profile_->prop_bin_catalog_ms += 0.0;
                profile_->prop_witness_ms += 0.0;
                profile_->prop_cmp_ms += 0.0;
                profile_->candidate_prune_ms += candidate_prune_ms_local;
                profile_->signature_build_ms += target_sig_build_ms_local;
                profile_->sat_ms += sat_ms_local;
                profile_->project_allowset_ms += project_allowset_ms_local;
                profile_->propagate_ms += (prop_index_build_ms_local + prop_rel_build_ms_local +
                                           prop_ac_delta_ms_local + candidate_prune_ms_local);

                profile_->prop_index_build_ms += prop_index_build_ms_local;
                profile_->prop_rel_build_ms += prop_rel_build_ms_local;
                profile_->prop_ac_delta_ms += prop_ac_delta_ms_local;
                profile_->prop_witness_frontier_ms += 0.0;
                profile_->prop_cmp_summary_ms += 0.0;
                profile_->target_sig_build_ms += target_sig_build_ms_local;

                profile_->rows_scanned_for_target_sig += rows_scanned_sig_local;
                profile_->witness_frontier_steps += witness_frontier_steps_local;
                profile_->query_local_cache_hits += query_local_cache_hits_local;
                profile_->query_local_cache_misses += query_local_cache_misses_local;
                profile_->project_n_join_evals_max = std::max<int>(profile_->project_n_join_evals_max,
                                                                   (int)eq_entries.size());

                profile_->sat_calls++;
                profile_->sat_models_total += allowed_sids;
                profile_->allow_rows_total += allowed_rows;
                profile_->bytes_block_words += block_words.size() * sizeof(uint64) +
                                              block_ids.size() * sizeof(uint32);
            }

            elog(NOTICE,
                 "policy_profile_target: table=%s n_rows=%u allowed_rows=%llu density=%.6f mode_hint=%d "
                 "nfeatures=%u natoms=%u ast_ntok=%d sat_ast_ntok=%d total_sids=%u allowed_sids=%u "
                 "exact_terms_raw=%zu exact_terms_dedup=%zu exact_terms_pruned=%zu exact_terms_subsumed=%zu "
                 "prop_index_build_ms=%.3f prop_rel_build_ms=%.3f prop_ac_delta_ms=%.3f "
                 "prop_witness_frontier_ms=%.3f prop_cmp_summary_ms=%.3f candidate_prune_ms=%.3f "
                 "target_sig_build_ms=%.3f sat_ms=%.3f project_allowset_ms=%.3f "
                 "rows_scanned_for_prop=%llu rows_scanned_for_cmp=%llu rows_scanned_for_target_sig=%llu "
                 "pair_rel_count=%llu pair_rel_edges=%llu domain_token_deletions=%llu "
                 "witness_frontier_steps=%llu query_local_cache_hits=%llu query_local_cache_misses=%llu "
                 "contexts_total=%llu contexts_cached=%llu contexts_pruned_superset=%llu candidate_rows_pre_sig=%llu",
                 target.c_str(),
                 target_td->manifest.nrows,
                 (unsigned long long)allowed_rows,
                 density,
                 mode_hint,
                 (unsigned)sat_feature_ids.size(),
                 (unsigned)feature_atom_ids.size(),
                 ast_ntok,
                 sat_ntok,
                 total_sids,
                 allowed_sids,
                 final_terms_raw.size(),
                 final_terms_dedup.size(),
                 final_terms_pruned.size(),
                 (size_t)contexts_pruned_superset_local,
                 prop_index_build_ms_local,
                 prop_rel_build_ms_local,
                 prop_ac_delta_ms_local,
                 0.0,
                 0.0,
                 candidate_prune_ms_local,
                 target_sig_build_ms_local,
                 sat_ms_local,
                 project_allowset_ms_local,
                 (unsigned long long)(profile_ ? profile_->rows_scanned_for_prop : 0),
                 (unsigned long long)(profile_ ? profile_->rows_scanned_for_cmp : 0),
                 (unsigned long long)rows_scanned_sig_local,
                 (unsigned long long)eq_entries.size(),
                 (unsigned long long)(profile_ ? profile_->pair_rel_edges : 0),
                 (unsigned long long)(profile_ ? profile_->domain_token_deletions : 0),
                 (unsigned long long)witness_frontier_steps_local,
                 (unsigned long long)query_local_cache_hits_local,
                 (unsigned long long)query_local_cache_misses_local,
                 (unsigned long long)contexts_total_local,
                 (unsigned long long)context_cache.size(),
                 (unsigned long long)contexts_pruned_superset_local,
                 (unsigned long long)candidate_rows_pre_sig);

            return true;
        } catch (const std::exception &e) {
            ereport(ERROR, (errmsg("policy: build_target_allow failed target=%s: %s",
                                   target.c_str(),
                                   e.what())));
        } catch (...) {
            ereport(ERROR, (errmsg("policy: build_target_allow failed target=%s: unknown exception",
                                   target.c_str())));
        }
        return false;
    }
private:
    int target_index(const std::string &target) const
    {
        if (!in_ || !in_->target_tables || in_->target_count <= 0)
            return -1;
        for (int i = 0; i < in_->target_count; i++) {
            if (!in_->target_tables[i])
                continue;
            if (to_lower_copy(in_->target_tables[i]) == target)
                return i;
        }
        return -1;
    }

    static cvc5::Term mk_not_term(cvc5::Solver *solver, const cvc5::Term &t)
    {
        if (!solver)
            throw std::runtime_error("cvc5 solver is null");
        std::vector<cvc5::Term> not_terms;
        not_terms.reserve(1);
        not_terms.push_back(t);
        return solver->mkTerm(cvc5::Kind::NOT, not_terms);
    }

    static void build_row_signatures_subset(const std::vector<DenseBits> &term_masks,
                                            const DenseBits &candidate_rows,
                                            uint32 nrows,
                                            std::vector<uint32> *row_sid,
                                            std::vector<uint64> *sid_words,
                                            uint32 *out_nbits,
                                            uint32 *out_nwords,
                                            uint64 *rows_scanned_out)
    {
        if (!row_sid || !sid_words || !out_nbits || !out_nwords)
            return;

        const uint32 nbits = (uint32)term_masks.size();
        const uint32 nwords = std::max<uint32>(1u, (nbits + 63u) / 64u);
        *out_nbits = nbits;
        *out_nwords = nwords;

        row_sid->assign(nrows, UINT32_MAX);
        sid_words->clear();
        if (rows_scanned_out)
            *rows_scanned_out = 0;
        if (nrows == 0 || !candidate_rows.any())
            return;

        std::vector<uint32> rids;
        rids.reserve((size_t)candidate_rows.count());
        candidate_rows.for_each_set([&](uint32 rid) {
            if (rid < nrows)
                rids.push_back(rid);
        });
        if (rows_scanned_out)
            *rows_scanned_out = (uint64)rids.size();
        if (rids.empty())
            return;

        sid_words->reserve((size_t)std::min<uint32>((uint32)rids.size(), 16384u) * nwords);
        const size_t k = term_masks.size();

        if (nwords == 1u) {
            std::unordered_map<uint64, uint32> sid_by_sig;
            sid_by_sig.reserve((size_t)std::min<uint32>((uint32)rids.size(), 16384u));
            for (uint32 rid : rids) {
                uint64 sig = 0ULL;
                for (size_t i = 0; i < k; i++) {
                    if (term_masks[i].test(rid))
                        sig |= (1ULL << i);
                }
                auto it = sid_by_sig.find(sig);
                uint32 sid = 0;
                if (it == sid_by_sig.end()) {
                    sid = (uint32)(sid_words->size() / nwords);
                    sid_by_sig.emplace(sig, sid);
                    sid_words->push_back(sig);
                } else {
                    sid = it->second;
                }
                (*row_sid)[rid] = sid;
            }
            return;
        }

        struct SigEntry {
            std::vector<uint64> words;
            uint32 sid = 0;
        };
        std::unordered_map<uint64, std::vector<SigEntry>> by_hash;
        by_hash.reserve((size_t)std::min<uint32>((uint32)rids.size(), 16384u));
        std::vector<uint64> tmp((size_t)nwords, 0ULL);

        for (uint32 rid : rids) {
            std::fill(tmp.begin(), tmp.end(), 0ULL);
            for (size_t i = 0; i < k; i++) {
                if (!term_masks[i].test(rid))
                    continue;
                tmp[i >> 6] |= (1ULL << (i & 63u));
            }
            uint64 h = 1469598103934665603ULL;
            for (uint64 w : tmp)
                h = hash_combine64(h, w);

            uint32 sid = UINT32_MAX;
            auto &bucket = by_hash[h];
            for (const SigEntry &e : bucket) {
                if (e.words == tmp) {
                    sid = e.sid;
                    break;
                }
            }
            if (sid == UINT32_MAX) {
                sid = (uint32)(sid_words->size() / nwords);
                bucket.push_back(SigEntry{tmp, sid});
                sid_words->insert(sid_words->end(), tmp.begin(), tmp.end());
            }
            (*row_sid)[rid] = sid;
        }
    }

    static cvc5::Term build_cvc5_expr_postfix(const PolicyAstTokC *toks,
                                              int ntok,
                                              cvc5::Solver *solver,
                                              const std::unordered_map<int, cvc5::Term> &atom_vars)
    {
        if (!solver)
            throw std::runtime_error("cvc5 solver is null");
        if (!toks || ntok <= 0)
            return solver->mkTrue();

        std::vector<cvc5::Term> st;
        st.reserve((size_t)ntok);
        for (int i = 0; i < ntok; i++) {
            const PolicyAstTokC &tk = toks[i];
            if (tk.kind == POLICY_AST_TOK_TRUE) {
                st.push_back(solver->mkTrue());
                continue;
            }
            if (tk.kind == POLICY_AST_TOK_FALSE) {
                st.push_back(solver->mkFalse());
                continue;
            }
            if (tk.kind == POLICY_AST_TOK_VAR) {
                if (tk.value <= 0) {
                    st.push_back(solver->mkFalse());
                } else {
                    auto it = atom_vars.find(tk.value);
                    if (it == atom_vars.end()) {
                        throw std::runtime_error("unknown AST variable in SAT term");
                    }
                    st.push_back(it->second);
                }
                continue;
            }
            if (tk.kind != POLICY_AST_TOK_AND && tk.kind != POLICY_AST_TOK_OR)
                throw std::runtime_error("invalid AST token kind");
            if (st.size() < 2)
                throw std::runtime_error("postfix AST stack underflow");
            cvc5::Term b = st.back();
            st.pop_back();
            cvc5::Term a = st.back();
            st.pop_back();
            if (tk.kind == POLICY_AST_TOK_OR) {
                std::vector<cvc5::Term> ors;
                ors.reserve(2);
                ors.push_back(a);
                ors.push_back(b);
                st.push_back(solver->mkTerm(cvc5::Kind::OR, ors));
            } else {
                std::vector<cvc5::Term> ands;
                ands.reserve(2);
                ands.push_back(a);
                ands.push_back(b);
                st.push_back(solver->mkTerm(cvc5::Kind::AND, ands));
            }
        }
        if (st.size() != 1)
            throw std::runtime_error("postfix AST final stack size != 1");
        return st.back();
    }

    void cvc5_allowed_sids_postfix(const PolicyAstTokC *ast_toks,
                                   int ast_ntok,
                                   const std::vector<int> &feature_atom_ids,
                                   const std::unordered_map<int, bool> &const_atom_values,
                                   const std::unordered_map<int, int> &atom_alias,
                                   const std::vector<uint64> &sid_words,
                                   uint32 sid_nbits,
                                   uint32 sid_nwords,
                                   std::vector<uint8_t> *sid_allowed)
    {
        if (!sid_allowed)
            return;
        uint32 sid_count = (sid_nwords > 0) ? (uint32)(sid_words.size() / sid_nwords) : 0u;
        sid_allowed->assign(sid_count, 0u);
        if (sid_count == 0)
            return;
        if (!ast_toks || ast_ntok <= 0) {
            std::fill(sid_allowed->begin(), sid_allowed->end(), 1u);
            return;
        }

        if (sid_nbits != feature_atom_ids.size())
            ereport(ERROR,
                    (errmsg("policy: signature bitwidth mismatch sid_nbits=%u feature_atoms=%zu",
                            sid_nbits, feature_atom_ids.size())));

        auto resolve_alias = [&](int aid) -> int {
            int cur = aid;
            for (int hops = 0; hops < 16; hops++) {
                auto it = atom_alias.find(cur);
                if (it == atom_alias.end() || it->second <= 0 || it->second == cur)
                    break;
                cur = it->second;
            }
            return cur;
        };

        std::vector<PolicyAstTokC> ast_norm;
        {
            std::string ast_err;
            if (!canonicalize_postfix_ast(ast_toks, ast_ntok, &ast_norm, &ast_err))
                ereport(ERROR, (errmsg("policy: malformed AST in SAT stage: %s", ast_err.c_str())));
        }
        for (PolicyAstTokC &tk : ast_norm) {
            if (tk.kind == POLICY_AST_TOK_VAR && tk.value > 0)
                tk.value = resolve_alias(tk.value);
        }
        const PolicyAstTokC *ast_use = ast_norm.empty() ? nullptr : ast_norm.data();
        int ast_use_ntok = (int)ast_norm.size();
        if (!ast_use || ast_use_ntok <= 0) {
            std::fill(sid_allowed->begin(), sid_allowed->end(), 1u);
            return;
        }

        std::set<int> atom_ids;
        for (int i = 0; i < ast_use_ntok; i++) {
            if (ast_use[i].kind == POLICY_AST_TOK_VAR && ast_use[i].value > 0)
                atom_ids.insert(ast_use[i].value);
        }

        std::string sat_stage = "init";
        uint64 sat_sid_count_local = sid_count;
        uint64 sat_check_calls_local = 0;
        uint64 sat_assumptions_total_local = 0;
        uint64 sat_unique_assignments_local = 0;
        uint64 sat_cache_hits_local = 0;
        uint64 sat_nogood_prunes_local = 0;
        uint64 sat_nogoods_added_local = 0;
        uint64 sat_core_terms_total_local = 0;
        uint64 sat_core_terms_max_local = 0;
        uint64 sat_subsumed_dropped_local = 0;
        try {
            cvc5::Solver solver;
            solver.setOption("produce-models", "false");
            solver.setOption("incremental", "true");
            solver.setOption("produce-unsat-assumptions", "true");
            solver.setLogic("QF_UF");

            cvc5::Sort bsort = solver.getBooleanSort();
            std::unordered_map<int, cvc5::Term> atom_vars;
            std::unordered_map<int, cvc5::Term> atom_pos_lit;
            std::unordered_map<int, cvc5::Term> atom_neg_lit;
            atom_vars.reserve(atom_ids.size() * 2u + 1u);
            atom_pos_lit.reserve(atom_ids.size() * 2u + 1u);
            atom_neg_lit.reserve(atom_ids.size() * 2u + 1u);
            for (int aid : atom_ids) {
                cvc5::Term v = solver.mkConst(bsort, "y" + std::to_string(aid));
                atom_vars.emplace(aid, v);
                atom_pos_lit.emplace(aid, v);
                atom_neg_lit.emplace(aid, mk_not_term(&solver, v));
            }

            sat_stage = "build_expr";
            cvc5::Term expr = build_cvc5_expr_postfix(ast_use, ast_use_ntok, &solver, atom_vars);
            sat_stage = "assert_expr";
            solver.assertFormula(expr);

            std::unordered_map<int, bool> const_norm;
            const_norm.reserve(const_atom_values.size() * 2u + 1u);
            bool const_conflict = false;
            for (const auto &kv : const_atom_values) {
                int aid = resolve_alias(kv.first);
                auto itc = const_norm.find(aid);
                if (itc == const_norm.end()) {
                    const_norm.emplace(aid, kv.second);
                } else if (itc->second != kv.second) {
                    const_conflict = true;
                    break;
                }
            }
            if (const_conflict) {
                std::fill(sid_allowed->begin(), sid_allowed->end(), 0u);
                if (profile_) {
                    profile_->sat_sid_count += sat_sid_count_local;
                    profile_->sat_check_calls += sat_check_calls_local;
                    profile_->sat_assumptions_total += sat_assumptions_total_local;
                    profile_->sat_unique_assignments += sat_unique_assignments_local;
                    profile_->sat_cache_hits += sat_cache_hits_local;
                    profile_->sat_nogood_prunes += sat_nogood_prunes_local;
                    profile_->sat_nogoods_added += sat_nogoods_added_local;
                    profile_->sat_core_terms_total += sat_core_terms_total_local;
                    profile_->sat_core_terms_max =
                        std::max<uint64>(profile_->sat_core_terms_max, sat_core_terms_max_local);
                    profile_->sat_subsumed_dropped += sat_subsumed_dropped_local;
                }
                return;
            }

            for (const auto &kv : const_norm) {
                auto it = atom_vars.find(kv.first);
                if (it == atom_vars.end())
                    continue;
                auto pit = atom_pos_lit.find(kv.first);
                auto nit = atom_neg_lit.find(kv.first);
                if (pit == atom_pos_lit.end() || nit == atom_neg_lit.end())
                    continue;
                solver.assertFormula(kv.second ? pit->second : nit->second);
            }

            std::vector<uint32> used_feature_bits;
            std::vector<cvc5::Term> used_true_lits;
            std::vector<cvc5::Term> used_false_lits;
            used_feature_bits.reserve(feature_atom_ids.size());
            used_true_lits.reserve(feature_atom_ids.size());
            used_false_lits.reserve(feature_atom_ids.size());
            for (size_t i = 0; i < feature_atom_ids.size(); i++) {
                int aid = resolve_alias(feature_atom_ids[i]);
                if (const_norm.find(aid) != const_norm.end())
                    continue;
                auto vit = atom_vars.find(aid);
                if (vit == atom_vars.end())
                    continue;
                auto pit = atom_pos_lit.find(aid);
                auto nit = atom_neg_lit.find(aid);
                if (pit == atom_pos_lit.end() || nit == atom_neg_lit.end())
                    continue;
                used_feature_bits.push_back((uint32)i);
                used_true_lits.push_back(pit->second);
                used_false_lits.push_back(nit->second);
            }

            std::vector<cvc5::Term> assumptions;
            assumptions.resize(used_feature_bits.size());
            std::unordered_map<uint64, uint8_t> sid_cache_u64;
            struct BitsCacheEntry {
                std::vector<uint64> key_words;
                uint8_t value = 0u;
            };
            std::unordered_map<uint64, std::vector<BitsCacheEntry>> sid_cache_bits;
            bool cache64 = used_feature_bits.size() <= 64u;
            const uint32 key_nwords = cache64 ? 0u : (uint32)((used_feature_bits.size() + 63u) / 64u);
            std::vector<uint64> key_words;
            if (!cache64)
                key_words.assign((size_t)key_nwords, 0ULL);

            std::vector<cvc5::Term> assum_terms;
            std::vector<uint32> assum_codes;
            assum_terms.reserve(used_feature_bits.size() * 2u + 1u);
            assum_codes.reserve(used_feature_bits.size() * 2u + 1u);
            for (uint32 ui = 0; ui < (uint32)used_feature_bits.size(); ui++) {
                assum_terms.push_back(used_true_lits[(size_t)ui]);
                assum_codes.push_back((ui << 1) | 1u);
                assum_terms.push_back(used_false_lits[(size_t)ui]);
                assum_codes.push_back(ui << 1);
            }
            auto decode_assumption_code = [&](const cvc5::Term &t, uint32 *code_out) -> bool {
                for (size_t i = 0; i < assum_terms.size(); i++) {
                    if (assum_terms[i] == t) {
                        if (code_out)
                            *code_out = assum_codes[i];
                        return true;
                    }
                }
                return false;
            };

            struct Nogood64 {
                uint64 mask = 0ULL;
                uint64 value = 0ULL;
            };
            struct NogoodBits {
                std::vector<uint64> mask_words;
                std::vector<uint64> value_words;
            };
            std::vector<Nogood64> nogoods64;
            std::vector<NogoodBits> nogoods_bits;
            nogoods64.reserve(64);
            nogoods_bits.reserve(64);

            auto nogood64_matches = [&](uint64 sig) -> bool {
                for (const Nogood64 &ng : nogoods64) {
                    if ((sig & ng.mask) == ng.value)
                        return true;
                }
                return false;
            };
            auto add_nogood64_from_core = [&](const std::vector<cvc5::Term> &core_terms) {
                sat_core_terms_total_local += (uint64)core_terms.size();
                sat_core_terms_max_local = std::max<uint64>(sat_core_terms_max_local, (uint64)core_terms.size());
                uint64 mask = 0ULL;
                uint64 value = 0ULL;
                for (const cvc5::Term &t : core_terms) {
                    uint32 code = 0;
                    if (!decode_assumption_code(t, &code))
                        continue;
                    uint32 ui = code >> 1;
                    bool on = (code & 1u) != 0u;
                    if (ui >= 64u)
                        continue;
                    uint64 bm = (1ULL << ui);
                    mask |= bm;
                    if (on)
                        value |= bm;
                }
                if (mask == 0ULL)
                    return;
                for (const Nogood64 &ng : nogoods64) {
                    bool existing_subsumes_new =
                        ((mask & ng.mask) == ng.mask) &&
                        ((value & ng.mask) == ng.value);
                    if (existing_subsumes_new) {
                        sat_subsumed_dropped_local++;
                        return;
                    }
                }
                size_t wr = 0;
                uint64 removed = 0;
                for (size_t i = 0; i < nogoods64.size(); i++) {
                    const Nogood64 &ng = nogoods64[i];
                    bool new_subsumes_existing =
                        ((ng.mask & mask) == mask) &&
                        ((ng.value & mask) == value);
                    if (new_subsumes_existing) {
                        removed++;
                        continue;
                    }
                    if (wr != i)
                        nogoods64[wr] = ng;
                    wr++;
                }
                nogoods64.resize(wr);
                nogoods64.push_back(Nogood64{mask, value});
                sat_subsumed_dropped_local += removed;
                sat_nogoods_added_local++;
            };

            auto nogood_bits_matches = [&](const std::vector<uint64> &key) -> bool {
                for (const NogoodBits &ng : nogoods_bits) {
                    bool ok = true;
                    for (size_t w = 0; w < key.size(); w++) {
                        if ((key[w] & ng.mask_words[w]) != ng.value_words[w]) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok)
                        return true;
                }
                return false;
            };
            auto add_nogood_bits_from_core = [&](const std::vector<cvc5::Term> &core_terms) {
                if (key_nwords == 0u)
                    return;
                sat_core_terms_total_local += (uint64)core_terms.size();
                sat_core_terms_max_local = std::max<uint64>(sat_core_terms_max_local, (uint64)core_terms.size());
                std::vector<uint64> mask((size_t)key_nwords, 0ULL);
                std::vector<uint64> value((size_t)key_nwords, 0ULL);
                for (const cvc5::Term &t : core_terms) {
                    uint32 code = 0;
                    if (!decode_assumption_code(t, &code))
                        continue;
                    uint32 ui = code >> 1;
                    bool on = (code & 1u) != 0u;
                    uint32 wi = ui >> 6;
                    if (wi >= key_nwords)
                        continue;
                    uint64 bm = (1ULL << (ui & 63u));
                    mask[(size_t)wi] |= bm;
                    if (on)
                        value[(size_t)wi] |= bm;
                }
                bool any = false;
                for (uint64 w : mask) {
                    if (w != 0ULL) {
                        any = true;
                        break;
                    }
                }
                if (!any)
                    return;

                for (const NogoodBits &ng : nogoods_bits) {
                    bool existing_subsumes_new = true;
                    for (uint32 w = 0; w < key_nwords; w++) {
                        if ((mask[(size_t)w] & ng.mask_words[(size_t)w]) != ng.mask_words[(size_t)w] ||
                            (value[(size_t)w] & ng.mask_words[(size_t)w]) != ng.value_words[(size_t)w]) {
                            existing_subsumes_new = false;
                            break;
                        }
                    }
                    if (existing_subsumes_new) {
                        sat_subsumed_dropped_local++;
                        return;
                    }
                }

                size_t wr = 0;
                uint64 removed = 0;
                for (size_t i = 0; i < nogoods_bits.size(); i++) {
                    const NogoodBits &ng = nogoods_bits[i];
                    bool new_subsumes_existing = true;
                    for (uint32 w = 0; w < key_nwords; w++) {
                        if ((ng.mask_words[(size_t)w] & mask[(size_t)w]) != mask[(size_t)w] ||
                            (ng.value_words[(size_t)w] & mask[(size_t)w]) != value[(size_t)w]) {
                            new_subsumes_existing = false;
                            break;
                        }
                    }
                    if (new_subsumes_existing) {
                        removed++;
                        continue;
                    }
                    if (wr != i)
                        nogoods_bits[wr] = ng;
                    wr++;
                }
                nogoods_bits.resize(wr);

                NogoodBits ng;
                ng.mask_words = std::move(mask);
                ng.value_words = std::move(value);
                nogoods_bits.push_back(std::move(ng));
                sat_subsumed_dropped_local += removed;
                sat_nogoods_added_local++;
            };

            if (cache64)
                sid_cache_u64.reserve(std::min<uint32>(sid_count, 65536u));
            else
                sid_cache_bits.reserve(std::min<uint32>(sid_count, 65536u));

            for (uint32 sid = 0; sid < sid_count; sid++) {
                size_t base = (size_t)sid * (size_t)sid_nwords;
                uint8_t cached = 0u;

                if (cache64) {
                    uint64 sig = 0ULL;
                    for (size_t ui = 0; ui < used_feature_bits.size(); ui++) {
                        uint32 bit = used_feature_bits[ui];
                        uint64 w = sid_words[base + (bit >> 6)];
                        if (((w >> (bit & 63u)) & 1ULL) != 0ULL)
                            sig |= (1ULL << ui);
                    }
                    if (nogood64_matches(sig)) {
                        cached = 0u;
                        sat_nogood_prunes_local++;
                    } else {
                        auto cit = sid_cache_u64.find(sig);
                        if (cit != sid_cache_u64.end()) {
                            cached = cit->second;
                            sat_cache_hits_local++;
                        } else {
                            for (size_t ui = 0; ui < used_feature_bits.size(); ui++) {
                                bool on = ((sig >> ui) & 1ULL) != 0ULL;
                                assumptions[ui] = on ? used_true_lits[ui] : used_false_lits[ui];
                            }
                            sat_stage = "check_sid";
                            sat_check_calls_local++;
                            sat_assumptions_total_local += assumptions.size();
                            sat_unique_assignments_local++;
                            cvc5::Result r = assumptions.empty() ? solver.checkSat() : solver.checkSatAssuming(assumptions);
                            cached = (uint8_t)(r.isSat() ? 1u : 0u);
                            sid_cache_u64.emplace(sig, cached);
                            if (cached == 0u && !assumptions.empty()) {
                                try {
                                    std::vector<cvc5::Term> core_terms = solver.getUnsatAssumptions();
                                    add_nogood64_from_core(core_terms);
                                } catch (const std::exception &) {
                                }
                            }
                        }
                    }
                } else {
                    std::fill(key_words.begin(), key_words.end(), 0ULL);
                    for (size_t ui = 0; ui < used_feature_bits.size(); ui++) {
                        uint32 bit = used_feature_bits[ui];
                        uint64 w = sid_words[base + (bit >> 6)];
                        if (((w >> (bit & 63u)) & 1ULL) != 0ULL)
                            key_words[ui >> 6] |= (1ULL << (ui & 63u));
                    }
                    uint64 kh = 1469598103934665603ULL;
                    for (uint64 w : key_words)
                        kh = hash_combine64(kh, w);
                    if (nogood_bits_matches(key_words)) {
                        cached = 0u;
                        sat_nogood_prunes_local++;
                    } else {
                        auto bit = sid_cache_bits.find(kh);
                        bool hit = false;
                        if (bit != sid_cache_bits.end()) {
                            for (const BitsCacheEntry &ent : bit->second) {
                                if (ent.key_words == key_words) {
                                    cached = ent.value;
                                    sat_cache_hits_local++;
                                    hit = true;
                                    break;
                                }
                            }
                        }
                        if (!hit) {
                            for (size_t ui = 0; ui < used_feature_bits.size(); ui++) {
                                bool on = ((key_words[ui >> 6] >> (ui & 63u)) & 1ULL) != 0ULL;
                                assumptions[ui] = on ? used_true_lits[ui] : used_false_lits[ui];
                            }
                            sat_stage = "check_sid";
                            sat_check_calls_local++;
                            sat_assumptions_total_local += assumptions.size();
                            sat_unique_assignments_local++;
                            cvc5::Result r = assumptions.empty() ? solver.checkSat() : solver.checkSatAssuming(assumptions);
                            cached = (uint8_t)(r.isSat() ? 1u : 0u);
                            sid_cache_bits[kh].push_back(BitsCacheEntry{key_words, cached});
                            if (cached == 0u && !assumptions.empty()) {
                                try {
                                    std::vector<cvc5::Term> core_terms = solver.getUnsatAssumptions();
                                    add_nogood_bits_from_core(core_terms);
                                } catch (const std::exception &) {
                                }
                            }
                        } else {
                            // cached set above on hit
                        }
                    }
                }
                (*sid_allowed)[sid] = cached;
            }
            if (profile_) {
                profile_->sat_sid_count += sat_sid_count_local;
                profile_->sat_check_calls += sat_check_calls_local;
                profile_->sat_assumptions_total += sat_assumptions_total_local;
                profile_->sat_unique_assignments += sat_unique_assignments_local;
                profile_->sat_cache_hits += sat_cache_hits_local;
                profile_->sat_nogood_prunes += sat_nogood_prunes_local;
                profile_->sat_nogoods_added += sat_nogoods_added_local;
                profile_->sat_core_terms_total += sat_core_terms_total_local;
                profile_->sat_core_terms_max =
                    std::max<uint64>(profile_->sat_core_terms_max, sat_core_terms_max_local);
                profile_->sat_subsumed_dropped += sat_subsumed_dropped_local;
            }
        } catch (const std::exception &e) {
            ereport(ERROR, (errmsg("policy: cvc5 failure stage=%s: %s",
                                   sat_stage.c_str(),
                                   e.what())));
        }
    }

    static void project_allowed_rows(const TableArtifact &td,
                                     const std::vector<uint32> &row_sid,
                                     const std::vector<uint8_t> &sid_allowed,
                                     const DenseBits *root_mask,
                                     std::vector<uint32> *out_block_ids,
                                     std::vector<uint64> *out_block_words,
                                     uint64 *out_allowed_rows)
    {
        if (!out_block_ids || !out_block_words)
            return;
        out_block_ids->clear();
        out_block_words->clear();
        if (out_allowed_rows)
            *out_allowed_rows = 0;
        if (row_sid.empty() || sid_allowed.empty())
            return;

        std::map<uint32, std::array<uint64, kWordsPerBlock>> by_blk;
        size_t n = std::min(row_sid.size(), td.ctid_blk.size());
        n = std::min(n, td.ctid_off.size());
        for (size_t rid = 0; rid < n; rid++) {
            if (root_mask && !root_mask->test((uint32)rid))
                continue;
            uint32 sid = row_sid[rid];
            if (sid >= sid_allowed.size() || sid_allowed[sid] == 0u)
                continue;
            int32 blk_i = td.ctid_blk[rid];
            int32 off_i = td.ctid_off[rid];
            if (blk_i < 0 || off_i < 1 || off_i > (int32)kMaxOff)
                continue;
            uint32 blk = (uint32)blk_i;
            uint32 off0 = (uint32)off_i - 1u;
            uint32 wi = off0 >> 6;
            uint32 bi = off0 & 63u;
            auto &arr = by_blk[blk];
            arr[wi] |= (1ULL << bi);
            if (out_allowed_rows)
                (*out_allowed_rows)++;
        }

        out_block_ids->reserve(by_blk.size());
        out_block_words->reserve(by_blk.size() * kWordsPerBlock);
        for (const auto &kv : by_blk) {
            out_block_ids->push_back(kv.first);
            for (uint32 i = 0; i < kWordsPerBlock; i++)
                out_block_words->push_back(kv.second[i]);
        }
    }

    TableArtifact *require_table(const std::string &table)
    {
        auto it = tables_.find(table);
        if (it != tables_.end())
            return &it->second;

        auto t0 = Clock::now();

        BlobRef manifest_b;
        BlobRef ctid_b;
        BlobRef cols_b;

        std::string mname = table + "_code_base";
        std::string cname = table + "_ctid";
        std::string colname = "meta/cols/" + table;

        if (!resolver_.get(mname, &manifest_b))
            ereport(ERROR, (errmsg("policy: missing artifact %s", mname.c_str())));
        if (!resolver_.get(cname, &ctid_b))
            ereport(ERROR, (errmsg("policy: missing artifact %s", cname.c_str())));
        if (!resolver_.get(colname, &cols_b))
            ereport(ERROR, (errmsg("policy: missing artifact %s", colname.c_str())));

        TableArtifact td;
        td.name = table;

        if (manifest_b.len < 20 || std::memcmp(manifest_b.data, "CB04", 4) != 0)
            ereport(ERROR, (errmsg("policy: malformed code manifest %s", mname.c_str())));

        size_t p = 4;
        int32 nrows = 0, chunk_rows = 0, ncols = 0, nchunks = 0;
        if (!read_i32(manifest_b.data, manifest_b.len, &p, &nrows) ||
            !read_i32(manifest_b.data, manifest_b.len, &p, &chunk_rows) ||
            !read_i32(manifest_b.data, manifest_b.len, &p, &ncols) ||
            !read_i32(manifest_b.data, manifest_b.len, &p, &nchunks))
            ereport(ERROR, (errmsg("policy: truncated code manifest %s", mname.c_str())));

        td.manifest.nrows = (uint32)std::max(0, nrows);
        td.manifest.chunk_rows = (uint32)std::max(1, chunk_rows);
        td.manifest.ncols = (uint32)std::max(0, ncols);
        td.manifest.nchunks = (uint32)std::max(0, nchunks);

        if (ctid_b.len % (sizeof(int32) * 2u) != 0)
            ereport(ERROR, (errmsg("policy: malformed ctid artifact %s", cname.c_str())));

        size_t n_pairs = ctid_b.len / (sizeof(int32) * 2u);
        td.ctid_blk.resize(n_pairs);
        td.ctid_off.resize(n_pairs);

        const int32 *cp = (const int32 *)ctid_b.data;
        int32 max_blk = -1;
        for (size_t i = 0; i < n_pairs; i++) {
            int32 blk = cp[i * 2u + 0u];
            int32 off = cp[i * 2u + 1u];
            td.ctid_blk[i] = blk;
            td.ctid_off[i] = off;
            if (blk > max_blk)
                max_blk = blk;
        }
        td.total_blocks = (max_blk >= 0) ? ((uint32)max_blk + 1u) : 0u;
        if (td.manifest.nrows == 0)
            td.manifest.nrows = (uint32)n_pairs;
        if ((uint32)n_pairs != td.manifest.nrows)
            ereport(ERROR,
                    (errmsg("policy: row-count mismatch for table %s manifest=%u ctid=%zu",
                            table.c_str(), td.manifest.nrows, n_pairs)));

        td.cols = split_lines_blob(cols_b);
        for (size_t i = 0; i < td.cols.size(); i++) {
            std::string full = to_lower_copy(td.cols[i]);
            td.col_idx[full] = (int)i;
            size_t dot = full.find('.');
            if (dot != std::string::npos && dot + 1 < full.size()) {
                std::string bare = full.substr(dot + 1);
                if (td.col_idx.find(bare) == td.col_idx.end())
                    td.col_idx[bare] = (int)i;
            }
        }

        auto it2 = tables_.emplace(table, std::move(td)).first;

        if (profile_)
            profile_->artifact_parse_ms += Ms(Clock::now() - t0).count();
        return &it2->second;
    }

    int require_col_idx(const std::string &table, const std::string &col)
    {
        TableArtifact *td = require_table(table);
        auto it = td->col_idx.find(to_lower_copy(col));
        if (it != td->col_idx.end())
            return it->second;

        std::string full = to_lower_copy(table + "." + col);
        auto it2 = td->col_idx.find(full);
        if (it2 != td->col_idx.end())
            return it2->second;

        ereport(ERROR, (errmsg("policy: column not found in artifacts: %s.%s", table.c_str(), col.c_str())));
        return -1;
    }

    int find_col_idx_or_neg(const std::string &table, const std::string &col)
    {
        TableArtifact *td = require_table(table);
        auto it = td->col_idx.find(to_lower_copy(col));
        if (it != td->col_idx.end())
            return it->second;

        std::string full = to_lower_copy(table + "." + col);
        auto it2 = td->col_idx.find(full);
        if (it2 != td->col_idx.end())
            return it2->second;

        return -1;
    }

    const std::vector<int32> *decode_col_tokens(const std::string &table, int col_idx)
    {
        TableArtifact *td = require_table(table);
        auto it = td->col_tokens.find(col_idx);
        if (it != td->col_tokens.end())
            return &it->second;

        auto t0 = Clock::now();

        std::vector<int32> out;
        out.reserve(td->manifest.nrows);

        for (uint32 chunk = 0; chunk < td->manifest.nchunks; chunk++) {
            std::string cname = table + "_code_col_" + std::to_string(col_idx) + "_chunk_" + std::to_string(chunk);
            BlobRef b;
            if (!resolver_.get(cname, &b))
                ereport(ERROR, (errmsg("policy: missing code chunk %s", cname.c_str())));
            if (b.len < 16 || std::memcmp(b.data, "CC04", 4) != 0)
                ereport(ERROR, (errmsg("policy: malformed code chunk %s", cname.c_str())));

            size_t p = 4;
            int32 rows_i32 = 0;
            int32 payload_len_i32 = 0;
            uint16 bw = 0;
            uint16 reserved = 0;

            if (!read_i32(b.data, b.len, &p, &rows_i32))
                ereport(ERROR, (errmsg("policy: truncated chunk header %s", cname.c_str())));
            if (p + sizeof(uint16) * 2u > b.len)
                ereport(ERROR, (errmsg("policy: truncated bw/reserved in %s", cname.c_str())));
            std::memcpy(&bw, b.data + p, sizeof(uint16));
            p += sizeof(uint16);
            std::memcpy(&reserved, b.data + p, sizeof(uint16));
            p += sizeof(uint16);
            (void)reserved;
            if (!read_i32(b.data, b.len, &p, &payload_len_i32))
                ereport(ERROR, (errmsg("policy: truncated payload len %s", cname.c_str())));

            if (rows_i32 < 0 || payload_len_i32 < 0)
                ereport(ERROR, (errmsg("policy: negative chunk header %s", cname.c_str())));

            uint32 rows = (uint32)rows_i32;
            uint32 payload_len = (uint32)payload_len_i32;
            if (p + payload_len > b.len)
                ereport(ERROR, (errmsg("policy: payload overflow %s", cname.c_str())));

            const uint8 *payload = (const uint8 *)(b.data + p);
            size_t payload_pos = 0;
            uint64 acc = 0;
            int acc_bits = 0;
            uint64 mask = (bw == 64) ? ~0ULL : ((bw == 0) ? 0ULL : ((1ULL << bw) - 1ULL));

            for (uint32 r = 0; r < rows; r++) {
                while (acc_bits < (int)bw) {
                    if (payload_pos >= payload_len)
                        ereport(ERROR, (errmsg("policy: bitpack underflow %s", cname.c_str())));
                    acc |= ((uint64)payload[payload_pos++]) << acc_bits;
                    acc_bits += 8;
                }
                uint32 enc = (uint32)(acc & mask);
                acc >>= bw;
                acc_bits -= (int)bw;
                int32 tok = (enc == 0u) ? -1 : (int32)(enc - 1u);
                out.push_back(tok);
            }
        }

        if (out.size() != td->manifest.nrows)
            ereport(ERROR,
                    (errmsg("policy: decoded rows mismatch table=%s col=%d decoded=%zu expected=%u",
                            table.c_str(), col_idx, out.size(), td->manifest.nrows)));

        auto it2 = td->col_tokens.emplace(col_idx, std::move(out)).first;
        if (profile_) {
            profile_->decode_ms += Ms(Clock::now() - t0).count();
            profile_->bytes_decoded_buffers_retained += it2->second.size() * sizeof(int32);
        }
        return &it2->second;
    }

    int domain_of_col(const ColRef &c) const
    {
        auto it = col_domain_.find(c.key());
        return (it == col_domain_.end()) ? -1 : it->second;
    }

    void load_col_domain_meta()
    {
        auto t0 = Clock::now();
        BlobRef b;
        if (!resolver_.get("meta/col_domain", &b)) {
            if (profile_)
                profile_->artifact_parse_ms += Ms(Clock::now() - t0).count();
            return;
        }
        std::vector<std::string> lines = split_lines_blob(b);
        for (const std::string &ln : lines) {
            size_t eq = ln.find('=');
            if (eq == std::string::npos)
                continue;
            std::string k = to_lower_copy(trim_copy(ln.substr(0, eq)));
            std::string v = trim_copy(ln.substr(eq + 1));
            col_domain_[k] = std::atoi(v.c_str());
        }
        if (profile_)
            profile_->artifact_parse_ms += Ms(Clock::now() - t0).count();
    }

    void load_atoms()
    {
        atom_by_id_.clear();
        if (!in_ || !in_->atoms || in_->atom_count <= 0)
            return;

        atom_by_id_.reserve((size_t)in_->atom_count * 2u + 1u);
        for (int i = 0; i < in_->atom_count; i++) {
            const PolicyAtomC &a = in_->atoms[i];
            AtomInfo ai;
            ai.atom_id = a.atom_id;
            ai.kind = a.kind;
            ai.op = a.op;
            ai.join_class_id = a.join_class_id;
            ai.scope_id = parse_scope_id_from_canon_key(a.canon_key);
            if (a.lhs_schema_key)
                (void)parse_schema_key(a.lhs_schema_key, &ai.lhs);
            if (a.rhs_schema_key)
                (void)parse_schema_key(a.rhs_schema_key, &ai.rhs);
            for (int k = 0; k < a.const_count; k++) {
                const char *cv = (a.const_values && a.const_values[k]) ? a.const_values[k] : "";
                ai.const_values.emplace_back(cv);
            }

            if (ai.join_class_id < 0 && ai.kind == POLICY_ATOM_COL_CONST)
                ai.join_class_id = domain_of_col(ai.lhs);
            if (ai.kind == POLICY_ATOM_COL_COL && ai.join_class_id < 0)
                ai.join_class_id = domain_of_col(ai.lhs);

            atom_by_id_[ai.atom_id] = std::move(ai);
        }
    }

    void load_scan_qual_atoms()
    {
        scan_quals_.clear();
        if (!in_ || !in_->scan_qual_atoms || in_->scan_qual_atom_count <= 0)
            return;

        scan_quals_.reserve((size_t)in_->scan_qual_atom_count);
        for (int i = 0; i < in_->scan_qual_atom_count; i++) {
            const PolicyScanQualAtomC &qa = in_->scan_qual_atoms[i];
            if (!qa.target_table || !qa.target_table[0])
                continue;

            QualAtom q;
            q.table = to_lower_copy(qa.target_table);
            q.kind = qa.kind;
            q.op = qa.op;
            if (qa.lhs_schema_key)
                (void)parse_schema_key(qa.lhs_schema_key, &q.lhs);
            if (qa.rhs_schema_key)
                (void)parse_schema_key(qa.rhs_schema_key, &q.rhs);
            if (qa.const_value)
                q.const_value = qa.const_value;

            scan_quals_.push_back(std::move(q));
        }
    }

    bool load_dict(const AtomInfo &a, const ColRef &col, int domain_id, DictData *out)
    {
        if (!out)
            return false;

        std::string cache_key;
        std::string dict_name;
        std::string dtype_name;

        if (domain_id >= 0) {
            std::string sid = std::to_string(domain_id);
            cache_key = "domain:" + sid;
            dict_name = "dict/domain/" + sid;
            dtype_name = "meta/dict_type/domain/" + sid;
        } else {
            cache_key = col.key();
            dict_name = "dict/" + col.table + "/" + col.col;
            dtype_name = "meta/dict_type/" + col.table + "/" + col.col;
        }

        auto it = dict_cache_.find(cache_key);
        if (it != dict_cache_.end()) {
            *out = it->second;
            return true;
        }

        BlobRef db;
        if (!resolver_.get(dict_name, &db))
            ereport(ERROR, (errmsg("policy: missing dict artifact %s", dict_name.c_str())));

        BlobRef tb;
        std::string dtype = "text";
        if (resolver_.get(dtype_name, &tb) && tb.ok() && tb.len > 0)
            dtype = to_lower_copy(trim_copy(std::string(tb.data, tb.len)));

        DictData d;
        d.dtype = dtype;

        size_t p = 0;
        while (p < db.len) {
            int32 n = 0;
            if (!read_i32(db.data, db.len, &p, &n))
                ereport(ERROR, (errmsg("policy: malformed dict header %s", dict_name.c_str())));
            if (n < 0 || p + (size_t)n > db.len)
                ereport(ERROR, (errmsg("policy: malformed dict payload %s", dict_name.c_str())));
            d.values.emplace_back(db.data + p, (size_t)n);
            p += (size_t)n;
        }

        d.token_by_norm.reserve(d.values.size() * 2u + 1u);
        for (size_t i = 0; i < d.values.size(); i++) {
            std::string norm = normalize_literal_for_type(d.values[i], d.dtype);
            if (d.token_by_norm.find(norm) == d.token_by_norm.end())
                d.token_by_norm[norm] = (int32)i;
        }

        auto it2 = dict_cache_.emplace(cache_key, std::move(d)).first;
        *out = it2->second;
        (void)a;
        return true;
    }

    bool load_rank(int domain_id, RankData *out)
    {
        if (!out)
            return false;

        auto it = rank_cache_.find(domain_id);
        if (it != rank_cache_.end()) {
            *out = it->second;
            return true;
        }

        RankData r;
        std::string sid = std::to_string(domain_id);
        std::string rank_name = "rank/domain/" + sid;

        BlobRef rb;
        if (resolver_.get(rank_name, &rb) && rb.ok() && rb.len >= sizeof(int32) && rb.len % sizeof(int32) == 0) {
            size_t n = rb.len / sizeof(int32);
            r.rank_by_tok.resize(n);
            std::memcpy(r.rank_by_tok.data(), rb.data, rb.len);
            r.present = true;
        }

        auto it2 = rank_cache_.emplace(domain_id, std::move(r)).first;
        *out = it2->second;
        return true;
    }

    static int32 rank_or_identity(const RankData &r, int32 tok)
    {
        if (tok < 0)
            return tok;
        if (r.present && (size_t)tok < r.rank_by_tok.size())
            return r.rank_by_tok[(size_t)tok];
        return tok;
    }

    DenseBits eval_col_const(const AtomInfo &a)
    {
        TableArtifact *td = require_table(a.lhs.table);
        int col_idx = require_col_idx(a.lhs.table, a.lhs.col);
        const std::vector<int32> *tok = decode_col_tokens(a.lhs.table, col_idx);

        DictData d;
        if (!load_dict(a, a.lhs, a.join_class_id, &d))
            ereport(ERROR, (errmsg("policy: dict load failed for %s.%s", a.lhs.table.c_str(), a.lhs.col.c_str())));

        std::vector<uint8_t> allow(d.values.size(), 0u);
        if (a.op == POLICY_OP_EQ || a.op == POLICY_OP_NE) {
            std::unordered_set<int32> want;
            for (const std::string &vraw : a.const_values) {
                std::string norm = normalize_literal_for_type(vraw, d.dtype);
                auto it = d.token_by_norm.find(norm);
                if (it != d.token_by_norm.end())
                    want.insert(it->second);
            }
            for (size_t i = 0; i < allow.size(); i++) {
                bool in = (want.find((int32)i) != want.end());
                allow[i] = (uint8_t)((a.op == POLICY_OP_EQ) ? in : (!in));
            }
        } else {
            std::string rhs = a.const_values.empty() ? "" : a.const_values[0];
            for (size_t i = 0; i < allow.size(); i++) {
                int cmp = cmp_by_type(d.dtype, d.values[i], rhs);
                allow[i] = (uint8_t)(op_cmp_true(a.op, cmp) ? 1 : 0);
            }
        }

        DenseBits out(td->manifest.nrows);
        out.clear_all();
        for (uint32 rid = 0; rid < td->manifest.nrows; rid++) {
            int32 t = (*tok)[rid];
            if (t < 0 || (size_t)t >= allow.size())
                continue;
            if (allow[(size_t)t])
                out.set(rid);
        }
        return out;
    }

    DenseBits eval_col_col_same_table(const AtomInfo &a)
    {
        TableArtifact *td = require_table(a.lhs.table);
        int li = require_col_idx(a.lhs.table, a.lhs.col);
        int ri = require_col_idx(a.rhs.table, a.rhs.col);

        const std::vector<int32> *lt = decode_col_tokens(a.lhs.table, li);
        const std::vector<int32> *rt = decode_col_tokens(a.rhs.table, ri);

        RankData rank;
        if (a.join_class_id >= 0)
            (void)load_rank(a.join_class_id, &rank);

        DenseBits out(td->manifest.nrows);
        out.clear_all();

        for (uint32 rid = 0; rid < td->manifest.nrows; rid++) {
            int32 l = (*lt)[rid];
            int32 r = (*rt)[rid];
            if (l < 0 || r < 0)
                continue;
            bool keep = false;
            switch (a.op) {
                case POLICY_OP_EQ: keep = (l == r); break;
                case POLICY_OP_NE: keep = (l != r); break;
                case POLICY_OP_LT: keep = (rank_or_identity(rank, l) < rank_or_identity(rank, r)); break;
                case POLICY_OP_LE: keep = (rank_or_identity(rank, l) <= rank_or_identity(rank, r)); break;
                case POLICY_OP_GT: keep = (rank_or_identity(rank, l) > rank_or_identity(rank, r)); break;
                case POLICY_OP_GE: keep = (rank_or_identity(rank, l) >= rank_or_identity(rank, r)); break;
                default: keep = false; break;
            }
            if (keep)
                out.set(rid);
        }
        return out;
    }

    DenseBits eval_local_atom(const AtomInfo &a)
    {
        if (a.kind == POLICY_ATOM_COL_CONST)
            return eval_col_const(a);
        if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table)
            return eval_col_col_same_table(a);

        TableArtifact *td = require_table(a.lhs.table);
        DenseBits out(td ? td->manifest.nrows : 0);
        out.clear_all();
        return out;
    }

    DenseBits eval_scan_qual_atom(const QualAtom &q)
    {
        AtomInfo tmp;
        tmp.kind = (q.kind == POLICY_SCAN_QUAL_COL_COL) ? POLICY_ATOM_COL_COL : POLICY_ATOM_COL_CONST;
        tmp.op = q.op;
        tmp.lhs = q.lhs;
        tmp.rhs = q.rhs;
        if (tmp.lhs.table.empty())
            tmp.lhs.table = q.table;
        if (!q.const_value.empty())
            tmp.const_values.push_back(q.const_value);
        tmp.join_class_id = domain_of_col(tmp.lhs);

        if (tmp.kind == POLICY_ATOM_COL_COL && tmp.lhs.table != tmp.rhs.table) {
            TableArtifact *td = require_table(q.table);
            DenseBits out(td ? td->manifest.nrows : 0);
            out.fill_all();
            return out;
        }
        if (tmp.lhs.table.empty() || tmp.lhs.col.empty()) {
            TableArtifact *td = require_table(q.table);
            DenseBits out(td ? td->manifest.nrows : 0);
            out.fill_all();
            return out;
        }
        if (find_col_idx_or_neg(tmp.lhs.table, tmp.lhs.col) < 0) {
            TableArtifact *td = require_table(q.table);
            DenseBits out(td ? td->manifest.nrows : 0);
            out.fill_all();
            return out;
        }
        if (tmp.kind == POLICY_ATOM_COL_COL) {
            if (tmp.rhs.table.empty())
                tmp.rhs.table = tmp.lhs.table;
            if (tmp.rhs.col.empty() || find_col_idx_or_neg(tmp.rhs.table, tmp.rhs.col) < 0) {
                TableArtifact *td = require_table(q.table);
                DenseBits out(td ? td->manifest.nrows : 0);
                out.fill_all();
                return out;
            }
        }
        return eval_local_atom(tmp);
    }

    const DenseBits &local_mask_for_atom(const AtomInfo &a)
    {
        auto it = local_atom_cache_.find(a.atom_id);
        if (it != local_atom_cache_.end())
            return it->second;

        DenseBits m = eval_local_atom(a);
        auto it2 = local_atom_cache_.emplace(a.atom_id, std::move(m)).first;
        return it2->second;
    }

    const DenseBits &scan_qual_mask_for_table(const std::string &table)
    {
        auto it = scan_qual_cache_.find(table);
        if (it != scan_qual_cache_.end())
            return it->second;

        TableArtifact *td = require_table(table);
        DenseBits m(td->manifest.nrows);
        m.fill_all();
        // Keep policy semantics independent of scan-instance qualifiers.
        // Query quals are enforced by the PostgreSQL executor path.

        auto it2 = scan_qual_cache_.emplace(table, std::move(m)).first;
        return it2->second;
    }

    uint32 domain_token_count(int domain_id)
    {
        auto it = domain_ntokens_.find(domain_id);
        if (it != domain_ntokens_.end())
            return it->second;

        AtomInfo fake;
        fake.join_class_id = domain_id;
        ColRef c;
        DictData d;
        if (!load_dict(fake, c, domain_id, &d))
            return 0;
        uint32 n = (uint32)d.values.size();
        domain_ntokens_[domain_id] = n;
        return n;
    }

    static bool prune_by_support(DenseBits *rows,
                                 const std::vector<int32> &tok,
                                 const std::vector<uint8_t> &support,
                                 uint64 *removed_out = nullptr,
                                 uint64 *scanned_out = nullptr)
    {
        if (!rows)
            return false;
        DenseBits pruned(rows->nbits());
        pruned.clear_all();
        uint64 removed = 0;
        uint64 scanned = 0;

        rows->for_each_set([&](uint32 rid) {
            scanned++;
            int32 t = tok[rid];
            if (t < 0 || (size_t)t >= support.size())
                return;
            if (support[(size_t)t]) {
                pruned.set(rid);
            } else {
                removed++;
            }
        });

        bool changed = !pruned.equals(*rows);
        if (changed)
            *rows = std::move(pruned);
        if (removed_out)
            *removed_out = removed;
        if (scanned_out)
            *scanned_out = scanned;
        return changed;
    }

    void ensure_composite_tokens(EqConstraint *eq)
    {
        if (!eq || !eq->composite)
            return;
        if (eq->comp.ready)
            return;
        auto t0 = Clock::now();

        TableArtifact *lt = require_table(eq->left_table);
        TableArtifact *rt = require_table(eq->right_table);
        if (!lt || !rt) {
            eq->comp.ready = true;
            return;
        }

        std::vector<const std::vector<int32> *> left_cols;
        std::vector<const std::vector<int32> *> right_cols;
        left_cols.reserve(eq->left_col_idxs.size());
        right_cols.reserve(eq->right_col_idxs.size());
        for (int cidx : eq->left_col_idxs)
            left_cols.push_back(decode_col_tokens(eq->left_table, cidx));
        for (int cidx : eq->right_col_idxs)
            right_cols.push_back(decode_col_tokens(eq->right_table, cidx));

        eq->comp.left_rid_to_tok.assign(lt->manifest.nrows, -1);
        eq->comp.right_rid_to_tok.assign(rt->manifest.nrows, -1);
        std::unordered_map<uint64, std::vector<int32>> hash_to_tokids;
        hash_to_tokids.reserve((size_t)lt->manifest.nrows / 4u + (size_t)rt->manifest.nrows / 4u + 8u);
        std::vector<int32> dict_parts;
        dict_parts.reserve((size_t)(lt->manifest.nrows + rt->manifest.nrows) *
                           std::max<size_t>(1u, left_cols.size()) / 8u);
        int32 next_tok = 0;
        auto find_or_add = [&](const std::vector<int32> &parts) -> int32 {
            uint64 hsh = 1469598103934665603ULL;
            for (int32 v : parts)
                hsh = hash_combine64(hsh, (uint64)(uint32)v);
            auto &bucket = hash_to_tokids[hsh];
            const size_t arity = parts.size();
            for (int32 tok : bucket) {
                size_t base = (size_t)tok * arity;
                bool same = true;
                for (size_t i = 0; i < arity; i++) {
                    if (dict_parts[base + i] != parts[i]) {
                        same = false;
                        break;
                    }
                }
                if (same)
                    return tok;
            }
            int32 tok = next_tok++;
            bucket.push_back(tok);
            dict_parts.insert(dict_parts.end(), parts.begin(), parts.end());
            return tok;
        };

        auto stamp_side = [&](const std::vector<const std::vector<int32> *> &cols_tok,
                              std::vector<int32> *rid_to_tok) {
            std::vector<int32> parts(cols_tok.size(), 0);
            for (uint32 rid = 0; rid < rid_to_tok->size(); rid++) {
                bool any_null = false;
                for (size_t ci = 0; ci < cols_tok.size(); ci++) {
                    int32 tv = (*(cols_tok[ci]))[rid];
                    if (tv < 0) {
                        any_null = true;
                        break;
                    }
                    parts[ci] = tv;
                }
                if (any_null)
                    continue;
                (*rid_to_tok)[rid] = find_or_add(parts);
            }
        };

        stamp_side(left_cols, &eq->comp.left_rid_to_tok);
        stamp_side(right_cols, &eq->comp.right_rid_to_tok);

        eq->comp.ntokens = (uint32)next_tok;
        eq->comp.ready = true;
        if (profile_) {
            double ms = Ms(Clock::now() - t0).count();
            profile_->stamp_ms += ms;
            profile_->composite_stamp_ms += ms;
        }
    }

    const std::vector<int32> *eq_tokens_side(EqConstraint *eq, bool left)
    {
        if (!eq)
            return nullptr;
        if (!eq->composite) {
            const std::string &table = left ? eq->left_table : eq->right_table;
            int col = left ? eq->left_col_idxs[0] : eq->right_col_idxs[0];
            return decode_col_tokens(table, col);
        }
        ensure_composite_tokens(eq);
        return left ? &eq->comp.left_rid_to_tok : &eq->comp.right_rid_to_tok;
    }

    uint32 eq_token_count(EqConstraint *eq)
    {
        if (!eq)
            return 0;
        if (!eq->composite)
            return domain_token_count(eq->domain_id);
        ensure_composite_tokens(eq);
        return eq->comp.ntokens;
    }

    bool apply_eq_constraint(EqConstraint *eq,
                             std::unordered_map<std::string, DenseBits> *active,
                             int *join_evals)
    {
        if (!eq || !active)
            return false;

        if (join_evals)
            (*join_evals)++;

        DenseBits &la = (*active)[eq->left_table];
        DenseBits &ra = (*active)[eq->right_table];
        if (profile_) {
            profile_->rows_scanned_for_prop += la.count();
            profile_->rows_scanned_for_prop += ra.count();
        }

        const std::vector<int32> *ltok = eq_tokens_side(eq, true);
        const std::vector<int32> *rtok = eq_tokens_side(eq, false);

        uint32 ntok = eq_token_count(eq);
        if (ntok == 0) {
            bool changed = la.any() || ra.any();
            la.clear_all();
            ra.clear_all();
            return changed;
        }

        std::vector<uint8_t> supp_l(ntok, 0u);
        std::vector<uint8_t> supp_r(ntok, 0u);

        la.for_each_set([&](uint32 rid) {
            int32 t = (*ltok)[rid];
            if (t >= 0 && (uint32)t < ntok)
                supp_l[(size_t)t] = 1u;
        });
        ra.for_each_set([&](uint32 rid) {
            int32 t = (*rtok)[rid];
            if (t >= 0 && (uint32)t < ntok)
                supp_r[(size_t)t] = 1u;
        });

        std::vector<uint8_t> inter(ntok, 0u);
        bool any = false;
        uint64 token_deletions = 0;
        for (uint32 i = 0; i < ntok; i++) {
            inter[i] = (uint8_t)(supp_l[i] & supp_r[i]);
            if (inter[i]) {
                any = true;
            } else if (supp_l[i] || supp_r[i]) {
                token_deletions++;
            }
        }
        if (profile_) {
            profile_->pair_rel_edges += ntok;
            profile_->domain_token_deletions += token_deletions;
        }

        if (!any) {
            bool changed = la.any() || ra.any();
            la.clear_all();
            ra.clear_all();
            return changed;
        }

        bool changed = false;
        uint64 l_removed = 0, r_removed = 0;
        changed |= prune_by_support(&la, *ltok, inter, &l_removed, nullptr);
        changed |= prune_by_support(&ra, *rtok, inter, &r_removed, nullptr);
        if (profile_)
            profile_->domain_token_deletions += (l_removed + r_removed);
        return changed;
    }

    static bool tok_vs_summary(int op, int32 tok, int32 rk, const CmpSummary &s)
    {
        if (tok < 0 || !s.any)
            return false;
        switch (op) {
            case POLICY_OP_EQ:
                return ((size_t)tok < s.support.size()) ? (s.support[(size_t)tok] != 0u) : false;
            case POLICY_OP_NE:
                if (s.nonnull_count >= 2)
                    return true;
                return tok != s.only_tok;
            case POLICY_OP_LT:
                return rk < s.max_rank;
            case POLICY_OP_LE:
                return rk <= s.max_rank;
            case POLICY_OP_GT:
                return rk > s.min_rank;
            case POLICY_OP_GE:
                return rk >= s.min_rank;
            default:
                return false;
        }
    }

    bool apply_cmp_constraint(const CmpConstraint &cmp,
                              const std::vector<EqConstraint> &eqs,
                              std::unordered_map<std::string, DenseBits> *active)
    {
        if (!active)
            return false;

        DenseBits &la = (*active)[cmp.left_table];
        DenseBits &ra = (*active)[cmp.right_table];
        if (profile_) {
            profile_->rows_scanned_for_cmp += la.count();
            profile_->rows_scanned_for_cmp += ra.count();
        }

        const std::vector<int32> *ltok = decode_col_tokens(cmp.left_table, cmp.left_col_idx);
        const std::vector<int32> *rtok = decode_col_tokens(cmp.right_table, cmp.right_col_idx);

        uint32 ntok = domain_token_count(cmp.domain_id);
        if (ntok == 0) {
            bool changed = la.any() || ra.any();
            la.clear_all();
            ra.clear_all();
            return changed;
        }

        RankData rank;
        (void)load_rank(cmp.domain_id, &rank);

        // Optional grouping by an equality hub between the same endpoints.
        const std::vector<int32> *lg = nullptr;
        const std::vector<int32> *rg = nullptr;
        uint32 gtok_n = 1;
        if (cmp.group_eq_idx >= 0 && cmp.group_eq_idx < (int)eqs.size()) {
            EqConstraint *eq = const_cast<EqConstraint *>(&eqs[(size_t)cmp.group_eq_idx]);
            if (eq->left_table == cmp.left_table && eq->right_table == cmp.right_table) {
                lg = eq_tokens_side(eq, true);
                rg = eq_tokens_side(eq, false);
                gtok_n = std::max(1u, eq_token_count(eq));
            } else if (eq->left_table == cmp.right_table && eq->right_table == cmp.left_table) {
                lg = eq_tokens_side(eq, false);
                rg = eq_tokens_side(eq, true);
                gtok_n = std::max(1u, eq_token_count(eq));
            }
        }

        std::unordered_map<int32, CmpSummary> sb;
        std::unordered_map<int32, CmpSummary> sa;
        sb.reserve(gtok_n / 2u + 1u);
        sa.reserve(gtok_n / 2u + 1u);

        bool need_support = (cmp.op == POLICY_OP_EQ);
        auto update_summary = [&](CmpSummary *s, int32 tok) {
            if (!s)
                return;
            if (!s->any) {
                s->any = true;
                s->min_rank = std::numeric_limits<int32>::max();
                s->max_rank = std::numeric_limits<int32>::min();
                s->nonnull_count = 0;
                s->only_tok = -1;
                if (need_support)
                    s->support.assign(ntok, 0u);
            }
            s->nonnull_count++;
            if (s->nonnull_count == 1)
                s->only_tok = tok;
            int32 rk = rank_or_identity(rank, tok);
            if (rk < s->min_rank) s->min_rank = rk;
            if (rk > s->max_rank) s->max_rank = rk;
            if (need_support && (uint32)tok < ntok)
                s->support[(size_t)tok] = 1u;
        };

        ra.for_each_set([&](uint32 rid) {
            int32 v = (*rtok)[rid];
            if (v < 0 || (uint32)v >= ntok)
                return;
            int32 g = 0;
            if (rg) {
                g = (*rg)[rid];
                if (g < 0)
                    return;
            }
            update_summary(&sb[g], v);
        });

        la.for_each_set([&](uint32 rid) {
            int32 v = (*ltok)[rid];
            if (v < 0 || (uint32)v >= ntok)
                return;
            int32 g = 0;
            if (lg) {
                g = (*lg)[rid];
                if (g < 0)
                    return;
            }
            update_summary(&sa[g], v);
        });

        DenseBits lp(la.nbits());
        DenseBits rp(ra.nbits());
        lp.clear_all();
        rp.clear_all();

        la.for_each_set([&](uint32 rid) {
            int32 t = (*ltok)[rid];
            if (t < 0 || (uint32)t >= ntok)
                return;
            int32 g = 0;
            if (lg) {
                g = (*lg)[rid];
                if (g < 0)
                    return;
            }
            auto it = sb.find(g);
            if (it == sb.end())
                return;
            int32 rk = rank_or_identity(rank, t);
            if (tok_vs_summary(cmp.op, t, rk, it->second))
                lp.set(rid);
        });

        int inv = inverse_op(cmp.op);
        ra.for_each_set([&](uint32 rid) {
            int32 t = (*rtok)[rid];
            if (t < 0 || (uint32)t >= ntok)
                return;
            int32 g = 0;
            if (rg) {
                g = (*rg)[rid];
                if (g < 0)
                    return;
            }
            auto it = sa.find(g);
            if (it == sa.end())
                return;
            int32 rk = rank_or_identity(rank, t);
            if (tok_vs_summary(inv, t, rk, it->second))
                rp.set(rid);
        });

        bool changed = false;
        if (!lp.equals(la)) {
            la = std::move(lp);
            changed = true;
        }
        if (!rp.equals(ra)) {
            ra = std::move(rp);
            changed = true;
        }
        return changed;
    }

private:
    ArtifactResolver resolver_;
    const PolicyEngineInputC *in_ = nullptr;
    BuildProfile *profile_ = nullptr;

    std::unordered_map<std::string, int> col_domain_;
    std::unordered_map<int, AtomInfo> atom_by_id_;
    std::vector<QualAtom> scan_quals_;

    std::unordered_map<std::string, TableArtifact> tables_;
    std::unordered_map<std::string, DictData> dict_cache_;
    std::unordered_map<int, RankData> rank_cache_;
    std::unordered_map<int, uint32> domain_ntokens_;

    std::unordered_map<int, DenseBits> local_atom_cache_;
    std::unordered_map<std::string, DenseBits> scan_qual_cache_;
    std::unordered_map<std::string, DenseBits> policy_allow_mask_cache_;
    std::unordered_map<std::string, AllowCacheEntry> allow_cache_;
    std::deque<std::string> allow_cache_lru_;
    static constexpr size_t kAllowCacheMaxEntries = 64u;
};

static void fill_profile_c(const BuildProfile &p, PolicyRunProfileC *out)
{
    if (!out)
        return;
    std::memset(out, 0, sizeof(*out));

    out->artifact_parse_ms = p.artifact_parse_ms;
    out->atoms_ms = p.atoms_ms;
    out->stamp_ms = p.stamp_ms;
    out->propagate_ms = p.propagate_ms;
    out->project_ms = p.project_ms;
    out->decode_ms = p.decode_ms;
    out->bin_ms = p.bin_ms;
    out->local_sat_ms = p.local_sat_ms;
    out->policy_total_ms = p.policy_total_ms;
    out->build_hubs_ms = p.build_hubs_ms;
    out->composite_stamp_ms = p.composite_stamp_ms;
    out->build_context_ms = p.build_context_ms;
    out->signature_build_ms = p.signature_build_ms;
    out->sat_ms = p.sat_ms;
    out->project_allowset_ms = p.project_allowset_ms;
    out->prop_build_arcs_ms = p.prop_build_arcs_ms;
    out->prop_ac_ms = p.prop_ac_ms;
    out->prop_scc_ms = p.prop_scc_ms;
    out->prop_bin_catalog_ms = p.prop_bin_catalog_ms;
    out->prop_witness_ms = p.prop_witness_ms;
    out->prop_cmp_ms = p.prop_cmp_ms;
    out->semantic_dedup_ms = p.semantic_dedup_ms;
    out->candidate_prune_ms = p.candidate_prune_ms;
    out->sig_const_fold_ms = p.sig_const_fold_ms;
    out->allow_cache_hit = p.allow_cache_hit;
    out->allow_cache_miss = p.allow_cache_miss;
    out->allow_cache_build_ms = p.allow_cache_build_ms;
    out->bin_build_rows_scanned = p.bin_build_rows_scanned;
    out->bin_count_final = p.bin_count_final;
    out->bin_build_avg_probe_len =
        (p.bin_build_rows_scanned > 0)
            ? ((double)p.bin_build_probe_steps / (double)p.bin_build_rows_scanned)
            : 0.0;
    out->bin_build_max_probe_len = p.bin_build_max_probe_len;
    out->bin_build_rehash_count = p.bin_build_rehash_count;
    out->bin_build_hub_count = p.bin_build_hub_count;
    out->bin_build_local_atom_count = p.bin_build_local_atom_count;
    out->bin_build_extra_count = p.bin_build_extra_count;

    out->prop_iters = p.prop_iters;
    out->prop_join_scans_total = p.prop_join_scans_total;
    out->project_n_join_evals_max = p.project_n_join_evals_max;

    out->block_words_nwords_per_block = kWordsPerBlock;
    out->bytes_block_words = p.bytes_block_words;
    out->bytes_decoded_buffers_retained = p.bytes_decoded_buffers_retained;
}

static void log_policy_profile_query(const BuildProfile &p, int filtered_targets)
{
    (void)filtered_targets;
    double sat_avg_assumptions =
        (p.sat_check_calls > 0) ? ((double)p.sat_assumptions_total / (double)p.sat_check_calls) : 0.0;
    double sat_avg_core_terms =
        (p.sat_nogoods_added > 0) ? ((double)p.sat_core_terms_total / (double)p.sat_nogoods_added) : 0.0;
    double bin_build_avg_probe_len =
        (p.bin_build_rows_scanned > 0)
            ? ((double)p.bin_build_probe_steps / (double)p.bin_build_rows_scanned)
            : 0.0;
    elog(NOTICE,
         "policy_profile_query: artifact_parse_ms=%.3f decode_ms=%.3f build_hubs_ms=%.3f composite_stamp_ms=%.3f "
         "build_context_ms=%.3f signature_build_ms=%.3f sat_ms=%.3f project_allowset_ms=%.3f "
         "hub_ms=%.3f stamp_ms=%.3f propagate_ms=%.3f bin_ms=%.3f sig_ms=%.3f "
         "prop_build_arcs_ms=%.3f prop_ac_ms=%.3f prop_scc_ms=%.3f "
         "prop_bin_catalog_ms=%.3f prop_witness_ms=%.3f prop_cmp_ms=%.3f "
         "prop_index_build_ms=%.3f prop_rel_build_ms=%.3f prop_ac_delta_ms=%.3f "
         "prop_witness_frontier_ms=%.3f prop_cmp_summary_ms=%.3f target_sig_build_ms=%.3f "
         "semantic_dedup_ms=%.3f candidate_prune_ms=%.3f sig_const_fold_ms=%.3f "
         "allow_cache_hit=%llu allow_cache_miss=%llu allow_cache_build_ms=%.3f "
         "allow_cache_hit_in_query=%llu allow_cache_miss_in_query=%llu allow_cache_build_ms_in_query=%.3f "
         "bin_build_rows_scanned=%llu bin_count_final=%llu bin_build_avg_probe_len=%.3f "
         "bin_build_max_probe_len=%llu bin_build_rehash_count=%llu "
         "bin_build_hub_count=%llu bin_build_local_atom_count=%llu bin_build_extra_count=%llu "
         "rows_scanned_for_prop=%llu rows_scanned_for_cmp=%llu rows_scanned_for_target_sig=%llu "
         "pair_rel_count=%llu pair_rel_edges=%llu domain_token_deletions=%llu "
         "witness_frontier_steps=%llu query_local_cache_hits=%llu query_local_cache_misses=%llu "
         "sat_sid_count=%llu sat_check_calls=%llu sat_assumptions_total=%llu sat_avg_assumptions=%.3f "
         "sat_unique_assignments=%llu sat_cache_hits=%llu "
         "sat_nogood_prunes=%llu sat_nogoods_added=%llu sat_subsumed_dropped=%llu "
         "sat_core_terms_total=%llu sat_core_terms_max=%llu sat_avg_core_terms=%.3f",
         p.artifact_parse_ms,
         p.decode_ms,
         p.build_hubs_ms,
         p.composite_stamp_ms,
         p.build_context_ms,
         p.signature_build_ms,
         p.sat_ms,
         p.project_allowset_ms,
         p.build_hubs_ms,
         p.composite_stamp_ms,
         p.propagate_ms,
         p.prop_bin_catalog_ms,
         (p.target_sig_build_ms > 0.0 ? p.target_sig_build_ms : p.signature_build_ms),
         p.prop_build_arcs_ms,
         p.prop_ac_ms,
         p.prop_scc_ms,
         p.prop_bin_catalog_ms,
         p.prop_witness_ms,
         p.prop_cmp_ms,
         p.prop_index_build_ms,
         p.prop_rel_build_ms,
         p.prop_ac_delta_ms,
         p.prop_witness_frontier_ms,
         p.prop_cmp_summary_ms,
         p.target_sig_build_ms,
         p.semantic_dedup_ms,
         p.candidate_prune_ms,
         p.sig_const_fold_ms,
         (unsigned long long)p.allow_cache_hit,
         (unsigned long long)p.allow_cache_miss,
         p.allow_cache_build_ms,
         (unsigned long long)p.allow_cache_hit,
         (unsigned long long)p.allow_cache_miss,
         p.allow_cache_build_ms,
         (unsigned long long)p.bin_build_rows_scanned,
         (unsigned long long)p.bin_count_final,
         bin_build_avg_probe_len,
         (unsigned long long)p.bin_build_max_probe_len,
         (unsigned long long)p.bin_build_rehash_count,
         (unsigned long long)p.bin_build_hub_count,
         (unsigned long long)p.bin_build_local_atom_count,
         (unsigned long long)p.bin_build_extra_count,
         (unsigned long long)p.rows_scanned_for_prop,
         (unsigned long long)p.rows_scanned_for_cmp,
         (unsigned long long)p.rows_scanned_for_target_sig,
         (unsigned long long)p.pair_rel_count,
         (unsigned long long)p.pair_rel_edges,
         (unsigned long long)p.domain_token_deletions,
         (unsigned long long)p.witness_frontier_steps,
         (unsigned long long)p.query_local_cache_hits,
         (unsigned long long)p.query_local_cache_misses,
         (unsigned long long)p.sat_sid_count,
         (unsigned long long)p.sat_check_calls,
         (unsigned long long)p.sat_assumptions_total,
         sat_avg_assumptions,
         (unsigned long long)p.sat_unique_assignments,
         (unsigned long long)p.sat_cache_hits,
         (unsigned long long)p.sat_nogood_prunes,
         (unsigned long long)p.sat_nogoods_added,
         (unsigned long long)p.sat_subsumed_dropped,
         (unsigned long long)p.sat_core_terms_total,
         (unsigned long long)p.sat_core_terms_max,
         sat_avg_core_terms);
}

} // namespace

extern "C" {

typedef struct PolicyRunHandle {
    PolicyAllowListC allow_list;
    PolicyRunProfileC profile;
} PolicyRunHandle;

PolicyRunHandle *policy_run(const PolicyArtifactC *arts, int art_count, const PolicyEngineInputC *in)
{
    if (!in)
        return nullptr;

    auto t0 = Clock::now();

    PolicyRunHandle *h = (PolicyRunHandle *)palloc0(sizeof(PolicyRunHandle));
    BuildProfile p;

    if (in->target_count <= 0 || !in->target_tables) {
        fill_profile_c(p, &h->profile);
        return h;
    }

    h->allow_list.count = in->target_count;
    h->allow_list.items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * (size_t)in->target_count);

    Engine eng(arts, art_count, in, &p);

    std::vector<std::string> targets;
    targets.reserve((size_t)in->target_count);
    std::unordered_set<std::string> target_set;
    target_set.reserve((size_t)in->target_count * 2u + 1u);
    for (int i = 0; i < in->target_count; i++) {
        const char *t = in->target_tables[i];
        if (!t || !t[0])
            continue;
        std::string tn = to_lower_copy(t);
        if (target_set.insert(tn).second)
            targets.push_back(std::move(tn));
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> deps;
    deps.reserve(targets.size() * 2u + 1u);
    std::unordered_map<std::string, int> indeg;
    indeg.reserve(targets.size() * 2u + 1u);
    for (const std::string &t : targets)
        indeg[t] = 0;
    for (const std::string &t : targets) {
        std::unordered_set<std::string> d = eng.target_dependencies(t);
        std::unordered_set<std::string> dflt;
        for (const std::string &x : d) {
            if (target_set.find(x) != target_set.end() && x != t)
                dflt.insert(x);
        }
        deps[t] = std::move(dflt);
    }
    for (const auto &kv : deps)
        indeg[kv.first] = (int)kv.second.size();

    std::unordered_map<std::string, std::vector<std::string>> rev;
    rev.reserve(targets.size() * 2u + 1u);
    for (const auto &kv : deps) {
        const std::string &t = kv.first;
        for (const std::string &d : kv.second)
            rev[d].push_back(t);
    }

    std::deque<std::string> q;
    for (const std::string &t : targets) {
        if (indeg[t] == 0)
            q.push_back(t);
    }
    std::vector<std::string> build_order;
    build_order.reserve(targets.size());
    while (!q.empty()) {
        std::string t = q.front();
        q.pop_front();
        build_order.push_back(t);
        auto rit = rev.find(t);
        if (rit == rev.end())
            continue;
        for (const std::string &n : rit->second) {
            auto it = indeg.find(n);
            if (it == indeg.end())
                continue;
            if (--(it->second) == 0)
                q.push_back(n);
        }
    }
    if (build_order.size() < targets.size()) {
        std::unordered_set<std::string> done(build_order.begin(), build_order.end());
        std::vector<std::string> cycle_targets;
        cycle_targets.reserve(targets.size());
        for (const std::string &t : targets) {
            if (done.find(t) == done.end())
                cycle_targets.push_back(t);
        }
        std::string cycle_list;
        for (size_t i = 0; i < cycle_targets.size(); i++) {
            if (i > 0)
                cycle_list.push_back(',');
            cycle_list.append(cycle_targets[i]);
        }
        ereport(ERROR,
                (errmsg("policy: cyclic target dependency graph detected in policy evaluation"),
                 errdetail("unresolved targets: %s", cycle_list.c_str())));
    }

    int out_count = 0;
    for (const std::string &t : build_order) {
        PolicyTableAllowC item;
        if (!eng.build_target_allow(t, &item))
            ereport(ERROR,
                    (errmsg("policy: failed building allow-set for target %s", t.c_str())));
        h->allow_list.items[out_count++] = item;
    }

    h->allow_list.count = out_count;
    p.policy_total_ms = Ms(Clock::now() - t0).count();

    fill_profile_c(p, &h->profile);
    log_policy_profile_query(p, out_count);
    return h;
}

const PolicyAllowListC *policy_run_allow_list(const PolicyRunHandle *h)
{
    return h ? &h->allow_list : nullptr;
}

const PolicyRunProfileC *policy_run_profile(const PolicyRunHandle *h)
{
    return h ? &h->profile : nullptr;
}

} // extern "C"

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

using Term = std::vector<int>;

static void normalize_term(Term *t)
{
    if (!t)
        return;
    std::sort(t->begin(), t->end());
    t->erase(std::unique(t->begin(), t->end()), t->end());
}

static std::string term_key(const Term &t)
{
    std::string out;
    for (size_t i = 0; i < t.size(); i++) {
        if (i)
            out.push_back(',');
        out += std::to_string(t[i]);
    }
    return out;
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
        if (tk.kind == POLICY_AST_TOK_VAR) {
            // Constant postfix AST may encode literals as VAR(0/1).
            // Atom-ids (>1) are not valid in this constant evaluator.
            if (tk.value < 0 || tk.value > 1)
                return false;
            st.push_back((tk.value == 1) ? 1u : 0u);
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

static std::vector<int> parse_positive_atom_ids_from_ast_str(const char *ast_cstr)
{
    std::vector<int> out;
    if (!ast_cstr || !ast_cstr[0])
        return out;
    const std::string s(ast_cstr);
    const size_t n = s.size();
    for (size_t i = 0; i < n; i++) {
        if (s[i] != 'y' && s[i] != 'Y')
            continue;
        size_t j = i + 1u;
        bool neg = false;
        if (j < n && s[j] == '-') {
            neg = true;
            j++;
        }
        if (j >= n || !std::isdigit((unsigned char)s[j]))
            continue;
        int v = 0;
        while (j < n && std::isdigit((unsigned char)s[j])) {
            int d = s[j] - '0';
            if (v > (std::numeric_limits<int>::max() - d) / 10)
                break;
            v = v * 10 + d;
            j++;
        }
        if (!neg && v > 0)
            out.push_back(v);
        i = j;
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
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

struct TableBinEntry {
    std::vector<int32> hub_vals;
    std::vector<uint8_t> local_bits;
    std::vector<int32> extra_vals;
    uint32 count = 0;
};

struct TableBinCatalog {
    std::vector<int> hub_ids;
    std::unordered_map<int, uint32> hub_pos;
    std::vector<int> local_atom_ids;
    std::unordered_map<int, uint32> local_pos;
    std::vector<int> extra_col_idxs;
    std::unordered_map<int, uint32> extra_pos;
    std::vector<TableBinEntry> bins;
    std::unordered_map<int, DenseBits> local_sat_bins;
    std::vector<uint32> row_to_bin;
    // CSR rows grouped by bin: rows for bin bi are in [bin_offsets[bi], bin_offsets[bi+1]).
    std::vector<uint32> bin_offsets;
    std::vector<uint32> bin_rids;
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

static std::unordered_map<std::string, AllowCacheEntry> g_allow_cache;
static std::deque<std::string> g_allow_cache_lru;
static constexpr size_t kAllowCacheMaxEntries = 64u;

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

static void put_allow_cache_entry(const std::string &key, AllowCacheEntry &&entry)
{
    auto it = g_allow_cache.find(key);
    if (it == g_allow_cache.end() && g_allow_cache_lru.size() >= kAllowCacheMaxEntries) {
        const std::string evict = g_allow_cache_lru.front();
        g_allow_cache_lru.pop_front();
        g_allow_cache.erase(evict);
    }
    if (it != g_allow_cache.end()) {
        for (auto q = g_allow_cache_lru.begin(); q != g_allow_cache_lru.end(); ++q) {
            if (*q == key) {
                g_allow_cache_lru.erase(q);
                break;
            }
        }
    }
    g_allow_cache_lru.push_back(key);
    g_allow_cache[key] = std::move(entry);
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
        if (target_idx < 0 || !in_ || !in_->target_ast_toks || !in_->target_ast_tok_offsets ||
            !in_->target_ast_tok_counts || target_idx >= in_->target_count)
            return deps;
        int off = in_->target_ast_tok_offsets[target_idx];
        int cnt = in_->target_ast_tok_counts[target_idx];
        if (off < 0 || cnt <= 0 || (off + cnt) > in_->target_ast_tok_len)
            return deps;
        const PolicyAstTokC *ast_toks = in_->target_ast_toks + off;
        for (int i = 0; i < cnt; i++) {
            const PolicyAstTokC &tk = ast_toks[i];
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
        const PolicyAstTokC *ast_toks = nullptr;
        int ast_ntok = 0;
        if (target_idx >= 0 && in_ &&
            in_->target_ast_toks && in_->target_ast_tok_offsets && in_->target_ast_tok_counts &&
            target_idx < in_->target_count) {
            int off = in_->target_ast_tok_offsets[target_idx];
            int cnt = in_->target_ast_tok_counts[target_idx];
            if (off >= 0 && cnt >= 0 && (off + cnt) <= in_->target_ast_tok_len) {
                ast_toks = in_->target_ast_toks + off;
                ast_ntok = cnt;
            }
        }

        bool allow_cache_enabled = cf_bool_guc("custom_filter.enable_allow_cache", true);
        bool allow_cache_miss_recorded = false;
        std::string allow_cache_key;
        if (allow_cache_enabled) {
            allow_cache_key =
                make_allow_cache_key(target, in_, target_idx, ast_toks, ast_ntok,
                                     target_td->manifest.nrows, target_td->total_blocks);
            auto acit = g_allow_cache.find(allow_cache_key);
            if (acit != g_allow_cache.end()) {
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
            if (allow_cache_miss_recorded && profile_) {
                profile_->allow_cache_build_ms += Ms(Clock::now() - t_allow_build0).count();
            }
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
            if (out->blocks > 0 && out->block_ids) {
                ce.block_ids.assign(out->block_ids, out->block_ids + out->blocks);
            }
            if (out->blocks > 0 && out->block_words) {
                size_t nwords = (size_t)out->blocks * kWordsPerBlock;
                ce.block_words.assign(out->block_words, out->block_words + nwords);
            }
            put_allow_cache_entry(allow_cache_key, std::move(ce));
        };

        std::vector<int> feature_atom_ids;
        feature_atom_ids.reserve((size_t)std::max(0, ast_ntok));
        std::vector<int> root_must_leaves;
        std::unordered_map<int, std::vector<int>> mandatory_atoms_by_atom;
        mandatory_atoms_by_atom.reserve((size_t)std::max(0, ast_ntok));
        std::unordered_map<int, std::vector<std::vector<int>>> mandatory_terms_by_atom;
        mandatory_terms_by_atom.reserve((size_t)std::max(0, ast_ntok));
        if (ast_toks && ast_ntok > 0) {
            struct AstCtxNode {
                int kind = POLICY_AST_TOK_VAR;
                int atom_id = 0;
                int left = -1;
                int right = -1;
                int parent = -1;
                std::vector<int> leaves;
                std::vector<int> must_leaves;
            };
            std::vector<AstCtxNode> nodes;
            nodes.reserve((size_t)ast_ntok);
            std::vector<int> st;
            st.reserve((size_t)ast_ntok);
            for (int i = 0; i < ast_ntok; i++) {
                const PolicyAstTokC &tk = ast_toks[i];
                if (tk.kind == POLICY_AST_TOK_VAR) {
                    if (tk.value > 0)
                        feature_atom_ids.push_back(tk.value);
                    AstCtxNode n;
                    n.kind = tk.kind;
                    n.atom_id = tk.value;
                    if (tk.value > 0) {
                        n.leaves.push_back(tk.value);
                        n.must_leaves.push_back(tk.value);
                    }
                    nodes.push_back(std::move(n));
                    st.push_back((int)nodes.size() - 1);
                    continue;
                }
                if (tk.kind != POLICY_AST_TOK_AND && tk.kind != POLICY_AST_TOK_OR)
                    ereport(ERROR, (errmsg("policy: invalid AST token kind=%d target=%s", tk.kind, target.c_str())));
                if (st.size() < 2)
                    ereport(ERROR, (errmsg("policy: malformed postfix AST stack underflow target=%s", target.c_str())));
                int right = st.back(); st.pop_back();
                int left = st.back(); st.pop_back();

                AstCtxNode n;
                n.kind = tk.kind;
                n.left = left;
                n.right = right;
                n.leaves = nodes[(size_t)left].leaves;
                n.leaves.insert(n.leaves.end(),
                                nodes[(size_t)right].leaves.begin(),
                                nodes[(size_t)right].leaves.end());
                std::sort(n.leaves.begin(), n.leaves.end());
                n.leaves.erase(std::unique(n.leaves.begin(), n.leaves.end()), n.leaves.end());
                if (tk.kind == POLICY_AST_TOK_AND) {
                    n.must_leaves = nodes[(size_t)left].must_leaves;
                    n.must_leaves.insert(n.must_leaves.end(),
                                         nodes[(size_t)right].must_leaves.begin(),
                                         nodes[(size_t)right].must_leaves.end());
                    std::sort(n.must_leaves.begin(), n.must_leaves.end());
                    n.must_leaves.erase(std::unique(n.must_leaves.begin(), n.must_leaves.end()),
                                        n.must_leaves.end());
                } else { // OR
                    const std::vector<int> &lm = nodes[(size_t)left].must_leaves;
                    const std::vector<int> &rm = nodes[(size_t)right].must_leaves;
                    n.must_leaves.reserve(std::min(lm.size(), rm.size()));
                    size_t a = 0, b = 0;
                    while (a < lm.size() && b < rm.size()) {
                        if (lm[a] == rm[b]) {
                            n.must_leaves.push_back(lm[a]);
                            a++;
                            b++;
                        } else if (lm[a] < rm[b]) {
                            a++;
                        } else {
                            b++;
                        }
                    }
                }
                nodes.push_back(std::move(n));
                int p = (int)nodes.size() - 1;
                nodes[(size_t)left].parent = p;
                nodes[(size_t)right].parent = p;
                st.push_back(p);
            }
            if (st.size() == 1u && st.back() >= 0 && (size_t)st.back() < nodes.size()) {
                root_must_leaves = nodes[(size_t)st.back()].must_leaves;
                std::sort(root_must_leaves.begin(), root_must_leaves.end());
                root_must_leaves.erase(std::remove_if(root_must_leaves.begin(),
                                                      root_must_leaves.end(),
                                                      [](int v) { return v <= 0; }),
                                       root_must_leaves.end());
                root_must_leaves.erase(std::unique(root_must_leaves.begin(), root_must_leaves.end()),
                                       root_must_leaves.end());
            }
            std::sort(feature_atom_ids.begin(), feature_atom_ids.end());
            feature_atom_ids.erase(std::unique(feature_atom_ids.begin(), feature_atom_ids.end()), feature_atom_ids.end());

            auto add_unique_sorted = [](std::vector<int> *dst, int v) {
                if (!dst)
                    return;
                if (std::binary_search(dst->begin(), dst->end(), v))
                    return;
                dst->insert(std::lower_bound(dst->begin(), dst->end(), v), v);
            };

            for (size_t ni = 0; ni < nodes.size(); ni++) {
                const AstCtxNode &leaf = nodes[ni];
                if (leaf.kind != POLICY_AST_TOK_VAR || leaf.atom_id <= 0)
                    continue;
                int leaf_scope = -1;
                auto lsit = atom_by_id_.find(leaf.atom_id);
                if (lsit != atom_by_id_.end())
                    leaf_scope = lsit->second.scope_id;
                std::vector<int> req;
                req.push_back(leaf.atom_id);
                int child = (int)ni;
                int parent = leaf.parent;
                while (parent >= 0) {
                    const AstCtxNode &pn = nodes[(size_t)parent];
                    if (pn.kind == POLICY_AST_TOK_AND) {
                        int sibling = (pn.left == child) ? pn.right : pn.left;
                        if (sibling >= 0 && (size_t)sibling < nodes.size()) {
                            for (int y : nodes[(size_t)sibling].must_leaves) {
                                if (y <= 0)
                                    continue;
                                auto yit = atom_by_id_.find(y);
                                if (leaf_scope >= 0 &&
                                    yit != atom_by_id_.end() &&
                                    yit->second.scope_id >= 0 &&
                                    yit->second.scope_id != leaf_scope)
                                    continue;
                                add_unique_sorted(&req, y);
                            }
                        }
                    }
                    child = parent;
                    parent = nodes[(size_t)child].parent;
                }
                if (leaf_scope >= 0) {
                    std::vector<int> filtered;
                    filtered.reserve(req.size());
                    for (int y : req) {
                        if (y == leaf.atom_id) {
                            filtered.push_back(y);
                            continue;
                        }
                        auto yit = atom_by_id_.find(y);
                        if (yit == atom_by_id_.end()) {
                            filtered.push_back(y);
                            continue;
                        }
                        if (yit->second.scope_id < 0 || yit->second.scope_id == leaf_scope)
                            filtered.push_back(y);
                    }
                    req.swap(filtered);
                }
                std::sort(req.begin(), req.end());
                req.erase(std::unique(req.begin(), req.end()), req.end());

                auto it = mandatory_atoms_by_atom.find(leaf.atom_id);
                if (it == mandatory_atoms_by_atom.end()) {
                    mandatory_atoms_by_atom.emplace(leaf.atom_id, std::move(req));
                } else {
                    std::vector<int> inter;
                    inter.reserve(std::min(it->second.size(), req.size()));
                    std::set_intersection(it->second.begin(),
                                          it->second.end(),
                                          req.begin(),
                                          req.end(),
                                          std::back_inserter(inter));
                    if (!inter.empty())
                        it->second = std::move(inter);
                }
                mandatory_terms_by_atom[leaf.atom_id].push_back(req);
            }

            for (auto &kv : mandatory_terms_by_atom) {
                auto &terms = kv.second;
                for (auto &t : terms) {
                    std::sort(t.begin(), t.end());
                    t.erase(std::unique(t.begin(), t.end()), t.end());
                }
                std::sort(terms.begin(), terms.end(),
                          [](const std::vector<int> &a, const std::vector<int> &b) {
                              if (a.size() != b.size())
                                  return a.size() < b.size();
                              return a < b;
                          });
                terms.erase(std::unique(terms.begin(), terms.end()), terms.end());
            }

        }

        if (!ast_toks || ast_ntok <= 0 || feature_atom_ids.empty()) {
            bool constant_ast_mode = false;
            bool constant_ast_ok = false;
            bool constant_ast_value = false;
            if (feature_atom_ids.empty()) {
                if (ast_toks && ast_ntok > 0) {
                    constant_ast_mode = true;
                    constant_ast_value = eval_postfix_constant_ast(ast_toks, ast_ntok, &constant_ast_ok);
                } else if (target_idx >= 0 && in_ && in_->target_asts &&
                           target_idx < in_->target_count && in_->target_asts[target_idx]) {
                    std::string asts = to_lower_copy(trim_copy(in_->target_asts[target_idx]));
                    if (asts == "y0" || asts == "(y0)" || asts == "false") {
                        constant_ast_mode = true;
                        constant_ast_ok = true;
                        constant_ast_value = false;
                    } else if (asts == "y1" || asts == "(y1)" || asts == "true") {
                        constant_ast_mode = true;
                        constant_ast_ok = true;
                        constant_ast_value = true;
                    }
                }
                if (constant_ast_mode && !constant_ast_ok)
                    ereport(ERROR,
                            (errmsg("policy: malformed constant AST target=%s ast_ntok=%d",
                                    target.c_str(), ast_ntok)));
            }
            int32 max_blk = -1;
            for (int32 b : target_td->ctid_blk) {
                if (b > max_blk)
                    max_blk = b;
            }
            uint32 total_blocks = (max_blk >= 0) ? ((uint32)max_blk + 1u) : 0u;
            std::vector<uint32> block_ids;
            std::vector<uint64> block_words;
            block_ids.reserve(total_blocks);
            block_words.reserve((size_t)total_blocks * kWordsPerBlock);

            uint64 allowed_rows = 0;
            std::vector<uint64> dense((size_t)total_blocks * kWordsPerBlock, 0ULL);
            std::vector<uint8_t> touched(total_blocks, 0u);

            bool allow_all = (!constant_ast_mode || constant_ast_value);
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
            for (uint32 blk : block_ids) {
                size_t base = (size_t)blk * kWordsPerBlock;
                for (uint32 w = 0; w < kWordsPerBlock; w++)
                    block_words.push_back(dense[base + w]);
            }

            uint64 *words_out = nullptr;
            uint32 *ids_out = nullptr;
            if (!block_words.empty()) {
                size_t bytes = block_words.size() * sizeof(uint64);
                words_out = (uint64 *)palloc0(bytes);
                std::memcpy(words_out, block_words.data(), bytes);
            }
            if (!block_ids.empty()) {
                size_t bytes = block_ids.size() * sizeof(uint32);
                ids_out = (uint32 *)palloc0(bytes);
                std::memcpy(ids_out, block_ids.data(), bytes);
            }

            out->table = pstrdup(target.c_str());
            out->block_words = words_out;
            out->block_ids = ids_out;
            out->blocks = (uint32)block_ids.size();
            out->total_blocks = total_blocks;
            out->n_rows = target_td->manifest.nrows;
            out->allowed_rows = allowed_rows;
            out->allowed_sids = allow_all ? 1u : 0u;
            out->total_sids = 1u;
            out->hub_prop_ms = 0.0;
            out->sat_ms = 0.0;
            out->sid_build_ms = 0.0;
            if (constant_ast_mode && !constant_ast_value) {
                out->mode_hint = POLICY_MODE_HINT_EMPTY;
                out->mode_reason = pstrdup("constant_false_ast");
            } else if (constant_ast_mode) {
                out->mode_hint = POLICY_MODE_HINT_ALL;
                out->mode_reason = pstrdup("constant_true_ast");
            } else {
                out->mode_hint = POLICY_MODE_HINT_ALL;
                out->mode_reason = pstrdup("empty_policy_ast");
            }
            if (profile_)
                profile_->allow_rows_total += allowed_rows;
            policy_allow_mask_cache_[target] = allow_mask;
            maybe_store_allow_cache(policy_allow_mask_cache_[target]);
            note_allow_cache_build_time();
            double density0 = (target_td->manifest.nrows > 0)
                                  ? ((double)allowed_rows / (double)target_td->manifest.nrows)
                                  : 0.0;
            elog(NOTICE,
                 "policy_profile_target: table=%s n_rows=%u allowed_rows=%llu density=%.6f mode_hint=%d "
                 "nfeatures=0 ast_ntok=%d total_sids=%u allowed_sids=%u hubs=0 arcs=0 scc_count=0 max_scc_size=0 decoded_cols_count=%s:%u",
                 target.c_str(),
                 target_td->manifest.nrows,
                 (unsigned long long)allowed_rows,
                 density0,
                 out->mode_hint,
                 ast_ntok,
                 out->total_sids,
                 out->allowed_sids,
                 target.c_str(),
                 (unsigned)target_td->col_tokens.size());
            return true;
        }

        // Correctness-first: keep AST variable ids and evaluated atom ids 1:1.
        // Cross-policy / cross-context alias collapsing can incorrectly merge
        // semantically distinct atom occurrences in combined policy sets.
        std::unordered_map<int, int> atom_eval_rep;
        atom_eval_rep.reserve(feature_atom_ids.size() * 2u + 1u);
        std::vector<int> eval_atom_ids;
        eval_atom_ids.reserve(feature_atom_ids.size());
        for (int aid : feature_atom_ids) {
            atom_eval_rep[aid] = aid;
            eval_atom_ids.push_back(aid);
        }

        auto t_hub0 = Clock::now();
        std::unordered_set<std::string> tables;
        tables.reserve(eval_atom_ids.size() * 2u + 4u);
        tables.insert(target);

        std::vector<const AtomInfo *> join_atoms;
        std::vector<const AtomInfo *> cross_cmp_atoms;
        std::vector<const AtomInfo *> local_atoms;
        join_atoms.reserve(eval_atom_ids.size());
        cross_cmp_atoms.reserve(eval_atom_ids.size());
        local_atoms.reserve(eval_atom_ids.size());
        for (int aid : eval_atom_ids) {
            auto it = atom_by_id_.find(aid);
            if (it == atom_by_id_.end())
                continue;
            const AtomInfo &a = it->second;
            if (!a.lhs.table.empty())
                tables.insert(a.lhs.table);
            if (!a.rhs.table.empty())
                tables.insert(a.rhs.table);
            if (a.kind == POLICY_ATOM_JOIN_EQ && a.lhs.table != a.rhs.table) {
                join_atoms.push_back(&a);
            } else if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table != a.rhs.table) {
                cross_cmp_atoms.push_back(&a);
            } else {
                local_atoms.push_back(&a);
            }
        }

        std::unordered_map<std::string, DenseBits> base_rows;
        base_rows.reserve(tables.size() * 2u + 1u);
        for (const std::string &t : tables) {
            TableArtifact *td = require_table(t);
            DenseBits mask(td ? td->manifest.nrows : 0u);
            mask.fill_all();
            auto pit = policy_allow_mask_cache_.find(t);
            if (pit != policy_allow_mask_cache_.end() &&
                pit->second.nbits() == mask.nbits()) {
                mask.bit_and(pit->second);
            }
            base_rows.emplace(t, std::move(mask));
        }

        struct Hub {
            int idx = -1;
            std::string left_table;
            std::string right_table;
            bool composite = false;
            int domain_id = -1;
            std::vector<int> left_col_idxs;
            std::vector<int> right_col_idxs;
            const std::vector<int32> *left_tok = nullptr;
            const std::vector<int32> *right_tok = nullptr;
            std::vector<int32> left_comp_tok;
            std::vector<int32> right_comp_tok;
            uint32 ntok = 0;
            std::vector<int> atom_ids;
        };

        struct Inc {
            int hub_idx = -1;
            bool on_left = true;
            const std::vector<int32> *tok = nullptr;
        };

        struct Arc {
            int from_hub = -1;
            int to_hub = -1;
            std::string table;
            const std::vector<int32> *from_tok = nullptr;
            const std::vector<int32> *to_tok = nullptr;
        };

        struct ArcAdj {
            int from_hub = -1;
            int to_hub = -1;
            uint32 from_ntok = 0;
            std::vector<uint32> from_keys; // sparse sorted from_tok keys
            std::vector<uint32> offsets;   // size from_keys + 1
            std::vector<int32> to_vals;    // concatenated sorted adjacency

            bool range_for_from(int32 from_tok, uint32 *b_out, uint32 *e_out) const
            {
                if (from_tok < 0 || (uint32)from_tok >= from_ntok || from_keys.empty() || offsets.empty())
                    return false;
                auto it = std::lower_bound(from_keys.begin(), from_keys.end(), (uint32)from_tok);
                if (it == from_keys.end() || *it != (uint32)from_tok)
                    return false;
                size_t idx = (size_t)(it - from_keys.begin());
                if (idx + 1u >= offsets.size())
                    return false;
                uint32 b = offsets[idx];
                uint32 e = offsets[idx + 1u];
                if (b >= e || e > to_vals.size())
                    return false;
                if (b_out)
                    *b_out = b;
                if (e_out)
                    *e_out = e;
                return true;
            }

            bool has_pair(int32 from_tok, int32 to_tok) const
            {
                if (from_tok < 0 || to_tok < 0)
                    return false;
                uint32 b = 0, e = 0;
                if (!range_for_from(from_tok, &b, &e))
                    return false;
                auto it = std::lower_bound(to_vals.begin() + b, to_vals.begin() + e, to_tok);
                return (it != (to_vals.begin() + e) && *it == to_tok);
            }

            bool has_any_to_in_domain(int32 from_tok, const DenseBits &dom_to) const
            {
                uint32 b = 0, e = 0;
                if (!range_for_from(from_tok, &b, &e))
                    return false;
                for (uint32 i = b; i < e; i++) {
                    int32 tv = to_vals[(size_t)i];
                    if (tv >= 0 && (uint32)tv < dom_to.nbits() && dom_to.test((uint32)tv))
                        return true;
                }
                return false;
            }

            void image_from_domain(const DenseBits &dom_from, DenseBits *out) const
            {
                if (!out || offsets.empty() || from_keys.empty())
                    return;
                dom_from.for_each_set([&](uint32 from_tok) {
                    uint32 b = 0, e = 0;
                    if (!range_for_from((int32)from_tok, &b, &e))
                        return;
                    for (uint32 i = b; i < e; i++) {
                        int32 tv = to_vals[(size_t)i];
                        if (tv >= 0 && (uint32)tv < out->nbits())
                            out->set((uint32)tv);
                    }
                });
            }
        };

        auto pair_scope_key = [](const std::string &a, const std::string &b, int scope_id, int atom_id) {
            std::string k = (a <= b) ? (a + "|" + b) : (b + "|" + a);
            k.push_back('|');
            if (scope_id >= 0) {
                k += "s";
                k += std::to_string(scope_id);
            } else {
                // Unknown scope: never composite across atoms for safety.
                k += "a";
                k += std::to_string(atom_id);
            }
            return k;
        };

        std::unordered_map<std::string, std::vector<const AtomInfo *>> join_groups;
        join_groups.reserve(join_atoms.size() * 2u + 1u);
        for (const AtomInfo *a : join_atoms) {
            join_groups[pair_scope_key(a->lhs.table, a->rhs.table, a->scope_id, a->atom_id)].push_back(a);
        }

        std::vector<Hub> hubs;
        hubs.reserve(join_groups.size());
        std::unordered_map<int, int> atom_to_hub;
        atom_to_hub.reserve(feature_atom_ids.size() * 2u + 1u);

        double stamp_ms_local = 0.0;
        auto build_composite_tokens = [&](Hub *h) {
            if (!h || !h->composite)
                return;
            TableArtifact *lt = require_table(h->left_table);
            TableArtifact *rt = require_table(h->right_table);
            if (!lt || !rt)
                return;
            std::vector<const std::vector<int32> *> lcols;
            std::vector<const std::vector<int32> *> rcols;
            lcols.reserve(h->left_col_idxs.size());
            rcols.reserve(h->right_col_idxs.size());
            for (int c : h->left_col_idxs)
                lcols.push_back(decode_col_tokens(h->left_table, c));
            for (int c : h->right_col_idxs)
                rcols.push_back(decode_col_tokens(h->right_table, c));

            auto t0 = Clock::now();
            h->left_comp_tok.assign(lt->manifest.nrows, -1);
            h->right_comp_tok.assign(rt->manifest.nrows, -1);
            std::unordered_map<uint64, std::vector<int32>> hash_to_tokids;
            std::unordered_map<uint64, int32> packed2_to_tok;
            hash_to_tokids.reserve((size_t)lt->manifest.nrows / 4u + (size_t)rt->manifest.nrows / 4u + 8u);
            packed2_to_tok.reserve((size_t)lt->manifest.nrows / 4u + (size_t)rt->manifest.nrows / 4u + 8u);
            std::vector<int32> dict_parts;
            dict_parts.reserve((size_t)(lt->manifest.nrows + rt->manifest.nrows) * std::max<size_t>(1u, lcols.size()) / 8u);
            int32 next = 0;
            const size_t arity = lcols.size();
            const bool use_packed2 = (arity == 2u);
            auto find_or_add = [&](const std::vector<int32> &parts) -> int32 {
                if (use_packed2) {
                    uint64 packed = ((uint64)(uint32)parts[0] << 32) | (uint64)(uint32)parts[1];
                    auto it = packed2_to_tok.find(packed);
                    if (it != packed2_to_tok.end())
                        return it->second;
                    int32 tok = next++;
                    packed2_to_tok.emplace(packed, tok);
                    return tok;
                }
                uint64 hsh = 1469598103934665603ULL;
                for (int32 v : parts)
                    hsh = hash_combine64(hsh, (uint64)(uint32)v);
                auto &bucket = hash_to_tokids[hsh];
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
                int32 tok = next++;
                bucket.push_back(tok);
                dict_parts.insert(dict_parts.end(), parts.begin(), parts.end());
                return tok;
            };
            auto stamp_side = [&](const std::vector<const std::vector<int32> *> &cols,
                                  std::vector<int32> *dst) {
                std::vector<int32> parts(cols.size(), 0);
                for (uint32 rid = 0; rid < dst->size(); rid++) {
                    bool nullish = false;
                    for (size_t ci = 0; ci < cols.size(); ci++) {
                        int32 t = (*(cols[ci]))[rid];
                        if (t < 0) {
                            nullish = true;
                            break;
                        }
                        parts[ci] = t;
                    }
                    if (nullish)
                        continue;
                    (*dst)[rid] = find_or_add(parts);
                }
            };
            stamp_side(lcols, &h->left_comp_tok);
            stamp_side(rcols, &h->right_comp_tok);
            h->left_tok = &h->left_comp_tok;
            h->right_tok = &h->right_comp_tok;
            h->ntok = (uint32)std::max<int32>(0, next);
            stamp_ms_local += Ms(Clock::now() - t0).count();
        };

        for (auto &kv : join_groups) {
            auto &atoms = kv.second;
            if (atoms.empty())
                continue;
            std::sort(atoms.begin(), atoms.end(), [](const AtomInfo *x, const AtomInfo *y) {
                if (x->join_class_id != y->join_class_id)
                    return x->join_class_id < y->join_class_id;
                return x->atom_id < y->atom_id;
            });

            Hub h;
            h.idx = (int)hubs.size();
            h.left_table = atoms[0]->lhs.table;
            h.right_table = atoms[0]->rhs.table;
            h.composite = (atoms.size() > 1);
            h.domain_id = atoms[0]->join_class_id;
            for (const AtomInfo *a : atoms) {
                bool same_dir = (a->lhs.table == h.left_table && a->rhs.table == h.right_table);
                h.left_col_idxs.push_back(require_col_idx(same_dir ? a->lhs.table : a->rhs.table,
                                                          same_dir ? a->lhs.col : a->rhs.col));
                h.right_col_idxs.push_back(require_col_idx(same_dir ? a->rhs.table : a->lhs.table,
                                                           same_dir ? a->rhs.col : a->lhs.col));
                h.atom_ids.push_back(a->atom_id);
            }
            if (!h.composite) {
                h.left_tok = decode_col_tokens(h.left_table, h.left_col_idxs[0]);
                h.right_tok = decode_col_tokens(h.right_table, h.right_col_idxs[0]);
                uint32 nt = 0;
                if (h.domain_id >= 0)
                    nt = domain_token_count(h.domain_id);
                auto bump = [&](const std::vector<int32> *v) {
                    if (!v) return;
                    int32 mx = -1;
                    for (int32 x : *v) if (x > mx) mx = x;
                    if (mx >= 0)
                        nt = std::max(nt, (uint32)mx + 1u);
                };
                bump(h.left_tok);
                bump(h.right_tok);
                h.ntok = nt;
            } else {
                build_composite_tokens(&h);
            }
            hubs.push_back(std::move(h));
            int hid = (int)hubs.size() - 1;
            for (int aid : hubs[(size_t)hid].atom_ids)
                atom_to_hub[aid] = hid;
        }
        for (Hub &h : hubs) {
            if (!h.composite)
                continue;
            h.left_tok = &h.left_comp_tok;
            h.right_tok = &h.right_comp_tok;
        }

        std::unordered_map<std::string, std::vector<Inc>> incidences;
        incidences.reserve(tables.size() * 2u + 1u);
        for (Hub &h : hubs) {
            incidences[h.left_table].push_back(Inc{h.idx, true, h.left_tok});
            incidences[h.right_table].push_back(Inc{h.idx, false, h.right_tok});
        }

        std::vector<Arc> arcs;
        arcs.reserve(32);
        for (const auto &kv : incidences) {
            const std::string &table = kv.first;
            const std::vector<Inc> &incs = kv.second;
            if (incs.size() < 2)
                continue;
            auto mit = base_rows.find(table);
            if (mit == base_rows.end())
                continue;
            for (size_t i = 0; i < incs.size(); i++) {
                for (size_t j = 0; j < incs.size(); j++) {
                    if (i == j)
                        continue;
                    const Inc &fi = incs[i];
                    const Inc &ti = incs[j];
                    if (!fi.tok || !ti.tok)
                        continue;
                    Arc arc;
                    arc.from_hub = fi.hub_idx;
                    arc.to_hub = ti.hub_idx;
                    arc.table = table;
                    arc.from_tok = fi.tok;
                    arc.to_tok = ti.tok;

                    arcs.push_back(std::move(arc));
                }
            }
        }

        std::vector<uint8_t> hub_reaches_target(hubs.size(), 0u);
        auto tit_for_reach = incidences.find(target);
        if (tit_for_reach != incidences.end()) {
            std::vector<std::vector<int>> undir(hubs.size());
            for (const Arc &arc : arcs) {
                if (arc.from_hub < 0 || arc.to_hub < 0)
                    continue;
                if ((size_t)arc.from_hub >= hubs.size() || (size_t)arc.to_hub >= hubs.size())
                    continue;
                undir[(size_t)arc.from_hub].push_back(arc.to_hub);
                undir[(size_t)arc.to_hub].push_back(arc.from_hub);
            }
            std::deque<int> dq;
            for (const Inc &inc : tit_for_reach->second) {
                if (inc.hub_idx < 0 || (size_t)inc.hub_idx >= hubs.size())
                    continue;
                if (!hub_reaches_target[(size_t)inc.hub_idx]) {
                    hub_reaches_target[(size_t)inc.hub_idx] = 1u;
                    dq.push_back(inc.hub_idx);
                }
            }
            while (!dq.empty()) {
                int h = dq.front();
                dq.pop_front();
                for (int nh : undir[(size_t)h]) {
                    if (nh < 0 || (size_t)nh >= hubs.size())
                        continue;
                    if (!hub_reaches_target[(size_t)nh]) {
                        hub_reaches_target[(size_t)nh] = 1u;
                        dq.push_back(nh);
                    }
                }
            }
        }

        auto t_hub1 = Clock::now();

        auto t_prop0 = Clock::now();
        uint64 domain_prunes = 0;
        uint64 prop_arcs_processed = 0;
        int prop_iters = 0;
        double prop_build_arcs_ms_local = 0.0;
        double prop_ac_ms_local = 0.0;
        double prop_scc_ms_local = 0.0;
        double prop_bin_catalog_ms_local = 0.0;
        double prop_witness_ms_local = 0.0;
        double prop_cmp_ms_local = 0.0;
        double semantic_dedup_ms_local = 0.0;
        double candidate_prune_ms_local = 0.0;
        double sig_const_fold_ms_local = 0.0;
        uint64 bin_build_rows_scanned_local = 0;
        uint64 bin_count_final_local = 0;
        uint64 bin_build_probe_steps_local = 0;
        uint64 bin_build_max_probe_len_local = 0;
        uint64 bin_build_rehash_count_local = 0;
        uint64 bin_build_hub_count_local = 0;
        uint64 bin_build_local_atom_count_local = 0;
        uint64 bin_build_extra_count_local = 0;
        bool any_empty_domain = false;

        struct TargetHubRef {
            int hub_idx = -1;
            const std::vector<int32> *target_tok = nullptr;
        };

        struct WitnessSupport {
            bool use_global = false;
            bool global_value = false;
            std::vector<TargetHubRef> target_refs;
            std::vector<DenseBits> target_supports;
        };

        struct ContextState {
            bool any_empty = false;
            std::unordered_map<std::string, DenseBits> active_bins_by_table;
            std::vector<DenseBits> dom;
            std::vector<DenseBits> scratch_images;
            std::vector<uint8_t> hub_active;
            std::vector<ArcAdj> arc_adjs;
            std::vector<std::vector<int>> out_arc_ids;
            std::vector<std::vector<int>> in_arc_ids;
            std::vector<std::vector<int>> undir_adj;
            std::unordered_map<uint64, std::vector<int>> arc_ids_by_dir;
            std::vector<int> weak_comp;
            std::vector<std::vector<int>> sccs;
            std::vector<int> hub_scc;
        };

        auto arc_dir_key = [](int from_hub, int to_hub) -> uint64 {
            return ((uint64)(uint32)from_hub << 32) | (uint64)(uint32)to_hub;
        };

        std::vector<std::unordered_set<int>> hub_scope_ids(hubs.size());
        for (size_t hi = 0; hi < hubs.size(); hi++) {
            for (int aid : hubs[hi].atom_ids) {
                auto ait = atom_by_id_.find(aid);
                if (ait == atom_by_id_.end())
                    continue;
                if (ait->second.scope_id >= 0)
                    hub_scope_ids[hi].insert(ait->second.scope_id);
            }
        }

        auto hub_matches_scope = [&](int hid, int scope_id) -> bool {
            if (hid < 0 || (size_t)hid >= hubs.size())
                return false;
            if (scope_id < 0)
                return true;
            const auto &scopes = hub_scope_ids[(size_t)hid];
            return scopes.find(scope_id) != scopes.end();
        };

        struct ScopePathCache {
            std::unordered_map<std::string, int> parent_hub;
            std::unordered_map<std::string, std::string> parent_table;
            std::unordered_set<std::string> reachable;
        };
        std::unordered_map<int, ScopePathCache> scope_path_cache;
        scope_path_cache.reserve(8);
        std::unordered_map<int, std::vector<Term>> mandatory_terms_cache;
        mandatory_terms_cache.reserve(feature_atom_ids.size() * 2u + 1u);
        uint64 contexts_total_terms = 0;
        uint64 contexts_pruned_superset = 0;

        auto scope_paths = [&](int scope_id) -> ScopePathCache & {
            auto it = scope_path_cache.find(scope_id);
            if (it != scope_path_cache.end())
                return it->second;

            ScopePathCache pc;
            pc.reachable.reserve(incidences.size() * 2u + 1u);
            std::deque<std::string> qtbl;
            qtbl.push_back(target);
            pc.reachable.insert(target);

            while (!qtbl.empty()) {
                std::string cur = qtbl.front();
                qtbl.pop_front();
                auto iit = incidences.find(cur);
                if (iit == incidences.end())
                    continue;
                for (const Inc &inc : iit->second) {
                    if (!hub_matches_scope(inc.hub_idx, scope_id))
                        continue;
                    const Hub &h = hubs[(size_t)inc.hub_idx];
                    std::string nxt = (h.left_table == cur) ? h.right_table : h.left_table;
                    if (nxt.empty())
                        continue;
                    if (!pc.reachable.insert(nxt).second)
                        continue;
                    pc.parent_hub[nxt] = inc.hub_idx;
                    pc.parent_table[nxt] = cur;
                    qtbl.push_back(nxt);
                }
            }
            auto ins = scope_path_cache.emplace(scope_id, std::move(pc));
            return ins.first->second;
        };

        auto expand_mandatory_term = [&](const Term &seed_term, int atom_id) -> Term {
            Term req = seed_term;
            if (req.empty())
                req.push_back(atom_id);

            std::unordered_set<int> req_set(req.begin(), req.end());
            std::unordered_set<std::string> need_tables;
            need_tables.reserve(req.size() * 2u + 2u);
            need_tables.insert(target);
            int atom_scope = -1;
            auto scope_it = atom_by_id_.find(atom_id);
            if (scope_it != atom_by_id_.end())
                atom_scope = scope_it->second.scope_id;

            auto add_anchor_table = [&](int aid) {
                auto ait = atom_by_id_.find(aid);
                if (ait == atom_by_id_.end())
                    return;
                const AtomInfo &a = ait->second;
                if (a.kind == POLICY_ATOM_JOIN_EQ && a.lhs.table != a.rhs.table) {
                    if (a.lhs.table == target && !a.rhs.table.empty())
                        need_tables.insert(a.rhs.table);
                    else if (!a.lhs.table.empty())
                        need_tables.insert(a.lhs.table);
                    else if (!a.rhs.table.empty())
                        need_tables.insert(a.rhs.table);
                    return;
                }
                if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table != a.rhs.table) {
                    if (a.lhs.table == target && !a.rhs.table.empty())
                        need_tables.insert(a.rhs.table);
                    else if (!a.lhs.table.empty())
                        need_tables.insert(a.lhs.table);
                    else if (!a.rhs.table.empty())
                        need_tables.insert(a.rhs.table);
                    return;
                }
                if (!a.lhs.table.empty())
                    need_tables.insert(a.lhs.table);
            };

            for (int rid : req)
                add_anchor_table(rid);
            add_anchor_table(atom_id);

            auto add_hub_atoms = [&](int hid) {
                if (hid < 0 || (size_t)hid >= hubs.size())
                    return;
                const Hub &h = hubs[(size_t)hid];
                for (int haid : h.atom_ids) {
                    if (haid <= 0)
                        continue;
                    if (atom_scope >= 0) {
                        auto ait = atom_by_id_.find(haid);
                        if (ait == atom_by_id_.end() || ait->second.scope_id != atom_scope)
                            continue;
                    }
                    if (req_set.insert(haid).second)
                    req.push_back(haid);
                }
            };

            ScopePathCache &pc = scope_paths(atom_scope);
            for (const std::string &tbl : need_tables) {
                if (tbl == target)
                    continue;
                if (pc.reachable.find(tbl) == pc.reachable.end())
                    continue;

                std::string cur = tbl;
                while (cur != target) {
                    auto hit = pc.parent_hub.find(cur);
                    auto pit = pc.parent_table.find(cur);
                    if (hit == pc.parent_hub.end() || pit == pc.parent_table.end())
                        break;
                    add_hub_atoms(hit->second);
                    cur = pit->second;
                }
            }

            std::sort(req.begin(), req.end());
            req.erase(std::unique(req.begin(), req.end()), req.end());
            return req;
        };

        auto mandatory_terms_for_atom = [&](int atom_id) -> const std::vector<Term> & {
            static const std::vector<Term> kEmptyTerms;
            if (atom_id <= 0)
                return kEmptyTerms;

            auto mit = mandatory_terms_cache.find(atom_id);
            if (mit != mandatory_terms_cache.end())
                return mit->second;

            std::vector<Term> seeds;
            auto oit = mandatory_terms_by_atom.find(atom_id);
            if (oit != mandatory_terms_by_atom.end() && !oit->second.empty()) {
                seeds = oit->second;
            } else {
                auto bit = mandatory_atoms_by_atom.find(atom_id);
                if (bit != mandatory_atoms_by_atom.end() && !bit->second.empty())
                    seeds.push_back(bit->second);
            }
            if (seeds.empty())
                seeds.push_back(Term{atom_id});

            std::vector<Term> terms;
            terms.reserve(seeds.size());
            std::unordered_set<std::string> seen;
            seen.reserve(seeds.size() * 2u + 1u);
            for (const Term &seed : seeds) {
                Term t = expand_mandatory_term(seed, atom_id);
                normalize_term(&t);
                std::string tk = term_key(t);
                if (!seen.insert(tk).second)
                    continue;
                terms.push_back(std::move(t));
            }
            if (terms.empty())
                terms.push_back(Term{atom_id});

            // Context subsumption pruning:
            // If T1 is a strict subset of T2, T2 is redundant for witness-support
            // union semantics and can be removed.
            auto is_subset_sorted = [](const Term &a, const Term &b) -> bool {
                if (a.size() > b.size())
                    return false;
                size_t i = 0, j = 0;
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
            };
            std::sort(terms.begin(),
                      terms.end(),
                      [](const Term &a, const Term &b) {
                          if (a.size() != b.size())
                              return a.size() < b.size();
                          return a < b;
                      });
            std::vector<Term> pruned;
            pruned.reserve(terms.size());
            for (const Term &t : terms) {
                bool covered = false;
                for (const Term &k : pruned) {
                    if (k.size() >= t.size())
                        break;
                    if (is_subset_sorted(k, t)) {
                        covered = true;
                        contexts_pruned_superset++;
                        break;
                    }
                }
                if (!covered)
                    pruned.push_back(t);
            }
            terms.swap(pruned);
            contexts_total_terms += (uint64)terms.size();

            auto ins = mandatory_terms_cache.emplace(atom_id, std::move(terms));
            return ins.first->second;
        };

        std::unordered_map<std::string, std::vector<int>> local_atoms_all_by_table;
        local_atoms_all_by_table.reserve(tables.size() * 2u + 1u);
        for (int aid : eval_atom_ids) {
            auto ait = atom_by_id_.find(aid);
            if (ait == atom_by_id_.end())
                continue;
            const AtomInfo &a = ait->second;
            bool local_same_table =
                (a.kind == POLICY_ATOM_COL_CONST) ||
                (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table);
            if (!local_same_table)
                continue;
            local_atoms_all_by_table[a.lhs.table].push_back(aid);
        }
        for (auto &kv : local_atoms_all_by_table) {
            std::vector<int> &aids = kv.second;
            std::sort(aids.begin(), aids.end());
            aids.erase(std::unique(aids.begin(), aids.end()), aids.end());
        }

        std::unordered_map<std::string, std::vector<int>> extra_cols_by_table;
        extra_cols_by_table.reserve(tables.size() * 2u + 1u);
        for (const AtomInfo *ap : cross_cmp_atoms) {
            if (!ap)
                continue;
            if (!ap->lhs.table.empty()) {
                int cidx = require_col_idx(ap->lhs.table, ap->lhs.col);
                extra_cols_by_table[ap->lhs.table].push_back(cidx);
            }
            if (!ap->rhs.table.empty()) {
                int cidx = require_col_idx(ap->rhs.table, ap->rhs.col);
                extra_cols_by_table[ap->rhs.table].push_back(cidx);
            }
        }
        for (auto &kv : extra_cols_by_table) {
            std::vector<int> &cols = kv.second;
            std::sort(cols.begin(), cols.end());
            cols.erase(std::unique(cols.begin(), cols.end()), cols.end());
        }

        std::unordered_map<std::string, const TableBinCatalog *> table_bin_catalogs;
        table_bin_catalogs.reserve(tables.size() * 2u + 1u);
        auto build_table_catalog_key =
            [&](const std::string &table,
                const std::vector<std::string> &hub_key_parts,
                const std::vector<int> &local_atom_ids,
                const std::vector<int> &extra_col_idxs,
                bool with_csr) -> std::string {
                std::string key = table;
                key += "|h=";
                for (size_t i = 0; i < hub_key_parts.size(); i++) {
                    if (i)
                        key.push_back(';');
                    key += hub_key_parts[i];
                }
                key += "|l=";
                for (size_t i = 0; i < local_atom_ids.size(); i++) {
                    if (i)
                        key.push_back(',');
                    key += std::to_string(local_atom_ids[i]);
                }
                key += "|e=";
                for (size_t i = 0; i < extra_col_idxs.size(); i++) {
                    if (i)
                        key.push_back(',');
                    key += std::to_string(extra_col_idxs[i]);
                }
                key += "|csr=";
                key += with_csr ? "1" : "0";
                return key;
            };
        for (const std::string &table : tables) {
            auto brow_it = base_rows.find(table);
            if (brow_it == base_rows.end())
                continue;
            TableBinCatalog cat;
            std::vector<std::string> hub_key_parts;
            auto inc_it = incidences.find(table);
            if (inc_it != incidences.end()) {
                cat.hub_ids.reserve(inc_it->second.size());
                hub_key_parts.reserve(inc_it->second.size());
                for (const Inc &inc : inc_it->second) {
                    if (inc.hub_idx < 0 || (size_t)inc.hub_idx >= hubs.size())
                        continue;
                    if ((size_t)inc.hub_idx < hub_reaches_target.size() &&
                        !hub_reaches_target[(size_t)inc.hub_idx])
                        continue;
                    if (!inc.tok)
                        continue;
                    if (cat.hub_pos.find(inc.hub_idx) != cat.hub_pos.end())
                        continue;
                    uint32 pos = (uint32)cat.hub_ids.size();
                    cat.hub_ids.push_back(inc.hub_idx);
                    cat.hub_pos.emplace(inc.hub_idx, pos);
                    const Hub &h = hubs[(size_t)inc.hub_idx];
                    std::string hk;
                    hk.reserve(h.atom_ids.size() * 6u + 4u);
                    hk.push_back((h.left_table == table) ? 'L' : 'R');
                    hk.push_back(':');
                    for (size_t ai = 0; ai < h.atom_ids.size(); ai++) {
                        if (ai)
                            hk.push_back(',');
                        hk += std::to_string(h.atom_ids[ai]);
                    }
                    hub_key_parts.push_back(std::move(hk));
                }
            }
            std::sort(hub_key_parts.begin(), hub_key_parts.end());
            auto lat_it = local_atoms_all_by_table.find(table);
            if (lat_it != local_atoms_all_by_table.end()) {
                cat.local_atom_ids = lat_it->second;
            }
            auto ecols_it = extra_cols_by_table.find(table);
            if (ecols_it != extra_cols_by_table.end()) {
                cat.extra_col_idxs = ecols_it->second;
            }
            bool need_target_row_map = (table == target);
            if (cat.hub_ids.empty() && cat.local_atom_ids.empty() && cat.extra_col_idxs.empty() &&
                !need_target_row_map)
                continue;

            std::string cache_key =
                build_table_catalog_key(table,
                                        hub_key_parts,
                                        cat.local_atom_ids,
                                        cat.extra_col_idxs,
                                        need_target_row_map);
            auto cache_it = table_bin_catalog_cache_.find(cache_key);
            if (cache_it == table_bin_catalog_cache_.end()) {
                auto t_bin_cat0 = Clock::now();
                for (size_t i = 0; i < cat.local_atom_ids.size(); i++)
                    cat.local_pos.emplace(cat.local_atom_ids[i], (uint32)i);
                for (size_t i = 0; i < cat.extra_col_idxs.size(); i++)
                    cat.extra_pos.emplace(cat.extra_col_idxs[i], (uint32)i);

                std::vector<const std::vector<int32> *> hub_tok_cols(cat.hub_ids.size(), nullptr);
                if (inc_it != incidences.end()) {
                    for (const Inc &inc : inc_it->second) {
                        auto pit = cat.hub_pos.find(inc.hub_idx);
                        if (pit == cat.hub_pos.end())
                            continue;
                        hub_tok_cols[(size_t)pit->second] = inc.tok;
                    }
                }
                std::vector<const DenseBits *> local_masks(cat.local_atom_ids.size(), nullptr);
                for (size_t i = 0; i < cat.local_atom_ids.size(); i++) {
                    auto ait = atom_by_id_.find(cat.local_atom_ids[i]);
                    if (ait == atom_by_id_.end())
                        continue;
                    local_masks[i] = &local_mask_for_atom(ait->second);
                }
                std::vector<const std::vector<int32> *> extra_tok_cols(cat.extra_col_idxs.size(), nullptr);
                for (size_t i = 0; i < cat.extra_col_idxs.size(); i++)
                    extra_tok_cols[i] = decode_col_tokens(table, cat.extra_col_idxs[i]);

                TableArtifact *tt = require_table(table);
                uint32 nrows_table = tt ? tt->manifest.nrows : 0u;
                cat.row_to_bin.assign(nrows_table, UINT32_MAX);

                std::unordered_map<uint64, std::vector<uint32>> hash_to_bins;
                hash_to_bins.reserve((size_t)std::max<uint64>(16u, nrows_table / 2u));
                std::vector<int32> hub_vals(cat.hub_ids.size(), -1);
                std::vector<uint8_t> local_bits(cat.local_atom_ids.size(), 0u);
                std::vector<int32> extra_vals(cat.extra_col_idxs.size(), -1);
                auto process_catalog_row = [&](uint32 rid) {
                    if (rid >= nrows_table)
                        return;
                    bin_build_rows_scanned_local++;
                    size_t bucket_count_before = hash_to_bins.bucket_count();
                    uint64 hsh = 1469598103934665603ULL;
                    for (size_t hi = 0; hi < cat.hub_ids.size(); hi++) {
                        int32 tok = -1;
                        const auto *col = hub_tok_cols[hi];
                        if (col && (size_t)rid < col->size()) {
                            tok = (*col)[rid];
                            int hid = cat.hub_ids[hi];
                            if (hid < 0 || (size_t)hid >= hubs.size() ||
                                tok < 0 || (uint32)tok >= hubs[(size_t)hid].ntok)
                                tok = -1;
                        }
                        hub_vals[hi] = tok;
                        hsh = hash_combine64(hsh, (uint64)(uint32)(tok + 1));
                    }
                    for (size_t li = 0; li < cat.local_atom_ids.size(); li++) {
                        bool on = local_masks[li] && local_masks[li]->test(rid);
                        local_bits[li] = (uint8_t)(on ? 1u : 0u);
                        hsh = hash_combine64(hsh, on ? 0x9e3779b97f4a7c15ULL : 0ULL);
                    }
                    for (size_t ei = 0; ei < cat.extra_col_idxs.size(); ei++) {
                        int32 tok = -1;
                        const auto *col = extra_tok_cols[ei];
                        if (col && (size_t)rid < col->size())
                            tok = (*col)[rid];
                        extra_vals[ei] = tok;
                        hsh = hash_combine64(hsh, (uint64)(uint32)(tok + 1));
                    }
                    auto &bucket = hash_to_bins[hsh];
                    if (hash_to_bins.bucket_count() != bucket_count_before)
                        bin_build_rehash_count_local++;
                    uint32 matched_bi = UINT32_MAX;
                    uint64 probe_len = 1ULL;
                    for (uint32 bi : bucket) {
                        probe_len++;
                        if ((size_t)bi >= cat.bins.size())
                            continue;
                        const TableBinEntry &e = cat.bins[(size_t)bi];
                        if (e.hub_vals == hub_vals && e.local_bits == local_bits && e.extra_vals == extra_vals) {
                            cat.bins[(size_t)bi].count++;
                            matched_bi = bi;
                            break;
                        }
                    }
                    if (matched_bi == UINT32_MAX) {
                        matched_bi = (uint32)cat.bins.size();
                        bucket.push_back(matched_bi);
                        TableBinEntry e;
                        e.hub_vals = hub_vals;
                        e.local_bits = local_bits;
                        e.extra_vals = extra_vals;
                        e.count = 1u;
                        cat.bins.push_back(std::move(e));
                    }
                    cat.row_to_bin[(size_t)rid] = matched_bi;
                    bin_build_probe_steps_local += probe_len;
                    if (probe_len > bin_build_max_probe_len_local)
                        bin_build_max_probe_len_local = probe_len;
                };

                bool base_all_rows = (brow_it->second.nbits() == nrows_table &&
                                      brow_it->second.count() >= (uint64)nrows_table);
                if (base_all_rows) {
                    for (uint32 rid = 0; rid < nrows_table; rid++)
                        process_catalog_row(rid);
                } else {
                    brow_it->second.for_each_set([&](uint32 rid) {
                        process_catalog_row(rid);
                    });
                }

                for (size_t li = 0; li < cat.local_atom_ids.size(); li++) {
                    DenseBits sat((uint32)cat.bins.size());
                    sat.clear_all();
                    for (uint32 bi = 0; bi < (uint32)cat.bins.size(); bi++) {
                        if ((size_t)bi >= cat.bins.size())
                            continue;
                        if (li < cat.bins[(size_t)bi].local_bits.size() &&
                            cat.bins[(size_t)bi].local_bits[li] != 0u) {
                            sat.set(bi);
                        }
                    }
                    cat.local_sat_bins.emplace(cat.local_atom_ids[li], std::move(sat));
                }

                if (need_target_row_map) {
                    cat.bin_offsets.assign(cat.bins.size() + 1u, 0u);
                    for (size_t bi = 0; bi < cat.bins.size(); bi++)
                        cat.bin_offsets[bi + 1u] = cat.bin_offsets[bi] + cat.bins[bi].count;
                    cat.bin_rids.assign(cat.bin_offsets.back(), 0u);
                    std::vector<uint32> cursor = cat.bin_offsets;
                    for (uint32 rid = 0; rid < (uint32)cat.row_to_bin.size(); rid++) {
                        uint32 bi = cat.row_to_bin[(size_t)rid];
                        if (bi >= cat.bins.size())
                            continue;
                        uint32 pos = cursor[(size_t)bi]++;
                        if ((size_t)pos < cat.bin_rids.size())
                            cat.bin_rids[(size_t)pos] = rid;
                    }
                }

                bin_count_final_local += (uint64)cat.bins.size();
                bin_build_hub_count_local += (uint64)cat.hub_ids.size();
                bin_build_local_atom_count_local += (uint64)cat.local_atom_ids.size();
                bin_build_extra_count_local += (uint64)cat.extra_col_idxs.size();
                prop_bin_catalog_ms_local += Ms(Clock::now() - t_bin_cat0).count();
                cache_it = table_bin_catalog_cache_.emplace(cache_key, std::move(cat)).first;
            }
            table_bin_catalogs.emplace(table, &cache_it->second);
        }

        std::unordered_map<std::string, DenseBits> base_active_bins_by_table;
        base_active_bins_by_table.reserve(table_bin_catalogs.size() * 2u + 1u);
        for (const auto &kv : table_bin_catalogs) {
            const std::string &table = kv.first;
            const TableBinCatalog *catp = kv.second;
            if (!catp)
                continue;
            DenseBits active((uint32)catp->bins.size());
            active.clear_all();
            auto brow_it = base_rows.find(table);
            if (brow_it != base_rows.end()) {
                const DenseBits &base_mask = brow_it->second;
                if ((uint64)base_mask.nbits() > 0 &&
                    base_mask.count() >= (uint64)base_mask.nbits()) {
                    active.fill_all();
                } else {
                    base_mask.for_each_set([&](uint32 rid) {
                        if ((size_t)rid >= catp->row_to_bin.size())
                            return;
                        uint32 bi = catp->row_to_bin[(size_t)rid];
                        if (bi < active.nbits())
                            active.set(bi);
                    });
                }
            }
            base_active_bins_by_table.emplace(table, std::move(active));
        }

        std::unordered_map<std::string, ContextState> context_cache;
        uint64 context_builds = 0;
        uint64 arc_adj_cache_hits = 0;
        uint64 arc_adj_cache_misses = 0;
        uint64 table_support_cache_hits = 0;
        uint64 table_support_cache_misses = 0;
        struct ArcAdjCacheEntry {
            uint64 active_hash = 0;
            uint64 active_count = 0;
            DenseBits active_bins;
            ArcAdj adj;
        };
        std::unordered_map<uint64, std::vector<ArcAdjCacheEntry>> arc_adj_cache;
        arc_adj_cache.reserve((size_t)std::max<int>(32, (int)arcs.size() * 4));
        static constexpr uint64 kCacheDenseSkipPct = 35ULL;
        static constexpr size_t kCacheBucketCap = 16u;
        auto arc_rel_cache_key = [&](const std::string &table, int from_hub, int to_hub) -> uint64 {
            uint64 h = 1469598103934665603ULL;
            h = hash_combine64(h, std::hash<std::string>{}(table));
            h = hash_combine64(h, (uint64)(uint32)from_hub);
            h = hash_combine64(h, (uint64)(uint32)to_hub);
            return h;
        };
        struct TableSupportCacheEntry {
            uint64 active_hash = 0;
            uint64 active_count = 0;
            DenseBits active_bins;
            std::vector<DenseBits> supports; // aligned with TableBinCatalog::hub_ids
        };
        std::unordered_map<std::string, std::vector<TableSupportCacheEntry>> table_support_cache;
        table_support_cache.reserve(table_bin_catalogs.size() * 2u + 1u);

        auto build_context_state = [&](const std::vector<int> &mandatory_atoms) -> ContextState {
            ContextState ctx;
            std::unordered_map<std::string, std::vector<int>> local_atoms_by_table;
            local_atoms_by_table.reserve(tables.size() * 2u + 1u);
            for (int mid : mandatory_atoms) {
                auto ait = atom_by_id_.find(mid);
                if (ait == atom_by_id_.end())
                    continue;
                const AtomInfo &ma = ait->second;
                bool local_same_table =
                    (ma.kind == POLICY_ATOM_COL_CONST) ||
                    (ma.kind == POLICY_ATOM_COL_COL && ma.lhs.table == ma.rhs.table);
                if (!local_same_table)
                    continue;
                local_atoms_by_table[ma.lhs.table].push_back(mid);
            }
            for (auto &kv : local_atoms_by_table) {
                std::vector<int> &aids = kv.second;
                std::sort(aids.begin(), aids.end());
                aids.erase(std::unique(aids.begin(), aids.end()), aids.end());
            }

            ctx.hub_active.assign(hubs.size(), 0u);
            for (int mid : mandatory_atoms) {
                auto ait = atom_by_id_.find(mid);
                if (ait == atom_by_id_.end())
                    continue;
                const AtomInfo &ma = ait->second;
                if (!(ma.kind == POLICY_ATOM_JOIN_EQ && ma.lhs.table != ma.rhs.table))
                    continue;
                auto hit = atom_to_hub.find(ma.atom_id);
                if (hit != atom_to_hub.end() && hit->second >= 0 && (size_t)hit->second < ctx.hub_active.size())
                    ctx.hub_active[(size_t)hit->second] = 1u;
            }

            ctx.active_bins_by_table.reserve(table_bin_catalogs.size() * 2u + 1u);
            for (const auto &kv : table_bin_catalogs) {
                const std::string &table = kv.first;
                const TableBinCatalog *catp = kv.second;
                if (!catp)
                    continue;
                const TableBinCatalog &cat = *catp;
                DenseBits active((uint32)cat.bins.size());
                active.clear_all();
                auto base_it = base_active_bins_by_table.find(table);
                if (base_it != base_active_bins_by_table.end() &&
                    base_it->second.nbits() == active.nbits()) {
                    active = base_it->second;
                }
                auto lat = local_atoms_by_table.find(table);
                if (lat != local_atoms_by_table.end()) {
                    for (int aid : lat->second) {
                        auto sit = cat.local_sat_bins.find(aid);
                        if (sit == cat.local_sat_bins.end()) {
                            active.clear_all();
                            break;
                        }
                        active.bit_and(sit->second);
                    }
                }
                ctx.active_bins_by_table.emplace(table, std::move(active));
            }

            std::unordered_map<std::string, const std::vector<DenseBits> *> table_hub_supports;
            table_hub_supports.reserve(table_bin_catalogs.size() * 2u + 1u);
            std::unordered_map<std::string, std::vector<DenseBits>> table_hub_supports_owned;
            table_hub_supports_owned.reserve(table_bin_catalogs.size() * 2u + 1u);
            for (const auto &kv : table_bin_catalogs) {
                const std::string &table = kv.first;
                const TableBinCatalog *catp = kv.second;
                if (!catp)
                    continue;
                const TableBinCatalog &cat = *catp;
                if (cat.hub_ids.empty())
                    continue;
                auto abit = ctx.active_bins_by_table.find(table);
                if (abit == ctx.active_bins_by_table.end())
                    continue;
                const DenseBits &active = abit->second;
                uint64 active_count = active.count();
                const std::vector<DenseBits> *supports_ptr = nullptr;

                auto build_supports_for_active = [&](std::vector<DenseBits> *dst) {
                    if (!dst)
                        return;
                    dst->clear();
                    dst->resize(cat.hub_ids.size());
                    for (size_t hi = 0; hi < cat.hub_ids.size(); hi++) {
                        int hid = cat.hub_ids[hi];
                        if (hid < 0 || (size_t)hid >= hubs.size()) {
                            (*dst)[hi].reset(0u);
                            continue;
                        }
                        (*dst)[hi].reset(hubs[(size_t)hid].ntok);
                        (*dst)[hi].clear_all();
                    }
                    active.for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= cat.bins.size())
                            return;
                        const TableBinEntry &bin = cat.bins[(size_t)bi];
                        for (size_t hi = 0; hi < cat.hub_ids.size(); hi++) {
                            int hid = cat.hub_ids[hi];
                            if (hid < 0 || (size_t)hid >= hubs.size())
                                continue;
                            if (hi >= bin.hub_vals.size())
                                continue;
                            int32 tok = bin.hub_vals[hi];
                            if (tok < 0 || (uint32)tok >= hubs[(size_t)hid].ntok)
                                continue;
                            (*dst)[hi].set((uint32)tok);
                        }
                    });
                };

                bool cacheable_support =
                    (active.nbits() > 0u &&
                     (active_count * 100ULL) <= ((uint64)active.nbits() * kCacheDenseSkipPct));
                if (cacheable_support) {
                    uint64 active_hash = active.hash64();
                    auto &bucket = table_support_cache[table];
                    for (const TableSupportCacheEntry &ce : bucket) {
                        if (ce.active_hash != active_hash || ce.active_count != active_count)
                            continue;
                        if (!ce.active_bins.equals(active))
                            continue;
                        supports_ptr = &ce.supports;
                        table_support_cache_hits++;
                        break;
                    }
                    if (!supports_ptr) {
                        TableSupportCacheEntry ce;
                        ce.active_hash = active_hash;
                        ce.active_count = active_count;
                        ce.active_bins = active;
                        build_supports_for_active(&ce.supports);
                        if (bucket.size() >= kCacheBucketCap)
                            bucket.erase(bucket.begin());
                        bucket.push_back(std::move(ce));
                        supports_ptr = &bucket.back().supports;
                        table_support_cache_misses++;
                    }
                } else {
                    auto &owned = table_hub_supports_owned[table];
                    build_supports_for_active(&owned);
                    supports_ptr = &owned;
                }

                table_hub_supports.emplace(table, supports_ptr);
            }

            ctx.dom.resize(hubs.size());
            for (size_t hi = 0; hi < hubs.size(); hi++) {
                const Hub &h = hubs[hi];
                ctx.dom[hi].reset(h.ntok);
                if (!ctx.hub_active[hi]) {
                    ctx.dom[hi].fill_all();
                    continue;
                }
                DenseBits left(h.ntok), right(h.ntok);
                left.clear_all();
                right.clear_all();
                auto add_from_cached_support = [&](const std::string &table, DenseBits *out) {
                    if (!out)
                        return;
                    auto cat_it = table_bin_catalogs.find(table);
                    auto sup_it = table_hub_supports.find(table);
                    if (cat_it == table_bin_catalogs.end() || sup_it == table_hub_supports.end())
                        return;
                    const TableBinCatalog *catp = cat_it->second;
                    if (!catp)
                        return;
                    auto pit = catp->hub_pos.find((int)hi);
                    if (pit == catp->hub_pos.end())
                        return;
                    uint32 pos = pit->second;
                    const std::vector<DenseBits> *supports = sup_it->second;
                    if (!supports || (size_t)pos >= supports->size())
                        return;
                    *out = (*supports)[(size_t)pos];
                };
                add_from_cached_support(h.left_table, &left);
                add_from_cached_support(h.right_table, &right);
                ctx.dom[hi] = std::move(left);
                (void)ctx.dom[hi].intersect_with_changed(right);
                if (!ctx.dom[hi].any())
                    ctx.any_empty = true;
            }
            if (ctx.any_empty) {
                any_empty_domain = true;
                return ctx;
            }
            ctx.scratch_images.resize(hubs.size());

            auto t_arc_build0 = Clock::now();
            ctx.out_arc_ids.assign(hubs.size(), {});
            ctx.in_arc_ids.assign(hubs.size(), {});
            ctx.undir_adj.assign(hubs.size(), {});
            for (size_t arc_idx = 0; arc_idx < arcs.size(); arc_idx++) {
                const Arc &arc = arcs[arc_idx];
                if (!arc.from_tok || !arc.to_tok)
                    continue;
                if (arc.from_hub < 0 || arc.to_hub < 0)
                    continue;
                if ((size_t)arc.from_hub >= hubs.size() || (size_t)arc.to_hub >= hubs.size())
                    continue;
                if ((size_t)arc.from_hub < hub_reaches_target.size() && !hub_reaches_target[(size_t)arc.from_hub])
                    continue;
                if ((size_t)arc.to_hub < hub_reaches_target.size() && !hub_reaches_target[(size_t)arc.to_hub])
                    continue;
                if (!ctx.hub_active[(size_t)arc.from_hub] || !ctx.hub_active[(size_t)arc.to_hub])
                    continue;

                ArcAdj adj;
                adj.from_hub = arc.from_hub;
                adj.to_hub = arc.to_hub;
                adj.from_ntok = hubs[(size_t)arc.from_hub].ntok;
                std::vector<std::pair<uint32, uint32>> pairs;
                auto tcat = table_bin_catalogs.find(arc.table);
                auto tactive = ctx.active_bins_by_table.find(arc.table);
                bool cache_hit = false;
                bool cacheable_arc = false;
                if (tcat != table_bin_catalogs.end() && tactive != ctx.active_bins_by_table.end()) {
                    const TableBinCatalog *tcatp = tcat->second;
                    if (!tcatp)
                        continue;
                    const DenseBits &active_bins = tactive->second;
                    uint64 active_count = active_bins.count();
                    cacheable_arc =
                        (active_bins.nbits() > 0u &&
                         (active_count * 100ULL) <= ((uint64)active_bins.nbits() * kCacheDenseSkipPct));
                    if (cacheable_arc) {
                        uint64 active_hash = active_bins.hash64();
                        uint64 rel_key = arc_rel_cache_key(arc.table, arc.from_hub, arc.to_hub);
                        auto cbit = arc_adj_cache.find(rel_key);
                        if (cbit != arc_adj_cache.end()) {
                            for (const ArcAdjCacheEntry &ce : cbit->second) {
                                if (ce.active_hash != active_hash || ce.active_count != active_count)
                                    continue;
                                if (!ce.active_bins.equals(active_bins))
                                    continue;
                                adj = ce.adj;
                                arc_adj_cache_hits++;
                                cache_hit = true;
                                break;
                            }
                        }
                    }
                    if (!adj.from_keys.empty()) {
                        int aidx = (int)ctx.arc_adjs.size();
                        ctx.arc_adjs.push_back(std::move(adj));
                        ctx.out_arc_ids[(size_t)arc.from_hub].push_back(aidx);
                        ctx.in_arc_ids[(size_t)arc.to_hub].push_back(aidx);
                        ctx.undir_adj[(size_t)arc.from_hub].push_back(arc.to_hub);
                        ctx.undir_adj[(size_t)arc.to_hub].push_back(arc.from_hub);
                        ctx.arc_ids_by_dir[arc_dir_key(arc.from_hub, arc.to_hub)].push_back(aidx);
                        continue;
                    }
                    if (!cache_hit && cacheable_arc)
                        arc_adj_cache_misses++;
                    auto fit = tcatp->hub_pos.find(arc.from_hub);
                    auto tit = tcatp->hub_pos.find(arc.to_hub);
                    if (fit != tcatp->hub_pos.end() && tit != tcatp->hub_pos.end()) {
                        uint32 fpos = fit->second;
                        uint32 tpos = tit->second;
                        pairs.reserve((size_t)std::max<uint64>(16u, tactive->second.count()));
                        tactive->second.for_each_set([&](uint32 bi) {
                            if ((size_t)bi >= tcatp->bins.size())
                                return;
                            const TableBinEntry &bin = tcatp->bins[(size_t)bi];
                            if ((size_t)fpos >= bin.hub_vals.size() || (size_t)tpos >= bin.hub_vals.size())
                                return;
                            int32 f = bin.hub_vals[(size_t)fpos];
                            int32 t = bin.hub_vals[(size_t)tpos];
                            if (f < 0 || t < 0)
                                return;
                            if ((uint32)f >= hubs[(size_t)arc.from_hub].ntok ||
                                (uint32)t >= hubs[(size_t)arc.to_hub].ntok)
                                return;
                            pairs.emplace_back((uint32)f, (uint32)t);
                        });
                    }
                }
                if (!pairs.empty()) {
                    std::sort(pairs.begin(), pairs.end());
                    pairs.erase(std::unique(pairs.begin(), pairs.end()), pairs.end());

                    adj.from_keys.reserve(pairs.size() / 2u + 1u);
                    adj.offsets.reserve(pairs.size() / 2u + 2u);
                    adj.to_vals.reserve(pairs.size());

                    uint32 cur_from = std::numeric_limits<uint32>::max();
                    for (const auto &p : pairs) {
                        uint32 f = p.first;
                        uint32 t = p.second;
                        if (f != cur_from) {
                            adj.from_keys.push_back(f);
                            adj.offsets.push_back((uint32)adj.to_vals.size());
                            cur_from = f;
                        }
                        adj.to_vals.push_back((int32)t);
                    }
                    adj.offsets.push_back((uint32)adj.to_vals.size());
                }
                if (adj.from_keys.empty())
                    continue;

                if (cacheable_arc && tactive != ctx.active_bins_by_table.end()) {
                    uint64 rel_key = arc_rel_cache_key(arc.table, arc.from_hub, arc.to_hub);
                    auto &bucket = arc_adj_cache[rel_key];
                    ArcAdjCacheEntry ce;
                    ce.active_hash = tactive->second.hash64();
                    ce.active_count = tactive->second.count();
                    ce.active_bins = tactive->second;
                    ce.adj = adj;
                    if (bucket.size() >= kCacheBucketCap)
                        bucket.erase(bucket.begin());
                    bucket.push_back(std::move(ce));
                }

                int aidx = (int)ctx.arc_adjs.size();
                ctx.arc_adjs.push_back(std::move(adj));
                ctx.out_arc_ids[(size_t)arc.from_hub].push_back(aidx);
                ctx.in_arc_ids[(size_t)arc.to_hub].push_back(aidx);
                ctx.undir_adj[(size_t)arc.from_hub].push_back(arc.to_hub);
                ctx.undir_adj[(size_t)arc.to_hub].push_back(arc.from_hub);
                ctx.arc_ids_by_dir[arc_dir_key(arc.from_hub, arc.to_hub)].push_back(aidx);
            }
            ctx.weak_comp.assign(hubs.size(), -1);
            int comp_id = 0;
            for (size_t hi = 0; hi < hubs.size(); hi++) {
                if (!ctx.hub_active[hi] || ctx.weak_comp[hi] >= 0)
                    continue;
                std::deque<int> dq;
                dq.push_back((int)hi);
                ctx.weak_comp[hi] = comp_id;
                while (!dq.empty()) {
                    int h = dq.front();
                    dq.pop_front();
                    for (int nh : ctx.undir_adj[(size_t)h]) {
                        if (nh < 0 || (size_t)nh >= hubs.size())
                            continue;
                        if (!ctx.hub_active[(size_t)nh] || ctx.weak_comp[(size_t)nh] >= 0)
                            continue;
                        ctx.weak_comp[(size_t)nh] = comp_id;
                        dq.push_back(nh);
                    }
                }
                comp_id++;
            }
            auto t_arc_build1 = Clock::now();
            prop_build_arcs_ms_local += Ms(t_arc_build1 - t_arc_build0).count();

            // Bin-level AC propagation:
            // D(to) := D(to) ∩ Image(Rel(from,to), D(from))
            auto run_ac = [&](std::deque<int> *seed, std::vector<uint8_t> *changed_hubs) -> bool {
                if (!seed || ctx.arc_adjs.empty())
                    return false;
                bool changed_any = false;
                std::vector<uint8_t> inq(ctx.arc_adjs.size(), 0u);
                std::deque<int> q = *seed;
                for (int ai : q) {
                    if (ai >= 0 && (size_t)ai < inq.size())
                        inq[(size_t)ai] = 1u;
                }
                while (!q.empty()) {
                    int ai = q.front();
                    q.pop_front();
                    if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                        continue;
                    inq[(size_t)ai] = 0u;
                    prop_iters++;
                    prop_arcs_processed++;
                    const ArcAdj &adj = ctx.arc_adjs[(size_t)ai];
                    int from_h = adj.from_hub;
                    int to_h = adj.to_hub;
                    if (from_h < 0 || to_h < 0)
                        continue;
                    if ((size_t)from_h >= ctx.dom.size() || (size_t)to_h >= ctx.dom.size())
                        continue;

                    DenseBits &image = ctx.scratch_images[(size_t)to_h];
                    if (image.nbits() != ctx.dom[(size_t)to_h].nbits())
                        image.reset(ctx.dom[(size_t)to_h].nbits());
                    image.clear_all();
                    adj.image_from_domain(ctx.dom[(size_t)from_h], &image);
                    bool shrank = ctx.dom[(size_t)to_h].intersect_with_changed(image);
                    if (!shrank)
                        continue;
                    changed_any = true;
                    domain_prunes++;
                    if (changed_hubs && (size_t)to_h < changed_hubs->size())
                        (*changed_hubs)[(size_t)to_h] = 1u;
                    if (!ctx.dom[(size_t)to_h].any()) {
                        ctx.any_empty = true;
                        any_empty_domain = true;
                        return true;
                    }
                    if ((size_t)to_h >= ctx.out_arc_ids.size())
                        continue;
                    for (int nei : ctx.out_arc_ids[(size_t)to_h]) {
                        if (nei >= 0 && (size_t)nei < inq.size() && !inq[(size_t)nei]) {
                            inq[(size_t)nei] = 1u;
                            q.push_back(nei);
                        }
                    }
                }
                return changed_any;
            };

            auto compute_sccs = [&]() -> std::vector<std::vector<int>> {
                std::vector<std::vector<int>> sccs;
                int n = (int)hubs.size();
                std::vector<int> idx((size_t)n, -1);
                std::vector<int> low((size_t)n, -1);
                std::vector<uint8_t> onst((size_t)n, 0u);
                std::vector<int> st;
                st.reserve((size_t)n);
                int tick = 0;
                std::function<void(int)> dfs = [&](int v) {
                    idx[(size_t)v] = low[(size_t)v] = tick++;
                    st.push_back(v);
                    onst[(size_t)v] = 1u;
                    for (int ai : ctx.out_arc_ids[(size_t)v]) {
                        if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                            continue;
                        int to = ctx.arc_adjs[(size_t)ai].to_hub;
                        if (to < 0 || (size_t)to >= hubs.size() || !ctx.hub_active[(size_t)to])
                            continue;
                        if (idx[(size_t)to] < 0) {
                            dfs(to);
                            low[(size_t)v] = std::min(low[(size_t)v], low[(size_t)to]);
                        } else if (onst[(size_t)to]) {
                            low[(size_t)v] = std::min(low[(size_t)v], idx[(size_t)to]);
                        }
                    }
                    if (low[(size_t)v] == idx[(size_t)v]) {
                        std::vector<int> comp;
                        while (!st.empty()) {
                            int w = st.back();
                            st.pop_back();
                            onst[(size_t)w] = 0u;
                            comp.push_back(w);
                            if (w == v)
                                break;
                        }
                        sccs.push_back(std::move(comp));
                    }
                };
                for (int v = 0; v < n; v++) {
                    if (!ctx.hub_active[(size_t)v] || idx[(size_t)v] >= 0)
                        continue;
                    dfs(v);
                }
                return sccs;
            };

            auto pair_ok = [&](int from_hub, int to_hub, int32 from_tok, int32 to_tok) -> bool {
                auto dit = ctx.arc_ids_by_dir.find(arc_dir_key(from_hub, to_hub));
                if (dit == ctx.arc_ids_by_dir.end())
                    return true;
                for (int ai : dit->second) {
                    if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                        continue;
                    if (!ctx.arc_adjs[(size_t)ai].has_pair(from_tok, to_tok))
                        return false;
                }
                return true;
            };

            auto run_exact_scc = [&](const std::vector<int> &comp) -> bool {
                if (comp.size() < 2)
                    return false;

                std::vector<int> order = comp;
                std::sort(order.begin(), order.end(), [&](int a, int b) {
                    return ctx.dom[(size_t)a].count() < ctx.dom[(size_t)b].count();
                });

                std::vector<std::vector<int32>> cand(hubs.size());
                for (int h : order) {
                    ctx.dom[(size_t)h].for_each_set([&](uint32 tok) { cand[(size_t)h].push_back((int32)tok); });
                    if (cand[(size_t)h].empty()) {
                        ctx.dom[(size_t)h].clear_all();
                        ctx.any_empty = true;
                        any_empty_domain = true;
                        return true;
                    }
                }

                std::vector<DenseBits> supported(hubs.size());
                for (int h : order) {
                    supported[(size_t)h].reset(hubs[(size_t)h].ntok);
                    supported[(size_t)h].clear_all();
                }

                auto all_supported = [&]() -> bool {
                    for (int h : order) {
                        if (supported[(size_t)h].count() < ctx.dom[(size_t)h].count())
                            return false;
                    }
                    return true;
                };

                auto exists_compat = [&](int h1, int32 tok1, int h2) -> bool {
                    const std::vector<int32> &c2 = cand[(size_t)h2];
                    for (int32 tok2 : c2) {
                        if (pair_ok(h1, h2, tok1, tok2) && pair_ok(h2, h1, tok2, tok1))
                            return true;
                    }
                    return false;
                };

                std::vector<int32> assign(hubs.size(), -1);
                bool stop_all = false;
                bool budget_exceeded = false;
                uint64 visited = 0;
                const uint64 kNodeBudget = 20000000ULL;
                std::function<void(size_t)> dfs = [&](size_t depth) {
                    if (stop_all)
                        return;
                    if (depth == order.size()) {
                        for (int h : order) {
                            int32 tv = assign[(size_t)h];
                            if (tv >= 0)
                                supported[(size_t)h].set((uint32)tv);
                        }
                        if (all_supported())
                            stop_all = true;
                        return;
                    }
                    int h = order[depth];
                    for (int32 tok : cand[(size_t)h]) {
                        visited++;
                        if (visited > kNodeBudget) {
                            budget_exceeded = true;
                            return;
                        }
                        bool ok = true;
                        for (size_t i = 0; i < depth && ok; i++) {
                            int oh = order[i];
                            int32 ov = assign[(size_t)oh];
                            if (ov < 0)
                                continue;
                            if (!pair_ok(h, oh, tok, ov) || !pair_ok(oh, h, ov, tok))
                                ok = false;
                        }
                        if (!ok)
                            continue;
                        for (size_t i = depth + 1; i < order.size() && ok; i++) {
                            int uh = order[i];
                            if (!exists_compat(h, tok, uh))
                                ok = false;
                        }
                        if (!ok)
                            continue;
                        assign[(size_t)h] = tok;
                        dfs(depth + 1u);
                        assign[(size_t)h] = -1;
                        if (stop_all || budget_exceeded)
                            break;
                    }
                };
                dfs(0u);
                if (budget_exceeded) {
                    return false;
                }

                bool changed = false;
                for (int h : order) {
                    uint64 before = ctx.dom[(size_t)h].count();
                    bool shrank = ctx.dom[(size_t)h].intersect_with_changed(supported[(size_t)h]);
                    if (shrank) {
                        changed = true;
                        uint64 after = ctx.dom[(size_t)h].count();
                        if (after < before)
                            domain_prunes += (before - after);
                        if (after == 0) {
                            ctx.any_empty = true;
                            any_empty_domain = true;
                            break;
                        }
                    }
                }
                return changed;
            };

            auto t_scc_build0 = Clock::now();
            std::vector<std::vector<int>> sccs = compute_sccs();
            ctx.sccs = sccs;
            ctx.hub_scc.assign(hubs.size(), -1);
            for (size_t si = 0; si < sccs.size(); si++) {
                for (int h : sccs[si]) {
                    if (h >= 0 && (size_t)h < hubs.size())
                        ctx.hub_scc[(size_t)h] = (int)si;
                }
            }
            auto t_scc_build1 = Clock::now();
            prop_scc_ms_local += Ms(t_scc_build1 - t_scc_build0).count();
            static constexpr bool kEnableExactSccRefine = false;
            bool has_cycle_scc = false;
            if (kEnableExactSccRefine) {
                for (const std::vector<int> &comp : sccs) {
                    if (comp.size() >= 2u) {
                        has_cycle_scc = true;
                        break;
                    }
                }
            }
            std::vector<uint8_t> scc_exact_seen(sccs.size(), 0u);

            bool changed_outer = true;
            int outer_guard = 0;
            while (!ctx.any_empty && changed_outer && outer_guard < 16) {
                outer_guard++;
                changed_outer = false;
                std::vector<uint8_t> changed_hubs(hubs.size(), 0u);
                std::deque<int> seed;
                for (int ai = 0; ai < (int)ctx.arc_adjs.size(); ai++)
                    seed.push_back(ai);
                auto t_ac0 = Clock::now();
                bool ac_changed = run_ac(&seed, &changed_hubs);
                prop_ac_ms_local += Ms(Clock::now() - t_ac0).count();
                if (ac_changed)
                    changed_outer = true;
                if (ctx.any_empty)
                    break;
                if (has_cycle_scc) {
                    for (size_t si = 0; si < sccs.size(); si++) {
                        const std::vector<int> &comp = sccs[si];
                        if (comp.size() < 2u)
                            continue;
                        bool need_exact = (scc_exact_seen[si] == 0u);
                        if (!need_exact) {
                            for (int h : comp) {
                                if (h >= 0 && (size_t)h < changed_hubs.size() &&
                                    changed_hubs[(size_t)h]) {
                                    need_exact = true;
                                    break;
                                }
                            }
                        }
                        if (!need_exact)
                            continue;
                        auto t_scc_exact0 = Clock::now();
                        bool exact_changed = run_exact_scc(comp);
                        prop_scc_ms_local += Ms(Clock::now() - t_scc_exact0).count();
                        if (exact_changed)
                            changed_outer = true;
                        scc_exact_seen[si] = 1u;
                        if (ctx.any_empty)
                            break;
                    }
                }
            }
            return ctx;
        };

        auto context_relevant_atom = [&](int aid) -> bool {
            auto ait = atom_by_id_.find(aid);
            if (ait == atom_by_id_.end())
                return false;
            const AtomInfo &a = ait->second;
            bool local_same_table =
                (a.kind == POLICY_ATOM_COL_CONST) ||
                (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table);
            if (local_same_table)
                return a.lhs.table != target;
            if (a.kind == POLICY_ATOM_JOIN_EQ && a.lhs.table != a.rhs.table)
                return true;
            return false;
        };

        auto context_for_ctxatoms = [&](int atom_scope, const Term &ctx_atoms) -> const ContextState & {
            std::string key = std::to_string(atom_scope);
            key.push_back('|');
            key += term_key(ctx_atoms);
            auto it = context_cache.find(key);
            if (it != context_cache.end()) {
                return it->second;
            }
            ContextState ctx = build_context_state(ctx_atoms);
            auto ins = context_cache.emplace(std::move(key), std::move(ctx));
            context_builds++;
            return ins.first->second;
        };
        std::unordered_map<int, std::vector<const ContextState *>> atom_context_list_cache;
        atom_context_list_cache.reserve(feature_atom_ids.size() * 2u + 1u);
        auto atom_requires_context = [&](int atom_id) -> bool {
            auto ait = atom_by_id_.find(atom_id);
            if (ait == atom_by_id_.end())
                return false;
            const AtomInfo &a = ait->second;
            if (a.kind == POLICY_ATOM_COL_CONST)
                return a.lhs.table != target;
            if (a.kind == POLICY_ATOM_COL_COL)
                return (a.lhs.table != a.rhs.table) || (a.lhs.table != target);
            if (a.kind == POLICY_ATOM_JOIN_EQ)
                return true;
            return false;
        };

        auto contexts_for_atom = [&](int atom_id) -> const std::vector<const ContextState *> & {
            static const std::vector<const ContextState *> kEmpty;
            if (atom_id <= 0)
                return kEmpty;
            if (!atom_requires_context(atom_id))
                return kEmpty;
            auto it = atom_context_list_cache.find(atom_id);
            if (it != atom_context_list_cache.end())
                return it->second;

            int atom_scope = -1;
            auto ait = atom_by_id_.find(atom_id);
            if (ait != atom_by_id_.end())
                atom_scope = ait->second.scope_id;

            auto is_subset_sorted = [](const Term &a, const Term &b) -> bool {
                if (a.size() > b.size())
                    return false;
                size_t i = 0, j = 0;
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
            };

            std::vector<Term> ctx_terms;
            std::vector<const ContextState *> out;
            const std::vector<Term> &terms = mandatory_terms_for_atom(atom_id);
            ctx_terms.reserve(terms.size());
            std::unordered_set<std::string> seen_ctx_terms;
            seen_ctx_terms.reserve(terms.size() * 2u + 1u);
            for (const Term &t : terms) {
                Term ctx_atoms;
                ctx_atoms.reserve(t.size());
                for (int mid : t) {
                    if (context_relevant_atom(mid))
                        ctx_atoms.push_back(mid);
                }
                std::sort(ctx_atoms.begin(), ctx_atoms.end());
                ctx_atoms.erase(std::unique(ctx_atoms.begin(), ctx_atoms.end()), ctx_atoms.end());
                std::string ctk = term_key(ctx_atoms);
                if (!seen_ctx_terms.insert(ctk).second)
                    continue;
                ctx_terms.push_back(std::move(ctx_atoms));
            }
            if (ctx_terms.empty()) {
                Term fallback;
                if (context_relevant_atom(atom_id))
                    fallback.push_back(atom_id);
                ctx_terms.push_back(std::move(fallback));
            }

            std::sort(ctx_terms.begin(),
                      ctx_terms.end(),
                      [](const Term &a, const Term &b) {
                          if (a.size() != b.size())
                              return a.size() < b.size();
                          return a < b;
                      });
            std::vector<Term> pruned_ctx_terms;
            pruned_ctx_terms.reserve(ctx_terms.size());
            for (const Term &t : ctx_terms) {
                bool covered = false;
                for (const Term &k : pruned_ctx_terms) {
                    if (k.size() >= t.size())
                        break;
                    if (is_subset_sorted(k, t)) {
                        covered = true;
                        contexts_pruned_superset++;
                        break;
                    }
                }
                if (!covered)
                    pruned_ctx_terms.push_back(t);
            }

            out.reserve(pruned_ctx_terms.size());
            for (const Term &ctx_atoms : pruned_ctx_terms)
                out.push_back(&context_for_ctxatoms(atom_scope, ctx_atoms));

            auto ins = atom_context_list_cache.emplace(atom_id, std::move(out));
            return ins.first->second;
        };

        auto context_for_atom = [&](int atom_id) -> const ContextState & {
            const std::vector<const ContextState *> &ctxs = contexts_for_atom(atom_id);
            if (!ctxs.empty() && ctxs[0])
                return *ctxs[0];
            static ContextState kEmptyCtx;
            return kEmptyCtx;
        };

        auto table_connected_to_target_in_ctx = [&](const std::string &table, const ContextState &ctx) -> bool {
            auto tit = incidences.find(target);
            auto wit = incidences.find(table);
            if (tit == incidences.end() || wit == incidences.end())
                return false;
            for (const Inc &a : tit->second) {
                if (a.hub_idx < 0 || (size_t)a.hub_idx >= hubs.size())
                    continue;
                if ((size_t)a.hub_idx >= ctx.hub_active.size() || !ctx.hub_active[(size_t)a.hub_idx])
                    continue;
                int ca = ((size_t)a.hub_idx < ctx.weak_comp.size()) ? ctx.weak_comp[(size_t)a.hub_idx] : -1;
                if (ca < 0)
                    continue;
                for (const Inc &b : wit->second) {
                    if (b.hub_idx < 0 || (size_t)b.hub_idx >= hubs.size())
                        continue;
                    if ((size_t)b.hub_idx >= ctx.hub_active.size() || !ctx.hub_active[(size_t)b.hub_idx])
                        continue;
                    int cb = ((size_t)b.hub_idx < ctx.weak_comp.size()) ? ctx.weak_comp[(size_t)b.hub_idx] : -1;
                    if (cb >= 0 && cb == ca)
                        return true;
                }
            }
            return false;
        };

        struct WitnessMemoEntry {
            const ContextState *ctx = nullptr;
            std::string witness_table;
            std::vector<int> pref_hubs_sorted;
            uint64 pred_hash = 0;
            uint64 pred_count = 0;
            DenseBits pred_bins;
            WitnessSupport ws;
        };
        std::unordered_map<uint64, std::vector<WitnessMemoEntry>> witness_support_memo;
        witness_support_memo.reserve(128);
        uint64 witness_memo_hits = 0;
        uint64 witness_memo_misses = 0;
        auto hash_pref_hubs = [](const std::vector<int> &hubs_vec) -> uint64 {
            uint64 h = 1469598103934665603ULL;
            for (int v : hubs_vec)
                h = hash_combine64(h, (uint64)(uint32)v);
            return h;
        };
        auto witness_memo_bucket_key = [&](const ContextState *ctxp,
                                           const std::string &wtable,
                                           uint64 pred_hash,
                                           uint64 pred_count,
                                           uint64 pref_hash) -> uint64 {
            uint64 h = 1469598103934665603ULL;
            h = hash_combine64(h, (uint64)(uintptr_t)ctxp);
            h = hash_combine64(h, std::hash<std::string>{}(wtable));
            h = hash_combine64(h, pred_hash);
            h = hash_combine64(h, pred_count);
            h = hash_combine64(h, pref_hash);
            return h;
        };

        auto build_witness_support_from_bins =
            [&](const std::string &wtable,
                const DenseBits &pred_bins,
                const ContextState &ctx,
                const std::unordered_set<int> *preferred_target_hubs) -> WitnessSupport {
                std::vector<int> pref_hubs_sorted;
                if (preferred_target_hubs && !preferred_target_hubs->empty()) {
                    pref_hubs_sorted.assign(preferred_target_hubs->begin(), preferred_target_hubs->end());
                    std::sort(pref_hubs_sorted.begin(), pref_hubs_sorted.end());
                    pref_hubs_sorted.erase(std::unique(pref_hubs_sorted.begin(), pref_hubs_sorted.end()),
                                           pref_hubs_sorted.end());
                }
                uint64 pred_hash = pred_bins.hash64();
                uint64 pred_count = pred_bins.count();
                uint64 pref_hash = hash_pref_hubs(pref_hubs_sorted);
                uint64 memo_key = witness_memo_bucket_key(&ctx, wtable, pred_hash, pred_count, pref_hash);
                auto mit = witness_support_memo.find(memo_key);
                if (mit != witness_support_memo.end()) {
                    for (const WitnessMemoEntry &e : mit->second) {
                        if (e.ctx != &ctx || e.witness_table != wtable)
                            continue;
                        if (e.pred_hash != pred_hash || e.pred_count != pred_count)
                            continue;
                        if (e.pref_hubs_sorted != pref_hubs_sorted)
                            continue;
                        if (!e.pred_bins.equals(pred_bins))
                            continue;
                        witness_memo_hits++;
                        return e.ws;
                    }
                }
                witness_memo_misses++;

                WitnessSupport ws;
                if (ctx.any_empty || !pred_bins.any())
                    return ws;

                auto wit_inc_it = incidences.find(wtable);
                auto tgt_inc_it = incidences.find(target);
                if (wit_inc_it == incidences.end() || wit_inc_it->second.empty() ||
                    tgt_inc_it == incidences.end() || tgt_inc_it->second.empty()) {
                    ws.use_global = true;
                    ws.global_value = pred_bins.any();
                    return ws;
                }

                bool connected = table_connected_to_target_in_ctx(wtable, ctx);
                if (!connected) {
                    ws.use_global = true;
                    ws.global_value = pred_bins.any();
                    return ws;
                }

                auto wcat_it = table_bin_catalogs.find(wtable);
                if (wcat_it == table_bin_catalogs.end()) {
                    ws.use_global = true;
                    ws.global_value = pred_bins.any();
                    return ws;
                }
                const TableBinCatalog *wcatp = wcat_it->second;
                if (!wcatp)
                    return ws;
                const TableBinCatalog &wcat = *wcatp;

                std::vector<DenseBits> seed_base;
                std::vector<DenseBits> hub_support;
                std::vector<uint8_t> is_seed(hubs.size(), 0u);
                seed_base.resize(hubs.size());
                hub_support.resize(hubs.size());
                for (size_t hi = 0; hi < hubs.size(); hi++) {
                    seed_base[hi].reset(hubs[hi].ntok);
                    seed_base[hi].clear_all();
                    hub_support[hi].reset(hubs[hi].ntok);
                    hub_support[hi].clear_all();
                }

                for (const Inc &inc : wit_inc_it->second) {
                    if (!inc.tok || inc.hub_idx < 0 || (size_t)inc.hub_idx >= hubs.size())
                        continue;
                    if ((size_t)inc.hub_idx >= ctx.hub_active.size() || !ctx.hub_active[(size_t)inc.hub_idx])
                        continue;
                    auto hpit = wcat.hub_pos.find(inc.hub_idx);
                    if (hpit == wcat.hub_pos.end())
                        continue;
                    uint32 hub_pos = hpit->second;
                    const Hub &h = hubs[(size_t)inc.hub_idx];
                    DenseBits &seed = seed_base[(size_t)inc.hub_idx];
                    pred_bins.for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= wcat.bins.size())
                            return;
                        const TableBinEntry &bin = wcat.bins[(size_t)bi];
                        if ((size_t)hub_pos >= bin.hub_vals.size())
                            return;
                        int32 tv = bin.hub_vals[(size_t)hub_pos];
                        if (tv < 0 || (uint32)tv >= h.ntok)
                            return;
                        if (ctx.dom[(size_t)inc.hub_idx].test((uint32)tv))
                            seed.set((uint32)tv);
                    });
                    if (seed.any()) {
                        is_seed[(size_t)inc.hub_idx] = 1u;
                        hub_support[(size_t)inc.hub_idx] = seed;
                    }
                }

                bool any_seed = false;
                for (size_t hi = 0; hi < hubs.size(); hi++) {
                    if (is_seed[hi]) {
                        any_seed = true;
                        break;
                    }
                }
                if (!any_seed)
                    return ws;

                // Trim witness propagation to relevant directed region:
                // hubs reachable from seeds and able to reach preferred target hubs.
                std::vector<uint8_t> needed_hubs;
                bool restrict_to_needed = false;
                // Disabled by default: aggressive trimming can over-prune valid
                // witness paths and cause false negatives.
                static constexpr bool kEnableWitnessNeededTrim = false;
                if (kEnableWitnessNeededTrim && preferred_target_hubs && !preferred_target_hubs->empty()) {
                    std::vector<uint8_t> reach_from_seed(hubs.size(), 0u);
                    std::vector<uint8_t> reach_to_pref(hubs.size(), 0u);
                    std::deque<int> q;

                    for (size_t hi = 0; hi < hubs.size(); hi++) {
                        if (!is_seed[hi])
                            continue;
                        reach_from_seed[hi] = 1u;
                        q.push_back((int)hi);
                    }
                    while (!q.empty()) {
                        int h = q.front();
                        q.pop_front();
                        if (h < 0 || (size_t)h >= ctx.out_arc_ids.size())
                            continue;
                        for (int ai : ctx.out_arc_ids[(size_t)h]) {
                            if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                                continue;
                            int to = ctx.arc_adjs[(size_t)ai].to_hub;
                            if (to < 0 || (size_t)to >= hubs.size())
                                continue;
                            if ((size_t)to >= ctx.hub_active.size() || !ctx.hub_active[(size_t)to])
                                continue;
                            if (reach_from_seed[(size_t)to])
                                continue;
                            reach_from_seed[(size_t)to] = 1u;
                            q.push_back(to);
                        }
                    }

                    for (int ph : *preferred_target_hubs) {
                        if (ph < 0 || (size_t)ph >= hubs.size())
                            continue;
                        if ((size_t)ph >= ctx.hub_active.size() || !ctx.hub_active[(size_t)ph])
                            continue;
                        if (!reach_to_pref[(size_t)ph]) {
                            reach_to_pref[(size_t)ph] = 1u;
                            q.push_back(ph);
                        }
                    }
                    while (!q.empty()) {
                        int h = q.front();
                        q.pop_front();
                        if (h < 0 || (size_t)h >= ctx.in_arc_ids.size())
                            continue;
                        for (int ai : ctx.in_arc_ids[(size_t)h]) {
                            if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                                continue;
                            int from = ctx.arc_adjs[(size_t)ai].from_hub;
                            if (from < 0 || (size_t)from >= hubs.size())
                                continue;
                            if ((size_t)from >= ctx.hub_active.size() || !ctx.hub_active[(size_t)from])
                                continue;
                            if (reach_to_pref[(size_t)from])
                                continue;
                            reach_to_pref[(size_t)from] = 1u;
                            q.push_back(from);
                        }
                    }

                    needed_hubs.assign(hubs.size(), 0u);
                    for (size_t hi = 0; hi < hubs.size(); hi++) {
                        if (reach_from_seed[hi] && reach_to_pref[hi])
                            needed_hubs[hi] = 1u;
                    }
                    restrict_to_needed = true;

                    bool any_needed_seed = false;
                    for (size_t hi = 0; hi < hubs.size(); hi++) {
                        if (!is_seed[hi])
                            continue;
                        if (needed_hubs[hi]) {
                            any_needed_seed = true;
                            continue;
                        }
                        is_seed[hi] = 0u;
                        seed_base[hi].clear_all();
                        hub_support[hi].clear_all();
                    }
                    if (!any_needed_seed)
                        return ws;
                }

                auto pair_ok = [&](int from_hub, int to_hub, int32 from_tok, int32 to_tok) -> bool {
                    auto dit = ctx.arc_ids_by_dir.find(arc_dir_key(from_hub, to_hub));
                    if (dit == ctx.arc_ids_by_dir.end())
                        return true;
                    for (int ai : dit->second) {
                        if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                            continue;
                        if (!ctx.arc_adjs[(size_t)ai].has_pair(from_tok, to_tok))
                            return false;
                    }
                    return true;
                };

                auto run_exact_scc_support = [&](int scc_id) -> bool {
                    if (scc_id < 0 || (size_t)scc_id >= ctx.sccs.size())
                        return false;
                    const std::vector<int> &comp = ctx.sccs[(size_t)scc_id];
                    if (comp.size() < 2u)
                        return false;

                    bool has_constraint = false;
                    for (int h : comp) {
                        if (h < 0 || (size_t)h >= hubs.size())
                            continue;
                        if (is_seed[(size_t)h] || hub_support[(size_t)h].any()) {
                            has_constraint = true;
                            break;
                        }
                    }
                    if (!has_constraint)
                        return true;

                    std::vector<int> order = comp;
                    std::vector<std::vector<int32>> cand(hubs.size());
                    std::vector<uint8_t> constrained(hubs.size(), 0u);
                    for (int h : order) {
                        DenseBits allow = ctx.dom[(size_t)h];
                        if (is_seed[(size_t)h]) {
                            allow.bit_and(seed_base[(size_t)h]);
                            constrained[(size_t)h] = 1u;
                        } else if (hub_support[(size_t)h].any()) {
                            allow.bit_and(hub_support[(size_t)h]);
                            constrained[(size_t)h] = 1u;
                        }
                        allow.for_each_set([&](uint32 tok) {
                            cand[(size_t)h].push_back((int32)tok);
                        });
                    }

                    std::sort(order.begin(), order.end(), [&](int a, int b) {
                        return cand[(size_t)a].size() < cand[(size_t)b].size();
                    });

                    bool no_solution = false;
                    for (int h : order) {
                        if (cand[(size_t)h].empty()) {
                            no_solution = true;
                            break;
                        }
                    }
                    if (no_solution) {
                        for (int h : order)
                            hub_support[(size_t)h].clear_all();
                        return true;
                    }

                    auto constrained_image = [&](int from_h, int to_h, const DenseBits &from_dom, DenseBits *out) {
                        if (!out)
                            return;
                        out->reset(ctx.dom[(size_t)to_h].nbits());
                        out->fill_all();
                        auto dit = ctx.arc_ids_by_dir.find(arc_dir_key(from_h, to_h));
                        if (dit == ctx.arc_ids_by_dir.end())
                            return;
                        bool any_arc = false;
                        for (int ai : dit->second) {
                            if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                                continue;
                            any_arc = true;
                            DenseBits img(ctx.dom[(size_t)to_h].nbits());
                            img.clear_all();
                            ctx.arc_adjs[(size_t)ai].image_from_domain(from_dom, &img);
                            out->bit_and(img);
                        }
                        if (!any_arc)
                            out->fill_all();
                    };

                    if (order.size() == 2u) {
                        int hA = order[0];
                        int hB = order[1];
                        DenseBits candA(ctx.dom[(size_t)hA].nbits());
                        DenseBits candB(ctx.dom[(size_t)hB].nbits());
                        candA.clear_all();
                        candB.clear_all();
                        for (int32 t : cand[(size_t)hA]) candA.set((uint32)t);
                        for (int32 t : cand[(size_t)hB]) candB.set((uint32)t);

                        DenseBits suppA = candA;
                        DenseBits suppB = candB;
                        for (int iter = 0; iter < 64; iter++) {
                            DenseBits imgB(ctx.dom[(size_t)hB].nbits());
                            constrained_image(hA, hB, suppA, &imgB);
                            imgB.bit_and(candB);

                            DenseBits imgA(ctx.dom[(size_t)hA].nbits());
                            constrained_image(hB, hA, imgB, &imgA);
                            imgA.bit_and(candA);

                            bool chA = suppA.intersect_with_changed(imgA);
                            bool chB = suppB.intersect_with_changed(imgB);
                            if (!chA && !chB)
                                break;
                            if (!suppA.any() || !suppB.any())
                                break;
                        }

                        for (int h : order) {
                            const DenseBits &sup = (h == hA) ? suppA : suppB;
                            DenseBits next(hubs[(size_t)h].ntok);
                            next.clear_all();
                            if (is_seed[(size_t)h]) {
                                next = sup;
                                next.bit_and(seed_base[(size_t)h]);
                            } else if (constrained[(size_t)h]) {
                                next = hub_support[(size_t)h];
                                next.bit_and(sup);
                            } else {
                                next = sup;
                            }
                            hub_support[(size_t)h] = std::move(next);
                        }
                        return true;
                    }

                    std::vector<DenseBits> supported(hubs.size());
                    for (int h : order) {
                        supported[(size_t)h].reset(hubs[(size_t)h].ntok);
                        supported[(size_t)h].clear_all();
                    }

                    auto exists_compat = [&](int h1, int32 tok1, int h2) -> bool {
                        const std::vector<int32> &c2 = cand[(size_t)h2];
                        for (int32 tok2 : c2) {
                            if (pair_ok(h1, h2, tok1, tok2) && pair_ok(h2, h1, tok2, tok1))
                                return true;
                        }
                        return false;
                    };

                    std::vector<int32> assign(hubs.size(), -1);
                    bool budget_exceeded = false;
                    uint64 visited = 0;
                    const uint64 kNodeBudget = 5000000ULL;
                    std::function<void(size_t)> dfs = [&](size_t depth) {
                        if (budget_exceeded)
                            return;
                        if (depth == order.size()) {
                            for (int h : order) {
                                int32 tv = assign[(size_t)h];
                                if (tv >= 0)
                                    supported[(size_t)h].set((uint32)tv);
                            }
                            return;
                        }
                        int h = order[depth];
                        for (int32 tok : cand[(size_t)h]) {
                            visited++;
                            if (visited > kNodeBudget) {
                                budget_exceeded = true;
                                return;
                            }
                            bool ok = true;
                            for (size_t i = 0; i < depth && ok; i++) {
                                int oh = order[i];
                                int32 ov = assign[(size_t)oh];
                                if (ov < 0)
                                    continue;
                                if (!pair_ok(h, oh, tok, ov) || !pair_ok(oh, h, ov, tok))
                                    ok = false;
                            }
                            if (!ok)
                                continue;
                            for (size_t i = depth + 1; i < order.size() && ok; i++) {
                                int uh = order[i];
                                if (!exists_compat(h, tok, uh))
                                    ok = false;
                            }
                            if (!ok)
                                continue;
                            assign[(size_t)h] = tok;
                            dfs(depth + 1u);
                            assign[(size_t)h] = -1;
                            if (budget_exceeded)
                                return;
                        }
                    };
                    dfs(0u);

                    if (budget_exceeded) {
                        return false;
                    }

                    for (int h : order) {
                        DenseBits next(hubs[(size_t)h].ntok);
                        next.clear_all();
                        if (is_seed[(size_t)h]) {
                            next = supported[(size_t)h];
                            next.bit_and(seed_base[(size_t)h]);
                        } else if (constrained[(size_t)h]) {
                            next = hub_support[(size_t)h];
                            next.bit_and(supported[(size_t)h]);
                        } else {
                            next = supported[(size_t)h];
                        }
                        hub_support[(size_t)h] = std::move(next);
                    }
                    return true;
                };

                int nscc = (int)ctx.sccs.size();
                std::vector<std::vector<int>> scc_out((size_t)nscc);
                std::vector<int> indeg((size_t)nscc, 0);
                std::unordered_set<uint64> edge_seen;
                edge_seen.reserve((size_t)ctx.arc_adjs.size() * 2u + 1u);
                for (const ArcAdj &adj : ctx.arc_adjs) {
                    if (adj.from_hub < 0 || adj.to_hub < 0)
                        continue;
                    if ((size_t)adj.from_hub >= ctx.hub_scc.size() || (size_t)adj.to_hub >= ctx.hub_scc.size())
                        continue;
                    int sf = ctx.hub_scc[(size_t)adj.from_hub];
                    int st = ctx.hub_scc[(size_t)adj.to_hub];
                    if (sf < 0 || st < 0 || sf == st)
                        continue;
                    uint64 ek = ((uint64)(uint32)sf << 32) | (uint64)(uint32)st;
                    if (!edge_seen.insert(ek).second)
                        continue;
                    scc_out[(size_t)sf].push_back(st);
                    indeg[(size_t)st]++;
                }

                std::deque<int> topo_q;
                for (int i = 0; i < nscc; i++) {
                    if (indeg[(size_t)i] == 0)
                        topo_q.push_back(i);
                }
                std::vector<int> topo;
                topo.reserve((size_t)nscc);
                while (!topo_q.empty()) {
                    int s = topo_q.front();
                    topo_q.pop_front();
                    topo.push_back(s);
                    for (int t : scc_out[(size_t)s]) {
                        if (--indeg[(size_t)t] == 0)
                            topo_q.push_back(t);
                    }
                }
                if ((int)topo.size() != nscc) {
                    topo.clear();
                    for (int i = 0; i < nscc; i++)
                        topo.push_back(i);
                }

                for (int sid : topo) {
                    if (sid < 0 || (size_t)sid >= ctx.sccs.size())
                        continue;
                    const std::vector<int> &comp = ctx.sccs[(size_t)sid];
                    bool cyclic_comp = false;
                    if (comp.size() >= 2u) {
                        std::unordered_set<uint64> undirected_edges;
                        undirected_edges.reserve(comp.size() * 4u + 1u);
                        std::unordered_set<int> comp_set(comp.begin(), comp.end());
                        for (int h : comp) {
                            if (h < 0 || (size_t)h >= ctx.undir_adj.size())
                                continue;
                            for (int nh : ctx.undir_adj[(size_t)h]) {
                                if (comp_set.find(nh) == comp_set.end())
                                    continue;
                                uint32 a = (uint32)std::min(h, nh);
                                uint32 b = (uint32)std::max(h, nh);
                                undirected_edges.insert(((uint64)a << 32) | (uint64)b);
                            }
                        }
                        if (comp.size() == 2u) {
                            // 2-node SCC is a cycle when the pair is connected.
                            cyclic_comp = !undirected_edges.empty();
                        } else {
                            cyclic_comp = undirected_edges.size() >= comp.size();
                        }
                    }
                    bool active_comp = false;
                    for (int h : comp) {
                        if (h >= 0 && (size_t)h < hub_support.size() &&
                            (!restrict_to_needed || ((size_t)h < needed_hubs.size() && needed_hubs[(size_t)h])) &&
                            hub_support[(size_t)h].any()) {
                            active_comp = true;
                            break;
                        }
                    }
                    if (!active_comp)
                        continue;

                    bool exact_refined = true;
                    if (cyclic_comp)
                        exact_refined = run_exact_scc_support(sid);

                    // Propagate witness support to fixpoint so multi-hop paths inside an SCC
                    // do not depend on component iteration order.
                    std::deque<int> qh;
                    std::vector<uint8_t> inq(hubs.size(), 0u);
                    for (int h : comp) {
                        if (h < 0 || (size_t)h >= hub_support.size())
                            continue;
                        if (hub_support[(size_t)h].any()) {
                            qh.push_back(h);
                            inq[(size_t)h] = 1u;
                        }
                    }
                    while (!qh.empty()) {
                        int h = qh.front();
                        qh.pop_front();
                        if (h < 0 || (size_t)h >= hub_support.size())
                            continue;
                        if (restrict_to_needed &&
                            ((size_t)h >= needed_hubs.size() || !needed_hubs[(size_t)h]))
                            continue;
                        inq[(size_t)h] = 0u;
                        const DenseBits &from = hub_support[(size_t)h];
                        if (!from.any())
                            continue;
                        int from_scc = ((size_t)h < ctx.hub_scc.size()) ? ctx.hub_scc[(size_t)h] : -1;
                        for (int ai : ctx.out_arc_ids[(size_t)h]) {
                            if (ai < 0 || (size_t)ai >= ctx.arc_adjs.size())
                                continue;
                            const ArcAdj &adj = ctx.arc_adjs[(size_t)ai];
                            int to_h = adj.to_hub;
                            if (to_h < 0 || (size_t)to_h >= hubs.size())
                                continue;
                            if (restrict_to_needed &&
                                ((size_t)to_h >= needed_hubs.size() || !needed_hubs[(size_t)to_h]))
                                continue;
                            int to_scc = ((size_t)to_h < ctx.hub_scc.size()) ? ctx.hub_scc[(size_t)to_h] : -1;
                            // Cyclic SCCs are handled exactly above. Do not re-expand support
                            // within the same SCC using monotone union propagation.
                            if (cyclic_comp && exact_refined && from_scc >= 0 && from_scc == to_scc)
                                continue;
                            DenseBits img(ctx.dom[(size_t)to_h].nbits());
                            img.clear_all();
                            adj.image_from_domain(from, &img);
                            img.bit_and(ctx.dom[(size_t)to_h]);
                            if ((size_t)to_h < is_seed.size() && is_seed[(size_t)to_h]) {
                                // Seed hubs are fixed by predicate bins and must not expand.
                                img.bit_and(seed_base[(size_t)to_h]);
                                continue;
                            }
                            uint64 before = hub_support[(size_t)to_h].count();
                            hub_support[(size_t)to_h].bit_or(img);
                            if (hub_support[(size_t)to_h].count() > before &&
                                !inq[(size_t)to_h]) {
                                qh.push_back(to_h);
                                inq[(size_t)to_h] = 1u;
                            }
                        }
                    }
                }

                for (const Inc &inc : tgt_inc_it->second) {
                    if (!inc.tok || inc.hub_idx < 0 || (size_t)inc.hub_idx >= hubs.size())
                        continue;
                    if ((size_t)inc.hub_idx >= ctx.hub_active.size() || !ctx.hub_active[(size_t)inc.hub_idx])
                        continue;
                    if (restrict_to_needed &&
                        ((size_t)inc.hub_idx >= needed_hubs.size() || !needed_hubs[(size_t)inc.hub_idx]))
                        continue;
                    if (preferred_target_hubs && !preferred_target_hubs->empty() &&
                        preferred_target_hubs->find(inc.hub_idx) == preferred_target_hubs->end())
                        continue;
                    if (!hub_support[(size_t)inc.hub_idx].any())
                        continue;
                    ws.target_refs.push_back(TargetHubRef{inc.hub_idx, inc.tok});
                    ws.target_supports.push_back(hub_support[(size_t)inc.hub_idx]);
                }
                if (ws.target_refs.empty()) {
                    ws.use_global = false;
                    ws.global_value = false;
                }
                WitnessMemoEntry me;
                me.ctx = &ctx;
                me.witness_table = wtable;
                me.pref_hubs_sorted = std::move(pref_hubs_sorted);
                me.pred_hash = pred_hash;
                me.pred_count = pred_count;
                me.pred_bins = pred_bins;
                me.ws = ws;
                witness_support_memo[memo_key].push_back(std::move(me));
                return ws;
            };

        auto preferred_target_hubs_for_atom = [&](const AtomInfo &a) -> std::unordered_set<int> {
            std::unordered_set<int> out;
            int atom_scope = a.scope_id;
            ScopePathCache &pc = scope_paths(atom_scope);
            auto add_from_table = [&](const std::string &tbl) {
                if (tbl.empty() || tbl == target)
                    return;
                if (pc.reachable.find(tbl) == pc.reachable.end())
                    return;
                std::string cur = tbl;
                while (cur != target) {
                    auto hit = pc.parent_hub.find(cur);
                    auto pit = pc.parent_table.find(cur);
                    if (hit == pc.parent_hub.end() || pit == pc.parent_table.end())
                        break;
                    if (pit->second == target)
                        out.insert(hit->second);
                    cur = pit->second;
                }
            };
            add_from_table(a.lhs.table);
            add_from_table(a.rhs.table);
            return out;
        };

        auto active_bins_for_table = [&](const ContextState &ctx, const std::string &table) -> const DenseBits * {
            auto it = ctx.active_bins_by_table.find(table);
            if (it == ctx.active_bins_by_table.end())
                return nullptr;
            return &it->second;
        };

            auto pred_bins_for_local_atom = [&](const AtomInfo &a, const ContextState &ctx, DenseBits *out) -> bool {
                if (!out || a.lhs.table.empty())
                    return false;
                auto cat_it = table_bin_catalogs.find(a.lhs.table);
                if (cat_it == table_bin_catalogs.end())
                    return false;
                const TableBinCatalog *catp = cat_it->second;
                if (!catp)
                    return false;
                auto act = active_bins_for_table(ctx, a.lhs.table);
                if (!act)
                    return false;
                auto sit = catp->local_sat_bins.find(a.atom_id);
                if (sit == catp->local_sat_bins.end())
                    return false;
                *out = *act;
                out->bit_and(sit->second);
                return true;
            };

        auto build_witness_support = [&](const AtomInfo &a, const ContextState &ctx) -> WitnessSupport {
            WitnessSupport ws;
            if (a.lhs.table.empty())
                return ws;
            DenseBits pred_bins;
            if (!pred_bins_for_local_atom(a, ctx, &pred_bins))
                return ws;
            std::unordered_set<int> pref = preferred_target_hubs_for_atom(a);
            return build_witness_support_from_bins(a.lhs.table, pred_bins, ctx, &pref);
        };
        auto table_reachable_in_scope = [&](const std::string &table, int scope_id) -> bool {
            if (table.empty())
                return false;
            if (table == target)
                return true;
            ScopePathCache &pc = scope_paths(scope_id);
            return pc.reachable.find(table) != pc.reachable.end();
        };

        auto merge_witness_support = [&](WitnessSupport *dst, const WitnessSupport &src) {
            if (!dst)
                return;
            if (dst->use_global && dst->global_value)
                return;
            if (src.use_global) {
                if (src.global_value) {
                    dst->use_global = true;
                    dst->global_value = true;
                    dst->target_refs.clear();
                    dst->target_supports.clear();
                }
                return;
            }
            if (src.target_refs.empty() || src.target_supports.empty())
                return;
            size_t nref = std::min(src.target_refs.size(), src.target_supports.size());
            for (size_t i = 0; i < nref; i++) {
                const TargetHubRef &sref = src.target_refs[i];
                const DenseBits &ssupp = src.target_supports[i];
                size_t pos = SIZE_MAX;
                for (size_t j = 0; j < dst->target_refs.size(); j++) {
                    if (j >= dst->target_supports.size())
                        break;
                    const TargetHubRef &dref = dst->target_refs[j];
                    if (dref.hub_idx == sref.hub_idx && dref.target_tok == sref.target_tok) {
                        pos = j;
                        break;
                    }
                }
                if (pos == SIZE_MAX) {
                    dst->target_refs.push_back(sref);
                    dst->target_supports.push_back(ssupp);
                } else {
                    dst->target_supports[pos].bit_or(ssupp);
                }
            }
        };

        auto t_witness0 = Clock::now();
        std::unordered_map<int, WitnessSupport> witness_support_by_atom;
        witness_support_by_atom.reserve(local_atoms.size() * 2u + 1u);
        for (const AtomInfo *ap : local_atoms) {
            if (!ap)
                continue;
            if (ap->lhs.table == target)
                continue;
            if (!(ap->kind == POLICY_ATOM_COL_CONST ||
                  (ap->kind == POLICY_ATOM_COL_COL && ap->lhs.table == ap->rhs.table)))
                continue;
            if (hubs.empty()) {
                WitnessSupport ws;
                ws.use_global = true;
                ws.global_value = false;
                auto cat_it = table_bin_catalogs.find(ap->lhs.table);
                if (cat_it != table_bin_catalogs.end()) {
                    const TableBinCatalog *catp = cat_it->second;
                    if (catp) {
                        auto sit = catp->local_sat_bins.find(ap->atom_id);
                        if (sit != catp->local_sat_bins.end())
                            ws.global_value = sit->second.any();
                    }
                }
                witness_support_by_atom.emplace(ap->atom_id, std::move(ws));
                continue;
            }
            if (!table_reachable_in_scope(ap->lhs.table, ap->scope_id)) {
                WitnessSupport ws;
                ws.use_global = true;
                ws.global_value = false;
                auto cat_it = table_bin_catalogs.find(ap->lhs.table);
                if (cat_it != table_bin_catalogs.end()) {
                    const TableBinCatalog *catp = cat_it->second;
                    if (catp) {
                        auto sit = catp->local_sat_bins.find(ap->atom_id);
                        if (sit != catp->local_sat_bins.end())
                            ws.global_value = sit->second.any();
                    }
                }
                witness_support_by_atom.emplace(ap->atom_id, std::move(ws));
                continue;
            }
            WitnessSupport agg;
            const std::vector<const ContextState *> &ctxs = contexts_for_atom(ap->atom_id);
            for (const ContextState *ctxp : ctxs) {
                if (!ctxp)
                    continue;
                WitnessSupport ws = build_witness_support(*ap, *ctxp);
                merge_witness_support(&agg, ws);
            }
            witness_support_by_atom.emplace(ap->atom_id, std::move(agg));
        }
        for (const AtomInfo *ap : join_atoms) {
            if (!ap)
                continue;
            if (ap->lhs.table == target || ap->rhs.table == target)
                continue;
            WitnessSupport agg;
            std::string dbg_anchor;
            const std::vector<const ContextState *> &ctxs = contexts_for_atom(ap->atom_id);
            for (const ContextState *ctxp : ctxs) {
                if (!ctxp)
                    continue;
                const ContextState &ctx = *ctxp;
                WitnessSupport ws;
                if (ctx.any_empty) {
                    ws.use_global = true;
                    ws.global_value = false;
                    merge_witness_support(&agg, ws);
                    continue;
                }
                bool lhs_conn = table_connected_to_target_in_ctx(ap->lhs.table, ctx);
                bool rhs_conn = table_connected_to_target_in_ctx(ap->rhs.table, ctx);
                if (!lhs_conn && !rhs_conn) {
                    auto hit = atom_to_hub.find(ap->atom_id);
                    bool nonempty = false;
                    if (hit != atom_to_hub.end() &&
                        hit->second >= 0 &&
                        (size_t)hit->second < ctx.hub_active.size() &&
                        ctx.hub_active[(size_t)hit->second] &&
                        (size_t)hit->second < ctx.dom.size()) {
                        nonempty = ctx.dom[(size_t)hit->second].any();
                    }
                    ws.use_global = true;
                    ws.global_value = nonempty;
                    merge_witness_support(&agg, ws);
                    continue;
                }
                const std::string &anchor = lhs_conn ? ap->lhs.table : ap->rhs.table;
                dbg_anchor = anchor;
                const DenseBits *anchor_bins = active_bins_for_table(ctx, anchor);
                if (!anchor_bins) {
                    ws.use_global = true;
                    ws.global_value = false;
                } else {
                    std::unordered_set<int> pref = preferred_target_hubs_for_atom(*ap);
                    ws = build_witness_support_from_bins(anchor, *anchor_bins, ctx, &pref);
                }
                merge_witness_support(&agg, ws);
            }
            WitnessSupport ws = std::move(agg);
            witness_support_by_atom[ap->atom_id] = std::move(ws);
        }
        prop_witness_ms_local += Ms(Clock::now() - t_witness0).count();

        struct CmpFeatData {
            bool enabled = false;
            bool global = false;
            bool global_value = false;
            int op = 0;
            int target_col_idx = -1;
            const std::vector<int32> *target_tok = nullptr;
            int group_hub_idx = -1;
            const std::vector<int32> *target_group_tok = nullptr;
            RankData rank;
            CmpSummary global_summary;
            std::unordered_map<int32, CmpSummary> by_group;
        };

        auto update_summary = [&](CmpSummary *s, int32 tok, int op, uint32 ntok, const RankData &rank) {
            if (!s)
                return;
            if (!s->any) {
                s->any = true;
                s->nonnull_count = 0;
                s->min_rank = std::numeric_limits<int32>::max();
                s->max_rank = std::numeric_limits<int32>::min();
                s->only_tok = -1;
                if (op == POLICY_OP_EQ)
                    s->support.assign(ntok, 0u);
            }
            s->nonnull_count++;
            if (s->nonnull_count == 1)
                s->only_tok = tok;
            int32 rk = rank_or_identity(rank, tok);
            if (rk < s->min_rank)
                s->min_rank = rk;
            if (rk > s->max_rank)
                s->max_rank = rk;
            if (op == POLICY_OP_EQ && (uint32)tok < ntok)
                s->support[(size_t)tok] = 1u;
        };

        auto t_cmp0 = Clock::now();
        std::unordered_map<int, CmpFeatData> cmp_feature_by_atom;
        cmp_feature_by_atom.reserve(cross_cmp_atoms.size() * 2u + 1u);
        auto atom_contexts_or_fallback = [&](int atom_id) -> std::vector<const ContextState *> {
            std::vector<const ContextState *> out;
            const std::vector<const ContextState *> &ctxs = contexts_for_atom(atom_id);
            if (!ctxs.empty()) {
                out.reserve(ctxs.size());
                for (const ContextState *c : ctxs) {
                    if (c)
                        out.push_back(c);
                }
            }
            if (out.empty()) {
                const ContextState &ctx0 = context_for_atom(atom_id);
                out.push_back(&ctx0);
            }
            return out;
        };
        auto token_upper_bound_from_bins = [&](const std::string &table, int col_idx) -> uint32 {
            auto cit = table_bin_catalogs.find(table);
            if (cit == table_bin_catalogs.end() || !cit->second)
                return 0u;
            const TableBinCatalog *cat = cit->second;
            auto ep = cat->extra_pos.find(col_idx);
            if (ep == cat->extra_pos.end())
                return 0u;
            uint32 pos = ep->second;
            int32 mx = -1;
            for (const TableBinEntry &bin : cat->bins) {
                if ((size_t)pos >= bin.extra_vals.size())
                    continue;
                int32 tok = bin.extra_vals[(size_t)pos];
                if (tok > mx)
                    mx = tok;
            }
            return (mx >= 0) ? ((uint32)mx + 1u) : 0u;
        };
        auto choose_cmp_group_hub =
            [&](const AtomInfo &a,
                const std::string &witness,
                const std::vector<const ContextState *> &ctx_list) -> int {
                std::vector<int> cands;
                cands.reserve(8);
                for (size_t hi = 0; hi < hubs.size(); hi++) {
                    const Hub &h = hubs[hi];
                    bool pair_match = ((h.left_table == target && h.right_table == witness) ||
                                       (h.left_table == witness && h.right_table == target));
                    if (!pair_match)
                        continue;
                    if (a.scope_id >= 0 && !hub_matches_scope((int)hi, a.scope_id))
                        continue;
                    cands.push_back((int)hi);
                }
                if (cands.empty())
                    return -1;
                if (cands.size() == 1u)
                    return cands[0];

                int best_h = -1;
                int best_score = -1;
                bool tie = false;
                for (int hid : cands) {
                    int score = 0;
                    for (const ContextState *ctxp : ctx_list) {
                        if (!ctxp)
                            continue;
                        if ((size_t)hid < ctxp->hub_active.size() && ctxp->hub_active[(size_t)hid] != 0u)
                            score++;
                    }
                    if (score > best_score) {
                        best_score = score;
                        best_h = hid;
                        tie = false;
                    } else if (score == best_score) {
                        tie = true;
                    }
                }
                if (!tie && best_score > 0)
                    return best_h;
                return -1;
            };
        for (const AtomInfo *ap : cross_cmp_atoms) {
            const AtomInfo &a = *ap;
            CmpFeatData cf;
            cf.enabled = true;
            std::vector<const ContextState *> ctx_list = atom_contexts_or_fallback(a.atom_id);
            bool target_on_left = (a.lhs.table == target);
            bool target_on_right = (a.rhs.table == target);
            if (!target_on_left && !target_on_right) {
                int li = require_col_idx(a.lhs.table, a.lhs.col);
                int ri = require_col_idx(a.rhs.table, a.rhs.col);
                uint32 ntok = (a.join_class_id >= 0) ? domain_token_count(a.join_class_id) : 0u;
                if (ntok == 0) {
                    ntok = std::max(token_upper_bound_from_bins(a.lhs.table, li),
                                    token_upper_bound_from_bins(a.rhs.table, ri));
                }
                if (a.join_class_id >= 0)
                    (void)load_rank(a.join_class_id, &cf.rank);
                WitnessSupport cmp_ws_agg;
                for (const ContextState *ctxp : ctx_list) {
                    if (!ctxp)
                        continue;
                    const ContextState &ctx = *ctxp;
                    if (ctx.any_empty)
                        continue;
                    bool lhs_conn = table_connected_to_target_in_ctx(a.lhs.table, ctx);
                    bool rhs_conn = table_connected_to_target_in_ctx(a.rhs.table, ctx);

                    if (!lhs_conn && !rhs_conn) {
                        WitnessSupport ws;
                        ws.use_global = true;
                        ws.global_value = false;
                        const DenseBits *rhs_bins = active_bins_for_table(ctx, a.rhs.table);
                        const DenseBits *lhs_bins = active_bins_for_table(ctx, a.lhs.table);
                        auto rcat_it = table_bin_catalogs.find(a.rhs.table);
                        auto lcat_it = table_bin_catalogs.find(a.lhs.table);
                        if (rhs_bins && lhs_bins &&
                            rcat_it != table_bin_catalogs.end() && rcat_it->second &&
                            lcat_it != table_bin_catalogs.end() && lcat_it->second) {
                            const TableBinCatalog *rcat = rcat_it->second;
                            const TableBinCatalog *lcat = lcat_it->second;
                            auto rpos_it = rcat->extra_pos.find(ri);
                            auto lpos_it = lcat->extra_pos.find(li);
                            if (rpos_it != rcat->extra_pos.end() &&
                                lpos_it != lcat->extra_pos.end()) {
                                uint32 rpos = rpos_it->second;
                                uint32 lpos = lpos_it->second;
                                CmpSummary rs;
                                rs.any = false;
                                rhs_bins->for_each_set([&](uint32 bi) {
                                    if ((size_t)bi >= rcat->bins.size())
                                        return;
                                    const TableBinEntry &bin = rcat->bins[(size_t)bi];
                                    if ((size_t)rpos >= bin.extra_vals.size())
                                        return;
                                    int32 tv = bin.extra_vals[(size_t)rpos];
                                    if (tv < 0 || (uint32)tv >= ntok)
                                        return;
                                    update_summary(&rs, tv, a.op, ntok, cf.rank);
                                });
                                if (rs.any) {
                                    lhs_bins->for_each_set([&](uint32 bi) {
                                        if (ws.global_value)
                                            return;
                                        if ((size_t)bi >= lcat->bins.size())
                                            return;
                                        const TableBinEntry &bin = lcat->bins[(size_t)bi];
                                        if ((size_t)lpos >= bin.extra_vals.size())
                                            return;
                                        int32 tv = bin.extra_vals[(size_t)lpos];
                                        if (tv < 0 || (uint32)tv >= ntok)
                                            return;
                                        int32 rk = rank_or_identity(cf.rank, tv);
                                        if (tok_vs_summary(a.op, tv, rk, rs))
                                            ws.global_value = true;
                                    });
                                }
                            }
                        }
                        merge_witness_support(&cmp_ws_agg, ws);
                        continue;
                    }

                    bool anchor_left = lhs_conn || !rhs_conn;
                    const std::string &anchor_table = anchor_left ? a.lhs.table : a.rhs.table;
                    const std::string &other_table = anchor_left ? a.rhs.table : a.lhs.table;
                    int anchor_col_idx = anchor_left ? li : ri;
                    int other_col_idx = anchor_left ? ri : li;
                    int anchor_op = anchor_left ? a.op : inverse_op(a.op);

                    const DenseBits *anchor_bins = active_bins_for_table(ctx, anchor_table);
                    const DenseBits *other_bins = active_bins_for_table(ctx, other_table);
                    auto acat_it = table_bin_catalogs.find(anchor_table);
                    auto ocat_it = table_bin_catalogs.find(other_table);
                    if (!anchor_bins || !other_bins ||
                        acat_it == table_bin_catalogs.end() || !acat_it->second ||
                        ocat_it == table_bin_catalogs.end() || !ocat_it->second) {
                        continue;
                    }
                    const TableBinCatalog *acat = acat_it->second;
                    const TableBinCatalog *ocat = ocat_it->second;
                    auto apos_it = acat->extra_pos.find(anchor_col_idx);
                    auto opos_it = ocat->extra_pos.find(other_col_idx);
                    if (apos_it == acat->extra_pos.end() ||
                        opos_it == ocat->extra_pos.end()) {
                        continue;
                    }
                    uint32 apos = apos_it->second;
                    uint32 opos = opos_it->second;

                    CmpSummary other_summary;
                    other_summary.any = false;
                    other_bins->for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= ocat->bins.size())
                            return;
                        const TableBinEntry &bin = ocat->bins[(size_t)bi];
                        if ((size_t)opos >= bin.extra_vals.size())
                            return;
                        int32 tv = bin.extra_vals[(size_t)opos];
                        if (tv < 0 || (uint32)tv >= ntok)
                            return;
                        update_summary(&other_summary, tv, anchor_op, ntok, cf.rank);
                    });

                    DenseBits cmp_bins(anchor_bins->nbits());
                    cmp_bins.clear_all();
                    if (other_summary.any) {
                        anchor_bins->for_each_set([&](uint32 bi) {
                            if ((size_t)bi >= acat->bins.size())
                                return;
                            const TableBinEntry &bin = acat->bins[(size_t)bi];
                            if ((size_t)apos >= bin.extra_vals.size())
                                return;
                            int32 tv = bin.extra_vals[(size_t)apos];
                            if (tv < 0 || (uint32)tv >= ntok)
                                return;
                            int32 rk = rank_or_identity(cf.rank, tv);
                            if (tok_vs_summary(anchor_op, tv, rk, other_summary))
                                cmp_bins.set(bi);
                        });
                    }
                    WitnessSupport ws = build_witness_support_from_bins(anchor_table, cmp_bins, ctx, nullptr);
                    merge_witness_support(&cmp_ws_agg, ws);
                }
                witness_support_by_atom[a.atom_id] = std::move(cmp_ws_agg);
                cf.enabled = false;
                cmp_feature_by_atom[a.atom_id] = std::move(cf);
                continue;
            }

            const std::string witness = target_on_left ? a.rhs.table : a.lhs.table;
            int target_col_idx = require_col_idx(target, target_on_left ? a.lhs.col : a.rhs.col);
            int witness_col_idx = require_col_idx(witness, target_on_left ? a.rhs.col : a.lhs.col);
            const std::vector<int32> *target_tok = decode_col_tokens(target, target_col_idx);

            uint32 ntok = (a.join_class_id >= 0) ? domain_token_count(a.join_class_id) : 0u;
            if (ntok == 0) {
                ntok = std::max(token_upper_bound_from_bins(target, target_col_idx),
                                token_upper_bound_from_bins(witness, witness_col_idx));
            }

            int eff_op = target_on_left ? a.op : inverse_op(a.op);
            cf.op = eff_op;
            cf.target_col_idx = target_col_idx;
            cf.target_tok = target_tok;
            if (a.join_class_id >= 0)
                (void)load_rank(a.join_class_id, &cf.rank);

            cf.group_hub_idx = choose_cmp_group_hub(a, witness, ctx_list);

            const std::vector<int32> *w_group = nullptr;
            if (cf.group_hub_idx >= 0) {
                const Hub &gh = hubs[(size_t)cf.group_hub_idx];
                if (gh.left_table == target) {
                    cf.target_group_tok = gh.left_tok;
                    w_group = gh.right_tok;
                } else {
                    cf.target_group_tok = gh.right_tok;
                    w_group = gh.left_tok;
                }
            }

            for (const ContextState *ctxp : ctx_list) {
                if (!ctxp)
                    continue;
                const ContextState &ctx = *ctxp;
                if (ctx.any_empty)
                    continue;
                const DenseBits *wit_bins = active_bins_for_table(ctx, witness);
                auto wcat_it = table_bin_catalogs.find(witness);
                if (!wit_bins || wcat_it == table_bin_catalogs.end() || !wcat_it->second)
                    continue;
                const TableBinCatalog *wcat = wcat_it->second;
                auto wpos_it = wcat->extra_pos.find(witness_col_idx);
                if (wpos_it == wcat->extra_pos.end())
                    continue;
                uint32 wpos = wpos_it->second;
                auto append_global_summary = [&]() {
                    wit_bins->for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= wcat->bins.size())
                            return;
                        const TableBinEntry &bin = wcat->bins[(size_t)bi];
                        if ((size_t)wpos >= bin.extra_vals.size())
                            return;
                        int32 v = bin.extra_vals[(size_t)wpos];
                        if (v < 0 || (uint32)v >= ntok)
                            return;
                        update_summary(&cf.global_summary, v, eff_op, ntok, cf.rank);
                    });
                };
                bool group_active = (cf.group_hub_idx >= 0 &&
                                     (size_t)cf.group_hub_idx < ctx.hub_active.size() &&
                                     ctx.hub_active[(size_t)cf.group_hub_idx] != 0u);
                if (cf.group_hub_idx >= 0 && w_group && group_active) {
                    auto gpos_it = wcat->hub_pos.find(cf.group_hub_idx);
                    if (gpos_it == wcat->hub_pos.end()) {
                        append_global_summary();
                        continue;
                    }
                    uint32 gpos = gpos_it->second;
                    wit_bins->for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= wcat->bins.size())
                            return;
                        const TableBinEntry &bin = wcat->bins[(size_t)bi];
                        if ((size_t)gpos >= bin.hub_vals.size() || (size_t)wpos >= bin.extra_vals.size())
                            return;
                        int32 g = bin.hub_vals[(size_t)gpos];
                        int32 v = bin.extra_vals[(size_t)wpos];
                        if (g < 0 || v < 0 || (uint32)v >= ntok)
                            return;
                        if (group_active &&
                            ((uint32)g >= ctx.dom[(size_t)cf.group_hub_idx].nbits() ||
                             !ctx.dom[(size_t)cf.group_hub_idx].test((uint32)g)))
                            return;
                        update_summary(&cf.by_group[g], v, eff_op, ntok, cf.rank);
                    });
                } else {
                    append_global_summary();
                }
            }
            cmp_feature_by_atom[a.atom_id] = std::move(cf);
        }
        prop_cmp_ms_local += Ms(Clock::now() - t_cmp0).count();

        auto t_prop1 = Clock::now();

        enum FeatureKind {
            FEAT_GLOBAL_CONST = 0,
            FEAT_TARGET_LOCAL_MASK = 1,
            FEAT_TARGET_HUB_MEMBERSHIP = 2,
            FEAT_TARGET_CMP = 3,
            FEAT_TARGET_WITNESS_LOCAL = 4
        };

        struct Feature {
            int atom_id = 0;
            int kind = FEAT_GLOBAL_CONST;
            bool global_value = false;
            const DenseBits *local_mask = nullptr;
            const DenseBits *hub_dom = nullptr;
            const std::vector<int32> *target_hub_tok = nullptr;
            const CmpFeatData *cmp = nullptr;
            const WitnessSupport *witness = nullptr;
        };

        std::unordered_map<uint64, DenseBits> hub_dom_union_cache;
        hub_dom_union_cache.reserve(feature_atom_ids.size() * 2u + 1u);
        auto hub_dom_key = [](int atom_id, int hub_id) -> uint64 {
            return ((uint64)(uint32)atom_id << 32) | (uint64)(uint32)hub_id;
        };
        auto hub_dom_for_atom = [&](int atom_id, int hid) -> const DenseBits * {
            if (hid < 0 || (size_t)hid >= hubs.size())
                return nullptr;
            uint64 k = hub_dom_key(atom_id, hid);
            auto it = hub_dom_union_cache.find(k);
            if (it != hub_dom_union_cache.end())
                return &it->second;

            bool any = false;
            DenseBits dom(hubs[(size_t)hid].ntok);
            dom.clear_all();
            const std::vector<const ContextState *> &ctxs = contexts_for_atom(atom_id);
            for (const ContextState *ctxp : ctxs) {
                if (!ctxp)
                    continue;
                const ContextState &ctx = *ctxp;
                if ((size_t)hid >= ctx.hub_active.size() || !ctx.hub_active[(size_t)hid])
                    continue;
                if ((size_t)hid >= ctx.dom.size())
                    continue;
                if (!any) {
                    dom = ctx.dom[(size_t)hid];
                    any = true;
                } else {
                    dom.bit_or(ctx.dom[(size_t)hid]);
                }
            }
            if (!any)
                return nullptr;
            auto ins = hub_dom_union_cache.emplace(k, std::move(dom));
            return &ins.first->second;
        };

        std::vector<Feature> features;
        features.reserve(feature_atom_ids.size());
        for (int aid : feature_atom_ids) {
            Feature f;
            f.atom_id = aid;
            int rep_aid = aid;
            auto arit = atom_eval_rep.find(aid);
            if (arit != atom_eval_rep.end() && arit->second > 0)
                rep_aid = arit->second;
            auto ait = atom_by_id_.find(rep_aid);
            if (ait == atom_by_id_.end()) {
                f.kind = FEAT_GLOBAL_CONST;
                f.global_value = false;
                features.push_back(f);
                continue;
            }
            const AtomInfo &a = ait->second;
            if (a.kind == POLICY_ATOM_COL_CONST ||
                (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table)) {
                if (a.lhs.table == target) {
                    f.kind = FEAT_TARGET_LOCAL_MASK;
                    f.local_mask = &local_mask_for_atom(a);
                } else {
                    auto wit = witness_support_by_atom.find(rep_aid);
                    if (wit == witness_support_by_atom.end()) {
                        f.kind = FEAT_GLOBAL_CONST;
                        f.global_value = false;
                    } else if (wit->second.use_global) {
                        f.kind = FEAT_GLOBAL_CONST;
                        f.global_value = wit->second.global_value;
                    } else {
                        f.kind = FEAT_TARGET_WITNESS_LOCAL;
                        f.witness = &wit->second;
                    }
                }
            } else if (a.kind == POLICY_ATOM_JOIN_EQ) {
                auto hit = atom_to_hub.find(a.atom_id);
                if (hit == atom_to_hub.end()) {
                    f.kind = FEAT_GLOBAL_CONST;
                    f.global_value = false;
                } else {
                    int hid = hit->second;
                    const Hub &h = hubs[(size_t)hid];
                    const DenseBits *hub_dom = hub_dom_for_atom(rep_aid, hid);
                    if (h.left_table == target) {
                        f.kind = FEAT_TARGET_HUB_MEMBERSHIP;
                        f.hub_dom = hub_dom;
                        f.target_hub_tok = h.left_tok;
                    } else if (h.right_table == target) {
                        f.kind = FEAT_TARGET_HUB_MEMBERSHIP;
                        f.hub_dom = hub_dom;
                        f.target_hub_tok = h.right_tok;
                    } else {
                        auto wit = witness_support_by_atom.find(rep_aid);
                        if (wit != witness_support_by_atom.end()) {
                            if (wit->second.use_global) {
                                f.kind = FEAT_GLOBAL_CONST;
                                f.global_value = wit->second.global_value;
                            } else {
                                f.kind = FEAT_TARGET_WITNESS_LOCAL;
                                f.witness = &wit->second;
                            }
                        } else {
                            f.kind = FEAT_GLOBAL_CONST;
                            f.global_value = (hub_dom != nullptr) && hub_dom->any();
                        }
                    }
                }
            } else if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table != a.rhs.table) {
                auto wit = witness_support_by_atom.find(rep_aid);
                if (wit != witness_support_by_atom.end()) {
                    if (wit->second.use_global) {
                        f.kind = FEAT_GLOBAL_CONST;
                        f.global_value = wit->second.global_value;
                    } else {
                        f.kind = FEAT_TARGET_WITNESS_LOCAL;
                        f.witness = &wit->second;
                    }
                    features.push_back(f);
                    continue;
                }
                auto cit = cmp_feature_by_atom.find(rep_aid);
                if (cit == cmp_feature_by_atom.end() || !cit->second.enabled) {
                    f.kind = FEAT_GLOBAL_CONST;
                    f.global_value = false;
                } else if (cit->second.global) {
                    f.kind = FEAT_GLOBAL_CONST;
                    f.global_value = cit->second.global_value;
                } else {
                    f.kind = FEAT_TARGET_CMP;
                    f.cmp = &cit->second;
                }
            } else {
                f.kind = FEAT_GLOBAL_CONST;
                f.global_value = false;
            }
            features.push_back(f);
        }
        // Semantic pruning before signature stamping.
        // Correctness-first default: keep policy-scoped atom variables distinct
        // and avoid alias collapsing at this stage.
        //
        // NOTE:
        // Evaluator intentionally scopes atom keys per policy clause. Aggressive
        // cross-atom dedup/aliasing here can merge vars that are textually
        // similar but context-dependent for witness semantics, causing row
        // mismatches. Keep dedup disabled until we have a proven-safe aliasing
        // criterion.
        bool kEnableSemanticDedup = cf_bool_guc("custom_filter.enable_semantic_dedup", false);
        std::unordered_map<int, bool> const_atom_values;
        const_atom_values.reserve(features.size() * 2u + 1u);
        std::unordered_map<int, int> atom_alias;
        atom_alias.reserve(features.size() * 2u + 1u);
        auto atom_scope_of = [&](int aid) -> int {
            auto it = atom_by_id_.find(aid);
            return (it == atom_by_id_.end()) ? -1 : it->second.scope_id;
        };

        uint64 dedup_removed = 0;
        uint64 const_folded = 0;
        uint32 raw_feature_count = (uint32)features.size();
        uint32 dedup_feature_count = raw_feature_count;

        auto t_dedup0 = Clock::now();
        if (!kEnableSemanticDedup) {
            for (const Feature &f : features) {
                atom_alias[f.atom_id] = f.atom_id;
                if (f.kind == FEAT_GLOBAL_CONST)
                    const_atom_values[f.atom_id] = f.global_value;
            }
        } else {
            std::vector<Feature> uniq_features;
            uniq_features.reserve(features.size());

            std::unordered_map<uint64, std::vector<size_t>> local_mask_buckets;
            std::unordered_map<uint64, std::vector<size_t>> hub_buckets;
            std::unordered_map<uint64, std::vector<size_t>> cmp_buckets;
            std::unordered_map<uint64, std::vector<size_t>> witness_buckets;

            auto ptr_mix = [](const void *p) -> uint64 {
                uint64 v = (uint64)(uintptr_t)p;
                v ^= (v >> 33);
                v *= 0xff51afd7ed558ccdULL;
                v ^= (v >> 33);
                v *= 0xc4ceb9fe1a85ec53ULL;
                v ^= (v >> 33);
                return v;
            };
            auto witness_hash = [&](const WitnessSupport *ws) -> uint64 {
                if (!ws)
                    return 0ULL;
                uint64 h = 1469598103934665603ULL;
                size_t nref = std::min(ws->target_refs.size(), ws->target_supports.size());
                for (size_t i = 0; i < nref; i++) {
                    const TargetHubRef &ref = ws->target_refs[i];
                    if (!ref.target_tok)
                        continue;
                    h ^= ptr_mix(ref.target_tok);
                    h *= 1099511628211ULL;
                    h ^= (uint64)(uint32)ref.hub_idx;
                    h *= 1099511628211ULL;
                    h ^= ws->target_supports[i].hash64();
                    h *= 1099511628211ULL;
                }
                return h;
            };
            auto witness_equiv = [&](const WitnessSupport *a, const WitnessSupport *b) -> bool {
                if (a == b)
                    return true;
                if (!a || !b)
                    return false;
                size_t na = std::min(a->target_refs.size(), a->target_supports.size());
                size_t nb = std::min(b->target_refs.size(), b->target_supports.size());
                if (na != nb)
                    return false;
                for (size_t i = 0; i < na; i++) {
                    const TargetHubRef &ra = a->target_refs[i];
                    const TargetHubRef &rb = b->target_refs[i];
                    if (ra.hub_idx != rb.hub_idx || ra.target_tok != rb.target_tok)
                        return false;
                    if (!a->target_supports[i].equals(b->target_supports[i]))
                        return false;
                }
                return true;
            };

            for (const Feature &f : features) {
                int f_scope = atom_scope_of(f.atom_id);
                if (f.kind == FEAT_GLOBAL_CONST) {
                    const_atom_values[f.atom_id] = f.global_value;
                    atom_alias[f.atom_id] = f.atom_id;
                    continue;
                }
                // Unknown scope: never dedup across atoms.
                if (f_scope < 0) {
                    atom_alias[f.atom_id] = f.atom_id;
                    uniq_features.push_back(f);
                    continue;
                }

                // Exact constant-fold for local target masks.
                if (f.kind == FEAT_TARGET_LOCAL_MASK && f.local_mask) {
                    uint64 c = f.local_mask->count();
                    if (c == 0ULL || c >= (uint64)target_td->manifest.nrows) {
                        const_atom_values[f.atom_id] = (c >= (uint64)target_td->manifest.nrows);
                        atom_alias[f.atom_id] = f.atom_id;
                        const_folded++;
                        continue;
                    }
                }

                size_t rep_idx = SIZE_MAX;
                if (f.kind == FEAT_TARGET_LOCAL_MASK) {
                    if (!f.local_mask) {
                        const_atom_values[f.atom_id] = false;
                        atom_alias[f.atom_id] = f.atom_id;
                        const_folded++;
                        continue;
                    }
                    uint64 hk = f.local_mask->hash64();
                    auto bit = local_mask_buckets.find(hk);
                    if (bit != local_mask_buckets.end()) {
                        for (size_t idx : bit->second) {
                            if (idx >= uniq_features.size())
                                continue;
                            const Feature &u = uniq_features[idx];
                            if (atom_scope_of(u.atom_id) != f_scope)
                                continue;
                            if (u.kind != FEAT_TARGET_LOCAL_MASK || !u.local_mask)
                                continue;
                            if (u.local_mask->equals(*f.local_mask)) {
                                rep_idx = idx;
                                break;
                            }
                        }
                    }
                    if (rep_idx == SIZE_MAX)
                        local_mask_buckets[hk].push_back(uniq_features.size());
                } else if (f.kind == FEAT_TARGET_HUB_MEMBERSHIP) {
                    if (!f.hub_dom || !f.target_hub_tok) {
                        const_atom_values[f.atom_id] = false;
                        atom_alias[f.atom_id] = f.atom_id;
                        const_folded++;
                        continue;
                    }
                    uint64 hk = 1469598103934665603ULL;
                    hk ^= ptr_mix(f.target_hub_tok);
                    hk *= 1099511628211ULL;
                    hk ^= f.hub_dom->hash64();
                    hk *= 1099511628211ULL;
                    auto bit = hub_buckets.find(hk);
                    if (bit != hub_buckets.end()) {
                        for (size_t idx : bit->second) {
                            if (idx >= uniq_features.size())
                                continue;
                            const Feature &u = uniq_features[idx];
                            if (atom_scope_of(u.atom_id) != f_scope)
                                continue;
                            if (u.kind == FEAT_TARGET_HUB_MEMBERSHIP &&
                                u.target_hub_tok == f.target_hub_tok &&
                                u.hub_dom && u.hub_dom->equals(*f.hub_dom)) {
                                rep_idx = idx;
                                break;
                            }
                        }
                    }
                    if (rep_idx == SIZE_MAX)
                        hub_buckets[hk].push_back(uniq_features.size());
                } else if (f.kind == FEAT_TARGET_CMP) {
                    if (!f.cmp) {
                        const_atom_values[f.atom_id] = false;
                        atom_alias[f.atom_id] = f.atom_id;
                        const_folded++;
                        continue;
                    }
                    uint64 hk = ptr_mix(f.cmp);
                    auto bit = cmp_buckets.find(hk);
                    if (bit != cmp_buckets.end()) {
                        for (size_t idx : bit->second) {
                            if (idx >= uniq_features.size())
                                continue;
                            const Feature &u = uniq_features[idx];
                            if (atom_scope_of(u.atom_id) != f_scope)
                                continue;
                            if (u.kind == FEAT_TARGET_CMP && u.cmp == f.cmp) {
                                rep_idx = idx;
                                break;
                            }
                        }
                    }
                    if (rep_idx == SIZE_MAX)
                        cmp_buckets[hk].push_back(uniq_features.size());
                } else if (f.kind == FEAT_TARGET_WITNESS_LOCAL) {
                    if (!f.witness) {
                        const_atom_values[f.atom_id] = false;
                        atom_alias[f.atom_id] = f.atom_id;
                        const_folded++;
                        continue;
                    }
                    uint64 hk = witness_hash(f.witness);
                    auto bit = witness_buckets.find(hk);
                    if (bit != witness_buckets.end()) {
                        for (size_t idx : bit->second) {
                            if (idx >= uniq_features.size())
                                continue;
                            const Feature &u = uniq_features[idx];
                            if (atom_scope_of(u.atom_id) != f_scope)
                                continue;
                            if (u.kind == FEAT_TARGET_WITNESS_LOCAL &&
                                witness_equiv(u.witness, f.witness)) {
                                rep_idx = idx;
                                break;
                            }
                        }
                    }
                    if (rep_idx == SIZE_MAX)
                        witness_buckets[hk].push_back(uniq_features.size());
                }

                if (rep_idx != SIZE_MAX) {
                    atom_alias[f.atom_id] = uniq_features[rep_idx].atom_id;
                    dedup_removed++;
                    continue;
                }

                atom_alias[f.atom_id] = f.atom_id;
                uniq_features.push_back(f);
            }
            features.swap(uniq_features);
            dedup_feature_count = (uint32)features.size();
        }
        semantic_dedup_ms_local += Ms(Clock::now() - t_dedup0).count();

        auto resolve_alias_feature = [&](int aid) -> int {
            int cur = aid;
            for (int hops = 0; hops < 16; hops++) {
                auto it = atom_alias.find(cur);
                if (it == atom_alias.end() || it->second <= 0 || it->second == cur)
                    break;
                cur = it->second;
            }
            return cur;
        };

        const TableBinCatalog *target_bin_cat = nullptr;
        auto tcat_it = table_bin_catalogs.find(target);
        if (tcat_it != table_bin_catalogs.end())
            target_bin_cat = tcat_it->second;
        std::unordered_map<const std::vector<int32> *, int> target_hub_idx_by_tok;
        std::unordered_map<const std::vector<int32> *, int> target_hub_pos_by_tok;
        target_hub_idx_by_tok.reserve(incidences.size() * 2u + 1u);
        target_hub_pos_by_tok.reserve(incidences.size() * 2u + 1u);
        auto t_inc = incidences.find(target);
        if (target_bin_cat && t_inc != incidences.end()) {
            for (const Inc &inc : t_inc->second) {
                if (!inc.tok)
                    continue;
                auto pit = target_bin_cat->hub_pos.find(inc.hub_idx);
                if (pit == target_bin_cat->hub_pos.end())
                    continue;
                target_hub_idx_by_tok[inc.tok] = inc.hub_idx;
                target_hub_pos_by_tok[inc.tok] = (int)pit->second;
            }
        }
        bool has_target_bins =
            (target_bin_cat != nullptr &&
             !target_bin_cat->bins.empty() &&
             !target_bin_cat->row_to_bin.empty());

        std::unordered_map<int, const Feature *> feature_by_atom;
        feature_by_atom.reserve(features.size() * 2u + 1u);
        for (const Feature &f : features)
            feature_by_atom[f.atom_id] = &f;

        const uint32 target_nrows = target_td->manifest.nrows;
        const DenseBits *target_base_rows = nullptr;
        auto target_base_it = base_rows.find(target);
        if (target_base_it != base_rows.end() &&
            target_base_it->second.nbits() == target_nrows) {
            target_base_rows = &target_base_it->second;
        }
        DenseBits candidate_rows(target_nrows);
        candidate_rows.fill_all();
        DenseBits candidate_bins;
        uint64 mandatory_atoms_count = 0;
        auto prune_candidate_bins_with_feature = [&](const Feature &f, DenseBits *cand) {
            if (!cand || !cand->any() || !target_bin_cat)
                return;
            if (f.kind == FEAT_GLOBAL_CONST) {
                if (!f.global_value)
                    cand->clear_all();
                return;
            }
            if (f.kind == FEAT_TARGET_LOCAL_MASK) {
                auto sit = target_bin_cat->local_sat_bins.find(f.atom_id);
                if (sit == target_bin_cat->local_sat_bins.end()) {
                    cand->clear_all();
                    return;
                }
                cand->bit_and(sit->second);
                return;
            }
            if (f.kind == FEAT_TARGET_HUB_MEMBERSHIP) {
                if (!f.hub_dom || !f.target_hub_tok) {
                    cand->clear_all();
                    return;
                }
                auto hp = target_hub_pos_by_tok.find(f.target_hub_tok);
                if (hp == target_hub_pos_by_tok.end() || hp->second < 0) {
                    cand->clear_all();
                    return;
                }
                int hpos = hp->second;
                DenseBits keep(cand->nbits());
                keep.clear_all();
                cand->for_each_set([&](uint32 bi) {
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        return;
                    const TableBinEntry &bin = target_bin_cat->bins[(size_t)bi];
                    if ((size_t)hpos >= bin.hub_vals.size())
                        return;
                    int32 tv = bin.hub_vals[(size_t)hpos];
                    if (tv < 0 || (uint32)tv >= f.hub_dom->nbits())
                        return;
                    if (f.hub_dom->test((uint32)tv))
                        keep.set(bi);
                });
                *cand = std::move(keep);
                return;
            }
            if (f.kind == FEAT_TARGET_CMP) {
                if (!f.cmp) {
                    cand->clear_all();
                    return;
                }
                auto ep = target_bin_cat->extra_pos.find(f.cmp->target_col_idx);
                if (ep == target_bin_cat->extra_pos.end()) {
                    cand->clear_all();
                    return;
                }
                int extra_pos = (int)ep->second;
                int group_pos = -1;
                if (f.cmp->group_hub_idx >= 0) {
                    auto gp = target_bin_cat->hub_pos.find(f.cmp->group_hub_idx);
                    if (gp != target_bin_cat->hub_pos.end())
                        group_pos = (int)gp->second;
                }
                DenseBits keep(cand->nbits());
                keep.clear_all();
                cand->for_each_set([&](uint32 bi) {
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        return;
                    const TableBinEntry &bin = target_bin_cat->bins[(size_t)bi];
                    if ((size_t)extra_pos >= bin.extra_vals.size())
                        return;
                    int32 tv = bin.extra_vals[(size_t)extra_pos];
                    if (tv < 0)
                        return;
                    int32 rk = rank_or_identity(f.cmp->rank, tv);
                    bool ok = false;
                    if (group_pos >= 0) {
                        if ((size_t)group_pos >= bin.hub_vals.size())
                            ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                        else {
                            int32 gtok = bin.hub_vals[(size_t)group_pos];
                            if (gtok >= 0) {
                                auto it = f.cmp->by_group.find(gtok);
                                if (it != f.cmp->by_group.end())
                                    ok = tok_vs_summary(f.cmp->op, tv, rk, it->second);
                                else
                                    ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                            } else {
                                ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                            }
                        }
                    } else {
                        ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                    }
                    if (ok)
                        keep.set(bi);
                });
                *cand = std::move(keep);
                return;
            }
            if (f.kind == FEAT_TARGET_WITNESS_LOCAL) {
                if (!f.witness || f.witness->use_global) {
                    if (!f.witness || !f.witness->global_value)
                        cand->clear_all();
                    return;
                }
                size_t nref = std::min(f.witness->target_refs.size(), f.witness->target_supports.size());
                if (nref == 0u) {
                    cand->clear_all();
                    return;
                }
                std::vector<int> hub_pos;
                std::vector<const DenseBits *> supports;
                hub_pos.reserve(nref);
                supports.reserve(nref);
                for (size_t ri = 0; ri < nref; ri++) {
                    const TargetHubRef &ref = f.witness->target_refs[ri];
                    auto hp = target_hub_pos_by_tok.find(ref.target_tok);
                    if (!ref.target_tok || hp == target_hub_pos_by_tok.end() || hp->second < 0)
                        continue;
                    hub_pos.push_back(hp->second);
                    supports.push_back(&f.witness->target_supports[ri]);
                }
                if (hub_pos.empty()) {
                    cand->clear_all();
                    return;
                }
                DenseBits keep(cand->nbits());
                keep.clear_all();
                cand->for_each_set([&](uint32 bi) {
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        return;
                    const TableBinEntry &bin = target_bin_cat->bins[(size_t)bi];
                    bool ok = false;
                    size_t m = std::min(hub_pos.size(), supports.size());
                    for (size_t i = 0; i < m; i++) {
                        int hp = hub_pos[i];
                        if (hp < 0 || (size_t)hp >= bin.hub_vals.size())
                            continue;
                        int32 tv = bin.hub_vals[(size_t)hp];
                        const DenseBits *supp = supports[i];
                        if (tv >= 0 && supp && (uint32)tv < supp->nbits() && supp->test((uint32)tv)) {
                            ok = true;
                            break;
                        }
                    }
                    if (ok)
                        keep.set(bi);
                });
                *cand = std::move(keep);
                return;
            }
            cand->clear_all();
        };
        auto prune_candidate_with_feature = [&](const Feature &f, DenseBits *cand) {
            if (!cand || !cand->any())
                return;
            if (f.kind == FEAT_GLOBAL_CONST) {
                if (!f.global_value)
                    cand->clear_all();
                return;
            }
            if (f.kind == FEAT_TARGET_LOCAL_MASK) {
                if (!f.local_mask) {
                    cand->clear_all();
                    return;
                }
                cand->bit_and(*f.local_mask);
                return;
            }
            if (f.kind == FEAT_TARGET_HUB_MEMBERSHIP) {
                if (!f.hub_dom || !f.target_hub_tok) {
                    cand->clear_all();
                    return;
                }
                DenseBits keep(cand->nbits());
                keep.clear_all();
                cand->for_each_set([&](uint32 rid) {
                    int32 tv = (*(f.target_hub_tok))[rid];
                    if (tv < 0 || (uint32)tv >= f.hub_dom->nbits())
                        return;
                    if (f.hub_dom->test((uint32)tv))
                        keep.set(rid);
                });
                *cand = std::move(keep);
                return;
            }
            if (f.kind == FEAT_TARGET_CMP) {
                if (!f.cmp || !f.cmp->target_tok) {
                    cand->clear_all();
                    return;
                }
                DenseBits keep(cand->nbits());
                keep.clear_all();
                cand->for_each_set([&](uint32 rid) {
                    int32 tv = (*(f.cmp->target_tok))[rid];
                    if (tv < 0)
                        return;
                    int32 rk = rank_or_identity(f.cmp->rank, tv);
                    bool ok = false;
                    if (f.cmp->group_hub_idx >= 0 && f.cmp->target_group_tok) {
                        int32 gtok = (*(f.cmp->target_group_tok))[rid];
                        if (gtok >= 0) {
                            auto it = f.cmp->by_group.find(gtok);
                            if (it != f.cmp->by_group.end())
                                ok = tok_vs_summary(f.cmp->op, tv, rk, it->second);
                            else
                                ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                        } else {
                            ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                        }
                    } else {
                        ok = tok_vs_summary(f.cmp->op, tv, rk, f.cmp->global_summary);
                    }
                    if (ok)
                        keep.set(rid);
                });
                *cand = std::move(keep);
                return;
            }
            if (f.kind == FEAT_TARGET_WITNESS_LOCAL) {
                if (!f.witness || f.witness->use_global) {
                    if (!f.witness || !f.witness->global_value)
                        cand->clear_all();
                    return;
                }
                DenseBits keep(cand->nbits());
                keep.clear_all();
                size_t nref = std::min(f.witness->target_refs.size(), f.witness->target_supports.size());
                if (nref == 0u) {
                    cand->clear_all();
                    return;
                }
                cand->for_each_set([&](uint32 rid) {
                    bool ok = false;
                    for (size_t ri = 0; ri < nref; ri++) {
                        const TargetHubRef &ref = f.witness->target_refs[ri];
                        const DenseBits &supp = f.witness->target_supports[ri];
                        if (!ref.target_tok)
                            continue;
                        int32 tv = (*(ref.target_tok))[rid];
                        if (tv < 0 || (uint32)tv >= supp.nbits())
                            continue;
                        if (supp.test((uint32)tv)) {
                            ok = true;
                            break;
                        }
                    }
                    if (ok)
                        keep.set(rid);
                });
                *cand = std::move(keep);
                return;
            }
            cand->clear_all();
        };
        uint64 candidate_rows_pre_sig = 0ULL;
        auto t_candidate_prune0 = Clock::now();
        if (has_target_bins) {
            candidate_bins.reset((uint32)target_bin_cat->bins.size());
            candidate_bins.fill_all();
            if (!root_must_leaves.empty()) {
                for (int aid0 : root_must_leaves) {
                    if (aid0 <= 0)
                        continue;
                    mandatory_atoms_count++;
                    int aid = resolve_alias_feature(aid0);
                    auto cit = const_atom_values.find(aid);
                    if (cit != const_atom_values.end()) {
                        if (!cit->second)
                            candidate_bins.clear_all();
                        continue;
                    }
                    auto fit = feature_by_atom.find(aid);
                    if (fit == feature_by_atom.end() || !fit->second) {
                        candidate_bins.clear_all();
                        continue;
                    }
                    prune_candidate_bins_with_feature(*(fit->second), &candidate_bins);
                    if (!candidate_bins.any())
                        break;
                }
            }
            candidate_bins.for_each_set([&](uint32 bi) {
                if ((size_t)bi >= target_bin_cat->bins.size())
                    return;
                if (target_base_rows &&
                    target_bin_cat->bin_offsets.size() == target_bin_cat->bins.size() + 1u &&
                    !target_bin_cat->bin_rids.empty()) {
                    uint32 b = target_bin_cat->bin_offsets[(size_t)bi];
                    uint32 e = target_bin_cat->bin_offsets[(size_t)bi + 1u];
                    for (uint32 pos = b; pos < e; pos++) {
                        if ((size_t)pos >= target_bin_cat->bin_rids.size())
                            break;
                        uint32 rid = target_bin_cat->bin_rids[(size_t)pos];
                        if (rid < target_base_rows->nbits() && target_base_rows->test(rid))
                            candidate_rows_pre_sig++;
                    }
                } else {
                    candidate_rows_pre_sig += (uint64)target_bin_cat->bins[(size_t)bi].count;
                }
            });
        } else {
            if (!root_must_leaves.empty()) {
                for (int aid0 : root_must_leaves) {
                    if (aid0 <= 0)
                        continue;
                    mandatory_atoms_count++;
                    int aid = resolve_alias_feature(aid0);
                    auto cit = const_atom_values.find(aid);
                    if (cit != const_atom_values.end()) {
                        if (!cit->second)
                            candidate_rows.clear_all();
                        continue;
                    }
                    auto fit = feature_by_atom.find(aid);
                    if (fit == feature_by_atom.end() || !fit->second) {
                        // Unknown mandatory atom means unsatisfiable in current feature space.
                        candidate_rows.clear_all();
                        continue;
                    }
                    prune_candidate_with_feature(*(fit->second), &candidate_rows);
                    if (!candidate_rows.any())
                        break;
                }
            }
            candidate_rows_pre_sig = candidate_rows.count();
        }
        candidate_prune_ms_local += Ms(Clock::now() - t_candidate_prune0).count();
        if (candidate_rows_pre_sig == 0ULL) {
            out->table = pstrdup(target.c_str());
            out->block_words = nullptr;
            out->block_ids = nullptr;
            out->blocks = 0;
            out->total_blocks = target_td->total_blocks;
            out->n_rows = target_td->manifest.nrows;
            out->allowed_rows = 0;
            out->allowed_sids = 0;
            out->total_sids = 0;
            out->hub_prop_ms = Ms(t_prop1 - t_prop0).count();
            out->sat_ms = 0.0;
            out->sid_build_ms = 0.0;
            out->mode_hint = POLICY_MODE_HINT_EMPTY;
            out->mode_reason = pstrdup("mandatory_atoms_unsat");
            DenseBits allow_none(target_td->manifest.nrows);
            allow_none.clear_all();
            policy_allow_mask_cache_[target] = allow_none;
            maybe_store_allow_cache(allow_none);
            note_allow_cache_build_time();
            if (profile_) {
                double build_hubs_ms_local = Ms(t_hub1 - t_hub0).count();
                double composite_stamp_ms_local = stamp_ms_local;
                double build_ctx_ms_local = Ms(t_prop1 - t_prop0).count();
                profile_->build_hubs_ms += build_hubs_ms_local;
                profile_->composite_stamp_ms += composite_stamp_ms_local;
                profile_->build_context_ms += build_ctx_ms_local;
                profile_->prop_build_arcs_ms += prop_build_arcs_ms_local;
                profile_->prop_ac_ms += prop_ac_ms_local;
                profile_->prop_scc_ms += prop_scc_ms_local;
                profile_->prop_bin_catalog_ms += prop_bin_catalog_ms_local;
                profile_->prop_witness_ms += prop_witness_ms_local;
                profile_->prop_cmp_ms += prop_cmp_ms_local;
                profile_->semantic_dedup_ms += semantic_dedup_ms_local;
                profile_->candidate_prune_ms += candidate_prune_ms_local;
                profile_->sig_const_fold_ms += sig_const_fold_ms_local;
                profile_->signature_build_ms += 0.0;
                profile_->sat_ms += 0.0;
                profile_->project_allowset_ms += 0.0;
                profile_->atoms_ms += build_hubs_ms_local;
                profile_->stamp_ms += composite_stamp_ms_local;
                profile_->propagate_ms += build_ctx_ms_local;
                profile_->bin_ms += 0.0;
                profile_->local_sat_ms += 0.0;
                profile_->project_ms += 0.0;
                profile_->bin_build_rows_scanned += bin_build_rows_scanned_local;
                profile_->bin_count_final += bin_count_final_local;
                profile_->bin_build_probe_steps += bin_build_probe_steps_local;
                profile_->bin_build_max_probe_len =
                    std::max<uint64>(profile_->bin_build_max_probe_len, bin_build_max_probe_len_local);
                profile_->bin_build_rehash_count += bin_build_rehash_count_local;
                profile_->bin_build_hub_count += bin_build_hub_count_local;
                profile_->bin_build_local_atom_count += bin_build_local_atom_count_local;
                profile_->bin_build_extra_count += bin_build_extra_count_local;
                profile_->terms_total++;
            }
            double bin_build_avg_probe_len_local =
                (bin_build_rows_scanned_local > 0)
                    ? ((double)bin_build_probe_steps_local / (double)bin_build_rows_scanned_local)
                    : 0.0;
            elog(NOTICE,
                 "policy_profile_target: table=%s n_rows=%u allowed_rows=0 density=0.000000 mode_hint=%d "
                 "nfeatures=%u features_raw=%u features_dedup=%u dedup_removed=%llu const_folded=%llu "
                 "ast_ntok=%d total_sids=0 allowed_sids=0 hubs=%zu arcs=0 scc_count=0 max_scc_size=0 "
                 "contexts_cached=%zu contexts_built=%llu contexts_total=%llu contexts_pruned_superset=%llu "
                 "arc_adj_cache_hits=%llu arc_adj_cache_misses=%llu "
                 "prop_bin_catalog_ms=%.3f prop_witness_ms=%.3f prop_cmp_ms=%.3f "
                 "semantic_dedup_ms=%.3f candidate_prune_ms=%.3f sig_const_fold_ms=%.3f "
                 "bin_build_rows_scanned=%llu bin_count_final=%llu bin_build_avg_probe_len=%.3f "
                 "bin_build_max_probe_len=%llu bin_build_rehash_count=%llu "
                 "bin_build_hub_count=%llu bin_build_local_atom_count=%llu bin_build_extra_count=%llu "
                 "mandatory_atoms_count=%llu candidate_rows_pre_sig=%llu witness_memo_hits=%llu witness_memo_misses=%llu decoded_cols_count=%s",
                 target.c_str(),
                 target_td->manifest.nrows,
                 POLICY_MODE_HINT_EMPTY,
                 0u,
                 raw_feature_count,
                 dedup_feature_count,
                 (unsigned long long)dedup_removed,
                 (unsigned long long)const_folded,
                 ast_ntok,
                 hubs.size(),
                 context_cache.size(),
                 (unsigned long long)context_builds,
                 (unsigned long long)contexts_total_terms,
                 (unsigned long long)contexts_pruned_superset,
                 (unsigned long long)arc_adj_cache_hits,
                 (unsigned long long)arc_adj_cache_misses,
                 prop_bin_catalog_ms_local,
                 prop_witness_ms_local,
                 prop_cmp_ms_local,
                 semantic_dedup_ms_local,
                 candidate_prune_ms_local,
                 sig_const_fold_ms_local,
                 (unsigned long long)bin_build_rows_scanned_local,
                 (unsigned long long)bin_count_final_local,
                 bin_build_avg_probe_len_local,
                 (unsigned long long)bin_build_max_probe_len_local,
                 (unsigned long long)bin_build_rehash_count_local,
                 (unsigned long long)bin_build_hub_count_local,
                 (unsigned long long)bin_build_local_atom_count_local,
                 (unsigned long long)bin_build_extra_count_local,
                 (unsigned long long)mandatory_atoms_count,
                 (unsigned long long)candidate_rows_pre_sig,
                 (unsigned long long)witness_memo_hits,
                 (unsigned long long)witness_memo_misses,
                 target.c_str());
            return true;
        }

        struct MaskFeatureGroup {
            int atom_id = 0;
            const DenseBits *mask = nullptr;
            std::vector<uint32> bits;
            uint64 packed_word = 0ULL;
            std::vector<std::pair<uint32, uint64>> packed_words;
        };
        struct HubFeatureGroup {
            int hub_idx = -1;
            int hub_pos = -1;
            const DenseBits *dom = nullptr;
            const std::vector<int32> *tok = nullptr;
            std::vector<uint32> bits;
            uint64 packed_word = 0ULL;
            std::vector<std::pair<uint32, uint64>> packed_words;
        };
        struct CmpFeatureEval {
            uint32 bit = 0;
            const CmpFeatData *cmp = nullptr;
            uint32 word_idx = 0;
            uint64 bit_mask = 0ULL;
            int target_extra_pos = -1;
            int target_group_pos = -1;
        };
        struct WitnessFeatureEval {
            uint32 bit = 0;
            std::vector<const std::vector<int32> *> target_toks;
            std::vector<const DenseBits *> target_supports;
            uint32 word_idx = 0;
            uint64 bit_mask = 0ULL;
            std::vector<int> target_hub_pos;
        };

        std::vector<int> sig_atom_ids;
        sig_atom_ids.reserve(features.size());
        std::vector<MaskFeatureGroup> mask_groups;
        std::vector<HubFeatureGroup> hub_groups;
        std::vector<CmpFeatureEval> cmp_features_eval;
        std::vector<WitnessFeatureEval> witness_features_eval;

        auto add_mask_group_bit = [&](int atom_id, const DenseBits *mask, uint32 bit) {
            if (!mask)
                return;
            for (MaskFeatureGroup &g : mask_groups) {
                if (g.mask == mask) {
                    g.bits.push_back(bit);
                    return;
                }
            }
            MaskFeatureGroup g;
            g.atom_id = atom_id;
            g.mask = mask;
            g.bits.push_back(bit);
            mask_groups.push_back(std::move(g));
        };

        auto add_hub_group_bit =
            [&](const DenseBits *dom, const std::vector<int32> *tok, uint32 bit) {
            if (!dom || !tok)
                return;
            int hid = -1;
            int hpos = -1;
            auto hi = target_hub_idx_by_tok.find(tok);
            auto hp = target_hub_pos_by_tok.find(tok);
            if (hi != target_hub_idx_by_tok.end())
                hid = hi->second;
            if (hp != target_hub_pos_by_tok.end())
                hpos = hp->second;
            for (HubFeatureGroup &g : hub_groups) {
                if (g.dom == dom && g.tok == tok) {
                    g.bits.push_back(bit);
                    return;
                }
            }
            HubFeatureGroup g;
            g.hub_idx = hid;
            g.hub_pos = hpos;
            g.dom = dom;
            g.tok = tok;
            g.bits.push_back(bit);
            hub_groups.push_back(std::move(g));
        };

        uint32 next_sig_bit = 0u;
        for (const Feature &f : features) {
            if (f.kind == FEAT_GLOBAL_CONST) {
                const_atom_values[f.atom_id] = f.global_value;
                continue;
            }
            uint32 bit = next_sig_bit++;
            sig_atom_ids.push_back(f.atom_id);
            if (f.kind == FEAT_TARGET_LOCAL_MASK) {
                add_mask_group_bit(f.atom_id, f.local_mask, bit);
            } else if (f.kind == FEAT_TARGET_HUB_MEMBERSHIP) {
                add_hub_group_bit(f.hub_dom, f.target_hub_tok, bit);
            } else if (f.kind == FEAT_TARGET_CMP) {
                cmp_features_eval.push_back(CmpFeatureEval{bit, f.cmp});
            } else if (f.kind == FEAT_TARGET_WITNESS_LOCAL) {
                WitnessFeatureEval wf;
                wf.bit = bit;
                if (f.witness && !f.witness->use_global) {
                    size_t nref = std::min(f.witness->target_refs.size(), f.witness->target_supports.size());
                    wf.target_toks.reserve(nref);
                    wf.target_supports.reserve(nref);
                    for (size_t i = 0; i < nref; i++) {
                        const TargetHubRef &ref = f.witness->target_refs[i];
                        if (!ref.target_tok)
                            continue;
                        wf.target_toks.push_back(ref.target_tok);
                        wf.target_supports.push_back(&f.witness->target_supports[i]);
                    }
                }
                witness_features_eval.push_back(std::move(wf));
            }
        }

        auto t_sig0 = Clock::now();
        uint32 nbits = next_sig_bit;
        uint32 nwords = std::max<uint32>(1u, (nbits + 63u) / 64u);

        auto build_packed_words = [&](const std::vector<uint32> &bits,
                                      uint64 *packed_word,
                                      std::vector<std::pair<uint32, uint64>> *packed_words) {
            if (packed_word)
                *packed_word = 0ULL;
            if (!packed_words)
                return;
            packed_words->clear();
            std::unordered_map<uint32, uint64> by_word;
            by_word.reserve(bits.size() * 2u + 1u);
            for (uint32 bit : bits) {
                uint32 wi = bit >> 6;
                uint64 bm = (1ULL << (bit & 63u));
                if (nwords == 1u) {
                    if (packed_word)
                        *packed_word |= bm;
                } else {
                    by_word[wi] |= bm;
                }
            }
            if (nwords > 1u) {
                packed_words->reserve(by_word.size());
                for (const auto &kv : by_word)
                    packed_words->push_back({kv.first, kv.second});
                std::sort(packed_words->begin(),
                          packed_words->end(),
                          [](const std::pair<uint32, uint64> &a, const std::pair<uint32, uint64> &b) {
                              return a.first < b.first;
                          });
            }
        };

        for (MaskFeatureGroup &g : mask_groups)
            build_packed_words(g.bits, &g.packed_word, &g.packed_words);
        for (HubFeatureGroup &g : hub_groups)
            build_packed_words(g.bits, &g.packed_word, &g.packed_words);
        for (CmpFeatureEval &cf : cmp_features_eval) {
            cf.word_idx = (cf.bit >> 6);
            cf.bit_mask = (1ULL << (cf.bit & 63u));
            cf.target_extra_pos = -1;
            cf.target_group_pos = -1;
            if (target_bin_cat && cf.cmp) {
                auto ep = target_bin_cat->extra_pos.find(cf.cmp->target_col_idx);
                if (ep != target_bin_cat->extra_pos.end())
                    cf.target_extra_pos = (int)ep->second;
                if (cf.cmp->group_hub_idx >= 0) {
                    auto gp = target_bin_cat->hub_pos.find(cf.cmp->group_hub_idx);
                    if (gp != target_bin_cat->hub_pos.end())
                        cf.target_group_pos = (int)gp->second;
                }
            }
        }
        for (WitnessFeatureEval &wf : witness_features_eval) {
            wf.word_idx = (wf.bit >> 6);
            wf.bit_mask = (1ULL << (wf.bit & 63u));
            wf.target_hub_pos.clear();
            size_t nref = std::min(wf.target_toks.size(), wf.target_supports.size());
            if (nref == 0u)
                continue;
            std::vector<const std::vector<int32> *> toks_keep;
            std::vector<const DenseBits *> supp_keep;
            toks_keep.reserve(nref);
            supp_keep.reserve(nref);
            wf.target_hub_pos.reserve(nref);
            for (size_t i = 0; i < nref; i++) {
                const std::vector<int32> *tokp = wf.target_toks[i];
                auto hp = target_hub_pos_by_tok.find(tokp);
                if (hp == target_hub_pos_by_tok.end() || hp->second < 0)
                    continue;
                toks_keep.push_back(tokp);
                supp_keep.push_back(wf.target_supports[i]);
                wf.target_hub_pos.push_back(hp->second);
            }
            wf.target_toks.swap(toks_keep);
            wf.target_supports.swap(supp_keep);
        }

        std::vector<uint64> sid_words_flat;
        sid_words_flat.reserve((size_t)nwords * 1024u);

        int32 max_blk = -1;
        for (int32 b : target_td->ctid_blk) {
            if (b > max_blk)
                max_blk = b;
        }
        uint32 total_blocks = (max_blk >= 0) ? ((uint32)max_blk + 1u) : 0u;
        std::vector<uint64> dense((size_t)total_blocks * kWordsPerBlock, 0ULL);
        std::vector<uint8_t> touched(total_blocks, 0u);
        std::vector<uint32> block_ids;
        block_ids.reserve(total_blocks / 8u + 16u);
        uint64 allowed_rows = 0;
        DenseBits allow_mask(target_td->manifest.nrows);
        allow_mask.clear_all();

        std::vector<uint32> row_sid;
        std::vector<uint32> bin_sid;
        std::vector<uint8_t> sid_allowed;
        sid_allowed.reserve(1024);

        uint32 sid_count = 0;
        const uint32 nrows = target_td->manifest.nrows;
        bool use_bin_signatures = has_target_bins;
        if (!use_bin_signatures)
            row_sid.assign(target_td->manifest.nrows, UINT32_MAX);
        bool use_active_rows =
            (!use_bin_signatures && candidate_rows_pre_sig < ((uint64)nrows * 9ULL) / 10ULL);
        std::vector<uint32> active_rids;
        if (!use_bin_signatures && use_active_rows) {
            active_rids.reserve((size_t)candidate_rows_pre_sig);
            candidate_rows.for_each_set([&](uint32 rid) {
                active_rids.push_back(rid);
            });
        }
        const uint32 build_rows = use_bin_signatures ? 0u : (use_active_rows ? (uint32)active_rids.size() : nrows);
        std::vector<uint64> sig_block_words;
        const uint32 kSigBlockRows = 4096u;
        if (use_bin_signatures) {
            const uint32 n_target_bins = (uint32)target_bin_cat->bins.size();
            DenseBits active_bins(n_target_bins);
            if (candidate_bins.nbits() == n_target_bins) {
                active_bins = candidate_bins;
            } else {
                active_bins.fill_all();
            }

            std::vector<int> mask_local_pos(mask_groups.size(), -1);
            if (target_bin_cat) {
                for (size_t gi = 0; gi < mask_groups.size(); gi++) {
                    auto it = target_bin_cat->local_pos.find(mask_groups[gi].atom_id);
                    if (it != target_bin_cat->local_pos.end())
                        mask_local_pos[gi] = (int)it->second;
                }
            }

            auto build_bin_sig_words = [&](const TableBinEntry &bin, uint64 *sig1, std::vector<uint64> *sigv) {
                if (nwords == 1u) {
                    if (!sig1)
                        return;
                    *sig1 = 0ULL;
                    for (size_t gi = 0; gi < mask_groups.size(); gi++) {
                        int lp = (gi < mask_local_pos.size()) ? mask_local_pos[gi] : -1;
                        if (lp < 0 || (size_t)lp >= bin.local_bits.size())
                            continue;
                        if (bin.local_bits[(size_t)lp] != 0u)
                            *sig1 |= mask_groups[gi].packed_word;
                    }
                    for (const HubFeatureGroup &g : hub_groups) {
                        if (!g.dom || g.hub_pos < 0 || (size_t)g.hub_pos >= bin.hub_vals.size())
                            continue;
                        int32 tv = bin.hub_vals[(size_t)g.hub_pos];
                        if (tv < 0 || (uint32)tv >= g.dom->nbits() || !g.dom->test((uint32)tv))
                            continue;
                        *sig1 |= g.packed_word;
                    }
                    for (const CmpFeatureEval &cf : cmp_features_eval) {
                        if (!cf.cmp || cf.target_extra_pos < 0 ||
                            (size_t)cf.target_extra_pos >= bin.extra_vals.size())
                            continue;
                        int32 tv = bin.extra_vals[(size_t)cf.target_extra_pos];
                        if (tv < 0)
                            continue;
                        int32 rk = rank_or_identity(cf.cmp->rank, tv);
                        bool ok = false;
                        if (cf.target_group_pos >= 0) {
                            if ((size_t)cf.target_group_pos >= bin.hub_vals.size())
                                ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                            else {
                                int32 gtok = bin.hub_vals[(size_t)cf.target_group_pos];
                                if (gtok >= 0) {
                                    auto it = cf.cmp->by_group.find(gtok);
                                    if (it != cf.cmp->by_group.end())
                                        ok = tok_vs_summary(cf.cmp->op, tv, rk, it->second);
                                    else
                                        ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                                } else {
                                    ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                                }
                            }
                        } else {
                            ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                        }
                        if (ok)
                            *sig1 |= cf.bit_mask;
                    }
                    for (const WitnessFeatureEval &wf : witness_features_eval) {
                        if (wf.target_hub_pos.empty() || wf.target_supports.empty())
                            continue;
                        bool ok = false;
                        size_t nref = std::min(wf.target_hub_pos.size(), wf.target_supports.size());
                        for (size_t ri = 0; ri < nref; ri++) {
                            int hp = wf.target_hub_pos[ri];
                            if (hp < 0 || (size_t)hp >= bin.hub_vals.size())
                                continue;
                            int32 tv = bin.hub_vals[(size_t)hp];
                            if (tv < 0)
                                continue;
                            const DenseBits *supp = wf.target_supports[ri];
                            if (supp && (uint32)tv < supp->nbits() && supp->test((uint32)tv)) {
                                ok = true;
                                break;
                            }
                        }
                        if (ok)
                            *sig1 |= wf.bit_mask;
                    }
                    return;
                }

                if (!sigv)
                    return;
                std::fill(sigv->begin(), sigv->end(), 0ULL);
                for (size_t gi = 0; gi < mask_groups.size(); gi++) {
                    int lp = (gi < mask_local_pos.size()) ? mask_local_pos[gi] : -1;
                    if (lp < 0 || (size_t)lp >= bin.local_bits.size())
                        continue;
                    if (bin.local_bits[(size_t)lp] == 0u)
                        continue;
                    for (const auto &wm : mask_groups[gi].packed_words)
                        (*sigv)[(size_t)wm.first] |= wm.second;
                }
                for (const HubFeatureGroup &g : hub_groups) {
                    if (!g.dom || g.hub_pos < 0 || (size_t)g.hub_pos >= bin.hub_vals.size())
                        continue;
                    int32 tv = bin.hub_vals[(size_t)g.hub_pos];
                    if (tv < 0 || (uint32)tv >= g.dom->nbits() || !g.dom->test((uint32)tv))
                        continue;
                    for (const auto &wm : g.packed_words)
                        (*sigv)[(size_t)wm.first] |= wm.second;
                }
                for (const CmpFeatureEval &cf : cmp_features_eval) {
                    if (!cf.cmp || cf.target_extra_pos < 0 ||
                        (size_t)cf.target_extra_pos >= bin.extra_vals.size())
                        continue;
                    int32 tv = bin.extra_vals[(size_t)cf.target_extra_pos];
                    if (tv < 0)
                        continue;
                    int32 rk = rank_or_identity(cf.cmp->rank, tv);
                    bool ok = false;
                    if (cf.target_group_pos >= 0) {
                        if ((size_t)cf.target_group_pos >= bin.hub_vals.size())
                            ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                        else {
                            int32 gtok = bin.hub_vals[(size_t)cf.target_group_pos];
                            if (gtok >= 0) {
                                auto it = cf.cmp->by_group.find(gtok);
                                if (it != cf.cmp->by_group.end())
                                    ok = tok_vs_summary(cf.cmp->op, tv, rk, it->second);
                                else
                                    ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                            } else {
                                ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                            }
                        }
                    } else {
                        ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                    }
                    if (ok)
                        (*sigv)[(size_t)cf.word_idx] |= cf.bit_mask;
                }
                for (const WitnessFeatureEval &wf : witness_features_eval) {
                    if (wf.target_hub_pos.empty() || wf.target_supports.empty())
                        continue;
                    bool ok = false;
                    size_t nref = std::min(wf.target_hub_pos.size(), wf.target_supports.size());
                    for (size_t ri = 0; ri < nref; ri++) {
                        int hp = wf.target_hub_pos[ri];
                        if (hp < 0 || (size_t)hp >= bin.hub_vals.size())
                            continue;
                        int32 tv = bin.hub_vals[(size_t)hp];
                        if (tv < 0)
                            continue;
                        const DenseBits *supp = wf.target_supports[ri];
                        if (supp && (uint32)tv < supp->nbits() && supp->test((uint32)tv)) {
                            ok = true;
                            break;
                        }
                    }
                    if (ok)
                        (*sigv)[(size_t)wf.word_idx] |= wf.bit_mask;
                }
            };

            auto t_sig_const0 = Clock::now();
            std::vector<uint64> const_word_mask((size_t)nwords, 0ULL);
            if (nbits > 0u && active_bins.any()) {
                if (nwords == 1u) {
                    uint64 sig_or = 0ULL;
                    uint64 sig_and = (nbits >= 64u) ? ~0ULL : ((1ULL << nbits) - 1ULL);
                    active_bins.for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= target_bin_cat->bins.size())
                            return;
                        uint64 sig = 0ULL;
                        build_bin_sig_words(target_bin_cat->bins[(size_t)bi], &sig, nullptr);
                        sig_or |= sig;
                        sig_and &= sig;
                    });
                    for (uint32 bit = 0; bit < nbits; bit++) {
                        bool on_any = ((sig_or >> bit) & 1ULL) != 0ULL;
                        bool on_all = ((sig_and >> bit) & 1ULL) != 0ULL;
                        if (on_any == on_all && (size_t)bit < sig_atom_ids.size()) {
                            const_atom_values[sig_atom_ids[(size_t)bit]] = on_all;
                            const_word_mask[0] |= (1ULL << bit);
                        }
                    }
                } else {
                    std::vector<uint64> sig_or((size_t)nwords, 0ULL);
                    std::vector<uint64> sig_and((size_t)nwords, ~0ULL);
                    if ((nbits & 63u) != 0u)
                        sig_and.back() = ((1ULL << (nbits & 63u)) - 1ULL);
                    std::vector<uint64> sig_words((size_t)nwords, 0ULL);
                    active_bins.for_each_set([&](uint32 bi) {
                        if ((size_t)bi >= target_bin_cat->bins.size())
                            return;
                        build_bin_sig_words(target_bin_cat->bins[(size_t)bi], nullptr, &sig_words);
                        for (uint32 w = 0; w < nwords; w++) {
                            sig_or[(size_t)w] |= sig_words[(size_t)w];
                            sig_and[(size_t)w] &= sig_words[(size_t)w];
                        }
                    });
                    for (uint32 bit = 0; bit < nbits; bit++) {
                        uint32 wi = bit >> 6;
                        uint64 bm = (1ULL << (bit & 63u));
                        bool on_any = (sig_or[(size_t)wi] & bm) != 0ULL;
                        bool on_all = (sig_and[(size_t)wi] & bm) != 0ULL;
                        if (on_any == on_all && (size_t)bit < sig_atom_ids.size()) {
                            const_atom_values[sig_atom_ids[(size_t)bit]] = on_all;
                            const_word_mask[(size_t)wi] |= bm;
                        }
                    }
                }
            }
            sig_const_fold_ms_local += Ms(Clock::now() - t_sig_const0).count();

            bin_sid.assign(n_target_bins, UINT32_MAX);
            if (nbits == 0u) {
                sid_count = 1u;
                sid_words_flat.push_back(0ULL);
                active_bins.for_each_set([&](uint32 bi) {
                    if (bi < bin_sid.size())
                        bin_sid[(size_t)bi] = 0u;
                });
            } else if (nwords == 1u) {
                std::unordered_map<uint64, uint32> sid_by_sig;
                sid_by_sig.reserve((size_t)std::min<uint64>(active_bins.count(), 65536u));
                active_bins.for_each_set([&](uint32 bi) {
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        return;
                    uint64 sig = 0ULL;
                    build_bin_sig_words(target_bin_cat->bins[(size_t)bi], &sig, nullptr);
                    sig &= ~const_word_mask[0];

                    uint32 sid = UINT32_MAX;
                    auto it = sid_by_sig.find(sig);
                    if (it == sid_by_sig.end()) {
                        sid = sid_count++;
                        sid_by_sig.emplace(sig, sid);
                        sid_words_flat.push_back(sig);
                    } else {
                        sid = it->second;
                    }
                    bin_sid[(size_t)bi] = sid;
                });
            } else {
                struct SigEntry {
                    std::vector<uint64> words;
                    uint32 sid = 0;
                };
                std::unordered_map<uint64, std::vector<SigEntry>> buckets;
                buckets.reserve((size_t)std::min<uint64>(active_bins.count(), 32768u));
                std::vector<uint64> sig_words((size_t)nwords, 0ULL);
                active_bins.for_each_set([&](uint32 bi) {
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        return;
                    build_bin_sig_words(target_bin_cat->bins[(size_t)bi], nullptr, &sig_words);
                    for (uint32 w = 0; w < nwords; w++)
                        sig_words[(size_t)w] &= ~const_word_mask[(size_t)w];

                    uint64 h = 1469598103934665603ULL;
                    for (uint32 w = 0; w < nwords; w++)
                        h = hash_combine64(h, sig_words[(size_t)w]);
                    uint32 sid = UINT32_MAX;
                    auto &bucket = buckets[h];
                    for (const SigEntry &e : bucket) {
                        if (e.words == sig_words) {
                            sid = e.sid;
                            break;
                        }
                    }
                    if (sid == UINT32_MAX) {
                        sid = sid_count++;
                        SigEntry ent;
                        ent.sid = sid;
                        ent.words = sig_words;
                        bucket.push_back(std::move(ent));
                        sid_words_flat.insert(sid_words_flat.end(), sig_words.begin(), sig_words.end());
                    }
                    bin_sid[(size_t)bi] = sid;
                });
            }
        } else {

        if (nbits == 0u) {
            sid_count = 1u;
            if (use_active_rows) {
                for (uint32 rid : active_rids)
                    row_sid[rid] = 0u;
            } else {
                std::fill(row_sid.begin(), row_sid.end(), 0u);
            }
            sid_words_flat.push_back(0ULL);
        } else if (nwords == 1u) {
            std::unordered_map<uint64, uint32> sid_by_sig;
            sid_by_sig.reserve((size_t)std::min<uint32>(build_rows, 65536u));
            for (uint32 base = 0; base < build_rows; base += kSigBlockRows) {
                uint32 rows_in_block = std::min<uint32>(kSigBlockRows, build_rows - base);
                sig_block_words.assign((size_t)rows_in_block, 0ULL);

                for (const MaskFeatureGroup &g : mask_groups) {
                    if (!g.mask)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        if (!g.mask->test(rid))
                            continue;
                        sig_block_words[(size_t)i] |= g.packed_word;
                    }
                }

                for (const HubFeatureGroup &g : hub_groups) {
                    if (!g.dom || !g.tok)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        int32 tv = (*(g.tok))[rid];
                        if (tv < 0 || (uint32)tv >= g.dom->nbits() || !g.dom->test((uint32)tv))
                            continue;
                        sig_block_words[(size_t)i] |= g.packed_word;
                    }
                }

                for (const CmpFeatureEval &cf : cmp_features_eval) {
                    if (!cf.cmp || !cf.cmp->target_tok)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        int32 tv = (*(cf.cmp->target_tok))[rid];
                        if (tv < 0)
                            continue;
                        int32 rk = rank_or_identity(cf.cmp->rank, tv);
                        bool ok = false;
                        if (cf.cmp->group_hub_idx >= 0 && cf.cmp->target_group_tok) {
                            int32 gtok = (*(cf.cmp->target_group_tok))[rid];
                            if (gtok >= 0) {
                                auto it = cf.cmp->by_group.find(gtok);
                                if (it != cf.cmp->by_group.end())
                                    ok = tok_vs_summary(cf.cmp->op, tv, rk, it->second);
                                else
                                    ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                            } else {
                                ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                            }
                        } else {
                            ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                        }
                        if (ok)
                            sig_block_words[(size_t)i] |= cf.bit_mask;
                    }
                }

                for (const WitnessFeatureEval &wf : witness_features_eval) {
                    if (wf.target_toks.empty() || wf.target_supports.empty())
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        bool ok = false;
                        size_t nref = std::min(wf.target_toks.size(), wf.target_supports.size());
                        for (size_t ri = 0; ri < nref; ri++) {
                            int32 tv = (*(wf.target_toks[ri]))[rid];
                            if (tv < 0)
                                continue;
                            const DenseBits *supp = wf.target_supports[ri];
                            if (supp && (uint32)tv < supp->nbits() && supp->test((uint32)tv)) {
                                ok = true;
                                break;
                            }
                        }
                        if (ok)
                            sig_block_words[(size_t)i] |= wf.bit_mask;
                    }
                }

                for (uint32 i = 0; i < rows_in_block; i++) {
                    uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                    uint64 sig = sig_block_words[(size_t)i];
                    uint32 sid = UINT32_MAX;
                    auto it = sid_by_sig.find(sig);
                    if (it == sid_by_sig.end()) {
                        sid = sid_count++;
                        sid_by_sig.emplace(sig, sid);
                        sid_words_flat.push_back(sig);
                    } else {
                        sid = it->second;
                    }
                    row_sid[rid] = sid;
                }
            }
        } else {
            struct SigEntry {
                std::vector<uint64> words;
                uint32 sid = 0;
            };
            std::unordered_map<uint64, std::vector<SigEntry>> buckets;
            buckets.reserve((size_t)std::min<uint32>(build_rows, 32768u));
            sig_block_words.reserve((size_t)kSigBlockRows * nwords);
            for (uint32 base = 0; base < build_rows; base += kSigBlockRows) {
                uint32 rows_in_block = std::min<uint32>(kSigBlockRows, build_rows - base);
                sig_block_words.assign((size_t)rows_in_block * nwords, 0ULL);

                for (const MaskFeatureGroup &g : mask_groups) {
                    if (!g.mask)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        if (!g.mask->test(rid))
                            continue;
                        size_t row_base = (size_t)i * nwords;
                        for (const auto &wm : g.packed_words)
                            sig_block_words[row_base + wm.first] |= wm.second;
                    }
                }

                for (const HubFeatureGroup &g : hub_groups) {
                    if (!g.dom || !g.tok)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        int32 tv = (*(g.tok))[rid];
                        if (tv < 0 || (uint32)tv >= g.dom->nbits() || !g.dom->test((uint32)tv))
                            continue;
                        size_t row_base = (size_t)i * nwords;
                        for (const auto &wm : g.packed_words)
                            sig_block_words[row_base + wm.first] |= wm.second;
                    }
                }

                for (const CmpFeatureEval &cf : cmp_features_eval) {
                    if (!cf.cmp || !cf.cmp->target_tok)
                        continue;
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        int32 tv = (*(cf.cmp->target_tok))[rid];
                        if (tv < 0)
                            continue;
                        int32 rk = rank_or_identity(cf.cmp->rank, tv);
                        bool ok = false;
                        if (cf.cmp->group_hub_idx >= 0 && cf.cmp->target_group_tok) {
                            int32 gtok = (*(cf.cmp->target_group_tok))[rid];
                            if (gtok < 0)
                                continue;
                            auto it = cf.cmp->by_group.find(gtok);
                            if (it == cf.cmp->by_group.end())
                                continue;
                            ok = tok_vs_summary(cf.cmp->op, tv, rk, it->second);
                        } else {
                            ok = tok_vs_summary(cf.cmp->op, tv, rk, cf.cmp->global_summary);
                        }
                        if (ok) {
                            size_t row_base = (size_t)i * nwords;
                            sig_block_words[row_base + cf.word_idx] |= cf.bit_mask;
                        }
                    }
                }

                for (const WitnessFeatureEval &wf : witness_features_eval) {
                    if (wf.target_toks.empty() || wf.target_supports.empty())
                        continue;
                    size_t nref = std::min(wf.target_toks.size(), wf.target_supports.size());
                    for (uint32 i = 0; i < rows_in_block; i++) {
                        uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                        bool ok = false;
                        for (size_t ri = 0; ri < nref; ri++) {
                            int32 tv = (*(wf.target_toks[ri]))[rid];
                            if (tv < 0)
                                continue;
                            const DenseBits *supp = wf.target_supports[ri];
                            if (supp && (uint32)tv < supp->nbits() && supp->test((uint32)tv)) {
                                ok = true;
                                break;
                            }
                        }
                        if (ok) {
                            size_t row_base = (size_t)i * nwords;
                            sig_block_words[row_base + wf.word_idx] |= wf.bit_mask;
                        }
                    }
                }

                for (uint32 i = 0; i < rows_in_block; i++) {
                    size_t row_base = (size_t)i * nwords;
                    uint64 h = 1469598103934665603ULL;
                    for (uint32 w = 0; w < nwords; w++)
                        h = hash_combine64(h, sig_block_words[row_base + w]);
                    uint32 sid = UINT32_MAX;
                    auto &bucket = buckets[h];
                    for (const SigEntry &e : bucket) {
                        bool same = true;
                        for (uint32 w = 0; w < nwords; w++) {
                            if (e.words[(size_t)w] != sig_block_words[row_base + w]) {
                                same = false;
                                break;
                            }
                        }
                        if (same) {
                            sid = e.sid;
                            break;
                        }
                    }
                    if (sid == UINT32_MAX) {
                        sid = sid_count++;
                        SigEntry ent;
                        ent.sid = sid;
                        ent.words.assign(sig_block_words.begin() + row_base,
                                         sig_block_words.begin() + (row_base + nwords));
                        bucket.push_back(std::move(ent));
                        sid_words_flat.insert(sid_words_flat.end(),
                                              sig_block_words.begin() + row_base,
                                              sig_block_words.begin() + (row_base + nwords));
                    }
                    uint32 rid = use_active_rows ? active_rids[(size_t)base + i] : (base + i);
                    row_sid[rid] = sid;
                }
            }
        }
        }
        auto t_sig1 = Clock::now();
        auto t_sat0 = Clock::now();
        cvc5_allowed_sids_postfix(ast_toks,
                                  ast_ntok,
                                  sig_atom_ids,
                                  const_atom_values,
                                  atom_alias,
                                  sid_words_flat,
                                  nbits,
                                  nwords,
                                  &sid_allowed);
        auto t_sat1 = Clock::now();
        double sat_ms_local = Ms(t_sat1 - t_sat0).count();

        uint32 total_sids = sid_count;
        uint32 allowed_sids = 0;
        for (uint8_t v : sid_allowed)
            allowed_sids += (v != 0u);

        if (allowed_sids == 0u) {
            out->table = pstrdup(target.c_str());
            out->block_words = nullptr;
            out->block_ids = nullptr;
            out->blocks = 0u;
            out->total_blocks = target_td->total_blocks;
            out->n_rows = target_td->manifest.nrows;
            out->allowed_rows = 0u;
            out->allowed_sids = 0u;
            out->total_sids = total_sids;
            out->hub_prop_ms = Ms(t_prop1 - t_prop0).count();
            out->sat_ms = sat_ms_local;
            out->sid_build_ms = Ms(t_sig1 - t_sig0).count();
            out->mode_hint = POLICY_MODE_HINT_EMPTY;
            out->mode_reason = pstrdup("sat_no_allowed_sid");
            DenseBits allow_none(target_td->manifest.nrows);
            allow_none.clear_all();
            policy_allow_mask_cache_[target] = allow_none;
            maybe_store_allow_cache(allow_none);
            note_allow_cache_build_time();
            if (profile_) {
                double build_hubs_ms_local = Ms(t_hub1 - t_hub0).count();
                double composite_stamp_ms_local = stamp_ms_local;
                double build_ctx_ms_local = Ms(t_prop1 - t_prop0).count();
                double signature_ms_local = Ms(t_sig1 - t_sig0).count();
                profile_->build_hubs_ms += build_hubs_ms_local;
                profile_->composite_stamp_ms += composite_stamp_ms_local;
                profile_->build_context_ms += build_ctx_ms_local;
                profile_->prop_build_arcs_ms += prop_build_arcs_ms_local;
                profile_->prop_ac_ms += prop_ac_ms_local;
                profile_->prop_scc_ms += prop_scc_ms_local;
                profile_->prop_bin_catalog_ms += prop_bin_catalog_ms_local;
                profile_->prop_witness_ms += prop_witness_ms_local;
                profile_->prop_cmp_ms += prop_cmp_ms_local;
                profile_->semantic_dedup_ms += semantic_dedup_ms_local;
                profile_->candidate_prune_ms += candidate_prune_ms_local;
                profile_->sig_const_fold_ms += sig_const_fold_ms_local;
                profile_->signature_build_ms += signature_ms_local;
                profile_->sat_ms += sat_ms_local;
                profile_->project_allowset_ms += 0.0;
                profile_->atoms_ms += build_hubs_ms_local;
                profile_->stamp_ms += composite_stamp_ms_local;
                profile_->propagate_ms += build_ctx_ms_local;
                profile_->bin_ms += 0.0;
                profile_->local_sat_ms += sat_ms_local;
                profile_->project_ms += 0.0;
                profile_->sat_calls++;
                profile_->bin_build_rows_scanned += bin_build_rows_scanned_local;
                profile_->bin_count_final += bin_count_final_local;
                profile_->bin_build_probe_steps += bin_build_probe_steps_local;
                profile_->bin_build_max_probe_len =
                    std::max<uint64>(profile_->bin_build_max_probe_len, bin_build_max_probe_len_local);
                profile_->bin_build_rehash_count += bin_build_rehash_count_local;
                profile_->bin_build_hub_count += bin_build_hub_count_local;
                profile_->bin_build_local_atom_count += bin_build_local_atom_count_local;
                profile_->bin_build_extra_count += bin_build_extra_count_local;
                if (any_empty_domain)
                    profile_->terms_total++;
            }
            return true;
        }

        bool target_base_all =
            (!target_base_rows || target_base_rows->count() >= (uint64)nrows);
        if (allowed_sids == total_sids &&
            candidate_rows_pre_sig >= (uint64)nrows &&
            target_base_all) {
            out->table = pstrdup(target.c_str());
            out->block_words = nullptr;
            out->block_ids = nullptr;
            out->blocks = 0u;
            out->total_blocks = target_td->total_blocks;
            out->n_rows = target_td->manifest.nrows;
            out->allowed_rows = target_td->manifest.nrows;
            out->allowed_sids = allowed_sids;
            out->total_sids = total_sids;
            out->hub_prop_ms = Ms(t_prop1 - t_prop0).count();
            out->sat_ms = sat_ms_local;
            out->sid_build_ms = Ms(t_sig1 - t_sig0).count();
            out->mode_hint = POLICY_MODE_HINT_ALL;
            out->mode_reason = pstrdup("all_sids_allowed");
            DenseBits allow_all(target_td->manifest.nrows);
            allow_all.fill_all();
            policy_allow_mask_cache_[target] = allow_all;
            maybe_store_allow_cache(allow_all);
            note_allow_cache_build_time();
            if (profile_) {
                double build_hubs_ms_local = Ms(t_hub1 - t_hub0).count();
                double composite_stamp_ms_local = stamp_ms_local;
                double build_ctx_ms_local = Ms(t_prop1 - t_prop0).count();
                double signature_ms_local = Ms(t_sig1 - t_sig0).count();
                profile_->build_hubs_ms += build_hubs_ms_local;
                profile_->composite_stamp_ms += composite_stamp_ms_local;
                profile_->build_context_ms += build_ctx_ms_local;
                profile_->prop_build_arcs_ms += prop_build_arcs_ms_local;
                profile_->prop_ac_ms += prop_ac_ms_local;
                profile_->prop_scc_ms += prop_scc_ms_local;
                profile_->prop_bin_catalog_ms += prop_bin_catalog_ms_local;
                profile_->prop_witness_ms += prop_witness_ms_local;
                profile_->prop_cmp_ms += prop_cmp_ms_local;
                profile_->semantic_dedup_ms += semantic_dedup_ms_local;
                profile_->candidate_prune_ms += candidate_prune_ms_local;
                profile_->sig_const_fold_ms += sig_const_fold_ms_local;
                profile_->signature_build_ms += signature_ms_local;
                profile_->sat_ms += sat_ms_local;
                profile_->project_allowset_ms += 0.0;
                profile_->atoms_ms += build_hubs_ms_local;
                profile_->stamp_ms += composite_stamp_ms_local;
                profile_->propagate_ms += build_ctx_ms_local;
                profile_->bin_ms += 0.0;
                profile_->local_sat_ms += sat_ms_local;
                profile_->project_ms += 0.0;
                profile_->sat_calls++;
                profile_->allow_rows_total += target_td->manifest.nrows;
                profile_->bin_build_rows_scanned += bin_build_rows_scanned_local;
                profile_->bin_count_final += bin_count_final_local;
                profile_->bin_build_probe_steps += bin_build_probe_steps_local;
                profile_->bin_build_max_probe_len =
                    std::max<uint64>(profile_->bin_build_max_probe_len, bin_build_max_probe_len_local);
                profile_->bin_build_rehash_count += bin_build_rehash_count_local;
                profile_->bin_build_hub_count += bin_build_hub_count_local;
                profile_->bin_build_local_atom_count += bin_build_local_atom_count_local;
                profile_->bin_build_extra_count += bin_build_extra_count_local;
                if (any_empty_domain)
                    profile_->terms_total++;
            }
            return true;
        }

        if (allowed_sids == 0u && ast_toks && ast_ntok > 0 && sid_count > 0u && nbits > 0u) {
            std::unordered_set<int> ast_atom_ids;
            ast_atom_ids.reserve((size_t)ast_ntok * 2u + 1u);
            for (int i = 0; i < ast_ntok; i++) {
                const PolicyAstTokC &tk = ast_toks[i];
                if (tk.kind == POLICY_AST_TOK_VAR && tk.value > 0)
                    ast_atom_ids.insert(tk.value);
            }

            std::vector<uint64> sid_rows(sid_count, 0ULL);
            if (use_bin_signatures && target_bin_cat) {
                for (uint32 bi = 0; bi < bin_sid.size(); bi++) {
                    uint32 sid = bin_sid[(size_t)bi];
                    if (sid >= sid_rows.size())
                        continue;
                    if ((size_t)bi >= target_bin_cat->bins.size())
                        continue;
                    if (target_base_rows &&
                        target_bin_cat->bin_offsets.size() == target_bin_cat->bins.size() + 1u &&
                        !target_bin_cat->bin_rids.empty()) {
                        uint32 b = target_bin_cat->bin_offsets[(size_t)bi];
                        uint32 e = target_bin_cat->bin_offsets[(size_t)bi + 1u];
                        uint64 cnt = 0;
                        for (uint32 pos = b; pos < e; pos++) {
                            if ((size_t)pos >= target_bin_cat->bin_rids.size())
                                break;
                            uint32 rid = target_bin_cat->bin_rids[(size_t)pos];
                            if (rid < target_base_rows->nbits() && target_base_rows->test(rid))
                                cnt++;
                        }
                        sid_rows[(size_t)sid] += cnt;
                    } else {
                        sid_rows[(size_t)sid] += (uint64)target_bin_cat->bins[(size_t)bi].count;
                    }
                }
            } else {
                for (uint32 rid = 0; rid < nrows; rid++) {
                    uint32 sid = row_sid[rid];
                    if (sid < sid_rows.size())
                        sid_rows[sid]++;
                }
            }

            std::vector<uint64> true_rows_by_bit((size_t)nbits, 0ULL);
            for (uint32 sid = 0; sid < sid_count; sid++) {
                uint64 rows_for_sid = sid_rows[sid];
                if (rows_for_sid == 0)
                    continue;
                size_t base = (size_t)sid * (size_t)nwords;
                for (uint32 bit = 0; bit < nbits; bit++) {
                    uint64 w = sid_words_flat[base + (bit >> 6)];
                    if (((w >> (bit & 63u)) & 1ULL) != 0ULL)
                        true_rows_by_bit[(size_t)bit] += rows_for_sid;
                }
            }

            std::string sig_diag;
            for (uint32 bit = 0; bit < nbits && (size_t)bit < sig_atom_ids.size(); bit++) {
                int aid = sig_atom_ids[(size_t)bit];
                if (!ast_atom_ids.empty() && ast_atom_ids.find(aid) == ast_atom_ids.end())
                    continue;
                if (!sig_diag.empty())
                    sig_diag.push_back(',');
                sig_diag += "y";
                sig_diag += std::to_string(aid);
                sig_diag += ":";
                sig_diag += std::to_string((unsigned long long)true_rows_by_bit[(size_t)bit]);
            }

            std::string const_diag;
            for (const auto &kv : const_atom_values) {
                int aid = kv.first;
                if (!ast_atom_ids.empty() && ast_atom_ids.find(aid) == ast_atom_ids.end())
                    continue;
                if (!const_diag.empty())
                    const_diag.push_back(',');
                const_diag += "y";
                const_diag += std::to_string(aid);
                const_diag += ":";
                const_diag += (kv.second ? "1" : "0");
            }

            elog(NOTICE,
                 "policy_sig_diag: table=%s allowed_sids=0 total_sids=%u nbits=%u ast_ntok=%d sig_true_rows=[%s] const_vals=[%s]",
                 target.c_str(),
                 total_sids,
                 nbits,
                 ast_ntok,
                 sig_diag.c_str(),
                 const_diag.c_str());
        }

        auto t_proj0 = Clock::now();
        auto project_row = [&](uint32 rid) {
            allow_mask.set(rid);
            int32 blk_i = target_td->ctid_blk[rid];
            int32 off_i = target_td->ctid_off[rid];
            if (blk_i < 0 || off_i < 1 || off_i > (int32)kMaxOff)
                return;
            uint32 blk = (uint32)blk_i;
            uint32 off0 = (uint32)off_i - 1u;
            size_t base = (size_t)blk * kWordsPerBlock;
            dense[base + (off0 >> 6)] |= (1ULL << (off0 & 63u));
            if (!touched[blk]) {
                touched[blk] = 1u;
                block_ids.push_back(blk);
            }
            allowed_rows++;
        };
        if (use_bin_signatures) {
            bool have_bin_csr =
                (target_bin_cat &&
                 target_bin_cat->bin_offsets.size() == target_bin_cat->bins.size() + 1u &&
                 !target_bin_cat->bin_rids.empty());
            if (have_bin_csr) {
                DenseBits allowed_bins((uint32)target_bin_cat->bins.size());
                allowed_bins.clear_all();
                for (uint32 bi = 0; bi < (uint32)bin_sid.size(); bi++) {
                    uint32 sid = bin_sid[(size_t)bi];
                    if (sid < sid_allowed.size() && sid_allowed[(size_t)sid] != 0u)
                        allowed_bins.set(bi);
                }
                allowed_bins.for_each_set([&](uint32 bi) {
                    if ((size_t)bi + 1u >= target_bin_cat->bin_offsets.size())
                        return;
                    uint32 b = target_bin_cat->bin_offsets[(size_t)bi];
                    uint32 e = target_bin_cat->bin_offsets[(size_t)bi + 1u];
                    for (uint32 pos = b; pos < e; pos++) {
                        if ((size_t)pos >= target_bin_cat->bin_rids.size())
                            break;
                        uint32 rid = target_bin_cat->bin_rids[(size_t)pos];
                        if (rid >= nrows)
                            continue;
                        if (target_base_rows && !target_base_rows->test(rid))
                            continue;
                        project_row(rid);
                    }
                });
            } else {
                auto sid_for_rid = [&](uint32 rid) -> uint32 {
                    if (!target_bin_cat || (size_t)rid >= target_bin_cat->row_to_bin.size())
                        return UINT32_MAX;
                    uint32 bi = target_bin_cat->row_to_bin[(size_t)rid];
                    if (bi >= bin_sid.size())
                        return UINT32_MAX;
                    if (candidate_bins.nbits() == bin_sid.size() && !candidate_bins.test(bi))
                        return UINT32_MAX;
                    return bin_sid[(size_t)bi];
                };
                for (uint32 rid = 0; rid < nrows; rid++) {
                    if (target_base_rows && !target_base_rows->test(rid))
                        continue;
                    uint32 sid = sid_for_rid(rid);
                    if (sid >= sid_allowed.size() || sid_allowed[sid] == 0u)
                        continue;
                    project_row(rid);
                }
            }
        } else if (use_active_rows) {
            for (uint32 rid : active_rids) {
                uint32 sid = row_sid[rid];
                if (sid >= sid_allowed.size() || sid_allowed[sid] == 0u)
                    continue;
                project_row(rid);
            }
        } else {
            for (uint32 rid = 0; rid < nrows; rid++) {
                uint32 sid = row_sid[rid];
                if (sid >= sid_allowed.size() || sid_allowed[sid] == 0u)
                    continue;
                project_row(rid);
            }
        }
        std::sort(block_ids.begin(), block_ids.end());
        std::vector<uint64> block_words;
        block_words.reserve((size_t)block_ids.size() * kWordsPerBlock);
        for (uint32 blk : block_ids) {
            size_t base = (size_t)blk * kWordsPerBlock;
            for (uint32 w = 0; w < kWordsPerBlock; w++)
                block_words.push_back(dense[base + w]);
        }
        auto t_proj1 = Clock::now();

        double density = (target_td->manifest.nrows > 0)
                             ? (double)allowed_rows / (double)target_td->manifest.nrows
                             : 0.0;
        double page_density = (target_td->total_blocks > 0)
                                  ? (double)block_ids.size() / (double)target_td->total_blocks
                                  : 0.0;

        int mode_hint = POLICY_MODE_HINT_FILTER;
        const char *mode_reason = "dense_allow_set";
        if (allowed_rows == 0) {
            mode_hint = POLICY_MODE_HINT_EMPTY;
            mode_reason = "empty_allow_set";
        } else if (target_td->manifest.nrows > 0 && allowed_rows >= (uint64)target_td->manifest.nrows) {
            mode_hint = POLICY_MODE_HINT_ALL;
            mode_reason = "all_allow_set";
            block_ids.clear();
            block_words.clear();
        } else {
            static constexpr double kTidRowDensityCutoff = 0.02;
            static constexpr double kTidPageDensityCutoff = 0.30;
            static constexpr double kTidPageDensityCutoffSmallRows = 0.40;
            static constexpr uint64 kTidRowsCutoff = 4096ULL;

            bool sparse_density_tid =
                (target_td->total_blocks > 0 &&
                 density <= kTidRowDensityCutoff &&
                 page_density <= kTidPageDensityCutoff);
            bool small_cardinality_tid =
                (target_td->total_blocks > 0 &&
                 allowed_rows <= kTidRowsCutoff &&
                 page_density <= kTidPageDensityCutoffSmallRows);

            if (sparse_density_tid) {
                mode_hint = POLICY_MODE_HINT_TID;
                mode_reason = "sparse_allow_set";
            } else if (small_cardinality_tid) {
                mode_hint = POLICY_MODE_HINT_TID;
                mode_reason = "small_allow_set";
            }
        }

        uint64 *words_out = nullptr;
        uint32 *ids_out = nullptr;

        if (!block_words.empty()) {
            size_t bytes = block_words.size() * sizeof(uint64);
            words_out = (uint64 *)palloc0(bytes);
            std::memcpy(words_out, block_words.data(), bytes);
        }
        if (!block_ids.empty()) {
            size_t bytes = block_ids.size() * sizeof(uint32);
            ids_out = (uint32 *)palloc0(bytes);
            std::memcpy(ids_out, block_ids.data(), bytes);
        }

        out->table = pstrdup(target.c_str());
        out->block_words = words_out;
        out->block_ids = ids_out;
        out->blocks = (uint32)block_ids.size();
        out->total_blocks = target_td->total_blocks;
        out->n_rows = target_td->manifest.nrows;
        out->allowed_rows = allowed_rows;
        out->allowed_sids = allowed_sids;
        out->total_sids = total_sids;
        out->hub_prop_ms = Ms(t_prop1 - t_prop0).count();
        out->sat_ms = sat_ms_local;
        out->sid_build_ms = Ms(t_sig1 - t_sig0).count();
        out->mode_hint = mode_hint;
        out->mode_reason = pstrdup(mode_reason);
        policy_allow_mask_cache_[target] = allow_mask;
        maybe_store_allow_cache(allow_mask);
        note_allow_cache_build_time();

        if (profile_) {
            double build_hubs_ms_local = Ms(t_hub1 - t_hub0).count();
            double composite_stamp_ms_local = stamp_ms_local;
            double build_ctx_ms_local = Ms(t_prop1 - t_prop0).count();
            double signature_ms_local = Ms(t_sig1 - t_sig0).count();
            double project_ms_local = Ms(t_proj1 - t_proj0).count();

            profile_->build_hubs_ms += build_hubs_ms_local;
            profile_->composite_stamp_ms += composite_stamp_ms_local;
            profile_->build_context_ms += build_ctx_ms_local;
            profile_->prop_build_arcs_ms += prop_build_arcs_ms_local;
            profile_->prop_ac_ms += prop_ac_ms_local;
            profile_->prop_scc_ms += prop_scc_ms_local;
            profile_->prop_bin_catalog_ms += prop_bin_catalog_ms_local;
            profile_->prop_witness_ms += prop_witness_ms_local;
            profile_->prop_cmp_ms += prop_cmp_ms_local;
            profile_->semantic_dedup_ms += semantic_dedup_ms_local;
            profile_->candidate_prune_ms += candidate_prune_ms_local;
            profile_->sig_const_fold_ms += sig_const_fold_ms_local;
            profile_->signature_build_ms += signature_ms_local;
            profile_->sat_ms += sat_ms_local;
            profile_->project_allowset_ms += project_ms_local;

            profile_->atoms_ms += build_hubs_ms_local;
            profile_->stamp_ms += composite_stamp_ms_local;
            profile_->propagate_ms += build_ctx_ms_local;
            profile_->bin_ms += signature_ms_local;
            profile_->local_sat_ms += sat_ms_local;
            profile_->project_ms += project_ms_local;
            profile_->sat_calls++;
            profile_->sat_models_total += allowed_sids;
            profile_->allow_rows_total += allowed_rows;
            profile_->bytes_block_words += block_words.size() * sizeof(uint64) + block_ids.size() * sizeof(uint32);
            profile_->prop_iters += prop_iters;
            profile_->project_n_join_evals_max = std::max<int>(profile_->project_n_join_evals_max, (int)domain_prunes);
            profile_->bin_build_rows_scanned += bin_build_rows_scanned_local;
            profile_->bin_count_final += bin_count_final_local;
            profile_->bin_build_probe_steps += bin_build_probe_steps_local;
            profile_->bin_build_max_probe_len =
                std::max<uint64>(profile_->bin_build_max_probe_len, bin_build_max_probe_len_local);
            profile_->bin_build_rehash_count += bin_build_rehash_count_local;
            profile_->bin_build_hub_count += bin_build_hub_count_local;
            profile_->bin_build_local_atom_count += bin_build_local_atom_count_local;
            profile_->bin_build_extra_count += bin_build_extra_count_local;
            if (any_empty_domain)
                profile_->terms_total++;
        }

        int max_scc_size = 0;
        int scc_count = 0;
        int arcs_count = 0;
        for (const auto &ckv : context_cache) {
            const ContextState &ctx = ckv.second;
            arcs_count = std::max<int>(arcs_count, (int)ctx.arc_adjs.size());
            scc_count = std::max<int>(scc_count, (int)ctx.sccs.size());
            for (const auto &comp : ctx.sccs)
                max_scc_size = std::max<int>(max_scc_size, (int)comp.size());
        }
        std::string decoded_cols;
        for (const std::string &t : tables) {
            TableArtifact *tdp = require_table(t);
            if (!decoded_cols.empty())
                decoded_cols.push_back(';');
            decoded_cols += t;
            decoded_cols.push_back(':');
            decoded_cols += std::to_string(tdp ? tdp->col_tokens.size() : 0u);
        }
        double bin_build_avg_probe_len_local =
            (bin_build_rows_scanned_local > 0)
                ? ((double)bin_build_probe_steps_local / (double)bin_build_rows_scanned_local)
                : 0.0;
        elog(NOTICE,
             "policy_profile_target: table=%s n_rows=%u allowed_rows=%llu density=%.6f mode_hint=%d "
             "nfeatures=%u features_raw=%u features_dedup=%u dedup_removed=%llu const_folded=%llu "
             "ast_ntok=%d total_sids=%u allowed_sids=%u hubs=%zu arcs=%d scc_count=%d max_scc_size=%d "
             "contexts_cached=%zu contexts_built=%llu contexts_total=%llu contexts_pruned_superset=%llu "
             "table_support_cache_hits=%llu table_support_cache_misses=%llu "
             "arc_adj_cache_hits=%llu arc_adj_cache_misses=%llu "
             "prop_bin_catalog_ms=%.3f prop_witness_ms=%.3f prop_cmp_ms=%.3f "
             "semantic_dedup_ms=%.3f candidate_prune_ms=%.3f sig_const_fold_ms=%.3f "
             "bin_build_rows_scanned=%llu bin_count_final=%llu bin_build_avg_probe_len=%.3f "
             "bin_build_max_probe_len=%llu bin_build_rehash_count=%llu "
             "bin_build_hub_count=%llu bin_build_local_atom_count=%llu bin_build_extra_count=%llu "
             "mandatory_atoms_count=%llu candidate_rows_pre_sig=%llu witness_memo_hits=%llu witness_memo_misses=%llu "
             "decoded_cols_count=%s",
             target.c_str(),
             target_td->manifest.nrows,
             (unsigned long long)allowed_rows,
             density,
             mode_hint,
             nbits,
             raw_feature_count,
             dedup_feature_count,
             (unsigned long long)dedup_removed,
             (unsigned long long)const_folded,
             ast_ntok,
             total_sids,
             allowed_sids,
             hubs.size(),
             arcs_count,
             scc_count,
             max_scc_size,
             context_cache.size(),
             (unsigned long long)context_builds,
             (unsigned long long)contexts_total_terms,
             (unsigned long long)contexts_pruned_superset,
             (unsigned long long)table_support_cache_hits,
             (unsigned long long)table_support_cache_misses,
             (unsigned long long)arc_adj_cache_hits,
             (unsigned long long)arc_adj_cache_misses,
             prop_bin_catalog_ms_local,
             prop_witness_ms_local,
             prop_cmp_ms_local,
             semantic_dedup_ms_local,
             candidate_prune_ms_local,
             sig_const_fold_ms_local,
             (unsigned long long)bin_build_rows_scanned_local,
             (unsigned long long)bin_count_final_local,
             bin_build_avg_probe_len_local,
             (unsigned long long)bin_build_max_probe_len_local,
             (unsigned long long)bin_build_rehash_count_local,
             (unsigned long long)bin_build_hub_count_local,
             (unsigned long long)bin_build_local_atom_count_local,
             (unsigned long long)bin_build_extra_count_local,
             (unsigned long long)mandatory_atoms_count,
             (unsigned long long)candidate_rows_pre_sig,
             (unsigned long long)witness_memo_hits,
             (unsigned long long)witness_memo_misses,
             decoded_cols.c_str());
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

    static cvc5::Term mk_bool_assign_term(cvc5::Solver *solver, const cvc5::Term &var, bool value)
    {
        if (!solver)
            throw std::runtime_error("cvc5 solver is null");
        if (value)
            return var;
        std::vector<cvc5::Term> eq_terms;
        eq_terms.reserve(2);
        eq_terms.push_back(var);
        eq_terms.push_back(solver->mkFalse());
        return solver->mkTerm(cvc5::Kind::EQUAL, eq_terms);
    }

    static void build_row_signatures(const std::vector<DenseBits> &term_masks,
                                     uint32 nrows,
                                     std::vector<uint32> *row_sid,
                                     std::vector<uint64> *sid_words,
                                     uint32 *out_nbits,
                                     uint32 *out_nwords)
    {
        if (!row_sid || !sid_words || !out_nbits || !out_nwords)
            return;

        const uint32 nbits = (uint32)term_masks.size();
        const uint32 nwords = std::max<uint32>(1u, (nbits + 63u) / 64u);
        *out_nbits = nbits;
        *out_nwords = nwords;

        row_sid->assign(nrows, 0u);
        sid_words->clear();
        if (nrows == 0)
            return;

        sid_words->reserve((size_t)std::min<uint32>(nrows, 16384u) * nwords);
        const size_t k = term_masks.size();

        if (nwords == 1u) {
            std::unordered_map<uint64, uint32> sid_by_sig;
            sid_by_sig.reserve((size_t)std::min<uint32>(nrows, 16384u));
            for (uint32 rid = 0; rid < nrows; rid++) {
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
        by_hash.reserve((size_t)std::min<uint32>(nrows, 16384u));
        std::vector<uint64> tmp((size_t)nwords, 0ULL);

        for (uint32 rid = 0; rid < nrows; rid++) {
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
            if (tk.kind == POLICY_AST_TOK_VAR) {
                if (tk.value <= 0) {
                    st.push_back(solver->mkFalse());
                } else {
                    auto it = atom_vars.find(tk.value);
                    st.push_back((it == atom_vars.end()) ? solver->mkFalse() : it->second);
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
        ast_norm.reserve((size_t)ast_ntok);
        for (int i = 0; i < ast_ntok; i++) {
            PolicyAstTokC tk = ast_toks[i];
            if (tk.kind == POLICY_AST_TOK_VAR && tk.value > 0)
                tk.value = resolve_alias(tk.value);
            ast_norm.push_back(tk);
        }
        const PolicyAstTokC *ast_use = ast_norm.empty() ? ast_toks : ast_norm.data();
        int ast_use_ntok = ast_norm.empty() ? ast_ntok : (int)ast_norm.size();

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

    static bool prune_by_support(DenseBits *rows, const std::vector<int32> &tok, const std::vector<uint8_t> &support)
    {
        if (!rows)
            return false;
        DenseBits pruned(rows->nbits());
        pruned.clear_all();

        rows->for_each_set([&](uint32 rid) {
            int32 t = tok[rid];
            if (t < 0 || (size_t)t >= support.size())
                return;
            if (support[(size_t)t])
                pruned.set(rid);
        });

        bool changed = !pruned.equals(*rows);
        if (changed)
            *rows = std::move(pruned);
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
        for (uint32 i = 0; i < ntok; i++) {
            inter[i] = (uint8_t)(supp_l[i] & supp_r[i]);
            if (inter[i])
                any = true;
        }

        if (!any) {
            bool changed = la.any() || ra.any();
            la.clear_all();
            ra.clear_all();
            return changed;
        }

        bool changed = false;
        changed |= prune_by_support(&la, *ltok, inter);
        changed |= prune_by_support(&ra, *rtok, inter);
        return changed;
    }

    static void build_summary(const DenseBits &rows,
                              const std::vector<int32> &tok,
                              const RankData &rank,
                              uint32 ntok,
                              bool need_support,
                              CmpSummary *out)
    {
        if (!out)
            return;
        out->any = false;
        out->nonnull_count = 0;
        out->min_rank = std::numeric_limits<int32>::max();
        out->max_rank = std::numeric_limits<int32>::min();
        out->only_tok = -1;
        out->support.clear();
        if (need_support)
            out->support.assign(ntok, 0u);

        rows.for_each_set([&](uint32 rid) {
            int32 t = tok[rid];
            if (t < 0 || (uint32)t >= ntok)
                return;
            out->any = true;
            out->nonnull_count++;
            if (out->nonnull_count == 1)
                out->only_tok = t;
            int32 rk = rank_or_identity(rank, t);
            if (rk < out->min_rank)
                out->min_rank = rk;
            if (rk > out->max_rank)
                out->max_rank = rk;
            if (need_support)
                out->support[(size_t)t] = 1u;
        });
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

    static bool any_empty(const std::unordered_map<std::string, DenseBits> &active)
    {
        for (const auto &kv : active) {
            if (!kv.second.any())
                return true;
        }
        return false;
    }

    struct PairKey {
        std::string a;
        std::string b;

        bool operator==(const PairKey &o) const { return a == o.a && b == o.b; }
    };

    struct PairKeyHash {
        size_t operator()(const PairKey &k) const
        {
            return std::hash<std::string>{}(k.a) ^ (std::hash<std::string>{}(k.b) << 1);
        }
    };

    DenseBits eval_term(const std::string &target,
                        const Term &term,
                        int *iters_out,
                        int *join_evals_out)
    {
        TableArtifact *tt = require_table(target);
        if (!tt)
            ereport(ERROR, (errmsg("policy: missing target table %s", target.c_str())));

        if (iters_out)
            *iters_out = 0;
        if (join_evals_out)
            *join_evals_out = 0;

        if (term.empty()) {
            DenseBits all(tt->manifest.nrows);
            all.fill_all();
            return all;
        }

        std::unordered_set<std::string> tables;
        tables.insert(target);

        std::vector<const AtomInfo *> local_atoms;
        std::vector<const AtomInfo *> join_atoms;
        std::vector<const AtomInfo *> cross_atoms;

        for (int aid : term) {
            auto it = atom_by_id_.find(aid);
            if (it == atom_by_id_.end()) {
                DenseBits none(tt->manifest.nrows);
                none.clear_all();
                return none;
            }
            const AtomInfo &a = it->second;
            tables.insert(a.lhs.table);
            if (!a.rhs.table.empty())
                tables.insert(a.rhs.table);

            if (a.kind == POLICY_ATOM_JOIN_EQ) {
                if (a.lhs.table == a.rhs.table) {
                    local_atoms.push_back(&a);
                } else {
                    join_atoms.push_back(&a);
                }
            } else if (a.kind == POLICY_ATOM_COL_CONST) {
                local_atoms.push_back(&a);
            } else if (a.kind == POLICY_ATOM_COL_COL) {
                if (a.lhs.table == a.rhs.table)
                    local_atoms.push_back(&a);
                else
                    cross_atoms.push_back(&a);
            }
        }

        std::unordered_map<std::string, DenseBits> active;
        active.reserve(tables.size() * 2u + 1u);
        for (const std::string &t : tables) {
            TableArtifact *td = require_table(t);
            DenseBits mask(td->manifest.nrows);
            mask.fill_all();
            mask.bit_and(scan_qual_mask_for_table(t));
            active.emplace(t, std::move(mask));
        }

        for (const AtomInfo *ap : local_atoms) {
            const AtomInfo &a = *ap;
            auto it = active.find(a.lhs.table);
            if (it == active.end())
                continue;
            it->second.bit_and(local_mask_for_atom(a));
        }

        if (any_empty(active)) {
            DenseBits none(tt->manifest.nrows);
            none.clear_all();
            return none;
        }

        // Build eq constraints with composite folding per table pair.
        std::unordered_map<PairKey, std::vector<const AtomInfo *>, PairKeyHash> per_pair;
        per_pair.reserve(join_atoms.size() * 2u + 1u);
        for (const AtomInfo *ap : join_atoms) {
            PairKey k;
            if (ap->lhs.table <= ap->rhs.table) {
                k.a = ap->lhs.table;
                k.b = ap->rhs.table;
            } else {
                k.a = ap->rhs.table;
                k.b = ap->lhs.table;
            }
            per_pair[k].push_back(ap);
        }

        std::vector<EqConstraint> eqs;
        eqs.reserve(join_atoms.size());
        for (auto &kv : per_pair) {
            auto &atoms = kv.second;
            std::sort(atoms.begin(), atoms.end(), [](const AtomInfo *x, const AtomInfo *y) {
                if (x->join_class_id != y->join_class_id)
                    return x->join_class_id < y->join_class_id;
                return x->atom_id < y->atom_id;
            });

            if (atoms.size() == 1) {
                const AtomInfo *a = atoms[0];
                EqConstraint e;
                e.left_table = a->lhs.table;
                e.right_table = a->rhs.table;
                e.left_col_idxs.push_back(require_col_idx(a->lhs.table, a->lhs.col));
                e.right_col_idxs.push_back(require_col_idx(a->rhs.table, a->rhs.col));
                e.domain_id = a->join_class_id;
                e.composite = false;
                eqs.push_back(std::move(e));
                continue;
            }

            EqConstraint e;
            e.left_table = atoms[0]->lhs.table;
            e.right_table = atoms[0]->rhs.table;
            e.composite = true;
            e.domain_id = -1;
            for (const AtomInfo *a : atoms) {
                bool same_dir = (a->lhs.table == e.left_table && a->rhs.table == e.right_table);
                if (same_dir) {
                    e.left_col_idxs.push_back(require_col_idx(a->lhs.table, a->lhs.col));
                    e.right_col_idxs.push_back(require_col_idx(a->rhs.table, a->rhs.col));
                } else {
                    e.left_col_idxs.push_back(require_col_idx(a->rhs.table, a->rhs.col));
                    e.right_col_idxs.push_back(require_col_idx(a->lhs.table, a->lhs.col));
                }
            }
            eqs.push_back(std::move(e));
        }

        std::vector<CmpConstraint> cmps;
        cmps.reserve(cross_atoms.size());
        for (const AtomInfo *ap : cross_atoms) {
            CmpConstraint c;
            c.left_table = ap->lhs.table;
            c.right_table = ap->rhs.table;
            c.left_col_idx = require_col_idx(ap->lhs.table, ap->lhs.col);
            c.right_col_idx = require_col_idx(ap->rhs.table, ap->rhs.col);
            c.op = ap->op;
            c.domain_id = ap->join_class_id;

            for (size_t i = 0; i < eqs.size(); i++) {
                const EqConstraint &e = eqs[i];
                if ((e.left_table == c.left_table && e.right_table == c.right_table) ||
                    (e.left_table == c.right_table && e.right_table == c.left_table)) {
                    c.group_eq_idx = (int)i;
                    break;
                }
            }
            cmps.push_back(std::move(c));
        }

        int join_evals = 0;
        int iters = 0;

        bool changed = true;
        while (changed && iters < 24) {
            changed = false;
            iters++;

            for (EqConstraint &e : eqs) {
                changed |= apply_eq_constraint(&e, &active, &join_evals);
                if (profile_)
                    profile_->prop_join_scans_total++;
            }

            if (any_empty(active))
                break;

            bool cmp_changed = false;
            for (const CmpConstraint &c : cmps)
                cmp_changed |= apply_cmp_constraint(c, eqs, &active);

            changed |= cmp_changed;
            if (any_empty(active))
                break;
        }

        if (iters_out)
            *iters_out = iters;
        if (join_evals_out)
            *join_evals_out = join_evals;

        if (any_empty(active)) {
            DenseBits none(tt->manifest.nrows);
            none.clear_all();
            return none;
        }

        auto it_target = active.find(target);
        if (it_target != active.end())
            return it_target->second;

        bool witness_nonempty = true;
        for (const auto &kv : active) {
            if (!kv.second.any()) {
                witness_nonempty = false;
                break;
            }
        }

        DenseBits out(tt->manifest.nrows);
        if (witness_nonempty)
            out.fill_all();
        else
            out.clear_all();
        return out;
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
    std::unordered_map<std::string, TableBinCatalog> table_bin_catalog_cache_;
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
         "semantic_dedup_ms=%.3f candidate_prune_ms=%.3f sig_const_fold_ms=%.3f "
         "allow_cache_hit=%llu allow_cache_miss=%llu allow_cache_build_ms=%.3f "
         "bin_build_rows_scanned=%llu bin_count_final=%llu bin_build_avg_probe_len=%.3f "
         "bin_build_max_probe_len=%llu bin_build_rehash_count=%llu "
         "bin_build_hub_count=%llu bin_build_local_atom_count=%llu bin_build_extra_count=%llu "
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
         p.build_hubs_ms + p.artifact_parse_ms,
         p.composite_stamp_ms,
         p.build_context_ms,
         p.project_allowset_ms,
         p.signature_build_ms,
         p.prop_build_arcs_ms,
         p.prop_ac_ms,
         p.prop_scc_ms,
         p.prop_bin_catalog_ms,
         p.prop_witness_ms,
         p.prop_cmp_ms,
         p.semantic_dedup_ms,
         p.candidate_prune_ms,
         p.sig_const_fold_ms,
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
        for (const std::string &t : targets) {
            if (done.find(t) == done.end())
                build_order.push_back(t);
        }
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

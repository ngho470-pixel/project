#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" {
#include "postgres.h"
#include "executor/spi.h"
#include "storage/itemptr.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/elog.h"
#include "utils/palloc.h"
}

#include "policy_evaluator.h"

using Clock = std::chrono::steady_clock;
using Ms = std::chrono::duration<double, std::milli>;

namespace {

/* Fixed per-block bitmap layout: offsets are 1-based CTID offsets. */
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
    uint32 allowed_sids;
    uint32 total_sids;
    double hub_prop_ms;
    double sat_ms;
    double sid_build_ms;
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
} PolicyRunProfileC;

} // extern "C"

struct BuildProfile {
    double artifact_parse_ms = 0.0;
    double atoms_ms = 0.0;
    double propagate_ms = 0.0;
    double decode_ms = 0.0;
    double sat_ms = 0.0;
    double policy_total_ms = 0.0;
    uint64 sat_calls = 0;
    uint64 sat_models_total = 0;
    uint64 terms_total = 0;
    uint64 allow_rows_total = 0;
    int prop_iters = 0;
};

static inline uint64 words_for_bits(uint32 nbits)
{
    return (uint64)((nbits + 63u) / 64u);
}

struct RowBits {
    uint32 nbits = 0;
    std::vector<uint64_t> words;

    RowBits() = default;
    explicit RowBits(uint32 n) { reset(n); }

    void reset(uint32 n)
    {
        nbits = n;
        words.assign((size_t)words_for_bits(n), 0ULL);
    }

    void clear_all()
    {
        std::fill(words.begin(), words.end(), 0ULL);
    }

    void fill_all()
    {
        std::fill(words.begin(), words.end(), ~0ULL);
        trim_tail();
    }

    void set(uint32 i)
    {
        if (i >= nbits)
            return;
        words[(size_t)i >> 6] |= (1ULL << (i & 63u));
    }

    bool test(uint32 i) const
    {
        if (i >= nbits)
            return false;
        return (words[(size_t)i >> 6] & (1ULL << (i & 63u))) != 0ULL;
    }

    bool any() const
    {
        for (uint64_t w : words) {
            if (w)
                return true;
        }
        return false;
    }

    uint64 count() const
    {
        uint64 c = 0;
        for (uint64_t w : words)
            c += (uint64)__builtin_popcountll((unsigned long long)w);
        return c;
    }

    bool equals(const RowBits &o) const
    {
        return nbits == o.nbits && words == o.words;
    }

    void bit_and(const RowBits &o)
    {
        size_t n = std::min(words.size(), o.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] &= o.words[i];
        for (size_t i = n; i < words.size(); i++)
            words[i] = 0ULL;
    }

    void bit_or(const RowBits &o)
    {
        size_t n = std::min(words.size(), o.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] |= o.words[i];
    }

    void bit_not()
    {
        for (uint64_t &w : words)
            w = ~w;
        trim_tail();
    }

    template <typename Fn>
    void for_each_set(Fn &&fn) const
    {
        for (size_t wi = 0; wi < words.size(); wi++) {
            uint64_t w = words[wi];
            while (w) {
                uint64_t lsb = w & (~w + 1ULL);
                unsigned bit = (unsigned)__builtin_ctzll((unsigned long long)w);
                uint32 idx = (uint32)(wi * 64u + bit);
                if (idx < nbits)
                    fn(idx);
                w ^= lsb;
            }
        }
    }

private:
    void trim_tail()
    {
        if (nbits == 0 || words.empty())
            return;
        uint32 r = nbits & 63u;
        if (r == 0)
            return;
        uint64_t mask = (1ULL << r) - 1ULL;
        words.back() &= mask;
    }
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
    std::string out = q ? q : "public.files";
    return out;
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

struct ColRef {
    std::string table;
    std::string col;

    std::string key() const
    {
        return table + "." + col;
    }
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

struct AtomDesc {
    int atom_id = 0;
    int kind = 0;
    int op = 0;
    int join_class_id = -1;
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

struct TableData {
    std::string name;
    CodeManifest manifest;
    std::vector<int32> ctid_blk;
    std::vector<int32> ctid_off;
    uint32 total_blocks = 0;
    std::vector<std::string> cols;
    std::unordered_map<std::string, int> col_idx;
    std::unordered_map<int, std::vector<int32>> col_tokens;
};

struct DictData {
    std::vector<std::string> values;
    std::string dtype;
    std::unordered_map<std::string, int32> token_by_norm;
};

struct RankData {
    std::vector<int32> rank_by_tok;
    bool present = false;
};

enum ExprTokType {
    TOK_END = 0,
    TOK_VAR,
    TOK_AND,
    TOK_OR,
    TOK_LP,
    TOK_RP
};

struct ExprTok {
    ExprTokType type = TOK_END;
    int var_id = 0;
};

struct ExprNode {
    enum Type { VAR = 1, AND = 2, OR = 3 } type = VAR;
    int var_id = 0;
    std::unique_ptr<ExprNode> left;
    std::unique_ptr<ExprNode> right;
};

class ExprParser {
public:
    explicit ExprParser(const std::string &s) : s_(s) {}

    std::unique_ptr<ExprNode> parse()
    {
        next();
        auto root = parse_or();
        if (!root)
            return nullptr;
        if (tok_.type != TOK_END)
            return nullptr;
        return root;
    }

private:
    std::unique_ptr<ExprNode> parse_or()
    {
        auto lhs = parse_and();
        if (!lhs)
            return nullptr;
        while (tok_.type == TOK_OR) {
            next();
            auto rhs = parse_and();
            if (!rhs)
                return nullptr;
            auto p = std::make_unique<ExprNode>();
            p->type = ExprNode::OR;
            p->left = std::move(lhs);
            p->right = std::move(rhs);
            lhs = std::move(p);
        }
        return lhs;
    }

    std::unique_ptr<ExprNode> parse_and()
    {
        auto lhs = parse_primary();
        if (!lhs)
            return nullptr;
        while (tok_.type == TOK_AND) {
            next();
            auto rhs = parse_primary();
            if (!rhs)
                return nullptr;
            auto p = std::make_unique<ExprNode>();
            p->type = ExprNode::AND;
            p->left = std::move(lhs);
            p->right = std::move(rhs);
            lhs = std::move(p);
        }
        return lhs;
    }

    std::unique_ptr<ExprNode> parse_primary()
    {
        if (tok_.type == TOK_VAR) {
            auto n = std::make_unique<ExprNode>();
            n->type = ExprNode::VAR;
            n->var_id = tok_.var_id;
            next();
            return n;
        }
        if (tok_.type == TOK_LP) {
            next();
            auto n = parse_or();
            if (!n || tok_.type != TOK_RP)
                return nullptr;
            next();
            return n;
        }
        return nullptr;
    }

    static bool is_word_char(char c)
    {
        return std::isalnum((unsigned char)c) || c == '_';
    }

    void next()
    {
        skip_ws();
        if (pos_ >= s_.size()) {
            tok_ = ExprTok{TOK_END, 0};
            return;
        }
        char c = s_[pos_];
        if (c == '(') {
            pos_++;
            tok_ = ExprTok{TOK_LP, 0};
            return;
        }
        if (c == ')') {
            pos_++;
            tok_ = ExprTok{TOK_RP, 0};
            return;
        }
        if (c == 'y' || c == 'Y') {
            size_t p = pos_ + 1;
            int id = 0;
            bool any = false;
            while (p < s_.size() && std::isdigit((unsigned char)s_[p])) {
                any = true;
                id = id * 10 + (int)(s_[p] - '0');
                p++;
            }
            if (!any) {
                tok_ = ExprTok{TOK_END, 0};
                return;
            }
            pos_ = p;
            tok_ = ExprTok{TOK_VAR, id};
            return;
        }

        if (std::isalpha((unsigned char)c)) {
            size_t p = pos_;
            while (p < s_.size() && is_word_char(s_[p]))
                p++;
            std::string w = to_lower_copy(s_.substr(pos_, p - pos_));
            pos_ = p;
            if (w == "and") {
                tok_ = ExprTok{TOK_AND, 0};
                return;
            }
            if (w == "or") {
                tok_ = ExprTok{TOK_OR, 0};
                return;
            }
        }

        tok_ = ExprTok{TOK_END, 0};
    }

    void skip_ws()
    {
        while (pos_ < s_.size() && std::isspace((unsigned char)s_[pos_]))
            pos_++;
    }

    std::string s_;
    size_t pos_ = 0;
    ExprTok tok_;
};

using Term = std::vector<int>;
using Dnf = std::vector<Term>;

static void normalize_term(Term *t)
{
    if (!t)
        return;
    std::sort(t->begin(), t->end());
    t->erase(std::unique(t->begin(), t->end()), t->end());
}

static std::string term_key(const Term &t)
{
    std::string k;
    for (size_t i = 0; i < t.size(); i++) {
        if (i > 0)
            k.push_back(',');
        k += std::to_string(t[i]);
    }
    return k;
}

static Dnf dnf_from_expr(const ExprNode *n, bool *ok, uint32 *model_count_cap)
{
    if (!n) {
        *ok = false;
        return {};
    }
    if (n->type == ExprNode::VAR) {
        if (n->var_id <= 0) {
            *ok = true;
            return {};
        }
        *ok = true;
        return Dnf{Term{n->var_id}};
    }

    bool ok_l = true;
    bool ok_r = true;
    Dnf l = dnf_from_expr(n->left.get(), &ok_l, model_count_cap);
    Dnf r = dnf_from_expr(n->right.get(), &ok_r, model_count_cap);
    if (!ok_l || !ok_r) {
        *ok = false;
        return {};
    }

    if (n->type == ExprNode::OR) {
        Dnf out;
        out.reserve(l.size() + r.size());
        for (const Term &t : l)
            out.push_back(t);
        for (const Term &t : r)
            out.push_back(t);
        std::unordered_set<std::string> seen;
        Dnf uniq;
        uniq.reserve(out.size());
        for (Term &t : out) {
            normalize_term(&t);
            std::string k = term_key(t);
            if (seen.insert(k).second)
                uniq.push_back(std::move(t));
        }
        *ok = true;
        return uniq;
    }

    Dnf out;
    if (!l.empty() && !r.empty()) {
        out.reserve(l.size() * r.size());
        for (const Term &a : l) {
            for (const Term &b : r) {
                Term t;
                t.reserve(a.size() + b.size());
                t.insert(t.end(), a.begin(), a.end());
                t.insert(t.end(), b.begin(), b.end());
                normalize_term(&t);
                out.push_back(std::move(t));
                if (model_count_cap && *model_count_cap > 0 && out.size() > *model_count_cap) {
                    *ok = false;
                    return {};
                }
            }
        }
    }

    std::unordered_set<std::string> seen;
    Dnf uniq;
    uniq.reserve(out.size());
    for (Term &t : out) {
        std::string k = term_key(t);
        if (seen.insert(k).second)
            uniq.push_back(std::move(t));
    }
    *ok = true;
    return uniq;
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
    if (nz == std::string::npos)
        intp = "0";
    else
        intp = intp.substr(nz);

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
            e = e.substr(enz);
            out.push_back('e');
            if (eneg)
                out.push_back('-');
            out += e;
        }
    }

    if (out == "-0")
        out = "0";
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

class Engine {
public:
    Engine(const PolicyArtifactC *arts, int art_count, const PolicyEngineInputC *in, BuildProfile *profile)
        : resolver_(arts, art_count), in_(in), profile_(profile)
    {
        load_col_domain_meta();
        load_atoms();
    }

    bool build_target_allow(const std::string &target, const std::string &ast_str, PolicyTableAllowC *out)
    {
        if (!out)
            return false;
        std::memset(out, 0, sizeof(*out));

        auto *target_ti = require_table(target);
        if (!target_ti)
            return false;

        auto t_sat0 = Clock::now();
        std::unique_ptr<ExprNode> ast;
        if (ast_str.empty()) {
            ast.reset();
        } else {
            ExprParser parser(ast_str);
            ast = parser.parse();
            if (!ast)
                ereport(ERROR, (errmsg("policy: failed to parse target AST for %s: %s", target.c_str(), ast_str.c_str())));
        }

        bool ok = true;
        uint32 model_cap = 100000u;
        Dnf terms;
        if (!ast) {
            terms.push_back(Term{});
        } else {
            terms = dnf_from_expr(ast.get(), &ok, &model_cap);
        }
        if (!ok)
            ereport(ERROR, (errmsg("policy: DNF expansion failed for target %s", target.c_str())));

        if (profile_) {
            profile_->sat_calls++;
            profile_->sat_models_total += (uint64)terms.size();
            profile_->terms_total += (uint64)terms.size();
            profile_->sat_ms += Ms(Clock::now() - t_sat0).count();
        }

        std::vector<RowBits> term_masks;
        term_masks.reserve(terms.size());

        auto t_prop0 = Clock::now();
        for (const Term &term : terms) {
            term_masks.push_back(eval_term(target, term));
        }
        auto t_prop1 = Clock::now();
        const double hub_prop_ms = Ms(t_prop1 - t_prop0).count();
        if (profile_)
            profile_->propagate_ms += hub_prop_ms;

        RowBits allowed(target_ti->manifest.nrows);
        allowed.clear_all();
        for (const RowBits &tm : term_masks)
            allowed.bit_or(tm);

        auto t_decode0 = Clock::now();
        std::vector<uint32> block_ids;
        std::vector<uint64_t> words;
        uint64 allowed_rows = 0;
        build_sparse_allow_words(*target_ti, allowed, &block_ids, &words, &allowed_rows);

        uint32 allowed_sids = 0;
        uint32 total_sids = 0;
        compute_term_signatures(term_masks, allowed, &allowed_sids, &total_sids);

        uint64 *words_out = nullptr;
        uint32 *block_ids_out = nullptr;
        uint32 blocks = (uint32)block_ids.size();

        if (!words.empty()) {
            size_t nbytes = words.size() * sizeof(uint64_t);
            words_out = (uint64 *)palloc0(nbytes);
            std::memcpy(words_out, words.data(), nbytes);
        }
        if (!block_ids.empty()) {
            size_t nbytes = block_ids.size() * sizeof(uint32);
            block_ids_out = (uint32 *)palloc0(nbytes);
            std::memcpy(block_ids_out, block_ids.data(), nbytes);
        }

        auto t_decode1 = Clock::now();
        const double sid_build_ms = Ms(t_decode1 - t_decode0).count();

        out->table = pstrdup(target.c_str());
        out->block_words = words_out;
        out->block_ids = block_ids_out;
        out->blocks = blocks;
        out->total_blocks = target_ti->total_blocks;
        out->n_rows = target_ti->manifest.nrows;
        out->allowed_sids = allowed_sids;
        out->total_sids = total_sids;
        out->hub_prop_ms = hub_prop_ms;
        out->sat_ms = profile_ ? profile_->sat_ms : 0.0;
        out->sid_build_ms = sid_build_ms;

        if (profile_) {
            profile_->decode_ms += sid_build_ms;
            profile_->allow_rows_total += allowed_rows;
        }
        return true;
    }

private:
    struct JoinEdge {
        std::string a_table;
        std::string b_table;
        int a_col_idx = -1;
        int b_col_idx = -1;
        int domain_id = -1;
    };

    struct CrossCmp {
        std::string a_table;
        std::string b_table;
        int a_col_idx = -1;
        int b_col_idx = -1;
        int domain_id = -1;
        int op = 0;
    };

    struct CompSummary {
        bool any = false;
        uint64 nonnull_count = 0;
        int32 min_rank = 0;
        int32 max_rank = 0;
        int32 only_tok = -1;
        std::vector<uint8_t> support;
    };

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
            int did = std::atoi(v.c_str());
            col_domain_[k] = did;
        }
        if (profile_)
            profile_->artifact_parse_ms += Ms(Clock::now() - t0).count();
    }

    void load_atoms()
    {
        auto t0 = Clock::now();
        atom_by_id_.clear();
        if (!in_ || !in_->atoms || in_->atom_count <= 0) {
            if (profile_)
                profile_->atoms_ms += Ms(Clock::now() - t0).count();
            return;
        }
        atom_by_id_.reserve((size_t)in_->atom_count * 2u + 1u);
        for (int i = 0; i < in_->atom_count; i++) {
            const PolicyAtomC &a = in_->atoms[i];
            AtomDesc d;
            d.atom_id = a.atom_id;
            d.kind = a.kind;
            d.op = a.op;
            d.join_class_id = a.join_class_id;
            if (a.lhs_schema_key)
                (void)parse_schema_key(a.lhs_schema_key, &d.lhs);
            if (a.rhs_schema_key)
                (void)parse_schema_key(a.rhs_schema_key, &d.rhs);
            for (int v = 0; v < a.const_count; v++) {
                const char *cv = (a.const_values && a.const_values[v]) ? a.const_values[v] : "";
                d.const_values.emplace_back(cv);
            }
            atom_by_id_[d.atom_id] = std::move(d);
        }
        if (profile_)
            profile_->atoms_ms += Ms(Clock::now() - t0).count();
    }

    TableData *require_table(const std::string &table)
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

        TableData td;
        td.name = table;

        if (manifest_b.len < 20 || std::memcmp(manifest_b.data, "CB04", 4) != 0)
            ereport(ERROR, (errmsg("policy: invalid code manifest for %s", table.c_str())));
        size_t mp = 4;
        int32 nrows = 0, chunk_rows = 0, ncols = 0, nchunks = 0;
        if (!read_i32(manifest_b.data, manifest_b.len, &mp, &nrows) ||
            !read_i32(manifest_b.data, manifest_b.len, &mp, &chunk_rows) ||
            !read_i32(manifest_b.data, manifest_b.len, &mp, &ncols) ||
            !read_i32(manifest_b.data, manifest_b.len, &mp, &nchunks))
            ereport(ERROR, (errmsg("policy: truncated code manifest for %s", table.c_str())));

        td.manifest.nrows = (uint32)std::max(0, nrows);
        td.manifest.chunk_rows = (uint32)std::max(1, chunk_rows);
        td.manifest.ncols = (uint32)std::max(0, ncols);
        td.manifest.nchunks = (uint32)std::max(0, nchunks);

        if (ctid_b.len % (sizeof(int32) * 2u) != 0)
            ereport(ERROR, (errmsg("policy: malformed ctid artifact for %s", table.c_str())));
        size_t pairs = ctid_b.len / (sizeof(int32) * 2u);
        td.ctid_blk.resize(pairs);
        td.ctid_off.resize(pairs);
        const int32 *p = (const int32 *)ctid_b.data;
        int32 max_blk = -1;
        for (size_t i = 0; i < pairs; i++) {
            int32 blk = p[i * 2u + 0u];
            int32 off = p[i * 2u + 1u];
            td.ctid_blk[i] = blk;
            td.ctid_off[i] = off;
            if (blk > max_blk)
                max_blk = blk;
        }
        td.total_blocks = (max_blk >= 0) ? ((uint32)max_blk + 1u) : 0u;
        if (td.manifest.nrows == 0)
            td.manifest.nrows = (uint32)pairs;
        if ((uint32)pairs != td.manifest.nrows)
            ereport(ERROR,
                    (errmsg("policy: row-count mismatch for %s (manifest=%u ctid=%zu)",
                            table.c_str(), td.manifest.nrows, pairs)));

        td.cols = split_lines_blob(cols_b);
        for (size_t i = 0; i < td.cols.size(); i++) {
            std::string full = to_lower_copy(td.cols[i]);
            td.col_idx[full] = (int)i;
            size_t dot = full.find('.');
            if (dot != std::string::npos && dot + 1 < full.size()) {
                std::string c = full.substr(dot + 1);
                if (td.col_idx.find(c) == td.col_idx.end())
                    td.col_idx[c] = (int)i;
            }
        }
        if (td.manifest.ncols == 0)
            td.manifest.ncols = (uint32)td.cols.size();

        auto it2 = tables_.emplace(table, std::move(td)).first;
        if (profile_)
            profile_->artifact_parse_ms += Ms(Clock::now() - t0).count();
        return &it2->second;
    }

    const std::vector<int32> *decode_col_tokens(const std::string &table, int col_idx)
    {
        TableData *td = require_table(table);
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
                ereport(ERROR, (errmsg("policy: missing code column chunk %s", cname.c_str())));
            if (b.len < 16 || std::memcmp(b.data, "CC04", 4) != 0)
                ereport(ERROR, (errmsg("policy: malformed code column chunk %s", cname.c_str())));

            size_t p = 4;
            int32 rows_i32 = 0;
            int32 payload_len_i32 = 0;
            uint16 bw = 0;
            uint16 reserved = 0;
            if (!read_i32(b.data, b.len, &p, &rows_i32))
                ereport(ERROR, (errmsg("policy: truncated chunk header %s", cname.c_str())));
            if (p + sizeof(uint16) * 2u > b.len)
                ereport(ERROR, (errmsg("policy: truncated chunk bw/reserved %s", cname.c_str())));
            std::memcpy(&bw, b.data + p, sizeof(uint16));
            p += sizeof(uint16);
            std::memcpy(&reserved, b.data + p, sizeof(uint16));
            p += sizeof(uint16);
            (void)reserved;
            if (!read_i32(b.data, b.len, &p, &payload_len_i32))
                ereport(ERROR, (errmsg("policy: truncated chunk payload len %s", cname.c_str())));
            if (rows_i32 < 0 || payload_len_i32 < 0)
                ereport(ERROR, (errmsg("policy: negative chunk header values %s", cname.c_str())));
            uint32 rows = (uint32)rows_i32;
            uint32 payload_len = (uint32)payload_len_i32;
            if (p + payload_len > b.len)
                ereport(ERROR, (errmsg("policy: payload overflow in chunk %s", cname.c_str())));
            const uint8 *payload = (const uint8 *)(b.data + p);
            size_t payload_pos = 0;
            uint64_t acc = 0;
            int acc_bits = 0;
            uint64_t mask = (bw == 64) ? ~0ULL : ((bw == 0) ? 0ULL : ((1ULL << bw) - 1ULL));

            for (uint32 r = 0; r < rows; r++) {
                while (acc_bits < (int)bw) {
                    if (payload_pos >= payload_len)
                        ereport(ERROR, (errmsg("policy: bitpack underflow in chunk %s", cname.c_str())));
                    acc |= ((uint64_t)payload[payload_pos++]) << acc_bits;
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
                    (errmsg("policy: decoded row mismatch for %s col=%d decoded=%zu expected=%u",
                            table.c_str(), col_idx, out.size(), td->manifest.nrows)));

        auto it2 = td->col_tokens.emplace(col_idx, std::move(out)).first;
        if (profile_)
            profile_->decode_ms += Ms(Clock::now() - t0).count();
        return &it2->second;
    }

    int require_col_idx(const std::string &table, const std::string &col)
    {
        TableData *td = require_table(table);
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

    int domain_of_col(const ColRef &c) const
    {
        auto it = col_domain_.find(c.key());
        if (it == col_domain_.end())
            return -1;
        return it->second;
    }

    bool load_dict(const AtomDesc &a, DictData *out)
    {
        if (!out)
            return false;

        std::string key;
        std::string dict_name;
        std::string dtype_name;
        if (a.join_class_id >= 0) {
            std::string sid = std::to_string(a.join_class_id);
            key = "domain:" + sid;
            dict_name = "dict/domain/" + sid;
            dtype_name = "meta/dict_type/domain/" + sid;
        } else {
            key = a.lhs.key();
            dict_name = "dict/" + a.lhs.table + "/" + a.lhs.col;
            dtype_name = "meta/dict_type/" + a.lhs.table + "/" + a.lhs.col;
        }

        auto it = dict_cache_.find(key);
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

        DictData dd;
        dd.dtype = dtype;

        size_t p = 0;
        while (p < db.len) {
            int32 n = 0;
            if (!read_i32(db.data, db.len, &p, &n))
                ereport(ERROR, (errmsg("policy: malformed dict header %s", dict_name.c_str())));
            if (n < 0 || p + (size_t)n > db.len)
                ereport(ERROR, (errmsg("policy: malformed dict value %s", dict_name.c_str())));
            dd.values.emplace_back(db.data + p, (size_t)n);
            p += (size_t)n;
        }

        dd.token_by_norm.reserve(dd.values.size() * 2u + 1u);
        for (size_t i = 0; i < dd.values.size(); i++) {
            std::string norm = normalize_literal_for_type(dd.values[i], dd.dtype);
            if (dd.token_by_norm.find(norm) == dd.token_by_norm.end())
                dd.token_by_norm[norm] = (int32)i;
        }

        auto it2 = dict_cache_.emplace(key, std::move(dd)).first;
        *out = it2->second;
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

        RankData rd;
        std::string sid = std::to_string(domain_id);
        std::string rank_name = "rank/domain/" + sid;
        BlobRef rb;
        if (resolver_.get(rank_name, &rb) && rb.ok() && rb.len >= sizeof(int32)) {
            if (rb.len % sizeof(int32) == 0) {
                size_t n = rb.len / sizeof(int32);
                rd.rank_by_tok.resize(n);
                std::memcpy(rd.rank_by_tok.data(), rb.data, rb.len);
                rd.present = true;
            }
        }

        auto it2 = rank_cache_.emplace(domain_id, std::move(rd)).first;
        *out = it2->second;
        return true;
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

    RowBits eval_local_atom(const AtomDesc &a)
    {
        if (a.kind == POLICY_ATOM_COL_CONST)
            return eval_col_const(a);
        if (a.kind == POLICY_ATOM_COL_COL && a.lhs.table == a.rhs.table)
            return eval_col_col_same_table(a);

        TableData *tt = require_table(a.lhs.table);
        RowBits empty(tt ? tt->manifest.nrows : 0);
        empty.clear_all();
        return empty;
    }

    RowBits eval_col_const(const AtomDesc &a)
    {
        TableData *td = require_table(a.lhs.table);
        int col_idx = require_col_idx(a.lhs.table, a.lhs.col);
        const std::vector<int32> *tok = decode_col_tokens(a.lhs.table, col_idx);

        DictData dict;
        if (!load_dict(a, &dict))
            ereport(ERROR, (errmsg("policy: dict load failed for %s.%s", a.lhs.table.c_str(), a.lhs.col.c_str())));

        std::vector<uint8_t> allow(dict.values.size(), 0u);

        if (a.op == POLICY_OP_EQ || a.op == POLICY_OP_NE) {
            std::unordered_set<int32> wanted;
            for (const std::string &vraw : a.const_values) {
                std::string norm = normalize_literal_for_type(vraw, dict.dtype);
                auto it = dict.token_by_norm.find(norm);
                if (it != dict.token_by_norm.end())
                    wanted.insert(it->second);
            }
            for (size_t i = 0; i < dict.values.size(); i++) {
                bool in = (wanted.find((int32)i) != wanted.end());
                allow[i] = (uint8_t)((a.op == POLICY_OP_EQ) ? in : (!in));
            }
        } else {
            std::string rhs = a.const_values.empty() ? "" : a.const_values[0];
            for (size_t i = 0; i < dict.values.size(); i++) {
                int cmp = cmp_by_type(dict.dtype, dict.values[i], rhs);
                allow[i] = (uint8_t)(op_cmp_true(a.op, cmp) ? 1 : 0);
            }
        }

        RowBits out(td->manifest.nrows);
        out.clear_all();
        for (uint32 rid = 0; rid < td->manifest.nrows; rid++) {
            int32 t = (*tok)[rid];
            if (t < 0)
                continue;
            if ((size_t)t >= allow.size())
                continue;
            if (allow[(size_t)t])
                out.set(rid);
        }
        return out;
    }

    static int32 rank_or_identity(const RankData &rd, int32 tok)
    {
        if (tok < 0)
            return tok;
        if (rd.present && (size_t)tok < rd.rank_by_tok.size())
            return rd.rank_by_tok[(size_t)tok];
        return tok;
    }

    RowBits eval_col_col_same_table(const AtomDesc &a)
    {
        TableData *td = require_table(a.lhs.table);
        int li = require_col_idx(a.lhs.table, a.lhs.col);
        int ri = require_col_idx(a.rhs.table, a.rhs.col);
        const std::vector<int32> *lt = decode_col_tokens(a.lhs.table, li);
        const std::vector<int32> *rt = decode_col_tokens(a.rhs.table, ri);

        RankData rank;
        if (a.join_class_id >= 0)
            (void)load_rank(a.join_class_id, &rank);

        RowBits out(td->manifest.nrows);
        out.clear_all();
        for (uint32 rid = 0; rid < td->manifest.nrows; rid++) {
            int32 l = (*lt)[rid];
            int32 r = (*rt)[rid];
            if (l < 0 || r < 0)
                continue;
            bool keep = false;
            switch (a.op) {
                case POLICY_OP_EQ:
                    keep = (l == r);
                    break;
                case POLICY_OP_NE:
                    keep = (l != r);
                    break;
                case POLICY_OP_LT:
                    keep = (rank_or_identity(rank, l) < rank_or_identity(rank, r));
                    break;
                case POLICY_OP_LE:
                    keep = (rank_or_identity(rank, l) <= rank_or_identity(rank, r));
                    break;
                case POLICY_OP_GT:
                    keep = (rank_or_identity(rank, l) > rank_or_identity(rank, r));
                    break;
                case POLICY_OP_GE:
                    keep = (rank_or_identity(rank, l) >= rank_or_identity(rank, r));
                    break;
                default:
                    keep = false;
            }
            if (keep)
                out.set(rid);
        }
        return out;
    }

    uint32 domain_token_count(int domain_id)
    {
        auto it = domain_ntokens_.find(domain_id);
        if (it != domain_ntokens_.end())
            return it->second;

        AtomDesc fake;
        fake.join_class_id = domain_id;
        fake.lhs.table = "";
        fake.lhs.col = "";
        DictData d;
        if (!load_dict(fake, &d))
            return 0;
        uint32 n = (uint32)d.values.size();
        domain_ntokens_[domain_id] = n;
        return n;
    }

    static bool prune_with_token_support(RowBits *active, const std::vector<int32> &tok_col, const std::vector<uint8_t> &support)
    {
        if (!active)
            return false;
        RowBits pruned(active->nbits);
        pruned.clear_all();
        active->for_each_set([&](uint32 rid) {
            int32 tok = tok_col[rid];
            if (tok < 0)
                return;
            if ((size_t)tok >= support.size())
                return;
            if (support[(size_t)tok])
                pruned.set(rid);
        });
        bool changed = !pruned.equals(*active);
        if (changed)
            *active = std::move(pruned);
        return changed;
    }

    bool apply_join_edge(const JoinEdge &e, std::unordered_map<std::string, RowBits> *active)
    {
        if (!active)
            return false;
        RowBits &a = (*active)[e.a_table];
        RowBits &b = (*active)[e.b_table];
        const std::vector<int32> *atok = decode_col_tokens(e.a_table, e.a_col_idx);
        const std::vector<int32> *btok = decode_col_tokens(e.b_table, e.b_col_idx);
        uint32 ntok = domain_token_count(e.domain_id);
        if (ntok == 0) {
            bool changed = a.any() || b.any();
            a.clear_all();
            b.clear_all();
            return changed;
        }

        std::vector<uint8_t> supp_a(ntok, 0u);
        std::vector<uint8_t> supp_b(ntok, 0u);

        a.for_each_set([&](uint32 rid) {
            int32 t = (*atok)[rid];
            if (t >= 0 && (uint32)t < ntok)
                supp_a[(size_t)t] = 1u;
        });
        b.for_each_set([&](uint32 rid) {
            int32 t = (*btok)[rid];
            if (t >= 0 && (uint32)t < ntok)
                supp_b[(size_t)t] = 1u;
        });

        std::vector<uint8_t> inter(ntok, 0u);
        bool any = false;
        for (uint32 i = 0; i < ntok; i++) {
            inter[i] = (uint8_t)(supp_a[i] & supp_b[i]);
            if (inter[i])
                any = true;
        }
        if (!any) {
            bool changed = a.any() || b.any();
            a.clear_all();
            b.clear_all();
            return changed;
        }

        bool changed = false;
        changed |= prune_with_token_support(&a, *atok, inter);
        changed |= prune_with_token_support(&b, *btok, inter);
        return changed;
    }

    void build_summary(const RowBits &active,
                       const std::vector<int32> &tok,
                       const RankData &rank,
                       uint32 ntok,
                       bool need_support,
                       CompSummary *out)
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

        active.for_each_set([&](uint32 rid) {
            int32 t = tok[rid];
            if (t < 0)
                return;
            if ((uint32)t >= ntok)
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

    static bool eval_tok_vs_summary(int op, int32 tok, int32 rk, const CompSummary &s)
    {
        if (tok < 0)
            return false;
        if (!s.any)
            return false;

        switch (op) {
            case POLICY_OP_EQ:
                if ((size_t)tok >= s.support.size())
                    return false;
                return s.support[(size_t)tok] != 0u;
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

    bool apply_cross_cmp(const CrossCmp &c, std::unordered_map<std::string, RowBits> *active)
    {
        if (!active)
            return false;
        RowBits &a = (*active)[c.a_table];
        RowBits &b = (*active)[c.b_table];

        const std::vector<int32> *atok = decode_col_tokens(c.a_table, c.a_col_idx);
        const std::vector<int32> *btok = decode_col_tokens(c.b_table, c.b_col_idx);

        uint32 ntok = domain_token_count(c.domain_id);
        if (ntok == 0) {
            bool changed = a.any() || b.any();
            a.clear_all();
            b.clear_all();
            return changed;
        }

        RankData rank;
        (void)load_rank(c.domain_id, &rank);

        CompSummary sb;
        CompSummary sa;
        bool need_support = (c.op == POLICY_OP_EQ);
        build_summary(b, *btok, rank, ntok, need_support, &sb);
        build_summary(a, *atok, rank, ntok, need_support, &sa);

        RowBits pa(a.nbits);
        pa.clear_all();
        a.for_each_set([&](uint32 rid) {
            int32 t = (*atok)[rid];
            if (t < 0 || (uint32)t >= ntok)
                return;
            int32 rk = rank_or_identity(rank, t);
            if (eval_tok_vs_summary(c.op, t, rk, sb))
                pa.set(rid);
        });

        RowBits pb(b.nbits);
        pb.clear_all();
        int inv = inverse_op(c.op);
        b.for_each_set([&](uint32 rid) {
            int32 t = (*btok)[rid];
            if (t < 0 || (uint32)t >= ntok)
                return;
            int32 rk = rank_or_identity(rank, t);
            if (eval_tok_vs_summary(inv, t, rk, sa))
                pb.set(rid);
        });

        bool changed = false;
        if (!pa.equals(a)) {
            a = std::move(pa);
            changed = true;
        }
        if (!pb.equals(b)) {
            b = std::move(pb);
            changed = true;
        }
        return changed;
    }

    RowBits eval_term(const std::string &target, const Term &term)
    {
        TableData *target_t = require_table(target);
        if (!target_t)
            ereport(ERROR, (errmsg("policy: missing target table %s", target.c_str())));

        if (term.empty()) {
            RowBits all(target_t->manifest.nrows);
            all.fill_all();
            return all;
        }

        std::unordered_set<std::string> tables;
        std::vector<const AtomDesc *> local_atoms;
        std::vector<JoinEdge> join_edges;
        std::vector<CrossCmp> cross_cmps;

        for (int aid : term) {
            auto it = atom_by_id_.find(aid);
            if (it == atom_by_id_.end()) {
                RowBits none(target_t->manifest.nrows);
                none.clear_all();
                return none;
            }
            const AtomDesc &a = it->second;
            if (a.kind == POLICY_ATOM_JOIN_EQ) {
                tables.insert(a.lhs.table);
                tables.insert(a.rhs.table);
                JoinEdge e;
                e.a_table = a.lhs.table;
                e.b_table = a.rhs.table;
                e.a_col_idx = require_col_idx(a.lhs.table, a.lhs.col);
                e.b_col_idx = require_col_idx(a.rhs.table, a.rhs.col);
                e.domain_id = a.join_class_id;
                join_edges.push_back(e);
                continue;
            }
            if (a.kind == POLICY_ATOM_COL_CONST) {
                tables.insert(a.lhs.table);
                local_atoms.push_back(&a);
                continue;
            }
            if (a.kind == POLICY_ATOM_COL_COL) {
                tables.insert(a.lhs.table);
                tables.insert(a.rhs.table);
                if (a.lhs.table == a.rhs.table) {
                    local_atoms.push_back(&a);
                } else {
                    CrossCmp c;
                    c.a_table = a.lhs.table;
                    c.b_table = a.rhs.table;
                    c.a_col_idx = require_col_idx(a.lhs.table, a.lhs.col);
                    c.b_col_idx = require_col_idx(a.rhs.table, a.rhs.col);
                    c.domain_id = a.join_class_id;
                    c.op = a.op;
                    cross_cmps.push_back(c);
                }
                continue;
            }
        }

        std::unordered_map<std::string, RowBits> active;
        active.reserve(tables.size() * 2u + 1u);
        for (const std::string &t : tables) {
            TableData *td = require_table(t);
            RowBits bits(td->manifest.nrows);
            bits.fill_all();
            active.emplace(t, std::move(bits));
        }

        for (const AtomDesc *ap : local_atoms) {
            const AtomDesc &a = *ap;
            RowBits m = eval_local_atom(a);
            auto it = active.find(a.lhs.table);
            if (it == active.end())
                continue;
            it->second.bit_and(m);
        }

        auto any_empty = [&]() -> bool {
            for (const auto &kv : active) {
                if (!kv.second.any())
                    return true;
            }
            return false;
        };

        if (any_empty()) {
            RowBits none(target_t->manifest.nrows);
            none.clear_all();
            return none;
        }

        bool changed = true;
        int iter = 0;
        while (changed && iter < 16) {
            changed = false;
            iter++;
            for (const JoinEdge &e : join_edges)
                changed |= apply_join_edge(e, &active);
            for (const CrossCmp &c : cross_cmps)
                changed |= apply_cross_cmp(c, &active);
            if (any_empty())
                break;
        }
        if (profile_)
            profile_->prop_iters += iter;

        if (any_empty()) {
            RowBits none(target_t->manifest.nrows);
            none.clear_all();
            return none;
        }

        auto it_t = active.find(target);
        if (it_t != active.end())
            return it_t->second;

        RowBits global_ok(target_t->manifest.nrows);
        global_ok.fill_all();
        return global_ok;
    }

    void build_sparse_allow_words(const TableData &td,
                                  const RowBits &allowed,
                                  std::vector<uint32> *out_block_ids,
                                  std::vector<uint64_t> *out_words,
                                  uint64 *out_allowed_rows)
    {
        if (!out_block_ids || !out_words)
            return;
        out_block_ids->clear();
        out_words->clear();
        if (out_allowed_rows)
            *out_allowed_rows = 0;

        std::map<uint32, std::array<uint64_t, kWordsPerBlock>> by_blk;

        allowed.for_each_set([&](uint32 rid) {
            if ((size_t)rid >= td.ctid_blk.size() || (size_t)rid >= td.ctid_off.size())
                return;
            int32 blk_i = td.ctid_blk[(size_t)rid];
            int32 off_i = td.ctid_off[(size_t)rid];
            if (blk_i < 0 || off_i < 1 || off_i > (int32)kMaxOff)
                return;
            uint32 blk = (uint32)blk_i;
            uint32 off0 = (uint32)off_i - 1u;
            uint32 wi = off0 >> 6;
            uint32 bi = off0 & 63u;
            auto &arr = by_blk[blk];
            arr[wi] |= (1ULL << bi);
            if (out_allowed_rows)
                (*out_allowed_rows)++;
        });

        out_block_ids->reserve(by_blk.size());
        out_words->reserve(by_blk.size() * kWordsPerBlock);
        for (const auto &kv : by_blk) {
            out_block_ids->push_back(kv.first);
            for (uint32 i = 0; i < kWordsPerBlock; i++)
                out_words->push_back(kv.second[i]);
        }
    }

    void compute_term_signatures(const std::vector<RowBits> &term_masks,
                                 const RowBits &allowed,
                                 uint32 *out_allowed_sids,
                                 uint32 *out_total_sids)
    {
        if (out_allowed_sids)
            *out_allowed_sids = 0;
        if (out_total_sids)
            *out_total_sids = 0;
        if (term_masks.empty()) {
            if (out_total_sids)
                *out_total_sids = allowed.any() ? 1u : 0u;
            if (out_allowed_sids)
                *out_allowed_sids = allowed.any() ? 1u : 0u;
            return;
        }

        uint32 nrows = term_masks[0].nbits;
        if (term_masks.size() > 63u) {
            if (out_total_sids)
                *out_total_sids = 2u;
            if (out_allowed_sids)
                *out_allowed_sids = allowed.any() ? 1u : 0u;
            return;
        }

        std::unordered_set<uint64_t> all_sigs;
        std::unordered_set<uint64_t> allowed_sigs;
        all_sigs.reserve((size_t)std::min<uint32>(nrows, 200000u));
        allowed_sigs.reserve((size_t)std::min<uint32>(nrows, 200000u));

        for (uint32 rid = 0; rid < nrows; rid++) {
            uint64_t sig = 0ULL;
            for (size_t i = 0; i < term_masks.size(); i++) {
                if (term_masks[i].test(rid))
                    sig |= (1ULL << i);
            }
            all_sigs.insert(sig);
            if (sig != 0ULL)
                allowed_sigs.insert(sig);
        }

        if (out_total_sids)
            *out_total_sids = (uint32)std::min<size_t>(all_sigs.size(), (size_t)UINT32_MAX);
        if (out_allowed_sids)
            *out_allowed_sids = (uint32)std::min<size_t>(allowed_sigs.size(), (size_t)UINT32_MAX);
    }

private:
    ArtifactResolver resolver_;
    const PolicyEngineInputC *in_ = nullptr;
    BuildProfile *profile_ = nullptr;

    std::unordered_map<int, AtomDesc> atom_by_id_;
    std::unordered_map<std::string, int> col_domain_;
    std::unordered_map<std::string, TableData> tables_;
    std::unordered_map<std::string, DictData> dict_cache_;
    std::unordered_map<int, RankData> rank_cache_;
    std::unordered_map<int, uint32> domain_ntokens_;
};

static int profile_k()
{
    const char *v = GetConfigOption("custom_filter.profile_k", true, false);
    if (!v || !v[0])
        return 0;
    return std::atoi(v);
}

static std::string profile_query()
{
    const char *v = GetConfigOption("custom_filter.profile_query", true, false);
    if (!v || !v[0])
        return "";
    return v;
}

static void fill_profile_c(const BuildProfile &p, PolicyRunProfileC *out)
{
    if (!out)
        return;
    std::memset(out, 0, sizeof(*out));
    out->artifact_parse_ms = p.artifact_parse_ms;
    out->atoms_ms = p.atoms_ms;
    out->propagate_ms = p.propagate_ms;
    out->decode_ms = p.decode_ms;
    out->policy_total_ms = p.policy_total_ms;
    out->prop_iters = p.prop_iters;
    out->block_words_nwords_per_block = kWordsPerBlock;
}

static void log_policy_profile_query(const BuildProfile &p, int filtered_targets)
{
    elog(NOTICE,
         "policy_profile_query: K=%d query_id=%s total_ms=%.3f load_ms=%.3f prop_ms=%.3f decode_ms=%.3f sat_calls=%llu sat_ms=%.3f sat_models_total=%llu terms_total=%llu allow_rows_total=%llu bin_ops_total=0 bins_touched_total=0 bin_rids_scanned_total=0 allow_cache_hit=0 allow_cache_miss=0 allow_cache_build_ms=0 filtered_targets=%d",
         profile_k(),
         profile_query().c_str(),
         p.policy_total_ms,
         p.artifact_parse_ms,
         p.propagate_ms,
         p.decode_ms,
         (unsigned long long)p.sat_calls,
         p.sat_ms,
         (unsigned long long)p.sat_models_total,
         (unsigned long long)p.terms_total,
         (unsigned long long)p.allow_rows_total,
         filtered_targets);
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

    if (in->target_count <= 0 || !in->target_tables || !in->target_asts) {
        fill_profile_c(p, &h->profile);
        return h;
    }

    h->allow_list.count = in->target_count;
    h->allow_list.items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * (size_t)in->target_count);

    Engine eng(arts, art_count, in, &p);

    int out_count = 0;
    for (int i = 0; i < in->target_count; i++) {
        const char *t = in->target_tables[i];
        if (!t || !t[0])
            continue;
        const char *ast = (in->target_asts && in->target_asts[i]) ? in->target_asts[i] : "";
        PolicyTableAllowC item;
        if (!eng.build_target_allow(to_lower_copy(t), ast, &item))
            ereport(ERROR, (errmsg("policy: failed building allow-list for target %s", t)));
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

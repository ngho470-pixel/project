#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <cvc5/cvc5.h>

extern "C" {
#include "postgres.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/builtins.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/palloc.h"
}

#include "policy_evaluator.h"
#include "policy_spec.h"

using Clock = std::chrono::steady_clock;
using Ms = std::chrono::duration<double, std::milli>;

#define CF_TRACE_LOG(fmt, ...)                \
    do {                                      \
        if (cf_trace_enabled())               \
            elog(NOTICE, fmt, ##__VA_ARGS__); \
    } while (0)

#define PF_CHECK_FOR_INTERRUPTS(counter)      \
    do {                                      \
        if (((counter) & 0x3FFFu) == 0u)      \
            CHECK_FOR_INTERRUPTS();           \
    } while (0)

extern "C" {

typedef struct PolicyArtifactC {
    const char *name;
    const void *data;
    size_t len;
} PolicyArtifactC;

typedef struct PolicyTableAllowC {
    const char *table;
    uint64 *block_words;
    uint32 *block_ids;     // optional sorted physical block ids for sparse block_words
    uint32 blocks;         // number of allocated block entries in block_words
    uint32 total_blocks;   // total physical block span for this table (max_blk + 1)
    uint32 n_rows;
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
} PolicyRunProfileC;

} // extern "C"

namespace {

static constexpr uint32 kMaxOffsetNumber = 512;
static constexpr uint32 kWordsPerBlock = (kMaxOffsetNumber + 63u) / 64u;

using CtidKey = std::uint64_t;

static inline CtidKey make_ctid_key(int32 blk, int32 off)
{
    return (CtidKey((uint32)blk) << 32) | uint32(off);
}

static inline bool rid_bit_test(const uint8 *bits, uint32 rid)
{
    if (!bits) return false;
    return (bits[rid >> 3] & (uint8)(1u << (rid & 7u))) != 0;
}

static inline void rid_bit_set(uint8 *bits, uint32 rid)
{
    bits[rid >> 3] |= (uint8)(1u << (rid & 7u));
}

static bool policy_runtime_strict_mode_enabled()
{
    /*
     * Class-engine-only runtime: when policy evaluation is invoked, strict
     * semantics are always enforced.
     */
    return true;
}

static bytea *
cf_fetch_file_bytea(const char *name)
{
    auto files_table_sql = []() -> std::string {
        const char *cfg = GetConfigOption("custom_filter.files_table", true, false);
        const char *raw = (cfg && cfg[0]) ? cfg : "public.files";
        const char *dot = std::strchr(raw, '.');
        if (dot && std::strchr(dot + 1, '.') == nullptr)
        {
            std::string schema(raw, (size_t)(dot - raw));
            std::string table(dot + 1);
            char *q = quote_qualified_identifier(schema.c_str(), table.c_str());
            std::string out = q ? q : "public.files";
            if (q) pfree(q);
            return out;
        }
        const char *q = quote_identifier(raw);
        std::string out = q ? q : "public.files";
        return out;
    };
    StringInfoData sql;
    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "SELECT file FROM %s "
                     "WHERE COALESCE(run_id,'') = COALESCE(current_setting('custom_filter.run_id', true), '') "
                     "AND name = %s",
                     files_table_sql().c_str(),
                     quote_literal_cstr(name));
    int ret = SPI_execute(sql.data, true, 0);
    if (ret != SPI_OK_SELECT || SPI_processed != 1)
        return nullptr;
    bool isnull = false;
    Datum d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
    if (isnull)
        return nullptr;
    bytea *src = DatumGetByteaP(d);
    bytea *copy = (bytea *)palloc(VARSIZE(src));
    memcpy(copy, src, VARSIZE(src));
    return copy;
}

static std::string trim_ws(const std::string &s)
{
    size_t b = 0;
    while (b < s.size() && std::isspace((unsigned char)s[b])) b++;
    size_t e = s.size();
    while (e > b && std::isspace((unsigned char)s[e - 1])) e--;
    return s.substr(b, e - b);
}

static std::string lower_str(std::string s)
{
    for (char &c : s)
        c = (char)std::tolower((unsigned char)c);
    return s;
}

static std::vector<std::string> split_lines(const std::string &s)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find('\n', start);
        if (end == std::string::npos) end = s.size();
        if (end > start)
            out.push_back(s.substr(start, end - start));
        start = end + 1;
    }
    return out;
}

struct TokenBitset {
    enum class Rep {
        DENSE,
        SPARSE,
    };

    size_t nbits = 0;
    Rep rep = Rep::DENSE;
    std::vector<uint64_t> words;
    std::vector<uint32_t> sparse;

    TokenBitset() = default;
    explicit TokenBitset(size_t bits) { reset(bits); }

    void reset(size_t bits)
    {
        nbits = bits;
        rep = Rep::DENSE;
        words.assign((nbits + 63u) / 64u, 0);
        sparse.clear();
    }

    void clear_all()
    {
        if (rep == Rep::DENSE)
            std::fill(words.begin(), words.end(), 0);
        else
            sparse.clear();
    }

    void fill_all()
    {
        rep = Rep::DENSE;
        sparse.clear();
        std::fill(words.begin(), words.end(), ~uint64_t(0));
        trim_tail_dense();
    }

    bool any() const
    {
        if (rep == Rep::SPARSE)
            return !sparse.empty();
        for (uint64_t w : words) {
            if (w != 0) return true;
        }
        return false;
    }

    bool is_all() const
    {
        if (rep == Rep::SPARSE)
            return nbits > 0 && sparse.size() == nbits;
        if (nbits == 0) return true;
        if (words.empty()) return true;
        for (size_t i = 0; i + 1 < words.size(); i++) {
            if (words[i] != ~uint64_t(0))
                return false;
        }
        size_t rem = nbits & 63u;
        uint64_t mask = (rem == 0) ? ~uint64_t(0) : ((uint64_t(1) << rem) - 1u);
        return words.back() == mask;
    }

    void set(size_t bit)
    {
        if (bit >= nbits) return;
        if (rep == Rep::DENSE) {
            words[bit >> 6] |= (uint64_t(1) << (bit & 63u));
            return;
        }
        uint32_t b = (uint32_t)bit;
        auto it = std::lower_bound(sparse.begin(), sparse.end(), b);
        if (it == sparse.end() || *it != b)
            sparse.insert(it, b);
        rebalance();
    }

    void clear(size_t bit)
    {
        if (bit >= nbits) return;
        if (rep == Rep::DENSE) {
            words[bit >> 6] &= ~(uint64_t(1) << (bit & 63u));
            return;
        }
        uint32_t b = (uint32_t)bit;
        auto it = std::lower_bound(sparse.begin(), sparse.end(), b);
        if (it != sparse.end() && *it == b)
            sparse.erase(it);
    }

    void set_range(size_t begin_bit, size_t end_bit)
    {
        if (begin_bit >= end_bit || begin_bit >= nbits)
            return;
        ensure_dense();
        end_bit = std::min(end_bit, nbits);
        size_t wb = begin_bit >> 6;
        size_t we = (end_bit - 1u) >> 6;
        uint32 ob = (uint32)(begin_bit & 63u);
        uint32 oe = (uint32)((end_bit - 1u) & 63u);

        if (wb == we) {
            uint64_t mask_lo = (ob == 0) ? ~uint64_t(0) : (~uint64_t(0) << ob);
            uint64_t mask_hi = (oe == 63u) ? ~uint64_t(0) : ((uint64_t(1) << (oe + 1u)) - 1u);
            words[wb] |= (mask_lo & mask_hi);
            trim_tail_dense();
            return;
        }

        // First partial word.
        words[wb] |= (~uint64_t(0) << ob);
        // Full words in the middle.
        for (size_t i = wb + 1; i < we; i++)
            words[i] = ~uint64_t(0);
        // Last partial word.
        uint64_t mask_hi = (oe == 63u) ? ~uint64_t(0) : ((uint64_t(1) << (oe + 1u)) - 1u);
        words[we] |= mask_hi;
        trim_tail_dense();
        rebalance();
    }

    bool test(size_t bit) const
    {
        if (bit >= nbits) return false;
        if (rep == Rep::SPARSE) {
            uint32_t b = (uint32_t)bit;
            return std::binary_search(sparse.begin(), sparse.end(), b);
        }
        return (words[bit >> 6] & (uint64_t(1) << (bit & 63u))) != 0;
    }

    bool equals(const TokenBitset &o) const
    {
        if (nbits != o.nbits)
            return false;
        if (rep == o.rep) {
            if (rep == Rep::DENSE)
                return words == o.words;
            return sparse == o.sparse;
        }
        if (count() != o.count())
            return false;
        bool eq = true;
        for_each_set([&](int32_t tok) {
            if (!o.test((size_t)tok))
                eq = false;
        });
        return eq;
    }

    void bit_and(const TokenBitset &o)
    {
        ensure_dense();
        TokenBitset tmp = o;
        tmp.ensure_dense();
        size_t n = std::min(words.size(), tmp.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] &= tmp.words[i];
        for (size_t i = n; i < words.size(); i++)
            words[i] = 0;
        rebalance();
    }

    void bit_or(const TokenBitset &o)
    {
        ensure_dense();
        TokenBitset tmp = o;
        tmp.ensure_dense();
        size_t n = std::min(words.size(), tmp.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] |= tmp.words[i];
        trim_tail_dense();
        rebalance();
    }

    bool intersect_with_changed(const TokenBitset &o)
    {
        ensure_dense();
        TokenBitset tmp = o;
        tmp.ensure_dense();
        bool changed = false;
        size_t n = std::min(words.size(), tmp.words.size());
        for (size_t i = 0; i < n; i++) {
            uint64_t nw = words[i] & tmp.words[i];
            if (nw != words[i]) changed = true;
            words[i] = nw;
        }
        for (size_t i = n; i < words.size(); i++) {
            if (words[i] != 0) changed = true;
            words[i] = 0;
        }
        rebalance();
        return changed;
    }

    size_t count() const
    {
        if (rep == Rep::SPARSE)
            return sparse.size();
        size_t c = 0;
        for (uint64_t w : words)
            c += (size_t)__builtin_popcountll(w);
        return c;
    }

    double density() const
    {
        if (nbits == 0)
            return 0.0;
        return (double)count() / (double)nbits;
    }

    bool is_sparse_rep() const
    {
        return rep == Rep::SPARSE;
    }

    size_t memory_bytes() const
    {
        if (rep == Rep::SPARSE)
            return sparse.size() * sizeof(uint32_t);
        return words.size() * sizeof(uint64_t);
    }

    void adapt_representation()
    {
        rebalance();
    }

    template <typename Fn>
    void for_each_set(Fn &&fn) const
    {
        if (rep == Rep::SPARSE) {
            for (uint32_t tok : sparse)
                fn((int32_t)tok);
            return;
        }
        for (size_t wi = 0; wi < words.size(); wi++) {
            uint64_t w = words[wi];
            while (w) {
                uint64_t lsb = w & (~w + 1ull);
                unsigned bit = (unsigned)__builtin_ctzll(w);
                size_t tok = (wi << 6) + bit;
                if (tok < nbits)
                    fn((int32_t)tok);
                w ^= lsb;
            }
        }
    }

private:
    void trim_tail_dense()
    {
        if (nbits == 0 || words.empty()) return;
        size_t rem = nbits & 63u;
        if (rem == 0) return;
        uint64_t mask = (uint64_t(1) << rem) - 1u;
        words.back() &= mask;
    }

    size_t dense_bytes() const
    {
        return words.size() * sizeof(uint64_t);
    }

    size_t sparse_bytes() const
    {
        return sparse.size() * sizeof(uint32_t);
    }

    void ensure_dense()
    {
        if (rep == Rep::DENSE)
            return;
        words.assign((nbits + 63u) / 64u, 0);
        for (uint32_t tok : sparse) {
            if ((size_t)tok < nbits)
                words[(size_t)tok >> 6] |= (uint64_t(1) << (tok & 63u));
        }
        sparse.clear();
        rep = Rep::DENSE;
    }

    void ensure_sparse()
    {
        if (rep == Rep::SPARSE)
            return;
        sparse.clear();
        sparse.reserve(count());
        for (size_t wi = 0; wi < words.size(); wi++) {
            uint64_t w = words[wi];
            while (w) {
                uint64_t lsb = w & (~w + 1ull);
                unsigned bit = (unsigned)__builtin_ctzll(w);
                size_t tok = (wi << 6) + bit;
                if (tok < nbits)
                    sparse.push_back((uint32_t)tok);
                w ^= lsb;
            }
        }
        words.clear();
        rep = Rep::SPARSE;
    }

    void rebalance()
    {
        if (nbits == 0)
            return;
        // Memory-oriented switch with mild hysteresis.
        if (rep == Rep::DENSE) {
            size_t c = count();
            size_t dbytes = dense_bytes();
            size_t sbytes = c * sizeof(uint32_t);
            if (c > 0 && (sbytes + 64u) < (dbytes / 2u))
                ensure_sparse();
            return;
        }
        size_t sbytes = sparse_bytes();
        size_t dbytes = ((nbits + 63u) / 64u) * sizeof(uint64_t);
        if (sbytes > dbytes || sparse.size() > (nbits / 4u))
            ensure_dense();
    }
};

enum class AstType {
    VAR,
    AND,
    OR,
};

struct BoolAst {
    AstType type = AstType::VAR;
    int var_id = -1;
    BoolAst *left = nullptr;
    BoolAst *right = nullptr;
};

enum class FormulaTokKind {
    VAR,
    AND,
    OR,
};

struct FormulaToken {
    FormulaTokKind kind = FormulaTokKind::VAR;
    int var_id = -1;
};

struct SatCnf {
    int nvars = 0;
    std::vector<std::vector<int>> clauses;  // literals: +v means var=true, -v means var=false
};

static inline void cnf_add_clause(SatCnf *cnf, std::initializer_list<int> lits)
{
    if (!cnf)
        return;
    cnf->clauses.emplace_back(lits);
}

static void cnf_add_tseitin_or_equiv(SatCnf *cnf, int z, int a, int b)
{
    // z <-> (a OR b)
    // (a -> z) & (b -> z) & (z -> a OR b)
    cnf_add_clause(cnf, {-a, z});
    cnf_add_clause(cnf, {-b, z});
    cnf_add_clause(cnf, {-z, a, b});
}

static void cnf_add_tseitin_and_equiv(SatCnf *cnf, int z, int a, int b)
{
    // z <-> (a AND b)
    // (z -> a) & (z -> b) & ((a AND b) -> z)
    cnf_add_clause(cnf, {-z, a});
    cnf_add_clause(cnf, {-z, b});
    cnf_add_clause(cnf, {z, -a, -b});
}

struct CnfExprRef {
    bool is_const = false;
    bool const_val = false;
    int var = 0;
};

struct OrSelectorBinding {
    const BoolAst *node = nullptr;  // AstType::OR node
    int selector_var = 0;           // true => pick left, false => pick right
};

struct CnfBuildInfo {
    std::unordered_map<const BoolAst *, CnfExprRef> node_expr;
    std::vector<OrSelectorBinding> selectors;
};

static inline int negate_lit(int lit)
{
    return -lit;
}

static void cnf_add_implication_lit_to_expr(SatCnf *cnf,
                                            int antecedent_lit,
                                            const CnfExprRef &rhs)
{
    if (!cnf)
        return;
    // antecedent_lit => rhs
    // CNF: (¬antecedent_lit OR rhs)
    if (rhs.is_const) {
        if (!rhs.const_val) {
            cnf_add_clause(cnf, {negate_lit(antecedent_lit)});
        }
        return;
    }
    cnf_add_clause(cnf, {negate_lit(antecedent_lit), rhs.var});
}

static CnfExprRef build_formula_cnf_tseitin_rec(const BoolAst *node,
                                                SatCnf *cnf,
                                                CnfBuildInfo *info)
{
    if (!node || !cnf) {
        CnfExprRef out;
        out.is_const = true;
        out.const_val = false;
        return out;
    }

    if (node->type == AstType::VAR) {
        CnfExprRef out;
        if (node->var_id <= 0) {
            out.is_const = true;
            out.const_val = false;
            return out;
        }
        if (node->var_id > cnf->nvars)
            cnf->nvars = node->var_id;
        out.is_const = false;
        out.var = node->var_id;
        if (info)
            info->node_expr[node] = out;
        return out;
    }

    CnfExprRef lhs = build_formula_cnf_tseitin_rec(node->left, cnf, info);
    CnfExprRef rhs = build_formula_cnf_tseitin_rec(node->right, cnf, info);

    if (node->type == AstType::OR && info) {
        OrSelectorBinding sel;
        sel.node = node;
        sel.selector_var = ++cnf->nvars;
        info->selectors.push_back(sel);
        // selector=true chooses left, selector=false chooses right.
        cnf_add_implication_lit_to_expr(cnf, sel.selector_var, lhs);
        cnf_add_implication_lit_to_expr(cnf, -sel.selector_var, rhs);
    }

    if (node->type == AstType::AND) {
        if ((lhs.is_const && !lhs.const_val) || (rhs.is_const && !rhs.const_val)) {
            CnfExprRef out;
            out.is_const = true;
            out.const_val = false;
            if (info)
                info->node_expr[node] = out;
            return out;
        }
        if (lhs.is_const && lhs.const_val) {
            if (info)
                info->node_expr[node] = rhs;
            return rhs;
        }
        if (rhs.is_const && rhs.const_val) {
            if (info)
                info->node_expr[node] = lhs;
            return lhs;
        }
    } else {
        if ((lhs.is_const && lhs.const_val) || (rhs.is_const && rhs.const_val)) {
            CnfExprRef out;
            out.is_const = true;
            out.const_val = true;
            if (info)
                info->node_expr[node] = out;
            return out;
        }
        if (lhs.is_const && !lhs.const_val) {
            if (info)
                info->node_expr[node] = rhs;
            return rhs;
        }
        if (rhs.is_const && !rhs.const_val) {
            if (info)
                info->node_expr[node] = lhs;
            return lhs;
        }
    }

    int z = ++cnf->nvars;
    if (node->type == AstType::AND)
        cnf_add_tseitin_and_equiv(cnf, z, lhs.var, rhs.var);
    else
        cnf_add_tseitin_or_equiv(cnf, z, lhs.var, rhs.var);

    CnfExprRef out;
    out.is_const = false;
    out.var = z;
    if (info)
        info->node_expr[node] = out;
    return out;
}

static bool build_formula_cnf_tseitin(const BoolAst *root,
                                      int n_input_vars,
                                      SatCnf *out,
                                      CnfBuildInfo *info = nullptr)
{
    if (!out)
        return false;
    out->nvars = std::max(0, n_input_vars);
    out->clauses.clear();
    if (info) {
        info->node_expr.clear();
        info->selectors.clear();
    }

    if (!root) {
        // Empty formula => TRUE.
        return true;
    }

    CnfExprRef root_ref = build_formula_cnf_tseitin_rec(root, out, info);
    if (root_ref.is_const) {
        if (!root_ref.const_val)
            out->clauses.push_back({}); // unsat
        return true;
    }
    out->clauses.push_back({root_ref.var});
    return true;
}

class Cvc5CnfSolver {
public:
    explicit Cvc5CnfSolver(const SatCnf &cnf) { init(cnf); }

    bool ok() const
    {
        return d_ok;
    }

    bool solve_with_assumptions(const std::vector<int> &assumptions)
    {
        if (!d_ok)
            return false;
        d_last_sat = false;
        std::vector<int8_t> assign((size_t) d_nvars + 1u, 0);
        for (int lit : assumptions) {
            if (!valid_lit(lit))
                return false;
            if (!apply_lit(assign, lit))
                return false;
        }
        if (!dpll(assign))
            return false;
        d_model.assign((size_t) d_nvars + 1u, 0);
        for (int v = 1; v <= d_nvars; v++) {
            int8_t val = assign[(size_t) v];
            if (val == 0)
                val = -1; // deterministic total model
            d_model[(size_t) v] = val;
        }
        d_last_sat = true;
        return true;
    }

    bool add_clause(const std::vector<int> &cl)
    {
        if (!d_ok)
            return false;
        for (int lit : cl) {
            if (!valid_lit(lit))
                return false;
        }
        d_clauses.push_back(cl);
        return true;
    }

    bool model_value(int var, bool *out)
    {
        if (!out || !d_ok || !d_last_sat)
            return false;
        if (var <= 0 || var > d_nvars || (size_t) var >= d_model.size())
            return false;
        int8_t val = d_model[(size_t) var];
        if (val == 0)
            val = -1;
        *out = (val > 0);
        return true;
    }

private:
    int d_nvars = 0;
    std::vector<std::vector<int>> d_clauses;
    std::vector<int8_t> d_model; // 1-based assignment: -1 false, +1 true
    bool d_ok = false;
    bool d_last_sat = false;

    bool valid_lit(int lit) const
    {
        if (lit == 0)
            return false;
        int var = (lit > 0) ? lit : -lit;
        return (var > 0 && var <= d_nvars);
    }

    static inline int lit_value(const std::vector<int8_t> &assign, int lit)
    {
        int var = (lit > 0) ? lit : -lit;
        int8_t v = assign[(size_t) var];
        if (v == 0)
            return 0;
        return (lit > 0) ? (int) v : -(int) v;
    }

    static bool apply_lit(std::vector<int8_t> &assign, int lit)
    {
        int var = (lit > 0) ? lit : -lit;
        int8_t want = (lit > 0) ? 1 : -1;
        int8_t cur = assign[(size_t) var];
        if (cur == 0) {
            assign[(size_t) var] = want;
            return true;
        }
        if (cur != want)
            return false;
        return true;
    }

    bool unit_propagate(std::vector<int8_t> &assign) const
    {
        bool changed = true;
        while (changed) {
            changed = false;
            for (const auto &cl : d_clauses) {
                bool sat = false;
                int unassigned = 0;
                int unit_lit = 0;
                for (int lit : cl) {
                    int lv = lit_value(assign, lit);
                    if (lv > 0) {
                        sat = true;
                        break;
                    }
                    if (lv == 0) {
                        unassigned++;
                        unit_lit = lit;
                    }
                }
                if (sat)
                    continue;
                if (unassigned == 0)
                    return false;
                if (unassigned == 1) {
                    if (!apply_lit(assign, unit_lit))
                        return false;
                    changed = true;
                }
            }
        }
        return true;
    }

    bool dpll(std::vector<int8_t> &assign) const
    {
        if (!unit_propagate(assign))
            return false;
        int branch_var = 0;
        for (int v = 1; v <= d_nvars; v++) {
            if (assign[(size_t) v] == 0) {
                branch_var = v;
                break;
            }
        }
        if (branch_var == 0)
            return true;

        std::vector<int8_t> saved = assign;
        assign[(size_t) branch_var] = 1;
        if (dpll(assign))
            return true;

        assign = std::move(saved);
        assign[(size_t) branch_var] = -1;
        if (dpll(assign))
            return true;

        assign[(size_t) branch_var] = 0;
        return false;
    }

    bool init(const SatCnf &cnf)
    {
        d_ok = false;
        d_last_sat = false;
        d_nvars = cnf.nvars;
        d_clauses.clear();
        d_clauses.reserve(cnf.clauses.size());
        for (const auto &cl : cnf.clauses) {
            for (int lit : cl) {
                if (!valid_lit(lit)) {
                    ereport(ERROR,
                            (errmsg("policy: SAT CNF init failed: invalid literal %d (nvars=%d)",
                                    lit, d_nvars)));
                    return false;
                }
            }
            d_clauses.push_back(cl);
        }
        d_ok = true;
        return true;
    }
};

struct AstParser {
    std::string src;
    size_t pos = 0;
    std::vector<BoolAst *> nodes;

    explicit AstParser(const std::string &s) : src(s) {}

    ~AstParser()
    {
        for (BoolAst *n : nodes)
            delete n;
    }

    void skip_ws()
    {
        while (pos < src.size() && std::isspace((unsigned char)src[pos])) pos++;
    }

    bool eat_char(char c)
    {
        skip_ws();
        if (pos < src.size() && src[pos] == c) {
            pos++;
            return true;
        }
        return false;
    }

    bool eat_word_ci(const char *w)
    {
        skip_ws();
        size_t n = std::strlen(w);
        if (pos + n > src.size()) return false;
        for (size_t i = 0; i < n; i++) {
            if (std::tolower((unsigned char)src[pos + i]) != std::tolower((unsigned char)w[i]))
                return false;
        }
        size_t after = pos + n;
        if (after < src.size()) {
            char c = src[after];
            if (std::isalnum((unsigned char)c) || c == '_')
                return false;
        }
        pos = after;
        return true;
    }

    BoolAst *node(AstType t, int var = -1, BoolAst *l = nullptr, BoolAst *r = nullptr)
    {
        BoolAst *n = new BoolAst();
        n->type = t;
        n->var_id = var;
        n->left = l;
        n->right = r;
        nodes.push_back(n);
        return n;
    }

    BoolAst *parse_var()
    {
        skip_ws();
        if (pos >= src.size() || (src[pos] != 'y' && src[pos] != 'Y'))
            return nullptr;
        size_t p = pos + 1;
        int sign = 1;
        if (p < src.size() && (src[p] == '+' || src[p] == '-')) {
            if (src[p] == '-')
                sign = -1;
            p++;
        }
        int id = 0;
        bool any = false;
        while (p < src.size() && std::isdigit((unsigned char)src[p])) {
            id = id * 10 + (src[p] - '0');
            any = true;
            p++;
        }
        if (!any) return nullptr;
        pos = p;
        return node(AstType::VAR, sign * id);
    }

    BoolAst *parse_atom()
    {
        skip_ws();
        if (eat_char('(')) {
            BoolAst *e = parse_or();
            if (!eat_char(')'))
                return nullptr;
            return e;
        }
        return parse_var();
    }

    BoolAst *parse_and()
    {
        BoolAst *lhs = parse_atom();
        if (!lhs) return nullptr;
        while (true) {
            size_t save = pos;
            if (!eat_word_ci("and")) {
                pos = save;
                break;
            }
            BoolAst *rhs = parse_atom();
            if (!rhs) return nullptr;
            lhs = node(AstType::AND, -1, lhs, rhs);
        }
        return lhs;
    }

    BoolAst *parse_or()
    {
        BoolAst *lhs = parse_and();
        if (!lhs) return nullptr;
        while (true) {
            size_t save = pos;
            if (!eat_word_ci("or")) {
                pos = save;
                break;
            }
            BoolAst *rhs = parse_and();
            if (!rhs) return nullptr;
            lhs = node(AstType::OR, -1, lhs, rhs);
        }
        return lhs;
    }
};

using DnfTerm = std::vector<int>;
using DnfList = std::vector<DnfTerm>;

static void normalize_term(DnfTerm *t)
{
    std::sort(t->begin(), t->end());
    t->erase(std::unique(t->begin(), t->end()), t->end());
}

static DnfList dnf_or(const DnfList &a, const DnfList &b)
{
    DnfList out = a;
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

static DnfList dnf_and(const DnfList &a, const DnfList &b, size_t cap)
{
    DnfList out;
    if (a.empty() || b.empty())
        return out;
    out.reserve(std::min(cap, a.size() * b.size()));
    for (const auto &ta : a) {
        for (const auto &tb : b) {
            DnfTerm t = ta;
            t.insert(t.end(), tb.begin(), tb.end());
            normalize_term(&t);
            out.push_back(std::move(t));
            if (out.size() > cap)
                ereport(ERROR,
                        (errmsg("policy: DNF expansion exceeded cap=%zu", cap)));
        }
    }
    return out;
}

static DnfList ast_to_dnf(const BoolAst *node, size_t cap)
{
    if (!node) return {};
    if (node->type == AstType::VAR) {
        if (node->var_id <= 0) {
            // y0 is FALSE sentinel from evaluator.
            return {};
        }
        DnfList out;
        out.push_back({node->var_id});
        return out;
    }
    if (node->type == AstType::OR)
        return dnf_or(ast_to_dnf(node->left, cap), ast_to_dnf(node->right, cap));
    return dnf_and(ast_to_dnf(node->left, cap), ast_to_dnf(node->right, cap), cap);
}

static void dedup_dnf_terms(DnfList *terms)
{
    if (!terms || terms->empty())
        return;
    std::sort(terms->begin(), terms->end());
    terms->erase(std::unique(terms->begin(), terms->end()), terms->end());
}

static void flatten_ast_by_op(const BoolAst *node,
                              AstType op,
                              std::vector<const BoolAst *> *out)
{
    if (!node || !out)
        return;
    if (node->type == op) {
        flatten_ast_by_op(node->left, op, out);
        flatten_ast_by_op(node->right, op, out);
        return;
    }
    out->push_back(node);
}

static void flatten_policy_composition_chain(const BoolAst *node,
                                             AstType op,
                                             std::vector<const BoolAst *> *out)
{
    if (!node || !out)
        return;
    std::vector<const BoolAst *> rev;
    const BoolAst *cur = node;
    while (cur && cur->type == op && cur->left && cur->right) {
        rev.push_back(cur->right);
        cur = cur->left;
    }
    if (cur)
        rev.push_back(cur);
    for (auto it = rev.rbegin(); it != rev.rend(); ++it)
        out->push_back(*it);
}

static BoolAst *clone_bool_ast_palloc(const BoolAst *node)
{
    if (!node)
        return nullptr;
    BoolAst *out = (BoolAst *)palloc0(sizeof(BoolAst));
    out->type = node->type;
    out->var_id = node->var_id;
    out->left = clone_bool_ast_palloc(node->left);
    out->right = clone_bool_ast_palloc(node->right);
    return out;
}

static void collect_ast_positive_vars(const BoolAst *node, std::vector<int> *out)
{
    if (!node || !out)
        return;
    if (node->type == AstType::VAR) {
        if (node->var_id > 0)
            out->push_back(node->var_id);
        return;
    }
    collect_ast_positive_vars(node->left, out);
    collect_ast_positive_vars(node->right, out);
}

static bool remap_ast_vars_inplace(BoolAst *node, const std::vector<int> &local_to_global)
{
    if (!node)
        return true;
    if (node->type == AstType::VAR) {
        if (node->var_id <= 0)
            return true;
        int lid = node->var_id;
        if (lid < 0 || lid >= (int)local_to_global.size())
            return false;
        int gid = local_to_global[(size_t)lid];
        if (gid <= 0)
            return false;
        node->var_id = gid;
        return true;
    }
    return remap_ast_vars_inplace(node->left, local_to_global) &&
           remap_ast_vars_inplace(node->right, local_to_global);
}

struct Loaded;
struct TargetPlan;

static bool mark_needed_columns_for_formula(const std::string &target,
                                            const BoolAst *root,
                                            Loaded *loaded,
                                            TargetPlan *tp);

struct ColRef {
    std::string table;
    std::string col;

    std::string key() const
    {
        return table + "." + col;
    }
};

static bool parse_colref(const std::string &s, ColRef *out)
{
    if (!out) return false;
    auto p = s.find('.');
    if (p == std::string::npos || p == 0 || p + 1 >= s.size())
        return false;
    out->table = s.substr(0, p);
    out->col = s.substr(p + 1);
    return true;
}

static bool parse_schema_key(const std::string &key, ColRef *out, int *class_id, bool *is_join)
{
    if (!out || !class_id || !is_join)
        return false;
    if (key.rfind("join:", 0) == 0) {
        *is_join = true;
        std::string rest = key.substr(5);
        std::string table_col = rest;
        int cid = -1;
        auto p = rest.find(" class=");
        if (p != std::string::npos) {
            table_col = rest.substr(0, p);
            cid = std::atoi(rest.substr(p + 7).c_str());
        }
        if (!parse_colref(table_col, out))
            return false;
        *class_id = cid;
        return true;
    }
    if (key.rfind("const:", 0) == 0) {
        *is_join = false;
        std::string rest = key.substr(6);
        if (!parse_colref(rest, out))
            return false;
        *class_id = -1;
        return true;
    }
    return false;
}

enum class DictType {
    TEXT,
    NUMERIC,
};

static DictType parse_dict_type_str(const std::string &s)
{
    std::string t = lower_str(trim_ws(s));
    if (t.find("int") != std::string::npos) return DictType::NUMERIC;
    if (t.find("numeric") != std::string::npos) return DictType::NUMERIC;
    if (t.find("float") != std::string::npos) return DictType::NUMERIC;
    if (t.find("double") != std::string::npos) return DictType::NUMERIC;
    if (t.find("decimal") != std::string::npos) return DictType::NUMERIC;
    return DictType::TEXT;
}

static bool parse_number(const std::string &s, double *out)
{
    if (!out) return false;
    char *end = nullptr;
    errno = 0;
    double v = std::strtod(s.c_str(), &end);
    if (errno != 0 || end == s.c_str() || *end != '\0')
        return false;
    *out = v;
    return true;
}

enum class AtomKind {
    JOIN,
    CONST,
    COLCOL,
};

enum class ConstOp {
    EQ,
    LT,
    LE,
    GT,
    GE,
    NE,
};

static inline bool is_ordered_cmp(ConstOp op);

struct Atom {
    int id = -1;
    AtomKind kind = AtomKind::CONST;
    int join_class_id = -1;
    std::string lhs_schema_key;
    std::string rhs_schema_key;
    ColRef left;
    ColRef right;
    ConstOp op = ConstOp::EQ;
    std::vector<std::string> values;
};

struct ArtifactBlob {
    const uint8_t *data = nullptr;
    size_t len = 0;
    bytea *owned = nullptr;
};

struct ArtifactStore {
    mutable std::unordered_map<std::string, ArtifactBlob> blobs;
    mutable std::vector<bytea *> owned;

    bool get(const std::string &name, ArtifactBlob *out) const
    {
        auto it = blobs.find(name);
        if (it != blobs.end()) {
            if (out) *out = it->second;
            return true;
        }
        bytea *b = cf_fetch_file_bytea(name.c_str());
        if (!b)
            return false;
        owned.push_back(b);
        ArtifactBlob bb;
        bb.data = (const uint8_t *)VARDATA(b);
        bb.len = (size_t)(VARSIZE(b) - VARHDRSZ);
        bb.owned = b;
        blobs[name] = bb;
        if (out) *out = bb;
        return true;
    }
};

struct TableData {
    enum class CodeFormat {
        NONE,
        CB03_MANIFEST,
        CB04_MANIFEST,
        CB02_SINGLE,
        RAW,
    };

    std::string name;

    std::vector<std::string> meta_cols;            // table.col list in code order
    std::unordered_map<std::string, int> col_idx;  // table.col -> index

    std::vector<int32_t> ctid_blk;
    std::vector<int32_t> ctid_off;
    uint32 total_blocks = 0;

    CodeFormat code_format = CodeFormat::NONE;
    ArtifactBlob code_base;
    uint32 cb03_total_rows = 0;
    uint32 cb03_chunk_rows = 0;
    int cb03_ntoks = -1;
    int cb03_chunk_count = 0;

    uint32 nrows = 0;
    int ntoks = 0;

    std::set<int> needed_cols;
    std::vector<std::vector<int32_t>> decoded_cols;  // indexed by meta col index
};

struct SignatureCacheEntry {
    std::string table;
    std::vector<int> schema_cols;          // meta col indexes in signature order
    std::vector<int> schema_pos_by_col;    // meta col idx -> schema pos, -1 if absent
    uint32 nsig = 0;
    std::vector<int32_t> sig_tokens;       // flattened [sid * schema_cols.size() + pos]
    std::vector<uint32_t> row_offsets;     // size nsig + 1, rows for sid in rows_flat[offsets[sid]:offsets[sid+1])
    std::vector<uint32_t> rows_flat;       // concatenated row ids grouped by sid
    std::vector<uint32_t> sig_mask_offsets;   // size nsig + 1, sparse triples per signature
    std::vector<uint32_t> sig_mask_blocks;    // triple: heap block
    std::vector<uint8_t> sig_mask_word_idx;   // triple: word index inside block
    std::vector<uint64_t> sig_mask_word_vals; // triple: OR mask for that word
    size_t mask_mem_bytes = 0;
    size_t mem_bytes = 0;
};

struct BinIndexCacheEntry {
    std::string table;
    int domain_id = -1;
    std::vector<uint32_t> off;   // ntokens + 1
    std::vector<uint32_t> rids;  // concatenated rid slices
    size_t mem_bytes = 0;
};

static uint64_t hash_row_tokens(const std::vector<int32_t> &toks);

struct CanonTermMapCacheEntry {
    std::string table;
    std::vector<int> canon_schema_cols;
    std::vector<int> term_schema_cols;
    std::vector<int32_t> canon_to_term_sid;  // size = canon nsig, -1 invalid
    size_t mem_bytes = 0;
};

struct KeyVecHash {
    size_t operator()(const std::vector<int32_t> &v) const
    {
        return (size_t)hash_row_tokens(v);
    }
};

struct RestrictKeyIndexCacheEntry {
    std::string table;
    std::vector<int> canon_schema_cols;
    std::vector<int> key_col_idxs;  // table meta col idxs (subset of canonical schema)
    std::unordered_map<std::vector<int32_t>, std::vector<uint32_t>, KeyVecHash> key_to_canon_sids;
    size_t mem_bytes = 0;
};

struct ClausePredicate {
    int atom_id = -1;
    int col_idx = -1;
    TokenBitset allowed;
    const std::vector<int32_t> *col_data = nullptr;
};

struct ClauseClassGroup {
    int domain_id = -1;
    int class_pos = -1;  // clause-local variable position
    std::vector<int> col_idxs;
    std::vector<const std::vector<int32_t> *> col_data;
};

struct ClauseComparator {
    int atom_id = -1;
    int left_pos = -1;      // clause-local variable position
    int right_pos = -1;     // clause-local variable position
    int domain_id = -1;     // shared comparable domain id
    ConstOp op = ConstOp::EQ;
    const std::vector<int32_t> *rank_data = nullptr;
};

struct ClauseTablePlan {
    std::string table;
    std::vector<ClauseClassGroup> class_groups;
    std::vector<ClausePredicate> predicates;
};

struct ClausePlan {
    std::string target;
    std::vector<int> atom_ids;
    std::vector<ClauseTablePlan> tables;
    std::vector<int> join_classes;      // variable position -> domain_id
    std::vector<ClauseComparator> compares;
    bool has_join_atom = false;
    bool has_colcmp_atom = false;
    bool target_present = false;
    bool unsat = false;
    bool acyclic_hint = false;
};

struct TargetLocalAtom {
    int var_id = -1;
    int atom_id = -1;
    int col_idx = -1;
    TokenBitset allowed;
    const std::vector<int32_t> *col_data = nullptr;
};

struct TargetPlan {
    std::string target;
    std::vector<ClausePlan> clauses;
    std::vector<std::vector<ClausePlan>> restrictive_clause_sets;
    bool factored_enabled = false;
    bool deny_all = false;
    std::vector<BoolAst *> perm_policy_roots;         // permissive policies as separate AST roots
    std::vector<BoolAst *> rest_policy_roots;         // restrictive policies as separate AST roots
    bool local_formula_enabled = false;
    std::vector<FormulaToken> local_formula_rpn;
    std::vector<TargetLocalAtom> local_formula_atoms;
    std::vector<int> local_var_slot;
    BoolAst *formula_root = nullptr;                 // full target formula over y-atom vars
    std::vector<int> formula_atom_ids;               // positive y-ids referenced by formula_root
    std::vector<std::string> formula_tables;         // tables referenced by atoms in formula_root
};

struct ScanQualLocalAtom {
    enum class Kind {
        COL_CONST = 1,
        COL_COL = 2,
    };
    Kind kind = Kind::COL_CONST;
    std::string target_table;
    std::string lhs_schema_key;  // table.col
    std::string rhs_schema_key;  // table.col (COL_COL only)
    ConstOp op = ConstOp::EQ;
    std::string const_value;     // COL_CONST only
};

struct Loaded {
    ArtifactStore artifacts;

    std::unordered_map<std::string, TableData> tables;
    std::unordered_map<std::string, std::vector<std::string>> dicts;
    std::unordered_map<std::string, DictType> dict_types;
    std::unordered_set<std::string> dict_sorted;
    std::unordered_map<int, std::vector<std::string>> domain_dicts;
    std::unordered_map<int, DictType> domain_dict_types;
    std::unordered_set<int> domain_dict_sorted;
    std::unordered_map<int, std::vector<int32_t>> domain_token_rank;
    std::unordered_set<int> domain_has_rank;

    std::unordered_map<int, Atom> atoms_by_id;
    std::unordered_map<std::string, int> atom_id_by_canon;

    std::unordered_map<std::string, int> join_class_by_col;
    std::unordered_map<std::string, int> col_domain_by_col;  // artifact domain id from meta/col_domain
    std::map<int, std::vector<std::string>> join_class_cols;

    std::vector<std::string> target_order;
    std::unordered_map<std::string, TargetPlan> targets;

    std::vector<int> class_domain;  // max_token + 1

    mutable std::unordered_map<std::string, SignatureCacheEntry> signature_cache;
    mutable std::unordered_map<std::string, BinIndexCacheEntry> bin_index_cache;
    mutable std::unordered_map<std::string, CanonTermMapCacheEntry> canon_term_map_cache;
    mutable std::unordered_map<std::string, RestrictKeyIndexCacheEntry> restrict_key_index_cache;
    std::unordered_map<std::string, std::vector<ScanQualLocalAtom>> scan_qual_atoms_by_target;
};

struct BuildProfile {
    double artifact_parse_ms = 0.0;
    double atoms_ms = 0.0;
    double propagate_ms = 0.0;
    double project_ms = 0.0;
    double project_mask_ms = 0.0;
    double project_row_ms = 0.0;
    size_t project_mask_bytes = 0;
    int project_n_join_evals_max = 0;
    int project_clause_words_max = 0;
    double decode_ms = 0.0;
    int prop_iters = 0;
    double total_ms = 0.0;
    int clause_plan_count_max = 0;
    uint64 prop_join_scans_total = 0;
    int unique_join_struct_sigs_max = 0;
    std::unordered_map<std::string, uint64> prop_table_scan_counts;
    std::string prop_table_scans_compact;
    uint64 sat_calls = 0;
    double sat_ms = 0.0;
    uint64 sat_models_total = 0;
    uint64 sat_conflicts = 0;
    uint64 sat_decisions = 0;
    uint64 terms_total = 0;
    double term_eval_ms_total = 0.0;
    double combine_algebra_ms = 0.0;
    uint64 allow_rows_total = 0;
    uint64 bin_ops_total = 0;
    uint64 bins_touched_total = 0;
    uint64 bin_rids_scanned_total = 0;
    uint64 heap_rows_scanned_total = 0;
    uint64 allow_cache_hit = 0;
    uint64 allow_cache_miss = 0;
    double allow_cache_build_ms = 0.0;
    uint64 signature_cache_hits = 0;
    uint64 signature_cache_misses = 0;
    uint64 term_code_scans = 0;
    uint64 target_full_row_scans = 0;
    size_t target_rid_bitmap_bytes = 0;
    size_t signature_cache_bytes = 0;
    uint64 active_sig_dense_count = 0;
    uint64 active_sig_sparse_count = 0;
    double active_sig_density_sum = 0.0;
    uint64 domain_set_dense_count = 0;
    uint64 domain_set_sparse_count = 0;
    double domain_set_density_sum = 0.0;
    uint64 block_words_blocks_allocated = 0;
    uint64 block_words_total_blocks = 0;
    size_t block_words_dense_bytes = 0;
    uint64 block_words_nblocks = 0;
    uint64 block_words_nwords_per_block = 0;
    uint64 proj_sig_count = 0;
    uint64 proj_sig_total = 0;
    uint64 proj_sig_new = 0;
    uint64 proj_sig_skipped = 0;
    uint64 proj_mask_or_ops = 0;
    uint64 proj_rid_iters = 0;
    uint64 proj_rid_iters_scan_enforcement = 0;
    uint64 proj_rid_iters_dependency = 0;
    uint64 canon_term_map_cache_hits = 0;
    uint64 canon_term_map_cache_misses = 0;
    double canon_term_map_build_ms = 0.0;
    size_t canon_term_map_bytes = 0;
    double restrict_key_index_build_ms = 0.0;
    uint64 restrict_key_index_entries = 0;
    size_t restrict_key_index_bytes = 0;
    double restrict_key_prune_ms = 0.0;
    uint64 sigmask_cache_hits = 0;
    uint64 sigmask_cache_misses = 0;
    double sigmask_build_ms = 0.0;
    size_t sigmask_bytes = 0;
    size_t bytes_sig_ctid_masks = 0;
    size_t bytes_block_words = 0;
    size_t bytes_artifact_buffers_retained = 0;
    size_t bytes_decoded_buffers_retained = 0;
    uint64 witness_activesig_tables = 0;
    uint64 witness_sig_count_total = 0;
    double support_recompute_ms = 0.0;
    double sig_prune_ms = 0.0;
    uint64 pair_bundle_count = 0;
    double pair_bundle_build_ms = 0.0;
    double pair_bundle_prune_ms = 0.0;
    uint64 pair_bundle_keys_total = 0;
    uint64 pair_bundle_pruned_sigs_total = 0;
    uint64 pair_bundle_iters = 0;
    uint64 qual_atoms_total = 0;
    uint64 qual_atoms_applied = 0;
    uint64 qual_pruned_sigs = 0;
    double qual_prune_ms = 0.0;
    uint64 restrict_sig_tables = 0;
    uint64 restrict_sig_schema_cols_total = 0;
    size_t restrict_sig_bytes_total = 0;
    double restrict_sig_apply_ms = 0.0;
    double restrict_term_apply_ms = 0.0;
    uint64 restrict_term_sigs_kept = 0;
    uint64 restrict_term_sigs_dropped = 0;
    uint64 pf2_enabled_targets = 0;
    uint64 pf2_terms_total = 0;
    uint64 pf2_terms_supported = 0;
    uint64 pf2_terms_single_hub = 0;
    uint64 pf2_terms_two_hop = 0;
    uint64 pf2_terms_tree = 0;
    uint64 pf2_terms_failed_shape = 0;
    int64_t pf2_hub_domain_id = -1;
    uint64 pf2_hub_key_arity = 0;
    uint64 pf2_ntokens = 0;
    uint64 pf2_stamp_rows_scanned_total = 0;
    uint64 pf2_stamp_rows_scanned_A = 0;
    uint64 pf2_stamp_rows_scanned_B = 0;
    double pf2_stamp_ms = 0.0;
    double pf2_stamp_ms_A = 0.0;
    double pf2_stamp_ms_B = 0.0;
    double pf2_tok_and_or_ms = 0.0;
    double pf2_tok_compose_ms = 0.0;
    uint64 pf2_project_bin_rids_total = 0;
    double pf2_project_ms = 0.0;
    uint64 pf2_tree_domains = 0;
    uint64 pf2_tree_tables = 0;
    uint64 pf2_tree_edges = 0;
    uint64 pf2_tree_passes = 0;
    uint64 pf2_tree_table_updates = 0;
    uint64 pf2_tree_rows_scanned_total = 0;
    double pf2_tree_update_ms = 0.0;
    double pf2_tree_project_ms = 0.0;
    uint64 pf2_cmp_total = 0;
    uint64 pf2_cmp_supported = 0;
    uint64 pf2_cmp_key_arity_max = 0;
    double pf2_cmp_summary_build_ms = 0.0;
    uint64 pf2_cmp_summary_keys_total = 0;
    uint64 pf2_cmp_checks_total = 0;
    uint64 pf2_cmp_rejects_total = 0;
    uint64 pf2_cmp_key2_entries = 0;
    size_t pf2_cmp_key2_dense_bytes = 0;
    double pf2_cmp_key2_build_ms = 0.0;
    uint64 pf2_cmp_key2_rows_scanned = 0;
    uint64 pf2_cmp_key2_updates = 0;
    uint64 pf2_cmp_key2_lookups = 0;
    uint64 pf2_cmp_witness_witness_total = 0;
    uint64 pf2_cmp_witness_witness_supported = 0;
    uint64 pf2_cmp_filter_rows_checked = 0;
    uint64 pf2_cmp_filter_rows_reject = 0;
    uint64 pf2_cmp_chain_total = 0;
    uint64 pf2_cmp_chain_supported = 0;
    double pf2_cmp_chain_build_ms = 0.0;
    uint64 pf2_cmp_chain_bridge_rows_scanned = 0;
    uint64 pf2_cmp_chain_compose_steps = 0;
    uint64 pf2_cmp_chain_filter_rows_checked = 0;
    uint64 pf2_cmp_chain_filter_rows_reject = 0;
    double pf2_total_ms = 0.0;
    uint64 class_td_terms_total = 0;
    uint64 class_td_terms_supported = 0;
    uint64 class_td_width_max = 0;
    uint64 class_td_bags = 0;
    double class_td_build_ms = 0.0;
    double class_td_dp_ms = 0.0;
    uint64 class_td_msg_entries_total = 0;
    uint64 class_td_msg_bytes_total = 0;
    uint64 class_td_msg_pairs_total = 0;
    double class_td_join_ms = 0.0;
    double class_td_project_ms = 0.0;
    uint64 class_td_reduction_passes = 0;
    double class_td_reduction_ms = 0.0;
    uint64 class_td_reduction_removed_pairs = 0;
    uint64 class_td_pairs_before = 0;
    uint64 class_td_pairs_after = 0;
    uint64 class_td_elim_order = 0;
    uint64 class_td_peak_msg_pairs = 0;
    uint64 class_td_peak_msg_bytes = 0;
    double class_td_cmp_filter_ms = 0.0;
    uint64 class_td_cmp_filter_removed_pairs = 0;
    uint64 class_td_fail_width = 0;
    int64_t class_td_last_width = -1;
    int64_t class_td_last_bags = -1;
    uint64 class_terms_ok = 0;
    uint64 class_terms_reject = 0;
    uint64 class_route_single_hub = 0;
    uint64 class_route_two_hop = 0;
    uint64 class_route_tree = 0;
    uint64 class_route_cycle_rect = 0;
    uint64 class_route_td_cycle = 0;
    uint64 class_route_reject = 0;
};

struct RestrictSigState {
    std::vector<int> schema_cols;  // canonical query-local schema for the table
    TokenBitset active_sig;        // union across SAT models / final target formula on canonical schema
    mutable std::unordered_map<std::string, TokenBitset> term_restrict_cache;  // term schema key -> projected allowed term sigs
};

static bool append_clause_plans_from_ast(const std::string &target,
                                         const BoolAst *root,
                                         size_t dnf_cap,
                                         Loaded *out,
                                         std::vector<ClausePlan> *dst);

static size_t token_bitset_mem_bytes(const TokenBitset &bs);
static int profile_k();
static std::string profile_query();
struct SparseBlockWords;
static bool get_or_build_bin_index_cache_entry(const Loaded &loaded,
                                               const std::string &table,
                                               int domain_id,
                                               const BinIndexCacheEntry **out_entry);
static bool get_bin_slice(const Loaded &loaded,
                          const std::string &table,
                          int domain_id,
                          int32_t token,
                          const uint32_t **out_rids,
                          size_t *out_len);
static bool row_matches_table_predicates_only(const ClauseTablePlan &tp,
                                              uint32 rid,
                                              const uint8 *restrict_bits);
static bool pf2_get_group_token_on_row(const ClauseClassGroup &cg,
                                       uint32 rid,
                                       int32_t *out_tok);
static std::vector<int> table_needed_signature_schema(const TableData &ti);
static bool get_or_build_signature_cache_entry_with_schema(const Loaded &loaded,
                                                           const std::string &table,
                                                           const TableData &ti,
                                                           const std::vector<int> &schema_cols,
                                                           const SignatureCacheEntry **out_entry,
                                                           BuildProfile *profile);
static bool bind_clause_views(ClausePlan *cl, Loaded *loaded);
static void build_all_allowed_for_target(const TableData &target_ti,
                                         const uint8 *target_rbits,
                                         SparseBlockWords *out_words,
                                         std::vector<uint8_t> *out_rid_bits);

enum class ClassRouteKind {
    SINGLE_HUB,
    TWO_HOP,
    TREE,
    CYCLE_RECT,
    TD_CYCLE,
    REJECT,
};

static uint64_t hash_row_tokens(const std::vector<int32_t> &toks)
{
    uint64_t h = 1469598103934665603ULL;
    for (int32_t v : toks) {
        uint64_t x = (uint64_t)(uint32_t)v;
        h ^= x + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    }
    return h;
}

static std::string bin_index_cache_key(const std::string &table, int domain_id)
{
    return table + "|D" + std::to_string(domain_id);
}

static bool decode_u32_blob(const ArtifactBlob &blob, std::vector<uint32_t> *out)
{
    if (!out)
        return false;
    out->clear();
    if (!blob.data)
        return false;
    if ((blob.len % sizeof(uint32_t)) != 0)
        return false;
    size_t n = blob.len / sizeof(uint32_t);
    out->resize(n);
    if (n > 0)
        std::memcpy(out->data(), blob.data, blob.len);
    return true;
}

static bool get_or_build_bin_index_cache_entry(const Loaded &loaded,
                                               const std::string &table,
                                               int domain_id,
                                               const BinIndexCacheEntry **out_entry)
{
    if (!out_entry)
        return false;
    *out_entry = nullptr;
    if (domain_id < 0)
        return false;

    std::string key = bin_index_cache_key(table, domain_id);
    auto it = loaded.bin_index_cache.find(key);
    if (it != loaded.bin_index_cache.end()) {
        *out_entry = &it->second;
        return true;
    }

    ArtifactBlob off_blob;
    ArtifactBlob rids_blob;
    std::string off_name = "bin/" + table + "/domain_" + std::to_string(domain_id) + ".off";
    std::string rids_name = "bin/" + table + "/domain_" + std::to_string(domain_id) + ".rids";
    if (!loaded.artifacts.get(off_name, &off_blob) || !loaded.artifacts.get(rids_name, &rids_blob)) {
        ereport(ERROR,
                (errmsg("policy: missing bin index artifacts for %s domain %d",
                        table.c_str(), domain_id)));
    }

    BinIndexCacheEntry ent;
    ent.table = table;
    ent.domain_id = domain_id;
    if (!decode_u32_blob(off_blob, &ent.off) || !decode_u32_blob(rids_blob, &ent.rids))
        return false;
    if (ent.off.empty())
        return false;
    if (ent.off.back() != ent.rids.size())
        return false;
    for (size_t i = 1; i < ent.off.size(); i++) {
        if (ent.off[i] < ent.off[i - 1])
            return false;
    }
    ent.mem_bytes = ent.off.size() * sizeof(uint32_t) + ent.rids.size() * sizeof(uint32_t);

    auto [ins_it, inserted] = loaded.bin_index_cache.emplace(std::move(key), std::move(ent));
    if (!inserted)
        return false;
    *out_entry = &ins_it->second;
    return true;
}

static bool get_bin_slice(const Loaded &loaded,
                          const std::string &table,
                          int domain_id,
                          int32_t token,
                          const uint32_t **out_rids,
                          size_t *out_len)
{
    if (out_rids)
        *out_rids = nullptr;
    if (out_len)
        *out_len = 0;
    if (token < 0)
        return true;

    const BinIndexCacheEntry *ent = nullptr;
    if (!get_or_build_bin_index_cache_entry(loaded, table, domain_id, &ent))
        return false;
    if (!ent || ent->off.empty())
        return true;
    size_t t = (size_t)token;
    if (t + 1u >= ent->off.size())
        return true;
    uint32_t begin = ent->off[t];
    uint32_t end = ent->off[t + 1u];
    if (end < begin || (size_t)end > ent->rids.size())
        return false;
    if (out_rids && begin < end)
        *out_rids = ent->rids.data() + begin;
    if (out_len)
        *out_len = (size_t)(end - begin);
    return true;
}

static int find_global_atom_id_for_bundle_atom(const PolicyAtomC *ba, const Loaded *out)
{
    if (!ba || !out)
        return -1;
    if (ba->canon_key && ba->canon_key[0]) {
        auto it = out->atom_id_by_canon.find(ba->canon_key);
        if (it != out->atom_id_by_canon.end())
            return it->second;
    }
    for (const auto &kv : out->atoms_by_id) {
        const Atom &a = kv.second;
        if (a.kind == AtomKind::JOIN && ba->kind == POLICY_ATOM_JOIN_EQ) {
            if (ba->lhs_schema_key && ba->rhs_schema_key &&
                a.lhs_schema_key == ba->lhs_schema_key &&
                a.rhs_schema_key == ba->rhs_schema_key) {
                return a.id;
            }
        } else if (a.kind == AtomKind::COLCOL && ba->kind == POLICY_ATOM_COL_COL) {
            if (ba->lhs_schema_key && ba->rhs_schema_key &&
                a.lhs_schema_key == ba->lhs_schema_key &&
                a.rhs_schema_key == ba->rhs_schema_key &&
                (int)a.op == ba->op) {
                return a.id;
            }
        } else if (a.kind == AtomKind::CONST && ba->kind == POLICY_ATOM_COL_CONST) {
            if (ba->lhs_schema_key && a.lhs_schema_key == ba->lhs_schema_key &&
                (int)a.op == ba->op && (int)a.values.size() == ba->const_count) {
                bool vals_ok = true;
                for (int i = 0; i < ba->const_count; i++) {
                    const char *v = (ba->const_values && ba->const_values[i]) ? ba->const_values[i] : "";
                    if ((size_t)i >= a.values.size() || a.values[(size_t)i] != v) {
                        vals_ok = false;
                        break;
                    }
                }
                if (vals_ok)
                    return a.id;
            }
        }
    }
    return -1;
}

static std::string format_prop_table_scan_counts(const std::unordered_map<std::string, uint64> &counts)
{
    if (counts.empty())
        return "";
    std::vector<std::pair<std::string, uint64>> items;
    items.reserve(counts.size());
    for (const auto &kv : counts)
        items.push_back(kv);
    std::sort(items.begin(), items.end(),
              [](const auto &a, const auto &b) {
                  if (a.second != b.second) return a.second > b.second;
                  return a.first < b.first;
              });
    std::string out;
    out.reserve(items.size() * 16u);
    for (size_t i = 0; i < items.size(); i++) {
        if (i > 0) out.push_back('|');
        out += items[i].first;
        out.push_back(':');
        out += std::to_string((unsigned long long)items[i].second);
    }
    return out;
}

static inline uint64_t hash_combine_u64(uint64_t h, uint64_t v)
{
    // 64-bit mix (boost-like).
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

static uint64_t hash_token_bitset_words(const TokenBitset &bs)
{
    uint64_t h = 1469598103934665603ULL;
    h = hash_combine_u64(h, (uint64_t)bs.nbits);
    h = hash_combine_u64(h, (uint64_t)bs.count());
    bs.for_each_set([&](int32_t tok) {
        h = hash_combine_u64(h, (uint64_t)(uint32_t)tok);
    });
    return h;
}

struct ClauseEvalCache {
    std::unordered_map<std::string, bool> table_witness;
};

struct AllowCacheEntry {
    uint32 n_rows = 0;
    uint32 total_blocks = 0;
    std::vector<uint64_t> words;
    std::vector<uint32_t> block_ids;
    uint64 allowed_rows = 0;
};

static std::unordered_map<std::string, AllowCacheEntry> g_allow_cache;

static std::string current_run_id_string()
{
    const char *cfg = GetConfigOption("custom_filter.run_id", true, false);
    if (!cfg || !cfg[0])
        return "";
    return std::string(cfg);
}

static uint64_t target_plan_policy_fingerprint(const TargetPlan &tp)
{
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&](uint64_t v) {
        h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    };
    mix(tp.deny_all ? 1u : 0u);
    mix((uint64_t)tp.formula_atom_ids.size());
    for (int aid : tp.formula_atom_ids)
        mix((uint64_t)(uint32_t)aid);
    std::vector<int> perm_vars;
    for (const BoolAst *r : tp.perm_policy_roots)
        collect_ast_positive_vars(r, &perm_vars);
    std::sort(perm_vars.begin(), perm_vars.end());
    perm_vars.erase(std::unique(perm_vars.begin(), perm_vars.end()), perm_vars.end());
    mix((uint64_t)perm_vars.size());
    for (int v : perm_vars)
        mix((uint64_t)(uint32_t)v);
    std::vector<int> rest_vars;
    for (const BoolAst *r : tp.rest_policy_roots)
        collect_ast_positive_vars(r, &rest_vars);
    std::sort(rest_vars.begin(), rest_vars.end());
    rest_vars.erase(std::unique(rest_vars.begin(), rest_vars.end()), rest_vars.end());
    mix((uint64_t)rest_vars.size());
    for (int v : rest_vars)
        mix((uint64_t)(uint32_t)v);
    return h;
}

static std::string allow_cache_key_for_target(const TargetPlan &tp,
                                              const TableData &target_ti)
{
    std::string k = current_run_id_string();
    k.push_back('|');
    k += tp.target;
    k += "|rows=" + std::to_string((unsigned long long)target_ti.nrows);
    k += "|blocks=" + std::to_string((unsigned long long)target_ti.total_blocks);
    char hbuf[32];
    snprintf(hbuf, sizeof(hbuf), "%016llx",
             (unsigned long long)target_plan_policy_fingerprint(tp));
    k += "|policy=";
    k += hbuf;
    return k;
}

static std::string table_witness_signature(const ClauseTablePlan &tp, const uint8 *rbits)
{
    std::string key = tp.table;
    key += "|rb=" + std::to_string((unsigned long long)(uintptr_t)rbits);
    key += "|pred=";
    std::vector<std::string> preds;
    preds.reserve(tp.predicates.size());
    for (const auto &pred : tp.predicates) {
        uint64_t ph = hash_token_bitset_words(pred.allowed);
        std::string s = std::to_string(pred.col_idx);
        s.push_back(':');
        char hbuf[32];
        snprintf(hbuf, sizeof(hbuf), "%016llx", (unsigned long long)ph);
        s += hbuf;
        preds.push_back(std::move(s));
    }
    std::sort(preds.begin(), preds.end());
    for (size_t i = 0; i < preds.size(); i++) {
        if (i > 0) key.push_back(';');
        key += preds[i];
    }
    return key;
}

static bool table_has_predicate_witness(const ClauseTablePlan &tp,
                                        const Loaded &loaded,
                                        const TableData &ti,
                                        const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                        std::unordered_map<std::string, bool> *witness_cache = nullptr)
{
    const RestrictSigState *restrict_state = nullptr;
    if (restrict_sigs) {
        auto it_rs = restrict_sigs->find(tp.table);
        if (it_rs != restrict_sigs->end())
            restrict_state = &it_rs->second;
    }

    std::string cache_key;
    if (witness_cache) {
        cache_key = table_witness_signature(tp, nullptr);
        if (restrict_state) {
            cache_key += "|restrict_schema=" + std::to_string(restrict_state->schema_cols.size());
            cache_key += "|restrict_bits=" + std::to_string((unsigned long long)restrict_state->active_sig.count());
        }
        auto it = witness_cache->find(cache_key);
        if (it != witness_cache->end())
            return it->second;
    }

    std::vector<int32_t> rid_to_sid;
    if (restrict_state) {
        const SignatureCacheEntry *sig_entry = nullptr;
        if (!get_or_build_signature_cache_entry_with_schema(loaded,
                                                            tp.table,
                                                            ti,
                                                            restrict_state->schema_cols,
                                                            &sig_entry,
                                                            nullptr)) {
            return false;
        }
        if (!sig_entry)
            return false;
        rid_to_sid.assign(ti.nrows, -1);
        for (uint32 sid = 0; sid < sig_entry->nsig; sid++) {
            uint32 begin = sig_entry->row_offsets[(size_t)sid];
            uint32 end = sig_entry->row_offsets[(size_t)sid + 1u];
            if (begin > end || end > sig_entry->rows_flat.size())
                return false;
            for (uint32 p = begin; p < end; p++) {
                uint32 rid = sig_entry->rows_flat[(size_t)p];
                if (rid < rid_to_sid.size())
                    rid_to_sid[(size_t)rid] = (int32_t)sid;
            }
        }
    }

    bool found = false;
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if (!row_matches_table_predicates_only(tp, rid, nullptr))
            continue;
        if (restrict_state) {
            int32_t sid = (rid < rid_to_sid.size()) ? rid_to_sid[(size_t)rid] : -1;
            if (sid < 0 || !restrict_state->active_sig.test((size_t)sid))
                continue;
        }
        found = true;
        break;
    }
    if (witness_cache)
        (*witness_cache)[cache_key] = found;
    return found;
}

static bool has_magic(const ArtifactBlob &b, const char *magic, size_t n)
{
    return b.data && b.len >= n && std::memcmp(b.data, magic, n) == 0;
}

static bool parse_cb03_manifest(const ArtifactBlob &b,
                                uint32 *out_total,
                                uint32 *out_chunk_rows,
                                int *out_ntoks,
                                int *out_chunk_count)
{
    if (!out_total || !out_chunk_rows || !out_ntoks || !out_chunk_count)
        return false;
    if (!has_magic(b, "CB03", 4) || b.len < 20)
        return false;
    int32_t total_raw = 0;
    int32_t chunk_rows_raw = 0;
    int32_t ntoks_raw = 0;
    int32_t chunks_raw = 0;
    std::memcpy(&total_raw, b.data + 4, sizeof(int32_t));
    std::memcpy(&chunk_rows_raw, b.data + 8, sizeof(int32_t));
    std::memcpy(&ntoks_raw, b.data + 12, sizeof(int32_t));
    std::memcpy(&chunks_raw, b.data + 16, sizeof(int32_t));
    if (total_raw < 0 || chunk_rows_raw < 0 || ntoks_raw < 0 || chunks_raw < 0)
        return false;
    *out_total = (uint32)total_raw;
    *out_chunk_rows = (uint32)chunk_rows_raw;
    *out_ntoks = (int)ntoks_raw;
    *out_chunk_count = (int)chunks_raw;
    return true;
}

static bool parse_cb04_manifest(const ArtifactBlob &b,
                                uint32 *out_total,
                                uint32 *out_chunk_rows,
                                int *out_ntoks,
                                int *out_chunk_count)
{
    if (!out_total || !out_chunk_rows || !out_ntoks || !out_chunk_count)
        return false;
    if (!has_magic(b, "CB04", 4) || b.len < 20)
        return false;
    int32_t total_raw = 0;
    int32_t chunk_rows_raw = 0;
    int32_t ntoks_raw = 0;
    int32_t chunks_raw = 0;
    std::memcpy(&total_raw, b.data + 4, sizeof(int32_t));
    std::memcpy(&chunk_rows_raw, b.data + 8, sizeof(int32_t));
    std::memcpy(&ntoks_raw, b.data + 12, sizeof(int32_t));
    std::memcpy(&chunks_raw, b.data + 16, sizeof(int32_t));
    if (total_raw < 0 || chunk_rows_raw < 0 || ntoks_raw < 0 || chunks_raw < 0)
        return false;
    *out_total = (uint32)total_raw;
    *out_chunk_rows = (uint32)chunk_rows_raw;
    *out_ntoks = (int)ntoks_raw;
    *out_chunk_count = (int)chunks_raw;
    return true;
}

static bool decode_cb02_append(const ArtifactBlob &b,
                               int expect_ntoks,
                               std::function<void(uint32, const uint8_t *, int)> on_row,
                               uint32 rid_base,
                               uint32 *out_rows,
                               int *out_ntoks)
{
    if (!has_magic(b, "CB02", 4) || b.len < 12)
        return false;
    int32_t nrows_raw = 0;
    int32_t payload_len_raw = 0;
    std::memcpy(&nrows_raw, b.data + 4, sizeof(int32_t));
    std::memcpy(&payload_len_raw, b.data + 8, sizeof(int32_t));
    if (nrows_raw < 0 || payload_len_raw < 0)
        return false;
    uint32 nrows = (uint32)nrows_raw;
    size_t payload_len = (size_t)payload_len_raw;
    if (12 + payload_len != b.len)
        return false;

    const uint8_t *p = b.data + 12;
    const uint8_t *end = p + payload_len;
    int ntoks_seen = -1;

    for (uint32 r = 0; r < nrows; r++) {
        PF_CHECK_FOR_INTERRUPTS(r);
        if (p + sizeof(uint16_t) > end)
            return false;
        uint16_t nt = 0;
        std::memcpy(&nt, p, sizeof(uint16_t));
        p += sizeof(uint16_t);
        if (ntoks_seen < 0)
            ntoks_seen = (int)nt;
        else if (ntoks_seen != (int)nt)
            return false;
        if (expect_ntoks >= 0 && (int)nt != expect_ntoks)
            return false;
        size_t bytes = (size_t)nt * sizeof(int32_t);
        if (p + bytes > end)
            return false;
        on_row(rid_base + r, p, (int)nt);
        p += bytes;
    }

    if (p != end)
        return false;

    if (out_rows) *out_rows = nrows;
    if (out_ntoks) *out_ntoks = ntoks_seen;
    return true;
}

static bool decode_cc04_column_append(const ArtifactBlob &b,
                                      uint32 expect_rows,
                                      std::function<void(uint32, int32_t)> on_value,
                                      uint32 rid_base)
{
    if (!has_magic(b, "CC04", 4) || b.len < 16)
        return false;
    int32_t nrows_raw = 0;
    uint16_t bitw = 0;
    uint16_t reserved = 0;
    int32_t payload_len_raw = 0;
    std::memcpy(&nrows_raw, b.data + 4, sizeof(int32_t));
    std::memcpy(&bitw, b.data + 8, sizeof(uint16_t));
    std::memcpy(&reserved, b.data + 10, sizeof(uint16_t));
    std::memcpy(&payload_len_raw, b.data + 12, sizeof(int32_t));
    if (reserved != 0)
        return false;
    if (nrows_raw < 0 || payload_len_raw < 0)
        return false;
    uint32 nrows = (uint32)nrows_raw;
    if (expect_rows > 0 && nrows != expect_rows)
        return false;
    if (bitw == 0 || bitw > 32)
        return false;
    size_t payload_len = (size_t)payload_len_raw;
    if (16 + payload_len != b.len)
        return false;

    const uint8_t *p = b.data + 16;
    const uint8_t *end = p + payload_len;
    uint64_t acc = 0;
    unsigned acc_bits = 0;
    uint64_t mask = (bitw == 32) ? 0xFFFFFFFFULL : ((uint64_t(1) << bitw) - 1ULL);

    for (uint32 r = 0; r < nrows; r++) {
        PF_CHECK_FOR_INTERRUPTS(r);
        while (acc_bits < bitw) {
            if (p >= end)
                return false;
            acc |= (uint64_t)(*p++) << acc_bits;
            acc_bits += 8;
        }
        uint32_t enc = (uint32_t)(acc & mask);
        acc >>= bitw;
        acc_bits -= bitw;
        int32_t tok = (enc == 0u) ? -1 : (int32_t)(enc - 1u);
        on_value(rid_base + r, tok);
    }
    return true;
}

static std::vector<std::string> parse_dict_values(const ArtifactBlob &b)
{
    std::vector<std::string> out;
    if (!b.data || b.len == 0)
        return out;
    const char *ptr = (const char *)b.data;
    int len = (int)b.len;
    int off = 0;
    while (off + 4 <= len) {
        int32 slen = 0;
        std::memcpy(&slen, ptr + off, 4);
        off += 4;
        if (slen < 0 || off + slen > len)
            break;
        out.emplace_back(ptr + off, ptr + off + slen);
        off += slen;
    }
    return out;
}

static ConstOp parse_policy_op(int op)
{
    switch (op) {
        case POLICY_OP_EQ: return ConstOp::EQ;
        case POLICY_OP_LT: return ConstOp::LT;
        case POLICY_OP_LE: return ConstOp::LE;
        case POLICY_OP_GT: return ConstOp::GT;
        case POLICY_OP_GE: return ConstOp::GE;
        case POLICY_OP_NE: return ConstOp::NE;
        default:
            ereport(ERROR, (errmsg("policy: unsupported strict operator code=%d", op)));
    }
}

static size_t token_bitset_mem_bytes(const TokenBitset &bs)
{
    return sizeof(TokenBitset) +
           bs.words.capacity() * sizeof(uint64_t) +
           bs.sparse.capacity() * sizeof(uint32_t);
}

static int profile_k()
{
    const char *v = GetConfigOption("custom_filter.profile_k", true, false);
    if (!v || !v[0]) return 0;
    return std::atoi(v);
}

static std::string profile_query()
{
    const char *v = GetConfigOption("custom_filter.profile_query", true, false);
    if (!v) return "";
    return std::string(v);
}

static bool load_atoms(const PolicyEngineInputC *in, Loaded *out)
{
    if (!in || !out)
        return false;

    auto t0 = Clock::now();
    for (int i = 0; i < in->atom_count; i++) {
        const PolicyAtomC *pa = &in->atoms[i];
        if (!pa || !pa->lhs_schema_key)
            continue;

        Atom a;
        a.id = pa->atom_id;
        a.join_class_id = pa->join_class_id;
        a.lhs_schema_key = pa->lhs_schema_key ? pa->lhs_schema_key : "";
        a.rhs_schema_key = pa->rhs_schema_key ? pa->rhs_schema_key : "";

        if (pa->kind == POLICY_ATOM_JOIN_EQ) {
            a.kind = AtomKind::JOIN;
            ColRef lref, rref;
            int cid = -1;
            bool is_join = false;
            if (!parse_schema_key(a.lhs_schema_key, &lref, &cid, &is_join) || !is_join)
                return false;
            if (!parse_schema_key(a.rhs_schema_key, &rref, &cid, &is_join) || !is_join)
                return false;
            a.left = lref;
            a.right = rref;
            if (a.join_class_id < 0)
                a.join_class_id = cid;
            a.op = ConstOp::EQ;
        } else if (pa->kind == POLICY_ATOM_COL_COL) {
            a.kind = AtomKind::COLCOL;
            ColRef lref, rref;
            int cid_l = -1;
            int cid_r = -1;
            bool is_join_l = false;
            bool is_join_r = false;
            if (!parse_schema_key(a.lhs_schema_key, &lref, &cid_l, &is_join_l) || !is_join_l)
                return false;
            if (!parse_schema_key(a.rhs_schema_key, &rref, &cid_r, &is_join_r) || !is_join_r)
                return false;
            a.left = lref;
            a.right = rref;
            if (a.join_class_id < 0)
                a.join_class_id = (cid_l >= 0) ? cid_l : cid_r;
            a.op = parse_policy_op(pa->op);
        } else if (pa->kind == POLICY_ATOM_COL_CONST) {
            a.kind = AtomKind::CONST;
            ColRef lref;
            int cid = -1;
            bool is_join = false;
            if (!parse_schema_key(a.lhs_schema_key, &lref, &cid, &is_join))
                return false;
            a.left = lref;
            a.op = parse_policy_op(pa->op);
            for (int v = 0; v < pa->const_count; v++) {
                if (pa->const_values && pa->const_values[v])
                    a.values.push_back(pa->const_values[v]);
            }
        } else {
            continue;
        }

        out->atoms_by_id[a.id] = std::move(a);
        if (pa->canon_key && pa->canon_key[0]) {
            out->atom_id_by_canon[pa->canon_key] = pa->atom_id;
        }
    }

    out->scan_qual_atoms_by_target.clear();
    if (in->scan_qual_atom_count > 0 && in->scan_qual_atoms) {
        out->scan_qual_atoms_by_target.reserve((size_t)in->scan_qual_atom_count);
        for (int i = 0; i < in->scan_qual_atom_count; i++) {
            const PolicyScanQualAtomC *qa = &in->scan_qual_atoms[i];
            if (!qa || !qa->target_table || !qa->target_table[0] ||
                !qa->lhs_schema_key || !qa->lhs_schema_key[0]) {
                continue;
            }
            ScanQualLocalAtom a;
            a.target_table = qa->target_table;
            a.lhs_schema_key = qa->lhs_schema_key;
            a.op = parse_policy_op(qa->op);
            if (qa->kind == POLICY_SCAN_QUAL_COL_CONST) {
                a.kind = ScanQualLocalAtom::Kind::COL_CONST;
                if (qa->const_value)
                    a.const_value = qa->const_value;
            } else if (qa->kind == POLICY_SCAN_QUAL_COL_COL) {
                if (!qa->rhs_schema_key || !qa->rhs_schema_key[0])
                    continue;
                a.kind = ScanQualLocalAtom::Kind::COL_COL;
                a.rhs_schema_key = qa->rhs_schema_key;
            } else {
                continue;
            }
            out->scan_qual_atoms_by_target[a.target_table].push_back(std::move(a));
        }
    }

    auto t1 = Clock::now();
    CF_TRACE_LOG("policy: atom_parse_ms=%.3f", Ms(t1 - t0).count());
    return true;
}

static bool load_artifact_metadata(const PolicyArtifactC *arts, int art_count, Loaded *out)
{
    if (!arts || art_count <= 0 || !out)
        return false;

    for (int i = 0; i < art_count; i++) {
        if (!arts[i].name || !arts[i].data)
            continue;
        ArtifactBlob bb;
        bb.data = (const uint8_t *)arts[i].data;
        bb.len = arts[i].len;
        bb.owned = nullptr;
        out->artifacts.blobs[arts[i].name] = bb;
    }

    ArtifactBlob join_classes_blob;
    if (out->artifacts.get("meta/join_classes", &join_classes_blob) && join_classes_blob.data) {
        std::string txt((const char *)join_classes_blob.data, join_classes_blob.len);
        auto lines = split_lines(txt);
        for (const std::string &line : lines) {
            auto cpos = line.find("class=");
            auto cols_pos = line.find("cols=");
            if (cpos == std::string::npos || cols_pos == std::string::npos)
                continue;
            int cid = std::atoi(line.c_str() + cpos + 6);
            std::string list = line.substr(cols_pos + 5);
            std::stringstream ss(list);
            std::string item;
            while (std::getline(ss, item, ',')) {
                item = trim_ws(item);
                if (item.empty()) continue;
                out->join_class_cols[cid].push_back(item);
                out->join_class_by_col[item] = cid;
            }
        }
    }
    ArtifactBlob col_domain_blob;
    if (out->artifacts.get("meta/col_domain", &col_domain_blob) && col_domain_blob.data) {
        std::string txt((const char *)col_domain_blob.data, col_domain_blob.len);
        auto lines = split_lines(txt);
        for (const std::string &line : lines) {
            auto eq = line.find('=');
            if (eq == std::string::npos)
                continue;
            std::string col = trim_ws(line.substr(0, eq));
            std::string rhs = trim_ws(line.substr(eq + 1));
            if (col.empty() || rhs.empty())
                continue;
            int cid = std::atoi(rhs.c_str());
            out->col_domain_by_col[col] = cid;
            out->join_class_by_col[col] = cid;
            out->join_class_cols[cid].push_back(col);
        }
    }

    for (const auto &kv : out->atoms_by_id) {
        const Atom &a = kv.second;
        if (a.kind == AtomKind::JOIN && a.join_class_id >= 0) {
            out->join_class_by_col[a.left.key()] = a.join_class_id;
            out->join_class_by_col[a.right.key()] = a.join_class_id;
            out->join_class_cols[a.join_class_id].push_back(a.left.key());
            out->join_class_cols[a.join_class_id].push_back(a.right.key());
        } else if (a.kind == AtomKind::COLCOL && a.join_class_id >= 0) {
            out->join_class_by_col[a.left.key()] = a.join_class_id;
            out->join_class_by_col[a.right.key()] = a.join_class_id;
            out->join_class_cols[a.join_class_id].push_back(a.left.key());
            out->join_class_cols[a.join_class_id].push_back(a.right.key());
        } else if (a.kind == AtomKind::CONST && a.join_class_id >= 0) {
            out->join_class_by_col[a.left.key()] = a.join_class_id;
            out->join_class_cols[a.join_class_id].push_back(a.left.key());
        }
    }

    for (auto &kv : out->join_class_cols) {
        auto &v = kv.second;
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }

    for (const auto &kv : out->artifacts.blobs) {
        const std::string &name = kv.first;
        const ArtifactBlob &bb = kv.second;

        if (name.rfind("meta/cols/", 0) == 0) {
            std::string table = name.substr(std::strlen("meta/cols/"));
            TableData &ti = out->tables[table];
            ti.name = table;
            std::string txt((const char *)bb.data, bb.len);
            ti.meta_cols = split_lines(txt);
            ti.col_idx.clear();
            for (size_t i = 0; i < ti.meta_cols.size(); i++) {
                ti.col_idx[ti.meta_cols[i]] = (int)i;
            }
            continue;
        }

        if (name.rfind("dict/domain/", 0) == 0) {
            std::string sid = name.substr(std::strlen("dict/domain/"));
            int cid = std::atoi(sid.c_str());
            out->domain_dicts[cid] = parse_dict_values(bb);
            continue;
        }

        if (name.rfind("dict/", 0) == 0) {
            std::string rest = name.substr(std::strlen("dict/"));
            auto p = rest.find('/');
            if (p == std::string::npos) continue;
            std::string key = rest.substr(0, p) + "." + rest.substr(p + 1);
            out->dicts[key] = parse_dict_values(bb);
            continue;
        }

        if (name.rfind("meta/dict_type/domain/", 0) == 0) {
            std::string sid = name.substr(std::strlen("meta/dict_type/domain/"));
            int cid = std::atoi(sid.c_str());
            std::string val((const char *)bb.data, bb.len);
            out->domain_dict_types[cid] = parse_dict_type_str(val);
            continue;
        }

        if (name.rfind("meta/dict_type/", 0) == 0) {
            std::string rest = name.substr(std::strlen("meta/dict_type/"));
            auto p = rest.find('/');
            if (p == std::string::npos) continue;
            std::string key = rest.substr(0, p) + "." + rest.substr(p + 1);
            std::string val((const char *)bb.data, bb.len);
            out->dict_types[key] = parse_dict_type_str(val);
            continue;
        }

        if (name.rfind("meta/dict_sorted/domain/", 0) == 0) {
            std::string sid = name.substr(std::strlen("meta/dict_sorted/domain/"));
            int cid = std::atoi(sid.c_str());
            std::string val((const char *)bb.data, bb.len);
            std::string low = lower_str(trim_ws(val));
            bool sorted = !(low.empty() || low == "0" || low == "off" || low == "false" || low == "no");
            if (sorted)
                out->domain_dict_sorted.insert(cid);
            continue;
        }

        if (name.rfind("meta/dict_sorted/", 0) == 0) {
            std::string rest = name.substr(std::strlen("meta/dict_sorted/"));
            auto p = rest.find('/');
            if (p == std::string::npos) continue;
            std::string key = rest.substr(0, p) + "." + rest.substr(p + 1);
            std::string val((const char *)bb.data, bb.len);
            std::string low = lower_str(trim_ws(val));
            bool sorted = !(low.empty() || low == "0" || low == "off" || low == "false" || low == "no");
            if (sorted)
                out->dict_sorted.insert(key);
            continue;
        }

        if (name.size() > 5 && name.substr(name.size() - 5) == "_ctid") {
            std::string table = name.substr(0, name.size() - 5);
            TableData &ti = out->tables[table];
            ti.name = table;
            size_t n = bb.len / sizeof(int32_t);
            if ((n % 2u) != 0u)
                ereport(ERROR,
                        (errmsg("policy: invalid ctid artifact %s length=%zu", name.c_str(), bb.len)));
            ti.ctid_blk.resize(n / 2u);
            ti.ctid_off.resize(n / 2u);
            const int32_t *arr = (const int32_t *)bb.data;
            for (size_t i = 0; i < n / 2u; i++) {
                ti.ctid_blk[i] = arr[2 * i];
                ti.ctid_off[i] = arr[2 * i + 1];
            }
            continue;
        }

        if (name.rfind("rank/domain/", 0) == 0) {
            std::string sid = name.substr(std::strlen("rank/domain/"));
            int cid = std::atoi(sid.c_str());
            if (bb.len % sizeof(int32_t) != 0) {
                ereport(ERROR,
                        (errmsg("policy: invalid rank/domain artifact %s len=%zu",
                                name.c_str(), bb.len)));
            }
            size_t n = bb.len / sizeof(int32_t);
            std::vector<int32_t> ranks(n, -1);
            if (n > 0)
                std::memcpy(ranks.data(), bb.data, bb.len);
            out->domain_token_rank[cid] = std::move(ranks);
            continue;
        }

        if (name.rfind("meta/dict_rank/domain/", 0) == 0) {
            std::string sid = name.substr(std::strlen("meta/dict_rank/domain/"));
            int cid = std::atoi(sid.c_str());
            std::string val((const char *)bb.data, bb.len);
            std::string low = lower_str(trim_ws(val));
            bool has_rank = !(low.empty() || low == "0" || low == "off" || low == "false" || low == "no");
            if (has_rank)
                out->domain_has_rank.insert(cid);
            continue;
        }

        if (name.size() > 10 && name.substr(name.size() - 10) == "_code_base") {
            std::string table = name.substr(0, name.size() - 10);
            TableData &ti = out->tables[table];
            ti.name = table;
            ti.code_base = bb;

            uint32 total = 0;
            uint32 chunk_rows = 0;
            int ntoks = -1;
            int chunks = 0;
            if (parse_cb04_manifest(bb, &total, &chunk_rows, &ntoks, &chunks)) {
                ti.code_format = TableData::CodeFormat::CB04_MANIFEST;
                ti.cb03_total_rows = total;
                ti.cb03_chunk_rows = chunk_rows;
                ti.cb03_ntoks = ntoks;
                ti.cb03_chunk_count = chunks;
            } else if (parse_cb03_manifest(bb, &total, &chunk_rows, &ntoks, &chunks)) {
                ti.code_format = TableData::CodeFormat::CB03_MANIFEST;
                ti.cb03_total_rows = total;
                ti.cb03_chunk_rows = chunk_rows;
                ti.cb03_ntoks = ntoks;
                ti.cb03_chunk_count = chunks;
            } else if (has_magic(bb, "CB02", 4)) {
                ti.code_format = TableData::CodeFormat::CB02_SINGLE;
            } else {
                ti.code_format = TableData::CodeFormat::RAW;
            }
            continue;
        }

        if (name.size() > 5 && name.substr(name.size() - 5) == "_code") {
            std::string table = name.substr(0, name.size() - 5);
            TableData &ti = out->tables[table];
            ti.name = table;
            ti.code_base = bb;
            ti.code_format = TableData::CodeFormat::RAW;
            continue;
        }
    }

    for (auto &kv : out->tables) {
        TableData &ti = kv.second;
        if (!ti.ctid_blk.empty()) {
            ti.nrows = (uint32)ti.ctid_blk.size();
            int32 max_blk = -1;
            for (int32 b : ti.ctid_blk) {
                if (b > max_blk)
                    max_blk = b;
            }
            ti.total_blocks = (max_blk >= 0) ? ((uint32)max_blk + 1u) : 0u;
        }
        if (ti.code_format == TableData::CodeFormat::CB03_MANIFEST ||
            ti.code_format == TableData::CodeFormat::CB04_MANIFEST) {
            if (ti.nrows == 0)
                ti.nrows = ti.cb03_total_rows;
            if (ti.cb03_total_rows != ti.nrows) {
                ereport(ERROR,
                        (errmsg("policy: row mismatch table=%s manifest_rows=%u ctid_rows=%u",
                                ti.name.c_str(), ti.cb03_total_rows, ti.nrows)));
            }
            ti.ntoks = ti.cb03_ntoks;
        }
        if (ti.ntoks < 0 && !ti.meta_cols.empty())
            ti.ntoks = (int)ti.meta_cols.size();
        if (!ti.meta_cols.empty() && ti.ntoks >= 0 && (int)ti.meta_cols.size() != ti.ntoks) {
            ereport(ERROR,
                    (errmsg("policy: ntoks/meta mismatch table=%s ntoks=%d meta_cols=%zu",
                            ti.name.c_str(), ti.ntoks, ti.meta_cols.size())));
        }
        ti.decoded_cols.assign(ti.meta_cols.size(), {});
    }

    return true;
}

static bool eval_const_match(ConstOp op,
                             const std::string &dict_val,
                             const std::vector<std::string> &const_vals,
                             DictType dtype)
{
    if (op == ConstOp::EQ || op == ConstOp::NE) {
        bool found = false;
        for (const auto &v : const_vals) {
            if (dtype == DictType::NUMERIC) {
                double l = 0.0;
                double r = 0.0;
                if (parse_number(dict_val, &l) && parse_number(v, &r)) {
                    if (l == r) {
                        found = true;
                        break;
                    }
                } else if (dict_val == v) {
                    found = true;
                    break;
                }
            } else {
                if (dict_val == v) {
                    found = true;
                    break;
                }
            }
        }
        if (op == ConstOp::NE)
            return !found;
        return found;
    }

    std::string rhs = const_vals.empty() ? "" : const_vals.front();
    if (dtype == DictType::NUMERIC) {
        double l = 0.0;
        double r = 0.0;
        if (parse_number(dict_val, &l) && parse_number(rhs, &r)) {
            switch (op) {
                case ConstOp::LT: return l < r;
                case ConstOp::LE: return l <= r;
                case ConstOp::GT: return l > r;
                case ConstOp::GE: return l >= r;
                default: return false;
            }
        }
    }

    switch (op) {
        case ConstOp::LT: return dict_val < rhs;
        case ConstOp::LE: return dict_val <= rhs;
        case ConstOp::GT: return dict_val > rhs;
        case ConstOp::GE: return dict_val >= rhs;
        default: return false;
    }
}

static size_t lower_bound_text(const std::vector<std::string> &dict_vals, const std::string &rhs)
{
    auto it = std::lower_bound(dict_vals.begin(), dict_vals.end(), rhs);
    return (size_t)(it - dict_vals.begin());
}

static size_t upper_bound_text(const std::vector<std::string> &dict_vals, const std::string &rhs)
{
    auto it = std::upper_bound(dict_vals.begin(), dict_vals.end(), rhs);
    return (size_t)(it - dict_vals.begin());
}

static bool lower_bound_numeric(const std::vector<std::string> &dict_vals, double rhs, size_t *out_idx)
{
    if (!out_idx) return false;
    size_t lo = 0;
    size_t hi = dict_vals.size();
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        double v = 0.0;
        if (!parse_number(dict_vals[mid], &v))
            return false;
        if (v < rhs)
            lo = mid + 1;
        else
            hi = mid;
    }
    *out_idx = lo;
    return true;
}

static bool upper_bound_numeric(const std::vector<std::string> &dict_vals, double rhs, size_t *out_idx)
{
    if (!out_idx) return false;
    size_t lo = 0;
    size_t hi = dict_vals.size();
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        double v = 0.0;
        if (!parse_number(dict_vals[mid], &v))
            return false;
        if (v <= rhs)
            lo = mid + 1;
        else
            hi = mid;
    }
    *out_idx = lo;
    return true;
}

static bool find_eq_token_sorted(const std::vector<std::string> &dict_vals,
                                 const std::string &rhs,
                                 DictType dtype,
                                 size_t *out_tok)
{
    if (!out_tok) return false;
    if (dtype == DictType::NUMERIC) {
        double r = 0.0;
        if (!parse_number(rhs, &r))
            return false;
        size_t idx = 0;
        if (!lower_bound_numeric(dict_vals, r, &idx))
            return false;
        if (idx >= dict_vals.size())
            return false;
        double v = 0.0;
        if (!parse_number(dict_vals[idx], &v))
            return false;
        if (v != r)
            return false;
        *out_tok = idx;
        return true;
    }

    size_t idx = lower_bound_text(dict_vals, rhs);
    if (idx >= dict_vals.size() || dict_vals[idx] != rhs)
        return false;
    *out_tok = idx;
    return true;
}

static TokenBitset build_allowed_token_set(const Atom &a,
                                           const std::vector<std::string> &dict_vals,
                                           DictType dtype,
                                           bool dict_sorted)
{
    TokenBitset bits(dict_vals.size());
    if (dict_vals.empty())
        return bits;

    // Fast path for sorted dicts (binary search/range set).
    if (dict_sorted) {
        if (a.op == ConstOp::EQ) {
            std::string rhs = a.values.empty() ? "" : a.values.front();
            size_t tok = 0;
            if (find_eq_token_sorted(dict_vals, rhs, dtype, &tok))
                bits.set(tok);
            return bits;
        }

        if (a.op == ConstOp::NE) {
            bits.fill_all();
            for (const auto &rhs : a.values) {
                size_t tok = 0;
                if (find_eq_token_sorted(dict_vals, rhs, dtype, &tok))
                    bits.clear(tok);
            }
            return bits;
        }

        // Range ops use the first RHS value, matching eval_const_match().
        std::string rhs = a.values.empty() ? "" : a.values.front();
        size_t lo = 0;
        size_t hi = 0;

        if (dtype == DictType::NUMERIC) {
            double r = 0.0;
            if (!parse_number(rhs, &r))
                dict_sorted = false;  // fall back
            else {
                if (a.op == ConstOp::LT || a.op == ConstOp::GE) {
                    if (!lower_bound_numeric(dict_vals, r, &lo))
                        dict_sorted = false;
                }
                if (a.op == ConstOp::LE || a.op == ConstOp::GT) {
                    if (!upper_bound_numeric(dict_vals, r, &hi))
                        dict_sorted = false;
                }
                if (a.op == ConstOp::LT) {
                    bits.set_range(0, lo);
                    return bits;
                }
                if (a.op == ConstOp::LE) {
                    bits.set_range(0, hi);
                    return bits;
                }
                if (a.op == ConstOp::GT) {
                    bits.set_range(hi, dict_vals.size());
                    return bits;
                }
                if (a.op == ConstOp::GE) {
                    bits.set_range(lo, dict_vals.size());
                    return bits;
                }
            }
        } else {
            if (a.op == ConstOp::LT) {
                hi = lower_bound_text(dict_vals, rhs);
                bits.set_range(0, hi);
                return bits;
            }
            if (a.op == ConstOp::LE) {
                hi = upper_bound_text(dict_vals, rhs);
                bits.set_range(0, hi);
                return bits;
            }
            if (a.op == ConstOp::GT) {
                lo = upper_bound_text(dict_vals, rhs);
                bits.set_range(lo, dict_vals.size());
                return bits;
            }
            if (a.op == ConstOp::GE) {
                lo = lower_bound_text(dict_vals, rhs);
                bits.set_range(lo, dict_vals.size());
                return bits;
            }
        }
        // Fall through to scan if numeric parse/bounds failed.
    }

    for (size_t i = 0; i < dict_vals.size(); i++) {
        if (eval_const_match(a.op, dict_vals[i], a.values, dtype))
            bits.set(i);
    }
    return bits;
}

static bool is_clause_acyclic_hint(const ClausePlan &cl)
{
    std::unordered_map<int, int> idx;
    for (int i = 0; i < (int)cl.join_classes.size(); i++)
        idx[i] = i;
    int n = (int)idx.size();
    if (n <= 1)
        return true;

    std::vector<int> parent(n);
    for (int i = 0; i < n; i++) parent[i] = i;
    auto findp = [&](int x) {
        int r = x;
        while (parent[r] != r) r = parent[r];
        while (parent[x] != x) {
            int nx = parent[x];
            parent[x] = r;
            x = nx;
        }
        return r;
    };

    auto unite = [&](int a, int b) -> bool {
        int ra = findp(a);
        int rb = findp(b);
        if (ra == rb)
            return false;
        parent[rb] = ra;
        return true;
    };

    for (const auto &tp : cl.tables) {
        std::set<int> uniq;
        for (const auto &cg : tp.class_groups)
            uniq.insert(cg.class_pos);
        if (uniq.size() > 2)
            return false;
        if (uniq.size() == 2) {
            auto it = uniq.begin();
            int a = idx[*it++];
            int b = idx[*it];
            if (!unite(a, b))
                return false;
        }
    }
    return true;
}

static bool append_clause_plans_from_dnf(const std::string &target,
                                         const DnfList &dnf_terms,
                                         Loaded *out,
                                         std::vector<ClausePlan> *dst)
{
    if (!out || !dst)
        return false;

    for (const DnfTerm &term : dnf_terms) {
        ClausePlan cl;
        cl.target = target;
        cl.atom_ids = term;

        struct TempTable {
            std::unordered_map<int, std::vector<std::string>> var_cols;  // var_pos -> list of table.col
            struct TempPred {
                int atom_id = -1;
                std::string col_key;
                TokenBitset allowed;
            };
            std::vector<TempPred> preds;
        };

        struct TempCmp {
            int atom_id = -1;
            int left_pos = -1;
            int right_pos = -1;
            int domain_id = -1;
            ConstOp op = ConstOp::EQ;
        };

        struct ColNode {
            std::string key;
            std::string table;
            int domain_hint = -1;
        };

        std::unordered_map<std::string, TempTable> tmp_tables;
        std::vector<TempCmp> tmp_cmps;
        std::vector<ColNode> nodes;
        std::unordered_map<std::string, int> node_idx;
        std::vector<int> parent;
        std::vector<uint8_t> rankv;

        bool unsat = false;
        bool hard_error = false;

        auto ensure_node = [&](const ColRef &cr, int domain_hint) -> int {
            std::string key = cr.key();
            auto it = node_idx.find(key);
            if (it != node_idx.end()) {
                int idx = it->second;
                if (domain_hint >= 0) {
                    if (nodes[(size_t)idx].domain_hint < 0) {
                        nodes[(size_t)idx].domain_hint = domain_hint;
                    } else if (nodes[(size_t)idx].domain_hint != domain_hint) {
                        ereport(ERROR,
                                (errmsg("policy: inconsistent domain hints for %s: %d vs %d",
                                        key.c_str(),
                                        nodes[(size_t)idx].domain_hint,
                                        domain_hint)));
                    }
                }
                return idx;
            }
            int idx = (int)nodes.size();
            ColNode n;
            n.key = key;
            n.table = cr.table;
            n.domain_hint = domain_hint;
            nodes.push_back(std::move(n));
            node_idx[key] = idx;
            parent.push_back(idx);
            rankv.push_back(0);
            return idx;
        };

        std::function<int(int)> findp = [&](int x) -> int {
            while (parent[(size_t)x] != x) {
                parent[(size_t)x] = parent[(size_t)parent[(size_t)x]];
                x = parent[(size_t)x];
            }
            return x;
        };
        auto unite = [&](int a, int b) {
            int ra = findp(a);
            int rb = findp(b);
            if (ra == rb)
                return;
            uint8_t rka = rankv[(size_t)ra];
            uint8_t rkb = rankv[(size_t)rb];
            if (rka < rkb)
                std::swap(ra, rb);
            parent[(size_t)rb] = ra;
            if (rka == rkb)
                rankv[(size_t)ra]++;
        };

        for (int aid : term) {
            auto ita = out->atoms_by_id.find(aid);
            if (ita == out->atoms_by_id.end()) {
                unsat = true;
                break;
            }
            const Atom &a = ita->second;

            if (a.kind == AtomKind::JOIN) {
                cl.has_join_atom = true;
                if (a.join_class_id < 0) {
                    unsat = true;
                    break;
                }
                int li = ensure_node(a.left, a.join_class_id);
                int ri = ensure_node(a.right, a.join_class_id);
                unite(li, ri);
            } else if (a.kind == AtomKind::COLCOL) {
                cl.has_colcmp_atom = true;
                if (a.join_class_id < 0) {
                    ereport(ERROR,
                            (errmsg("policy: col-col atom missing domain id y%d (%s %s %s)",
                                    a.id,
                                    a.left.key().c_str(),
                                    (a.op == ConstOp::NE ? "!=" :
                                     a.op == ConstOp::LT ? "<" :
                                     a.op == ConstOp::LE ? "<=" :
                                     a.op == ConstOp::GT ? ">" :
                                     a.op == ConstOp::GE ? ">=" : "="),
                                    a.right.key().c_str())));
                }
                (void)ensure_node(a.left, a.join_class_id);
                (void)ensure_node(a.right, a.join_class_id);
            } else {
                /*
                 * Unary const atoms are local table predicates and must not create
                 * join-variable components. Join vars are induced only by JOIN/COLCOL atoms.
                 */
            }
        }

        if (unsat) {
            cl.unsat = true;
            dst->push_back(std::move(cl));
            continue;
        }

        std::unordered_map<int, std::vector<int>> root_members;
        for (size_t i = 0; i < nodes.size(); i++) {
            int r = findp((int)i);
            root_members[r].push_back((int)i);
        }

        struct RootOrd {
            int root = -1;
            std::string ord_key;
        };
        std::vector<RootOrd> roots;
        roots.reserve(root_members.size());
        for (const auto &kv : root_members) {
            std::string kmin;
            bool first = true;
            for (int ni : kv.second) {
                const std::string &ck = nodes[(size_t)ni].key;
                if (first || ck < kmin) {
                    kmin = ck;
                    first = false;
                }
            }
            roots.push_back({kv.first, kmin});
        }
        std::sort(roots.begin(), roots.end(),
                  [](const RootOrd &a, const RootOrd &b) {
                      if (a.ord_key != b.ord_key) return a.ord_key < b.ord_key;
                      return a.root < b.root;
                  });

        std::unordered_map<int, int> root_to_var;
        for (const RootOrd &ro : roots) {
            auto itm = root_members.find(ro.root);
            if (itm == root_members.end())
                continue;
            int domain_id = -1;
            for (int ni : itm->second) {
                const ColNode &cn = nodes[(size_t)ni];
                int d = -1;
                auto it_dom = out->join_class_by_col.find(cn.key);
                if (it_dom != out->join_class_by_col.end())
                    d = it_dom->second;
                if (d < 0)
                    d = cn.domain_hint;
                if (d >= 0) {
                    if (domain_id < 0)
                        domain_id = d;
                    else if (domain_id != d) {
                        ereport(ERROR,
                                (errmsg("policy: cross-domain variable component in clause target=%s root=%s (%d vs %d)",
                                        target.c_str(),
                                        ro.ord_key.c_str(),
                                        domain_id,
                                        d)));
                    }
                }
            }
            if (domain_id < 0) {
                hard_error = true;
                break;
            }
            int pos = (int)cl.join_classes.size();
            root_to_var[ro.root] = pos;
            cl.join_classes.push_back(domain_id);
        }
        if (hard_error) {
            unsat = true;
        }

        for (int aid : term) {
            if (unsat) break;
            auto ita = out->atoms_by_id.find(aid);
            if (ita == out->atoms_by_id.end()) {
                unsat = true;
                break;
            }
            const Atom &a = ita->second;

            if (a.kind == AtomKind::JOIN) {
                int li = node_idx[a.left.key()];
                int ri = node_idx[a.right.key()];
                int lv = root_to_var[findp(li)];
                int rv = root_to_var[findp(ri)];
                if (lv != rv) {
                    ereport(ERROR,
                            (errmsg("policy: equijoin atom y%d split into different vars (%d,%d)",
                                    a.id, lv, rv)));
                }
                tmp_tables[a.left.table].var_cols[lv].push_back(a.left.key());
                tmp_tables[a.right.table].var_cols[rv].push_back(a.right.key());
            } else if (a.kind == AtomKind::COLCOL) {
                int li = node_idx[a.left.key()];
                int ri = node_idx[a.right.key()];
                int lv = root_to_var[findp(li)];
                int rv = root_to_var[findp(ri)];
                int dl = (lv >= 0 && lv < (int)cl.join_classes.size()) ? cl.join_classes[(size_t)lv] : -1;
                int dr = (rv >= 0 && rv < (int)cl.join_classes.size()) ? cl.join_classes[(size_t)rv] : -1;
                if (dl < 0 || dr < 0 || dl != dr) {
                    ereport(ERROR,
                            (errmsg("policy: col-col atom y%d uses mismatched domains (%s,%s) domainL=%d domainR=%d",
                                    a.id, a.left.key().c_str(), a.right.key().c_str(), dl, dr)));
                }
                TempCmp cc;
                cc.atom_id = a.id;
                cc.left_pos = lv;
                cc.right_pos = rv;
                cc.domain_id = dl;
                cc.op = a.op;
                tmp_cmps.push_back(std::move(cc));
                tmp_tables[a.left.table].var_cols[lv].push_back(a.left.key());
                tmp_tables[a.right.table].var_cols[rv].push_back(a.right.key());
            } else {
                std::string key = a.left.key();
                DictType dtype = DictType::TEXT;
                bool sorted = false;
                const std::vector<std::string> *dict_vals = nullptr;
                bool used_domain_dict = false;

                if (a.join_class_id >= 0) {
                    auto itdd = out->domain_dicts.find(a.join_class_id);
                    if (itdd != out->domain_dicts.end()) {
                        dict_vals = &itdd->second;
                        used_domain_dict = true;
                        auto itdtype = out->domain_dict_types.find(a.join_class_id);
                        if (itdtype != out->domain_dict_types.end())
                            dtype = itdtype->second;
                        sorted = (out->domain_dict_sorted.find(a.join_class_id) != out->domain_dict_sorted.end());
                    }
                }

                if (!dict_vals) {
                    auto itd = out->dicts.find(key);
                    if (itd != out->dicts.end()) {
                        dict_vals = &itd->second;
                        auto itdt = out->dict_types.find(key);
                        if (itdt != out->dict_types.end())
                            dtype = itdt->second;
                        sorted = (out->dict_sorted.find(key) != out->dict_sorted.end());
                    }
                }

                if (!dict_vals) {
                    if (a.join_class_id >= 0) {
                        ereport(ERROR,
                                (errmsg("policy: missing domain dict for const atom y%d col=%s class=%d",
                                        a.id, key.c_str(), a.join_class_id)));
                    }
                    ereport(ERROR,
                            (errmsg("policy: missing dict for const atom y%d col=%s",
                                    a.id, key.c_str())));
                }

                TokenBitset allowed = build_allowed_token_set(a, *dict_vals, dtype, sorted);
                if (!allowed.any()) {
                    unsat = true;
                    break;
                }

                TempTable::TempPred p;
                p.atom_id = a.id;
                p.col_key = key;
                p.allowed = std::move(allowed);
                tmp_tables[a.left.table].preds.push_back(std::move(p));
                (void)used_domain_dict;

                auto it_node = node_idx.find(a.left.key());
                if (it_node != node_idx.end()) {
                    int idx = it_node->second;
                    int vp = root_to_var[findp(idx)];
                    tmp_tables[a.left.table].var_cols[vp].push_back(a.left.key());
                }
            }
        }

        cl.unsat = unsat;
        if (unsat) {
            dst->push_back(std::move(cl));
            continue;
        }

        for (auto &tkv : tmp_tables) {
            const std::string &tname = tkv.first;
            auto it_table = out->tables.find(tname);
            if (it_table == out->tables.end()) {
                ereport(ERROR,
                        (errmsg("policy: missing table artifacts for %s", tname.c_str())));
            }
            TableData &ti = it_table->second;
            ClauseTablePlan tp_tbl;
            tp_tbl.table = tname;

            for (auto &ckv : tkv.second.var_cols) {
                ClauseClassGroup cg;
                cg.class_pos = ckv.first;
                if (cg.class_pos < 0 || cg.class_pos >= (int)cl.join_classes.size())
                    continue;
                cg.domain_id = cl.join_classes[(size_t)cg.class_pos];
                std::sort(ckv.second.begin(), ckv.second.end());
                ckv.second.erase(std::unique(ckv.second.begin(), ckv.second.end()), ckv.second.end());
                for (const auto &col_key : ckv.second) {
                    auto it_idx = ti.col_idx.find(col_key);
                    if (it_idx == ti.col_idx.end()) {
                        ereport(ERROR,
                                (errmsg("policy: missing column %s in meta/cols/%s",
                                        col_key.c_str(), tname.c_str())));
                    }
                    cg.col_idxs.push_back(it_idx->second);
                    ti.needed_cols.insert(it_idx->second);
                }
                if (!cg.col_idxs.empty())
                    tp_tbl.class_groups.push_back(std::move(cg));
            }
            std::sort(tp_tbl.class_groups.begin(), tp_tbl.class_groups.end(),
                      [](const ClauseClassGroup &a, const ClauseClassGroup &b) {
                          if (a.class_pos != b.class_pos) return a.class_pos < b.class_pos;
                          return a.domain_id < b.domain_id;
                      });

            for (auto &pp : tkv.second.preds) {
                ClausePredicate p;
                p.atom_id = pp.atom_id;
                auto it_idx = ti.col_idx.find(pp.col_key);
                if (it_idx == ti.col_idx.end()) {
                    ereport(ERROR,
                            (errmsg("policy: missing predicate column %s in meta/cols/%s",
                                    pp.col_key.c_str(), tname.c_str())));
                }
                p.col_idx = it_idx->second;
                p.allowed = std::move(pp.allowed);
                ti.needed_cols.insert(p.col_idx);
                tp_tbl.predicates.push_back(std::move(p));
            }

            if (tname == target)
                cl.target_present = true;

            cl.tables.push_back(std::move(tp_tbl));
        }

        cl.compares.reserve(tmp_cmps.size());
        for (const auto &cc : tmp_cmps) {
            if (cc.left_pos < 0 || cc.left_pos >= (int)cl.join_classes.size() ||
                cc.right_pos < 0 || cc.right_pos >= (int)cl.join_classes.size()) {
                ereport(ERROR,
                        (errmsg("policy: invalid comparator var positions y%d (%d,%d)",
                                cc.atom_id, cc.left_pos, cc.right_pos)));
            }
            ClauseComparator cmp;
            cmp.atom_id = cc.atom_id;
            cmp.left_pos = cc.left_pos;
            cmp.right_pos = cc.right_pos;
            cmp.domain_id = cc.domain_id;
            cmp.op = cc.op;
            if (cmp.op == ConstOp::LT || cmp.op == ConstOp::LE ||
                cmp.op == ConstOp::GT || cmp.op == ConstOp::GE) {
                if (out->domain_has_rank.find(cmp.domain_id) == out->domain_has_rank.end() ||
                    out->domain_token_rank.find(cmp.domain_id) == out->domain_token_rank.end()) {
                    ereport(ERROR,
                            (errmsg("policy: ordered col-col requires rank artifact domain=%d atom=y%d",
                                    cmp.domain_id, cmp.atom_id)));
                }
            }
            cl.compares.push_back(std::move(cmp));
        }

        cl.acyclic_hint = (!cl.has_colcmp_atom) && is_clause_acyclic_hint(cl);
        dst->push_back(std::move(cl));
    }
    return true;
}

static bool append_clause_plans_from_ast(const std::string &target,
                                         const BoolAst *root,
                                         size_t dnf_cap,
                                         Loaded *out,
                                         std::vector<ClausePlan> *dst)
{
    if (!root || !out || !dst)
        return false;
    DnfList dnf_terms = ast_to_dnf(root, dnf_cap);
    dedup_dnf_terms(&dnf_terms);
    return append_clause_plans_from_dnf(target, dnf_terms, out, dst);
}

static bool mark_needed_columns_for_formula(const std::string &target,
                                            const BoolAst *root,
                                            Loaded *loaded,
                                            TargetPlan *tp)
{
    if (!loaded || !tp)
        return false;
    if (!root)
        return true;

    std::vector<int> vars;
    collect_ast_positive_vars(root, &vars);
    std::sort(vars.begin(), vars.end());
    vars.erase(std::unique(vars.begin(), vars.end()), vars.end());

    {
        std::unordered_set<int> merged(tp->formula_atom_ids.begin(), tp->formula_atom_ids.end());
        merged.insert(vars.begin(), vars.end());
        tp->formula_atom_ids.assign(merged.begin(), merged.end());
        std::sort(tp->formula_atom_ids.begin(), tp->formula_atom_ids.end());
    }

    {
        std::unordered_set<std::string> tables(tp->formula_tables.begin(), tp->formula_tables.end());
        for (int vid : vars) {
            auto ita = loaded->atoms_by_id.find(vid);
            if (ita == loaded->atoms_by_id.end())
                continue;
            const Atom &a = ita->second;
            if (!a.left.table.empty())
                tables.insert(a.left.table);
            if ((a.kind == AtomKind::JOIN || a.kind == AtomKind::COLCOL) && !a.right.table.empty())
                tables.insert(a.right.table);
        }
        tp->formula_tables.assign(tables.begin(), tables.end());
        std::sort(tp->formula_tables.begin(), tp->formula_tables.end());
    }

    std::vector<ClausePlan> plans;
    if (!append_clause_plans_from_ast(target, root, /*dnf_cap=*/200000u, loaded, &plans))
        return false;
    if (!plans.empty()) {
        tp->clauses.reserve(tp->clauses.size() + plans.size());
        for (auto &cl : plans)
            tp->clauses.push_back(std::move(cl));
    }
    return true;
}

static bool compile_target_plan(const std::string &target,
                                const char *ast_str,
                                Loaded *out,
                                BuildProfile *profile)
{
    if (!out || !profile)
        return false;

    TargetPlan tp;
    tp.target = target;

    std::string ast = ast_str ? ast_str : "";
    ast = trim_ws(ast);
    if (ast.empty()) {
        out->targets[target] = std::move(tp);
        return true;
    }

    auto t_atoms0 = Clock::now();

    AstParser parser(ast);
    BoolAst *root = parser.parse_or();
    parser.skip_ws();
    if (!root || parser.pos != parser.src.size()) {
        ereport(ERROR,
                (errmsg("policy: failed to parse target AST target=%s ast=%s",
                        target.c_str(), ast.c_str())));
    }
    tp.formula_root = clone_bool_ast_palloc(root);
    tp.formula_atom_ids.clear();
    tp.formula_tables.clear();
    tp.perm_policy_roots.clear();
    tp.rest_policy_roots.clear();
    if (tp.formula_root)
        tp.perm_policy_roots.push_back(tp.formula_root);
    if (!mark_needed_columns_for_formula(target, tp.formula_root, out, &tp))
        return false;

    auto t_atoms1 = Clock::now();
    profile->atoms_ms += Ms(t_atoms1 - t_atoms0).count();

    out->targets[target] = std::move(tp);
    return true;
}

static bool compile_target_plan_factored(const std::string &target,
                                         const char *combined_ast_str,
                                         const char *perm_ast_str,
                                         const char *rest_ast_str,
                                         const PolicyEngineInputC *in,
                                         Loaded *out,
                                         BuildProfile *profile)
{
    if (!out || !profile)
        return false;
    (void)in;

    TargetPlan tp;
    tp.target = target;
    tp.factored_enabled = false;

    auto t_atoms0 = Clock::now();

    std::string combined_ast = trim_ws(combined_ast_str ? combined_ast_str : "");
    std::string perm_ast = trim_ws(perm_ast_str ? perm_ast_str : "");
    std::string rest_ast = trim_ws(rest_ast_str ? rest_ast_str : "");

    std::string effective_ast = combined_ast;
    if (effective_ast.empty()) {
        if (perm_ast.empty()) {
            // Postgres semantics: no permissive policy means deny-all.
            tp.deny_all = true;
            effective_ast = "y0";
        } else if (rest_ast.empty()) {
            effective_ast = perm_ast;
        } else {
            effective_ast = "(" + perm_ast + ") and (" + rest_ast + ")";
        }
    }

    tp.formula_atom_ids.clear();
    tp.formula_tables.clear();
    tp.perm_policy_roots.clear();
    tp.rest_policy_roots.clear();

    AstParser parser_combined(effective_ast);
    BoolAst *root_combined = parser_combined.parse_or();
    parser_combined.skip_ws();
    if (!root_combined || parser_combined.pos != parser_combined.src.size()) {
        ereport(ERROR,
                (errmsg("policy: failed to parse target AST target=%s ast=%s",
                        target.c_str(), effective_ast.c_str())));
    }
    tp.formula_root = clone_bool_ast_palloc(root_combined);
    if (!mark_needed_columns_for_formula(target, tp.formula_root, out, &tp))
        return false;
    if (tp.formula_root && tp.formula_root->type == AstType::VAR && tp.formula_root->var_id == 0)
        tp.deny_all = true;

    bool used_bundle_policies = false;
    if (!tp.deny_all && in && in->bundle_count > 0 && in->bundles) {
        for (int bi = 0; bi < in->bundle_count; bi++) {
            const PolicyBundleC *b = &in->bundles[bi];
            if (!b || !b->target_table || !b->ast)
                continue;
            if (target != std::string(b->target_table))
                continue;

            std::string bast = trim_ws(b->ast);
            if (bast.empty())
                continue;

            AstParser parser_b(bast);
            BoolAst *root_b = parser_b.parse_or();
            parser_b.skip_ws();
            if (!root_b || parser_b.pos != parser_b.src.size()) {
                ereport(ERROR,
                        (errmsg("policy: failed to parse bundle AST target=%s policy_id=%d ast=%s",
                                target.c_str(), b->policy_id, bast.c_str())));
            }

            BoolAst *cp = clone_bool_ast_palloc(root_b);

            std::vector<int> local_to_global((size_t)std::max(0, b->atom_count) + 1u, 0);
            for (int ai = 0; ai < b->atom_count; ai++) {
                const PolicyAtomC *pa = &b->atoms[ai];
                if (!pa || pa->atom_id <= 0 || !pa->canon_key)
                    continue;
                auto it_gid = out->atom_id_by_canon.find(pa->canon_key);
                int gid = -1;
                if (it_gid != out->atom_id_by_canon.end())
                    gid = it_gid->second;
                else
                    gid = find_global_atom_id_for_bundle_atom(pa, out);
                if (gid <= 0) {
                    ereport(ERROR,
                            (errmsg("policy: bundle atom canon_key not found in global atoms target=%s policy_id=%d key=%s",
                                    target.c_str(), b->policy_id, pa->canon_key)));
                }
                if (pa->atom_id >= (int)local_to_global.size())
                    local_to_global.resize((size_t)pa->atom_id + 1u, 0);
                local_to_global[(size_t)pa->atom_id] = gid;
            }
            if (!remap_ast_vars_inplace(cp, local_to_global)) {
                ereport(ERROR,
                        (errmsg("policy: failed to remap bundle AST vars to global ids target=%s policy_id=%d",
                                target.c_str(), b->policy_id)));
            }

            if (b->permissive) {
                tp.perm_policy_roots.push_back(cp);
            } else {
                tp.rest_policy_roots.push_back(cp);
            }
            if (!mark_needed_columns_for_formula(target, cp, out, &tp))
                return false;
            used_bundle_policies = true;
        }
    }

    if (!used_bundle_policies) {
        if (!perm_ast.empty()) {
            AstParser parser_perm(perm_ast);
            BoolAst *root_perm = parser_perm.parse_or();
            parser_perm.skip_ws();
            if (!root_perm || parser_perm.pos != parser_perm.src.size()) {
                ereport(ERROR,
                        (errmsg("policy: failed to parse permissive AST target=%s ast=%s",
                                target.c_str(), perm_ast.c_str())));
            }
            std::vector<const BoolAst *> perm_parts;
            flatten_policy_composition_chain(root_perm, AstType::OR, &perm_parts);
            for (const BoolAst *part : perm_parts) {
                BoolAst *cp = clone_bool_ast_palloc(part);
                tp.perm_policy_roots.push_back(cp);
                if (!mark_needed_columns_for_formula(target, cp, out, &tp))
                    return false;
            }
        }

        if (!rest_ast.empty()) {
            AstParser parser_rest(rest_ast);
            BoolAst *root_rest = parser_rest.parse_or();
            parser_rest.skip_ws();
            if (!root_rest || parser_rest.pos != parser_rest.src.size()) {
                ereport(ERROR,
                        (errmsg("policy: failed to parse restrictive AST target=%s ast=%s",
                                target.c_str(), rest_ast.c_str())));
            }
            std::vector<const BoolAst *> rest_parts;
            flatten_policy_composition_chain(root_rest, AstType::AND, &rest_parts);
            for (const BoolAst *part : rest_parts) {
                BoolAst *cp = clone_bool_ast_palloc(part);
                tp.rest_policy_roots.push_back(cp);
                if (!mark_needed_columns_for_formula(target, cp, out, &tp))
                    return false;
            }
        }
    }

    if (tp.perm_policy_roots.empty() && tp.formula_root && !tp.deny_all) {
        tp.perm_policy_roots.push_back(tp.formula_root);
    }

    auto t_atoms1 = Clock::now();
    profile->atoms_ms += Ms(t_atoms1 - t_atoms0).count();
    out->targets[target] = std::move(tp);
    return true;
}

static bool decode_table_needed_columns(TableData *ti,
                                        ArtifactStore *store,
                                        std::vector<int> *class_domain,
                                        const std::unordered_map<std::string, int> &join_class_by_col)
{
    if (!ti || !store || !class_domain)
        return false;

    if (ti->needed_cols.empty())
        return true;
    if (ti->meta_cols.empty()) {
        ereport(ERROR,
                (errmsg("policy: missing meta/cols for table %s", ti->name.c_str())));
    }

    if (ti->nrows == 0) {
        if (ti->code_format == TableData::CodeFormat::CB03_MANIFEST)
            ti->nrows = ti->cb03_total_rows;
        else if (!ti->ctid_blk.empty())
            ti->nrows = (uint32)ti->ctid_blk.size();
    }

    if (ti->nrows == 0)
        return true;

    for (int col_idx : ti->needed_cols) {
        if (col_idx < 0 || col_idx >= (int)ti->decoded_cols.size())
            return false;
        ti->decoded_cols[col_idx].assign(ti->nrows, -1);
    }

    auto on_row = [&](uint32 rid, const uint8_t *row, int ntoks) {
        if (rid >= ti->nrows) return;
        for (int col_idx : ti->needed_cols) {
            if (col_idx < 0 || col_idx >= ntoks) continue;
            int32_t tok = -1;
            std::memcpy(&tok, row + (size_t)col_idx * sizeof(int32_t), sizeof(int32_t));
            ti->decoded_cols[col_idx][rid] = tok;

            if (tok >= 0 && col_idx < (int)ti->meta_cols.size()) {
                auto itc = join_class_by_col.find(ti->meta_cols[col_idx]);
                if (itc != join_class_by_col.end()) {
                    int cid = itc->second;
                    if (cid >= 0) {
                        if (cid >= (int)class_domain->size())
                            class_domain->resize((size_t)cid + 1u, 0);
                        if (tok + 1 > (*class_domain)[cid])
                            (*class_domain)[cid] = tok + 1;
                    }
                }
            }
        }
    };

    if (ti->code_format == TableData::CodeFormat::CB04_MANIFEST) {
        for (int col_idx : ti->needed_cols) {
            uint32 rid = 0;
            for (int i = 0; i < ti->cb03_chunk_count; i++) {
                std::string chunk_name = ti->name + "_code_col_" + std::to_string(col_idx) +
                                         "_chunk_" + std::to_string(i);
                ArtifactBlob chunk;
                if (!store->get(chunk_name, &chunk)) {
                    ereport(ERROR,
                            (errmsg("policy: missing code column chunk artifact %s", chunk_name.c_str())));
                }
                uint32 rows_left = (rid <= ti->nrows) ? (ti->nrows - rid) : 0u;
                uint32 expect_rows = std::min<uint32>(ti->cb03_chunk_rows, rows_left);
                bool ok = decode_cc04_column_append(
                    chunk,
                    expect_rows,
                    [&](uint32 rr, int32_t tok) {
                        ti->decoded_cols[col_idx][rr] = tok;
                        if (tok >= 0 && col_idx < (int)ti->meta_cols.size()) {
                            auto itc = join_class_by_col.find(ti->meta_cols[col_idx]);
                            if (itc != join_class_by_col.end()) {
                                int cid = itc->second;
                                if (cid >= 0) {
                                    if (cid >= (int)class_domain->size())
                                        class_domain->resize((size_t)cid + 1u, 0);
                                    if (tok + 1 > (*class_domain)[cid])
                                        (*class_domain)[cid] = tok + 1;
                                }
                            }
                        }
                    },
                    rid);
                if (!ok) {
                    ereport(ERROR,
                            (errmsg("policy: invalid CC04 chunk %s", chunk_name.c_str())));
                }
                rid += expect_rows;
            }
            if (rid != ti->nrows) {
                ereport(ERROR,
                        (errmsg("policy: decoded rows mismatch table=%s col=%d decoded=%u expected=%u",
                                ti->name.c_str(), col_idx, rid, ti->nrows)));
            }
        }
        return true;
    }

    if (ti->code_format == TableData::CodeFormat::CB03_MANIFEST) {
        uint32 rid = 0;
        for (int i = 0; i < ti->cb03_chunk_count; i++) {
            std::string chunk_name = ti->name + "_code_chunk_" + std::to_string(i);
            ArtifactBlob chunk;
            if (!store->get(chunk_name, &chunk)) {
                ereport(ERROR,
                        (errmsg("policy: missing code chunk artifact %s", chunk_name.c_str())));
            }
            uint32 nrows_chunk = 0;
            int ntoks_chunk = -1;
            bool ok = decode_cb02_append(
                chunk,
                ti->cb03_ntoks,
                on_row,
                rid,
                &nrows_chunk,
                &ntoks_chunk);
            if (!ok) {
                ereport(ERROR,
                        (errmsg("policy: invalid CB02 chunk %s", chunk_name.c_str())));
            }
            rid += nrows_chunk;
        }
        if (rid != ti->nrows) {
            ereport(ERROR,
                    (errmsg("policy: decoded rows mismatch table=%s decoded=%u expected=%u",
                            ti->name.c_str(), rid, ti->nrows)));
        }
        return true;
    }

    if (ti->code_format == TableData::CodeFormat::CB02_SINGLE) {
        uint32 nrows_chunk = 0;
        int ntoks_chunk = -1;
        if (!decode_cb02_append(ti->code_base,
                                (int)ti->meta_cols.size(),
                                on_row,
                                0,
                                &nrows_chunk,
                                &ntoks_chunk)) {
            ereport(ERROR,
                    (errmsg("policy: invalid CB02 artifact for table %s", ti->name.c_str())));
        }
        if (ti->nrows == 0)
            ti->nrows = nrows_chunk;
        if (nrows_chunk != ti->nrows) {
            ereport(ERROR,
                    (errmsg("policy: decoded rows mismatch table=%s decoded=%u expected=%u",
                            ti->name.c_str(), nrows_chunk, ti->nrows)));
        }
        return true;
    }

    if (ti->code_format == TableData::CodeFormat::RAW) {
        if (!ti->code_base.data || ti->code_base.len == 0) {
            ereport(ERROR,
                    (errmsg("policy: missing RAW code data for table %s", ti->name.c_str())));
        }
        size_t nints = ti->code_base.len / sizeof(int32_t);
        if (ti->nrows == 0)
            ereport(ERROR,
                    (errmsg("policy: RAW code requires known nrows table=%s", ti->name.c_str())));
        if (ti->nrows == 0)
            return false;
        if (nints % ti->nrows != 0) {
            ereport(ERROR,
                    (errmsg("policy: invalid RAW code length for table %s", ti->name.c_str())));
        }
        size_t stride = nints / ti->nrows;
        bool has_rid = false;
        if (stride == ti->meta_cols.size() + 1)
            has_rid = true;
        else if (stride != ti->meta_cols.size())
            ereport(ERROR,
                    (errmsg("policy: unexpected RAW stride table=%s stride=%zu cols=%zu",
                            ti->name.c_str(), stride, ti->meta_cols.size())));

        const int32_t *arr = (const int32_t *)ti->code_base.data;
        for (uint32 rid = 0; rid < ti->nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
const int32_t *row = arr + (size_t)rid * stride;
            for (int col_idx : ti->needed_cols) {
                size_t off = has_rid ? (size_t)col_idx + 1u : (size_t)col_idx;
                int32_t tok = row[off];
                ti->decoded_cols[col_idx][rid] = tok;

                if (tok >= 0 && col_idx < (int)ti->meta_cols.size()) {
                    auto itc = join_class_by_col.find(ti->meta_cols[col_idx]);
                    if (itc != join_class_by_col.end()) {
                        int cid = itc->second;
                        if (cid >= 0) {
                            if (cid >= (int)class_domain->size())
                                class_domain->resize((size_t)cid + 1u, 0);
                            if (tok + 1 > (*class_domain)[cid])
                                (*class_domain)[cid] = tok + 1;
                        }
                    }
                }
            }
        }
        return true;
    }

    ereport(ERROR,
            (errmsg("policy: missing code artifact format for table %s", ti->name.c_str())));
    return false;
}

static size_t estimate_artifact_store_bytes(const ArtifactStore &store)
{
    size_t total = 0;
    for (bytea *b : store.owned) {
        if (!b)
            continue;
        total += (size_t)VARSIZE_ANY_EXHDR(b);
    }
    return total;
}

static size_t estimate_decoded_columns_bytes(const Loaded &loaded)
{
    size_t total = 0;
    for (const auto &kv : loaded.tables) {
        const TableData &ti = kv.second;
        for (const auto &col : ti.decoded_cols)
            total += col.size() * sizeof(int32_t);
    }
    return total;
}

static void release_loaded_artifact_buffers(Loaded *loaded)
{
    if (!loaded)
        return;
    for (auto &kv : loaded->tables)
        kv.second.code_base = ArtifactBlob{};
    for (bytea *b : loaded->artifacts.owned) {
        if (b)
            pfree(b);
    }
    loaded->artifacts.owned.clear();
    loaded->artifacts.blobs.clear();
}

static bool bind_clause_views(ClausePlan *cl, Loaded *loaded)
{
    if (!cl || !loaded)
        return false;
    for (auto &tp : cl->tables) {
        auto it = loaded->tables.find(tp.table);
        if (it == loaded->tables.end())
            return false;
        TableData &ti = it->second;

        for (auto &p : tp.predicates) {
            if (p.col_idx < 0 || p.col_idx >= (int)ti.decoded_cols.size())
                return false;
            p.col_data = &ti.decoded_cols[p.col_idx];
        }
        for (auto &cg : tp.class_groups) {
            cg.col_data.clear();
            for (int col_idx : cg.col_idxs) {
                if (col_idx < 0 || col_idx >= (int)ti.decoded_cols.size())
                    return false;
                cg.col_data.push_back(&ti.decoded_cols[col_idx]);
            }
        }
    }
    for (auto &cmp : cl->compares) {
        cmp.rank_data = nullptr;
        if (is_ordered_cmp(cmp.op)) {
            auto it = loaded->domain_token_rank.find(cmp.domain_id);
            if (it == loaded->domain_token_rank.end()) {
                ereport(ERROR,
                        (errmsg("policy: ordered comparator missing rank/domain/%d for atom y%d",
                                cmp.domain_id, cmp.atom_id)));
            }
            cmp.rank_data = &it->second;
        }
    }
    return true;
}

static bool bind_target_local_views(TargetPlan *tp, Loaded *loaded)
{
    if (!tp || !loaded)
        return false;
    if (!tp->local_formula_enabled)
        return true;

    auto it = loaded->tables.find(tp->target);
    if (it == loaded->tables.end())
        return false;
    TableData &ti = it->second;

    for (auto &a : tp->local_formula_atoms) {
        if (a.col_idx < 0 || a.col_idx >= (int)ti.decoded_cols.size())
            return false;
        a.col_data = &ti.decoded_cols[a.col_idx];
    }
    return true;
}

static inline bool is_ordered_cmp(ConstOp op)
{
    return op == ConstOp::LT || op == ConstOp::LE ||
           op == ConstOp::GT || op == ConstOp::GE;
}

static inline int32_t token_rank_of(int32_t tok, const std::vector<int32_t> *rank_data)
{
    if (tok < 0)
        return std::numeric_limits<int32_t>::min();
    if (rank_data && (size_t)tok < rank_data->size()) {
        int32_t r = (*rank_data)[(size_t)tok];
        if (r >= 0)
            return r;
    }
    return tok;
}

static bool token_compare(ConstOp op, int32_t ltok, int32_t rtok, const std::vector<int32_t> *rank_data)
{
    if (ltok < 0 || rtok < 0)
        return false;
    if (op == ConstOp::NE)
        return ltok != rtok;
    if (op == ConstOp::EQ)
        return ltok == rtok;
    int32_t lr = token_rank_of(ltok, rank_data);
    int32_t rr = token_rank_of(rtok, rank_data);
    switch (op) {
        case ConstOp::LT: return lr < rr;
        case ConstOp::LE: return lr <= rr;
        case ConstOp::GT: return lr > rr;
        case ConstOp::GE: return lr >= rr;
        default: break;
    }
    return false;
}

static std::vector<int> table_needed_signature_schema(const TableData &ti)
{
    std::vector<int> cols;
    cols.reserve(ti.needed_cols.size());
    for (int c : ti.needed_cols) {
        if (c >= 0)
            cols.push_back(c);
    }
    std::sort(cols.begin(), cols.end());
    cols.erase(std::unique(cols.begin(), cols.end()), cols.end());
    return cols;
}

static std::string signature_cache_key(const std::string &table, const std::vector<int> &schema_cols)
{
    std::string key = table;
    key.push_back('|');
    for (size_t i = 0; i < schema_cols.size(); i++) {
        if (i > 0)
            key.push_back(',');
        key += std::to_string(schema_cols[i]);
    }
    return key;
}

static bool signature_tokens_equal(const SignatureCacheEntry &entry,
                                   uint32 sid,
                                   const std::vector<int32_t> &row_toks)
{
    size_t ncols = entry.schema_cols.size();
    if (row_toks.size() != ncols)
        return false;
    size_t base = (size_t)sid * ncols;
    if (base + ncols > entry.sig_tokens.size())
        return false;
    for (size_t i = 0; i < ncols; i++) {
        if (entry.sig_tokens[base + i] != row_toks[i])
            return false;
    }
    return true;
}

static bool get_or_build_signature_cache_entry_with_schema(const Loaded &loaded,
                                                           const std::string &table,
                                                           const TableData &ti,
                                                           const std::vector<int> &schema_cols,
                                                           const SignatureCacheEntry **out_entry,
                                                           BuildProfile *profile);

static inline bool signature_get_col_token(const SignatureCacheEntry &entry,
                                           uint32 sid,
                                           int col_idx,
                                           int32_t *out_tok);

static bool build_signature_cache_entry(const std::string &table,
                                        const TableData &ti,
                                        const std::vector<int> &schema_cols,
                                        SignatureCacheEntry *out_entry,
                                        BuildProfile *profile)
{
    if (!out_entry)
        return false;
    out_entry->table = table;
    out_entry->schema_cols = schema_cols;
    out_entry->schema_pos_by_col.assign(ti.meta_cols.size(), -1);
    for (size_t i = 0; i < schema_cols.size(); i++) {
        int col_idx = schema_cols[i];
        if (col_idx < 0 || col_idx >= (int)ti.meta_cols.size())
            return false;
        out_entry->schema_pos_by_col[(size_t)col_idx] = (int)i;
    }
    out_entry->nsig = 0;
    out_entry->sig_tokens.clear();
    out_entry->row_offsets.clear();
    out_entry->rows_flat.clear();
    out_entry->sig_mask_offsets.clear();
    out_entry->sig_mask_blocks.clear();
    out_entry->sig_mask_word_idx.clear();
    out_entry->sig_mask_word_vals.clear();
    out_entry->mask_mem_bytes = 0;

    if (ti.nrows == 0 || schema_cols.empty()) {
        out_entry->row_offsets.assign(1, 0);
        out_entry->sig_mask_offsets.assign(1, 0);
        out_entry->mem_bytes =
            out_entry->schema_cols.size() * sizeof(int) +
            out_entry->schema_pos_by_col.size() * sizeof(int) +
            out_entry->sig_tokens.size() * sizeof(int32_t) +
            out_entry->row_offsets.size() * sizeof(uint32_t) +
            out_entry->rows_flat.size() * sizeof(uint32_t) +
            out_entry->sig_mask_offsets.size() * sizeof(uint32_t) +
            out_entry->sig_mask_blocks.size() * sizeof(uint32_t) +
            out_entry->sig_mask_word_idx.size() * sizeof(uint8_t) +
            out_entry->sig_mask_word_vals.size() * sizeof(uint64_t);
        if (profile)
            profile->term_code_scans++;
        return true;
    }

    std::unordered_map<uint64_t, std::vector<uint32_t>> hash_to_sids;
    hash_to_sids.reserve((size_t)ti.nrows / 2u + 1u);
    std::vector<int32_t> row_toks(schema_cols.size(), -1);
    std::vector<uint32_t> sid_by_rid(ti.nrows, 0);

    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
uint64_t h = 1469598103934665603ULL;
        for (size_t i = 0; i < schema_cols.size(); i++) {
            int col_idx = schema_cols[i];
            if (col_idx < 0 || col_idx >= (int)ti.decoded_cols.size())
                return false;
            const std::vector<int32_t> &col = ti.decoded_cols[(size_t)col_idx];
            if (rid >= col.size())
                return false;
            int32_t tok = col[(size_t)rid];
            row_toks[i] = tok;
            h = hash_combine_u64(h, (uint64_t)(uint32_t)tok);
        }

        auto &cand = hash_to_sids[h];
        uint32 sid = UINT32_MAX;
        for (uint32 existing_sid : cand) {
            if (signature_tokens_equal(*out_entry, existing_sid, row_toks)) {
                sid = existing_sid;
                break;
            }
        }
        if (sid == UINT32_MAX) {
            sid = out_entry->nsig++;
            out_entry->sig_tokens.insert(out_entry->sig_tokens.end(), row_toks.begin(), row_toks.end());
            cand.push_back(sid);
        }
        sid_by_rid[(size_t)rid] = sid;
    }

    std::vector<uint32_t> counts(out_entry->nsig, 0);
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
uint32 sid = sid_by_rid[(size_t)rid];
        if (sid >= counts.size())
            return false;
        counts[(size_t)sid]++;
    }

    out_entry->row_offsets.assign((size_t)out_entry->nsig + 1u, 0);
    for (uint32 sid = 0; sid < out_entry->nsig; sid++) {
        out_entry->row_offsets[(size_t)sid + 1u] =
            out_entry->row_offsets[(size_t)sid] + counts[(size_t)sid];
    }
    out_entry->rows_flat.assign(ti.nrows, 0);
    std::vector<uint32_t> cursor = out_entry->row_offsets;
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
uint32 sid = sid_by_rid[(size_t)rid];
        uint32 pos = cursor[(size_t)sid]++;
        if (pos >= out_entry->rows_flat.size())
            return false;
        out_entry->rows_flat[(size_t)pos] = rid;
    }

    auto t_sigmask0 = Clock::now();
    out_entry->sig_mask_offsets.assign((size_t)out_entry->nsig + 1u, 0u);
    for (uint32 sid = 0; sid < out_entry->nsig; sid++) {
        uint32 begin = out_entry->row_offsets[(size_t)sid];
        uint32 end = out_entry->row_offsets[(size_t)sid + 1u];
        if (begin > end || end > out_entry->rows_flat.size())
            return false;
        size_t sid_mask_begin = out_entry->sig_mask_blocks.size();

        for (uint32 p = begin; p < end; p++) {
            uint32 rid = out_entry->rows_flat[(size_t)p];
            if ((size_t)rid >= ti.ctid_blk.size() || (size_t)rid >= ti.ctid_off.size())
                continue;
            int32 blk = ti.ctid_blk[(size_t)rid];
            int32 off = ti.ctid_off[(size_t)rid];
            if (blk < 0 || off <= 0 || off > (int32)kMaxOffsetNumber)
                continue;
            uint32 off0 = (uint32)(off - 1);
            uint8_t wi = (uint8_t)(off0 >> 6);
            uint64_t bit = (uint64_t(1) << (off0 & 63u));
            if (out_entry->sig_mask_blocks.size() > sid_mask_begin) {
                size_t last = out_entry->sig_mask_blocks.size() - 1u;
                if (out_entry->sig_mask_blocks[last] == (uint32)blk &&
                    out_entry->sig_mask_word_idx[last] == wi) {
                    out_entry->sig_mask_word_vals[last] |= bit;
                    continue;
                }
            }
            out_entry->sig_mask_blocks.push_back((uint32)blk);
            out_entry->sig_mask_word_idx.push_back(wi);
            out_entry->sig_mask_word_vals.push_back(bit);
        }
        out_entry->sig_mask_offsets[(size_t)sid + 1u] =
            (uint32)out_entry->sig_mask_blocks.size();
    }

    out_entry->mask_mem_bytes =
        out_entry->sig_mask_offsets.size() * sizeof(uint32_t) +
        out_entry->sig_mask_blocks.size() * sizeof(uint32_t) +
        out_entry->sig_mask_word_idx.size() * sizeof(uint8_t) +
        out_entry->sig_mask_word_vals.size() * sizeof(uint64_t);
    if (profile)
        profile->sigmask_build_ms += Ms(Clock::now() - t_sigmask0).count();

    out_entry->mem_bytes =
        out_entry->schema_cols.size() * sizeof(int) +
        out_entry->schema_pos_by_col.size() * sizeof(int) +
        out_entry->sig_tokens.size() * sizeof(int32_t) +
        out_entry->row_offsets.size() * sizeof(uint32_t) +
        out_entry->rows_flat.size() * sizeof(uint32_t) +
        out_entry->mask_mem_bytes;

    if (profile)
        profile->term_code_scans++;
    return true;
}

static bool get_or_build_signature_cache_entry_with_schema(const Loaded &loaded,
                                                           const std::string &table,
                                                           const TableData &ti,
                                                           const std::vector<int> &schema_cols,
                                                           const SignatureCacheEntry **out_entry,
                                                           BuildProfile *profile)
{
    if (!out_entry)
        return false;
    std::string key = signature_cache_key(table, schema_cols);
    auto it = loaded.signature_cache.find(key);
    if (it != loaded.signature_cache.end()) {
        if (profile)
            profile->signature_cache_hits++;
        if (profile)
            profile->sigmask_cache_hits++;
        *out_entry = &it->second;
        return true;
    }

    SignatureCacheEntry built;
    if (!build_signature_cache_entry(table, ti, schema_cols, &built, profile))
        return false;
    auto [ins_it, inserted] = loaded.signature_cache.emplace(std::move(key), std::move(built));
    if (!inserted)
        return false;
    if (profile)
        profile->signature_cache_misses++;
    if (profile)
        profile->sigmask_cache_misses++;
    if (profile)
        profile->signature_cache_bytes += ins_it->second.mem_bytes;
    if (profile)
        profile->bytes_sig_ctid_masks += ins_it->second.mask_mem_bytes;
    if (profile)
        profile->sigmask_bytes += ins_it->second.mask_mem_bytes;
    *out_entry = &ins_it->second;
    return true;
}

static inline bool signature_get_col_token(const SignatureCacheEntry &entry,
                                           uint32 sid,
                                           int col_idx,
                                           int32_t *out_tok)
{
    if (!out_tok || col_idx < 0 || col_idx >= (int)entry.schema_pos_by_col.size())
        return false;
    if (sid >= entry.nsig)
        return false;
    int pos = entry.schema_pos_by_col[(size_t)col_idx];
    if (pos < 0)
        return false;
    size_t ncols = entry.schema_cols.size();
    size_t off = (size_t)sid * ncols + (size_t)pos;
    if (off >= entry.sig_tokens.size())
        return false;
    *out_tok = entry.sig_tokens[off];
    return true;
}

static ConstOp flip_cmp_orientation(ConstOp op)
{
    switch (op) {
    case ConstOp::LT: return ConstOp::GT;
    case ConstOp::LE: return ConstOp::GE;
    case ConstOp::GT: return ConstOp::LT;
    case ConstOp::GE: return ConstOp::LE;
    case ConstOp::EQ:
    case ConstOp::NE:
        return op;
    default:
        return op;
    }
}

struct SparseBlockWords {
    uint32 total_blocks = 0;
    std::vector<uint64_t> dense_words; // dense block_words: [blk * kWordsPerBlock + wi]

    void ensure_dense(uint32 blocks)
    {
        if (blocks > total_blocks)
            total_blocks = blocks;
        size_t need_words = (size_t)total_blocks * (size_t)kWordsPerBlock;
        if (dense_words.size() < need_words)
            dense_words.resize(need_words, 0);
    }

    void clear()
    {
        total_blocks = 0;
        dense_words.clear();
    }

    bool any() const
    {
        for (uint64_t w : dense_words) {
            if (w != 0)
                return true;
        }
        return false;
    }

    bool set_ctid(int32 blk, int32 off)
    {
        if (blk < 0 || off <= 0 || off > (int32)kMaxOffsetNumber)
            return false;
        uint32 b = (uint32)blk;
        ensure_dense(b + 1u);
        uint32 off0 = (uint32)(off - 1);
        size_t flat = (size_t)b * (size_t)kWordsPerBlock + (size_t)(off0 >> 6);
        if (flat >= dense_words.size())
            return false;
        dense_words[flat] |= (uint64_t(1) << (off0 & 63u));
        return true;
    }

    bool or_word(uint32 blk, uint8_t wi, uint64_t mask)
    {
        if (wi >= kWordsPerBlock)
            return false;
        ensure_dense(blk + 1u);
        size_t flat = (size_t)blk * (size_t)kWordsPerBlock + (size_t)wi;
        if (flat >= dense_words.size())
            return false;
        dense_words[flat] |= mask;
        return true;
    }

    bool or_inplace(const SparseBlockWords &o)
    {
        ensure_dense(std::max(total_blocks, o.total_blocks));
        size_t n = std::min(dense_words.size(), o.dense_words.size());
        for (size_t i = 0; i < n; i++)
            dense_words[i] |= o.dense_words[i];
        return true;
    }

    bool and_inplace(const SparseBlockWords &o)
    {
        ensure_dense(std::max(total_blocks, o.total_blocks));
        size_t n = dense_words.size();
        size_t on = o.dense_words.size();
        for (size_t i = 0; i < n; i++) {
            uint64_t rhs = (i < on) ? o.dense_words[i] : 0;
            dense_words[i] &= rhs;
        }
        return true;
    }

    size_t blocks_allocated() const
    {
        if (dense_words.empty() || total_blocks == 0)
            return 0;
        size_t blocks = 0;
        for (uint32 blk = 0; blk < total_blocks; blk++) {
            bool anyw = false;
            size_t base = (size_t)blk * (size_t)kWordsPerBlock;
            for (size_t i = 0; i < kWordsPerBlock; i++) {
                if (base + i < dense_words.size() && dense_words[base + i] != 0) {
                    anyw = true;
                    break;
                }
            }
            if (anyw)
                blocks++;
        }
        return blocks;
    }

    size_t words_bytes() const
    {
        return dense_words.size() * sizeof(uint64_t);
    }

    size_t block_id_bytes() const
    {
        return blocks_allocated() * sizeof(uint32_t);
    }

    void to_sorted_arrays(std::vector<uint32> *out_block_ids,
                          std::vector<uint64_t> *out_words) const
    {
        if (!out_block_ids || !out_words)
            return;
        out_block_ids->clear();
        out_words->clear();
        if (dense_words.empty() || total_blocks == 0)
            return;
        out_block_ids->reserve(blocks_allocated());
        for (uint32 blk = 0; blk < total_blocks; blk++) {
            size_t base = (size_t)blk * (size_t)kWordsPerBlock;
            bool anyw = false;
            for (size_t i = 0; i < kWordsPerBlock; i++) {
                if (base + i < dense_words.size() && dense_words[base + i] != 0) {
                    anyw = true;
                    break;
                }
            }
            if (!anyw)
                continue;
            out_block_ids->push_back(blk);
            for (size_t i = 0; i < kWordsPerBlock; i++) {
                out_words->push_back((base + i < dense_words.size()) ? dense_words[base + i] : 0);
            }
        }
    }
};

static bool row_matches_table_predicates_only(const ClauseTablePlan &tp,
                                              uint32 rid,
                                              const uint8 *restrict_bits = nullptr)
{
    if (restrict_bits && !rid_bit_test(restrict_bits, rid))
        return false;
    for (const auto &pred : tp.predicates) {
        if (!pred.col_data || rid >= pred.col_data->size())
            return false;
        int32_t tok = (*pred.col_data)[rid];
        if (tok < 0)
            return false;
        if (!pred.allowed.test((size_t)tok))
            return false;
    }
    return true;
}

struct Pf2SingleHubTableStampPlan {
    const ClauseTablePlan *tp = nullptr;
    const TableData *ti = nullptr;
    const ClauseClassGroup *hub_group = nullptr;
    bool is_target = false;
};

struct Pf2LocalComparator {
    const ClauseComparator *cmp = nullptr;
    int left_group_idx = -1;
    int right_group_idx = -1;
};

struct Pf2TwoHopPattern {
    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;
    const ClauseTablePlan *a_tp = nullptr;    // middle witness
    const TableData *a_ti = nullptr;
    const ClauseTablePlan *b_tp = nullptr;    // leaf witness
    const TableData *b_ti = nullptr;
    const ClauseClassGroup *t_h1 = nullptr;
    const ClauseClassGroup *a_h1 = nullptr;
    const ClauseClassGroup *a_h2 = nullptr;
    const ClauseClassGroup *b_h2 = nullptr;
    int h1_domain = -1;
    int h2_domain = -1;
    std::vector<Pf2LocalComparator> t_local_cmps;
    std::vector<Pf2LocalComparator> a_local_cmps;
    std::vector<Pf2LocalComparator> b_local_cmps;
};

static inline const ClauseClassGroup *pf2_find_group_by_domain(const ClauseTablePlan &tp, int domain_id)
{
    const ClauseClassGroup *found = nullptr;
    for (const auto &cg : tp.class_groups) {
        if (cg.domain_id != domain_id)
            continue;
        if (found)
            return nullptr;
        found = &cg;
    }
    return found;
}

static bool pf2_get_group_token_on_row(const ClauseClassGroup &cg,
                                       uint32 rid,
                                       int32_t *out_tok)
{
    if (!out_tok || cg.col_data.empty())
        return false;
    if ((size_t)rid >= cg.col_data[0]->size())
        return false;
    int32_t tok = (*cg.col_data[0])[rid];
    if (tok < 0) {
        *out_tok = -1;
        return true;
    }
    for (size_t i = 1; i < cg.col_data.size(); i++) {
        if ((size_t)rid >= cg.col_data[i]->size())
            return false;
        if ((*cg.col_data[i])[rid] != tok) {
            *out_tok = -1;
            return true;
        }
    }
    *out_tok = tok;
    return true;
}

static bool pf2_row_matches_table_local_atoms(const ClauseTablePlan &tp,
                                              const std::vector<Pf2LocalComparator> &local_cmps,
                                              uint32 rid)
{
    if (!row_matches_table_predicates_only(tp, rid, nullptr))
        return false;
    if (local_cmps.empty())
        return true;
    for (const auto &lc : local_cmps) {
        if (!lc.cmp || lc.left_group_idx < 0 || lc.right_group_idx < 0)
            return false;
        if ((size_t)lc.left_group_idx >= tp.class_groups.size() ||
            (size_t)lc.right_group_idx >= tp.class_groups.size()) {
            return false;
        }
        int32_t ltok = -1;
        int32_t rtok = -1;
        if (!pf2_get_group_token_on_row(tp.class_groups[(size_t)lc.left_group_idx], rid, &ltok) ||
            !pf2_get_group_token_on_row(tp.class_groups[(size_t)lc.right_group_idx], rid, &rtok)) {
            return false;
        }
        if (ltok < 0 || rtok < 0)
            return false;
        if (!token_compare(lc.cmp->op, ltok, rtok, lc.cmp->rank_data))
            return false;
    }
    return true;
}

static bool pf2_map_local_comparators_for_table(const ClausePlan &cl,
                                                const ClauseTablePlan &tp,
                                                std::vector<Pf2LocalComparator> *out_local_cmps,
                                                bool *out_has_unsupported_cross_cmp,
                                                bool allow_local_target_cmps)
{
    if (!out_local_cmps)
        return false;
    out_local_cmps->clear();
    if (out_has_unsupported_cross_cmp)
        *out_has_unsupported_cross_cmp = false;

    std::unordered_map<int, int> group_idx_by_pos;
    group_idx_by_pos.reserve(tp.class_groups.size());
    for (size_t i = 0; i < tp.class_groups.size(); i++) {
        group_idx_by_pos[tp.class_groups[i].class_pos] = (int)i;
    }

    for (const ClauseComparator &cmp : cl.compares) {
        auto itl = group_idx_by_pos.find(cmp.left_pos);
        auto itr = group_idx_by_pos.find(cmp.right_pos);
        bool l_here = (itl != group_idx_by_pos.end());
        bool r_here = (itr != group_idx_by_pos.end());
        if (!l_here && !r_here)
            continue;
        if (l_here && r_here) {
            if (!allow_local_target_cmps && tp.table == cl.target) {
                if (out_has_unsupported_cross_cmp)
                    *out_has_unsupported_cross_cmp = true;
                return true;
            }
            out_local_cmps->push_back(Pf2LocalComparator{&cmp, itl->second, itr->second});
            continue;
        }
        if (out_has_unsupported_cross_cmp)
            *out_has_unsupported_cross_cmp = true;
        return true;
    }
    return true;
}

static bool pf2_build_present_tokens_for_table(const Loaded &loaded,
                                               const std::string &table,
                                               int hub_domain_id,
                                               size_t ntokens,
                                               TokenBitset *out_bits)
{
    if (!out_bits)
        return false;
    out_bits->reset(ntokens);
    out_bits->clear_all();
    const BinIndexCacheEntry *ent = nullptr;
    if (!get_or_build_bin_index_cache_entry(loaded, table, hub_domain_id, &ent))
        return false;
    if (!ent)
        return false;
    if (ent->off.empty())
        return true;
    size_t limit = std::min(ntokens, ent->off.size() > 0 ? (ent->off.size() - 1u) : 0u);
    for (size_t t = 0; t < limit; t++) {
        if (ent->off[t + 1u] > ent->off[t])
            out_bits->set(t);
    }
    out_bits->adapt_representation();
    return true;
}

static bool eval_term_conjunction_pf2_single_hub(const Loaded &loaded,
                                                 const std::string &target,
                                                 const ClausePlan &cl,
                                                 const ClauseTablePlan &target_tp,
                                                 const TableData &target_ti,
                                                 const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                                 BuildProfile *profile,
                                                 SparseBlockWords *out_words,
                                                 std::vector<uint8_t> *out_rid_bits,
                                                 bool *out_term_has_rows,
                                                 bool *out_supported)
{
    if (out_supported)
        *out_supported = false;
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (!profile || !out_words)
        return false;

    auto t_pf20 = Clock::now();

    // PF-V2.2 intentionally excludes dependency-restricted witness tables.
    (void)restrict_sigs;

    std::unordered_set<int> cross_domains;
    cross_domains.reserve(4);
    for (int aid : cl.atom_ids) {
        auto it = loaded.atoms_by_id.find(aid);
        if (it == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it->second;
        if (a.kind == AtomKind::COLCOL) {
            // Allow same-table col-col atoms as row-local checks.
            if (a.left.table != a.right.table)
                return true;
            continue;
        }
        if (a.kind == AtomKind::JOIN) {
            if (a.join_class_id < 0)
                return true;
            cross_domains.insert(a.join_class_id);
        }
    }
    if (cross_domains.size() != 1)
        return true;
    int hub_domain_id = *cross_domains.begin();

    // Target must be hub-only for this stage (predicates are allowed and enforced at projection).
    const ClauseClassGroup *target_hub_group = nullptr;
    for (const auto &cg : target_tp.class_groups) {
        if (cg.domain_id == hub_domain_id) {
            if (target_hub_group)
                return true;
            target_hub_group = &cg;
        } else {
            return true;
        }
    }
    if (!target_hub_group || target_hub_group->col_data.empty())
        return true;

    std::vector<Pf2SingleHubTableStampPlan> plans;
    plans.reserve(cl.tables.size());
    for (const auto &tp_tbl : cl.tables) {
        auto it_t = loaded.tables.find(tp_tbl.table);
        if (it_t == loaded.tables.end())
            return false;
        const ClauseClassGroup *hub_group = nullptr;
        for (const auto &cg : tp_tbl.class_groups) {
            if (cg.domain_id != hub_domain_id)
                continue;
            if (hub_group)
                return true; // multi-hub participation on one table unsupported
            hub_group = &cg;
        }
        if (tp_tbl.table == target) {
            if (!hub_group)
                return true;
            plans.push_back({&tp_tbl, &it_t->second, hub_group, true});
            continue;
        }
        if (!hub_group)
            return true;
        plans.push_back({&tp_tbl, &it_t->second, hub_group, false});
    }

    size_t ntokens = 0;
    auto itdd = loaded.domain_dicts.find(hub_domain_id);
    if (itdd != loaded.domain_dicts.end())
        ntokens = itdd->second.size();
    if (ntokens == 0) {
        const BinIndexCacheEntry *ent = nullptr;
        if (!get_or_build_bin_index_cache_entry(loaded, target, hub_domain_id, &ent))
            return false;
        if (!ent || ent->off.empty())
            return true;
        ntokens = ent->off.size() - 1u;
    }

    profile->pf2_terms_supported++;
    profile->pf2_terms_single_hub++;
    profile->pf2_hub_domain_id = hub_domain_id;
    profile->pf2_hub_key_arity = 1;
    profile->pf2_ntokens = std::max<uint64>(profile->pf2_ntokens, (uint64)ntokens);

    auto t_tok0 = Clock::now();
    TokenBitset tok_allow(ntokens);
    tok_allow.fill_all();

    // Join atoms under the hub reduce to token-presence intersections.
    for (const auto &pl : plans) {
        TokenBitset present(ntokens);
        if (!pf2_build_present_tokens_for_table(loaded, pl.tp->table, hub_domain_id, ntokens, &present))
            return false;
        tok_allow.bit_and(present);
        if (!tok_allow.any())
            break;
    }
    profile->pf2_tok_and_or_ms += Ms(Clock::now() - t_tok0).count();
    if (!tok_allow.any()) {
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported)
            *out_supported = true;
        if (out_term_has_rows)
            *out_term_has_rows = false;
        return true;
    }

    auto t_stamp0 = Clock::now();
    // One witness scan per table, stamping hub tokens that satisfy all local predicates.
    for (const auto &pl : plans) {
        if (pl.is_target)
            continue;
        if (!pl.tp || !pl.ti || !pl.hub_group || pl.hub_group->col_data.empty())
            return false;
        if (pl.tp->predicates.empty())
            continue;

        TokenBitset witness_tok(ntokens);
        witness_tok.clear_all();
        const auto &hub_col0 = *pl.hub_group->col_data[0];
        profile->pf2_stamp_rows_scanned_total += pl.ti->nrows;
        for (uint32 rid = 0; rid < pl.ti->nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if ((size_t)rid >= hub_col0.size())
                return false;
            int32_t tok = hub_col0[rid];
            if (tok < 0 || (size_t)tok >= ntokens)
                continue;
            if (!tok_allow.test((size_t)tok))
                continue;
            bool hub_ok = true;
            for (size_t i = 1; i < pl.hub_group->col_data.size(); i++) {
                if ((size_t)rid >= pl.hub_group->col_data[i]->size() ||
                    (*pl.hub_group->col_data[i])[rid] != tok) {
                    hub_ok = false;
                    break;
                }
            }
            if (!hub_ok)
                continue;
            if (!row_matches_table_predicates_only(*pl.tp, rid, nullptr))
                continue;
            witness_tok.set((size_t)tok);
        }
        witness_tok.adapt_representation();
        tok_allow.bit_and(witness_tok);
        if (!tok_allow.any())
            break;
    }
    profile->pf2_stamp_ms += Ms(Clock::now() - t_stamp0).count();
    if (!tok_allow.any()) {
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported)
            *out_supported = true;
        if (out_term_has_rows)
            *out_term_has_rows = false;
        return true;
    }

    auto t_proj0 = Clock::now();
    uint32 projected_rows = 0;
    tok_allow.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
            return;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, target, hub_domain_id, tok_i32, &rid_ptr, &rid_len))
            ereport(ERROR,
                    (errmsg("policy: PF-V2.2 bin slice lookup failed table=%s domain=%d tok=%d",
                            target.c_str(), hub_domain_id, tok_i32)));
        profile->pf2_project_bin_rids_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            if (!row_matches_table_predicates_only(target_tp, rid, nullptr))
                continue;
            if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                ereport(ERROR,
                        (errmsg("policy: PF-V2.2 failed to stamp CTID table=%s rid=%u", target.c_str(), rid)));
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
            projected_rows++;
        }
    });
    profile->pf2_project_ms += Ms(Clock::now() - t_proj0).count();
    profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();

    if (out_supported)
        *out_supported = true;
    if (out_term_has_rows)
        *out_term_has_rows = (projected_rows > 0);
    return true;
}

static bool pf2_detect_two_hop_pattern(const Loaded &loaded,
                                       const std::string &target,
                                       const ClausePlan &cl,
                                       const ClauseTablePlan &target_tp,
                                       const TableData &target_ti,
                                       Pf2TwoHopPattern *out_pat)
{
    if (!out_pat)
        return false;
    *out_pat = Pf2TwoHopPattern{};
    out_pat->target_tp = &target_tp;
    out_pat->target_ti = &target_ti;

    struct Edge { std::string u; std::string v; int d = -1; };
    std::vector<Edge> edges;
    edges.reserve(4);
    std::unordered_set<std::string> term_tables;
    term_tables.reserve(cl.tables.size());
    for (const auto &tp : cl.tables)
        term_tables.insert(tp.table);

    for (int aid : cl.atom_ids) {
        auto it = loaded.atoms_by_id.find(aid);
        if (it == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it->second;
        if (a.kind == AtomKind::JOIN) {
            if (a.join_class_id < 0) {
                CF_TRACE_LOG("pf2_two_hop unsupported: join atom missing class target=%s", target.c_str());
                return true;
            }
            if (a.left.table == a.right.table) {
                CF_TRACE_LOG("pf2_two_hop unsupported: same-table JOIN atom target=%s", target.c_str());
                return true;
            }
            edges.push_back(Edge{a.left.table, a.right.table, a.join_class_id});
        } else if (a.kind == AtomKind::COLCOL) {
            // Allow same-table col-col only; cross-table col-col unsupported in PF-V2.3.
            if (a.left.table != a.right.table) {
                CF_TRACE_LOG("pf2_two_hop unsupported: cross-table COLCOL atom left=%s right=%s op=%d",
                             a.left.table.c_str(), a.right.table.c_str(), (int)a.op);
                return true;
            }
        } else if (a.kind == AtomKind::CONST) {
            // fine
        } else {
            CF_TRACE_LOG("pf2_two_hop unsupported: atom kind %d", (int)a.kind);
            return true;
        }
    }

    if (edges.size() != 2) {
        CF_TRACE_LOG("pf2_two_hop unsupported: edges.size=%zu target=%s", edges.size(), target.c_str());
        return true;
    }
    if (term_tables.size() != 3) {
        CF_TRACE_LOG("pf2_two_hop unsupported: term_tables.size=%zu target=%s", term_tables.size(), target.c_str());
        return true;
    }

    int target_edge_idx = -1;
    for (size_t i = 0; i < edges.size(); i++) {
        if (edges[i].u == target || edges[i].v == target) {
            if (target_edge_idx >= 0)
                {
                    CF_TRACE_LOG("pf2_two_hop unsupported: target touches >1 join edge target=%s", target.c_str());
                    return true;
                }
            target_edge_idx = (int)i;
        }
    }
    if (target_edge_idx < 0) {
        CF_TRACE_LOG("pf2_two_hop unsupported: no target edge target=%s", target.c_str());
        return true;
    }

    const Edge &e_t = edges[(size_t)target_edge_idx];
    const Edge &e_o = edges[(size_t)(1 - target_edge_idx)];
    std::string a_tbl = (e_t.u == target) ? e_t.v : e_t.u;
    if (a_tbl.empty()) {
        CF_TRACE_LOG("pf2_two_hop unsupported: empty middle table target=%s", target.c_str());
        return true;
    }
    if (e_o.u != a_tbl && e_o.v != a_tbl) {
        CF_TRACE_LOG("pf2_two_hop unsupported: edges do not chain through middle target=%s", target.c_str());
        return true;
    }
    std::string b_tbl = (e_o.u == a_tbl) ? e_o.v : e_o.u;
    if (b_tbl.empty() || b_tbl == target) {
        CF_TRACE_LOG("pf2_two_hop unsupported: invalid leaf table target=%s", target.c_str());
        return true;
    }

    int h1 = e_t.d;
    int h2 = e_o.d;
    if (h1 < 0 || h2 < 0) {
        CF_TRACE_LOG("pf2_two_hop unsupported: negative domain id h1=%d h2=%d", h1, h2);
        return true;
    }
    if (h1 == h2) {
        CF_TRACE_LOG("pf2_two_hop unsupported: h1==h2 (%d)", h1);
        return true; // avoid ambiguous same-domain two-edge cases in PF-V2.3
    }

    const ClauseTablePlan *a_tp = nullptr;
    const ClauseTablePlan *b_tp = nullptr;
    const TableData *a_ti = nullptr;
    const TableData *b_ti = nullptr;
    for (const auto &tp : cl.tables) {
        if (tp.table == a_tbl) a_tp = &tp;
        if (tp.table == b_tbl) b_tp = &tp;
    }
    auto it_a = loaded.tables.find(a_tbl);
    auto it_b = loaded.tables.find(b_tbl);
    if (it_a == loaded.tables.end() || it_b == loaded.tables.end())
        return false;
    a_ti = &it_a->second;
    b_ti = &it_b->second;
    if (!a_tp || !b_tp) {
        CF_TRACE_LOG("pf2_two_hop unsupported: missing clause table plan a=%p b=%p", (void*)a_tp, (void*)b_tp);
        return true;
    }

    const ClauseClassGroup *t_h1 = pf2_find_group_by_domain(target_tp, h1);
    const ClauseClassGroup *a_h1 = pf2_find_group_by_domain(*a_tp, h1);
    const ClauseClassGroup *a_h2 = pf2_find_group_by_domain(*a_tp, h2);
    const ClauseClassGroup *b_h2 = pf2_find_group_by_domain(*b_tp, h2);
    if (!t_h1 || !a_h1 || !a_h2 || !b_h2) {
        CF_TRACE_LOG("pf2_two_hop unsupported: missing class groups t_h1=%p a_h1=%p a_h2=%p b_h2=%p",
                     (void*)t_h1, (void*)a_h1, (void*)a_h2, (void*)b_h2);
        return true;
    }

    // `class_groups` may include extra domains used by local predicates/other columns.
    // Shape strictness is enforced by the two join-edge topology above plus target-local predicate/comparator checks.

    // Local comparator support: same-table only on A/B; no cross-table comparator.
    bool unsupported_cmp = false;
    std::vector<Pf2LocalComparator> t_local;
    if (!pf2_map_local_comparators_for_table(cl, target_tp, &t_local, &unsupported_cmp, true))
        return false;
    if (unsupported_cmp) {
        CF_TRACE_LOG("pf2_two_hop unsupported: target comparators unsupported=%d",
                     unsupported_cmp ? 1 : 0);
        return true;
    }
    out_pat->t_local_cmps = std::move(t_local);

    if (!pf2_map_local_comparators_for_table(cl, *a_tp, &out_pat->a_local_cmps, &unsupported_cmp, true))
        return false;
    if (unsupported_cmp) {
        CF_TRACE_LOG("pf2_two_hop unsupported: middle comparators unsupported");
        return true;
    }
    if (!pf2_map_local_comparators_for_table(cl, *b_tp, &out_pat->b_local_cmps, &unsupported_cmp, true))
        return false;
    if (unsupported_cmp) {
        CF_TRACE_LOG("pf2_two_hop unsupported: leaf comparators unsupported");
        return true;
    }

    out_pat->a_tp = a_tp;
    out_pat->a_ti = a_ti;
    out_pat->b_tp = b_tp;
    out_pat->b_ti = b_ti;
    out_pat->t_h1 = t_h1;
    out_pat->a_h1 = a_h1;
    out_pat->a_h2 = a_h2;
    out_pat->b_h2 = b_h2;
    out_pat->h1_domain = h1;
    out_pat->h2_domain = h2;
    return true;
}

static bool eval_term_conjunction_pf2_two_hop(const Loaded &loaded,
                                              const std::string &target,
                                              const ClausePlan &cl,
                                              const ClauseTablePlan &target_tp,
                                              const TableData &target_ti,
                                              const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                              BuildProfile *profile,
                                              SparseBlockWords *out_words,
                                              std::vector<uint8_t> *out_rid_bits,
                                              bool *out_term_has_rows,
                                              bool *out_supported)
{
    if (out_supported)
        *out_supported = false;
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (!profile || !out_words)
        return false;
    auto t_pf20 = Clock::now();

    (void)restrict_sigs;

    Pf2TwoHopPattern pat;
    if (!pf2_detect_two_hop_pattern(loaded, target, cl, target_tp, target_ti, &pat))
        return false;
    if (!pat.a_tp || !pat.b_tp || !pat.t_h1 || !pat.a_h1 || !pat.a_h2 || !pat.b_h2)
        return true;

    size_t ntok_h1 = 0, ntok_h2 = 0;
    auto itd1 = loaded.domain_dicts.find(pat.h1_domain);
    auto itd2 = loaded.domain_dicts.find(pat.h2_domain);
    if (itd1 != loaded.domain_dicts.end()) ntok_h1 = itd1->second.size();
    if (itd2 != loaded.domain_dicts.end()) ntok_h2 = itd2->second.size();
    if (ntok_h1 == 0) {
        const BinIndexCacheEntry *ent = nullptr;
        if (!get_or_build_bin_index_cache_entry(loaded, target, pat.h1_domain, &ent))
            return false;
        if (!ent || ent->off.empty())
            return true;
        ntok_h1 = ent->off.size() - 1u;
    }
    if (ntok_h2 == 0) {
        const BinIndexCacheEntry *ent = nullptr;
        if (!get_or_build_bin_index_cache_entry(loaded, pat.b_tp->table, pat.h2_domain, &ent))
            return false;
        if (!ent || ent->off.empty())
            return true;
        ntok_h2 = ent->off.size() - 1u;
    }
    if (ntok_h1 == 0 || ntok_h2 == 0)
        return true;

    profile->pf2_terms_supported++;
    profile->pf2_terms_two_hop++;
    profile->pf2_hub_domain_id = pat.h1_domain;
    profile->pf2_hub_key_arity = 1;
    profile->pf2_ntokens = std::max<uint64>(profile->pf2_ntokens, (uint64)ntok_h1);

    auto t_tok0 = Clock::now();
    TokenBitset tok_t_present(ntok_h1);
    if (!pf2_build_present_tokens_for_table(loaded, target, pat.h1_domain, ntok_h1, &tok_t_present))
        return false;
    if (!tok_t_present.any()) {
        profile->pf2_tok_and_or_ms += Ms(Clock::now() - t_tok0).count();
        profile->pf2_tok_compose_ms += Ms(Clock::now() - t_tok0).count();
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported) *out_supported = true;
        return true;
    }

    // Build Tok_B(H2): local predicates on B only.
    auto t_b0 = Clock::now();
    TokenBitset tok_b_h2(ntok_h2);
    tok_b_h2.clear_all();
    const auto &b_h2_col0 = *pat.b_h2->col_data[0];
    profile->pf2_stamp_rows_scanned_total += pat.b_ti->nrows;
    profile->pf2_stamp_rows_scanned_B += pat.b_ti->nrows;
    for (uint32 rid = 0; rid < pat.b_ti->nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if ((size_t)rid >= b_h2_col0.size())
            return false;
        int32_t h2 = b_h2_col0[(size_t)rid];
        if (h2 < 0 || (size_t)h2 >= ntok_h2)
            continue;
        bool group_ok = true;
        for (size_t i = 1; i < pat.b_h2->col_data.size(); i++) {
            if ((size_t)rid >= pat.b_h2->col_data[i]->size() ||
                (*pat.b_h2->col_data[i])[rid] != h2) {
                group_ok = false;
                break;
            }
        }
        if (!group_ok)
            continue;
        if (!pf2_row_matches_table_local_atoms(*pat.b_tp, pat.b_local_cmps, rid))
            continue;
        tok_b_h2.set((size_t)h2);
    }
    tok_b_h2.adapt_representation();
    double ms_b = Ms(Clock::now() - t_b0).count();
    profile->pf2_stamp_ms += ms_b;
    profile->pf2_stamp_ms_B += ms_b;

    if (!tok_b_h2.any()) {
        double ms_comp = Ms(Clock::now() - t_tok0).count();
        profile->pf2_tok_and_or_ms += ms_comp;
        profile->pf2_tok_compose_ms += ms_comp;
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported) *out_supported = true;
        return true;
    }

    // Compose through A: local predicates on A and A.H2 must be in Tok_B(H2), stamp H1.
    auto t_a0 = Clock::now();
    TokenBitset tok_a_h1(ntok_h1);
    tok_a_h1.clear_all();
    const auto &a_h1_col0 = *pat.a_h1->col_data[0];
    const auto &a_h2_col0 = *pat.a_h2->col_data[0];
    profile->pf2_stamp_rows_scanned_total += pat.a_ti->nrows;
    profile->pf2_stamp_rows_scanned_A += pat.a_ti->nrows;
    for (uint32 rid = 0; rid < pat.a_ti->nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if ((size_t)rid >= a_h1_col0.size() || (size_t)rid >= a_h2_col0.size())
            return false;
        int32_t h1 = a_h1_col0[(size_t)rid];
        int32_t h2 = a_h2_col0[(size_t)rid];
        if (h1 < 0 || h2 < 0 || (size_t)h1 >= ntok_h1 || (size_t)h2 >= ntok_h2)
            continue;
        bool g1_ok = true;
        for (size_t i = 1; i < pat.a_h1->col_data.size(); i++) {
            if ((size_t)rid >= pat.a_h1->col_data[i]->size() ||
                (*pat.a_h1->col_data[i])[rid] != h1) {
                g1_ok = false;
                break;
            }
        }
        if (!g1_ok)
            continue;
        bool g2_ok = true;
        for (size_t i = 1; i < pat.a_h2->col_data.size(); i++) {
            if ((size_t)rid >= pat.a_h2->col_data[i]->size() ||
                (*pat.a_h2->col_data[i])[rid] != h2) {
                g2_ok = false;
                break;
            }
        }
        if (!g2_ok)
            continue;
        if (!tok_t_present.test((size_t)h1))
            continue;
        if (!tok_b_h2.test((size_t)h2))
            continue;
        if (!pf2_row_matches_table_local_atoms(*pat.a_tp, pat.a_local_cmps, rid))
            continue;
        tok_a_h1.set((size_t)h1);
    }
    tok_a_h1.adapt_representation();
    double ms_a = Ms(Clock::now() - t_a0).count();
    profile->pf2_stamp_ms += ms_a;
    profile->pf2_stamp_ms_A += ms_a;

    tok_a_h1.bit_and(tok_t_present);
    double ms_comp = Ms(Clock::now() - t_tok0).count();
    profile->pf2_tok_and_or_ms += ms_comp;
    profile->pf2_tok_compose_ms += ms_comp;

    if (!tok_a_h1.any()) {
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported) *out_supported = true;
        return true;
    }

    auto t_proj0 = Clock::now();
    uint32 projected_rows = 0;
    tok_a_h1.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
            return;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, target, pat.h1_domain, tok_i32, &rid_ptr, &rid_len))
            ereport(ERROR,
                    (errmsg("policy: PF-V2.3 bin slice lookup failed table=%s domain=%d tok=%d",
                            target.c_str(), pat.h1_domain, tok_i32)));
        profile->pf2_project_bin_rids_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            if (!pf2_row_matches_table_local_atoms(target_tp, pat.t_local_cmps, rid))
                continue;
            if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                ereport(ERROR,
                        (errmsg("policy: PF-V2.3 failed to stamp CTID table=%s rid=%u", target.c_str(), rid)));
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
            projected_rows++;
        }
    });
    profile->pf2_project_ms += Ms(Clock::now() - t_proj0).count();
    profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();

    if (out_supported)
        *out_supported = true;
    if (out_term_has_rows)
        *out_term_has_rows = (projected_rows > 0);
    return true;
}

struct Pf2TreeDomainNode {
    int domain_id = -1;
    size_t ntokens = 0;
    std::vector<int> edge_ids;  // incident Pf2TreeEdge ids
};

struct Pf2TreeTableNode {
    const ClauseTablePlan *tp = nullptr;
    const TableData *ti = nullptr;
    bool is_target = false;
    std::vector<int> edge_ids;  // incident Pf2TreeEdge ids
    std::vector<Pf2LocalComparator> local_cmps;
};

struct Pf2TreeEdge {
    int table_idx = -1;
    int domain_idx = -1;
    const ClauseClassGroup *group = nullptr;
};

struct Pf2TreeComparatorEndpoint {
    int table_idx = -1;
    const ClauseClassGroup *cmp_group = nullptr;  // column being compared on this endpoint
    std::vector<const ClauseClassGroup *> key_groups;  // separator key domains present on this endpoint
};

struct Pf2TreeComparatorPlan {
    const ClauseComparator *cmp = nullptr;
    int left_table_idx = -1;
    int right_table_idx = -1;
    bool witness_witness = false;
    bool witness_witness_chain = false;
    int key_arity = 0;
    std::array<int, 2> key_domain_ids{{-1, -1}};
    // Ordered path from left endpoint to right endpoint; for tree routes these are unique.
    std::vector<int> path_domain_ids_lr;
    std::vector<int> path_bridge_tables_lr;  // excludes comparator endpoint tables
    Pf2TreeComparatorEndpoint left_ep;
    Pf2TreeComparatorEndpoint right_ep;
    bool ordered = false;
};

static inline uint64_t pf2_pack_key2(int32_t k0, int32_t k1)
{
    return (uint64_t(uint32_t(k0)) << 32) | uint64_t(uint32_t(k1));
}

struct Pf2TreePattern {
    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;
    int target_table_idx = -1;
    int target_hub_domain_idx = -1;  // root domain for target component
    std::vector<Pf2TreeDomainNode> domains;
    std::vector<Pf2TreeTableNode> tables;
    std::vector<Pf2TreeEdge> edges;
    std::vector<Pf2TreeComparatorPlan> cmps;
    std::vector<int> comp_of_domain;
    std::vector<int> comp_of_table;
    int component_count = 0;
};

static inline const ClauseClassGroup *pf2_find_group_by_class_pos(const ClauseTablePlan &tp, int class_pos)
{
    for (const auto &cg : tp.class_groups) {
        if (cg.class_pos == class_pos)
            return &cg;
    }
    return nullptr;
}

static bool pf2_tree_detect_pattern(const Loaded &loaded,
                                    const std::string &target,
                                    const ClausePlan &cl,
                                    const ClauseTablePlan &target_tp,
                                    const TableData &target_ti,
                                    Pf2TreePattern *out_pat)
{
    if (!out_pat)
        return false;
    *out_pat = Pf2TreePattern{};
    out_pat->target_tp = &target_tp;
    out_pat->target_ti = &target_ti;

    // PF-V2 paths currently exclude dependency-restricted witness semantics.
    // Caller enforces this before reaching here.

    struct JoinAtomEdge {
        std::string u;
        std::string v;
        int d = -1;
    };
    std::vector<JoinAtomEdge> join_edges;
    join_edges.reserve(8);

    for (int aid : cl.atom_ids) {
        auto it = loaded.atoms_by_id.find(aid);
        if (it == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it->second;
        if (a.kind == AtomKind::JOIN) {
            if (a.join_class_id < 0 || a.left.table == a.right.table)
                return true;
            join_edges.push_back({a.left.table, a.right.table, a.join_class_id});
        } else if (a.kind == AtomKind::COLCOL) {
            // Cross-table comparators are handled by PF-V2.5 planning below.
            // Same-table comparators remain local row checks.
        } else if (a.kind != AtomKind::CONST) {
            return true;
        }
    }
    if (join_edges.empty())
        return true;

    std::unordered_map<std::string, const ClauseTablePlan *> tp_by_table;
    std::unordered_map<std::string, const TableData *> ti_by_table;
    tp_by_table.reserve(cl.tables.size());
    ti_by_table.reserve(cl.tables.size());
    for (const auto &tp_tbl : cl.tables) {
        tp_by_table[tp_tbl.table] = &tp_tbl;
        auto it = loaded.tables.find(tp_tbl.table);
        if (it == loaded.tables.end())
            return false;
        ti_by_table[tp_tbl.table] = &it->second;
    }
    if (tp_by_table.find(target) == tp_by_table.end())
        return true;

    std::unordered_map<std::string, int> table_idx_by_name;
    table_idx_by_name.reserve(tp_by_table.size());
    std::unordered_map<int, int> domain_idx_by_id;
    domain_idx_by_id.reserve(8);

    auto ensure_table_idx = [&](const std::string &table) -> int {
        auto it = table_idx_by_name.find(table);
        if (it != table_idx_by_name.end())
            return it->second;
        auto it_tp = tp_by_table.find(table);
        auto it_ti = ti_by_table.find(table);
        if (it_tp == tp_by_table.end() || it_ti == ti_by_table.end())
            return -1;
        int idx = (int)out_pat->tables.size();
        Pf2TreeTableNode node;
        node.tp = it_tp->second;
        node.ti = it_ti->second;
        node.is_target = (table == target);
        // PF-V2.5 handles cross-table comparators separately. Here we only collect same-table
        // comparators and local predicates for row checks.
        if (!pf2_map_local_comparators_for_table(cl, *node.tp, &node.local_cmps, nullptr, true))
            return -2;
        out_pat->tables.push_back(std::move(node));
        table_idx_by_name.emplace(table, idx);
        return idx;
    };

    auto ensure_domain_idx = [&](int domain_id) -> int {
        auto it = domain_idx_by_id.find(domain_id);
        if (it != domain_idx_by_id.end())
            return it->second;
        int idx = (int)out_pat->domains.size();
        Pf2TreeDomainNode dn;
        dn.domain_id = domain_id;
        auto itd = loaded.domain_dicts.find(domain_id);
        if (itd != loaded.domain_dicts.end())
            dn.ntokens = itd->second.size();
        out_pat->domains.push_back(std::move(dn));
        domain_idx_by_id.emplace(domain_id, idx);
        return idx;
    };

    std::unordered_set<std::string> seen_incident;
    seen_incident.reserve(join_edges.size() * 2u + 4u);

    for (const auto &je : join_edges) {
        int ti_u = ensure_table_idx(je.u);
        int ti_v = ensure_table_idx(je.v);
        if (ti_u == -2 || ti_v == -2)
            return false;
        if (ti_u < 0 || ti_v < 0)
            return true;
        int di = ensure_domain_idx(je.d);
        if (di < 0)
            return false;
        auto add_incident = [&](int table_idx, const std::string &table_name) -> bool {
            std::string key = table_name + "|D" + std::to_string(je.d);
            if (!seen_incident.insert(key).second)
                return true;
            const ClauseClassGroup *cg = pf2_find_group_by_domain(*out_pat->tables[(size_t)table_idx].tp, je.d);
            if (!cg || cg->col_data.empty())
                return false;
            if (out_pat->domains[(size_t)di].ntokens == 0) {
                const BinIndexCacheEntry *ent = nullptr;
                if (!get_or_build_bin_index_cache_entry(loaded, table_name, je.d, &ent))
                    return false;
                if (!ent || ent->off.empty())
                    return false;
                out_pat->domains[(size_t)di].ntokens = ent->off.size() - 1u;
            }
            Pf2TreeEdge e;
            e.table_idx = table_idx;
            e.domain_idx = di;
            e.group = cg;
            int eid = (int)out_pat->edges.size();
            out_pat->edges.push_back(e);
            out_pat->tables[(size_t)table_idx].edge_ids.push_back(eid);
            out_pat->domains[(size_t)di].edge_ids.push_back(eid);
            return true;
        };
        if (!add_incident(ti_u, je.u) || !add_incident(ti_v, je.v))
            return false;
    }

    // Reject terms with tables that participate in no join edge (PF-V2.4 tree scope).
    for (size_t i = 0; i < out_pat->tables.size(); i++) {
        if (out_pat->tables[i].edge_ids.empty())
            return true;
    }

    auto itt = table_idx_by_name.find(target);
    if (itt == table_idx_by_name.end())
        return true;
    out_pat->target_table_idx = itt->second;
    if (out_pat->tables[(size_t)out_pat->target_table_idx].edge_ids.size() != 1u)
        return true;  // multi-hub target unsupported in PF-V2.4
    int root_eid = out_pat->tables[(size_t)out_pat->target_table_idx].edge_ids[0];
    out_pat->target_hub_domain_idx = out_pat->edges[(size_t)root_eid].domain_idx;

    // Component labeling on bipartite graph.
    int nd = (int)out_pat->domains.size();
    int nt = (int)out_pat->tables.size();
    int ngraph = nd + nt;
    std::vector<std::vector<int>> adj_edges((size_t)ngraph);
    for (int eid = 0; eid < (int)out_pat->edges.size(); eid++) {
        const auto &e = out_pat->edges[(size_t)eid];
        int dnode = e.domain_idx;
        int tnode = nd + e.table_idx;
        adj_edges[(size_t)dnode].push_back(eid);
        adj_edges[(size_t)tnode].push_back(eid);
    }
    std::vector<int> comp_node((size_t)ngraph, -1);
    out_pat->comp_of_domain.assign((size_t)nd, -1);
    out_pat->comp_of_table.assign((size_t)nt, -1);
    int comp_id = 0;
    for (int start = 0; start < ngraph; start++) {
        if (adj_edges[(size_t)start].empty() || comp_node[(size_t)start] >= 0)
            continue;
        std::deque<int> q;
        q.push_back(start);
        comp_node[(size_t)start] = comp_id;
        int comp_edges_twice = 0;
        int comp_nodes = 0;
        while (!q.empty()) {
            int u = q.front();
            q.pop_front();
            comp_nodes++;
            comp_edges_twice += (int)adj_edges[(size_t)u].size();
            for (int eid : adj_edges[(size_t)u]) {
                const auto &e = out_pat->edges[(size_t)eid];
                int v = (u < nd) ? (nd + e.table_idx) : e.domain_idx;
                if (comp_node[(size_t)v] >= 0)
                    continue;
                comp_node[(size_t)v] = comp_id;
                q.push_back(v);
            }
        }
        int comp_edges = comp_edges_twice / 2;
        // Acyclic component => tree (connected by BFS construction): edges = nodes - 1
        if (comp_edges != comp_nodes - 1)
            return true;
        comp_id++;
    }
    out_pat->component_count = comp_id;
    for (int di = 0; di < nd; di++)
        out_pat->comp_of_domain[(size_t)di] = comp_node[(size_t)di];
    for (int ti = 0; ti < nt; ti++)
        out_pat->comp_of_table[(size_t)ti] = comp_node[(size_t)(nd + ti)];

    if (out_pat->target_hub_domain_idx < 0 ||
        out_pat->target_hub_domain_idx >= nd ||
        out_pat->comp_of_domain[(size_t)out_pat->target_hub_domain_idx] < 0)
        return true;

    auto unsupported_shape = [&]() -> bool {
        *out_pat = Pf2TreePattern{};
        return true;
    };

    auto node_from_domain = [&](int di) { return di; };
    auto node_from_table = [&](int ti) { return nd + ti; };

    // Class-engine comparator planning on the acyclic factor graph:
    // - target-endpoint comparators: existing keyed summary checks in target projection.
    // - witness-witness comparators: Stage 3A (adjacent-only) checked during table-message emission.
    for (const ClauseComparator &cmp : cl.compares) {
        auto ita = loaded.atoms_by_id.find(cmp.atom_id);
        if (ita == loaded.atoms_by_id.end())
            return false;
        const Atom &a = ita->second;
        if (a.kind != AtomKind::COLCOL)
            continue;
        if (a.left.table == a.right.table)
            continue; // local comparator handled in row-local checks

        out_pat->cmps.reserve(out_pat->cmps.size() + 1u);
        auto itl = table_idx_by_name.find(a.left.table);
        auto itr = table_idx_by_name.find(a.right.table);
        if (itl == table_idx_by_name.end() || itr == table_idx_by_name.end())
            return unsupported_shape();
        int lti = itl->second;
        int rti = itr->second;
        if (lti < 0 || rti < 0 || lti >= (int)out_pat->tables.size() || rti >= (int)out_pat->tables.size())
            return false;

        bool witness_witness = (lti != out_pat->target_table_idx && rti != out_pat->target_table_idx);

        const ClauseTablePlan &ltp = *out_pat->tables[(size_t)lti].tp;
        const ClauseTablePlan &rtp = *out_pat->tables[(size_t)rti].tp;
        const ClauseClassGroup *l_cmp_group = pf2_find_group_by_class_pos(ltp, cmp.left_pos);
        const ClauseClassGroup *r_cmp_group = pf2_find_group_by_class_pos(rtp, cmp.right_pos);
        if (!l_cmp_group || !r_cmp_group)
            return unsupported_shape();

        int src = node_from_table(lti);
        int dst = node_from_table(rti);
        std::vector<int> parent((size_t)ngraph, -1);
        std::vector<int> parent_edge((size_t)ngraph, -1);
        std::deque<int> q;
        q.push_back(src);
        parent[(size_t)src] = src;
        while (!q.empty() && parent[(size_t)dst] < 0) {
            int u = q.front();
            q.pop_front();
            for (int eid : adj_edges[(size_t)u]) {
                const auto &e = out_pat->edges[(size_t)eid];
                int v = (u < nd) ? node_from_table(e.table_idx) : node_from_domain(e.domain_idx);
                if (parent[(size_t)v] >= 0)
                    continue;
                parent[(size_t)v] = u;
                parent_edge[(size_t)v] = eid;
                q.push_back(v);
            }
        }
        if (parent[(size_t)dst] < 0)
            return unsupported_shape();

        std::vector<int> path_nodes_rev;
        for (int cur = dst;; cur = parent[(size_t)cur]) {
            path_nodes_rev.push_back(cur);
            if (cur == src)
                break;
            if (parent[(size_t)cur] < 0)
                return unsupported_shape();
        }
        std::vector<int> path_nodes;
        path_nodes.reserve(path_nodes_rev.size());
        for (auto it = path_nodes_rev.rbegin(); it != path_nodes_rev.rend(); ++it)
            path_nodes.push_back(*it);

        std::vector<int> path_domain_idxs;
        path_domain_idxs.reserve(path_nodes.size());
        for (int n : path_nodes) {
            if (n < nd)
                path_domain_idxs.push_back(n);
        }

        std::vector<int> path_bridge_tables;
        for (size_t i = 1; i + 1 < path_nodes.size(); i++) {
            int n = path_nodes[i];
            if (n >= nd)
                path_bridge_tables.push_back(n - nd);
        }
        if (path_domain_idxs.empty())
            return unsupported_shape();

        Pf2TreeComparatorPlan cp;
        cp.cmp = &cmp;
        cp.left_table_idx = lti;
        cp.right_table_idx = rti;
        cp.witness_witness = witness_witness;
        cp.left_ep.table_idx = lti;
        cp.right_ep.table_idx = rti;
        cp.left_ep.cmp_group = l_cmp_group;
        cp.right_ep.cmp_group = r_cmp_group;
        cp.ordered = is_ordered_cmp(cmp.op);
        cp.path_domain_ids_lr.clear();
        cp.path_domain_ids_lr.reserve(path_domain_idxs.size());
        for (int pdi : path_domain_idxs)
            cp.path_domain_ids_lr.push_back(out_pat->domains[(size_t)pdi].domain_id);
        cp.path_bridge_tables_lr = path_bridge_tables;

        if (witness_witness) {
            int left_adj_domain = cp.path_domain_ids_lr.front();
            int right_adj_domain = cp.path_domain_ids_lr.back();
            cp.witness_witness_chain = !cp.path_bridge_tables_lr.empty();
            cp.key_arity = (left_adj_domain == right_adj_domain) ? 1 : 2;
            cp.key_domain_ids[0] = left_adj_domain;
            cp.key_domain_ids[1] = (cp.key_arity == 2) ? right_adj_domain : -1;
            if (cp.key_arity < 1 || cp.key_arity > 2)
                return unsupported_shape();
            cp.left_ep.key_groups.clear();
            cp.right_ep.key_groups.clear();
            for (int i = 0; i < cp.key_arity; i++) {
                int key_domain = cp.key_domain_ids[(size_t)i];
                const ClauseClassGroup *lk = pf2_find_group_by_domain(ltp, key_domain);
                const ClauseClassGroup *rk = pf2_find_group_by_domain(rtp, key_domain);
                // If the endpoint does not expose this key as a join group but the comparator
                // column itself is in the same comparable domain, reuse the comparator group.
                if (!lk && cp.cmp && cp.cmp->domain_id == key_domain && l_cmp_group)
                    lk = l_cmp_group;
                if (!rk && cp.cmp && cp.cmp->domain_id == key_domain && r_cmp_group)
                    rk = r_cmp_group;
                cp.left_ep.key_groups.push_back(lk);
                cp.right_ep.key_groups.push_back(rk);
            }
            const ClauseClassGroup *left_adj_group = pf2_find_group_by_domain(ltp, left_adj_domain);
            const ClauseClassGroup *right_adj_group = pf2_find_group_by_domain(rtp, right_adj_domain);
            if (!left_adj_group || !right_adj_group)
                return unsupported_shape();
            if (!cp.witness_witness_chain && cp.key_arity == 2) {
                // Adjacent witness-witness with two-key separators is not covered in Stage 3A/3B.
                return unsupported_shape();
            }
        } else {
            cp.key_arity = (int)path_domain_idxs.size();
            if (cp.key_arity < 1 || cp.key_arity > 2)
                return unsupported_shape();
            for (int i = 0; i < cp.key_arity; i++) {
                int pdi = path_domain_idxs[(size_t)i];
                cp.key_domain_ids[(size_t)i] = out_pat->domains[(size_t)pdi].domain_id;
                const ClauseClassGroup *lk = pf2_find_group_by_domain(ltp, cp.key_domain_ids[(size_t)i]);
                const ClauseClassGroup *rk = pf2_find_group_by_domain(rtp, cp.key_domain_ids[(size_t)i]);
                // PF-V2.6: if a separator key domain is not present as a join class on an endpoint
                // table, allow reuse of the comparator endpoint column group when the comparator
                // domain matches the separator domain.
                if (!lk && cp.cmp && cp.cmp->domain_id == cp.key_domain_ids[(size_t)i] && l_cmp_group)
                    lk = l_cmp_group;
                if (!rk && cp.cmp && cp.cmp->domain_id == cp.key_domain_ids[(size_t)i] && r_cmp_group)
                    rk = r_cmp_group;
                cp.left_ep.key_groups.push_back(lk);
                cp.right_ep.key_groups.push_back(rk);
            }
            // Target-endpoint comparator: require target endpoint to carry the full separator key tuple.
            const Pf2TreeComparatorEndpoint &target_ep =
                (lti == out_pat->target_table_idx) ? cp.left_ep : cp.right_ep;
            if ((int)target_ep.key_groups.size() != cp.key_arity)
                return unsupported_shape();
            for (int i = 0; i < cp.key_arity; i++) {
                if (!target_ep.key_groups[(size_t)i])
                    return unsupported_shape();
            }
        }

        out_pat->cmps.push_back(std::move(cp));
    }

    return true;
}

static bool pf2_tree_compute_domain_to_table_message(const Pf2TreePattern &pat,
                                                     int domain_idx,
                                                     int exclude_edge_id,
                                                     const std::vector<TokenBitset> &msg_t_to_d,
                                                     const std::vector<uint8_t> &msg_t_to_d_ready,
                                                     TokenBitset *out)
{
    if (!out || domain_idx < 0 || domain_idx >= (int)pat.domains.size())
        return false;
    const auto &dn = pat.domains[(size_t)domain_idx];
    out->reset(dn.ntokens);
    out->fill_all();
    bool saw = false;
    for (int eid : dn.edge_ids) {
        if (eid == exclude_edge_id)
            continue;
        if (eid < 0 || eid >= (int)msg_t_to_d.size() || !msg_t_to_d_ready[(size_t)eid])
            return false;
        out->bit_and(msg_t_to_d[(size_t)eid]);
        saw = true;
        if (!out->any())
            break;
    }
    if (!saw)
        out->fill_all(); // intersection over empty set = universe
    out->adapt_representation();
    return true;
}

struct Pf2TreeWitnessCmpContext;

static bool pf2_tree_prepare_witness_cmp_context(const Loaded &loaded,
                                                 const Pf2TreePattern &pat,
                                                 int table_idx,
                                                 const std::vector<TokenBitset> &msg_d_to_t,
                                                 const std::vector<uint8_t> &msg_d_to_t_ready,
                                                 BuildProfile *profile,
                                                 Pf2TreeWitnessCmpContext *out_ctx);

static bool pf2_tree_witness_cmp_filter_row(const Pf2TreePattern &pat,
                                            int table_idx,
                                            uint32 rid,
                                            BuildProfile *profile,
                                            const Pf2TreeWitnessCmpContext *ctx,
                                            bool *out_accept);

static bool pf2_tree_emit_table_messages(const Loaded &loaded,
                                         const Pf2TreePattern &pat,
                                         int table_idx,
                                         const std::vector<TokenBitset> &msg_d_to_t,
                                         const std::vector<uint8_t> &msg_d_to_t_ready,
                                         const std::vector<int> &out_edge_ids,
                                         int preferred_drive_edge_id,
                                         BuildProfile *profile,
                                         const Pf2TreeWitnessCmpContext *ww_ctx,
                                         std::vector<TokenBitset> *msg_t_to_d,
                                         std::vector<uint8_t> *msg_t_to_d_ready)
{
    if (table_idx < 0 || table_idx >= (int)pat.tables.size() || !profile || !msg_t_to_d || !msg_t_to_d_ready)
        return false;
    const auto &tn = pat.tables[(size_t)table_idx];
    if (!tn.tp || !tn.ti)
        return false;
    if (out_edge_ids.empty())
        return true;

    std::unordered_set<int> out_set(out_edge_ids.begin(), out_edge_ids.end());
    for (int oe : out_edge_ids) {
        if (oe < 0 || oe >= (int)pat.edges.size())
            return false;
        int di = pat.edges[(size_t)oe].domain_idx;
        (*msg_t_to_d)[(size_t)oe].reset(pat.domains[(size_t)di].ntokens);
        (*msg_t_to_d)[(size_t)oe].clear_all();
    }

    // Pick a safe driving edge. If driving edge is also an output edge, rows that fail its inbound
    // message could still support that outgoing message, so only use it if its inbound is not used.
    int drive_eid = -1;
    auto is_safe_drive = [&](int eid) -> bool {
        return out_set.find(eid) == out_set.end();
    };
    if (preferred_drive_edge_id >= 0 && is_safe_drive(preferred_drive_edge_id))
        drive_eid = preferred_drive_edge_id;
    if (drive_eid < 0) {
        size_t best_count = std::numeric_limits<size_t>::max();
        for (int eid : tn.edge_ids) {
            if (!is_safe_drive(eid))
                continue;
            if (eid < 0 || eid >= (int)msg_d_to_t.size() || !msg_d_to_t_ready[(size_t)eid])
                continue;
            size_t c = msg_d_to_t[(size_t)eid].count();
            if (c < best_count) {
                best_count = c;
                drive_eid = eid;
            }
        }
    }
    // Fallback (e.g. leaf table upward message): drive by full token presence on the outgoing edge.
    if (drive_eid < 0)
        drive_eid = out_edge_ids[0];

    auto t_up0 = Clock::now();
    profile->pf2_tree_table_updates++;

    const auto &drive_edge = pat.edges[(size_t)drive_eid];
    int drive_domain_idx = drive_edge.domain_idx;
    int drive_domain_id = pat.domains[(size_t)drive_domain_idx].domain_id;

    std::vector<const TokenBitset *> inbound_bits((size_t)tn.edge_ids.size(), nullptr);
    std::vector<int> edge_pos_to_out_idx((size_t)tn.edge_ids.size(), -1);
    for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
        int eid = tn.edge_ids[pos];
        if (eid < 0 || eid >= (int)pat.edges.size())
            return false;
        if (eid >= 0 && eid < (int)msg_d_to_t.size() && msg_d_to_t_ready[(size_t)eid])
            inbound_bits[pos] = &msg_d_to_t[(size_t)eid];
    }
    for (size_t oi = 0; oi < out_edge_ids.size(); oi++) {
        int oe = out_edge_ids[oi];
        for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
            if (tn.edge_ids[pos] == oe) {
                edge_pos_to_out_idx[pos] = (int)oi;
                break;
            }
        }
    }

    std::vector<int32_t> row_toks(tn.edge_ids.size(), -1);
    std::vector<int> fail_poss;
    fail_poss.reserve(tn.edge_ids.size());

    auto process_row = [&](uint32 rid) -> bool {
        if (!pf2_row_matches_table_local_atoms(*tn.tp, tn.local_cmps, rid))
            return true;
        if (ww_ctx) {
            bool ww_ok = true;
            if (!pf2_tree_witness_cmp_filter_row(pat, table_idx, rid, profile, ww_ctx, &ww_ok))
                return false;
            if (!ww_ok)
                return true;
        }

        fail_poss.clear();
        for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
            int eid = tn.edge_ids[pos];
            const auto &e = pat.edges[(size_t)eid];
            int32_t tok = -1;
            if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                return false;
            row_toks[pos] = tok;
            if (tok < 0)
                return true; // NULL / inconsistent class columns => row unusable
            const TokenBitset *inb = inbound_bits[pos];
            if (!inb)
                continue; // inbound excluded / not ready for this edge
            if (!inb->test((size_t)tok))
                fail_poss.push_back((int)pos);
        }
        if (fail_poss.size() > 1u)
            return true;

        for (size_t oi = 0; oi < out_edge_ids.size(); oi++) {
            int out_eid = out_edge_ids[oi];
            int out_pos = -1;
            for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
                if (tn.edge_ids[pos] == out_eid) { out_pos = (int)pos; break; }
            }
            if (out_pos < 0)
                return false;
            if (fail_poss.size() == 1u && fail_poss[0] != out_pos)
                continue;
            int32_t out_tok = row_toks[(size_t)out_pos];
            if (out_tok < 0)
                continue;
            int out_di = pat.edges[(size_t)out_eid].domain_idx;
            if ((size_t)out_tok >= pat.domains[(size_t)out_di].ntokens)
                continue;
            (*msg_t_to_d)[(size_t)out_eid].set((size_t)out_tok);
        }
        return true;
    };

    const BinIndexCacheEntry *ent = nullptr;
    if (!get_or_build_bin_index_cache_entry(loaded, tn.tp->table, drive_domain_id, &ent))
        return false;
    if (!ent || ent->off.empty())
        return false;

    auto scan_token_slice = [&](int32_t tok_i32) -> bool {
        if (tok_i32 < 0)
            return true;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, tn.tp->table, drive_domain_id, tok_i32, &rid_ptr, &rid_len))
            return false;
        profile->pf2_tree_rows_scanned_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
if (!process_row(rid_ptr ? rid_ptr[i] : 0u))
                return false;
        }
        return true;
    };

    bool drive_restricted = false;
    for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
        if (tn.edge_ids[pos] == drive_eid) {
            if (inbound_bits[pos] && is_safe_drive(drive_eid))
                drive_restricted = true;
            break;
        }
    }
    if (drive_restricted) {
        for (size_t pos = 0; pos < tn.edge_ids.size(); pos++) {
            if (tn.edge_ids[pos] == drive_eid) {
                inbound_bits[pos]->for_each_set([&](int32_t tok_i32) {
                    CHECK_FOR_INTERRUPTS();
if (!scan_token_slice(tok_i32))
                        ereport(ERROR, (errmsg("policy: PF-V2.4 table scan token slice failed")));
                });
                break;
            }
        }
    } else {
        size_t nt = ent->off.size() - 1u;
        for (size_t t = 0; t < nt; t++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)t);
if (ent->off[t + 1u] == ent->off[t])
                continue;
            if (!scan_token_slice((int32_t)t))
                return false;
        }
    }

    for (int oe : out_edge_ids) {
        (*msg_t_to_d)[(size_t)oe].adapt_representation();
        (*msg_t_to_d_ready)[(size_t)oe] = 1;
    }
    profile->pf2_tree_update_ms += Ms(Clock::now() - t_up0).count();
    return true;
}

struct Pf2CmpSummaryKey1 {
    int key_domain_id = -1;
    int cmp_domain_id = -1;
    const std::vector<int32_t> *rank_data = nullptr;
    bool need_rank = false;
    bool need_eqset = false;
    bool need_neq = false;
    std::vector<uint8_t> present;
    std::vector<int32_t> min_rank;
    std::vector<int32_t> max_rank;
    std::vector<TokenBitset> eq_sets;  // allocated only when need_eqset
    std::vector<uint8_t> neq_cnt;       // 0/1/2 distinct witness y tokens per key
    std::vector<int32_t> neq_one;       // valid only when neq_cnt==1
};

struct Pf2CmpSummaryKey2Dense {
    bool enabled = false;
    size_t n0 = 0;
    size_t n1 = 0;
    std::vector<uint8_t> present;
    std::vector<int32_t> min_rank;
    std::vector<int32_t> max_rank;
    std::vector<uint8_t> neq_cnt;   // 0/1/2
    std::vector<int32_t> neq_one;   // valid only when neq_cnt==1
    // Equality summaries stay sparse in PF-V2.6 initial implementation.
};

struct Pf2CmpSummaryKey2Entry {
    uint8_t present = 0;
    int32_t min_rank = std::numeric_limits<int32_t>::max();
    int32_t max_rank = std::numeric_limits<int32_t>::min();
    std::unique_ptr<TokenBitset> eqset;
    uint8_t neq_cnt = 0;
    int32_t neq_one = -1;
};

struct Pf2CmpSummaryKey2 {
    std::array<int, 2> key_domain_ids{{-1, -1}};
    int cmp_domain_id = -1;
    const std::vector<int32_t> *rank_data = nullptr;
    bool need_rank = false;
    bool need_eqset = false;
    bool need_neq = false;
    Pf2CmpSummaryKey2Dense dense;
    std::unordered_map<uint64_t, Pf2CmpSummaryKey2Entry> sparse;
    size_t cmp_ntokens = 0;
};

struct Pf2CmpSummaryAny {
    int key_arity = 0;
    Pf2CmpSummaryKey1 key1;
    Pf2CmpSummaryKey2 key2;
};

struct Pf2CycleRectPattern {
    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;
    const ClauseTablePlan *witness_tp = nullptr;
    const TableData *witness_ti = nullptr;
    int target_table_idx = -1;
    int witness_table_idx = -1;
    std::array<int, 2> key_domain_ids{{-1, -1}};  // canonical order for summary keys
    std::array<const ClauseClassGroup *, 2> target_key_groups{{nullptr, nullptr}};
    std::array<const ClauseClassGroup *, 2> witness_key_groups{{nullptr, nullptr}};
    int hub_domain_id = -1;       // one of key_domain_ids, used for target bin projection
    int hub_domain_key_idx = -1;  // index into key_domain_ids
    std::vector<Pf2LocalComparator> target_local_cmps;
    std::vector<Pf2LocalComparator> witness_local_cmps;
    Pf2TreeComparatorPlan cmp_plan; // optional; cmp_plan.cmp == nullptr means no cross-table comparator
};

static bool pf2_map_local_only_comparators_for_table(const ClausePlan &cl,
                                                     const ClauseTablePlan &tp,
                                                     std::vector<Pf2LocalComparator> *out_local_cmps)
{
    if (!out_local_cmps)
        return false;
    out_local_cmps->clear();
    std::unordered_map<int, int> group_idx_by_pos;
    group_idx_by_pos.reserve(tp.class_groups.size());
    for (size_t i = 0; i < tp.class_groups.size(); i++)
        group_idx_by_pos[tp.class_groups[i].class_pos] = (int)i;
    for (const ClauseComparator &cmp : cl.compares) {
        auto itl = group_idx_by_pos.find(cmp.left_pos);
        auto itr = group_idx_by_pos.find(cmp.right_pos);
        bool l_here = (itl != group_idx_by_pos.end());
        bool r_here = (itr != group_idx_by_pos.end());
        if (!(l_here && r_here))
            continue;
        out_local_cmps->push_back(Pf2LocalComparator{&cmp, itl->second, itr->second});
    }
    return true;
}

static bool pf2_cycle_rect_detect_pattern(const Loaded &loaded,
                                          const std::string &target,
                                          const ClausePlan &cl,
                                          const ClauseTablePlan &target_tp,
                                          const TableData &target_ti,
                                          Pf2CycleRectPattern *out_pat)
{
    if (!out_pat)
        return false;
    *out_pat = Pf2CycleRectPattern{};
    out_pat->target_tp = &target_tp;
    out_pat->target_ti = &target_ti;

    struct JoinEdgeRec {
        std::string u;
        std::string v;
        int d = -1;
    };
    std::vector<JoinEdgeRec> joins;
    joins.reserve(4);
    for (int aid : cl.atom_ids) {
        auto it = loaded.atoms_by_id.find(aid);
        if (it == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it->second;
        if (a.kind == AtomKind::JOIN) {
            if (a.join_class_id < 0 || a.left.table == a.right.table)
                return true;
            joins.push_back({a.left.table, a.right.table, a.join_class_id});
        } else if (a.kind == AtomKind::COLCOL) {
            // handled below via cl.compares
        } else if (a.kind != AtomKind::CONST) {
            return true;
        }
    }
    if (joins.size() != 2u)
        return true;

    // Collect exactly two tables and require both joins between target and same witness.
    std::unordered_set<std::string> tables_seen;
    for (const auto &j : joins) {
        tables_seen.insert(j.u);
        tables_seen.insert(j.v);
    }
    if (tables_seen.size() != 2u)
        return true;
    if (tables_seen.find(target) == tables_seen.end())
        return true;
    std::string witness;
    for (const auto &nm : tables_seen) {
        if (nm != target) {
            witness = nm;
            break;
        }
    }
    if (witness.empty())
        return true;

    std::array<int, 2> key_domains{{-1, -1}};
    for (size_t i = 0; i < joins.size(); i++) {
        const auto &j = joins[i];
        bool between_target_witness =
            ((j.u == target && j.v == witness) || (j.u == witness && j.v == target));
        if (!between_target_witness)
            return true;
        key_domains[i] = j.d;
        if (j.d < 0)
            return true;
    }
    if (key_domains[0] == key_domains[1])
        return true;
    if (key_domains[1] < key_domains[0])
        std::swap(key_domains[0], key_domains[1]);
    out_pat->key_domain_ids = key_domains;

    auto itw = loaded.tables.find(witness);
    if (itw == loaded.tables.end())
        return false;
    out_pat->witness_ti = &itw->second;
    for (const auto &tp_tbl : cl.tables) {
        if (tp_tbl.table == target)
            out_pat->target_tp = &tp_tbl;
        else if (tp_tbl.table == witness)
            out_pat->witness_tp = &tp_tbl;
        else
            return true; // third table unsupported in cycle-rect v2.7
    }
    if (!out_pat->target_tp || !out_pat->witness_tp)
        return true;

    if (!pf2_map_local_only_comparators_for_table(cl, *out_pat->target_tp, &out_pat->target_local_cmps) ||
        !pf2_map_local_only_comparators_for_table(cl, *out_pat->witness_tp, &out_pat->witness_local_cmps)) {
        return false;
    }

    for (int i = 0; i < 2; i++) {
        out_pat->target_key_groups[(size_t)i] = pf2_find_group_by_domain(*out_pat->target_tp, key_domains[i]);
        out_pat->witness_key_groups[(size_t)i] = pf2_find_group_by_domain(*out_pat->witness_tp, key_domains[i]);
        if (!out_pat->target_key_groups[(size_t)i] || !out_pat->witness_key_groups[(size_t)i])
            return true;
    }

    // Comparator support: require at most one cross-table comparator, with one endpoint on target and one on witness.
    std::unordered_map<int, int> tgt_group_idx_by_pos;
    std::unordered_map<int, int> wit_group_idx_by_pos;
    tgt_group_idx_by_pos.reserve(out_pat->target_tp->class_groups.size());
    wit_group_idx_by_pos.reserve(out_pat->witness_tp->class_groups.size());
    for (size_t i = 0; i < out_pat->target_tp->class_groups.size(); i++)
        tgt_group_idx_by_pos[out_pat->target_tp->class_groups[i].class_pos] = (int)i;
    for (size_t i = 0; i < out_pat->witness_tp->class_groups.size(); i++)
        wit_group_idx_by_pos[out_pat->witness_tp->class_groups[i].class_pos] = (int)i;

    int cross_cmp_count = 0;
    for (const ClauseComparator &cmp : cl.compares) {
        bool l_t = tgt_group_idx_by_pos.find(cmp.left_pos) != tgt_group_idx_by_pos.end();
        bool r_t = tgt_group_idx_by_pos.find(cmp.right_pos) != tgt_group_idx_by_pos.end();
        bool l_w = wit_group_idx_by_pos.find(cmp.left_pos) != wit_group_idx_by_pos.end();
        bool r_w = wit_group_idx_by_pos.find(cmp.right_pos) != wit_group_idx_by_pos.end();

        if ((l_t && r_t) || (l_w && r_w))
            continue; // local comparator already handled
        if (!((l_t && r_w) || (l_w && r_t)))
            return true; // cross comparator with other table/shape unsupported

        cross_cmp_count++;
        if (cross_cmp_count > 1)
            return true;
        const ClauseComparator *cmp_ptr = &cmp;
        bool left_is_target = l_t;
        const ClauseClassGroup *t_cmp_group = pf2_find_group_by_class_pos(*out_pat->target_tp,
                                                                          left_is_target ? cmp.left_pos : cmp.right_pos);
        const ClauseClassGroup *w_cmp_group = pf2_find_group_by_class_pos(*out_pat->witness_tp,
                                                                          left_is_target ? cmp.right_pos : cmp.left_pos);
        if (!t_cmp_group || !w_cmp_group)
            return true;

        Pf2TreeComparatorPlan cp;
        cp.cmp = cmp_ptr;
        cp.left_table_idx = left_is_target ? 0 : 1;
        cp.right_table_idx = left_is_target ? 1 : 0;
        cp.key_arity = 2;
        cp.key_domain_ids = {{key_domains[0], key_domains[1]}};
        cp.ordered = is_ordered_cmp(cmp.op);
        cp.left_ep.table_idx = cp.left_table_idx;
        cp.right_ep.table_idx = cp.right_table_idx;
        if (left_is_target) {
            cp.left_ep.cmp_group = t_cmp_group;
            cp.right_ep.cmp_group = w_cmp_group;
            cp.left_ep.key_groups = {out_pat->target_key_groups[0], out_pat->target_key_groups[1]};
            cp.right_ep.key_groups = {out_pat->witness_key_groups[0], out_pat->witness_key_groups[1]};
            out_pat->target_table_idx = 0;
            out_pat->witness_table_idx = 1;
        } else {
            cp.left_ep.cmp_group = w_cmp_group;
            cp.right_ep.cmp_group = t_cmp_group;
            cp.left_ep.key_groups = {out_pat->witness_key_groups[0], out_pat->witness_key_groups[1]};
            cp.right_ep.key_groups = {out_pat->target_key_groups[0], out_pat->target_key_groups[1]};
            out_pat->target_table_idx = 1;
            out_pat->witness_table_idx = 0;
        }
        out_pat->cmp_plan = std::move(cp);
    }

    if (cross_cmp_count == 0)
        return true; // v2.7 cycle path is for policy29-like comparator cycles

    // Choose projection hub on target by smaller token universe (deterministic tie-break by domain id).
    size_t ntok0 = 0, ntok1 = 0;
    if (auto it = loaded.domain_dicts.find(key_domains[0]); it != loaded.domain_dicts.end())
        ntok0 = it->second.size();
    if (auto it = loaded.domain_dicts.find(key_domains[1]); it != loaded.domain_dicts.end())
        ntok1 = it->second.size();
    int hub_idx = (ntok1 > 0 && (ntok0 == 0 || ntok1 < ntok0)) ? 1 : 0;
    out_pat->hub_domain_key_idx = hub_idx;
    out_pat->hub_domain_id = key_domains[hub_idx];
    if (out_pat->target_table_idx < 0)
        out_pat->target_table_idx = 0;
    if (out_pat->witness_table_idx < 0)
        out_pat->witness_table_idx = 1;
    return true;
}

static bool pf2_cycle_build_cmp_summary_key2_direct(const Loaded &loaded,
                                                    const Pf2CycleRectPattern &pat,
                                                    BuildProfile *profile,
                                                    Pf2CmpSummaryKey2 *out)
{
    if (!profile || !out || !pat.cmp_plan.cmp || !pat.witness_tp || !pat.witness_ti)
        return false;
    const Pf2TreeComparatorPlan &cp = pat.cmp_plan;
    const ClauseComparator *cmp = cp.cmp;
    bool target_is_left = (cp.left_table_idx == pat.target_table_idx);
    if (!target_is_left && cp.right_table_idx != pat.target_table_idx)
        return false;
    ConstOp op_target = target_is_left ? cmp->op : flip_cmp_orientation(cmp->op);
    const Pf2TreeComparatorEndpoint &w_ep = target_is_left ? cp.right_ep : cp.left_ep;
    if (!w_ep.cmp_group || w_ep.key_groups.size() != 2u || !w_ep.key_groups[0] || !w_ep.key_groups[1])
        return false;

    bool need_rank = is_ordered_cmp(op_target);
    bool need_eqset = (op_target == ConstOp::EQ);
    bool need_neq = (op_target == ConstOp::NE);
    size_t cmp_ntokens = 0;
    if (auto itd = loaded.domain_dicts.find(cmp->domain_id); itd != loaded.domain_dicts.end())
        cmp_ntokens = itd->second.size();

    Pf2CmpSummaryKey2 s;
    s.key_domain_ids = cp.key_domain_ids;
    s.cmp_domain_id = cmp->domain_id;
    s.rank_data = cmp->rank_data;
    s.need_rank = need_rank;
    s.need_eqset = need_eqset;
    s.need_neq = need_neq;
    s.cmp_ntokens = cmp_ntokens;

    size_t k0_ntokens = 0, k1_ntokens = 0;
    if (auto itd = loaded.domain_dicts.find(cp.key_domain_ids[0]); itd != loaded.domain_dicts.end())
        k0_ntokens = itd->second.size();
    if (auto itd = loaded.domain_dicts.find(cp.key_domain_ids[1]); itd != loaded.domain_dicts.end())
        k1_ntokens = itd->second.size();
    const uint64_t dense_threshold_cells = 2'000'000ull;
    uint64_t cell_prod = (uint64_t)k0_ntokens * (uint64_t)k1_ntokens;
    if (need_rank && !need_eqset && k0_ntokens > 0 && k1_ntokens > 0 && cell_prod <= dense_threshold_cells) {
        s.dense.enabled = true;
        s.dense.n0 = k0_ntokens;
        s.dense.n1 = k1_ntokens;
        size_t ncell = (size_t)cell_prod;
        s.dense.present.assign(ncell, 0);
        s.dense.min_rank.assign(ncell, std::numeric_limits<int32_t>::max());
        s.dense.max_rank.assign(ncell, std::numeric_limits<int32_t>::min());
        profile->pf2_cmp_key2_dense_bytes +=
            s.dense.present.size() * sizeof(uint8_t) +
            s.dense.min_rank.size() * sizeof(int32_t) +
            s.dense.max_rank.size() * sizeof(int32_t);
    }
    if (s.dense.enabled && need_neq) {
        size_t ncell = (size_t)cell_prod;
        s.dense.neq_cnt.assign(ncell, 0);
        s.dense.neq_one.assign(ncell, -1);
        profile->pf2_cmp_key2_dense_bytes +=
            s.dense.neq_cnt.size() * sizeof(uint8_t) +
            s.dense.neq_one.size() * sizeof(int32_t);
    }

    auto t0 = Clock::now();
    uint64 rows_scanned = 0;
    uint64 updates = 0;

    for (uint32 rid = 0; rid < pat.witness_ti->nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
rows_scanned++;
        if (!pf2_row_matches_table_local_atoms(*pat.witness_tp, pat.witness_local_cmps, rid))
            continue;
        int32_t k0 = -1, k1 = -1, ytok = -1;
        if (!pf2_get_group_token_on_row(*w_ep.key_groups[0], rid, &k0) ||
            !pf2_get_group_token_on_row(*w_ep.key_groups[1], rid, &k1) ||
            !pf2_get_group_token_on_row(*w_ep.cmp_group, rid, &ytok)) {
            return false;
        }
        if (k0 < 0 || k1 < 0 || ytok < 0)
            continue;
        updates++;
        if (s.dense.enabled) {
            if ((size_t)k0 >= s.dense.n0 || (size_t)k1 >= s.dense.n1)
                continue;
            size_t idx = (size_t)k0 * s.dense.n1 + (size_t)k1;
            s.dense.present[idx] = 1;
            if (s.need_rank) {
                int32_t yr = token_rank_of(ytok, s.rank_data);
                if (yr < s.dense.min_rank[idx]) s.dense.min_rank[idx] = yr;
                if (yr > s.dense.max_rank[idx]) s.dense.max_rank[idx] = yr;
            }
            if (s.need_neq && idx < s.dense.neq_cnt.size()) {
                uint8_t &cnt = s.dense.neq_cnt[idx];
                int32_t &one = s.dense.neq_one[idx];
                if (cnt == 0) {
                    cnt = 1;
                    one = ytok;
                } else if (cnt == 1 && one != ytok) {
                    cnt = 2;
                    one = -1;
                }
            }
        } else {
            uint64_t kk = pf2_pack_key2(k0, k1);
            auto &e = s.sparse[kk];
            e.present = 1;
            if (s.need_rank) {
                int32_t yr = token_rank_of(ytok, s.rank_data);
                if (yr < e.min_rank) e.min_rank = yr;
                if (yr > e.max_rank) e.max_rank = yr;
            }
            if (s.need_eqset) {
                if (!e.eqset)
                    e.eqset.reset(new TokenBitset(s.cmp_ntokens));
                if ((size_t)ytok < e.eqset->nbits)
                    e.eqset->set((size_t)ytok);
            }
            if (s.need_neq) {
                if (e.neq_cnt == 0) {
                    e.neq_cnt = 1;
                    e.neq_one = ytok;
                } else if (e.neq_cnt == 1 && e.neq_one != ytok) {
                    e.neq_cnt = 2;
                    e.neq_one = -1;
                }
            }
        }
    }
    if (s.need_eqset) {
        for (auto &kv : s.sparse) {
            if (kv.second.eqset)
                kv.second.eqset->adapt_representation();
        }
    }
    uint64 distinct_entries = s.dense.enabled ? 0ull : (uint64)s.sparse.size();
    if (s.dense.enabled) {
        for (uint8_t p : s.dense.present)
            if (p) distinct_entries++;
    }
    profile->pf2_cmp_summary_keys_total += distinct_entries;
    profile->pf2_cmp_key2_entries += distinct_entries;
    profile->pf2_cmp_key2_rows_scanned += rows_scanned;
    profile->pf2_cmp_key2_updates += updates;
    double ms = Ms(Clock::now() - t0).count();
    profile->pf2_cmp_key2_build_ms += ms;
    profile->pf2_cmp_summary_build_ms += ms;
    *out = std::move(s);
    return true;
}

static bool pf2_tree_build_cmp_summary_key1(const Loaded &loaded,
                                            const Pf2TreePattern &pat,
                                            const Pf2TreeComparatorPlan &cp,
                                            int target_table_idx,
                                            const std::vector<TokenBitset> &msg_d_to_t,
                                            const std::vector<uint8_t> &msg_d_to_t_ready,
                                            BuildProfile *profile,
                                            Pf2CmpSummaryKey1 *out)
{
    if (!profile || !out || !cp.cmp || cp.key_arity != 1)
        return false;
    bool target_is_left = (cp.left_table_idx == target_table_idx);
    if (!target_is_left && cp.right_table_idx != target_table_idx)
        return false;

    const Pf2TreeComparatorEndpoint &w_ep = target_is_left ? cp.right_ep : cp.left_ep;
    if (w_ep.table_idx < 0 || w_ep.table_idx >= (int)pat.tables.size() ||
        !w_ep.cmp_group || w_ep.key_groups.size() != 1u || !w_ep.key_groups[0]) {
        return false;
    }
    const auto &wn = pat.tables[(size_t)w_ep.table_idx];
    if (!wn.tp || !wn.ti)
        return false;

    int key_domain_id = cp.key_domain_ids[0];
    int key_domain_idx = -1;
    int key_edge_id = -1;
    for (int eid : wn.edge_ids) {
        if (eid < 0 || eid >= (int)pat.edges.size())
            return false;
        int di = pat.edges[(size_t)eid].domain_idx;
        if (di >= 0 && di < (int)pat.domains.size() && pat.domains[(size_t)di].domain_id == key_domain_id) {
            key_domain_idx = di;
            key_edge_id = eid;
            break;
        }
    }
    if (key_domain_idx < 0 || key_edge_id < 0)
        return false;
    ConstOp op_target = target_is_left ? cp.cmp->op : flip_cmp_orientation(cp.cmp->op);
    bool need_rank = is_ordered_cmp(op_target);
    bool need_eqset = (op_target == ConstOp::EQ);
    bool need_neq = (op_target == ConstOp::NE);

    auto t0 = Clock::now();
    Pf2CmpSummaryKey1 s;
    s.key_domain_id = key_domain_id;
    s.cmp_domain_id = cp.cmp->domain_id;
    s.rank_data = cp.cmp->rank_data;
    s.need_rank = need_rank;
    s.need_eqset = need_eqset;
    s.need_neq = need_neq;
    size_t key_ntokens = pat.domains[(size_t)key_domain_idx].ntokens;
    s.present.assign(key_ntokens, 0);
    if (need_rank) {
        s.min_rank.assign(key_ntokens, std::numeric_limits<int32_t>::max());
        s.max_rank.assign(key_ntokens, std::numeric_limits<int32_t>::min());
    }
    size_t cmp_ntokens = 0;
    auto itd = loaded.domain_dicts.find(cp.cmp->domain_id);
    if (itd != loaded.domain_dicts.end())
        cmp_ntokens = itd->second.size();
    if (cmp_ntokens == 0)
        cmp_ntokens = (size_t)std::max(0, loaded.class_domain.size() > (size_t)cp.cmp->domain_id ? loaded.class_domain[(size_t)cp.cmp->domain_id] : 0);
    if (need_eqset)
        s.eq_sets.assign(key_ntokens, TokenBitset(cmp_ntokens));
    if (need_neq) {
        s.neq_cnt.assign(key_ntokens, 0);
        s.neq_one.assign(key_ntokens, -1);
    }

    const BinIndexCacheEntry *ent = nullptr;
    if (!get_or_build_bin_index_cache_entry(loaded, wn.tp->table, key_domain_id, &ent))
        return false;
    if (!ent || ent->off.empty())
        return false;

    const TokenBitset &key_inbound = msg_d_to_t[(size_t)key_edge_id];
    std::vector<int32_t> edge_toks(wn.edge_ids.size(), -1);
    uint64 local_keys_counted = 0;

    auto scan_key_tok = [&](int32_t key_tok_i32) -> bool {
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, wn.tp->table, key_domain_id, key_tok_i32, &rid_ptr, &rid_len))
            return false;
        profile->pf2_tree_rows_scanned_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*wn.tp, wn.local_cmps, rid))
                continue;
            bool ok = true;
            for (size_t pos = 0; pos < wn.edge_ids.size(); pos++) {
                int eid = wn.edge_ids[pos];
                const auto &e = pat.edges[(size_t)eid];
                int32_t tok = -1;
                if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                    return false;
                edge_toks[pos] = tok;
                if (tok < 0) {
                    ok = false;
                    break;
                }
                if (msg_d_to_t_ready[(size_t)eid] &&
                    !msg_d_to_t[(size_t)eid].test((size_t)tok)) {
                    ok = false;
                    break;
                }
            }
            if (!ok)
                continue;

            int32_t key_tok = -1;
            if (!pf2_get_group_token_on_row(*w_ep.key_groups[0], rid, &key_tok))
                return false;
            if (key_tok < 0 || (size_t)key_tok >= key_ntokens)
                continue;
            int32_t ytok = -1;
            if (!pf2_get_group_token_on_row(*w_ep.cmp_group, rid, &ytok))
                return false;
            if (ytok < 0)
                continue;

            if (!s.present[(size_t)key_tok]) {
                s.present[(size_t)key_tok] = 1;
                local_keys_counted++;
            }
            if (s.need_rank) {
                int32_t yr = token_rank_of(ytok, s.rank_data);
                if (yr < s.min_rank[(size_t)key_tok]) s.min_rank[(size_t)key_tok] = yr;
                if (yr > s.max_rank[(size_t)key_tok]) s.max_rank[(size_t)key_tok] = yr;
            }
            if (s.need_eqset) {
                if ((size_t)ytok < s.eq_sets[(size_t)key_tok].nbits)
                    s.eq_sets[(size_t)key_tok].set((size_t)ytok);
            }
            if (s.need_neq) {
                uint8_t &cnt = s.neq_cnt[(size_t)key_tok];
                int32_t &one = s.neq_one[(size_t)key_tok];
                if (cnt == 0) {
                    cnt = 1;
                    one = ytok;
                } else if (cnt == 1 && one != ytok) {
                    cnt = 2;
                    one = -1;
                }
            }
        }
        return true;
    };

    if (msg_d_to_t_ready[(size_t)key_edge_id]) {
        key_inbound.for_each_set([&](int32_t tok_i32) {
            CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
                return;
            if (!scan_key_tok(tok_i32))
                ereport(ERROR, (errmsg("policy: PF-V2.5 comparator summary scan failed")));
        });
    } else {
        size_t nt = ent->off.size() - 1u;
        for (size_t t = 0; t < nt; t++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)t);
if (ent->off[t + 1u] == ent->off[t])
                continue;
            if (!scan_key_tok((int32_t)t))
                return false;
        }
    }

    if (need_eqset) {
        for (auto &bs : s.eq_sets)
            bs.adapt_representation();
    }
    profile->pf2_cmp_summary_keys_total += local_keys_counted;
    profile->pf2_cmp_summary_build_ms += Ms(Clock::now() - t0).count();
    *out = std::move(s);
    return true;
}

static bool pf2_tree_build_cmp_summary_key2(const Loaded &loaded,
                                            const Pf2TreePattern &pat,
                                            const Pf2TreeComparatorPlan &cp,
                                            int target_table_idx,
                                            const std::vector<TokenBitset> &msg_d_to_t,
                                            const std::vector<uint8_t> &msg_d_to_t_ready,
                                            BuildProfile *profile,
                                            Pf2CmpSummaryKey2 *out)
{
    if (!profile || !out || !cp.cmp || cp.key_arity != 2)
        return false;
    bool target_is_left = (cp.left_table_idx == target_table_idx);
    if (!target_is_left && cp.right_table_idx != target_table_idx)
        return false;

    ConstOp op_target = target_is_left ? cp.cmp->op : flip_cmp_orientation(cp.cmp->op);

    const Pf2TreeComparatorEndpoint &t_ep = target_is_left ? cp.left_ep : cp.right_ep;
    const Pf2TreeComparatorEndpoint &w_ep = target_is_left ? cp.right_ep : cp.left_ep;
    if (!t_ep.cmp_group || t_ep.key_groups.size() != 2u || !t_ep.key_groups[0] || !t_ep.key_groups[1] ||
        !w_ep.cmp_group) {
        return false;
    }
    if (w_ep.table_idx < 0 || w_ep.table_idx >= (int)pat.tables.size())
        return false;

    // Orient separator key order from target -> witness.
    int cp_key_idx0 = target_is_left ? 0 : 1;
    int cp_key_idx1 = target_is_left ? 1 : 0;
    int kdom0 = cp.key_domain_ids[(size_t)cp_key_idx0];
    int kdom1 = cp.key_domain_ids[(size_t)cp_key_idx1];
    if (kdom0 < 0 || kdom1 < 0)
        return false;

    // Witness endpoint must at least expose the path-near separator key (k1).
    if (w_ep.key_groups.size() != 2u || !w_ep.key_groups[(size_t)cp_key_idx1])
        return false;
    const ClauseClassGroup *w_key1_group = w_ep.key_groups[(size_t)cp_key_idx1];

    bool need_rank = is_ordered_cmp(op_target);
    bool need_eqset = (op_target == ConstOp::EQ);
    bool need_neq = (op_target == ConstOp::NE);

    size_t cmp_ntokens = 0;
    auto itd_cmp = loaded.domain_dicts.find(cp.cmp->domain_id);
    if (itd_cmp != loaded.domain_dicts.end())
        cmp_ntokens = itd_cmp->second.size();

    // Resolve witness key1 edge/domain.
    const auto &wn = pat.tables[(size_t)w_ep.table_idx];
    int w_key1_domain_idx = -1;
    int w_key1_edge_id = -1;
    for (int eid : wn.edge_ids) {
        if (eid < 0 || eid >= (int)pat.edges.size())
            return false;
        int di = pat.edges[(size_t)eid].domain_idx;
        if (di >= 0 && di < (int)pat.domains.size() &&
            pat.domains[(size_t)di].domain_id == kdom1) {
            w_key1_domain_idx = di;
            w_key1_edge_id = eid;
            break;
        }
    }
    if (w_key1_domain_idx < 0 || w_key1_edge_id < 0 || !msg_d_to_t_ready[(size_t)w_key1_edge_id])
        return false;

    size_t k1_ntokens = pat.domains[(size_t)w_key1_domain_idx].ntokens;
    std::vector<uint8_t> w_present(k1_ntokens, 0);
    std::vector<int32_t> w_min_rank;
    std::vector<int32_t> w_max_rank;
    std::vector<TokenBitset> w_eq_sets;
    std::vector<uint8_t> w_neq_cnt;
    std::vector<int32_t> w_neq_one;
    if (need_rank) {
        w_min_rank.assign(k1_ntokens, std::numeric_limits<int32_t>::max());
        w_max_rank.assign(k1_ntokens, std::numeric_limits<int32_t>::min());
    }
    if (need_eqset)
        w_eq_sets.assign(k1_ntokens, TokenBitset(cmp_ntokens));
    if (need_neq) {
        w_neq_cnt.assign(k1_ntokens, 0);
        w_neq_one.assign(k1_ntokens, -1);
    }

    auto t0 = Clock::now();
    uint64 rows_scanned_total = 0;
    uint64 local_summary_updates = 0;

    // Pass 1: witness endpoint summary keyed by k1.
    const TokenBitset &w_key1_inbound = msg_d_to_t[(size_t)w_key1_edge_id];
    auto scan_witness_key1 = [&](int32_t key_tok_i32) -> bool {
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, wn.tp->table, kdom1, key_tok_i32, &rid_ptr, &rid_len))
            return false;
        profile->pf2_tree_rows_scanned_total += rid_len;
        rows_scanned_total += (uint64)rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*wn.tp, wn.local_cmps, rid))
                continue;
            bool ok = true;
            for (int eid : wn.edge_ids) {
                if (!msg_d_to_t_ready[(size_t)eid]) { ok = false; break; }
                const auto &e = pat.edges[(size_t)eid];
                int32_t tok = -1;
                if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                    return false;
                if (tok < 0 || !msg_d_to_t[(size_t)eid].test((size_t)tok)) { ok = false; break; }
            }
            if (!ok)
                continue;
            int32_t k1 = -1;
            if (!pf2_get_group_token_on_row(*w_key1_group, rid, &k1))
                return false;
            int32_t ytok = -1;
            if (!pf2_get_group_token_on_row(*w_ep.cmp_group, rid, &ytok))
                return false;
            if (k1 < 0 || ytok < 0 || (size_t)k1 >= k1_ntokens)
                continue;
            w_present[(size_t)k1] = 1;
            if (need_rank) {
                int32_t yr = token_rank_of(ytok, cp.cmp->rank_data);
                if (yr < w_min_rank[(size_t)k1]) w_min_rank[(size_t)k1] = yr;
                if (yr > w_max_rank[(size_t)k1]) w_max_rank[(size_t)k1] = yr;
            }
            if (need_eqset && (size_t)ytok < w_eq_sets[(size_t)k1].nbits)
                w_eq_sets[(size_t)k1].set((size_t)ytok);
            if (need_neq) {
                uint8_t &cnt = w_neq_cnt[(size_t)k1];
                int32_t &one = w_neq_one[(size_t)k1];
                if (cnt == 0) {
                    cnt = 1;
                    one = ytok;
                } else if (cnt == 1 && one != ytok) {
                    cnt = 2;
                    one = -1;
                }
            }
        }
        return true;
    };
    w_key1_inbound.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (!scan_witness_key1(tok_i32))
            ereport(ERROR, (errmsg("policy: PF-V2.6 key2 witness summary scan failed")));
    });
    if (need_eqset) {
        for (auto &bs : w_eq_sets)
            bs.adapt_representation();
    }

    // Find the unique bridge table on the target->witness path carrying both separator domains.
    int bridge_tidx = -1;
    const ClauseClassGroup *bridge_k0_group = nullptr;
    const ClauseClassGroup *bridge_k1_group = nullptr;
    for (size_t ti = 0; ti < pat.tables.size(); ti++) {
        if ((int)ti == target_table_idx || (int)ti == w_ep.table_idx)
            continue;
        const auto &tn = pat.tables[ti];
        const ClauseClassGroup *g0 = pf2_find_group_by_domain(*tn.tp, kdom0);
        const ClauseClassGroup *g1 = pf2_find_group_by_domain(*tn.tp, kdom1);
        if (!g0 || !g1)
            continue;
        if (bridge_tidx >= 0)
            return false; // ambiguous
        bridge_tidx = (int)ti;
        bridge_k0_group = g0;
        bridge_k1_group = g1;
    }
    if (bridge_tidx < 0 || !bridge_k0_group || !bridge_k1_group)
        return false;
    const auto &bn = pat.tables[(size_t)bridge_tidx];

    // Build (k0,k1) summary by scanning bridge rows once and composing witness k1 summary.
    Pf2CmpSummaryKey2 s;
    s.key_domain_ids = {{kdom0, kdom1}};
    s.cmp_domain_id = cp.cmp->domain_id;
    s.rank_data = cp.cmp->rank_data;
    s.need_rank = need_rank;
    s.need_eqset = need_eqset;
    s.need_neq = need_neq;
    s.cmp_ntokens = cmp_ntokens;

    int k0_domain_idx = -1;
    int k0_edge_id = -1;
    int k1_domain_idx = -1;
    int k1_edge_id = -1;
    for (int eid : bn.edge_ids) {
        if (eid < 0 || eid >= (int)pat.edges.size())
            return false;
        int di = pat.edges[(size_t)eid].domain_idx;
        int did = pat.domains[(size_t)di].domain_id;
        if (did == kdom0) { k0_domain_idx = di; k0_edge_id = eid; }
        if (did == kdom1) { k1_domain_idx = di; k1_edge_id = eid; }
    }
    if (k0_domain_idx < 0 || k1_domain_idx < 0 || k0_edge_id < 0 || k1_edge_id < 0)
        return false;
    if (!msg_d_to_t_ready[(size_t)k0_edge_id] || !msg_d_to_t_ready[(size_t)k1_edge_id])
        return false;

    size_t k0_ntokens = pat.domains[(size_t)k0_domain_idx].ntokens;
    k1_ntokens = pat.domains[(size_t)k1_domain_idx].ntokens;
    const uint64_t dense_threshold_cells = 2'000'000ull;
    uint64_t cell_prod = (uint64_t)k0_ntokens * (uint64_t)k1_ntokens;
    if (need_rank && !need_eqset && k0_ntokens > 0 && k1_ntokens > 0 && cell_prod <= dense_threshold_cells) {
        s.dense.enabled = true;
        s.dense.n0 = k0_ntokens;
        s.dense.n1 = k1_ntokens;
        size_t ncell = (size_t)cell_prod;
        s.dense.present.assign(ncell, 0);
        s.dense.min_rank.assign(ncell, std::numeric_limits<int32_t>::max());
        s.dense.max_rank.assign(ncell, std::numeric_limits<int32_t>::min());
        profile->pf2_cmp_key2_dense_bytes +=
            s.dense.present.size() * sizeof(uint8_t) +
            s.dense.min_rank.size() * sizeof(int32_t) +
            s.dense.max_rank.size() * sizeof(int32_t);
    }
    if (s.dense.enabled && need_neq) {
        size_t ncell = (size_t)cell_prod;
        s.dense.neq_cnt.assign(ncell, 0);
        s.dense.neq_one.assign(ncell, -1);
        profile->pf2_cmp_key2_dense_bytes +=
            s.dense.neq_cnt.size() * sizeof(uint8_t) +
            s.dense.neq_one.size() * sizeof(int32_t);
    }

    int drive_eid = k0_edge_id;
    size_t cnt0 = msg_d_to_t[(size_t)k0_edge_id].count();
    size_t cnt1 = msg_d_to_t[(size_t)k1_edge_id].count();
    if (cnt1 < cnt0)
        drive_eid = k1_edge_id;
    int drive_domain_id = pat.domains[(size_t)pat.edges[(size_t)drive_eid].domain_idx].domain_id;
    const TokenBitset &drive_in = msg_d_to_t[(size_t)drive_eid];

    auto update_pair_summary = [&](int32_t k0, int32_t k1) {
        if (k0 < 0 || k1 < 0 || (size_t)k1 >= w_present.size() || !w_present[(size_t)k1])
            return;
        local_summary_updates++;
        if (s.dense.enabled) {
            size_t idx = (size_t)k0 * s.dense.n1 + (size_t)k1;
            if (idx >= s.dense.present.size())
                return;
            s.dense.present[idx] = 1;
            int32_t minr = w_min_rank[(size_t)k1];
            int32_t maxr = w_max_rank[(size_t)k1];
            if (minr < s.dense.min_rank[idx]) s.dense.min_rank[idx] = minr;
            if (maxr > s.dense.max_rank[idx]) s.dense.max_rank[idx] = maxr;
            if (s.need_neq && idx < s.dense.neq_cnt.size() && (size_t)k1 < w_neq_cnt.size()) {
                uint8_t wc = w_neq_cnt[(size_t)k1];
                int32_t wo = w_neq_one[(size_t)k1];
                uint8_t &cnt = s.dense.neq_cnt[idx];
                int32_t &one = s.dense.neq_one[idx];
                if (cnt == 0) {
                    cnt = wc;
                    one = (wc == 1) ? wo : -1;
                } else if (cnt == 1) {
                    if (wc >= 2 || (wc == 1 && one != wo)) {
                        cnt = 2;
                        one = -1;
                    }
                }
            }
            return;
        }
        uint64_t kk = pf2_pack_key2(k0, k1);
        auto &e = s.sparse[kk];
        e.present = 1;
        if (s.need_rank) {
            int32_t minr = w_min_rank[(size_t)k1];
            int32_t maxr = w_max_rank[(size_t)k1];
            if (minr < e.min_rank) e.min_rank = minr;
            if (maxr > e.max_rank) e.max_rank = maxr;
        }
        if (s.need_eqset) {
            if (!e.eqset)
                e.eqset.reset(new TokenBitset(s.cmp_ntokens));
            e.eqset->bit_or(w_eq_sets[(size_t)k1]);
        }
        if (s.need_neq) {
            uint8_t wc = w_neq_cnt[(size_t)k1];
            int32_t wo = w_neq_one[(size_t)k1];
            if (wc > 0) {
                if (e.neq_cnt == 0) {
                    e.neq_cnt = wc;
                    e.neq_one = (wc == 1) ? wo : -1;
                } else if (e.neq_cnt == 1) {
                    if (wc >= 2 || (wc == 1 && e.neq_one != wo)) {
                        e.neq_cnt = 2;
                        e.neq_one = -1;
                    }
                }
            }
        }
    };

    auto scan_bridge_tok = [&](int32_t drive_tok_i32) -> bool {
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, bn.tp->table, drive_domain_id, drive_tok_i32, &rid_ptr, &rid_len))
            return false;
        profile->pf2_tree_rows_scanned_total += rid_len;
        rows_scanned_total += (uint64)rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*bn.tp, bn.local_cmps, rid))
                continue;
            bool ok = true;
            for (int eid : bn.edge_ids) {
                if (!msg_d_to_t_ready[(size_t)eid]) { ok = false; break; }
                const auto &e = pat.edges[(size_t)eid];
                int32_t tok = -1;
                if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                    return false;
                if (tok < 0 || !msg_d_to_t[(size_t)eid].test((size_t)tok)) { ok = false; break; }
            }
            if (!ok)
                continue;
            int32_t k0 = -1, k1 = -1;
            if (!pf2_get_group_token_on_row(*bridge_k0_group, rid, &k0) ||
                !pf2_get_group_token_on_row(*bridge_k1_group, rid, &k1))
                return false;
            update_pair_summary(k0, k1);
        }
        return true;
    };

    drive_in.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (!scan_bridge_tok(tok_i32))
            ereport(ERROR, (errmsg("policy: PF-V2.6 key2 bridge summary scan failed")));
    });

    uint64 distinct_entries = s.dense.enabled ? 0ull : (uint64)s.sparse.size();
    if (s.dense.enabled) {
        for (uint8_t p : s.dense.present)
            if (p) distinct_entries++;
    }
    profile->pf2_cmp_key2_entries += distinct_entries;
    profile->pf2_cmp_summary_keys_total += distinct_entries;
    profile->pf2_cmp_key2_rows_scanned += rows_scanned_total;
    profile->pf2_cmp_key2_updates += local_summary_updates;
    double ms = Ms(Clock::now() - t0).count();
    profile->pf2_cmp_key2_build_ms += ms;
    profile->pf2_cmp_summary_build_ms += ms;
    *out = std::move(s);
    return true;
}

static bool pf2_tree_build_cmp_summary_chain_key1(const Loaded &loaded,
                                                  const Pf2TreePattern &pat,
                                                  const Pf2TreeComparatorPlan &cp,
                                                  int target_table_idx,
                                                  const std::vector<TokenBitset> &msg_d_to_t,
                                                  const std::vector<uint8_t> &msg_d_to_t_ready,
                                                  BuildProfile *profile,
                                                  Pf2CmpSummaryKey1 *out)
{
    if (!profile || !out || !cp.cmp || !cp.witness_witness || !cp.witness_witness_chain)
        return false;
    if (cp.path_domain_ids_lr.size() < 2u || cp.path_bridge_tables_lr.empty())
        return false;
    bool target_is_left = (cp.left_table_idx == target_table_idx);
    if (!target_is_left && cp.right_table_idx != target_table_idx)
        return false;

    const Pf2TreeComparatorEndpoint &t_ep = target_is_left ? cp.left_ep : cp.right_ep;
    const Pf2TreeComparatorEndpoint &w_ep = target_is_left ? cp.right_ep : cp.left_ep;
    if (!t_ep.cmp_group || !w_ep.cmp_group)
        return false;

    int key_target_domain = target_is_left ? cp.path_domain_ids_lr.front() : cp.path_domain_ids_lr.back();
    int key_witness_domain = target_is_left ? cp.path_domain_ids_lr.back() : cp.path_domain_ids_lr.front();
    const auto &ttn = pat.tables[(size_t)target_table_idx];
    const auto &wtn = pat.tables[(size_t)w_ep.table_idx];
    if (!ttn.tp || !ttn.ti || !wtn.tp || !wtn.ti)
        return false;

    auto find_domain_idx_by_id = [&](int domain_id) -> int {
        for (size_t di = 0; di < pat.domains.size(); di++) {
            if (pat.domains[di].domain_id == domain_id)
                return (int)di;
        }
        return -1;
    };
    int t_key_domain_idx = find_domain_idx_by_id(key_target_domain);
    int w_key_domain_idx = find_domain_idx_by_id(key_witness_domain);
    if (t_key_domain_idx < 0 || w_key_domain_idx < 0)
        return false;

    auto find_edge_in_table = [&](int table_idx, int domain_id) -> int {
        if (table_idx < 0 || table_idx >= (int)pat.tables.size())
            return -1;
        const auto &tn = pat.tables[(size_t)table_idx];
        for (int eid : tn.edge_ids) {
            if (eid < 0 || eid >= (int)pat.edges.size())
                return -1;
            int di = pat.edges[(size_t)eid].domain_idx;
            if (di >= 0 && di < (int)pat.domains.size() &&
                pat.domains[(size_t)di].domain_id == domain_id)
                return eid;
        }
        return -1;
    };

    std::vector<int> path_domains_t_to_w;
    std::vector<int> path_bridges_t_to_w;
    path_domains_t_to_w.reserve(cp.path_domain_ids_lr.size());
    path_bridges_t_to_w.reserve(cp.path_bridge_tables_lr.size());
    if (target_is_left) {
        path_domains_t_to_w = cp.path_domain_ids_lr;
        path_bridges_t_to_w = cp.path_bridge_tables_lr;
    } else {
        path_domains_t_to_w.assign(cp.path_domain_ids_lr.rbegin(), cp.path_domain_ids_lr.rend());
        path_bridges_t_to_w.assign(cp.path_bridge_tables_lr.rbegin(), cp.path_bridge_tables_lr.rend());
    }
    if (path_domains_t_to_w.size() != path_bridges_t_to_w.size() + 1u)
        return false;
    key_target_domain = path_domains_t_to_w.front();
    key_witness_domain = path_domains_t_to_w.back();

    const ClauseClassGroup *w_key_group = pf2_find_group_by_domain(*wtn.tp, key_witness_domain);
    if (!w_key_group)
        return false;

    t_key_domain_idx = find_domain_idx_by_id(key_target_domain);
    w_key_domain_idx = find_domain_idx_by_id(key_witness_domain);
    if (t_key_domain_idx < 0 || w_key_domain_idx < 0)
        return false;

    int w_key_edge_id = find_edge_in_table(w_ep.table_idx, key_witness_domain);
    if (w_key_edge_id < 0)
        return false;

    ConstOp op_target = target_is_left ? cp.cmp->op : flip_cmp_orientation(cp.cmp->op);
    bool need_rank = is_ordered_cmp(op_target);
    bool need_eqset = (op_target == ConstOp::EQ);
    bool need_neq = (op_target == ConstOp::NE);

    size_t cmp_ntokens = 0;
    if (auto itd = loaded.domain_dicts.find(cp.cmp->domain_id); itd != loaded.domain_dicts.end())
        cmp_ntokens = itd->second.size();

    // Base summary keyed by witness-adjacent domain.
    Pf2CmpSummaryKey1 base;
    base.key_domain_id = key_witness_domain;
    base.cmp_domain_id = cp.cmp->domain_id;
    base.rank_data = cp.cmp->rank_data;
    base.need_rank = need_rank;
    base.need_eqset = need_eqset;
    base.need_neq = need_neq;
    size_t base_ntokens = pat.domains[(size_t)w_key_domain_idx].ntokens;
    base.present.assign(base_ntokens, 0);
    if (need_rank) {
        base.min_rank.assign(base_ntokens, std::numeric_limits<int32_t>::max());
        base.max_rank.assign(base_ntokens, std::numeric_limits<int32_t>::min());
    }
    if (need_eqset)
        base.eq_sets.assign(base_ntokens, TokenBitset(cmp_ntokens));
    if (need_neq) {
        base.neq_cnt.assign(base_ntokens, 0);
        base.neq_one.assign(base_ntokens, -1);
    }

    auto update_y = [&](Pf2CmpSummaryKey1 &s, int32_t k, int32_t ytok) {
        if (k < 0 || ytok < 0 || (size_t)k >= s.present.size())
            return;
        s.present[(size_t)k] = 1;
        if (s.need_rank) {
            int32_t yr = token_rank_of(ytok, s.rank_data);
            if (yr < s.min_rank[(size_t)k]) s.min_rank[(size_t)k] = yr;
            if (yr > s.max_rank[(size_t)k]) s.max_rank[(size_t)k] = yr;
        }
        if (s.need_eqset && (size_t)k < s.eq_sets.size() && (size_t)ytok < s.eq_sets[(size_t)k].nbits)
            s.eq_sets[(size_t)k].set((size_t)ytok);
        if (s.need_neq && (size_t)k < s.neq_cnt.size()) {
            uint8_t &cnt = s.neq_cnt[(size_t)k];
            int32_t &one = s.neq_one[(size_t)k];
            if (cnt == 0) {
                cnt = 1;
                one = ytok;
            } else if (cnt == 1 && one != ytok) {
                cnt = 2;
                one = -1;
            }
        }
    };

    auto merge_key = [&](Pf2CmpSummaryKey1 &dst, int32_t dst_k, const Pf2CmpSummaryKey1 &src, int32_t src_k) {
        if (dst_k < 0 || src_k < 0 || (size_t)dst_k >= dst.present.size() || (size_t)src_k >= src.present.size())
            return;
        if (!src.present[(size_t)src_k])
            return;
        dst.present[(size_t)dst_k] = 1;
        if (dst.need_rank) {
            if (src.min_rank[(size_t)src_k] < dst.min_rank[(size_t)dst_k])
                dst.min_rank[(size_t)dst_k] = src.min_rank[(size_t)src_k];
            if (src.max_rank[(size_t)src_k] > dst.max_rank[(size_t)dst_k])
                dst.max_rank[(size_t)dst_k] = src.max_rank[(size_t)src_k];
        }
        if (dst.need_eqset && (size_t)src_k < src.eq_sets.size() && (size_t)dst_k < dst.eq_sets.size())
            dst.eq_sets[(size_t)dst_k].bit_or(src.eq_sets[(size_t)src_k]);
        if (dst.need_neq) {
            uint8_t src_cnt = src.neq_cnt[(size_t)src_k];
            if (src_cnt == 0)
                return;
            uint8_t &dst_cnt = dst.neq_cnt[(size_t)dst_k];
            int32_t &dst_one = dst.neq_one[(size_t)dst_k];
            int32_t src_one = src.neq_one[(size_t)src_k];
            if (dst_cnt == 0) {
                dst_cnt = src_cnt;
                dst_one = (src_cnt == 1) ? src_one : -1;
            } else if (dst_cnt == 1) {
                if (src_cnt >= 2 || (src_cnt == 1 && dst_one != src_one)) {
                    dst_cnt = 2;
                    dst_one = -1;
                }
            }
        }
    };

    uint64 bridge_rows_scanned = 0;
    auto t_chain0 = Clock::now();

    const BinIndexCacheEntry *w_ent = nullptr;
    if (!get_or_build_bin_index_cache_entry(loaded, wtn.tp->table, key_witness_domain, &w_ent))
        return false;
    if (!w_ent || w_ent->off.empty())
        return false;
    auto scan_witness_tok = [&](int32_t key_tok_i32) -> bool {
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, wtn.tp->table, key_witness_domain, key_tok_i32, &rid_ptr, &rid_len))
            return false;
        profile->pf2_tree_rows_scanned_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*wtn.tp, wtn.local_cmps, rid))
                continue;
            bool ok = true;
            for (int eid : wtn.edge_ids) {
                const auto &e = pat.edges[(size_t)eid];
                int32_t tok = -1;
                if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                    return false;
                if (tok < 0) {
                    ok = false;
                    break;
                }
                if (msg_d_to_t_ready[(size_t)eid] && !msg_d_to_t[(size_t)eid].test((size_t)tok)) {
                    ok = false;
                    break;
                }
            }
            if (!ok)
                continue;
            int32_t kw = -1, ytok = -1;
            if (!pf2_get_group_token_on_row(*w_key_group, rid, &kw) ||
                !pf2_get_group_token_on_row(*w_ep.cmp_group, rid, &ytok))
                return false;
            if (kw < 0 || ytok < 0)
                continue;
            update_y(base, kw, ytok);
        }
        return true;
    };
    if (msg_d_to_t_ready[(size_t)w_key_edge_id]) {
        msg_d_to_t[(size_t)w_key_edge_id].for_each_set([&](int32_t tok_i32) {
            CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
                return;
            if (!scan_witness_tok(tok_i32))
                ereport(ERROR, (errmsg("policy: class_engine chain witness summary scan failed")));
        });
    } else {
        size_t nt = w_ent->off.size() - 1u;
        for (size_t t = 0; t < nt; t++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)t);
if (w_ent->off[t + 1u] == w_ent->off[t])
                continue;
            if (!scan_witness_tok((int32_t)t))
                return false;
        }
    }
    if (need_eqset) {
        for (auto &bs : base.eq_sets)
            bs.adapt_representation();
    }

    Pf2CmpSummaryKey1 cur = std::move(base);
    for (int step = (int)path_bridges_t_to_w.size() - 1; step >= 0; step--) {
        int bridge_tidx = path_bridges_t_to_w[(size_t)step];
        if (bridge_tidx < 0 || bridge_tidx >= (int)pat.tables.size())
            return false;
        const auto &btn = pat.tables[(size_t)bridge_tidx];
        if (!btn.tp || !btn.ti)
            return false;
        int left_domain = path_domains_t_to_w[(size_t)step];
        int right_domain = path_domains_t_to_w[(size_t)step + 1u];
        if (cur.key_domain_id != right_domain)
            return false;

        int left_domain_idx = find_domain_idx_by_id(left_domain);
        if (left_domain_idx < 0)
            return false;
        const ClauseClassGroup *b_key_left = pf2_find_group_by_domain(*btn.tp, left_domain);
        const ClauseClassGroup *b_key_right = pf2_find_group_by_domain(*btn.tp, right_domain);
        if (!b_key_left || !b_key_right)
            return false;
        int b_edge_left = find_edge_in_table(bridge_tidx, left_domain);
        int b_edge_right = find_edge_in_table(bridge_tidx, right_domain);
        if (b_edge_left < 0 || b_edge_right < 0)
            return false;

        Pf2CmpSummaryKey1 next;
        next.key_domain_id = left_domain;
        next.cmp_domain_id = cp.cmp->domain_id;
        next.rank_data = cp.cmp->rank_data;
        next.need_rank = need_rank;
        next.need_eqset = need_eqset;
        next.need_neq = need_neq;
        size_t next_ntokens = pat.domains[(size_t)left_domain_idx].ntokens;
        next.present.assign(next_ntokens, 0);
        if (need_rank) {
            next.min_rank.assign(next_ntokens, std::numeric_limits<int32_t>::max());
            next.max_rank.assign(next_ntokens, std::numeric_limits<int32_t>::min());
        }
        if (need_eqset)
            next.eq_sets.assign(next_ntokens, TokenBitset(cmp_ntokens));
        if (need_neq) {
            next.neq_cnt.assign(next_ntokens, 0);
            next.neq_one.assign(next_ntokens, -1);
        }

        int drive_eid = b_edge_left;
        if (msg_d_to_t_ready[(size_t)b_edge_right] &&
            (!msg_d_to_t_ready[(size_t)b_edge_left] ||
             msg_d_to_t[(size_t)b_edge_right].count() < msg_d_to_t[(size_t)b_edge_left].count())) {
            drive_eid = b_edge_right;
        }
        int drive_domain_id = pat.domains[(size_t)pat.edges[(size_t)drive_eid].domain_idx].domain_id;
        const BinIndexCacheEntry *b_ent = nullptr;
        if (!get_or_build_bin_index_cache_entry(loaded, btn.tp->table, drive_domain_id, &b_ent))
            return false;
        if (!b_ent || b_ent->off.empty())
            return false;

        auto scan_bridge_tok = [&](int32_t drive_tok_i32) -> bool {
            const uint32_t *rid_ptr = nullptr;
            size_t rid_len = 0;
            if (!get_bin_slice(loaded, btn.tp->table, drive_domain_id, drive_tok_i32, &rid_ptr, &rid_len))
                return false;
            profile->pf2_tree_rows_scanned_total += rid_len;
            bridge_rows_scanned += (uint64)rid_len;
            for (size_t i = 0; i < rid_len; i++) {
                PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
                if (!pf2_row_matches_table_local_atoms(*btn.tp, btn.local_cmps, rid))
                    continue;
                bool ok = true;
                for (int eid : btn.edge_ids) {
                    const auto &e = pat.edges[(size_t)eid];
                    int32_t tok = -1;
                    if (!pf2_get_group_token_on_row(*e.group, rid, &tok))
                        return false;
                    if (tok < 0) {
                        ok = false;
                        break;
                    }
                    if (msg_d_to_t_ready[(size_t)eid] && !msg_d_to_t[(size_t)eid].test((size_t)tok)) {
                        ok = false;
                        break;
                    }
                }
                if (!ok)
                    continue;
                int32_t k_left = -1, k_right = -1;
                if (!pf2_get_group_token_on_row(*b_key_left, rid, &k_left) ||
                    !pf2_get_group_token_on_row(*b_key_right, rid, &k_right))
                    return false;
                if (k_left < 0 || k_right < 0)
                    continue;
                merge_key(next, k_left, cur, k_right);
            }
            return true;
        };

        if (msg_d_to_t_ready[(size_t)drive_eid]) {
            msg_d_to_t[(size_t)drive_eid].for_each_set([&](int32_t tok_i32) {
                CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
                    return;
                if (!scan_bridge_tok(tok_i32))
                    ereport(ERROR, (errmsg("policy: class_engine chain bridge summary scan failed")));
            });
        } else {
            size_t nt = b_ent->off.size() - 1u;
            for (size_t t = 0; t < nt; t++) {
                PF_CHECK_FOR_INTERRUPTS((uint32)t);
if (b_ent->off[t + 1u] == b_ent->off[t])
                    continue;
                if (!scan_bridge_tok((int32_t)t))
                    return false;
            }
        }

        if (need_eqset) {
            for (auto &bs : next.eq_sets)
                bs.adapt_representation();
        }
        cur = std::move(next);
        profile->pf2_cmp_chain_compose_steps += 1;
    }

    uint64 keys_counted = 0;
    for (uint8_t p : cur.present) {
        if (p)
            keys_counted++;
    }
    double build_ms = Ms(Clock::now() - t_chain0).count();
    profile->pf2_cmp_summary_keys_total += keys_counted;
    profile->pf2_cmp_summary_build_ms += build_ms;
    profile->pf2_cmp_chain_build_ms += build_ms;
    profile->pf2_cmp_chain_bridge_rows_scanned += bridge_rows_scanned;
    *out = std::move(cur);
    return true;
}

static bool pf2_cmp_summary_accept_target_row(const Pf2TreeComparatorPlan &cp,
                                              int target_table_idx,
                                              const Pf2CmpSummaryAny &s_any,
                                              uint32 rid,
                                              BuildProfile *profile)
{
    if (!cp.cmp || !profile)
        return false;
    bool target_is_left = (cp.left_table_idx == target_table_idx);
    if (!target_is_left && cp.right_table_idx != target_table_idx)
        return false;
    const Pf2TreeComparatorEndpoint &t_ep = target_is_left ? cp.left_ep : cp.right_ep;
    if (!t_ep.cmp_group || t_ep.key_groups.empty())
        return false;
    int32_t xtok = -1;
    if (!pf2_get_group_token_on_row(*t_ep.cmp_group, rid, &xtok))
        return false;
    profile->pf2_cmp_checks_total++;
    ConstOp op = target_is_left ? cp.cmp->op : flip_cmp_orientation(cp.cmp->op);
    if (s_any.key_arity == 1) {
        const Pf2CmpSummaryKey1 &s = s_any.key1;
        const ClauseClassGroup *key_group = nullptr;
        if (cp.key_arity == 1) {
            if (t_ep.key_groups.size() != 1u || !t_ep.key_groups[0])
                return false;
            key_group = t_ep.key_groups[0];
        } else {
            for (int i = 0; i < cp.key_arity && i < (int)t_ep.key_groups.size(); i++) {
                if (cp.key_domain_ids[(size_t)i] == s.key_domain_id && t_ep.key_groups[(size_t)i]) {
                    key_group = t_ep.key_groups[(size_t)i];
                    break;
                }
            }
            if (!key_group)
                return false;
        }
        int32_t key_tok = -1;
        if (!pf2_get_group_token_on_row(*key_group, rid, &key_tok))
            return false;
        if (key_tok < 0 || xtok < 0 || (size_t)key_tok >= s.present.size() || !s.present[(size_t)key_tok]) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        if (op == ConstOp::EQ) {
            if ((size_t)key_tok >= s.eq_sets.size() || (size_t)xtok >= s.eq_sets[(size_t)key_tok].nbits ||
                !s.eq_sets[(size_t)key_tok].test((size_t)xtok)) {
                profile->pf2_cmp_rejects_total++;
                return false;
            }
            return true;
        }
        if (op == ConstOp::NE) {
            if ((size_t)key_tok >= s.neq_cnt.size()) {
                profile->pf2_cmp_rejects_total++;
                return false;
            }
            uint8_t cnt = s.neq_cnt[(size_t)key_tok];
            if (cnt >= 2)
                return true;
            if (cnt == 1) {
                if ((size_t)key_tok < s.neq_one.size() && s.neq_one[(size_t)key_tok] != xtok)
                    return true;
            }
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        if (!is_ordered_cmp(op) || !s.need_rank) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        int32_t xr = token_rank_of(xtok, s.rank_data);
        int32_t minr = s.min_rank[(size_t)key_tok];
        int32_t maxr = s.max_rank[(size_t)key_tok];
        bool ok = false;
        switch (op) {
            case ConstOp::LE: ok = (xr <= maxr); break;
            case ConstOp::LT: ok = (xr < maxr); break;
            case ConstOp::GE: ok = (xr >= minr); break;
            case ConstOp::GT: ok = (xr > minr); break;
            default: break;
        }
        if (!ok)
            profile->pf2_cmp_rejects_total++;
        return ok;
    }

    if (s_any.key_arity != 2)
        return false;
    if (t_ep.key_groups.size() != 2u || !t_ep.key_groups[0] || !t_ep.key_groups[1])
        return false;
    int cp_key_idx0 = target_is_left ? 0 : 1;
    int cp_key_idx1 = target_is_left ? 1 : 0;
    int32_t k0 = -1, k1 = -1;
    if (!pf2_get_group_token_on_row(*t_ep.key_groups[(size_t)cp_key_idx0], rid, &k0) ||
        !pf2_get_group_token_on_row(*t_ep.key_groups[(size_t)cp_key_idx1], rid, &k1))
        return false;
    const Pf2CmpSummaryKey2 &s2 = s_any.key2;
    profile->pf2_cmp_key2_lookups++;
    if (k0 < 0 || k1 < 0 || xtok < 0) {
        profile->pf2_cmp_rejects_total++;
        return false;
    }

    if (op == ConstOp::NE) {
        if (s2.dense.enabled) {
            if ((size_t)k0 >= s2.dense.n0 || (size_t)k1 >= s2.dense.n1) {
                profile->pf2_cmp_rejects_total++;
                return false;
            }
            size_t idx = (size_t)k0 * s2.dense.n1 + (size_t)k1;
            if (idx >= s2.dense.present.size() || !s2.dense.present[idx] ||
                idx >= s2.dense.neq_cnt.size() || idx >= s2.dense.neq_one.size()) {
                profile->pf2_cmp_rejects_total++;
                return false;
            }
            uint8_t cnt = s2.dense.neq_cnt[idx];
            if (cnt >= 2)
                return true;
            if (cnt == 1 && s2.dense.neq_one[idx] != xtok)
                return true;
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        auto itn = s2.sparse.find(pf2_pack_key2(k0, k1));
        if (itn == s2.sparse.end() || !itn->second.present) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        const auto &en = itn->second;
        if (en.neq_cnt >= 2)
            return true;
        if (en.neq_cnt == 1 && en.neq_one != xtok)
            return true;
        profile->pf2_cmp_rejects_total++;
        return false;
    }
    if (s2.dense.enabled) {
        if ((size_t)k0 >= s2.dense.n0 || (size_t)k1 >= s2.dense.n1) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        size_t idx = (size_t)k0 * s2.dense.n1 + (size_t)k1;
        if (idx >= s2.dense.present.size() || !s2.dense.present[idx]) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        if (op == ConstOp::EQ) {
            auto it = s2.sparse.find(pf2_pack_key2(k0, k1));
            if (it == s2.sparse.end() || !it->second.eqset ||
                (size_t)xtok >= it->second.eqset->nbits || !it->second.eqset->test((size_t)xtok)) {
                profile->pf2_cmp_rejects_total++;
                return false;
            }
            return true;
        }
        if (!is_ordered_cmp(op) || !s2.need_rank) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        int32_t xr = token_rank_of(xtok, s2.rank_data);
        int32_t minr = s2.dense.min_rank[idx];
        int32_t maxr = s2.dense.max_rank[idx];
        bool ok = false;
        switch (op) {
            case ConstOp::LE: ok = (xr <= maxr); break;
            case ConstOp::LT: ok = (xr < maxr); break;
            case ConstOp::GE: ok = (xr >= minr); break;
            case ConstOp::GT: ok = (xr > minr); break;
            default: break;
        }
        if (!ok) profile->pf2_cmp_rejects_total++;
        return ok;
    }

    auto it = s2.sparse.find(pf2_pack_key2(k0, k1));
    if (it == s2.sparse.end() || !it->second.present) {
        profile->pf2_cmp_rejects_total++;
        return false;
    }
    const auto &e = it->second;
    if (op == ConstOp::EQ) {
        if (!e.eqset || (size_t)xtok >= e.eqset->nbits || !e.eqset->test((size_t)xtok)) {
            profile->pf2_cmp_rejects_total++;
            return false;
        }
        return true;
    }
    if (!is_ordered_cmp(op) || !s2.need_rank) {
        profile->pf2_cmp_rejects_total++;
        return false;
    }
    int32_t xr = token_rank_of(xtok, s2.rank_data);
    bool ok = false;
    switch (op) {
        case ConstOp::LE: ok = (xr <= e.max_rank); break;
        case ConstOp::LT: ok = (xr < e.max_rank); break;
        case ConstOp::GE: ok = (xr >= e.min_rank); break;
        case ConstOp::GT: ok = (xr > e.min_rank); break;
        default: break;
    }
    if (!ok) profile->pf2_cmp_rejects_total++;
    return ok;
}

struct Pf2TreeWitnessCmpEval {
    size_t cmp_idx = 0;
    bool is_chain = false;
    Pf2CmpSummaryAny summary;
};

struct Pf2TreeWitnessCmpContext {
    int table_idx = -1;
    std::vector<Pf2TreeWitnessCmpEval> evals;
};

static bool pf2_cmp_summary_has_support(const Pf2CmpSummaryAny &s_any)
{
    if (s_any.key_arity == 1) {
        for (uint8_t p : s_any.key1.present) {
            if (p)
                return true;
        }
        return false;
    }
    if (s_any.key_arity == 2) {
        if (s_any.key2.dense.enabled) {
            for (uint8_t p : s_any.key2.dense.present) {
                if (p)
                    return true;
            }
            return false;
        }
        for (const auto &kv : s_any.key2.sparse) {
            if (kv.second.present)
                return true;
        }
        return false;
    }
    return false;
}

static bool pf2_tree_prepare_witness_cmp_context(const Loaded &loaded,
                                                 const Pf2TreePattern &pat,
                                                 int table_idx,
                                                 const std::vector<TokenBitset> &msg_d_to_t,
                                                 const std::vector<uint8_t> &msg_d_to_t_ready,
                                                 BuildProfile *profile,
                                                 Pf2TreeWitnessCmpContext *out_ctx)
{
    if (!out_ctx || !profile)
        return false;
    *out_ctx = Pf2TreeWitnessCmpContext{};
    out_ctx->table_idx = table_idx;
    if (table_idx < 0 || table_idx >= (int)pat.tables.size())
        return false;

    for (size_t ci = 0; ci < pat.cmps.size(); ci++) {
        const auto &cp = pat.cmps[ci];
        if (!cp.cmp || !cp.witness_witness)
            continue;
        if (cp.left_table_idx != table_idx && cp.right_table_idx != table_idx)
            continue;

        Pf2TreeWitnessCmpEval ev;
        ev.cmp_idx = ci;
        if (cp.witness_witness_chain) {
            Pf2CmpSummaryKey1 s_chain;
            if (!pf2_tree_build_cmp_summary_chain_key1(loaded, pat, cp, table_idx,
                                                       msg_d_to_t, msg_d_to_t_ready, profile, &s_chain)) {
                return false;
            }
            ev.is_chain = true;
            ev.summary.key_arity = 1;
            ev.summary.key1 = std::move(s_chain);
        } else if (cp.key_arity == 1) {
            Pf2CmpSummaryKey1 s1;
            if (!pf2_tree_build_cmp_summary_key1(loaded, pat, cp, table_idx,
                                                 msg_d_to_t, msg_d_to_t_ready, profile, &s1)) {
                return false;
            }
            ev.summary.key_arity = 1;
            ev.summary.key1 = std::move(s1);
        } else if (cp.key_arity == 2) {
            Pf2CmpSummaryKey2 s2;
            if (!pf2_tree_build_cmp_summary_key2(loaded, pat, cp, table_idx,
                                                 msg_d_to_t, msg_d_to_t_ready, profile, &s2)) {
                return false;
            }
            ev.summary.key_arity = 2;
            ev.summary.key2 = std::move(s2);
        } else {
            return false;
        }
        if (!pf2_cmp_summary_has_support(ev.summary))
            continue;
        out_ctx->evals.push_back(std::move(ev));
    }
    return true;
}

static bool pf2_tree_witness_cmp_filter_row(const Pf2TreePattern &pat,
                                            int table_idx,
                                            uint32 rid,
                                            BuildProfile *profile,
                                            const Pf2TreeWitnessCmpContext *ctx,
                                            bool *out_accept)
{
    if (!profile || !out_accept)
        return false;
    *out_accept = true;
    if (!ctx)
        return true;
    if (ctx->table_idx != table_idx)
        return false;
    if (ctx->evals.empty())
        return true;

    for (const auto &ev : ctx->evals) {
        if (ev.cmp_idx >= pat.cmps.size())
            return false;
        profile->pf2_cmp_filter_rows_checked++;
        if (ev.is_chain)
            profile->pf2_cmp_chain_filter_rows_checked++;
        if (!pf2_cmp_summary_accept_target_row(pat.cmps[ev.cmp_idx], table_idx, ev.summary, rid, profile)) {
            profile->pf2_cmp_filter_rows_reject++;
            if (ev.is_chain)
                profile->pf2_cmp_chain_filter_rows_reject++;
            *out_accept = false;
            return true;
        }
    }
    return true;
}

static bool eval_term_conjunction_pf2_cycle_rect(const Loaded &loaded,
                                                 const std::string &target,
                                                 const ClausePlan &cl,
                                                 const ClauseTablePlan &target_tp,
                                                 const TableData &target_ti,
                                                 const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                                 BuildProfile *profile,
                                                 SparseBlockWords *out_words,
                                                 std::vector<uint8_t> *out_rid_bits,
                                                 bool *out_term_has_rows,
                                                 bool *out_supported)
{
    if (out_supported)
        *out_supported = false;
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (!profile || !out_words)
        return false;

    (void)restrict_sigs;

    auto t_pf0 = Clock::now();
    Pf2CycleRectPattern pat;
    if (!pf2_cycle_rect_detect_pattern(loaded, target, cl, target_tp, target_ti, &pat))
        return false;
    if (!pat.target_tp || !pat.target_ti || !pat.witness_tp || !pat.witness_ti || !pat.cmp_plan.cmp)
        return true;

    profile->pf2_terms_supported++;
    profile->pf2_hub_domain_id = pat.hub_domain_id;
    profile->pf2_hub_key_arity = 1;
    if (auto itd = loaded.domain_dicts.find(pat.hub_domain_id); itd != loaded.domain_dicts.end())
        profile->pf2_ntokens = std::max<uint64>(profile->pf2_ntokens, (uint64)itd->second.size());
    profile->pf2_cmp_total += 1;
    profile->pf2_cmp_key_arity_max = std::max<uint64>(profile->pf2_cmp_key_arity_max, 2);

    Pf2CmpSummaryKey2 key2_summary;
    if (!pf2_cycle_build_cmp_summary_key2_direct(loaded, pat, profile, &key2_summary))
        return false;
    profile->pf2_cmp_supported += 1;

    size_t hub_ntokens = 0;
    if (auto itd = loaded.domain_dicts.find(pat.hub_domain_id); itd != loaded.domain_dicts.end())
        hub_ntokens = itd->second.size();
    if (hub_ntokens == 0) {
        const BinIndexCacheEntry *hub_ent = nullptr;
        if (!get_or_build_bin_index_cache_entry(loaded, target, pat.hub_domain_id, &hub_ent))
            return false;
        if (hub_ent && !hub_ent->off.empty())
            hub_ntokens = hub_ent->off.size() - 1u;
    }
    profile->pf2_ntokens = std::max<uint64>(profile->pf2_ntokens, (uint64)hub_ntokens);
    TokenBitset hub_allowed(hub_ntokens);
    hub_allowed.clear_all();

    int hk = pat.hub_domain_key_idx;
    if (key2_summary.dense.enabled) {
        for (size_t i0 = 0; i0 < key2_summary.dense.n0; i0++) {
            for (size_t i1 = 0; i1 < key2_summary.dense.n1; i1++) {
                size_t idx = i0 * key2_summary.dense.n1 + i1;
                if (idx >= key2_summary.dense.present.size() || !key2_summary.dense.present[idx])
                    continue;
                size_t ht = (hk == 0) ? i0 : i1;
                if (ht < hub_allowed.nbits)
                    hub_allowed.set(ht);
            }
        }
    } else {
        for (const auto &kv : key2_summary.sparse) {
            if (!kv.second.present)
                continue;
            int32_t k0 = (int32_t)(kv.first >> 32);
            int32_t k1 = (int32_t)(kv.first & 0xffffffffu);
            int32_t ht = (hk == 0) ? k0 : k1;
            if (ht >= 0 && (size_t)ht < hub_allowed.nbits)
                hub_allowed.set((size_t)ht);
        }
    }
    hub_allowed.adapt_representation();

    if (!hub_allowed.any()) {
        profile->pf2_total_ms += Ms(Clock::now() - t_pf0).count();
        if (out_supported)
            *out_supported = true;
        return true;
    }

    Pf2CmpSummaryAny cmp_any;
    cmp_any.key_arity = 2;
    cmp_any.key2 = std::move(key2_summary);

    auto t_proj0 = Clock::now();
    uint32 projected_rows = 0;
    hub_allowed.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
            return;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, target, pat.hub_domain_id, tok_i32, &rid_ptr, &rid_len))
            ereport(ERROR,
                    (errmsg("policy: PF-V2.7 cycle bin slice lookup failed table=%s domain=%d tok=%d",
                            target.c_str(), pat.hub_domain_id, tok_i32)));
        profile->pf2_project_bin_rids_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*pat.target_tp, pat.target_local_cmps, rid))
                continue;
            if (!pf2_cmp_summary_accept_target_row(pat.cmp_plan, pat.target_table_idx, cmp_any, rid, profile))
                continue;
            if ((size_t)rid >= pat.target_ti->ctid_blk.size() || (size_t)rid >= pat.target_ti->ctid_off.size())
                continue;
            if (!out_words->set_ctid(pat.target_ti->ctid_blk[(size_t)rid], pat.target_ti->ctid_off[(size_t)rid]))
                ereport(ERROR,
                        (errmsg("policy: PF-V2.7 failed to stamp CTID table=%s rid=%u",
                                target.c_str(), rid)));
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
            projected_rows++;
        }
    });
    profile->pf2_project_ms += Ms(Clock::now() - t_proj0).count();
    profile->pf2_total_ms += Ms(Clock::now() - t_pf0).count();

    if (out_supported)
        *out_supported = true;
    if (out_term_has_rows)
        *out_term_has_rows = (projected_rows > 0);
    return true;
}

static bool eval_term_conjunction_pf2_tree(const Loaded &loaded,
                                           const std::string &target,
                                           const ClausePlan &cl,
                                           const ClauseTablePlan &target_tp,
                                           const TableData &target_ti,
                                           const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                           BuildProfile *profile,
                                           SparseBlockWords *out_words,
                                           std::vector<uint8_t> *out_rid_bits,
                                           bool *out_term_has_rows,
                                           bool *out_supported)
{
    if (out_supported)
        *out_supported = false;
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (!profile || !out_words)
        return false;

    auto t_pf20 = Clock::now();
    (void)restrict_sigs;

    Pf2TreePattern pat;
    if (!pf2_tree_detect_pattern(loaded, target, cl, target_tp, target_ti, &pat))
        return false;
    if (pat.target_table_idx < 0 || pat.target_hub_domain_idx < 0 || pat.edges.empty())
        return true;

    profile->pf2_terms_supported++;
    profile->pf2_hub_domain_id = pat.domains[(size_t)pat.target_hub_domain_idx].domain_id;
    profile->pf2_hub_key_arity = 1;
    profile->pf2_ntokens = std::max<uint64>(profile->pf2_ntokens,
                                            (uint64)pat.domains[(size_t)pat.target_hub_domain_idx].ntokens);
    profile->pf2_terms_tree++;
    profile->pf2_tree_domains += (uint64)pat.domains.size();
    profile->pf2_tree_tables += (uint64)pat.tables.size();
    profile->pf2_tree_edges += (uint64)pat.edges.size();
    profile->pf2_tree_passes += 2;
    profile->pf2_cmp_total += (uint64)pat.cmps.size();
    uint64 ww_cmp_total = 0;
    uint64 ww_chain_total = 0;
    for (const auto &cp : pat.cmps) {
        profile->pf2_cmp_key_arity_max = std::max<uint64>(profile->pf2_cmp_key_arity_max, (uint64)cp.key_arity);
        if (cp.witness_witness) {
            ww_cmp_total++;
            if (cp.witness_witness_chain)
                ww_chain_total++;
        }
    }
    profile->pf2_cmp_witness_witness_total += ww_cmp_total;
    profile->pf2_cmp_witness_witness_supported += ww_cmp_total;
    profile->pf2_cmp_chain_total += ww_chain_total;
    profile->pf2_cmp_chain_supported += ww_chain_total;

    std::vector<TokenBitset> msg_t_to_d;
    std::vector<TokenBitset> msg_d_to_t;
    std::vector<uint8_t> msg_t_to_d_ready((size_t)pat.edges.size(), 0);
    std::vector<uint8_t> msg_d_to_t_ready((size_t)pat.edges.size(), 0);
    msg_t_to_d.reserve(pat.edges.size());
    msg_d_to_t.reserve(pat.edges.size());
    for (const auto &e : pat.edges) {
        size_t ntok = pat.domains[(size_t)e.domain_idx].ntokens;
        msg_t_to_d.emplace_back(ntok);
        msg_d_to_t.emplace_back(ntok);
    }

    int nd = (int)pat.domains.size();
    int nt = (int)pat.tables.size();
    int ngraph = nd + nt;
    std::vector<std::vector<int>> adj_edges((size_t)ngraph);
    for (int eid = 0; eid < (int)pat.edges.size(); eid++) {
        const auto &e = pat.edges[(size_t)eid];
        adj_edges[(size_t)e.domain_idx].push_back(eid);
        adj_edges[(size_t)(nd + e.table_idx)].push_back(eid);
    }

    auto node_from_domain = [&](int di) { return di; };
    auto node_from_table = [&](int ti) { return nd + ti; };

    // Process each connected component independently; only target component contributes tokens.
    TokenBitset target_root_allowed(pat.domains[(size_t)pat.target_hub_domain_idx].ntokens);
    target_root_allowed.clear_all();
    bool have_target_component = false;

    for (int comp = 0; comp < pat.component_count; comp++) {
        int root_domain_idx = -1;
        if (pat.comp_of_domain[(size_t)pat.target_hub_domain_idx] == comp) {
            root_domain_idx = pat.target_hub_domain_idx;
            have_target_component = true;
        } else {
            for (int di = 0; di < nd; di++) {
                if (pat.comp_of_domain[(size_t)di] == comp) {
                    root_domain_idx = di;
                    break;
                }
            }
        }
        if (root_domain_idx < 0)
            continue;

        int root_node = node_from_domain(root_domain_idx);
        std::vector<int> parent_edge((size_t)ngraph, -1);
        std::vector<int> parent_node((size_t)ngraph, -1);
        std::vector<int> depth((size_t)ngraph, -1);
        std::vector<int> order;
        order.reserve((size_t)ngraph);
        std::deque<int> q;
        q.push_back(root_node);
        depth[(size_t)root_node] = 0;
        while (!q.empty()) {
            int u = q.front();
            q.pop_front();
            order.push_back(u);
            for (int eid : adj_edges[(size_t)u]) {
                const auto &e = pat.edges[(size_t)eid];
                int v = (u < nd) ? node_from_table(e.table_idx) : node_from_domain(e.domain_idx);
                if (u < nd && pat.comp_of_table[(size_t)e.table_idx] != comp)
                    continue;
                if (u >= nd && pat.comp_of_domain[(size_t)e.domain_idx] != comp)
                    continue;
                if (depth[(size_t)v] >= 0)
                    continue;
                depth[(size_t)v] = depth[(size_t)u] + 1;
                parent_edge[(size_t)v] = eid;
                parent_node[(size_t)v] = u;
                q.push_back(v);
            }
        }

        // Upward pass (leaves -> root).
        for (auto it = order.rbegin(); it != order.rend(); ++it) {
            int u = *it;
            if (u == root_node)
                continue;
            int pe = parent_edge[(size_t)u];
            if (pe < 0)
                return false;
            if (u < nd) {
                // domain -> parent table
                TokenBitset tmp;
                if (!pf2_tree_compute_domain_to_table_message(pat, u, pe, msg_t_to_d, msg_t_to_d_ready, &tmp))
                    return false;
                msg_d_to_t[(size_t)pe] = std::move(tmp);
                msg_d_to_t_ready[(size_t)pe] = 1;
            } else {
                // table -> parent domain
                int ti = u - nd;
                const auto &tn = pat.tables[(size_t)ti];
                int drive = -1;
                size_t best = std::numeric_limits<size_t>::max();
                for (int eid : tn.edge_ids) {
                    if (eid == pe)
                        continue;
                    if (!msg_d_to_t_ready[(size_t)eid])
                        continue;
                    size_t c = msg_d_to_t[(size_t)eid].count();
                    if (c < best) { best = c; drive = eid; }
                }
                std::vector<int> outs{pe};
                Pf2TreeWitnessCmpContext ww_ctx;
                if (!pf2_tree_prepare_witness_cmp_context(loaded, pat, ti, msg_d_to_t, msg_d_to_t_ready,
                                                          profile, &ww_ctx))
                    return false;
                if (!pf2_tree_emit_table_messages(loaded, pat, ti, msg_d_to_t, msg_d_to_t_ready,
                                                  outs, drive, profile, &ww_ctx, &msg_t_to_d, &msg_t_to_d_ready))
                    return false;
            }
        }

        // Downward pass (root -> leaves).
        for (int u : order) {
            if (u < nd) {
                // domain -> child tables
                for (int eid : adj_edges[(size_t)u]) {
                    const auto &e = pat.edges[(size_t)eid];
                    if (pat.comp_of_table[(size_t)e.table_idx] != comp)
                        continue;
                    int child = node_from_table(e.table_idx);
                    if (parent_node[(size_t)child] != u)
                        continue;
                    TokenBitset tmp;
                    if (!pf2_tree_compute_domain_to_table_message(pat, u, eid, msg_t_to_d, msg_t_to_d_ready, &tmp))
                        return false;
                    msg_d_to_t[(size_t)eid] = std::move(tmp);
                    msg_d_to_t_ready[(size_t)eid] = 1;
                }
            } else {
                int ti = u - nd;
                const auto &tn = pat.tables[(size_t)ti];
                std::vector<int> child_outs;
                child_outs.reserve(tn.edge_ids.size());
                int pe = parent_edge[(size_t)u];
                for (int eid : tn.edge_ids) {
                    const auto &e = pat.edges[(size_t)eid];
                    int dn_node = node_from_domain(e.domain_idx);
                    if (parent_node[(size_t)dn_node] == u)
                        child_outs.push_back(eid);
                }
                if (!child_outs.empty()) {
                    Pf2TreeWitnessCmpContext ww_ctx;
                    if (!pf2_tree_prepare_witness_cmp_context(loaded, pat, ti, msg_d_to_t, msg_d_to_t_ready,
                                                              profile, &ww_ctx))
                        return false;
                    if (!pf2_tree_emit_table_messages(loaded, pat, ti, msg_d_to_t, msg_d_to_t_ready,
                                                      child_outs, pe, profile, &ww_ctx,
                                                      &msg_t_to_d, &msg_t_to_d_ready))
                        return false;
                }
            }
        }

        // Final root-domain allowed tokens for this component.
        TokenBitset root_allowed(pat.domains[(size_t)root_domain_idx].ntokens);
        root_allowed.fill_all();
        bool saw_neighbor = false;
        for (int eid : pat.domains[(size_t)root_domain_idx].edge_ids) {
            const auto &e = pat.edges[(size_t)eid];
            if (pat.comp_of_table[(size_t)e.table_idx] != comp)
                continue;
            if (!msg_t_to_d_ready[(size_t)eid])
                return false;
            root_allowed.bit_and(msg_t_to_d[(size_t)eid]);
            saw_neighbor = true;
            if (!root_allowed.any())
                break;
        }
        if (!saw_neighbor || !root_allowed.any()) {
            if (comp == pat.comp_of_domain[(size_t)pat.target_hub_domain_idx]) {
                target_root_allowed.clear_all();
            }
            profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
            if (out_supported)
                *out_supported = true;
            if (out_term_has_rows)
                *out_term_has_rows = false;
            return true;
        }
        if (comp == pat.comp_of_domain[(size_t)pat.target_hub_domain_idx]) {
            target_root_allowed = std::move(root_allowed);
        }
    }

    if (!have_target_component || !target_root_allowed.any()) {
        profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();
        if (out_supported)
            *out_supported = true;
        return true;
    }

    // PF-V2.5 comparator summaries (initial exact subset):
    // cross-table comparators keyed by separator domain tuple, checked during target projection.
    std::vector<Pf2CmpSummaryAny> cmp_summaries((size_t)pat.cmps.size());
    std::vector<uint8_t> cmp_summary_ready((size_t)pat.cmps.size(), 0);
    for (size_t ci = 0; ci < pat.cmps.size(); ci++) {
        const auto &cp = pat.cmps[ci];
        if (!cp.cmp)
            return false;
        if (cp.witness_witness)
            continue; // enforced during tree message propagation
        if (cp.left_table_idx != pat.target_table_idx && cp.right_table_idx != pat.target_table_idx)
            return true;
        if (cp.key_arity == 1) {
            Pf2CmpSummaryKey1 s1;
            if (!pf2_tree_build_cmp_summary_key1(loaded, pat, cp, pat.target_table_idx,
                                                 msg_d_to_t, msg_d_to_t_ready, profile, &s1)) {
                return false;
            }
            cmp_summaries[ci].key_arity = 1;
            cmp_summaries[ci].key1 = std::move(s1);
            cmp_summary_ready[ci] = 1;
            profile->pf2_cmp_supported++;
            continue;
        }
        if (cp.key_arity == 2) {
            Pf2CmpSummaryKey2 s2;
            if (!pf2_tree_build_cmp_summary_key2(loaded, pat, cp, pat.target_table_idx,
                                                 msg_d_to_t, msg_d_to_t_ready, profile, &s2)) {
                return false;
            }
            cmp_summaries[ci].key_arity = 2;
            cmp_summaries[ci].key2 = std::move(s2);
            cmp_summary_ready[ci] = 1;
            profile->pf2_cmp_supported++;
            continue;
        }
        return true;
    }

    // Project target root-domain tokens to target rows via bins, applying target-local row checks exactly.
    auto t_proj0 = Clock::now();
    uint32 projected_rows = 0;
    int target_hub_domain_id = pat.domains[(size_t)pat.target_hub_domain_idx].domain_id;
    const auto &tnode = pat.tables[(size_t)pat.target_table_idx];
    target_root_allowed.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
            return;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, target, target_hub_domain_id, tok_i32, &rid_ptr, &rid_len))
            ereport(ERROR,
                    (errmsg("policy: PF-V2.4 bin slice lookup failed table=%s domain=%d tok=%d",
                            target.c_str(), target_hub_domain_id, tok_i32)));
        profile->pf2_project_bin_rids_total += rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*tnode.tp, tnode.local_cmps, rid))
                continue;
            bool cmp_ok = true;
            for (size_t ci = 0; ci < pat.cmps.size(); ci++) {
                if (pat.cmps[ci].witness_witness)
                    continue;
                if (!cmp_summary_ready[ci]) {
                    cmp_ok = false;
                    break;
                }
                if (!pf2_cmp_summary_accept_target_row(pat.cmps[ci], pat.target_table_idx,
                                                       cmp_summaries[ci], rid, profile)) {
                    cmp_ok = false;
                    break;
                }
            }
            if (!cmp_ok)
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                ereport(ERROR,
                        (errmsg("policy: PF-V2.4 failed to stamp CTID table=%s rid=%u", target.c_str(), rid)));
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
            projected_rows++;
        }
    });
    double proj_ms = Ms(Clock::now() - t_proj0).count();
    profile->pf2_project_ms += proj_ms;
    profile->pf2_tree_project_ms += proj_ms;
    profile->pf2_total_ms += Ms(Clock::now() - t_pf20).count();

    if (out_supported)
        *out_supported = true;
    if (out_term_has_rows)
        *out_term_has_rows = (projected_rows > 0);
    return true;
}

static inline int class_td_width_limit()
{
    int w = 2;
    const char *g = GetConfigOption("custom_filter.class_td_width_limit", true, false);
    if (g && g[0]) {
        char *endp = nullptr;
        long v = std::strtol(g, &endp, 10);
        if (endp && *endp == '\0' && v > 0 && v < 64)
            w = (int)v;
    }
    return w;
}

static inline bool class_td_reduction_enabled()
{
    const char *g = GetConfigOption("custom_filter.class_td_reduction", true, false);
    if (!g || !g[0])
        return true; // class-engine default
    std::string v = lower_str(trim_ws(g));
    return !(v.empty() || v == "0" || v == "off" || v == "false" || v == "no");
}

struct ClassTdTableFactor {
    const ClauseTablePlan *tp = nullptr;
    const TableData *ti = nullptr;
    std::vector<int> vars;  // class_pos vars
    std::vector<const ClauseClassGroup *> groups; // aligned with vars
    std::vector<Pf2LocalComparator> local_cmps;
    int drive_group_idx = -1;
    size_t drive_ntokens = 0;
};

struct ClassTdTuple {
    uint32_t tok[3] = {0u, 0u, 0u};
};

struct ClassTdRelation {
    std::vector<int> vars;  // sorted class_pos vars (arity <= 3 for W<=2)
    std::vector<ClassTdTuple> tuples;
    bool has_empty = false; // used when vars.empty()

    inline size_t arity() const { return vars.size(); }
    inline size_t size() const { return vars.empty() ? (has_empty ? 1u : 0u) : tuples.size(); }
    inline bool empty() const { return size() == 0u; }
};

struct ClassTdCyclePattern {
    bool matched = false;
    bool width_exceeded = false;
    int td_width = 0;
    std::vector<std::vector<int>> bags; // vars per elimination bag
    std::vector<int> elim_order;        // class_pos elimination order (target vars last)
    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;
    std::vector<int> target_vars;       // class_pos vars appearing on target table
    std::vector<ClassTdTableFactor> factors;
    std::vector<ClauseComparator> cross_table_cmps;
};

static int class_td_find_group_pos_for_col(const ClauseTablePlan &tp,
                                           const TableData &ti,
                                           const std::string &col_key)
{
    auto it_idx = ti.col_idx.find(col_key);
    if (it_idx == ti.col_idx.end())
        return -1;
    int col_idx = it_idx->second;
    for (const auto &cg : tp.class_groups) {
        for (int cidx : cg.col_idxs) {
            if (cidx == col_idx)
                return cg.class_pos;
        }
    }
    return -1;
}

static bool class_td_relation_contains_var(const ClassTdRelation &r, int var)
{
    return std::find(r.vars.begin(), r.vars.end(), var) != r.vars.end();
}

static inline int class_td_var_pos(const std::vector<int> &vars, int v)
{
    for (size_t i = 0; i < vars.size(); i++) {
        if (vars[i] == v)
            return (int)i;
    }
    return -1;
}

static inline bool class_td_tuple_less(const ClassTdTuple &a, const ClassTdTuple &b, size_t arity)
{
    for (size_t i = 0; i < arity; i++) {
        if (a.tok[i] < b.tok[i])
            return true;
        if (a.tok[i] > b.tok[i])
            return false;
    }
    return false;
}

static inline bool class_td_tuple_eq(const ClassTdTuple &a, const ClassTdTuple &b, size_t arity)
{
    for (size_t i = 0; i < arity; i++) {
        if (a.tok[i] != b.tok[i])
            return false;
    }
    return true;
}

static inline size_t class_td_relation_bytes(const ClassTdRelation &r)
{
    return sizeof(ClassTdRelation) +
           r.vars.capacity() * sizeof(int) +
           r.tuples.capacity() * sizeof(ClassTdTuple);
}

static void class_td_relation_sort_unique(ClassTdRelation *r)
{
    if (!r)
        return;
    if (r->vars.empty()) {
        if (!r->has_empty && !r->tuples.empty())
            r->has_empty = true;
        r->tuples.clear();
        return;
    }
    const size_t arity = r->vars.size();
    std::sort(r->tuples.begin(), r->tuples.end(),
              [arity](const ClassTdTuple &x, const ClassTdTuple &y) {
                  return class_td_tuple_less(x, y, arity);
              });
    auto it = std::unique(r->tuples.begin(), r->tuples.end(),
                          [arity](const ClassTdTuple &x, const ClassTdTuple &y) {
                              return class_td_tuple_eq(x, y, arity);
                          });
    r->tuples.erase(it, r->tuples.end());
}

static bool class_td_relation_contains_tuple(const ClassTdRelation &r,
                                             const std::vector<int32_t> &vals)
{
    if (r.vars.size() != vals.size() || r.vars.empty())
        return false;
    ClassTdTuple key;
    for (size_t i = 0; i < vals.size(); i++) {
        if (vals[i] < 0)
            return false;
        key.tok[i] = (uint32_t)vals[i];
    }
    auto it = std::lower_bound(r.tuples.begin(), r.tuples.end(), key,
                               [&](const ClassTdTuple &x, const ClassTdTuple &y) {
                                   return class_td_tuple_less(x, y, r.vars.size());
                               });
    if (it == r.tuples.end())
        return false;
    return class_td_tuple_eq(*it, key, r.vars.size());
}

static bool class_td_filter_relation_by_comparators(const ClassTdRelation &in,
                                                    const std::vector<ClauseComparator> &cmps,
                                                    ClassTdRelation *out)
{
    if (!out)
        return false;
    *out = in;
    if (in.empty() || in.vars.empty() || cmps.empty())
        return true;

    std::vector<int> lpos(cmps.size(), -1);
    std::vector<int> rpos(cmps.size(), -1);
    for (size_t i = 0; i < cmps.size(); i++) {
        lpos[i] = class_td_var_pos(in.vars, cmps[i].left_pos);
        rpos[i] = class_td_var_pos(in.vars, cmps[i].right_pos);
    }

    std::vector<ClassTdTuple> kept;
    kept.reserve(in.tuples.size());
    for (const ClassTdTuple &t : in.tuples) {
        bool ok = true;
        for (size_t i = 0; i < cmps.size(); i++) {
            if (lpos[i] < 0 || rpos[i] < 0)
                continue;
            int32_t lt = (int32_t)t.tok[(size_t)lpos[i]];
            int32_t rt = (int32_t)t.tok[(size_t)rpos[i]];
            if (!token_compare(cmps[i].op, lt, rt, cmps[i].rank_data)) {
                ok = false;
                break;
            }
        }
        if (ok)
            kept.push_back(t);
    }
    out->tuples.swap(kept);
    class_td_relation_sort_unique(out);
    return true;
}

static bool class_td_join_two_relations(const ClassTdRelation &a,
                                        const ClassTdRelation &b,
                                        const std::vector<ClauseComparator> &cmps,
                                        BuildProfile *profile,
                                        ClassTdRelation *out)
{
    if (!out)
        return false;
    auto t0 = Clock::now();
    out->vars.clear();
    out->tuples.clear();
    out->has_empty = false;

    if (a.empty() || b.empty()) {
        if (profile)
            profile->class_td_join_ms += Ms(Clock::now() - t0).count();
        return true;
    }
    std::vector<int> union_vars = a.vars;
    for (int v : b.vars)
        union_vars.push_back(v);
    std::sort(union_vars.begin(), union_vars.end());
    union_vars.erase(std::unique(union_vars.begin(), union_vars.end()), union_vars.end());
    if (union_vars.size() > 3u)
        return false;
    out->vars = union_vars;
    if (a.vars.empty()) {
        *out = b;
        if (profile)
            profile->class_td_join_ms += Ms(Clock::now() - t0).count();
        return class_td_filter_relation_by_comparators(*out, cmps, out);
    }
    if (b.vars.empty()) {
        *out = a;
        if (profile)
            profile->class_td_join_ms += Ms(Clock::now() - t0).count();
        return class_td_filter_relation_by_comparators(*out, cmps, out);
    }

    std::vector<int> shared;
    shared.reserve(std::min(a.vars.size(), b.vars.size()));
    for (int v : a.vars) {
        if (class_td_var_pos(b.vars, v) >= 0)
            shared.push_back(v);
    }

    int pos_u_a[3] = {-1, -1, -1};
    int pos_u_b[3] = {-1, -1, -1};
    for (size_t ui = 0; ui < union_vars.size(); ui++) {
        pos_u_a[ui] = class_td_var_pos(a.vars, union_vars[ui]);
        pos_u_b[ui] = class_td_var_pos(b.vars, union_vars[ui]);
    }

    auto emit_join = [&](const ClassTdTuple &ta, const ClassTdTuple &tb) {
        ClassTdTuple tu;
        for (size_t ui = 0; ui < union_vars.size(); ui++) {
            int pa = pos_u_a[ui];
            int pb = pos_u_b[ui];
            if (pa >= 0 && pb >= 0) {
                if (ta.tok[(size_t)pa] != tb.tok[(size_t)pb])
                    return;
                tu.tok[ui] = ta.tok[(size_t)pa];
            } else if (pa >= 0) {
                tu.tok[ui] = ta.tok[(size_t)pa];
            } else if (pb >= 0) {
                tu.tok[ui] = tb.tok[(size_t)pb];
            } else {
                return;
            }
        }
        out->tuples.push_back(tu);
    };

    if (shared.empty()) {
        out->tuples.reserve(a.tuples.size() * b.tuples.size());
        for (const ClassTdTuple &ta : a.tuples) {
            for (const ClassTdTuple &tb : b.tuples)
                emit_join(ta, tb);
        }
    } else {
        std::vector<uint32_t> ia(a.tuples.size());
        std::vector<uint32_t> ib(b.tuples.size());
        std::iota(ia.begin(), ia.end(), 0u);
        std::iota(ib.begin(), ib.end(), 0u);

        int posa[3] = {-1, -1, -1};
        int posb[3] = {-1, -1, -1};
        for (size_t i = 0; i < shared.size(); i++) {
            posa[i] = class_td_var_pos(a.vars, shared[i]);
            posb[i] = class_td_var_pos(b.vars, shared[i]);
            if (posa[i] < 0 || posb[i] < 0)
                return false;
        }

        auto key_less_a = [&](uint32_t li, uint32_t ri) {
            const ClassTdTuple &x = a.tuples[(size_t)li];
            const ClassTdTuple &y = a.tuples[(size_t)ri];
            for (size_t i = 0; i < shared.size(); i++) {
                uint32_t lx = x.tok[(size_t)posa[i]];
                uint32_t ly = y.tok[(size_t)posa[i]];
                if (lx < ly)
                    return true;
                if (lx > ly)
                    return false;
            }
            return false;
        };
        auto key_less_b = [&](uint32_t li, uint32_t ri) {
            const ClassTdTuple &x = b.tuples[(size_t)li];
            const ClassTdTuple &y = b.tuples[(size_t)ri];
            for (size_t i = 0; i < shared.size(); i++) {
                uint32_t lx = x.tok[(size_t)posb[i]];
                uint32_t ly = y.tok[(size_t)posb[i]];
                if (lx < ly)
                    return true;
                if (lx > ly)
                    return false;
            }
            return false;
        };
        std::sort(ia.begin(), ia.end(), key_less_a);
        std::sort(ib.begin(), ib.end(), key_less_b);

        auto key_cmp_ab = [&](uint32_t ai, uint32_t bi) {
            const ClassTdTuple &x = a.tuples[(size_t)ai];
            const ClassTdTuple &y = b.tuples[(size_t)bi];
            for (size_t i = 0; i < shared.size(); i++) {
                uint32_t lx = x.tok[(size_t)posa[i]];
                uint32_t ly = y.tok[(size_t)posb[i]];
                if (lx < ly)
                    return -1;
                if (lx > ly)
                    return 1;
            }
            return 0;
        };
        auto key_eq_a = [&](uint32_t li, uint32_t ri) {
            const ClassTdTuple &x = a.tuples[(size_t)li];
            const ClassTdTuple &y = a.tuples[(size_t)ri];
            for (size_t i = 0; i < shared.size(); i++) {
                if (x.tok[(size_t)posa[i]] != y.tok[(size_t)posa[i]])
                    return false;
            }
            return true;
        };
        auto key_eq_b = [&](uint32_t li, uint32_t ri) {
            const ClassTdTuple &x = b.tuples[(size_t)li];
            const ClassTdTuple &y = b.tuples[(size_t)ri];
            for (size_t i = 0; i < shared.size(); i++) {
                if (x.tok[(size_t)posb[i]] != y.tok[(size_t)posb[i]])
                    return false;
            }
            return true;
        };

        size_t pa = 0, pb = 0;
        while (pa < ia.size() && pb < ib.size()) {
            int cmp = key_cmp_ab(ia[pa], ib[pb]);
            if (cmp < 0) {
                size_t na = pa + 1;
                while (na < ia.size() && key_eq_a(ia[pa], ia[na]))
                    na++;
                pa = na;
                continue;
            }
            if (cmp > 0) {
                size_t nb = pb + 1;
                while (nb < ib.size() && key_eq_b(ib[pb], ib[nb]))
                    nb++;
                pb = nb;
                continue;
            }
            size_t na = pa + 1;
            while (na < ia.size() && key_eq_a(ia[pa], ia[na]))
                na++;
            size_t nb = pb + 1;
            while (nb < ib.size() && key_eq_b(ib[pb], ib[nb]))
                nb++;
            for (size_t xa = pa; xa < na; xa++) {
                for (size_t xb = pb; xb < nb; xb++) {
                    emit_join(a.tuples[(size_t)ia[xa]], b.tuples[(size_t)ib[xb]]);
                }
            }
            pa = na;
            pb = nb;
        }
    }
    class_td_relation_sort_unique(out);
    if (!class_td_filter_relation_by_comparators(*out, cmps, out))
        return false;
    if (profile)
        profile->class_td_join_ms += Ms(Clock::now() - t0).count();
    return true;
}

static bool class_td_project_drop_var(const ClassTdRelation &in,
                                      int drop_var,
                                      const std::vector<ClauseComparator> &cmps,
                                      BuildProfile *profile,
                                      ClassTdRelation *out)
{
    if (!out)
        return false;
    auto t0 = Clock::now();
    out->vars.clear();
    out->tuples.clear();
    out->has_empty = false;
    for (int v : in.vars) {
        if (v != drop_var)
            out->vars.push_back(v);
    }
    int drop_pos = class_td_var_pos(in.vars, drop_var);
    if (drop_pos < 0) {
        *out = in;
        if (profile)
            profile->class_td_project_ms += Ms(Clock::now() - t0).count();
        return true;
    }
    if (out->vars.empty()) {
        out->has_empty = !in.empty();
        if (profile)
            profile->class_td_project_ms += Ms(Clock::now() - t0).count();
        return true;
    }
    for (const ClassTdTuple &t : in.tuples) {
        ClassTdTuple p;
        size_t wi = 0;
        for (size_t i = 0; i < in.vars.size(); i++) {
            if ((int)i == drop_pos)
                continue;
            p.tok[wi++] = t.tok[i];
        }
        out->tuples.push_back(p);
    }
    class_td_relation_sort_unique(out);
    if (!class_td_filter_relation_by_comparators(*out, cmps, out))
        return false;
    if (profile)
        profile->class_td_project_ms += Ms(Clock::now() - t0).count();
    return true;
}

static bool class_td_project_to_vars(const ClassTdRelation &in,
                                     const std::vector<int> &keep_vars,
                                     const std::vector<ClauseComparator> &cmps,
                                     BuildProfile *profile,
                                     ClassTdRelation *out)
{
    if (!out)
        return false;
    auto t0 = Clock::now();
    out->vars = keep_vars;
    out->tuples.clear();
    out->has_empty = false;
    if (keep_vars.empty()) {
        out->has_empty = !in.empty();
        if (profile)
            profile->class_td_project_ms += Ms(Clock::now() - t0).count();
        return true;
    }
    int pos_in[3] = {-1, -1, -1};
    for (size_t i = 0; i < keep_vars.size(); i++) {
        pos_in[i] = class_td_var_pos(in.vars, keep_vars[i]);
        if (pos_in[i] < 0)
            return false;
    }
    for (int v : keep_vars) {
        if (class_td_var_pos(in.vars, v) < 0)
            return false;
    }
    for (const ClassTdTuple &t : in.tuples) {
        ClassTdTuple p;
        for (size_t i = 0; i < keep_vars.size(); i++)
            p.tok[i] = t.tok[(size_t)pos_in[i]];
        out->tuples.push_back(p);
    }
    class_td_relation_sort_unique(out);
    if (!class_td_filter_relation_by_comparators(*out, cmps, out))
        return false;
    if (profile)
        profile->class_td_project_ms += Ms(Clock::now() - t0).count();
    return true;
}

static bool class_td_build_factor_relation(const Loaded &loaded,
                                           const ClassTdTableFactor &f,
                                           ClassTdRelation *out_rel,
                                           uint64 *out_rows_scanned)
{
    if (!f.tp || !f.ti || !out_rel)
        return false;
    out_rel->vars = f.vars;
    out_rel->tuples.clear();
    out_rel->has_empty = false;
    if (out_rows_scanned)
        *out_rows_scanned = 0;

    if (f.vars.empty()) {
        for (uint32 rid = 0; rid < f.ti->nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if (out_rows_scanned)
                (*out_rows_scanned)++;
            if (!pf2_row_matches_table_local_atoms(*f.tp, f.local_cmps, rid))
                continue;
            out_rel->has_empty = true;
            break;
        }
        return true;
    }
    if (f.drive_group_idx < 0 || (size_t)f.drive_group_idx >= f.groups.size())
        return false;
    const ClauseClassGroup *dg = f.groups[(size_t)f.drive_group_idx];
    if (!dg)
        return false;

    for (size_t tok = 0; tok < f.drive_ntokens; tok++) {
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, f.tp->table, dg->domain_id, (int32_t)tok, &rid_ptr, &rid_len))
            return false;
        if (out_rows_scanned)
            *out_rows_scanned += (uint64)rid_len;
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (!pf2_row_matches_table_local_atoms(*f.tp, f.local_cmps, rid))
                continue;
            ClassTdTuple tup;
            bool ok = true;
            for (size_t gi = 0; gi < f.groups.size(); gi++) {
                const ClauseClassGroup *cg = f.groups[gi];
                int32_t tv = -1;
                if (!cg || !pf2_get_group_token_on_row(*cg, rid, &tv)) {
                    ok = false;
                    break;
                }
                if (tv < 0) {
                    ok = false;
                    break;
                }
                tup.tok[gi] = (uint32_t)tv;
            }
            if (ok)
                out_rel->tuples.push_back(tup);
        }
    }
    class_td_relation_sort_unique(out_rel);
    return true;
}

static bool class_td_cycle_detect_pattern(const Loaded &loaded,
                                          const std::string &target,
                                          const ClausePlan &cl,
                                          const ClauseTablePlan &target_tp,
                                          const TableData &target_ti,
                                          ClassTdCyclePattern *out_pat)
{
    if (!out_pat)
        return false;
    *out_pat = ClassTdCyclePattern{};
    out_pat->target_tp = &target_tp;
    out_pat->target_ti = &target_ti;

    // Build fast table lookup over clause tables.
    std::unordered_map<std::string, const ClauseTablePlan *> tp_by_name;
    std::unordered_map<std::string, const TableData *> ti_by_name;
    tp_by_name.reserve(cl.tables.size());
    ti_by_name.reserve(cl.tables.size());
    for (const auto &tp : cl.tables) {
        tp_by_name[tp.table] = &tp;
        auto it_t = loaded.tables.find(tp.table);
        if (it_t == loaded.tables.end())
            return false;
        ti_by_name[tp.table] = &it_t->second;
    }
    if (tp_by_name.find(target) == tp_by_name.end())
        return true;

    // Collect join incidences table<->class_pos from JOIN atoms.
    struct IncEdge { int t = -1; int v = -1; };
    std::vector<IncEdge> inc_edges;
    std::vector<std::pair<int, int>> cmp_edges;  // class_pos pairs for cross-table comparators
    std::vector<ClauseComparator> cross_table_cmps_all;
    std::unordered_map<std::string, int> table_idx;
    std::unordered_map<int, int> var_idx;
    std::vector<std::string> table_names;
    std::vector<int> vars;
    auto ensure_table = [&](const std::string &tname) -> int {
        auto it = table_idx.find(tname);
        if (it != table_idx.end())
            return it->second;
        int idx = (int)table_idx.size();
        table_idx[tname] = idx;
        table_names.push_back(tname);
        return idx;
    };
    auto ensure_var = [&](int class_pos) -> int {
        auto it = var_idx.find(class_pos);
        if (it != var_idx.end())
            return it->second;
        int idx = (int)var_idx.size();
        var_idx[class_pos] = idx;
        vars.push_back(class_pos);
        return idx;
    };

    std::unordered_set<std::string> seen_inc;
    seen_inc.reserve(cl.atom_ids.size() * 2u + 4u);
    for (int aid : cl.atom_ids) {
        auto it = loaded.atoms_by_id.find(aid);
        if (it == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it->second;
        if (a.kind != AtomKind::JOIN)
            continue;
        if (a.left.table == a.right.table)
            return true;
        auto itl_tp = tp_by_name.find(a.left.table);
        auto itr_tp = tp_by_name.find(a.right.table);
        auto itl_ti = ti_by_name.find(a.left.table);
        auto itr_ti = ti_by_name.find(a.right.table);
        if (itl_tp == tp_by_name.end() || itr_tp == tp_by_name.end() ||
            itl_ti == ti_by_name.end() || itr_ti == ti_by_name.end()) {
            return true;
        }
        int lp = class_td_find_group_pos_for_col(*itl_tp->second, *itl_ti->second, a.left.key());
        int rp = class_td_find_group_pos_for_col(*itr_tp->second, *itr_ti->second, a.right.key());
        if (lp < 0 || rp < 0 || lp != rp)
            return true;
        int ti_l = ensure_table(a.left.table);
        int ti_r = ensure_table(a.right.table);
        int vi = ensure_var(lp);
        std::string k1 = a.left.table + "|V" + std::to_string(lp);
        std::string k2 = a.right.table + "|V" + std::to_string(lp);
        if (seen_inc.insert(k1).second)
            inc_edges.push_back({ti_l, vi});
        if (seen_inc.insert(k2).second)
            inc_edges.push_back({ti_r, vi});
    }
    // Collect cross-table comparators as TD constraints.
    for (const ClauseComparator &cmp : cl.compares) {
        auto it_atom = loaded.atoms_by_id.find(cmp.atom_id);
        if (it_atom == loaded.atoms_by_id.end())
            return false;
        const Atom &a = it_atom->second;
        if (a.kind != AtomKind::COLCOL)
            continue;
        if (a.left.table == a.right.table)
            continue;
        // Comparator table endpoints must be present in the current clause table set.
        if (tp_by_name.find(a.left.table) == tp_by_name.end() ||
            tp_by_name.find(a.right.table) == tp_by_name.end()) {
            return true;
        }
        int ti_l = ensure_table(a.left.table);
        int ti_r = ensure_table(a.right.table);
        int vi_l = ensure_var(cmp.left_pos);
        int vi_r = ensure_var(cmp.right_pos);
        std::string k1 = a.left.table + "|V" + std::to_string(cmp.left_pos);
        std::string k2 = a.right.table + "|V" + std::to_string(cmp.right_pos);
        if (seen_inc.insert(k1).second)
            inc_edges.push_back({ti_l, vi_l});
        if (seen_inc.insert(k2).second)
            inc_edges.push_back({ti_r, vi_r});
        cmp_edges.emplace_back(cmp.left_pos, cmp.right_pos);
        cross_table_cmps_all.push_back(cmp);
    }
    if (inc_edges.empty())
        return true;
    auto it_target_table = table_idx.find(target);
    if (it_target_table == table_idx.end())
        return true;

    int nt = (int)table_names.size();
    int nv = (int)vars.size();
    int n = nt + nv;
    std::vector<std::vector<int>> adj((size_t)n);
    for (const auto &e : inc_edges) {
        int tn = e.t;
        int vn = nt + e.v;
        if (tn < 0 || tn >= nt || e.v < 0 || e.v >= nv)
            return false;
        adj[(size_t)tn].push_back(vn);
        adj[(size_t)vn].push_back(tn);
    }

    // Target-connected component only.
    std::vector<int> comp(n, 0);
    std::deque<int> q;
    q.push_back(it_target_table->second);
    comp[(size_t)it_target_table->second] = 1;
    while (!q.empty()) {
        int u = q.front();
        q.pop_front();
        for (int v : adj[(size_t)u]) {
            if (comp[(size_t)v])
                continue;
            comp[(size_t)v] = 1;
            q.push_back(v);
        }
    }
    int comp_nodes = 0;
    for (int f : comp)
        if (f)
            comp_nodes++;
    int comp_edges = 0;
    for (const auto &e : inc_edges) {
        int tn = e.t;
        int vn = nt + e.v;
        if (comp[(size_t)tn] && comp[(size_t)vn])
            comp_edges++;
    }
    if (comp_nodes <= 0 || comp_edges <= 0)
        return true;
    if (comp_edges == comp_nodes - 1)
        return true; // acyclic, handled by tree route

    // Build factors from component tables.
    std::unordered_set<int> vars_in_comp;
    for (int vi = 0; vi < nv; vi++) {
        if (comp[(size_t)(nt + vi)])
            vars_in_comp.insert(vars[(size_t)vi]);
    }
    for (const auto &ce : cmp_edges) {
        vars_in_comp.insert(ce.first);
        vars_in_comp.insert(ce.second);
    }
    std::vector<int> target_vars;
    target_vars.reserve(target_tp.class_groups.size());
    for (const auto &cg : target_tp.class_groups) {
        if (vars_in_comp.find(cg.class_pos) != vars_in_comp.end())
            target_vars.push_back(cg.class_pos);
    }
    std::sort(target_vars.begin(), target_vars.end());
    target_vars.erase(std::unique(target_vars.begin(), target_vars.end()), target_vars.end());
    if (target_vars.empty())
        return true;
    out_pat->target_vars = target_vars;
    for (const ClauseComparator &cmp : cross_table_cmps_all) {
        if (vars_in_comp.find(cmp.left_pos) == vars_in_comp.end() ||
            vars_in_comp.find(cmp.right_pos) == vars_in_comp.end())
            continue;
        out_pat->cross_table_cmps.push_back(cmp);
    }

    // Build primal graph over class_pos vars.
    std::set<int> all_vars_set(vars_in_comp.begin(), vars_in_comp.end());
    std::unordered_map<int, std::set<int>> primal;
    for (int v : all_vars_set)
        primal[v] = {};
    for (const ClauseComparator &cmp : out_pat->cross_table_cmps) {
        if (cmp.left_pos < 0 || cmp.right_pos < 0)
            return false;
        primal[cmp.left_pos].insert(cmp.right_pos);
        primal[cmp.right_pos].insert(cmp.left_pos);
    }

    for (int ti = 0; ti < nt; ti++) {
        if (!comp[(size_t)ti])
            continue;
        const std::string &tname = table_names[(size_t)ti];
        auto ittp = tp_by_name.find(tname);
        auto itti = ti_by_name.find(tname);
        if (ittp == tp_by_name.end() || itti == ti_by_name.end())
            return false;
        ClassTdTableFactor f;
        f.tp = ittp->second;
        f.ti = itti->second;
        if (!pf2_map_local_only_comparators_for_table(cl, *f.tp, &f.local_cmps))
            return false;
        for (const auto &cg : f.tp->class_groups) {
            if (vars_in_comp.find(cg.class_pos) == vars_in_comp.end())
                continue;
            f.vars.push_back(cg.class_pos);
            f.groups.push_back(&cg);
        }
        std::vector<size_t> ord(f.vars.size());
        for (size_t i = 0; i < ord.size(); i++)
            ord[i] = i;
        std::sort(ord.begin(), ord.end(), [&](size_t a, size_t b) { return f.vars[a] < f.vars[b]; });
        std::vector<int> svars;
        std::vector<const ClauseClassGroup *> sgroups;
        svars.reserve(ord.size());
        sgroups.reserve(ord.size());
        for (size_t oi : ord) {
            svars.push_back(f.vars[oi]);
            sgroups.push_back(f.groups[oi]);
        }
        f.vars.swap(svars);
        f.groups.swap(sgroups);
        if (!f.vars.empty()) {
            for (size_t i = 0; i < f.vars.size(); i++) {
                for (size_t j = i + 1; j < f.vars.size(); j++) {
                    primal[f.vars[i]].insert(f.vars[j]);
                    primal[f.vars[j]].insert(f.vars[i]);
                }
            }
            size_t best_ntok = std::numeric_limits<size_t>::max();
            int best_idx = -1;
            for (size_t gi = 0; gi < f.groups.size(); gi++) {
                const ClauseClassGroup *cg = f.groups[gi];
                if (!cg)
                    continue;
                size_t ntok = 0;
                auto itd = loaded.domain_dicts.find(cg->domain_id);
                if (itd != loaded.domain_dicts.end())
                    ntok = itd->second.size();
                if (ntok == 0) {
                    const BinIndexCacheEntry *ent = nullptr;
                    if (!get_or_build_bin_index_cache_entry(loaded, f.tp->table, cg->domain_id, &ent))
                        return false;
                    if (ent && !ent->off.empty())
                        ntok = ent->off.size() - 1u;
                }
                if (ntok == 0)
                    continue;
                if (ntok < best_ntok) {
                    best_ntok = ntok;
                    best_idx = (int)gi;
                }
            }
            if (best_idx < 0 || best_ntok == 0)
                return true;
            f.drive_group_idx = best_idx;
            f.drive_ntokens = best_ntok;
        }
        out_pat->factors.push_back(std::move(f));
    }
    if (out_pat->factors.empty())
        return true;

    // Deterministic min-fill elimination with target vars last.
    std::set<int> remaining = all_vars_set;
    std::unordered_set<int> target_var_set(target_vars.begin(), target_vars.end());
    std::vector<std::vector<int>> bags;
    std::vector<int> elim;
    int width = 0;
    while (!remaining.empty()) {
        bool have_non_target = false;
        for (int v : remaining) {
            if (target_var_set.find(v) == target_var_set.end()) {
                have_non_target = true;
                break;
            }
        }
        int pick = -1;
        int pick_fill = std::numeric_limits<int>::max();
        int pick_deg = std::numeric_limits<int>::max();
        std::vector<int> pick_nei;
        for (int v : remaining) {
            bool is_target_var = (target_var_set.find(v) != target_var_set.end());
            if (have_non_target && is_target_var)
                continue;
            std::vector<int> nei;
            for (int u : primal[v]) {
                if (remaining.find(u) != remaining.end())
                    nei.push_back(u);
            }
            std::sort(nei.begin(), nei.end());
            int fill = 0;
            for (size_t i = 0; i < nei.size(); i++) {
                for (size_t j = i + 1; j < nei.size(); j++) {
                    int a = nei[i], b = nei[j];
                    if (primal[a].find(b) == primal[a].end())
                        fill++;
                }
            }
            int deg = (int)nei.size();
            if (fill < pick_fill ||
                (fill == pick_fill && deg < pick_deg) ||
                (fill == pick_fill && deg == pick_deg && v < pick)) {
                pick = v;
                pick_fill = fill;
                pick_deg = deg;
                pick_nei = std::move(nei);
            }
        }
        if (pick < 0)
            return false;
        std::vector<int> bag = pick_nei;
        bag.push_back(pick);
        std::sort(bag.begin(), bag.end());
        bag.erase(std::unique(bag.begin(), bag.end()), bag.end());
        width = std::max(width, (int)bag.size() - 1);
        bags.push_back(bag);
        elim.push_back(pick);
        for (size_t i = 0; i < pick_nei.size(); i++) {
            for (size_t j = i + 1; j < pick_nei.size(); j++) {
                primal[pick_nei[i]].insert(pick_nei[j]);
                primal[pick_nei[j]].insert(pick_nei[i]);
            }
        }
        for (int u : pick_nei)
            primal[u].erase(pick);
        primal[pick].clear();
        remaining.erase(pick);
    }

    out_pat->matched = true;
    out_pat->td_width = width;
    out_pat->width_exceeded = (width > class_td_width_limit());
    out_pat->bags = std::move(bags);
    out_pat->elim_order = std::move(elim);
    return true;
}

static uint64 class_td_pairs_count(const std::vector<ClassTdRelation> &factors)
{
    uint64 n = 0;
    for (const ClassTdRelation &r : factors) {
        if (r.vars.size() == 2u)
            n += (uint64)r.tuples.size();
    }
    return n;
}

static uint64 class_td_safe_mul_u64(uint64 a, uint64 b)
{
    if (a == 0 || b == 0)
        return 0;
    if (a > (std::numeric_limits<uint64>::max() / b))
        return std::numeric_limits<uint64>::max();
    return a * b;
}

static bool class_td_compute_var_ntokens(const Loaded &loaded,
                                         const ClausePlan &cl,
                                         const std::vector<ClassTdRelation> &factors,
                                         std::unordered_map<int, size_t> *out_ntok)
{
    if (!out_ntok)
        return false;
    out_ntok->clear();
    std::unordered_set<int> vars;
    for (const ClassTdRelation &r : factors) {
        for (int v : r.vars)
            vars.insert(v);
    }
    for (int v : vars) {
        size_t nt = 0;
        if (v >= 0 && (size_t)v < cl.join_classes.size()) {
            int dom = cl.join_classes[(size_t)v];
            auto itd = loaded.domain_dicts.find(dom);
            if (itd != loaded.domain_dicts.end())
                nt = itd->second.size();
        }
        if (nt == 0) {
            uint32_t mx = 0;
            bool seen = false;
            for (const ClassTdRelation &r : factors) {
                int p = class_td_var_pos(r.vars, v);
                if (p < 0)
                    continue;
                for (const ClassTdTuple &t : r.tuples) {
                    seen = true;
                    mx = std::max(mx, t.tok[(size_t)p]);
                }
            }
            if (seen)
                nt = (size_t)mx + 1u;
        }
        if (nt == 0)
            nt = 1;
        (*out_ntok)[v] = nt;
    }
    return true;
}

static bool class_td_apply_cmp_support_prune(const std::vector<ClauseComparator> &cmps,
                                             std::unordered_map<int, TokenBitset> *supports)
{
    if (!supports)
        return false;
    for (const ClauseComparator &cmp : cmps) {
        auto itl = supports->find(cmp.left_pos);
        auto itr = supports->find(cmp.right_pos);
        if (itl == supports->end() || itr == supports->end())
            continue;
        TokenBitset lnew = itl->second;
        TokenBitset rnew = itr->second;
        lnew.clear_all();
        rnew.clear_all();

        if (cmp.op == ConstOp::EQ) {
            lnew = itl->second;
            lnew.bit_and(itr->second);
            rnew = itr->second;
            rnew.bit_and(itl->second);
        } else if (cmp.op == ConstOp::NE) {
            size_t rc = itr->second.count();
            size_t lc = itl->second.count();
            if (rc >= 2u) {
                lnew = itl->second;
            } else if (rc == 1u) {
                int32_t one = -1;
                itr->second.for_each_set([&](int32_t t) { one = t; });
                lnew = itl->second;
                if (one >= 0)
                    lnew.clear((size_t)one);
            }
            if (lc >= 2u) {
                rnew = itr->second;
            } else if (lc == 1u) {
                int32_t one = -1;
                itl->second.for_each_set([&](int32_t t) { one = t; });
                rnew = itr->second;
                if (one >= 0)
                    rnew.clear((size_t)one);
            }
        } else {
            if (!cmp.rank_data)
                return false;
            int32_t lmin = std::numeric_limits<int32_t>::max();
            int32_t lmax = std::numeric_limits<int32_t>::min();
            int32_t rmin = std::numeric_limits<int32_t>::max();
            int32_t rmax = std::numeric_limits<int32_t>::min();
            itl->second.for_each_set([&](int32_t t) {
                int32_t rk = token_rank_of(t, cmp.rank_data);
                lmin = std::min(lmin, rk);
                lmax = std::max(lmax, rk);
            });
            itr->second.for_each_set([&](int32_t t) {
                int32_t rk = token_rank_of(t, cmp.rank_data);
                rmin = std::min(rmin, rk);
                rmax = std::max(rmax, rk);
            });

            if (rmin <= rmax) {
                itl->second.for_each_set([&](int32_t t) {
                    int32_t rk = token_rank_of(t, cmp.rank_data);
                    bool ok = false;
                    switch (cmp.op) {
                        case ConstOp::LT: ok = (rk < rmax); break;
                        case ConstOp::LE: ok = (rk <= rmax); break;
                        case ConstOp::GT: ok = (rk > rmin); break;
                        case ConstOp::GE: ok = (rk >= rmin); break;
                        default: break;
                    }
                    if (ok)
                        lnew.set((size_t)t);
                });
            }
            if (lmin <= lmax) {
                itr->second.for_each_set([&](int32_t t) {
                    int32_t rk = token_rank_of(t, cmp.rank_data);
                    bool ok = false;
                    switch (cmp.op) {
                        case ConstOp::LT: ok = (rk > lmin); break;
                        case ConstOp::LE: ok = (rk >= lmin); break;
                        case ConstOp::GT: ok = (rk < lmax); break;
                        case ConstOp::GE: ok = (rk <= lmax); break;
                        default: break;
                    }
                    if (ok)
                        rnew.set((size_t)t);
                });
            }
        }
        itl->second.intersect_with_changed(lnew);
        itr->second.intersect_with_changed(rnew);
    }
    return true;
}

static bool class_td_semijoin_reduction(const Loaded &loaded,
                                        const ClausePlan &cl,
                                        const std::vector<ClauseComparator> &cmps,
                                        std::vector<ClassTdRelation> *factors,
                                        BuildProfile *profile)
{
    if (!factors || !profile)
        return false;
    if (factors->size() < 2u)
        return true;

    std::unordered_map<int, size_t> var_ntok;
    if (!class_td_compute_var_ntokens(loaded, cl, *factors, &var_ntok))
        return false;

    auto run_pass = [&](uint64 *out_removed_pairs) -> bool {
        if (out_removed_pairs)
            *out_removed_pairs = 0;

        std::unordered_map<int, TokenBitset> supports_global;
        std::unordered_map<int, bool> supports_seen;
        supports_global.reserve(var_ntok.size() * 2u + 1u);
        supports_seen.reserve(var_ntok.size() * 2u + 1u);
        for (const auto &kv : var_ntok) {
            supports_global.emplace(kv.first, TokenBitset(kv.second));
            supports_global[kv.first].clear_all();
            supports_seen[kv.first] = false;
        }

        for (const ClassTdRelation &r : *factors) {
            if (r.empty() || r.vars.empty())
                continue;
            for (size_t p = 0; p < r.vars.size(); p++) {
                int v = r.vars[p];
                auto itn = var_ntok.find(v);
                if (itn == var_ntok.end())
                    return false;
                TokenBitset local(itn->second);
                local.clear_all();
                for (const ClassTdTuple &t : r.tuples)
                    local.set((size_t)t.tok[p]);
                if (!supports_seen[v]) {
                    supports_global[v] = local;
                    supports_seen[v] = true;
                } else {
                    supports_global[v].bit_and(local);
                }
            }
        }

        if (!class_td_apply_cmp_support_prune(cmps, &supports_global))
            return false;

        uint64 removed_pairs = 0;
        uint64 cmp_removed_pairs = 0;
        auto t_cmp0 = Clock::now();
        for (ClassTdRelation &r : *factors) {
            if (r.empty() || r.vars.empty())
                continue;
            size_t before = r.tuples.size();
            std::vector<ClassTdTuple> kept;
            kept.reserve(before);
            for (const ClassTdTuple &t : r.tuples) {
                bool ok = true;
                for (size_t p = 0; p < r.vars.size(); p++) {
                    auto its = supports_global.find(r.vars[p]);
                    if (its == supports_global.end() || !its->second.test((size_t)t.tok[p])) {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    kept.push_back(t);
            }
            r.tuples.swap(kept);
            if (r.vars.size() == 2u && before >= r.tuples.size())
                removed_pairs += (uint64)(before - r.tuples.size());
            if (r.empty())
                return true;

            size_t before_cmp = r.tuples.size();
            ClassTdRelation filtered;
            if (!class_td_filter_relation_by_comparators(r, cmps, &filtered))
                return false;
            r = std::move(filtered);
            if (r.vars.size() == 2u && before_cmp >= r.tuples.size())
                cmp_removed_pairs += (uint64)(before_cmp - r.tuples.size());
        }
        profile->class_td_cmp_filter_ms += Ms(Clock::now() - t_cmp0).count();
        profile->class_td_cmp_filter_removed_pairs += cmp_removed_pairs;
        if (out_removed_pairs)
            *out_removed_pairs = removed_pairs + cmp_removed_pairs;
        return true;
    };

    const uint64 pairs_before = class_td_pairs_count(*factors);
    profile->class_td_pairs_before += pairs_before;
    auto t0 = Clock::now();
    uint64 removed1 = 0;
    if (!run_pass(&removed1))
        return false;
    profile->class_td_reduction_passes += 1;

    uint64 removed_total = removed1;
    if (pairs_before > 0) {
        double shrink = (double)removed1 / (double)pairs_before;
        if (shrink >= 0.05) {
            uint64 removed2 = 0;
            if (!run_pass(&removed2))
                return false;
            profile->class_td_reduction_passes += 1;
            removed_total += removed2;
        }
    }

    uint64 pairs_after = class_td_pairs_count(*factors);
    uint64 removed_exact = (pairs_before >= pairs_after) ? (pairs_before - pairs_after) : 0u;
    (void)removed_total;
    profile->class_td_reduction_ms += Ms(Clock::now() - t0).count();
    profile->class_td_reduction_removed_pairs += removed_exact;
    profile->class_td_pairs_after += pairs_after;
    return true;
}

static uint64 class_td_domain_cap(const std::vector<int> &vars,
                                  const std::unordered_map<int, size_t> &var_ntok)
{
    if (vars.empty())
        return 1u;
    uint64 cap = 1u;
    for (int v : vars) {
        auto it = var_ntok.find(v);
        if (it == var_ntok.end() || it->second == 0u)
            continue;
        cap = class_td_safe_mul_u64(cap, (uint64)it->second);
    }
    return cap;
}

struct ClassTdEstRel {
    std::vector<int> vars;
    uint64 sz = 0;
};

static uint64 class_td_estimate_peak_for_order(const std::vector<int> &order,
                                               const std::vector<ClassTdRelation> &factors,
                                               const std::unordered_map<int, size_t> &var_ntok)
{
    std::vector<ClassTdEstRel> rels;
    rels.reserve(factors.size());
    for (const ClassTdRelation &r : factors)
        rels.push_back(ClassTdEstRel{r.vars, (uint64)r.size()});
    uint64 peak = 0;
    for (int v : order) {
        std::vector<size_t> take;
        for (size_t i = 0; i < rels.size(); i++) {
            if (class_td_var_pos(rels[i].vars, v) >= 0)
                take.push_back(i);
        }
        if (take.empty())
            continue;
        std::vector<int> uvars = rels[take[0]].vars;
        uint64 merged = rels[take[0]].sz;
        for (size_t ti = 1; ti < take.size(); ti++) {
            const ClassTdEstRel &r = rels[take[ti]];
            for (int rv : r.vars)
                uvars.push_back(rv);
            merged = class_td_safe_mul_u64(merged, r.sz);
        }
        std::sort(uvars.begin(), uvars.end());
        uvars.erase(std::unique(uvars.begin(), uvars.end()), uvars.end());
        merged = std::min<uint64>(merged, class_td_domain_cap(uvars, var_ntok));
        std::vector<int> pvars;
        pvars.reserve(uvars.size());
        for (int uv : uvars) {
            if (uv != v)
                pvars.push_back(uv);
        }
        uint64 proj = std::min<uint64>(merged, class_td_domain_cap(pvars, var_ntok));
        if (proj > peak)
            peak = proj;

        std::vector<ClassTdEstRel> keep;
        std::vector<uint8_t> is_take(rels.size(), 0);
        for (size_t idx : take)
            is_take[idx] = 1;
        for (size_t i = 0; i < rels.size(); i++) {
            if (!is_take[i])
                keep.push_back(std::move(rels[i]));
        }
        keep.push_back(ClassTdEstRel{std::move(pvars), proj});
        rels.swap(keep);
    }
    return peak;
}

static bool eval_term_conjunction_pf2_td_cycle(const Loaded &loaded,
                                               const std::string &target,
                                               const ClausePlan &cl,
                                               const ClauseTablePlan &target_tp,
                                               const TableData &target_ti,
                                               const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                               BuildProfile *profile,
                                               SparseBlockWords *out_words,
                                               std::vector<uint8_t> *out_rid_bits,
                                               bool *out_term_has_rows,
                                               bool *out_supported)
{
    if (out_supported)
        *out_supported = false;
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (!profile || !out_words)
        return false;
    (void)restrict_sigs;

    profile->class_td_terms_total++;
    auto t_build0 = Clock::now();
    ClassTdCyclePattern pat;
    if (!class_td_cycle_detect_pattern(loaded, target, cl, target_tp, target_ti, &pat))
        return false;
    profile->class_td_build_ms += Ms(Clock::now() - t_build0).count();
    if (!pat.matched)
        return true;
    if (pat.width_exceeded) {
        profile->class_td_fail_width++;
        profile->class_td_last_width = pat.td_width;
        profile->class_td_last_bags = (int64_t)pat.bags.size();
        ereport(ERROR,
                (errmsg("policy: class_engine unsupported term shape on target=%s (td_width=%d > W=%d)",
                        target.c_str(), pat.td_width, class_td_width_limit())));
    }

    profile->class_td_terms_supported++;
    profile->pf2_terms_supported++;
    profile->class_td_width_max = std::max<uint64>(profile->class_td_width_max, (uint64)pat.td_width);
    profile->class_td_bags += (uint64)pat.bags.size();
    profile->class_td_last_width = pat.td_width;
    profile->class_td_last_bags = (int64_t)pat.bags.size();

    std::vector<ClassTdRelation> factors;
    factors.reserve(pat.factors.size());
    uint64 factor_rows_scanned = 0;
    uint64 factor_tuple_total = 0;
    for (const auto &f : pat.factors) {
        ClassTdRelation r;
        uint64 rows_scanned = 0;
        if (!class_td_build_factor_relation(loaded, f, &r, &rows_scanned))
            return false;
        factor_rows_scanned += rows_scanned;
        factor_tuple_total += (uint64)r.size();
        if (r.empty()) {
            if (out_supported)
                *out_supported = true;
            return true;
        }
        factors.push_back(std::move(r));
    }
    profile->pf2_tree_rows_scanned_total += factor_rows_scanned;
    profile->pf2_cmp_summary_keys_total += 0;
    profile->pf2_cmp_supported += 0;
    profile->pf2_cmp_total += 0;
    profile->class_td_msg_bytes_total += 0;
    (void)factor_tuple_total;

    if (class_td_reduction_enabled()) {
        if (!class_td_semijoin_reduction(loaded, cl, pat.cross_table_cmps, &factors, profile))
            return false;
    }
    for (const ClassTdRelation &r : factors) {
        if (r.empty()) {
            if (out_supported)
                *out_supported = true;
            return true;
        }
    }

    auto t_dp0 = Clock::now();
    std::unordered_set<int> protected_var_set(pat.target_vars.begin(), pat.target_vars.end());
    for (const ClauseComparator &cmp : pat.cross_table_cmps) {
        protected_var_set.insert(cmp.left_pos);
        protected_var_set.insert(cmp.right_pos);
    }
    std::vector<int> elim_order;
    elim_order.reserve(pat.elim_order.size());
    for (int v : pat.elim_order) {
        if (protected_var_set.find(v) == protected_var_set.end())
            elim_order.push_back(v);
    }
    if (!elim_order.empty()) {
        std::unordered_map<int, size_t> var_ntok;
        if (!class_td_compute_var_ntokens(loaded, cl, factors, &var_ntok))
            return false;
        uint64 peak_forward = class_td_estimate_peak_for_order(elim_order, factors, var_ntok);
        std::vector<int> elim_order_rev = elim_order;
        std::reverse(elim_order_rev.begin(), elim_order_rev.end());
        uint64 peak_reverse = class_td_estimate_peak_for_order(elim_order_rev, factors, var_ntok);
        bool use_reverse = (peak_reverse < peak_forward);
        profile->class_td_elim_order = use_reverse ? 1u : 0u;
        if (use_reverse)
            elim_order.swap(elim_order_rev);
    } else {
        profile->class_td_elim_order = 0u;
    }
    for (int v : elim_order) {
        std::vector<size_t> take;
        for (size_t i = 0; i < factors.size(); i++) {
            if (class_td_relation_contains_var(factors[i], v))
                take.push_back(i);
        }
        if (take.empty())
            continue;
        ClassTdRelation merged = factors[take[0]];
        for (size_t i = 1; i < take.size(); i++) {
            ClassTdRelation tmp;
            if (!class_td_join_two_relations(merged, factors[take[i]], pat.cross_table_cmps, profile, &tmp))
                return false;
            merged = std::move(tmp);
            if (merged.empty())
                break;
        }
        if (merged.empty()) {
            factors.clear();
            break;
        }
        ClassTdRelation projected;
        if (!class_td_project_drop_var(merged, v, pat.cross_table_cmps, profile, &projected))
            return false;
        profile->class_td_msg_entries_total += (uint64)projected.size();
        uint64 msg_bytes = (uint64)class_td_relation_bytes(projected);
        profile->class_td_msg_bytes_total += msg_bytes;
        if (projected.vars.size() == 2u)
            profile->class_td_msg_pairs_total += (uint64)projected.tuples.size();
        uint64 msg_pairs = (projected.vars.size() == 2u) ? (uint64)projected.tuples.size() : 0u;
        if (msg_pairs > profile->class_td_peak_msg_pairs)
            profile->class_td_peak_msg_pairs = msg_pairs;
        if (msg_bytes > profile->class_td_peak_msg_bytes)
            profile->class_td_peak_msg_bytes = msg_bytes;
        std::vector<ClassTdRelation> keep;
        keep.reserve(factors.size() - take.size() + 1u);
        std::vector<uint8_t> is_take(factors.size(), 0);
        for (size_t idx : take)
            is_take[idx] = 1;
        for (size_t i = 0; i < factors.size(); i++) {
            if (!is_take[i])
                keep.push_back(std::move(factors[i]));
        }
        keep.push_back(std::move(projected));
        factors.swap(keep);
    }

    if (factors.empty()) {
        profile->class_td_dp_ms += Ms(Clock::now() - t_dp0).count();
        if (out_supported)
            *out_supported = true;
        return true;
    }

    ClassTdRelation final_rel = factors[0];
    for (size_t i = 1; i < factors.size(); i++) {
        ClassTdRelation tmp;
        if (!class_td_join_two_relations(final_rel, factors[i], pat.cross_table_cmps, profile, &tmp))
            return false;
        final_rel = std::move(tmp);
        if (final_rel.empty())
            break;
    }
    if (!final_rel.empty()) {
        ClassTdRelation filtered;
        if (!class_td_filter_relation_by_comparators(final_rel, pat.cross_table_cmps, &filtered))
            return false;
        final_rel = std::move(filtered);
    }
    if (!final_rel.empty()) {
        ClassTdRelation proj;
        static const std::vector<ClauseComparator> kNoCmps;
        if (!class_td_project_to_vars(final_rel, pat.target_vars, kNoCmps, profile, &proj))
            return false;
        final_rel = std::move(proj);
    }
    profile->class_td_dp_ms += Ms(Clock::now() - t_dp0).count();

    if (final_rel.empty()) {
        if (out_supported)
            *out_supported = true;
        return true;
    }

    std::unordered_map<int, const ClauseClassGroup *> target_group_by_var;
    target_group_by_var.reserve(target_tp.class_groups.size() * 2u + 1u);
    for (const auto &cg : target_tp.class_groups)
        target_group_by_var[cg.class_pos] = &cg;
    std::vector<const ClauseClassGroup *> target_groups;
    target_groups.reserve(pat.target_vars.size());
    for (int v : pat.target_vars) {
        auto it = target_group_by_var.find(v);
        if (it == target_group_by_var.end() || !it->second)
            return false;
        target_groups.push_back(it->second);
    }

    std::vector<Pf2LocalComparator> target_local_cmps;
    if (!pf2_map_local_only_comparators_for_table(cl, target_tp, &target_local_cmps))
        return false;

    auto t_proj0 = Clock::now();
    uint32 projected_rows = 0;
    if (pat.target_vars.size() == 1u) {
        std::vector<int32_t> toks;
        toks.reserve(final_rel.tuples.size());
        for (const ClassTdTuple &t : final_rel.tuples)
            toks.push_back((int32_t)t.tok[0]);
        std::sort(toks.begin(), toks.end());
        toks.erase(std::unique(toks.begin(), toks.end()), toks.end());
        int dom = target_groups[0]->domain_id;
        for (int32_t tok : toks) {
            const uint32_t *rid_ptr = nullptr;
            size_t rid_len = 0;
            if (!get_bin_slice(loaded, target, dom, tok, &rid_ptr, &rid_len))
                return false;
            profile->pf2_project_bin_rids_total += rid_len;
            for (size_t i = 0; i < rid_len; i++) {
                PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
                if (!pf2_row_matches_table_local_atoms(target_tp, target_local_cmps, rid))
                    continue;
                if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                    continue;
                if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                    return false;
                if (out_rid_bits)
                    rid_bit_set(out_rid_bits->data(), rid);
                projected_rows++;
            }
        }
    } else if (pat.target_vars.size() == 2u) {
        int dom0 = target_groups[0]->domain_id;
        int dom1 = target_groups[1]->domain_id;
        for (const ClassTdTuple &tt : final_rel.tuples) {
            int32_t t0 = (int32_t)tt.tok[0];
            int32_t t1 = (int32_t)tt.tok[1];
            const uint32_t *r0 = nullptr;
            const uint32_t *r1 = nullptr;
            size_t n0 = 0, n1 = 0;
            if (!get_bin_slice(loaded, target, dom0, t0, &r0, &n0) ||
                !get_bin_slice(loaded, target, dom1, t1, &r1, &n1)) {
                return false;
            }
            profile->pf2_project_bin_rids_total += (n0 + n1);
            size_t i = 0, j = 0;
            while (i < n0 && j < n1) {
                uint32 a = r0 ? r0[i] : 0u;
                uint32 b = r1 ? r1[j] : 0u;
                if (a == b) {
                    uint32 rid = a;
                    if (pf2_row_matches_table_local_atoms(target_tp, target_local_cmps, rid) &&
                        (size_t)rid < target_ti.ctid_blk.size() &&
                        (size_t)rid < target_ti.ctid_off.size()) {
                        if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                            return false;
                        if (out_rid_bits)
                            rid_bit_set(out_rid_bits->data(), rid);
                        projected_rows++;
                    }
                    i++;
                    j++;
                } else if (a < b) {
                    i++;
                } else {
                    j++;
                }
            }
        }
    } else {
        // Width cap W=2 implies target vars <=3. For arity>2, scan target rows once and test tuple membership.
        for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
std::vector<int32_t> tv;
            tv.reserve(target_groups.size());
            bool ok = true;
            for (const ClauseClassGroup *cg : target_groups) {
                int32_t tok = -1;
                if (!cg || !pf2_get_group_token_on_row(*cg, rid, &tok) || tok < 0) {
                    ok = false;
                    break;
                }
                tv.push_back(tok);
            }
            if (!ok)
                continue;
            if (!class_td_relation_contains_tuple(final_rel, tv))
                continue;
            if (!pf2_row_matches_table_local_atoms(target_tp, target_local_cmps, rid))
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                return false;
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
            projected_rows++;
        }
    }
    double proj_ms = Ms(Clock::now() - t_proj0).count();
    profile->pf2_project_ms += proj_ms;
    profile->pf2_total_ms += proj_ms;

    if (out_supported)
        *out_supported = true;
    if (out_term_has_rows)
        *out_term_has_rows = (projected_rows > 0);
    return true;
}

static const char *class_route_name(ClassRouteKind k)
{
    switch (k) {
        case ClassRouteKind::SINGLE_HUB: return "single_hub";
        case ClassRouteKind::TWO_HOP: return "two_hop";
        case ClassRouteKind::TREE: return "tree";
        case ClassRouteKind::CYCLE_RECT: return "cycle_rect";
        case ClassRouteKind::TD_CYCLE: return "td_cycle";
        case ClassRouteKind::REJECT: return "reject";
    }
    return "reject";
}

static void log_class_route_notice(const std::string &target,
                                   const std::vector<int> &term_atoms,
                                   ClassRouteKind route,
                                   const char *reason = "",
                                   int td_width = -1,
                                   int td_bags = -1)
{
    std::string term_sig;
    term_sig.reserve(term_atoms.size() * 8u + 8u);
    for (size_t i = 0; i < term_atoms.size(); i++) {
        if (i > 0)
            term_sig.push_back(',');
        term_sig += std::to_string(term_atoms[i]);
    }
    elog(NOTICE,
         "class_route_term: target=%s route=%s width=%d bags=%d term_atoms=%s reason=%s",
         target.c_str(),
         class_route_name(route),
         td_width,
         td_bags,
         term_sig.empty() ? "-" : term_sig.c_str(),
         (reason && reason[0]) ? reason : "-");
}

static void log_policy_profile_query(const BuildProfile &p, int filtered_targets)
{
    elog(NOTICE,
         "policy_profile_query: K=%d query_id=%s total_ms=%.3f load_ms=%.3f local_ms=0.000 prop_ms=%.3f decode_ms=%.3f sat_calls=%llu sat_ms=%.3f sat_models_total=%llu sat_conflicts=%llu sat_decisions=%llu terms_total=%llu term_eval_ms_total=%.3f combine_algebra_ms=%.3f allow_rows_total=%llu bin_ops_total=%llu bins_touched_total=%llu bin_rids_scanned_total=%llu heap_rows_scanned_total=%llu allow_cache_hit=%llu allow_cache_miss=%llu allow_cache_build_ms=%.3f cache_hits=0 closure_tables=0 filtered_targets=%d clause_plan_count_max=%d prop_join_scans_total=%llu unique_join_struct_sigs_max=%d signature_cache_hits=%llu signature_cache_misses=%llu term_code_scans=%llu target_full_row_scans=%llu target_rid_bitmap_bytes=%zu signature_cache_bytes=%zu active_sig_dense_count=%llu active_sig_sparse_count=%llu active_sig_density_sum=%.6f domain_set_dense_count=%llu domain_set_sparse_count=%llu domain_set_density_sum=%.6f block_words_blocks_allocated=%llu block_words_total_blocks=%llu block_words_dense_bytes=%zu block_words_nblocks=%llu block_words_nwords_per_block=%llu proj_sig_count=%llu proj_sig_total=%llu proj_sig_new=%llu proj_sig_skipped=%llu proj_mask_or_ops=%llu proj_rid_iters=%llu proj_rid_iters_scan_enforcement=%llu proj_rid_iters_dependency=%llu canon_term_map_cache_hits=%llu canon_term_map_cache_misses=%llu canon_term_map_build_ms=%.3f canon_term_map_bytes=%zu restrict_key_index_build_ms=%.3f restrict_key_index_entries=%llu restrict_key_index_bytes=%zu restrict_key_prune_ms=%.3f sigmask_cache_hits=%llu sigmask_cache_misses=%llu sigmask_build_ms=%.3f sigmask_bytes=%zu bytes_sig_ctid_masks=%zu bytes_block_words=%zu bytes_artifact_buffers_retained=%zu bytes_decoded_buffers_retained=%zu witness_activesig_tables=%llu witness_sig_count_total=%llu support_recompute_ms=%.3f sig_prune_ms=%.3f pair_bundle_count=%llu pair_bundle_build_ms=%.3f pair_bundle_prune_ms=%.3f pair_bundle_keys_total=%llu pair_bundle_pruned_sigs_total=%llu pair_bundle_iters=%llu qual_atoms_total=%llu qual_atoms_applied=%llu qual_pruned_sigs=%llu qual_prune_ms=%.3f restrict_sig_tables=%llu restrict_sig_schema_cols_total=%llu restrict_sig_bytes_total=%zu restrict_sig_apply_ms=%.3f restrict_term_apply_ms=%.3f restrict_term_sigs_kept=%llu restrict_term_sigs_dropped=%llu pf2_enabled_targets=%llu pf2_terms_total=%llu pf2_terms_supported=%llu pf2_terms_single_hub=%llu pf2_terms_two_hop=%llu pf2_terms_tree=%llu pf2_terms_failed_shape=%llu pf2_hub_domain_id=%lld pf2_hub_key_arity=%llu pf2_ntokens=%llu pf2_stamp_rows_scanned_total=%llu pf2_stamp_rows_scanned_A=%llu pf2_stamp_rows_scanned_B=%llu pf2_stamp_ms=%.3f pf2_stamp_ms_A=%.3f pf2_stamp_ms_B=%.3f pf2_tok_and_or_ms=%.3f pf2_tok_compose_ms=%.3f pf2_project_bin_rids_total=%llu pf2_project_ms=%.3f pf2_tree_domains=%llu pf2_tree_tables=%llu pf2_tree_edges=%llu pf2_tree_passes=%llu pf2_tree_table_updates=%llu pf2_tree_rows_scanned_total=%llu pf2_tree_update_ms=%.3f pf2_tree_project_ms=%.3f pf2_cmp_total=%llu pf2_cmp_supported=%llu pf2_cmp_key_arity_max=%llu pf2_cmp_summary_build_ms=%.3f pf2_cmp_summary_keys_total=%llu pf2_cmp_checks_total=%llu pf2_cmp_rejects_total=%llu pf2_cmp_key2_entries=%llu pf2_cmp_key2_dense_bytes=%zu pf2_cmp_key2_build_ms=%.3f pf2_cmp_key2_rows_scanned=%llu pf2_cmp_key2_updates=%llu pf2_cmp_key2_lookups=%llu pf2_cmp_witness_witness_total=%llu pf2_cmp_witness_witness_supported=%llu pf2_cmp_filter_rows_checked=%llu pf2_cmp_filter_rows_reject=%llu pf2_cmp_chain_total=%llu pf2_cmp_chain_supported=%llu pf2_cmp_chain_build_ms=%.3f pf2_cmp_chain_bridge_rows_scanned=%llu pf2_cmp_chain_compose_steps=%llu pf2_cmp_chain_filter_rows_checked=%llu pf2_cmp_chain_filter_rows_reject=%llu pf2_total_ms=%.3f class_td_terms_total=%llu class_td_terms_supported=%llu class_td_width_max=%llu class_td_bags=%llu class_td_build_ms=%.3f class_td_dp_ms=%.3f class_td_msg_entries_total=%llu class_td_msg_bytes_total=%llu class_td_msg_pairs_total=%llu class_td_join_ms=%.3f class_td_project_ms=%.3f class_td_reduction_passes=%llu class_td_reduction_ms=%.3f class_td_reduction_removed_pairs=%llu class_td_pairs_before=%llu class_td_pairs_after=%llu class_td_elim_order=%llu class_td_peak_msg_pairs=%llu class_td_peak_msg_bytes=%llu class_td_cmp_filter_ms=%.3f class_td_cmp_filter_removed_pairs=%llu class_td_fail_width=%llu class_terms_ok=%llu class_terms_reject=%llu class_route_single_hub=%llu class_route_two_hop=%llu class_route_tree=%llu class_route_cycle_rect=%llu class_route_td_cycle=%llu class_route_reject=%llu",
         profile_k(),
         profile_query().c_str(),
         p.total_ms,
         p.artifact_parse_ms,
         p.propagate_ms,
         p.decode_ms,
         (unsigned long long)p.sat_calls,
         p.sat_ms,
         (unsigned long long)p.sat_models_total,
         (unsigned long long)p.sat_conflicts,
         (unsigned long long)p.sat_decisions,
         (unsigned long long)p.terms_total,
         p.term_eval_ms_total,
         p.combine_algebra_ms,
         (unsigned long long)p.allow_rows_total,
         (unsigned long long)p.bin_ops_total,
         (unsigned long long)p.bins_touched_total,
         (unsigned long long)p.bin_rids_scanned_total,
         (unsigned long long)p.heap_rows_scanned_total,
         (unsigned long long)p.allow_cache_hit,
         (unsigned long long)p.allow_cache_miss,
         p.allow_cache_build_ms,
         filtered_targets,
         p.clause_plan_count_max,
         (unsigned long long)p.prop_join_scans_total,
         p.unique_join_struct_sigs_max,
         (unsigned long long)p.signature_cache_hits,
         (unsigned long long)p.signature_cache_misses,
         (unsigned long long)p.term_code_scans,
         (unsigned long long)p.target_full_row_scans,
         p.target_rid_bitmap_bytes,
         p.signature_cache_bytes,
         (unsigned long long)p.active_sig_dense_count,
         (unsigned long long)p.active_sig_sparse_count,
         p.active_sig_density_sum,
         (unsigned long long)p.domain_set_dense_count,
         (unsigned long long)p.domain_set_sparse_count,
         p.domain_set_density_sum,
         (unsigned long long)p.block_words_blocks_allocated,
         (unsigned long long)p.block_words_total_blocks,
         p.block_words_dense_bytes,
         (unsigned long long)p.block_words_nblocks,
         (unsigned long long)p.block_words_nwords_per_block,
         (unsigned long long)p.proj_sig_count,
         (unsigned long long)p.proj_sig_total,
         (unsigned long long)p.proj_sig_new,
         (unsigned long long)p.proj_sig_skipped,
         (unsigned long long)p.proj_mask_or_ops,
         (unsigned long long)p.proj_rid_iters,
         (unsigned long long)p.proj_rid_iters_scan_enforcement,
         (unsigned long long)p.proj_rid_iters_dependency,
         (unsigned long long)p.canon_term_map_cache_hits,
         (unsigned long long)p.canon_term_map_cache_misses,
         p.canon_term_map_build_ms,
         p.canon_term_map_bytes,
         p.restrict_key_index_build_ms,
         (unsigned long long)p.restrict_key_index_entries,
         p.restrict_key_index_bytes,
         p.restrict_key_prune_ms,
         (unsigned long long)p.sigmask_cache_hits,
         (unsigned long long)p.sigmask_cache_misses,
         p.sigmask_build_ms,
         p.sigmask_bytes,
         p.bytes_sig_ctid_masks,
         p.bytes_block_words,
         p.bytes_artifact_buffers_retained,
         p.bytes_decoded_buffers_retained,
         (unsigned long long)p.witness_activesig_tables,
         (unsigned long long)p.witness_sig_count_total,
         p.support_recompute_ms,
         p.sig_prune_ms,
         (unsigned long long)p.pair_bundle_count,
         p.pair_bundle_build_ms,
         p.pair_bundle_prune_ms,
         (unsigned long long)p.pair_bundle_keys_total,
         (unsigned long long)p.pair_bundle_pruned_sigs_total,
         (unsigned long long)p.pair_bundle_iters,
         (unsigned long long)p.qual_atoms_total,
         (unsigned long long)p.qual_atoms_applied,
         (unsigned long long)p.qual_pruned_sigs,
         p.qual_prune_ms,
         (unsigned long long)p.restrict_sig_tables,
         (unsigned long long)p.restrict_sig_schema_cols_total,
         p.restrict_sig_bytes_total,
         p.restrict_sig_apply_ms,
         p.restrict_term_apply_ms,
         (unsigned long long)p.restrict_term_sigs_kept,
         (unsigned long long)p.restrict_term_sigs_dropped,
         (unsigned long long)p.pf2_enabled_targets,
         (unsigned long long)p.pf2_terms_total,
         (unsigned long long)p.pf2_terms_supported,
         (unsigned long long)p.pf2_terms_single_hub,
         (unsigned long long)p.pf2_terms_two_hop,
         (unsigned long long)p.pf2_terms_tree,
         (unsigned long long)p.pf2_terms_failed_shape,
         (long long)p.pf2_hub_domain_id,
         (unsigned long long)p.pf2_hub_key_arity,
         (unsigned long long)p.pf2_ntokens,
         (unsigned long long)p.pf2_stamp_rows_scanned_total,
         (unsigned long long)p.pf2_stamp_rows_scanned_A,
         (unsigned long long)p.pf2_stamp_rows_scanned_B,
         p.pf2_stamp_ms,
         p.pf2_stamp_ms_A,
         p.pf2_stamp_ms_B,
         p.pf2_tok_and_or_ms,
         p.pf2_tok_compose_ms,
         (unsigned long long)p.pf2_project_bin_rids_total,
         p.pf2_project_ms,
         (unsigned long long)p.pf2_tree_domains,
         (unsigned long long)p.pf2_tree_tables,
         (unsigned long long)p.pf2_tree_edges,
         (unsigned long long)p.pf2_tree_passes,
         (unsigned long long)p.pf2_tree_table_updates,
         (unsigned long long)p.pf2_tree_rows_scanned_total,
         p.pf2_tree_update_ms,
         p.pf2_tree_project_ms,
         (unsigned long long)p.pf2_cmp_total,
         (unsigned long long)p.pf2_cmp_supported,
         (unsigned long long)p.pf2_cmp_key_arity_max,
         p.pf2_cmp_summary_build_ms,
         (unsigned long long)p.pf2_cmp_summary_keys_total,
         (unsigned long long)p.pf2_cmp_checks_total,
         (unsigned long long)p.pf2_cmp_rejects_total,
         (unsigned long long)p.pf2_cmp_key2_entries,
         p.pf2_cmp_key2_dense_bytes,
         p.pf2_cmp_key2_build_ms,
         (unsigned long long)p.pf2_cmp_key2_rows_scanned,
         (unsigned long long)p.pf2_cmp_key2_updates,
         (unsigned long long)p.pf2_cmp_key2_lookups,
         (unsigned long long)p.pf2_cmp_witness_witness_total,
         (unsigned long long)p.pf2_cmp_witness_witness_supported,
         (unsigned long long)p.pf2_cmp_filter_rows_checked,
         (unsigned long long)p.pf2_cmp_filter_rows_reject,
         (unsigned long long)p.pf2_cmp_chain_total,
         (unsigned long long)p.pf2_cmp_chain_supported,
         p.pf2_cmp_chain_build_ms,
         (unsigned long long)p.pf2_cmp_chain_bridge_rows_scanned,
         (unsigned long long)p.pf2_cmp_chain_compose_steps,
         (unsigned long long)p.pf2_cmp_chain_filter_rows_checked,
         (unsigned long long)p.pf2_cmp_chain_filter_rows_reject,
         p.pf2_total_ms,
         (unsigned long long)p.class_td_terms_total,
         (unsigned long long)p.class_td_terms_supported,
         (unsigned long long)p.class_td_width_max,
         (unsigned long long)p.class_td_bags,
         p.class_td_build_ms,
         p.class_td_dp_ms,
         (unsigned long long)p.class_td_msg_entries_total,
         (unsigned long long)p.class_td_msg_bytes_total,
         (unsigned long long)p.class_td_msg_pairs_total,
         p.class_td_join_ms,
         p.class_td_project_ms,
         (unsigned long long)p.class_td_reduction_passes,
         p.class_td_reduction_ms,
         (unsigned long long)p.class_td_reduction_removed_pairs,
         (unsigned long long)p.class_td_pairs_before,
         (unsigned long long)p.class_td_pairs_after,
         (unsigned long long)p.class_td_elim_order,
         (unsigned long long)p.class_td_peak_msg_pairs,
         (unsigned long long)p.class_td_peak_msg_bytes,
         p.class_td_cmp_filter_ms,
         (unsigned long long)p.class_td_cmp_filter_removed_pairs,
         (unsigned long long)p.class_td_fail_width,
         (unsigned long long)p.class_terms_ok,
         (unsigned long long)p.class_terms_reject,
         (unsigned long long)p.class_route_single_hub,
         (unsigned long long)p.class_route_two_hop,
         (unsigned long long)p.class_route_tree,
         (unsigned long long)p.class_route_cycle_rect,
         (unsigned long long)p.class_route_td_cycle,
         (unsigned long long)p.class_route_reject);
}

static bool load_phase(const PolicyArtifactC *arts,
                       int art_count,
                       const PolicyEngineInputC *in,
                       Loaded *out,
                       BuildProfile *profile)
{
    if (!arts || art_count <= 0 || !in || !out || !profile)
        return false;

    auto t0 = Clock::now();

    if (!load_atoms(in, out))
        return false;
    if (!load_artifact_metadata(arts, art_count, out))
        return false;

    for (int i = 0; i < in->target_count; i++) {
        if (!in->target_tables || !in->target_tables[i])
            continue;
        std::string target = in->target_tables[i];
        out->target_order.push_back(target);
        const char *ast = (in->target_asts && in->target_asts[i]) ? in->target_asts[i] : "";
        const char *perm_ast = (in->target_perm_asts && in->target_perm_asts[i]) ? in->target_perm_asts[i] : "";
        const char *rest_ast = (in->target_rest_asts && in->target_rest_asts[i]) ? in->target_rest_asts[i] : "";
        if (in->target_perm_asts || in->target_rest_asts) {
            if (!compile_target_plan_factored(target, ast, perm_ast, rest_ast, in, out, profile))
                return false;
        } else {
            if (!compile_target_plan(target, ast, out, profile))
                return false;
        }
    }

    for (auto &tkv : out->targets) {
        for (auto &cl : tkv.second.clauses) {
            if (!bind_clause_views(&cl, out))
                return false;
        }
        for (auto &clset : tkv.second.restrictive_clause_sets) {
            for (auto &cl : clset) {
                if (!bind_clause_views(&cl, out))
                    return false;
            }
        }
        if (!bind_target_local_views(&tkv.second, out))
            return false;
    }

    for (auto &kv : out->tables) {
        if (!decode_table_needed_columns(&kv.second,
                                         &out->artifacts,
                                         &out->class_domain,
                                         out->join_class_by_col)) {
            return false;
        }
    }

    for (auto &tkv : out->targets) {
        for (auto &cl : tkv.second.clauses) {
            if (!bind_clause_views(&cl, out))
                return false;
        }
        for (auto &clset : tkv.second.restrictive_clause_sets) {
            for (auto &cl : clset) {
                if (!bind_clause_views(&cl, out))
                    return false;
            }
        }
        if (!bind_target_local_views(&tkv.second, out))
            return false;
    }

    profile->bytes_decoded_buffers_retained = estimate_decoded_columns_bytes(*out);
    release_loaded_artifact_buffers(out);
    profile->bytes_artifact_buffers_retained = estimate_artifact_store_bytes(out->artifacts);

    auto t1 = Clock::now();
    profile->artifact_parse_ms = Ms(t1 - t0).count();
    CF_TRACE_LOG("policy: load_ms=%.3f", profile->artifact_parse_ms);
    return true;
}

static bool extract_term_from_selector_model(const BoolAst *node,
                                             Cvc5CnfSolver *solver,
                                             const std::unordered_map<const BoolAst *, int> &selector_by_or,
                                             std::vector<int> *out_term,
                                             bool *out_true)
{
    if (!solver || !out_term || !out_true)
        return false;
    if (!node) {
        *out_true = false;
        return true;
    }

    if (node->type == AstType::VAR) {
        bool v = false;
        if (node->var_id > 0) {
            if (!solver->model_value(node->var_id, &v))
                return false;
            if (v)
                out_term->push_back(node->var_id);
        }
        *out_true = v;
        return true;
    }

    if (node->type == AstType::AND) {
        bool lt = false;
        bool rt = false;
        if (!extract_term_from_selector_model(node->left, solver, selector_by_or, out_term, &lt))
            return false;
        if (!extract_term_from_selector_model(node->right, solver, selector_by_or, out_term, &rt))
            return false;
        *out_true = (lt && rt);
        return true;
    }

    auto it_sel = selector_by_or.find(node);
    if (it_sel == selector_by_or.end())
        return false;
    bool pick_left = true;
    if (!solver->model_value(it_sel->second, &pick_left))
        return false;
    const BoolAst *chosen = pick_left ? node->left : node->right;
    bool child_true = false;
    if (!extract_term_from_selector_model(chosen, solver, selector_by_or, out_term, &child_true))
        return false;
    *out_true = child_true;
    return true;
}

static bool block_decision_clause(Cvc5CnfSolver *solver, const std::vector<int> &decision_lits)
{
    if (!solver)
        return false;
    std::vector<int> cl;
    cl.reserve(decision_lits.size());
    for (int lit : decision_lits)
        cl.push_back(-lit);
    std::sort(cl.begin(), cl.end());
    cl.erase(std::unique(cl.begin(), cl.end()), cl.end());
    if (cl.empty())
        return solver->add_clause({});
    return solver->add_clause(cl);
}

static inline void rid_bits_or_inplace(std::vector<uint8_t> *dst, const std::vector<uint8_t> &src)
{
    if (!dst)
        return;
    size_t n = std::min(dst->size(), src.size());
    for (size_t i = 0; i < n; i++)
        (*dst)[i] |= src[i];
}

static inline void rid_bits_and_inplace(std::vector<uint8_t> *dst, const std::vector<uint8_t> &src)
{
    if (!dst)
        return;
    size_t n = std::min(dst->size(), src.size());
    for (size_t i = 0; i < n; i++)
        (*dst)[i] &= src[i];
    for (size_t i = n; i < dst->size(); i++)
        (*dst)[i] = 0;
}

static int domain_id_for_table_col_idx(const Loaded &loaded,
                                       const ClauseTablePlan &tp,
                                       const TableData &ti,
                                       int col_idx)
{
    for (const auto &cg : tp.class_groups) {
        for (int idx : cg.col_idxs) {
            if (idx == col_idx)
                return cg.domain_id;
        }
    }
    if (col_idx >= 0 && (size_t)col_idx < ti.meta_cols.size()) {
        auto it = loaded.col_domain_by_col.find(ti.meta_cols[(size_t)col_idx]);
        if (it != loaded.col_domain_by_col.end())
            return it->second;
    }
    return -1;
}

static bool build_predicate_rid_bits_from_bins(const Loaded &loaded,
                                               const ClauseTablePlan &tp,
                                               const TableData &ti,
                                               const ClausePredicate &pred,
                                               BuildProfile *profile,
                                               std::vector<uint8_t> *out_bits)
{
    if (!out_bits)
        return false;
    out_bits->assign((ti.nrows + 7u) / 8u, 0);
    int domain_id = domain_id_for_table_col_idx(loaded, tp, ti, pred.col_idx);
    if (domain_id < 0)
        return false;

    pred.allowed.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
if (tok_i32 < 0)
            return;
        const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, tp.table, domain_id, tok_i32, &rid_ptr, &rid_len)) {
            ereport(ERROR,
                    (errmsg("policy: bin slice lookup failed table=%s domain=%d tok=%d",
                            tp.table.c_str(), domain_id, tok_i32)));
        }
        if (profile) {
            profile->bins_touched_total++;
            profile->bin_rids_scanned_total += (uint64)rid_len;
            profile->bin_ops_total++;
            profile->pf2_project_bin_rids_total += (uint64)rid_len;
        }
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (rid < ti.nrows)
                rid_bit_set(out_bits->data(), rid);
        }
    });
    return true;
}

static bool maybe_eval_single_table_const_term_bin_only(const Loaded &loaded,
                                                        const std::string &target,
                                                        const ClausePlan &cl,
                                                        const ClauseTablePlan &target_tp,
                                                        const TableData &target_ti,
                                                        BuildProfile *profile,
                                                        SparseBlockWords *out_words,
                                                        std::vector<uint8_t> *out_rid_bits,
                                                        bool *out_term_has_rows,
                                                        bool *out_applied)
{
    if (out_applied)
        *out_applied = false;
    if (!profile || !out_words)
        return false;
    if (!(cl.tables.size() == 1 && cl.tables[0].table == target))
        return true;
    if (!cl.compares.empty())
        return true;

    for (int aid : cl.atom_ids) {
        auto ita = loaded.atoms_by_id.find(aid);
        if (ita == loaded.atoms_by_id.end())
            return false;
        const Atom &a = ita->second;
        if (a.kind != AtomKind::CONST || a.left.table != target)
            return true;
    }

    out_words->clear();
    out_words->total_blocks = target_ti.total_blocks;
    std::vector<uint8_t> accum;
    bool have_accum = false;

    if (target_tp.predicates.empty()) {
        build_all_allowed_for_target(target_ti, nullptr, out_words, out_rid_bits);
        if (out_term_has_rows)
            *out_term_has_rows = out_words->any();
        if (out_applied)
            *out_applied = true;
        return true;
    }

    for (const ClausePredicate &pred : target_tp.predicates) {
        std::vector<uint8_t> pred_bits;
        if (!build_predicate_rid_bits_from_bins(loaded, target_tp, target_ti, pred, profile, &pred_bits))
            return false;
        if (!have_accum) {
            accum = std::move(pred_bits);
            have_accum = true;
        } else {
            rid_bits_and_inplace(&accum, pred_bits);
        }
    }

    if (!have_accum)
        accum.assign((target_ti.nrows + 7u) / 8u, 0);

    uint32 kept_rows = 0;
    for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if (!rid_bit_test(accum.data(), rid))
            continue;
        if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
            continue;
        (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
        kept_rows++;
    }
    if (out_rid_bits)
        *out_rid_bits = std::move(accum);
    if (out_term_has_rows)
        *out_term_has_rows = (kept_rows > 0);

    profile->pf2_terms_supported++;
    profile->pf2_terms_single_hub++;
    if (out_applied)
        *out_applied = true;
    return true;
}

static bool build_const_atom_rid_bits_target(const Loaded &loaded,
                                             const std::string &target,
                                             const TableData &target_ti,
                                             const Atom &a,
                                             BuildProfile *profile,
                                             std::vector<uint8_t> *out_bits)
{
    if (!out_bits)
        return false;
    out_bits->assign((target_ti.nrows + 7u) / 8u, 0);
    if (a.kind != AtomKind::CONST || a.left.table != target)
        return false;

    int domain_id = a.join_class_id;
    if (domain_id < 0) {
        auto it_dom = loaded.col_domain_by_col.find(a.left.key());
        if (it_dom != loaded.col_domain_by_col.end())
            domain_id = it_dom->second;
    }
    if (domain_id < 0)
        return false;

    const std::vector<std::string> *dict_vals = nullptr;
    DictType dtype = DictType::TEXT;
    bool sorted = false;
    auto itd = loaded.domain_dicts.find(domain_id);
    if (itd != loaded.domain_dicts.end()) {
        dict_vals = &itd->second;
        auto itdt = loaded.domain_dict_types.find(domain_id);
        if (itdt != loaded.domain_dict_types.end())
            dtype = itdt->second;
        sorted = (loaded.domain_dict_sorted.find(domain_id) != loaded.domain_dict_sorted.end());
    }
    if (!dict_vals)
        return false;

    TokenBitset allowed = build_allowed_token_set(a, *dict_vals, dtype, sorted);
    if (!allowed.any())
        return true;

    allowed.for_each_set([&](int32_t tok_i32) {
        CHECK_FOR_INTERRUPTS();
const uint32_t *rid_ptr = nullptr;
        size_t rid_len = 0;
        if (!get_bin_slice(loaded, target, domain_id, tok_i32, &rid_ptr, &rid_len)) {
            ereport(ERROR,
                    (errmsg("policy: bin slice lookup failed table=%s domain=%d tok=%d",
                            target.c_str(), domain_id, tok_i32)));
        }
        if (profile) {
            profile->bins_touched_total++;
            profile->bin_rids_scanned_total += (uint64)rid_len;
            profile->bin_ops_total++;
            profile->pf2_project_bin_rids_total += (uint64)rid_len;
        }
        for (size_t i = 0; i < rid_len; i++) {
            PF_CHECK_FOR_INTERRUPTS((uint32)i);
uint32 rid = rid_ptr ? rid_ptr[i] : 0u;
            if (rid < target_ti.nrows)
                rid_bit_set(out_bits->data(), rid);
        }
    });
    return true;
}

static bool class_set_target_sig_bits_from_rids(const Loaded &loaded,
                                                const std::string &target,
                                                const TableData &target_ti,
                                                const std::vector<uint8_t> &rid_bits,
                                                BuildProfile *profile,
                                                TokenBitset *io_sig_bits);

static bool maybe_eval_formula_single_table_bin_fast(const Loaded &loaded,
                                                     const std::string &target,
                                                     const TableData &target_ti,
                                                     const BoolAst *formula_root,
                                                     const std::vector<int> &vars,
                                                     BuildProfile *profile,
                                                     SparseBlockWords *out_words,
                                                     std::vector<uint8_t> *out_rid_bits,
                                                     TokenBitset *out_formula_sig_bits,
                                                     bool *out_applied)
{
    if (out_applied)
        *out_applied = false;
    if (!formula_root || !profile || !out_words)
        return true;
    auto t_fast0 = Clock::now();

    std::unordered_map<int, std::vector<uint8_t>> atom_bits;
    atom_bits.reserve(vars.size() * 2u + 1u);
    for (int v : vars) {
        if (v <= 0)
            return true;
        auto ita = loaded.atoms_by_id.find(v);
        if (ita == loaded.atoms_by_id.end())
            return true;
        const Atom &a = ita->second;
        if (a.kind != AtomKind::CONST || a.left.table != target)
            return true;
        std::vector<uint8_t> bits;
        if (!build_const_atom_rid_bits_target(loaded, target, target_ti, a, profile, &bits))
            return true;
        atom_bits.emplace(v, std::move(bits));
    }

    std::unordered_map<const BoolAst *, std::vector<uint8_t>> memo;
    std::function<bool(const BoolAst *, std::vector<uint8_t> *)> eval_node =
        [&](const BoolAst *node, std::vector<uint8_t> *out_bits) -> bool {
            if (!node || !out_bits)
                return false;
            auto it_m = memo.find(node);
            if (it_m != memo.end()) {
                *out_bits = it_m->second;
                return true;
            }
            std::vector<uint8_t> bits((target_ti.nrows + 7u) / 8u, 0);
            if (node->type == AstType::VAR) {
                if (node->var_id <= 0) {
                    // conservative: var<=0 treated as false for fast-path formulas
                    bits.assign((target_ti.nrows + 7u) / 8u, 0);
                } else {
                    auto it = atom_bits.find(node->var_id);
                    if (it == atom_bits.end())
                        return false;
                    bits = it->second;
                }
            } else if (node->type == AstType::AND || node->type == AstType::OR) {
                std::vector<uint8_t> lb, rb;
                if (!eval_node(node->left, &lb) || !eval_node(node->right, &rb))
                    return false;
                bits = std::move(lb);
                if (node->type == AstType::AND)
                    rid_bits_and_inplace(&bits, rb);
                else
                    rid_bits_or_inplace(&bits, rb);
                if (profile)
                    profile->bin_ops_total++;
            } else {
                return false;
            }
            memo.emplace(node, bits);
            *out_bits = std::move(bits);
            return true;
        };

    std::vector<uint8_t> formula_bits;
    if (!eval_node(formula_root, &formula_bits))
        return true;

    out_words->clear();
    out_words->total_blocks = target_ti.total_blocks;
    for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if (!rid_bit_test(formula_bits.data(), rid))
            continue;
        if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
            continue;
        (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
    }
    if (out_rid_bits)
        *out_rid_bits = formula_bits;

    if (out_formula_sig_bits) {
        if (!class_set_target_sig_bits_from_rids(loaded,
                                                 target,
                                                 target_ti,
                                                 formula_bits,
                                                 profile,
                                                 out_formula_sig_bits)) {
            return false;
        }
    }

    profile->terms_total++;
    profile->term_eval_ms_total += Ms(Clock::now() - t_fast0).count();
    profile->class_terms_ok++;
    profile->class_route_single_hub++;
    log_class_route_notice(target, vars, ClassRouteKind::SINGLE_HUB, "single_table_formula_bin_fast");

    if (out_applied)
        *out_applied = true;
    return true;
}

static uint32 popcount_sparse_words_flat(const std::vector<uint64_t> &words_flat)
{
    uint64 total = 0;
    for (uint64_t w : words_flat)
        total += (uint64)__builtin_popcountll(w);
    if (total > std::numeric_limits<uint32>::max())
        return std::numeric_limits<uint32>::max();
    return (uint32)total;
}

static void build_all_allowed_for_target(const TableData &target_ti,
                                         const uint8 *target_rbits,
                                         SparseBlockWords *out_words,
                                         std::vector<uint8_t> *out_rid_bits)
{
    if (!out_words)
        return;
    out_words->clear();
    out_words->total_blocks = target_ti.total_blocks;
    if (out_rid_bits)
        out_rid_bits->assign((target_ti.nrows + 7u) / 8u, 0);
    for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if (target_rbits && !rid_bit_test(target_rbits, rid))
            continue;
        if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
            continue;
        (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
        if (out_rid_bits)
            rid_bit_set(out_rid_bits->data(), rid);
    }
}

static void copy_sparse_words(const SparseBlockWords &src, SparseBlockWords *dst)
{
    if (!dst)
        return;
    dst->total_blocks = src.total_blocks;
    dst->dense_words = src.dense_words;
}

static bool class_set_target_sig_bits_from_rids(const Loaded &loaded,
                                                const std::string &target,
                                                const TableData &target_ti,
                                                const std::vector<uint8_t> &rid_bits,
                                                BuildProfile *profile,
                                                TokenBitset *io_sig_bits)
{
    if (!io_sig_bits)
        return true;
    std::vector<int> canon_schema = table_needed_signature_schema(target_ti);
    const SignatureCacheEntry *canon_entry = nullptr;
    if (!get_or_build_signature_cache_entry_with_schema(loaded, target, target_ti, canon_schema, &canon_entry, profile))
        return false;
    if (!canon_entry)
        return false;
    std::vector<int32_t> row_to_sid(target_ti.nrows, -1);
    for (uint32 sid = 0; sid < canon_entry->nsig; sid++) {
        uint32 b = canon_entry->row_offsets[(size_t)sid];
        uint32 e = canon_entry->row_offsets[(size_t)sid + 1u];
        for (uint32 p = b; p < e; p++) {
            uint32 rid = canon_entry->rows_flat[(size_t)p];
            if (rid < row_to_sid.size())
                row_to_sid[(size_t)rid] = (int32_t)sid;
        }
    }
    for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
        PF_CHECK_FOR_INTERRUPTS(rid);
if (!rid_bit_test(rid_bits.data(), rid))
            continue;
        int32_t sid = row_to_sid[(size_t)rid];
        if (sid >= 0)
            io_sig_bits->set((size_t)sid);
    }
    io_sig_bits->adapt_representation();
    return true;
}

static bool eval_term_conjunction_words(const Loaded &loaded,
                                        const std::string &target,
                                        const std::vector<int> &term_atoms,
                                        const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                        BuildProfile *profile,
                                        std::unordered_map<std::string, TokenBitset> *already_projected_sig_by_schema,
                                        SparseBlockWords *out_words,
                                        std::vector<uint8_t> *out_rid_bits,
                                        TokenBitset *out_term_canon_sig_bits,
                                        bool *out_term_has_rows,
                                        bool *out_prop_conflict)
{
    if (out_term_has_rows)
        *out_term_has_rows = false;
    if (out_prop_conflict)
        *out_prop_conflict = false;
    if (!profile || !out_words)
        return false;

    auto it_target = loaded.tables.find(target);
    if (it_target == loaded.tables.end())
        return false;
    const TableData &target_ti = it_target->second;
    (void)already_projected_sig_by_schema;
    if (out_term_canon_sig_bits) {
        std::vector<int> canon_schema = table_needed_signature_schema(target_ti);
        const SignatureCacheEntry *canon_entry = nullptr;
        if (!get_or_build_signature_cache_entry_with_schema(loaded,
                                                            target,
                                                            target_ti,
                                                            canon_schema,
                                                            &canon_entry,
                                                            profile))
            return false;
        if (!canon_entry)
            return false;
        out_term_canon_sig_bits->reset((size_t)canon_entry->nsig);
        out_term_canon_sig_bits->clear_all();
    }
    out_words->clear();
    out_words->total_blocks = target_ti.total_blocks;
    if (out_rid_bits)
        out_rid_bits->assign((target_ti.nrows + 7u) / 8u, 0);

    const uint8 *target_rbits = nullptr;

    if (term_atoms.empty()) {
        for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if (target_rbits && !rid_bit_test(target_rbits, rid))
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
        }
        if (out_term_has_rows)
            *out_term_has_rows = out_words->any();
        if (out_term_canon_sig_bits && out_words->any()) {
            out_term_canon_sig_bits->fill_all();
            out_term_canon_sig_bits->adapt_representation();
        }
        return true;
    }

    DnfTerm t = term_atoms;
    normalize_term(&t);
    DnfList dnf_terms;
    dnf_terms.push_back(std::move(t));

    std::vector<ClausePlan> plans;
    if (!append_clause_plans_from_dnf(target, dnf_terms, const_cast<Loaded *>(&loaded), &plans))
        return false;
    if (plans.empty())
        return true;

    ClausePlan cl = std::move(plans[0]);
    if (!bind_clause_views(&cl, const_cast<Loaded *>(&loaded)))
        return false;

    if (cl.unsat) {
        if (out_prop_conflict)
            *out_prop_conflict = true;
        return true;
    }

    const ClauseTablePlan *target_tp = nullptr;
    bool clause_global_ok = true;
    for (const auto &tp_tbl : cl.tables) {
        auto it_t = loaded.tables.find(tp_tbl.table);
        if (it_t == loaded.tables.end())
            return false;
        const TableData &ti = it_t->second;

        if (tp_tbl.table == target)
            target_tp = &tp_tbl;

        if (tp_tbl.table != target && tp_tbl.class_groups.empty()) {
            if (!table_has_predicate_witness(tp_tbl, loaded, ti, restrict_sigs, nullptr)) {
                clause_global_ok = false;
                break;
            }
        }
    }
    if (!clause_global_ok) {
        if (out_prop_conflict)
            *out_prop_conflict = true;
        return true;
    }

    if (!cl.target_present || !target_tp) {
        for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if (target_rbits && !rid_bit_test(target_rbits, rid))
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
        }
        if (out_term_has_rows)
            *out_term_has_rows = out_words->any();
        if (out_term_canon_sig_bits && out_words->any()) {
            out_term_canon_sig_bits->fill_all();
            out_term_canon_sig_bits->adapt_representation();
        }
        return true;
    }

    if (profile)
        profile->pf2_terms_total++;

    std::vector<uint8_t> local_rid_bits;
    std::vector<uint8_t> *route_rid_bits = out_rid_bits;
    if (!route_rid_bits && out_term_canon_sig_bits) {
        local_rid_bits.assign((target_ti.nrows + 7u) / 8u, 0);
        route_rid_bits = &local_rid_bits;
    }

    if (cl.tables.size() == 1 && cl.tables[0].table == target) {
        bool applied_bin_only = false;
        auto t_term0 = Clock::now();
        if (!maybe_eval_single_table_const_term_bin_only(loaded,
                                                         target,
                                                         cl,
                                                         *target_tp,
                                                         target_ti,
                                                         profile,
                                                         out_words,
                                                         route_rid_bits,
                                                         out_term_has_rows,
                                                         &applied_bin_only)) {
            return false;
        }
        if (applied_bin_only) {
            profile->class_terms_ok++;
            profile->class_route_single_hub++;
            log_class_route_notice(target, term_atoms, ClassRouteKind::SINGLE_HUB, "single_table_bin_only");
            profile->term_eval_ms_total += Ms(Clock::now() - t_term0).count();
            if (out_term_canon_sig_bits &&
                !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
                return false;
            return true;
        }
    }

    if (target_tp->class_groups.empty() ||
        (cl.tables.size() == 1 && cl.tables[0].table == target)) {
        std::vector<Pf2LocalComparator> target_local_cmps;
        bool unsupported_cross_cmp = false;
        if (!pf2_map_local_comparators_for_table(cl,
                                                 *target_tp,
                                                 &target_local_cmps,
                                                 &unsupported_cross_cmp,
                                                 /*allow_local_target_cmps=*/true)) {
            return false;
        }
        if (unsupported_cross_cmp) {
            profile->pf2_terms_failed_shape++;
            profile->class_terms_reject++;
            profile->class_route_reject++;
            log_class_route_notice(target, term_atoms, ClassRouteKind::REJECT, "target_local_unsupported_cmp");
            ereport(ERROR,
                    (errmsg("policy: class_engine unsupported local comparator shape on target=%s", target.c_str())));
        }
        for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if (profile)
                profile->heap_rows_scanned_total++;
            if (target_rbits && !rid_bit_test(target_rbits, rid))
                continue;
            if (!pf2_row_matches_table_local_atoms(*target_tp, target_local_cmps, rid))
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            if (!out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]))
                continue;
            if (route_rid_bits)
                rid_bit_set(route_rid_bits->data(), rid);
        }
        profile->class_terms_ok++;
        profile->class_route_single_hub++;
        log_class_route_notice(target, term_atoms, ClassRouteKind::SINGLE_HUB, "target_local_only");
        if (out_term_has_rows)
            *out_term_has_rows = out_words->any();
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }

    bool pf2_supported = false;
    bool pf2_has_rows = false;
    std::string route_failures;
    auto mark_route_fail = [&](const char *route, const char *why) {
        if (!route || !route[0])
            return;
        if (!route_failures.empty())
            route_failures.push_back(';');
        route_failures += route;
        if (why && why[0]) {
            route_failures.push_back(':');
            route_failures += why;
        }
    };
    auto record_ok_route = [&](ClassRouteKind r) {
        profile->class_terms_ok++;
        switch (r) {
            case ClassRouteKind::SINGLE_HUB: profile->class_route_single_hub++; break;
            case ClassRouteKind::TWO_HOP: profile->class_route_two_hop++; break;
            case ClassRouteKind::TREE: profile->class_route_tree++; break;
            case ClassRouteKind::CYCLE_RECT: profile->class_route_cycle_rect++; break;
            case ClassRouteKind::TD_CYCLE: profile->class_route_td_cycle++; break;
            case ClassRouteKind::REJECT: profile->class_route_reject++; break;
        }
        log_class_route_notice(target, term_atoms, r);
    };

    if (!eval_term_conjunction_pf2_single_hub(loaded,
                                              target,
                                              cl,
                                              *target_tp,
                                              target_ti,
                                              restrict_sigs,
                                              profile,
                                              out_words,
                                              route_rid_bits,
                                              &pf2_has_rows,
                                              &pf2_supported))
        return false;
    if (pf2_supported) {
        record_ok_route(ClassRouteKind::SINGLE_HUB);
        if (out_term_has_rows)
            *out_term_has_rows = pf2_has_rows;
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }
    mark_route_fail("single_hub", "no_match_or_unsupported");

    if (!eval_term_conjunction_pf2_two_hop(loaded,
                                           target,
                                           cl,
                                           *target_tp,
                                           target_ti,
                                           restrict_sigs,
                                           profile,
                                           out_words,
                                           route_rid_bits,
                                           &pf2_has_rows,
                                           &pf2_supported))
        return false;
    if (pf2_supported) {
        record_ok_route(ClassRouteKind::TWO_HOP);
        if (out_term_has_rows)
            *out_term_has_rows = pf2_has_rows;
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }
    mark_route_fail("two_hop", "no_match_or_unsupported");

    if (!eval_term_conjunction_pf2_cycle_rect(loaded,
                                              target,
                                              cl,
                                              *target_tp,
                                              target_ti,
                                              restrict_sigs,
                                              profile,
                                              out_words,
                                              route_rid_bits,
                                              &pf2_has_rows,
                                              &pf2_supported))
        return false;
    if (pf2_supported) {
        record_ok_route(ClassRouteKind::CYCLE_RECT);
        if (out_term_has_rows)
            *out_term_has_rows = pf2_has_rows;
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }
    mark_route_fail("cycle_rect", "no_match_or_unsupported");

    if (!eval_term_conjunction_pf2_td_cycle(loaded,
                                            target,
                                            cl,
                                            *target_tp,
                                            target_ti,
                                            restrict_sigs,
                                            profile,
                                            out_words,
                                            route_rid_bits,
                                            &pf2_has_rows,
                                            &pf2_supported))
        return false;
    if (pf2_supported) {
        profile->class_terms_ok++;
        profile->class_route_td_cycle++;
        log_class_route_notice(target,
                               term_atoms,
                               ClassRouteKind::TD_CYCLE,
                               "",
                               (int)profile->class_td_last_width,
                               (int)profile->class_td_last_bags);
        if (out_term_has_rows)
            *out_term_has_rows = pf2_has_rows;
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }
    mark_route_fail("td_cycle", "no_match_or_unsupported");

    if (!eval_term_conjunction_pf2_tree(loaded,
                                        target,
                                        cl,
                                        *target_tp,
                                        target_ti,
                                        restrict_sigs,
                                        profile,
                                        out_words,
                                        route_rid_bits,
                                        &pf2_has_rows,
                                        &pf2_supported))
        return false;
    if (pf2_supported) {
        record_ok_route(ClassRouteKind::TREE);
        if (out_term_has_rows)
            *out_term_has_rows = pf2_has_rows;
        if (out_term_canon_sig_bits &&
            !class_set_target_sig_bits_from_rids(loaded, target, target_ti, *route_rid_bits, profile, out_term_canon_sig_bits))
            return false;
        return true;
    }
    mark_route_fail("tree", "no_match_or_unsupported");

    profile->pf2_terms_failed_shape++;
    profile->class_terms_reject++;
    profile->class_route_reject++;
    std::string table_shape;
    for (size_t i = 0; i < cl.tables.size(); i++) {
        const auto &tp = cl.tables[i];
        if (!table_shape.empty())
            table_shape.push_back(';');
        table_shape += tp.table;
        table_shape += "(groups=" + std::to_string(tp.class_groups.size()) +
                       ",preds=" + std::to_string(tp.predicates.size()) + ")";
    }
    std::string cmp_shape;
    for (size_t i = 0; i < cl.compares.size(); i++) {
        const auto &cp = cl.compares[i];
        if (!cmp_shape.empty())
            cmp_shape.push_back(';');
        cmp_shape += "a" + std::to_string(cp.atom_id) +
                     "(l=" + std::to_string(cp.left_pos) +
                     ",r=" + std::to_string(cp.right_pos) +
                     ",d=" + std::to_string(cp.domain_id) +
                     ",op=" + std::to_string((int)cp.op) + ")";
    }
    elog(NOTICE,
         "class_route_reject_debug: target=%s atom_ids=%zu tables=%s join_vars=%zu has_join=%d has_colcmp=%d compares=%s route_failures=%s",
         target.c_str(),
         cl.atom_ids.size(),
         table_shape.empty() ? "-" : table_shape.c_str(),
         cl.join_classes.size(),
         cl.has_join_atom ? 1 : 0,
         cl.has_colcmp_atom ? 1 : 0,
         cmp_shape.empty() ? "-" : cmp_shape.c_str(),
         route_failures.empty() ? "-" : route_failures.c_str());
    log_class_route_notice(target,
                           term_atoms,
                           ClassRouteKind::REJECT,
                           route_failures.empty() ? "unsupported_term_shape" : route_failures.c_str());
    ereport(ERROR,
            (errmsg("policy: class_engine unsupported term shape on target=%s", target.c_str()),
             errhint("strict experimental mode allows only class_engine supported shapes")));
}

static bool eval_formula_root_words(const Loaded &loaded,
                                    const std::string &target,
                                    const TableData &target_ti,
                                    const BoolAst *formula_root,
                                    const uint8 *target_rbits,
                                    const std::unordered_map<std::string, RestrictSigState> *restrict_sigs,
                                    BuildProfile *profile,
                                    SparseBlockWords *out_words,
                                    std::vector<uint8_t> *out_rid_bits,
                                    TokenBitset *out_formula_sig_bits)
{
    if (!profile || !out_words)
        return false;

    out_words->clear();
    out_words->total_blocks = target_ti.total_blocks;
    if (out_rid_bits)
        out_rid_bits->assign((target_ti.nrows + 7u) / 8u, 0);
    if (out_formula_sig_bits) {
        out_formula_sig_bits->reset(0);
        out_formula_sig_bits->clear_all();
    }
    if (!formula_root) {
        for (uint32 rid = 0; rid < target_ti.nrows; rid++) {
            PF_CHECK_FOR_INTERRUPTS(rid);
if (target_rbits && !rid_bit_test(target_rbits, rid))
                continue;
            if ((size_t)rid >= target_ti.ctid_blk.size() || (size_t)rid >= target_ti.ctid_off.size())
                continue;
            (void)out_words->set_ctid(target_ti.ctid_blk[(size_t)rid], target_ti.ctid_off[(size_t)rid]);
            if (out_rid_bits)
                rid_bit_set(out_rid_bits->data(), rid);
        }
        if (out_formula_sig_bits) {
            std::vector<int> canon_schema = table_needed_signature_schema(target_ti);
            const SignatureCacheEntry *canon_entry = nullptr;
            if (!get_or_build_signature_cache_entry_with_schema(loaded,
                                                                target,
                                                                target_ti,
                                                                canon_schema,
                                                                &canon_entry,
                                                                profile)) {
                return false;
            }
            if (!canon_entry)
                return false;
            out_formula_sig_bits->reset((size_t)canon_entry->nsig);
            out_formula_sig_bits->fill_all();
            out_formula_sig_bits->adapt_representation();
        }
        return true;
    }

    auto t_proj0 = Clock::now();
    std::vector<int> vars;
    collect_ast_positive_vars(formula_root, &vars);

    bool single_table_fast_applied = false;
    if (!maybe_eval_formula_single_table_bin_fast(loaded,
                                                  target,
                                                  target_ti,
                                                  formula_root,
                                                  vars,
                                                  profile,
                                                  out_words,
                                                  out_rid_bits,
                                                  out_formula_sig_bits,
                                                  &single_table_fast_applied)) {
        return false;
    }
    if (single_table_fast_applied) {
        profile->project_row_ms += Ms(Clock::now() - t_proj0).count();
        profile->project_ms += Ms(Clock::now() - t_proj0).count();
        return true;
    }

    SatCnf cnf;
    CnfBuildInfo cnf_info;
    int n_input_vars = 0;
    for (int v : vars)
        n_input_vars = std::max(n_input_vars, v);
    if (!build_formula_cnf_tseitin(formula_root, n_input_vars, &cnf, &cnf_info))
        return false;
    std::unordered_map<const BoolAst *, int> selector_by_or;
    selector_by_or.reserve(cnf_info.selectors.size() * 2u + 1u);
    for (const auto &s : cnf_info.selectors)
        selector_by_or[s.node] = s.selector_var;

    if (out_formula_sig_bits) {
        std::vector<int> canon_schema = table_needed_signature_schema(target_ti);
        const SignatureCacheEntry *canon_entry = nullptr;
        if (!get_or_build_signature_cache_entry_with_schema(loaded,
                                                            target,
                                                            target_ti,
                                                            canon_schema,
                                                            &canon_entry,
                                                            profile)) {
            return false;
        }
        if (!canon_entry)
            return false;
        out_formula_sig_bits->reset((size_t)canon_entry->nsig);
        out_formula_sig_bits->clear_all();
    }

    auto t_row0 = Clock::now();
    std::unordered_map<std::string, TokenBitset> already_projected_sig_by_schema;
    already_projected_sig_by_schema.reserve(8);
    SparseBlockWords term_words;
    TokenBitset term_canon_sig_bits;

    /*
     * Fast path: formula has no OR selectors, so SAT model enumeration would
     * execute exactly one conjunction and then terminate. Skip solver startup.
     */
    if (cnf_info.selectors.empty()) {
        std::vector<int> term = vars;
        normalize_term(&term);
        bool prop_conflict = false;
        bool term_has_rows = false;
        std::vector<uint8_t> term_rids;
        std::vector<uint8_t> *term_rids_ptr = nullptr;
        if (out_rid_bits) {
            term_rids.assign((target_ti.nrows + 7u) / 8u, 0);
            term_rids_ptr = &term_rids;
        }
        auto t_term0 = Clock::now();
        profile->terms_total++;
        if (!eval_term_conjunction_words(loaded,
                                         target,
                                         term,
                                         restrict_sigs,
                                         profile,
                                         &already_projected_sig_by_schema,
                                         &term_words,
                                         term_rids_ptr,
                                         out_formula_sig_bits ? &term_canon_sig_bits : nullptr,
                                         &term_has_rows,
                                         &prop_conflict)) {
            return false;
        }
        profile->term_eval_ms_total += Ms(Clock::now() - t_term0).count();

        if (!prop_conflict) {
            (void)out_words->or_inplace(term_words);
            if (out_rid_bits)
                rid_bits_or_inplace(out_rid_bits, term_rids);
            if (out_formula_sig_bits)
                out_formula_sig_bits->bit_or(term_canon_sig_bits);
            profile->project_n_join_evals_max =
                std::max(profile->project_n_join_evals_max, 1);
            profile->project_clause_words_max =
                std::max(profile->project_clause_words_max,
                         std::max(1, (int)((term.size() + 63u) / 64u)));
        }

        if (out_formula_sig_bits)
            out_formula_sig_bits->adapt_representation();
        profile->project_row_ms += Ms(Clock::now() - t_row0).count();
        profile->project_ms += Ms(Clock::now() - t_proj0).count();
        return true;
    }

    Cvc5CnfSolver solver(cnf);
    if (!solver.ok())
        return false;

    int terms_evaluated = 0;
    std::unordered_set<std::string> seen_terms;
    seen_terms.reserve(256);

    auto collect_selector_decision_lits = [&]() -> std::vector<int> {
        std::vector<int> out;
        out.reserve(cnf_info.selectors.size());
        for (const auto &sb : cnf_info.selectors) {
            bool pick_left = true;
            if (!solver.model_value(sb.selector_var, &pick_left))
                return {};
            out.push_back(pick_left ? sb.selector_var : -sb.selector_var);
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    };

    auto t_sat0 = Clock::now();
    for (;;) {
        profile->sat_calls++;
        if (!solver.solve_with_assumptions({}))
            break;
        profile->sat_models_total++;

        std::vector<int> decision_lits = collect_selector_decision_lits();
        if (cnf_info.selectors.size() > 0 && decision_lits.empty())
            return false;
        profile->sat_decisions += (uint64)decision_lits.size();
        if (!decision_lits.empty()) {
            std::string sel;
            for (size_t i = 0; i < decision_lits.size(); i++) {
                if (i > 0)
                    sel.push_back(',');
                sel += std::to_string(decision_lits[i]);
            }
            CF_TRACE_LOG("policy: sat_model target=%s selectors=[%s]",
                         target.c_str(), sel.c_str());
        }

        std::vector<int> term;
        bool term_true = false;
        if (!extract_term_from_selector_model(formula_root,
                                              &solver,
                                              selector_by_or,
                                              &term,
                                              &term_true))
            return false;
        if (!term_true) {
            if (!block_decision_clause(&solver, decision_lits))
                return false;
            continue;
        }
        normalize_term(&term);

        std::string term_sig;
        for (size_t i = 0; i < term.size(); i++) {
            if (i > 0) term_sig.push_back(',');
            term_sig += std::to_string(term[i]);
        }
        if (!seen_terms.insert(term_sig).second) {
            if (!block_decision_clause(&solver, decision_lits))
                return false;
            continue;
        }

        bool prop_conflict = false;
        bool term_has_rows = false;
        std::vector<uint8_t> term_rids;
        std::vector<uint8_t> *term_rids_ptr = nullptr;
        if (out_rid_bits) {
            term_rids.assign((target_ti.nrows + 7u) / 8u, 0);
            term_rids_ptr = &term_rids;
        }
        auto t_term0 = Clock::now();
        profile->terms_total++;
        if (!eval_term_conjunction_words(loaded,
                                         target,
                                         term,
                                         restrict_sigs,
                                         profile,
                                         &already_projected_sig_by_schema,
                                         &term_words,
                                         term_rids_ptr,
                                         out_formula_sig_bits ? &term_canon_sig_bits : nullptr,
                                         &term_has_rows,
                                         &prop_conflict)) {
            return false;
        }
        profile->term_eval_ms_total += Ms(Clock::now() - t_term0).count();

        if (prop_conflict) {
            CF_TRACE_LOG("policy: theory_lemma_conflict target=%s selectors=%zu",
                         target.c_str(), decision_lits.size());
            profile->sat_conflicts++;
            if (!block_decision_clause(&solver, decision_lits))
                return false;
            continue;
        }

        (void)out_words->or_inplace(term_words);
        if (out_rid_bits)
            rid_bits_or_inplace(out_rid_bits, term_rids);
        if (out_formula_sig_bits)
            out_formula_sig_bits->bit_or(term_canon_sig_bits);

        terms_evaluated++;
        profile->project_n_join_evals_max =
            std::max(profile->project_n_join_evals_max, terms_evaluated);
        profile->project_clause_words_max =
            std::max(profile->project_clause_words_max,
                     std::max(1, (int)((term.size() + 63u) / 64u)));

        // Theory-lemma hook: this conjunction cannot contribute any target row.
        if (!term_has_rows) {
            if (!block_decision_clause(&solver, decision_lits))
                return false;
            continue;
        }

        // Block this selector-decision model and continue enumeration.
        if (!block_decision_clause(&solver, decision_lits))
            return false;
    }
    profile->sat_ms += Ms(Clock::now() - t_sat0).count();

    if (out_formula_sig_bits)
        out_formula_sig_bits->adapt_representation();

    profile->project_row_ms += Ms(Clock::now() - t_row0).count();
    profile->project_ms += Ms(Clock::now() - t_proj0).count();
    return true;
}

static bool build_target_allow_list(const Loaded &loaded,
                                    const TargetPlan &tp,
                                    PolicyTableAllowC *out_item,
                                    BuildProfile *profile,
                                    const std::unordered_map<std::string, RestrictSigState> *restrict_sigs = nullptr,
                                    std::vector<uint8_t> *out_rid_bits = nullptr,
                                    ClauseEvalCache *shared_cache = nullptr,
                                    RestrictSigState *out_restrict_sig = nullptr)
{
    if (!out_item || !profile)
        return false;
    (void)shared_cache;
    if (policy_runtime_strict_mode_enabled() && !out_restrict_sig)
        profile->pf2_enabled_targets++;

    auto it_t = loaded.tables.find(tp.target);
    if (it_t == loaded.tables.end()) {
        ereport(ERROR,
                (errmsg("policy: target table artifacts missing: %s", tp.target.c_str())));
    }
    const TableData &target_ti = it_t->second;
    const uint8 *target_rbits = nullptr;

    const bool allow_cache_eligible = policy_runtime_strict_mode_enabled() &&
                                      out_restrict_sig == nullptr &&
                                      target_rbits == nullptr &&
                                      !tp.target.empty();
    std::string allow_cache_key;
    if (allow_cache_eligible)
        allow_cache_key = allow_cache_key_for_target(tp, target_ti);
    if (allow_cache_eligible) {
        auto itc = g_allow_cache.find(allow_cache_key);
        if (itc != g_allow_cache.end()) {
            const AllowCacheEntry &ce = itc->second;
            size_t words_nbytes = ce.words.size() * sizeof(uint64_t);
            size_t block_ids_nbytes = ce.block_ids.size() * sizeof(uint32_t);
            uint64 *words = nullptr;
            uint32 *block_ids = nullptr;
            if (words_nbytes > 0) {
                words = (uint64 *)palloc0(words_nbytes);
                std::memcpy(words, ce.words.data(), words_nbytes);
            }
            if (block_ids_nbytes > 0) {
                block_ids = (uint32 *)palloc0(block_ids_nbytes);
                std::memcpy(block_ids, ce.block_ids.data(), block_ids_nbytes);
            }
            out_item->table = pstrdup(tp.target.c_str());
            out_item->block_words = words;
            out_item->block_ids = block_ids;
            out_item->blocks = (uint32)ce.block_ids.size();
            out_item->total_blocks = ce.total_blocks;
            out_item->n_rows = ce.n_rows;
            profile->allow_cache_hit++;
            profile->allow_rows_total += ce.allowed_rows;
            return true;
        }
        profile->allow_cache_miss++;
    }

    auto t_allow_build0 = Clock::now();
    std::vector<int> target_canon_schema = table_needed_signature_schema(target_ti);
    const SignatureCacheEntry *target_canon_entry = nullptr;
    if (out_restrict_sig) {
        if (!get_or_build_signature_cache_entry_with_schema(loaded,
                                                            tp.target,
                                                            target_ti,
                                                            target_canon_schema,
                                                            &target_canon_entry,
                                                            profile))
            return false;
        if (!target_canon_entry)
            return false;
    }
    SparseBlockWords final_words;
    final_words.total_blocks = target_ti.total_blocks;
    std::vector<uint8_t> final_rid_bits;
    const bool need_rid_bits = (out_rid_bits != nullptr);
    if (need_rid_bits)
        final_rid_bits.assign((target_ti.nrows + 7u) / 8u, 0);
    TokenBitset final_sig_bits;
    if (out_restrict_sig) {
        final_sig_bits.reset((size_t)target_canon_entry->nsig);
        final_sig_bits.clear_all();
    }

    auto fill_all_target_sigs = [&](TokenBitset *dst) {
        if (!dst || !target_canon_entry)
            return;
        dst->reset((size_t)target_canon_entry->nsig);
        dst->fill_all();
        dst->adapt_representation();
    };

    profile->clause_plan_count_max = std::max(profile->clause_plan_count_max, (int)tp.formula_atom_ids.size());
    profile->unique_join_struct_sigs_max =
        std::max(profile->unique_join_struct_sigs_max, (int)tp.formula_tables.size());
    auto combine_op_timed = [&](const std::function<void()> &fn) {
        auto t0 = Clock::now();
        fn();
        profile->combine_algebra_ms += Ms(Clock::now() - t0).count();
    };

    if (tp.deny_all) {
        final_words.clear();
        final_words.total_blocks = target_ti.total_blocks;
        if (need_rid_bits)
            std::fill(final_rid_bits.begin(), final_rid_bits.end(), 0);
        if (out_restrict_sig) {
            final_sig_bits.reset((size_t)target_canon_entry->nsig);
            final_sig_bits.clear_all();
        }
    } else if (!tp.perm_policy_roots.empty() || !tp.rest_policy_roots.empty()) {
        SparseBlockWords perm_words;
        perm_words.total_blocks = target_ti.total_blocks;
        std::vector<uint8_t> perm_rids;
        if (need_rid_bits)
            perm_rids.assign((target_ti.nrows + 7u) / 8u, 0);
        TokenBitset perm_sig_bits;
        if (out_restrict_sig) {
            perm_sig_bits.reset((size_t)target_canon_entry->nsig);
            perm_sig_bits.clear_all();
        }

        if (!tp.perm_policy_roots.empty()) {
            for (const BoolAst *pr : tp.perm_policy_roots) {
                SparseBlockWords tmp_words;
                tmp_words.total_blocks = target_ti.total_blocks;
                std::vector<uint8_t> tmp_rids;
                std::vector<uint8_t> *tmp_rids_ptr = nullptr;
                TokenBitset tmp_sig_bits;
                if (need_rid_bits) {
                    tmp_rids.assign((target_ti.nrows + 7u) / 8u, 0);
                    tmp_rids_ptr = &tmp_rids;
                }
                if (!eval_formula_root_words(loaded,
                                             tp.target,
                                             target_ti,
                                             pr,
                                             target_rbits,
                                             restrict_sigs,
                                             profile,
                                             &tmp_words,
                                             tmp_rids_ptr,
                                             out_restrict_sig ? &tmp_sig_bits : nullptr))
                    return false;
                combine_op_timed([&]() { (void)perm_words.or_inplace(tmp_words); });
                if (need_rid_bits)
                    combine_op_timed([&]() { rid_bits_or_inplace(&perm_rids, tmp_rids); });
                if (out_restrict_sig)
                    combine_op_timed([&]() { perm_sig_bits.bit_or(tmp_sig_bits); });
            }
        } else {
            std::vector<uint8_t> *perm_rids_ptr = need_rid_bits ? &perm_rids : nullptr;
            if (!eval_formula_root_words(loaded,
                                         tp.target,
                                         target_ti,
                                         tp.formula_root,
                                         target_rbits,
                                         restrict_sigs,
                                         profile,
                                         &perm_words,
                                         perm_rids_ptr,
                                         out_restrict_sig ? &perm_sig_bits : nullptr))
                return false;
        }

        copy_sparse_words(perm_words, &final_words);
        if (need_rid_bits)
            final_rid_bits = perm_rids;
        if (out_restrict_sig)
            final_sig_bits = perm_sig_bits;

        if (!tp.rest_policy_roots.empty()) {
            SparseBlockWords rest_words;
            std::vector<uint8_t> rest_rids;
            std::vector<uint8_t> *rest_rids_ptr = need_rid_bits ? &rest_rids : nullptr;
            TokenBitset rest_sig_bits;
            build_all_allowed_for_target(target_ti, target_rbits, &rest_words, rest_rids_ptr);
            if (out_restrict_sig)
                fill_all_target_sigs(&rest_sig_bits);

            for (const BoolAst *rr : tp.rest_policy_roots) {
                SparseBlockWords tmp_words;
                tmp_words.total_blocks = target_ti.total_blocks;
                std::vector<uint8_t> tmp_rids;
                std::vector<uint8_t> *tmp_rids_ptr = nullptr;
                TokenBitset tmp_sig_bits;
                if (need_rid_bits) {
                    tmp_rids.assign((target_ti.nrows + 7u) / 8u, 0);
                    tmp_rids_ptr = &tmp_rids;
                }
                if (!eval_formula_root_words(loaded,
                                             tp.target,
                                             target_ti,
                                             rr,
                                             target_rbits,
                                             restrict_sigs,
                                             profile,
                                             &tmp_words,
                                             tmp_rids_ptr,
                                             out_restrict_sig ? &tmp_sig_bits : nullptr))
                    return false;
                combine_op_timed([&]() { (void)rest_words.and_inplace(tmp_words); });
                if (need_rid_bits)
                    combine_op_timed([&]() { rid_bits_and_inplace(&rest_rids, tmp_rids); });
                if (out_restrict_sig)
                    combine_op_timed([&]() { rest_sig_bits.bit_and(tmp_sig_bits); });
            }
            combine_op_timed([&]() { (void)final_words.and_inplace(rest_words); });
            if (need_rid_bits)
                combine_op_timed([&]() { rid_bits_and_inplace(&final_rid_bits, rest_rids); });
            if (out_restrict_sig)
                combine_op_timed([&]() { final_sig_bits.bit_and(rest_sig_bits); });
        }
    } else if (!tp.formula_root) {
        build_all_allowed_for_target(target_ti,
                                     target_rbits,
                                     &final_words,
                                     need_rid_bits ? &final_rid_bits : nullptr);
        if (out_restrict_sig)
            fill_all_target_sigs(&final_sig_bits);
    } else {
        if (!eval_formula_root_words(loaded,
                                     tp.target,
                                     target_ti,
                                     tp.formula_root,
                                     target_rbits,
                                     restrict_sigs,
                                     profile,
                                     &final_words,
                                     need_rid_bits ? &final_rid_bits : nullptr,
                                     out_restrict_sig ? &final_sig_bits : nullptr))
            return false;
    }

    if (out_restrict_sig) {
        out_restrict_sig->schema_cols = target_canon_schema;
        out_restrict_sig->active_sig = std::move(final_sig_bits);
        if (profile) {
            profile->restrict_sig_tables++;
            profile->restrict_sig_schema_cols_total += (uint64)out_restrict_sig->schema_cols.size();
            profile->restrict_sig_bytes_total +=
                out_restrict_sig->schema_cols.size() * sizeof(int) +
                token_bitset_mem_bytes(out_restrict_sig->active_sig);
        }
    }

    if (out_rid_bits) {
        *out_rid_bits = std::move(final_rid_bits);
        profile->target_rid_bitmap_bytes += out_rid_bits->size();
    }

    auto t_decode0 = Clock::now();
    std::vector<uint32> block_ids_vec;
    std::vector<uint64_t> words_vec;
    final_words.to_sorted_arrays(&block_ids_vec, &words_vec);
    uint64 *words = nullptr;
    uint32 *block_ids = nullptr;
    uint32 blocks = (uint32)block_ids_vec.size();
    size_t words_nbytes = words_vec.size() * sizeof(uint64_t);
    size_t block_ids_nbytes = block_ids_vec.size() * sizeof(uint32);
    if (words_nbytes > 0) {
        words = (uint64 *)palloc0(words_nbytes);
        std::memcpy(words, words_vec.data(), words_nbytes);
    }
    if (block_ids_nbytes > 0) {
        block_ids = (uint32 *)palloc0(block_ids_nbytes);
        std::memcpy(block_ids, block_ids_vec.data(), block_ids_nbytes);
    }
    uint32 allowed_rows = popcount_sparse_words_flat(words_vec);
    profile->allow_rows_total += (uint64)allowed_rows;
    profile->block_words_blocks_allocated += blocks;
    profile->block_words_total_blocks += final_words.total_blocks;
    profile->block_words_dense_bytes += final_words.words_bytes();
    profile->block_words_nblocks += final_words.total_blocks;
    profile->block_words_nwords_per_block =
        std::max<uint64>(profile->block_words_nwords_per_block, (uint64)kWordsPerBlock);
    profile->bytes_block_words += words_nbytes + block_ids_nbytes;
    auto t_decode1 = Clock::now();
    profile->decode_ms += Ms(t_decode1 - t_decode0).count();

    out_item->table = pstrdup(tp.target.c_str());
    out_item->block_words = words;
    out_item->block_ids = block_ids;
    out_item->blocks = blocks;
    out_item->total_blocks = final_words.total_blocks;
    out_item->n_rows = target_ti.nrows;

    if (allow_cache_eligible) {
        AllowCacheEntry ce;
        ce.n_rows = target_ti.nrows;
        ce.total_blocks = final_words.total_blocks;
        ce.words = words_vec;
        ce.block_ids = block_ids_vec;
        ce.allowed_rows = (uint64)allowed_rows;
        g_allow_cache[allow_cache_key] = std::move(ce);
        profile->allow_cache_build_ms += Ms(Clock::now() - t_allow_build0).count();
    }

    CF_TRACE_LOG("policy: allow_%s count=%u/%u", tp.target.c_str(), allowed_rows, target_ti.nrows);
    return true;
}

} // namespace

extern "C" {

typedef struct PolicyRunHandle {
    PolicyAllowListC allow_list;
    PolicyRunProfileC profile;
} PolicyRunHandle;

static void fill_run_profile(const BuildProfile &bp, PolicyRunProfileC *out)
{
    if (!out) return;
    out->artifact_parse_ms = bp.artifact_parse_ms;
    out->atoms_ms = bp.atoms_ms;
    out->propagate_ms = bp.propagate_ms;
    out->project_ms = bp.project_ms;
    out->project_mask_ms = bp.project_mask_ms;
    out->project_row_ms = bp.project_row_ms;
    out->project_mask_bytes = bp.project_mask_bytes;
    out->project_n_join_evals_max = bp.project_n_join_evals_max;
    out->project_clause_words_max = bp.project_clause_words_max;
    out->stamp_ms = 0.0;
    out->bin_ms = 0.0;
    out->local_sat_ms = 0.0;
    out->fill_ms = 0.0;
    out->prop_ms = bp.propagate_ms;
    out->prop_iters = bp.prop_iters;
    out->decode_ms = bp.decode_ms;
    out->policy_total_ms = bp.total_ms;
    out->clause_plan_count_max = bp.clause_plan_count_max;
    out->prop_join_scans_total = bp.prop_join_scans_total;
    out->unique_join_struct_sigs_max = bp.unique_join_struct_sigs_max;
    out->prop_table_scans = bp.prop_table_scans_compact.empty() ? nullptr : pstrdup(bp.prop_table_scans_compact.c_str());
    out->signature_cache_hits = bp.signature_cache_hits;
    out->signature_cache_misses = bp.signature_cache_misses;
    out->term_code_scans = bp.term_code_scans;
    out->target_full_row_scans = bp.target_full_row_scans;
    out->target_rid_bitmap_bytes = bp.target_rid_bitmap_bytes;
    out->signature_cache_bytes = bp.signature_cache_bytes;
    out->active_sig_dense_count = bp.active_sig_dense_count;
    out->active_sig_sparse_count = bp.active_sig_sparse_count;
    out->active_sig_density_sum = bp.active_sig_density_sum;
    out->domain_set_dense_count = bp.domain_set_dense_count;
    out->domain_set_sparse_count = bp.domain_set_sparse_count;
    out->domain_set_density_sum = bp.domain_set_density_sum;
    out->block_words_blocks_allocated = bp.block_words_blocks_allocated;
    out->block_words_total_blocks = bp.block_words_total_blocks;
    out->block_words_dense_bytes = bp.block_words_dense_bytes;
    out->block_words_nblocks = bp.block_words_nblocks;
    out->block_words_nwords_per_block = bp.block_words_nwords_per_block;
    out->proj_sig_count = bp.proj_sig_count;
    out->proj_sig_total = bp.proj_sig_total;
    out->proj_sig_new = bp.proj_sig_new;
    out->proj_sig_skipped = bp.proj_sig_skipped;
    out->proj_mask_or_ops = bp.proj_mask_or_ops;
    out->proj_rid_iters = bp.proj_rid_iters;
    out->proj_rid_iters_scan_enforcement = bp.proj_rid_iters_scan_enforcement;
    out->proj_rid_iters_dependency = bp.proj_rid_iters_dependency;
    out->canon_term_map_cache_hits = bp.canon_term_map_cache_hits;
    out->canon_term_map_cache_misses = bp.canon_term_map_cache_misses;
    out->canon_term_map_build_ms = bp.canon_term_map_build_ms;
    out->canon_term_map_bytes = bp.canon_term_map_bytes;
    out->restrict_key_index_build_ms = bp.restrict_key_index_build_ms;
    out->restrict_key_index_entries = bp.restrict_key_index_entries;
    out->restrict_key_index_bytes = bp.restrict_key_index_bytes;
    out->restrict_key_prune_ms = bp.restrict_key_prune_ms;
    out->sigmask_cache_hits = bp.sigmask_cache_hits;
    out->sigmask_cache_misses = bp.sigmask_cache_misses;
    out->sigmask_build_ms = bp.sigmask_build_ms;
    out->sigmask_bytes = bp.sigmask_bytes;
    out->bytes_sig_ctid_masks = bp.bytes_sig_ctid_masks;
    out->bytes_block_words = bp.bytes_block_words;
    out->bytes_artifact_buffers_retained = bp.bytes_artifact_buffers_retained;
    out->bytes_decoded_buffers_retained = bp.bytes_decoded_buffers_retained;
    out->qual_atoms_total = bp.qual_atoms_total;
    out->qual_atoms_applied = bp.qual_atoms_applied;
    out->qual_pruned_sigs = bp.qual_pruned_sigs;
    out->qual_prune_ms = bp.qual_prune_ms;
    out->restrict_sig_tables = bp.restrict_sig_tables;
    out->restrict_sig_schema_cols_total = bp.restrict_sig_schema_cols_total;
    out->restrict_sig_bytes_total = bp.restrict_sig_bytes_total;
    out->restrict_sig_apply_ms = bp.restrict_sig_apply_ms;
    out->restrict_term_apply_ms = bp.restrict_term_apply_ms;
    out->restrict_term_sigs_kept = bp.restrict_term_sigs_kept;
    out->restrict_term_sigs_dropped = bp.restrict_term_sigs_dropped;
}

PolicyRunHandle *
policy_run(const PolicyArtifactC *arts, int art_count, const PolicyEngineInputC *in)
{
    if (!arts || art_count <= 0 || !in)
        return nullptr;

    auto t0 = Clock::now();

    PolicyRunHandle *h = (PolicyRunHandle *)palloc0(sizeof(PolicyRunHandle));
    Loaded loaded;
    BuildProfile profile;

    if (!load_phase(arts, art_count, in, &loaded, &profile))
        return nullptr;

    h->allow_list.count = 0;
    h->allow_list.items = nullptr;

    if (!loaded.target_order.empty()) {
        h->allow_list.items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * loaded.target_order.size());

        // IMPORTANT: to match Postgres RLS semantics, policy clauses that reference other
        // tables must see those tables *already filtered* by their own policies.
        //
        // We do a dependency-ordered build where a target table depends on any other
        // policy-target table referenced in its policy AST.
        const int N = (int)loaded.target_order.size();
        std::unordered_map<std::string, int> idx;
        idx.reserve((size_t)N * 2u);
        for (int i = 0; i < N; i++)
            idx.emplace(loaded.target_order[i], i);

        std::vector<int> indegree((size_t)N, 0);
        std::vector<std::vector<int>> dependents((size_t)N);

        for (int ti = 0; ti < N; ti++) {
            const std::string &tname = loaded.target_order[ti];
            auto it_tp = loaded.targets.find(tname);
            if (it_tp == loaded.targets.end())
                continue;
            const TargetPlan &tp = it_tp->second;

            std::unordered_set<int> deps;
            deps.reserve(8);

            {
                for (const std::string &tbl : tp.formula_tables) {
                    if (tbl == tname)
                        continue;
                    if (loaded.targets.find(tbl) == loaded.targets.end())
                        continue;  // referenced table has no policy => unrestricted
                    auto it_dep = idx.find(tbl);
                    if (it_dep == idx.end())
                        continue;
                    int di = it_dep->second;
                    if (di == ti)
                        continue;
                    deps.insert(di);
                }
            }

            for (int di : deps) {
                dependents[(size_t)di].push_back(ti);
                indegree[(size_t)ti]++;
            }
        }

        std::deque<int> q;
        for (int i = 0; i < N; i++) {
            if (indegree[(size_t)i] == 0)
                q.push_back(i);
        }

        std::vector<int> order;
        order.reserve((size_t)N);
        while (!q.empty()) {
            int u = q.front();
            q.pop_front();
            order.push_back(u);
            for (int v : dependents[(size_t)u]) {
                int &deg = indegree[(size_t)v];
                deg--;
                if (deg == 0)
                    q.push_back(v);
            }
        }
        if ((int)order.size() != N) {
            ereport(ERROR,
                    (errmsg("policy: dependency cycle across policy targets (RLS recursion)"),
                     errdetail("target_count=%d", N)));
        }

        std::unordered_map<std::string, RestrictSigState> restrict_sigs;
        restrict_sigs.reserve((size_t)N * 2u);

        int out_count = 0;
        for (int oi = 0; oi < N; oi++) {
            int tindex = order[(size_t)oi];
            const std::string &tname = loaded.target_order[(size_t)tindex];
            auto it_tp = loaded.targets.find(tname);
            if (it_tp == loaded.targets.end())
                continue;

            const bool need_restrict_sig = !dependents[(size_t)tindex].empty();
            RestrictSigState restrict_sig_out;
            if (!build_target_allow_list(loaded,
                                         it_tp->second,
                                         &h->allow_list.items[out_count],
                                         &profile,
                                         &restrict_sigs,
                                         nullptr,
                                         nullptr,
                                         need_restrict_sig ? &restrict_sig_out : nullptr)) {
                return nullptr;
            }

            if (need_restrict_sig) {
                restrict_sigs[tname] = std::move(restrict_sig_out);
            } else {
                restrict_sigs.erase(tname);
            }
            out_count++;
        }

        h->allow_list.count = out_count;
    }

    for (auto &kv : loaded.tables)
        kv.second.decoded_cols.clear();
    loaded.signature_cache.clear();
    profile.bytes_decoded_buffers_retained = estimate_decoded_columns_bytes(loaded);
    profile.bytes_artifact_buffers_retained = estimate_artifact_store_bytes(loaded.artifacts);

    auto t1 = Clock::now();
    profile.total_ms = Ms(t1 - t0).count();
    profile.prop_table_scans_compact = format_prop_table_scan_counts(profile.prop_table_scan_counts);

    fill_run_profile(profile, &h->profile);

    log_policy_profile_query(profile, h->allow_list.count);

    return h;
}

const PolicyAllowListC *
policy_run_allow_list(const PolicyRunHandle *h)
{
    if (!h) return nullptr;
    return &h->allow_list;
}

const PolicyRunProfileC *
policy_run_profile(const PolicyRunHandle *h)
{
    if (!h) return nullptr;
    return &h->profile;
}

bool
policy_build_allow_bits_general(const PolicyArtifactC *arts,
                                int art_count,
                                const PolicyEngineInputC *in,
                                PolicyAllowListC *out)
{
    if (!out) return false;
    PolicyRunHandle *h = policy_run(arts, art_count, in);
    if (!h) return false;
    *out = h->allow_list;
    return true;
}

} // extern "C"

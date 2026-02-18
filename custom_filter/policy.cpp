#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern "C" {
#include "postgres.h"
#include "executor/spi.h"
#include "fmgr.h"
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

extern "C" {

typedef struct PolicyArtifactC {
    const char *name;
    const void *data;
    size_t len;
} PolicyArtifactC;

typedef struct PolicyTableAllowC {
    const char *table;
    uint64 *block_words;
    uint32 blocks;
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
    double stamp_ms;
    double bin_ms;
    double local_sat_ms;
    double fill_ms;
    double prop_ms;
    int prop_iters;
    double decode_ms;
    double policy_total_ms;
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

static bytea *
cf_fetch_file_bytea(const char *name)
{
    StringInfoData sql;
    initStringInfo(&sql);
    appendStringInfo(&sql,
                     "SELECT file FROM public.files WHERE name = %s",
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
    size_t nbits = 0;
    std::vector<uint64_t> words;

    TokenBitset() = default;
    explicit TokenBitset(size_t bits) { reset(bits); }

    void reset(size_t bits)
    {
        nbits = bits;
        words.assign((nbits + 63u) / 64u, 0);
    }

    void clear_all()
    {
        std::fill(words.begin(), words.end(), 0);
    }

    void fill_all()
    {
        std::fill(words.begin(), words.end(), ~uint64_t(0));
        trim_tail();
    }

    bool any() const
    {
        for (uint64_t w : words) {
            if (w != 0) return true;
        }
        return false;
    }

    void set(size_t bit)
    {
        if (bit >= nbits) return;
        words[bit >> 6] |= (uint64_t(1) << (bit & 63u));
    }

    bool test(size_t bit) const
    {
        if (bit >= nbits) return false;
        return (words[bit >> 6] & (uint64_t(1) << (bit & 63u))) != 0;
    }

    bool equals(const TokenBitset &o) const
    {
        return nbits == o.nbits && words == o.words;
    }

    void bit_and(const TokenBitset &o)
    {
        size_t n = std::min(words.size(), o.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] &= o.words[i];
        for (size_t i = n; i < words.size(); i++)
            words[i] = 0;
    }

    void bit_or(const TokenBitset &o)
    {
        size_t n = std::min(words.size(), o.words.size());
        for (size_t i = 0; i < n; i++)
            words[i] |= o.words[i];
        trim_tail();
    }

    bool intersect_with_changed(const TokenBitset &o)
    {
        bool changed = false;
        size_t n = std::min(words.size(), o.words.size());
        for (size_t i = 0; i < n; i++) {
            uint64_t nw = words[i] & o.words[i];
            if (nw != words[i]) changed = true;
            words[i] = nw;
        }
        for (size_t i = n; i < words.size(); i++) {
            if (words[i] != 0) changed = true;
            words[i] = 0;
        }
        return changed;
    }

private:
    void trim_tail()
    {
        if (nbits == 0 || words.empty()) return;
        size_t rem = nbits & 63u;
        if (rem == 0) return;
        uint64_t mask = (uint64_t(1) << rem) - 1u;
        words.back() &= mask;
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
        int id = 0;
        bool any = false;
        while (p < src.size() && std::isdigit((unsigned char)src[p])) {
            id = id * 10 + (src[p] - '0');
            any = true;
            p++;
        }
        if (!any) return nullptr;
        pos = p;
        return node(AstType::VAR, id);
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

static void emit_ast_rpn(const BoolAst *node, std::vector<FormulaToken> *out)
{
    if (!node || !out)
        return;
    if (node->type == AstType::VAR) {
        out->push_back({FormulaTokKind::VAR, node->var_id});
        return;
    }
    emit_ast_rpn(node->left, out);
    emit_ast_rpn(node->right, out);
    if (node->type == AstType::AND)
        out->push_back({FormulaTokKind::AND, -1});
    else
        out->push_back({FormulaTokKind::OR, -1});
}

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

static bool like_match_rec(const std::string &text,
                           size_t ti,
                           const std::string &pat,
                           size_t pi)
{
    while (pi < pat.size()) {
        char p = pat[pi];
        if (p == '%') {
            while (pi + 1 < pat.size() && pat[pi + 1] == '%') pi++;
            if (pi + 1 == pat.size())
                return true;
            for (size_t k = ti; k <= text.size(); k++) {
                if (like_match_rec(text, k, pat, pi + 1))
                    return true;
            }
            return false;
        }
        if (p == '_') {
            if (ti >= text.size()) return false;
            ti++;
            pi++;
            continue;
        }
        if (ti >= text.size() || text[ti] != p)
            return false;
        ti++;
        pi++;
    }
    return ti == text.size();
}

static bool like_match(const std::string &text, const std::string &pat)
{
    return like_match_rec(text, 0, pat, 0);
}

enum class AtomKind {
    JOIN,
    CONST,
};

enum class ConstOp {
    EQ,
    IN,
    LIKE,
    LT,
    LE,
    GT,
    GE,
    NE,
};

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
    std::unordered_map<std::string, ArtifactBlob> blobs;
    std::vector<bytea *> owned;

    bool get(const std::string &name, ArtifactBlob *out)
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
        CB02_SINGLE,
        RAW,
    };

    std::string name;

    std::vector<std::string> meta_cols;            // table.col list in code order
    std::unordered_map<std::string, int> col_idx;  // table.col -> index

    std::vector<int32_t> ctid_blk;
    std::vector<int32_t> ctid_off;

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

struct ClausePredicate {
    int atom_id = -1;
    int col_idx = -1;
    TokenBitset allowed;
    const std::vector<int32_t> *col_data = nullptr;
};

struct ClauseClassGroup {
    int class_id = -1;
    int class_pos = -1;
    std::vector<int> col_idxs;
    std::vector<const std::vector<int32_t> *> col_data;
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
    std::vector<int> join_classes;
    bool has_join_atom = false;
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
    bool local_formula_enabled = false;
    std::vector<FormulaToken> local_formula_rpn;
    std::vector<TargetLocalAtom> local_formula_atoms;
    std::vector<int> local_var_slot;
};

struct Loaded {
    ArtifactStore artifacts;

    std::unordered_map<std::string, TableData> tables;
    std::unordered_map<std::string, std::vector<std::string>> dicts;
    std::unordered_map<std::string, DictType> dict_types;

    std::unordered_map<int, Atom> atoms_by_id;

    std::unordered_map<std::string, int> join_class_by_col;
    std::map<int, std::vector<std::string>> join_class_cols;

    std::vector<std::string> target_order;
    std::unordered_map<std::string, TargetPlan> targets;

    std::vector<int> class_domain;  // max_token + 1
};

struct BuildProfile {
    double artifact_parse_ms = 0.0;
    double atoms_ms = 0.0;
    double propagate_ms = 0.0;
    double decode_ms = 0.0;
    int prop_iters = 0;
    double total_ms = 0.0;
};

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
        } else if (pa->kind == POLICY_ATOM_COL_CONST) {
            a.kind = AtomKind::CONST;
            ColRef lref;
            int cid = -1;
            bool is_join = false;
            if (!parse_schema_key(a.lhs_schema_key, &lref, &cid, &is_join))
                return false;
            a.left = lref;

            switch (pa->op) {
                case POLICY_OP_EQ: a.op = ConstOp::EQ; break;
                case POLICY_OP_IN: a.op = ConstOp::IN; break;
                case POLICY_OP_LIKE: a.op = ConstOp::LIKE; break;
                case POLICY_OP_LT: a.op = ConstOp::LT; break;
                case POLICY_OP_LE: a.op = ConstOp::LE; break;
                case POLICY_OP_GT: a.op = ConstOp::GT; break;
                case POLICY_OP_GE: a.op = ConstOp::GE; break;
                case POLICY_OP_NE: a.op = ConstOp::NE; break;
                default: a.op = ConstOp::EQ; break;
            }
            for (int v = 0; v < pa->const_count; v++) {
                if (pa->const_values && pa->const_values[v])
                    a.values.push_back(pa->const_values[v]);
            }
        } else {
            continue;
        }

        out->atoms_by_id[a.id] = std::move(a);
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

    for (const auto &kv : out->atoms_by_id) {
        const Atom &a = kv.second;
        if (a.kind == AtomKind::JOIN && a.join_class_id >= 0) {
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

        if (name.rfind("dict/", 0) == 0) {
            std::string rest = name.substr(std::strlen("dict/"));
            auto p = rest.find('/');
            if (p == std::string::npos) continue;
            std::string key = rest.substr(0, p) + "." + rest.substr(p + 1);
            out->dicts[key] = parse_dict_values(bb);
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

        if (name.size() > 10 && name.substr(name.size() - 10) == "_code_base") {
            std::string table = name.substr(0, name.size() - 10);
            TableData &ti = out->tables[table];
            ti.name = table;
            ti.code_base = bb;

            uint32 total = 0;
            uint32 chunk_rows = 0;
            int ntoks = -1;
            int chunks = 0;
            if (parse_cb03_manifest(bb, &total, &chunk_rows, &ntoks, &chunks)) {
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
        }
        if (ti.code_format == TableData::CodeFormat::CB03_MANIFEST) {
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
    if (op == ConstOp::EQ || op == ConstOp::IN || op == ConstOp::NE) {
        bool found = false;
        for (const auto &v : const_vals) {
            if (dict_val == v) {
                found = true;
                break;
            }
        }
        if (op == ConstOp::NE)
            return !found;
        return found;
    }

    if (op == ConstOp::LIKE) {
        for (const auto &p : const_vals) {
            if (like_match(dict_val, p))
                return true;
        }
        return false;
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

static TokenBitset build_allowed_token_set(const Atom &a,
                                           const std::vector<std::string> &dict_vals,
                                           DictType dtype)
{
    TokenBitset bits(dict_vals.size());
    if (a.op == ConstOp::NE)
        bits.fill_all();
    for (size_t i = 0; i < dict_vals.size(); i++) {
        bool ok = eval_const_match(a.op, dict_vals[i], a.values, dtype);
        if (a.op == ConstOp::NE) {
            if (!ok)
                bits.set(i);
        } else if (ok) {
            bits.set(i);
        }
    }
    return bits;
}

static bool is_clause_acyclic_hint(const ClausePlan &cl)
{
    std::unordered_map<int, int> idx;
    for (int cid : cl.join_classes)
        idx[cid] = (int)idx.size();
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
            uniq.insert(cg.class_id);
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

static void collect_formula_var_ids(const std::vector<FormulaToken> &rpn, std::vector<int> *out_vars)
{
    if (!out_vars)
        return;
    out_vars->clear();
    for (const auto &tk : rpn) {
        if (tk.kind == FormulaTokKind::VAR && tk.var_id > 0)
            out_vars->push_back(tk.var_id);
    }
    std::sort(out_vars->begin(), out_vars->end());
    out_vars->erase(std::unique(out_vars->begin(), out_vars->end()), out_vars->end());
}

static bool try_compile_target_local_formula(const std::string &target,
                                             const std::vector<FormulaToken> &rpn,
                                             Loaded *out,
                                             TargetPlan *tp)
{
    if (!out || !tp || rpn.empty())
        return false;

    std::vector<int> vars;
    collect_formula_var_ids(rpn, &vars);
    if (vars.empty())
        return false;

    // Fast path is valid only when every referenced atom is target-local const.
    for (int vid : vars) {
        auto ita = out->atoms_by_id.find(vid);
        if (ita == out->atoms_by_id.end())
            continue;  // unknown atom id acts as FALSE (same behavior as DNF fallback).
        const Atom &a = ita->second;
        if (a.kind != AtomKind::CONST || a.left.table != target)
            return false;
    }

    auto it_table = out->tables.find(target);
    if (it_table == out->tables.end()) {
        ereport(ERROR,
                (errmsg("policy: missing table artifacts for %s", target.c_str())));
    }
    TableData &ti = it_table->second;

    int max_var = vars.empty() ? 0 : vars.back();
    tp->local_var_slot.assign((size_t)max_var + 1u, -1);
    tp->local_formula_rpn = rpn;
    tp->local_formula_atoms.clear();

    for (int vid : vars) {
        auto ita = out->atoms_by_id.find(vid);
        if (ita == out->atoms_by_id.end())
            continue;
        const Atom &a = ita->second;

        std::string key = a.left.key();
        auto itd = out->dicts.find(key);
        if (itd == out->dicts.end()) {
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            a.id, key.c_str())));
        }
        DictType dtype = DictType::TEXT;
        auto itdt = out->dict_types.find(key);
        if (itdt != out->dict_types.end())
            dtype = itdt->second;

        auto it_idx = ti.col_idx.find(key);
        if (it_idx == ti.col_idx.end()) {
            ereport(ERROR,
                    (errmsg("policy: missing predicate column %s in meta/cols/%s",
                            key.c_str(), target.c_str())));
        }

        TargetLocalAtom la;
        la.var_id = vid;
        la.atom_id = a.id;
        la.col_idx = it_idx->second;
        la.allowed = build_allowed_token_set(a, itd->second, dtype);

        ti.needed_cols.insert(la.col_idx);
        tp->local_var_slot[(size_t)vid] = (int)tp->local_formula_atoms.size();
        tp->local_formula_atoms.push_back(std::move(la));
    }

    tp->local_formula_enabled = true;
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

    AstParser parser(ast);
    BoolAst *root = parser.parse_or();
    parser.skip_ws();
    if (!root || parser.pos != parser.src.size()) {
        ereport(ERROR,
                (errmsg("policy: failed to parse target AST target=%s ast=%s",
                        target.c_str(), ast.c_str())));
    }

    auto t_atoms0 = Clock::now();

    std::vector<FormulaToken> rpn;
    emit_ast_rpn(root, &rpn);
    if (try_compile_target_local_formula(target, rpn, out, &tp)) {
        auto t_atoms1 = Clock::now();
        profile->atoms_ms += Ms(t_atoms1 - t_atoms0).count();
        out->targets[target] = std::move(tp);
        return true;
    }

    auto dnf_terms = ast_to_dnf(root, 4096);
    dedup_dnf_terms(&dnf_terms);

    for (const DnfTerm &term : dnf_terms) {
        ClausePlan cl;
        cl.target = target;
        cl.atom_ids = term;

        struct TempTable {
            std::unordered_map<int, std::vector<std::string>> class_cols;  // class -> list of table.col
            struct TempPred {
                int atom_id = -1;
                std::string col_key;
                TokenBitset allowed;
            };
            std::vector<TempPred> preds;
        };

        std::unordered_map<std::string, TempTable> tmp_tables;
        std::set<int> join_classes;

        bool unsat = false;

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
                join_classes.insert(a.join_class_id);
                tmp_tables[a.left.table].class_cols[a.join_class_id].push_back(a.left.key());
                tmp_tables[a.right.table].class_cols[a.join_class_id].push_back(a.right.key());
            } else {
                std::string key = a.left.key();
                auto itd = out->dicts.find(key);
                if (itd == out->dicts.end()) {
                    ereport(ERROR,
                            (errmsg("policy: missing dict for const atom y%d col=%s",
                                    a.id, key.c_str())));
                }
                DictType dtype = DictType::TEXT;
                auto itdt = out->dict_types.find(key);
                if (itdt != out->dict_types.end())
                    dtype = itdt->second;

                TokenBitset allowed = build_allowed_token_set(a, itd->second, dtype);
                if (!allowed.any()) {
                    unsat = true;
                    break;
                }

                TempTable::TempPred p;
                p.atom_id = a.id;
                p.col_key = key;
                p.allowed = std::move(allowed);
                tmp_tables[a.left.table].preds.push_back(std::move(p));

                if (a.join_class_id >= 0) {
                    join_classes.insert(a.join_class_id);
                    tmp_tables[a.left.table].class_cols[a.join_class_id].push_back(a.left.key());
                }
            }
        }

        cl.unsat = unsat;
        if (unsat) {
            tp.clauses.push_back(std::move(cl));
            continue;
        }

        cl.join_classes.assign(join_classes.begin(), join_classes.end());

        std::unordered_map<int, int> class_pos;
        for (size_t i = 0; i < cl.join_classes.size(); i++)
            class_pos[cl.join_classes[i]] = (int)i;

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

            for (auto &ckv : tkv.second.class_cols) {
                ClauseClassGroup cg;
                cg.class_id = ckv.first;
                auto itp = class_pos.find(cg.class_id);
                if (itp == class_pos.end())
                    continue;
                cg.class_pos = itp->second;
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

        cl.acyclic_hint = is_clause_acyclic_hint(cl);
        tp.clauses.push_back(std::move(cl));
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

static bool row_matches_clause_table(const ClauseTablePlan &tp,
                                     uint32 rid,
                                     const std::vector<TokenBitset> &allowed,
                                     std::vector<int32_t> *out_group_tokens,
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

    if (out_group_tokens)
        out_group_tokens->assign(tp.class_groups.size(), -1);

    for (size_t g = 0; g < tp.class_groups.size(); g++) {
        const ClauseClassGroup &cg = tp.class_groups[g];
        if (cg.class_pos < 0 || cg.class_pos >= (int)allowed.size())
            return false;
        if (cg.col_data.empty())
            return false;
        int32_t tok = (*cg.col_data[0])[rid];
        if (tok < 0)
            return false;
        for (size_t i = 1; i < cg.col_data.size(); i++) {
            int32_t tk = (*cg.col_data[i])[rid];
            if (tk != tok)
                return false;
        }
        if (!allowed[cg.class_pos].test((size_t)tok))
            return false;
        if (out_group_tokens)
            (*out_group_tokens)[g] = tok;
    }

    return true;
}

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

static bool compute_table_support(const ClausePlan &cl,
                                  const ClauseTablePlan &tp,
                                  const TableData &ti,
                                  const std::vector<TokenBitset> &allowed,
                                  std::vector<TokenBitset> *support,
                                  const std::unordered_map<std::string, const uint8 *> *restrict_bits,
                                  bool *table_has_any)
{
    if (!support) return false;

    support->clear();
    support->reserve(tp.class_groups.size());
    for (const auto &cg : tp.class_groups) {
        if (cg.class_pos < 0 || cg.class_pos >= (int)cl.join_classes.size())
            return false;
        const TokenBitset &al = allowed[cg.class_pos];
        support->emplace_back(al.nbits);
    }

    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(tp.table);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }

    bool any_row = false;
    std::vector<int32_t> toks;

    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        if (!row_matches_clause_table(tp, rid, allowed, &toks, rbits))
            continue;
        any_row = true;
        for (size_t g = 0; g < tp.class_groups.size(); g++) {
            int32_t tok = toks[g];
            if (tok >= 0)
                (*support)[g].set((size_t)tok);
        }
    }

    if (table_has_any)
        *table_has_any = any_row;
    return true;
}

static bool propagate_clause(const ClausePlan &cl,
                             const Loaded &loaded,
                             std::vector<TokenBitset> *allowed_out,
                             int *out_iters,
                             const std::unordered_map<std::string, const uint8 *> *restrict_bits,
                             double *out_ms)
{
    if (!allowed_out || !out_iters || !out_ms)
        return false;

    auto t0 = Clock::now();

    allowed_out->clear();
    allowed_out->reserve(cl.join_classes.size());
    for (int cid : cl.join_classes) {
        size_t dom = 0;
        if (cid >= 0 && cid < (int)loaded.class_domain.size())
            dom = (size_t)loaded.class_domain[cid];
        TokenBitset b(dom);
        b.fill_all();
        allowed_out->push_back(std::move(b));
    }

    int iterations = 0;

    auto sweep = [&](bool reverse, bool *out_changed) -> bool {
        bool any_change = false;
        if (!reverse) {
            for (size_t ti_idx = 0; ti_idx < cl.tables.size(); ti_idx++) {
                const ClauseTablePlan &tp = cl.tables[ti_idx];
                auto it_t = loaded.tables.find(tp.table);
                if (it_t == loaded.tables.end())
                    return false;
                const TableData &ti = it_t->second;
                std::vector<TokenBitset> support;
                if (!compute_table_support(cl, tp, ti, *allowed_out, &support, restrict_bits, nullptr))
                    return false;
                for (size_t g = 0; g < tp.class_groups.size(); g++) {
                    const ClauseClassGroup &cg = tp.class_groups[g];
                    if ((*allowed_out)[cg.class_pos].intersect_with_changed(support[g]))
                        any_change = true;
                }
            }
            if (out_changed) *out_changed = any_change;
            return true;
        }

        for (int ti_idx = (int)cl.tables.size() - 1; ti_idx >= 0; ti_idx--) {
            const ClauseTablePlan &tp = cl.tables[(size_t)ti_idx];
            auto it_t = loaded.tables.find(tp.table);
            if (it_t == loaded.tables.end())
                return false;
            const TableData &ti = it_t->second;
            std::vector<TokenBitset> support;
            if (!compute_table_support(cl, tp, ti, *allowed_out, &support, restrict_bits, nullptr))
                return false;
            for (size_t g = 0; g < tp.class_groups.size(); g++) {
                const ClauseClassGroup &cg = tp.class_groups[g];
                if ((*allowed_out)[cg.class_pos].intersect_with_changed(support[g]))
                    any_change = true;
            }
        }
        if (out_changed) *out_changed = any_change;
        return true;
    };

    if (cl.acyclic_hint) {
        // Two directional passes (Yannakakis-style fast path for tree-like clauses).
        bool ch0 = false;
        bool ch1 = false;
        if (!sweep(false, &ch0)) return false;
        if (!sweep(true, &ch1)) return false;
        iterations = 1;
        for (const auto &b : *allowed_out) {
            if (!b.any()) {
                *out_iters = iterations;
                *out_ms = Ms(Clock::now() - t0).count();
                return true;
            }
        }
        if (!ch0 && !ch1) {
            *out_iters = iterations;
            *out_ms = Ms(Clock::now() - t0).count();
            return true;
        }
    }

    const int cap = cl.acyclic_hint ? 8 : 20;
    for (;;) {
        bool ch0 = false;
        bool ch1 = false;
        if (!sweep(false, &ch0)) return false;
        if (!sweep(true, &ch1)) return false;
        iterations++;
        bool any_change = ch0 || ch1;

        bool empty = false;
        for (const auto &b : *allowed_out) {
            if (!b.any()) {
                empty = true;
                break;
            }
        }
        if (empty || !any_change)
            break;

        if (iterations >= cap) {
            ereport(ERROR,
                    (errmsg("policy: cycle_fixpoint_cap target=%s cap=%d",
                            cl.target.c_str(), cap)));
        }
    }

    *out_iters = std::max(iterations, cl.acyclic_hint ? 1 : 0);
    *out_ms = Ms(Clock::now() - t0).count();
    return true;
}

static bool table_has_witness(const ClausePlan &cl,
                              const ClauseTablePlan &tp,
                              const TableData &ti,
                              const std::vector<TokenBitset> &allowed,
                              const std::unordered_map<std::string, const uint8 *> *restrict_bits)
{
    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(tp.table);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        if (row_matches_clause_table(tp, rid, allowed, nullptr, rbits))
            return true;
    }
    return false;
}

static bool build_rid_bits_for_clause_target(const ClausePlan &cl,
                                             const Loaded &loaded,
                                             const std::vector<TokenBitset> &allowed,
                                             std::vector<uint8_t> *out_bits,
                                             const std::unordered_map<std::string, const uint8 *> *restrict_bits,
                                             bool *out_clause_global_ok)
{
    if (!out_bits || !out_clause_global_ok)
        return false;

    *out_clause_global_ok = true;

    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;

    for (const auto &tp : cl.tables) {
        auto it_t = loaded.tables.find(tp.table);
        if (it_t == loaded.tables.end())
            return false;
        const TableData &ti = it_t->second;

        if (tp.table == cl.target) {
            target_tp = &tp;
            target_ti = &ti;
        }

        if (tp.table != cl.target) {
            if (!table_has_witness(cl, tp, ti, allowed, restrict_bits)) {
                *out_clause_global_ok = false;
                break;
            }
        }
    }

    if (!*out_clause_global_ok)
        return true;

    if (!target_tp || !target_ti) {
        // Clause independent of target row: if global witness exists, allow all target rows.
        auto it_tt = loaded.tables.find(cl.target);
        if (it_tt == loaded.tables.end())
            return false;
        const TableData &tt = it_tt->second;
        out_bits->assign((tt.nrows + 7u) / 8u, 0xFF);
        if ((tt.nrows & 7u) != 0u)
            out_bits->back() &= (uint8)((1u << (tt.nrows & 7u)) - 1u);
        return true;
    }

    out_bits->assign((target_ti->nrows + 7u) / 8u, 0);

    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(cl.target);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }

    for (uint32 rid = 0; rid < target_ti->nrows; rid++) {
        if (row_matches_clause_table(*target_tp, rid, allowed, nullptr, rbits)) {
            rid_bit_set(out_bits->data(), rid);
        }
    }

    return true;
}

static bool table_has_predicate_witness(const ClauseTablePlan &tp,
                                        const TableData &ti,
                                        const std::unordered_map<std::string, const uint8 *> *restrict_bits)
{
    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(tp.table);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        if (row_matches_table_predicates_only(tp, rid, rbits))
            return true;
    }
    return false;
}

static bool build_rid_bits_for_clause_nojoins(const ClausePlan &cl,
                                              const Loaded &loaded,
                                              std::vector<uint8_t> *out_bits,
                                              const std::unordered_map<std::string, const uint8 *> *restrict_bits,
                                              bool *out_clause_global_ok)
{
    if (!out_bits || !out_clause_global_ok)
        return false;

    *out_clause_global_ok = true;

    const ClauseTablePlan *target_tp = nullptr;
    const TableData *target_ti = nullptr;

    for (const auto &tp : cl.tables) {
        auto it_t = loaded.tables.find(tp.table);
        if (it_t == loaded.tables.end())
            return false;
        const TableData &ti = it_t->second;

        if (tp.table == cl.target) {
            target_tp = &tp;
            target_ti = &ti;
        } else {
            if (!table_has_predicate_witness(tp, ti, restrict_bits)) {
                *out_clause_global_ok = false;
                break;
            }
        }
    }

    if (!*out_clause_global_ok)
        return true;

    if (!target_tp || !target_ti) {
        auto it_tt = loaded.tables.find(cl.target);
        if (it_tt == loaded.tables.end())
            return false;
        const TableData &tt = it_tt->second;
        out_bits->assign((tt.nrows + 7u) / 8u, 0xFF);
        if ((tt.nrows & 7u) != 0u)
            out_bits->back() &= (uint8)((1u << (tt.nrows & 7u)) - 1u);
        return true;
    }

    out_bits->assign((target_ti->nrows + 7u) / 8u, 0);
    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(cl.target);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }
    for (uint32 rid = 0; rid < target_ti->nrows; rid++) {
        if (row_matches_table_predicates_only(*target_tp, rid, rbits))
            rid_bit_set(out_bits->data(), rid);
    }
    return true;
}

static bool build_rid_bits_for_target_local_formula(const TargetPlan &tp,
                                                    const Loaded &loaded,
                                                    std::vector<uint8_t> *out_bits,
                                                    const std::unordered_map<std::string, const uint8 *> *restrict_bits)
{
    if (!out_bits)
        return false;
    auto it_t = loaded.tables.find(tp.target);
    if (it_t == loaded.tables.end())
        return false;
    const TableData &ti = it_t->second;

    out_bits->assign((ti.nrows + 7u) / 8u, 0);
    const uint8 *rbits = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(tp.target);
        if (it_rb != restrict_bits->end())
            rbits = it_rb->second;
    }

    std::vector<uint8_t> atom_vals(tp.local_formula_atoms.size(), 0);
    std::vector<uint8_t> stack;
    stack.reserve(tp.local_formula_rpn.size());

    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        if (rbits && !rid_bit_test(rbits, rid))
            continue;

        for (size_t i = 0; i < tp.local_formula_atoms.size(); i++) {
            const auto &a = tp.local_formula_atoms[i];
            if (!a.col_data || rid >= a.col_data->size())
                return false;
            int32_t tok = (*a.col_data)[rid];
            atom_vals[i] = (tok >= 0 && a.allowed.test((size_t)tok)) ? 1u : 0u;
        }

        stack.clear();
        for (const auto &tk : tp.local_formula_rpn) {
            if (tk.kind == FormulaTokKind::VAR) {
                uint8_t v = 0;
                if (tk.var_id > 0 && (size_t)tk.var_id < tp.local_var_slot.size()) {
                    int slot = tp.local_var_slot[(size_t)tk.var_id];
                    if (slot >= 0 && (size_t)slot < atom_vals.size())
                        v = atom_vals[(size_t)slot];
                }
                stack.push_back(v);
                continue;
            }

            if (stack.size() < 2)
                return false;
            uint8_t rhs = stack.back(); stack.pop_back();
            uint8_t lhs = stack.back(); stack.pop_back();
            if (tk.kind == FormulaTokKind::AND)
                stack.push_back((lhs && rhs) ? 1u : 0u);
            else
                stack.push_back((lhs || rhs) ? 1u : 0u);
        }

        if (stack.size() != 1)
            return false;
        if (stack.back())
            rid_bit_set(out_bits->data(), rid);
    }
    return true;
}

static bool build_block_words_from_rid_bits(const TableData &ti,
                                            const std::vector<uint8_t> &rid_bits,
                                            uint64 **out_words,
                                            uint32 *out_blocks,
                                            size_t *out_nbytes,
                                            uint32 *out_allowed)
{
    if (!out_words || !out_blocks || !out_nbytes || !out_allowed)
        return false;

    *out_words = nullptr;
    *out_blocks = 0;
    *out_nbytes = 0;
    *out_allowed = 0;

    if (ti.nrows == 0 || ti.ctid_blk.empty() || ti.ctid_off.empty())
        return true;

    int32 max_blk = -1;
    for (uint32 r = 0; r < ti.nrows; r++) {
        if ((size_t)r >= ti.ctid_blk.size()) break;
        if ((int32)ti.ctid_blk[r] > max_blk)
            max_blk = ti.ctid_blk[r];
    }
    if (max_blk < 0)
        return true;

    uint32 blocks = (uint32)max_blk + 1u;
    size_t nwords = (size_t)blocks * (size_t)kWordsPerBlock;
    size_t nbytes = nwords * sizeof(uint64_t);
    uint64 *words = (uint64 *)palloc0(nbytes);

    uint32 allowed_rows = 0;
    for (uint32 rid = 0; rid < ti.nrows; rid++) {
        if ((size_t)rid_bits.size() <= (rid >> 3))
            break;
        if (!rid_bit_test(rid_bits.data(), rid))
            continue;
        if ((size_t)rid >= ti.ctid_blk.size() || (size_t)rid >= ti.ctid_off.size())
            continue;

        int32 blk = ti.ctid_blk[rid];
        int32 off = ti.ctid_off[rid];
        if (blk < 0 || off <= 0 || off > (int32)kMaxOffsetNumber)
            continue;
        if ((uint32)blk >= blocks)
            continue;
        uint32 off0 = (uint32)(off - 1);
        size_t flat = (size_t)(uint32)blk * (size_t)kWordsPerBlock + (size_t)(off0 >> 6);
        words[flat] |= (uint64_t(1) << (off0 & 63u));
        allowed_rows++;
    }

    *out_words = words;
    *out_blocks = blocks;
    *out_nbytes = nbytes;
    *out_allowed = allowed_rows;
    return true;
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

static void log_policy_profile_query(const BuildProfile &p, int filtered_targets)
{
    elog(NOTICE,
         "policy_profile_query: K=%d query_id=%s total_ms=%.3f load_ms=%.3f local_ms=0.000 prop_ms=%.3f decode_ms=%.3f sat_calls=0 cache_hits=0 closure_tables=0 filtered_targets=%d",
         profile_k(),
         profile_query().c_str(),
         p.total_ms,
         p.artifact_parse_ms,
         p.propagate_ms,
         p.decode_ms,
         filtered_targets);
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
        if (!compile_target_plan(target, ast, out, profile))
            return false;
    }

    for (auto &tkv : out->targets) {
        for (auto &cl : tkv.second.clauses) {
            if (!bind_clause_views(&cl, out))
                return false;
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
        if (!bind_target_local_views(&tkv.second, out))
            return false;
    }

    auto t1 = Clock::now();
    profile->artifact_parse_ms = Ms(t1 - t0).count();
    CF_TRACE_LOG("policy: load_ms=%.3f", profile->artifact_parse_ms);
    return true;
}

static bool build_target_allow_list(const Loaded &loaded,
                                    const TargetPlan &tp,
                                    PolicyTableAllowC *out_item,
                                    BuildProfile *profile,
                                    const std::unordered_map<std::string, const uint8 *> *restrict_bits = nullptr)
{
    if (!out_item || !profile)
        return false;

    auto it_t = loaded.tables.find(tp.target);
    if (it_t == loaded.tables.end()) {
        ereport(ERROR,
                (errmsg("policy: target table artifacts missing: %s", tp.target.c_str())));
    }
    const TableData &target_ti = it_t->second;
    std::vector<uint8_t> final_bits((target_ti.nrows + 7u) / 8u, 0);

    if (tp.local_formula_enabled) {
        if (!build_rid_bits_for_target_local_formula(tp, loaded, &final_bits, restrict_bits))
            return false;
    } else {
        for (const ClausePlan &cl : tp.clauses) {
            if (cl.unsat)
                continue;

            bool clause_global_ok = true;
            std::vector<uint8_t> clause_bits;

            if (!cl.has_join_atom) {
                if (!build_rid_bits_for_clause_nojoins(cl,
                                                       loaded,
                                                       &clause_bits,
                                                       restrict_bits,
                                                       &clause_global_ok)) {
                    return false;
                }
                if (!clause_global_ok)
                    continue;
            } else {
                std::vector<TokenBitset> allowed;
                int iters = 0;
                double ms_prop = 0.0;
                if (!propagate_clause(cl, loaded, &allowed, &iters, restrict_bits, &ms_prop))
                    return false;
                profile->propagate_ms += ms_prop;
                profile->prop_iters += iters;

                bool empty = false;
                for (const auto &b : allowed) {
                    if (!b.any()) {
                        empty = true;
                        break;
                    }
                }
                if (empty)
                    continue;

                if (!build_rid_bits_for_clause_target(cl,
                                                      loaded,
                                                      allowed,
                                                      &clause_bits,
                                                      restrict_bits,
                                                      &clause_global_ok)) {
                    return false;
                }
                if (!clause_global_ok)
                    continue;
            }

            size_t n = std::min(final_bits.size(), clause_bits.size());
            for (size_t i = 0; i < n; i++)
                final_bits[i] |= clause_bits[i];
        }
    }

    auto t_decode0 = Clock::now();
    uint64 *words = nullptr;
    uint32 blocks = 0;
    size_t nbytes = 0;
    uint32 allowed_rows = 0;
    if (!build_block_words_from_rid_bits(target_ti,
                                         final_bits,
                                         &words,
                                         &blocks,
                                         &nbytes,
                                         &allowed_rows)) {
        return false;
    }
    auto t_decode1 = Clock::now();
    profile->decode_ms += Ms(t_decode1 - t_decode0).count();

    out_item->table = pstrdup(tp.target.c_str());
    out_item->block_words = words;
    out_item->blocks = blocks;
    out_item->n_rows = target_ti.nrows;

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
    out->project_ms = 0.0;
    out->stamp_ms = 0.0;
    out->bin_ms = 0.0;
    out->local_sat_ms = 0.0;
    out->fill_ms = 0.0;
    out->prop_ms = bp.propagate_ms;
    out->prop_iters = bp.prop_iters;
    out->decode_ms = bp.decode_ms;
    out->policy_total_ms = bp.total_ms;
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

        int out_count = 0;
        for (const std::string &target : loaded.target_order) {
            auto it_tp = loaded.targets.find(target);
            if (it_tp == loaded.targets.end())
                continue;
            if (!build_target_allow_list(loaded, it_tp->second, &h->allow_list.items[out_count], &profile, nullptr))
                return nullptr;
            out_count++;
        }
        h->allow_list.count = out_count;
    }

    auto t1 = Clock::now();
    profile.total_ms = Ms(t1 - t0).count();

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

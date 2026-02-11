#include <vector>
#include <cstring>
#include <string>
#include <cstdint>
#include <chrono>
#include <algorithm>
#include <unordered_map>
#include <map>
#include <set>
#include <sstream>

extern "C" {
#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"
#include "utils/palloc.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
}
#include "policy_evaluator.h"
#include "policy_spec.h"
#include <limits>
#include <cvc5/cvc5.h>

using CtidKey = std::uint64_t;
using Clock = std::chrono::steady_clock;
using Ms = std::chrono::duration<double, std::milli>;

#define CF_TRACE_LOG(fmt, ...) \
    do { \
        if (cf_trace_enabled()) \
            elog(NOTICE, fmt, ##__VA_ARGS__); \
    } while (0)

static bytea *
cf_fetch_file_bytea(const char *name)
{
    StringInfoData sql;
    initStringInfo(&sql);
    appendStringInfo(&sql, "SELECT file FROM public.files WHERE name = %s",
                     quote_literal_cstr(name));
    CF_TRACE_LOG( "policy_stamp: spi: %s", sql.data);
    int ret = SPI_execute(sql.data, true, 0);
    if (ret != SPI_OK_SELECT || SPI_processed != 1)
        return nullptr;
    bool isnull = false;
    Datum d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
    if (isnull) return nullptr;
    bytea *src = DatumGetByteaP(d);
    bytea *copy = (bytea *)palloc(VARSIZE(src));
    memcpy(copy, src, VARSIZE(src));
    return copy;
}

static std::string
cf_bytea_to_string(bytea *b)
{
    if (!b) return "";
    int len = VARSIZE(b) - VARHDRSZ;
    if (len <= 0) return "";
    return std::string(VARDATA(b), VARDATA(b) + len);
}

static inline CtidKey
make_ctid_key(int blk, int off)
{
    return (CtidKey(std::uint32_t(blk)) << 32) | std::uint32_t(off);
}

static inline bool
allow_bit(const uint8 *bits, uint32 rid)
{
    if (!bits) return true;
    return (bits[rid >> 3] & (uint8)(1u << (rid & 7))) != 0;
}

namespace {

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

static std::vector<std::string> split_tab(const std::string &s)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t end = s.find('\t', start);
        if (end == std::string::npos) end = s.size();
        out.push_back(s.substr(start, end - start));
        start = end + 1;
        if (end == s.size()) break;
    }
    return out;
}

static std::set<int> parse_ast_vars(const std::string &s)
{
    std::set<int> out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == 'y') {
            size_t j = i + 1;
            int v = 0;
            bool any = false;
            while (j < s.size() && std::isdigit((unsigned char)s[j])) {
                v = v * 10 + (s[j] - '0');
                any = true;
                j++;
            }
            if (any) out.insert(v);
        }
    }
    return out;
}

static std::vector<std::string> parse_dict_values(bytea *b)
{
    std::vector<std::string> out;
    if (!b) return out;
    char *ptr = VARDATA(b);
    int len = VARSIZE(b) - VARHDRSZ;
    int off = 0;
    while (off + 4 <= len) {
        int32 slen = 0;
        memcpy(&slen, ptr + off, 4);
        off += 4;
        if (slen < 0 || off + slen > len) break;
        out.emplace_back(ptr + off, ptr + off + slen);
        off += slen;
    }
    return out;
}

static void append_top_counts(const std::vector<uint64_t> &counts,
                              const std::vector<std::string> &sig_bits,
                              int topn)
{
    std::vector<int> idx(counts.size());
    for (size_t i = 0; i < counts.size(); i++) idx[i] = (int)i;
    std::sort(idx.begin(), idx.end(), [&](int a, int b) {
        return counts[a] > counts[b];
    });
    for (int i = 0; i < topn && i < (int)idx.size(); i++) {
        int id = idx[i];
        CF_TRACE_LOG( "policy_stamp: class[%d] sig=%s count=%lu",
             id, sig_bits[id].c_str(), (unsigned long)counts[id]);
    }
}
} // namespace

typedef struct PolicyRunProfileC {
    double artifact_parse_ms;
    double stamp_ms;
    double bin_ms;
    double local_sat_ms;
    double prop_ms;
    int prop_iters;
    double decode_ms;
    double policy_total_ms;
} PolicyRunProfileC;

namespace api = cvc5;


extern "C" {
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
}

namespace {

static std::string trim_ws(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

static std::string lower_str(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

static std::string unquote(const std::string &s) {
    if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'')
        return s.substr(1, s.size() - 2);
    return s;
}

static std::string to_lower_str(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

static bool debug_trace_enabled() {
    return cf_trace_enabled();
}

static bool debug_contract_enabled() {
    return cf_debug_enabled() && !cf_trace_enabled();
}

static bool contract_mode_enabled() {
    return cf_contract_enabled();
}

struct ColRef {
    std::string table;
    std::string col;
    std::string key() const { return table + "." + col; }
};

enum class AtomKind { JOIN, CONST };
enum class ConstOp { EQ, NE, LT, LE, GT, GE, IN, LIKE };

struct Loaded;

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
    std::vector<double> num_values;
    bool numeric = false;
};

struct AstNode {
    enum Type { VAR, AND, OR } type;
    int var_id = -1;
    AstNode *left = nullptr;
    AstNode *right = nullptr;
};

enum Tri { TRI_FALSE = 0, TRI_TRUE = 1, TRI_UNKNOWN = 2 };

static Tri tri_and(Tri a, Tri b) {
    if (a == TRI_FALSE || b == TRI_FALSE) return TRI_FALSE;
    if (a == TRI_TRUE && b == TRI_TRUE) return TRI_TRUE;
    return TRI_UNKNOWN;
}

static Tri tri_or(Tri a, Tri b) {
    if (a == TRI_TRUE || b == TRI_TRUE) return TRI_TRUE;
    if (a == TRI_FALSE && b == TRI_FALSE) return TRI_FALSE;
    return TRI_UNKNOWN;
}

static Tri eval_ast(const AstNode *node, const std::vector<int> &vals) {
    if (!node) return TRI_UNKNOWN;
    if (node->type == AstNode::VAR) {
        if (node->var_id <= 0 || node->var_id >= (int)vals.size()) return TRI_UNKNOWN;
        int v = vals[node->var_id];
        if (v < 0) return TRI_UNKNOWN;
        return v ? TRI_TRUE : TRI_FALSE;
    }
    Tri l = eval_ast(node->left, vals);
    Tri r = eval_ast(node->right, vals);
    return (node->type == AstNode::AND) ? tri_and(l, r) : tri_or(l, r);
}

static std::string sql_literal(const std::string &v);

static std::string atom_to_sql(const Atom &a) {
    if (a.kind == AtomKind::JOIN) {
        return a.left.key() + " = " + a.right.key();
    }
    std::string col = a.left.key();
    if (a.op == ConstOp::LIKE) {
        if (a.values.empty()) return col + " LIKE ''";
        return col + " LIKE " + sql_literal(a.values[0]);
    }
    if (a.op == ConstOp::IN) {
        std::string out = col + " IN (";
        for (size_t i = 0; i < a.values.size(); i++) {
            if (i > 0) out += ",";
            out += sql_literal(a.values[i]);
        }
        out += ")";
        return out;
    }
    if (a.op == ConstOp::EQ && !a.values.empty()) {
        return col + " = " + sql_literal(a.values[0]);
    }
    if (a.op == ConstOp::NE && !a.values.empty()) {
        return col + " <> " + sql_literal(a.values[0]);
    }
    if (!a.values.empty()) {
        std::string op;
        switch (a.op) {
            case ConstOp::LT: op = "<"; break;
            case ConstOp::LE: op = "<="; break;
            case ConstOp::GT: op = ">"; break;
            case ConstOp::GE: op = ">="; break;
            default: op = "="; break;
        }
        return col + " " + op + " " + sql_literal(a.values[0]);
    }
    return col;
}

static std::string ast_to_sql(const AstNode *node, const std::map<int, std::string> &atom_sql) {
    if (!node) return "";
    if (node->type == AstNode::VAR) {
        auto it = atom_sql.find(node->var_id);
        if (it != atom_sql.end()) return it->second;
        return "TRUE";
    }
    std::string l = ast_to_sql(node->left, atom_sql);
    std::string r = ast_to_sql(node->right, atom_sql);
    std::string op = (node->type == AstNode::AND) ? " AND " : " OR ";
    return "(" + l + op + r + ")";
}

static void collect_ast_vars(const AstNode *node, std::set<int> &vars) {
    if (!node) return;
    if (node->type == AstNode::VAR) {
        if (node->var_id > 0)
            vars.insert(node->var_id);
        return;
    }
    collect_ast_vars(node->left, vars);
    collect_ast_vars(node->right, vars);
}

static AstNode *parse_ast_expr(const std::vector<std::string> &toks, size_t &idx);

static AstNode *parse_ast_atom(const std::vector<std::string> &toks, size_t &idx) {
    if (idx >= toks.size()) return nullptr;
    const std::string &tok = toks[idx];
    if (tok == "(") {
        idx++;
        AstNode *node = parse_ast_expr(toks, idx);
        if (idx < toks.size() && toks[idx] == ")") idx++;
        return node;
    }
    if (!tok.empty() && tok[0] == 'y') {
        AstNode *node = new AstNode();
        node->type = AstNode::VAR;
        node->var_id = std::atoi(tok.c_str() + 1);
        idx++;
        return node;
    }
    return nullptr;
}

static AstNode *parse_ast_and(const std::vector<std::string> &toks, size_t &idx) {
    AstNode *left = parse_ast_atom(toks, idx);
    while (idx < toks.size() && toks[idx] == "and") {
        idx++;
        AstNode *right = parse_ast_atom(toks, idx);
        AstNode *node = new AstNode();
        node->type = AstNode::AND;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

static AstNode *parse_ast_expr(const std::vector<std::string> &toks, size_t &idx) {
    AstNode *left = parse_ast_and(toks, idx);
    while (idx < toks.size() && toks[idx] == "or") {
        idx++;
        AstNode *right = parse_ast_and(toks, idx);
        AstNode *node = new AstNode();
        node->type = AstNode::OR;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

static AstNode *parse_ast_string(const std::string &ast_str) {
    std::string lower = lower_str(ast_str);
    std::vector<std::string> toks;
    for (size_t i = 0; i < lower.size(); ) {
        char c = lower[i];
        if (std::isspace(static_cast<unsigned char>(c))) { i++; continue; }
        if (c == '(' || c == ')') {
            toks.push_back(std::string(1, c));
            i++;
            continue;
        }
        if (c == 'y') {
            size_t j = i + 1;
            while (j < lower.size() && std::isdigit(static_cast<unsigned char>(lower[j]))) j++;
            toks.push_back(lower.substr(i, j - i));
            i = j;
            continue;
        }
        size_t j = i + 1;
        while (j < lower.size() && std::isalpha(static_cast<unsigned char>(lower[j]))) j++;
        toks.push_back(lower.substr(i, j - i));
        i = j;
    }
    size_t idx = 0;
    return parse_ast_expr(toks, idx);
}

static bool parse_colref(const std::string &s, ColRef *out) {
    auto pos = s.find('.');
    if (pos == std::string::npos) return false;
    out->table = s.substr(0, pos);
    out->col = s.substr(pos + 1);
    return true;
}

static bool parse_schema_key(const std::string &key, ColRef *out, int *class_id, bool *is_join) {
    if (is_join) *is_join = false;
    if (class_id) *class_id = -1;
    if (key.rfind("join:", 0) == 0) {
        std::string rest = key.substr(5);
        std::string tablecol = rest;
        int cid = -1;
        size_t pos = rest.find(" class=");
        if (pos != std::string::npos) {
            tablecol = rest.substr(0, pos);
            cid = std::atoi(rest.substr(pos + 7).c_str());
        }
        if (!parse_colref(tablecol, out)) return false;
        if (is_join) *is_join = true;
        if (class_id) *class_id = cid;
        return true;
    }
    if (key.rfind("const:", 0) == 0) {
        std::string rest = key.substr(6);
        if (!parse_colref(rest, out)) return false;
        if (is_join) *is_join = false;
        if (class_id) *class_id = -1;
        return true;
    }
    return false;
}

static std::vector<std::string> parse_dict(const char *buf, size_t len) {
    std::vector<std::string> vals;
    size_t offset = 0;
    while (offset + 4 <= len) {
        int32 l = 0;
        std::memcpy(&l, buf + offset, 4);
        offset += 4;
        if (l < 0 || offset + (size_t)l > len) break;
        vals.emplace_back(buf + offset, buf + offset + l);
        offset += l;
    }
    return vals;
}

static std::vector<std::string> parse_schema_lines(const std::string &text) {
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string line = trim_ws(text.substr(start, end - start));
        if (!line.empty())
            lines.push_back(line);
        if (end >= text.size()) break;
        start = end + 1;
    }
    return lines;
}

struct CtidArray {
    const int32_t *data = nullptr;
    uint32 len = 0; // number of int32 entries
};

static int32 find_rid_linear(const CtidArray &arr, int32 blk, int32 off) {
    if (!arr.data || arr.len < 2) return -1;
    uint32 n = arr.len / 2;
    for (uint32 r = 0; r < n; r++) {
        int32 b = arr.data[2 * r];
        int32 o = arr.data[2 * r + 1];
        if (b == blk && o == off)
            return (int32)r;
    }
    return -1;
}

static bool parse_number(const std::string &s, double *out) {
    char *end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (!end || end == s.c_str() || *end != '\0') return false;
    *out = v;
    return true;
}

enum class DictType { INT, FLOAT, TEXT, UNKNOWN };

static DictType parse_dict_type_str(const std::string &s) {
    std::string v = to_lower_str(trim_ws(s));
    if (v == "int") return DictType::INT;
    if (v == "float") return DictType::FLOAT;
    if (v == "text") return DictType::TEXT;
    return DictType::UNKNOWN;
}

static bool dict_type_numeric(DictType t) {
    return t == DictType::INT || t == DictType::FLOAT;
}

static bool is_like_prefix_pattern(const std::string &pat, std::string *prefix_out) {
    if (pat.size() < 2) return false;
    if (pat.back() != '%') return false;
    for (size_t i = 0; i + 1 < pat.size(); i++) {
        if (pat[i] == '%' || pat[i] == '_') return false;
    }
    if (prefix_out) *prefix_out = pat.substr(0, pat.size() - 1);
    return true;
}

static bool starts_with(const std::string &s, const std::string &prefix) {
    return s.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), s.begin());
}

static bool like_match(const std::string &s, const std::string &pat) {
    /* Minimal Postgres LIKE matcher for % (any sequence) and _ (single char). */
    size_t si = 0, pi = 0;
    size_t star_pi = std::string::npos;
    size_t star_si = 0;

    while (si < s.size()) {
        if (pi < pat.size() && (pat[pi] == '_' || pat[pi] == s[si])) {
            si++;
            pi++;
            continue;
        }
        if (pi < pat.size() && pat[pi] == '%') {
            while (pi < pat.size() && pat[pi] == '%')
                pi++;
            if (pi == pat.size())
                return true; /* trailing % matches everything */
            star_pi = pi;
            star_si = si;
            continue;
        }
        if (star_pi != std::string::npos) {
            star_si++;
            si = star_si;
            pi = star_pi;
            continue;
        }
        return false;
    }
    while (pi < pat.size() && pat[pi] == '%')
        pi++;
    return pi == pat.size();
}

static std::vector<uint8_t> build_allowed_tokens(const std::vector<std::string> &dict_vals,
                                                 const Atom &atom,
                                                 DictType dict_type) {
    std::vector<uint8_t> allowed(dict_vals.size(), 0);
    if (dict_vals.empty()) return allowed;

    const bool numeric_type = dict_type_numeric(dict_type);

    if (atom.op == ConstOp::LIKE) {
        if (numeric_type) {
            ereport(ERROR, (errmsg("policy: LIKE requires text dict for %s",
                                   atom.left.key().c_str())));
        }
        if (atom.values.empty()) {
            ereport(ERROR, (errmsg("policy: LIKE missing pattern for %s",
                                   atom.left.key().c_str())));
        }
        std::string prefix;
        if (is_like_prefix_pattern(atom.values[0], &prefix)) {
            if (prefix.empty()) {
                std::fill(allowed.begin(), allowed.end(), 1);
                return allowed;
            }
            auto it = std::lower_bound(dict_vals.begin(), dict_vals.end(), prefix);
            size_t idx = (size_t)(it - dict_vals.begin());
            while (idx < dict_vals.size() && starts_with(dict_vals[idx], prefix)) {
                allowed[idx] = 1;
                idx++;
            }
            return allowed;
        }

        /* General LIKE patterns: scan dict values and match with wildcards. */
        const std::string &pat = atom.values[0];
        for (size_t i = 0; i < dict_vals.size(); i++) {
            allowed[i] = like_match(dict_vals[i], pat) ? 1 : 0;
        }
        return allowed;
    }

    if (atom.op == ConstOp::EQ || atom.op == ConstOp::IN || atom.op == ConstOp::NE) {
        if (numeric_type) {
            std::vector<double> qvals;
            qvals.reserve(atom.values.size());
            for (const auto &v : atom.values) {
                double dv = 0.0;
                if (!parse_number(v, &dv)) {
                    ereport(ERROR, (errmsg("policy: numeric literal parse failed for %s",
                                           v.c_str())));
                }
                qvals.push_back(dv);
            }
            for (size_t i = 0; i < dict_vals.size(); i++) {
                double dv = 0.0;
                if (!parse_number(dict_vals[i], &dv)) {
                    ereport(ERROR, (errmsg("policy: numeric dict parse failed for %s",
                                           atom.left.key().c_str())));
                }
                bool hit = false;
                for (double q : qvals) {
                    if (dv == q) { hit = true; break; }
                }
                if (atom.op == ConstOp::NE) {
                    allowed[i] = hit ? 0 : 1;
                } else {
                    allowed[i] = hit ? 1 : 0;
                }
            }
        } else {
            for (size_t i = 0; i < dict_vals.size(); i++) {
                bool hit = false;
                for (const auto &q : atom.values) {
                    if (dict_vals[i] == q) { hit = true; break; }
                }
                if (atom.op == ConstOp::NE) {
                    allowed[i] = hit ? 0 : 1;
                } else {
                    allowed[i] = hit ? 1 : 0;
                }
            }
        }
        return allowed;
    }

    if (!numeric_type) {
        ereport(ERROR, (errmsg("policy: range operator requires numeric dict for %s",
                               atom.left.key().c_str())));
    }
    if (atom.values.empty()) {
        ereport(ERROR, (errmsg("policy: range operator missing literal for %s",
                               atom.left.key().c_str())));
    }
    double q = 0.0;
    if (!parse_number(atom.values[0], &q)) {
        ereport(ERROR, (errmsg("policy: numeric literal parse failed for %s",
                               atom.values[0].c_str())));
    }
    std::vector<double> dict_nums;
    dict_nums.reserve(dict_vals.size());
    for (const auto &v : dict_vals) {
        double dv = 0.0;
        if (!parse_number(v, &dv)) {
            ereport(ERROR, (errmsg("policy: numeric dict parse failed for %s",
                                   atom.left.key().c_str())));
        }
        dict_nums.push_back(dv);
    }
    auto it_lo = std::lower_bound(dict_nums.begin(), dict_nums.end(), q);
    auto it_hi = std::upper_bound(dict_nums.begin(), dict_nums.end(), q);
    size_t lo = (size_t)(it_lo - dict_nums.begin());
    size_t hi = (size_t)(it_hi - dict_nums.begin());
    switch (atom.op) {
        case ConstOp::LT:
            for (size_t i = 0; i < lo; i++) allowed[i] = 1;
            break;
        case ConstOp::LE:
            for (size_t i = 0; i < hi; i++) allowed[i] = 1;
            break;
        case ConstOp::GT:
            for (size_t i = hi; i < dict_vals.size(); i++) allowed[i] = 1;
            break;
        case ConstOp::GE:
            for (size_t i = lo; i < dict_vals.size(); i++) allowed[i] = 1;
            break;
        default:
            break;
    }
    return allowed;
}

struct Bitset {
    std::vector<uint8_t> bytes;
    size_t nbits = 0;
    void ensure(size_t bit) {
        if (bit + 1 > nbits) {
            nbits = bit + 1;
            size_t need = (nbits + 7) / 8;
            if (need > bytes.size())
                bytes.resize(need, 0);
        }
    }
    void set(size_t bit) {
        ensure(bit);
        bytes[bit >> 3] |= (uint8_t)(1u << (bit & 7));
    }
    bool test(size_t bit) const {
        if (bit >= nbits) return false;
        return (bytes[bit >> 3] & (uint8_t)(1u << (bit & 7))) != 0;
    }
};

static size_t bitset_popcount(const Bitset &bs, size_t limit_bits) {
    size_t cnt = 0;
    size_t n = std::min(limit_bits, bs.nbits);
    for (size_t i = 0; i < n; i++) {
        if (bs.test(i)) cnt++;
    }
    return cnt;
}

static void bitset_set_all(Bitset &bs, size_t nbits) {
    bs.nbits = nbits;
    size_t bytes = (nbits + 7) / 8;
    bs.bytes.assign(bytes, 0xFF);
    if (nbits % 8) {
        uint8_t mask = (uint8_t)((1u << (nbits % 8)) - 1u);
        bs.bytes.back() &= mask;
    }
}

static bool bitset_equals(const Bitset &a, const Bitset &b, size_t limit_bits) {
    size_t nbits = std::min(limit_bits, std::min(a.nbits, b.nbits));
    size_t nbytes = (nbits + 7) / 8;
    for (size_t i = 0; i < nbytes; i++) {
        uint8_t mask = 0xFF;
        if (i + 1 == nbytes && (nbits % 8) != 0)
            mask = (uint8_t)((1u << (nbits % 8)) - 1u);
        uint8_t av = (i < a.bytes.size()) ? (a.bytes[i] & mask) : 0;
        uint8_t bv = (i < b.bytes.size()) ? (b.bytes[i] & mask) : 0;
        if (av != bv) return false;
    }
    return true;
}

static bool bitset_intersect(Bitset &dst, const Bitset &src) {
    bool changed = false;
    size_t n = dst.bytes.size();
    size_t m = src.bytes.size();
    size_t nmin = std::min(n, m);
    for (size_t i = 0; i < nmin; i++) {
        uint8_t before = dst.bytes[i];
        dst.bytes[i] &= src.bytes[i];
        if (dst.bytes[i] != before) changed = true;
    }
    for (size_t i = nmin; i < n; i++) {
        if (dst.bytes[i] != 0) {
            dst.bytes[i] = 0;
            changed = true;
        }
    }
    return changed;
}

static std::string bitset_first_tokens(const Bitset &bs, size_t limit) {
    std::string out;
    size_t count = 0;
    for (size_t i = 0; i < bs.nbits && count < limit; i++) {
        if (bs.test(i)) {
            if (!out.empty()) out += ",";
            out += std::to_string(i);
            count++;
        }
    }
    if (out.empty()) out = "<none>";
    return out;
}

static std::string sql_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\'') out += "''";
        else out.push_back(c);
    }
    return out;
}

static std::string sql_literal(const std::string &v) {
    double dv = 0.0;
    if (parse_number(v, &dv)) return v;
    return "'" + sql_escape(v) + "'";
}

struct TableInfo {
    std::string name;
    const int32_t *code = nullptr;
    size_t code_len = 0;
    uint32 n_rows = 0;
    std::map<std::string, int> schema_offset;
    int stride = 0;
    std::vector<int> join_class_ids;
    std::vector<int> join_token_idx;
    struct JoinAtomInfo {
        int atom_id;
        int class_id;
        int token_idx;
        std::string other_table;
    };
    std::vector<JoinAtomInfo> join_atoms;
    std::vector<int> const_atom_ids;
    std::vector<int> const_token_idx;
};

struct Loaded {
    std::map<std::string, TableInfo> tables;
    std::map<std::string, CtidArray> ctid_map;
    std::map<std::string, std::vector<std::string>> dicts;
    std::map<std::string, DictType> dict_types;
    std::set<std::string> target_set;
    std::map<std::string, AstNode*> target_ast;
    std::map<std::string, std::set<int>> target_vars;
    std::map<std::string, std::set<int>> target_join_classes;
    bool has_multi_join = false;
    std::vector<Atom> atoms;
    std::vector<Atom*> atom_by_id;
    std::map<std::string, int> join_class_by_col;
    std::map<int, std::vector<std::string>> join_class_cols;
    int class_count = 0;
};

static DictType dict_type_for_key(const Loaded &loaded, const std::string &key) {
    auto it = loaded.dict_types.find(key);
    if (it != loaded.dict_types.end()) return it->second;
    return DictType::UNKNOWN;
}

struct AstInfo {
    std::set<std::string> tables;
    bool has_join = false;
};

static AstInfo collect_ast_info(const Loaded &loaded, const AstNode *node) {
    AstInfo info;
    if (!node) return info;
    if (node->type == AstNode::VAR) {
        int id = node->var_id;
        if (id > 0 && id < (int)loaded.atom_by_id.size()) {
            const Atom *ap = loaded.atom_by_id[id];
            if (ap) {
                if (ap->kind == AtomKind::JOIN) {
                    info.has_join = true;
                    info.tables.insert(ap->left.table);
                    info.tables.insert(ap->right.table);
                } else {
                    info.tables.insert(ap->left.table);
                }
            }
        }
        return info;
    }
    AstInfo l = collect_ast_info(loaded, node->left);
    AstInfo r = collect_ast_info(loaded, node->right);
    info.has_join = l.has_join || r.has_join;
    info.tables = l.tables;
    info.tables.insert(r.tables.begin(), r.tables.end());
    return info;
}

struct DerivedVar {
    int id = -1;
    std::string table;
    AstNode *ast = nullptr;
    std::set<int> vars;
};

static AstNode *clone_ast(const AstNode *node) {
    if (!node) return nullptr;
    AstNode *n = new AstNode();
    n->type = node->type;
    n->var_id = node->var_id;
    n->left = clone_ast(node->left);
    n->right = clone_ast(node->right);
    return n;
}

static AstNode *extract_local_subtrees(const Loaded &loaded,
                                       const AstNode *node,
                                       const std::string &target,
                                       std::vector<DerivedVar> &out,
                                       int &next_id,
                                       bool parent_extracted = false)
{
    if (!node) return nullptr;
    AstInfo info = collect_ast_info(loaded, node);
    if (!parent_extracted && !info.has_join && info.tables.size() == 1) {
        const std::string &tbl = *info.tables.begin();
        if (tbl != target) {
            DerivedVar dv;
            dv.id = next_id++;
            dv.table = tbl;
            dv.ast = clone_ast(node);
            collect_ast_vars(node, dv.vars);
            out.push_back(dv);
            AstNode *var = new AstNode();
            var->type = AstNode::VAR;
            var->var_id = dv.id;
            return var;
        }
    }
    if (node->type == AstNode::VAR) {
        AstNode *n = new AstNode();
        n->type = AstNode::VAR;
        n->var_id = node->var_id;
        return n;
    }
    AstNode *n = new AstNode();
    n->type = node->type;
    n->left = extract_local_subtrees(loaded, node->left, target, out, next_id, parent_extracted);
    n->right = extract_local_subtrees(loaded, node->right, target, out, next_id, parent_extracted);
    return n;
}

struct Hubs {
    std::vector<std::map<std::string, Bitset>> present_by_class;
    std::map<int, std::vector<uint8_t>> const_allowed;
    std::vector<size_t> max_tok;
};

// NOTE: We intentionally avoid a "sig_by_row: vector<string>" pipeline here.
// With millions of rows, one heap allocation per row causes massive RSS and
// allocator overhead. The active implementation does streaming signature
// binning and only stores one signature per *bin* (flat byte slab), plus a
// row_to_bin map.

static bool load_phase(const PolicyArtifactC *arts, int art_count,
                       const PolicyEngineInputC *in, Loaded *out)
{
    if (!arts || art_count <= 0 || !in || !out)
        return false;
    const bool contract = debug_contract_enabled();
    const bool contract_mode = contract_mode_enabled();

    for (int i = 0; i < in->target_count; i++) {
        if (!in->target_tables || !in->target_tables[i]) continue;
        std::string t = in->target_tables[i];
        out->target_set.insert(t);
        const char *astr = (in->target_asts && in->target_asts[i]) ? in->target_asts[i] : "";
        if (astr && astr[0] != '\0') {
            AstNode *node = parse_ast_string(astr);
            out->target_ast[t] = node;
            collect_ast_vars(node, out->target_vars[t]);
        } else {
            out->target_ast[t] = nullptr;
        }
    }

    out->atoms.reserve(in->atom_count);
    for (int i = 0; i < in->atom_count; i++) {
        const PolicyAtomC *pa = &in->atoms[i];
        if (!pa->lhs_schema_key) continue;
        Atom atom;
        atom.id = pa->atom_id;
        atom.join_class_id = pa->join_class_id;
        atom.lhs_schema_key = pa->lhs_schema_key ? pa->lhs_schema_key : "";
        atom.rhs_schema_key = pa->rhs_schema_key ? pa->rhs_schema_key : "";
        if (pa->kind == POLICY_ATOM_JOIN_EQ) {
            atom.kind = AtomKind::JOIN;
            ColRef lref, rref;
            int cid = -1;
            bool is_join = false;
            if (!parse_schema_key(atom.lhs_schema_key, &lref, &cid, &is_join))
                return false;
            if (!parse_schema_key(atom.rhs_schema_key, &rref, &cid, &is_join))
                return false;
            atom.left = lref;
            atom.right = rref;
        } else if (pa->kind == POLICY_ATOM_COL_CONST) {
            atom.kind = AtomKind::CONST;
            ColRef lref;
            int cid = -1;
            bool is_join = false;
            if (!parse_schema_key(atom.lhs_schema_key, &lref, &cid, &is_join))
                return false;
            atom.left = lref;
            if (pa->op == POLICY_OP_EQ) atom.op = ConstOp::EQ;
            else if (pa->op == POLICY_OP_NE) atom.op = ConstOp::NE;
            else if (pa->op == POLICY_OP_IN) atom.op = ConstOp::IN;
            else if (pa->op == POLICY_OP_LIKE) atom.op = ConstOp::LIKE;
            else if (pa->op == POLICY_OP_LT) atom.op = ConstOp::LT;
            else if (pa->op == POLICY_OP_LE) atom.op = ConstOp::LE;
            else if (pa->op == POLICY_OP_GT) atom.op = ConstOp::GT;
            else if (pa->op == POLICY_OP_GE) atom.op = ConstOp::GE;
            for (int v = 0; v < pa->const_count; v++) {
                if (pa->const_values && pa->const_values[v])
                    atom.values.push_back(pa->const_values[v]);
            }
        } else {
            continue;
        }
        out->atoms.push_back(atom);
    }

    for (auto &a : out->atoms) {
        if (a.kind == AtomKind::JOIN) {
            if (a.join_class_id < 0)
                return false;
            out->join_class_by_col[a.left.key()] = a.join_class_id;
            out->join_class_by_col[a.right.key()] = a.join_class_id;
        } else if (a.join_class_id >= 0) {
            out->join_class_by_col[a.left.key()] = a.join_class_id;
        }
    }
    for (const auto &kv : out->join_class_by_col) {
        if (kv.second + 1 > out->class_count)
            out->class_count = kv.second + 1;
    }
    if (out->class_count == 0 && !out->atoms.empty())
        out->class_count = 1;

    bool has_join_atoms = false;
    for (const auto &a : out->atoms) {
        if (a.kind == AtomKind::JOIN) {
            has_join_atoms = true;
            break;
        }
    }

    std::map<std::string, std::set<std::string>> table_join_cols;
    std::map<std::string, std::set<std::string>> table_const_cols;
    for (auto &a : out->atoms) {
        if (a.kind == AtomKind::JOIN) {
            table_join_cols[a.left.table].insert(a.left.key());
            table_join_cols[a.right.table].insert(a.right.key());
        } else {
            table_const_cols[a.left.table].insert(a.left.key());
            if (a.join_class_id >= 0)
                table_join_cols[a.left.table].insert(a.left.key());
        }
    }

    std::map<std::string, std::string> schema_text;
    std::map<std::string, int> stride_map;
    std::map<std::string, std::vector<std::string>> cols_map;
    const std::string schema_suffix = "_code_schema";
    const std::string stride_suffix = "_code_stride";
    const size_t schema_len = schema_suffix.size();
    const size_t stride_len = stride_suffix.size();
    bool saw_join_classes = false;
    size_t join_classes_bytes = 0;
    for (int i = 0; i < art_count; i++) {
        const char *art_name = arts[i].name ? arts[i].name : "(null)";
        if (contract)
            CF_TRACE_LOG( "policy_contract: artifact name=%s bytes=%zu",
                 art_name, (size_t)arts[i].len);
        if (!arts[i].name || !arts[i].data) continue;
        std::string name = arts[i].name;
        if (name == "meta/join_classes") {
            saw_join_classes = true;
            join_classes_bytes = arts[i].len;
            std::string jc_txt((const char *)arts[i].data, arts[i].len);
            auto lines = split_lines(jc_txt);
            for (const auto &line : lines) {
                size_t cpos = line.find("class=");
                size_t cols = line.find("cols=");
                if (cpos == std::string::npos || cols == std::string::npos)
                    continue;
                int cid = std::atoi(line.c_str() + cpos + 6);
                std::string list = line.substr(cols + 5);
                std::stringstream ss(list);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    while (!item.empty() && std::isspace((unsigned char)item.front()))
                        item.erase(item.begin());
                    while (!item.empty() && std::isspace((unsigned char)item.back()))
                        item.pop_back();
                    if (!item.empty())
                        out->join_class_cols[cid].push_back(item);
                }
            }
            continue;
        }
        if (name.rfind("meta/cols/", 0) == 0) {
            std::string table = name.substr(strlen("meta/cols/"));
            cols_map[table] = parse_schema_lines(std::string((const char *)arts[i].data, arts[i].len));
        } else if (name.size() > 10 && name.substr(name.size() - 10) == "_code_base") {
            std::string table = name.substr(0, name.size() - 10);
            TableInfo &ti = out->tables[table];
            ti.name = table;
            ti.code = (const int32_t *)arts[i].data;
            ti.code_len = arts[i].len / sizeof(int32_t);
        } else if (name.size() > 5 && name.substr(name.size() - 5) == "_code") {
            std::string table = name.substr(0, name.size() - 5);
            TableInfo &ti = out->tables[table];
            ti.name = table;
            ti.code = (const int32_t *)arts[i].data;
            ti.code_len = arts[i].len / sizeof(int32_t);
        } else if (name.size() > 5 && name.substr(name.size() - 5) == "_ctid") {
            std::string table = name.substr(0, name.size() - 5);
            CtidArray arr;
            arr.data = (const int32_t *)arts[i].data;
            arr.len = (uint32)(arts[i].len / sizeof(int32_t));
            out->ctid_map[table] = arr;
        } else if (name.size() > schema_len && name.substr(name.size() - schema_len) == schema_suffix) {
            std::string table = name.substr(0, name.size() - schema_len);
            schema_text[table] = std::string((const char *)arts[i].data, arts[i].len);
        } else if (name.size() > stride_len && name.substr(name.size() - stride_len) == stride_suffix) {
            std::string table = name.substr(0, name.size() - stride_len);
            if (arts[i].len < (size_t)sizeof(int32_t))
                return false;
            int32_t s = 0;
            std::memcpy(&s, arts[i].data, sizeof(int32_t));
            stride_map[table] = (int)s;
        } else if (name.rfind("meta/dict_type/", 0) == 0) {
            std::string rest = name.substr(strlen("meta/dict_type/"));
            auto pos = rest.find('/');
            if (pos == std::string::npos) continue;
            std::string table = rest.substr(0, pos);
            std::string col = rest.substr(pos + 1);
            std::string key = table + "." + col;
            std::string val((const char *)arts[i].data, arts[i].len);
            out->dict_types[key] = parse_dict_type_str(val);
        } else if (name.rfind("dict/", 0) == 0) {
            std::string rest = name.substr(strlen("dict/"));
            auto pos = rest.find('/');
            if (pos == std::string::npos) continue;
            std::string table = rest.substr(0, pos);
            std::string col = rest.substr(pos + 1);
            std::string key = table + "." + col;
            out->dicts[key] = parse_dict((const char *)arts[i].data, arts[i].len);
        } else if (name.size() > 5 && name.substr(name.size() - 5) == "_dict") {
            std::string base = name.substr(0, name.size() - 5);
            auto pos = base.find('_');
            if (pos == std::string::npos) continue;
            std::string table = base.substr(0, pos);
            std::string col = base.substr(pos + 1);
            std::string key = table + "." + col;
            out->dicts[key] = parse_dict((const char *)arts[i].data, arts[i].len);
        }
    }

    std::map<std::string, int> meta_class_by_col;
    if (contract) {
        for (const auto &kv : out->join_class_cols) {
            int cid = kv.first;
            for (const auto &col : kv.second) {
                auto ins = meta_class_by_col.emplace(col, cid);
                if (!ins.second && ins.first->second != cid) {
                    ereport(ERROR, (errmsg("policy_contract: meta/join_classes duplicate col %s in classes %d and %d",
                                           col.c_str(), ins.first->second, cid)));
                }
            }
        }
        if (has_join_atoms) {
            if (!saw_join_classes)
                ereport(ERROR, (errmsg("policy_contract: missing meta/join_classes artifact")));
            if (join_classes_bytes == 0 || meta_class_by_col.empty())
                ereport(ERROR, (errmsg("policy_contract: meta/join_classes empty (bytes=%zu)",
                                       join_classes_bytes)));
        }
        for (const auto &a : out->atoms) {
            if (a.kind == AtomKind::JOIN) {
                auto itl = meta_class_by_col.find(a.left.key());
                auto itr = meta_class_by_col.find(a.right.key());
                if (itl == meta_class_by_col.end() || itr == meta_class_by_col.end()) {
                    ereport(ERROR, (errmsg("policy_contract: join atom y%d missing in meta/join_classes (lhs=%s rhs=%s)",
                                           a.id, a.left.key().c_str(), a.right.key().c_str())));
                }
                if (itl->second != itr->second) {
                    ereport(ERROR, (errmsg("policy_contract: join atom y%d meta class mismatch lhs=%d rhs=%d (lhs=%s rhs=%s)",
                                           a.id, itl->second, itr->second,
                                           a.left.key().c_str(), a.right.key().c_str())));
                }
                if (a.join_class_id != itl->second) {
                    ereport(ERROR, (errmsg("policy_contract: join atom y%d class mismatch atom=%d meta=%d (lhs=%s rhs=%s)",
                                           a.id, a.join_class_id, itl->second,
                                           a.left.key().c_str(), a.right.key().c_str())));
                }
            } else if (a.join_class_id >= 0) {
                auto itl = meta_class_by_col.find(a.left.key());
                if (itl == meta_class_by_col.end()) {
                    ereport(ERROR, (errmsg("policy_contract: const atom y%d missing in meta/join_classes (col=%s)",
                                           a.id, a.left.key().c_str())));
                }
                if (a.join_class_id != itl->second) {
                    ereport(ERROR, (errmsg("policy_contract: const atom y%d class mismatch atom=%d meta=%d (col=%s)",
                                           a.id, a.join_class_id, itl->second, a.left.key().c_str())));
                }
            }
        }
    }

    for (auto &kv : out->tables) {
        TableInfo &ti = kv.second;
        std::vector<std::string> join_cols(table_join_cols[ti.name].begin(),
                                           table_join_cols[ti.name].end());
        std::vector<std::string> const_cols(table_const_cols[ti.name].begin(),
                                            table_const_cols[ti.name].end());
        std::sort(join_cols.begin(), join_cols.end());
        std::sort(const_cols.begin(), const_cols.end());

        auto cit = cols_map.find(ti.name);
        if (cit != cols_map.end()) {
            const auto &cols = cit->second;
            ti.stride = (int)cols.size() + 1;
            if (ti.stride <= 0)
                return false;
            ti.schema_offset["rid"] = 0;
            for (size_t i = 0; i < cols.size(); i++) {
                const std::string &c = cols[i];
                ti.schema_offset["const:" + c] = (int)i + 1;
                auto itc = out->join_class_by_col.find(c);
                if (itc != out->join_class_by_col.end()) {
                    std::string key = "join:" + c + " class=" + std::to_string(itc->second);
                    ti.schema_offset[key] = (int)i + 1;
                }
            }
        } else {
            auto sit = schema_text.find(ti.name);
            if (sit == schema_text.end())
                return false;
            auto stit = stride_map.find(ti.name);
            if (stit == stride_map.end())
                return false;
            ti.stride = stit->second;
            if (ti.stride <= 0)
                return false;
            std::vector<std::string> lines = parse_schema_lines(sit->second);
            if ((int)lines.size() != ti.stride)
                return false;
            for (size_t i = 0; i < lines.size(); i++)
                ti.schema_offset[lines[i]] = (int)i;
        }

        if (ti.code_len % (size_t)ti.stride != 0)
            return false;
        ti.n_rows = (uint32)(ti.code_len / (size_t)ti.stride);

        for (const auto &c : join_cols) {
            int cid = out->join_class_by_col[c];
            std::string key = "join:" + c + " class=" + std::to_string(cid);
            auto it = ti.schema_offset.find(key);
            if (it == ti.schema_offset.end())
                return false;
            ti.join_class_ids.push_back(cid);
            ti.join_token_idx.push_back(it->second);
        }
        for (auto &a : out->atoms) {
            if (a.kind != AtomKind::JOIN)
                continue;
            if (a.left.table == ti.name) {
                TableInfo::JoinAtomInfo info;
                info.atom_id = a.id;
                info.class_id = a.join_class_id;
                auto it = ti.schema_offset.find(a.lhs_schema_key);
                if (it == ti.schema_offset.end())
                    return false;
                info.token_idx = it->second;
                info.other_table = a.right.table;
                ti.join_atoms.push_back(info);
            } else if (a.right.table == ti.name) {
                TableInfo::JoinAtomInfo info;
                info.atom_id = a.id;
                info.class_id = a.join_class_id;
                auto it = ti.schema_offset.find(a.rhs_schema_key);
                if (it == ti.schema_offset.end())
                    return false;
                info.token_idx = it->second;
                info.other_table = a.left.table;
                ti.join_atoms.push_back(info);
            }
        }
        for (auto &a : out->atoms) {
            if (a.kind != AtomKind::CONST) continue;
            if (a.left.table != ti.name) continue;
            ti.const_atom_ids.push_back(a.id);
            auto it = ti.schema_offset.find(a.lhs_schema_key);
            if (it == ti.schema_offset.end())
                return false;
            ti.const_token_idx.push_back(it->second);
        }
    }

    int max_id = 0;
    for (auto &a : out->atoms)
        if (a.id > max_id) max_id = a.id;
    out->atom_by_id.assign(max_id + 1, nullptr);
    for (auto &a : out->atoms) {
        if (a.id > 0 && a.id < (int)out->atom_by_id.size())
            out->atom_by_id[a.id] = &a;
    }

    for (const auto &kv : out->target_vars) {
        const std::string &tname = kv.first;
        const std::set<int> &vars = kv.second;
        std::set<int> jc;
        for (int aid : vars) {
            if (aid <= 0 || aid >= (int)out->atom_by_id.size())
                continue;
            const Atom *ap = out->atom_by_id[aid];
            if (!ap) continue;
            if (ap->kind == AtomKind::JOIN && ap->join_class_id >= 0)
                jc.insert(ap->join_class_id);
        }
        out->target_join_classes[tname] = jc;
        if (jc.size() > 1) {
            std::string list;
            for (int cid : jc) {
                if (!list.empty()) list += ", ";
                list += std::to_string(cid);
            }
            out->has_multi_join = true;
            if (contract_mode) {
                CF_TRACE_LOG( "policy_contract: multi-join target=%s classes=[%s]",
                     tname.c_str(), list.c_str());
            }
        }
    }

    if (contract) {
        for (const auto &kv : out->join_class_cols) {
            std::string cols;
            for (size_t i = 0; i < kv.second.size(); i++) {
                if (i > 0) cols += ", ";
                cols += kv.second[i];
            }
            CF_TRACE_LOG( "policy_contract: join_class=%d cols=[%s]", kv.first, cols.c_str());
        }
        for (const auto &kv : out->tables) {
            const TableInfo &ti = kv.second;
            auto cit = cols_map.find(ti.name);
            if (cit != cols_map.end()) {
                std::string cols;
                for (size_t i = 0; i < cit->second.size(); i++) {
                    if (i > 0) cols += ", ";
                    cols += cit->second[i];
                }
                CF_TRACE_LOG( "policy_contract: meta/cols/%s=[%s]", ti.name.c_str(), cols.c_str());
            }
            CF_TRACE_LOG( "policy_contract: %s_code_base stride=%d rows=%u",
                 ti.name.c_str(), ti.stride, ti.n_rows);
        }
        std::set<std::string> printed_offsets;
        for (const auto &a : out->atoms) {
            if (a.kind == AtomKind::JOIN) {
                std::string k1 = a.left.key();
                std::string k2 = a.right.key();
                const TableInfo &lt = out->tables[a.left.table];
                const TableInfo &rt = out->tables[a.right.table];
                std::string o1 = a.lhs_schema_key;
                std::string o2 = a.rhs_schema_key;
                if (printed_offsets.insert(o1).second) {
                    auto it = lt.schema_offset.find(o1);
                    if (it != lt.schema_offset.end())
                        CF_TRACE_LOG( "policy_contract: offset %s = %d stride=%d",
                             o1.c_str(), it->second, lt.stride);
                }
                if (printed_offsets.insert(o2).second) {
                    auto it = rt.schema_offset.find(o2);
                    if (it != rt.schema_offset.end())
                        CF_TRACE_LOG( "policy_contract: offset %s = %d stride=%d",
                             o2.c_str(), it->second, rt.stride);
                }
            } else {
                const TableInfo &lt = out->tables[a.left.table];
                std::string key = a.lhs_schema_key;
                if (printed_offsets.insert(key).second) {
                    auto it = lt.schema_offset.find(key);
                    if (it != lt.schema_offset.end())
                        CF_TRACE_LOG( "policy_contract: offset %s = %d stride=%d",
                             key.c_str(), it->second, lt.stride);
                }
            }
        }
        for (const auto &a : out->atoms) {
            if (a.kind == AtomKind::JOIN) {
                int meta_lhs = -1;
                int meta_rhs = -1;
                auto itl = meta_class_by_col.find(a.left.key());
                if (itl != meta_class_by_col.end()) meta_lhs = itl->second;
                auto itr = meta_class_by_col.find(a.right.key());
                if (itr != meta_class_by_col.end()) meta_rhs = itr->second;
                std::string class_cols;
                auto itc = out->join_class_cols.find(meta_lhs);
                if (itc != out->join_class_cols.end()) {
                    for (size_t i = 0; i < itc->second.size(); i++) {
                        if (i > 0) class_cols += ", ";
                        class_cols += itc->second[i];
                    }
                }
                CF_TRACE_LOG( "policy_contract: atom y%d type=JOIN_EQ lhs=%s rhs=%s join_class=%d meta_lhs=%d meta_rhs=%d class_cols=[%s]",
                     a.id, a.left.key().c_str(), a.right.key().c_str(), a.join_class_id,
                     meta_lhs, meta_rhs, class_cols.c_str());
            } else {
                std::string dict_name = "dict/" + a.left.table + "/" + a.left.col;
                std::string vals;
                std::string toks;
                const char *eval = "exact";
                if (a.op == ConstOp::LIKE) eval = "prefix_evaluated";
                else if (a.op == ConstOp::LT || a.op == ConstOp::LE ||
                         a.op == ConstOp::GT || a.op == ConstOp::GE) {
                    eval = "range_evaluated";
                } else if (a.op == ConstOp::NE) {
                    eval = "neq_evaluated";
                }
                bool requires_dict = true;
                auto it = out->dicts.find(a.left.key());
                bool dict_present = (it != out->dicts.end());
                if (requires_dict && !dict_present) {
                    ereport(ERROR, (errmsg("policy_contract: missing dict for atom y%d col=%s op=%d",
                                           a.id, a.left.key().c_str(), (int)a.op)));
                }
                bool numeric = true;
                std::vector<double> num_values;
                for (const auto &v : a.values) {
                    double dv = 0.0;
                    if (!parse_number(v, &dv)) {
                        numeric = false;
                        break;
                    }
                    num_values.push_back(dv);
                }
                if (!numeric) num_values.clear();
                for (size_t i = 0; i < a.values.size(); i++) {
                    if (i > 0) vals += ",";
                    vals += a.values[i];
                    int tid = -1;
                    if (dict_present && (a.op == ConstOp::EQ || a.op == ConstOp::IN || a.op == ConstOp::NE)) {
                        if (numeric && i < num_values.size()) {
                            for (size_t j = 0; j < it->second.size(); j++) {
                                double dv = 0.0;
                                if (parse_number(it->second[j], &dv) && dv == num_values[i]) {
                                    tid = (int)j;
                                    break;
                                }
                            }
                        } else {
                            for (size_t j = 0; j < it->second.size(); j++) {
                                if (it->second[j] == a.values[i]) { tid = (int)j; break; }
                            }
                        }
                        if (tid < 0 && (a.op == ConstOp::EQ || a.op == ConstOp::IN)) {
                            ereport(ERROR, (errmsg("policy_contract: atom y%d literal %s not found in dict %s",
                                                   a.id, a.values[i].c_str(), dict_name.c_str())));
                        }
                    }
                    if (i > 0) toks += ",";
                    toks += std::to_string(tid);
                }
                CF_TRACE_LOG( "policy_contract: atom y%d type=COL_CONST col=%s op=%d join_class=%d dict=%s dict_present=%d eval=%s vals=[%s] toks=[%s]",
                     a.id, a.left.key().c_str(), (int)a.op, a.join_class_id,
                     dict_name.c_str(), dict_present ? 1 : 0, eval, vals.c_str(), toks.c_str());
            }
        }
        for (const auto &kv : out->target_ast) {
            std::map<int, std::string> atom_sql;
            for (const auto &a : out->atoms) {
                atom_sql[a.id] = atom_to_sql(a);
            }
            std::string expr = ast_to_sql(kv.second, atom_sql);
            CF_TRACE_LOG( "policy_contract: AST(%s)=%s", kv.first.c_str(), expr.c_str());
        }
    }

    return true;
}

static bool hub_phase(const Loaded &loaded, Hubs *hubs)
{
    if (!hubs) return false;
    hubs->present_by_class.assign(loaded.class_count, {});
    hubs->max_tok.assign(loaded.class_count, 0);

    std::set<std::string> dict_printed;
    for (auto &a : loaded.atoms) {
        if (a.kind != AtomKind::CONST) continue;
        auto it = loaded.dicts.find(a.left.key());
        if (it == loaded.dicts.end())
            return false;
        DictType dtype = dict_type_for_key(loaded, a.left.key());
        hubs->const_allowed[a.id] = build_allowed_tokens(it->second, a, dtype);
        if (dict_printed.insert(a.left.key()).second) {
            CF_TRACE_LOG( "policy: dict %s size=%zu", a.left.key().c_str(), it->second.size());
        }
        if (!a.values.empty()) {
            std::string toks;
            for (size_t i = 0; i < a.values.size(); i++) {
                int tid = -1;
                for (size_t j = 0; j < it->second.size(); j++) {
                    if (it->second[j] == a.values[i]) { tid = (int)j; break; }
                }
                if (!toks.empty()) toks += ",";
                toks += std::to_string(tid);
            }
            CF_TRACE_LOG( "policy: const %s tokens=[%s]",
                 a.left.key().c_str(), toks.c_str());
        }
    }

    for (auto &kv : loaded.tables) {
        const TableInfo &ti = kv.second;
        int stride = ti.stride;
        if (stride <= 1 || ti.n_rows == 0) continue;

        for (uint32 r = 0; r < ti.n_rows; r++) {
            const int32_t *row = ti.code + (size_t)r * (size_t)stride;
            for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                int idx = ti.join_token_idx[j];
                int32 tok = row[idx];
                if (tok >= 0) {
                    int cid = ti.join_class_ids[j];
                    hubs->present_by_class[cid][ti.name].set((size_t)tok);
                    if ((size_t)tok > hubs->max_tok[cid])
                        hubs->max_tok[cid] = (size_t)tok;
                }
            }
        }
    }

    return true;
}

static bool build_allow_all(const Loaded &loaded, PolicyAllowListC *out)
{
    if (!out) return false;
    int target_count = 0;
    for (const auto &kv : loaded.tables) {
        if (loaded.target_set.count(kv.first) > 0)
            target_count++;
    }
    out->count = 0;
    out->items = target_count > 0
                     ? (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * target_count)
                     : nullptr;
    for (const auto &kv : loaded.tables) {
        const TableInfo &ti = kv.second;
        if (ti.n_rows == 0) continue;
        if (loaded.target_set.count(ti.name) == 0)
            continue;
        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *)palloc0(bytes);
        memset(bits, 0xFF, bytes);
        out->items[out->count].table = pstrdup(ti.name.c_str());
        out->items[out->count].allow_bits = bits;
        out->items[out->count].n_rows = ti.n_rows;
        out->count++;
        CF_TRACE_LOG( "policy: allow_%s count = %u / %u",
             ti.name.c_str(), ti.n_rows, ti.n_rows);
    }
    return true;
}

static void run_multi_join_contract(const Loaded &loaded)
{
    for (const auto &tkv : loaded.target_join_classes) {
        const std::string &target = tkv.first;
        const std::set<int> &classes = tkv.second;
        if (classes.size() <= 1)
            continue;

        StringInfoData clist;
        initStringInfo(&clist);
        for (int cid : classes) {
            if (clist.len > 0) appendStringInfoString(&clist, ", ");
            appendStringInfo(&clist, "%d", cid);
        }
        CF_TRACE_LOG( "policy_contract: multi_join target=%s join_classes=[%s]",
             target.c_str(), clist.data);

        std::map<int, std::set<std::string>> class_tables;
        std::map<std::string, std::set<int>> table_classes;

        auto it_vars = loaded.target_vars.find(target);
        if (it_vars != loaded.target_vars.end()) {
            for (int aid : it_vars->second) {
                if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                    continue;
                const Atom *ap = loaded.atom_by_id[aid];
                if (!ap || ap->kind != AtomKind::JOIN)
                    continue;
                int cid = ap->join_class_id;
                if (cid < 0 || classes.count(cid) == 0)
                    continue;
                class_tables[cid].insert(ap->left.table);
                class_tables[cid].insert(ap->right.table);
                table_classes[ap->left.table].insert(cid);
                table_classes[ap->right.table].insert(cid);
            }
        }

        for (const auto &kv : class_tables) {
            int cid = kv.first;
            if (kv.second.size() != 2) {
                std::string tables;
                for (const auto &tname : kv.second) {
                    if (!tables.empty()) tables += ", ";
                    tables += tname;
                }
                ereport(ERROR,
                        (errmsg("policy_contract: multi_join class=%d has %zu tables [%s]; only binary join classes supported in Step-2A",
                                cid, kv.second.size(), tables.c_str())));
            }
        }

        std::map<std::string, std::vector<int>> table_class_list;
        for (const auto &kv : table_classes) {
            std::vector<int> v(kv.second.begin(), kv.second.end());
            std::sort(v.begin(), v.end());
            table_class_list[kv.first] = std::move(v);
        }

        std::map<std::string, std::map<int, int>> table_class_idx;
        for (const auto &kv : table_class_list) {
            const std::string &tname = kv.first;
            auto it_t = loaded.tables.find(tname);
            if (it_t == loaded.tables.end())
                continue;
            const TableInfo &ti = it_t->second;
            for (int cid : kv.second) {
                int idx = -1;
                for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                    if (ti.join_class_ids[j] == cid) {
                        idx = ti.join_token_idx[j];
                        break;
                    }
                }
                if (idx < 0) {
                    ereport(ERROR,
                            (errmsg("policy_contract: multi_join missing join token index for table=%s class=%d",
                                    tname.c_str(), cid)));
                }
                table_class_idx[tname][cid] = idx;
            }
        }

        std::map<int, size_t> domain_size;
        for (int cid : classes) {
            int max_tok = -1;
            auto it = class_tables.find(cid);
            if (it == class_tables.end())
                continue;
            for (const auto &tname : it->second) {
                auto it_t = loaded.tables.find(tname);
                if (it_t == loaded.tables.end())
                    continue;
                const TableInfo &ti = it_t->second;
                int idx = -1;
                auto it_idx = table_class_idx[tname].find(cid);
                if (it_idx != table_class_idx[tname].end())
                    idx = it_idx->second;
                if (idx < 0) continue;
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                    int32 tok = row[idx];
                    if (tok > max_tok) max_tok = tok;
                }
            }
            if (max_tok >= 0)
                domain_size[cid] = (size_t)max_tok + 1;
            else
                domain_size[cid] = 0;
        }

        std::map<int, Bitset> allowed;
        for (int cid : classes) {
            bitset_set_all(allowed[cid], domain_size[cid]);
        }

        std::map<int, std::vector<uint8_t>> const_allowed;
        if (it_vars != loaded.target_vars.end()) {
            for (int aid : it_vars->second) {
                if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                    continue;
                const Atom *ap = loaded.atom_by_id[aid];
                if (!ap || ap->kind != AtomKind::CONST)
                    continue;
                auto it_dict = loaded.dicts.find(ap->left.key());
                if (it_dict == loaded.dicts.end()) {
                    ereport(ERROR,
                            (errmsg("policy_contract: multi_join missing dict for const atom y%d col=%s",
                                    aid, ap->left.key().c_str())));
                }
                DictType dtype = dict_type_for_key(loaded, ap->left.key());
                const_allowed[aid] = build_allowed_tokens(it_dict->second, *ap, dtype);
            }
        }

        std::map<std::string, std::vector<uint8_t>> local_ok;
        std::map<std::string, uint32> local_ok_count;
        const AstNode *ast = nullptr;
        auto it_ast = loaded.target_ast.find(target);
        if (it_ast != loaded.target_ast.end())
            ast = it_ast->second;

        for (const auto &tckv : table_class_list) {
            const std::string &tname = tckv.first;
            auto it_t = loaded.tables.find(tname);
            if (it_t == loaded.tables.end())
                continue;
            const TableInfo &ti = it_t->second;
            std::vector<int> const_ids;
            std::vector<int> const_idx;
            if (it_vars != loaded.target_vars.end()) {
                for (size_t i = 0; i < ti.const_atom_ids.size(); i++) {
                    int aid = ti.const_atom_ids[i];
                    if (it_vars->second.count(aid) == 0)
                        continue;
                    const Atom *ap = (aid > 0 && aid < (int)loaded.atom_by_id.size()) ? loaded.atom_by_id[aid] : nullptr;
                    if (!ap || ap->kind != AtomKind::CONST)
                        continue;
                    const_ids.push_back(aid);
                    const_idx.push_back(ti.const_token_idx[i]);
                }
            }

            if (const_ids.empty()) {
                local_ok_count[tname] = ti.n_rows;
                continue;
            }

            std::vector<uint8_t> ok(ti.n_rows, 0);
            std::vector<int> vals(loaded.atom_by_id.size(), 1);
            uint32 cnt = 0;
            for (uint32 r = 0; r < ti.n_rows; r++) {
                const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                for (size_t k = 0; k < const_ids.size(); k++) {
                    int aid = const_ids[k];
                    int idx = const_idx[k];
                    int32 tok = row[idx];
                    bool allow = false;
                    auto it_allow = const_allowed.find(aid);
                    if (tok >= 0 && it_allow != const_allowed.end()) {
                        const auto &al = it_allow->second;
                        if ((size_t)tok < al.size() && al[(size_t)tok])
                            allow = true;
                    }
                    vals[aid] = allow ? 1 : 0;
                }
                Tri res = ast ? eval_ast(ast, vals) : TRI_TRUE;
                bool row_ok = (res != TRI_FALSE);
                if (row_ok) cnt++;
                ok[r] = row_ok ? 1 : 0;
                for (int aid : const_ids)
                    vals[aid] = 1;
            }
            local_ok_count[tname] = cnt;
            local_ok[tname] = std::move(ok);
        }

        for (const auto &kv : local_ok_count) {
            auto it_t = loaded.tables.find(kv.first);
            uint32 total = it_t != loaded.tables.end() ? it_t->second.n_rows : 0;
            CF_TRACE_LOG( "policy_contract: multi_join local_ok %s = %u / %u",
                 kv.first.c_str(), kv.second, total);
        }

        int iterations = 0;
        bool changed = true;
        const int max_iter = 32;
        while (changed && iterations < max_iter) {
            changed = false;
            iterations++;
            for (int cid : classes) {
                size_t D = domain_size[cid];
                if (D == 0) continue;
                auto it_tables = class_tables.find(cid);
                if (it_tables == class_tables.end() || it_tables->second.empty())
                    continue;
                Bitset new_allowed;
                bool first = true;
                for (const auto &tname : it_tables->second) {
                    auto it_t = loaded.tables.find(tname);
                    if (it_t == loaded.tables.end())
                        continue;
                    const TableInfo &ti = it_t->second;
                    int idxJ = -1;
                    auto it_idx = table_class_idx[tname].find(cid);
                    if (it_idx != table_class_idx[tname].end())
                        idxJ = it_idx->second;
                    if (idxJ < 0)
                        continue;
                    Bitset support;
                    support.nbits = D;
                    support.bytes.assign((D + 7) / 8, 0);
                    auto it_ok = local_ok.find(tname);
                    const std::vector<uint8_t> *ok_rows = (it_ok != local_ok.end()) ? &it_ok->second : nullptr;
                    for (uint32 r = 0; r < ti.n_rows; r++) {
                        if (ok_rows && !(*ok_rows)[r])
                            continue;
                        const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                        bool row_ok = true;
                        for (int ocid : table_class_list[tname]) {
                            if (ocid == cid)
                                continue;
                            int idxK = -1;
                            auto it_k = table_class_idx[tname].find(ocid);
                            if (it_k != table_class_idx[tname].end())
                                idxK = it_k->second;
                            if (idxK < 0) continue;
                            int32 tokK = row[idxK];
                            if (tokK < 0 || !allowed[ocid].test((size_t)tokK)) {
                                row_ok = false;
                                break;
                            }
                        }
                        if (!row_ok)
                            continue;
                        int32 tokJ = row[idxJ];
                        if (tokJ >= 0)
                            support.set((size_t)tokJ);
                    }
                    if (first) {
                        new_allowed = support;
                        first = false;
                    } else {
                        bitset_intersect(new_allowed, support);
                    }
                }
                if (bitset_intersect(allowed[cid], new_allowed))
                    changed = true;
            }
        }

        for (int cid : classes) {
            size_t D = domain_size[cid];
            size_t pop = bitset_popcount(allowed[cid], D);
            CF_TRACE_LOG( "policy_contract: multi_join class=%d allowed=%zu / %zu tokens=[%s]",
                 cid, pop, D, bitset_first_tokens(allowed[cid], 8).c_str());
        }
        CF_TRACE_LOG( "policy_contract: multi_join iterations=%d", iterations);
        if (iterations >= max_iter)
            CF_TRACE_LOG( "policy_contract: multi_join hit max iterations=%d", max_iter);
    }
}

struct AstCheckResult {
    bool valid = true;
    bool has_join = false;
    std::set<std::string> const_tables;
    std::string reason;
};

struct TableCache {
    std::unordered_map<std::string, std::vector<uint8_t>> atom_row_truth;
    std::unordered_map<std::string, std::unordered_map<std::string, uint8_t>> decision_cache;
    struct GlobalSigCache {
        uint32 n_rows = 0;
        size_t nbytes = 0;
        std::vector<std::string> atom_keys;
        std::vector<int> token_idx;
        std::unordered_map<std::string, std::vector<uint8_t>> allowed_by_key;
        std::unordered_map<std::string, int> atom_index;
        std::vector<int> row_to_bin;
        // bin signatures stored densely as n_bins * nbytes bytes (no per-row / per-bin heap objects)
        std::vector<uint8_t> bin_sig_flat;
        std::vector<uint32_t> hist;
        double ms_stamp = 0.0;
        double ms_bin = 0.0;
        bool ready = false;
    } global;
};

struct LocalOkCache {
    MemoryContext ctx = nullptr;
    std::unordered_map<std::string, TableCache> tables;
    std::unordered_map<std::string, int> scan_counts;
    struct QueryProfileAgg {
        bool valid = false;
        std::string query;
        int k = 0;
        double total_ms = 0.0;
        double local_ms = 0.0;
        double prop_ms = 0.0;
        double decode_ms = 0.0;
        int sat_calls = 0;
        int cache_hits = 0;
        int closure_tables = 0;
        int filtered_targets = 0;
    } agg;
    MemoryContextCallback cb;
    bool cb_registered = false;
};

static LocalOkCache g_local_cache;

struct LocalStat {
    std::string table;
    int atoms = 0;
    size_t bins = 0;
    int sat_calls = 0;
    int cache_hits = 0;
    double ms_stamp = 0.0;
    double ms_bin = 0.0;
    double ms_eval = 0.0;
    double ms_fill = 0.0;
};

struct PropStat {
    int class_id = -1;
    size_t tokens_total = 0;
    size_t tokens_allowed = 0;
};

struct DecodeStat {
    std::string table;
    uint32 rows_total = 0;
    uint32 rows_allowed = 0;
    double ms_decode = 0.0;
};

struct BundleProfile {
    int bundle_id = 0;
    std::string target;
    int k = 0;
    std::string query;
    std::vector<LocalStat> local;
    std::vector<PropStat> prop;
    std::vector<DecodeStat> decode;
    double local_ms_total = 0.0;
    double prop_ms_total = 0.0;
    int prop_iterations = 0;
    double decode_ms_total = 0.0;
    double total_ms = 0.0;
};

static void flush_query_profile();

static void ensure_local_cache_ctx() {
    MemoryContext cur = CurrentMemoryContext;
    if (g_local_cache.ctx != cur) {
        if (g_local_cache.agg.valid)
            flush_query_profile();
        g_local_cache.tables.clear();
        g_local_cache.scan_counts.clear();
        g_local_cache.agg = LocalOkCache::QueryProfileAgg{};
        g_local_cache.ctx = cur;
        g_local_cache.cb_registered = false;
    }
}

static void flush_query_profile() {
    if (!g_local_cache.agg.valid)
        return;
    StringInfoData buf;
    initStringInfo(&buf);
    appendStringInfo(&buf,
                     "policy_profile_query: K=%d query_id=%s total_ms=%.3f local_ms=%.3f prop_ms=%.3f decode_ms=%.3f sat_calls=%d cache_hits=%d closure_tables=%d filtered_targets=%d",
                     g_local_cache.agg.k,
                     g_local_cache.agg.query.c_str(),
                     g_local_cache.agg.total_ms,
                     g_local_cache.agg.local_ms,
                     g_local_cache.agg.prop_ms,
                     g_local_cache.agg.decode_ms,
                     g_local_cache.agg.sat_calls,
                     g_local_cache.agg.cache_hits,
                     g_local_cache.agg.closure_tables,
                     g_local_cache.agg.filtered_targets);
    CF_TRACE_LOG( "%s", buf.data);
    for (const auto &kv : g_local_cache.scan_counts) {
        CF_TRACE_LOG( "policy: scan_count table=%s count=%d",
             kv.first.c_str(), kv.second);
    }
    g_local_cache.agg = LocalOkCache::QueryProfileAgg{};
    g_local_cache.scan_counts.clear();
}

static void query_reset_callback(void *arg) {
    (void)arg;
    flush_query_profile();
}

static void register_query_callback() {
    if (g_local_cache.cb_registered || !g_local_cache.ctx)
        return;
    g_local_cache.cb.func = query_reset_callback;
    g_local_cache.cb.arg = nullptr;
    MemoryContextRegisterResetCallback(g_local_cache.ctx, &g_local_cache.cb);
    g_local_cache.cb_registered = true;
}

static int profile_k() {
    const char *v = GetConfigOption("custom_filter.profile_k", true, false);
    if (!v) return 0;
    return std::atoi(v);
}

static std::string profile_query() {
    const char *v = GetConfigOption("custom_filter.profile_query", true, false);
    if (!v) return "";
    return v;
}

static int next_bundle_id() {
    static MemoryContext ctx = nullptr;
    static std::string last_query;
    static int seq = 0;
    MemoryContext cur = CurrentMemoryContext;
    std::string q = profile_query();
    if (ctx != cur || q != last_query) {
        ctx = cur;
        last_query = q;
        seq = 0;
    }
    return ++seq;
}

static size_t bitset_popcount_intersection(const Bitset &a, const Bitset &b, size_t limit_bits) {
    size_t nbits = std::min(limit_bits, std::min(a.nbits, b.nbits));
    size_t cnt = 0;
    for (size_t i = 0; i < nbits; i++) {
        if (a.test(i) && b.test(i)) cnt++;
    }
    return cnt;
}

static void log_profile(const BundleProfile &p) {
    StringInfoData buf;
    initStringInfo(&buf);
    appendStringInfo(&buf, "policy_profile_bundle: bundle=%d target=%s K=%d query=%s ",
                     p.bundle_id, p.target.c_str(), p.k, p.query.c_str());
    appendStringInfoString(&buf, "local={");
    for (size_t i = 0; i < p.local.size(); i++) {
        const auto &ls = p.local[i];
        if (i > 0) appendStringInfoString(&buf, "|");
        appendStringInfo(&buf, "%s:atoms=%d,bins=%zu,sat=%d,hits=%d,ms=%.3f/%.3f/%.3f/%.3f",
                         ls.table.c_str(), ls.atoms, ls.bins, ls.sat_calls, ls.cache_hits,
                         ls.ms_stamp, ls.ms_bin, ls.ms_eval, ls.ms_fill);
    }
    appendStringInfo(&buf, ",total_ms=%.3f} ", p.local_ms_total);
    appendStringInfoString(&buf, "prop={");
    appendStringInfo(&buf, "iter=%d,ms=%.3f,classes=[", p.prop_iterations, p.prop_ms_total);
    for (size_t i = 0; i < p.prop.size(); i++) {
        const auto &ps = p.prop[i];
        if (i > 0) appendStringInfoString(&buf, ",");
        appendStringInfo(&buf, "%d:%zu/%zu", ps.class_id, ps.tokens_allowed, ps.tokens_total);
    }
    appendStringInfoString(&buf, "]} ");
    appendStringInfoString(&buf, "decode={");
    for (size_t i = 0; i < p.decode.size(); i++) {
        const auto &ds = p.decode[i];
        if (i > 0) appendStringInfoString(&buf, "|");
        appendStringInfo(&buf, "%s:%u/%u,ms=%.3f",
                         ds.table.c_str(), ds.rows_allowed, ds.rows_total, ds.ms_decode);
    }
    appendStringInfo(&buf, ",total_ms=%.3f} ", p.decode_ms_total);
    appendStringInfo(&buf, "total_ms=%.3f", p.total_ms);
    CF_TRACE_LOG( "%s", buf.data);
}

static void update_query_profile(const BundleProfile &p, const Loaded &loaded) {
    ensure_local_cache_ctx();
    register_query_callback();
    auto &agg = g_local_cache.agg;
    if (!agg.valid) {
        agg.valid = true;
        agg.query = profile_query();
        agg.k = profile_k();
        agg.closure_tables = (int)loaded.tables.size();
        agg.filtered_targets = (int)loaded.target_set.size();
    }
    agg.total_ms += p.total_ms;
    agg.local_ms += p.local_ms_total;
    agg.prop_ms += p.prop_ms_total;
    agg.decode_ms += p.decode_ms_total;
    for (const auto &ls : p.local) {
        agg.sat_calls += ls.sat_calls;
        agg.cache_hits += ls.cache_hits;
    }
}

static std::string const_atom_key(const Atom *ap) {
    if (!ap) return "";
    std::string key = ap->lhs_schema_key;
    key += "|";
    key += std::to_string((int)ap->op);
    key += "|";
    for (size_t i = 0; i < ap->values.size(); i++) {
        if (i > 0) key += ",";
        key += ap->values[i];
    }
    return key;
}

static std::string ast_to_string_simple(const AstNode *node) {
    if (!node) return "";
    if (node->type == AstNode::VAR) {
        return "y" + std::to_string(node->var_id);
    }
    std::string l = ast_to_string_simple(node->left);
    std::string r = ast_to_string_simple(node->right);
    std::string op = (node->type == AstNode::AND) ? " and " : " or ";
    return "(" + l + op + r + ")";
}

static std::string build_cache_key(const AstNode *ast,
                                   const Loaded &loaded,
                                   const std::vector<int> &const_ids) {
    std::string key = ast ? ast_to_string_simple(ast) : "<null>";
    std::vector<std::string> atom_keys;
    atom_keys.reserve(const_ids.size());
    for (int aid : const_ids) {
        const Atom *ap = (aid > 0 && aid < (int)loaded.atom_by_id.size())
                             ? loaded.atom_by_id[aid]
                             : nullptr;
        if (ap && ap->kind == AtomKind::CONST) {
            atom_keys.push_back(const_atom_key(ap));
        }
    }
    std::sort(atom_keys.begin(), atom_keys.end());
    key += "|atoms=";
    for (size_t i = 0; i < atom_keys.size(); i++) {
        if (i > 0) key += ";";
        key += atom_keys[i];
    }
    return key;
}

static std::string base_sig_for_bits(size_t nbits) {
    size_t nbytes = (nbits + 7) / 8;
    std::string s(nbytes, (char)0xFF);
    if (nbits % 8 != 0 && nbytes > 0) {
        uint8_t mask = (uint8_t)((1u << (nbits % 8)) - 1u);
        s[nbytes - 1] = (char)(s[nbytes - 1] & mask);
    }
    return s;
}

static inline bool get_sig_bit_idx(const std::string &s, size_t bit) {
    size_t byte = bit >> 3;
    if (byte >= s.size()) return false;
    size_t off = bit & 7;
    return (s[byte] & (char)(1u << off)) != 0;
}

static inline void set_sig_bit_idx(std::string &s, size_t bit, bool val) {
    size_t byte = bit >> 3;
    if (byte >= s.size()) return;
    uint8_t mask = (uint8_t)(1u << (bit & 7));
    if (val) s[byte] = (char)(s[byte] | mask);
    else s[byte] = (char)(s[byte] & (char)~mask);
}

static inline bool get_sig_bit_bytes(const uint8_t *sig, size_t nbytes, size_t bit) {
    size_t byte = bit >> 3;
    if (!sig || byte >= nbytes) return false;
    return (sig[byte] & (uint8_t)(1u << (bit & 7))) != 0;
}

static inline void set_sig_bit_bytes(uint8_t *sig, size_t nbytes, size_t bit, bool val) {
    size_t byte = bit >> 3;
    if (!sig || byte >= nbytes) return;
    uint8_t mask = (uint8_t)(1u << (bit & 7));
    if (val) sig[byte] |= mask;
    else sig[byte] &= (uint8_t)~mask;
}

static inline uint64_t hash_bytes_fnv1a64(const uint8_t *data, size_t len) {
    const uint64_t FNV_OFFSET = 1469598103934665603ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= FNV_PRIME;
    }
    // Avoid the sentinel 0 just in case a caller uses 0 as "empty".
    return h ? h : 1ULL;
}

static inline size_t next_pow2(size_t x) {
    if (x <= 2) return 2;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    if (sizeof(size_t) == 8) x |= x >> 32;
    x++;
    return x;
}

struct BinTable {
    std::vector<int32_t> bin_id;
    std::vector<uint64_t> hash;
    size_t mask = 0;

    void init(size_t cap_pow2) {
        size_t cap = next_pow2(std::max<size_t>(cap_pow2, 2));
        bin_id.assign(cap, -1);
        hash.assign(cap, 0);
        mask = cap - 1;
    }

    void maybe_grow(size_t n_bins, const std::vector<uint8_t> &bin_sig_flat, size_t nbytes) {
        if (bin_id.empty()) {
            init(1024);
        }
        size_t cap = bin_id.size();
        // Grow when load factor would exceed ~0.7 after inserting one more bin.
        if ((n_bins + 1) * 10 < cap * 7) {
            return;
        }
        size_t new_cap = cap * 2;
        std::vector<int32_t> new_id(new_cap, -1);
        std::vector<uint64_t> new_hash(new_cap, 0);
        size_t new_mask = new_cap - 1;

        for (size_t bid = 0; bid < n_bins; bid++) {
            const uint8_t *sig = bin_sig_flat.data() + bid * nbytes;
            uint64_t h = hash_bytes_fnv1a64(sig, nbytes);
            size_t idx = (size_t)h & new_mask;
            while (new_id[idx] != -1) {
                idx = (idx + 1) & new_mask;
            }
            new_id[idx] = (int32_t)bid;
            new_hash[idx] = h;
        }

        bin_id.swap(new_id);
        hash.swap(new_hash);
        mask = new_mask;
    }

    int32_t find_or_insert(uint64_t h,
                           const uint8_t *sig,
                           size_t nbytes,
                           std::vector<uint8_t> &bin_sig_flat,
                           std::vector<uint32_t> &hist) {
        maybe_grow(hist.size(), bin_sig_flat, nbytes);

        size_t idx = (size_t)h & mask;
        for (;;) {
            int32_t bid = bin_id[idx];
            if (bid == -1) {
                int32_t new_id = (int32_t)hist.size();
                bin_id[idx] = new_id;
                hash[idx] = h;
                size_t off = bin_sig_flat.size();
                bin_sig_flat.resize(off + nbytes);
                if (nbytes > 0) {
                    memcpy(bin_sig_flat.data() + off, sig, nbytes);
                }
                hist.push_back(0);
                return new_id;
            }
            if (hash[idx] == h) {
                const uint8_t *existing = bin_sig_flat.data() + (size_t)bid * nbytes;
                if (memcmp(existing, sig, nbytes) == 0) {
                    return bid;
                }
            }
            idx = (idx + 1) & mask;
        }
    }
};

static void clear_sig_bit(std::string &s, int atom_id) {
    if (atom_id <= 0) return;
    size_t bit = (size_t)(atom_id - 1);
    size_t byte = bit >> 3;
    size_t off = bit & 7;
    if (byte >= s.size()) return;
    s[byte] = (char)(s[byte] & (char)~(1u << off));
}

static bool ast_collect_and_vars(const AstNode *node, std::vector<int> &vars) {
    if (!node) return true;
    if (node->type == AstNode::VAR) {
        vars.push_back(node->var_id);
        return true;
    }
    if (node->type == AstNode::AND) {
        return ast_collect_and_vars(node->left, vars) &&
               ast_collect_and_vars(node->right, vars);
    }
    return false;
}

static void dnf_expand_terms(const AstNode *node,
                             std::vector<std::vector<int>> &out,
                             size_t max_terms,
                             bool &overflow) {
    if (!node || overflow) return;
    if (node->type == AstNode::VAR) {
        out.push_back({node->var_id});
        return;
    }
    if (node->type == AstNode::AND) {
        std::vector<std::vector<int>> left;
        std::vector<std::vector<int>> right;
        dnf_expand_terms(node->left, left, max_terms, overflow);
        dnf_expand_terms(node->right, right, max_terms, overflow);
        if (overflow) return;
        std::vector<std::vector<int>> merged;
        merged.reserve(left.size() * right.size());
        for (const auto &l : left) {
            for (const auto &r : right) {
                std::vector<int> term;
                term.reserve(l.size() + r.size());
                term.insert(term.end(), l.begin(), l.end());
                term.insert(term.end(), r.begin(), r.end());
                std::sort(term.begin(), term.end());
                term.erase(std::unique(term.begin(), term.end()), term.end());
                merged.push_back(std::move(term));
                if (merged.size() > max_terms) {
                    overflow = true;
                    return;
                }
            }
        }
        out.swap(merged);
        return;
    }
    if (node->type == AstNode::OR) {
        std::vector<std::vector<int>> left;
        std::vector<std::vector<int>> right;
        dnf_expand_terms(node->left, left, max_terms, overflow);
        dnf_expand_terms(node->right, right, max_terms, overflow);
        if (overflow) return;
        out.reserve(left.size() + right.size());
        for (auto &t : left) out.push_back(std::move(t));
        for (auto &t : right) out.push_back(std::move(t));
        if (out.size() > max_terms) {
            overflow = true;
            return;
        }
        // Deduplicate identical terms to keep explosion down.
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return;
    }
    overflow = true;
}

static AstNode *build_and_ast(const std::vector<int> &vars) {
    if (vars.empty()) return nullptr;
    AstNode *root = nullptr;
    for (int v : vars) {
        AstNode *leaf = new AstNode();
        leaf->type = AstNode::VAR;
        leaf->var_id = v;
        if (!root) {
            root = leaf;
        } else {
            AstNode *node = new AstNode();
            node->type = AstNode::AND;
            node->left = root;
            node->right = leaf;
            root = node;
        }
    }
    return root;
}

static bool eval_bins_sat_flat(const AstNode *ast,
                               int atom_count,
                               const std::vector<uint8_t> &bin_sig_flat,
                               size_t nbytes,
                               size_t n_bins,
                               std::vector<uint8_t> *allow_bin,
                               double *sat_ms,
                               int *sat_calls) {
    if (!allow_bin) return false;
    allow_bin->assign(n_bins, 0);
    if (sat_calls) *sat_calls = 0;
    if (!ast) {
        std::fill(allow_bin->begin(), allow_bin->end(), 1);
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    std::vector<int> and_vars;
    bool pure_and = ast_collect_and_vars(ast, and_vars);

    if (pure_and) {
        for (size_t b = 0; b < n_bins; b++) {
            const uint8_t *sig = bin_sig_flat.data() + b * nbytes;
            bool ok = true;
            for (int aid : and_vars) {
                if (aid <= 0) continue;
                if (!get_sig_bit_bytes(sig, nbytes, (size_t)(aid - 1))) { ok = false; break; }
            }
            (*allow_bin)[b] = ok ? 1 : 0;
        }
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    api::Solver slv;
    slv.setLogic("SAT");
    slv.setOption("produce-models", "false");
    slv.setOption("incremental", "true");
    api::Sort B = slv.getBooleanSort();
    std::vector<api::Term> yvars(atom_count + 1);
    for (int i = 1; i <= atom_count; i++) {
        yvars[i] = slv.mkConst(B, "y" + std::to_string(i));
    }

    struct CnfCtx {
        api::Solver *slv;
        api::Sort B;
        std::vector<api::Term> *yvars;
        int next_id;
        std::vector<api::Term> clauses;
    };
    CnfCtx ctx{&slv, B, &yvars, 0, {}};

    std::function<api::Term(const AstNode*)> build_cnf = [&](const AstNode *node) -> api::Term {
        if (!node) return ctx.slv->mkBoolean(true);
        if (node->type == AstNode::VAR) {
            int id = node->var_id;
            if (id <= 0 || id >= (int)ctx.yvars->size())
                return ctx.slv->mkBoolean(true);
            return (*ctx.yvars)[id];
        }
        api::Term a = build_cnf(node->left);
        api::Term b = build_cnf(node->right);
        api::Term z = ctx.slv->mkConst(ctx.B, "t" + std::to_string(++ctx.next_id));
        if (node->type == AstNode::AND) {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), b}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}),
                                                   ctx.slv->mkTerm(api::Kind::NOT, {b}),
                                                   z}));
        } else {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {b}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a, b}));
        }
        return z;
    };

    api::Term top = build_cnf(ast);
    for (auto &cl : ctx.clauses)
        slv.assertFormula(cl);
    slv.assertFormula(top);

    auto t0 = Clock::now();
    for (size_t b = 0; b < n_bins; b++) {
        const uint8_t *sig = bin_sig_flat.data() + b * nbytes;
        std::vector<api::Term> assumptions;
        assumptions.reserve(atom_count);
        for (int i = 1; i <= atom_count; i++) {
            bool bit = get_sig_bit_bytes(sig, nbytes, (size_t)(i - 1));
            api::Term lit = bit ? yvars[i]
                                : slv.mkTerm(api::Kind::NOT, {yvars[i]});
            assumptions.push_back(lit);
        }
        api::Result r = slv.checkSatAssuming(assumptions);
        if (sat_calls) (*sat_calls)++;
        if (r.isSat())
            (*allow_bin)[b] = 1;
    }
    auto t1 = Clock::now();
    if (sat_ms) *sat_ms = Ms(t1 - t0).count();
    return true;
}

static bool eval_bins_sat(const AstNode *ast, int atom_count,
                          const std::vector<std::string> &bin_sig,
                          std::unordered_map<std::string, uint8_t> *decision_cache,
                          std::vector<uint8_t> *allow_bin,
                          double *sat_ms,
                          int *sat_calls,
                          int *cache_hits) {
    if (!allow_bin) return false;
    allow_bin->assign(bin_sig.size(), 0);
    if (sat_calls) *sat_calls = 0;
    if (cache_hits) *cache_hits = 0;
    if (!ast) {
        std::fill(allow_bin->begin(), allow_bin->end(), 1);
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    std::vector<int> and_vars;
    bool pure_and = ast_collect_and_vars(ast, and_vars);

    auto sig_bit = [&](const std::string &s, int aid) -> bool {
        if (aid <= 0) return true;
        size_t bit = (size_t)(aid - 1);
        size_t byte = bit >> 3;
        size_t off = bit & 7;
        if (byte >= s.size()) return false;
        return (s[byte] & (char)(1u << off)) != 0;
    };

    if (pure_and) {
        for (size_t b = 0; b < bin_sig.size(); b++) {
            const std::string &s = bin_sig[b];
            if (decision_cache) {
                auto it = decision_cache->find(s);
                if (it != decision_cache->end()) {
                    (*allow_bin)[b] = it->second;
                    if (cache_hits) (*cache_hits)++;
                    continue;
                }
            }
            bool ok = true;
            for (int aid : and_vars) {
                if (!sig_bit(s, aid)) { ok = false; break; }
            }
            (*allow_bin)[b] = ok ? 1 : 0;
            if (decision_cache) (*decision_cache)[s] = (*allow_bin)[b];
        }
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    api::Solver slv;
    slv.setLogic("SAT");
    slv.setOption("produce-models", "false");
    slv.setOption("incremental", "true");
    api::Sort B = slv.getBooleanSort();
    std::vector<api::Term> yvars(atom_count + 1);
    for (int i = 1; i <= atom_count; i++) {
        yvars[i] = slv.mkConst(B, "y" + std::to_string(i));
    }

    struct CnfCtx {
        api::Solver *slv;
        api::Sort B;
        std::vector<api::Term> *yvars;
        int next_id;
        std::vector<api::Term> clauses;
    };
    CnfCtx ctx{&slv, B, &yvars, 0, {}};

    std::function<api::Term(const AstNode*)> build_cnf = [&](const AstNode *node) -> api::Term {
        if (!node) return ctx.slv->mkBoolean(true);
        if (node->type == AstNode::VAR) {
            int id = node->var_id;
            if (id <= 0 || id >= (int)ctx.yvars->size())
                return ctx.slv->mkBoolean(true);
            return (*ctx.yvars)[id];
        }
        api::Term a = build_cnf(node->left);
        api::Term b = build_cnf(node->right);
        api::Term z = ctx.slv->mkConst(ctx.B, "t" + std::to_string(++ctx.next_id));
        if (node->type == AstNode::AND) {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), b}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}),
                                                   ctx.slv->mkTerm(api::Kind::NOT, {b}),
                                                   z}));
        } else {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {b}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a, b}));
        }
        return z;
    };

    api::Term top = build_cnf(ast);
    for (auto &cl : ctx.clauses)
        slv.assertFormula(cl);
    slv.assertFormula(top);

    auto t0 = Clock::now();
    for (size_t b = 0; b < bin_sig.size(); b++) {
        const std::string &s = bin_sig[b];
        if (decision_cache) {
            auto it = decision_cache->find(s);
            if (it != decision_cache->end()) {
                (*allow_bin)[b] = it->second;
                if (cache_hits) (*cache_hits)++;
                continue;
            }
        }
        std::vector<api::Term> assumptions;
        assumptions.reserve(atom_count);
        for (int i = 1; i <= atom_count; i++) {
            bool bit = false;
            if (!s.empty()) {
                bit = (s[(i - 1) >> 3] & (1u << ((i - 1) & 7))) != 0;
            }
            api::Term lit = bit ? yvars[i]
                                : slv.mkTerm(api::Kind::NOT, {yvars[i]});
            assumptions.push_back(lit);
        }
        api::Result r = slv.checkSatAssuming(assumptions);
        if (sat_calls) (*sat_calls)++;
        if (r.isSat())
            (*allow_bin)[b] = 1;
        if (decision_cache) (*decision_cache)[s] = (*allow_bin)[b];
    }
    auto t1 = Clock::now();
    if (sat_ms) *sat_ms = Ms(t1 - t0).count();
    return true;
}

static bool eval_bins_sat_partial(const AstNode *ast,
                                  int atom_count,
                                  const std::vector<int> &atom_ids,
                                  const std::vector<std::string> &bin_sig,
                                  std::unordered_map<std::string, uint8_t> *decision_cache,
                                  std::vector<uint8_t> *allow_bin,
                                  double *sat_ms,
                                  int *sat_calls,
                                  int *cache_hits) {
    if (!allow_bin) return false;
    allow_bin->assign(bin_sig.size(), 0);
    if (sat_calls) *sat_calls = 0;
    if (cache_hits) *cache_hits = 0;
    if (!ast) {
        std::fill(allow_bin->begin(), allow_bin->end(), 1);
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    std::vector<int> and_vars;
    bool pure_and = ast_collect_and_vars(ast, and_vars);
    auto sig_bit = [&](const std::string &s, size_t idx) -> bool {
        size_t byte = idx >> 3;
        if (byte >= s.size()) return false;
        return (s[byte] & (char)(1u << (idx & 7))) != 0;
    };

    if (pure_and) {
        std::unordered_set<int> and_set(and_vars.begin(), and_vars.end());
        for (size_t b = 0; b < bin_sig.size(); b++) {
            const std::string &s = bin_sig[b];
            if (decision_cache) {
                auto it = decision_cache->find(s);
                if (it != decision_cache->end()) {
                    (*allow_bin)[b] = it->second;
                    if (cache_hits) (*cache_hits)++;
                    continue;
                }
            }
            bool ok = true;
            for (size_t i = 0; i < atom_ids.size(); i++) {
                int aid = atom_ids[i];
                if (and_set.count(aid) == 0) continue;
                if (!sig_bit(s, i)) { ok = false; break; }
            }
            (*allow_bin)[b] = ok ? 1 : 0;
            if (decision_cache) (*decision_cache)[s] = (*allow_bin)[b];
        }
        if (sat_ms) *sat_ms = 0.0;
        return true;
    }

    api::Solver slv;
    slv.setLogic("SAT");
    slv.setOption("produce-models", "false");
    slv.setOption("incremental", "true");
    api::Sort B = slv.getBooleanSort();
    std::vector<api::Term> yvars(atom_count + 1);
    for (int i = 1; i <= atom_count; i++) {
        yvars[i] = slv.mkConst(B, "y" + std::to_string(i));
    }

    struct CnfCtx {
        api::Solver *slv;
        api::Sort B;
        std::vector<api::Term> *yvars;
        int next_id;
        std::vector<api::Term> clauses;
    };
    CnfCtx ctx{&slv, B, &yvars, 0, {}};

    std::function<api::Term(const AstNode*)> build_cnf = [&](const AstNode *node) -> api::Term {
        if (!node) return ctx.slv->mkBoolean(true);
        if (node->type == AstNode::VAR) {
            int id = node->var_id;
            if (id <= 0 || id >= (int)ctx.yvars->size())
                return ctx.slv->mkBoolean(true);
            return (*ctx.yvars)[id];
        }
        api::Term a = build_cnf(node->left);
        api::Term b = build_cnf(node->right);
        api::Term z = ctx.slv->mkConst(ctx.B, "t" + std::to_string(++ctx.next_id));
        if (node->type == AstNode::AND) {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), b}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}),
                                                   ctx.slv->mkTerm(api::Kind::NOT, {b}),
                                                   z}));
        } else {
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {a}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {b}), z}));
            ctx.clauses.push_back(ctx.slv->mkTerm(api::Kind::OR,
                                                  {ctx.slv->mkTerm(api::Kind::NOT, {z}), a, b}));
        }
        return z;
    };

    api::Term top = build_cnf(ast);
    for (auto &cl : ctx.clauses)
        slv.assertFormula(cl);
    slv.assertFormula(top);

    auto t0 = Clock::now();
    for (size_t b = 0; b < bin_sig.size(); b++) {
        const std::string &s = bin_sig[b];
        if (decision_cache) {
            auto it = decision_cache->find(s);
            if (it != decision_cache->end()) {
                (*allow_bin)[b] = it->second;
                if (cache_hits) (*cache_hits)++;
                continue;
            }
        }
        std::vector<api::Term> assumptions;
        assumptions.reserve(atom_ids.size());
        for (size_t i = 0; i < atom_ids.size(); i++) {
            int aid = atom_ids[i];
            if (aid <= 0 || aid >= (int)yvars.size())
                continue;
            bool bit = sig_bit(s, i);
            api::Term lit = bit ? yvars[aid]
                                : slv.mkTerm(api::Kind::NOT, {yvars[aid]});
            assumptions.push_back(lit);
        }
        api::Result r = slv.checkSatAssuming(assumptions);
        if (sat_calls) (*sat_calls)++;
        if (r.isSat())
            (*allow_bin)[b] = 1;
        if (decision_cache) (*decision_cache)[s] = (*allow_bin)[b];
    }
    auto t1 = Clock::now();
    if (sat_ms) *sat_ms = Ms(t1 - t0).count();
    return true;
}

static bool build_const_allowed_map(const Loaded &loaded,
                                    const std::set<int> &vars,
                                    std::map<int, std::vector<uint8_t>> *out) {
    if (!out) return false;
    out->clear();
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::CONST)
            continue;
        auto it_dict = loaded.dicts.find(ap->left.key());
        if (it_dict == loaded.dicts.end()) {
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            aid, ap->left.key().c_str())));
        }
        DictType dtype = dict_type_for_key(loaded, ap->left.key());
        (*out)[aid] = build_allowed_tokens(it_dict->second, *ap, dtype);
    }
    return true;
}

struct AtomEvalInfo {
    std::string key;
    int token_idx = -1;
    const std::vector<uint8_t> *allowed = nullptr;
};

static bool ensure_atom_truths(const TableInfo &ti,
                               const std::vector<AtomEvalInfo> &atoms,
                               TableCache &tc) {
    if (atoms.empty())
        return true;
    for (const auto &ai : atoms) {
        if (!ai.allowed || ai.token_idx < 0)
            return false;
        tc.atom_row_truth[ai.key].assign(ti.n_rows, 0);
    }
    for (uint32 r = 0; r < ti.n_rows; r++) {
        const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
        for (const auto &ai : atoms) {
            int32 tok = row[ai.token_idx];
            bool allow = false;
            if (tok >= 0 && (size_t)tok < ai.allowed->size() &&
                (*ai.allowed)[(size_t)tok]) {
                allow = true;
            }
            tc.atom_row_truth[ai.key][r] = allow ? 1 : 0;
        }
    }
    return true;
}

static void rebuild_global_bins(const TableInfo &ti,
                                TableCache &tc,
                                double *ms_stamp,
                                double *ms_bin) {
    TableCache::GlobalSigCache &gs = tc.global;
    size_t G = gs.atom_keys.size();
    std::string base_sig = base_sig_for_bits(G);
    gs.nbytes = base_sig.size();
    gs.n_rows = ti.n_rows;
    gs.row_to_bin.assign(ti.n_rows, 0);
    gs.bin_sig_flat.clear();
    gs.hist.clear();
    if (ti.n_rows == 0 || gs.nbytes == 0) {
        gs.ready = true;
        g_local_cache.scan_counts[ti.name] += 1;
        if (ms_stamp) *ms_stamp = 0.0;
        if (ms_bin) *ms_bin = 0.0;
        return;
    }

    std::vector<uint8_t> base_bytes(gs.nbytes, 0);
    memcpy(base_bytes.data(), base_sig.data(), gs.nbytes);

    // Streaming stamp+bin: compute signatures into a reused chunk buffer, then bin immediately.
    const uint32 CHUNK = 4096;
    std::vector<uint8_t> sig_chunk;
    sig_chunk.reserve((size_t)CHUNK * gs.nbytes);

    // Open-addressing table keyed by (hash, signature-bytes) to avoid per-row allocations.
    BinTable tab;
    tab.init(std::max<size_t>(1024, (size_t)ti.n_rows / 2));

    double stamp_ms_acc = 0.0;
    double bin_ms_acc = 0.0;

    for (uint32 start = 0; start < ti.n_rows; start += CHUNK) {
        uint32 end = start + CHUNK;
        if (end > ti.n_rows) end = ti.n_rows;
        uint32 n = end - start;
        sig_chunk.resize((size_t)n * gs.nbytes);

        auto ts0 = Clock::now();
        for (uint32 i = 0; i < n; i++) {
            uint32 r = start + i;
            uint8_t *sig = sig_chunk.data() + (size_t)i * gs.nbytes;
            memcpy(sig, base_bytes.data(), gs.nbytes);

            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            for (size_t a = 0; a < G; a++) {
                int idx = (a < gs.token_idx.size()) ? gs.token_idx[a] : -1;
                bool allow = false;
                if (idx >= 0) {
                    int32 tok = row[idx];
                    if (tok >= 0) {
                        const std::string &akey = gs.atom_keys[a];
                        auto it_allow = gs.allowed_by_key.find(akey);
                        if (it_allow != gs.allowed_by_key.end()) {
                            const auto &al = it_allow->second;
                            if ((size_t)tok < al.size() && al[(size_t)tok])
                                allow = true;
                        }
                    }
                }
                if (!allow) {
                    set_sig_bit_bytes(sig, gs.nbytes, a, false);
                }
            }
        }
        auto ts1 = Clock::now();
        stamp_ms_acc += Ms(ts1 - ts0).count();

        auto tb0 = Clock::now();
        for (uint32 i = 0; i < n; i++) {
            const uint8_t *sig = sig_chunk.data() + (size_t)i * gs.nbytes;
            uint64_t h = hash_bytes_fnv1a64(sig, gs.nbytes);
            int32_t bid = tab.find_or_insert(h, sig, gs.nbytes, gs.bin_sig_flat, gs.hist);
            gs.row_to_bin[start + i] = (int)bid;
            gs.hist[(size_t)bid] += 1;
        }
        auto tb1 = Clock::now();
        bin_ms_acc += Ms(tb1 - tb0).count();
    }

    gs.ready = true;
    g_local_cache.scan_counts[ti.name] += 1;
    if (ms_stamp) *ms_stamp = stamp_ms_acc;
    if (ms_bin) *ms_bin = bin_ms_acc;
}

static bool compute_local_ok_bins(const Loaded &loaded,
                                  const std::string &table,
                                  const AstNode *ast,
                                  const std::set<int> &target_vars,
                                  const std::map<int, std::vector<uint8_t>> &const_allowed,
                                  std::vector<uint8_t> *out_ok,
                                  uint32 *out_count,
                                  LocalStat *stat,
                                  int bundle_id = 0)
{
    if (!out_ok || !out_count) return false;
    (void)const_allowed;
    ensure_local_cache_ctx();
    register_query_callback();
    auto it_t = loaded.tables.find(table);
    if (it_t == loaded.tables.end())
        return false;
    const TableInfo &ti = it_t->second;
    TableCache &tc = g_local_cache.tables[table];
    std::vector<int> const_ids;
    std::vector<const Atom*> const_atoms;
    for (size_t i = 0; i < ti.const_atom_ids.size(); i++) {
        int aid = ti.const_atom_ids[i];
        if (target_vars.count(aid) == 0)
            continue;
        const Atom *ap = (aid > 0 && aid < (int)loaded.atom_by_id.size())
                             ? loaded.atom_by_id[aid]
                             : nullptr;
        if (!ap || ap->kind != AtomKind::CONST)
            continue;
        const_ids.push_back(aid);
        const_atoms.push_back(ap);
    }
    if (const_ids.empty()) {
        out_ok->clear();
        *out_count = ti.n_rows;
        if (stat) {
            stat->table = table;
            stat->atoms = 0;
            stat->bins = 0;
            stat->sat_calls = 0;
            stat->cache_hits = 0;
            stat->ms_stamp = 0.0;
            stat->ms_bin = 0.0;
            stat->ms_eval = 0.0;
            stat->ms_fill = 0.0;
        }
        return true;
    }

    // ensure global atoms + bins for this table
    double stamp_ms = 0.0;
    double bin_ms = 0.0;
    if (!tc.global.ready) {
        tc.global.atom_keys.clear();
        tc.global.atom_index.clear();
        tc.global.token_idx.clear();
        tc.global.allowed_by_key.clear();
        for (int aid : ti.const_atom_ids) {
            if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                continue;
            const Atom *ap = loaded.atom_by_id[aid];
            if (!ap || ap->kind != AtomKind::CONST)
                continue;
            std::string akey = const_atom_key(ap);
            if (tc.global.atom_index.find(akey) != tc.global.atom_index.end())
                continue;
            auto itoff = ti.schema_offset.find(ap->lhs_schema_key);
            if (itoff == ti.schema_offset.end())
                ereport(ERROR,
                        (errmsg("policy: missing column offset for %s", ap->lhs_schema_key.c_str())));
            auto it_dict = loaded.dicts.find(ap->left.key());
            if (it_dict == loaded.dicts.end())
                ereport(ERROR,
                        (errmsg("policy: missing dict for const atom y%d col=%s",
                                ap->id, ap->left.key().c_str())));
            tc.global.atom_index[akey] = (int)tc.global.atom_keys.size();
            tc.global.atom_keys.push_back(akey);
            tc.global.token_idx.push_back(itoff->second);
            DictType dtype = dict_type_for_key(loaded, ap->left.key());
            tc.global.allowed_by_key[akey] = build_allowed_tokens(it_dict->second, *ap, dtype);
        }
        rebuild_global_bins(ti, tc, &stamp_ms, &bin_ms);
        tc.global.ms_stamp = stamp_ms;
        tc.global.ms_bin = bin_ms;
        CF_TRACE_LOG( "policy: global_atoms table=%s count=%zu",
             table.c_str(), tc.global.atom_keys.size());
        CF_TRACE_LOG( "policy: global_bins table=%s bins=%zu rows=%u",
             table.c_str(), tc.global.hist.size(), ti.n_rows);
    } else {
        // enforce no new atoms mid-query
        for (const Atom *ap : const_atoms) {
            std::string akey = const_atom_key(ap);
            if (tc.global.atom_index.find(akey) == tc.global.atom_index.end()) {
                ereport(ERROR,
                        (errmsg("policy: new atom encountered after global scan table=%s atom=%s",
                                table.c_str(), akey.c_str())));
            }
        }
        stamp_ms = 0.0;
        bin_ms = 0.0;
    }

    if (bundle_id > 0) {
        CF_TRACE_LOG( "policy: bundle_eval target=%s bundle_id=%d uses_atoms=%zu",
             table.c_str(), bundle_id, const_ids.size());
    }

    int atom_count = (int)loaded.atom_by_id.size() - 1;
    std::string base_sig = base_sig_for_bits((size_t)atom_count);
    std::vector<int> atom_to_global(atom_count + 1, -1);
    for (const Atom *ap : const_atoms) {
        std::string akey = const_atom_key(ap);
        auto it = tc.global.atom_index.find(akey);
        if (it != tc.global.atom_index.end() && ap->id > 0 && ap->id < (int)atom_to_global.size())
            atom_to_global[ap->id] = it->second;
    }

    std::vector<std::string> bin_sig_bundle;
    const size_t n_bins = tc.global.hist.size();
    bin_sig_bundle.reserve(n_bins);
    for (size_t b = 0; b < n_bins; b++) {
        const uint8_t *gsig = tc.global.bin_sig_flat.data() + b * tc.global.nbytes;
        std::string s = base_sig;
        for (int aid : const_ids) {
            int gidx = (aid >= 0 && aid < (int)atom_to_global.size()) ? atom_to_global[aid] : -1;
            if (gidx < 0) continue;
            bool bit = get_sig_bit_bytes(gsig, tc.global.nbytes, (size_t)gidx);
            set_sig_bit_idx(s, (size_t)(aid - 1), bit);
        }
        bin_sig_bundle.push_back(std::move(s));
    }

    std::vector<uint8_t> allow_bin;
    double sat_ms = 0.0;
    int sat_calls = 0;
    int cache_hits = 0;
    std::string cache_key = build_cache_key(ast, loaded, const_ids);
    auto &dec_cache = tc.decision_cache[cache_key];
    if (!eval_bins_sat(ast, atom_count, bin_sig_bundle, &dec_cache, &allow_bin,
                       &sat_ms, &sat_calls, &cache_hits))
        return false;
    auto t4 = Clock::now();

    out_ok->assign(ti.n_rows, 0);
    uint32 cnt = 0;
    for (uint32 r = 0; r < ti.n_rows; r++) {
        int b = tc.global.row_to_bin[r];
        bool ok = (b >= 0 && b < (int)allow_bin.size() && allow_bin[(size_t)b]);
        if (ok) {
            (*out_ok)[r] = 1;
            cnt++;
        }
    }
    auto t5 = Clock::now();

    CF_TRACE_LOG( "policy: local_bins table=%s atoms=%zu bins=%zu",
         table.c_str(), const_ids.size(), n_bins);
    CF_TRACE_LOG( "policy: local_ms table=%s stamp=%.3f bin=%.3f eval=%.3f fill=%.3f",
         table.c_str(),
         stamp_ms,
         bin_ms,
         sat_ms,
         Ms(t5 - t4).count());
    CF_TRACE_LOG( "policy: local_eval table=%s sat_calls=%d cache_hits=%d",
         table.c_str(), sat_calls, cache_hits);

    if (stat) {
        stat->table = table;
        stat->atoms = (int)const_ids.size();
        stat->bins = n_bins;
        stat->sat_calls = sat_calls;
        stat->cache_hits = cache_hits;
        stat->ms_stamp = stamp_ms;
        stat->ms_bin = bin_ms;
        stat->ms_eval = sat_ms;
        stat->ms_fill = Ms(t5 - t4).count();
    }

    *out_count = cnt;
    return true;
}

static AstCheckResult ast_check_node(const Loaded &loaded, const AstNode *node)
{
    AstCheckResult res;
    if (!node)
        return res;
    if (node->type == AstNode::VAR) {
        int id = node->var_id;
        if (id <= 0 || id >= (int)loaded.atom_by_id.size() || !loaded.atom_by_id[id]) {
            res.valid = false;
            res.reason = "missing atom for var";
            return res;
        }
        const Atom *ap = loaded.atom_by_id[id];
        if (ap->kind == AtomKind::JOIN) {
            res.has_join = true;
        } else {
            res.const_tables.insert(ap->left.table);
        }
        return res;
    }
    AstCheckResult l = ast_check_node(loaded, node->left);
    AstCheckResult r = ast_check_node(loaded, node->right);
    if (!l.valid) return l;
    if (!r.valid) return r;
    if (node->type == AstNode::OR) {
        if (l.has_join || r.has_join) {
            res.valid = false;
            res.reason = "OR mixes join atoms";
            return res;
        }
        if (l.const_tables.size() != 1 || r.const_tables.size() != 1) {
            res.valid = false;
            res.reason = "OR across multiple tables";
            return res;
        }
        const std::string &lt = *l.const_tables.begin();
        const std::string &rt = *r.const_tables.begin();
        if (lt != rt) {
            res.valid = false;
            res.reason = "OR across different tables";
            return res;
        }
        res.const_tables.insert(lt);
        return res;
    }
    if (node->type == AstNode::AND) {
        res.has_join = l.has_join || r.has_join;
        res.const_tables = l.const_tables;
        res.const_tables.insert(r.const_tables.begin(), r.const_tables.end());
        return res;
    }
    res.valid = false;
    res.reason = "unsupported AST node";
    return res;
}

static bool ast_supported_multi_join(const Loaded &loaded, const AstNode *ast,
                                     std::string *reason)
{
    if (!ast) {
        if (reason) *reason = "missing AST";
        return false;
    }
    AstCheckResult res = ast_check_node(loaded, ast);
    if (!res.valid) {
        if (reason) *reason = res.reason.empty() ? "invalid AST" : res.reason;
        return false;
    }
    return true;
}

static bool multi_join_enforce_ast(const Loaded &loaded,
                                   const std::string &target,
                                   const AstNode *ast,
                                   const std::set<int> &vars,
                                   PolicyAllowListC *out,
                                   BundleProfile *profile,
                                   bool log_detail,
                                   std::map<int, Bitset> *out_allowed,
                                   const std::map<std::string, const uint8*> *restrict_bits)
{
    if (!out) return false;

    if (!ast) {
        ereport(ERROR, (errmsg("policy: missing AST for target %s", target.c_str())));
    }

    std::map<int, std::set<std::string>> class_tables;
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::JOIN)
            continue;
        int cid = ap->join_class_id;
        if (cid < 0)
            continue;
        class_tables[cid].insert(ap->left.table);
        class_tables[cid].insert(ap->right.table);
    }
    if (class_tables.empty()) {
        const TableInfo &ti = loaded.tables.find(target)->second;
        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, target, ast, vars,
                                   std::map<int, std::vector<uint8_t>>{}, &ok_rows, &cnt,
                                   &lst, profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", target.c_str())));
        }
        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *)palloc0(bytes);
        const uint8 *target_restrict = nullptr;
        if (restrict_bits) {
            auto it_rb = restrict_bits->find(target);
            if (it_rb != restrict_bits->end())
                target_restrict = it_rb->second;
        }
        cnt = 0;
        for (uint32 r = 0; r < ti.n_rows; r++) {
            if (!ok_rows.empty() && !ok_rows[r])
                continue;
            if (!allow_bit(target_restrict, r))
                continue;
            bits[r >> 3] |= (uint8)(1u << (r & 7));
            cnt++;
        }
        out->count = 0;
        out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
        out->items[0].table = pstrdup(target.c_str());
        out->items[0].allow_bits = bits;
        out->items[0].n_rows = ti.n_rows;
        out->count = 1;
        if (log_detail)
            CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), cnt, ti.n_rows);
        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
        if (out_allowed) out_allowed->clear();
        return true;
    }

    struct Edge {
        std::string a;
        std::string b;
        int cid;
    };
    std::vector<Edge> edges;
    std::set<std::string> nodes;
    for (const auto &kv : class_tables) {
        int cid = kv.first;
        if (kv.second.size() < 2) {
            std::string tables;
            for (const auto &t : kv.second) {
                if (!tables.empty()) tables += ", ";
                tables += t;
            }
            ereport(ERROR,
                    (errmsg("policy: multi-join class=%d has %zu tables [%s]; expected >= 2",
                            cid, kv.second.size(), tables.c_str())));
        }
        // Join classes represent equality constraints across N tables.
        // Any spanning tree across the tables is a sound representation.
        auto it = kv.second.begin();
        std::string center = *it++;
        nodes.insert(center);
        for (; it != kv.second.end(); ++it) {
            const std::string &other = *it;
            edges.push_back({center, other, cid});
            nodes.insert(other);
        }
    }

    if (nodes.count(target) == 0) {
        ereport(ERROR,
                (errmsg("policy: target %s not present in join graph", target.c_str())));
    }
    bool is_tree = (edges.size() == nodes.size() - 1);

    std::map<std::string, std::vector<std::string>> adj;
    std::map<std::string, std::map<std::string, int>> edge_class;
    for (const auto &e : edges) {
        adj[e.a].push_back(e.b);
        adj[e.b].push_back(e.a);
        edge_class[e.a][e.b] = e.cid;
        edge_class[e.b][e.a] = e.cid;
    }

    std::set<std::string> visited;
    std::map<std::string, std::string> parent;
    std::map<std::string, std::vector<std::string>> children;
    std::vector<std::string> preorder;
    std::vector<std::string> postorder;
    if (is_tree) {
        std::function<void(const std::string&, const std::string&)> dfs =
            [&](const std::string &t, const std::string &p) {
                if (visited.count(t))
                    ereport(ERROR, (errmsg("policy: multi-join graph has a cycle at %s", t.c_str())));
                visited.insert(t);
                parent[t] = p;
                preorder.push_back(t);
                for (const auto &n : adj[t]) {
                    if (n == p) continue;
                    dfs(n, t);
                    children[t].push_back(n);
                }
                postorder.push_back(t);
            };
        dfs(target, "");
        if (visited.size() != nodes.size()) {
            ereport(ERROR,
                    (errmsg("policy: multi-join graph disconnected (visited=%zu nodes=%zu)",
                            visited.size(), nodes.size())));
        }
    }

    std::map<std::string, std::map<int, int>> table_class_idx;
    for (const auto &t : nodes) {
        auto it_t = loaded.tables.find(t);
        if (it_t == loaded.tables.end())
            ereport(ERROR, (errmsg("policy: missing table %s in loaded artifacts", t.c_str())));
        const TableInfo &ti = it_t->second;
        for (const auto &n : adj[t]) {
            int cid = edge_class[t][n];
            int idx = -1;
            for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                if (ti.join_class_ids[j] == cid) {
                    idx = ti.join_token_idx[j];
                    break;
                }
            }
            if (idx < 0) {
                ereport(ERROR,
                        (errmsg("policy: missing join token index for table=%s class=%d",
                                t.c_str(), cid)));
            }
            table_class_idx[t][cid] = idx;
        }
    }

    std::map<int, size_t> domain_size;
    for (const auto &e : edges) {
        int cid = e.cid;
        int max_tok = -1;
        for (const auto &t : {e.a, e.b}) {
            const TableInfo &ti = loaded.tables.find(t)->second;
            int idx = table_class_idx[t][cid];
            for (uint32 r = 0; r < ti.n_rows; r++) {
                const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                int32 tok = row[idx];
                if (tok > max_tok) max_tok = tok;
            }
        }
        size_t ds = (max_tok >= 0) ? (size_t)max_tok + 1 : 0;
        auto it_ds = domain_size.find(cid);
        if (it_ds == domain_size.end() || ds > it_ds->second)
            domain_size[cid] = ds;
    }

    std::map<int, std::vector<uint8_t>> const_allowed;
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::CONST)
            continue;
        auto it_dict = loaded.dicts.find(ap->left.key());
        if (it_dict == loaded.dicts.end()) {
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            aid, ap->left.key().c_str())));
        }
        DictType dtype = dict_type_for_key(loaded, ap->left.key());
        const_allowed[aid] = build_allowed_tokens(it_dict->second, *ap, dtype);
    }

    std::map<std::string, std::vector<uint8_t>> local_ok;
    std::map<std::string, uint32> local_ok_count;
    for (const auto &t : nodes) {
        const TableInfo &ti = loaded.tables.find(t)->second;
        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, t, ast, vars,
                                   const_allowed, &ok_rows, &cnt, &lst,
                                   profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", t.c_str())));
        }
        if (ok_rows.empty()) {
            local_ok_count[t] = ti.n_rows;
            continue;
        }
        if (log_detail)
            CF_TRACE_LOG( "policy: local_ok source=bins table=%s", t.c_str());
        local_ok_count[t] = cnt;
        local_ok[t] = std::move(ok_rows);
        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
    }

    if (log_detail) {
        for (const auto &kv : local_ok_count) {
            const TableInfo &ti = loaded.tables.find(kv.first)->second;
            CF_TRACE_LOG( "policy: multi_join local_ok %s = %u / %u",
                 kv.first.c_str(), kv.second, ti.n_rows);
        }
    }

    if (!is_tree) {
        // Cyclic join graph fallback: exact row-level chase using unique token->row maps.
        //
        // This path assumes join atoms are all conjunctive (AND) and local predicates are
        // table-local (the precondition for this function). We compute, for each target row
        // that passes local_ok, whether the join constraints can be satisfied by chasing
        // equality tokens across the join graph.

        struct AdjE {
            int to = -1;
            int cid = -1;
            int idx_self = -1;
            int idx_to = -1;
        };

        std::vector<std::string> node_list(nodes.begin(), nodes.end());
        std::unordered_map<std::string, int> node_id;
        node_id.reserve(node_list.size());
        for (size_t i = 0; i < node_list.size(); i++)
            node_id[node_list[i]] = (int)i;
        auto it_tid = node_id.find(target);
        if (it_tid == node_id.end())
            ereport(ERROR, (errmsg("policy: target %s not present in join graph", target.c_str())));
        int target_id = it_tid->second;
        const size_t N = node_list.size();

        std::vector<const TableInfo*> ti_by_id(N, nullptr);
        for (size_t i = 0; i < N; i++) {
            auto it_t = loaded.tables.find(node_list[i]);
            if (it_t == loaded.tables.end())
                ereport(ERROR, (errmsg("policy: missing table %s in loaded artifacts", node_list[i].c_str())));
            ti_by_id[i] = &it_t->second;
        }

        std::vector<const std::vector<uint8_t>*> ok_by_id(N, nullptr);
        for (size_t i = 0; i < N; i++) {
            auto it_ok = local_ok.find(node_list[i]);
            if (it_ok != local_ok.end())
                ok_by_id[i] = &it_ok->second;
        }

        std::vector<const uint8*> restrict_by_id(N, nullptr);
        if (restrict_bits) {
            for (size_t i = 0; i < N; i++) {
                auto it_rb = restrict_bits->find(node_list[i]);
                if (it_rb != restrict_bits->end())
                    restrict_by_id[i] = it_rb->second;
            }
        }

        // Build adjacency with token indices for quick per-row lookups.
        std::vector<std::vector<AdjE>> adj_id(N);
        adj_id.assign(N, {});
        for (const auto &e : edges) {
            int ia = node_id[e.a];
            int ib = node_id[e.b];
            int idx_a = table_class_idx[e.a][e.cid];
            int idx_b = table_class_idx[e.b][e.cid];
            adj_id[(size_t)ia].push_back({ib, e.cid, idx_a, idx_b});
            adj_id[(size_t)ib].push_back({ia, e.cid, idx_b, idx_a});
        }

        // Build unique tok->row maps for non-target tables on incident join classes.
        std::vector<std::unordered_map<int, std::vector<int32_t>>> row_by_tok(N);
        for (size_t i = 0; i < N; i++) {
            if ((int)i == target_id) continue;
            const TableInfo &ti = *ti_by_id[i];
            for (const auto &ae : adj_id[i]) {
                int cid = ae.cid;
                if (row_by_tok[i].find(cid) != row_by_tok[i].end())
                    continue;
                auto it_ds = domain_size.find(cid);
                size_t D = (it_ds != domain_size.end()) ? it_ds->second : 0;
                if (D == 0)
                    continue;
                std::vector<int32_t> map(D, -1);
                bool unique = true;
                int idx = table_class_idx[node_list[i]][cid];
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    if (ok_by_id[i] && !(*ok_by_id[i])[r])
                        continue;
                    if (!allow_bit(restrict_by_id[i], r))
                        continue;
                    const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                    int32 tok = row[idx];
                    if (tok < 0 || (size_t)tok >= D)
                        continue;
                    if (map[(size_t)tok] == -1) {
                        map[(size_t)tok] = (int32_t)r;
                    } else {
                        unique = false;
                        break;
                    }
                }
                if (unique) {
                    row_by_tok[i][cid] = std::move(map);
                }
            }
        }

        const TableInfo &ti_t = *ti_by_id[(size_t)target_id];
        size_t bytes = (ti_t.n_rows + 7) / 8;
        uint8 *bits = (uint8 *)palloc0(bytes);
        uint32 passed = 0;

        std::vector<int32_t> assigned(N, -1);
        std::vector<int> q;
        q.reserve(N);

        for (uint32 r = 0; r < ti_t.n_rows; r++) {
            if (ok_by_id[(size_t)target_id] && !(*ok_by_id[(size_t)target_id])[r])
                continue;
            if (!allow_bit(restrict_by_id[(size_t)target_id], r))
                continue;

            std::fill(assigned.begin(), assigned.end(), -1);
            q.clear();
            assigned[(size_t)target_id] = (int32_t)r;
            q.push_back(target_id);

            bool ok = true;
            for (size_t qi = 0; qi < q.size() && ok; qi++) {
                int cur = q[qi];
                const TableInfo &ti_cur = *ti_by_id[(size_t)cur];
                int32 rid_cur = assigned[(size_t)cur];
                const int32_t *row_cur = ti_cur.code + (size_t)rid_cur * (size_t)ti_cur.stride;
                for (const auto &ae : adj_id[(size_t)cur]) {
                    int to = ae.to;
                    int32 tok = row_cur[ae.idx_self];
                    if (tok < 0) { ok = false; break; }

                    int32 rid_to = assigned[(size_t)to];
                    if (rid_to >= 0) {
                        const TableInfo &ti_to = *ti_by_id[(size_t)to];
                        const int32_t *row_to = ti_to.code + (size_t)rid_to * (size_t)ti_to.stride;
                        int32 tok2 = row_to[ae.idx_to];
                        if (tok2 != tok) { ok = false; break; }
                        continue;
                    }

                    // Deterministically assign only if the target table has a unique tok->row map for this class.
                    auto it_m = row_by_tok[(size_t)to].find(ae.cid);
                    if (it_m == row_by_tok[(size_t)to].end())
                        continue;  // Defer; may be assigned via another edge.
                    const auto &map = it_m->second;
                    if ((size_t)tok >= map.size()) { ok = false; break; }
                    rid_to = map[(size_t)tok];
                    if (rid_to < 0) { ok = false; break; }
                    assigned[(size_t)to] = rid_to;
                    q.push_back(to);
                }
            }
            if (!ok)
                continue;

            // Require all tables to be assigned (join atoms are conjunctive).
            for (size_t i = 0; i < N; i++) {
                if (assigned[i] < 0) { ok = false; break; }
            }
            if (!ok)
                continue;

            // Final edge check (covers deferred edges).
            for (const auto &e : edges) {
                int ia = node_id[e.a];
                int ib = node_id[e.b];
                const TableInfo &ta = *ti_by_id[(size_t)ia];
                const TableInfo &tb = *ti_by_id[(size_t)ib];
                int idx_a = table_class_idx[e.a][e.cid];
                int idx_b = table_class_idx[e.b][e.cid];
                const int32_t *ra = ta.code + (size_t)assigned[(size_t)ia] * (size_t)ta.stride;
                const int32_t *rb = tb.code + (size_t)assigned[(size_t)ib] * (size_t)tb.stride;
                int32 toka = ra[idx_a];
                int32 tokb = rb[idx_b];
                if (toka < 0 || tokb < 0 || toka != tokb) { ok = false; break; }
            }
            if (!ok)
                continue;

            bits[r >> 3] |= (uint8)(1u << (r & 7));
            passed++;
        }

        out->count = 0;
        out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
        out->items[0].table = pstrdup(target.c_str());
        out->items[0].allow_bits = bits;
        out->items[0].n_rows = ti_t.n_rows;
        out->count = 1;
        if (log_detail)
            CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti_t.n_rows);
        if (out_allowed) out_allowed->clear();
        if (profile) {
            DecodeStat ds;
            ds.table = target;
            ds.rows_total = ti_t.n_rows;
            ds.rows_allowed = passed;
            ds.ms_decode = 0.0;
            profile->decode.push_back(ds);
            profile->decode_ms_total += ds.ms_decode;
        }
        return true;
    }

    std::map<std::string, std::map<std::string, Bitset>> msg_map;
    auto compute_msg = [&](const std::string &from, const std::string &to) -> Bitset {
        int cid = edge_class[from][to];
        size_t D = domain_size[cid];
        Bitset msg;
        msg.nbits = D;
        msg.bytes.assign((D + 7) / 8, 0);
        const TableInfo &ti = loaded.tables.find(from)->second;
        int idx_to = table_class_idx[from][cid];
        const std::vector<uint8_t> *ok_rows = nullptr;
        auto it_ok = local_ok.find(from);
        if (it_ok != local_ok.end())
            ok_rows = &it_ok->second;
        const uint8 *from_restrict = nullptr;
        if (restrict_bits) {
            auto it_rb = restrict_bits->find(from);
            if (it_rb != restrict_bits->end())
                from_restrict = it_rb->second;
        }
        for (uint32 r = 0; r < ti.n_rows; r++) {
            if (ok_rows && !(*ok_rows)[r])
                continue;
            if (!allow_bit(from_restrict, r))
                continue;
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            bool row_ok = true;
            for (const auto &n : adj[from]) {
                if (n == to)
                    continue;
                int cid_n = edge_class[from][n];
                int idx_n = table_class_idx[from][cid_n];
                int32 tok_n = row[idx_n];
                auto it_m = msg_map.find(n);
                if (tok_n < 0 || it_m == msg_map.end() || !it_m->second[from].test((size_t)tok_n)) {
                    row_ok = false;
                    break;
                }
            }
            if (!row_ok)
                continue;
            int32 tok = row[idx_to];
            if (tok >= 0)
                msg.set((size_t)tok);
        }
        return msg;
    };

    auto t_prop_start = Clock::now();
    for (const auto &t : postorder) {
        if (t == target) continue;
        const std::string &p = parent[t];
        msg_map[t][p] = compute_msg(t, p);
    }
    for (const auto &t : preorder) {
        for (const auto &c : children[t]) {
            msg_map[t][c] = compute_msg(t, c);
        }
    }
    auto t_prop_end = Clock::now();
    if (profile) {
        profile->prop_ms_total = Ms(t_prop_end - t_prop_start).count();
        profile->prop_iterations = 1;
    }

    std::map<int, Bitset> allowed_by_class;
    for (const auto &e : edges) {
        int cid = e.cid;
        Bitset allow = msg_map[e.a][e.b];
        bitset_intersect(allow, msg_map[e.b][e.a]);
        auto it_allow = allowed_by_class.find(cid);
        if (it_allow == allowed_by_class.end()) {
            allowed_by_class[cid] = std::move(allow);
        } else {
            bitset_intersect(it_allow->second, allow);
        }
    }
    if (log_detail || profile) {
        for (const auto &kv : allowed_by_class) {
            int cid = kv.first;
            size_t D = domain_size[cid];
            size_t pop = bitset_popcount(kv.second, D);
            if (log_detail)
                CF_TRACE_LOG( "policy: multi_join class=%d allowed=%zu / %zu",
                     cid, pop, D);
            if (profile) {
                PropStat ps;
                ps.class_id = cid;
                ps.tokens_total = D;
                ps.tokens_allowed = pop;
                profile->prop.push_back(ps);
            }
        }
    }

    const TableInfo &ti = loaded.tables.find(target)->second;
    size_t bytes = (ti.n_rows + 7) / 8;
    uint8 *bits = (uint8 *)palloc0(bytes);
    uint32 passed = 0;
    const std::vector<uint8_t> *ok_rows = nullptr;
    auto it_ok = local_ok.find(target);
    if (it_ok != local_ok.end())
        ok_rows = &it_ok->second;
    const uint8 *target_restrict = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(target);
        if (it_rb != restrict_bits->end())
            target_restrict = it_rb->second;
    }
    auto t_decode_start = Clock::now();
    for (uint32 r = 0; r < ti.n_rows; r++) {
        if (ok_rows && !(*ok_rows)[r])
            continue;
        if (!allow_bit(target_restrict, r))
            continue;
        const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
        bool row_ok = true;
        for (const auto &n : adj[target]) {
            int cid = edge_class[target][n];
            int idx = table_class_idx[target][cid];
            int32 tok = row[idx];
            if (tok < 0 || !msg_map[n][target].test((size_t)tok)) {
                row_ok = false;
                break;
            }
        }
        if (row_ok) {
            bits[r >> 3] |= (uint8)(1u << (r & 7));
            passed++;
        }
    }
    auto t_decode_end = Clock::now();

    out->count = 0;
    out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
    out->items[0].table = pstrdup(target.c_str());
    out->items[0].allow_bits = bits;
    out->items[0].n_rows = ti.n_rows;
    out->count = 1;
    if (log_detail)
        CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti.n_rows);
    if (profile) {
        DecodeStat ds;
        ds.table = target;
        ds.rows_total = ti.n_rows;
        ds.rows_allowed = passed;
        ds.ms_decode = Ms(t_decode_end - t_decode_start).count();
        profile->decode.push_back(ds);
        profile->decode_ms_total += ds.ms_decode;
    }

    if (out_allowed)
        *out_allowed = std::move(allowed_by_class);
    return true;
}

static bool multi_join_token_domain_or(const Loaded &loaded,
                                       const AstNode *ast,
                                       const std::set<int> &vars,
                                       PolicyAllowListC *out,
                                       BundleProfile *profile,
                                       bool log_detail) {
    if (!out) return false;
    if (!ast) {
        ereport(ERROR, (errmsg("policy: missing AST for token-domain evaluation")));
    }
    if (loaded.target_set.size() != 1) {
        ereport(ERROR,
                (errmsg("policy: multi-join enforcement supports a single target table (targets=%zu)",
                        loaded.target_set.size())));
    }
    const std::string target = *loaded.target_set.begin();

    std::map<int, std::set<std::string>> class_tables;
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::JOIN)
            continue;
        int cid = ap->join_class_id;
        if (cid < 0)
            continue;
        class_tables[cid].insert(ap->left.table);
        class_tables[cid].insert(ap->right.table);
    }
    if (class_tables.empty()) {
        const TableInfo &ti = loaded.tables.find(target)->second;
        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, target, ast, vars,
                                   std::map<int, std::vector<uint8_t>>{}, &ok_rows, &cnt,
                                   &lst, profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", target.c_str())));
        }
        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *)palloc0(bytes);
        if (ok_rows.empty()) {
            memset(bits, 0xFF, bytes);
            cnt = ti.n_rows;
        } else {
            for (uint32 r = 0; r < ti.n_rows; r++) {
                if (ok_rows[r])
                    bits[r >> 3] |= (uint8)(1u << (r & 7));
            }
        }
        out->count = 0;
        out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
        out->items[0].table = pstrdup(target.c_str());
        out->items[0].allow_bits = bits;
        out->items[0].n_rows = ti.n_rows;
        out->count = 1;
        if (log_detail)
            CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), cnt, ti.n_rows);
        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
        return true;
    }

    if (class_tables.size() != 1) {
        ereport(ERROR,
                (errmsg("policy: token-domain OR currently supports a single join class (classes=%zu)",
                        class_tables.size())));
    }

    std::set<std::string> nodes;
    for (const auto &kv : class_tables) {
        for (const auto &t : kv.second)
            nodes.insert(t);
    }
    if (nodes.count(target) == 0) {
        ereport(ERROR,
                (errmsg("policy: target %s not present in join graph", target.c_str())));
    }

    std::map<std::string, std::map<int, int>> table_class_idx;
    for (const auto &t : nodes) {
        auto it_t = loaded.tables.find(t);
        if (it_t == loaded.tables.end())
            ereport(ERROR, (errmsg("policy: missing table %s in loaded artifacts", t.c_str())));
        const TableInfo &ti = it_t->second;
        for (int cid : ti.join_class_ids) {
            int idx = -1;
            for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                if (ti.join_class_ids[j] == cid) {
                    idx = ti.join_token_idx[j];
                    break;
                }
            }
            if (idx >= 0)
                table_class_idx[t][cid] = idx;
        }
    }

    int primary_cid = class_tables.begin()->first;
    const std::set<std::string> &primary_tables = class_tables.begin()->second;
    std::map<int, size_t> domain_size;
    {
        int cid = primary_cid;
        int max_tok = -1;
        for (const auto &t : primary_tables) {
            const TableInfo &ti = loaded.tables.find(t)->second;
            auto it_idx = table_class_idx[t].find(cid);
            if (it_idx == table_class_idx[t].end())
                ereport(ERROR,
                        (errmsg("policy: missing join token index for table=%s class=%d",
                                t.c_str(), cid)));
            int idx = it_idx->second;
            for (uint32 r = 0; r < ti.n_rows; r++) {
                const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                int32 tok = row[idx];
                if (tok > max_tok) max_tok = tok;
            }
        }
        domain_size[cid] = (max_tok >= 0) ? (size_t)max_tok + 1 : 0;
    }

    std::map<int, std::vector<uint8_t>> const_allowed;
    build_const_allowed_map(loaded, vars, &const_allowed);

    std::map<std::string, std::vector<uint8_t>> local_ok;
    std::map<std::string, uint32> local_ok_count;
    for (const auto &t : nodes) {
        const TableInfo &ti = loaded.tables.find(t)->second;
        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, t, ast, vars,
                                   const_allowed, &ok_rows, &cnt, &lst,
                                   profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", t.c_str())));
        }
        if (ok_rows.empty()) {
            local_ok_count[t] = ti.n_rows;
            continue;
        }
        if (log_detail)
            CF_TRACE_LOG( "policy: local_ok source=bins table=%s", t.c_str());
        local_ok_count[t] = cnt;
        local_ok[t] = std::move(ok_rows);
        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
    }

    struct ConstAtomInfo {
        int atom_id;
        int token_idx;
        const std::vector<uint8_t> *allowed;
    };
    std::map<std::string, std::vector<ConstAtomInfo>> const_atoms_by_table;
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::CONST)
            continue;
        auto it_t = loaded.tables.find(ap->left.table);
        if (it_t == loaded.tables.end()) continue;
        const TableInfo &ti = it_t->second;
        auto it_off = ti.schema_offset.find(ap->lhs_schema_key);
        if (it_off == ti.schema_offset.end())
            ereport(ERROR,
                    (errmsg("policy: missing column offset for %s", ap->lhs_schema_key.c_str())));
        auto it_allowed = const_allowed.find(aid);
        if (it_allowed == const_allowed.end())
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            aid, ap->left.key().c_str())));
        ConstAtomInfo info;
        info.atom_id = aid;
        info.token_idx = it_off->second;
        info.allowed = &it_allowed->second;
        const_atoms_by_table[ap->left.table].push_back(info);
    }

    // atoms per class
    std::vector<int> target_const_ids;
    {
        auto it_tc = const_atoms_by_table.find(target);
        if (it_tc != const_atoms_by_table.end()) {
            for (const auto &ca : it_tc->second)
                target_const_ids.push_back(ca.atom_id);
        }
    }
    std::sort(target_const_ids.begin(), target_const_ids.end());
    target_const_ids.erase(std::unique(target_const_ids.begin(), target_const_ids.end()), target_const_ids.end());
    const size_t target_k = target_const_ids.size();
    if (target_k > 20) {
        ereport(ERROR,
                (errmsg("policy: token-domain OR target const atoms too many (%zu)", target_k)));
    }
    const size_t sig_space = (target_k == 0) ? 1 : ((size_t)1 << target_k);

    std::vector<int> target_const_token_idx;
    target_const_token_idx.reserve(target_k);
    std::vector<const std::vector<uint8_t>*> target_const_allowed;
    target_const_allowed.reserve(target_k);
    {
        const TableInfo &ti_t = loaded.tables.find(target)->second;
        for (int aid : target_const_ids) {
            const Atom *ap = (aid > 0 && aid < (int)loaded.atom_by_id.size())
                                 ? loaded.atom_by_id[aid] : nullptr;
            if (!ap) continue;
            auto it_off = ti_t.schema_offset.find(ap->lhs_schema_key);
            if (it_off == ti_t.schema_offset.end())
                ereport(ERROR,
                        (errmsg("policy: missing column offset for %s", ap->lhs_schema_key.c_str())));
            auto it_allow = const_allowed.find(aid);
            if (it_allow == const_allowed.end())
                ereport(ERROR,
                        (errmsg("policy: missing dict for const atom y%d col=%s",
                                aid, ap->left.key().c_str())));
            target_const_token_idx.push_back(it_off->second);
            target_const_allowed.push_back(&it_allow->second);
        }
    }

    std::map<int, Bitset> allowed;
    for (const auto &kv : domain_size) {
        Bitset bs;
        bs.nbits = kv.second;
        bs.bytes.assign((bs.nbits + 7) / 8, 0xFF);
        if (bs.nbits % 8 != 0 && !bs.bytes.empty()) {
            uint8 mask = (uint8)((1u << (bs.nbits % 8)) - 1u);
            bs.bytes.back() &= mask;
        }
        allowed[kv.first] = std::move(bs);
    }

    auto compute_support = [&](std::map<std::string, std::map<int, Bitset>> &support,
                               std::map<int, std::map<int, Bitset>> &support_const) {
        support.clear();
        support_const.clear();
        for (const auto &t : nodes) {
            const TableInfo &ti = loaded.tables.find(t)->second;
            const auto &t_const_atoms = const_atoms_by_table[t];
            for (int cid : ti.join_class_ids) {
                size_t D = domain_size[cid];
                Bitset bs;
                bs.nbits = D;
                bs.bytes.assign((D + 7) / 8, 0);
                support[t][cid] = std::move(bs);
            }
            for (const auto &ca : t_const_atoms) {
                for (int cid : ti.join_class_ids) {
                    size_t D = domain_size[cid];
                    Bitset bs;
                    bs.nbits = D;
                    bs.bytes.assign((D + 7) / 8, 0);
                    support_const[ca.atom_id][cid] = std::move(bs);
                }
            }
            for (uint32 r = 0; r < ti.n_rows; r++) {
                const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                for (int cid : ti.join_class_ids) {
                    int idx = table_class_idx[t][cid];
                    int32 tok = row[idx];
                    if (tok < 0) continue;
                    bool ok = true;
                    for (int cid2 : ti.join_class_ids) {
                        if (cid2 == cid) continue;
                        int idx2 = table_class_idx[t][cid2];
                        int32 tok2 = row[idx2];
                        if (tok2 < 0 || !allowed[cid2].test((size_t)tok2)) {
                            ok = false;
                            break;
                        }
                    }
                    if (!ok) continue;
                    support[t][cid].set((size_t)tok);
                }
                if (!t_const_atoms.empty()) {
                    for (const auto &ca : t_const_atoms) {
                        int32 tok_c = row[ca.token_idx];
                        bool atom_true = (tok_c >= 0 && (size_t)tok_c < ca.allowed->size() &&
                                          (*ca.allowed)[(size_t)tok_c]);
                        if (!atom_true) continue;
                        for (int cid : ti.join_class_ids) {
                            int idx = table_class_idx[t][cid];
                            int32 tok = row[idx];
                            if (tok < 0) continue;
                            bool ok = true;
                            for (int cid2 : ti.join_class_ids) {
                                if (cid2 == cid) continue;
                                int idx2 = table_class_idx[t][cid2];
                                int32 tok2 = row[idx2];
                                if (tok2 < 0 || !allowed[cid2].test((size_t)tok2)) {
                                    ok = false;
                                    break;
                                }
                            }
                            if (!ok) continue;
                            support_const[ca.atom_id][cid].set((size_t)tok);
                        }
                    }
                }
            }
        }
    };

    auto compute_allowed_sigs = [&](const std::map<std::string, std::map<int, Bitset>> &support,
                                    const std::map<int, std::map<int, Bitset>> &support_const,
                                    std::vector<std::vector<uint8_t>> &allowed_sigs) {
        int cid = primary_cid;
        size_t D = domain_size[cid];
        allowed_sigs.assign(D, std::vector<uint8_t>(sig_space, 0));
        std::vector<int> vals(loaded.atom_by_id.size(), -1);
        for (size_t tok = 0; tok < D; tok++) {
            for (int aid : vars) {
                if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                    continue;
                if (std::find(target_const_ids.begin(), target_const_ids.end(), aid) != target_const_ids.end()) {
                    vals[aid] = -1;
                    continue;
                }
                const Atom *ap = loaded.atom_by_id[aid];
                if (!ap) continue;
                bool v = false;
                if (ap->kind == AtomKind::JOIN) {
                    int jcid = ap->join_class_id;
                    if (jcid == cid) {
                        v = support.at(ap->left.table).at(cid).test(tok) &&
                            support.at(ap->right.table).at(cid).test(tok);
                    } else {
                        v = true;
                    }
                } else {
                    auto itp = support_const.find(aid);
                    if (itp != support_const.end()) {
                        auto itc = itp->second.find(cid);
                        if (itc != itp->second.end())
                            v = itc->second.test(tok);
                    }
                }
                vals[aid] = v ? 1 : 0;
            }
            for (size_t sig = 0; sig < sig_space; sig++) {
                for (size_t i = 0; i < target_const_ids.size(); i++) {
                    int aid = target_const_ids[i];
                    int bit = (sig >> i) & 1u;
                    if (aid > 0 && aid < (int)vals.size())
                        vals[aid] = bit ? 1 : 0;
                }
                Tri ev = eval_ast(ast, vals);
                if (ev == TRI_TRUE)
                    allowed_sigs[tok][sig] = 1;
            }
        }
    };

    const int max_iter = 50;
    int iterations = 0;
    bool changed = true;
    auto t_prop_start = Clock::now();
    while (changed && iterations < max_iter) {
        iterations++;
        changed = false;
        std::map<std::string, std::map<int, Bitset>> support;
        std::map<int, std::map<int, Bitset>> support_const;
        compute_support(support, support_const);
        std::vector<std::vector<uint8_t>> allowed_sigs;
        compute_allowed_sigs(support, support_const, allowed_sigs);

        int cid = primary_cid;
        size_t D = domain_size[cid];
        Bitset new_allow;
        new_allow.nbits = D;
        new_allow.bytes.assign((D + 7) / 8, 0);
        for (size_t tok = 0; tok < D; tok++) {
            bool any = false;
            for (size_t sig = 0; sig < sig_space; sig++) {
                if (allowed_sigs[tok][sig]) { any = true; break; }
            }
            if (any) new_allow.set(tok);
        }
        if (!bitset_equals(allowed[cid], new_allow, D)) {
            changed = true;
            allowed[cid] = std::move(new_allow);
        }
        if (log_detail) {
            size_t pop = bitset_popcount(allowed[cid], D);
            CF_TRACE_LOG( "policy: token_eval join_class=%d domain=%zu allowed=%zu",
                 cid, D, pop);
            CF_TRACE_LOG( "policy: token_eval target=%s target_atoms=%zu sig_space=%zu",
                 target.c_str(), target_k, sig_space);
        }
    }
    auto t_prop_end = Clock::now();
    if (profile) {
        profile->prop_ms_total = Ms(t_prop_end - t_prop_start).count();
        profile->prop_iterations = iterations;
    }
    if (log_detail) {
        CF_TRACE_LOG( "policy: token_eval iterations=%d", iterations);
    }

    // final allowed signatures for decode
    std::map<std::string, std::map<int, Bitset>> support_final;
    std::map<int, std::map<int, Bitset>> support_const_final;
    compute_support(support_final, support_const_final);
    std::vector<std::vector<uint8_t>> allowed_sigs_final;
    compute_allowed_sigs(support_final, support_const_final, allowed_sigs_final);

    const TableInfo &ti = loaded.tables.find(target)->second;
    size_t bytes = (ti.n_rows + 7) / 8;
    uint8 *bits = (uint8 *)palloc0(bytes);
    uint32 passed = 0;
    const std::vector<uint8_t> *ok_rows = nullptr;
    auto it_ok = local_ok.find(target);
    if (it_ok != local_ok.end())
        ok_rows = &it_ok->second;
    auto t_decode_start = Clock::now();
    for (uint32 r = 0; r < ti.n_rows; r++) {
        if (ok_rows && !(*ok_rows)[r])
            continue;
        const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
        auto it_idx = table_class_idx[target].find(primary_cid);
        if (it_idx == table_class_idx[target].end())
            continue;
        int32 tok = row[it_idx->second];
        if (tok < 0 || !allowed[primary_cid].test((size_t)tok))
            continue;
        size_t sig = 0;
        for (size_t i = 0; i < target_k; i++) {
            int idx = target_const_token_idx[i];
            int32 tokc = row[idx];
            bool v = (tokc >= 0 &&
                      (size_t)tokc < target_const_allowed[i]->size() &&
                      (*target_const_allowed[i])[(size_t)tokc]);
            if (v) sig |= (size_t)1 << i;
        }
        if (tok < 0 || (size_t)tok >= allowed_sigs_final.size())
            continue;
        if (sig >= allowed_sigs_final[(size_t)tok].size() ||
            !allowed_sigs_final[(size_t)tok][sig])
            continue;
        bits[r >> 3] |= (uint8)(1u << (r & 7));
        passed++;
    }
    auto t_decode_end = Clock::now();

    out->count = 0;
    out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
    out->items[0].table = pstrdup(target.c_str());
    out->items[0].allow_bits = bits;
    out->items[0].n_rows = ti.n_rows;
    out->count = 1;
    if (log_detail)
        CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti.n_rows);
    if (profile) {
        DecodeStat ds;
        ds.table = target;
        ds.rows_total = ti.n_rows;
        ds.rows_allowed = passed;
        ds.ms_decode = Ms(t_decode_end - t_decode_start).count();
        profile->decode.push_back(ds);
        profile->decode_ms_total += ds.ms_decode;
    }
    return true;
}

static Bitset bitset_intersect(const Bitset &a, const Bitset &b, size_t nbits) {
    Bitset out;
    out.nbits = nbits;
    out.bytes.assign((nbits + 7) / 8, 0);
    size_t nbytes = out.bytes.size();
    for (size_t i = 0; i < nbytes; i++) {
        uint8 av = (i < a.bytes.size()) ? a.bytes[i] : 0;
        uint8 bv = (i < b.bytes.size()) ? b.bytes[i] : 0;
        out.bytes[i] = av & bv;
    }
    if (nbits % 8 && !out.bytes.empty()) {
        uint8 mask = (uint8)((1u << (nbits % 8)) - 1u);
        out.bytes.back() &= mask;
    }
    return out;
}

static bool multi_join_enforce_general(const Loaded &loaded,
                                       const std::string &target,
                                       const AstNode *ast,
                                       const std::set<int> &vars,
                                       PolicyAllowListC *out,
                                       BundleProfile *profile,
                                       bool log_detail,
                                       const std::map<std::string, const uint8*> *restrict_bits) {
    if (!out) return false;
    if (!ast) {
        ereport(ERROR, (errmsg("policy: missing AST for multi-join OR")));
    }

    // Build join graph (tables as nodes, join classes as edges)
    std::map<int, std::set<std::string>> class_tables;
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::JOIN)
            continue;
        int cid = ap->join_class_id;
        if (cid < 0)
            continue;
        class_tables[cid].insert(ap->left.table);
        class_tables[cid].insert(ap->right.table);
    }
    if (class_tables.empty()) {
        return multi_join_enforce_ast(loaded, target, ast, vars, out, profile, log_detail, nullptr,
                                      restrict_bits);
    }

    struct Edge { std::string a; std::string b; int cid; };
    std::vector<Edge> edges;
    std::set<std::string> nodes;
    for (const auto &kv : class_tables) {
        int cid = kv.first;
        if (kv.second.size() < 2) {
            std::string tables;
            for (const auto &t : kv.second) {
                if (!tables.empty()) tables += ", ";
                tables += t;
            }
            ereport(ERROR,
                    (errmsg("policy: multi-join class=%d has %zu tables [%s]; expected >= 2",
                            cid, kv.second.size(), tables.c_str())));
        }
        // Join classes represent equality constraints across N tables.
        // Any spanning tree across the tables is a sound representation.
        auto it = kv.second.begin();
        std::string center = *it++;
        nodes.insert(center);
        for (; it != kv.second.end(); ++it) {
            const std::string &other = *it;
            edges.push_back({center, other, cid});
            nodes.insert(other);
        }
    }
    if (nodes.count(target) == 0) {
        ereport(ERROR,
                (errmsg("policy: target %s not present in join graph", target.c_str())));
    }
    if (edges.size() != nodes.size() - 1) {
        // Exact cyclic join graph fallback WITHOUT DNF:
        // Chase a unique joined tuple per target row (same preconditions/limitations as the
        // cyclic path in multi_join_enforce_ast), then evaluate the boolean AST directly on the
        // resulting atom truth assignment. This avoids combinatorial blowups from DNF expansion
        // on OR-heavy policies while staying exact for our functional join-key workloads.

        // Precompute allowed token sets for const atoms.
        std::map<int, std::vector<uint8_t>> const_allowed;
        build_const_allowed_map(loaded, vars, &const_allowed);

        // Build a stable node index for per-row chase.
        struct AdjE {
            int to = -1;
            int cid = -1;
            int idx_self = -1;
            int idx_to = -1;
        };

        std::vector<std::string> node_list(nodes.begin(), nodes.end());
        std::unordered_map<std::string, int> node_id;
        node_id.reserve(node_list.size());
        for (size_t i = 0; i < node_list.size(); i++)
            node_id[node_list[i]] = (int)i;

        auto it_tid = node_id.find(target);
        if (it_tid == node_id.end())
            ereport(ERROR, (errmsg("policy: target %s not present in join graph", target.c_str())));
        int target_id = it_tid->second;
        const size_t N = node_list.size();

        std::vector<const TableInfo*> ti_by_id(N, nullptr);
        for (size_t i = 0; i < N; i++) {
            auto it_t = loaded.tables.find(node_list[i]);
            if (it_t == loaded.tables.end())
                ereport(ERROR, (errmsg("policy: missing table %s in loaded artifacts", node_list[i].c_str())));
            ti_by_id[i] = &it_t->second;
        }

        std::vector<const uint8*> restrict_by_id(N, nullptr);
        if (restrict_bits) {
            for (size_t i = 0; i < N; i++) {
                auto it_rb = restrict_bits->find(node_list[i]);
                if (it_rb != restrict_bits->end())
                    restrict_by_id[i] = it_rb->second;
            }
        }

        auto get_node_idx = [&](const std::string &tbl) -> int {
            auto it = node_id.find(tbl);
            if (it == node_id.end())
                ereport(ERROR,
                        (errmsg("policy: table %s not present in join graph", tbl.c_str())));
            return it->second;
        };

        // map table->class->token idx (only for classes used by edges)
        std::map<std::string, std::map<int, int>> table_class_idx;
        for (const auto &e : edges) {
            for (const auto &t : {e.a, e.b}) {
                if (table_class_idx[t].find(e.cid) != table_class_idx[t].end())
                    continue;
                int nid = get_node_idx(t);
                const TableInfo &ti = *ti_by_id[(size_t)nid];
                int idx = -1;
                for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                    if (ti.join_class_ids[j] == e.cid) {
                        idx = ti.join_token_idx[j];
                        break;
                    }
                }
                if (idx < 0) {
                    ereport(ERROR,
                            (errmsg("policy: missing join token index for table=%s class=%d",
                                    t.c_str(), e.cid)));
                }
                table_class_idx[t][e.cid] = idx;
            }
        }

        auto get_join_token_idx = [&](const std::string &tbl, int cid) -> int {
            auto it_t = table_class_idx.find(tbl);
            if (it_t == table_class_idx.end())
                ereport(ERROR,
                        (errmsg("policy: missing join token index map for table=%s", tbl.c_str())));
            auto it_idx = it_t->second.find(cid);
            if (it_idx == it_t->second.end())
                ereport(ERROR,
                        (errmsg("policy: missing join token index for table=%s class=%d",
                                tbl.c_str(), cid)));
            return it_idx->second;
        };

        // domain size per class (max token id + 1)
        std::map<int, size_t> domain_size;
        for (const auto &e : edges) {
            int cid = e.cid;
            int max_tok = -1;
            for (const auto &t : {e.a, e.b}) {
                int nid = get_node_idx(t);
                const TableInfo &ti = *ti_by_id[(size_t)nid];
                int idx = get_join_token_idx(t, cid);
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    if (!allow_bit(restrict_by_id[(size_t)nid], r))
                        continue;
                    const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                    int32 tok = row[idx];
                    if (tok > max_tok) max_tok = tok;
                }
            }
            size_t ds = (max_tok >= 0) ? (size_t)max_tok + 1 : 0;
            auto it_ds = domain_size.find(cid);
            if (it_ds == domain_size.end() || ds > it_ds->second)
                domain_size[cid] = ds;
        }

        // Build adjacency with token indices for quick per-row lookups.
        std::vector<std::vector<AdjE>> adj_id(N);
        for (const auto &e : edges) {
            int ia = get_node_idx(e.a);
            int ib = get_node_idx(e.b);
            int idx_a = get_join_token_idx(e.a, e.cid);
            int idx_b = get_join_token_idx(e.b, e.cid);
            adj_id[(size_t)ia].push_back({ib, e.cid, idx_a, idx_b});
            adj_id[(size_t)ib].push_back({ia, e.cid, idx_b, idx_a});
        }

        // Build unique tok->row maps for non-target tables on incident join classes.
        std::vector<std::unordered_map<int, std::vector<int32_t>>> row_by_tok(N);
        for (size_t i = 0; i < N; i++) {
            if ((int)i == target_id) continue;
            const TableInfo &ti = *ti_by_id[i];
            for (const auto &ae : adj_id[i]) {
                int cid = ae.cid;
                if (row_by_tok[i].find(cid) != row_by_tok[i].end())
                    continue;
                auto it_ds = domain_size.find(cid);
                size_t D = (it_ds != domain_size.end()) ? it_ds->second : 0;
                if (D == 0)
                    continue;
                std::vector<int32_t> map(D, -1);
                bool unique = true;
                int idx = get_join_token_idx(node_list[i], cid);
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    if (!allow_bit(restrict_by_id[i], r))
                        continue;
                    const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                    int32 tok = row[idx];
                    if (tok < 0 || (size_t)tok >= D)
                        continue;
                    if (map[(size_t)tok] == -1) {
                        map[(size_t)tok] = (int32_t)r;
                    } else {
                        unique = false;
                        break;
                    }
                }
                if (unique) {
                    row_by_tok[i][cid] = std::move(map);
                }
            }
        }

        // Precompute const atom evaluation info.
        struct ConstInfo {
            int aid = -1;
            int node = -1;
            int token_idx = -1;
            const std::vector<uint8_t> *allowed = nullptr;
        };
        std::vector<ConstInfo> consts;
        int max_id = 0;
        for (int aid : vars) {
            if (aid > max_id) max_id = aid;
            if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                continue;
            const Atom *ap = loaded.atom_by_id[aid];
            if (!ap || ap->kind != AtomKind::CONST)
                continue;
            auto it_n = node_id.find(ap->left.table);
            if (it_n == node_id.end())
                ereport(ERROR,
                        (errmsg("policy: const atom table %s not present in join graph",
                                ap->left.table.c_str())));
            int nid = it_n->second;
            const TableInfo &ti = *ti_by_id[(size_t)nid];
            auto it_off = ti.schema_offset.find(ap->lhs_schema_key);
            if (it_off == ti.schema_offset.end())
                ereport(ERROR,
                        (errmsg("policy: missing column offset for %s",
                                ap->lhs_schema_key.c_str())));
            auto it_allow = const_allowed.find(aid);
            if (it_allow == const_allowed.end())
                ereport(ERROR,
                        (errmsg("policy: missing dict for const atom y%d col=%s",
                                aid, ap->left.key().c_str())));
            ConstInfo ci;
            ci.aid = aid;
            ci.node = nid;
            ci.token_idx = it_off->second;
            ci.allowed = &it_allow->second;
            consts.push_back(ci);
        }
        if (max_id < 1)
            ereport(ERROR, (errmsg("policy: empty AST vars for multi-join")));

        std::string base_sig = base_sig_for_bits((size_t)max_id);
        std::unordered_map<std::string, uint8_t> decision_cache;
        decision_cache.reserve(4096);

        auto sig_bit = [&](const std::string &s, int aid) -> bool {
            if (aid <= 0) return true;
            size_t bit = (size_t)(aid - 1);
            size_t byte = bit >> 3;
            if (byte >= s.size()) return true;
            return (s[byte] & (char)(1u << (bit & 7))) != 0;
        };
        std::function<bool(const AstNode*, const std::string&)> eval_sig =
            [&](const AstNode *node, const std::string &s) -> bool {
                if (!node) return true;
                if (node->type == AstNode::VAR)
                    return sig_bit(s, node->var_id);
                if (node->type == AstNode::AND) {
                    if (!eval_sig(node->left, s)) return false;
                    return eval_sig(node->right, s);
                }
                if (node->type == AstNode::OR) {
                    if (eval_sig(node->left, s)) return true;
                    return eval_sig(node->right, s);
                }
                return true;
            };

        const TableInfo &ti_t = *ti_by_id[(size_t)target_id];
        size_t bytes = (ti_t.n_rows + 7) / 8;
        uint8 *final_bits = (uint8 *)palloc0(bytes);
        uint32 passed = 0;

        std::vector<int32_t> assigned(N, -1);
        std::vector<int> q;
        q.reserve(N);

        const uint8 *target_restrict = restrict_by_id[(size_t)target_id];

        for (uint32 r = 0; r < ti_t.n_rows; r++) {
            if (!allow_bit(target_restrict, r))
                continue;

            std::fill(assigned.begin(), assigned.end(), -1);
            q.clear();
            assigned[(size_t)target_id] = (int32_t)r;
            q.push_back(target_id);

            bool ok = true;
            for (size_t qi = 0; qi < q.size() && ok; qi++) {
                int cur = q[qi];
                const TableInfo &ti_cur = *ti_by_id[(size_t)cur];
                int32 rid_cur = assigned[(size_t)cur];
                const int32_t *row_cur = ti_cur.code + (size_t)rid_cur * (size_t)ti_cur.stride;
                for (const auto &ae : adj_id[(size_t)cur]) {
                    int to = ae.to;
                    int32 tok = row_cur[ae.idx_self];
                    if (tok < 0) { ok = false; break; }

                    int32 rid_to = assigned[(size_t)to];
                    if (rid_to >= 0) {
                        const TableInfo &ti_to = *ti_by_id[(size_t)to];
                        const int32_t *row_to = ti_to.code + (size_t)rid_to * (size_t)ti_to.stride;
                        int32 tok2 = row_to[ae.idx_to];
                        if (tok2 != tok) { ok = false; break; }
                        continue;
                    }

                    auto it_m = row_by_tok[(size_t)to].find(ae.cid);
                    if (it_m == row_by_tok[(size_t)to].end())
                        continue;  // Defer; may be assigned via another edge.
                    const auto &map = it_m->second;
                    if ((size_t)tok >= map.size()) { ok = false; break; }
                    rid_to = map[(size_t)tok];
                    if (rid_to < 0) { ok = false; break; }
                    assigned[(size_t)to] = rid_to;
                    q.push_back(to);
                }
            }
            if (!ok)
                continue;

            // Require all tables to be assigned (join atoms are conjunctive).
            for (size_t i = 0; i < N; i++) {
                if (assigned[i] < 0) { ok = false; break; }
            }
            if (!ok)
                continue;

            // Final edge check (covers deferred edges).
            for (const auto &e : edges) {
                int ia = get_node_idx(e.a);
                int ib = get_node_idx(e.b);
                const TableInfo &ta = *ti_by_id[(size_t)ia];
                const TableInfo &tb = *ti_by_id[(size_t)ib];
                int idx_a = get_join_token_idx(e.a, e.cid);
                int idx_b = get_join_token_idx(e.b, e.cid);
                const int32_t *ra = ta.code + (size_t)assigned[(size_t)ia] * (size_t)ta.stride;
                const int32_t *rb = tb.code + (size_t)assigned[(size_t)ib] * (size_t)tb.stride;
                int32 toka = ra[idx_a];
                int32 tokb = rb[idx_b];
                if (toka < 0 || tokb < 0 || toka != tokb) { ok = false; break; }
            }
            if (!ok)
                continue;

            std::string sig = base_sig;
            for (const auto &ci : consts) {
                int32 rid = assigned[(size_t)ci.node];
                if (rid < 0) { ok = false; break; }
                const TableInfo &ti = *ti_by_id[(size_t)ci.node];
                if (!allow_bit(restrict_by_id[(size_t)ci.node], (uint32)rid)) {
                    ok = false;
                    break;
                }
                const int32_t *row = ti.code + (size_t)rid * (size_t)ti.stride;
                int32 tokc = row[ci.token_idx];
                bool v = (tokc >= 0 &&
                          (size_t)tokc < ci.allowed->size() &&
                          (*ci.allowed)[(size_t)tokc]);
                set_sig_bit_idx(sig, (size_t)(ci.aid - 1), v);
            }
            if (!ok)
                continue;

            uint8 allow = 0;
            auto it = decision_cache.find(sig);
            if (it != decision_cache.end()) {
                allow = it->second;
            } else {
                allow = eval_sig(ast, sig) ? 1 : 0;
                decision_cache.emplace(std::move(sig), allow);
            }

            if (allow) {
                final_bits[r >> 3] |= (uint8)(1u << (r & 7));
                passed++;
            }
        }

        out->count = 0;
        out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
        out->items[0].table = pstrdup(target.c_str());
        out->items[0].allow_bits = final_bits;
        out->items[0].n_rows = ti_t.n_rows;
        out->count = 1;
        if (log_detail)
            CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti_t.n_rows);
        if (profile) {
            DecodeStat ds;
            ds.table = target;
            ds.rows_total = ti_t.n_rows;
            ds.rows_allowed = passed;
            ds.ms_decode = 0.0;
            profile->decode.push_back(ds);
            profile->decode_ms_total += ds.ms_decode;
        }
        return true;
    }

    std::map<std::string, std::vector<std::string>> adj;
    std::map<std::string, std::map<std::string, int>> edge_class;
    for (const auto &e : edges) {
        adj[e.a].push_back(e.b);
        adj[e.b].push_back(e.a);
        edge_class[e.a][e.b] = e.cid;
        edge_class[e.b][e.a] = e.cid;
    }

    std::map<std::string, std::string> parent;
    std::map<std::string, int> parent_cid;
    std::vector<std::string> order;
    std::function<void(const std::string&, const std::string&)> dfs =
        [&](const std::string &t, const std::string &p) {
            order.push_back(t);
            for (const auto &n : adj[t]) {
                if (n == p) continue;
                parent[n] = t;
                parent_cid[n] = edge_class[t][n];
                dfs(n, t);
            }
        };
    parent[target] = "";
    dfs(target, "");

    // map table->class->token idx
    std::map<std::string, std::map<int, int>> table_class_idx;
    for (const auto &t : nodes) {
        auto it_t = loaded.tables.find(t);
        if (it_t == loaded.tables.end())
            ereport(ERROR, (errmsg("policy: missing table %s in loaded artifacts", t.c_str())));
        const TableInfo &ti = it_t->second;
        for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
            table_class_idx[t][ti.join_class_ids[j]] = ti.join_token_idx[j];
        }
    }

    // presence bitsets per table/class (exists row with token)
    std::map<std::string, std::map<int, Bitset>> presence;
    for (const auto &t : nodes) {
        const TableInfo &ti = loaded.tables.find(t)->second;
        for (int cid : ti.join_class_ids) {
            presence[t][cid] = Bitset{};
        }
        for (uint32 r = 0; r < ti.n_rows; r++) {
            if (restrict_bits) {
                auto it_rb = restrict_bits->find(t);
                if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                    continue;
            }
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            for (int cid : ti.join_class_ids) {
                int idx = table_class_idx[t][cid];
                int32 tok = row[idx];
                if (tok >= 0)
                    presence[t][cid].set((size_t)tok);
            }
        }
    }

    // domain size per class
    std::map<int, size_t> domain_size;
    for (const auto &kv : class_tables) {
        int cid = kv.first;
        size_t max_bits = 0;
        for (const auto &t : kv.second) {
            max_bits = std::max(max_bits, presence[t][cid].nbits);
        }
        domain_size[cid] = max_bits;
    }

    // Extract table-local subformulas (non-target)
    int next_id = (int)loaded.atom_by_id.size();
    std::vector<DerivedVar> derived;
    AstNode *global_ast = extract_local_subtrees(loaded, ast, target, derived, next_id);
    if (log_detail) {
        for (const auto &dv : derived) {
            CF_TRACE_LOG( "policy: extract_local table=%s z=%d atoms=%zu",
                 dv.table.c_str(), dv.id, dv.vars.size());
        }
        CF_TRACE_LOG( "policy: global_ast=%s", ast_to_string_simple(global_ast).c_str());
    }

    // const allowed tokens for all const atoms
    std::map<int, std::vector<uint8_t>> const_allowed;
    build_const_allowed_map(loaded, vars, &const_allowed);

    // token-level variable bitsets
    std::map<int, Bitset> var_bits;
    std::map<int, int> var_class;

    auto propagate_to_target = [&](const std::string &start_table, int start_cid,
                                   const Bitset &start_bits) -> std::pair<int, Bitset> {
        std::string cur_table = start_table;
        int cur_cid = start_cid;
        Bitset cur_bits = start_bits;
        while (cur_table != target) {
            auto itp = parent.find(cur_table);
            if (itp == parent.end() || itp->second.empty()) {
                ereport(ERROR,
                        (errmsg("policy: cannot propagate token truth from table %s to target %s",
                                cur_table.c_str(), target.c_str())));
            }
            std::string p = itp->second;
            if (p == target) {
                break;
            }
            int next_cid = parent_cid[p];
            const TableInfo &tp = loaded.tables.find(p)->second;
            auto it_in = table_class_idx[p].find(cur_cid);
            auto it_out = table_class_idx[p].find(next_cid);
            if (it_in == table_class_idx[p].end() || it_out == table_class_idx[p].end())
                ereport(ERROR,
                        (errmsg("policy: missing join token index for table=%s class=%d",
                                p.c_str(), cur_cid)));
            Bitset next_bits;
            size_t D = domain_size[next_cid];
            next_bits.nbits = D;
            next_bits.bytes.assign((D + 7) / 8, 0);
            for (uint32 r = 0; r < tp.n_rows; r++) {
                if (restrict_bits) {
                    auto it_rb = restrict_bits->find(p);
                    if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                        continue;
                }
                const int32_t *row = tp.code + (size_t)r * (size_t)tp.stride;
                int32 tok_in = row[it_in->second];
                if (tok_in < 0 || !cur_bits.test((size_t)tok_in))
                    continue;
                int32 tok_out = row[it_out->second];
                if (tok_out >= 0)
                    next_bits.set((size_t)tok_out);
            }
            cur_bits = std::move(next_bits);
            cur_cid = next_cid;
            cur_table = p;
        }
        return {cur_cid, cur_bits};
    };

    // derived vars
    for (const auto &dv : derived) {
        auto it_t = loaded.tables.find(dv.table);
        if (it_t == loaded.tables.end())
            ereport(ERROR, (errmsg("policy: missing table %s", dv.table.c_str())));
        if (parent_cid.find(dv.table) == parent_cid.end())
            ereport(ERROR,
                    (errmsg("policy: derived var table %s not connected to target %s",
                            dv.table.c_str(), target.c_str())));
        int anchor_cid = parent_cid[dv.table];
        const TableInfo &ti = it_t->second;
        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, dv.table, dv.ast, dv.vars,
                                   const_allowed, &ok_rows, &cnt, &lst,
                                   profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", dv.table.c_str())));
        }
        size_t allowed_sigs = 0;
        if (!ok_rows.empty()) {
            auto it_cache = g_local_cache.tables.find(dv.table);
            if (it_cache != g_local_cache.tables.end()) {
                const TableCache &tc = it_cache->second;
                std::vector<uint8_t> bin_allowed(tc.global.hist.size(), 0);
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    if (restrict_bits) {
                        auto it_rb = restrict_bits->find(dv.table);
                        if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                            continue;
                    }
                    if (!ok_rows[r]) continue;
                    int b = (r < tc.global.row_to_bin.size()) ? tc.global.row_to_bin[r] : -1;
                    if (b >= 0 && (size_t)b < bin_allowed.size())
                        bin_allowed[(size_t)b] = 1;
                }
                for (uint8 v : bin_allowed) {
                    if (v) allowed_sigs++;
                }
            }
        }
        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
        Bitset bits;
        size_t D = domain_size[anchor_cid];
        bits.nbits = D;
        bits.bytes.assign((D + 7) / 8, 0);
        int idx = table_class_idx[dv.table][anchor_cid];
        for (uint32 r = 0; r < ti.n_rows; r++) {
            if (restrict_bits) {
                auto it_rb = restrict_bits->find(dv.table);
                if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                    continue;
            }
            if (!ok_rows.empty() && !ok_rows[r])
                continue;
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            int32 tok = row[idx];
            if (tok >= 0)
                bits.set((size_t)tok);
        }
        auto propagated = propagate_to_target(dv.table, anchor_cid, bits);
        var_bits[dv.id] = std::move(propagated.second);
        var_class[dv.id] = propagated.first;
        if (log_detail) {
            CF_TRACE_LOG( "policy: z_eval table=%s z=%d bins=%zu sat_calls=%d allowed_sigs=%zu",
                 dv.table.c_str(), dv.id, lst.bins, lst.sat_calls, allowed_sigs);
            size_t pop = bitset_popcount(var_bits[dv.id], domain_size[var_class[dv.id]]);
            CF_TRACE_LOG( "policy: z_token_truth z=%d domain=%zu true=%zu",
                 dv.id, domain_size[var_class[dv.id]], pop);
        }
    }

    // join atom vars
    for (int aid : vars) {
        if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap || ap->kind != AtomKind::JOIN)
            continue;
        int cid = ap->join_class_id;
        size_t D = domain_size[cid];
        Bitset base = bitset_intersect(presence[ap->left.table][cid],
                                       presence[ap->right.table][cid], D);
        int target_cid = cid;
        if (table_class_idx[target].find(cid) == table_class_idx[target].end()) {
            std::string child;
            if (parent[ap->left.table] == ap->right.table)
                child = ap->left.table;
            else if (parent[ap->right.table] == ap->left.table)
                child = ap->right.table;
            else
                child = ap->left.table;
            auto propagated = propagate_to_target(child, cid, base);
            base = std::move(propagated.second);
            target_cid = propagated.first;
        }
        var_bits[aid] = std::move(base);
        var_class[aid] = target_cid;
    }

    // const atoms on non-target (if any left in AST)
    std::set<int> global_vars;
    collect_ast_vars(global_ast, global_vars);
    for (int vid : global_vars) {
        if (vid <= 0 || vid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[vid];
        if (!ap || ap->kind != AtomKind::CONST)
            continue;
        if (ap->left.table == target)
            continue;
        if (var_bits.find(vid) != var_bits.end())
            continue;
        if (parent_cid.find(ap->left.table) == parent_cid.end())
            ereport(ERROR,
                    (errmsg("policy: const atom table %s not connected to target", ap->left.table.c_str())));
        int anchor_cid = parent_cid[ap->left.table];
        const TableInfo &ti = loaded.tables.find(ap->left.table)->second;
        auto it_allowed = const_allowed.find(vid);
        if (it_allowed == const_allowed.end())
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            vid, ap->left.key().c_str())));
        Bitset bits;
        size_t D = domain_size[anchor_cid];
        bits.nbits = D;
        bits.bytes.assign((D + 7) / 8, 0);
        int idx = table_class_idx[ap->left.table][anchor_cid];
        int token_idx = ti.schema_offset.at(ap->lhs_schema_key);
        for (uint32 r = 0; r < ti.n_rows; r++) {
            if (restrict_bits) {
                auto it_rb = restrict_bits->find(ap->left.table);
                if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                    continue;
            }
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            int32 tokc = row[token_idx];
            bool ok = (tokc >= 0 && (size_t)tokc < it_allowed->second.size() &&
                       it_allowed->second[(size_t)tokc]);
            if (!ok) continue;
            int32 tok = row[idx];
            if (tok >= 0) bits.set((size_t)tok);
        }
        auto propagated = propagate_to_target(ap->left.table, anchor_cid, bits);
        var_bits[vid] = std::move(propagated.second);
        var_class[vid] = propagated.first;
    }

    // target const atoms
    std::vector<int> target_const_ids;
    for (int vid : global_vars) {
        if (vid <= 0 || vid >= (int)loaded.atom_by_id.size())
            continue;
        const Atom *ap = loaded.atom_by_id[vid];
        if (ap && ap->kind == AtomKind::CONST && ap->left.table == target)
            target_const_ids.push_back(vid);
    }
    std::sort(target_const_ids.begin(), target_const_ids.end());
    target_const_ids.erase(std::unique(target_const_ids.begin(), target_const_ids.end()),
                           target_const_ids.end());

    int max_id = 0;
    for (int vid : global_vars)
        max_id = std::max(max_id, vid);
    if (max_id < 1)
        ereport(ERROR, (errmsg("policy: empty AST after extraction")));

    // Precompute target token indices and allowed vectors for target const atoms
    std::vector<int> target_const_token_idx;
    std::vector<const std::vector<uint8_t>*> target_const_allowed;
    const TableInfo &ti_t = loaded.tables.find(target)->second;
    for (int aid : target_const_ids) {
        const Atom *ap = loaded.atom_by_id[aid];
        if (!ap) continue;
        auto it_off = ti_t.schema_offset.find(ap->lhs_schema_key);
        if (it_off == ti_t.schema_offset.end())
            ereport(ERROR,
                    (errmsg("policy: missing column offset for %s", ap->lhs_schema_key.c_str())));
        auto it_allow = const_allowed.find(aid);
        if (it_allow == const_allowed.end())
            ereport(ERROR,
                    (errmsg("policy: missing dict for const atom y%d col=%s",
                            aid, ap->left.key().c_str())));
        target_const_token_idx.push_back(it_off->second);
        target_const_allowed.push_back(&it_allow->second);
    }

    // Build+bin row signatures for target table (streaming; no per-row signature storage).
    std::string base_sig = base_sig_for_bits((size_t)max_id);
    const size_t nbytes = base_sig.size();
    std::vector<uint8_t> base_bytes(nbytes, 0);
    if (nbytes > 0) memcpy(base_bytes.data(), base_sig.data(), nbytes);

    std::vector<int> row_to_bin(ti_t.n_rows, 0);
    std::vector<uint8_t> bin_sig_flat;
    std::vector<uint32_t> hist;

    BinTable tab;
    tab.init(std::max<size_t>(1024, (size_t)ti_t.n_rows / 2));

    const uint32 CHUNK = 4096;
    std::vector<uint8_t> sig_chunk;
    sig_chunk.reserve((size_t)CHUNK * nbytes);

    for (uint32 start = 0; start < ti_t.n_rows; start += CHUNK) {
        uint32 end = start + CHUNK;
        if (end > ti_t.n_rows) end = ti_t.n_rows;
        uint32 n = end - start;
        sig_chunk.resize((size_t)n * nbytes);

        for (uint32 i = 0; i < n; i++) {
            uint32 r = start + i;
            uint8_t *sig = sig_chunk.data() + (size_t)i * nbytes;
            memcpy(sig, base_bytes.data(), nbytes);

            const int32_t *row = ti_t.code + (size_t)r * (size_t)ti_t.stride;
            // target const atoms
            for (size_t j = 0; j < target_const_ids.size(); j++) {
                int aid = target_const_ids[j];
                int idx = target_const_token_idx[j];
                int32 tok = row[idx];
                bool v = (tok >= 0 &&
                          (size_t)tok < target_const_allowed[j]->size() &&
                          (*target_const_allowed[j])[(size_t)tok]);
                set_sig_bit_bytes(sig, nbytes, (size_t)(aid - 1), v);
            }
            // token-level vars
            for (int vid : global_vars) {
                if (std::find(target_const_ids.begin(), target_const_ids.end(), vid) != target_const_ids.end())
                    continue;
                auto itv = var_bits.find(vid);
                auto itc = var_class.find(vid);
                if (itv == var_bits.end() || itc == var_class.end())
                    continue;
                int cid = itc->second;
                auto it_idx = table_class_idx[target].find(cid);
                if (it_idx == table_class_idx[target].end())
                    continue;
                int32 tok = row[it_idx->second];
                bool v = (tok >= 0 && itv->second.test((size_t)tok));
                set_sig_bit_bytes(sig, nbytes, (size_t)(vid - 1), v);
            }
        }

        for (uint32 i = 0; i < n; i++) {
            const uint8_t *sig = sig_chunk.data() + (size_t)i * nbytes;
            uint64_t h = hash_bytes_fnv1a64(sig, nbytes);
            int32_t bid = tab.find_or_insert(h, sig, nbytes, bin_sig_flat, hist);
            row_to_bin[start + i] = (int)bid;
            hist[(size_t)bid] += 1;
        }
    }

    std::vector<uint8_t> allow_bin;
    if (!eval_bins_sat_flat(global_ast, max_id, bin_sig_flat, nbytes, hist.size(),
                            &allow_bin, nullptr, nullptr))
        ereport(ERROR, (errmsg("policy: failed to eval AST bins")));

    // decode allowed rows
    size_t bytes = (ti_t.n_rows + 7) / 8;
    uint8 *bits = (uint8 *)palloc0(bytes);
    uint32 passed = 0;
    for (uint32 r = 0; r < ti_t.n_rows; r++) {
        if (restrict_bits) {
            auto it_rb = restrict_bits->find(target);
            if (it_rb != restrict_bits->end() && !allow_bit(it_rb->second, r))
                continue;
        }
        int b = row_to_bin[r];
        if (b >= 0 && b < (int)allow_bin.size() && allow_bin[(size_t)b]) {
            bits[r >> 3] |= (uint8)(1u << (r & 7));
            passed++;
        }
    }

    out->count = 0;
    out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
    out->items[0].table = pstrdup(target.c_str());
    out->items[0].allow_bits = bits;
    out->items[0].n_rows = ti_t.n_rows;
    out->count = 1;
    if (log_detail)
        CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti_t.n_rows);
    if (profile) {
        DecodeStat ds;
        ds.table = target;
        ds.rows_total = ti_t.n_rows;
        ds.rows_allowed = passed;
        ds.ms_decode = 0.0;
        profile->decode.push_back(ds);
        profile->decode_ms_total += ds.ms_decode;
    }
    return true;
}

static std::map<std::string, std::set<std::string>>
build_target_deps(const Loaded &loaded)
{
    std::map<std::string, std::set<std::string>> deps;
    for (const auto &t : loaded.target_set)
        deps[t];

    auto add_dep = [&](const std::string &target, const std::string &ref) {
        if (ref.empty() || ref == target)
            return;
        if (loaded.target_set.count(ref) == 0)
            return;
        deps[target].insert(ref);
    };

    for (const auto &t : loaded.target_set) {
        auto it_vars = loaded.target_vars.find(t);
        if (it_vars == loaded.target_vars.end())
            continue;
        for (int aid : it_vars->second) {
            if (aid <= 0 || aid >= (int)loaded.atom_by_id.size())
                continue;
            const Atom *ap = loaded.atom_by_id[aid];
            if (!ap)
                continue;
            if (ap->kind == AtomKind::CONST) {
                add_dep(t, ap->left.table);
            } else if (ap->kind == AtomKind::JOIN) {
                add_dep(t, ap->left.table);
                add_dep(t, ap->right.table);
            }
        }
    }
    return deps;
}

static std::vector<std::string>
target_topo_order(const Loaded &loaded)
{
    std::map<std::string, std::set<std::string>> deps = build_target_deps(loaded);
    std::map<std::string, int> state;
    std::vector<std::string> stack;
    std::vector<std::string> order;

    std::function<void(const std::string&)> dfs = [&](const std::string &t) {
        state[t] = 1;
        stack.push_back(t);
        auto it_dep = deps.find(t);
        if (it_dep != deps.end()) {
            for (const auto &u : it_dep->second) {
                int st = 0;
                auto it_state = state.find(u);
                if (it_state != state.end())
                    st = it_state->second;
                if (st == 0) {
                    dfs(u);
                } else if (st == 1) {
                    std::string cyc;
                    auto it_stack = std::find(stack.begin(), stack.end(), u);
                    if (it_stack == stack.end()) {
                        cyc = u;
                    } else {
                        for (auto it = it_stack; it != stack.end(); ++it) {
                            if (!cyc.empty()) cyc += " -> ";
                            cyc += *it;
                        }
                        if (!cyc.empty()) cyc += " -> ";
                        cyc += u;
                    }
                    ereport(ERROR,
                            (errmsg("policy: cyclic dependencies among targets: %s",
                                    cyc.c_str())));
                }
            }
        }
        stack.pop_back();
        state[t] = 2;
        order.push_back(t);
    };

    for (const auto &kv : deps) {
        if (state[kv.first] == 0)
            dfs(kv.first);
    }
    return order;
}

static bool
multi_join_enforce_one_target(const Loaded &loaded,
                              const std::string &target,
                              const std::map<std::string, const uint8*> *restrict_bits,
                              PolicyAllowListC *out,
                              BundleProfile *profile,
                              bool log_detail)
{
    if (!out) return false;
    auto it_ast = loaded.target_ast.find(target);
    if (it_ast == loaded.target_ast.end() || !it_ast->second) {
        ereport(ERROR, (errmsg("policy: missing AST for target %s", target.c_str())));
    }
    auto it_vars = loaded.target_vars.find(target);
    if (it_vars == loaded.target_vars.end()) {
        ereport(ERROR, (errmsg("policy: missing vars for target %s", target.c_str())));
    }

    std::string ast_reason;
    if (ast_supported_multi_join(loaded, it_ast->second, &ast_reason)) {
        return multi_join_enforce_ast(loaded, target, it_ast->second, it_vars->second,
                                      out, profile, log_detail, nullptr, restrict_bits);
    }

    if (!contract_mode_enabled()) {
        return multi_join_enforce_general(loaded, target, it_ast->second, it_vars->second,
                                          out, profile, log_detail, restrict_bits);
    }

    // Contract-only fallback: DNF expansion to handle OR across tables.
    std::vector<std::vector<int>> terms;
    bool overflow = false;
    const size_t max_terms = 256;
    dnf_expand_terms(it_ast->second, terms, max_terms, overflow);
    if (overflow || terms.empty()) {
        ereport(ERROR,
                (errmsg("policy: multi-join boolean structure unsupported for target %s (%s)",
                        target.c_str(),
                        overflow ? "DNF expansion overflow" : ast_reason.c_str())));
    }

    const TableInfo &ti = loaded.tables.find(target)->second;
    size_t bytes = (ti.n_rows + 7) / 8;
    uint8 *final_bits = (uint8 *)palloc0(bytes);
    std::map<int, Bitset> union_allowed;

    for (const auto &term : terms) {
        AstNode *term_ast = build_and_ast(term);
        std::set<int> term_vars;
        term_vars.insert(term.begin(), term.end());
        PolicyAllowListC term_out{};
        std::map<int, Bitset> term_allowed;
        if (!multi_join_enforce_ast(loaded, target, term_ast, term_vars,
                                    &term_out, profile, false, &term_allowed, restrict_bits)) {
            return false;
        }
        if (term_out.count == 1 && term_out.items && term_out.items[0].allow_bits) {
            uint8 *bits = term_out.items[0].allow_bits;
            for (size_t i = 0; i < bytes; i++) {
                final_bits[i] |= bits[i];
            }
        }
        for (auto &kv : term_allowed) {
            auto &dst = union_allowed[kv.first];
            if (dst.nbits == 0) {
                dst.nbits = kv.second.nbits;
                dst.bytes.assign((dst.nbits + 7) / 8, 0);
            }
            size_t nbytes = std::min(dst.bytes.size(), kv.second.bytes.size());
            for (size_t i = 0; i < nbytes; i++) {
                dst.bytes[i] |= kv.second.bytes[i];
            }
        }
    }

    const uint8 *target_restrict = nullptr;
    if (restrict_bits) {
        auto it_rb = restrict_bits->find(target);
        if (it_rb != restrict_bits->end())
            target_restrict = it_rb->second;
    }

    uint32 passed = 0;
    for (uint32 r = 0; r < ti.n_rows; r++) {
        if (!allow_bit(target_restrict, r)) {
            final_bits[r >> 3] &= (uint8) ~(1u << (r & 7));
            continue;
        }
        if (final_bits[r >> 3] & (uint8)(1u << (r & 7)))
            passed++;
    }
    out->count = 0;
    out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC));
    out->items[0].table = pstrdup(target.c_str());
    out->items[0].allow_bits = final_bits;
    out->items[0].n_rows = ti.n_rows;
    out->count = 1;

    if (log_detail) {
        CF_TRACE_LOG( "policy: multi_join or_terms=%zu", terms.size());
        for (const auto &kv : union_allowed) {
            size_t D = kv.second.nbits;
            size_t pop = bitset_popcount(kv.second, D);
            CF_TRACE_LOG( "policy: multi_join class=%d allowed=%zu / %zu",
                 kv.first, pop, D);
        }
        CF_TRACE_LOG( "policy: allow_%s count = %u / %u", target.c_str(), passed, ti.n_rows);
    }
    return true;
}

static bool
multi_join_enforce_multi_target(const Loaded &loaded,
                                PolicyAllowListC *out,
                                BundleProfile *profile)
{
    if (!out) return false;

    std::vector<std::string> order = target_topo_order(loaded);
    out->count = 0;
    out->items = order.empty()
                     ? nullptr
                     : (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * order.size());

    std::map<std::string, const uint8*> restrict_bits;
    for (const auto &target : order) {
        PolicyAllowListC tmp{};
        if (!multi_join_enforce_one_target(loaded, target, &restrict_bits, &tmp, profile, true))
            return false;
        if (tmp.count != 1 || !tmp.items || !tmp.items[0].table || !tmp.items[0].allow_bits) {
            ereport(ERROR,
                    (errmsg("policy: invalid multi-target allow list for target %s", target.c_str())));
        }

        const TableInfo &ti = loaded.tables.find(target)->second;
        if (tmp.items[0].n_rows != ti.n_rows) {
            ereport(ERROR,
                    (errmsg("policy: allow row mismatch for target %s allow_rows=%u expected=%u",
                            target.c_str(), tmp.items[0].n_rows, ti.n_rows)));
        }

        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *) palloc0(bytes);
        memcpy(bits, tmp.items[0].allow_bits, bytes);

        out->items[out->count].table = pstrdup(target.c_str());
        out->items[out->count].allow_bits = bits;
        out->items[out->count].n_rows = ti.n_rows;
        out->count++;

        restrict_bits[target] = bits;
    }

    return true;
}

static bool multi_join_enforce(const Loaded &loaded, PolicyAllowListC *out, BundleProfile *profile)
{
    if (!out) return false;
    if (loaded.target_set.empty()) {
        out->count = 0;
        out->items = nullptr;
        return true;
    }
    if (loaded.target_set.size() == 1) {
        const std::string target = *loaded.target_set.begin();
        return multi_join_enforce_one_target(loaded, target, nullptr, out, profile, true);
    }
    return multi_join_enforce_multi_target(loaded, out, profile);
}

static bool const_only_enforce(const Loaded &loaded, PolicyAllowListC *out, BundleProfile *profile)
{
    if (!out) return false;
    out->count = 0;
    if (loaded.target_set.empty())
        return true;
    out->items = (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * loaded.target_set.size());
    for (const auto &t : loaded.target_set) {
        auto it_t = loaded.tables.find(t);
        if (it_t == loaded.tables.end())
            ereport(ERROR, (errmsg("policy: missing table %s", t.c_str())));
        const TableInfo &ti = it_t->second;
        auto it_ast = loaded.target_ast.find(t);
        if (it_ast == loaded.target_ast.end() || !it_ast->second)
            ereport(ERROR, (errmsg("policy: missing AST for target %s", t.c_str())));
        auto it_vars = loaded.target_vars.find(t);
        if (it_vars == loaded.target_vars.end())
            ereport(ERROR, (errmsg("policy: missing vars for target %s", t.c_str())));

        std::map<int, std::vector<uint8_t>> const_allowed;
        build_const_allowed_map(loaded, it_vars->second, &const_allowed);

        std::vector<uint8_t> ok_rows;
        uint32 cnt = 0;
        LocalStat lst;
        if (!compute_local_ok_bins(loaded, t, it_ast->second, it_vars->second,
                                   const_allowed, &ok_rows, &cnt, &lst,
                                   profile ? profile->bundle_id : 0)) {
            ereport(ERROR,
                    (errmsg("policy: failed to compute local_ok bins for table %s", t.c_str())));
        }

        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *)palloc0(bytes);
        if (ok_rows.empty()) {
            memset(bits, 0xFF, bytes);
            cnt = ti.n_rows;
        } else {
            for (uint32 r = 0; r < ti.n_rows; r++) {
                if (ok_rows[r])
                    bits[r >> 3] |= (uint8)(1u << (r & 7));
            }
        }

        out->items[out->count].table = pstrdup(t.c_str());
        out->items[out->count].allow_bits = bits;
        out->items[out->count].n_rows = ti.n_rows;
        out->count++;

        CF_TRACE_LOG( "policy: allow_%s count = %u / %u",
             t.c_str(), cnt, ti.n_rows);

        if (profile && lst.atoms > 0) {
            profile->local.push_back(lst);
            profile->local_ms_total += lst.ms_stamp + lst.ms_bin + lst.ms_eval + lst.ms_fill;
        }
    }
    return true;
}

static bool token_domain_run(const Loaded &loaded, PolicyAllowListC *out)
{
    if (!out) return false;
    auto find_join_idx = [](const TableInfo &ti, int class_id) -> int {
        for (size_t i = 0; i < ti.join_class_ids.size(); i++) {
            if (ti.join_class_ids[i] == class_id)
                return ti.join_token_idx[i];
        }
        return -1;
    };
    auto max_token_for_class = [&](const TableInfo &ti, int class_id) -> int {
        int idx = find_join_idx(ti, class_id);
        if (idx < 0 || ti.n_rows == 0) return -1;
        int max_tok = -1;
        for (uint32 r = 0; r < ti.n_rows; r++) {
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            int32 tok = row[idx];
            if (tok > max_tok) max_tok = tok;
        }
        return max_tok;
    };

    const bool trace_dbg = debug_trace_enabled();
    std::set<int> logged_classes;
    std::map<int, std::vector<const Atom*>> class_atoms;
    for (const auto &a : loaded.atoms) {
        if (a.kind == AtomKind::JOIN && a.join_class_id >= 0) {
            class_atoms[a.join_class_id].push_back(&a);
        } else if (a.kind == AtomKind::CONST) {
            if (a.join_class_id >= 0) {
                class_atoms[a.join_class_id].push_back(&a);
            } else {
                auto it = loaded.tables.find(a.left.table);
                if (it != loaded.tables.end()) {
                    for (int cid : it->second.join_class_ids)
                        class_atoms[cid].push_back(&a);
                }
            }
        }
    }

    std::map<int, std::map<std::string, Bitset>> present;
    std::map<int, std::map<int, Bitset>> pred;
    std::map<int, int> domain_max;
    std::map<int, std::vector<uint8_t>> const_allowed;

    for (const auto &a : loaded.atoms) {
        if (a.kind != AtomKind::CONST) continue;
        auto it = loaded.dicts.find(a.left.key());
        if (it == loaded.dicts.end())
            return false;
        DictType dtype = dict_type_for_key(loaded, a.left.key());
        const_allowed[a.id] = build_allowed_tokens(it->second, a, dtype);
    }

    for (const auto &kv : loaded.tables) {
        const TableInfo &ti = kv.second;
        if (ti.n_rows == 0 || ti.stride <= 1) continue;
        for (uint32 r = 0; r < ti.n_rows; r++) {
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                int cid = ti.join_class_ids[j];
                int idx = ti.join_token_idx[j];
                int32 tok = row[idx];
                if (tok >= 0) {
                    present[cid][ti.name].set((size_t)tok);
                    if (tok > domain_max[cid]) domain_max[cid] = tok;
                }
            }
        }
    }

    for (const auto &a : loaded.atoms) {
        if (a.kind != AtomKind::CONST) continue;
        auto it_table = loaded.tables.find(a.left.table);
        if (it_table == loaded.tables.end()) continue;
        const TableInfo &ti = it_table->second;
        auto itoff = ti.schema_offset.find("const:" + a.left.key());
        if (itoff == ti.schema_offset.end()) continue;
        int off_const = itoff->second;
        auto it_allowed = const_allowed.find(a.id);
        if (it_allowed == const_allowed.end()) continue;
        const auto &allowed = it_allowed->second;

        if (a.join_class_id >= 0) {
            int cid = a.join_class_id;
            for (uint32 r = 0; r < ti.n_rows; r++) {
                const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                int32 tok = row[off_const];
                if (tok >= 0 && (size_t)tok < allowed.size() && allowed[(size_t)tok]) {
                    pred[cid][a.id].set((size_t)tok);
                    if (tok > domain_max[cid]) domain_max[cid] = tok;
                }
            }
        } else {
            for (size_t j = 0; j < ti.join_class_ids.size(); j++) {
                int cid = ti.join_class_ids[j];
                int off_join = ti.join_token_idx[j];
                for (uint32 r = 0; r < ti.n_rows; r++) {
                    const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
                    int32 tok = row[off_const];
                    if (tok >= 0 && (size_t)tok < allowed.size() && allowed[(size_t)tok]) {
                        int32 jtok = row[off_join];
                        if (jtok >= 0) {
                            pred[cid][a.id].set((size_t)jtok);
                            if (jtok > domain_max[cid]) domain_max[cid] = jtok;
                        }
                    }
                }
            }
        }
    }

    if (debug_contract_enabled()) {
        for (const auto &ckv : class_atoms) {
            int cid = ckv.first;
            int D = domain_max[cid] + 1;
            if (D <= 0) continue;
            CF_TRACE_LOG( "policy_contract: class=%d domain=%d", cid, D);
            for (const auto *ap : ckv.second) {
                if (!ap) continue;
                size_t pop = 0;
                if (ap->kind == AtomKind::JOIN) {
                    for (int tok = 0; tok < D; tok++) {
                        bool has_l = present[cid][ap->left.table].test((size_t)tok);
                        bool has_r = present[cid][ap->right.table].test((size_t)tok);
                        if (has_l && has_r) pop++;
                    }
                } else {
                    auto itp = pred[cid].find(ap->id);
                    if (itp != pred[cid].end())
                        pop = bitset_popcount(itp->second, (size_t)D);
                }
                CF_TRACE_LOG( "policy_contract: class=%d atom=y%d popcount=%zu / %d",
                     cid, ap->id, pop, D);
            }
        }
    }

    int target_count = 0;
    for (const auto &kv : loaded.tables) {
        if (loaded.target_set.count(kv.first) > 0)
            target_count++;
    }
    out->count = 0;
    out->items = target_count > 0
                     ? (PolicyTableAllowC *)palloc0(sizeof(PolicyTableAllowC) * target_count)
                     : nullptr;
    std::map<std::string, PolicyTableAllowC *> allow_map;

    for (const auto &kv : loaded.tables) {
        const TableInfo &ti = kv.second;
        if (ti.n_rows == 0) continue;
        if (loaded.target_set.count(ti.name) == 0)
            continue;
        const AstNode *ast = nullptr;
        auto it_ast = loaded.target_ast.find(ti.name);
        if (it_ast != loaded.target_ast.end())
            ast = it_ast->second;
        const std::set<int> *target_atom_ids = nullptr;
        auto it_vars = loaded.target_vars.find(ti.name);
        if (it_vars != loaded.target_vars.end())
            target_atom_ids = &it_vars->second;
        std::set<int> constrained_classes;
        if (target_atom_ids) {
            for (int aid : *target_atom_ids) {
                if (aid > 0 && aid < (int)loaded.atom_by_id.size()) {
                    const Atom *ap = loaded.atom_by_id[aid];
                    if (ap && ap->join_class_id >= 0)
                        constrained_classes.insert(ap->join_class_id);
                }
            }
        }

        std::map<int, std::vector<uint8_t>> allow_tok;
        uint32 rid_mismatch = 0;
        for (uint32 r = 0; r < ti.n_rows; r++) {
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            if (row[0] != (int32_t)r) {
                rid_mismatch++;
                if (rid_mismatch <= 3) {
                    CF_TRACE_LOG( "policy: rid mismatch table=%s row_idx=%u rid=%d",
                         ti.name.c_str(), r, row[0]);
                }
            }
        }
        if (rid_mismatch > 0) {
            CF_TRACE_LOG( "policy: rid_mismatch table=%s count=%u", ti.name.c_str(), rid_mismatch);
        }
        for (int cid : constrained_classes) {
            auto it_class = class_atoms.find(cid);
            if (it_class == class_atoms.end())
                continue;
            const auto &atoms = it_class->second;
            int D = domain_max[cid] + 1;
            if (D <= 0) continue;
            std::vector<int> atom_ids;
            atom_ids.reserve(atoms.size());
            if (target_atom_ids) {
                for (auto *ap : atoms) {
                    if (ap && target_atom_ids->count(ap->id))
                        atom_ids.push_back(ap->id);
                }
            } else {
                for (auto *ap : atoms) {
                    if (ap) atom_ids.push_back(ap->id);
                }
            }
            if (atom_ids.empty())
                continue;
            std::sort(atom_ids.begin(), atom_ids.end());
            int K = (int)atom_ids.size();
            std::unordered_map<uint64_t, int> bin_u64;
            std::unordered_map<std::string, int> bin_bytes;
            std::vector<uint64_t> class_sig_u64;
            std::vector<std::string> class_sig_bytes;
            std::vector<int> tok2class(D, -1);
            bool use_u64 = (K <= 64);
            for (int tok = 0; tok < D; tok++) {
                if (use_u64) {
                    uint64_t sig = 0;
                    for (int i = 0; i < K; i++) {
                        int aid = atom_ids[i];
                        bool val = false;
                        const Atom *ap = nullptr;
                        for (const auto &a : loaded.atoms) if (a.id == aid) { ap = &a; break; }
                        if (!ap) continue;
                        if (ap->kind == AtomKind::JOIN) {
                            bool has_l = present[cid][ap->left.table].test((size_t)tok);
                            bool has_r = present[cid][ap->right.table].test((size_t)tok);
                            val = has_l && has_r;
                        } else {
                            auto itp = pred[cid].find(aid);
                            if (itp != pred[cid].end())
                                val = itp->second.test((size_t)tok);
                        }
                        if (val) sig |= (1ULL << i);
                    }
                    auto it = bin_u64.find(sig);
                    int bid;
                    if (it == bin_u64.end()) {
                        bid = (int)class_sig_u64.size();
                        bin_u64[sig] = bid;
                        class_sig_u64.push_back(sig);
                    } else {
                        bid = it->second;
                    }
                    tok2class[tok] = bid;
                } else {
                    size_t nbytes = (K + 7) / 8;
                    std::string sig(nbytes, '\0');
                    for (int i = 0; i < K; i++) {
                        int aid = atom_ids[i];
                        bool val = false;
                        const Atom *ap = nullptr;
                        for (const auto &a : loaded.atoms) if (a.id == aid) { ap = &a; break; }
                        if (!ap) continue;
                        if (ap->kind == AtomKind::JOIN) {
                            bool has_l = present[cid][ap->left.table].test((size_t)tok);
                            bool has_r = present[cid][ap->right.table].test((size_t)tok);
                            val = has_l && has_r;
                        } else {
                            auto itp = pred[cid].find(aid);
                            if (itp != pred[cid].end())
                                val = itp->second.test((size_t)tok);
                        }
                        if (val)
                            sig[(size_t)i >> 3] |= (char)(1u << (i & 7));
                    }
                    auto it = bin_bytes.find(sig);
                    int bid;
                    if (it == bin_bytes.end()) {
                        bid = (int)class_sig_bytes.size();
                        bin_bytes[sig] = bid;
                        class_sig_bytes.push_back(sig);
                    } else {
                        bid = it->second;
                    }
                    tok2class[tok] = bid;
                }
            }

            std::vector<uint32_t> bin_counts(use_u64 ? class_sig_u64.size() : class_sig_bytes.size(), 0);
            for (int tok = 0; tok < D; tok++) {
                int bid = tok2class[(size_t)tok];
                if (bid >= 0 && bid < (int)bin_counts.size())
                    bin_counts[(size_t)bid]++;
            }

            std::vector<uint8_t> allow_bin(use_u64 ? class_sig_u64.size() : class_sig_bytes.size(), 0);
            int max_atom_id = 0;
            for (int aid : atom_ids) if (aid > max_atom_id) max_atom_id = aid;
            std::vector<int> vals((size_t)max_atom_id + 1, -1);
            for (size_t b = 0; b < allow_bin.size(); b++) {
                for (int aid : atom_ids) vals[aid] = -1;
                if (use_u64) {
                    uint64_t sig = class_sig_u64[b];
                    for (int i = 0; i < K; i++) {
                        int aid = atom_ids[i];
                        vals[aid] = (sig >> i) & 1ULL;
                    }
                } else {
                    const std::string &sig = class_sig_bytes[b];
                    for (int i = 0; i < K; i++) {
                        int aid = atom_ids[i];
                        bool bit = (sig[(size_t)i >> 3] >> (i & 7)) & 1;
                        vals[aid] = bit ? 1 : 0;
                    }
                }
                Tri ev = ast ? eval_ast(ast, vals) : TRI_TRUE;
                if (ev == TRI_TRUE) allow_bin[b] = 1;
            }
            std::vector<uint8_t> allow_tok_c((size_t)D, 0);
            for (int tok = 0; tok < D; tok++) {
                int bid = tok2class[(size_t)tok];
                if (bid >= 0 && allow_bin[(size_t)bid])
                    allow_tok_c[(size_t)tok] = 1;
            }
            allow_tok[cid] = std::move(allow_tok_c);

            if (trace_dbg && logged_classes.insert(cid).second) {
                auto sig_to_bits = [&](uint64_t sig) {
                    std::string bits;
                    bits.reserve((size_t)K);
                    for (int i = 0; i < K; i++) bits.push_back(((sig >> i) & 1ULL) ? '1' : '0');
                    return bits;
                };
                auto sig_to_bits_bytes = [&](const std::string &sig) {
                    std::string bits;
                    bits.reserve((size_t)K);
                    for (int i = 0; i < K; i++) {
                        bool bit = (sig[(size_t)i >> 3] >> (i & 7)) & 1;
                        bits.push_back(bit ? '1' : '0');
                    }
                    return bits;
                };

                size_t bins = allow_bin.size();
                uint32 allowed_bins = 0;
                for (size_t i = 0; i < allow_bin.size(); i++)
                    if (allow_bin[i]) allowed_bins++;
                uint32 allowed_tokens = 0;
                const auto &tok_allow_ref = allow_tok[cid];
                for (size_t i = 0; i < tok_allow_ref.size(); i++)
                    if (tok_allow_ref[i]) allowed_tokens++;

                CF_TRACE_LOG( "policy: class=%d domain=%d atoms=%d unique_bins=%zu bin_eval_calls=%zu allowed_bins=%u allowed_tokens=%u",
                     cid, D, K, bins, bins, allowed_bins, allowed_tokens);

                // top 10 bins by count
                std::vector<size_t> idx(bin_counts.size());
                for (size_t i = 0; i < idx.size(); i++) idx[i] = i;
                std::sort(idx.begin(), idx.end(),
                          [&](size_t a, size_t b) { return bin_counts[a] > bin_counts[b]; });
                size_t top = std::min<size_t>(10, idx.size());
                for (size_t i = 0; i < top; i++) {
                    size_t b = idx[i];
                    std::string bits = use_u64 ? sig_to_bits(class_sig_u64[b])
                                               : sig_to_bits_bytes(class_sig_bytes[b]);
                    CF_TRACE_LOG( "policy: class=%d bin sig=%s count=%u",
                         cid, bits.c_str(), bin_counts[b]);
                }
            }
        }

        size_t bytes = (ti.n_rows + 7) / 8;
        uint8 *bits = (uint8 *) palloc0(bytes);
        uint32 passed = 0;
        std::vector<int> ast_vals;
        if (ast && constrained_classes.empty()) {
            ast_vals.assign(loaded.atom_by_id.size(), 1);
        }
        for (uint32 r = 0; r < ti.n_rows; r++) {
            const int32_t *row = ti.code + (size_t)r * (size_t)ti.stride;
            int32 rid = row[0];
            if (rid < 0 || (uint32)rid >= ti.n_rows)
                continue;
            bool ok = true;
            for (int cid : constrained_classes) {
                int idx = find_join_idx(ti, cid);
                if (idx < 0)
                    continue;
                int32 tok = row[idx];
                auto it = allow_tok.find(cid);
                if (it == allow_tok.end()) continue;
                const auto &at = it->second;
                if (tok < 0 || (size_t)tok >= at.size() || !at[(size_t)tok]) {
                    ok = false;
                    break;
                }
            }
            if (ok && !ti.const_atom_ids.empty()) {
                if (ast && constrained_classes.empty()) {
                    std::fill(ast_vals.begin(), ast_vals.end(), 1);
                    for (size_t c = 0; c < ti.const_atom_ids.size(); c++) {
                        int atom_id = ti.const_atom_ids[c];
                        if (target_atom_ids && target_atom_ids->count(atom_id) == 0)
                            continue;
                        auto it_allowed = const_allowed.find(atom_id);
                        if (it_allowed == const_allowed.end()) continue;
                        int idx = ti.const_token_idx[c];
                        int32 tok = row[idx];
                        bool v = (tok >= 0 && (size_t)tok < it_allowed->second.size() &&
                                  it_allowed->second[(size_t)tok]);
                        if ((size_t)atom_id < ast_vals.size())
                            ast_vals[(size_t)atom_id] = v ? 1 : 0;
                    }
                    Tri ev = eval_ast(ast, ast_vals);
                    ok = (ev == TRI_TRUE);
                } else {
                    for (size_t c = 0; c < ti.const_atom_ids.size(); c++) {
                        int atom_id = ti.const_atom_ids[c];
                        if (target_atom_ids && target_atom_ids->count(atom_id) == 0)
                            continue;
                        auto it_allowed = const_allowed.find(atom_id);
                        if (it_allowed == const_allowed.end()) continue;
                        int idx = ti.const_token_idx[c];
                        int32 tok = row[idx];
                        if (tok < 0 || (size_t)tok >= it_allowed->second.size() ||
                            !it_allowed->second[(size_t)tok]) {
                            ok = false;
                            break;
                        }
                    }
                }
            }
            if (ok) {
                bits[(uint32)rid >> 3] |= (uint8)(1u << ((uint32)rid & 7));
                passed++;
            }
        }

        CF_TRACE_LOG( "policy: allow_%s count = %u / %u",
             ti.name.c_str(), passed, ti.n_rows);

        out->items[out->count].table = pstrdup(ti.name.c_str());
        out->items[out->count].allow_bits = bits;
        out->items[out->count].n_rows = ti.n_rows;
        allow_map[ti.name] = &out->items[out->count];
        out->count++;
    }

    return true;
}

} // namespace

typedef struct PolicyRunHandle {
    PolicyAllowListC allow_list;
    PolicyRunProfileC profile;
} PolicyRunHandle;

static void fill_run_profile(const BundleProfile &profile,
                             double parse_ms,
                             PolicyRunProfileC *out)
{
    if (!out) return;
    out->artifact_parse_ms = parse_ms;
    out->stamp_ms = 0.0;
    out->bin_ms = 0.0;
    out->local_sat_ms = 0.0;
    for (const auto &ls : profile.local) {
        out->stamp_ms += ls.ms_stamp;
        out->bin_ms += ls.ms_bin;
        out->local_sat_ms += ls.ms_eval;
    }
    out->prop_ms = profile.prop_ms_total;
    out->prop_iters = profile.prop_iterations;
    out->decode_ms = profile.decode_ms_total;
    out->policy_total_ms = profile.total_ms;
}

static void fill_decode_stats(const PolicyAllowListC *allow, BundleProfile *profile, double ms_decode_default)
{
    if (!allow || !profile) return;
    if (!profile->decode.empty())
        return;
    for (int i = 0; i < allow->count; i++) {
        const PolicyTableAllowC *it = &allow->items[i];
        if (!it->table) continue;
        DecodeStat ds;
        ds.table = it->table;
        ds.rows_total = it->n_rows;
        ds.rows_allowed = 0;
        for (uint32 r = 0; r < it->n_rows; r++) {
            if (it->allow_bits[r >> 3] & (uint8)(1u << (r & 7)))
                ds.rows_allowed++;
        }
        ds.ms_decode = ms_decode_default;
        profile->decode.push_back(ds);
        profile->decode_ms_total += ds.ms_decode;
    }
}

extern "C" PolicyRunHandle *
policy_run(const PolicyArtifactC *arts, int art_count, const PolicyEngineInputC *in)
{
    if (!arts || art_count <= 0 || !in)
        return nullptr;

    PolicyRunHandle *handle = (PolicyRunHandle *)palloc0(sizeof(PolicyRunHandle));
    Loaded loaded;
    auto t0 = Clock::now();
    if (!load_phase(arts, art_count, in, &loaded))
        return nullptr;
    auto t1 = Clock::now();
    double parse_ms = Ms(t1 - t0).count();
    CF_TRACE_LOG( "policy: load_ms=%.3f", parse_ms);

    BundleProfile profile;
    profile.bundle_id = next_bundle_id();
    profile.k = profile_k();
    profile.query = profile_query();
    if (!loaded.target_set.empty())
        profile.target = *loaded.target_set.begin();

    bool force_multi = loaded.has_multi_join;
    bool has_join = false;
    for (const auto &a : loaded.atoms) {
        if (a.kind == AtomKind::JOIN) {
            has_join = true;
            break;
        }
    }
    if (!force_multi && !loaded.target_set.empty()) {
        const std::string &t = *loaded.target_set.begin();
        auto it_ast = loaded.target_ast.find(t);
        if (it_ast != loaded.target_ast.end() && it_ast->second) {
            std::string reason;
            if (!ast_supported_multi_join(loaded, it_ast->second, &reason)) {
                force_multi = true;
            }
        }
    }
    // Join policies use the multi-join path to preserve AST semantics; the
    // token-domain fast path can over-constrain OR branches in decode.
    if (has_join)
        force_multi = true;

    if (contract_mode_enabled() && force_multi) {
        run_multi_join_contract(loaded);
        CF_TRACE_LOG( "policy_contract: multi_join debug only; allow-all for targets");
        if (!build_allow_all(loaded, &handle->allow_list))
            return nullptr;
        auto t_end = Clock::now();
        CF_TRACE_LOG( "policy: total_ms=%.3f", Ms(t_end - t0).count());
        profile.total_ms = Ms(t_end - t0).count();
        fill_decode_stats(&handle->allow_list, &profile, 0.0);
        log_profile(profile);
        update_query_profile(profile, loaded);
        fill_run_profile(profile, parse_ms, &handle->profile);
        return handle;
    }

    if (force_multi) {
        if (!multi_join_enforce(loaded, &handle->allow_list, &profile))
            return nullptr;
        auto t_end = Clock::now();
        CF_TRACE_LOG( "policy: total_ms=%.3f", Ms(t_end - t0).count());
        profile.total_ms = Ms(t_end - t0).count();
        fill_decode_stats(&handle->allow_list, &profile, 0.0);
        log_profile(profile);
        update_query_profile(profile, loaded);
        fill_run_profile(profile, parse_ms, &handle->profile);
        return handle;
    }

    if (!has_join) {
        if (!const_only_enforce(loaded, &handle->allow_list, &profile))
            return nullptr;
        auto t_done = Clock::now();
        CF_TRACE_LOG( "policy: total_ms=%.3f", Ms(t_done - t0).count());
        profile.total_ms = Ms(t_done - t0).count();
        fill_decode_stats(&handle->allow_list, &profile, 0.0);
        log_profile(profile);
        update_query_profile(profile, loaded);
        fill_run_profile(profile, parse_ms, &handle->profile);
        return handle;
    }

    if (!token_domain_run(loaded, &handle->allow_list))
        return nullptr;
    auto t2 = Clock::now();
    CF_TRACE_LOG( "policy: token_domain_ms=%.3f", Ms(t2 - t1).count());
    CF_TRACE_LOG( "policy: total_ms=%.3f", Ms(t2 - t0).count());
    profile.total_ms = Ms(t2 - t0).count();
    profile.prop_ms_total = Ms(t2 - t1).count();
    profile.prop_iterations = 0;
    fill_decode_stats(&handle->allow_list, &profile, 0.0);
    log_profile(profile);
    update_query_profile(profile, loaded);
    fill_run_profile(profile, parse_ms, &handle->profile);

    return handle;
}

extern "C" const PolicyAllowListC *
policy_run_allow_list(const PolicyRunHandle *h)
{
    if (!h) return nullptr;
    return &h->allow_list;
}

extern "C" const PolicyRunProfileC *
policy_run_profile(const PolicyRunHandle *h)
{
    if (!h) return nullptr;
    return &h->profile;
}

extern "C" bool
policy_build_allow_bits_general(const PolicyArtifactC *arts, int art_count,
                                const PolicyEngineInputC *in,
                                PolicyAllowListC *out)
{
    if (!out) return false;
    PolicyRunHandle *h = policy_run(arts, art_count, in);
    if (!h) return false;
    *out = h->allow_list;
    return true;
}

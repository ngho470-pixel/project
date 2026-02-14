#include "policy_evaluator.h"

extern "C" {
#include "postgres.h"
#include "utils/palloc.h"
#include "utils/guc.h"
}

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

struct AstNode {
    enum Type { VAR, AND, OR } type;
    std::string key;
    int var_id = -1;
    std::vector<AstNode *> children;
};

struct NodeStore {
    std::vector<AstNode *> nodes;
};

static thread_local NodeStore *g_node_store = nullptr;
static bool g_eval_debug = false;

struct Policy {
    int policy_id = -1;
    std::string target;
    std::string expr;
    AstNode *ast = nullptr;
    int line_no = 0;
    std::set<std::string> referenced_tables;
    std::set<std::pair<std::string, std::string>> const_cols;
    std::set<std::string> atom_keys;
    struct AtomDef {
        enum Kind { JOIN_EQ, COL_CONST } kind = COL_CONST;
        std::string key;
        std::string left_table;
        std::string left_col;
        std::string right_table;
        std::string right_col;
        std::string op;
        std::vector<std::string> values;
        int join_class_id = -1;
        int atom_id = -1;
    };
    std::vector<AtomDef> atoms;
};

struct Token {
    enum Type { IDENT, STRING, NUMBER, OP, LPAREN, RPAREN, COMMA, AND, OR } type;
    std::string text;
};

static std::string to_lower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

static bool eval_debug_enabled() {
    const char *v = GetConfigOption("custom_filter.debug_mode", true, false);
    if (!v) return false;
    std::string s = to_lower(v);
    return s != "off";
}

static const char *token_type_name(Token::Type t) {
    switch (t) {
        case Token::IDENT: return "IDENT";
        case Token::STRING: return "STRING";
        case Token::NUMBER: return "NUMBER";
        case Token::OP: return "OP";
        case Token::LPAREN: return "LPAREN";
        case Token::RPAREN: return "RPAREN";
        case Token::COMMA: return "COMMA";
        case Token::AND: return "AND";
        case Token::OR: return "OR";
    }
    return "UNKNOWN";
}

static std::string trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

static bool env_flag_enabled(const char *name) {
    const char *v = std::getenv(name);
    if (!v) return false;
    std::string s = to_lower(trim(v));
    return !(s.empty() || s == "0" || s == "off" || s == "false" || s == "no");
}

static std::string unquote(const std::string &s) {
    if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'')
        return s.substr(1, s.size() - 2);
    return s;
}

static std::string normalize_number_string(const std::string &s) {
    std::string t = trim(s);
    if (t.empty()) return t;

    std::string sign;
    if (t[0] == '+' || t[0] == '-') {
        if (t[0] == '-') sign = "-";
        t = t.substr(1);
    }

    std::string mant = t;
    std::string exp;
    size_t epos = t.find_first_of("eE");
    if (epos != std::string::npos) {
        mant = t.substr(0, epos);
        exp = t.substr(epos + 1);
    }

    std::string intpart = mant;
    std::string frac;
    size_t dpos = mant.find('.');
    if (dpos != std::string::npos) {
        intpart = mant.substr(0, dpos);
        frac = mant.substr(dpos + 1);
    }

    size_t nz = 0;
    while (nz < intpart.size() && intpart[nz] == '0') nz++;
    intpart = intpart.substr(nz);
    if (intpart.empty()) intpart = "0";

    while (!frac.empty() && frac.back() == '0') frac.pop_back();

    std::string norm = intpart;
    if (!frac.empty())
        norm += "." + frac;

    if (!exp.empty()) {
        exp = trim(exp);
        std::string exp_sign;
        if (!exp.empty() && (exp[0] == '+' || exp[0] == '-')) {
            if (exp[0] == '-') exp_sign = "-";
            exp = exp.substr(1);
        }
        size_t enz = 0;
        while (enz < exp.size() && exp[enz] == '0') enz++;
        exp = exp.substr(enz);
        if (exp.empty()) exp = "0";
        norm += "e" + exp_sign + exp;
    }

    if (norm == "0") sign.clear();
    return sign + norm;
}

static std::string normalize_literal(const Token &tok) {
    std::string val = tok.text;
    if (tok.type == Token::STRING) {
        val = unquote(val);
        val = trim(val);
        return val;
    }
    if (tok.type == Token::NUMBER) {
        return normalize_number_string(val);
    }
    return trim(val);
}

static bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.';
}

static std::vector<Token> tokenize_expr(const std::string &expr) {
    std::vector<Token> tokens;
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (std::isspace(static_cast<unsigned char>(c))) {
            i++;
            continue;
        }
        if (c == '(') {
            tokens.push_back({Token::LPAREN, "("});
            i++;
            continue;
        }
        if (c == ')') {
            tokens.push_back({Token::RPAREN, ")"});
            i++;
            continue;
        }
        if (c == ',') {
            tokens.push_back({Token::COMMA, ","});
            i++;
            continue;
        }
        if (c == '\'') {
            size_t j = i + 1;
            while (j < expr.size()) {
                if (expr[j] == '\'' && (j + 1 >= expr.size() || expr[j + 1] != '\'')) {
                    break;
                }
                if (expr[j] == '\'' && j + 1 < expr.size() && expr[j + 1] == '\'') {
                    j += 2;
                    continue;
                }
                j++;
            }
            if (j < expr.size()) j++;
            tokens.push_back({Token::STRING, expr.substr(i, j - i)});
            i = j;
            continue;
        }
        if (c == '!') {
            if (i + 1 < expr.size() && expr[i + 1] == '=') {
                tokens.push_back({Token::OP, "!="});
                i += 2;
                continue;
            }
            ereport(ERROR, (errmsg("unsupported operator: !")));
        }
        if (c == '<' || c == '>' || c == '=') {
            std::string op;
            op.push_back(c);
            if (i + 1 < expr.size()) {
                char n = expr[i + 1];
                if ((c == '<' || c == '>') && n == '=') {
                    op.push_back(n);
                    i++;
                } else if (c == '<' && n == '>') {
                    op.push_back(n);
                    i++;
                }
            }
            tokens.push_back({Token::OP, op});
            i++;
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '.' && i + 1 < expr.size() && std::isdigit(static_cast<unsigned char>(expr[i + 1])))) {
            size_t j = i + 1;
            while (j < expr.size() &&
                   (std::isdigit(static_cast<unsigned char>(expr[j])) || expr[j] == '.')) {
                j++;
            }
            tokens.push_back({Token::NUMBER, expr.substr(i, j - i)});
            i = j;
            continue;
        }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i + 1;
            while (j < expr.size() && is_ident_char(expr[j])) j++;
            std::string word = expr.substr(i, j - i);
            std::string lower = to_lower(word);
            if (lower == "date") {
                size_t k = j;
                while (k < expr.size() && std::isspace(static_cast<unsigned char>(expr[k]))) k++;
                if (k < expr.size() && expr[k] == '\'') {
                    ereport(ERROR, (errmsg("unsupported literal form: DATE '...'")));
                }
            }
            if (lower == "and") {
                tokens.push_back({Token::AND, lower});
            } else if (lower == "or") {
                tokens.push_back({Token::OR, lower});
            } else if (lower == "in" || lower == "like") {
                tokens.push_back({Token::OP, lower});
            } else {
                tokens.push_back({Token::IDENT, lower});
            }
            i = j;
            continue;
        }
        i++;
    }
    return tokens;
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

static AstNode *make_var_node(const std::string &key) {
    AstNode *node = new AstNode();
    node->type = AstNode::VAR;
    node->key = key;
    if (g_node_store) g_node_store->nodes.push_back(node);
    return node;
}

static AstNode *make_false_node() {
    AstNode *node = new AstNode();
    node->type = AstNode::VAR;
    node->key = "";
    node->var_id = 0; // y0 is treated as constant FALSE by downstream evaluator.
    if (g_node_store) g_node_store->nodes.push_back(node);
    return node;
}

static AstNode *make_node(AstNode::Type type, AstNode *left, AstNode *right) {
    AstNode *node = new AstNode();
    node->type = type;
    node->children.push_back(left);
    node->children.push_back(right);
    if (g_node_store) g_node_store->nodes.push_back(node);
    return node;
}

static AstNode *clone_ast(const AstNode *node) {
    if (!node) return nullptr;
    if (node->type == AstNode::VAR) {
        AstNode *n = make_var_node(node->key);
        n->var_id = node->var_id;
        return n;
    }
    AstNode *n = new AstNode();
    n->type = node->type;
    if (g_node_store) g_node_store->nodes.push_back(n);
    for (auto *child : node->children) {
        n->children.push_back(clone_ast(child));
    }
    return n;
}

static std::string join_tokens(const std::vector<Token> &tokens) {
    std::string out;
    for (size_t i = 0; i < tokens.size(); i++) {
        if (i > 0) out.push_back(' ');
        out += tokens[i].text;
    }
    return out;
}

static std::pair<std::string, std::string> split_table_col(const std::string &ident,
                                                           const std::string &target_table) {
    auto pos = ident.find('.');
    if (pos != std::string::npos) {
        return {ident.substr(0, pos), ident.substr(pos + 1)};
    }
    return {target_table, ident};
}

static std::string canonicalize_atom(const std::vector<Token> &tokens,
                                     const std::string &target_table,
                                     Policy &policy,
                                     Policy::AtomDef *out_def) {
    if (!out_def) return "";
    *out_def = Policy::AtomDef();

    for (const auto &t : tokens) {
        if (t.type == Token::IDENT && t.text == "between") {
            ereport(ERROR, (errmsg("unsupported operator: between")));
        }
    }

    std::string left_ident;
    std::string op;
    std::string right_ident;

    for (size_t i = 0; i < tokens.size(); i++) {
        if (tokens[i].type == Token::IDENT) {
            left_ident = tokens[i].text;
            break;
        }
    }
    for (size_t i = 0; i < tokens.size(); i++) {
        if (tokens[i].type == Token::OP) {
            op = to_lower(tokens[i].text);
            for (size_t j = i + 1; j < tokens.size(); j++) {
                if (tokens[j].type == Token::IDENT) {
                    right_ident = tokens[j].text;
                    break;
                }
                if (tokens[j].type == Token::STRING || tokens[j].type == Token::NUMBER) {
                    break;
                }
            }
            break;
        }
    }

    if (left_ident.empty() || op.empty())
        return "";
    if (op == "<>") op = "!=";

    auto left = split_table_col(left_ident, target_table);
    std::string left_full = left.first + "." + left.second;
    policy.referenced_tables.insert(left.first);

    if (!right_ident.empty() && op == "=") {
        auto right = split_table_col(right_ident, target_table);
        std::string right_full = right.first + "." + right.second;
        policy.referenced_tables.insert(right.first);
        out_def->kind = Policy::AtomDef::JOIN_EQ;
        out_def->left_table = left.first;
        out_def->left_col = left.second;
        out_def->right_table = right.first;
        out_def->right_col = right.second;
        if (left_full <= right_full) {
            out_def->key = "join:" + left_full + "=" + right_full;
        } else {
            std::swap(out_def->left_table, out_def->right_table);
            std::swap(out_def->left_col, out_def->right_col);
            out_def->key = "join:" + right_full + "=" + left_full;
        }
        return out_def->key;
    }
    if (!right_ident.empty()) {
        ereport(ERROR, (errmsg("unsupported column comparison: %s %s %s",
                               left_ident.c_str(), op.c_str(), right_ident.c_str())));
    }

    out_def->kind = Policy::AtomDef::COL_CONST;
    out_def->left_table = left.first;
    out_def->left_col = left.second;
    out_def->op = op;
    policy.const_cols.insert({left.first, left.second});

    std::vector<std::string> values;
    if (op == "in") {
        for (size_t i = 0; i < tokens.size(); i++) {
            if (tokens[i].type == Token::STRING || tokens[i].type == Token::NUMBER) {
                values.push_back(normalize_literal(tokens[i]));
            }
        }
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    } else {
        for (size_t i = 0; i < tokens.size(); i++) {
            if (tokens[i].type == Token::STRING || tokens[i].type == Token::NUMBER) {
                values.push_back(normalize_literal(tokens[i]));
                break;
            }
        }
    }
    out_def->values = values;

    if (op == "like") {
        if (values.empty()) {
            ereport(ERROR, (errmsg("LIKE pattern missing for %s", left_full.c_str())));
        }
        /* Accept general LIKE patterns; evaluation handles % and _ wildcards. */
    }

    std::string key = "const:" + left_full + "|" + op;
    if (!values.empty()) {
        if (op == "in") {
            key += "|";
            for (size_t i = 0; i < values.size(); i++) {
                if (i > 0) key += ",";
                key += values[i];
            }
        } else {
            key += "|" + values[0];
        }
    } else {
        key += "|" + join_tokens(tokens);
    }
    out_def->key = key;
    return key;
}

static AstNode *parse_or(const std::vector<Token> &tokens, size_t &idx,
                         const std::string &target_table, Policy &policy);

static AstNode *parse_atom(const std::vector<Token> &tokens, size_t &idx,
                           const std::string &target_table, Policy &policy) {
    if (idx >= tokens.size()) return nullptr;
    if (tokens[idx].type == Token::LPAREN) {
        idx++;
        AstNode *node = parse_or(tokens, idx, target_table, policy);
        if (idx < tokens.size() && tokens[idx].type == Token::RPAREN) idx++;
        return node;
    }

    std::vector<Token> atom_tokens;
    int depth = 0;
    while (idx < tokens.size()) {
        if (tokens[idx].type == Token::LPAREN) {
            depth++;
        } else if (tokens[idx].type == Token::RPAREN) {
            if (depth == 0) break;
            depth--;
        } else if ((tokens[idx].type == Token::AND || tokens[idx].type == Token::OR) && depth == 0) {
            break;
        }
        atom_tokens.push_back(tokens[idx]);
        idx++;
    }

    Policy::AtomDef def;
    std::string key = canonicalize_atom(atom_tokens, target_table, policy, &def);
    if (!key.empty()) {
        policy.atom_keys.insert(key);
        policy.atoms.push_back(def);
    }
    return make_var_node(key);
}

static AstNode *parse_and(const std::vector<Token> &tokens, size_t &idx,
                          const std::string &target_table, Policy &policy) {
    AstNode *left = parse_atom(tokens, idx, target_table, policy);
    while (idx < tokens.size() && tokens[idx].type == Token::AND) {
        idx++;
        AstNode *right = parse_atom(tokens, idx, target_table, policy);
        left = make_node(AstNode::AND, left, right);
    }
    return left;
}

static AstNode *parse_or(const std::vector<Token> &tokens, size_t &idx,
                         const std::string &target_table, Policy &policy) {
    AstNode *left = parse_and(tokens, idx, target_table, policy);
    while (idx < tokens.size() && tokens[idx].type == Token::OR) {
        idx++;
        AstNode *right = parse_and(tokens, idx, target_table, policy);
        left = make_node(AstNode::OR, left, right);
    }
    return left;
}

static int precedence(const AstNode *node) {
    if (!node) return 0;
    if (node->type == AstNode::OR) return 1;
    if (node->type == AstNode::AND) return 2;
    return 3;
}

static std::string ast_to_string(const AstNode *node) {
    if (!node) return "";
    if (node->type == AstNode::VAR) {
        return "y" + std::to_string(node->var_id);
    }
    std::string op = (node->type == AstNode::AND) ? " and " : " or ";
    std::string out;
    for (size_t i = 0; i < node->children.size(); i++) {
        if (i > 0) out += op;
        const AstNode *child = node->children[i];
        std::string part = ast_to_string(child);
        if (precedence(child) < precedence(node)) {
            out += "(" + part + ")";
        } else {
            out += part;
        }
    }
    return out;
}

static void assign_var_ids(AstNode *node, const std::map<std::string, int> &mapping) {
    if (!node) return;
    if (node->type == AstNode::VAR) {
        auto it = mapping.find(node->key);
        if (it != mapping.end()) node->var_id = it->second;
        return;
    }
    for (auto *child : node->children) {
        assign_var_ids(child, mapping);
    }
}

static std::vector<Policy> load_policies(const std::string &path) {
    std::vector<Policy> policies;
    std::ifstream in(path);
    if (!in.is_open()) {
        return policies;
    }
    std::string line;
    int line_no = 0;
    while (std::getline(in, line)) {
        line_no++;
        line = trim(line);
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string left = trim(line.substr(0, colon));
        std::string right = trim(line.substr(colon + 1));
        int policy_id = -1;
        size_t pos = 0;
        while (pos < left.size() && std::isspace(static_cast<unsigned char>(left[pos])))
            pos++;
        size_t id_start = pos;
        while (pos < left.size() && std::isdigit(static_cast<unsigned char>(left[pos])))
            pos++;
        if (pos > id_start) {
            try {
                policy_id = std::stoi(left.substr(id_start, pos - id_start));
            } catch (...) {
                policy_id = -1;
            }
            while (pos < left.size() &&
                   (left[pos] == '.' || std::isspace(static_cast<unsigned char>(left[pos]))))
                pos++;
            left = left.substr(pos);
        } else {
            left = left.substr(id_start);
        }
        left = to_lower(trim(left));
        if (left.empty() || right.empty()) continue;

        Policy pol;
        pol.policy_id = policy_id;
        pol.target = left;
        pol.expr = right;
        pol.line_no = line_no;
        pol.referenced_tables.insert(left);
        auto tokens = tokenize_expr(right);
        if (g_eval_debug) {
            std::string out;
            for (size_t ti = 0; ti < tokens.size(); ti++) {
                if (ti > 0) out += " ";
                out += std::string(token_type_name(tokens[ti].type)) + ":" + tokens[ti].text;
            }
            elog(NOTICE, "policy_eval: target=%s tokens=%s", pol.target.c_str(), out.c_str());
        }
        size_t idx = 0;
        pol.ast = parse_or(tokens, idx, pol.target, pol);
        policies.push_back(pol);
    }
    return policies;
}

static void collect_ast_keys(const AstNode *node, std::set<std::string> &keys) {
    if (!node) return;
    if (node->type == AstNode::VAR) {
        if (!node->key.empty())
            keys.insert(node->key);
        return;
    }
    for (const auto *child : node->children)
        collect_ast_keys(child, keys);
}

} // namespace

static PolicyEvalResultC *evaluate_policies_internal(const char *policy_path,
                                                     char **scanned_tables,
                                                     int n_scanned,
                                                     bool default_all_targets) {
    std::string path = policy_path ? policy_path : "";
    g_eval_debug = eval_debug_enabled();
    bool dump_policy_ast = env_flag_enabled("CF_DUMP_POLICY_AST") || g_eval_debug;
    NodeStore store;
    g_node_store = &store;
    auto policies = load_policies(path);

    std::set<std::string> known_tables;
    std::map<std::string, std::vector<size_t>> policies_by_target;
    std::map<std::string, std::set<std::string>> deps_by_target;
    for (size_t i = 0; i < policies.size(); i++) {
        if (policies[i].target.empty())
            continue;
        policies_by_target[policies[i].target].push_back(i);
        deps_by_target[policies[i].target].insert(policies[i].referenced_tables.begin(),
                                                  policies[i].referenced_tables.end());
        known_tables.insert(policies[i].referenced_tables.begin(),
                            policies[i].referenced_tables.end());
    }

    std::set<std::string> targets_with_policies;
    for (const auto &kv : policies_by_target)
        targets_with_policies.insert(kv.first);

    std::vector<std::string> scanned_list;
    std::set<std::string> scanned_set;
    for (int i = 0; i < n_scanned; i++) {
        if (!scanned_tables || !scanned_tables[i]) continue;
        std::string t = to_lower(scanned_tables[i]);
        if (t.empty()) continue;
        if (scanned_set.insert(t).second)
            scanned_list.push_back(t);
    }
    if (scanned_set.empty() && default_all_targets) {
        scanned_set = targets_with_policies;
        for (const auto &t : targets_with_policies)
            scanned_list.push_back(t);
    }

    std::set<std::string> policy_targets;
    for (const auto &t : scanned_set) {
        if (targets_with_policies.find(t) != targets_with_policies.end())
            policy_targets.insert(t);
    }

    std::set<std::string> closure_tables = scanned_set;
    std::deque<std::string> queue;
    for (const auto &t : policy_targets)
        queue.push_back(t);
    while (!queue.empty()) {
        std::string t = queue.front();
        queue.pop_front();
        auto it = deps_by_target.find(t);
        if (it == deps_by_target.end())
            continue;
        for (const auto &u : it->second) {
            closure_tables.insert(u);
            if (targets_with_policies.find(u) != targets_with_policies.end() &&
                policy_targets.find(u) == policy_targets.end()) {
                policy_targets.insert(u);
                queue.push_back(u);
            }
        }
    }

    std::map<std::string, AstNode *> perm_ast;
    std::map<std::string, AstNode *> rest_ast;
    std::map<std::string, int> perm_count_by_target;
    std::map<std::string, int> rest_count_by_target;
    int total_perm_policies = 0;
    int total_rest_policies = 0;
    for (size_t i = 0; i < policies.size(); i++) {
        const Policy &pol = policies[i];
        if (pol.target.empty() || !pol.ast)
            continue;
        if (policy_targets.find(pol.target) == policy_targets.end())
            continue;

        bool permissive = true; // Backward-compatible default.
        if (pol.policy_id > 0)
            permissive = (pol.policy_id % 2 == 1); // odd ids are permissive

        if (permissive) {
            perm_count_by_target[pol.target]++;
            total_perm_policies++;
            auto it = perm_ast.find(pol.target);
            if (it == perm_ast.end()) {
                perm_ast[pol.target] = pol.ast;
            } else {
                perm_ast[pol.target] = make_node(AstNode::OR, it->second, pol.ast);
            }
        } else {
            rest_count_by_target[pol.target]++;
            total_rest_policies++;
            auto it = rest_ast.find(pol.target);
            if (it == rest_ast.end()) {
                rest_ast[pol.target] = pol.ast;
            } else {
                rest_ast[pol.target] = make_node(AstNode::AND, it->second, pol.ast);
            }
        }
    }

    std::set<std::string> all_targets;
    for (const auto &kv : perm_ast)
        all_targets.insert(kv.first);
    for (const auto &kv : rest_ast)
        all_targets.insert(kv.first);

    std::map<std::string, AstNode *> target_ast;
    for (const auto &t : all_targets) {
        auto pit = perm_ast.find(t);
        auto rit = rest_ast.find(t);
        if (pit == perm_ast.end()) {
            // Postgres RLS requires at least one permissive policy; only-restrictive => deny all.
            target_ast[t] = make_false_node();
        } else if (rit == rest_ast.end()) {
            target_ast[t] = pit->second;
        } else {
            target_ast[t] = make_node(AstNode::AND, pit->second, rit->second);
        }
    }

    std::set<std::string> used_atom_keys;
    for (const auto &kv : target_ast)
        collect_ast_keys(kv.second, used_atom_keys);

    std::map<std::string, int> join_col_index;
    std::vector<std::string> join_cols;
    for (const auto &pol : policies) {
        for (const auto &atom : pol.atoms) {
            if (atom.kind != Policy::AtomDef::JOIN_EQ)
                continue;
            std::string lkey = atom.left_table + "." + atom.left_col;
            std::string rkey = atom.right_table + "." + atom.right_col;
            if (join_col_index.emplace(lkey, (int)join_cols.size()).second)
                join_cols.push_back(lkey);
            if (join_col_index.emplace(rkey, (int)join_cols.size()).second)
                join_cols.push_back(rkey);
        }
    }

    std::vector<int> parent(join_cols.size(), 0);
    for (size_t i = 0; i < join_cols.size(); i++) parent[i] = (int)i;
    auto uf_find = [&](int x) {
        while (parent[x] != x) {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        return x;
    };
    auto uf_union = [&](int a, int b) {
        int ra = uf_find(a);
        int rb = uf_find(b);
        if (ra != rb) parent[rb] = ra;
    };

    for (const auto &pol : policies) {
        for (const auto &atom : pol.atoms) {
            if (atom.kind != Policy::AtomDef::JOIN_EQ)
                continue;
            int ia = join_col_index[atom.left_table + "." + atom.left_col];
            int ib = join_col_index[atom.right_table + "." + atom.right_col];
            uf_union(ia, ib);
        }
    }

    std::map<int, std::vector<std::string>> class_members;
    for (size_t i = 0; i < join_cols.size(); i++) {
        int root = uf_find((int)i);
        class_members[root].push_back(join_cols[i]);
    }
    struct ClassKey {
        int root;
        std::string key;
    };
    std::vector<ClassKey> classes;
    classes.reserve(class_members.size());
    for (auto &kv : class_members) {
        auto &members = kv.second;
        std::sort(members.begin(), members.end());
        std::string key;
        for (size_t i = 0; i < members.size(); i++) {
            if (i > 0) key.push_back(',');
            key += members[i];
        }
        classes.push_back({kv.first, key});
    }
    std::sort(classes.begin(), classes.end(), [](const ClassKey &a, const ClassKey &b) {
        return a.key < b.key;
    });

    std::map<int, int> root_to_class;
    for (size_t i = 0; i < classes.size(); i++)
        root_to_class[classes[i].root] = (int)i;

    std::map<std::string, int> join_class_by_col;
    for (size_t i = 0; i < join_cols.size(); i++) {
        int cid = root_to_class[uf_find((int)i)];
        join_class_by_col[join_cols[i]] = cid;
    }

    for (auto &pol : policies) {
        for (auto &atom : pol.atoms) {
            if (atom.kind == Policy::AtomDef::JOIN_EQ) {
                std::string lkey = atom.left_table + "." + atom.left_col;
                std::string rkey = atom.right_table + "." + atom.right_col;
                atom.join_class_id = join_class_by_col[lkey];
                if (atom.join_class_id != join_class_by_col[rkey]) {
                    atom.join_class_id = join_class_by_col[lkey];
                }
            } else {
                std::string lkey = atom.left_table + "." + atom.left_col;
                auto it = join_class_by_col.find(lkey);
                if (it != join_class_by_col.end())
                    atom.join_class_id = it->second;
            }
        }
    }

    std::map<std::string, Policy::AtomDef> atom_defs;
    for (const auto &pol : policies) {
        if (policy_targets.find(pol.target) == policy_targets.end())
            continue;
        for (const auto &atom : pol.atoms) {
            if (atom.key.empty())
                continue;
            if (used_atom_keys.find(atom.key) == used_atom_keys.end())
                continue;
            if (atom_defs.find(atom.key) == atom_defs.end())
                atom_defs[atom.key] = atom;
        }
    }

    std::vector<std::string> atom_list;
    atom_list.reserve(atom_defs.size());
    for (const auto &kv : atom_defs)
        atom_list.push_back(kv.first);

    std::map<std::string, int> atom_map;
    for (size_t i = 0; i < atom_list.size(); i++)
        atom_map[atom_list[i]] = static_cast<int>(i + 1);

    for (auto &kv : target_ast) {
        if (kv.second) {
            assign_var_ids(kv.second, atom_map);
        }
    }
    for (auto &kv : perm_ast) {
        if (kv.second) {
            assign_var_ids(kv.second, atom_map);
        }
    }
    for (auto &kv : rest_ast) {
        if (kv.second) {
            assign_var_ids(kv.second, atom_map);
        }
    }
    if (dump_policy_ast) {
        int targets_perm0 = 0;
        for (const auto &kv : target_ast) {
            int perm_n = 0;
            auto pit = perm_count_by_target.find(kv.first);
            if (pit != perm_count_by_target.end())
                perm_n = pit->second;
            int rest_n = 0;
            auto rit = rest_count_by_target.find(kv.first);
            if (rit != rest_count_by_target.end())
                rest_n = rit->second;
            bool used_y0 = (kv.second && kv.second->type == AstNode::VAR && kv.second->var_id == 0);
            if (perm_n == 0 || used_y0)
                targets_perm0++;
            std::string ast_str = kv.second ? ast_to_string(kv.second) : "";
            elog(NOTICE, "CF_POLICY_AST target=%s perm=%d rest=%d y0=%d ast=%s",
                 kv.first.c_str(), perm_n, rest_n, used_y0 ? 1 : 0, ast_str.c_str());
        }
        elog(NOTICE,
             "CF_POLICY_AST_SUMMARY permissive_total=%d restrictive_total=%d targets=%d targets_perm0=%d",
             total_perm_policies, total_rest_policies, (int)target_ast.size(), targets_perm0);
    }

    std::vector<int> target_jc_counts;
    std::vector<int> target_jc_offsets;
    std::vector<int> target_jc_ids;
    target_jc_counts.reserve(target_ast.size());
    target_jc_offsets.reserve(target_ast.size());

    for (auto &kv : target_ast) {
        std::set<int> jc;
        if (kv.second) {
            std::set<std::string> keys;
            collect_ast_keys(kv.second, keys);
            for (const auto &k : keys) {
                auto it = atom_defs.find(k);
                if (it == atom_defs.end())
                    continue;
                const auto &atom = it->second;
                if (atom.kind == Policy::AtomDef::JOIN_EQ && atom.join_class_id >= 0)
                    jc.insert(atom.join_class_id);
            }
        }
        target_jc_offsets.push_back((int)target_jc_ids.size());
        target_jc_counts.push_back((int)jc.size());
        for (int cid : jc)
            target_jc_ids.push_back(cid);
        if (g_eval_debug) {
            std::string list;
            for (int cid : jc) {
                if (!list.empty()) list += ", ";
                list += std::to_string(cid);
            }
            elog(NOTICE, "policy_eval: target=%s join_classes=[%s]",
                 kv.first.c_str(), list.c_str());
        }
    }
    if (g_eval_debug) {
        for (size_t i = 0; i < policies.size(); i++) {
            const Policy &pol = policies[i];
            if (policy_targets.find(pol.target) == policy_targets.end())
                continue;
            std::string pol_ast = pol.ast ? ast_to_string(pol.ast) : "";
            elog(NOTICE, "policy_eval: policy[%d] target=%s expr=%s ast=%s",
                 pol.line_no, pol.target.c_str(), pol.expr.c_str(), pol_ast.c_str());
        }
        for (size_t i = 0; i < atom_list.size(); i++) {
            int id = (int)(i + 1);
            elog(NOTICE, "policy_eval: atom y%d = %s", id, atom_list[i].c_str());
        }
    }

    bool has_join_eq = false;
    std::set<std::pair<std::string, std::string>> needed_consts;
    for (const auto &kv : atom_defs) {
        const auto &atom = kv.second;
        if (atom.kind == Policy::AtomDef::JOIN_EQ) {
            has_join_eq = true;
        } else {
            needed_consts.insert({atom.left_table, atom.left_col});
        }
    }

    std::vector<std::string> needed_files;
    if (has_join_eq)
        needed_files.push_back("meta/join_classes");
    for (const auto &tbl : closure_tables) {
        if (known_tables.find(tbl) == known_tables.end())
            continue;
        needed_files.push_back(tbl + "_ctid");
        needed_files.push_back(tbl + "_code_base");
        needed_files.push_back("meta/cols/" + tbl);
    }
    for (const auto &col : needed_consts) {
        needed_files.push_back("dict/" + col.first + "/" + col.second);
        needed_files.push_back("meta/dict_type/" + col.first + "/" + col.second);
        needed_files.push_back("meta/dict_sorted/" + col.first + "/" + col.second);
    }
    std::sort(needed_files.begin(), needed_files.end());
    needed_files.erase(std::unique(needed_files.begin(), needed_files.end()), needed_files.end());

    auto map_const_op = [](const std::string &op) {
        if (op == "=") return POLICY_OP_EQ;
        if (op == "in") return POLICY_OP_IN;
        if (op == "like") return POLICY_OP_LIKE;
        if (op == "<") return POLICY_OP_LT;
        if (op == "<=") return POLICY_OP_LE;
        if (op == ">") return POLICY_OP_GT;
        if (op == ">=") return POLICY_OP_GE;
        if (op == "!=") return POLICY_OP_NE;
        return POLICY_OP_EQ;
    };

    struct BundleDef {
        std::string target;
        std::string ast;
        std::vector<Policy::AtomDef> atoms;
    };
    std::vector<BundleDef> bundles;
    bundles.reserve(policies.size());

    for (const auto &pol : policies) {
        if (policy_targets.find(pol.target) == policy_targets.end())
            continue;
        if (!pol.ast)
            continue;
        std::set<std::string> keys;
        collect_ast_keys(pol.ast, keys);
        std::map<std::string, Policy::AtomDef> b_defs;
        for (const auto &atom : pol.atoms) {
            if (atom.key.empty())
                continue;
            if (keys.find(atom.key) == keys.end())
                continue;
            if (b_defs.find(atom.key) == b_defs.end())
                b_defs[atom.key] = atom;
        }
        std::vector<std::string> b_list;
        b_list.reserve(b_defs.size());
        for (const auto &kv : b_defs)
            b_list.push_back(kv.first);
        std::map<std::string, int> b_map;
        for (size_t i = 0; i < b_list.size(); i++)
            b_map[b_list[i]] = static_cast<int>(i + 1);

        AstNode *b_ast = clone_ast(pol.ast);
        assign_var_ids(b_ast, b_map);
        std::string b_ast_str = ast_to_string(b_ast);

        BundleDef b;
        b.target = pol.target;
        b.ast = b_ast_str;
        b.atoms.reserve(b_list.size());
        for (const auto &k : b_list) {
            auto it = b_defs.find(k);
            if (it != b_defs.end())
                b.atoms.push_back(it->second);
        }
        bundles.push_back(std::move(b));
    }

    PolicyEvalResultC *res = (PolicyEvalResultC *)palloc0(sizeof(PolicyEvalResultC));
    res->needed_count = static_cast<int>(needed_files.size());
    res->needed_files = res->needed_count ? (char **)palloc0(sizeof(char *) * res->needed_count) : nullptr;
    for (int i = 0; i < res->needed_count; i++) {
        res->needed_files[i] = pstrdup(needed_files[i].c_str());
    }

    res->atom_count = static_cast<int>(atom_list.size());
    res->atoms = res->atom_count ? (PolicyAtomC *)palloc0(sizeof(PolicyAtomC) * res->atom_count) : nullptr;
    for (int i = 0; i < res->atom_count; i++) {
        const auto &key = atom_list[i];
        auto it = atom_defs.find(key);
        if (it == atom_defs.end()) continue;
        const auto &atom = it->second;
        PolicyAtomC *out = &res->atoms[i];
        out->atom_id = atom_map[key];
        out->kind = (atom.kind == Policy::AtomDef::JOIN_EQ) ? POLICY_ATOM_JOIN_EQ : POLICY_ATOM_COL_CONST;
        out->join_class_id = atom.join_class_id;
        out->canon_key = pstrdup(atom.key.c_str());
        if (atom.kind == Policy::AtomDef::JOIN_EQ) {
            std::string lkey = "join:" + atom.left_table + "." + atom.left_col +
                               " class=" + std::to_string(atom.join_class_id);
            std::string rkey = "join:" + atom.right_table + "." + atom.right_col +
                               " class=" + std::to_string(atom.join_class_id);
            out->lhs_schema_key = pstrdup(lkey.c_str());
            out->rhs_schema_key = pstrdup(rkey.c_str());
            out->op = 0;
            out->const_count = 0;
            out->const_values = nullptr;
        } else {
            std::string skey = "const:" + atom.left_table + "." + atom.left_col;
            out->lhs_schema_key = pstrdup(skey.c_str());
            out->rhs_schema_key = nullptr;
            out->op = map_const_op(atom.op);
            out->const_count = static_cast<int>(atom.values.size());
            out->const_values = out->const_count ? (char **)palloc0(sizeof(char *) * out->const_count) : nullptr;
            for (int v = 0; v < out->const_count; v++) {
                out->const_values[v] = pstrdup(atom.values[v].c_str());
            }
        }
    }

    res->bundle_count = static_cast<int>(bundles.size());
    res->bundles = res->bundle_count ? (PolicyBundleC *)palloc0(sizeof(PolicyBundleC) * res->bundle_count) : nullptr;
    for (int i = 0; i < res->bundle_count; i++) {
        const BundleDef &b = bundles[i];
        PolicyBundleC *outb = &res->bundles[i];
        outb->target_table = pstrdup(b.target.c_str());
        outb->ast = b.ast.empty() ? pstrdup("") : pstrdup(b.ast.c_str());
        outb->atom_count = static_cast<int>(b.atoms.size());
        outb->atoms = outb->atom_count ? (PolicyAtomC *)palloc0(sizeof(PolicyAtomC) * outb->atom_count) : nullptr;
        for (int j = 0; j < outb->atom_count; j++) {
            const Policy::AtomDef &atom = b.atoms[j];
            PolicyAtomC *out = &outb->atoms[j];
            out->atom_id = j + 1;
            out->kind = (atom.kind == Policy::AtomDef::JOIN_EQ) ? POLICY_ATOM_JOIN_EQ : POLICY_ATOM_COL_CONST;
            out->join_class_id = atom.join_class_id;
            out->canon_key = pstrdup(atom.key.c_str());
            if (atom.kind == Policy::AtomDef::JOIN_EQ) {
                std::string lkey = "join:" + atom.left_table + "." + atom.left_col +
                                   " class=" + std::to_string(atom.join_class_id);
                std::string rkey = "join:" + atom.right_table + "." + atom.right_col +
                                   " class=" + std::to_string(atom.join_class_id);
                out->lhs_schema_key = pstrdup(lkey.c_str());
                out->rhs_schema_key = pstrdup(rkey.c_str());
                out->op = 0;
                out->const_count = 0;
                out->const_values = nullptr;
            } else {
                std::string skey = "const:" + atom.left_table + "." + atom.left_col;
                out->lhs_schema_key = pstrdup(skey.c_str());
                out->rhs_schema_key = nullptr;
                out->op = map_const_op(atom.op);
                out->const_count = static_cast<int>(atom.values.size());
                out->const_values = out->const_count ? (char **)palloc0(sizeof(char *) * out->const_count) : nullptr;
                for (int v = 0; v < out->const_count; v++) {
                    out->const_values[v] = pstrdup(atom.values[v].c_str());
                }
            }
        }
    }

    res->target_count = static_cast<int>(target_ast.size());
    res->target_tables = res->target_count ? (char **)palloc0(sizeof(char *) * res->target_count) : nullptr;
    res->target_asts = res->target_count ? (char **)palloc0(sizeof(char *) * res->target_count) : nullptr;
    res->target_perm_asts = res->target_count ? (char **)palloc0(sizeof(char *) * res->target_count) : nullptr;
    res->target_rest_asts = res->target_count ? (char **)palloc0(sizeof(char *) * res->target_count) : nullptr;
    res->target_joinclass_counts = res->target_count ? (int *)palloc0(sizeof(int) * res->target_count) : nullptr;
    res->target_joinclass_offsets = res->target_count ? (int *)palloc0(sizeof(int) * res->target_count) : nullptr;
    res->target_joinclass_ids_len = static_cast<int>(target_jc_ids.size());
    res->target_joinclass_ids = res->target_joinclass_ids_len
                                    ? (int *)palloc0(sizeof(int) * res->target_joinclass_ids_len)
                                    : nullptr;
    for (int i = 0; i < res->target_joinclass_ids_len; i++)
        res->target_joinclass_ids[i] = target_jc_ids[i];
    int t = 0;
    for (auto &kv : target_ast) {
        res->target_tables[t] = pstrdup(kv.first.c_str());
        std::string ast_str = kv.second ? ast_to_string(kv.second) : "";
        res->target_asts[t] = ast_str.empty() ? pstrdup("") : pstrdup(ast_str.c_str());
        AstNode *perm_node = nullptr;
        auto pit = perm_ast.find(kv.first);
        if (pit != perm_ast.end())
            perm_node = pit->second;
        AstNode *rest_node = nullptr;
        auto rit = rest_ast.find(kv.first);
        if (rit != rest_ast.end())
            rest_node = rit->second;
        std::string perm_str = perm_node ? ast_to_string(perm_node) : "";
        std::string rest_str = rest_node ? ast_to_string(rest_node) : "";
        res->target_perm_asts[t] = perm_str.empty() ? pstrdup("") : pstrdup(perm_str.c_str());
        res->target_rest_asts[t] = rest_str.empty() ? pstrdup("") : pstrdup(rest_str.c_str());
        if (res->target_joinclass_counts && t < (int)target_jc_counts.size()) {
            res->target_joinclass_counts[t] = target_jc_counts[t];
            res->target_joinclass_offsets[t] = target_jc_offsets[t];
        }
        if (g_eval_debug) {
            elog(NOTICE, "policy_eval: combined_ast target=%s ast=%s perm_ast=%s rest_ast=%s",
                 kv.first.c_str(), ast_str.c_str(), perm_str.c_str(), rest_str.c_str());
        }
        t++;
    }

    res->ast_node_count = static_cast<int>(store.nodes.size());
    res->ast_nodes = res->ast_node_count ? (void **)palloc0(sizeof(void *) * res->ast_node_count) : nullptr;
    for (int i = 0; i < res->ast_node_count; i++)
        res->ast_nodes[i] = store.nodes[i];

    res->closure_count = static_cast<int>(closure_tables.size());
    res->closure_tables = res->closure_count ? (char **)palloc0(sizeof(char *) * res->closure_count) : nullptr;
    int c = 0;
    for (const auto &tbl : closure_tables)
        res->closure_tables[c++] = pstrdup(tbl.c_str());
    if (g_eval_debug)
        elog(NOTICE, "policy_eval: closure_count=%d", res->closure_count);

    res->scanned_count = static_cast<int>(scanned_list.size());
    res->scanned_tables = res->scanned_count ? (char **)palloc0(sizeof(char *) * res->scanned_count) : nullptr;
    for (int i = 0; i < res->scanned_count; i++)
        res->scanned_tables[i] = pstrdup(scanned_list[i].c_str());

    g_node_store = nullptr;

    return res;
}

PolicyEvalResultC *evaluate_policies_scanned(const char *policy_path,
                                             char **scanned_tables,
                                             int n_scanned) {
    return evaluate_policies_internal(policy_path, scanned_tables, n_scanned, false);
}

PolicyEvalResultC *evaluate_policies_c(const char *query_sql, const char *policy_path) {
    (void) query_sql;
    return evaluate_policies_internal(policy_path, nullptr, 0, true);
}

void free_policy_eval_result(PolicyEvalResultC *res) {
    if (!res) return;
    if (res->needed_files) {
        for (int i = 0; i < res->needed_count; i++) {
            if (res->needed_files[i]) pfree(res->needed_files[i]);
        }
        pfree(res->needed_files);
    }
    if (res->atoms) {
        for (int i = 0; i < res->atom_count; i++) {
            PolicyAtomC *a = &res->atoms[i];
            if (a->canon_key) pfree(a->canon_key);
            if (a->lhs_schema_key) pfree(a->lhs_schema_key);
            if (a->rhs_schema_key) pfree(a->rhs_schema_key);
            if (a->const_values) {
                for (int j = 0; j < a->const_count; j++) {
                    if (a->const_values[j]) pfree(a->const_values[j]);
                }
                pfree(a->const_values);
            }
        }
        pfree(res->atoms);
    }
    if (res->bundles) {
        for (int i = 0; i < res->bundle_count; i++) {
            PolicyBundleC *b = &res->bundles[i];
            if (b->target_table) pfree(b->target_table);
            if (b->ast) pfree(b->ast);
            if (b->atoms) {
                for (int j = 0; j < b->atom_count; j++) {
                    PolicyAtomC *a = &b->atoms[j];
                    if (a->canon_key) pfree(a->canon_key);
                    if (a->lhs_schema_key) pfree(a->lhs_schema_key);
                    if (a->rhs_schema_key) pfree(a->rhs_schema_key);
                    if (a->const_values) {
                        for (int k = 0; k < a->const_count; k++) {
                            if (a->const_values[k]) pfree(a->const_values[k]);
                        }
                        pfree(a->const_values);
                    }
                }
                pfree(b->atoms);
            }
        }
        pfree(res->bundles);
    }
    if (res->target_tables) {
        for (int i = 0; i < res->target_count; i++) {
            if (res->target_tables[i]) pfree(res->target_tables[i]);
        }
        pfree(res->target_tables);
    }
    if (res->target_asts) {
        for (int i = 0; i < res->target_count; i++) {
            if (res->target_asts[i]) pfree(res->target_asts[i]);
        }
        pfree(res->target_asts);
    }
    if (res->target_perm_asts) {
        for (int i = 0; i < res->target_count; i++) {
            if (res->target_perm_asts[i]) pfree(res->target_perm_asts[i]);
        }
        pfree(res->target_perm_asts);
    }
    if (res->target_rest_asts) {
        for (int i = 0; i < res->target_count; i++) {
            if (res->target_rest_asts[i]) pfree(res->target_rest_asts[i]);
        }
        pfree(res->target_rest_asts);
    }
    if (res->target_joinclass_counts)
        pfree(res->target_joinclass_counts);
    if (res->target_joinclass_offsets)
        pfree(res->target_joinclass_offsets);
    if (res->target_joinclass_ids)
        pfree(res->target_joinclass_ids);
    if (res->ast_nodes) {
        for (int i = 0; i < res->ast_node_count; i++) {
            AstNode *n = static_cast<AstNode *>(res->ast_nodes[i]);
            delete n;
        }
        pfree(res->ast_nodes);
    }
    if (res->closure_tables) {
        for (int i = 0; i < res->closure_count; i++) {
            if (res->closure_tables[i]) pfree(res->closure_tables[i]);
        }
        pfree(res->closure_tables);
    }
    if (res->scanned_tables) {
        for (int i = 0; i < res->scanned_count; i++) {
            if (res->scanned_tables[i]) pfree(res->scanned_tables[i]);
        }
        pfree(res->scanned_tables);
    }
    pfree(res);
}

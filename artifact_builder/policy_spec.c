#include "policy_spec.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    TOK_IDENT = 1,
    TOK_STRING,
    TOK_NUMBER,
    TOK_OP,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_COMMA
} TokenType;

typedef struct {
    TokenType type;
    char *text;
} Token;

typedef struct {
    PolicyAtom *items;
    int count;
    int cap;
} AtomList;

static char *str_dup_range(const char *s, size_t n) {
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static void to_lower_inplace(char *s) {
    for (; s && *s; s++) *s = (char)tolower((unsigned char)*s);
}

static char *trim_inplace(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
    return s;
}

static int token_push(Token **arr, int *count, int *cap, Token tok) {
    if (*count >= *cap) {
        int ncap = (*cap == 0) ? 32 : (*cap * 2);
        Token *narr = (Token *)realloc(*arr, sizeof(Token) * ncap);
        if (!narr) return -1;
        *arr = narr;
        *cap = ncap;
    }
    (*arr)[(*count)++] = tok;
    return 0;
}

static int tokenize(const char *s, Token **out_tokens, int *out_count) {
    *out_tokens = NULL;
    *out_count = 0;
    int cap = 0;
    const char *p = s;
    while (*p) {
        if (isspace((unsigned char)*p)) {
            p++;
            continue;
        }
        if (isalpha((unsigned char)*p) || *p == '_') {
            const char *start = p;
            while (isalnum((unsigned char)*p) || *p == '_' || *p == '.') p++;
            char *txt = str_dup_range(start, (size_t)(p - start));
            if (!txt) return -1;
            to_lower_inplace(txt);
            Token t = {TOK_IDENT, txt};
            if (token_push(out_tokens, out_count, &cap, t) != 0) return -1;
            continue;
        }
        if (isdigit((unsigned char)*p) || (*p == '-' && isdigit((unsigned char)p[1]))) {
            const char *start = p;
            p++;
            while (isdigit((unsigned char)*p) || *p == '.') p++;
            char *txt = str_dup_range(start, (size_t)(p - start));
            if (!txt) return -1;
            Token t = {TOK_NUMBER, txt};
            if (token_push(out_tokens, out_count, &cap, t) != 0) return -1;
            continue;
        }
        if (*p == '\'') {
            p++;
            size_t len = 0;
            char *buf = (char *)malloc(strlen(p) + 1);
            if (!buf) return -1;
            while (*p) {
                if (*p == '\'' && p[1] == '\'') {
                    buf[len++] = '\'';
                    p += 2;
                    continue;
                }
                if (*p == '\'') break;
                buf[len++] = *p++;
            }
            if (*p == '\'') p++;
            buf[len] = '\0';
            Token t = {TOK_STRING, buf};
            if (token_push(out_tokens, out_count, &cap, t) != 0) return -1;
            continue;
        }
        if (*p == '(') { Token t = {TOK_LPAREN, str_dup_range("(", 1)}; if (token_push(out_tokens, out_count, &cap, t) != 0) return -1; p++; continue; }
        if (*p == ')') { Token t = {TOK_RPAREN, str_dup_range(")", 1)}; if (token_push(out_tokens, out_count, &cap, t) != 0) return -1; p++; continue; }
        if (*p == ',') { Token t = {TOK_COMMA, str_dup_range(",", 1)}; if (token_push(out_tokens, out_count, &cap, t) != 0) return -1; p++; continue; }
        if (strchr("=<>!", *p)) {
            const char *start = p;
            p++;
            if ((*start == '<' || *start == '>' || *start == '!') && *p == '=') p++;
            else if (*start == '<' && *p == '>') p++;
            char *txt = str_dup_range(start, (size_t)(p - start));
            if (!txt) return -1;
            Token t = {TOK_OP, txt};
            if (token_push(out_tokens, out_count, &cap, t) != 0) return -1;
            continue;
        }
        p++;
    }
    return 0;
}

static void free_tokens(Token *toks, int ntok) {
    if (!toks) return;
    for (int i = 0; i < ntok; i++) {
        free(toks[i].text);
    }
    free(toks);
}

static int atom_push(AtomList *list, const PolicyAtom *atom) {
    if (list->count >= list->cap) {
        int ncap = (list->cap == 0) ? 16 : (list->cap * 2);
        PolicyAtom *nitems = (PolicyAtom *)realloc(list->items, sizeof(PolicyAtom) * ncap);
        if (!nitems) return -1;
        list->items = nitems;
        list->cap = ncap;
    }
    list->items[list->count++] = *atom;
    return 0;
}

static int copy_str(char *dst, size_t dstsz, const char *src) {
    if (!dst || dstsz == 0) return -1;
    if (!src) { dst[0] = '\0'; return 0; }
    size_t n = strlen(src);
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

static int parse_column(const char *ident, const char *target,
                        char *out_table, size_t out_table_sz,
                        char *out_col, size_t out_col_sz) {
    const char *dot = strrchr(ident, '.');
    if (dot) {
        size_t tlen = (size_t)(dot - ident);
        char *tmp = str_dup_range(ident, tlen);
        if (!tmp) return -1;
        to_lower_inplace(tmp);
        copy_str(out_table, out_table_sz, tmp);
        free(tmp);
        copy_str(out_col, out_col_sz, dot + 1);
        return 0;
    }
    copy_str(out_table, out_table_sz, target);
    copy_str(out_col, out_col_sz, ident);
    return 0;
}

static int is_keyword(const Token *t, const char *kw) {
    return t && t->type == TOK_IDENT && t->text && strcmp(t->text, kw) == 0;
}

static int is_column_ident(const Token *t) {
    if (!t || t->type != TOK_IDENT || !t->text) return 0;
    if (strcmp(t->text, "and") == 0) return 0;
    if (strcmp(t->text, "or") == 0) return 0;
    if (strcmp(t->text, "in") == 0) return 0;
    if (strcmp(t->text, "like") == 0) return 0;
    return 1;
}

static int parse_policy_atoms(const char *target, Token *toks, int ntok, AtomList *out) {
    for (int i = 0; i < ntok; i++) {
        if (toks[i].type != TOK_IDENT) continue;
        if (!is_column_ident(&toks[i])) continue;

        if (i + 1 < ntok && toks[i + 1].type == TOK_OP) {
            const char *op = toks[i + 1].text;
            if (i + 2 < ntok && toks[i + 2].type == TOK_IDENT) {
                if (!is_column_ident(&toks[i + 2])) continue;
                if (strcmp(op, "=") == 0) {
                    PolicyAtom a;
                    memset(&a, 0, sizeof(a));
                    a.type = ATOM_JOIN_EQ;
                    if (parse_column(toks[i].text, target,
                                     a.lhs_table, sizeof(a.lhs_table),
                                     a.lhs_col, sizeof(a.lhs_col)) != 0)
                        return -1;
                    if (parse_column(toks[i + 2].text, target,
                                     a.rhs_table, sizeof(a.rhs_table),
                                     a.rhs_col, sizeof(a.rhs_col)) != 0)
                        return -1;
                    copy_str(a.op, sizeof(a.op), "=");
                    if (atom_push(out, &a) != 0) return -1;
                    continue;
                }
            } else if (i + 2 < ntok &&
                       (toks[i + 2].type == TOK_STRING || toks[i + 2].type == TOK_NUMBER)) {
                PolicyAtom a;
                memset(&a, 0, sizeof(a));
                a.type = ATOM_COL_CONST;
                if (parse_column(toks[i].text, target,
                                 a.lhs_table, sizeof(a.lhs_table),
                                 a.lhs_col, sizeof(a.lhs_col)) != 0)
                    return -1;
                copy_str(a.op, sizeof(a.op), op);
                copy_str(a.literal, sizeof(a.literal), toks[i + 2].text);
                if (atom_push(out, &a) != 0) return -1;
                continue;
            }
        }

        if (i + 1 < ntok && is_keyword(&toks[i + 1], "in")) {
            PolicyAtom a;
            memset(&a, 0, sizeof(a));
            a.type = ATOM_COL_CONST;
            if (parse_column(toks[i].text, target,
                             a.lhs_table, sizeof(a.lhs_table),
                             a.lhs_col, sizeof(a.lhs_col)) != 0)
                return -1;
            copy_str(a.op, sizeof(a.op), "in");
            if (atom_push(out, &a) != 0) return -1;
            // advance to closing paren of the IN list (do not skip outer parens)
            int depth = 0;
            for (int j = i + 2; j < ntok; j++) {
                if (toks[j].type == TOK_LPAREN) {
                    depth++;
                    continue;
                }
                if (toks[j].type == TOK_RPAREN) {
                    if (depth <= 1) { i = j; break; }
                    depth--;
                }
            }
            continue;
        }

        if (i + 1 < ntok && is_keyword(&toks[i + 1], "like") &&
            i + 2 < ntok && toks[i + 2].type == TOK_STRING) {
            PolicyAtom a;
            memset(&a, 0, sizeof(a));
            a.type = ATOM_COL_CONST;
            if (parse_column(toks[i].text, target,
                             a.lhs_table, sizeof(a.lhs_table),
                             a.lhs_col, sizeof(a.lhs_col)) != 0)
                return -1;
            copy_str(a.op, sizeof(a.op), "like");
            copy_str(a.literal, sizeof(a.literal), toks[i + 2].text);
            if (atom_push(out, &a) != 0) return -1;
            continue;
        }
    }
    return 0;
}

int parse_policy_file(const char *policy_path, PolicySet *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(policy_path, "r");
    if (!fp) return -1;

    char linebuf[4096];
    while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
        char *line = trim_inplace(linebuf);
        if (*line == '\0') continue;
        if (*line == '#') continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *left = trim_inplace(line);
        char *right = trim_inplace(colon + 1);

        size_t pos = 0;
        while (left[pos] &&
               (isdigit((unsigned char)left[pos]) || left[pos] == '.' || isspace((unsigned char)left[pos])))
            pos++;
        left += pos;
        if (*left == '\0' || *right == '\0') continue;

        char target[POLICY_SPEC_MAX_NAME];
        copy_str(target, sizeof(target), left);
        to_lower_inplace(target);

        Token *toks = NULL;
        int ntok = 0;
        if (tokenize(right, &toks, &ntok) != 0) {
            free_tokens(toks, ntok);
            fclose(fp);
            free_policy_set(out);
            return -1;
        }

        AtomList atoms = {0};
        if (parse_policy_atoms(target, toks, ntok, &atoms) != 0) {
            free_tokens(toks, ntok);
            fclose(fp);
            free_policy_set(out);
            return -1;
        }
        free_tokens(toks, ntok);

        Policy pol;
        memset(&pol, 0, sizeof(pol));
        copy_str(pol.target_table, sizeof(pol.target_table), target);
        pol.atom_count = atoms.count;
        pol.atoms = atoms.items;

        if (out->policy_count == 0) {
            out->policies = (Policy *)malloc(sizeof(Policy));
            if (!out->policies) { fclose(fp); free_policy_set(out); return -1; }
            out->policy_count = 1;
            out->policies[0] = pol;
        } else {
            int n = out->policy_count + 1;
            Policy *np = (Policy *)realloc(out->policies, sizeof(Policy) * n);
            if (!np) { fclose(fp); free_policy_set(out); return -1; }
            out->policies = np;
            out->policies[out->policy_count] = pol;
            out->policy_count = n;
        }
    }
    fclose(fp);
    return 0;
}

void free_policy_set(PolicySet *ps) {
    if (!ps) return;
    if (ps->policies) {
        for (int i = 0; i < ps->policy_count; i++) {
            if (ps->policies[i].atoms)
                free(ps->policies[i].atoms);
        }
        free(ps->policies);
    }
    ps->policies = NULL;
    ps->policy_count = 0;
}

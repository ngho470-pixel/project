#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLICY_ATOM_JOIN_EQ = 1,
    POLICY_ATOM_COL_CONST = 2
} PolicyAtomKindC;

typedef enum {
    POLICY_OP_EQ = 1,
    POLICY_OP_IN = 2,
    POLICY_OP_LIKE = 3,
    POLICY_OP_LT = 4,
    POLICY_OP_LE = 5,
    POLICY_OP_GT = 6,
    POLICY_OP_GE = 7,
    POLICY_OP_NE = 8
} PolicyConstOpC;

typedef struct PolicyAtomC {
    int atom_id;                 /* y1..yk */
    int kind;                    /* PolicyAtomKindC */
    int join_class_id;           /* for JOIN_EQ or const on join column; -1 otherwise */
    char *canon_key;             /* canonical key (table.col|op|values or join eq) */
    char *lhs_schema_key;        /* join:table.col class=J or const:table.col */
    char *rhs_schema_key;        /* join:table.col class=J (JOIN_EQ only) */
    int op;                      /* PolicyConstOpC for COL_CONST */
    int const_count;
    char **const_values;         /* unquoted literal strings */
} PolicyAtomC;

typedef struct PolicyEngineInputC {
    int target_count;
    char **target_tables;
    char **target_asts;
    char **target_perm_asts;
    char **target_rest_asts;
    int atom_count;
    PolicyAtomC *atoms;
} PolicyEngineInputC;

typedef struct PolicyBundleC {
    char *target_table;
    char *ast;
    int atom_count;
    PolicyAtomC *atoms;
} PolicyBundleC;

typedef struct PolicyEvalResultC {
    int needed_count;
    char **needed_files;
    int target_count;
    char **target_tables;
    char **target_asts;
    char **target_perm_asts;
    char **target_rest_asts;
    int *target_joinclass_counts;
    int *target_joinclass_offsets;
    int *target_joinclass_ids;
    int target_joinclass_ids_len;
    int atom_count;
    PolicyAtomC *atoms;
    int bundle_count;
    PolicyBundleC *bundles;
    int ast_node_count;
    void **ast_nodes;
    int closure_count;
    char **closure_tables;
    int scanned_count;
    char **scanned_tables;
} PolicyEvalResultC;

PolicyEvalResultC *evaluate_policies_scanned(const char *policy_path,
                                             char **scanned_tables,
                                             int n_scanned);
PolicyEvalResultC *evaluate_policies_c(const char *query_sql, const char *policy_path);
void free_policy_eval_result(PolicyEvalResultC *res);

#ifdef __cplusplus
}
#endif

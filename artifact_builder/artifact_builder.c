#include "postgres.h"
#include "fmgr.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "lib/stringinfo.h"
#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "artifact_builder.hpp"
#include "policy_spec.h"

PG_MODULE_MAGIC;

#define FETCH_BATCH 10000

typedef struct {
    char *table;
    char *column;
} ABColumnRef;

typedef struct {
    ABColumnRef *items;
    int count;
    int cap;
} ColumnList;

typedef struct {
    char **items;
    int count;
    int cap;
} StringList;

typedef struct {
    int a;
    int b;
} JoinPair;

typedef struct {
    int *items;
    int count;
    int cap;
} IntList;

typedef struct {
    int id;
    IntList cols;
    char tmp_name[NAMEDATALEN];
} JoinClass;

typedef struct {
    int col_idx;
    int is_join;
    int join_class_id;
    char tmp_dict_name[NAMEDATALEN];
} TokenColumn;

typedef struct {
    ABColumnRef col;
    char tmp_name[NAMEDATALEN];
} ConstColumn;

static void str_list_add_unique(StringList *list, const char *value) {
    for (int i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) {
            return;
        }
    }
    if (list->count == list->cap) {
        int newcap = list->cap == 0 ? 8 : list->cap * 2;
        if (list->items) {
            list->items = (char **)repalloc(list->items, newcap * sizeof(char *));
        } else {
            list->items = (char **)palloc(newcap * sizeof(char *));
        }
        list->cap = newcap;
    }
    list->items[list->count++] = pstrdup(value);
}

static int column_index(const ColumnList *cols, const char *table, const char *col) {
    for (int i = 0; i < cols->count; i++) {
        if (strcmp(cols->items[i].table, table) == 0 && strcmp(cols->items[i].column, col) == 0) {
            return i;
        }
    }
    return -1;
}

static int column_add_unique(ColumnList *cols, const char *table, const char *col) {
    int idx = column_index(cols, table, col);
    if (idx >= 0) return idx;
    if (cols->count == cols->cap) {
        int newcap = cols->cap == 0 ? 16 : cols->cap * 2;
        if (cols->items) {
            cols->items = (ABColumnRef *)repalloc(cols->items, newcap * sizeof(ABColumnRef));
        } else {
            cols->items = (ABColumnRef *)palloc(newcap * sizeof(ABColumnRef));
        }
        cols->cap = newcap;
    }
    cols->items[cols->count].table = pstrdup(table);
    cols->items[cols->count].column = pstrdup(col);
    return cols->count++;
}

static bool parse_schema_key_simple(const char *key, char **out_table, char **out_col) {
    if (!key || !out_table || !out_col) return false;
    const char *p = strchr(key, ':');
    if (!p) return false;
    p++;
    const char *end = strchr(p, ' ');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    const char *dot = memchr(p, '.', len);
    if (!dot) return false;
    size_t tlen = (size_t)(dot - p);
    size_t clen = len - tlen - 1;
    *out_table = pnstrdup(p, (int)tlen);
    *out_col = pnstrdup(dot + 1, (int)clen);
    return true;
}

static void int_list_add(IntList *list, int value) {
    if (list->count == list->cap) {
        int newcap = list->cap == 0 ? 8 : list->cap * 2;
        if (list->items) {
            list->items = (int *)repalloc(list->items, newcap * sizeof(int));
        } else {
            list->items = (int *)palloc(newcap * sizeof(int));
        }
        list->cap = newcap;
    }
    list->items[list->count++] = value;
}


static void sort_string_list(StringList *list) {
    if (!list || list->count <= 1) return;
    for (int i = 0; i < list->count; i++) {
        for (int j = i + 1; j < list->count; j++) {
            if (strcmp(list->items[i], list->items[j]) > 0) {
                char *tmp = list->items[i];
                list->items[i] = list->items[j];
                list->items[j] = tmp;
            }
        }
    }
}

static void sort_columns_by_name(const ColumnList *cols, IntList *idxs) {
    if (!cols || !idxs || idxs->count <= 1) return;
    for (int i = 0; i < idxs->count; i++) {
        for (int j = i + 1; j < idxs->count; j++) {
            int ai = idxs->items[i];
            int bi = idxs->items[j];
            int cmp = strcmp(cols->items[ai].table, cols->items[bi].table);
            if (cmp == 0) cmp = strcmp(cols->items[ai].column, cols->items[bi].column);
            if (cmp > 0) {
                int tmp = idxs->items[i];
                idxs->items[i] = idxs->items[j];
                idxs->items[j] = tmp;
            }
        }
    }
}

static bytea *cstring_to_bytea(const char *s) {
    if (!s) s = "";
    int len = (int)strlen(s);
    bytea *ba = (bytea *)palloc(VARHDRSZ + len);
    SET_VARSIZE(ba, VARHDRSZ + len);
    if (len > 0) memcpy(VARDATA(ba), s, len);
    return ba;
}

static void insert_file(const char *name, bytea *data) {
    Oid argtypes[2] = {TEXTOID, BYTEAOID};
    Datum values[2];
    char nulls[2] = {' ', ' '};
    values[0] = CStringGetTextDatum(name);
    values[1] = PointerGetDatum(data);
    int ret = SPI_execute_with_args(
        "INSERT INTO public.files (name, file) VALUES ($1, $2)",
        2, argtypes, values, nulls, false, 0);
    if (ret != SPI_OK_INSERT)
        ereport(ERROR, (errmsg("failed to insert file %s", name)));
}

static void insert_file_text(const char *name, const char *text) {
    bytea *ba = cstring_to_bytea(text);
    insert_file(name, ba);
}

static const char *dict_type_for_col(const char *table, const char *col) {
    if (!table || !col) return "text";
    Oid argtypes[2] = {TEXTOID, TEXTOID};
    Datum values[2];
    char nulls[2] = {' ', ' '};
    values[0] = CStringGetTextDatum(table);
    values[1] = CStringGetTextDatum(col);
    int ret = SPI_execute_with_args(
        "SELECT t.typname, t.typcategory "
        "FROM pg_attribute a "
        "JOIN pg_class c ON c.oid = a.attrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN pg_type t ON t.oid = a.atttypid "
        "WHERE c.relname = $1 AND a.attname = $2 "
        "AND a.attnum > 0 AND NOT a.attisdropped "
        "AND n.nspname = 'public'",
        2, argtypes, values, nulls, true, 0);
    if (ret != SPI_OK_SELECT || SPI_processed == 0) {
        return "text";
    }
    SPITupleTable *tuptable = SPI_tuptable;
    TupleDesc tupdesc = tuptable->tupdesc;
    char *typname = SPI_getvalue(tuptable->vals[0], tupdesc, 1);
    char *typcat = SPI_getvalue(tuptable->vals[0], tupdesc, 2);
    const char *out = "text";
    if (typname && (strcmp(typname, "int2") == 0 ||
                    strcmp(typname, "int4") == 0 ||
                    strcmp(typname, "int8") == 0)) {
        out = "int";
    } else if (typcat && typcat[0] == 'N') {
        out = "float";
    } else {
        out = "text";
    }
    if (typname) pfree(typname);
    if (typcat) pfree(typcat);
    return out;
}

static void write_dict_from_tmp(const char *name, const char *tmp_table) {
    StringInfoData sql;
    initStringInfo(&sql);
    appendStringInfo(&sql, "SELECT val FROM %s ORDER BY tok", quote_identifier(tmp_table));
    SPIPlanPtr plan = SPI_prepare(sql.data, 0, NULL);
    if (!plan) ereport(ERROR, (errmsg("SPI_prepare failed for dict %s", tmp_table)));
    Portal portal = SPI_cursor_open(NULL, plan, NULL, NULL, false);
    if (!portal) ereport(ERROR, (errmsg("SPI_cursor_open failed for dict %s", tmp_table)));

    ByteaBuilder *bb = bb_create();
    while (true) {
        SPI_cursor_fetch(portal, true, FETCH_BATCH);
        if (SPI_processed == 0) break;
        SPITupleTable *tuptable = SPI_tuptable;
        TupleDesc tupdesc = tuptable->tupdesc;
        for (uint64 r = 0; r < SPI_processed; r++) {
            char *val = SPI_getvalue(tuptable->vals[r], tupdesc, 1);
            int32 len = val ? (int32)strlen(val) : 0;
            bb_append_int32(bb, len);
            if (len > 0) {
                bb_append_bytes(bb, val, (size_t)len);
                pfree(val);
            }
        }
    }
    SPI_cursor_close(portal);
    insert_file(name, bb_to_bytea(bb));
    bb_free(bb);
}

Datum build_base(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(build_base);

Datum build_base(PG_FUNCTION_ARGS) {
    if (PG_NARGS() < 1 || PG_ARGISNULL(0)) {
        ereport(ERROR, (errmsg("build_base requires policy path")));
    }
    const char *path = text_to_cstring(PG_GETARG_TEXT_PP(0));

    ColumnList cols = {0};
    ColumnList const_cols_list = {0};
    StringList tables = {0};

    PolicySet ps;
    memset(&ps, 0, sizeof(ps));
    if (parse_policy_file(path, &ps) != 0) {
        ereport(ERROR, (errmsg("failed to parse policies at %s", path)));
    }

    if (SPI_connect() != SPI_OK_CONNECT) {
        ereport(ERROR, (errmsg("SPI_connect failed")));
    }
    SPI_execute("SET LOCAL search_path TO public, pg_catalog", false, 0);
    SPI_execute("CREATE TABLE IF NOT EXISTS public.files (name text, file bytea)", false, 0);

    int join_atom_count = 0;
    int *col_class = NULL;
    int col_class_cap = 0;
    int *join_left = NULL;
    int *join_right = NULL;
    int join_cap = 0;
    int join_count = 0;

    for (int p = 0; p < ps.policy_count; p++) {
        Policy *pol = &ps.policies[p];
        if (pol->target_table[0] != '\0')
            str_list_add_unique(&tables, pol->target_table);
        for (int i = 0; i < pol->atom_count; i++) {
            PolicyAtom *a = &pol->atoms[i];
            if (a->lhs_table[0] == '\0' || a->lhs_col[0] == '\0')
                continue;
            int lidx = column_add_unique(&cols, a->lhs_table, a->lhs_col);
            str_list_add_unique(&tables, a->lhs_table);
            if (a->type == ATOM_COL_CONST) {
                column_add_unique(&const_cols_list, a->lhs_table, a->lhs_col);
            }
            if (a->type == ATOM_JOIN_EQ) {
                if (a->rhs_table[0] == '\0' || a->rhs_col[0] == '\0')
                    ereport(ERROR, (errmsg("join atom missing rhs table/col")));
                int ridx = column_add_unique(&cols, a->rhs_table, a->rhs_col);
                str_list_add_unique(&tables, a->rhs_table);
                join_atom_count++;
                if (join_count >= join_cap) {
                    int newcap = join_cap == 0 ? 32 : join_cap * 2;
                    join_left = join_left ? (int *)repalloc(join_left, sizeof(int) * newcap)
                                          : (int *)palloc(sizeof(int) * newcap);
                    join_right = join_right ? (int *)repalloc(join_right, sizeof(int) * newcap)
                                            : (int *)palloc(sizeof(int) * newcap);
                    join_cap = newcap;
                }
                join_left[join_count] = lidx;
                join_right[join_count] = ridx;
                join_count++;
            }
        }
    }

    // Ensure const dicts are created for any const atom column, regardless of target.
    for (int p = 0; p < ps.policy_count; p++) {
        Policy *pol = &ps.policies[p];
        for (int i = 0; i < pol->atom_count; i++) {
            PolicyAtom *a = &pol->atoms[i];
            if (a->type != ATOM_COL_CONST) continue;
            if (a->lhs_table[0] == '\0' || a->lhs_col[0] == '\0')
                continue;
            column_add_unique(&const_cols_list, a->lhs_table, a->lhs_col);
            str_list_add_unique(&tables, a->lhs_table);
        }
    }

    sort_string_list(&tables);

    int ncols = cols.count;
    bool *is_join_col = (bool *)palloc0(sizeof(bool) * ncols);
    int nclasses = 0;
    JoinClass *classes = NULL;

    if (join_atom_count > 0) {
        int *parent = (int *)palloc(sizeof(int) * ncols);
        for (int i = 0; i < ncols; i++) parent[i] = i;
        for (int i = 0; i < join_count; i++) {
            int li = join_left[i];
            int ri = join_right[i];
            is_join_col[li] = true;
            is_join_col[ri] = true;
            int a = li, b = ri;
            while (parent[a] != a) a = parent[a];
            while (parent[b] != b) b = parent[b];
            if (a != b) parent[b] = a;
        }

        int *root_map = (int *)palloc(sizeof(int) * ncols);
        for (int i = 0; i < ncols; i++) root_map[i] = -1;

        typedef struct {
            int root;
            IntList cols;
            char *key;
        } JoinClassTmp;

        JoinClassTmp *tmp = (JoinClassTmp *)palloc0(sizeof(JoinClassTmp) * ncols);
        int tmp_count = 0;
        for (int i = 0; i < ncols; i++) {
            if (!is_join_col[i]) continue;
            int r = i;
            while (parent[r] != r) r = parent[r];
            int idx = root_map[r];
            if (idx < 0) {
                idx = tmp_count++;
                root_map[r] = idx;
                tmp[idx].root = r;
            }
            int_list_add(&tmp[idx].cols, i);
        }

        ColumnList *g_cols = &cols;
        for (int i = 0; i < tmp_count; i++) {
            int n = tmp[i].cols.count;
            if (n > 1) {
                for (int a = 0; a < n; a++) {
                    for (int b = a + 1; b < n; b++) {
                        int ia = tmp[i].cols.items[a];
                        int ib = tmp[i].cols.items[b];
                        ABColumnRef *ca = &g_cols->items[ia];
                        ABColumnRef *cb = &g_cols->items[ib];
                        int cmp = strcmp(ca->table, cb->table);
                        if (cmp == 0) cmp = strcmp(ca->column, cb->column);
                        if (cmp > 0) {
                            int t = tmp[i].cols.items[a];
                            tmp[i].cols.items[a] = tmp[i].cols.items[b];
                            tmp[i].cols.items[b] = t;
                        }
                    }
                }
            }
            StringInfoData key;
            initStringInfo(&key);
            for (int j = 0; j < tmp[i].cols.count; j++) {
                ABColumnRef *c = &g_cols->items[tmp[i].cols.items[j]];
                if (j > 0) appendStringInfoChar(&key, ',');
                appendStringInfo(&key, "%s.%s", c->table, c->column);
            }
            tmp[i].key = pstrdup(key.data);
        }

        for (int i = 0; i < tmp_count; i++) {
            for (int j = i + 1; j < tmp_count; j++) {
                if (strcmp(tmp[i].key, tmp[j].key) > 0) {
                    JoinClassTmp t = tmp[i];
                    tmp[i] = tmp[j];
                    tmp[j] = t;
                }
            }
        }

        nclasses = tmp_count;
        if (nclasses > 0) {
            classes = (JoinClass *)palloc0(sizeof(JoinClass) * nclasses);
            for (int i = 0; i < nclasses; i++) classes[i].id = i;
            for (int i = 0; i < nclasses; i++) {
                for (int j = 0; j < tmp[i].cols.count; j++) {
                    int col_idx = tmp[i].cols.items[j];
                    int_list_add(&classes[i].cols, col_idx);
                }
            }
        }
    }
    if (ncols > 0) {
        col_class_cap = ncols;
        col_class = (int *)palloc0(sizeof(int) * col_class_cap);
        for (int i = 0; i < col_class_cap; i++) col_class[i] = -1;
        for (int i = 0; i < nclasses; i++) {
            for (int j = 0; j < classes[i].cols.count; j++) {
                int col_idx = classes[i].cols.items[j];
                if (col_idx >= 0 && col_idx < col_class_cap)
                    col_class[col_idx] = i;
            }
        }
    }
    if (join_atom_count > 0 && nclasses <= 0)
        ereport(ERROR, (errmsg("join atoms present but no join classes")));
    if (join_atom_count > 0) {
        int join_col_total = 0;
        for (int i = 0; i < nclasses; i++)
            join_col_total += classes[i].cols.count;
        if (join_col_total <= 0)
            ereport(ERROR, (errmsg("join atoms present but join classes empty")));
    }

    // meta/tables
    {
        StringInfoData buf;
        initStringInfo(&buf);
        for (int i = 0; i < tables.count; i++) {
            appendStringInfoString(&buf, tables.items[i]);
            appendStringInfoChar(&buf, '\n');
        }
        insert_file_text("meta/tables", buf.data);
    }

    // meta/join_classes
    {
        StringInfoData buf;
        initStringInfo(&buf);
        for (int i = 0; i < nclasses; i++) {
            appendStringInfo(&buf, "class=%d cols=", i);
            // sort members by table.col
            for (int j = 0; j < classes[i].cols.count; j++) {
                for (int k = j + 1; k < classes[i].cols.count; k++) {
                    int ai = classes[i].cols.items[j];
                    int bi = classes[i].cols.items[k];
                    int cmp = strcmp(cols.items[ai].table, cols.items[bi].table);
                    if (cmp == 0) cmp = strcmp(cols.items[ai].column, cols.items[bi].column);
                    if (cmp > 0) {
                        int tmp = classes[i].cols.items[j];
                        classes[i].cols.items[j] = classes[i].cols.items[k];
                        classes[i].cols.items[k] = tmp;
                    }
                }
            }
            for (int j = 0; j < classes[i].cols.count; j++) {
                int col_idx = classes[i].cols.items[j];
                if (j > 0) appendStringInfoString(&buf, ",");
                appendStringInfo(&buf, "%s.%s", cols.items[col_idx].table, cols.items[col_idx].column);
            }
            appendStringInfoChar(&buf, '\n');
        }
        insert_file_text("meta/join_classes", buf.data);
    }

    free_policy_set(&ps);

    // Create temp tables for join classes
    for (int i = 0; i < nclasses; i++) {
        snprintf(classes[i].tmp_name, sizeof(classes[i].tmp_name), "tmp_jc_%d", i);
        StringInfoData sql;
        initStringInfo(&sql);
        appendStringInfo(&sql, "DROP TABLE IF EXISTS %s", quote_identifier(classes[i].tmp_name));
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
        resetStringInfo(&sql);
        appendStringInfo(&sql,
                         "CREATE TEMP TABLE %s (val text, tok int)",
                         quote_identifier(classes[i].tmp_name));
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
        resetStringInfo(&sql);
        appendStringInfo(&sql,
                         "INSERT INTO %s "
                         "SELECT val, (row_number() OVER (ORDER BY sortval)-1)::int AS tok FROM (",
                         quote_identifier(classes[i].tmp_name));
        for (int j = 0; j < classes[i].cols.count; j++) {
            int col_idx = classes[i].cols.items[j];
            char *table = cols.items[col_idx].table;
            char *col = cols.items[col_idx].column;
            if (j > 0) appendStringInfoString(&sql, " UNION ");
            appendStringInfo(&sql,
                             "SELECT DISTINCT %s AS sortval, %s::text AS val FROM %s WHERE %s IS NOT NULL",
                             quote_identifier(col), quote_identifier(col),
                             quote_identifier(table), quote_identifier(col));
        }
        appendStringInfoString(&sql, ") s");
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
    }

    
    
    // Const columns temp dicts (for tokenization)
    ConstColumn *const_cols = (ConstColumn *)palloc0(sizeof(ConstColumn) * const_cols_list.count);
    int n_const = 0;
    for (int i = 0; i < const_cols_list.count; i++) {
        const_cols[n_const].col = const_cols_list.items[i];
        snprintf(const_cols[n_const].tmp_name, sizeof(const_cols[n_const].tmp_name),
                 "tmp_dict_%d", n_const);
        n_const++;
    }
    for (int i = 0; i < n_const; i++) {
        StringInfoData sql;
        initStringInfo(&sql);
        appendStringInfo(&sql, "DROP TABLE IF EXISTS %s", quote_identifier(const_cols[i].tmp_name));
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
        resetStringInfo(&sql);
        appendStringInfo(&sql,
                         "CREATE TEMP TABLE %s (val text, tok int)",
                         quote_identifier(const_cols[i].tmp_name));
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
        resetStringInfo(&sql);
        appendStringInfo(&sql,
                         "INSERT INTO %s "
                         "SELECT val, (row_number() OVER (ORDER BY sortval)-1)::int AS tok FROM ("
                         "SELECT DISTINCT %s AS sortval, %s::text AS val FROM %s WHERE %s IS NOT NULL"
                         ") s",
                         quote_identifier(const_cols[i].tmp_name),
                         quote_identifier(const_cols[i].col.column),
                         quote_identifier(const_cols[i].col.column),
                         quote_identifier(const_cols[i].col.table),
                         quote_identifier(const_cols[i].col.column));
        SPI_execute(sql.data, false, 0);
        CommandCounterIncrement();
    }

// meta/cols/<table> and table artifacts
    for (int ti = 0; ti < tables.count; ti++) {
        char *table = tables.items[ti];
        IntList join_cols = {0};
        IntList const_cols_idx = {0};
        for (int i = 0; i < ncols; i++) {
            if (strcmp(cols.items[i].table, table) != 0) continue;
            if (is_join_col[i]) int_list_add(&join_cols, i);
            else int_list_add(&const_cols_idx, i);
        }
        sort_columns_by_name(&cols, &join_cols);
        sort_columns_by_name(&cols, &const_cols_idx);

        // write meta/cols/<table>
        {
            StringInfoData buf;
            initStringInfo(&buf);
            for (int i = 0; i < join_cols.count; i++) {
                int col_idx = join_cols.items[i];
                appendStringInfo(&buf, "%s.%s\n", cols.items[col_idx].table, cols.items[col_idx].column);
            }
            for (int i = 0; i < const_cols_idx.count; i++) {
                int col_idx = const_cols_idx.items[i];
                appendStringInfo(&buf, "%s.%s\n", cols.items[col_idx].table, cols.items[col_idx].column);
            }
            char name[NAMEDATALEN * 2];
            snprintf(name, sizeof(name), "meta/cols/%s", table);
            insert_file_text(name, buf.data);
        }

        int token_count = join_cols.count + const_cols_idx.count;
        TokenColumn *tokcols = (TokenColumn *)palloc0(sizeof(TokenColumn) * token_count);
        int tpos = 0;
        for (int i = 0; i < join_cols.count; i++) {
            int col_idx = join_cols.items[i];
            int cid = (col_class && col_idx < col_class_cap) ? col_class[col_idx] : -1;
            if (cid < 0)
                ereport(ERROR, (errmsg("missing join class id for %s.%s",
                                       cols.items[col_idx].table, cols.items[col_idx].column)));
            tokcols[tpos].col_idx = col_idx;
            tokcols[tpos].is_join = 1;
            tokcols[tpos].join_class_id = cid;
            tpos++;
        }
        for (int i = 0; i < const_cols_idx.count; i++) {
            int col_idx = const_cols_idx.items[i];
            tokcols[tpos].col_idx = col_idx;
            tokcols[tpos].is_join = 0;
            tokcols[tpos].join_class_id = -1;
            for (int j = 0; j < const_cols_list.count; j++) {
                if (strcmp(const_cols[j].col.table, cols.items[col_idx].table) == 0 &&
                    strcmp(const_cols[j].col.column, cols.items[col_idx].column) == 0) {
                    strncpy(tokcols[tpos].tmp_dict_name, const_cols[j].tmp_name, NAMEDATALEN);
                    break;
                }
            }
            tpos++;
        }

        StringInfoData sql;
        initStringInfo(&sql);
        appendStringInfo(&sql, "SELECT %s.ctid", quote_identifier(table));
        for (int i = 0; i < token_count; i++) {
            appendStringInfo(&sql, ", t%d.tok", i);
        }
        appendStringInfo(&sql, " FROM %s", quote_identifier(table));
        for (int i = 0; i < token_count; i++) {
            int col_idx = tokcols[i].col_idx;
            char *colname = cols.items[col_idx].column;
            if (tokcols[i].is_join) {
                char *tmp = classes[tokcols[i].join_class_id].tmp_name;
                appendStringInfo(&sql, " LEFT JOIN %s t%d ON t%d.val = %s.%s::text",
                                 quote_identifier(tmp), i, i,
                                 quote_identifier(table), quote_identifier(colname));
            } else {
                appendStringInfo(&sql, " LEFT JOIN %s t%d ON t%d.val = %s.%s::text",
                                 quote_identifier(tokcols[i].tmp_dict_name), i, i,
                                 quote_identifier(table), quote_identifier(colname));
            }
        }
        appendStringInfo(&sql, " ORDER BY %s.ctid", quote_identifier(table));

        SPIPlanPtr plan = SPI_prepare(sql.data, 0, NULL);
        if (!plan) ereport(ERROR, (errmsg("SPI_prepare failed for table %s", table)));
        Portal portal = SPI_cursor_open(NULL, plan, NULL, NULL, false);
        if (!portal) ereport(ERROR, (errmsg("SPI_cursor_open failed for table %s", table)));

        ByteaBuilder *ctid_bb = bb_create();
        ByteaBuilder *code_bb = bb_create();
        int64 rid = 0;
        while (true) {
            SPI_cursor_fetch(portal, true, FETCH_BATCH);
            if (SPI_processed == 0) break;
            SPITupleTable *tuptable = SPI_tuptable;
            TupleDesc tupdesc = tuptable->tupdesc;
            for (uint64 r = 0; r < SPI_processed; r++) {
                HeapTuple tuple = tuptable->vals[r];
                bool isnull;
                Datum ctid_d = SPI_getbinval(tuple, tupdesc, 1, &isnull);
                if (isnull) continue;
                ItemPointerData *ip = DatumGetItemPointer(ctid_d);
                int32 blk = (int32)ItemPointerGetBlockNumber(ip);
                int32 off = (int32)ItemPointerGetOffsetNumber(ip);
                bb_append_int32(ctid_bb, blk);
                bb_append_int32(ctid_bb, off);

                bb_append_int32(code_bb, (int32)rid);
                for (int i = 0; i < token_count; i++) {
                    Datum tok = SPI_getbinval(tuple, tupdesc, 2 + i, &isnull);
                    int32 tval = isnull ? -1 : DatumGetInt32(tok);
                    bb_append_int32(code_bb, tval);
                }
                rid++;
            }
        }
        SPI_cursor_close(portal);

        char name_ctid[NAMEDATALEN];
        char name_code[NAMEDATALEN * 2];
        snprintf(name_ctid, sizeof(name_ctid), "%s_ctid", table);
        snprintf(name_code, sizeof(name_code), "%s_code_base", table);
        insert_file(name_ctid, bb_to_bytea(ctid_bb));
        insert_file(name_code, bb_to_bytea(code_bb));
        bb_free(ctid_bb);
        bb_free(code_bb);
    }

    // write dict/<T>/<col> only for const columns using the tmp dicts (token order)
    for (int i = 0; i < n_const; i++) {
        char name[NAMEDATALEN * 3];
        const char *table = const_cols[i].col.table;
        const char *col = const_cols[i].col.column;
        snprintf(name, sizeof(name), "dict/%s/%s", table, col);
        write_dict_from_tmp(name, const_cols[i].tmp_name);
        const char *dtype = dict_type_for_col(table, col);
        char dtype_name[NAMEDATALEN * 3];
        snprintf(dtype_name, sizeof(dtype_name), "meta/dict_type/%s/%s", table, col);
        insert_file_text(dtype_name, dtype);
        char sorted_name[NAMEDATALEN * 3];
        snprintf(sorted_name, sizeof(sorted_name), "meta/dict_sorted/%s/%s", table, col);
        insert_file_text(sorted_name, "1");
    }

    SPI_finish();
    PG_RETURN_VOID();
}

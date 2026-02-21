#include "postgres.h"
#include "fmgr.h"
#include "executor/spi.h"
#include "executor/tuptable.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"
#include "utils/timestamp.h"
#include "utils/date.h"
#include "utils/varlena.h"
#include "lib/stringinfo.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "catalog/pg_type_d.h"
#include "catalog/namespace.h"
#include "common/hashfn.h"
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
    HTAB *tok_map;
    int32 next_tok;
} JoinClass;

typedef struct {
    int col_idx;
    int is_join;
    int join_class_id;
    int const_col_idx;
    HTAB *tok_map;
    AttrNumber attnum;
    Oid typid;
    Oid typoutput;
    bool typisvarlena;
} TokenColumn;

typedef struct {
    ABColumnRef col;
    HTAB *tok_map;
    int32 next_tok;
    Oid typid;
    bool uses_join_map;
    int join_class_id;
} ConstColumn;

typedef enum {
    DICT_KEY_TEXT = 0,
    DICT_KEY_INT64 = 1,
    DICT_KEY_BYTES = 2
} DictKeyKind;

typedef struct DictTokEntry DictTokEntry;
struct DictTokEntry {
    uint64 hkey;
    int32 tok;
    int32 blen;
    DictKeyKind key_kind;
    int64 ival;
    char *val;
    DictTokEntry *next;
};

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

static inline double elapsed_ms(TimestampTz t0)
{
    return ((double) (GetCurrentTimestamp() - t0)) / 1000.0;
}

static SPIPlanPtr g_insert_file_plan = NULL;

static void prepare_insert_file_plan(void)
{
    Oid argtypes[2] = {TEXTOID, BYTEAOID};
    SPIPlanPtr plan = SPI_prepare(
        "INSERT INTO public.files (name, file) VALUES ($1, $2)",
        2, argtypes);
    if (!plan)
        ereport(ERROR, (errmsg("artifact_builder: SPI_prepare insert plan failed")));
    g_insert_file_plan = SPI_saveplan(plan);
    SPI_freeplan(plan);
    if (!g_insert_file_plan)
        ereport(ERROR, (errmsg("artifact_builder: SPI_saveplan insert plan failed")));
}

static void insert_file(const char *name, bytea *data) {
    Datum values[2];
    char nulls[2] = {' ', ' '};
    if (!g_insert_file_plan)
        ereport(ERROR, (errmsg("artifact_builder: insert plan not initialized")));
    values[0] = CStringGetTextDatum(name);
    values[1] = PointerGetDatum(data);
    int ret = SPI_execute_plan(g_insert_file_plan, values, nulls, false, 0);
    if (ret != SPI_OK_INSERT)
        ereport(ERROR, (errmsg("failed to insert file %s", name)));
}

static void insert_file_text(const char *name, const char *text) {
    bytea *ba = cstring_to_bytea(text);
    insert_file(name, ba);
}

static void flush_code_chunk(const char *table,
                             int *chunk_idx,
                             uint32 *chunk_rows,
                             ByteaBuilder **code_payload_bb_ptr)
{
    if (!table || !chunk_idx || !chunk_rows || !code_payload_bb_ptr)
        return;
    if (*chunk_rows == 0 || !*code_payload_bb_ptr)
        return;

    ByteaBuilder *code_payload_bb = *code_payload_bb_ptr;
    ByteaBuilder *code_bb = bb_create();
    size_t payload_len = bb_size(code_payload_bb);
    if (payload_len > (size_t) INT32_MAX)
        ereport(ERROR, (errmsg("code payload chunk too large for %s chunk=%d: %zu bytes",
                               table, *chunk_idx, payload_len)));
    if (*chunk_rows > (uint32) INT32_MAX)
        ereport(ERROR, (errmsg("code chunk row count too large for %s chunk=%d: %u",
                               table, *chunk_idx, *chunk_rows)));

    bb_reserve(code_bb, sizeof(uint32) + sizeof(int32) + sizeof(int32) + payload_len);
    const char magic[4] = {'C', 'B', '0', '2'};
    bb_append_bytes(code_bb, magic, sizeof(magic));
    bb_append_int32(code_bb, (int32) *chunk_rows);
    bb_append_int32(code_bb, (int32) payload_len);
    bytea *payload_ba = bb_to_bytea(code_payload_bb);
    bb_append_bytes(code_bb, VARDATA(payload_ba), (size_t) VARSIZE_ANY_EXHDR(payload_ba));

    char chunk_name[NAMEDATALEN * 2];
    snprintf(chunk_name, sizeof(chunk_name), "%s_code_chunk_%d", table, *chunk_idx);
    bytea *chunk_ba = bb_to_bytea(code_bb);
    insert_file(chunk_name, chunk_ba);

    /* Free large temporaries aggressively to cap per-build peak RSS. */
    if (payload_ba) pfree(payload_ba);
    if (chunk_ba) pfree(chunk_ba);
    bb_free(code_bb);
    bb_free(code_payload_bb);
    *code_payload_bb_ptr = NULL;
    *chunk_rows = 0;
    (*chunk_idx)++;
}

static size_t estimate_table_rows(const char *table) {
    Oid argtypes[1] = {TEXTOID};
    Datum values[1];
    char nulls[1] = {' '};
    values[0] = CStringGetTextDatum(table);
    int ret = SPI_execute_with_args(
        "SELECT GREATEST(COALESCE(c.reltuples, 0), 0)::bigint "
        "FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relname = $1",
        1, argtypes, values, nulls, true, 1);
    if (ret != SPI_OK_SELECT || SPI_processed == 0)
        return 0;
    bool isnull = false;
    Datum d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
    if (isnull)
        return 0;
    int64 est = DatumGetInt64(d);
    if (est <= 0)
        return 0;
    return (size_t) est;
}

static Oid column_type_oid(const char *table, const char *col) {
    if (!table || !col) return InvalidOid;
    Oid argtypes[2] = {TEXTOID, TEXTOID};
    Datum values[2];
    char nulls[2] = {' ', ' '};
    values[0] = CStringGetTextDatum(table);
    values[1] = CStringGetTextDatum(col);
    int ret = SPI_execute_with_args(
        "SELECT a.atttypid "
        "FROM pg_attribute a "
        "JOIN pg_class c ON c.oid = a.attrelid "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relname = $1 AND a.attname = $2 "
        "AND a.attnum > 0 AND NOT a.attisdropped "
        "AND n.nspname = 'public'",
        2, argtypes, values, nulls, true, 0);
    if (ret != SPI_OK_SELECT || SPI_processed == 0)
        return InvalidOid;
    bool isnull = false;
    Datum d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
    if (isnull)
        return InvalidOid;
    return DatumGetObjectId(d);
}

static const char *dict_type_label_for_oid(Oid typid) {
    if (typid == INT2OID || typid == INT4OID || typid == INT8OID)
        return "int";
    if (typid == DATEOID)
        return "date";
    if (typid == FLOAT4OID || typid == FLOAT8OID || typid == NUMERICOID)
        return "float";
    if (typid == BPCHAROID)
        return "bpchar";
    return "text";
}

static uint64 dict_hash_key_text(const char *val) {
    if (!val) return 0;
    return hash_bytes_extended((const unsigned char *)val, strlen(val), 0);
}

static uint64 dict_hash_key_bytes(const char *data, int32 len)
{
    if (!data || len <= 0)
        return 0;
    return hash_bytes_extended((const unsigned char *) data, (size_t) len, 0);
}

static uint64 dict_hash_key_int64(int64 ival)
{
    return hash_bytes_extended((const unsigned char *) &ival, sizeof(int64), 0);
}

static inline bool dict_typid_uses_intkey(Oid typid)
{
    return typid == INT2OID || typid == INT4OID || typid == INT8OID ||
           typid == OIDOID || typid == DATEOID;
}

static inline int64 dict_datum_to_intkey(Oid typid, Datum v)
{
    switch (typid) {
        case INT2OID:
            return (int64) DatumGetInt16(v);
        case INT4OID:
            return (int64) DatumGetInt32(v);
        case INT8OID:
            return (int64) DatumGetInt64(v);
        case OIDOID:
            return (int64) DatumGetObjectId(v);
        case DATEOID:
            return (int64) DatumGetDateADT(v);
        default:
            ereport(ERROR, (errmsg("artifact_builder: unsupported int-key typid=%u", typid)));
    }
    return 0;
}

static inline bool dict_typid_uses_bytekey(Oid typid)
{
    return typid == TEXTOID || typid == VARCHAROID ||
           typid == BPCHAROID || typid == NUMERICOID;
}

static HTAB *dict_map_create(const char *name, long est_rows, MemoryContext mcxt) {
    HASHCTL ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.keysize = sizeof(uint64);
    ctl.entrysize = sizeof(DictTokEntry);
    ctl.hcxt = mcxt;
    if (est_rows < 128) est_rows = 128;
    return hash_create(name, est_rows, &ctl, HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
}

static int32 dict_map_get_or_insert_text(HTAB *map,
                                         MemoryContext mcxt,
                                         const char *val,
                                         int32 *next_tok,
                                         bool *out_inserted)
{
    bool found = false;
    uint64 hkey = dict_hash_key_text(val);
    DictTokEntry *head = (DictTokEntry *) hash_search(map, &hkey, HASH_ENTER, &found);
    if (!head)
        ereport(ERROR, (errmsg("artifact_builder: hash insert failed")));

    if (!found) {
        int32 tok = *next_tok;
        (*next_tok)++;
        head->hkey = hkey;
        head->tok = tok;
        head->blen = val ? (int32) strlen(val) : 0;
        head->key_kind = DICT_KEY_TEXT;
        head->ival = 0;
        head->val = MemoryContextStrdup(mcxt, val);
        head->next = NULL;
        if (out_inserted) *out_inserted = true;
        return tok;
    }

    for (DictTokEntry *cur = head; cur; cur = cur->next) {
        if (cur->key_kind == DICT_KEY_TEXT && cur->val && strcmp(cur->val, val) == 0) {
            if (out_inserted) *out_inserted = false;
            return cur->tok;
        }
        if (!cur->next) {
            int32 tok = *next_tok;
            (*next_tok)++;
            DictTokEntry *extra = (DictTokEntry *) MemoryContextAlloc(mcxt, sizeof(DictTokEntry));
            extra->hkey = hkey;
            extra->tok = tok;
            extra->blen = val ? (int32) strlen(val) : 0;
            extra->key_kind = DICT_KEY_TEXT;
            extra->ival = 0;
            extra->val = MemoryContextStrdup(mcxt, val);
            extra->next = NULL;
            cur->next = extra;
            if (out_inserted) *out_inserted = true;
            return tok;
        }
    }

    ereport(ERROR, (errmsg("artifact_builder: unreachable in dict_map_get_or_insert_text")));
    return -1;
}

static int32 dict_map_get_or_insert_int64(HTAB *map,
                                          MemoryContext mcxt,
                                          int64 ival,
                                          int32 *next_tok,
                                          bool *out_inserted)
{
    bool found = false;
    uint64 hkey = dict_hash_key_int64(ival);
    DictTokEntry *head = (DictTokEntry *) hash_search(map, &hkey, HASH_ENTER, &found);
    if (!head)
        ereport(ERROR, (errmsg("artifact_builder: hash insert failed")));

    if (!found) {
        int32 tok = *next_tok;
        (*next_tok)++;
        head->hkey = hkey;
        head->tok = tok;
        head->blen = 0;
        head->key_kind = DICT_KEY_INT64;
        head->ival = ival;
        head->val = NULL;
        head->next = NULL;
        if (out_inserted) *out_inserted = true;
        return tok;
    }

    for (DictTokEntry *cur = head; cur; cur = cur->next) {
        if (cur->key_kind == DICT_KEY_INT64 && cur->ival == ival) {
            if (out_inserted) *out_inserted = false;
            return cur->tok;
        }
        if (!cur->next) {
            int32 tok = *next_tok;
            (*next_tok)++;
            DictTokEntry *extra = (DictTokEntry *) MemoryContextAlloc(mcxt, sizeof(DictTokEntry));
            extra->hkey = hkey;
            extra->tok = tok;
            extra->blen = 0;
            extra->key_kind = DICT_KEY_INT64;
            extra->ival = ival;
            extra->val = NULL;
            extra->next = NULL;
            cur->next = extra;
            if (out_inserted) *out_inserted = true;
            return tok;
        }
    }

    ereport(ERROR, (errmsg("artifact_builder: unreachable in dict_map_get_or_insert_int64")));
    return -1;
}

static int32 dict_map_get_or_insert_bytes(HTAB *map,
                                          MemoryContext mcxt,
                                          const char *data,
                                          int32 len,
                                          int32 *next_tok,
                                          bool *out_inserted)
{
    bool found = false;
    uint64 hkey = dict_hash_key_bytes(data, len);
    DictTokEntry *head = (DictTokEntry *) hash_search(map, &hkey, HASH_ENTER, &found);
    if (!head)
        ereport(ERROR, (errmsg("artifact_builder: hash insert failed")));

    if (!found) {
        int32 tok = *next_tok;
        (*next_tok)++;
        head->hkey = hkey;
        head->tok = tok;
        head->blen = len;
        head->key_kind = DICT_KEY_BYTES;
        head->ival = 0;
        if (len > 0) {
            head->val = (char *) MemoryContextAlloc(mcxt, (size_t) len + 1);
            memcpy(head->val, data, (size_t) len);
            head->val[len] = '\0';
        } else {
            head->val = NULL;
        }
        head->next = NULL;
        if (out_inserted) *out_inserted = true;
        return tok;
    }

    for (DictTokEntry *cur = head; cur; cur = cur->next) {
        if (cur->key_kind == DICT_KEY_BYTES && cur->blen == len) {
            if (len == 0 || (cur->val && data && memcmp(cur->val, data, (size_t) len) == 0)) {
                if (out_inserted) *out_inserted = false;
                return cur->tok;
            }
        }
        if (!cur->next) {
            int32 tok = *next_tok;
            (*next_tok)++;
            DictTokEntry *extra = (DictTokEntry *) MemoryContextAlloc(mcxt, sizeof(DictTokEntry));
            extra->hkey = hkey;
            extra->tok = tok;
            extra->blen = len;
            extra->key_kind = DICT_KEY_BYTES;
            extra->ival = 0;
            if (len > 0) {
                extra->val = (char *) MemoryContextAlloc(mcxt, (size_t) len + 1);
                memcpy(extra->val, data, (size_t) len);
                extra->val[len] = '\0';
            } else {
                extra->val = NULL;
            }
            extra->next = NULL;
            cur->next = extra;
            if (out_inserted) *out_inserted = true;
            return tok;
        }
    }

    ereport(ERROR, (errmsg("artifact_builder: unreachable in dict_map_get_or_insert_bytes")));
    return -1;
}

static void write_dict_from_map(const char *name, HTAB *map, int32 n_tokens, Oid dict_typid)
{
    if (!name || !map || n_tokens < 0)
        ereport(ERROR, (errmsg("artifact_builder: invalid write_dict_from_map args")));

    DictTokEntry **vals = NULL;
    if (n_tokens > 0)
        vals = (DictTokEntry **) palloc0(sizeof(DictTokEntry *) * (size_t) n_tokens);

    HASH_SEQ_STATUS seq;
    hash_seq_init(&seq, map);
    DictTokEntry *head = NULL;
    while ((head = (DictTokEntry *) hash_seq_search(&seq)) != NULL) {
        for (DictTokEntry *cur = head; cur; cur = cur->next) {
            if (cur->tok < 0 || cur->tok >= n_tokens)
                ereport(ERROR, (errmsg("artifact_builder: dict token out of range tok=%d n=%d", cur->tok, n_tokens)));
            vals[cur->tok] = cur;
        }
    }

    Oid typed_out_func = InvalidOid;
    bool typed_out_varlena = false;
    if (dict_typid == DATEOID || dict_typid == NUMERICOID)
        getTypeOutputInfo(dict_typid, &typed_out_func, &typed_out_varlena);
    (void) typed_out_varlena;

    ByteaBuilder *bb = bb_create();
    for (int32 tok = 0; tok < n_tokens; tok++) {
        DictTokEntry *ent = vals ? vals[tok] : NULL;
        const char *val = NULL;
        char intbuf[64];
        int32 len = 0;
        char *tmp_out = NULL;
        struct varlena *tmp_num = NULL;

        if (ent) {
            if (ent->key_kind == DICT_KEY_TEXT) {
                val = ent->val ? ent->val : "";
                len = (int32) strlen(val);
            } else if (ent->key_kind == DICT_KEY_INT64) {
                if (dict_typid == DATEOID) {
                    tmp_out = OidOutputFunctionCall(typed_out_func, DateADTGetDatum((DateADT) ent->ival));
                    val = tmp_out ? tmp_out : "";
                    len = (int32) strlen(val);
                } else {
                    len = (int32) snprintf(intbuf, sizeof(intbuf), "%lld", (long long) ent->ival);
                    if (len < 0)
                        len = 0;
                    val = intbuf;
                }
            } else if (ent->key_kind == DICT_KEY_BYTES) {
                if (dict_typid == NUMERICOID) {
                    tmp_num = (struct varlena *) palloc((size_t) ent->blen + VARHDRSZ);
                    SET_VARSIZE(tmp_num, (size_t) ent->blen + VARHDRSZ);
                    if (ent->blen > 0)
                        memcpy(VARDATA(tmp_num), ent->val, (size_t) ent->blen);
                    tmp_out = OidOutputFunctionCall(typed_out_func, PointerGetDatum(tmp_num));
                    val = tmp_out ? tmp_out : "";
                    len = (int32) strlen(val);
                } else {
                    val = ent->val ? ent->val : "";
                    len = ent->blen > 0 ? ent->blen : 0;
                }
            }
        }

        bb_append_int32(bb, len);
        if (len > 0)
            bb_append_bytes(bb, val, (size_t) len);
        if (tmp_out)
            pfree(tmp_out);
        if (tmp_num)
            pfree(tmp_num);
    }
    insert_file(name, bb_to_bytea(bb));
    bb_free(bb);
    if (vals)
        pfree(vals);
}

Datum build_base(PG_FUNCTION_ARGS);
PG_FUNCTION_INFO_V1(build_base);

Datum build_base(PG_FUNCTION_ARGS) {
    if (PG_NARGS() < 1 || PG_ARGISNULL(0)) {
        ereport(ERROR, (errmsg("build_base requires policy path")));
    }
    const char *path = text_to_cstring(PG_GETARG_TEXT_PP(0));
    TimestampTz build_t0 = GetCurrentTimestamp();

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
    SetConfigOption("max_parallel_workers", "0", PGC_USERSET, PGC_S_SESSION);
    SetConfigOption("max_parallel_workers_per_gather", "0", PGC_USERSET, PGC_S_SESSION);
    SetConfigOption("max_parallel_maintenance_workers", "0", PGC_USERSET, PGC_S_SESSION);
    SetConfigOption("parallel_leader_participation", "off", PGC_USERSET, PGC_S_SESSION);
    SPI_execute("SET LOCAL search_path TO public, pg_catalog", false, 0);
    SPI_execute("SET LOCAL synchronous_commit TO off", false, 0);
    SPI_execute("CREATE TABLE IF NOT EXISTS public.files (name text, file bytea)", false, 0);
    SPI_execute("TRUNCATE TABLE public.files", false, 0);
    SPI_execute("DROP INDEX IF EXISTS files_name_uidx", false, 0);
    g_insert_file_plan = NULL;
    prepare_insert_file_plan();

    int join_atom_count = 0;
    int *col_class = NULL;
    int col_class_cap = 0;
    int *join_left = NULL;
    int *join_right = NULL;
    int join_cap = 0;
    int join_count = 0;
    /*
     * Keep token dictionaries in a context that survives SPI statement memory
     * resets for the whole build.
     */
    MemoryContext build_mcxt = AllocSetContextCreate(TopTransactionContext,
                                                     "artifact_builder_build_ctx",
                                                     ALLOCSET_DEFAULT_SIZES);

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

    /*
     * Build join-class token maps on-the-fly during table tokenization to avoid
     * extra DISTINCT/ORDER BY passes over large tables.
     */
    for (int i = 0; i < nclasses; i++) {
        size_t est_rows = 0;
        StringList class_tables = {0};
        for (int j = 0; j < classes[i].cols.count; j++) {
            int col_idx = classes[i].cols.items[j];
            str_list_add_unique(&class_tables, cols.items[col_idx].table);
        }
        for (int t = 0; t < class_tables.count; t++)
            est_rows += estimate_table_rows(class_tables.items[t]);
        if (est_rows > (size_t) LONG_MAX)
            est_rows = (size_t) LONG_MAX;
        char map_name[NAMEDATALEN * 2];
        snprintf(map_name, sizeof(map_name), "jc_tok_map_%d", i);
        classes[i].tok_map = dict_map_create(map_name, (long) est_rows, build_mcxt);
        classes[i].next_tok = 0;
    }
    elog(NOTICE, "artifact_builder: join_class_map_init classes=%d ms=%.3f",
         nclasses, elapsed_ms(build_t0));

    // Const-column maps: also built on-the-fly while scanning the owning table.
    ConstColumn *const_cols = (ConstColumn *)palloc0(sizeof(ConstColumn) * const_cols_list.count);
    int n_const = 0;
    for (int i = 0; i < const_cols_list.count; i++) {
        const_cols[n_const].col = const_cols_list.items[i];
        const_cols[n_const].typid = column_type_oid(const_cols[n_const].col.table,
                                                    const_cols[n_const].col.column);
        const_cols[n_const].uses_join_map = false;
        const_cols[n_const].join_class_id = -1;

        int col_idx = column_index(&cols,
                                   const_cols[n_const].col.table,
                                   const_cols[n_const].col.column);
        int cid = (col_idx >= 0 && col_class && col_idx < col_class_cap) ? col_class[col_idx] : -1;
        if (col_idx >= 0 && is_join_col[col_idx] && cid >= 0) {
            const_cols[n_const].uses_join_map = true;
            const_cols[n_const].join_class_id = cid;
            const_cols[n_const].tok_map = classes[cid].tok_map;
            const_cols[n_const].next_tok = 0;
        } else {
            size_t est_rows = estimate_table_rows(const_cols[n_const].col.table);
            if (est_rows > (size_t) LONG_MAX)
                est_rows = (size_t) LONG_MAX;
            char map_name[NAMEDATALEN * 2];
            snprintf(map_name, sizeof(map_name), "const_tok_map_%d", n_const);
            const_cols[n_const].tok_map = dict_map_create(map_name, (long) est_rows, build_mcxt);
            const_cols[n_const].next_tok = 0;
        }
        n_const++;
    }

// meta/cols/<table> and table artifacts
    for (int ti = 0; ti < tables.count; ti++) {
        TimestampTz table_t0 = GetCurrentTimestamp();
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
            tokcols[tpos].const_col_idx = -1;
            tokcols[tpos].tok_map = classes[cid].tok_map;
            tpos++;
        }
        for (int i = 0; i < const_cols_idx.count; i++) {
            int col_idx = const_cols_idx.items[i];
            tokcols[tpos].col_idx = col_idx;
            tokcols[tpos].is_join = 0;
            tokcols[tpos].join_class_id = -1;
            tokcols[tpos].const_col_idx = -1;
            for (int j = 0; j < const_cols_list.count; j++) {
                if (strcmp(const_cols[j].col.table, cols.items[col_idx].table) == 0 &&
                    strcmp(const_cols[j].col.column, cols.items[col_idx].column) == 0) {
                    tokcols[tpos].tok_map = const_cols[j].tok_map;
                    tokcols[tpos].const_col_idx = j;
                    break;
                }
            }
            if (!tokcols[tpos].tok_map)
                ereport(ERROR, (errmsg("missing const token map for %s.%s",
                                       cols.items[col_idx].table, cols.items[col_idx].column)));
            tpos++;
        }

        ByteaBuilder *ctid_bb = bb_create();
        /* Chunk code payloads to avoid >1GB bytea / allocator limits on large tables (e.g., tpch10 lineitem). */
        const uint32 code_chunk_max_rows = 1000000; /* keep per-chunk payload comfortably <256MB */
        ByteaBuilder *code_payload_bb = NULL;
        size_t est_rows = estimate_table_rows(table);
        if (est_rows == 0)
            est_rows = 1024;
        if (est_rows > (SIZE_MAX / (sizeof(int32) * 2)))
            est_rows = SIZE_MAX / (sizeof(int32) * 2);
        bb_reserve(ctid_bb, est_rows * sizeof(int32) * 2);
        size_t payload_per_row = sizeof(uint16);
        if (token_count > 0) {
            if ((size_t) token_count > (SIZE_MAX - payload_per_row) / sizeof(int32))
                ereport(ERROR, (errmsg("token count overflow for %s", table)));
            payload_per_row += (size_t) token_count * sizeof(int32);
        }
        if (est_rows > 0 && payload_per_row > 0) {
            size_t max_rows = SIZE_MAX / payload_per_row;
            if (est_rows > max_rows)
                est_rows = max_rows;
        }
        int32 *row_tokens = NULL;
        if (token_count > 0)
            row_tokens = (int32 *) palloc(sizeof(int32) * token_count);
        if (token_count > (int) UINT16_MAX)
            ereport(ERROR, (errmsg("too many token columns for %s: %d", table, token_count)));

        Oid relid = RelnameGetRelid(table);
        if (!OidIsValid(relid))
            ereport(ERROR, (errmsg("relation not found: %s", table)));
        Relation rel = table_open(relid, AccessShareLock);
        TupleDesc rel_desc = RelationGetDescr(rel);
        for (int i = 0; i < token_count; i++) {
            int col_idx = tokcols[i].col_idx;
            AttrNumber attnum = get_attnum(relid, cols.items[col_idx].column);
            if (attnum == InvalidAttrNumber)
                ereport(ERROR, (errmsg("missing attribute %s.%s",
                                       table, cols.items[col_idx].column)));
            tokcols[i].attnum = attnum;
            tokcols[i].typid = TupleDescAttr(rel_desc, attnum - 1)->atttypid;
            getTypeOutputInfo(tokcols[i].typid, &tokcols[i].typoutput, &tokcols[i].typisvarlena);
        }

        PushActiveSnapshot(GetTransactionSnapshot());
        TableScanDesc scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);
        TupleTableSlot *slot = MakeSingleTupleTableSlot(rel_desc, table_slot_callbacks(rel));
        int64 total_rows = 0;
        int chunk_idx = 0;
        uint32 chunk_rows = 0;

        while (table_scan_getnextslot(scan, ForwardScanDirection, slot)) {
            if (!ItemPointerIsValid(&slot->tts_tid))
                continue;
            int32 blk = (int32) ItemPointerGetBlockNumber(&slot->tts_tid);
            int32 off = (int32) ItemPointerGetOffsetNumber(&slot->tts_tid);
            bb_append_int32(ctid_bb, blk);
            bb_append_int32(ctid_bb, off);

            if (!code_payload_bb) {
                code_payload_bb = bb_create();
                size_t reserve_rows = code_chunk_max_rows;
                if (reserve_rows > (SIZE_MAX / payload_per_row))
                    reserve_rows = SIZE_MAX / payload_per_row;
                bb_reserve(code_payload_bb, reserve_rows * payload_per_row);
            }

            uint16 ntoks = (uint16) token_count;
            bb_append_bytes(code_payload_bb, &ntoks, sizeof(uint16));
            for (int i = 0; i < token_count; i++) {
                bool isnull = false;
                Datum v = slot_getattr(slot, tokcols[i].attnum, &isnull);
                int32 tval = -1;
                if (!isnull) {
                    int32 *next_tok_ptr = NULL;
                    if (tokcols[i].is_join) {
                        int jc = tokcols[i].join_class_id;
                        if (jc < 0 || jc >= nclasses)
                            ereport(ERROR, (errmsg("invalid join class index %d", jc)));
                        next_tok_ptr = &classes[jc].next_tok;
                    } else {
                        int ci = tokcols[i].const_col_idx;
                        if (ci < 0 || ci >= n_const)
                            ereport(ERROR, (errmsg("invalid const column index %d", ci)));
                        next_tok_ptr = &const_cols[ci].next_tok;
                    }

                    if (dict_typid_uses_intkey(tokcols[i].typid)) {
                        int64 ikey = dict_datum_to_intkey(tokcols[i].typid, v);
                        tval = dict_map_get_or_insert_int64(tokcols[i].tok_map,
                                                            build_mcxt,
                                                            ikey,
                                                            next_tok_ptr,
                                                            NULL);
                    } else if (dict_typid_uses_bytekey(tokcols[i].typid)) {
                        struct varlena *vl_orig = (struct varlena *) DatumGetPointer(v);
                        struct varlena *vl = PG_DETOAST_DATUM_PACKED(v);
                        const char *bytes = VARDATA_ANY(vl);
                        int32 blen = (int32) VARSIZE_ANY_EXHDR(vl);
                        if (tokcols[i].typid == BPCHAROID) {
                            while (blen > 0 && bytes[blen - 1] == ' ')
                                blen--;
                        }
                        tval = dict_map_get_or_insert_bytes(tokcols[i].tok_map,
                                                            build_mcxt,
                                                            bytes,
                                                            blen,
                                                            next_tok_ptr,
                                                            NULL);
                        if (vl != vl_orig)
                            pfree(vl);
                    } else {
                        char *txt = OidOutputFunctionCall(tokcols[i].typoutput, v);
                        if (txt) {
                            if (tokcols[i].typid == BPCHAROID) {
                                size_t n = strlen(txt);
                                while (n > 0 && txt[n - 1] == ' ') {
                                    txt[n - 1] = '\0';
                                    n--;
                                }
                            }
                            tval = dict_map_get_or_insert_text(tokcols[i].tok_map,
                                                               build_mcxt,
                                                               txt,
                                                               next_tok_ptr,
                                                               NULL);
                            pfree(txt);
                        }
                    }
                }
                row_tokens[i] = tval;
            }
            if (token_count > 0)
                bb_append_bytes(code_payload_bb, row_tokens, (size_t) token_count * sizeof(int32));
            total_rows++;
            chunk_rows++;
            if (chunk_rows >= code_chunk_max_rows) {
                flush_code_chunk(table, &chunk_idx, &chunk_rows, &code_payload_bb);
            }
        }
        table_endscan(scan);
        ExecDropSingleTupleTableSlot(slot);
        PopActiveSnapshot();
        table_close(rel, AccessShareLock);

        char name_ctid[NAMEDATALEN];
        char name_code[NAMEDATALEN * 2];
        snprintf(name_ctid, sizeof(name_ctid), "%s_ctid", table);
        snprintf(name_code, sizeof(name_code), "%s_code_base", table);

        /* Flush final partial chunk and then write a small CB03 manifest at <table>_code_base. */
        flush_code_chunk(table, &chunk_idx, &chunk_rows, &code_payload_bb);
        if (total_rows > (int64) INT32_MAX)
            ereport(ERROR, (errmsg("row count too large for %s: " INT64_FORMAT, table, total_rows)));

        ByteaBuilder *manifest_bb = bb_create();
        const char magic3[4] = {'C', 'B', '0', '3'};
        bb_append_bytes(manifest_bb, magic3, sizeof(magic3));
        bb_append_int32(manifest_bb, (int32) total_rows);
        bb_append_int32(manifest_bb, (int32) code_chunk_max_rows);
        bb_append_int32(manifest_bb, (int32) token_count);
        bb_append_int32(manifest_bb, (int32) chunk_idx);

        bytea *ctid_ba = bb_to_bytea(ctid_bb);
        insert_file(name_ctid, ctid_ba);
        if (ctid_ba) pfree(ctid_ba);

        bytea *manifest_ba = bb_to_bytea(manifest_bb);
        insert_file(name_code, manifest_ba);
        if (manifest_ba) pfree(manifest_ba);

        if (row_tokens)
            pfree(row_tokens);
        bb_free(ctid_bb);
        if (code_payload_bb)
            bb_free(code_payload_bb);
        bb_free(manifest_bb);
        elog(NOTICE, "artifact_builder: table_tokenize table=%s rows=%lld token_cols=%d ms=%.3f",
             table, (long long) total_rows, token_count, elapsed_ms(table_t0));
    }

    /*
     * Persist const-column dictionaries after tokenization. Token assignment is
     * insertion-order based (unsorted), so mark dict_sorted=0.
     */
    for (int i = 0; i < n_const; i++) {
        TimestampTz dict_t0 = GetCurrentTimestamp();
        char dict_name[NAMEDATALEN * 3];
        snprintf(dict_name, sizeof(dict_name), "dict/%s/%s",
                 const_cols[i].col.table, const_cols[i].col.column);
        int32 ntoks = const_cols[i].next_tok;
        if (const_cols[i].uses_join_map) {
            int cid = const_cols[i].join_class_id;
            if (cid < 0 || cid >= nclasses)
                ereport(ERROR, (errmsg("invalid const join class %d", cid)));
            ntoks = classes[cid].next_tok;
        }
        write_dict_from_map(dict_name, const_cols[i].tok_map, ntoks, const_cols[i].typid);

        char dtype_name[NAMEDATALEN * 3];
        snprintf(dtype_name, sizeof(dtype_name), "meta/dict_type/%s/%s",
                 const_cols[i].col.table, const_cols[i].col.column);
        insert_file_text(dtype_name, dict_type_label_for_oid(const_cols[i].typid));

        char sorted_name[NAMEDATALEN * 3];
        snprintf(sorted_name, sizeof(sorted_name), "meta/dict_sorted/%s/%s",
                 const_cols[i].col.table, const_cols[i].col.column);
        insert_file_text(sorted_name, "0");

        elog(NOTICE,
             "artifact_builder: const_dict table=%s col=%s tokens=%d sorted=0 ms=%.3f",
             const_cols[i].col.table, const_cols[i].col.column,
             ntoks, elapsed_ms(dict_t0));
    }

    elog(NOTICE, "artifact_builder: total_ms=%.3f tables=%d join_classes=%d const_cols=%d",
         elapsed_ms(build_t0), tables.count, nclasses, n_const);

    if (g_insert_file_plan) {
        SPI_freeplan(g_insert_file_plan);
        g_insert_file_plan = NULL;
    }
    SPI_execute("CREATE UNIQUE INDEX IF NOT EXISTS files_name_uidx ON public.files(name)", false, 0);

    MemoryContextDelete(build_mcxt);
    SPI_finish();
    PG_RETURN_VOID();
}

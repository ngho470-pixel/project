#include "artifact_builder.hpp"

extern "C" {
#include "postgres.h"
#include "utils/varlena.h"
}

#include <vector>
#include <cstring>

static inline void set_varsize_4b(bytea *ptr, size_t len) {
#ifdef WORDS_BIGENDIAN
    *((uint32 *)ptr) = ((uint32)len) & 0x3FFFFFFF;
#else
    *((uint32 *)ptr) = ((uint32)len) << 2;
#endif
}

struct ByteaBuilder {
    std::vector<char> buf;
};

extern "C" ByteaBuilder *bb_create(void) {
    return new ByteaBuilder();
}

extern "C" void bb_reserve(ByteaBuilder *bb, size_t nbytes) {
    if (!bb) return;
    bb->buf.reserve(nbytes);
}

extern "C" void bb_append_int32(ByteaBuilder *bb, int32 value) {
    if (!bb) return;
    char bytes[4];
    std::memcpy(bytes, &value, 4);
    bb->buf.insert(bb->buf.end(), bytes, bytes + 4);
}

extern "C" void bb_append_bytes(ByteaBuilder *bb, const char *data, size_t len) {
    if (!bb || !data || len == 0) return;
    bb->buf.insert(bb->buf.end(), data, data + len);
}

extern "C" bytea *bb_to_bytea(ByteaBuilder *bb) {
    if (!bb) return nullptr;
    size_t len = bb->buf.size();
    bytea *out = (bytea *)palloc(VARHDRSZ + len);
    set_varsize_4b(out, VARHDRSZ + len);
    if (len > 0) {
        std::memcpy(((char *)out) + VARHDRSZ, bb->buf.data(), len);
    }
    return out;
}

extern "C" size_t bb_size(ByteaBuilder *bb) {
    if (!bb) return 0;
    return bb->buf.size();
}

extern "C" void bb_free(ByteaBuilder *bb) {
    delete bb;
}

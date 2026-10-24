// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Resolve private Binder transaction constants from this system's DEX, once at
// registration. Never guess transaction numbers: a wrong number can call a
// different WindowManager method. Unsupported/stripped images fail closed.
#include "service/keyguard.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef __ANDROID__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#endif

struct byte_view {
    const unsigned char *data;
    size_t size;
    bool bad;
};
static bool view_has(struct byte_view *view, size_t position, size_t length) {
    if (position > view->size || length > view->size - position) {
        view->bad = true;
        return false;
    }
    return true;
}
static uint32_t view_uint(struct byte_view *view, size_t position, size_t length) {
    if (!view_has(view, position, length)) return 0;
    uint32_t value = 0;
    for (size_t i = 0; i < length; ++i) value |= (uint32_t)view->data[position + i] << (8 * i);
    return value;
}
static uint32_t view_u32(struct byte_view *view, size_t position) {
    return view_uint(view, position, 4);
}
static uint32_t view_uleb128(struct byte_view *view, size_t *position) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 5; ++i) {
        unsigned byte = view_uint(view, (*position)++, 1);
        if (i == 4 && byte > 15) {
            view->bad = true;
            return 0;
        }
        value |= (byte & 127U) << (7 * i);
        if (!(byte & 128U)) return value;
    }
    view->bad = true;
    return 0;
}
static const char *dex_string(struct byte_view *view, uint32_t index) {
    if (index >= view_u32(view, 56)) {
        view->bad = true;
        return "";
    }
    size_t position = view_u32(view, (size_t)view_u32(view, 60) + (size_t)index * 4);
    (void)view_uleb128(view, &position);
    if (!view_has(view, position, 1) || !memchr(view->data + position, 0, view->size - position)) {
        view->bad = true;
        return "";
    }
    return (const char *)view->data + position;
}

static int keyguard_ids_from_dex(const void *data, size_t size, int ids[3]) {
    struct byte_view view = {data, size, false};
    if (size < 112 || memcmp(data, "dex\n", 4) || view_u32(&view, 40) != 0x12345678) return -1;
    uint32_t count = view_u32(&view, 96), offset = view_u32(&view, 100);
    if (count > size / 32 || !view_has(&view, offset, (size_t)count * 32)) return -1;
    for (uint32_t i = 0; i < count && !view.bad; ++i) {
        size_t class_def = (size_t)offset + i * 32;
        uint32_t type = view_u32(&view, class_def);
        if (type >= view_u32(&view, 64)) return -1;
        const char *name =
            dex_string(&view, view_u32(&view, (size_t)view_u32(&view, 68) + (size_t)type * 4));
        if (strcmp(name, "Landroid/view/IWindowManager$Stub;")) continue;
        size_t class_data = view_u32(&view, class_def + 24),
               static_values = view_u32(&view, class_def + 28);
        if (!class_data || !static_values) return -1;
        uint32_t fields = view_uleb128(&view, &class_data);
        for (unsigned n = 0; n < 3; ++n) (void)view_uleb128(&view, &class_data);
        uint32_t values = view_uleb128(&view, &static_values);
        if (fields > 4096 || values > fields) return -1;
        uint32_t field = 0;
        unsigned found = 0;
        static const char *const wanted[] = {"TRANSACTION_isKeyguardLocked",
            "TRANSACTION_addKeyguardLockedStateListener",
            "TRANSACTION_removeKeyguardLockedStateListener"};
        int resolved[3] = {0};
        for (uint32_t n = 0; n < values && !view.bad; ++n) {
            uint32_t delta = view_uleb128(&view, &class_data);
            if (UINT32_MAX - field < delta) return -1;
            field += delta;
            (void)view_uleb128(&view, &class_data);
            if (field >= view_u32(&view, 80)) return -1;
            name = dex_string(
                &view, view_u32(&view, (size_t)view_u32(&view, 84) + (size_t)field * 8 + 4));
            unsigned tag = view_uint(&view, static_values++, 1), kind = tag & 31U,
                     width = (tag >> 5) + 1;
            // Stub static values are scalar constants. Refuse unfamiliar encoding.
            if (kind == 0x1c || kind == 0x1d || width > 8) return -1;
            uint32_t value = 0;
            if (kind != 0x1e && kind != 0x1f) {
                if (!view_has(&view, static_values, width)) return -1;
                if (width <= 4) value = view_uint(&view, static_values, width);
                static_values += width;
            }
            for (unsigned k = 0; k < 3; ++k) {
                if (strcmp(name, wanted[k])) continue;
                if (kind != 4 || width > 4 || value == 0 || value > 0xffffff || (found & (1U << k)))
                    return -1;
                resolved[k] = (int)value;
                found |= 1U << k;
            }
        }
        if (view.bad || found != 7 || resolved[0] == resolved[1] || resolved[1] == resolved[2] ||
            resolved[0] == resolved[2])
            return -1;
        memcpy(ids, resolved, sizeof(resolved));
        return 0;
    }
    return -1;
}

#ifdef __ANDROID__
int asteriskd_keyguard_resolve_ids(int ids[3]) {
    int fd = open("/system/framework/framework.jar", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat status;
    if (fstat(fd, &status) || status.st_size < 22 || status.st_size > 256 * 1024 * 1024) {
        close(fd);
        return -1;
    }
    size_t size = (size_t)status.st_size;
    void *mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) return -1;
    struct byte_view view = {mapped, size, false};
    int result = -1;
    size_t end = size - 22, limit = size > 65557 ? size - 65557 : 0;
    while (end > limit && view_u32(&view, end) != 0x06054b50) --end;
    if (view_u32(&view, end) != 0x06054b50 || end + 22 + view_uint(&view, end + 20, 2) != size)
        goto done;
    unsigned entries = view_uint(&view, end + 10, 2);
    size_t entry = view_u32(&view, end + 16);
    for (unsigned i = 0; i < entries && !view.bad; ++i) {
        if (!view_has(&view, entry, 46) || view_u32(&view, entry) != 0x02014b50) break;
        unsigned method = view_uint(&view, entry + 10, 2), flags = view_uint(&view, entry + 8, 2);
        size_t packed = view_u32(&view, entry + 20), unpacked = view_u32(&view, entry + 24);
        size_t name_size = view_uint(&view, entry + 28, 2), extra = view_uint(&view, entry + 30, 2),
               comment = view_uint(&view, entry + 32, 2);
        size_t local = view_u32(&view, entry + 42), name = entry + 46;
        if (!view_has(&view, name, name_size + extra + comment)) break;
        entry = name + name_size + extra + comment;
        if (name_size < 11 || memcmp(view.data + name, "classes", 7) ||
            memcmp(view.data + name + name_size - 4, ".dex", 4))
            continue;
        if ((flags & 1) || unpacked < 112 || unpacked > 64 * 1024 * 1024 ||
            !view_has(&view, local, 30) || view_u32(&view, local) != 0x04034b50)
            break;
        size_t content =
            local + 30 + view_uint(&view, local + 26, 2) + view_uint(&view, local + 28, 2);
        if (!view_has(&view, content, packed)) break;
        if (method == 0 && packed == unpacked) {
            result = keyguard_ids_from_dex(view.data + content, unpacked, ids);
        } else if (method == 8) {
            unsigned char *decoded = malloc(unpacked);
            if (!decoded) break;
            z_stream stream = {0};
            stream.next_in = (Bytef *)view.data + content;
            stream.avail_in = (uInt)packed;
            stream.next_out = decoded;
            stream.avail_out = (uInt)unpacked;
            if (inflateInit2(&stream, -MAX_WBITS) == Z_OK) {
                if (inflate(&stream, Z_FINISH) == Z_STREAM_END && stream.total_out == unpacked)
                    result = keyguard_ids_from_dex(decoded, unpacked, ids);
                inflateEnd(&stream);
            }
            free(decoded);
        }
        if (result == 0) break;
    }
done:
    munmap(mapped, size);
    return view.bad ? -1 : result;
}
#else
int asteriskd_keyguard_resolve_ids(int ids[3]) {
    (void)ids;
    return -1;
}
#endif

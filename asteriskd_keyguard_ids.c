// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Resolve private Binder transaction constants from this system's DEX, once at
// registration. Never guess transaction numbers: a wrong number can call a
// different WindowManager method. Unsupported/stripped images fail closed.
#include "asteriskd_keyguard.h"
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

struct bytes { const unsigned char *data; size_t size; bool bad; };
static bool span(struct bytes *b, size_t p, size_t n) {
    if (p > b->size || n > b->size - p) { b->bad = true; return false; }
    return true;
}
static uint32_t number(struct bytes *b, size_t p, size_t n) {
    if (!span(b, p, n)) return 0;
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i) v |= (uint32_t)b->data[p+i] << (8*i);
    return v;
}
static uint32_t word(struct bytes *b, size_t p) { return number(b,p,4); }
static uint32_t leb(struct bytes *b, size_t *p) {
    uint32_t v = 0;
    for (unsigned i = 0; i < 5; ++i) {
        unsigned c = number(b,(*p)++,1);
        if (i == 4 && c > 15) { b->bad = true; return 0; }
        v |= (c & 127U) << (7*i);
        if (!(c & 128U)) return v;
    }
    b->bad = true;
    return 0;
}
static const char *string_at(struct bytes *b, uint32_t i) {
    if (i >= word(b,56)) { b->bad = true; return ""; }
    size_t p = word(b,(size_t)word(b,60) + (size_t)i*4);
    (void)leb(b,&p);
    if (!span(b,p,1) || !memchr(b->data+p,0,b->size-p)) { b->bad = true; return ""; }
    return (const char *)b->data+p;
}

int asteriskd_keyguard_ids_from_dex(const void *data, size_t size, int ids[3]) {
    struct bytes b = {data,size,false};
    if (size < 112 || memcmp(data,"dex\n",4) || word(&b,40) != 0x12345678) return -1;
    uint32_t count = word(&b,96), offset = word(&b,100);
    if (count > size/32 || !span(&b,offset,(size_t)count*32)) return -1;
    for (uint32_t i = 0; i < count && !b.bad; ++i) {
        size_t c = (size_t)offset + i*32;
        uint32_t type = word(&b,c);
        if (type >= word(&b,64)) return -1;
        const char *name = string_at(&b,word(&b,(size_t)word(&b,68)+(size_t)type*4));
        if (strcmp(name,"Landroid/view/IWindowManager$Stub;")) continue;
        size_t p = word(&b,c+24), v = word(&b,c+28);
        if (!p || !v) return -1;
        uint32_t fields = leb(&b,&p);
        for (unsigned n = 0; n < 3; ++n) (void)leb(&b,&p);
        uint32_t values = leb(&b,&v);
        if (fields > 4096 || values > fields) return -1;
        uint32_t field = 0; unsigned found = 0;
        static const char *const wanted[] = {"TRANSACTION_isKeyguardLocked",
            "TRANSACTION_addKeyguardLockedStateListener", "TRANSACTION_removeKeyguardLockedStateListener"};
        int resolved[3] = {0};
        for (uint32_t n = 0; n < values && !b.bad; ++n) {
            uint32_t delta = leb(&b,&p);
            if (UINT32_MAX-field < delta) return -1;
            field += delta; (void)leb(&b,&p);
            if (field >= word(&b,80)) return -1;
            name = string_at(&b,word(&b,(size_t)word(&b,84)+(size_t)field*8+4));
            unsigned tag = number(&b,v++,1), kind = tag&31U, width = (tag>>5)+1;
            // Stub static values are scalar constants. Refuse unfamiliar encoding.
            if (kind == 0x1c || kind == 0x1d || width > 8) return -1;
            uint32_t value = 0;
            if (kind != 0x1e && kind != 0x1f) {
                if (!span(&b,v,width)) return -1;
                if (width <= 4) value = number(&b,v,width);
                v += width;
            }
            for (unsigned k = 0; k < 3; ++k) {
                if (strcmp(name,wanted[k])) continue;
                if (kind != 4 || width > 4 || value == 0 || value > 0xffffff || (found & (1U<<k))) return -1;
                resolved[k] = (int)value; found |= 1U<<k;
            }
        }
        if (b.bad || found != 7 || resolved[0] == resolved[1] || resolved[1] == resolved[2] || resolved[0] == resolved[2]) return -1;
        memcpy(ids,resolved,sizeof(resolved));
        return 0;
    }
    return -1;
}

#ifdef __ANDROID__
int asteriskd_keyguard_resolve_ids(int ids[3]) {
    int fd = open("/system/framework/framework.jar",O_RDONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd,&st) || st.st_size < 22 || st.st_size > 256*1024*1024) { close(fd); return -1; }
    size_t size = (size_t)st.st_size;
    void *mapped = mmap(NULL,size,PROT_READ,MAP_PRIVATE,fd,0);
    close(fd);
    if (mapped == MAP_FAILED) return -1;
    struct bytes b = {mapped,size,false};
    int result = -1;
    size_t end = size-22, limit = size > 65557 ? size-65557 : 0;
    while (end > limit && word(&b,end) != 0x06054b50) --end;
    if (word(&b,end) != 0x06054b50 || end+22+number(&b,end+20,2) != size) goto done;
    unsigned entries = number(&b,end+10,2);
    size_t p = word(&b,end+16);
    for (unsigned i = 0; i < entries && !b.bad; ++i) {
        if (!span(&b,p,46) || word(&b,p) != 0x02014b50) break;
        unsigned method = number(&b,p+10,2), flags = number(&b,p+8,2);
        size_t packed = word(&b,p+20), unpacked = word(&b,p+24);
        size_t name_size = number(&b,p+28,2), extra = number(&b,p+30,2), comment = number(&b,p+32,2);
        size_t local = word(&b,p+42), name = p+46;
        if (!span(&b,name,name_size+extra+comment)) break;
        p = name+name_size+extra+comment;
        if (name_size < 11 || memcmp(b.data+name,"classes",7) || memcmp(b.data+name+name_size-4,".dex",4)) continue;
        if ((flags&1) || unpacked < 112 || unpacked > 64*1024*1024 || !span(&b,local,30) || word(&b,local) != 0x04034b50) break;
        size_t content = local+30+number(&b,local+26,2)+number(&b,local+28,2);
        if (!span(&b,content,packed)) break;
        if (method == 0 && packed == unpacked) {
            result = asteriskd_keyguard_ids_from_dex(b.data+content,unpacked,ids);
        } else if (method == 8) {
            unsigned char *decoded = malloc(unpacked);
            if (!decoded) break;
            z_stream z = {0}; z.next_in = (Bytef *)b.data+content; z.avail_in = (uInt)packed;
            z.next_out = decoded; z.avail_out = (uInt)unpacked;
            if (inflateInit2(&z,-MAX_WBITS) == Z_OK) {
                if (inflate(&z,Z_FINISH) == Z_STREAM_END && z.total_out == unpacked)
                    result = asteriskd_keyguard_ids_from_dex(decoded,unpacked,ids);
                inflateEnd(&z);
            }
            free(decoded);
        }
        if (result == 0) break;
    }
done:
    munmap(mapped,size);
    return b.bad ? -1 : result;
}
#else
int asteriskd_keyguard_resolve_ids(int ids[3]) { (void)ids; return -1; }
#endif

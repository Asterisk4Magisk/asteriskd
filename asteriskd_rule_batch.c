// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdlib.h>
#include <string.h>

#define ASTERISKD_RULE_BATCH_MAX_BYTES (8U * 1024U * 1024U)

struct rule_batch_builder {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
};

static void builder_destroy(struct rule_batch_builder *builder) {
    if (builder == NULL) return;
    free(builder->bytes);
    memset(builder, 0, sizeof(*builder));
}

static int builder_append(
    struct rule_batch_builder *builder, const void *bytes, size_t length) {
    if (builder == NULL || (length != 0U && bytes == NULL) ||
        length > ASTERISKD_RULE_BATCH_MAX_BYTES - builder->length) return -1;
    size_t required = builder->length + length;
    if (required > builder->capacity) {
        size_t capacity = builder->capacity == 0U ? 4096U : builder->capacity;
        while (capacity < required) {
            if (capacity > ASTERISKD_RULE_BATCH_MAX_BYTES / 2U) {
                capacity = ASTERISKD_RULE_BATCH_MAX_BYTES;
                break;
            }
            capacity *= 2U;
        }
        unsigned char *resized = realloc(builder->bytes, capacity);
        if (resized == NULL) return -1;
        builder->bytes = resized;
        builder->capacity = capacity;
    }
    if (length != 0U) memcpy(builder->bytes + builder->length, bytes, length);
    builder->length = required;
    return 0;
}

int asteriskd_rule_batch_document_render(
    const unsigned char *private_commands, size_t private_length,
    const unsigned char *ipv4_commands, size_t ipv4_length,
    const unsigned char *ipv6_commands, size_t ipv6_length,
    const unsigned char *hook_commands, size_t hook_length,
    unsigned char **document, size_t *document_length) {
    static const char header[] = "set -eu\n";
    if (document != NULL) *document = NULL;
    if (document_length != NULL) *document_length = 0U;
    if (document == NULL || document_length == NULL ||
        (private_length != 0U && private_commands == NULL) ||
        (ipv4_length != 0U && ipv4_commands == NULL) ||
        (ipv6_length != 0U && ipv6_commands == NULL) ||
        (hook_length != 0U && hook_commands == NULL)) return -1;

    struct rule_batch_builder builder = {0};
    if (builder_append(&builder, header, sizeof(header) - 1U) != 0 ||
        builder_append(&builder, private_commands, private_length) != 0 ||
        builder_append(&builder, ipv4_commands, ipv4_length) != 0 ||
        builder_append(&builder, ipv6_commands, ipv6_length) != 0 ||
        builder_append(&builder, hook_commands, hook_length) != 0 ||
        builder_append(&builder, "", 1U) != 0) {
        builder_destroy(&builder);
        return -1;
    }
    *document_length = builder.length - 1U;
    *document = builder.bytes;
    return 0;
}

#if defined(ASTERISKD_TESTING)
int asteriskd_test_rule_batch_document(
    const char *private_commands,
    const char *ipv4_commands,
    const char *ipv6_commands,
    const char *hook_commands,
    char **document,
    size_t *length) {
    if (private_commands == NULL || ipv4_commands == NULL ||
        ipv6_commands == NULL || hook_commands == NULL) return -1;
    return asteriskd_rule_batch_document_render(
        (const unsigned char *)private_commands, strlen(private_commands),
        (const unsigned char *)ipv4_commands, strlen(ipv4_commands),
        (const unsigned char *)ipv6_commands, strlen(ipv6_commands),
        (const unsigned char *)hook_commands, strlen(hook_commands),
        (unsigned char **)document, length);
}
#endif

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdlib.h>
#include <string.h>

/*
 * Renders one iptables-restore --noflush document: every table with queued
 * commands becomes its own "*table ... COMMIT" section, which the kernel
 * replaces atomically. Tables without commands are omitted.
 */
int asteriskd_rule_batch_restore_render(
    const char *const *table_names,
    const struct asteriskd_byte_buffer *commands,
    size_t table_count,
    unsigned char **document, size_t *document_length) {
    if (document != NULL) *document = NULL;
    if (document_length != NULL) *document_length = 0U;
    if (document == NULL || document_length == NULL ||
        (table_count != 0U && (table_names == NULL || commands == NULL))) return -1;

    struct asteriskd_byte_buffer buffer = {0};
    for (size_t index = 0U; index < table_count; ++index) {
        if (commands[index].length == 0U) continue;
        const char *name = table_names[index];
        if (name == NULL || name[0] == '\0' || commands[index].bytes == NULL ||
            commands[index].bytes[commands[index].length - 1U] != '\n' ||
            asteriskd_byte_buffer_append(&buffer, "*", 1U) != 0 ||
            asteriskd_byte_buffer_append(&buffer, name, strlen(name)) != 0 ||
            asteriskd_byte_buffer_append(&buffer, "\n", 1U) != 0 ||
            asteriskd_byte_buffer_append(
                &buffer, commands[index].bytes, commands[index].length) != 0 ||
            asteriskd_byte_buffer_append(&buffer, "COMMIT\n", 7U) != 0) {
            asteriskd_byte_buffer_destroy(&buffer);
            return -1;
        }
    }
    *document = buffer.bytes;
    *document_length = buffer.length;
    return 0;
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdlib.h>
#include <string.h>

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

    struct asteriskd_byte_buffer buffer = {0};
    if (asteriskd_byte_buffer_append(&buffer, header, sizeof(header) - 1U) != 0 ||
        asteriskd_byte_buffer_append(&buffer, private_commands, private_length) != 0 ||
        asteriskd_byte_buffer_append(&buffer, ipv4_commands, ipv4_length) != 0 ||
        asteriskd_byte_buffer_append(&buffer, ipv6_commands, ipv6_length) != 0 ||
        asteriskd_byte_buffer_append(&buffer, hook_commands, hook_length) != 0 ||
        asteriskd_byte_buffer_append(&buffer, "", 1U) != 0) {
        asteriskd_byte_buffer_destroy(&buffer);
        return -1;
    }
    *document_length = buffer.length - 1U;
    *document = buffer.bytes;
    return 0;
}

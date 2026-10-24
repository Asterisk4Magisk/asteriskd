// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Text writer for rendered child documents, bounded by ASTERISKD_MAX_JSON_SIZE. */

static int text_writer_reserve(struct asteriskd_text_writer *writer, size_t additional) {
    if (writer->result != 0) return writer->result;
    if (additional > ASTERISKD_MAX_JSON_SIZE ||
        writer->length > ASTERISKD_MAX_JSON_SIZE - additional) {
        writer->result = ASTERISKD_CONFIG_INVALID;
        return writer->result;
    }
    size_t needed = writer->length + additional + 1U;
    if (needed <= writer->capacity) return 0;
    size_t capacity = writer->capacity == 0U ? 256U : writer->capacity;
    while (capacity < needed) {
        if (capacity > (ASTERISKD_MAX_JSON_SIZE + 1U) / 2U) {
            capacity = ASTERISKD_MAX_JSON_SIZE + 1U;
            break;
        }
        capacity *= 2U;
    }
    unsigned char *bytes = realloc(writer->bytes, capacity);
    if (bytes == NULL) {
        writer->result = ASTERISKD_CONFIG_NO_MEMORY;
        return writer->result;
    }
    writer->bytes = bytes;
    writer->capacity = capacity;
    return 0;
}

static void text_writer_bytes(
    struct asteriskd_text_writer *writer, const char *bytes, size_t length) {
    if (bytes == NULL || text_writer_reserve(writer, length) != 0) return;
    memcpy(writer->bytes + writer->length, bytes, length);
    writer->length += length;
    writer->bytes[writer->length] = '\0';
}

void asteriskd_text_writer_literal(struct asteriskd_text_writer *writer, const char *literal) {
    text_writer_bytes(writer, literal, strlen(literal));
}

void asteriskd_text_writer_format(struct asteriskd_text_writer *writer, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    va_list copy;
    va_copy(copy, arguments);
    int count = vsnprintf(NULL, 0U, format, copy);
    va_end(copy);
    if (count < 0 || text_writer_reserve(writer, (size_t)count) != 0) {
        va_end(arguments);
        if (count < 0) writer->result = ASTERISKD_CONFIG_INVALID;
        return;
    }
    int written = vsnprintf((char *)writer->bytes + writer->length,
        writer->capacity - writer->length, format, arguments);
    va_end(arguments);
    if (written != count) {
        writer->result = ASTERISKD_CONFIG_INVALID;
        return;
    }
    writer->length += (size_t)count;
}

void asteriskd_text_writer_json_string(struct asteriskd_text_writer *writer, const char *value) {
    asteriskd_text_writer_literal(writer, "\"");
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != '\0' && writer->result == 0) {
        unsigned char byte = *cursor++;
        switch (byte) {
            case '\"': asteriskd_text_writer_literal(writer, "\\\""); break;
            case '\\': asteriskd_text_writer_literal(writer, "\\\\"); break;
            case '\b': asteriskd_text_writer_literal(writer, "\\b"); break;
            case '\f': asteriskd_text_writer_literal(writer, "\\f"); break;
            case '\n': asteriskd_text_writer_literal(writer, "\\n"); break;
            case '\r': asteriskd_text_writer_literal(writer, "\\r"); break;
            case '\t': asteriskd_text_writer_literal(writer, "\\t"); break;
            default:
                if (byte < 0x20U) asteriskd_text_writer_format(writer, "\\u%04x", (unsigned)byte);
                else text_writer_bytes(writer, (const char *)&byte, 1U);
                break;
        }
    }
    asteriskd_text_writer_literal(writer, "\"");
}

void asteriskd_text_writer_yaml_string(struct asteriskd_text_writer *writer, const char *value) {
    asteriskd_text_writer_literal(writer, "'");
    for (const char *cursor = value; *cursor != '\0'; ++cursor) {
        text_writer_bytes(writer, cursor, 1U);
        if (*cursor == '\'') asteriskd_text_writer_literal(writer, "'");
    }
    asteriskd_text_writer_literal(writer, "'");
}

int asteriskd_text_writer_take(
    struct asteriskd_text_writer *writer, struct asteriskd_anonymous_document *document) {
    if (writer->result != 0) {
        int result = writer->result;
        free(writer->bytes);
        memset(writer, 0, sizeof(*writer));
        return result;
    }
    if (writer->bytes == NULL) {
        writer->bytes = calloc(1U, 1U);
        if (writer->bytes == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    }
    document->bytes = writer->bytes;
    document->length = writer->length;
    memset(writer, 0, sizeof(*writer));
    return 0;
}

/* Growable byte buffer for rule batch scripts, bounded by ASTERISKD_BYTE_BUFFER_MAX_BYTES. */

void asteriskd_byte_buffer_destroy(struct asteriskd_byte_buffer *buffer) {
    if (buffer == NULL) return;
    free(buffer->bytes);
    memset(buffer, 0, sizeof(*buffer));
}

int asteriskd_byte_buffer_append(
    struct asteriskd_byte_buffer *buffer, const void *bytes, size_t length) {
    if (buffer == NULL || (length != 0U && bytes == NULL) ||
        length > ASTERISKD_BYTE_BUFFER_MAX_BYTES - buffer->length) return -1;
    size_t required = buffer->length + length;
    if (required > buffer->capacity) {
        size_t capacity = buffer->capacity == 0U ? 4096U : buffer->capacity;
        while (capacity < required) {
            if (capacity > ASTERISKD_BYTE_BUFFER_MAX_BYTES / 2U) {
                capacity = ASTERISKD_BYTE_BUFFER_MAX_BYTES;
                break;
            }
            capacity *= 2U;
        }
        unsigned char *resized = realloc(buffer->bytes, capacity);
        if (resized == NULL) return -1;
        buffer->bytes = resized;
        buffer->capacity = capacity;
    }
    if (length != 0U) memcpy(buffer->bytes + buffer->length, bytes, length);
    buffer->length = required;
    return 0;
}

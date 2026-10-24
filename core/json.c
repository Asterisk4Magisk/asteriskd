// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum parser_state {
    STATE_OBJECT_KEY_OR_END,
    STATE_OBJECT_KEY,
    STATE_OBJECT_COLON,
    STATE_OBJECT_VALUE,
    STATE_OBJECT_COMMA_OR_END,
    STATE_ARRAY_VALUE_OR_END,
    STATE_ARRAY_VALUE,
    STATE_ARRAY_COMMA_OR_END,
};

struct parser_frame {
    size_t token;
    enum parser_state state;
};

static void set_message(char *message, size_t message_size, const char *format, ...) {
    if (message == NULL || message_size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(message, message_size, format, arguments);
    va_end(arguments);
}

static bool is_space(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

static bool is_hex(char value) {
    return (value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'f') ||
        (value >= 'A' && value <= 'F');
}

static bool valid_utf8(const char *source, size_t length) {
    size_t index = 0U;
    while (index < length) {
        unsigned char first = (unsigned char)source[index++];
        if (first < 0x80U) continue;
        size_t continuation = 0U;
        uint32_t codepoint = 0U;
        if (first >= 0xC2U && first <= 0xDFU) {
            continuation = 1U;
            codepoint = first & 0x1FU;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            continuation = 2U;
            codepoint = first & 0x0FU;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            continuation = 3U;
            codepoint = first & 0x07U;
        } else {
            return false;
        }
        if (continuation > length - index) return false;
        for (size_t offset = 0U; offset < continuation; ++offset) {
            unsigned char next = (unsigned char)source[index++];
            if ((next & 0xC0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (uint32_t)(next & 0x3FU);
        }
        if ((continuation == 2U && codepoint < 0x800U) ||
            (continuation == 3U && codepoint < 0x10000U) ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU) || codepoint > 0x10FFFFU) return false;
    }
    return true;
}

static int scan_string(const char *source, size_t length, size_t start, size_t *end) {
    size_t index = start + 1U;
    while (index < length) {
        unsigned char value = (unsigned char)source[index];
        if (value == '"') {
            *end = index + 1U;
            return 0;
        }
        if (value < 0x20U) return -1;
        if (value != '\\') {
            ++index;
            continue;
        }
        ++index;
        if (index >= length) return -1;
        value = (unsigned char)source[index];
        if (value == 'u') {
            if (index + 4U >= length) return -1;
            for (size_t offset = 1U; offset <= 4U; ++offset) {
                if (!is_hex(source[index + offset])) return -1;
            }
            index += 5U;
        } else if (strchr("\"\\/bfnrt", (int)value) != NULL) {
            ++index;
        } else {
            return -1;
        }
    }
    return -1;
}

static bool number_delimiter(char value) {
    return value == '\0' || is_space(value) || value == ',' || value == ']' || value == '}';
}

static int scan_number(const char *source, size_t length, size_t start, size_t *end) {
    size_t index = start;
    if (source[index] == '-') {
        ++index;
        if (index >= length) return -1;
    }
    if (source[index] == '0') {
        ++index;
        if (index < length && source[index] >= '0' && source[index] <= '9') return -1;
    } else {
        if (source[index] < '1' || source[index] > '9') return -1;
        while (index < length && source[index] >= '0' && source[index] <= '9') ++index;
    }
    if (index < length && source[index] == '.') {
        ++index;
        if (index >= length || source[index] < '0' || source[index] > '9') return -1;
        while (index < length && source[index] >= '0' && source[index] <= '9') ++index;
    }
    if (index < length && (source[index] == 'e' || source[index] == 'E')) {
        ++index;
        if (index < length && (source[index] == '+' || source[index] == '-')) ++index;
        if (index >= length || source[index] < '0' || source[index] > '9') return -1;
        while (index < length && source[index] >= '0' && source[index] <= '9') ++index;
    }
    char following = index < length ? source[index] : '\0';
    if (!number_delimiter(following)) return -1;
    *end = index;
    return 0;
}

static int add_token(
    struct asteriskd_json_document *document,
    enum asteriskd_json_type type,
    size_t start,
    size_t end,
    size_t parent,
    bool count_child,
    size_t *token_index) {
    if (document->token_count >= document->token_capacity) return -1;
    size_t index = document->token_count++;
    document->tokens[index] = (struct asteriskd_json_token){
        .type = type,
        .start = start,
        .end = end,
        .parent = parent,
        .child_count = 0U,
    };
    if (count_child && parent != SIZE_MAX) ++document->tokens[parent].child_count;
    *token_index = index;
    return 0;
}

void asteriskd_json_document_destroy(struct asteriskd_json_document *document) {
    if (document == NULL) return;
    free(document->tokens);
    memset(document, 0, sizeof(*document));
}

static bool state_expects_value(enum parser_state state) {
    return state == STATE_OBJECT_VALUE || state == STATE_ARRAY_VALUE || state == STATE_ARRAY_VALUE_OR_END;
}

static void value_completed(struct parser_frame *frame) {
    if (frame->state == STATE_OBJECT_VALUE) {
        frame->state = STATE_OBJECT_COMMA_OR_END;
    } else {
        frame->state = STATE_ARRAY_COMMA_OR_END;
    }
}

int asteriskd_json_parse(
    const char *source,
    size_t length,
    struct asteriskd_json_document *document,
    char *message,
    size_t message_size) {
    if (document != NULL) memset(document, 0, sizeof(*document));
    if (source == NULL || document == NULL) {
        set_message(message, message_size, "invalid JSON arguments");
        return -1;
    }
    if (length == 0U || length > ASTERISKD_MAX_JSON_SIZE) {
        set_message(message, message_size, "invalid JSON size");
        return -1;
    }
    if (!valid_utf8(source, length)) {
        set_message(message, message_size, "invalid UTF-8");
        return ASTERISKD_CONFIG_INVALID;
    }
    document->source = source;
    document->source_length = length;
    size_t capacity = length + 1U;
    if (capacity > ASTERISKD_JSON_MAX_TOKENS) capacity = ASTERISKD_JSON_MAX_TOKENS;
    if (capacity > SIZE_MAX / sizeof(*document->tokens)) {
        set_message(message, message_size, "JSON token allocation overflow");
        memset(document, 0, sizeof(*document));
        return ASTERISKD_CONFIG_INVALID;
    }
    document->tokens = calloc(capacity, sizeof(*document->tokens));
    if (document->tokens == NULL) {
        set_message(message, message_size, "out of memory");
        memset(document, 0, sizeof(*document));
        return ASTERISKD_CONFIG_NO_MEMORY;
    }
    document->token_capacity = capacity;
    struct parser_frame frames[ASTERISKD_JSON_MAX_DEPTH];
    size_t depth = 0U;
    bool root_complete = false;
    size_t index = 0U;

    while (index < length) {
        while (index < length && is_space(source[index])) ++index;
        if (index >= length) break;

        if (depth > 0U) {
            struct parser_frame *frame = &frames[depth - 1U];
            char value = source[index];
            if ((frame->state == STATE_OBJECT_KEY_OR_END || frame->state == STATE_OBJECT_COMMA_OR_END) && value == '}') {
                if (frame->state == STATE_OBJECT_COMMA_OR_END || frame->state == STATE_OBJECT_KEY_OR_END) {
                    document->tokens[frame->token].end = index + 1U;
                    --depth;
                    ++index;
                    if (depth == 0U) root_complete = true;
                    continue;
                }
            }
            if ((frame->state == STATE_ARRAY_VALUE_OR_END || frame->state == STATE_ARRAY_COMMA_OR_END) && value == ']') {
                document->tokens[frame->token].end = index + 1U;
                --depth;
                ++index;
                if (depth == 0U) root_complete = true;
                continue;
            }
            if (frame->state == STATE_OBJECT_COMMA_OR_END || frame->state == STATE_ARRAY_COMMA_OR_END) {
                if (value != ',') {
                    set_message(message, message_size, "expected comma at byte %zu", index);
                    goto fail;
                }
                frame->state = frame->state == STATE_OBJECT_COMMA_OR_END ? STATE_OBJECT_KEY : STATE_ARRAY_VALUE;
                ++index;
                continue;
            }
            if (frame->state == STATE_OBJECT_COLON) {
                if (value != ':') {
                    set_message(message, message_size, "expected colon at byte %zu", index);
                    goto fail;
                }
                frame->state = STATE_OBJECT_VALUE;
                ++index;
                continue;
            }
            if (frame->state == STATE_OBJECT_KEY_OR_END || frame->state == STATE_OBJECT_KEY) {
                if (value != '"') {
                    set_message(message, message_size, "expected object key at byte %zu", index);
                    goto fail;
                }
                size_t end = 0U;
                size_t token = 0U;
                if (scan_string(source, length, index, &end) != 0 ||
                    add_token(document, ASTERISKD_JSON_STRING, index + 1U, end - 1U, frame->token, false, &token) != 0) {
                    set_message(message, message_size, "invalid object key at byte %zu", index);
                    goto fail;
                }
                (void)token;
                frame->state = STATE_OBJECT_COLON;
                index = end;
                continue;
            }
            if (!state_expects_value(frame->state)) {
                set_message(message, message_size, "unexpected token at byte %zu", index);
                goto fail;
            }
        } else if (root_complete) {
            set_message(message, message_size, "trailing JSON data at byte %zu", index);
            goto fail;
        }

        size_t parent = depth == 0U ? SIZE_MAX : frames[depth - 1U].token;
        bool count_child = depth != 0U;
        char value = source[index];
        enum asteriskd_json_type type;
        size_t end = 0U;
        bool container = false;
        if (value == '{' || value == '[') {
            type = value == '{' ? ASTERISKD_JSON_OBJECT : ASTERISKD_JSON_ARRAY;
            end = index + 1U;
            container = true;
        } else if (value == '"') {
            type = ASTERISKD_JSON_STRING;
            if (scan_string(source, length, index, &end) != 0) {
                set_message(message, message_size, "invalid string at byte %zu", index);
                goto fail;
            }
        } else if (value == 't' && length - index >= 4U && memcmp(source + index, "true", 4U) == 0) {
            type = ASTERISKD_JSON_TRUE;
            end = index + 4U;
        } else if (value == 'f' && length - index >= 5U && memcmp(source + index, "false", 5U) == 0) {
            type = ASTERISKD_JSON_FALSE;
            end = index + 5U;
        } else if (value == 'n' && length - index >= 4U && memcmp(source + index, "null", 4U) == 0) {
            type = ASTERISKD_JSON_NULL;
            end = index + 4U;
        } else if (value == '-' || (value >= '0' && value <= '9')) {
            type = ASTERISKD_JSON_NUMBER;
            if (scan_number(source, length, index, &end) != 0) {
                set_message(message, message_size, "invalid number at byte %zu", index);
                goto fail;
            }
        } else {
            set_message(message, message_size, "invalid value at byte %zu", index);
            goto fail;
        }
        if (!container && end < length && !number_delimiter(source[end])) {
            set_message(message, message_size, "invalid value boundary at byte %zu", end);
            goto fail;
        }
        size_t token = 0U;
        size_t token_start = type == ASTERISKD_JSON_STRING ? index + 1U : index;
        size_t token_end = type == ASTERISKD_JSON_STRING ? end - 1U : end;
        if (add_token(document, type, token_start, token_end, parent, count_child, &token) != 0) {
            set_message(message, message_size, "too many JSON tokens");
            goto fail;
        }
        if (depth > 0U) value_completed(&frames[depth - 1U]);
        if (container) {
            if (depth >= ASTERISKD_JSON_MAX_DEPTH) {
                set_message(message, message_size, "JSON nesting too deep");
                goto fail;
            }
            frames[depth++] = (struct parser_frame){
                .token = token,
                .state = type == ASTERISKD_JSON_OBJECT ? STATE_OBJECT_KEY_OR_END : STATE_ARRAY_VALUE_OR_END,
            };
            ++index;
        } else {
            index = end;
            if (depth == 0U) root_complete = true;
        }
    }
    if (depth != 0U || !root_complete || document->token_count == 0U) {
        set_message(message, message_size, "incomplete JSON document");
        goto fail;
    }
    set_message(message, message_size, "ok");
    return 0;
fail:
    asteriskd_json_document_destroy(document);
    return ASTERISKD_CONFIG_INVALID;
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void reconcile_error(
    char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

int asteriskd_reconcile_owned_resources(
    const struct asteriskd_reconcile_backend *backend,
    struct asteriskd_reconcile_report *report,
    char *error,
    size_t error_size) {
    enum asteriskd_reconcile_phase phase;

    if (report != NULL) {
        memset(report, 0, sizeof(*report));
        report->failed_phase = ASTERISKD_RECONCILE_PHASE_COUNT;
    }
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (backend == NULL || report == NULL || backend->remove_phase == NULL ||
        backend->verify_absent == NULL) {
        reconcile_error(error, error_size, "invalid reconcile backend");
        return ASTERISKD_CONFIG_INVALID;
    }

    for (phase = ASTERISKD_RECONCILE_QUIESCE;
         phase < ASTERISKD_RECONCILE_PHASE_COUNT;
         phase = (enum asteriskd_reconcile_phase)((int)phase + 1)) {
        int result;

        report->attempted[phase] = true;
        result = backend->remove_phase(
            backend->context, phase, error, error_size);
        if (result != 0) {
            report->failed_phase = phase;
            return result;
        }
    }

    {
        int result = backend->verify_absent(
            backend->context, error, error_size);
        if (result != 0) return result;
    }
    report->verified_absent = true;
    return 0;
}

struct reconcile_output_token {
    const char *bytes;
    size_t length;
};

static bool reconcile_token_equals(
    const struct reconcile_output_token *token, const char *expected) {
    size_t expected_length = strlen(expected);
    return token->length == expected_length &&
        memcmp(token->bytes, expected, expected_length) == 0;
}

static bool json_token_equals(
    const struct asteriskd_json_document *document,
    const struct asteriskd_json_token *token,
    const char *expected) {
    size_t expected_length;

    if (document == NULL || token == NULL || expected == NULL ||
        token->type != ASTERISKD_JSON_STRING || token->end < token->start ||
        token->end > document->source_length) return false;
    expected_length = strlen(expected);
    return token->end - token->start == expected_length &&
        memcmp(document->source + token->start,
            expected, expected_length) == 0;
}

int asteriskd_ip_link_output_is_dummy(
    const char *bytes, size_t length, bool *owned) {
    struct asteriskd_json_document document;
    bool found = false;
    char error[128U];
    int result;

    if (owned != NULL) *owned = false;
    if (bytes == NULL || length == 0U || owned == NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
    result = asteriskd_json_parse(
        bytes, length, &document, error, sizeof(error));
    if (result != 0) return ASTERISKD_CONFIG_INVALID;
    if (document.token_count < 2U ||
        document.tokens[0].type != ASTERISKD_JSON_ARRAY ||
        document.tokens[0].child_count != 1U ||
        document.tokens[1].type != ASTERISKD_JSON_OBJECT ||
        document.tokens[1].parent != 0U) {
        result = ASTERISKD_CONFIG_INVALID;
        goto done;
    }
    for (size_t index = 2U; index + 1U < document.token_count; ++index) {
        const struct asteriskd_json_token *key = &document.tokens[index];
        const struct asteriskd_json_token *value = &document.tokens[index + 1U];

        if (!json_token_equals(&document, key, "info_kind")) continue;
        if (found || key->parent == SIZE_MAX || value->parent != key->parent ||
            value->type != ASTERISKD_JSON_STRING) {
            result = ASTERISKD_CONFIG_INVALID;
            goto done;
        }
        found = true;
        *owned = json_token_equals(&document, value, "dummy");
    }
    result = found && *owned ? 0 : ASTERISKD_CONFIG_INVALID;
done:
    asteriskd_json_document_destroy(&document);
    return result;
}

static int reconcile_line_tokens(
    const char *line,
    size_t length,
    struct reconcile_output_token *tokens,
    size_t capacity,
    size_t *count) {
    size_t offset = 0U;

    *count = 0U;
    while (offset < length) {
        size_t start;
        while (offset < length &&
            (line[offset] == ' ' || line[offset] == '\t')) ++offset;
        if (offset == length) break;
        start = offset;
        while (offset < length &&
            line[offset] != ' ' && line[offset] != '\t') {
            unsigned char byte = (unsigned char)line[offset];
            if (byte < 0x21U || byte >= 0x7fU) return -1;
            ++offset;
        }
        if (*count >= capacity) return -1;
        tokens[*count].bytes = line + start;
        tokens[*count].length = offset - start;
        ++*count;
    }
    return *count == 0U ? -1 : 0;
}

int asteriskd_owned_policy_rule_output_count(
    const char *bytes,
    size_t length,
    const struct asteriskd_owned_policy_rule *rule,
    size_t *count) {
    char priority[24U];
    char mark[32U];
    char table[16U];
    size_t offset = 0U;

    if (count != NULL) *count = 0U;
    if ((length != 0U && bytes == NULL) || rule == NULL || count == NULL ||
        (rule->family != ASTERISKD_IP_FAMILY_IPV4 &&
         rule->family != ASTERISKD_IP_FAMILY_IPV6) ||
        rule->table == 0U || rule->priority == 0U || rule->mark == 0U ||
        rule->mark_mask == 0U ||
        snprintf(priority, sizeof(priority), "%" PRIu32 ":", rule->priority) <= 0 ||
        snprintf(mark, sizeof(mark), "0x%08" PRIx32 "/0x%08" PRIx32,
            rule->mark, rule->mark_mask) <= 0 ||
        snprintf(table, sizeof(table), "%" PRIu32, rule->table) <= 0) {
        return ASTERISKD_CONFIG_INVALID;
    }

    while (offset < length) {
        const char *line = bytes + offset;
        const char *newline = memchr(line, '\n', length - offset);
        struct reconcile_output_token tokens[10U];
        size_t token_count = 0U;
        size_t line_length;
        bool matches;

        if (newline == NULL) return ASTERISKD_CONFIG_INVALID;
        line_length = (size_t)(newline - line);
        if (line_length != 0U && line[line_length - 1U] == '\r') --line_length;
        if (reconcile_line_tokens(line, line_length, tokens,
                sizeof(tokens) / sizeof(tokens[0]), &token_count) != 0) {
            return ASTERISKD_CONFIG_INVALID;
        }
        matches = rule->invert_from_all
            ? token_count == 8U &&
                reconcile_token_equals(&tokens[0], priority) &&
                reconcile_token_equals(&tokens[1], "not") &&
                reconcile_token_equals(&tokens[2], "from") &&
                reconcile_token_equals(&tokens[3], "all") &&
                reconcile_token_equals(&tokens[4], "fwmark") &&
                reconcile_token_equals(&tokens[5], mark) &&
                reconcile_token_equals(&tokens[6], "lookup") &&
                reconcile_token_equals(&tokens[7], table)
            : token_count == 7U &&
                reconcile_token_equals(&tokens[0], priority) &&
                reconcile_token_equals(&tokens[1], "from") &&
                reconcile_token_equals(&tokens[2], "all") &&
                reconcile_token_equals(&tokens[3], "fwmark") &&
                reconcile_token_equals(&tokens[4], mark) &&
                reconcile_token_equals(&tokens[5], "lookup") &&
                reconcile_token_equals(&tokens[6], table);
        if (matches) ++*count;
        offset = (size_t)(newline - bytes) + 1U;
    }
    return 0;
}

int asteriskd_reconcile_after_listener(
    enum asteriskd_control_listener_result listener_result,
    const struct asteriskd_reconcile_backend *backend,
    struct asteriskd_reconcile_report *report,
    char *error,
    size_t error_size) {
    if (listener_result != ASTERISKD_CONTROL_LISTENER_OK) {
        if (report != NULL) {
            memset(report, 0, sizeof(*report));
            report->failed_phase = ASTERISKD_RECONCILE_PHASE_COUNT;
        }
        if (error != NULL && error_size != 0U) error[0] = '\0';
        reconcile_error(error, error_size, "control listener not acquired");
        return ASTERISKD_CONFIG_NOT_READY;
    }
    return asteriskd_reconcile_owned_resources(
        backend, report, error, error_size);
}

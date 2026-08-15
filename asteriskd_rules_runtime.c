// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

struct output_token {
    const char *bytes;
    size_t length;
};

static bool output_token_equals(const struct output_token *token, const char *text) {
    size_t length = strlen(text);
    return token->length == length && memcmp(token->bytes, text, length) == 0;
}

static bool output_token_decimal(const struct output_token *token) {
    if (token->length == 0U) return false;
    for (size_t index = 0U; index < token->length; ++index) {
        if (token->bytes[index] < '0' || token->bytes[index] > '9') return false;
    }
    return true;
}

static bool output_tokens_equal(
    const struct output_token *tokens, size_t count,
    const char *const *expected, size_t expected_count) {
    if (count != expected_count) return false;
    for (size_t index = 0U; index < count; ++index) {
        if (!output_token_equals(&tokens[index], expected[index])) return false;
    }
    return true;
}

static bool output_token_route_table(
    const struct output_token *token, const char *decimal, uint32_t table) {
    if (output_token_equals(token, decimal)) return true;
    return (table == 255U && output_token_equals(token, "local")) ||
        (table == 254U && output_token_equals(token, "main")) ||
        (table == 253U && output_token_equals(token, "default"));
}

static int output_line_tokens(
    const char *bytes, size_t length, struct output_token *tokens,
    size_t capacity, size_t *count) {
    *count = 0U;
    if (bytes == NULL || length == 0U || tokens == NULL || capacity == 0U ||
        memchr(bytes, '\0', length) != NULL || memchr(bytes, '\n', length) != NULL ||
        memchr(bytes, '\r', length) != NULL) return -1;
    size_t offset = 0U;
    while (offset < length) {
        while (offset < length && (bytes[offset] == ' ' || bytes[offset] == '\t')) ++offset;
        if (offset == length) break;
        size_t start = offset;
        while (offset < length && bytes[offset] != ' ' && bytes[offset] != '\t') {
            unsigned char byte = (unsigned char)bytes[offset];
            if (byte < 0x21U || byte >= 0x7fU) return -1;
            ++offset;
        }
        if (*count == capacity) return -1;
        tokens[*count] = (struct output_token){
            .bytes = bytes + start,
            .length = offset - start,
        };
        ++*count;
    }
    return *count == 0U ? -1 : 0;
}

int asteriskd_ip_rule_output_classify(
    const char *bytes, size_t length, const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state) {
    if (effect == NULL || state == NULL || effect->kind != ASTERISKD_ROUTE_EFFECT_IP_RULE ||
        (effect->family != ASTERISKD_IP_FAMILY_IPV4 &&
         effect->family != ASTERISKD_IP_FAMILY_IPV6) || effect->table == 0U ||
        effect->priority == 0U || effect->mark == 0U || effect->mark_mask == 0U) return -1;
    *state = ASTERISKD_RULES_SLOT_ABSENT;
    if (length == 0U) return 0;
    char priority[24U];
    char mark[32U];
    char table[16U];
    if (snprintf(priority, sizeof(priority), "%" PRIu32 ":", effect->priority) <= 0 ||
        snprintf(mark, sizeof(mark), "0x%08" PRIx32 "/0x%08" PRIx32,
            effect->mark, effect->mark_mask) <= 0 ||
        snprintf(table, sizeof(table), "%" PRIu32, effect->table) <= 0) return -1;
    const char *normal[] = {priority, "from", "all", "fwmark", mark, "lookup", table};
    const char *inverted[] = {
        priority, "not", "from", "all", "fwmark", mark, "lookup", table,
    };
    size_t matches = 0U;
    size_t offset = 0U;
    while (offset < length) {
        const char *line = bytes + offset;
        const char *newline = memchr(line, '\n', length - offset);
        if (newline == NULL) return -1;
        size_t line_length = (size_t)(newline - line);
        if (line_length != 0U && line[line_length - 1U] == '\r') --line_length;
        struct output_token tokens[12U];
        size_t count = 0U;
        if (output_line_tokens(line, line_length, tokens,
                sizeof(tokens) / sizeof(tokens[0]), &count) != 0) return -1;
        if (output_token_equals(&tokens[0], priority)) {
            ++matches;
            bool owned = output_tokens_equal(tokens, count,
                effect->invert_from_all ? inverted : normal,
                effect->invert_from_all ? sizeof(inverted) / sizeof(inverted[0]) :
                    sizeof(normal) / sizeof(normal[0]));
            if (!owned || matches > 1U) {
                *state = ASTERISKD_RULES_SLOT_FOREIGN;
                return 0;
            }
        }
        offset = (size_t)(newline - bytes) + 1U;
    }
    *state = matches == 1U ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_ABSENT;
    return 0;
}

static bool route_suffix_valid(
    const struct output_token *tokens, size_t count, size_t offset,
    const char *table_decimal, uint32_t table) {
    unsigned seen = 0U;
    while (offset < count) {
        unsigned bit = 0U;
        if (output_token_equals(&tokens[offset], "linkdown") ||
            output_token_equals(&tokens[offset], "onlink")) {
            bit = output_token_equals(&tokens[offset], "linkdown") ? 1U << 0U : 1U << 1U;
            ++offset;
        } else {
            if (offset + 1U >= count) return false;
            if (output_token_equals(&tokens[offset], "proto")) {
                bit = 1U << 2U;
                if (!output_token_equals(&tokens[offset + 1U], "boot") &&
                    !output_token_equals(&tokens[offset + 1U], "static") &&
                    !output_token_equals(&tokens[offset + 1U], "kernel")) return false;
            } else if (output_token_equals(&tokens[offset], "scope")) {
                bit = 1U << 3U;
                if (!output_token_equals(&tokens[offset + 1U], "link") &&
                    !output_token_equals(&tokens[offset + 1U], "host") &&
                    !output_token_equals(&tokens[offset + 1U], "global")) return false;
            } else if (output_token_equals(&tokens[offset], "metric")) {
                bit = 1U << 4U;
                if (!output_token_decimal(&tokens[offset + 1U])) return false;
            } else if (output_token_equals(&tokens[offset], "pref")) {
                bit = 1U << 5U;
                if (!output_token_equals(&tokens[offset + 1U], "low") &&
                    !output_token_equals(&tokens[offset + 1U], "medium") &&
                    !output_token_equals(&tokens[offset + 1U], "high")) return false;
            } else if (output_token_equals(&tokens[offset], "table")) {
                bit = 1U << 6U;
                if (!output_token_route_table(
                        &tokens[offset + 1U], table_decimal, table)) return false;
            } else {
                return false;
            }
            offset += 2U;
        }
        if ((seen & bit) != 0U) return false;
        seen |= bit;
    }
    return true;
}

int asteriskd_ip_route_output_classify(
    const char *bytes, size_t length, const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state) {
    if (effect == NULL || state == NULL || effect->kind != ASTERISKD_ROUTE_EFFECT_ROUTE ||
        (effect->family != ASTERISKD_IP_FAMILY_IPV4 &&
         effect->family != ASTERISKD_IP_FAMILY_IPV6) || effect->table == 0U ||
        effect->destination[0] == '\0' || effect->interface_name[0] == '\0') return -1;
    *state = ASTERISKD_RULES_SLOT_ABSENT;
    if (length == 0U) return 0;
    char table[16U];
    if (snprintf(table, sizeof(table), "%" PRIu32, effect->table) <= 0) return -1;
    size_t matches = 0U;
    size_t line_offset = 0U;
    while (line_offset < length) {
        const char *line = bytes + line_offset;
        const char *newline = memchr(line, '\n', length - line_offset);
        if (newline == NULL) return -1;
        size_t line_length = (size_t)(newline - line);
        if (line_length != 0U && line[line_length - 1U] == '\r') --line_length;
        struct output_token tokens[20U];
        size_t count = 0U;
        if (output_line_tokens(line, line_length, tokens,
                sizeof(tokens) / sizeof(tokens[0]), &count) != 0) return -1;
        size_t offset = effect->local_route ? 1U : 0U;
        bool destination_matches = count > offset &&
            output_token_equals(&tokens[offset], effect->destination);
        bool table_matches = false;
        bool table_present = false;
        for (size_t index = offset + 1U; index + 1U < count; ++index) {
            if (!output_token_equals(&tokens[index], "table")) continue;
            table_present = true;
            table_matches = output_token_route_table(
                &tokens[index + 1U], table, effect->table);
            break;
        }
        bool only_line = line_offset == 0U && (size_t)(newline - bytes) + 1U == length;
        if (destination_matches && (table_matches || (only_line && !table_present))) {
            ++matches;
            bool owned = !effect->local_route || output_token_equals(&tokens[0], "local");
            owned = owned && count > ++offset && output_token_equals(&tokens[offset], "dev");
            owned = owned && count > ++offset &&
                output_token_equals(&tokens[offset], effect->interface_name);
            ++offset;
            owned = owned && route_suffix_valid(
                tokens, count, offset, table, effect->table);
            if (!owned || matches > 1U) {
                *state = ASTERISKD_RULES_SLOT_FOREIGN;
                return 0;
            }
        }
        line_offset = (size_t)(newline - bytes) + 1U;
    }
    *state = matches == 1U ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_ABSENT;
    return 0;
}

int asteriskd_xtables_private_chain_counts(
    const char *bytes, size_t length, const char *chain,
    size_t *declaration_count, size_t *rule_count) {
    if (bytes == NULL || length == 0U || chain == NULL ||
        declaration_count == NULL || rule_count == NULL ||
        memchr(bytes, '\0', length) != NULL) return -1;
    size_t chain_length = strnlen(chain, ASTERISKD_MAX_CHAIN_NAME);
    if (chain_length == 0U || chain_length >= ASTERISKD_MAX_CHAIN_NAME ||
        bytes[length - 1U] != '\n') return -1;

    *declaration_count = 0U;
    *rule_count = 0U;
    size_t offset = 0U;
    while (offset < length) {
        const char *line = bytes + offset;
        const char *newline = memchr(line, '\n', length - offset);
        if (newline == NULL) return -1;
        size_t line_length = (size_t)(newline - line);
        if (line_length != 0U && line[line_length - 1U] == '\r') --line_length;
        if (line_length == 0U) return -1;

        if (line_length == chain_length + 3U &&
            memcmp(line, "-N ", 3U) == 0 &&
            memcmp(line + 3U, chain, chain_length) == 0) {
            ++*declaration_count;
        } else if (line_length > chain_length + 4U &&
            memcmp(line, "-A ", 3U) == 0 &&
            memcmp(line + 3U, chain, chain_length) == 0 &&
            line[chain_length + 3U] == ' ') {
            ++*rule_count;
        }
        offset = (size_t)(newline - bytes) + 1U;
    }
    return 0;
}

bool asteriskd_xtables_private_chain_shape_valid(
    const char *bytes, size_t length, const char *chain, size_t expected_rule_count) {
    size_t declarations = 0U;
    size_t rules = 0U;
    return asteriskd_xtables_private_chain_counts(
        bytes, length, chain, &declarations, &rules) == 0 &&
        declarations == 1U && rules == expected_rule_count;
}

size_t asteriskd_xtables_hook_arguments(
    const struct asteriskd_traffic_hook *hook, const char **arguments) {
    if (hook == NULL || arguments == NULL) return 0U;
    size_t count = 0U;
    if (hook->udp_destination_port_53) {
        arguments[count++] = "-p";
        arguments[count++] = "udp";
        arguments[count++] = "-m";
        arguments[count++] = "udp";
        arguments[count++] = "--dport";
        arguments[count++] = "53";
    }
    arguments[count++] = "-j";
    if (hook->verdict == ASTERISKD_HOOK_JUMP) {
        arguments[count++] = hook->jump_target;
    } else if (hook->verdict == ASTERISKD_HOOK_DROP) {
        arguments[count++] = "DROP";
    } else if (hook->verdict == ASTERISKD_HOOK_REJECT) {
        arguments[count++] = "REJECT";
        arguments[count++] = "--reject-with";
        arguments[count++] = "icmp6-port-unreachable";
    } else {
        return 0U;
    }
    return count;
}

int asteriskd_xtables_rule_output_locate(
    const char *bytes, size_t length, const char *chain,
    const char *const *arguments, size_t argument_count,
    size_t *matches, size_t *position) {
    if (bytes == NULL || length == 0U || chain == NULL || matches == NULL ||
        position == NULL ||
        (argument_count != 0U && arguments == NULL) ||
        memchr(bytes, '\0', length) != NULL || bytes[length - 1U] != '\n') return -1;
    size_t chain_length = strnlen(chain, ASTERISKD_MAX_CHAIN_NAME);
    if (chain_length == 0U || chain_length >= ASTERISKD_MAX_CHAIN_NAME) return -1;

    char expected[ASTERISKD_MAX_CHILD_ARG * 9U];
    int prefix = snprintf(expected, sizeof(expected), "-A %s", chain);
    if (prefix <= 0 || (size_t)prefix >= sizeof(expected)) return -1;
    size_t expected_length = (size_t)prefix;
    for (size_t index = 0U; index < argument_count; ++index) {
        const char *argument = arguments[index];
        size_t argument_length = argument == NULL ? 0U :
            strnlen(argument, ASTERISKD_MAX_CHILD_ARG);
        if (argument_length == 0U || argument_length >= ASTERISKD_MAX_CHILD_ARG ||
            strpbrk(argument, " \t\r\n") != NULL ||
            expected_length > sizeof(expected) - argument_length - 2U) return -1;
        expected[expected_length++] = ' ';
        memcpy(expected + expected_length, argument, argument_length);
        expected_length += argument_length;
        expected[expected_length] = '\0';
    }

    *matches = 0U;
    *position = 0U;
    size_t rule_position = 0U;
    size_t offset = 0U;
    while (offset < length) {
        const char *line = bytes + offset;
        const char *newline = memchr(line, '\n', length - offset);
        if (newline == NULL) return -1;
        size_t line_length = (size_t)(newline - line);
        if (line_length != 0U && line[line_length - 1U] == '\r') --line_length;
        bool is_chain_rule = line_length >= (size_t)prefix &&
            memcmp(line, expected, (size_t)prefix) == 0 &&
            (line_length == (size_t)prefix || line[(size_t)prefix] == ' ');
        if (is_chain_rule) ++rule_position;
        if (line_length == expected_length && memcmp(line, expected, expected_length) == 0) {
            ++*matches;
            *position = rule_position;
        }
        offset = (size_t)(newline - bytes) + 1U;
    }
    return 0;
}

int asteriskd_xtables_rule_output_count(
    const char *bytes, size_t length, const char *chain,
    const char *const *arguments, size_t argument_count, size_t *matches) {
    size_t position = 0U;
    return asteriskd_xtables_rule_output_locate(
        bytes, length, chain, arguments, argument_count, matches, &position);
}

void asteriskd_rules_runtime_init(struct asteriskd_rules_runtime *runtime) {
    if (runtime == NULL) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->initialized = true;
}

static bool rules_backend_complete(const struct asteriskd_rules_backend *backend) {
    return backend != NULL && backend->wal_apply_plan != NULL &&
        backend->wal_apply_private != NULL &&
        backend->wal_apply_route != NULL && backend->wal_apply_hook != NULL &&
        backend->probe_private != NULL && backend->probe_route != NULL &&
        backend->probe_hook != NULL && backend->wal_remove_private != NULL &&
        backend->wal_remove_route != NULL && backend->wal_remove_hook != NULL;
}

static bool runtime_has_cleanup(const struct asteriskd_rules_runtime *runtime) {
    for (size_t index = 0U; index < ASTERISKD_RULE_TRANSACTION_MAX_GROUPS; ++index) {
        if (runtime->private_cleanup_required[index] || runtime->hook_cleanup_required[index]) {
            return true;
        }
    }
    for (size_t index = 0U; index < ASTERISKD_RULE_TRANSACTION_MAX_ROUTES; ++index) {
        if (runtime->route_cleanup_required[index]) return true;
    }
    return false;
}

int asteriskd_rules_install(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_config *config,
    bool has_global_ipv6_address,
    const struct asteriskd_rules_backend *backend) {
    if (runtime == NULL || !runtime->initialized || config == NULL || !rules_backend_complete(backend) ||
        runtime->installed || runtime_has_cleanup(runtime)) return ASTERISKD_CONFIG_INVALID;
    struct asteriskd_rule_transaction_plan plan;
    int result = asteriskd_rule_transaction_plan_build(config, has_global_ipv6_address, &plan);
    if (result != 0) return result;
    runtime->plan = plan;
    if (plan.no_op ||
        (plan.private_group_count == 0U && plan.route_count == 0U &&
         plan.hook_group_count == 0U)) {
        runtime->installed = true;
        ++runtime->generation;
        return 0;
    }
    for (size_t index = 0U; index < plan.private_group_count; ++index) {
        runtime->private_cleanup_required[index] = true;
    }
    for (size_t index = 0U; index < plan.route_count; ++index) {
        runtime->route_cleanup_required[index] = true;
    }
    for (size_t index = 0U; index < plan.hook_group_count; ++index) {
        runtime->hook_cleanup_required[index] = true;
    }
    if (backend->wal_apply_plan(backend->ctx, &runtime->plan) != 0) {
        return ASTERISKD_CONFIG_IO;
    }
    runtime->installed = true;
    ++runtime->generation;
    return 0;
}

static int verify_private(
    const struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.private_group_count; ++index) {
        if (!runtime->private_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_private(backend->ctx, &runtime->plan.private_groups[index], &state) != 0 ||
            state != ASTERISKD_RULES_SLOT_OWNED) return ASTERISKD_CONFIG_IO;
    }
    return 0;
}

static int verify_routes(
    const struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.route_count; ++index) {
        if (!runtime->route_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_route(backend->ctx, &runtime->plan.routes[index], &state) != 0 ||
            state != ASTERISKD_RULES_SLOT_OWNED) return ASTERISKD_CONFIG_IO;
    }
    return 0;
}

static int verify_hooks(
    const struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.hook_group_count; ++index) {
        if (!runtime->hook_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_hook(backend->ctx, &runtime->plan.hook_groups[index], &state) != 0 ||
            state != ASTERISKD_RULES_SLOT_OWNED) return ASTERISKD_CONFIG_IO;
    }
    return 0;
}

int asteriskd_rules_verify(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    if (runtime == NULL || !runtime->initialized || !runtime->installed ||
        !rules_backend_complete(backend)) return ASTERISKD_CONFIG_INVALID;
    if (runtime->plan.no_op) return 0;
    if (verify_private(runtime, backend) != 0 || verify_routes(runtime, backend) != 0 ||
        verify_hooks(runtime, backend) != 0) return ASTERISKD_CONFIG_IO;
    return 0;
}

static int reconcile_private(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.private_group_count; ++index) {
        if (!runtime->private_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_private(backend->ctx, &runtime->plan.private_groups[index], &state) != 0 ||
            state == ASTERISKD_RULES_SLOT_FOREIGN) return ASTERISKD_CONFIG_IO;
        if (state == ASTERISKD_RULES_SLOT_ABSENT &&
            backend->wal_apply_private(backend->ctx, &runtime->plan.private_groups[index]) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
    }
    return 0;
}

static int reconcile_routes(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.route_count; ++index) {
        if (!runtime->route_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_route(backend->ctx, &runtime->plan.routes[index], &state) != 0 ||
            state == ASTERISKD_RULES_SLOT_FOREIGN) return ASTERISKD_CONFIG_IO;
        if (state == ASTERISKD_RULES_SLOT_ABSENT &&
            backend->wal_apply_route(backend->ctx, &runtime->plan.routes[index]) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
    }
    return 0;
}

static int reconcile_hooks(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    for (size_t index = 0U; index < runtime->plan.hook_group_count; ++index) {
        if (!runtime->hook_cleanup_required[index]) continue;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (backend->probe_hook(backend->ctx, &runtime->plan.hook_groups[index], &state) != 0 ||
            state == ASTERISKD_RULES_SLOT_FOREIGN) return ASTERISKD_CONFIG_IO;
        if (state == ASTERISKD_RULES_SLOT_ABSENT &&
            backend->wal_apply_hook(backend->ctx, &runtime->plan.hook_groups[index]) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
    }
    return 0;
}

int asteriskd_rules_reconcile(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    if (runtime == NULL || !runtime->initialized || !runtime->installed ||
        !rules_backend_complete(backend)) return ASTERISKD_CONFIG_INVALID;
    if (!runtime->plan.no_op && (reconcile_private(runtime, backend) != 0 ||
            reconcile_routes(runtime, backend) != 0 || reconcile_hooks(runtime, backend) != 0)) {
        return ASTERISKD_CONFIG_IO;
    }
    ++runtime->generation;
    return 0;
}

int asteriskd_rules_remove(
    struct asteriskd_rules_runtime *runtime,
    const struct asteriskd_rules_backend *backend) {
    if (runtime == NULL || !runtime->initialized || !rules_backend_complete(backend)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    int result = 0;
    for (size_t count = runtime->plan.hook_group_count; count > 0U; --count) {
        size_t index = count - 1U;
        if (!runtime->hook_cleanup_required[index]) continue;
        if (backend->wal_remove_hook(backend->ctx, &runtime->plan.hook_groups[index]) == 0) {
            runtime->hook_cleanup_required[index] = false;
        } else {
            result = ASTERISKD_CONFIG_IO;
        }
    }
    for (size_t count = runtime->plan.route_count; count > 0U; --count) {
        size_t index = count - 1U;
        if (!runtime->route_cleanup_required[index]) continue;
        if (backend->wal_remove_route(backend->ctx, &runtime->plan.routes[index]) == 0) {
            runtime->route_cleanup_required[index] = false;
        } else {
            result = ASTERISKD_CONFIG_IO;
        }
    }
    for (size_t count = runtime->plan.private_group_count; count > 0U; --count) {
        size_t index = count - 1U;
        if (!runtime->private_cleanup_required[index]) continue;
        if (backend->wal_remove_private(backend->ctx, &runtime->plan.private_groups[index]) == 0) {
            runtime->private_cleanup_required[index] = false;
        } else {
            result = ASTERISKD_CONFIG_IO;
        }
    }
    if (!runtime_has_cleanup(runtime)) runtime->installed = false;
    return result;
}

static bool rules_recovery_kind(enum asteriskd_recovery_kind kind) {
    return kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN ||
        kind == ASTERISKD_RECOVERY_IPTABLES_RULE || kind == ASTERISKD_RECOVERY_IP_RULE ||
        kind == ASTERISKD_RECOVERY_ROUTE || kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE;
}

int asteriskd_rules_recover(
    const struct asteriskd_recovery_record *records,
    size_t count,
    const struct asteriskd_rules_backend *backend) {
    if ((records == NULL && count != 0U) || backend == NULL ||
        backend->wal_recover_record == NULL) return ASTERISKD_CONFIG_INVALID;
    int result = 0;
    for (size_t remaining = count; remaining > 0U; --remaining) {
        const struct asteriskd_recovery_record *record = &records[remaining - 1U];
        if (!rules_recovery_kind(record->kind)) continue;
        if (backend->wal_recover_record(backend->ctx, record) != 0) result = ASTERISKD_CONFIG_IO;
    }
    return result;
}

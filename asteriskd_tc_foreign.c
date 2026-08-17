#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != NULL && capacity != 0U) (void)snprintf(error, capacity, "%s", message);
}

static bool lowercase_hex(const char *value, bool exact_tag) {
    size_t length = strnlen(value, ASTERISKD_MAX_HEX_ID);
    if (length == 0U || length >= ASTERISKD_MAX_HEX_ID || (length & 1U) != 0U ||
        (exact_tag && length != ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH)) return false;
    for (size_t index = 0U; index < length; ++index) {
        char byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) return false;
    }
    return true;
}

static bool interface_name_valid(const char *name) {
    size_t length = name == NULL ? 0U : strnlen(name, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strcmp(name, "all") == 0 || strcmp(name, "default") == 0 ||
        strcmp(name, "lo") == 0) return false;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)name[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || byte == '_' || byte == '-' || byte == '.')) {
            return false;
        }
    }
    return true;
}

static bool trusted_tether_bpf_name(const char *name) {
    static const char *const names[] = {
        "prog_offload_schedcls_tether_upstream6_ether",
        "prog_offload_schedcls_tether_upstream6_rawip",
        "prog_offload_schedcls_tether_downstream6_ether",
        "prog_offload_schedcls_tether_downstream6_rawip",
    };
    for (size_t index = 0U; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (strcmp(name, names[index]) == 0) return true;
    }
    return false;
}

static bool probe_valid(const struct asteriskd_foreign_tc_probe *probe) {
    if (probe == NULL || !interface_name_valid(probe->interface_name) ||
        probe->interface_index == 0U || probe->interface_link_index == 0U ||
        probe->interface_hardware_type == 0U || !lowercase_hex(probe->interface_address, false) ||
        probe->parent != ASTERISKD_TC_PARENT_CLSACT_INGRESS || probe->chain != 0U ||
        probe->protocol != ASTERISKD_ETH_PROTOCOL_IPV6 ||
        probe->priority != ASTERISKD_ANDROID_TETHER_TC_PRIORITY || probe->handle == 0U ||
        strnlen(probe->bpf_name, sizeof(probe->bpf_name)) == 0U ||
        strnlen(probe->bpf_name, sizeof(probe->bpf_name)) >= sizeof(probe->bpf_name) ||
        probe->bpf_flags != ASTERISKD_TC_BPF_FLAG_ACT_DIRECT ||
        probe->program_object_id == 0U ||
        probe->program_type != ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS ||
        !trusted_tether_bpf_name(probe->bpf_name) ||
        (probe->bpf_flags_gen & ~UINT32_C(0xf)) != 0U ||
        (probe->bpf_flags_gen & UINT32_C(0xc)) == UINT32_C(0xc) ||
        !lowercase_hex(probe->program_tag, true) || !probe->direct_action ||
        !probe->trusted_system_pin_match || probe->unknown_attributes) return false;
    return true;
}

struct json_member {
    size_t key;
    size_t value;
};

static bool token_equals(
    const struct asteriskd_json_document *document, size_t token_index, const char *expected) {
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    size_t expected_length = strlen(expected);
    return token->type == ASTERISKD_JSON_STRING && token->end >= token->start &&
        token->end - token->start == expected_length &&
        memcmp(document->source + token->start, expected, expected_length) == 0;
}

static int object_members(
    const struct asteriskd_json_document *document, size_t object_index,
    struct json_member *members, size_t capacity, size_t *count) {
    if (document == NULL || object_index >= document->token_count || members == NULL ||
        count == NULL || document->tokens[object_index].type != ASTERISKD_JSON_OBJECT ||
        document->tokens[object_index].child_count > capacity) return -1;
    size_t direct[32U];
    size_t direct_count = 0U;
    if (capacity > sizeof(direct) / sizeof(direct[0])) return -1;
    for (size_t index = object_index + 1U; index < document->token_count; ++index) {
        if (document->tokens[index].parent != object_index) continue;
        if (direct_count >= capacity * 2U) return -1;
        direct[direct_count++] = index;
    }
    size_t member_count = document->tokens[object_index].child_count;
    if (direct_count != member_count * 2U) return -1;
    for (size_t index = 0U; index < member_count; ++index) {
        size_t key = direct[index * 2U];
        size_t value = direct[index * 2U + 1U];
        if (document->tokens[key].type != ASTERISKD_JSON_STRING) return -1;
        for (size_t prior = 0U; prior < index; ++prior) {
            const struct asteriskd_json_token *left = &document->tokens[key];
            const struct asteriskd_json_token *right = &document->tokens[members[prior].key];
            size_t left_length = left->end - left->start;
            size_t right_length = right->end - right->start;
            if (left_length == right_length &&
                memcmp(document->source + left->start,
                    document->source + right->start, left_length) == 0) return -1;
        }
        members[index] = (struct json_member){.key = key, .value = value};
    }
    *count = member_count;
    return 0;
}

static int member_value(
    const struct asteriskd_json_document *document, const struct json_member *members,
    size_t count, const char *name, size_t *value) {
    for (size_t index = 0U; index < count; ++index) {
        if (token_equals(document, members[index].key, name)) {
            *value = members[index].value;
            return 0;
        }
    }
    return -1;
}

static int token_u32(
    const struct asteriskd_json_document *document, size_t token_index, uint32_t *value) {
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->type != ASTERISKD_JSON_NUMBER || token->start >= token->end) return -1;
    uint32_t result = 0U;
    for (size_t index = token->start; index < token->end; ++index) {
        unsigned char byte = (unsigned char)document->source[index];
        if (byte < '0' || byte > '9') return -1;
        uint32_t digit = (uint32_t)(byte - '0');
        if (result > (UINT32_MAX - digit) / 10U) return -1;
        result = result * 10U + digit;
    }
    *value = result;
    return 0;
}

static int token_ascii_string(
    const struct asteriskd_json_document *document, size_t token_index,
    char *value, size_t capacity) {
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->type != ASTERISKD_JSON_STRING || token->end < token->start) return -1;
    size_t length = token->end - token->start;
    if (length == 0U || length >= capacity) return -1;
    for (size_t index = token->start; index < token->end; ++index) {
        unsigned char byte = (unsigned char)document->source[index];
        if (byte < 0x20U || byte >= 0x7fU || byte == '\\') return -1;
    }
    memcpy(value, document->source + token->start, length);
    value[length] = '\0';
    return 0;
}

static int token_hex_u32(
    const struct asteriskd_json_document *document, size_t token_index, uint32_t *value) {
    char text[16U];
    if (token_ascii_string(document, token_index, text, sizeof(text)) != 0 ||
        text[0] != '0' || text[1] != 'x' || text[2] == '\0') return -1;
    uint32_t result = 0U;
    for (size_t index = 2U; text[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)text[index];
        uint32_t digit;
        if (byte >= '0' && byte <= '9') digit = (uint32_t)(byte - '0');
        else if (byte >= 'a' && byte <= 'f') digit = (uint32_t)(byte - 'a') + 10U;
        else return -1;
        if (result > (UINT32_MAX - digit) / 16U) return -1;
        result = result * 16U + digit;
    }
    if (result == 0U) return -1;
    *value = result;
    return 0;
}

static int parse_program(
    const struct asteriskd_json_document *document, size_t object_index,
    struct asteriskd_foreign_tc_probe *probe) {
    struct json_member members[2U];
    size_t count = 0U;
    size_t id = 0U;
    size_t tag = 0U;
    uint32_t object_id = 0U;
    if (object_members(document, object_index, members, 2U, &count) != 0 || count != 2U ||
        member_value(document, members, count, "id", &id) != 0 ||
        member_value(document, members, count, "tag", &tag) != 0 ||
        token_u32(document, id, &object_id) != 0 || object_id == 0U ||
        token_ascii_string(document, tag, probe->program_tag, sizeof(probe->program_tag)) != 0 ||
        !lowercase_hex(probe->program_tag, true)) return -1;
    probe->program_object_id = object_id;
    probe->program_type = ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS;
    return 0;
}

static int parse_options(
    const struct asteriskd_json_document *document, size_t object_index,
    struct asteriskd_foreign_tc_probe *probe) {
    struct json_member members[8U];
    size_t count = 0U;
    size_t handle = 0U;
    size_t name = 0U;
    size_t direct = 0U;
    size_t program = 0U;
    if (object_members(document, object_index, members, 8U, &count) != 0 || count < 4U ||
        member_value(document, members, count, "handle", &handle) != 0 ||
        member_value(document, members, count, "bpf_name", &name) != 0 ||
        member_value(document, members, count, "direct-action", &direct) != 0 ||
        member_value(document, members, count, "prog", &program) != 0 ||
        token_hex_u32(document, handle, &probe->handle) != 0 ||
        token_ascii_string(document, name, probe->bpf_name, sizeof(probe->bpf_name)) != 0 ||
        document->tokens[direct].type != ASTERISKD_JSON_TRUE ||
        parse_program(document, program, probe) != 0) return -1;
    probe->direct_action = true;
    probe->bpf_flags = ASTERISKD_TC_BPF_FLAG_ACT_DIRECT;
    bool in_hw = false;
    bool not_in_hw = false;
    for (size_t index = 0U; index < count; ++index) {
        size_t key = members[index].key;
        size_t value = members[index].value;
        if (token_equals(document, key, "handle") || token_equals(document, key, "bpf_name") ||
            token_equals(document, key, "direct-action") || token_equals(document, key, "prog")) {
            continue;
        }
        if (document->tokens[value].type != ASTERISKD_JSON_TRUE) return -1;
        if (token_equals(document, key, "skip_hw")) probe->bpf_flags_gen |= 1U;
        else if (token_equals(document, key, "skip_sw")) probe->bpf_flags_gen |= 2U;
        else if (token_equals(document, key, "in_hw")) {
            probe->bpf_flags_gen |= 4U;
            in_hw = true;
        } else if (token_equals(document, key, "not_in_hw")) {
            probe->bpf_flags_gen |= 8U;
            not_in_hw = true;
        } else {
            return -1;
        }
    }
    return in_hw && not_in_hw ? -1 : 0;
}

int asteriskd_foreign_tc_json_parse(
    const char *json, size_t json_length, struct asteriskd_foreign_tc_probe *probe,
    bool *present, char *error, size_t error_capacity) {
    if (probe != NULL) memset(probe, 0, sizeof(*probe));
    if (present != NULL) *present = false;
    if (json == NULL || probe == NULL || present == NULL) {
        set_error(error, error_capacity, "invalid foreign TC JSON arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_json_document document;
    int result = asteriskd_json_parse(json, json_length, &document, error, error_capacity);
    if (result != 0) return result;
    bool valid = document.token_count > 0U &&
        document.tokens[0].type == ASTERISKD_JSON_ARRAY &&
        document.tokens[0].child_count <= 1U;
    size_t filter = SIZE_MAX;
    if (valid && document.tokens[0].child_count == 1U) {
        for (size_t index = 1U; index < document.token_count; ++index) {
            if (document.tokens[index].parent == 0U) {
                if (filter != SIZE_MAX) valid = false;
                filter = index;
            }
        }
        valid = valid && filter != SIZE_MAX &&
            document.tokens[filter].type == ASTERISKD_JSON_OBJECT;
    }
    if (valid && filter != SIZE_MAX) {
        struct json_member members[5U];
        size_t count = 0U;
        size_t protocol = 0U;
        size_t priority = 0U;
        size_t kind = 0U;
        size_t chain = 0U;
        size_t options = 0U;
        valid = object_members(&document, filter, members, 5U, &count) == 0 && count == 5U &&
            member_value(&document, members, count, "protocol", &protocol) == 0 &&
            member_value(&document, members, count, "pref", &priority) == 0 &&
            member_value(&document, members, count, "kind", &kind) == 0 &&
            member_value(&document, members, count, "chain", &chain) == 0 &&
            member_value(&document, members, count, "options", &options) == 0 &&
            token_equals(&document, protocol, "ipv6") && token_equals(&document, kind, "bpf") &&
            token_u32(&document, priority, &probe->priority) == 0 &&
            probe->priority == ASTERISKD_ANDROID_TETHER_TC_PRIORITY &&
            token_u32(&document, chain, &probe->chain) == 0 &&
            parse_options(&document, options, probe) == 0;
        probe->protocol = ASTERISKD_ETH_PROTOCOL_IPV6;
    }
    if (valid && filter != SIZE_MAX) {
        probe->unknown_attributes = false;
        *present = true;
    } else if (!valid) {
        memset(probe, 0, sizeof(*probe));
        set_error(error, error_capacity, "invalid foreign TC filter JSON");
        result = ASTERISKD_CONFIG_INVALID;
    }
    asteriskd_json_document_destroy(&document);
    return result;
}

static void program_tag_hex(
    const unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE],
    char output[ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH + 1U]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0U; index < ASTERISKD_BPF_PROGRAM_TAG_SIZE; ++index) {
        output[index * 2U] = digits[tag[index] >> 4U];
        output[index * 2U + 1U] = digits[tag[index] & 0x0fU];
    }
    output[ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH] = '\0';
}

struct netlink_header_wire {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t pid;
};

struct tc_message_wire {
    uint8_t family;
    uint8_t pad1;
    uint16_t pad2;
    int32_t interface_index;
    uint32_t handle;
    uint32_t parent;
    uint32_t info;
};

struct route_attribute_wire {
    uint16_t length;
    uint16_t type;
};

struct route_attribute_view {
    const unsigned char *data;
    size_t length;
};

static size_t align4(size_t value) {
    return (value + 3U) & ~((size_t)3U);
}

static int route_attributes(
    const unsigned char *bytes, size_t length,
    struct route_attribute_view *views, size_t view_count) {
    memset(views, 0, view_count * sizeof(*views));
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct route_attribute_wire)) return -1;
        struct route_attribute_wire attribute;
        memcpy(&attribute, bytes + offset, sizeof(attribute));
        size_t raw_length = attribute.length;
        size_t aligned_length = align4(raw_length);
        uint16_t type = (uint16_t)(attribute.type & UINT16_C(0x3fff));
        if (raw_length < sizeof(attribute) || aligned_length > length - offset ||
            type == 0U || type >= view_count || views[type].data != NULL) return -1;
        views[type].data = bytes + offset + sizeof(attribute);
        views[type].length = raw_length - sizeof(attribute);
        offset += aligned_length;
    }
    return offset == length ? 0 : -1;
}

static bool attribute_u32(const struct route_attribute_view *view, uint32_t *value) {
    if (view->data == NULL || view->length != sizeof(*value)) return false;
    memcpy(value, view->data, sizeof(*value));
    return true;
}

static bool attribute_string(
    const struct route_attribute_view *view, char *value, size_t capacity) {
    if (view->data == NULL || view->length < 2U || view->length > capacity ||
        view->data[view->length - 1U] != '\0') return false;
    size_t length = view->length - 1U;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char byte = view->data[index];
        if (byte < 0x20U || byte >= 0x7fU || byte == '\0') return false;
    }
    memcpy(value, view->data, view->length);
    return true;
}

static uint16_t network_to_host_u16(uint16_t value) {
    return (uint16_t)((value << 8U) | (value >> 8U));
}

static bool netlink_done_success(const unsigned char *payload, size_t length) {
    if (length == 0U) return true;
    if (payload == NULL || length != sizeof(int32_t)) return false;
    int32_t result = 0;
    memcpy(&result, payload, sizeof(result));
    return result == 0;
}

static int decode_tc_filter_message(
    const unsigned char *bytes, size_t length, uint32_t interface_index,
    struct asteriskd_foreign_tc_probe *probe, bool *present) {
    if (length < sizeof(struct tc_message_wire)) return -1;
    struct tc_message_wire message;
    memcpy(&message, bytes, sizeof(message));
    if (message.interface_index != (int32_t)interface_index) return 0;
    uint32_t priority = message.info >> 16U;
    uint32_t protocol = network_to_host_u16((uint16_t)(message.info & UINT32_C(0xffff)));
    if (priority != ASTERISKD_ANDROID_TETHER_TC_PRIORITY ||
        protocol != ASTERISKD_ETH_PROTOCOL_IPV6) return 0;
    if (*present || message.parent != ASTERISKD_TC_PARENT_CLSACT_INGRESS) return -1;
    struct route_attribute_view attributes[17U];
    if (route_attributes(bytes + sizeof(message), length - sizeof(message),
            attributes, sizeof(attributes) / sizeof(attributes[0])) != 0 ||
        attributes[1U].data == NULL) return -1;
    for (size_t type = 1U; type < sizeof(attributes) / sizeof(attributes[0]); ++type) {
        if (attributes[type].data == NULL) continue;
        if (type != 1U && type != 2U && type != 3U && type != 7U &&
            type != 9U && type != 11U && type != 12U) return -1;
    }
    char kind[8U];
    if (!attribute_string(&attributes[1U], kind, sizeof(kind)) ||
        strcmp(kind, "bpf") != 0) return -1;
    uint32_t chain = 0U;
    if (attributes[11U].data != NULL &&
        !attribute_u32(&attributes[11U], &chain)) return -1;
    if (chain != 0U) return -1;
    if (message.handle == 0U) return attributes[2U].data == NULL ? 0 : -1;
    if (attributes[2U].data == NULL) return -1;

    struct route_attribute_view options[12U];
    if (route_attributes(attributes[2U].data, attributes[2U].length,
            options, sizeof(options) / sizeof(options[0])) != 0) return -1;
    for (size_t type = 1U; type < sizeof(options) / sizeof(options[0]); ++type) {
        if (options[type].data != NULL &&
            type != 7U && type != 8U && type != 9U && type != 10U && type != 11U) return -1;
    }
    uint32_t flags = 0U;
    uint32_t flags_gen = 0U;
    uint32_t object_id = 0U;
    if (!attribute_string(&options[7U], probe->bpf_name, sizeof(probe->bpf_name)) ||
        !trusted_tether_bpf_name(probe->bpf_name) ||
        !attribute_u32(&options[8U], &flags) ||
        (options[9U].data != NULL && !attribute_u32(&options[9U], &flags_gen)) ||
        options[10U].data == NULL ||
        options[10U].length != ASTERISKD_BPF_PROGRAM_TAG_SIZE ||
        !attribute_u32(&options[11U], &object_id) ||
        flags != ASTERISKD_TC_BPF_FLAG_ACT_DIRECT ||
        (flags_gen & ~UINT32_C(0xf)) != 0U ||
        (flags_gen & UINT32_C(0xc)) == UINT32_C(0xc) || object_id == 0U) return -1;
    memset(probe->program_tag, 0, sizeof(probe->program_tag));
    program_tag_hex(options[10U].data, probe->program_tag);
    probe->parent = message.parent;
    probe->chain = chain;
    probe->protocol = protocol;
    probe->priority = priority;
    probe->handle = message.handle;
    probe->bpf_flags = flags;
    probe->bpf_flags_gen = flags_gen;
    probe->program_object_id = object_id;
    probe->program_type = ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS;
    probe->direct_action = true;
    probe->unknown_attributes = false;
    *present = true;
    return 0;
}

int asteriskd_foreign_tc_netlink_decode(
    const void *data, size_t length, uint32_t expected_sequence,
    uint32_t expected_port_id, uint32_t interface_index,
    struct asteriskd_foreign_tc_probe *probe,
    bool *present, bool *done, char *error, size_t error_capacity) {
    if (data == NULL || length == 0U || expected_sequence == 0U ||
        expected_port_id == 0U ||
        interface_index == 0U || probe == NULL || present == NULL || done == NULL) {
        set_error(error, error_capacity, "invalid foreign TC netlink arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    const unsigned char *bytes = data;
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct netlink_header_wire)) goto invalid;
        struct netlink_header_wire header;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            header.sequence != expected_sequence ||
            (header.pid != 0U && header.pid != expected_port_id)) goto invalid;
        const unsigned char *payload = bytes + offset + sizeof(header);
        size_t payload_length = header.length - sizeof(header);
        if (header.type == 3U) {
            if (!netlink_done_success(payload, payload_length)) goto invalid;
            *done = true;
        } else if (header.type == 2U) {
            int32_t netlink_error = 0;
            if (payload_length < sizeof(netlink_error)) goto invalid;
            memcpy(&netlink_error, payload, sizeof(netlink_error));
            if (netlink_error != 0) goto invalid;
        } else if (header.type == 4U) {
            goto invalid;
        } else if (header.type == 44U) {
            if (*done || decode_tc_filter_message(
                    payload, payload_length, interface_index, probe, present) != 0) goto invalid;
        } else if (header.type != 1U) {
            goto invalid;
        }
        size_t aligned = align4(header.length);
        if (aligned > length - offset) goto invalid;
        offset += aligned;
    }
    return 0;
invalid:
    memset(probe, 0, sizeof(*probe));
    *present = false;
    *done = false;
    set_error(error, error_capacity, "invalid foreign TC netlink response");
    return ASTERISKD_CONFIG_INVALID;
}

static bool tc_filter_expectation_valid(
    const struct asteriskd_tc_filter_expectation *expectation) {
    if (expectation == NULL || expectation->interface_index == 0U ||
        expectation->parent == 0U || expectation->protocol == 0U ||
        expectation->priority == 0U || expectation->handle == 0U ||
        expectation->bpf_flags != ASTERISKD_TC_BPF_FLAG_ACT_DIRECT ||
        (expectation->bpf_flags_gen & ~UINT32_C(0xf)) != 0U ||
        (expectation->bpf_flags_gen & UINT32_C(0xc)) == UINT32_C(0xc) ||
        expectation->bpf_flags_gen_mask == 0U ||
        (expectation->bpf_flags_gen_mask & ~UINT32_C(0xf)) != 0U ||
        (expectation->bpf_flags_gen & ~expectation->bpf_flags_gen_mask) != 0U ||
        expectation->program_object_id == 0U ||
        strnlen(expectation->bpf_name, sizeof(expectation->bpf_name)) == 0U ||
        strnlen(expectation->bpf_name, sizeof(expectation->bpf_name)) >=
            sizeof(expectation->bpf_name)) return false;
    bool nonzero_tag = false;
    for (size_t index = 0U; index < sizeof(expectation->program_tag); ++index) {
        if (expectation->program_tag[index] != 0U) nonzero_tag = true;
    }
    return nonzero_tag;
}

static int decode_expected_tc_filter_message(
    const unsigned char *bytes, size_t length,
    const struct asteriskd_tc_filter_expectation *expectation,
    enum asteriskd_rules_slot_state *state) {
    if (length < sizeof(struct tc_message_wire)) return -1;
    struct tc_message_wire message;
    memcpy(&message, bytes, sizeof(message));
    if (message.interface_index != (int32_t)expectation->interface_index) return 0;
    uint32_t priority = message.info >> 16U;
    uint32_t protocol = network_to_host_u16((uint16_t)(message.info & UINT32_C(0xffff)));
    if (priority != expectation->priority || protocol != expectation->protocol) return 0;
    if (message.parent != expectation->parent || message.handle != expectation->handle) {
        return 0;
    }
    if (*state != ASTERISKD_RULES_SLOT_ABSENT) {
        *state = ASTERISKD_RULES_SLOT_FOREIGN;
        return 0;
    }
    struct route_attribute_view attributes[17U];
    if (route_attributes(bytes + sizeof(message), length - sizeof(message),
            attributes, sizeof(attributes) / sizeof(attributes[0])) != 0 ||
        attributes[1U].data == NULL || attributes[2U].data == NULL) return -1;
    for (size_t type = 1U; type < sizeof(attributes) / sizeof(attributes[0]); ++type) {
        if (attributes[type].data == NULL) continue;
        if (type != 1U && type != 2U && type != 3U && type != 7U &&
            type != 9U && type != 11U && type != 12U) return -1;
    }
    char kind[8U];
    uint32_t chain = 0U;
    if (!attribute_string(&attributes[1U], kind, sizeof(kind)) ||
        (attributes[11U].data != NULL && !attribute_u32(&attributes[11U], &chain))) return -1;

    struct route_attribute_view options[12U];
    if (route_attributes(attributes[2U].data, attributes[2U].length,
            options, sizeof(options) / sizeof(options[0])) != 0) return -1;
    for (size_t type = 1U; type < sizeof(options) / sizeof(options[0]); ++type) {
        if (options[type].data != NULL && type != 7U && type != 8U &&
            type != 9U && type != 10U && type != 11U) return -1;
    }
    char bpf_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t flags = 0U;
    uint32_t flags_gen = 0U;
    uint32_t object_id = 0U;
    if (!attribute_string(&options[7U], bpf_name, sizeof(bpf_name)) ||
        !attribute_u32(&options[8U], &flags) ||
        (options[9U].data != NULL && !attribute_u32(&options[9U], &flags_gen)) ||
        options[10U].data == NULL ||
        options[10U].length != ASTERISKD_BPF_PROGRAM_TAG_SIZE ||
        !attribute_u32(&options[11U], &object_id)) return -1;
    bool flags_gen_valid = (flags_gen & ~UINT32_C(0xf)) == 0U &&
        (flags_gen & UINT32_C(0xc)) != UINT32_C(0xc);
    bool exact = strcmp(kind, "bpf") == 0 && chain == 0U && flags_gen_valid &&
        strcmp(bpf_name, expectation->bpf_name) == 0 &&
        flags == expectation->bpf_flags &&
        (flags_gen & expectation->bpf_flags_gen_mask) == expectation->bpf_flags_gen &&
        object_id == expectation->program_object_id &&
        memcmp(options[10U].data, expectation->program_tag,
            ASTERISKD_BPF_PROGRAM_TAG_SIZE) == 0;
    *state = exact ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_FOREIGN;
    return 0;
}

int asteriskd_tc_filter_netlink_decode(
    const void *data, size_t length, uint32_t expected_sequence,
    uint32_t expected_port_id,
    const struct asteriskd_tc_filter_expectation *expectation,
    enum asteriskd_rules_slot_state *state, bool *done,
    char *error, size_t error_capacity) {
    if (data == NULL || length == 0U || expected_sequence == 0U ||
        expected_port_id == 0U ||
        !tc_filter_expectation_valid(expectation) || state == NULL || done == NULL ||
        (*state != ASTERISKD_RULES_SLOT_ABSENT &&
         *state != ASTERISKD_RULES_SLOT_OWNED &&
         *state != ASTERISKD_RULES_SLOT_FOREIGN)) {
        set_error(error, error_capacity, "invalid TC filter netlink arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    const unsigned char *bytes = data;
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct netlink_header_wire)) goto invalid;
        struct netlink_header_wire header;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            header.sequence != expected_sequence ||
            (header.pid != 0U && header.pid != expected_port_id)) goto invalid;
        const unsigned char *payload = bytes + offset + sizeof(header);
        size_t payload_length = header.length - sizeof(header);
        if (header.type == 3U) {
            if (!netlink_done_success(payload, payload_length)) goto invalid;
            *done = true;
        } else if (header.type == 2U) {
            int32_t netlink_error = 0;
            if (payload_length < sizeof(netlink_error)) goto invalid;
            memcpy(&netlink_error, payload, sizeof(netlink_error));
            if (netlink_error != 0) goto invalid;
        } else if (header.type == 4U) {
            goto invalid;
        } else if (header.type == 44U) {
            if (*done || decode_expected_tc_filter_message(
                    payload, payload_length, expectation, state) != 0) goto invalid;
        } else if (header.type != 1U) {
            goto invalid;
        }
        size_t aligned = align4(header.length);
        if (aligned > length - offset) goto invalid;
        offset += aligned;
    }
    return 0;
invalid:
    *state = ASTERISKD_RULES_SLOT_FOREIGN;
    *done = false;
    set_error(error, error_capacity, "invalid TC filter netlink response");
    return ASTERISKD_CONFIG_INVALID;
}

static bool tc_filter_slot_expectation_valid(
    const struct asteriskd_tc_filter_expectation *expectation) {
    return expectation != NULL && expectation->interface_index != 0U &&
        expectation->parent != 0U && expectation->protocol != 0U &&
        expectation->priority != 0U && expectation->handle != 0U;
}

static int decode_tc_filter_slot_message(
    const unsigned char *bytes, size_t length,
    const struct asteriskd_tc_filter_expectation *expectation,
    enum asteriskd_rules_slot_state *state) {
    if (length < sizeof(struct tc_message_wire)) return -1;
    struct tc_message_wire message;
    memcpy(&message, bytes, sizeof(message));
    if (message.interface_index != (int32_t)expectation->interface_index) return 0;
    uint32_t priority = message.info >> 16U;
    uint32_t protocol = network_to_host_u16((uint16_t)(message.info & UINT32_C(0xffff)));
    if (message.parent != expectation->parent || priority != expectation->priority ||
        protocol != expectation->protocol || message.handle != expectation->handle) return 0;
    *state = ASTERISKD_RULES_SLOT_FOREIGN;
    return 0;
}

int asteriskd_tc_filter_slot_netlink_decode(
    const void *data, size_t length, uint32_t expected_sequence,
    uint32_t expected_port_id,
    const struct asteriskd_tc_filter_expectation *expectation,
    enum asteriskd_rules_slot_state *state,
    bool *done, char *error, size_t error_capacity) {
    if (data == NULL || length == 0U || expected_sequence == 0U ||
        expected_port_id == 0U || !tc_filter_slot_expectation_valid(expectation) ||
        state == NULL || done == NULL ||
        (*state != ASTERISKD_RULES_SLOT_ABSENT &&
         *state != ASTERISKD_RULES_SLOT_FOREIGN)) {
        set_error(error, error_capacity, "invalid TC filter slot netlink arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    const unsigned char *bytes = data;
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct netlink_header_wire)) goto invalid;
        struct netlink_header_wire header;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            header.sequence != expected_sequence ||
            (header.pid != 0U && header.pid != expected_port_id)) goto invalid;
        const unsigned char *payload = bytes + offset + sizeof(header);
        size_t payload_length = header.length - sizeof(header);
        if (header.type == 3U) {
            if (!netlink_done_success(payload, payload_length)) goto invalid;
            *done = true;
        } else if (header.type == 2U) {
            int32_t netlink_error = 0;
            if (payload_length < sizeof(netlink_error)) goto invalid;
            memcpy(&netlink_error, payload, sizeof(netlink_error));
            if (netlink_error != 0) goto invalid;
        } else if (header.type == 4U) {
            goto invalid;
        } else if (header.type == 44U) {
            if (*done || decode_tc_filter_slot_message(
                    payload, payload_length, expectation, state) != 0) goto invalid;
        } else if (header.type != 1U) {
            goto invalid;
        }
        size_t aligned = align4(header.length);
        if (aligned > length - offset) goto invalid;
        offset += aligned;
    }
    return 0;
invalid:
    *state = ASTERISKD_RULES_SLOT_FOREIGN;
    *done = false;
    set_error(error, error_capacity, "invalid TC filter slot netlink response");
    return ASTERISKD_CONFIG_INVALID;
}

static int decode_tc_qdisc_message(
    const unsigned char *bytes, size_t length, uint32_t interface_index,
    enum asteriskd_rules_slot_state *state) {
    if (length < sizeof(struct tc_message_wire)) return -1;
    struct tc_message_wire message;
    memcpy(&message, bytes, sizeof(message));
    if (message.interface_index != (int32_t)interface_index) return 0;
    struct route_attribute_view attributes[15U];
    if (route_attributes(bytes + sizeof(message), length - sizeof(message),
            attributes, sizeof(attributes) / sizeof(attributes[0])) != 0 ||
        attributes[1U].data == NULL) return -1;
    for (size_t type = 1U; type < sizeof(attributes) / sizeof(attributes[0]); ++type) {
        if (attributes[type].data == NULL) continue;
        if (type != 1U && type != 2U && type != 3U && type != 4U &&
            type != 6U && type != 7U && type != 8U && type != 9U &&
            type != 10U && type != 12U && type != 13U && type != 14U) return -1;
    }
    char kind[16U];
    if (!attribute_string(&attributes[1U], kind, sizeof(kind))) return -1;
    bool claims_clsact_slot = message.parent == ASTERISKD_TC_PARENT_CLSACT ||
        message.handle == ASTERISKD_TC_HANDLE_CLSACT || strcmp(kind, "clsact") == 0;
    if (!claims_clsact_slot) return 0;
    if (*state != ASTERISKD_RULES_SLOT_ABSENT || strcmp(kind, "clsact") != 0 ||
        message.parent != ASTERISKD_TC_PARENT_CLSACT ||
        message.handle != ASTERISKD_TC_HANDLE_CLSACT ||
        (attributes[2U].data != NULL && attributes[2U].length != 0U) ||
        attributes[13U].data != NULL || attributes[14U].data != NULL) {
        *state = ASTERISKD_RULES_SLOT_FOREIGN;
        return 0;
    }
    *state = ASTERISKD_RULES_SLOT_OWNED;
    return 0;
}

int asteriskd_tc_qdisc_netlink_decode(
    const void *data, size_t length, uint32_t expected_sequence,
    uint32_t expected_port_id, uint32_t interface_index,
    enum asteriskd_rules_slot_state *state,
    bool *done, char *error, size_t error_capacity) {
    if (data == NULL || length == 0U || expected_sequence == 0U ||
        expected_port_id == 0U ||
        interface_index == 0U || state == NULL || done == NULL ||
        (*state != ASTERISKD_RULES_SLOT_ABSENT &&
         *state != ASTERISKD_RULES_SLOT_OWNED &&
         *state != ASTERISKD_RULES_SLOT_FOREIGN)) {
        set_error(error, error_capacity, "invalid TC qdisc netlink arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    const unsigned char *bytes = data;
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct netlink_header_wire)) goto invalid;
        struct netlink_header_wire header;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            header.sequence != expected_sequence ||
            (header.pid != 0U && header.pid != expected_port_id)) goto invalid;
        const unsigned char *payload = bytes + offset + sizeof(header);
        size_t payload_length = header.length - sizeof(header);
        if (header.type == 3U) {
            if (!netlink_done_success(payload, payload_length)) goto invalid;
            *done = true;
        } else if (header.type == 2U) {
            int32_t netlink_error = 0;
            if (payload_length < sizeof(netlink_error)) goto invalid;
            memcpy(&netlink_error, payload, sizeof(netlink_error));
            if (netlink_error != 0) goto invalid;
        } else if (header.type == 4U) {
            goto invalid;
        } else if (header.type == 36U) {
            if (*done || decode_tc_qdisc_message(
                    payload, payload_length, interface_index, state) != 0) goto invalid;
        } else if (header.type != 1U) {
            goto invalid;
        }
        size_t aligned = align4(header.length);
        if (aligned > length - offset) goto invalid;
        offset += aligned;
    }
    return 0;
invalid:
    *state = ASTERISKD_RULES_SLOT_FOREIGN;
    *done = false;
    set_error(error, error_capacity, "invalid TC qdisc netlink response");
    return ASTERISKD_CONFIG_INVALID;
}

int asteriskd_foreign_tc_trusted_pin_find(
    struct asteriskd_foreign_tc_probe *probe, const char *const *trusted_paths,
    size_t trusted_path_count, const struct asteriskd_bpf_program_backend *backend,
    char *selected_path, size_t selected_path_capacity, char *error, size_t error_capacity) {
    if (selected_path != NULL && selected_path_capacity != 0U) selected_path[0] = '\0';
    if (probe != NULL) probe->trusted_system_pin_match = false;
    if (probe == NULL || trusted_paths == NULL || trusted_path_count == 0U ||
        backend == NULL || backend->open_program == NULL || backend->program_info == NULL ||
        backend->close == NULL || selected_path == NULL || selected_path_capacity == 0U ||
        probe->program_object_id == 0U ||
        probe->program_type != ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS ||
        !lowercase_hex(probe->program_tag, true) ||
        strnlen(probe->bpf_name, sizeof(probe->bpf_name)) == 0U ||
        strnlen(probe->bpf_name, sizeof(probe->bpf_name)) >= sizeof(probe->bpf_name)) {
        set_error(error, error_capacity, "invalid trusted TC program arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    size_t match_count = 0U;
    const char *match = NULL;
    for (size_t index = 0U; index < trusted_path_count; ++index) {
        const char *path = trusted_paths[index];
        if (path == NULL || path[0] != '/') continue;
        const char *base = strrchr(path, '/');
        if (base == NULL || strcmp(base + 1U, probe->bpf_name) != 0) continue;
        int fd = -1;
        struct asteriskd_bpf_program_info info;
        memset(&info, 0, sizeof(info));
        int opened = backend->open_program(backend->context, path, &fd);
        int inspected = opened == 0 && fd >= 0
            ? backend->program_info(backend->context, fd, &info) : -1;
        int closed = fd >= 0 ? backend->close(backend->context, fd) : 0;
        char tag[ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH + 1U];
        program_tag_hex(info.tag, tag);
        if (opened == 0 && inspected == 0 && closed == 0 &&
            info.object_id == probe->program_object_id &&
            info.type == ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS &&
            strcmp(tag, probe->program_tag) == 0) {
            ++match_count;
            match = path;
        }
    }
    if (match_count != 1U || match == NULL || strlen(match) >= selected_path_capacity) {
        set_error(error, error_capacity, "TC program does not match one trusted system pin");
        return ASTERISKD_CONFIG_INVALID;
    }
    (void)snprintf(selected_path, selected_path_capacity, "%s", match);
    probe->trusted_system_pin_match = true;
    return 0;
}

static bool program_info_matches_probe(
    const struct asteriskd_bpf_program_info *info,
    const struct asteriskd_foreign_tc_probe *probe) {
    char tag[ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH + 1U];
    program_tag_hex(info->tag, tag);
    return info->object_id == probe->program_object_id &&
        info->type == ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS &&
        strcmp(tag, probe->program_tag) == 0;
}

int asteriskd_foreign_tc_pin_clone(
    const struct asteriskd_foreign_tc_probe *probe, const char *source_path,
    const char *destination_path, const struct asteriskd_bpf_program_backend *backend,
    uint64_t *object_id, char *error, size_t error_capacity) {
    if (object_id != NULL) *object_id = 0U;
    if (probe == NULL || !probe->trusted_system_pin_match || source_path == NULL ||
        destination_path == NULL || source_path[0] != '/' || destination_path[0] != '/' ||
        strcmp(source_path, destination_path) == 0 || object_id == NULL || backend == NULL ||
        backend->open_program == NULL || backend->program_info == NULL ||
        backend->pin_program == NULL || backend->close == NULL) {
        set_error(error, error_capacity, "invalid foreign TC pin clone arguments");
        return ASTERISKD_CONFIG_INVALID;
    }
    int source_fd = -1;
    struct asteriskd_bpf_program_info source_info;
    memset(&source_info, 0, sizeof(source_info));
    if (backend->open_program(backend->context, source_path, &source_fd) != 0 ||
        source_fd < 0 || backend->program_info(
            backend->context, source_fd, &source_info) != 0 ||
        !program_info_matches_probe(&source_info, probe)) {
        if (source_fd >= 0) (void)backend->close(backend->context, source_fd);
        set_error(error, error_capacity, "trusted TC source program changed");
        return ASTERISKD_CONFIG_INVALID;
    }
    int pinned = backend->pin_program(backend->context, source_fd, destination_path);
    int source_closed = backend->close(backend->context, source_fd);
    if (pinned != 0 || source_closed != 0) {
        set_error(error, error_capacity, "cannot create TC recovery pin");
        return ASTERISKD_CONFIG_INVALID;
    }
    int destination_fd = -1;
    struct asteriskd_bpf_program_info destination_info;
    memset(&destination_info, 0, sizeof(destination_info));
    if (backend->open_program(backend->context, destination_path, &destination_fd) != 0 ||
        destination_fd < 0 || backend->program_info(
            backend->context, destination_fd, &destination_info) != 0 ||
        !program_info_matches_probe(&destination_info, probe) ||
        destination_info.object_id != source_info.object_id) {
        if (destination_fd >= 0) (void)backend->close(backend->context, destination_fd);
        set_error(error, error_capacity, "TC recovery pin identity mismatch");
        return ASTERISKD_CONFIG_INVALID;
    }
    if (backend->close(backend->context, destination_fd) != 0) {
        set_error(error, error_capacity, "cannot close TC recovery pin");
        return ASTERISKD_CONFIG_INVALID;
    }
    *object_id = source_info.object_id;
    return 0;
}

int asteriskd_foreign_tc_plan_build(
    const struct asteriskd_foreign_tc_probe *probe, uint64_t recovery_pin_record_id,
    struct asteriskd_foreign_tc_plan *plan, char *error, size_t error_capacity) {
    if (plan == NULL) {
        set_error(error, error_capacity, "foreign TC plan output is required");
        return ASTERISKD_CONFIG_INVALID;
    }
    memset(plan, 0, sizeof(*plan));
    if (!probe_valid(probe) || recovery_pin_record_id == 0U ||
        recovery_pin_record_id == UINT64_MAX) {
        set_error(error, error_capacity, "untrusted foreign TC filter");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_foreign_tc_operation *pin = &plan->operations[0];
    pin->kind = ASTERISKD_FOREIGN_TC_PIN_PROGRAM;
    pin->recovery.record_id = recovery_pin_record_id;
    pin->recovery.status = ASTERISKD_RECOVERY_INTENT;
    pin->recovery.kind = ASTERISKD_RECOVERY_BPF_PIN;
    pin->recovery.resource.bpf_pin.pin_id = ASTERISKD_PIN_HOTSPOT_RECOVERY;
    pin->recovery.resource.bpf_pin.original_presence = false;

    struct asteriskd_foreign_tc_operation *filter = &plan->operations[1];
    filter->kind = ASTERISKD_FOREIGN_TC_DELETE_FILTER;
    filter->recovery.record_id = recovery_pin_record_id + 1U;
    filter->recovery.status = ASTERISKD_RECOVERY_INTENT;
    filter->recovery.kind = ASTERISKD_RECOVERY_TC_FILTER;
    struct asteriskd_tc_filter_resource *resource = &filter->recovery.resource.tc_filter;
    resource->ownership = ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT;
    resource->inverse = ASTERISKD_TC_INVERSE_RESTORE;
    resource->filter_id = ASTERISKD_FILTER_HOTSPOT_IPV6_OFFLOAD;
    resource->direction = ASTERISKD_TC_DIRECTION_INGRESS;
    (void)snprintf(resource->interface_name, sizeof(resource->interface_name), "%s",
        probe->interface_name);
    resource->interface_index = probe->interface_index;
    resource->interface_link_index = probe->interface_link_index;
    resource->interface_hardware_type = probe->interface_hardware_type;
    (void)snprintf(resource->interface_address, sizeof(resource->interface_address), "%s",
        probe->interface_address);
    resource->parent = probe->parent;
    resource->chain = probe->chain;
    resource->protocol = probe->protocol;
    resource->priority = probe->priority;
    resource->handle = probe->handle;
    (void)snprintf(resource->bpf_name, sizeof(resource->bpf_name), "%s", probe->bpf_name);
    resource->bpf_flags = probe->bpf_flags;
    resource->bpf_flags_gen = probe->bpf_flags_gen;
    resource->program_id = ASTERISKD_PROGRAM_ANDROID_TETHER_OFFLOAD;
    resource->program_type = ASTERISKD_PROGRAM_TYPE_SCHED_CLS;
    (void)snprintf(resource->program_tag, sizeof(resource->program_tag), "%s", probe->program_tag);
    resource->recovery_pin_record_id = recovery_pin_record_id;
    resource->original_presence = true;
    plan->operation_count = 2U;
    return 0;
}

int asteriskd_foreign_tc_cleanup_plan_build(
    const struct asteriskd_foreign_tc_plan *active, struct asteriskd_foreign_tc_plan *cleanup) {
    if (cleanup == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(cleanup, 0, sizeof(*cleanup));
    if (active == NULL || active->operation_count != 2U ||
        active->operations[0].kind != ASTERISKD_FOREIGN_TC_PIN_PROGRAM ||
        active->operations[1].kind != ASTERISKD_FOREIGN_TC_DELETE_FILTER ||
        active->operations[0].recovery.kind != ASTERISKD_RECOVERY_BPF_PIN ||
        active->operations[1].recovery.kind != ASTERISKD_RECOVERY_TC_FILTER) {
        return ASTERISKD_CONFIG_INVALID;
    }
    cleanup->operations[0] = active->operations[1];
    cleanup->operations[0].kind = ASTERISKD_FOREIGN_TC_RESTORE_FILTER;
    cleanup->operations[1] = active->operations[0];
    cleanup->operations[1].kind = ASTERISKD_FOREIGN_TC_UNPIN_PROGRAM;
    cleanup->operation_count = 2U;
    return 0;
}

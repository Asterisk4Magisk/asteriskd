// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != NULL && capacity != 0U) (void)snprintf(error, capacity, "%s", message);
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

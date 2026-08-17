// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "asteriskd.h"

#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define TOKEN_NONE SIZE_MAX
#define STATE_TEMP_ATTEMPTS 32U

static const char *const phase_names[] = {
    "validating", "acquiring", "recovering", "starting", "applying-rules",
    "running", "stopping", "stopped", "failed",
};

static const char *const owner_names[] = {"asteriskng", "asteriskbox", "asteriskmeta"};
static const char *const core_names[] = {"xray", "sing-box", "mihomo"};
static const char *const mode_names[] = {"tproxy", "tun", "tun2socks", "bpf2socks", "ebpf"};
static const char *const child_role_names[] = {"core", "helper"};
static const char *const child_type_names[] = {
    "xray", "sing-box", "mihomo", "hev-socks5-tunnel", "bpf2socks",
};
static const char *const component_names[] = {
    "runtime", "core", "helper", "matcher", "rules", "network", "state", "log", "control",
};
static const char *const failure_names[] = {
    "start_failed", "readiness_timeout", "child_exited", "state_invalid", "state_incompatible",
    "resource_collision", "io_error", "stop_failed", "internal_error",
};
static const char *const category_names[] = {
    "tproxy", "routing", "dns", "fake-dns", "local-bypass", "hotspot", "tc", "bpf", "ipv6-guard",
};
static const char *const recovery_status_names[] = {"intent", "applied"};
static const char *const recovery_kind_names[] = {
    "iptables-chain", "iptables-rule", "ip-rule", "route", "dummy-interface",
    "bpf-pin", "tc-qdisc", "tc-filter", "sysctl", "tether-state",
};
static const char *const family_names[] = {"ipv4", "ipv6"};
static const char *const table_names[] = {"filter", "nat", "mangle"};
static const char *const chain_names[] = {
    "tproxy", "routing", "dns", "fake-dns", "local-bypass", "hotspot",
};
static const char *const rule_names[] = {
    "tproxy-entry", "routing-entry", "dns-entry", "fake-dns-entry",
    "local-bypass-entry", "hotspot-entry",
};
static const char *const ip_rule_names[] = {"tproxy", "tunnel", "token"};
static const char *const route_names[] = {"tproxy", "tunnel", "token"};
static const char *const interface_id_names[] = {"ipv6-dummy"};
static const char *const pin_names[] = {
    "matcher-output-v4", "matcher-output-v6", "matcher-prerouting-v4",
    "matcher-prerouting-v6", "bpf2socks-local-address-v4",
    "bpf2socks-local-address-v6", "bpf2socks-tc-ingress",
    "bpf2socks-tc-egress",
};
static const char *const qdisc_names[] = {"hotspot-clsact"};
static const char *const filter_names[] = {
    "hotspot-ingress", "hotspot-egress",
};
static const char *const direction_names[] = {"ingress", "egress"};
static const char *const program_names[] = {
    "bpf2socks-ingress", "bpf2socks-egress",
};
static const char *const tc_ownership_names[] = {"daemon"};
static const char *const tc_inverse_names[] = {"remove"};
static const char *const sysctl_names[] = {"disable-ipv6", "route-localnet"};
static const char *const tether_names[] = {"dnsmasq"};

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (error == NULL || error_size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static bool owner_core_valid(enum asteriskd_owner owner, enum asteriskd_core_type core) {
    return (owner == ASTERISKD_OWNER_NG && core == ASTERISKD_CORE_XRAY) ||
        (owner == ASTERISKD_OWNER_BOX && core == ASTERISKD_CORE_SING_BOX) ||
        (owner == ASTERISKD_OWNER_META && core == ASTERISKD_CORE_MIHOMO);
}

static bool bytes_are_zero(const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    for (size_t index = 0U; index < length; ++index) {
        if (cursor[index] != 0U) return false;
    }
    return true;
}

static bool child_identity_is_zero(const struct asteriskd_child_identity *child) {
    return child->role == 0 && child->type == 0 && child->pid == 0 &&
        child->process_group_id == 0 && child->start_time_ticks == 0U &&
        child->exe_device == 0U && child->exe_inode == 0U && child->argc == 0U &&
        bytes_are_zero(child->argv, sizeof(child->argv));
}

static bool interface_name_valid(const char *value, bool allow_default) {
    if (value == NULL) return false;
    size_t length = strnlen(value, ASTERISKD_MAX_INTERFACE_NAME);
    if (length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    if (length == strlen("default") && memcmp(value, "default", length) == 0) return allow_default;
    if ((length == 1U && value[0] == '.') ||
        (length == 2U && value[0] == '.' && value[1] == '.')) return false;
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    for (size_t index = 0U; index < length; ++index) {
        char ch = value[index];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-')) return false;
    }
    return true;
}

static bool child_type_matches_core(enum asteriskd_child_type type, enum asteriskd_core_type core) {
    return (type == ASTERISKD_CHILD_TYPE_XRAY && core == ASTERISKD_CORE_XRAY) ||
        (type == ASTERISKD_CHILD_TYPE_SING_BOX && core == ASTERISKD_CORE_SING_BOX) ||
        (type == ASTERISKD_CHILD_TYPE_MIHOMO && core == ASTERISKD_CORE_MIHOMO);
}

static bool child_valid(
    const struct asteriskd_state_document *document,
    const struct asteriskd_child_identity *child,
    enum asteriskd_child_role slot) {
    if (child == NULL || (slot != ASTERISKD_CHILD_CORE && slot != ASTERISKD_CHILD_HELPER) ||
        child->role != slot || child->type < 0 || child->type >= ASTERISKD_CHILD_TYPE_COUNT ||
        child->pid <= 0 || child->process_group_id != child->pid || child->start_time_ticks == 0U ||
        child->exe_inode == 0U || child->argc == 0U || child->argc > ASTERISKD_MAX_CHILD_ARGV) return false;
    for (size_t index = 0U; index < child->argc; ++index) {
        size_t length = strnlen(child->argv[index], ASTERISKD_MAX_CHILD_ARG);
        if (length == 0U || length >= ASTERISKD_MAX_CHILD_ARG) return false;
    }
    if (slot == ASTERISKD_CHILD_CORE) return child_type_matches_core(child->type, document->core_type);
    if (document->mode == ASTERISKD_MODE_TUN2SOCKS) {
        return child->type == ASTERISKD_CHILD_TYPE_HEV_SOCKS5_TUNNEL;
    }
    if (document->mode == ASTERISKD_MODE_BPF2SOCKS) return child->type == ASTERISKD_CHILD_TYPE_BPF2SOCKS;
    return false;
}

static bool tc_filter_valid(const struct asteriskd_tc_filter_resource *resource) {
    if (resource->filter_id < 0 || resource->filter_id >= ASTERISKD_FILTER_COUNT ||
        resource->direction < 0 || resource->direction >= ASTERISKD_TC_DIRECTION_COUNT ||
        resource->program_id < 0 || resource->program_id >= ASTERISKD_PROGRAM_COUNT ||
        !interface_name_valid(resource->interface_name, false) || resource->interface_index == 0U) return false;
    return !resource->original_presence &&
        ((resource->direction == ASTERISKD_TC_DIRECTION_INGRESS &&
          resource->filter_id == ASTERISKD_FILTER_HOTSPOT_INGRESS &&
          resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS) ||
         (resource->direction == ASTERISKD_TC_DIRECTION_EGRESS &&
          resource->filter_id == ASTERISKD_FILTER_HOTSPOT_EGRESS &&
          resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS));
}

static bool record_resource_valid(const struct asteriskd_recovery_record *record) {
    if (record == NULL || record->record_id == 0U || record->status < 0 ||
        record->status > ASTERISKD_RECOVERY_APPLIED || record->kind < 0 ||
        record->kind >= ASTERISKD_RECOVERY_KIND_COUNT) return false;
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN:
            return record->resource.iptables_chain.family >= 0 &&
                record->resource.iptables_chain.family < ASTERISKD_IP_FAMILY_COUNT &&
                record->resource.iptables_chain.table >= 0 &&
                record->resource.iptables_chain.table < ASTERISKD_IP_TABLE_COUNT &&
                record->resource.iptables_chain.chain_id >= 0 &&
                record->resource.iptables_chain.chain_id < ASTERISKD_CHAIN_COUNT;
        case ASTERISKD_RECOVERY_IPTABLES_RULE: {
            const struct asteriskd_iptables_rule_resource *resource = &record->resource.iptables_rule;
            return resource->family >= 0 && resource->family < ASTERISKD_IP_FAMILY_COUNT &&
                resource->table >= 0 && resource->table < ASTERISKD_IP_TABLE_COUNT &&
                resource->chain_id >= 0 && resource->chain_id < ASTERISKD_CHAIN_COUNT &&
                resource->rule_id >= 0 && resource->rule_id < ASTERISKD_RULE_COUNT &&
                ((!resource->has_interface &&
                  bytes_are_zero(resource->interface_name, sizeof(resource->interface_name)) &&
                  resource->interface_index == 0U) ||
                 (resource->has_interface && interface_name_valid(resource->interface_name, false) &&
                  resource->interface_index > 0U));
        }
        case ASTERISKD_RECOVERY_IP_RULE:
            return record->resource.ip_rule.family >= 0 &&
                record->resource.ip_rule.family < ASTERISKD_IP_FAMILY_COUNT &&
                record->resource.ip_rule.rule_id >= 0 &&
                record->resource.ip_rule.rule_id < ASTERISKD_IP_RULE_COUNT;
        case ASTERISKD_RECOVERY_ROUTE:
            return record->resource.route.family >= 0 &&
                record->resource.route.family < ASTERISKD_IP_FAMILY_COUNT &&
                record->resource.route.route_id >= 0 && record->resource.route.route_id < ASTERISKD_ROUTE_COUNT &&
                interface_name_valid(record->resource.route.interface_name, false) &&
                record->resource.route.interface_index > 0U;
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE:
            return record->resource.dummy_interface.interface_id >= 0 &&
                record->resource.dummy_interface.interface_id < ASTERISKD_INTERFACE_COUNT &&
                ((!record->resource.dummy_interface.has_interface_index &&
                  record->resource.dummy_interface.interface_index == 0U) ||
                 (record->resource.dummy_interface.has_interface_index &&
                  record->resource.dummy_interface.interface_index > 0U)) &&
                (record->status != ASTERISKD_RECOVERY_APPLIED ||
                 record->resource.dummy_interface.has_interface_index);
        case ASTERISKD_RECOVERY_BPF_PIN:
            return record->resource.bpf_pin.pin_id >= 0 &&
                record->resource.bpf_pin.pin_id < ASTERISKD_PIN_COUNT &&
                ((!record->resource.bpf_pin.has_object_id &&
                  record->resource.bpf_pin.object_id == 0U) ||
                 (record->resource.bpf_pin.has_object_id &&
                  record->resource.bpf_pin.object_id > 0U)) &&
                (record->status != ASTERISKD_RECOVERY_APPLIED ||
                 record->resource.bpf_pin.has_object_id);
        case ASTERISKD_RECOVERY_TC_QDISC:
            return record->resource.tc_qdisc.qdisc_id >= 0 &&
                record->resource.tc_qdisc.qdisc_id < ASTERISKD_QDISC_COUNT &&
                interface_name_valid(record->resource.tc_qdisc.interface_name, false) &&
                record->resource.tc_qdisc.interface_index > 0U;
        case ASTERISKD_RECOVERY_TC_FILTER:
            return tc_filter_valid(&record->resource.tc_filter);
        case ASTERISKD_RECOVERY_SYSCTL:
            return record->resource.sysctl.sysctl_id >= 0 &&
                record->resource.sysctl.sysctl_id < ASTERISKD_SYSCTL_COUNT &&
                interface_name_valid(record->resource.sysctl.interface_name, true) &&
                strcmp(record->resource.sysctl.interface_name, "all") != 0 &&
                strcmp(record->resource.sysctl.interface_name, "lo") != 0 &&
                ((strcmp(record->resource.sysctl.interface_name, "default") == 0 &&
                  record->resource.sysctl.interface_index == 0U) ||
                 (strcmp(record->resource.sysctl.interface_name, "default") != 0 &&
                  record->resource.sysctl.interface_index > 0U)) &&
                record->resource.sysctl.original_value <= 1U &&
                record->resource.sysctl.desired_value <= 1U;
        case ASTERISKD_RECOVERY_TETHER_STATE:
            return record->resource.tether_state.tether_id >= 0 &&
                record->resource.tether_state.tether_id < ASTERISKD_TETHER_COUNT &&
                interface_name_valid(record->resource.tether_state.interface_name, false) &&
                record->resource.tether_state.interface_index > 0U &&
                record->resource.tether_state.original_active &&
                !record->resource.tether_state.desired_active;
        case ASTERISKD_RECOVERY_KIND_COUNT:
            return false;
    }
    return false;
}

static bool failure_valid(const struct asteriskd_state_failure *failure) {
    if (!failure->present) {
        return failure->code == 0 && failure->component == 0 &&
            bytes_are_zero(failure->message, sizeof(failure->message)) &&
            !failure->has_exit_code && failure->exit_code == 0 &&
            !failure->has_signal && failure->signal == 0;
    }
    if (failure->code < 0 || failure->code >= ASTERISKD_FAILURE_CODE_COUNT ||
        failure->component < 0 || failure->component >= ASTERISKD_COMPONENT_COUNT ||
        failure->message[0] == '\0' ||
        strnlen(failure->message, sizeof(failure->message)) >= sizeof(failure->message)) return false;
    if ((!failure->has_exit_code && failure->exit_code != 0) ||
        (!failure->has_signal && failure->signal != 0)) return false;
    if (failure->code == ASTERISKD_FAILURE_CHILD_EXITED) {
        return failure->has_exit_code != failure->has_signal &&
            (!failure->has_exit_code || failure->exit_code >= 0) &&
            (!failure->has_signal || failure->signal > 0);
    }
    return !failure->has_exit_code && !failure->has_signal;
}

static bool document_valid(const struct asteriskd_state_document *document) {
    if (document == NULL || !document->initialized || document->schema_version != ASTERISKD_STATE_VERSION ||
        document->phase < 0 || document->phase >= ASTERISKD_PHASE_COUNT ||
        document->owner < 0 || document->owner > ASTERISKD_OWNER_META ||
        document->core_type < 0 || document->core_type > ASTERISKD_CORE_MIHOMO ||
        document->mode < 0 || document->mode > ASTERISKD_MODE_EBPF ||
        !owner_core_valid(document->owner, document->core_type) ||
        document->recovery.next_record_id == 0U ||
        document->recovery.record_count > document->recovery.record_capacity ||
        document->recovery.record_count > ASTERISKD_JSON_MAX_TOKENS / 5U ||
        (document->recovery.record_count != 0U && document->recovery.records == NULL) ||
        !failure_valid(&document->failure) ||
        (document->matcher.active && !document->matcher.configured) ||
        (document->matcher.configured &&
         document->mode != ASTERISKD_MODE_TPROXY && document->mode != ASTERISKD_MODE_TUN &&
         document->mode != ASTERISKD_MODE_TUN2SOCKS) ||
        (document->rules.categories & ~ASTERISKD_RULE_CATEGORY_ALL) != 0U) return false;
    if (document->children.core_present &&
        !child_valid(document, &document->children.core, ASTERISKD_CHILD_CORE)) return false;
    if (!document->children.core_present && !child_identity_is_zero(&document->children.core)) return false;
    if (document->children.helper_present &&
        !child_valid(document, &document->children.helper, ASTERISKD_CHILD_HELPER)) return false;
    if (!document->children.helper_present && !child_identity_is_zero(&document->children.helper)) return false;
    if (document->children.helper_present !=
        (document->mode == ASTERISKD_MODE_TUN2SOCKS || document->mode == ASTERISKD_MODE_BPF2SOCKS) &&
        document->phase == ASTERISKD_PHASE_RUNNING) return false;
    if (document->phase == ASTERISKD_PHASE_RUNNING && !document->children.core_present) return false;
    if (document->phase == ASTERISKD_PHASE_RUNNING &&
        (document->failure.present ||
         (document->mode != ASTERISKD_MODE_EBPF && !document->rules.active) ||
         (document->matcher.configured && !document->matcher.active))) return false;
    if (document->phase == ASTERISKD_PHASE_FAILED && !document->failure.present) return false;
    if (!document->rules.active &&
        (document->rules.generation != 0U || document->rules.categories != 0U)) return false;
    if (document->rules.active &&
        (document->rules.generation == 0U || document->rules.categories == 0U)) return false;
    if (document->mode == ASTERISKD_MODE_EBPF &&
        (document->matcher.configured || document->matcher.active || document->rules.active ||
         document->rules.generation != 0U || document->rules.categories != 0U ||
         document->children.helper_present)) return false;
    if (document->mode == ASTERISKD_MODE_EBPF && document->children.core_present &&
        (document->owner != ASTERISKD_OWNER_BOX ||
         document->core_type != ASTERISKD_CORE_SING_BOX ||
         !document->recovery.core_owned_ebpf_boundary)) return false;
    uint64_t previous = 0U;
    bool saw_intent = false;
    for (size_t index = 0U; index < document->recovery.record_count; ++index) {
        const struct asteriskd_recovery_record *record = &document->recovery.records[index];
        if (!record_resource_valid(record) || record->record_id <= previous ||
            record->record_id >= document->recovery.next_record_id) return false;
        if (record->status == ASTERISKD_RECOVERY_INTENT) saw_intent = true;
        else if (saw_intent) return false;
        previous = record->record_id;
    }
    if (document->owner == ASTERISKD_OWNER_BOX &&
        document->core_type == ASTERISKD_CORE_SING_BOX && document->mode == ASTERISKD_MODE_EBPF) {
        if (document->children.helper_present ||
            document->matcher.configured || document->matcher.active || document->rules.active ||
            document->rules.generation != 0U || document->rules.categories != 0U) return false;
        for (size_t index = 0U; index < document->recovery.record_count; ++index) {
            const struct asteriskd_recovery_record *record = &document->recovery.records[index];
            if (record->kind != ASTERISKD_RECOVERY_SYSCTL ||
                record->resource.sysctl.sysctl_id != ASTERISKD_SYSCTL_DISABLE_IPV6) return false;
        }
    }
    if (document->recovery.core_owned_ebpf_boundary &&
        (document->owner != ASTERISKD_OWNER_BOX || document->core_type != ASTERISKD_CORE_SING_BOX ||
         document->mode != ASTERISKD_MODE_EBPF)) return false;
    if (document->phase == ASTERISKD_PHASE_STOPPED &&
        (document->children.core_present || document->children.helper_present || document->matcher.active ||
         document->rules.active || document->rules.generation != 0U || document->rules.categories != 0U ||
         document->recovery.record_count != 0U || document->recovery.core_owned_ebpf_boundary)) return false;
    return true;
}

int asteriskd_state_document_init(
    struct asteriskd_state_document *document,
    enum asteriskd_owner owner,
    enum asteriskd_core_type core,
    enum asteriskd_mode mode) {
    if (document == NULL) return ASTERISKD_STATE_INVALID;
    memset(document, 0, sizeof(*document));
    if (owner < 0 || owner > ASTERISKD_OWNER_META || core < 0 || core > ASTERISKD_CORE_MIHOMO ||
        mode < 0 || mode > ASTERISKD_MODE_EBPF || !owner_core_valid(owner, core)) {
        return ASTERISKD_STATE_INVALID;
    }
    document->schema_version = ASTERISKD_STATE_VERSION;
    document->phase = ASTERISKD_PHASE_STOPPED;
    document->owner = owner;
    document->core_type = core;
    document->mode = mode;
    document->recovery.next_record_id = 1U;
    document->initialized = true;
    return ASTERISKD_STATE_OK;
}

void asteriskd_state_document_destroy(struct asteriskd_state_document *document) {
    if (document == NULL) return;
    free(document->recovery.records);
    memset(document, 0, sizeof(*document));
}

int asteriskd_state_set_phase(struct asteriskd_state_document *document, enum asteriskd_phase phase) {
    if (document == NULL || !document->initialized || phase < 0 || phase >= ASTERISKD_PHASE_COUNT) {
        return ASTERISKD_STATE_INVALID;
    }
    document->phase = phase;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_child(
    struct asteriskd_state_document *document,
    const struct asteriskd_child_identity *child,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || child == NULL ||
        !child_valid(document, child, child->role)) {
        set_error(error, error_size, "invalid child identity");
        return ASTERISKD_STATE_INVALID;
    }
    if (child->role == ASTERISKD_CHILD_CORE) {
        document->children.core = *child;
        document->children.core_present = true;
    } else {
        document->children.helper = *child;
        document->children.helper_present = true;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_clear_child(
    struct asteriskd_state_document *document,
    enum asteriskd_child_role role) {
    if (document == NULL || !document->initialized ||
        (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER)) return ASTERISKD_STATE_INVALID;
    if (role == ASTERISKD_CHILD_CORE) {
        memset(&document->children.core, 0, sizeof(document->children.core));
        document->children.core_present = false;
    } else {
        memset(&document->children.helper, 0, sizeof(document->children.helper));
        document->children.helper_present = false;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_matcher(
    struct asteriskd_state_document *document,
    bool configured,
    bool active) {
    if (document == NULL || !document->initialized || active > configured ||
        (configured && !(document->mode == ASTERISKD_MODE_TPROXY || document->mode == ASTERISKD_MODE_TUN ||
                         document->mode == ASTERISKD_MODE_TUN2SOCKS))) return ASTERISKD_STATE_INVALID;
    document->matcher.configured = configured;
    document->matcher.active = active;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_rules(
    struct asteriskd_state_document *document,
    bool active,
    uint64_t generation,
    uint32_t categories) {
    if (document == NULL || !document->initialized ||
        (categories & ~ASTERISKD_RULE_CATEGORY_ALL) != 0U ||
        (!active && (generation != 0U || categories != 0U)) ||
        (active && (generation == 0U || categories == 0U)) ||
        (document->mode == ASTERISKD_MODE_EBPF && active)) return ASTERISKD_STATE_INVALID;
    document->rules.active = active;
    document->rules.generation = generation;
    document->rules.categories = categories;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_failure(
    struct asteriskd_state_document *document,
    enum asteriskd_failure_code code,
    enum asteriskd_component component,
    const char *message,
    bool has_exit_code,
    int exit_code,
    bool has_signal,
    int signal_value,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || code < 0 || code >= ASTERISKD_FAILURE_CODE_COUNT ||
        component < 0 || component >= ASTERISKD_COMPONENT_COUNT || message == NULL || message[0] == '\0' ||
        strnlen(message, ASTERISKD_MAX_STATE_MESSAGE) >= ASTERISKD_MAX_STATE_MESSAGE) {
        set_error(error, error_size, "invalid failure summary");
        return ASTERISKD_STATE_INVALID;
    }
    struct asteriskd_state_failure failure;
    memset(&failure, 0, sizeof(failure));
    failure.present = true;
    failure.code = code;
    failure.component = component;
    (void)snprintf(failure.message, sizeof(failure.message), "%s", message);
    failure.has_exit_code = has_exit_code;
    failure.exit_code = has_exit_code ? exit_code : 0;
    failure.has_signal = has_signal;
    failure.signal = has_signal ? signal_value : 0;
    if (!failure_valid(&failure)) {
        set_error(error, error_size, "invalid failure process result");
        return ASTERISKD_STATE_INVALID;
    }
    document->failure = failure;
    return ASTERISKD_STATE_OK;
}

void asteriskd_state_clear_failure(struct asteriskd_state_document *document) {
    if (document != NULL && document->initialized) memset(&document->failure, 0, sizeof(document->failure));
}

static int ensure_record_capacity(struct asteriskd_state_document *document, size_t needed) {
    if (needed > ASTERISKD_JSON_MAX_TOKENS / 5U ||
        needed > SIZE_MAX / sizeof(*document->recovery.records)) return ASTERISKD_STATE_INVALID;
    if (needed <= document->recovery.record_capacity) return ASTERISKD_STATE_OK;
    size_t capacity = document->recovery.record_capacity == 0U ? 8U : document->recovery.record_capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2U) return ASTERISKD_STATE_INVALID;
        capacity *= 2U;
    }
    struct asteriskd_recovery_record *records = realloc(
        document->recovery.records, capacity * sizeof(*records));
    if (records == NULL) return ASTERISKD_STATE_NO_MEMORY;
    document->recovery.records = records;
    document->recovery.record_capacity = capacity;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_append_recovery(
    struct asteriskd_state_document *document,
    const struct asteriskd_recovery_record *record,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || !record_resource_valid(record) ||
        (document->recovery.record_count != 0U &&
         (record->record_id <= document->recovery.records[document->recovery.record_count - 1U].record_id ||
          (document->recovery.records[document->recovery.record_count - 1U].status ==
               ASTERISKD_RECOVERY_INTENT &&
           record->status == ASTERISKD_RECOVERY_APPLIED))) ||
        (document->recovery.core_owned_ebpf_boundary &&
         (record->kind != ASTERISKD_RECOVERY_SYSCTL ||
          record->resource.sysctl.sysctl_id != ASTERISKD_SYSCTL_DISABLE_IPV6))) {
        set_error(error, error_size, "invalid recovery record");
        return ASTERISKD_STATE_INVALID;
    }
    int result = ensure_record_capacity(document, document->recovery.record_count + 1U);
    if (result != ASTERISKD_STATE_OK) return result;
    document->recovery.records[document->recovery.record_count++] = *record;
    if (record->record_id == UINT64_MAX) {
        --document->recovery.record_count;
        return ASTERISKD_STATE_INVALID;
    }
    if (document->recovery.next_record_id <= record->record_id) {
        document->recovery.next_record_id = record->record_id + 1U;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_mark_stopped(
    struct asteriskd_state_document *document,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || document->children.core_present ||
        document->children.helper_present || document->matcher.active || document->rules.active ||
        document->rules.generation != 0U || document->rules.categories != 0U ||
        document->recovery.core_owned_ebpf_boundary || document->recovery.record_count != 0U) {
        set_error(error, error_size, "live or recovery evidence remains");
        return ASTERISKD_STATE_INVALID;
    }
    enum asteriskd_phase previous = document->phase;
    document->phase = ASTERISKD_PHASE_STOPPED;
    if (!document_valid(document)) {
        document->phase = previous;
        set_error(error, error_size, "invalid stopped state");
        return ASTERISKD_STATE_INVALID;
    }
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

bool asteriskd_state_is_canonical_stopped(const struct asteriskd_state_document *document) {
    return document_valid(document) && document->phase == ASTERISKD_PHASE_STOPPED;
}

struct string_builder {
    char *bytes;
    size_t length;
    size_t capacity;
    int result;
};

static void builder_reserve(struct string_builder *builder, size_t extra) {
    if (builder->result != ASTERISKD_STATE_OK) return;
    if (extra > ASTERISKD_MAX_JSON_SIZE - builder->length) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    size_t needed = builder->length + extra + 1U;
    if (needed <= builder->capacity) return;
    size_t capacity = builder->capacity == 0U ? 1024U : builder->capacity;
    while (capacity < needed) {
        if (capacity > ASTERISKD_MAX_JSON_SIZE / 2U) {
            capacity = ASTERISKD_MAX_JSON_SIZE + 1U;
            break;
        }
        capacity *= 2U;
    }
    if (capacity > ASTERISKD_MAX_JSON_SIZE + 1U) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    char *bytes = realloc(builder->bytes, capacity);
    if (bytes == NULL) {
        builder->result = ASTERISKD_STATE_NO_MEMORY;
        return;
    }
    builder->bytes = bytes;
    builder->capacity = capacity;
}

static void builder_raw(struct string_builder *builder, const char *value) {
    size_t length = strlen(value);
    builder_reserve(builder, length);
    if (builder->result != ASTERISKD_STATE_OK) return;
    memcpy(builder->bytes + builder->length, value, length);
    builder->length += length;
    builder->bytes[builder->length] = '\0';
}

static void builder_format(struct string_builder *builder, const char *format, ...) {
    if (builder->result != ASTERISKD_STATE_OK) return;
    char buffer[512];
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= sizeof(buffer)) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    builder_reserve(builder, (size_t)count);
    if (builder->result != ASTERISKD_STATE_OK) return;
    memcpy(builder->bytes + builder->length, buffer, (size_t)count);
    builder->length += (size_t)count;
    builder->bytes[builder->length] = '\0';
}

static void builder_json_string(struct string_builder *builder, const char *value) {
    builder_raw(builder, "\"");
    for (const unsigned char *cursor = (const unsigned char *)value;
         builder->result == ASTERISKD_STATE_OK && *cursor != '\0'; ++cursor) {
        unsigned char ch = *cursor;
        switch (ch) {
            case '"': builder_raw(builder, "\\\""); break;
            case '\\': builder_raw(builder, "\\\\"); break;
            case '\b': builder_raw(builder, "\\b"); break;
            case '\f': builder_raw(builder, "\\f"); break;
            case '\n': builder_raw(builder, "\\n"); break;
            case '\r': builder_raw(builder, "\\r"); break;
            case '\t': builder_raw(builder, "\\t"); break;
            default:
                if (ch < 0x20U || ch == 0x7fU) builder_format(builder, "\\u%04x", (unsigned int)ch);
                else {
                    builder_reserve(builder, 1U);
                    if (builder->result == ASTERISKD_STATE_OK) {
                        builder->bytes[builder->length++] = (char)ch;
                        builder->bytes[builder->length] = '\0';
                    }
                }
                break;
        }
    }
    builder_raw(builder, "\"");
}

static const char *boolean_name(bool value) { return value ? "true" : "false"; }

static void serialize_child(
    struct string_builder *builder,
    bool present,
    const struct asteriskd_child_identity *child) {
    if (!present) {
        builder_raw(builder, "null");
        return;
    }
    builder_raw(builder, "{\"role\":");
    builder_json_string(builder, child_role_names[child->role]);
    builder_raw(builder, ",\"type\":");
    builder_json_string(builder, child_type_names[child->type]);
    builder_format(builder, ",\"pid\":%d,\"processGroupId\":%d,\"startTimeTicks\":%" PRIu64
        ",\"exeDevice\":%" PRIu64 ",\"exeInode\":%" PRIu64 ",\"argv\":[",
        child->pid, child->process_group_id, child->start_time_ticks, child->exe_device, child->exe_inode);
    for (size_t index = 0U; index < child->argc; ++index) {
        if (index != 0U) builder_raw(builder, ",");
        builder_json_string(builder, child->argv[index]);
    }
    builder_raw(builder, "]}");
}

static void serialize_nullable_interface(
    struct string_builder *builder,
    bool present,
    const char *name,
    uint32_t index) {
    builder_raw(builder, "\"interfaceName\":");
    if (present) builder_json_string(builder, name);
    else builder_raw(builder, "null");
    builder_raw(builder, ",\"interfaceIndex\":");
    if (present) builder_format(builder, "%" PRIu32, index);
    else builder_raw(builder, "null");
}

static void serialize_record_resource(
    struct string_builder *builder,
    const struct asteriskd_recovery_record *record) {
    builder_raw(builder, "{");
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN: {
            const struct asteriskd_iptables_chain_resource *resource = &record->resource.iptables_chain;
            builder_raw(builder, "\"family\":"); builder_json_string(builder, family_names[resource->family]);
            builder_raw(builder, ",\"table\":"); builder_json_string(builder, table_names[resource->table]);
            builder_raw(builder, ",\"chainId\":"); builder_json_string(builder, chain_names[resource->chain_id]);
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_IPTABLES_RULE: {
            const struct asteriskd_iptables_rule_resource *resource = &record->resource.iptables_rule;
            builder_raw(builder, "\"family\":"); builder_json_string(builder, family_names[resource->family]);
            builder_raw(builder, ",\"table\":"); builder_json_string(builder, table_names[resource->table]);
            builder_raw(builder, ",\"chainId\":"); builder_json_string(builder, chain_names[resource->chain_id]);
            builder_raw(builder, ",\"ruleId\":"); builder_json_string(builder, rule_names[resource->rule_id]);
            builder_raw(builder, ","); serialize_nullable_interface(builder, resource->has_interface,
                resource->interface_name, resource->interface_index);
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_IP_RULE: {
            const struct asteriskd_ip_rule_resource *resource = &record->resource.ip_rule;
            builder_raw(builder, "\"family\":"); builder_json_string(builder, family_names[resource->family]);
            builder_raw(builder, ",\"ruleId\":"); builder_json_string(builder, ip_rule_names[resource->rule_id]);
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_ROUTE: {
            const struct asteriskd_route_resource *resource = &record->resource.route;
            builder_raw(builder, "\"family\":"); builder_json_string(builder, family_names[resource->family]);
            builder_raw(builder, ",\"routeId\":"); builder_json_string(builder, route_names[resource->route_id]);
            builder_raw(builder, ",\"interfaceName\":"); builder_json_string(builder, resource->interface_name);
            builder_format(builder, ",\"interfaceIndex\":%" PRIu32 ",\"originalPresence\":%s",
                resource->interface_index, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE: {
            const struct asteriskd_dummy_interface_resource *resource = &record->resource.dummy_interface;
            builder_raw(builder, "\"interfaceId\":"); builder_json_string(builder, interface_id_names[resource->interface_id]);
            builder_raw(builder, ",\"interfaceIndex\":");
            if (resource->has_interface_index) builder_format(builder, "%" PRIu32, resource->interface_index);
            else builder_raw(builder, "null");
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_BPF_PIN: {
            const struct asteriskd_bpf_pin_resource *resource = &record->resource.bpf_pin;
            builder_raw(builder, "\"pinId\":"); builder_json_string(builder, pin_names[resource->pin_id]);
            builder_raw(builder, ",\"objectId\":");
            if (resource->has_object_id) builder_format(builder, "%" PRIu64, resource->object_id);
            else builder_raw(builder, "null");
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_TC_QDISC: {
            const struct asteriskd_tc_qdisc_resource *resource = &record->resource.tc_qdisc;
            builder_raw(builder, "\"qdiscId\":"); builder_json_string(builder, qdisc_names[resource->qdisc_id]);
            builder_raw(builder, ",\"interfaceName\":"); builder_json_string(builder, resource->interface_name);
            builder_format(builder, ",\"interfaceIndex\":%" PRIu32 ",\"originalPresence\":%s",
                resource->interface_index, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_TC_FILTER: {
            const struct asteriskd_tc_filter_resource *resource = &record->resource.tc_filter;
            builder_raw(builder, "\"ownership\":\"daemon\",\"inverse\":\"remove\"");
            builder_raw(builder, ",\"filterId\":"); builder_json_string(builder, filter_names[resource->filter_id]);
            builder_raw(builder, ",\"direction\":"); builder_json_string(builder, direction_names[resource->direction]);
            builder_raw(builder, ",\"interfaceName\":"); builder_json_string(builder, resource->interface_name);
            builder_format(builder, ",\"interfaceIndex\":%" PRIu32, resource->interface_index);
            builder_raw(builder, ",\"programId\":"); builder_json_string(builder, program_names[resource->program_id]);
            builder_raw(builder, ",\"originalPresence\":"); builder_raw(builder, boolean_name(resource->original_presence));
            break;
        }
        case ASTERISKD_RECOVERY_SYSCTL: {
            const struct asteriskd_sysctl_resource *resource = &record->resource.sysctl;
            builder_raw(builder, "\"sysctlId\":"); builder_json_string(builder, sysctl_names[resource->sysctl_id]);
            builder_raw(builder, ",\"interfaceName\":"); builder_json_string(builder, resource->interface_name);
            builder_format(builder, ",\"interfaceIndex\":%" PRIu32 ",\"originalValue\":%u,\"desiredValue\":%u",
                resource->interface_index, (unsigned int)resource->original_value, (unsigned int)resource->desired_value);
            break;
        }
        case ASTERISKD_RECOVERY_TETHER_STATE: {
            const struct asteriskd_tether_state_resource *resource = &record->resource.tether_state;
            builder_raw(builder, "\"tetherId\":"); builder_json_string(builder, tether_names[resource->tether_id]);
            builder_raw(builder, ",\"interfaceName\":"); builder_json_string(builder, resource->interface_name);
            builder_format(builder, ",\"interfaceIndex\":%" PRIu32 ",\"originalActive\":%s,\"desiredActive\":%s",
                resource->interface_index, boolean_name(resource->original_active), boolean_name(resource->desired_active));
            break;
        }
        case ASTERISKD_RECOVERY_KIND_COUNT:
            builder->result = ASTERISKD_STATE_INVALID;
            break;
    }
    builder_raw(builder, "}");
}

static void serialize_record(
    struct string_builder *builder,
    const struct asteriskd_recovery_record *record) {
    builder_format(builder, "{\"recordId\":%" PRIu64 ",\"status\":", record->record_id);
    builder_json_string(builder, recovery_status_names[record->status]);
    builder_raw(builder, ",\"kind\":"); builder_json_string(builder, recovery_kind_names[record->kind]);
    builder_raw(builder, ",\"resource\":"); serialize_record_resource(builder, record);
    builder_raw(builder, "}");
}

int asteriskd_state_serialize(
    const struct asteriskd_state_document *document,
    char **out,
    size_t *out_length,
    char *error,
    size_t error_size) {
    if (out != NULL) *out = NULL;
    if (out_length != NULL) *out_length = 0U;
    if (out == NULL || out_length == NULL || !document_valid(document)) {
        set_error(error, error_size, "invalid state document");
        return ASTERISKD_STATE_INVALID;
    }
    struct string_builder builder = {.result = ASTERISKD_STATE_OK};
    builder_raw(&builder, "{\"schemaVersion\":2,\"phase\":"); builder_json_string(&builder, phase_names[document->phase]);
    builder_raw(&builder, ",\"owner\":"); builder_json_string(&builder, owner_names[document->owner]);
    builder_raw(&builder, ",\"coreType\":"); builder_json_string(&builder, core_names[document->core_type]);
    builder_raw(&builder, ",\"mode\":"); builder_json_string(&builder, mode_names[document->mode]);
    builder_raw(&builder, ",\"children\":{\"core\":");
    serialize_child(&builder, document->children.core_present, &document->children.core);
    builder_raw(&builder, ",\"helper\":");
    serialize_child(&builder, document->children.helper_present, &document->children.helper);
    builder_raw(&builder, "},\"matcher\":{\"configured\":");
    builder_raw(&builder, boolean_name(document->matcher.configured));
    builder_raw(&builder, ",\"active\":"); builder_raw(&builder, boolean_name(document->matcher.active));
    builder_raw(&builder, "},\"rules\":{\"active\":"); builder_raw(&builder, boolean_name(document->rules.active));
    builder_format(&builder, ",\"generation\":%" PRIu64 ",\"categories\":[", document->rules.generation);
    bool first = true;
    for (int category = 0; category < (int)ASTERISKD_RULE_CATEGORY_COUNT; ++category) {
        if ((document->rules.categories & ASTERISKD_RULE_CATEGORY_BIT(category)) == 0U) continue;
        if (!first) builder_raw(&builder, ",");
        builder_json_string(&builder, category_names[category]);
        first = false;
    }
    builder_format(&builder, "]},\"recovery\":{\"nextRecordId\":%" PRIu64
        ",\"coreOwnedEbpfBoundary\":%s,\"records\":[",
        document->recovery.next_record_id, boolean_name(document->recovery.core_owned_ebpf_boundary));
    for (size_t index = 0U; index < document->recovery.record_count; ++index) {
        if (index != 0U) builder_raw(&builder, ",");
        serialize_record(&builder, &document->recovery.records[index]);
    }
    builder_raw(&builder, "]},\"failure\":");
    if (!document->failure.present) {
        builder_raw(&builder, "null");
    } else {
        builder_raw(&builder, "{\"code\":"); builder_json_string(&builder, failure_names[document->failure.code]);
        builder_raw(&builder, ",\"component\":"); builder_json_string(&builder, component_names[document->failure.component]);
        builder_raw(&builder, ",\"message\":"); builder_json_string(&builder, document->failure.message);
        builder_raw(&builder, ",\"exitCode\":");
        if (document->failure.has_exit_code) builder_format(&builder, "%d", document->failure.exit_code);
        else builder_raw(&builder, "null");
        builder_raw(&builder, ",\"signal\":");
        if (document->failure.has_signal) builder_format(&builder, "%d", document->failure.signal);
        else builder_raw(&builder, "null");
        builder_raw(&builder, "}");
    }
    builder_raw(&builder, "}");
    if (builder.result != ASTERISKD_STATE_OK) {
        free(builder.bytes);
        set_error(error, error_size, builder.result == ASTERISKD_STATE_NO_MEMORY ? "out of memory" : "state too large");
        return builder.result;
    }
    *out = builder.bytes;
    *out_length = builder.length;
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

static size_t next_direct(
    const struct asteriskd_json_document *document,
    size_t parent,
    size_t start) {
    for (size_t index = start; index < document->token_count; ++index) {
        if (document->tokens[index].parent == parent) return index;
    }
    return TOKEN_NONE;
}

static int append_utf8(uint32_t codepoint, char *out, size_t out_size, size_t *length) {
    unsigned char encoded[4];
    size_t count;
    if (codepoint <= 0x7fU) {
        encoded[0] = (unsigned char)codepoint;
        count = 1U;
    } else if (codepoint <= 0x7ffU) {
        encoded[0] = (unsigned char)(0xc0U | (codepoint >> 6U));
        encoded[1] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 2U;
    } else if (codepoint <= 0xffffU) {
        encoded[0] = (unsigned char)(0xe0U | (codepoint >> 12U));
        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 3U;
    } else {
        encoded[0] = (unsigned char)(0xf0U | (codepoint >> 18U));
        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 12U) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[3] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 4U;
    }
    if (*length + count >= out_size) return -1;
    memcpy(out + *length, encoded, count);
    *length += count;
    return 0;
}

static int hex_digit(char value, uint32_t *out) {
    if (value >= '0' && value <= '9') *out = (uint32_t)(value - '0');
    else if (value >= 'a' && value <= 'f') *out = (uint32_t)(value - 'a' + 10);
    else if (value >= 'A' && value <= 'F') *out = (uint32_t)(value - 'A' + 10);
    else return -1;
    return 0;
}

static int decode_json_string(
    const struct asteriskd_json_document *document,
    size_t token_index,
    char *out,
    size_t out_size) {
    if (token_index >= document->token_count ||
        document->tokens[token_index].type != ASTERISKD_JSON_STRING || out_size == 0U) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    size_t length = 0U;
    for (size_t input = token->start; input < token->end; ++input) {
        unsigned char value = (unsigned char)document->source[input];
        if (value != '\\') {
            if (value == 0U || length + 1U >= out_size) return -1;
            out[length++] = (char)value;
            continue;
        }
        if (++input >= token->end) return -1;
        value = (unsigned char)document->source[input];
        switch (value) {
            case '"': case '\\': case '/':
                if (length + 1U >= out_size) return -1;
                out[length++] = (char)value;
                break;
            case 'b': case 'f': case 'n': case 'r': case 't': {
                static const char decoded[] = {'\b', '\f', '\n', '\r', '\t'};
                static const char encoded[] = {'b', 'f', 'n', 'r', 't'};
                const char *found = strchr(encoded, (int)value);
                if (found == NULL || length + 1U >= out_size) return -1;
                out[length++] = decoded[(size_t)(found - encoded)];
                break;
            }
            case 'u': {
                if (input + 4U >= token->end) return -1;
                uint32_t codepoint = 0U;
                for (size_t offset = 1U; offset <= 4U; ++offset) {
                    uint32_t digit;
                    if (hex_digit(document->source[input + offset], &digit) != 0) return -1;
                    codepoint = codepoint * 16U + digit;
                }
                input += 4U;
                if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                    if (input + 6U >= token->end || document->source[input + 1U] != '\\' ||
                        document->source[input + 2U] != 'u') return -1;
                    uint32_t low = 0U;
                    for (size_t offset = 3U; offset <= 6U; ++offset) {
                        uint32_t digit;
                        if (hex_digit(document->source[input + offset], &digit) != 0) return -1;
                        low = low * 16U + digit;
                    }
                    if (low < 0xdc00U || low > 0xdfffU) return -1;
                    codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + (low - 0xdc00U);
                    input += 6U;
                } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
                    return -1;
                }
                if (codepoint == 0U || append_utf8(codepoint, out, out_size, &length) != 0) return -1;
                break;
            }
            default:
                return -1;
        }
    }
    out[length] = '\0';
    return 0;
}

static bool token_string_equals(
    const struct asteriskd_json_document *document,
    size_t token,
    const char *value) {
    char decoded[128];
    return decode_json_string(document, token, decoded, sizeof(decoded)) == 0 && strcmp(decoded, value) == 0;
}

static int object_values(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *const *names,
    size_t name_count,
    size_t *values) {
    if (object >= document->token_count || document->tokens[object].type != ASTERISKD_JSON_OBJECT ||
        name_count > 64U || document->tokens[object].child_count != name_count) return -1;
    for (size_t index = 0U; index < name_count; ++index) values[index] = TOKEN_NONE;
    size_t cursor = object + 1U;
    size_t pairs = 0U;
    while (true) {
        size_t key = next_direct(document, object, cursor);
        if (key == TOKEN_NONE) break;
        size_t value = next_direct(document, object, key + 1U);
        if (value == TOKEN_NONE || document->tokens[key].type != ASTERISKD_JSON_STRING) return -1;
        size_t found = TOKEN_NONE;
        for (size_t index = 0U; index < name_count; ++index) {
            if (token_string_equals(document, key, names[index])) {
                found = index;
                break;
            }
        }
        if (found == TOKEN_NONE || values[found] != TOKEN_NONE) return -1;
        values[found] = value;
        ++pairs;
        cursor = value + 1U;
    }
    return pairs == name_count ? 0 : -1;
}

static int find_unique_value(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *name,
    size_t *out) {
    if (object >= document->token_count || document->tokens[object].type != ASTERISKD_JSON_OBJECT) return -1;
    size_t found = TOKEN_NONE;
    size_t cursor = object + 1U;
    while (true) {
        size_t key = next_direct(document, object, cursor);
        if (key == TOKEN_NONE) break;
        size_t value = next_direct(document, object, key + 1U);
        if (value == TOKEN_NONE || document->tokens[key].type != ASTERISKD_JSON_STRING) return -1;
        if (token_string_equals(document, key, name)) {
            if (found != TOKEN_NONE) return -1;
            found = value;
        }
        cursor = value + 1U;
    }
    if (found == TOKEN_NONE) return -1;
    *out = found;
    return 0;
}

static int parse_enum_token(
    const struct asteriskd_json_document *document,
    size_t token,
    const char *const *names,
    size_t count,
    int *out) {
    char value[128];
    if (decode_json_string(document, token, value, sizeof(value)) != 0) return -1;
    for (size_t index = 0U; index < count; ++index) {
        if (strcmp(value, names[index]) == 0) {
            *out = (int)index;
            return 0;
        }
    }
    return -1;
}

static int parse_bool_token(
    const struct asteriskd_json_document *document,
    size_t token,
    bool *out) {
    if (token >= document->token_count) return -1;
    if (document->tokens[token].type == ASTERISKD_JSON_TRUE) {
        *out = true;
        return 0;
    }
    if (document->tokens[token].type == ASTERISKD_JSON_FALSE) {
        *out = false;
        return 0;
    }
    return -1;
}

static int parse_u64_token(
    const struct asteriskd_json_document *document,
    size_t token_index,
    uint64_t *out) {
    if (token_index >= document->token_count) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->type != ASTERISKD_JSON_NUMBER || token->start >= token->end) return -1;
    uint64_t value = 0U;
    for (size_t index = token->start; index < token->end; ++index) {
        char ch = document->source[index];
        if (ch < '0' || ch > '9') return -1;
        uint64_t digit = (uint64_t)(ch - '0');
        if (value > (UINT64_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    *out = value;
    return 0;
}

static int parse_u32_token(
    const struct asteriskd_json_document *document,
    size_t token,
    uint32_t *out) {
    uint64_t value;
    if (parse_u64_token(document, token, &value) != 0 || value > UINT32_MAX) return -1;
    *out = (uint32_t)value;
    return 0;
}

static int parse_positive_int_token(
    const struct asteriskd_json_document *document,
    size_t token,
    bool allow_zero,
    int *out) {
    uint64_t value;
    if (parse_u64_token(document, token, &value) != 0 || value > INT_MAX || (!allow_zero && value == 0U)) return -1;
    *out = (int)value;
    return 0;
}

static bool is_null_token(const struct asteriskd_json_document *document, size_t token) {
    return token < document->token_count && document->tokens[token].type == ASTERISKD_JSON_NULL;
}

static int parse_child(
    const struct asteriskd_json_document *json,
    size_t token,
    struct asteriskd_state_document *state,
    enum asteriskd_child_role slot) {
    if (is_null_token(json, token)) return 0;
    static const char *const names[] = {
        "role", "type", "pid", "processGroupId", "startTimeTicks", "exeDevice", "exeInode", "argv",
    };
    size_t values[8];
    struct asteriskd_child_identity child;
    memset(&child, 0, sizeof(child));
    int role, type;
    if (object_values(json, token, names, 8U, values) != 0 ||
        parse_enum_token(json, values[0], child_role_names, 2U, &role) != 0 ||
        parse_enum_token(json, values[1], child_type_names, ASTERISKD_CHILD_TYPE_COUNT, &type) != 0 ||
        parse_positive_int_token(json, values[2], false, &child.pid) != 0 ||
        parse_positive_int_token(json, values[3], false, &child.process_group_id) != 0 ||
        parse_u64_token(json, values[4], &child.start_time_ticks) != 0 ||
        parse_u64_token(json, values[5], &child.exe_device) != 0 ||
        parse_u64_token(json, values[6], &child.exe_inode) != 0 ||
        json->tokens[values[7]].type != ASTERISKD_JSON_ARRAY ||
        json->tokens[values[7]].child_count == 0U ||
        json->tokens[values[7]].child_count > ASTERISKD_MAX_CHILD_ARGV) return -1;
    child.role = (enum asteriskd_child_role)role;
    child.type = (enum asteriskd_child_type)type;
    child.argc = json->tokens[values[7]].child_count;
    size_t cursor = values[7] + 1U;
    for (size_t index = 0U; index < child.argc; ++index) {
        size_t argument = next_direct(json, values[7], cursor);
        if (argument == TOKEN_NONE ||
            decode_json_string(json, argument, child.argv[index], sizeof(child.argv[index])) != 0) return -1;
        cursor = argument + 1U;
    }
    if (!child_valid(state, &child, slot)) return -1;
    if (slot == ASTERISKD_CHILD_CORE) {
        state->children.core_present = true;
        state->children.core = child;
    } else {
        state->children.helper_present = true;
        state->children.helper = child;
    }
    return 0;
}

static int parse_nullable_interface(
    const struct asteriskd_json_document *json,
    size_t name_token,
    size_t index_token,
    bool *present,
    char *name,
    size_t name_size,
    uint32_t *index) {
    if (is_null_token(json, name_token) || is_null_token(json, index_token)) {
        if (!is_null_token(json, name_token) || !is_null_token(json, index_token)) return -1;
        *present = false;
        name[0] = '\0';
        *index = 0U;
        return 0;
    }
    *present = true;
    return decode_json_string(json, name_token, name, name_size) == 0 &&
        parse_u32_token(json, index_token, index) == 0 ? 0 : -1;
}

/*
 * Early 2.0 builds persisted Android tethering filters as restorable foreign
 * resources.  That design was removed: current startup deliberately applies
 * the pre-2.0 one-way TC cleanup instead.  Keep only this strict decoder so a
 * version-2 state file written by those builds can be migrated by dropping the
 * obsolete records; none of their restore data enters the runtime model.
 */
static bool legacy_lowercase_hex_valid(const char *value, size_t exact_length) {
    size_t length = value == NULL ? 0U : strnlen(value, ASTERISKD_MAX_HEX_ID);
    if (length == 0U || length >= ASTERISKD_MAX_HEX_ID ||
        (length & 1U) != 0U || (exact_length != 0U && length != exact_length)) return false;
    for (size_t index = 0U; index < length; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) return false;
    }
    return true;
}

static bool legacy_tether_bpf_name(const char *name) {
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

/* Returns one for an obsolete record, zero for a current record, and -1 for malformed legacy data. */
static int parse_obsolete_hotspot_record(
    const struct asteriskd_json_document *json,
    size_t object,
    const struct asteriskd_recovery_record *record) {
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        size_t pin_token;
        if (find_unique_value(json, object, "pinId", &pin_token) != 0 ||
            !token_string_equals(json, pin_token, "hotspot-recovery")) return 0;
        static const char *const names[] = {"pinId", "objectId", "originalPresence"};
        size_t values[3];
        uint64_t object_id = 0U;
        bool original_presence = false;
        bool has_object_id;
        if (object_values(json, object, names, 3U, values) != 0) return -1;
        has_object_id = !is_null_token(json, values[1]);
        if ((has_object_id &&
             (parse_u64_token(json, values[1], &object_id) != 0 || object_id == 0U)) ||
            parse_bool_token(json, values[2], &original_presence) != 0 || original_presence ||
            (record->status == ASTERISKD_RECOVERY_APPLIED && !has_object_id)) return -1;
        return 1;
    }
    if (record->kind != ASTERISKD_RECOVERY_TC_FILTER) return 0;
    size_t ownership_token;
    if (find_unique_value(json, object, "ownership", &ownership_token) != 0 ||
        !token_string_equals(json, ownership_token, "foreign-snapshot")) return 0;
    static const char *const names[] = {
        "ownership", "inverse", "filterId", "direction", "interfaceName", "interfaceIndex",
        "interfaceLinkIndex", "interfaceHardwareType", "interfaceAddress", "parent", "chain",
        "protocol", "priority", "handle", "bpfName", "bpfFlags", "bpfFlagsGen", "programId",
        "programType", "programTag", "recoveryPinRecordId", "originalPresence",
    };
    size_t values[22];
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char interface_address[ASTERISKD_MAX_HEX_ID];
    char bpf_name[ASTERISKD_MAX_INTERFACE_NAME];
    char program_tag[ASTERISKD_MAX_HEX_ID];
    uint32_t interface_index, interface_link_index, interface_hardware_type;
    uint32_t parent, chain, protocol, priority, handle, bpf_flags, bpf_flags_gen;
    uint64_t recovery_pin_record_id;
    bool original_presence;
    if (object_values(json, object, names, 22U, values) != 0 ||
        !token_string_equals(json, values[1], "restore") ||
        !token_string_equals(json, values[2], "hotspot-ipv6-offload") ||
        !token_string_equals(json, values[3], "ingress") ||
        decode_json_string(json, values[4], interface_name, sizeof(interface_name)) != 0 ||
        parse_u32_token(json, values[5], &interface_index) != 0 ||
        parse_u32_token(json, values[6], &interface_link_index) != 0 ||
        parse_u32_token(json, values[7], &interface_hardware_type) != 0 ||
        decode_json_string(json, values[8], interface_address, sizeof(interface_address)) != 0 ||
        parse_u32_token(json, values[9], &parent) != 0 ||
        parse_u32_token(json, values[10], &chain) != 0 ||
        parse_u32_token(json, values[11], &protocol) != 0 ||
        parse_u32_token(json, values[12], &priority) != 0 ||
        parse_u32_token(json, values[13], &handle) != 0 ||
        decode_json_string(json, values[14], bpf_name, sizeof(bpf_name)) != 0 ||
        parse_u32_token(json, values[15], &bpf_flags) != 0 ||
        parse_u32_token(json, values[16], &bpf_flags_gen) != 0 ||
        !token_string_equals(json, values[17], "android-tether-offload") ||
        !token_string_equals(json, values[18], "sched-cls") ||
        decode_json_string(json, values[19], program_tag, sizeof(program_tag)) != 0 ||
        parse_u64_token(json, values[20], &recovery_pin_record_id) != 0 ||
        parse_bool_token(json, values[21], &original_presence) != 0) return -1;
    return interface_name_valid(interface_name, false) && interface_index > 0U &&
        interface_link_index > 0U && interface_hardware_type > 0U &&
        legacy_lowercase_hex_valid(interface_address, 0U) &&
        parent == ASTERISKD_TC_PARENT_CLSACT_INGRESS && chain == 0U &&
        protocol == ASTERISKD_ETH_PROTOCOL_IPV6 && priority == 2U && handle > 0U &&
        legacy_tether_bpf_name(bpf_name) && bpf_flags == ASTERISKD_TC_BPF_FLAG_ACT_DIRECT &&
        (bpf_flags_gen & ~UINT32_C(0xf)) == 0U &&
        (bpf_flags_gen & UINT32_C(0xc)) != UINT32_C(0xc) &&
        legacy_lowercase_hex_valid(program_tag, ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH) &&
        recovery_pin_record_id > 0U && original_presence ? 1 : -1;
}

static int parse_record_resource(
    const struct asteriskd_json_document *json,
    size_t object,
    struct asteriskd_recovery_record *record) {
    int value;
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN: {
            static const char *const names[] = {"family", "table", "chainId", "originalPresence"};
            size_t values[4];
            struct asteriskd_iptables_chain_resource *resource = &record->resource.iptables_chain;
            if (object_values(json, object, names, 4U, values) != 0 ||
                parse_enum_token(json, values[0], family_names, ASTERISKD_IP_FAMILY_COUNT, &value) != 0) return -1;
            resource->family = (enum asteriskd_ip_family)value;
            if (parse_enum_token(json, values[1], table_names, ASTERISKD_IP_TABLE_COUNT, &value) != 0) return -1;
            resource->table = (enum asteriskd_ip_table)value;
            if (parse_enum_token(json, values[2], chain_names, ASTERISKD_CHAIN_COUNT, &value) != 0) return -1;
            resource->chain_id = (enum asteriskd_chain_id)value;
            return parse_bool_token(json, values[3], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_IPTABLES_RULE: {
            static const char *const names[] = {
                "family", "table", "chainId", "ruleId", "interfaceName", "interfaceIndex", "originalPresence",
            };
            size_t values[7];
            struct asteriskd_iptables_rule_resource *resource = &record->resource.iptables_rule;
            if (object_values(json, object, names, 7U, values) != 0 ||
                parse_enum_token(json, values[0], family_names, ASTERISKD_IP_FAMILY_COUNT, &value) != 0) return -1;
            resource->family = (enum asteriskd_ip_family)value;
            if (parse_enum_token(json, values[1], table_names, ASTERISKD_IP_TABLE_COUNT, &value) != 0) return -1;
            resource->table = (enum asteriskd_ip_table)value;
            if (parse_enum_token(json, values[2], chain_names, ASTERISKD_CHAIN_COUNT, &value) != 0) return -1;
            resource->chain_id = (enum asteriskd_chain_id)value;
            if (parse_enum_token(json, values[3], rule_names, ASTERISKD_RULE_COUNT, &value) != 0) return -1;
            resource->rule_id = (enum asteriskd_rule_id)value;
            if (parse_nullable_interface(json, values[4], values[5], &resource->has_interface,
                    resource->interface_name, sizeof(resource->interface_name), &resource->interface_index) != 0) return -1;
            return parse_bool_token(json, values[6], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_IP_RULE: {
            static const char *const names[] = {"family", "ruleId", "originalPresence"};
            size_t values[3];
            struct asteriskd_ip_rule_resource *resource = &record->resource.ip_rule;
            if (object_values(json, object, names, 3U, values) != 0 ||
                parse_enum_token(json, values[0], family_names, ASTERISKD_IP_FAMILY_COUNT, &value) != 0) return -1;
            resource->family = (enum asteriskd_ip_family)value;
            if (parse_enum_token(json, values[1], ip_rule_names, ASTERISKD_IP_RULE_COUNT, &value) != 0) return -1;
            resource->rule_id = (enum asteriskd_ip_rule_id)value;
            return parse_bool_token(json, values[2], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_ROUTE: {
            static const char *const names[] = {"family", "routeId", "interfaceName", "interfaceIndex", "originalPresence"};
            size_t values[5];
            struct asteriskd_route_resource *resource = &record->resource.route;
            if (object_values(json, object, names, 5U, values) != 0 ||
                parse_enum_token(json, values[0], family_names, ASTERISKD_IP_FAMILY_COUNT, &value) != 0) return -1;
            resource->family = (enum asteriskd_ip_family)value;
            if (parse_enum_token(json, values[1], route_names, ASTERISKD_ROUTE_COUNT, &value) != 0) return -1;
            resource->route_id = (enum asteriskd_route_id)value;
            return decode_json_string(json, values[2], resource->interface_name, sizeof(resource->interface_name)) == 0 &&
                parse_u32_token(json, values[3], &resource->interface_index) == 0 &&
                parse_bool_token(json, values[4], &resource->original_presence) == 0 ? 0 : -1;
        }
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE: {
            static const char *const names[] = {"interfaceId", "interfaceIndex", "originalPresence"};
            size_t values[3];
            struct asteriskd_dummy_interface_resource *resource = &record->resource.dummy_interface;
            if (object_values(json, object, names, 3U, values) != 0 ||
                parse_enum_token(json, values[0], interface_id_names, ASTERISKD_INTERFACE_COUNT, &value) != 0) return -1;
            resource->interface_id = (enum asteriskd_interface_id)value;
            if (!is_null_token(json, values[1])) {
                resource->has_interface_index = true;
                if (parse_u32_token(json, values[1], &resource->interface_index) != 0) return -1;
            }
            return parse_bool_token(json, values[2], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_BPF_PIN: {
            static const char *const names[] = {"pinId", "objectId", "originalPresence"};
            size_t values[3];
            struct asteriskd_bpf_pin_resource *resource = &record->resource.bpf_pin;
            if (object_values(json, object, names, 3U, values) != 0 ||
                parse_enum_token(json, values[0], pin_names, ASTERISKD_PIN_COUNT, &value) != 0) return -1;
            resource->pin_id = (enum asteriskd_pin_id)value;
            if (!is_null_token(json, values[1])) {
                resource->has_object_id = true;
                if (parse_u64_token(json, values[1], &resource->object_id) != 0) return -1;
            }
            return parse_bool_token(json, values[2], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_TC_QDISC: {
            static const char *const names[] = {"qdiscId", "interfaceName", "interfaceIndex", "originalPresence"};
            size_t values[4];
            struct asteriskd_tc_qdisc_resource *resource = &record->resource.tc_qdisc;
            if (object_values(json, object, names, 4U, values) != 0 ||
                parse_enum_token(json, values[0], qdisc_names, ASTERISKD_QDISC_COUNT, &value) != 0) return -1;
            resource->qdisc_id = (enum asteriskd_qdisc_id)value;
            return decode_json_string(json, values[1], resource->interface_name, sizeof(resource->interface_name)) == 0 &&
                parse_u32_token(json, values[2], &resource->interface_index) == 0 &&
                parse_bool_token(json, values[3], &resource->original_presence) == 0 ? 0 : -1;
        }
        case ASTERISKD_RECOVERY_TC_FILTER: {
            static const char *const names[] = {
                "ownership", "inverse", "filterId", "direction", "interfaceName", "interfaceIndex",
                "programId", "originalPresence",
            };
            size_t values[8];
            struct asteriskd_tc_filter_resource *resource = &record->resource.tc_filter;
            if (object_values(json, object, names, 8U, values) != 0 ||
                parse_enum_token(json, values[0], tc_ownership_names, 1U, &value) != 0 ||
                parse_enum_token(json, values[1], tc_inverse_names, 1U, &value) != 0) return -1;
            if (parse_enum_token(json, values[2], filter_names, ASTERISKD_FILTER_COUNT, &value) != 0) return -1;
            resource->filter_id = (enum asteriskd_filter_id)value;
            if (parse_enum_token(json, values[3], direction_names, ASTERISKD_TC_DIRECTION_COUNT, &value) != 0) return -1;
            resource->direction = (enum asteriskd_tc_direction)value;
            if (decode_json_string(json, values[4], resource->interface_name, sizeof(resource->interface_name)) != 0 ||
                parse_u32_token(json, values[5], &resource->interface_index) != 0 ||
                parse_enum_token(json, values[6], program_names, ASTERISKD_PROGRAM_COUNT, &value) != 0) return -1;
            resource->program_id = (enum asteriskd_program_id)value;
            return parse_bool_token(json, values[7], &resource->original_presence);
        }
        case ASTERISKD_RECOVERY_SYSCTL: {
            static const char *const names[] = {"sysctlId", "interfaceName", "interfaceIndex", "originalValue", "desiredValue"};
            size_t values[5];
            struct asteriskd_sysctl_resource *resource = &record->resource.sysctl;
            uint32_t original, desired;
            if (object_values(json, object, names, 5U, values) != 0 ||
                parse_enum_token(json, values[0], sysctl_names, ASTERISKD_SYSCTL_COUNT, &value) != 0) return -1;
            resource->sysctl_id = (enum asteriskd_sysctl_id)value;
            if (decode_json_string(json, values[1], resource->interface_name, sizeof(resource->interface_name)) != 0 ||
                parse_u32_token(json, values[2], &resource->interface_index) != 0 ||
                parse_u32_token(json, values[3], &original) != 0 || original > 1U ||
                parse_u32_token(json, values[4], &desired) != 0 || desired > 1U) return -1;
            resource->original_value = (uint8_t)original;
            resource->desired_value = (uint8_t)desired;
            return 0;
        }
        case ASTERISKD_RECOVERY_TETHER_STATE: {
            static const char *const names[] = {"tetherId", "interfaceName", "interfaceIndex", "originalActive", "desiredActive"};
            size_t values[5];
            struct asteriskd_tether_state_resource *resource = &record->resource.tether_state;
            if (object_values(json, object, names, 5U, values) != 0 ||
                parse_enum_token(json, values[0], tether_names, ASTERISKD_TETHER_COUNT, &value) != 0) return -1;
            resource->tether_id = (enum asteriskd_tether_id)value;
            return decode_json_string(json, values[1], resource->interface_name, sizeof(resource->interface_name)) == 0 &&
                parse_u32_token(json, values[2], &resource->interface_index) == 0 &&
                parse_bool_token(json, values[3], &resource->original_active) == 0 &&
                parse_bool_token(json, values[4], &resource->desired_active) == 0 ? 0 : -1;
        }
        case ASTERISKD_RECOVERY_KIND_COUNT:
            return -1;
    }
    return -1;
}

static int parse_recovery_record(
    const struct asteriskd_json_document *json,
    size_t object,
    struct asteriskd_recovery_record *record) {
    static const char *const names[] = {"recordId", "status", "kind", "resource"};
    size_t values[4];
    int value;
    memset(record, 0, sizeof(*record));
    if (object_values(json, object, names, 4U, values) != 0 ||
        parse_u64_token(json, values[0], &record->record_id) != 0 ||
        parse_enum_token(json, values[1], recovery_status_names, 2U, &value) != 0) return -1;
    record->status = (enum asteriskd_recovery_status)value;
    if (parse_enum_token(json, values[2], recovery_kind_names, ASTERISKD_RECOVERY_KIND_COUNT, &value) != 0) return -1;
    record->kind = (enum asteriskd_recovery_kind)value;
    int obsolete = parse_obsolete_hotspot_record(json, values[3], record);
    if (obsolete != 0) return obsolete;
    return parse_record_resource(json, values[3], record);
}

static int parse_failure(
    const struct asteriskd_json_document *json,
    size_t token,
    struct asteriskd_state_failure *failure) {
    memset(failure, 0, sizeof(*failure));
    if (is_null_token(json, token)) return 0;
    static const char *const names[] = {"code", "component", "message", "exitCode", "signal"};
    size_t values[5];
    int value;
    if (object_values(json, token, names, 5U, values) != 0 ||
        parse_enum_token(json, values[0], failure_names, ASTERISKD_FAILURE_CODE_COUNT, &value) != 0) return -1;
    failure->code = (enum asteriskd_failure_code)value;
    if (parse_enum_token(json, values[1], component_names, ASTERISKD_COMPONENT_COUNT, &value) != 0) return -1;
    failure->component = (enum asteriskd_component)value;
    if (decode_json_string(json, values[2], failure->message, sizeof(failure->message)) != 0) return -1;
    if (!is_null_token(json, values[3])) {
        failure->has_exit_code = true;
        if (parse_positive_int_token(json, values[3], true, &failure->exit_code) != 0) return -1;
    }
    if (!is_null_token(json, values[4])) {
        failure->has_signal = true;
        if (parse_positive_int_token(json, values[4], false, &failure->signal) != 0) return -1;
    }
    failure->present = true;
    return failure_valid(failure) ? 0 : -1;
}

int asteriskd_state_parse(
    const char *bytes,
    size_t length,
    struct asteriskd_state_document *state,
    char *error,
    size_t error_size) {
    if (state != NULL) memset(state, 0, sizeof(*state));
    if (bytes == NULL || state == NULL || length == 0U || length > ASTERISKD_MAX_JSON_SIZE) {
        set_error(error, error_size, "invalid state input");
        return ASTERISKD_STATE_INVALID;
    }
    size_t first = 0U;
    while (first < length && (bytes[first] == ' ' || bytes[first] == '\t' || bytes[first] == '\r' || bytes[first] == '\n')) ++first;
    if (first >= length || bytes[first] != '{') {
        set_error(error, error_size, "legacy-state-incompatible");
        return ASTERISKD_STATE_INCOMPATIBLE;
    }
    struct asteriskd_json_document json;
    int parse_result = asteriskd_json_parse(bytes, length, &json, error, error_size);
    if (parse_result != 0) {
        return parse_result == ASTERISKD_CONFIG_NO_MEMORY ? ASTERISKD_STATE_NO_MEMORY : ASTERISKD_STATE_INVALID;
    }
    static const char *const names[] = {
        "schemaVersion", "phase", "owner", "coreType", "mode", "children",
        "matcher", "rules", "recovery", "failure",
    };
    size_t values[10];
    size_t schema_token;
    uint64_t schema;
    int phase, owner, core, mode;
    int result = ASTERISKD_STATE_INVALID;
    if (json.tokens[0].type != ASTERISKD_JSON_OBJECT ||
        find_unique_value(&json, 0U, "schemaVersion", &schema_token) != 0 ||
        parse_u64_token(&json, schema_token, &schema) != 0) goto done;
    if (schema != ASTERISKD_STATE_VERSION) {
        result = ASTERISKD_STATE_INCOMPATIBLE;
        goto done;
    }
    if (object_values(&json, 0U, names, 10U, values) != 0) goto done;
    if (parse_enum_token(&json, values[1], phase_names, ASTERISKD_PHASE_COUNT, &phase) != 0 ||
        parse_enum_token(&json, values[2], owner_names, 3U, &owner) != 0 ||
        parse_enum_token(&json, values[3], core_names, 3U, &core) != 0 ||
        parse_enum_token(&json, values[4], mode_names, 5U, &mode) != 0 ||
        asteriskd_state_document_init(state, (enum asteriskd_owner)owner,
            (enum asteriskd_core_type)core, (enum asteriskd_mode)mode) != ASTERISKD_STATE_OK) goto done;
    state->phase = (enum asteriskd_phase)phase;
    static const char *const children_names[] = {"core", "helper"};
    size_t children_values[2];
    if (object_values(&json, values[5], children_names, 2U, children_values) != 0 ||
        parse_child(&json, children_values[0], state, ASTERISKD_CHILD_CORE) != 0 ||
        parse_child(&json, children_values[1], state, ASTERISKD_CHILD_HELPER) != 0) goto done;
    static const char *const matcher_names[] = {"configured", "active"};
    size_t matcher_values[2];
    if (object_values(&json, values[6], matcher_names, 2U, matcher_values) != 0 ||
        parse_bool_token(&json, matcher_values[0], &state->matcher.configured) != 0 ||
        parse_bool_token(&json, matcher_values[1], &state->matcher.active) != 0) goto done;
    static const char *const rules_names[] = {"active", "generation", "categories"};
    size_t rules_values[3];
    if (object_values(&json, values[7], rules_names, 3U, rules_values) != 0 ||
        parse_bool_token(&json, rules_values[0], &state->rules.active) != 0 ||
        parse_u64_token(&json, rules_values[1], &state->rules.generation) != 0 ||
        json.tokens[rules_values[2]].type != ASTERISKD_JSON_ARRAY ||
        json.tokens[rules_values[2]].child_count > ASTERISKD_RULE_CATEGORY_COUNT) goto done;
    size_t cursor = rules_values[2] + 1U;
    for (size_t index = 0U; index < json.tokens[rules_values[2]].child_count; ++index) {
        size_t token = next_direct(&json, rules_values[2], cursor);
        int category;
        if (token == TOKEN_NONE ||
            parse_enum_token(&json, token, category_names, ASTERISKD_RULE_CATEGORY_COUNT, &category) != 0 ||
            (state->rules.categories & ASTERISKD_RULE_CATEGORY_BIT(category)) != 0U) goto done;
        state->rules.categories |= ASTERISKD_RULE_CATEGORY_BIT(category);
        cursor = token + 1U;
    }
    static const char *const recovery_names[] = {"nextRecordId", "coreOwnedEbpfBoundary", "records"};
    size_t recovery_values[3];
    uint64_t declared_next_record_id;
    if (object_values(&json, values[8], recovery_names, 3U, recovery_values) != 0 ||
        parse_u64_token(&json, recovery_values[0], &declared_next_record_id) != 0 ||
        parse_bool_token(&json, recovery_values[1], &state->recovery.core_owned_ebpf_boundary) != 0 ||
        json.tokens[recovery_values[2]].type != ASTERISKD_JSON_ARRAY) goto done;
    state->recovery.next_record_id = 1U;
    cursor = recovery_values[2] + 1U;
    uint64_t previous_record_id = 0U;
    bool saw_intent = false;
    for (size_t index = 0U; index < json.tokens[recovery_values[2]].child_count; ++index) {
        size_t token = next_direct(&json, recovery_values[2], cursor);
        struct asteriskd_recovery_record record;
        int parsed = token == TOKEN_NONE ? -1 : parse_recovery_record(&json, token, &record);
        if (parsed < 0 || record.record_id <= previous_record_id ||
            record.record_id >= declared_next_record_id ||
            (record.status == ASTERISKD_RECOVERY_APPLIED && saw_intent) ||
            (parsed == 0 && asteriskd_state_append_recovery(
                state, &record, error, error_size) != ASTERISKD_STATE_OK)) goto done;
        if (record.status == ASTERISKD_RECOVERY_INTENT) saw_intent = true;
        previous_record_id = record.record_id;
        cursor = token + 1U;
    }
    if (declared_next_record_id < state->recovery.next_record_id) goto done;
    state->recovery.next_record_id = declared_next_record_id;
    if (parse_failure(&json, values[9], &state->failure) != 0 || !document_valid(state)) goto done;
    result = ASTERISKD_STATE_OK;
done:
    asteriskd_json_document_destroy(&json);
    if (result != ASTERISKD_STATE_OK) {
        asteriskd_state_document_destroy(state);
        set_error(error, error_size,
            result == ASTERISKD_STATE_INCOMPATIBLE ? "state schema incompatible" : "invalid state");
    } else {
        set_error(error, error_size, "ok");
    }
    return result;
}

#ifndef _WIN32
static enum asteriskd_file_kind system_file_kind(mode_t mode) {
    if (S_ISREG(mode)) return ASTERISKD_FILE_REGULAR;
    if (S_ISDIR(mode)) return ASTERISKD_FILE_DIRECTORY;
    if (S_ISFIFO(mode)) return ASTERISKD_FILE_FIFO;
    if (S_ISCHR(mode) || S_ISBLK(mode)) return ASTERISKD_FILE_DEVICE;
    if (S_ISLNK(mode)) return ASTERISKD_FILE_SYMLINK;
    return ASTERISKD_FILE_OTHER;
}

static int system_fstat(
    void *context,
    int fd,
    uint64_t *device,
    uint64_t *inode,
    enum asteriskd_file_kind *kind) {
    (void)context;
    struct stat status;
    if (fstat(fd, &status) != 0) return -1;
    *device = (uint64_t)status.st_dev;
    *inode = (uint64_t)status.st_ino;
    *kind = system_file_kind(status.st_mode);
    return 0;
}

static int system_dup(void *context, int fd, int *out) {
    (void)context;
    *out = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return *out >= 0 ? 0 : -1;
}

static int system_openat(
    void *context,
    int directory_fd,
    const char *name,
    uint32_t flags,
    uint32_t mode,
    int *out) {
    (void)context;
    int system_flags = 0;
    if ((flags & ASTERISKD_STATE_OPEN_WRITE) != 0U) system_flags |= O_WRONLY;
    else system_flags |= O_RDONLY;
    if ((flags & ASTERISKD_STATE_OPEN_CREATE) != 0U) system_flags |= O_CREAT;
    if ((flags & ASTERISKD_STATE_OPEN_EXCLUSIVE) != 0U) system_flags |= O_EXCL;
    if ((flags & ASTERISKD_STATE_OPEN_NOFOLLOW) != 0U) system_flags |= O_NOFOLLOW;
    if ((flags & ASTERISKD_STATE_OPEN_CLOEXEC) != 0U) system_flags |= O_CLOEXEC;
    if ((flags & ASTERISKD_STATE_OPEN_NONBLOCK) != 0U) system_flags |= O_NONBLOCK;
    *out = openat(directory_fd, name, system_flags, (mode_t)mode);
    return *out >= 0 ? 0 : -1;
}

static ptrdiff_t system_read(void *context, int fd, void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)read(fd, bytes, length);
}

static ptrdiff_t system_write(void *context, int fd, const void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)write(fd, bytes, length);
}

static int system_fsync(void *context, int fd) {
    (void)context;
    return fsync(fd);
}

static int system_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static int system_renameat(
    void *context,
    int old_directory_fd,
    const char *old_name,
    int new_directory_fd,
    const char *new_name) {
    (void)context;
    return renameat(old_directory_fd, old_name, new_directory_fd, new_name);
}

static int system_unlinkat(void *context, int directory_fd, const char *name) {
    (void)context;
    return unlinkat(directory_fd, name, 0);
}

static const struct asteriskd_state_file_backend system_state_backend = {
    .fstat_fd = system_fstat,
    .dup_cloexec = system_dup,
    .openat_fd = system_openat,
    .read_fd = system_read,
    .write_fd = system_write,
    .fsync_fd = system_fsync,
    .close_fd = system_close,
    .renameat_fd = system_renameat,
    .unlinkat_fd = system_unlinkat,
};
#endif

static bool file_backend_complete(const struct asteriskd_state_file_backend *backend) {
    return backend != NULL && backend->fstat_fd != NULL && backend->dup_cloexec != NULL &&
        backend->openat_fd != NULL && backend->read_fd != NULL && backend->write_fd != NULL &&
        backend->fsync_fd != NULL && backend->close_fd != NULL && backend->renameat_fd != NULL &&
        backend->unlinkat_fd != NULL;
}

int asteriskd_state_store_init_with_backend(
    struct asteriskd_state_store *store,
    int runtime_directory_fd,
    uint64_t expected_device,
    uint64_t expected_inode,
    const struct asteriskd_state_file_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (store != NULL) {
        memset(store, 0, sizeof(*store));
        store->directory_fd = -1;
    }
    if (store == NULL || runtime_directory_fd < 0 || expected_inode == 0U ||
        !file_backend_complete(backend)) {
        set_error(error, error_size, "invalid state store arguments");
        return ASTERISKD_STATE_INVALID;
    }
    uint64_t source_device, source_inode;
    enum asteriskd_file_kind source_kind;
    if (backend->fstat_fd(context, runtime_directory_fd, &source_device, &source_inode, &source_kind) != 0) {
        set_error(error, error_size, "state directory stat failed");
        return ASTERISKD_STATE_IO;
    }
    if (source_kind != ASTERISKD_FILE_DIRECTORY || source_device != expected_device ||
        source_inode != expected_inode) {
        set_error(error, error_size, "state directory identity mismatch");
        return ASTERISKD_STATE_INVALID;
    }
    int duplicate = -1;
    int duplicate_result = backend->dup_cloexec(context, runtime_directory_fd, &duplicate);
    if (duplicate_result != 0 || duplicate < 0) {
        if (duplicate >= 0) (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "state directory duplicate failed");
        return ASTERISKD_STATE_IO;
    }
    uint64_t duplicate_device, duplicate_inode;
    enum asteriskd_file_kind duplicate_kind;
    if (backend->fstat_fd(context, duplicate, &duplicate_device, &duplicate_inode, &duplicate_kind) != 0) {
        (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "duplicated state directory stat failed");
        return ASTERISKD_STATE_IO;
    }
    if (duplicate_kind != ASTERISKD_FILE_DIRECTORY || duplicate_device != source_device ||
        duplicate_inode != source_inode) {
        (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "duplicated state directory identity mismatch");
        return ASTERISKD_STATE_INVALID;
    }
    store->directory_fd = duplicate;
    store->directory_fd_owned = true;
    store->directory_device = source_device;
    store->directory_inode = source_inode;
    store->backend = backend;
    store->backend_context = context;
    store->temporary_sequence = 1U;
    store->initialized = true;
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_store_init(
    struct asteriskd_state_store *store,
    int runtime_directory_fd,
    uint64_t expected_device,
    uint64_t expected_inode,
    char *error,
    size_t error_size) {
#ifdef _WIN32
    if (store != NULL) {
        memset(store, 0, sizeof(*store));
        store->directory_fd = -1;
    }
    (void)runtime_directory_fd;
    (void)expected_device;
    (void)expected_inode;
    set_error(error, error_size, "real state store requires Linux; use injected host backend");
    return ASTERISKD_STATE_IO;
#else
    return asteriskd_state_store_init_with_backend(
        store, runtime_directory_fd, expected_device, expected_inode,
        &system_state_backend, NULL, error, error_size);
#endif
}

void asteriskd_state_store_close(struct asteriskd_state_store *store) {
    if (store == NULL) return;
    if (store->directory_fd_owned && store->directory_fd >= 0 && store->backend != NULL &&
        store->backend->close_fd != NULL) {
        (void)store->backend->close_fd(store->backend_context, store->directory_fd);
    }
    memset(store, 0, sizeof(*store));
    store->directory_fd = -1;
}

static int verify_store_directory(struct asteriskd_state_store *store) {
    if (store == NULL || !store->initialized || !store->directory_fd_owned ||
        store->directory_fd < 0 || !file_backend_complete(store->backend)) return ASTERISKD_STATE_INVALID;
    uint64_t device, inode;
    enum asteriskd_file_kind kind;
    if (store->backend->fstat_fd(
            store->backend_context, store->directory_fd, &device, &inode, &kind) != 0) {
        return ASTERISKD_STATE_IO;
    }
    return kind == ASTERISKD_FILE_DIRECTORY && device == store->directory_device &&
        inode == store->directory_inode ? ASTERISKD_STATE_OK : ASTERISKD_STATE_INVALID;
}

static int read_complete_file(
    struct asteriskd_state_store *store,
    int fd,
    char **out,
    size_t *out_length) {
    char *bytes = NULL;
    size_t length = 0U;
    size_t capacity = 4096U;
    bytes = malloc(capacity);
    if (bytes == NULL) return ASTERISKD_STATE_NO_MEMORY;
    while (true) {
        if (length == capacity) {
            if (capacity >= ASTERISKD_MAX_JSON_SIZE) {
                char extra;
                ptrdiff_t count = store->backend->read_fd(
                    store->backend_context, fd, &extra, sizeof(extra));
                if (count < 0) {
                    if (errno == EINTR) continue;
                    free(bytes);
                    return errno == ENOMEM ? ASTERISKD_STATE_NO_MEMORY : ASTERISKD_STATE_IO;
                }
                if (count == 0) break;
                free(bytes);
                return ASTERISKD_STATE_INVALID;
            }
            size_t next = capacity * 2U;
            if (next > ASTERISKD_MAX_JSON_SIZE) next = ASTERISKD_MAX_JSON_SIZE;
            char *grown = realloc(bytes, next);
            if (grown == NULL) {
                free(bytes);
                return ASTERISKD_STATE_NO_MEMORY;
            }
            bytes = grown;
            capacity = next;
        }
        ptrdiff_t count = store->backend->read_fd(
            store->backend_context, fd, bytes + length, capacity - length);
        if (count < 0) {
            if (errno == EINTR) continue;
            free(bytes);
            return errno == ENOMEM ? ASTERISKD_STATE_NO_MEMORY : ASTERISKD_STATE_IO;
        }
        if (count == 0) break;
        if ((size_t)count > capacity - length) {
            free(bytes);
            return ASTERISKD_STATE_IO;
        }
        length += (size_t)count;
    }
    if (length == 0U) {
        free(bytes);
        return ASTERISKD_STATE_INVALID;
    }
    *out = bytes;
    *out_length = length;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_store_load(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    char *error,
    size_t error_size) {
    if (state != NULL) memset(state, 0, sizeof(*state));
    if (state == NULL) return ASTERISKD_STATE_INVALID;
    int result = verify_store_directory(store);
    if (result != ASTERISKD_STATE_OK) {
        if (store != NULL) store->write_blocked = true;
        return result;
    }
    int fd = -1;
    uint32_t flags = ASTERISKD_STATE_OPEN_READ | ASTERISKD_STATE_OPEN_NOFOLLOW |
        ASTERISKD_STATE_OPEN_CLOEXEC | ASTERISKD_STATE_OPEN_NONBLOCK;
    errno = 0;
    int open_result = store->backend->openat_fd(
        store->backend_context, store->directory_fd, ASTERISKD_LEGACY_ROUTE_LOCALNET_LEAF,
        flags, 0U, &fd);
    int open_error = errno;
    if (open_result == 0 && fd >= 0) {
        (void)store->backend->close_fd(store->backend_context, fd);
        store->write_blocked = true;
        set_error(error, error_size, "legacy-state-incompatible: route-localnet sidecar exists");
        return ASTERISKD_STATE_INCOMPATIBLE;
    }
    if (fd >= 0) {
        (void)store->backend->close_fd(store->backend_context, fd);
        fd = -1;
    }
    if (open_result == 0 || open_error != ENOENT) {
        store->write_blocked = true;
        if (open_error == ELOOP) {
            set_error(error, error_size, "legacy-state-incompatible: route-localnet sidecar exists");
            return ASTERISKD_STATE_INCOMPATIBLE;
        }
        set_error(error, error_size, "legacy route-localnet state probe failed");
        return ASTERISKD_STATE_IO;
    }

    errno = 0;
    open_result = store->backend->openat_fd(
            store->backend_context, store->directory_fd, ASTERISKD_STATE_LEAF,
            flags, 0U, &fd);
    open_error = errno;
    if (open_result != 0 || fd < 0) {
        if (fd >= 0) {
            (void)store->backend->close_fd(store->backend_context, fd);
            fd = -1;
        }
        if (open_result != 0 && open_error == ENOENT) {
            set_error(error, error_size, "state not found");
            return ASTERISKD_STATE_NOT_FOUND;
        }
        if (open_result != 0 && open_error == ELOOP) {
            store->write_blocked = true;
            set_error(error, error_size, "state target is a symlink");
            return ASTERISKD_STATE_INVALID;
        }
        store->write_blocked = true;
        set_error(error, error_size, "open state failed");
        return ASTERISKD_STATE_IO;
    }
    uint64_t device, inode;
    enum asteriskd_file_kind kind;
    if (store->backend->fstat_fd(store->backend_context, fd, &device, &inode, &kind) != 0) {
        (void)store->backend->close_fd(store->backend_context, fd);
        store->write_blocked = true;
        set_error(error, error_size, "state target stat failed");
        return ASTERISKD_STATE_IO;
    }
    if (kind != ASTERISKD_FILE_REGULAR) {
        (void)store->backend->close_fd(store->backend_context, fd);
        set_error(error, error_size, "state target is not regular");
        store->write_blocked = true;
        return ASTERISKD_STATE_INVALID;
    }
    (void)device;
    (void)inode;
    char *bytes = NULL;
    size_t length = 0U;
    result = read_complete_file(store, fd, &bytes, &length);
    if (store->backend->close_fd(store->backend_context, fd) != 0 && result == ASTERISKD_STATE_OK) {
        result = ASTERISKD_STATE_IO;
    }
    if (result == ASTERISKD_STATE_OK) result = asteriskd_state_parse(bytes, length, state, error, error_size);
    free(bytes);
    if (result != ASTERISKD_STATE_OK) store->write_blocked = true;
    return result;
}

static int write_all(
    struct asteriskd_state_store *store,
    int fd,
    const char *bytes,
    size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ptrdiff_t count = store->backend->write_fd(
            store->backend_context, fd, bytes + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return ASTERISKD_STATE_IO;
        }
        if (count == 0 || (size_t)count > length - offset) return ASTERISKD_STATE_IO;
        offset += (size_t)count;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_store_save(
    struct asteriskd_state_store *store,
    const struct asteriskd_state_document *state,
    char *error,
    size_t error_size) {
    if (store == NULL || !store->initialized) return ASTERISKD_STATE_INVALID;
    if (store->write_blocked) {
        set_error(error, error_size, "state evidence is write-blocked");
        return ASTERISKD_STATE_WRITE_BLOCKED;
    }
    char *json = NULL;
    size_t length = 0U;
    int result = asteriskd_state_serialize(state, &json, &length, error, error_size);
    if (result != ASTERISKD_STATE_OK) return result;
    result = verify_store_directory(store);
    if (result != ASTERISKD_STATE_OK) {
        free(json);
        return result;
    }
    char temporary[96];
    int fd = -1;
    bool temp_exists = false;
    uint32_t flags = ASTERISKD_STATE_OPEN_WRITE | ASTERISKD_STATE_OPEN_CREATE |
        ASTERISKD_STATE_OPEN_EXCLUSIVE | ASTERISKD_STATE_OPEN_NOFOLLOW |
        ASTERISKD_STATE_OPEN_CLOEXEC;
    for (size_t attempt = 0U; attempt < STATE_TEMP_ATTEMPTS; ++attempt) {
        uint64_t sequence = store->temporary_sequence++;
        int count = snprintf(temporary, sizeof(temporary), ".asteriskd.state.tmp.%016" PRIx64, sequence);
        if (count < 0 || (size_t)count >= sizeof(temporary)) {
            result = ASTERISKD_STATE_INVALID;
            break;
        }
        errno = 0;
        int create_result = store->backend->openat_fd(
                store->backend_context, store->directory_fd, temporary,
                flags, 0600U, &fd);
        int create_error = errno;
        if (create_result == 0 && fd >= 0) {
            temp_exists = true;
            result = ASTERISKD_STATE_OK;
            break;
        }
        if (fd >= 0) {
            (void)store->backend->close_fd(store->backend_context, fd);
            (void)store->backend->unlinkat_fd(
                store->backend_context, store->directory_fd, temporary);
        }
        fd = -1;
        if (create_result == 0 || create_error != EEXIST) {
            result = ASTERISKD_STATE_IO;
            break;
        }
        result = ASTERISKD_STATE_IO;
    }
    if (!temp_exists) {
        free(json);
        set_error(error, error_size, "create state temp failed");
        return result;
    }
    result = write_all(store, fd, json, length);
    if (result == ASTERISKD_STATE_OK &&
        store->backend->fsync_fd(store->backend_context, fd) != 0) result = ASTERISKD_STATE_IO;
    if (store->backend->close_fd(store->backend_context, fd) != 0 && result == ASTERISKD_STATE_OK) {
        result = ASTERISKD_STATE_IO;
    }
    fd = -1;
    if (result == ASTERISKD_STATE_OK) {
        if (store->backend->renameat_fd(
                store->backend_context, store->directory_fd, temporary,
                store->directory_fd, ASTERISKD_STATE_LEAF) != 0) {
            result = ASTERISKD_STATE_IO;
        } else {
            temp_exists = false;
            if (store->backend->fsync_fd(store->backend_context, store->directory_fd) != 0) {
                result = ASTERISKD_STATE_IO;
                store->write_blocked = true;
            }
        }
    }
    if (temp_exists) {
        (void)store->backend->unlinkat_fd(store->backend_context, store->directory_fd, temporary);
    }
    free(json);
    set_error(error, error_size, result == ASTERISKD_STATE_OK ? "ok" : "atomic state save failed");
    return result;
}

static bool wal_backend_complete(const struct asteriskd_wal_effect_backend *backend) {
    return backend != NULL && backend->probe_original != NULL && backend->apply != NULL &&
        backend->verify_applied != NULL && backend->probe_recovery != NULL &&
        backend->undo != NULL && backend->verify_restored != NULL;
}

static bool identity_delta_is_empty(
    const struct asteriskd_wal_applied_identity_delta *delta) {
    return delta != NULL && !delta->has_interface_index && delta->interface_index == 0U &&
        !delta->has_object_id && delta->object_id == 0U;
}

static bool apply_verified_identity_delta(
    struct asteriskd_recovery_record *record,
    const struct asteriskd_wal_applied_identity_delta *delta) {
    if (record == NULL || delta == NULL) return false;
    if (record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE &&
        !record->resource.dummy_interface.has_interface_index) {
        if (!delta->has_interface_index || delta->interface_index == 0U ||
            delta->has_object_id || delta->object_id != 0U) return false;
        record->resource.dummy_interface.has_interface_index = true;
        record->resource.dummy_interface.interface_index = delta->interface_index;
        return true;
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN &&
        !record->resource.bpf_pin.has_object_id) {
        if (!delta->has_object_id || delta->object_id == 0U ||
            delta->has_interface_index || delta->interface_index != 0U) return false;
        record->resource.bpf_pin.has_object_id = true;
        record->resource.bpf_pin.object_id = delta->object_id;
        return true;
    }
    return identity_delta_is_empty(delta);
}

static bool verified_identities_are_unique(
    const struct asteriskd_recovery_record *records,
    size_t record_count) {
    enum pin_identity_domain {
        PIN_IDENTITY_NONE,
        PIN_IDENTITY_MATCHER_PROGRAM,
        PIN_IDENTITY_BPF2SOCKS_MAP,
        PIN_IDENTITY_BPF2SOCKS_PROGRAM,
    };
    for (size_t left = 0U; left < record_count; ++left) {
        for (size_t right = left + 1U; right < record_count; ++right) {
            if (records[left].kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE &&
                records[right].kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE &&
                records[left].resource.dummy_interface.interface_index ==
                    records[right].resource.dummy_interface.interface_index) return false;
            if (records[left].kind == ASTERISKD_RECOVERY_BPF_PIN &&
                records[right].kind == ASTERISKD_RECOVERY_BPF_PIN) {
                enum asteriskd_pin_id left_id = records[left].resource.bpf_pin.pin_id;
                enum asteriskd_pin_id right_id = records[right].resource.bpf_pin.pin_id;
                enum pin_identity_domain left_domain = left_id <= ASTERISKD_PIN_MATCHER_PREROUTING_V6 ?
                    PIN_IDENTITY_MATCHER_PROGRAM :
                    (left_id <= ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6 ?
                        PIN_IDENTITY_BPF2SOCKS_MAP :
                        (left_id <= ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS ?
                            PIN_IDENTITY_BPF2SOCKS_PROGRAM : PIN_IDENTITY_NONE));
                enum pin_identity_domain right_domain = right_id <= ASTERISKD_PIN_MATCHER_PREROUTING_V6 ?
                    PIN_IDENTITY_MATCHER_PROGRAM :
                    (right_id <= ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6 ?
                        PIN_IDENTITY_BPF2SOCKS_MAP :
                        (right_id <= ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS ?
                            PIN_IDENTITY_BPF2SOCKS_PROGRAM : PIN_IDENTITY_NONE));
                if (left_domain != PIN_IDENTITY_NONE && left_domain == right_domain &&
                    records[left].resource.bpf_pin.object_id ==
                        records[right].resource.bpf_pin.object_id) return false;
            }
        }
    }
    return true;
}

static bool apply_original_delta(
    struct asteriskd_recovery_record *record,
    const struct asteriskd_wal_original_delta *delta) {
    if (record == NULL || delta == NULL) return false;
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.iptables_chain.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_IPTABLES_RULE:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.iptables_rule.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_IP_RULE:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.ip_rule.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_ROUTE:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.route.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.dummy_interface.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_BPF_PIN:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.bpf_pin.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_TC_QDISC:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.tc_qdisc.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_TC_FILTER:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE ||
                delta->original_value != 0U || delta->original_active) return false;
            record->resource.tc_filter.original_presence = delta->original_presence;
            return true;
        case ASTERISKD_RECOVERY_SYSCTL:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_SYSCTL_VALUE ||
                delta->original_presence || delta->original_active || delta->original_value > 1U) return false;
            record->resource.sysctl.original_value = delta->original_value;
            return true;
        case ASTERISKD_RECOVERY_TETHER_STATE:
            if (delta->kind != ASTERISKD_WAL_ORIGINAL_DELTA_TETHER_ACTIVE ||
                delta->original_presence || delta->original_value != 0U) return false;
            record->resource.tether_state.original_active = delta->original_active;
            return true;
        case ASTERISKD_RECOVERY_KIND_COUNT:
            return false;
    }
    return false;
}

static bool wal_creation_original_is_absent(
    const struct asteriskd_recovery_record *record) {
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN:
            return !record->resource.iptables_chain.original_presence;
        case ASTERISKD_RECOVERY_IPTABLES_RULE:
            return !record->resource.iptables_rule.original_presence;
        case ASTERISKD_RECOVERY_IP_RULE:
            return !record->resource.ip_rule.original_presence;
        case ASTERISKD_RECOVERY_ROUTE:
            return !record->resource.route.original_presence;
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE:
            return !record->resource.dummy_interface.original_presence;
        case ASTERISKD_RECOVERY_BPF_PIN:
            return !record->resource.bpf_pin.original_presence;
        case ASTERISKD_RECOVERY_TC_QDISC:
            return !record->resource.tc_qdisc.original_presence;
        case ASTERISKD_RECOVERY_TC_FILTER:
            return !record->resource.tc_filter.original_presence;
        case ASTERISKD_RECOVERY_SYSCTL:
        case ASTERISKD_RECOVERY_TETHER_STATE:
        case ASTERISKD_RECOVERY_KIND_COUNT:
            return true;
    }
    return false;
}

static int wal_apply_records(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    struct asteriskd_recovery_record *records,
    size_t record_count,
    bool fixed_pin_batch,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (store != NULL && store->initialized && store->write_blocked) {
        set_error(error, error_size, "state evidence is write-blocked");
        return ASTERISKD_STATE_WRITE_BLOCKED;
    }
    if (store == NULL || state == NULL || !state->initialized || records == NULL ||
        !store->initialized || record_count == 0U || !wal_backend_complete(backend) || !document_valid(state) ||
        state->recovery.next_record_id == 0U ||
        record_count > UINT64_MAX - state->recovery.next_record_id ||
        record_count > SIZE_MAX / sizeof(*records) ||
        state->recovery.record_count > SIZE_MAX - record_count) {
        set_error(error, error_size, "invalid WAL apply arguments");
        return ASTERISKD_STATE_INVALID;
    }
    for (size_t index = 0U; index < record_count; ++index) {
        if (records[index].record_id != 0U || records[index].status != ASTERISKD_RECOVERY_INTENT) {
            set_error(error, error_size, "invalid WAL input record");
            return ASTERISKD_STATE_INVALID;
        }
        struct asteriskd_recovery_record input = records[index];
        input.record_id = 1U;
        bool identity_is_unclaimed =
            (input.kind != ASTERISKD_RECOVERY_DUMMY_INTERFACE ||
             (!input.resource.dummy_interface.has_interface_index &&
              input.resource.dummy_interface.interface_index == 0U)) &&
            (input.kind != ASTERISKD_RECOVERY_BPF_PIN ||
             (!input.resource.bpf_pin.has_object_id && input.resource.bpf_pin.object_id == 0U));
        if (!record_resource_valid(&input) || !identity_is_unclaimed) {
            set_error(error, error_size, "invalid WAL input resource");
            return ASTERISKD_STATE_INVALID;
        }
    }
    for (size_t index = 0U; index < state->recovery.record_count; ++index) {
        if (state->recovery.records[index].status == ASTERISKD_RECOVERY_INTENT) {
            set_error(error, error_size, "prior WAL intent is unresolved");
            return ASTERISKD_WAL_INCOMPLETE;
        }
    }

    struct asteriskd_recovery_record *captured = malloc(record_count * sizeof(*captured));
    struct asteriskd_recovery_record *applied = malloc(record_count * sizeof(*applied));
    if (captured == NULL || applied == NULL) {
        free(captured);
        free(applied);
        return ASTERISKD_STATE_NO_MEMORY;
    }
    memcpy(applied, records, record_count * sizeof(*applied));
    uint64_t first_record_id = state->recovery.next_record_id;
    for (size_t index = 0U; index < record_count; ++index) {
        captured[index] = records[index];
        captured[index].record_id = first_record_id + (uint64_t)index;
        captured[index].status = ASTERISKD_RECOVERY_INTENT;
        struct asteriskd_recovery_record planned = captured[index];
        struct asteriskd_wal_original_delta delta;
        memset(&delta, 0, sizeof(delta));
        if (backend->probe_original(context, &planned, &delta, error, error_size) != 0 ||
            !apply_original_delta(&captured[index], &delta) ||
            !record_resource_valid(&captured[index]) ||
            !wal_creation_original_is_absent(&captured[index]) ||
            (fixed_pin_batch && captured[index].resource.bpf_pin.original_presence)) {
            free(captured);
            free(applied);
            return ASTERISKD_STATE_IO;
        }
    }

    size_t previous_count = state->recovery.record_count;
    int result = ensure_record_capacity(state, previous_count + record_count);
    if (result != ASTERISKD_STATE_OK) {
        free(captured);
        free(applied);
        return result;
    }
    memcpy(&state->recovery.records[previous_count], captured, record_count * sizeof(*captured));
    state->recovery.record_count += record_count;
    state->recovery.next_record_id = first_record_id + (uint64_t)record_count;
    if (!document_valid(state)) {
        state->recovery.record_count = previous_count;
        state->recovery.next_record_id = first_record_id;
        free(captured);
        free(applied);
        set_error(error, error_size, "invalid captured WAL batch");
        return ASTERISKD_STATE_INVALID;
    }
    memcpy(records, captured, record_count * sizeof(*records));
    result = asteriskd_state_store_save(store, state, error, error_size);
    if (result != ASTERISKD_STATE_OK) {
        if (store->write_blocked) {
            memcpy(records, captured, record_count * sizeof(*records));
        } else {
            state->recovery.record_count = previous_count;
            state->recovery.next_record_id = first_record_id;
            memcpy(records, applied, record_count * sizeof(*records));
        }
        free(captured);
        free(applied);
        return result;
    }
    if (backend->apply(context, captured, record_count, error, error_size) != 0) {
        free(captured);
        free(applied);
        return ASTERISKD_STATE_IO;
    }
    memcpy(applied, captured, record_count * sizeof(*applied));
    for (size_t index = 0U; index < record_count; ++index) {
        struct asteriskd_wal_applied_identity_delta delta;
        memset(&delta, 0, sizeof(delta));
        if (backend->verify_applied(context, &captured[index], &delta, error, error_size) != 0 ||
            !apply_verified_identity_delta(&applied[index], &delta)) {
            free(captured);
            free(applied);
            return ASTERISKD_STATE_IO;
        }
        applied[index].status = ASTERISKD_RECOVERY_APPLIED;
        if (!record_resource_valid(&applied[index])) {
            free(captured);
            free(applied);
            return ASTERISKD_STATE_IO;
        }
    }
    if (!verified_identities_are_unique(applied, record_count)) {
        free(captured);
        free(applied);
        set_error(error, error_size, "verified WAL identities are not unique");
        return ASTERISKD_STATE_IO;
    }
    memcpy(&state->recovery.records[previous_count], applied, record_count * sizeof(*applied));
    if (!document_valid(state)) {
        memcpy(&state->recovery.records[previous_count], captured, record_count * sizeof(*captured));
        free(captured);
        free(applied);
        return ASTERISKD_STATE_IO;
    }
    result = asteriskd_state_store_save(store, state, error, error_size);
    if (result != ASTERISKD_STATE_OK) {
        memcpy(&state->recovery.records[previous_count], captured, record_count * sizeof(*captured));
        free(captured);
        free(applied);
        return result;
    }
    memcpy(records, applied, record_count * sizeof(*records));
    free(captured);
    free(applied);
    return ASTERISKD_STATE_OK;
}

int asteriskd_wal_apply(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    struct asteriskd_recovery_record *record,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (record != NULL && record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        set_error(error, error_size, "grouped pin requires fixed batch WAL");
        return ASTERISKD_STATE_INVALID;
    }
    return wal_apply_records(store, state, record, 1U, false, backend, context, error, error_size);
}

int asteriskd_wal_apply_batch(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    struct asteriskd_recovery_record *records,
    size_t record_count,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (records == NULL || record_count < 2U) {
        set_error(error, error_size, "invalid WAL batch");
        return ASTERISKD_STATE_INVALID;
    }
    for (size_t index = 0U; index < record_count; ++index) {
        enum asteriskd_recovery_kind kind = records[index].kind;
        if (kind != ASTERISKD_RECOVERY_IPTABLES_CHAIN &&
            kind != ASTERISKD_RECOVERY_IPTABLES_RULE &&
            kind != ASTERISKD_RECOVERY_IP_RULE &&
            kind != ASTERISKD_RECOVERY_ROUTE &&
            kind != ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
            set_error(error, error_size, "unsupported WAL batch resource");
            return ASTERISKD_STATE_INVALID;
        }
    }
    return wal_apply_records(
        store, state, records, record_count, false,
        backend, context, error, error_size);
}

static bool pin_batch_valid(
    enum asteriskd_wal_pin_batch_kind kind,
    const struct asteriskd_state_document *state,
    const struct asteriskd_recovery_record *records,
    size_t record_count) {
    static const enum asteriskd_pin_id matcher_v4[] = {
        ASTERISKD_PIN_MATCHER_OUTPUT_V4,
        ASTERISKD_PIN_MATCHER_PREROUTING_V4,
    };
    static const enum asteriskd_pin_id matcher_v4_v6[] = {
        ASTERISKD_PIN_MATCHER_OUTPUT_V4,
        ASTERISKD_PIN_MATCHER_OUTPUT_V6,
        ASTERISKD_PIN_MATCHER_PREROUTING_V4,
        ASTERISKD_PIN_MATCHER_PREROUTING_V6,
    };
    static const enum asteriskd_pin_id bpf2socks_v4[] = {
        ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4,
        ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS,
        ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS,
    };
    static const enum asteriskd_pin_id bpf2socks_v4_v6[] = {
        ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4,
        ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6,
        ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS,
        ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS,
    };
    const enum asteriskd_pin_id *expected = NULL;
    bool matcher_mode = state != NULL && state->matcher.configured &&
        (state->mode == ASTERISKD_MODE_TPROXY || state->mode == ASTERISKD_MODE_TUN ||
         state->mode == ASTERISKD_MODE_TUN2SOCKS);
    bool bpf2socks_mode = state != NULL && state->mode == ASTERISKD_MODE_BPF2SOCKS;
    if (kind == ASTERISKD_WAL_PIN_BATCH_MATCHER_IPV4 && matcher_mode && record_count == 2U) {
        expected = matcher_v4;
    } else if (kind == ASTERISKD_WAL_PIN_BATCH_MATCHER_DUAL_STACK &&
        matcher_mode && record_count == 4U) {
        expected = matcher_v4_v6;
    } else if (kind == ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_IPV4 &&
        bpf2socks_mode && record_count == 3U) {
        expected = bpf2socks_v4;
    } else if (kind == ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_DUAL_STACK &&
        bpf2socks_mode && record_count == 4U) {
        expected = bpf2socks_v4_v6;
    }
    if (expected == NULL || records == NULL) return false;
    for (size_t index = 0U; index < record_count; ++index) {
        if (records[index].record_id != 0U || records[index].status != ASTERISKD_RECOVERY_INTENT ||
            records[index].kind != ASTERISKD_RECOVERY_BPF_PIN ||
            records[index].resource.bpf_pin.pin_id != expected[index] ||
            records[index].resource.bpf_pin.has_object_id ||
            records[index].resource.bpf_pin.object_id != 0U ||
            records[index].resource.bpf_pin.original_presence) return false;
    }
    return true;
}

int asteriskd_wal_apply_pin_batch(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    enum asteriskd_wal_pin_batch_kind kind,
    struct asteriskd_recovery_record *records,
    size_t record_count,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (!pin_batch_valid(kind, state, records, record_count)) {
        set_error(error, error_size, "invalid fixed pin WAL batch");
        return ASTERISKD_STATE_INVALID;
    }
    return wal_apply_records(
        store, state, records, record_count, true, backend, context, error, error_size);
}

static int clear_record_durably(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    size_t index,
    char *error,
    size_t error_size) {
    struct asteriskd_recovery_record saved = state->recovery.records[index];
    size_t trailing = state->recovery.record_count - index - 1U;
    if (trailing != 0U) {
        memmove(&state->recovery.records[index], &state->recovery.records[index + 1U],
            trailing * sizeof(state->recovery.records[0]));
    }
    --state->recovery.record_count;
    int result = asteriskd_state_store_save(store, state, error, error_size);
    if (result != ASTERISKD_STATE_OK) {
        if (trailing != 0U) {
            memmove(&state->recovery.records[index + 1U], &state->recovery.records[index],
                trailing * sizeof(state->recovery.records[0]));
        }
        state->recovery.records[index] = saved;
        ++state->recovery.record_count;
    }
    return result;
}

static bool recovery_original_is_absent(const struct asteriskd_recovery_record *record) {
    switch (record->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN:
            return !record->resource.iptables_chain.original_presence;
        case ASTERISKD_RECOVERY_IPTABLES_RULE:
            return !record->resource.iptables_rule.original_presence;
        case ASTERISKD_RECOVERY_IP_RULE:
            return !record->resource.ip_rule.original_presence;
        case ASTERISKD_RECOVERY_ROUTE:
            return !record->resource.route.original_presence;
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE:
            return !record->resource.dummy_interface.original_presence;
        case ASTERISKD_RECOVERY_BPF_PIN:
            return !record->resource.bpf_pin.original_presence;
        case ASTERISKD_RECOVERY_TC_QDISC:
            return !record->resource.tc_qdisc.original_presence;
        case ASTERISKD_RECOVERY_TC_FILTER:
            return !record->resource.tc_filter.original_presence;
        case ASTERISKD_RECOVERY_SYSCTL:
            return record->resource.sysctl.interface_index > 0U &&
                strcmp(record->resource.sysctl.interface_name, "default") != 0;
        case ASTERISKD_RECOVERY_TETHER_STATE:
        case ASTERISKD_RECOVERY_KIND_COUNT:
            return false;
    }
    return false;
}

static int recover_record_at(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    size_t index,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    const struct asteriskd_recovery_record *record = &state->recovery.records[index];
    enum asteriskd_wal_resource_state resource_state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
    if (backend->probe_recovery(context, record, &resource_state, error, error_size) != 0 ||
        resource_state < ASTERISKD_WAL_RESOURCE_ORIGINAL ||
        resource_state > ASTERISKD_WAL_RESOURCE_AMBIGUOUS) {
        return ASTERISKD_WAL_INCOMPLETE;
    }
    bool restored = resource_state == ASTERISKD_WAL_RESOURCE_ORIGINAL ||
        (resource_state == ASTERISKD_WAL_RESOURCE_ABSENT && recovery_original_is_absent(record));
    if (resource_state == ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT) {
        if (backend->undo(context, record, error, error_size) == 0 &&
            backend->verify_restored(context, record, error, error_size) == 0) restored = true;
    }
    if (!restored) return ASTERISKD_WAL_INCOMPLETE;
    return clear_record_durably(store, state, index, error, error_size);
}

int asteriskd_wal_recover_record_id(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    uint64_t record_id,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (store == NULL || state == NULL || record_id == 0U ||
        !wal_backend_complete(backend) || !store->initialized ||
        !state->initialized || !document_valid(state)) return ASTERISKD_STATE_INVALID;
    if (store->write_blocked) return ASTERISKD_STATE_WRITE_BLOCKED;
    for (size_t index = 0U; index < state->recovery.record_count; ++index) {
        if (state->recovery.records[index].record_id == record_id) {
            return recover_record_at(
                store, state, index, backend, context, error, error_size);
        }
    }
    return ASTERISKD_STATE_NOT_FOUND;
}

int asteriskd_wal_recover(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    const struct asteriskd_wal_effect_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (store == NULL || state == NULL || !wal_backend_complete(backend) ||
        !store->initialized || !state->initialized || !document_valid(state)) {
        return ASTERISKD_STATE_INVALID;
    }
    if (store->write_blocked) return ASTERISKD_STATE_WRITE_BLOCKED;
    int overall = ASTERISKD_STATE_OK;
    size_t index = state->recovery.record_count;
    while (index > 0U) {
        --index;
        int clear_result = recover_record_at(
            store, state, index, backend, context, error, error_size);
        if (clear_result != ASTERISKD_STATE_OK) {
            if (overall == ASTERISKD_STATE_OK) {
                overall = clear_result == ASTERISKD_STATE_WRITE_BLOCKED ||
                    clear_result == ASTERISKD_STATE_IO
                    ? clear_result : ASTERISKD_WAL_INCOMPLETE;
            }
            if (store->write_blocked) break;
        }
    }
    return overall;
}


static bool typed_wal_sink_valid(const struct asteriskd_typed_wal_sink *sink) {
    return sink != NULL && sink->dispatch != NULL;
}

static int dispatch_apply_request(
    const struct asteriskd_typed_wal_sink *sink,
    enum asteriskd_typed_wal_source source,
    const struct asteriskd_recovery_record *record,
    char *error,
    size_t error_size) {
    if (!typed_wal_sink_valid(sink) || record == NULL || record->record_id != 0U ||
        record->status != ASTERISKD_RECOVERY_INTENT) {
        set_error(error, error_size, "invalid typed WAL apply request");
        return ASTERISKD_STATE_INVALID;
    }
    struct asteriskd_recovery_record validation = *record;
    validation.record_id = 1U;
    if (!record_resource_valid(&validation)) {
        set_error(error, error_size, "invalid typed WAL resource");
        return ASTERISKD_STATE_INVALID;
    }
    bool source_matches =
        ((source == ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE ||
          source == ASTERISKD_TYPED_WAL_IPV6_INTEGRITY) &&
         record->kind == ASTERISKD_RECOVERY_SYSCTL &&
         record->resource.sysctl.sysctl_id == ASTERISKD_SYSCTL_DISABLE_IPV6) ||
        (source == ASTERISKD_TYPED_WAL_TC_INTERFACE &&
         ((record->kind == ASTERISKD_RECOVERY_SYSCTL &&
           record->resource.sysctl.sysctl_id == ASTERISKD_SYSCTL_ROUTE_LOCALNET) ||
          record->kind == ASTERISKD_RECOVERY_TC_QDISC ||
          record->kind == ASTERISKD_RECOVERY_TC_FILTER));
    if (!source_matches) {
        set_error(error, error_size, "typed WAL source/resource mismatch");
        return ASTERISKD_STATE_INVALID;
    }
    struct asteriskd_typed_wal_request request;
    memset(&request, 0, sizeof(request));
    request.source = source;
    request.action = ASTERISKD_TYPED_WAL_APPLY;
    request.record = *record;
    return sink->dispatch(sink->context, &request, error, error_size);
}

int asteriskd_network_wal_ipv6_immediate(
    const struct asteriskd_typed_wal_sink *sink,
    const struct asteriskd_recovery_record *record,
    char *error,
    size_t error_size) {
    return dispatch_apply_request(
        sink, ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE, record, error, error_size);
}

int asteriskd_network_wal_ipv6_integrity(
    const struct asteriskd_typed_wal_sink *sink,
    const struct asteriskd_recovery_record *record,
    char *error,
    size_t error_size) {
    return dispatch_apply_request(
        sink, ASTERISKD_TYPED_WAL_IPV6_INTEGRITY, record, error, error_size);
}

int asteriskd_network_wal_tc_interface(
    const struct asteriskd_typed_wal_sink *sink,
    const struct asteriskd_recovery_record *record,
    char *error,
    size_t error_size) {
    return dispatch_apply_request(
        sink, ASTERISKD_TYPED_WAL_TC_INTERFACE, record, error, error_size);
}

int asteriskd_network_wal_rename(
    const struct asteriskd_typed_wal_sink *sink,
    uint64_t record_id,
    const char *previous_name,
    uint32_t previous_index,
    const char *verified_name,
    uint32_t verified_index,
    char *error,
    size_t error_size) {
    if (!typed_wal_sink_valid(sink) || record_id == 0U ||
        !interface_name_valid(previous_name, false) || previous_index == 0U ||
        !interface_name_valid(verified_name, false) || verified_index == 0U) {
        set_error(error, error_size, "invalid verified interface rename");
        return ASTERISKD_STATE_INVALID;
    }
    struct asteriskd_typed_wal_request request;
    memset(&request, 0, sizeof(request));
    request.source = ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE;
    request.action = ASTERISKD_TYPED_WAL_REBIND_INTERFACE;
    request.record_id = record_id;
    request.previous_interface_index = previous_index;
    request.verified_interface_index = verified_index;
    (void)snprintf(request.previous_interface_name,
        sizeof(request.previous_interface_name), "%s", previous_name);
    (void)snprintf(request.interface_name, sizeof(request.interface_name), "%s", verified_name);
    return sink->dispatch(sink->context, &request, error, error_size);
}

int asteriskd_network_wal_dellink(
    const struct asteriskd_typed_wal_sink *sink,
    uint64_t record_id,
    const char *interface_name,
    uint32_t verified_index,
    bool old_generation_absent_verified,
    char *error,
    size_t error_size) {
    if (!typed_wal_sink_valid(sink) || record_id == 0U ||
        !interface_name_valid(interface_name, false) || verified_index == 0U) {
        set_error(error, error_size, "invalid DELLINK WAL retirement");
        return ASTERISKD_STATE_INVALID;
    }
    if (!old_generation_absent_verified) {
        set_error(error, error_size, "old interface generation not verified absent");
        return ASTERISKD_WAL_INCOMPLETE;
    }
    struct asteriskd_typed_wal_request request;
    memset(&request, 0, sizeof(request));
    request.source = ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE;
    request.action = ASTERISKD_TYPED_WAL_RETIRE_INTERFACE;
    request.record_id = record_id;
    request.verified_interface_index = verified_index;
    request.old_generation_absent_verified = true;
    (void)snprintf(request.interface_name, sizeof(request.interface_name), "%s", interface_name);
    return sink->dispatch(sink->context, &request, error, error_size);
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_ntop InetNtopA
#else
#include <arpa/inet.h>

static int network_reopen(
    struct asteriskd_network_runtime *runtime, uint64_t now_milliseconds,
    char *error, size_t error_size);
#endif

#define ASTERISKD_NLMSG_ERROR 2U
#define ASTERISKD_NLMSG_DONE 3U
#define ASTERISKD_NLMSG_OVERRUN 4U
#define ASTERISKD_NLM_F_DUMP_INTR 0x10U
#define ASTERISKD_RTM_NEWLINK 16U
#define ASTERISKD_RTM_DELLINK 17U
#define ASTERISKD_RTM_NEWADDR 20U
#define ASTERISKD_RTM_DELADDR 21U
#define ASTERISKD_RTM_NEWRULE 32U
#define ASTERISKD_RTM_DELRULE 33U
#define ASTERISKD_IFLA_IFNAME 3U
#define ASTERISKD_IFA_ADDRESS 1U
#define ASTERISKD_IFA_LOCAL 2U
#define ASTERISKD_NLA_TYPE_MASK 0x3fffU
#define ASTERISKD_AF_INET6 10U
#define ASTERISKD_FIB_RULE_HEADER_SIZE 12U
#define ASTERISKD_FR_ACT_TO_TBL 1U
#define ASTERISKD_FRA_DST 1U
#define ASTERISKD_FRA_SRC 2U
#define ASTERISKD_FRA_IIFNAME 3U
#define ASTERISKD_FRA_PRIORITY 6U
#define ASTERISKD_FRA_FWMARK 10U
#define ASTERISKD_FRA_TABLE 15U
#define ASTERISKD_FRA_FWMASK 16U
#define ASTERISKD_FRA_OIFNAME 17U
#define ASTERISKD_FRA_UID_RANGE 20U
/* netd RouteController table numbering and Fwmark layout. */
#define ASTERISKD_NETD_TABLE_OFFSET 1000U
#define ASTERISKD_NETD_LOCAL_TABLE_OFFSET 1000000000U
#define ASTERISKD_NETD_FWMARK_NET_ID UINT32_C(0x0000ffff)
#define ASTERISKD_NETD_FWMARK_EXPLICIT UINT32_C(0x00010000)
#define ASTERISKD_NETD_FWMARK_NETWORK_MASK UINT32_C(0x0001ffff)
#define ASTERISKD_NETD_FWMARK_PERMISSION UINT32_C(0x000c0000)

struct network_nlmsg_header {
    uint32_t length;
    uint16_t type;
    uint16_t flags;
    uint32_t sequence;
    uint32_t sender;
};

_Static_assert(sizeof(struct network_nlmsg_header) == 16U, "netlink header ABI");

static bool backend_valid(const struct asteriskd_network_backend *backend) {
    return backend != NULL && backend->open != NULL && backend->receive != NULL &&
        backend->interface_name != NULL && backend->close != NULL;
}

static uint32_t required_groups(const struct asteriskd_config *config) {
    if (asteriskd_mode_core_managed(config->mode)) {
        uint32_t groups = config->disable_system_ipv6 ?
            ASTERISKD_NETWORK_GROUP_IPV6_ADDRESS | ASTERISKD_NETWORK_GROUP_LINK |
                ASTERISKD_NETWORK_GROUP_IPV6_RULE : 0U;
        if (config->hotspot_interface_prefix_count != 0U) {
            groups |= ASTERISKD_NETWORK_GROUP_LINK;
            if (config->enable_ipv6) groups |= ASTERISKD_NETWORK_GROUP_IPV6_ADDRESS;
        }
        return groups;
    }
    uint32_t groups = ASTERISKD_NETWORK_GROUP_IPV4_ADDRESS;
    if (config->enable_ipv6 || config->disable_system_ipv6) {
        groups |= ASTERISKD_NETWORK_GROUP_IPV6_ADDRESS;
    }
    if (config->disable_system_ipv6 ||
        (config->hotspot_interface_prefix_count != 0U &&
         (config->enable_ipv6 || config->mode == ASTERISKD_MODE_BPF2SOCKS))) {
        groups |= ASTERISKD_NETWORK_GROUP_LINK;
    }
    if (config->disable_system_ipv6) groups |= ASTERISKD_NETWORK_GROUP_IPV6_RULE;
    return groups;
}

int asteriskd_network_open(
    const struct asteriskd_config *config,
    const struct asteriskd_network_backend *backend,
    struct asteriskd_network_runtime *runtime,
    char *error,
    size_t error_size) {
    if (runtime != NULL) memset(runtime, 0, sizeof(*runtime));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || !backend_valid(backend) || runtime == NULL) {
        asteriskd_error_copy(error, error_size, "invalid network runtime input");
        return ASTERISKD_CONFIG_INVALID;
    }
    runtime->fd = -1;
    runtime->config = config;
    runtime->backend = backend;
    runtime->groups = required_groups(config);
    runtime->pending_batch_storage = calloc(1U, sizeof(*runtime->pending_batch_storage));
    if (runtime->pending_batch_storage == NULL) {
        memset(runtime, 0, sizeof(*runtime));
        asteriskd_error_copy(error, error_size, "network runtime allocation failed");
        return ASTERISKD_CONFIG_NO_MEMORY;
    }
    if (runtime->groups == 0U) {
        runtime->no_op = true;
        return 0;
    }
    int fd = -1;
    if (backend->open(backend->context, runtime->groups,
            ASTERISKD_NETWORK_RECEIVE_BUFFER_SIZE,
            ASTERISKD_NETWORK_SOCKET_RAW | ASTERISKD_NETWORK_SOCKET_NONBLOCK |
                ASTERISKD_NETWORK_SOCKET_CLOEXEC,
            &fd) != 0 || fd < 0) {
        free(runtime->pending_batch_storage);
        memset(runtime, 0, sizeof(*runtime));
        asteriskd_error_copy(error, error_size, "network socket open failed");
        return ASTERISKD_CONFIG_IO;
    }
    runtime->fd = fd;
    runtime->fd_owned = true;
    return 0;
}

static bool event_valid(const struct asteriskd_network_event *event) {
    if (event == NULL || event->action > ASTERISKD_EVENT_UPDATED ||
        event->interface_name[0] == '\0' ||
        strnlen(event->interface_name, sizeof(event->interface_name)) >= sizeof(event->interface_name)) {
        return false;
    }
    if (!event->is_address) return event->family == 0 && event->address[0] == '\0';
    return (event->family == ASTERISKD_ADDRESS_IPV4 || event->family == ASTERISKD_ADDRESS_IPV6) &&
        event->address[0] != '\0' &&
        strnlen(event->address, sizeof(event->address)) < sizeof(event->address);
}

static bool same_event(
    const struct asteriskd_network_event *left,
    const struct asteriskd_network_event *right) {
    return left->is_address == right->is_address && left->action == right->action &&
        left->family == right->family &&
        strcmp(left->interface_name, right->interface_name) == 0 &&
        strcmp(left->address, right->address) == 0;
}

static int network_note(
    struct asteriskd_network_runtime *runtime,
    const struct asteriskd_network_event *event,
    bool integrity_loss,
    uint64_t now_milliseconds) {
    if (runtime == NULL || runtime->pending_batch_storage == NULL ||
        (event == NULL && !integrity_loss) || (event != NULL && !event_valid(event)) ||
        now_milliseconds > UINT64_MAX - ASTERISKD_SYNC_DEBOUNCE_MILLIS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    bool changed = false;
    struct asteriskd_event_batch *batch = runtime->pending_batch_storage;
    if (event != NULL) {
        bool duplicate = false;
        for (size_t index = 0U; index < batch->count; ++index) {
            if (same_event(&batch->events[index], event)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            changed = true;
            if (batch->count == ASTERISKD_MAX_NETWORK_EVENTS) {
                batch->truncated = true;
            } else {
                batch->events[batch->count++] = *event;
            }
        }
    }
    if (integrity_loss) {
        runtime->integrity_loss = true;
        batch->truncated = true;
        changed = true;
        // A lost removal could leave a stale entry that suppresses a later re-add.
        runtime->known_address_count = 0U;
        // Lost rule events are recovered by one dump after the socket drains.
        if (runtime->config != NULL && runtime->config->disable_system_ipv6) {
            runtime->ipv6_guard_resync = true;
        }
    }
    if (changed) {
        runtime->deadline_present = true;
        runtime->deadline_milliseconds = now_milliseconds + ASTERISKD_SYNC_DEBOUNCE_MILLIS;
    }
    return 0;
}

static size_t align4(size_t value) {
    return (value + 3U) & ~((size_t)3U);
}

static bool interface_name_valid(const char *name) {
    size_t length = name == NULL ? 0U : strnlen(name, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)name[index];
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
              (byte >= '0' && byte <= '9') || byte == '_' || byte == '.' || byte == '-')) return false;
    }
    return true;
}

static bool hotspot_interface(const struct asteriskd_config *config, const char *name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        if (asteriskd_interface_matches_selector(
                name, config->hotspot_interface_prefixes[index])) return true;
    }
    return false;
}

static bool tracked_interface(const struct asteriskd_config *config, const char *name) {
    if (asteriskd_mode_core_managed(config->mode) || strcmp(name, "all") == 0 ||
        strcmp(name, "default") == 0 || strcmp(name, "lo") == 0) return false;
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (asteriskd_interface_matches_selector(
                name, config->ignored_interfaces[index])) return false;
    }
    for (size_t index = 0U; index < config->virtual_interface_count; ++index) {
        if (strcmp(name, config->virtual_interfaces[index]) == 0) return false;
    }
    return true;
}

static struct asteriskd_network_effect_request *pending_ipv6_request(
    struct asteriskd_network_runtime *runtime, const char *interface_name,
    uint32_t interface_index) {
    for (size_t index = 0U; index < runtime->immediate_request_count; ++index) {
        struct asteriskd_sysctl_resource *sysctl =
            &runtime->immediate_requests[index].effect.resource.sysctl;
        if (sysctl->sysctl_id == ASTERISKD_SYSCTL_DISABLE_IPV6 &&
            sysctl->interface_index == interface_index &&
            strcmp(sysctl->interface_name, interface_name) == 0) {
            return &runtime->immediate_requests[index];
        }
    }
    return NULL;
}

/* Queues a disable or restore request; a later request for the same interface wins. */
static int queue_ipv6_request(
    struct asteriskd_network_runtime *runtime, const char *interface_name,
    uint32_t interface_index, bool restore) {
    struct asteriskd_network_effect_request *request =
        pending_ipv6_request(runtime, interface_name, interface_index);
    if (request == NULL) {
        if (runtime->immediate_request_count >= ASTERISKD_MAX_NETWORK_IMMEDIATE_REQUESTS) {
            return ASTERISKD_CONFIG_INVALID;
        }
        request = &runtime->immediate_requests[runtime->immediate_request_count++];
    }
    memset(request, 0, sizeof(*request));
    request->effect.kind = ASTERISKD_EFFECT_SYSCTL;
    request->effect.resource.sysctl.sysctl_id = ASTERISKD_SYSCTL_DISABLE_IPV6;
    (void)snprintf(request->effect.resource.sysctl.interface_name,
        sizeof(request->effect.resource.sysctl.interface_name), "%s", interface_name);
    request->effect.resource.sysctl.interface_index = interface_index;
    request->effect.resource.sysctl.desired_value = 1U;
    request->restore = restore;
    return 0;
}

static int enforce_ipv6_security(
    struct asteriskd_network_runtime *runtime, const char *interface_name,
    uint32_t interface_index) {
    if (!runtime->config->disable_system_ipv6) return 0;
    if (runtime->backend->ipv6_disabled == NULL) {
        return ASTERISKD_CONFIG_IO;
    }
    // A queued restore has not reached sysctl yet; replace it without reading.
    if (pending_ipv6_request(runtime, interface_name, interface_index) != NULL) {
        return queue_ipv6_request(runtime, interface_name, interface_index, false);
    }
    uint8_t current = 0U;
    bool exists = false;
    if (runtime->backend->ipv6_disabled(runtime->backend->context, interface_name,
        interface_index, &current, &exists) != 0) return ASTERISKD_CONFIG_IO;
    if (!exists || current == 1U) return 0;
    if (current != 0U) return ASTERISKD_CONFIG_IO;
    return queue_ipv6_request(runtime, interface_name, interface_index, false);
}

static const struct asteriskd_netd_network *guarded_network(
    const struct asteriskd_network_runtime *runtime, const char *interface_name,
    uint32_t interface_index) {
    for (size_t index = 0U; index < runtime->netd_network_count; ++index) {
        const struct asteriskd_netd_network *network = &runtime->netd_networks[index];
        if (network->ipv6_guarded &&
            network->table - ASTERISKD_NETD_TABLE_OFFSET == interface_index &&
            strcmp(network->interface_name, interface_name) == 0) {
            return network;
        }
    }
    return NULL;
}

static int attribute_payload(
    const unsigned char *attributes,
    size_t attributes_length,
    uint16_t wanted_type,
    const unsigned char **payload,
    size_t *payload_length,
    bool prefer_last) {
    size_t offset = 0U;
    while (offset < attributes_length) {
        if (attributes_length - offset < 4U) return -1;
        uint16_t length;
        uint16_t type;
        memcpy(&length, attributes + offset, sizeof(length));
        memcpy(&type, attributes + offset + 2U, sizeof(type));
        if (length < 4U || length > attributes_length - offset ||
            align4(length) > attributes_length - offset) return -1;
        if (type == wanted_type && (*payload == NULL || prefer_last)) {
            *payload = attributes + offset + 4U;
            *payload_length = length - 4U;
        }
        offset += align4(length);
    }
    return offset == attributes_length ? 0 : -1;
}

/*
 * Tracks addresses already reported for reconciliation. RTM_NEWADDR also
 * reports lifetime and flag updates for an existing address (for example on
 * every IPv6 router advertisement); those do not change the address set that
 * reconciliation consumes. Returns true when the message must be reported.
 */
static bool known_address_update(
    struct asteriskd_network_runtime *runtime, uint32_t interface_index, int family,
    const unsigned char *address, size_t address_length, bool removed) {
    size_t index = 0U;
    for (; index < runtime->known_address_count; ++index) {
        const struct asteriskd_network_known_address *known = &runtime->known_addresses[index];
        if (known->interface_index == interface_index && known->family == family &&
            memcmp(known->address, address, address_length) == 0) break;
    }
    bool present = index < runtime->known_address_count;
    if (removed) {
        if (present) {
            runtime->known_addresses[index] =
                runtime->known_addresses[--runtime->known_address_count];
        }
        return true;
    }
    if (present) return false;
    // A full set only loses deduplication; every new address is still reported.
    if (runtime->known_address_count < ASTERISKD_MAX_NETWORK_KNOWN_ADDRESSES) {
        struct asteriskd_network_known_address *known =
            &runtime->known_addresses[runtime->known_address_count++];
        memset(known, 0, sizeof(*known));
        known->interface_index = interface_index;
        known->family = family;
        memcpy(known->address, address, address_length);
    }
    return true;
}

static int record_address_message(
    struct asteriskd_network_runtime *runtime,
    const unsigned char *message,
    size_t message_length,
    uint16_t message_type,
    uint64_t now_milliseconds) {
    if (message_length < sizeof(struct network_nlmsg_header) + 8U) return -1;
    const unsigned char *info = message + sizeof(struct network_nlmsg_header);
    int family = info[0] == 2U ? ASTERISKD_ADDRESS_IPV4 :
        info[0] == 10U ? ASTERISKD_ADDRESS_IPV6 : 0;
    if (family == 0) return 0;
    uint32_t interface_index;
    memcpy(&interface_index, info + 4U, sizeof(interface_index));
    if (interface_index == 0U) return -1;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    memset(interface_name, 0, sizeof(interface_name));
    if (runtime->backend->interface_name(runtime->backend->context, interface_index,
            interface_name, sizeof(interface_name)) != 0 || !interface_name_valid(interface_name)) return -1;
    const unsigned char *attributes = info + 8U;
    size_t attributes_length = message_length - sizeof(struct network_nlmsg_header) - 8U;
    const unsigned char *address = NULL;
    size_t address_length = 0U;
    if (attribute_payload(attributes, attributes_length, ASTERISKD_IFA_ADDRESS,
            &address, &address_length, false) != 0) return -1;
    const unsigned char *local = NULL;
    size_t local_length = 0U;
    if (attribute_payload(attributes, attributes_length, ASTERISKD_IFA_LOCAL,
            &local, &local_length, false) != 0) return -1;
    if (local != NULL) {
        address = local;
        address_length = local_length;
    }
    size_t expected_length = family == ASTERISKD_ADDRESS_IPV4 ? 4U : 16U;
    if (address == NULL || address_length != expected_length) return -1;
    // An IPv6 address on a guarded data network means IPv6 was re-enabled.
    if (message_type == ASTERISKD_RTM_NEWADDR && family == ASTERISKD_ADDRESS_IPV6 &&
        runtime->config->disable_system_ipv6 &&
        guarded_network(runtime, interface_name, interface_index) != NULL) {
        int security = enforce_ipv6_security(runtime, interface_name, interface_index);
        if (security != 0) return ASTERISKD_CONFIG_IO;
    }
    bool relevant = tracked_interface(runtime->config, interface_name) ||
        hotspot_interface(runtime->config, interface_name);
    if (!relevant) return 0;
    if (!known_address_update(runtime, interface_index, family, address, address_length,
            message_type == ASTERISKD_RTM_DELADDR)) return 0;
    struct asteriskd_network_event event;
    memset(&event, 0, sizeof(event));
    event.is_address = true;
    event.action = message_type == ASTERISKD_RTM_DELADDR ?
        ASTERISKD_EVENT_REMOVED : ASTERISKD_EVENT_ADDED;
    event.family = family;
    memcpy(event.interface_name, interface_name, strlen(interface_name) + 1U);
    int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    if (inet_ntop(native_family, address, event.address, sizeof(event.address)) == NULL) return -1;
    return network_note(runtime, &event, false, now_milliseconds);
}

static int record_link_message(
    struct asteriskd_network_runtime *runtime,
    const unsigned char *message,
    size_t message_length,
    uint16_t message_type,
    uint64_t now_milliseconds) {
    if (message_length < sizeof(struct network_nlmsg_header) + 16U) return -1;
    const unsigned char *info = message + sizeof(struct network_nlmsg_header);
    int32_t signed_index;
    memcpy(&signed_index, info + 4U, sizeof(signed_index));
    if (signed_index <= 0) return -1;
    const unsigned char *attributes = info + 16U;
    size_t attributes_length = message_length - sizeof(struct network_nlmsg_header) - 16U;
    const unsigned char *name_bytes = NULL;
    size_t name_length = 0U;
    if (attribute_payload(attributes, attributes_length, ASTERISKD_IFLA_IFNAME,
            &name_bytes, &name_length, false) != 0) return -1;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    memset(interface_name, 0, sizeof(interface_name));
    if (name_bytes != NULL) {
        size_t length = strnlen((const char *)name_bytes, name_length);
        if (length == 0U || length >= name_length || length >= sizeof(interface_name)) return -1;
        memcpy(interface_name, name_bytes, length);
    } else if (runtime->backend->interface_name(runtime->backend->context,
            (uint32_t)signed_index, interface_name, sizeof(interface_name)) != 0) {
        return -1;
    }
    if (!interface_name_valid(interface_name)) return -1;
    if (message_type == ASTERISKD_RTM_NEWLINK && runtime->config->disable_system_ipv6 &&
        guarded_network(runtime, interface_name, (uint32_t)signed_index) != NULL) {
        int security = enforce_ipv6_security(
            runtime, interface_name, (uint32_t)signed_index);
        if (security != 0) return ASTERISKD_CONFIG_IO;
    }
    if (!hotspot_interface(runtime->config, interface_name)) return 0;
    struct asteriskd_network_event event;
    memset(&event, 0, sizeof(event));
    event.action = message_type == ASTERISKD_RTM_DELLINK ?
        ASTERISKD_EVENT_REMOVED : ASTERISKD_EVENT_UPDATED;
    memcpy(event.interface_name, interface_name, strlen(interface_name) + 1U);
    return network_note(runtime, &event, false, now_milliseconds);
}

/*
 * netd keeps one routing table per network interface (ifindex + 1000) and
 * installs, per network, a global explicit-network rule whose fwmark carries
 * the netId, the explicit bit and the network permission, plus "oif <iface>"
 * rules for the same table. Networks that apps may use have permission NONE;
 * IMS, emergency and background networks require NETWORK or SYSTEM.
 */
enum netd_rule_kind {
    NETD_RULE_IGNORED,
    NETD_RULE_OUTPUT,
    NETD_RULE_UNRESTRICTED,
    NETD_RULE_RESTRICTED,
};

struct netd_rule {
    enum netd_rule_kind kind;
    uint32_t table;
    /* Priority identifies a rule but never determines whether its network is data. */
    uint32_t priority;
    uint32_t fwmark;
    uint32_t fwmask;
    uint32_t uid_start;
    uint32_t uid_end;
    uint32_t attributes_present;
    uint8_t destination_prefix;
    uint8_t source_prefix;
    uint8_t tos;
    unsigned char destination[16U];
    unsigned char source[16U];
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char input_interface_name[ASTERISKD_MAX_INTERFACE_NAME];
};

struct asteriskd_netd_rule {
    struct netd_rule rule;
    struct asteriskd_netd_rule *next;
};

static void netd_rules_clear(struct asteriskd_netd_rule **rules) {
    while (*rules != NULL) {
        struct asteriskd_netd_rule *next = (*rules)->next;
        free(*rules);
        *rules = next;
    }
}

/* Dumps and queued notifications can describe the same rule; membership is idempotent. */
static int netd_rules_update(
    struct asteriskd_netd_rule **rules, const struct netd_rule *rule,
    bool added, bool *changed) {
    *changed = false;
    struct asteriskd_netd_rule **entry = rules;
    while (*entry != NULL && memcmp(&(*entry)->rule, rule, sizeof(*rule)) != 0) {
        entry = &(*entry)->next;
    }
    if (*entry != NULL) {
        if (!added) {
            struct asteriskd_netd_rule *removed = *entry;
            *entry = removed->next;
            free(removed);
            *changed = true;
        }
    } else if (added) {
        *entry = calloc(1U, sizeof(**entry));
        if (*entry == NULL) return -1;
        memcpy(&(*entry)->rule, rule, sizeof(*rule));
        *changed = true;
    }
    return 0;
}

static int parse_netd_rule(
    const unsigned char *message, size_t message_length, struct netd_rule *rule) {
    memset(rule, 0, sizeof(*rule));
    if (message_length < sizeof(struct network_nlmsg_header) + ASTERISKD_FIB_RULE_HEADER_SIZE) {
        return -1;
    }
    const unsigned char *info = message + sizeof(struct network_nlmsg_header);
    // fib_rule_hdr: family, dst_len, src_len, tos, table, res1, res2, action, flags.
    if (info[0] != ASTERISKD_AF_INET6 || info[7] != ASTERISKD_FR_ACT_TO_TBL) return 0;
    rule->destination_prefix = info[1];
    rule->source_prefix = info[2];
    rule->tos = info[3];
    uint32_t table = info[4];
    const unsigned char *fwmark = NULL;
    const unsigned char *fwmask = NULL;
    const unsigned char *oif = NULL;
    size_t oif_length = 0U;
    bool uid_range = false;
    const unsigned char *attributes = info + ASTERISKD_FIB_RULE_HEADER_SIZE;
    size_t attributes_length =
        message_length - sizeof(struct network_nlmsg_header) - ASTERISKD_FIB_RULE_HEADER_SIZE;
    size_t offset = 0U;
    while (offset < attributes_length) {
        if (attributes_length - offset < 4U) return -1;
        uint16_t length;
        uint16_t type;
        memcpy(&length, attributes + offset, sizeof(length));
        memcpy(&type, attributes + offset + 2U, sizeof(type));
        if (length < 4U || align4(length) > attributes_length - offset) return -1;
        const unsigned char *payload = attributes + offset + 4U;
        size_t payload_length = length - 4U;
        switch (type & ASTERISKD_NLA_TYPE_MASK) {
            case ASTERISKD_FRA_DST:
            case ASTERISKD_FRA_SRC:
                if (payload_length != 16U) return -1;
                memcpy((type & ASTERISKD_NLA_TYPE_MASK) == ASTERISKD_FRA_DST
                        ? rule->destination : rule->source,
                    payload, payload_length);
                rule->attributes_present |= UINT32_C(1) << (type & ASTERISKD_NLA_TYPE_MASK);
                break;
            case ASTERISKD_FRA_IIFNAME: {
                size_t name_length = strnlen((const char *)payload, payload_length);
                if (name_length == 0U || name_length >= payload_length ||
                    name_length >= sizeof(rule->input_interface_name)) return -1;
                memcpy(rule->input_interface_name, payload, name_length);
                rule->attributes_present |= UINT32_C(1) << ASTERISKD_FRA_IIFNAME;
                break;
            }
            case ASTERISKD_FRA_PRIORITY:
                if (payload_length != 4U) return -1;
                memcpy(&rule->priority, payload, sizeof(rule->priority));
                rule->attributes_present |= UINT32_C(1) << ASTERISKD_FRA_PRIORITY;
                break;
            case ASTERISKD_FRA_TABLE:
                if (payload_length != 4U) return -1;
                memcpy(&table, payload, sizeof(table));
                break;
            case ASTERISKD_FRA_FWMARK:
                if (payload_length != 4U) return -1;
                fwmark = payload;
                memcpy(&rule->fwmark, payload, sizeof(rule->fwmark));
                rule->attributes_present |= UINT32_C(1) << ASTERISKD_FRA_FWMARK;
                break;
            case ASTERISKD_FRA_FWMASK:
                if (payload_length != 4U) return -1;
                fwmask = payload;
                memcpy(&rule->fwmask, payload, sizeof(rule->fwmask));
                rule->attributes_present |= UINT32_C(1) << ASTERISKD_FRA_FWMASK;
                break;
            case ASTERISKD_FRA_OIFNAME:
                oif = payload;
                oif_length = payload_length;
                break;
            case ASTERISKD_FRA_UID_RANGE:
                if (payload_length != 8U) return -1;
                uid_range = true;
                memcpy(&rule->uid_start, payload, sizeof(rule->uid_start));
                memcpy(&rule->uid_end, payload + 4U, sizeof(rule->uid_end));
                rule->attributes_present |= UINT32_C(1) << ASTERISKD_FRA_UID_RANGE;
                break;
            default:
                break;
        }
        offset += align4(length);
    }
    if (table <= ASTERISKD_NETD_TABLE_OFFSET || table >= ASTERISKD_NETD_LOCAL_TABLE_OFFSET) {
        return 0;
    }
    rule->table = table;
    // Restricted networks qualify their oif rule with a permission fwmark; it still names the table.
    if (oif != NULL) {
        size_t length = strnlen((const char *)oif, oif_length);
        if (length == 0U || length >= oif_length || length >= sizeof(rule->interface_name)) {
            return -1;
        }
        memcpy(rule->interface_name, oif, length);
        if (!interface_name_valid(rule->interface_name)) return -1;
        rule->kind = NETD_RULE_OUTPUT;
        return 0;
    }
    if (fwmark == NULL || fwmask == NULL || uid_range) return 0;
    uint32_t mark;
    uint32_t mask;
    memcpy(&mark, fwmark, sizeof(mark));
    memcpy(&mask, fwmask, sizeof(mask));
    if ((mask & ASTERISKD_NETD_FWMARK_NETWORK_MASK) != ASTERISKD_NETD_FWMARK_NETWORK_MASK ||
        (mark & ASTERISKD_NETD_FWMARK_EXPLICIT) == 0U ||
        (mark & ASTERISKD_NETD_FWMARK_NET_ID) == 0U) return 0;
    rule->kind = (mark & mask & ASTERISKD_NETD_FWMARK_PERMISSION) == 0U
        ? NETD_RULE_UNRESTRICTED : NETD_RULE_RESTRICTED;
    return 0;
}

static struct asteriskd_netd_network *netd_network_find(
    struct asteriskd_netd_network *networks, size_t count, uint32_t table) {
    for (size_t index = 0U; index < count; ++index) {
        if (networks[index].table == table) return &networks[index];
    }
    return NULL;
}

static void netd_counter_update(uint16_t *counter, bool added) {
    if (added) {
        if (*counter != UINT16_MAX) ++*counter;
    } else if (*counter != 0U) {
        --*counter;
    }
}

/* Applies one rule change to a network set; returns the affected entry or NULL. */
static struct asteriskd_netd_network *netd_network_update(
    struct asteriskd_netd_network *networks, size_t *count, bool *overflow,
    const struct netd_rule *rule, bool added) {
    struct asteriskd_netd_network *network = netd_network_find(networks, *count, rule->table);
    if (network == NULL) {
        if (!added) return NULL;
        if (*count >= ASTERISKD_MAX_INTERFACES) {
            *overflow = true;
            return NULL;
        }
        network = &networks[(*count)++];
        memset(network, 0, sizeof(*network));
        network->table = rule->table;
    }
    if (rule->kind == NETD_RULE_OUTPUT) {
        netd_counter_update(&network->output_rules, added);
        // Keep the last name after removal so a guarded interface can still be restored.
        if (added) memcpy(network->interface_name, rule->interface_name,
            sizeof(network->interface_name));
    } else if (rule->kind == NETD_RULE_UNRESTRICTED) {
        netd_counter_update(&network->unrestricted_rules, added);
    } else {
        netd_counter_update(&network->restricted_rules, added);
    }
    return network;
}

static void netd_network_remove_unused(struct asteriskd_network_runtime *runtime) {
    size_t kept = 0U;
    for (size_t index = 0U; index < runtime->netd_network_count; ++index) {
        const struct asteriskd_netd_network *network = &runtime->netd_networks[index];
        if (network->ipv6_guarded || network->output_rules != 0U ||
            network->unrestricted_rules != 0U || network->restricted_rules != 0U) {
            if (kept != index) runtime->netd_networks[kept] = *network;
            ++kept;
        }
    }
    if (kept != runtime->netd_network_count) {
        memset(&runtime->netd_networks[kept], 0,
            (runtime->netd_network_count - kept) * sizeof(runtime->netd_networks[0]));
        runtime->netd_network_count = kept;
    }
}

static uint32_t netd_network_index(const struct asteriskd_netd_network *network) {
    return network->table - ASTERISKD_NETD_TABLE_OFFSET;
}

/* A data network is unrestricted, has its output rule, and its table matches the ifindex. */
static bool netd_network_is_data(
    struct asteriskd_network_runtime *runtime, const struct asteriskd_netd_network *network) {
    if (network->unrestricted_rules == 0U || network->output_rules == 0U ||
        network->interface_name[0] == '\0' || strcmp(network->interface_name, "lo") == 0 ||
        asteriskd_interface_matches_selector(network->interface_name, "ipsec+")) return false;
    // The ifindex cross-check needs a system call; skip it while the state is unchanged.
    if (network->ipv6_guarded) return true;
    char observed[ASTERISKD_MAX_INTERFACE_NAME];
    memset(observed, 0, sizeof(observed));
    return runtime->backend->interface_name(runtime->backend->context,
               netd_network_index(network), observed, sizeof(observed)) == 0 &&
        strcmp(observed, network->interface_name) == 0;
}

static int netd_network_apply(
    struct asteriskd_network_runtime *runtime, struct asteriskd_netd_network *network) {
    bool data = netd_network_is_data(runtime, network);
    if (data == network->ipv6_guarded) return 0;
    network->ipv6_guarded = data;
    if (data) {
        return enforce_ipv6_security(
            runtime, network->interface_name, netd_network_index(network));
    }
    return queue_ipv6_request(
        runtime, network->interface_name, netd_network_index(network), true);
}

static int record_rule_message(
    struct asteriskd_network_runtime *runtime,
    const unsigned char *message,
    size_t message_length,
    uint16_t message_type) {
    if (!runtime->config->disable_system_ipv6) return 0;
    struct netd_rule rule;
    if (parse_netd_rule(message, message_length, &rule) != 0) return -1;
    if (rule.kind == NETD_RULE_IGNORED) return 0;
    bool changed = false;
    if (netd_rules_update(&runtime->netd_rules, &rule,
            message_type == ASTERISKD_RTM_NEWRULE, &changed) != 0) return ASTERISKD_CONFIG_IO;
    if (!changed) return 0;
    struct asteriskd_netd_network *network = netd_network_update(
        runtime->netd_networks, &runtime->netd_network_count,
        &runtime->netd_network_overflow, &rule, message_type == ASTERISKD_RTM_NEWRULE);
    if (network == NULL) return 0;
    int result = netd_network_apply(runtime, network);
    if (result != 0) return ASTERISKD_CONFIG_IO;
    netd_network_remove_unused(runtime);
    return 0;
}

int asteriskd_network_sync_ipv6_guard(
    struct asteriskd_network_runtime *runtime, char *error, size_t error_size) {
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (runtime == NULL || runtime->config == NULL || runtime->backend == NULL) {
        asteriskd_error_copy(error, error_size, "invalid IPv6 guard sync input");
        return ASTERISKD_CONFIG_INVALID;
    }
    runtime->ipv6_guard_resync = false;
    if (!runtime->config->disable_system_ipv6 || runtime->no_op) return 0;
    if (runtime->backend->dump_ipv6_rules == NULL) {
        asteriskd_error_copy(error, error_size, "IPv6 rule dump unavailable");
        return ASTERISKD_CONFIG_IO;
    }
    struct asteriskd_netd_network fresh[ASTERISKD_MAX_INTERFACES];
    struct asteriskd_netd_rule *fresh_rules = NULL;
    size_t fresh_count = 0U;
    bool overflow = false;
    int fd = -1;
    if (runtime->backend->dump_ipv6_rules(runtime->backend->context, &fd) != 0 || fd < 0) {
        asteriskd_error_copy(error, error_size, "IPv6 rule dump request failed");
        return ASTERISKD_CONFIG_IO;
    }
    int result = ASTERISKD_CONFIG_IO;
    bool done = false;
    unsigned char buffer[32768U];
    while (!done) {
        size_t length = 0U;
        uint32_t sender_pid = 0U;
        bool truncated = false;
        enum asteriskd_network_receive_result received = runtime->backend->receive(
            runtime->backend->context, fd, buffer, sizeof(buffer),
            &length, &sender_pid, &truncated);
        if (received == ASTERISKD_NETWORK_RECEIVE_INTERRUPTED) continue;
        if (received != ASTERISKD_NETWORK_RECEIVE_DATA || truncated || sender_pid != 0U ||
            length == 0U) break;
        size_t offset = 0U;
        bool malformed = false;
        while (offset < length && !done && !malformed) {
            struct network_nlmsg_header header;
            if (length - offset < sizeof(header)) {
                malformed = true;
                break;
            }
            memcpy(&header, buffer + offset, sizeof(header));
            if (header.length < sizeof(header) || align4(header.length) > length - offset ||
                (header.flags & ASTERISKD_NLM_F_DUMP_INTR) != 0U) {
                malformed = true;
                break;
            }
            if (header.type == ASTERISKD_NLMSG_DONE) {
                done = true;
            } else if (header.type == ASTERISKD_NLMSG_ERROR) {
                malformed = true;
            } else if (header.type == ASTERISKD_RTM_NEWRULE) {
                struct netd_rule rule;
                if (parse_netd_rule(buffer + offset, header.length, &rule) != 0) {
                    malformed = true;
                } else if (rule.kind != NETD_RULE_IGNORED) {
                    bool changed = false;
                    if (netd_rules_update(&fresh_rules, &rule, true, &changed) != 0) {
                        malformed = true;
                    } else if (changed) {
                        (void)netd_network_update(fresh, &fresh_count, &overflow, &rule, true);
                    }
                }
            }
            offset += align4(header.length);
        }
        if (malformed) break;
        if (done) result = 0;
    }
    (void)runtime->backend->close(runtime->backend->context, fd);
    if (result != 0) {
        netd_rules_clear(&fresh_rules);
        asteriskd_error_copy(error, error_size, "IPv6 rule dump failed");
        return result;
    }
    // Carry guard state into the fresh set; restore networks that disappeared.
    for (size_t index = 0U; index < runtime->netd_network_count; ++index) {
        const struct asteriskd_netd_network *old = &runtime->netd_networks[index];
        if (!old->ipv6_guarded) continue;
        struct asteriskd_netd_network *current = netd_network_find(fresh, fresh_count, old->table);
        if (current != NULL && strcmp(current->interface_name, old->interface_name) == 0) {
            current->ipv6_guarded = true;
        } else if (queue_ipv6_request(
                runtime, old->interface_name, netd_network_index(old), true) != 0) {
            asteriskd_error_copy(error, error_size, "IPv6 guard request capacity exceeded");
            netd_rules_clear(&fresh_rules);
            return ASTERISKD_CONFIG_IO;
        }
    }
    netd_rules_clear(&runtime->netd_rules);
    runtime->netd_rules = fresh_rules;
    memcpy(runtime->netd_networks, fresh, fresh_count * sizeof(fresh[0]));
    if (fresh_count < runtime->netd_network_count) {
        memset(&runtime->netd_networks[fresh_count], 0,
            (runtime->netd_network_count - fresh_count) * sizeof(fresh[0]));
    }
    runtime->netd_network_count = fresh_count;
    runtime->netd_network_overflow = overflow;
    for (size_t index = 0U; index < runtime->netd_network_count; ++index) {
        struct asteriskd_netd_network *network = &runtime->netd_networks[index];
        // Events may have been lost: re-check guarded networks as well as changes.
        int applied = network->ipv6_guarded && netd_network_is_data(runtime, network)
            ? enforce_ipv6_security(runtime, network->interface_name, netd_network_index(network))
            : netd_network_apply(runtime, network);
        if (applied != 0) {
            asteriskd_error_copy(error, error_size, "IPv6 guard request failed");
            return ASTERISKD_CONFIG_IO;
        }
    }
    netd_network_remove_unused(runtime);
    return 0;
}

void asteriskd_network_describe_ipv6_guard(
    const struct asteriskd_network_runtime *runtime, char *out, size_t size) {
    if (out == NULL || size == 0U) return;
    out[0] = '\0';
    if (runtime == NULL) return;
    size_t used = 0U;
    for (size_t index = 0U; index < runtime->netd_network_count && used + 1U < size; ++index) {
        const struct asteriskd_netd_network *network = &runtime->netd_networks[index];
        const char *state = network->ipv6_guarded ? "data" :
            network->restricted_rules != 0U && network->unrestricted_rules == 0U ? "restricted" :
            "incomplete";
        int written = network->interface_name[0] != '\0'
            ? snprintf(out + used, size - used, "%s%s:%s", used == 0U ? "" : ",",
                network->interface_name, state)
            : snprintf(out + used, size - used, "%stable%" PRIu32 ":%s", used == 0U ? "" : ",",
                network->table, state);
        if (written < 0) break;
        used += (size_t)written < size - used ? (size_t)written : size - used - 1U;
    }
    if (runtime->netd_network_overflow && used + 1U < size) {
        (void)snprintf(out + used, size - used, "%soverflow", used == 0U ? "" : ",");
    }
}

static int parse_datagram(
    struct asteriskd_network_runtime *runtime,
    const unsigned char *bytes,
    size_t length,
    uint32_t sender_pid,
    bool truncated,
    uint64_t now_milliseconds) {
    if (truncated || sender_pid != 0U) {
        return network_note(runtime, NULL, true, now_milliseconds);
    }
    size_t offset = 0U;
    while (offset < length) {
        if (length - offset < sizeof(struct network_nlmsg_header)) {
            return network_note(runtime, NULL, true, now_milliseconds);
        }
        struct network_nlmsg_header header;
        memcpy(&header, bytes + offset, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - offset ||
            align4(header.length) > length - offset) {
            return network_note(runtime, NULL, true, now_milliseconds);
        }
        int result = 0;
        if (header.type == ASTERISKD_NLMSG_ERROR || header.type == ASTERISKD_NLMSG_OVERRUN) {
            result = network_note(runtime, NULL, true, now_milliseconds);
        } else if (header.type == ASTERISKD_RTM_NEWADDR || header.type == ASTERISKD_RTM_DELADDR) {
            result = record_address_message(
                runtime, bytes + offset, header.length, header.type, now_milliseconds);
        } else if (header.type == ASTERISKD_RTM_NEWLINK || header.type == ASTERISKD_RTM_DELLINK) {
            result = record_link_message(
                runtime, bytes + offset, header.length, header.type, now_milliseconds);
        } else if (header.type == ASTERISKD_RTM_NEWRULE || header.type == ASTERISKD_RTM_DELRULE) {
            result = record_rule_message(runtime, bytes + offset, header.length, header.type);
        }
        if (result == ASTERISKD_CONFIG_IO) return result;
        if (result != 0) return network_note(runtime, NULL, true, now_milliseconds);
        offset += align4(header.length);
    }
    return 0;
}

int asteriskd_network_handle(
    struct asteriskd_network_runtime *runtime,
    uint64_t now_milliseconds,
    char *error,
    size_t error_size) {
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (runtime == NULL || runtime->backend == NULL || runtime->pending_batch_storage == NULL) {
        asteriskd_error_copy(error, error_size, "invalid network handle input");
        return ASTERISKD_CONFIG_INVALID;
    }
    if (runtime->no_op) return 0;
    unsigned char buffer[65536U];
    while (true) {
        size_t length = 0U;
        uint32_t sender_pid = 0U;
        bool truncated = false;
        enum asteriskd_network_receive_result received = runtime->backend->receive(
            runtime->backend->context, runtime->fd, buffer, sizeof(buffer),
            &length, &sender_pid, &truncated);
        if (received == ASTERISKD_NETWORK_RECEIVE_AGAIN) {
            return runtime->ipv6_guard_resync
                ? asteriskd_network_sync_ipv6_guard(runtime, error, error_size) : 0;
        }
        if (received == ASTERISKD_NETWORK_RECEIVE_INTERRUPTED) continue;
        if (received == ASTERISKD_NETWORK_RECEIVE_ENOBUFS) {
            if (network_note(runtime, NULL, true, now_milliseconds) != 0) break;
            continue;
        }
        if (received == ASTERISKD_NETWORK_RECEIVE_DATA && length != 0U &&
            parse_datagram(runtime, buffer, length, sender_pid, truncated, now_milliseconds) == 0) {
            continue;
        }
        if (received == ASTERISKD_NETWORK_RECEIVE_FATAL &&
            network_reopen(runtime, now_milliseconds, error, error_size) == 0) {
            continue;
        }
        asteriskd_error_copy(error, error_size, "network receive failed");
        return ASTERISKD_CONFIG_IO;
    }
    asteriskd_error_copy(error, error_size, "network event deadline overflow");
    return ASTERISKD_CONFIG_INVALID;
}

static int network_reopen(
    struct asteriskd_network_runtime *runtime, uint64_t now_milliseconds,
    char *error, size_t error_size) {
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (runtime == NULL || runtime->backend == NULL || runtime->no_op ||
        !runtime->fd_owned || runtime->backend->open == NULL || runtime->backend->close == NULL) {
        asteriskd_error_copy(error, error_size, "invalid network reopen input");
        return ASTERISKD_CONFIG_INVALID;
    }
    int old_fd = runtime->fd;
    runtime->fd = -1;
    runtime->fd_owned = false;
    if (runtime->backend->close(runtime->backend->context, old_fd) != 0) {
        asteriskd_error_copy(error, error_size, "network close before reopen failed");
        return ASTERISKD_CONFIG_IO;
    }
    int new_fd = -1;
    if (runtime->backend->open(runtime->backend->context, runtime->groups,
        ASTERISKD_NETWORK_RECEIVE_BUFFER_SIZE,
        ASTERISKD_NETWORK_SOCKET_RAW | ASTERISKD_NETWORK_SOCKET_NONBLOCK |
            ASTERISKD_NETWORK_SOCKET_CLOEXEC,
        &new_fd) != 0 || new_fd < 0) {
        asteriskd_error_copy(error, error_size, "network reopen failed");
        return ASTERISKD_CONFIG_IO;
    }
    runtime->fd = new_fd;
    runtime->fd_owned = true;
    if (network_note(runtime, NULL, true, now_milliseconds) != 0) {
        asteriskd_error_copy(error, error_size, "network reopen deadline overflow");
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

int asteriskd_network_set_effect_sink(
    struct asteriskd_network_runtime *runtime,
    const struct asteriskd_network_effect_sink *sink) {
    if (runtime == NULL || sink == NULL || sink->dispatch == NULL) return ASTERISKD_CONFIG_INVALID;
    runtime->effect_sink = sink;
    return 0;
}

bool asteriskd_network_has_immediate(const struct asteriskd_network_runtime *runtime) {
    return runtime != NULL && runtime->immediate_request_count != 0U;
}

int asteriskd_network_apply_immediate(
    struct asteriskd_network_runtime *runtime, char *error, size_t error_size) {
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (runtime == NULL ||
        (runtime->immediate_request_count != 0U &&
            (runtime->effect_sink == NULL ||
             runtime->effect_sink->dispatch == NULL))) {
        asteriskd_error_copy(error, error_size, "invalid immediate network apply input");
        return ASTERISKD_CONFIG_INVALID;
    }
    while (runtime->immediate_request_count != 0U) {
        if (runtime->effect_sink->dispatch(runtime->effect_sink->context,
                &runtime->immediate_requests[0], error, error_size) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
        --runtime->immediate_request_count;
        if (runtime->immediate_request_count != 0U) {
            memmove(&runtime->immediate_requests[0], &runtime->immediate_requests[1],
                runtime->immediate_request_count * sizeof(runtime->immediate_requests[0]));
        }
        memset(&runtime->immediate_requests[runtime->immediate_request_count], 0,
            sizeof(runtime->immediate_requests[0]));
    }
    return 0;
}

bool asteriskd_network_next_deadline(
    const struct asteriskd_network_runtime *runtime,
    uint64_t *deadline_milliseconds) {
    if (runtime == NULL || deadline_milliseconds == NULL || !runtime->deadline_present) return false;
    *deadline_milliseconds = runtime->deadline_milliseconds;
    return true;
}

int asteriskd_network_take_reconcile(
    struct asteriskd_network_runtime *runtime,
    uint64_t now_milliseconds,
    struct asteriskd_event_batch *batch,
    bool *integrity_loss) {
    if (batch != NULL) memset(batch, 0, sizeof(*batch));
    if (integrity_loss != NULL) *integrity_loss = false;
    if (runtime == NULL || runtime->pending_batch_storage == NULL || batch == NULL ||
        integrity_loss == NULL) return ASTERISKD_CONFIG_INVALID;
    if (!runtime->deadline_present || now_milliseconds < runtime->deadline_milliseconds) {
        return ASTERISKD_CONFIG_NOT_READY;
    }
    *batch = *runtime->pending_batch_storage;
    *integrity_loss = runtime->integrity_loss;
    memset(runtime->pending_batch_storage, 0, sizeof(*runtime->pending_batch_storage));
    runtime->integrity_loss = false;
    runtime->deadline_present = false;
    runtime->deadline_milliseconds = 0U;
    return 0;
}

int asteriskd_network_close(struct asteriskd_network_runtime *runtime) {
    if (runtime == NULL) return ASTERISKD_CONFIG_INVALID;
    int result = 0;
    if (runtime->fd_owned && runtime->backend != NULL &&
        runtime->backend->close(runtime->backend->context, runtime->fd) != 0) {
        result = ASTERISKD_CONFIG_IO;
    }
    free(runtime->pending_batch_storage);
    netd_rules_clear(&runtime->netd_rules);
    memset(runtime, 0, sizeof(*runtime));
    return result;
}

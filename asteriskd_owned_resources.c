// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

static const char *const owned_pin_paths[ASTERISKD_PIN_COUNT] = {
    [ASTERISKD_PIN_MATCHER_OUTPUT_V4] =
        "/sys/fs/bpf/asterisk/xt_output_v4",
    [ASTERISKD_PIN_MATCHER_OUTPUT_V6] =
        "/sys/fs/bpf/asterisk/xt_output_v6",
    [ASTERISKD_PIN_MATCHER_PREROUTING_V4] =
        "/sys/fs/bpf/asterisk/xt_prerouting_v4",
    [ASTERISKD_PIN_MATCHER_PREROUTING_V6] =
        "/sys/fs/bpf/asterisk/xt_prerouting_v6",
    [ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4] =
        "/sys/fs/bpf/asterisk/bpf2socks/local_addr_v4",
    [ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6] =
        "/sys/fs/bpf/asterisk/bpf2socks/local_addr_v6",
    [ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS] =
        "/sys/fs/bpf/asterisk/bpf2socks/tc_ingress",
    [ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS] =
        "/sys/fs/bpf/asterisk/bpf2socks/tc_egress",
};

static const struct asteriskd_owned_chain owned_chains[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL4_BEGIN"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL4_END"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_FILTER,
        "ASTERISK_TUN_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "ASTERISK_FAKE_IP_ICMP"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "ASTERISK_FAKE_IP_ICMP_PRE"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL6_BEGIN"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL6_END"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "ASTERISK_TUN6_FORWARD"},
};

static const struct asteriskd_owned_hook owned_hooks[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TPROXY_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TPROXY_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TUN_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TUN_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", false, "ASTERISK_TUN_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TUN6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", false, "ASTERISK_TUN6_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "OUTPUT", false, "ASTERISK_FAKE_IP_ICMP"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "PREROUTING", false, "ASTERISK_FAKE_IP_ICMP_PRE"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", true, "DROP"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "INPUT", true, "REJECT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", true, "REJECT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "OUTPUT", true, "REJECT"},
};

static const struct asteriskd_owned_policy_rule owned_policy_rules[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TUN_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
};

static const struct asteriskd_owned_resource_catalog owned_resource_catalog = {
    .bpf_root = "/sys/fs/bpf/asterisk",
    .bpf2_root = "/sys/fs/bpf/asterisk/bpf2socks",
    .fake_dns_output_chain = "ASTERISK_FAKE_IP_ICMP",
    .fake_dns_prerouting_chain = "ASTERISK_FAKE_IP_ICMP_PRE",
    .chains = owned_chains,
    .chain_count = sizeof(owned_chains) / sizeof(owned_chains[0]),
    .hooks = owned_hooks,
    .hook_count = sizeof(owned_hooks) / sizeof(owned_hooks[0]),
    .policy_rules = owned_policy_rules,
    .policy_rule_count =
        sizeof(owned_policy_rules) / sizeof(owned_policy_rules[0]),
    .token_route = {
        .family = ASTERISKD_IP_FAMILY_IPV6,
        .table = 255U,
        .destination = "fd7a:7374:6572:6973::/64",
        .interface_name = "lo",
    },
};

const struct asteriskd_owned_resource_catalog *asteriskd_owned_resource_catalog(void) {
    return &owned_resource_catalog;
}

const char *asteriskd_owned_pin_path(enum asteriskd_pin_id pin_id) {
    if ((unsigned int)pin_id >= ASTERISKD_PIN_COUNT) return NULL;
    return owned_pin_paths[pin_id];
}

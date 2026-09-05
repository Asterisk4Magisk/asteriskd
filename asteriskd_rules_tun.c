// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <string.h>

static int copy_text(char *target, size_t capacity, const char *value) {
    size_t length = strnlen(value, capacity);
    if (length == 0U || length >= capacity) return ASTERISKD_CONFIG_INVALID;
    memcpy(target, value, length + 1U);
    return 0;
}

static struct asteriskd_private_chain_group *add_group(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_ip_family family,
    enum asteriskd_ip_table table,
    enum asteriskd_chain_id chain_id) {
    if (plan->private_group_count >= ASTERISKD_RULE_TRANSACTION_MAX_GROUPS) return NULL;
    struct asteriskd_private_chain_group *group =
        &plan->private_groups[plan->private_group_count++];
    memset(group, 0, sizeof(*group));
    group->family = family;
    group->table = table;
    group->chain_id = chain_id;
    group->operation.kind = ASTERISKD_RESOURCE_OPERATION_IPTABLES_CHAIN;
    group->operation.resource.iptables_chain.family = family;
    group->operation.resource.iptables_chain.table = table;
    group->operation.resource.iptables_chain.chain_id = chain_id;
    return group;
}

static int add_name(struct asteriskd_private_chain_group *group, const char *name) {
    if (group == NULL || group->name_count >= ASTERISKD_RULE_TRANSACTION_MAX_NAMES) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return copy_text(group->names[group->name_count++], ASTERISKD_MAX_CHAIN_NAME, name);
}

static struct asteriskd_traffic_hook_group *add_hook_group(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_ip_family family,
    enum asteriskd_ip_table table) {
    if (plan->hook_group_count >= ASTERISKD_RULE_TRANSACTION_MAX_GROUPS) return NULL;
    struct asteriskd_traffic_hook_group *group = &plan->hook_groups[plan->hook_group_count++];
    memset(group, 0, sizeof(*group));
    group->family = family;
    group->table = table;
    group->chain_id = ASTERISKD_CHAIN_ROUTING;
    group->rule_id = ASTERISKD_RULE_ROUTING_ENTRY;
    group->operation.kind = ASTERISKD_RESOURCE_OPERATION_IPTABLES_RULE;
    group->operation.resource.iptables_rule.family = family;
    group->operation.resource.iptables_rule.table = table;
    group->operation.resource.iptables_rule.chain_id = ASTERISKD_CHAIN_ROUTING;
    group->operation.resource.iptables_rule.rule_id = ASTERISKD_RULE_ROUTING_ENTRY;
    return group;
}

static int add_jump(struct asteriskd_traffic_hook_group *group,
    enum asteriskd_builtin_chain builtin, bool insert_at_head, bool udp53,
    const char *target) {
    if (group == NULL || group->hook_count >= ASTERISKD_RULE_TRANSACTION_MAX_HOOKS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_traffic_hook *hook = &group->hooks[group->hook_count++];
    memset(hook, 0, sizeof(*hook));
    hook->builtin_chain = builtin;
    hook->insert_at_head = insert_at_head;
    hook->udp_destination_port_53 = udp53;
    hook->verdict = ASTERISKD_HOOK_JUMP;
    return copy_text(hook->jump_target, sizeof(hook->jump_target), target);
}

static int add_family(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_ip_family family,
    const char *prerouting,
    const char *output,
    const char *forward,
    const char *local_begin,
    const char *local_end,
    const char *tunnel,
    bool dns_only) {
    struct asteriskd_private_chain_group *local = add_group(plan, family,
        ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_LOCAL_BYPASS);
    struct asteriskd_private_chain_group *mangle = add_group(plan, family,
        ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_ROUTING);
    struct asteriskd_private_chain_group *filter = add_group(plan, family,
        ASTERISKD_IP_TABLE_FILTER, ASTERISKD_CHAIN_ROUTING);
    if (add_name(mangle, prerouting) != 0 || add_name(mangle, output) != 0 ||
        add_name(filter, forward) != 0 || add_name(local, local_begin) != 0 ||
        add_name(local, local_end) != 0) return ASTERISKD_CONFIG_INVALID;

    struct asteriskd_traffic_hook_group *mangle_hooks = add_hook_group(plan, family,
        ASTERISKD_IP_TABLE_MANGLE);
    struct asteriskd_traffic_hook_group *filter_hooks = add_hook_group(plan, family,
        ASTERISKD_IP_TABLE_FILTER);
    if (add_jump(mangle_hooks, ASTERISKD_BUILTIN_PREROUTING, true, dns_only, prerouting) != 0 ||
        add_jump(mangle_hooks, ASTERISKD_BUILTIN_OUTPUT, false, dns_only, output) != 0 ||
        add_jump(filter_hooks, ASTERISKD_BUILTIN_FORWARD, true, false, forward) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }

    if (plan->route_count + 2U > ASTERISKD_RULE_TRANSACTION_MAX_ROUTES) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_route_effect *rule = &plan->routes[plan->route_count++];
    struct asteriskd_route_effect *route = &plan->routes[plan->route_count++];
    memset(rule, 0, sizeof(*rule));
    memset(route, 0, sizeof(*route));
    rule->kind = ASTERISKD_ROUTE_EFFECT_IP_RULE;
    rule->family = family;
    rule->table = ASTERISKD_TUN_TABLE;
    rule->priority = ASTERISKD_ROUTE_RULE_PRIORITY;
    rule->mark = ASTERISKD_PRIMARY_MARK;
    rule->mark_mask = ASTERISKD_MARK_MASK;
    rule->ip_rule_id = ASTERISKD_IP_RULE_TUNNEL;
    route->kind = ASTERISKD_ROUTE_EFFECT_ROUTE;
    route->family = family;
    route->table = ASTERISKD_TUN_TABLE;
    route->route_id = ASTERISKD_ROUTE_TUNNEL;
    if (copy_text(route->destination, sizeof(route->destination), "default") != 0 ||
        copy_text(route->interface_name, sizeof(route->interface_name), tunnel) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

int asteriskd_tun_rule_transaction_plan_build(
    const struct asteriskd_config *config,
    struct asteriskd_rule_transaction_plan *plan) {
    if (config == NULL || plan == NULL ||
        config->mode != ASTERISKD_MODE_TUN2SOCKS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    const char *tunnel = config->helper.value.hev.tunnel_name;
    if (add_family(plan, ASTERISKD_IP_FAMILY_IPV4,
            "ASTERISK_TUN_PREROUTING", "ASTERISK_TUN_OUTPUT", "ASTERISK_TUN_FORWARD",
            "ASTERISK_LOCAL4_BEGIN", "ASTERISK_LOCAL4_END", tunnel, false) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    bool dns_only = !config->enable_ipv6;
    if ((!dns_only || (config->enable_local_dns && !config->disable_system_ipv6)) &&
        add_family(plan, ASTERISKD_IP_FAMILY_IPV6,
            "ASTERISK_TUN6_PREROUTING", "ASTERISK_TUN6_OUTPUT", "ASTERISK_TUN6_FORWARD",
            "ASTERISK_LOCAL6_BEGIN", "ASTERISK_LOCAL6_END", tunnel, dns_only) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

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

static struct asteriskd_private_chain_group *add_private_group(
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

static int add_private_name(struct asteriskd_private_chain_group *group, const char *name) {
    if (group == NULL || group->name_count >= ASTERISKD_RULE_TRANSACTION_MAX_NAMES) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return copy_text(group->names[group->name_count++], ASTERISKD_MAX_CHAIN_NAME, name);
}

static struct asteriskd_traffic_hook_group *add_hook_group(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_ip_family family,
    enum asteriskd_ip_table table,
    enum asteriskd_chain_id chain_id,
    enum asteriskd_rule_id rule_id) {
    if (plan->hook_group_count >= ASTERISKD_RULE_TRANSACTION_MAX_GROUPS) return NULL;
    struct asteriskd_traffic_hook_group *group = &plan->hook_groups[plan->hook_group_count++];
    memset(group, 0, sizeof(*group));
    group->family = family;
    group->table = table;
    group->chain_id = chain_id;
    group->rule_id = rule_id;
    group->operation.kind = ASTERISKD_RESOURCE_OPERATION_IPTABLES_RULE;
    group->operation.resource.iptables_rule.family = family;
    group->operation.resource.iptables_rule.table = table;
    group->operation.resource.iptables_rule.chain_id = chain_id;
    group->operation.resource.iptables_rule.rule_id = rule_id;
    return group;
}

static int add_jump(
    struct asteriskd_traffic_hook_group *group,
    enum asteriskd_builtin_chain builtin,
    bool insert_at_head,
    const char *target) {
    if (group == NULL || group->hook_count >= ASTERISKD_RULE_TRANSACTION_MAX_HOOKS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_traffic_hook *hook = &group->hooks[group->hook_count++];
    memset(hook, 0, sizeof(*hook));
    hook->builtin_chain = builtin;
    hook->insert_at_head = insert_at_head;
    hook->verdict = ASTERISKD_HOOK_JUMP;
    return copy_text(hook->jump_target, sizeof(hook->jump_target), target);
}

static struct asteriskd_route_effect *add_route(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_route_effect_kind kind,
    enum asteriskd_ip_family family) {
    if (plan->route_count >= ASTERISKD_RULE_TRANSACTION_MAX_ROUTES) return NULL;
    struct asteriskd_route_effect *effect = &plan->routes[plan->route_count++];
    memset(effect, 0, sizeof(*effect));
    effect->kind = kind;
    effect->family = family;
    return effect;
}

static int add_normal_route(
    struct asteriskd_rule_transaction_plan *plan,
    enum asteriskd_ip_family family) {
    struct asteriskd_route_effect *rule = add_route(plan, ASTERISKD_ROUTE_EFFECT_IP_RULE, family);
    struct asteriskd_route_effect *route = add_route(plan, ASTERISKD_ROUTE_EFFECT_ROUTE, family);
    if (rule == NULL || route == NULL) return ASTERISKD_CONFIG_INVALID;
    rule->table = ASTERISKD_TPROXY_TABLE;
    rule->priority = ASTERISKD_ROUTE_RULE_PRIORITY;
    rule->mark = ASTERISKD_PRIMARY_MARK;
    rule->mark_mask = ASTERISKD_MARK_MASK;
    rule->ip_rule_id = ASTERISKD_IP_RULE_TPROXY;
    route->table = ASTERISKD_TPROXY_TABLE;
    route->local_route = true;
    route->route_id = ASTERISKD_ROUTE_TPROXY;
    if (copy_text(route->destination, sizeof(route->destination), "default") != 0 ||
        copy_text(route->interface_name, sizeof(route->interface_name), "lo") != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

int asteriskd_tproxy_rule_transaction_plan_build(
    const struct asteriskd_config *config,
    bool has_global_ipv6_address,
    struct asteriskd_rule_transaction_plan *plan) {
    if (config == NULL || plan == NULL || config->mode != ASTERISKD_MODE_TPROXY) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_private_chain_group *local4 = add_private_group(plan,
        ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_LOCAL_BYPASS);
    struct asteriskd_private_chain_group *main4 = add_private_group(plan,
        ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_TPROXY);
    if (add_private_name(main4, "ASTERISK_TPROXY_PREROUTING") != 0 ||
        add_private_name(main4, "ASTERISK_TPROXY_OUTPUT") != 0 ||
        add_private_name(local4, "ASTERISKD_LOCAL4_BEGIN") != 0 ||
        add_private_name(local4, "ASTERISKD_LOCAL4_END") != 0 ||
        add_normal_route(plan, ASTERISKD_IP_FAMILY_IPV4) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_traffic_hook_group *hooks4 = add_hook_group(plan,
        ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        ASTERISKD_CHAIN_TPROXY, ASTERISKD_RULE_TPROXY_ENTRY);
    if (add_jump(hooks4, ASTERISKD_BUILTIN_PREROUTING, true,
            "ASTERISK_TPROXY_PREROUTING") != 0 ||
        add_jump(hooks4, ASTERISKD_BUILTIN_OUTPUT, false,
            "ASTERISK_TPROXY_OUTPUT") != 0) return ASTERISKD_CONFIG_INVALID;

    if (!config->enable_ipv6) return 0;
    struct asteriskd_private_chain_group *local6 = add_private_group(plan,
        ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_LOCAL_BYPASS);
    struct asteriskd_private_chain_group *main6 = add_private_group(plan,
        ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE, ASTERISKD_CHAIN_TPROXY);
    if (add_private_name(main6, "ASTERISK_TPROXY6_PREROUTING") != 0 ||
        add_private_name(main6, "ASTERISK_TPROXY6_OUTPUT") != 0 ||
        add_private_name(local6, "ASTERISKD_LOCAL6_BEGIN") != 0 ||
        add_private_name(local6, "ASTERISKD_LOCAL6_END") != 0) return ASTERISKD_CONFIG_INVALID;
    struct asteriskd_traffic_hook_group *hooks6 = add_hook_group(plan,
        ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        ASTERISKD_CHAIN_TPROXY, ASTERISKD_RULE_TPROXY_ENTRY);
    if (add_jump(hooks6, ASTERISKD_BUILTIN_PREROUTING, true,
            "ASTERISK_TPROXY6_PREROUTING") != 0 ||
        add_jump(hooks6, ASTERISKD_BUILTIN_OUTPUT, false,
            "ASTERISK_TPROXY6_OUTPUT") != 0) return ASTERISKD_CONFIG_INVALID;
    if (has_global_ipv6_address) return add_normal_route(plan, ASTERISKD_IP_FAMILY_IPV6);

    if (add_private_name(main6, "ASTERISK_TPROXY6_DUMMY_PRE") != 0 ||
        add_private_name(main6, "ASTERISK_TPROXY6_DUMMY") != 0 ||
        add_jump(hooks6, ASTERISKD_BUILTIN_PREROUTING, false,
            "ASTERISK_TPROXY6_DUMMY_PRE") != 0 ||
        add_jump(hooks6, ASTERISKD_BUILTIN_OUTPUT, false,
            "ASTERISK_TPROXY6_DUMMY") != 0) return ASTERISKD_CONFIG_INVALID;
    struct asteriskd_route_effect *dummy = add_route(plan,
        ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE, ASTERISKD_IP_FAMILY_IPV6);
    struct asteriskd_route_effect *rule = add_route(plan,
        ASTERISKD_ROUTE_EFFECT_IP_RULE, ASTERISKD_IP_FAMILY_IPV6);
    struct asteriskd_route_effect *route = add_route(plan,
        ASTERISKD_ROUTE_EFFECT_ROUTE, ASTERISKD_IP_FAMILY_IPV6);
    if (dummy == NULL || rule == NULL || route == NULL ||
        copy_text(dummy->interface_name, sizeof(dummy->interface_name), "xdummy") != 0 ||
        copy_text(dummy->interface_address, sizeof(dummy->interface_address),
            "fd01:5ca1:ab1e:8d97:497f:8b48:b9aa:85cd/128") != 0 ||
        copy_text(route->destination, sizeof(route->destination), "default") != 0 ||
        copy_text(route->interface_name, sizeof(route->interface_name), "xdummy") != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    rule->table = ASTERISKD_TPROXY_DUMMY_TABLE;
    rule->priority = ASTERISKD_ROUTE_RULE_PRIORITY;
    rule->mark = ASTERISKD_AUXILIARY_MARK;
    rule->mark_mask = ASTERISKD_MARK_MASK;
    rule->invert_from_all = true;
    rule->ip_rule_id = ASTERISKD_IP_RULE_TPROXY;
    route->table = ASTERISKD_TPROXY_DUMMY_TABLE;
    route->local_route = true;
    route->route_id = ASTERISKD_ROUTE_TPROXY;
    dummy->interface_id = ASTERISKD_INTERFACE_IPV6_DUMMY;
    return 0;
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <errno.h>
#include <string.h>

static struct asteriskd_private_chain_group *transaction_add_private_group(
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

static struct asteriskd_traffic_hook_group *transaction_add_hook_group(
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

static int transaction_add_hook(struct asteriskd_traffic_hook_group *group,
    enum asteriskd_builtin_chain builtin, bool insert_at_head,
    enum asteriskd_hook_verdict verdict, bool udp53, const char *target) {
    if (group == NULL || group->hook_count >= ASTERISKD_RULE_TRANSACTION_MAX_HOOKS) {
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_traffic_hook *hook = &group->hooks[group->hook_count++];
    hook->builtin_chain = builtin;
    hook->insert_at_head = insert_at_head;
    hook->dns_destination_protocol = udp53 ? ASTERISKD_DNS_UDP : ASTERISKD_DNS_NONE;
    hook->verdict = verdict;
    if (verdict == ASTERISKD_HOOK_JUMP) {
        return asteriskd_copy_string(hook->jump_target, sizeof(hook->jump_target), target);
    }
    return target == NULL ? 0 : ASTERISKD_CONFIG_INVALID;
}

static int transaction_add_fake_dns(
    struct asteriskd_rule_transaction_plan *plan) {
    const struct asteriskd_owned_resource_catalog *catalog =
        asteriskd_owned_resource_catalog();
    const char *output = catalog->fake_dns_output_chain;
    const char *prerouting = catalog->fake_dns_prerouting_chain;
    struct asteriskd_private_chain_group *group = transaction_add_private_group(plan,
        ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT, ASTERISKD_CHAIN_FAKE_DNS);
    if (group == NULL || asteriskd_copy_string(group->names[0], ASTERISKD_MAX_CHAIN_NAME, output) != 0 ||
        asteriskd_copy_string(group->names[1], ASTERISKD_MAX_CHAIN_NAME, prerouting) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    group->name_count = 2U;
    struct asteriskd_traffic_hook_group *hooks = transaction_add_hook_group(plan,
        ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        ASTERISKD_CHAIN_FAKE_DNS, ASTERISKD_RULE_FAKE_DNS_ENTRY);
    if (transaction_add_hook(hooks, ASTERISKD_BUILTIN_OUTPUT, true,
            ASTERISKD_HOOK_JUMP, false, output) != 0 ||
        transaction_add_hook(hooks, ASTERISKD_BUILTIN_PREROUTING, true,
            ASTERISKD_HOOK_JUMP, false, prerouting) != 0) return ASTERISKD_CONFIG_INVALID;
    return 0;
}

int asteriskd_rule_transaction_plan_build(const struct asteriskd_config *config,
    bool has_global_ipv6_address, struct asteriskd_rule_transaction_plan *plan) {
    if (plan != NULL) memset(plan, 0, sizeof(*plan));
    if (config == NULL || plan == NULL) return ASTERISKD_CONFIG_INVALID;
    if (asteriskd_mode_core_managed(config->mode)) {
        bool supported_core =
            config->owner == ASTERISKD_OWNER_BOX && config->core_type == ASTERISKD_CORE_SING_BOX;
        if (config->mode == ASTERISKD_MODE_TUN) {
            supported_core |=
                config->owner == ASTERISKD_OWNER_META && config->core_type == ASTERISKD_CORE_MIHOMO;
        }
        if (!supported_core) {
            return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
        }
        plan->no_op = true;
        return 0;
    }
    int result = 0;
    if (config->mode == ASTERISKD_MODE_TPROXY) {
        result =
            asteriskd_tproxy_rule_transaction_plan_build(config, has_global_ipv6_address, plan);
    } else if (config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        result = asteriskd_tun_rule_transaction_plan_build(config, plan);
    } else if (config->mode != ASTERISKD_MODE_BPF2SOCKS) {
        result = ASTERISKD_CONFIG_INVALID;
    }
    if (result != 0) return result;
    // Explicit Android network selections have priority 13000. Only an
    // intercepted DNS packet, classified in OUTPUT after forced bypasses, may
    // override that route; ordinary traffic retains the existing priority.
    if ((config->mode == ASTERISKD_MODE_TPROXY || config->mode == ASTERISKD_MODE_TUN2SOCKS) &&
        (config->dns_enhancement || config->enable_local_dns)) {
        size_t original_count = plan->route_count;
        for (size_t i = 0; i < original_count; i++)
            if (plan->routes[i].kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) {
                if (plan->route_count >= ASTERISKD_RULE_TRANSACTION_MAX_ROUTES)
                    return ASTERISKD_CONFIG_INVALID;
                struct asteriskd_route_effect *rule = &plan->routes[plan->route_count++];
                *rule = plan->routes[i];
                rule->priority = ASTERISKD_DNS_ROUTE_RULE_PRIORITY;
                rule->mark = ASTERISKD_DNS_PROXY_ROUTE_MARK;
                rule->mark_mask = ASTERISKD_DNS_MARK_MASK;
                rule->ip_rule_id = config->mode == ASTERISKD_MODE_TPROXY
                    ? ASTERISKD_IP_RULE_DNS_TPROXY
                    : ASTERISKD_IP_RULE_DNS_TUNNEL;
            }
    }
    if (config->mode == ASTERISKD_MODE_BPF2SOCKS &&
        (config->enable_ipv6 || config->enable_local_dns)) {
        if (plan->route_count >= ASTERISKD_RULE_TRANSACTION_MAX_ROUTES) {
            return ASTERISKD_CONFIG_INVALID;
        }
        struct asteriskd_route_effect *route = &plan->routes[plan->route_count++];
        memset(route, 0, sizeof(*route));
        route->kind = ASTERISKD_ROUTE_EFFECT_ROUTE;
        route->family = ASTERISKD_IP_FAMILY_IPV6;
        route->table = 255U;
        route->local_route = true;
        route->route_id = ASTERISKD_ROUTE_TOKEN;
        if (asteriskd_copy_string(
                route->destination, sizeof(route->destination), "fd7a:7374:6572:6973::/64") != 0 ||
            asteriskd_copy_string(route->interface_name, sizeof(route->interface_name), "lo") !=
                0) {
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    if (config->enable_fake_dns && transaction_add_fake_dns(plan) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    plan->hooks_are_last = true;
    return 0;
}

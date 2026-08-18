#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

int asteriskd_bpf2_token_route_plan_build(
    const struct asteriskd_config *config, enum asteriskd_route_slot_state slot,
    uint32_t loopback_interface_index, struct asteriskd_token_route_plan *plan,
    char *error, size_t error_capacity) {
    if (plan == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(plan, 0, sizeof(*plan));
    if (config == NULL || config->mode != ASTERISKD_MODE_BPF2SOCKS ||
        config->helper.type != ASTERISKD_HELPER_BPF2SOCKS ||
        slot < ASTERISKD_ROUTE_SLOT_ABSENT || slot > ASTERISKD_ROUTE_SLOT_FOREIGN) {
        if (error != NULL && error_capacity != 0U) {
            (void)snprintf(error, error_capacity, "%s", "invalid bpf2socks token route input");
        }
        return ASTERISKD_CONFIG_INVALID;
    }
    if (!config->enable_ipv6) return 0;
    if (loopback_interface_index == 0U || slot == ASTERISKD_ROUTE_SLOT_FOREIGN) {
        if (error != NULL && error_capacity != 0U) {
            (void)snprintf(error, error_capacity, "%s", slot == ASTERISKD_ROUTE_SLOT_FOREIGN ?
                "foreign IPv6 token route collision" : "loopback interface identity missing");
        }
        return ASTERISKD_CONFIG_IO;
    }
    (void)snprintf(plan->prefix, sizeof(plan->prefix), "%s", "fd7a:7374:6572:6973::/64");
    (void)snprintf(plan->interface_name, sizeof(plan->interface_name), "%s", "lo");
    plan->interface_index = loopback_interface_index;
    plan->local_table = true;
    if (slot == ASTERISKD_ROUTE_SLOT_OWNED) return 0;
    plan->create = true;
    plan->operation.kind = ASTERISKD_RESOURCE_OPERATION_ROUTE;
    plan->operation.resource.route.family = ASTERISKD_IP_FAMILY_IPV6;
    plan->operation.resource.route.route_id = ASTERISKD_ROUTE_TOKEN;
    (void)snprintf(plan->operation.resource.route.interface_name,
        sizeof(plan->operation.resource.route.interface_name), "%s", "lo");
    plan->operation.resource.route.interface_index = loopback_interface_index;
    plan->operation.resource.route.original_presence = false;
    return 0;
}

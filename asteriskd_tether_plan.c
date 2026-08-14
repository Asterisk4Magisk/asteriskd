#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t capacity, const char *format, ...) {
    if (error == NULL || capacity == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, capacity, format, arguments);
    va_end(arguments);
}

static bool interface_name_valid(const char *name) {
    if (name == NULL) return false;
    size_t length = strnlen(name, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strcmp(name, "all") == 0 || strcmp(name, "default") == 0 ||
        strcmp(name, "lo") == 0) return false;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)name[index];
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '_' || value == '-' || value == '.')) {
            return false;
        }
    }
    return true;
}

static bool interface_matches_selector(const char *name, const char *selector) {
    size_t selector_length = strnlen(selector, ASTERISKD_MAX_INTERFACE_NAME);
    if (selector_length == 0U || selector_length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    if (selector[selector_length - 1U] == '+') {
        return selector_length > 1U && strncmp(name, selector, selector_length - 1U) == 0;
    }
    return strcmp(name, selector) == 0;
}

static bool hotspot_matches(const struct asteriskd_config *config, const char *interface_name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        if (interface_matches_selector(interface_name, config->hotspot_interface_prefixes[index])) {
            return true;
        }
    }
    return false;
}

int asteriskd_tether_plan_build(
    const struct asteriskd_config *config, enum asteriskd_event_action action, int family,
    const struct asteriskd_tether_probe *probe, struct asteriskd_tether_plan *plan,
    char *error, size_t error_capacity) {
    if (plan == NULL) {
        set_error(error, error_capacity, "tether plan output is required");
        return -1;
    }
    memset(plan, 0, sizeof(*plan));
    if (config == NULL || probe == NULL || !interface_name_valid(probe->interface_name) ||
        probe->interface_index == 0U || action < ASTERISKD_EVENT_ADDED ||
        action > ASTERISKD_EVENT_UPDATED ||
        (family != ASTERISKD_ADDRESS_IPV4 && family != ASTERISKD_ADDRESS_IPV6)) {
        set_error(error, error_capacity, "invalid tether repair probe");
        return -1;
    }
    if (probe->dnsmasq_identity_valid && probe->dnsmasq_pid <= 1) {
        set_error(error, error_capacity, "invalid dnsmasq identity");
        return -1;
    }
    bool candidate = config->mode != ASTERISKD_MODE_EBPF && config->disable_system_ipv6 &&
        action == ASTERISKD_EVENT_ADDED && family == ASTERISKD_ADDRESS_IPV6 &&
        hotspot_matches(config, probe->interface_name);
    bool all_gates = probe->ndc_executable && probe->link_identity_matches &&
        probe->ipv6_disabled && probe->no_ipv6_addresses && probe->interface_active &&
        probe->status_started && probe->dnsmasq_identity_valid;
    if (!candidate || !all_gates) return 0;

    plan->required = true;
    (void)snprintf(plan->interface_name, sizeof(plan->interface_name), "%s", probe->interface_name);
    plan->interface_index = probe->interface_index;
    plan->old_dnsmasq_pid = probe->dnsmasq_pid;
    plan->recovery.status = ASTERISKD_RECOVERY_INTENT;
    plan->recovery.kind = ASTERISKD_RECOVERY_TETHER_STATE;
    struct asteriskd_tether_state_resource *resource = &plan->recovery.resource.tether_state;
    resource->tether_id = ASTERISKD_TETHER_DNSMASQ;
    (void)snprintf(resource->interface_name, sizeof(resource->interface_name), "%s",
        probe->interface_name);
    resource->interface_index = probe->interface_index;
    resource->original_active = true;
    resource->desired_active = false;
    return 0;
}

static bool plan_valid(const struct asteriskd_tether_plan *plan) {
    if (plan == NULL || !plan->required || !interface_name_valid(plan->interface_name) ||
        plan->interface_index == 0U || plan->old_dnsmasq_pid <= 1 ||
        plan->recovery.record_id != 0U || plan->recovery.status != ASTERISKD_RECOVERY_INTENT ||
        plan->recovery.kind != ASTERISKD_RECOVERY_TETHER_STATE) return false;
    const struct asteriskd_tether_state_resource *resource = &plan->recovery.resource.tether_state;
    return resource->tether_id == ASTERISKD_TETHER_DNSMASQ &&
        strcmp(resource->interface_name, plan->interface_name) == 0 &&
        resource->interface_index == plan->interface_index && resource->original_active &&
        !resource->desired_active;
}

int asteriskd_tether_plan_stop(
    const struct asteriskd_tether_plan *plan, const struct asteriskd_tether_backend *backend) {
    if (!plan_valid(plan) || backend == NULL || backend->stop == NULL) return -1;
    return backend->stop(backend->context) == 0 ? 1 : -1;
}

int asteriskd_tether_plan_restore(
    const struct asteriskd_tether_plan *plan, const struct asteriskd_tether_backend *backend) {
    if (!plan_valid(plan) || backend == NULL || backend->start == NULL || backend->verify == NULL) {
        return -1;
    }
    if (backend->start(backend->context) != 0 && backend->start(backend->context) != 0) return -1;
    bool active = false;
    int64_t current_pid = -1;
    if (backend->verify(backend->context, plan->interface_name, plan->interface_index,
        plan->old_dnsmasq_pid, &active, &current_pid) != 0 || !active || current_pid <= 1 ||
        current_pid == plan->old_dnsmasq_pid) return -1;
    return 1;
}

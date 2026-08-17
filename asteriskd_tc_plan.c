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

static bool slot_valid(enum asteriskd_tc_slot_state slot) {
    return slot >= ASTERISKD_TC_SLOT_ABSENT && slot <= ASTERISKD_TC_SLOT_FOREIGN;
}

enum asteriskd_tc_qdisc_cleanup_decision asteriskd_tc_qdisc_cleanup_decide(
    bool ingress_occupied, bool egress_occupied) {
    return ingress_occupied || egress_occupied
        ? ASTERISKD_TC_QDISC_CLEANUP_RETAIN_SHARED
        : ASTERISKD_TC_QDISC_CLEANUP_DELETE;
}

bool asteriskd_tc_qdisc_cleanup_restored(bool qdisc_present,
    enum asteriskd_tc_qdisc_cleanup_decision decision) {
    return !qdisc_present || decision == ASTERISKD_TC_QDISC_CLEANUP_RETAIN_SHARED;
}

static struct asteriskd_tc_plan_operation *append_operation(
    struct asteriskd_tc_plan *plan, enum asteriskd_tc_plan_operation_kind kind,
    enum asteriskd_recovery_kind recovery_kind) {
    if (plan->operation_count >= sizeof(plan->operations) / sizeof(plan->operations[0])) return NULL;
    struct asteriskd_tc_plan_operation *operation = &plan->operations[plan->operation_count++];
    memset(operation, 0, sizeof(*operation));
    operation->kind = kind;
    operation->recovery.status = ASTERISKD_RECOVERY_INTENT;
    operation->recovery.kind = recovery_kind;
    return operation;
}

static void copy_interface(char destination[ASTERISKD_MAX_INTERFACE_NAME], const char *source) {
    (void)snprintf(destination, ASTERISKD_MAX_INTERFACE_NAME, "%s", source);
}

static int append_route_localnet(
    struct asteriskd_tc_plan *plan, const struct asteriskd_tc_interface_probe *probe) {
    struct asteriskd_tc_plan_operation *operation = append_operation(
        plan, ASTERISKD_TC_PLAN_SET_ROUTE_LOCALNET, ASTERISKD_RECOVERY_SYSCTL);
    if (operation == NULL) return -1;
    struct asteriskd_sysctl_resource *resource = &operation->recovery.resource.sysctl;
    resource->sysctl_id = ASTERISKD_SYSCTL_ROUTE_LOCALNET;
    copy_interface(resource->interface_name, probe->interface_name);
    resource->interface_index = probe->interface_index;
    resource->original_value = 0U;
    resource->desired_value = 1U;
    return 0;
}

static int append_qdisc(
    struct asteriskd_tc_plan *plan, const struct asteriskd_tc_interface_probe *probe) {
    struct asteriskd_tc_plan_operation *operation = append_operation(
        plan, ASTERISKD_TC_PLAN_CREATE_CLSACT, ASTERISKD_RECOVERY_TC_QDISC);
    if (operation == NULL) return -1;
    struct asteriskd_tc_qdisc_resource *resource = &operation->recovery.resource.tc_qdisc;
    resource->qdisc_id = ASTERISKD_QDISC_HOTSPOT_CLSACT;
    copy_interface(resource->interface_name, probe->interface_name);
    resource->interface_index = probe->interface_index;
    resource->original_presence = false;
    return 0;
}

static int append_filter(
    struct asteriskd_tc_plan *plan, const struct asteriskd_tc_interface_probe *probe,
    enum asteriskd_tc_direction direction) {
    bool ingress = direction == ASTERISKD_TC_DIRECTION_INGRESS;
    struct asteriskd_tc_plan_operation *operation = append_operation(plan,
        ingress ? ASTERISKD_TC_PLAN_CREATE_INGRESS : ASTERISKD_TC_PLAN_CREATE_EGRESS,
        ASTERISKD_RECOVERY_TC_FILTER);
    if (operation == NULL) return -1;
    operation->priority = ASTERISKD_HOTSPOT_TC_PRIORITY;
    operation->handle = ASTERISKD_HOTSPOT_TC_HANDLE;
    operation->direct_action = true;
    struct asteriskd_tc_filter_resource *resource = &operation->recovery.resource.tc_filter;
    resource->filter_id = ingress ? ASTERISKD_FILTER_HOTSPOT_INGRESS :
        ASTERISKD_FILTER_HOTSPOT_EGRESS;
    resource->direction = direction;
    copy_interface(resource->interface_name, probe->interface_name);
    resource->interface_index = probe->interface_index;
    resource->program_id = ingress ? ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS :
        ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS;
    resource->original_presence = false;
    return 0;
}

int asteriskd_tc_install_plan_build(
    const struct asteriskd_config *config, const struct asteriskd_tc_interface_probe *probe,
    struct asteriskd_tc_plan *plan, char *error, size_t error_capacity) {
    if (plan == NULL) {
        set_error(error, error_capacity, "tc plan output is required");
        return -1;
    }
    memset(plan, 0, sizeof(*plan));
    if (config == NULL || probe == NULL || config->mode != ASTERISKD_MODE_BPF2SOCKS ||
        config->helper.type != ASTERISKD_HELPER_BPF2SOCKS ||
        !interface_name_valid(probe->interface_name) || probe->interface_index == 0U ||
        probe->route_localnet_value > 1U || !slot_valid(probe->qdisc) ||
        !slot_valid(probe->egress) || !slot_valid(probe->ingress)) {
        set_error(error, error_capacity, "invalid bpf2socks TC probe");
        return -1;
    }
    if (probe->qdisc == ASTERISKD_TC_SLOT_FOREIGN ||
        probe->egress == ASTERISKD_TC_SLOT_FOREIGN ||
        probe->ingress == ASTERISKD_TC_SLOT_FOREIGN ||
        probe->egress == ASTERISKD_TC_SLOT_COMPATIBLE ||
        probe->ingress == ASTERISKD_TC_SLOT_COMPATIBLE) {
        set_error(error, error_capacity, "foreign TC resource collision");
        return -1;
    }
    if ((probe->egress == ASTERISKD_TC_SLOT_OWNED ||
         probe->ingress == ASTERISKD_TC_SLOT_OWNED) &&
        probe->qdisc == ASTERISKD_TC_SLOT_ABSENT) {
        set_error(error, error_capacity, "TC filter exists without clsact");
        return -1;
    }
    if (probe->route_localnet_value == 0U && append_route_localnet(plan, probe) != 0) goto failed;
    if (probe->qdisc == ASTERISKD_TC_SLOT_ABSENT && append_qdisc(plan, probe) != 0) goto failed;
    if (probe->egress == ASTERISKD_TC_SLOT_ABSENT &&
        append_filter(plan, probe, ASTERISKD_TC_DIRECTION_EGRESS) != 0) goto failed;
    if (probe->ingress == ASTERISKD_TC_SLOT_ABSENT &&
        append_filter(plan, probe, ASTERISKD_TC_DIRECTION_INGRESS) != 0) goto failed;
    return 0;

failed:
    memset(plan, 0, sizeof(*plan));
    set_error(error, error_capacity, "too many TC plan operations");
    return -1;
}

int asteriskd_tc_cleanup_plan_build(
    const struct asteriskd_tc_plan *install, struct asteriskd_tc_plan *cleanup) {
    if (cleanup == NULL) return -1;
    memset(cleanup, 0, sizeof(*cleanup));
    if (install == NULL || install->operation_count >
        sizeof(install->operations) / sizeof(install->operations[0])) return -1;
    for (size_t index = install->operation_count; index > 0U; --index) {
        const struct asteriskd_tc_plan_operation *source = &install->operations[index - 1U];
        struct asteriskd_tc_plan_operation *destination =
            &cleanup->operations[cleanup->operation_count++];
        *destination = *source;
        switch (source->kind) {
            case ASTERISKD_TC_PLAN_SET_ROUTE_LOCALNET:
                destination->kind = ASTERISKD_TC_PLAN_RESTORE_ROUTE_LOCALNET;
                break;
            case ASTERISKD_TC_PLAN_CREATE_CLSACT:
                destination->kind = ASTERISKD_TC_PLAN_REMOVE_CLSACT;
                break;
            case ASTERISKD_TC_PLAN_CREATE_EGRESS:
                destination->kind = ASTERISKD_TC_PLAN_REMOVE_EGRESS;
                break;
            case ASTERISKD_TC_PLAN_CREATE_INGRESS:
                destination->kind = ASTERISKD_TC_PLAN_REMOVE_INGRESS;
                break;
            default:
                memset(cleanup, 0, sizeof(*cleanup));
                return -1;
        }
    }
    return 0;
}

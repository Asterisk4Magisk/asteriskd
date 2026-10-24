// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

int asteriskd_supervisor_effect_start_matcher(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_bpf_pin_ownership_backend *pin_backend =
        asteriskd_system_bpf_pin_ownership_backend();
    char error[256U];
    if (system->matcher_launch_ready || system->matcher_verified ||
        asteriskd_matcher_pin_plan_build(
            &system->loaded_config.config, &system->matcher_pin_plan) != 0) return -1;
    system->matcher_plan_ready = true;
    if (pin_backend == NULL || asteriskd_matcher_pin_preflight(
            &system->matcher_pin_plan, pin_backend, error, sizeof(error)) != 0 ||
        asteriskd_matcher_launch_prepare(
            &system->loaded_config.config, (const char *const *)environ,
            asteriskd_system_anonymous_file_backend(), &system->matcher_launch,
            error, sizeof(error)) != 0) return -1;
    system->matcher_launch_ready = true;
    struct asteriskd_resource_operation records[5U];
    size_t count = 0U;
    if (asteriskd_matcher_pin_records_build(
            &system->matcher_pin_plan, records, 5U, &count) != 0) return -1;
    system->active_pin_batch = system->loaded_config.config.enable_ipv6
        ? ASTERISKD_PIN_BATCH_MATCHER_DUAL_STACK
        : ASTERISKD_PIN_BATCH_MATCHER_IPV4;
    system->pin_batch_active = true;
    int result = asteriskd_supervisor_apply_and_verify(
        system, records, count, error, sizeof(error));
    system->pin_batch_active = false;
    int destroyed = asteriskd_matcher_launch_destroy(
        asteriskd_system_anonymous_file_backend(), &system->matcher_launch);
    system->matcher_launch_ready = false;
    return result == 0 && destroyed == 0 ? 0 : -1;
}

int asteriskd_supervisor_effect_start_helper(
    void *opaque, struct asteriskd_child_identity *identity) {
    struct asteriskd_system_supervisor *system = opaque;
    system->cleanup_in_progress = false;
    if (identity == NULL) return -1;
    if (system->loaded_config.config.helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) {
        if (asteriskd_supervisor_tun_compatibility_prepare(system) != 0) return -1;
        int result = asteriskd_supervisor_start_helper_process(system, identity);
        if (result != 0 && asteriskd_supervisor_tun_compatibility_cleanup(system) != 0) return -1;
        return result;
    }
    if (system->loaded_config.config.helper.type != ASTERISKD_HELPER_BPF2SOCKS) {
        return -1;
    }
    const struct asteriskd_bpf_pin_ownership_backend *pin_backend =
        asteriskd_system_bpf_pin_ownership_backend();
    char error[256U];
    if (asteriskd_b2s_pin_plan_build(
            &system->loaded_config.config, &system->b2s_pin_plan) != 0) return -1;
    system->b2s_plan_ready = true;
    if (pin_backend == NULL || asteriskd_b2s_pin_preflight(
            &system->b2s_pin_plan, pin_backend, error, sizeof(error)) != 0) return -1;
    struct asteriskd_resource_operation records[4U];
    size_t count = 0U;
    if (asteriskd_b2s_pin_records_build(
            &system->b2s_pin_plan, records, 4U, &count) != 0) return -1;
    system->active_pin_batch = system->loaded_config.config.enable_ipv6
        ? ASTERISKD_PIN_BATCH_BPF2SOCKS_DUAL_STACK
        : ASTERISKD_PIN_BATCH_BPF2SOCKS_IPV4;
    system->pin_batch_active = true;
    int result = asteriskd_supervisor_apply_and_verify(
        system, records, count, error, sizeof(error));
    system->pin_batch_active = false;
    if (result != 0 || !system->helper_identity_ready) return -1;
    *identity = system->helper_identity;
    return 0;
}

int asteriskd_supervisor_effect_open_network(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    system->cleanup_in_progress = false;
    char error[128U] = {0};
    if (asteriskd_network_open(&system->loaded_config.config,
            asteriskd_system_network_backend(), &system->network,
            error, sizeof(error)) != 0) {
        char message[192U];
        int written = snprintf(message, sizeof(message), "network open failed: detail=%s",
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_NETWORK, message);
        }
        return -1;
    }
    system->network_opened = true;
    system->network_effect_sink.dispatch = asteriskd_supervisor_network_effect_dispatch;
    system->network_effect_sink.context = system;
    if (asteriskd_network_set_effect_sink(
            &system->network, &system->network_effect_sink) != 0) return -1;
    return asteriskd_supervisor_sync_ipv6_guard(system);
}

int asteriskd_supervisor_collect_local_address_set(
    struct asteriskd_system_supervisor *system,
    int family,
    struct asteriskd_address_set *set) {
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    struct asteriskd_interface_address candidates[ASTERISKD_MAX_ADDRESSES];
    size_t count = 0U;
    int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_name == NULL ||
            entry->ifa_addr->sa_family != native_family) continue;
        if (count >= ASTERISKD_MAX_ADDRESSES) {
            freeifaddrs(addresses);
            return -1;
        }
        const void *raw = native_family == AF_INET
            ? (const void *)&((const struct sockaddr_in *)entry->ifa_addr)->sin_addr
            : (const void *)&((const struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr;
        if (snprintf(candidates[count].interface_name,
                sizeof(candidates[count].interface_name), "%s", entry->ifa_name) <= 0 ||
            inet_ntop(native_family, raw, candidates[count].address,
                sizeof(candidates[count].address)) == NULL) {
            freeifaddrs(addresses);
            return -1;
        }
        ++count;
    }
    freeifaddrs(addresses);
    char error[128U];
    return asteriskd_local_address_set_build(&system->loaded_config.config,
        family, candidates, count, set, error, sizeof(error)) == 0 ? 0 : -1;
}

static bool system_uses_iptables_local_bypass(
    const struct asteriskd_system_supervisor *system) {
    enum asteriskd_mode mode = system->loaded_config.config.mode;
    return mode == ASTERISKD_MODE_TPROXY ||
        mode == ASTERISKD_MODE_TUN2SOCKS;
}

int asteriskd_supervisor_capture_local_address_snapshot(
    struct asteriskd_system_supervisor *system) {
    system->local_address_snapshot_active = false;
    memset(&system->local_ipv4_snapshot, 0, sizeof(system->local_ipv4_snapshot));
    memset(&system->local_ipv6_snapshot, 0, sizeof(system->local_ipv6_snapshot));
    if (!system_uses_iptables_local_bypass(system)) return 0;
    if (asteriskd_supervisor_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV4,
            &system->local_ipv4_snapshot) != 0) return -1;
    if (system->loaded_config.config.enable_ipv6) {
        if (asteriskd_supervisor_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV6,
                &system->local_ipv6_snapshot) != 0) return -1;
    } else {
        system->local_ipv6_snapshot.family = ASTERISKD_ADDRESS_IPV6;
    }
    system->local_address_snapshot_active = true;
    return 0;
}

void asteriskd_supervisor_clear_local_address_snapshot(
    struct asteriskd_system_supervisor *system) {
    system->local_address_snapshot_active = false;
    memset(&system->local_ipv4_snapshot, 0, sizeof(system->local_ipv4_snapshot));
    memset(&system->local_ipv6_snapshot, 0, sizeof(system->local_ipv6_snapshot));
}

static int system_apply_local_bypass_plan(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    const char *consumer_chain,
    const struct asteriskd_local_bypass_plan *plan) {
    for (size_t index = 0U; index < plan->operation_count; ++index) {
        const struct asteriskd_local_bypass_operation *operation = &plan->operations[index];
        char cidr[ASTERISKD_MAX_CIDR];
        int written = snprintf(cidr, sizeof(cidr), "%s/%u", operation->address,
            family == ASTERISKD_IP_FAMILY_IPV4 ? 32U : 128U);
        if (written <= 0 || (size_t)written >= sizeof(cidr)) return -1;
        if (operation->kind == ASTERISKD_LOCAL_BYPASS_INSERT) {
            char position[24U];
            written = snprintf(position, sizeof(position), "%zu", operation->rule_number);
            const char *arguments[] = {position, "-d", cidr, "-j", "RETURN"};
            if (written <= 0 || (size_t)written >= sizeof(position) ||
                asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
                    "-I", consumer_chain, arguments,
                    sizeof(arguments) / sizeof(arguments[0])) != 0) return -1;
        } else if (operation->kind == ASTERISKD_LOCAL_BYPASS_DELETE) {
            const char *arguments[] = {"-d", cidr, "-j", "RETURN"};
            if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
                    "-D", consumer_chain, arguments,
                    sizeof(arguments) / sizeof(arguments[0])) != 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

static int system_reconcile_local_bypass_consumer(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    const char *consumer_chain,
    const char *begin_chain,
    const char *end_chain,
    const struct asteriskd_address_set *desired,
    bool *changed) {
    // The plan reads only "-A <consumer>" lines, so a captured table listing
    // replaces a per-chain listing without another iptables process.
    const char *rules = NULL;
    size_t rules_length = 0U;
    const struct system_rule_view *view =
        &system->rule_snapshot.xtables[family][ASTERISKD_IP_TABLE_MANGLE];
    if ((system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
            system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) && view->present) {
        rules = view->bytes;
        rules_length = view->length;
    } else {
        int exit_status = -1;
        if (asteriskd_supervisor_xtables_run(system, family, ASTERISKD_IP_TABLE_MANGLE,
                "-S", consumer_chain, NULL, 0U, true, &exit_status) != 0 ||
            exit_status != 0 || system->action_stdout_overflow) return -1;
        rules = system->action_stdout;
        rules_length = system->action_stdout_length;
    }
    struct asteriskd_local_bypass_plan plan;
    char error[160U];
    int address_family = family == ASTERISKD_IP_FAMILY_IPV4
        ? ASTERISKD_ADDRESS_IPV4 : ASTERISKD_ADDRESS_IPV6;
    if (asteriskd_local_bypass_plan_build(address_family, consumer_chain,
            begin_chain, end_chain, rules, rules_length,
            desired, &plan, error, sizeof(error)) != 0) {
        char message[256U];
        int written = snprintf(message, sizeof(message),
            "local bypass plan failed: chain=%s detail=%s", consumer_chain, error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    if (plan.operation_count != 0U) *changed = true;
    return system_apply_local_bypass_plan(system, family, consumer_chain, &plan);
}

static int system_reconcile_iptables_local_family(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, bool *changed) {
    const struct asteriskd_private_chain_group *local_group = NULL;
    const struct asteriskd_private_chain_group *consumer_group = NULL;
    enum asteriskd_chain_id consumer_id = system->loaded_config.config.mode ==
        ASTERISKD_MODE_TPROXY ? ASTERISKD_CHAIN_TPROXY : ASTERISKD_CHAIN_ROUTING;
    for (size_t index = 0U; index < system->rules_runtime.plan.private_group_count; ++index) {
        const struct asteriskd_private_chain_group *group =
            &system->rules_runtime.plan.private_groups[index];
        if (group->family != family || group->table != ASTERISKD_IP_TABLE_MANGLE) continue;
        if (group->chain_id == ASTERISKD_CHAIN_LOCAL_BYPASS) local_group = group;
        else if (group->chain_id == consumer_id) consumer_group = group;
    }
    if (local_group == NULL || local_group->name_count != 2U || consumer_group == NULL) return -1;
    const char *begin_chain = NULL;
    const char *end_chain = NULL;
    for (size_t index = 0U; index < local_group->name_count; ++index) {
        const char *name = local_group->names[index];
        if (strstr(name, "_BEGIN") != NULL) begin_chain = name;
        else if (strstr(name, "_END") != NULL) end_chain = name;
    }
    if (begin_chain == NULL || end_chain == NULL) return -1;
    int address_family = family == ASTERISKD_IP_FAMILY_IPV4
        ? ASTERISKD_ADDRESS_IPV4 : ASTERISKD_ADDRESS_IPV6;
    const struct asteriskd_address_set *desired = family == ASTERISKD_IP_FAMILY_IPV4
        ? &system->local_ipv4_snapshot : &system->local_ipv6_snapshot;
    if (!system->local_address_snapshot_active || desired->family != address_family) return -1;
    for (size_t index = 0U; index < consumer_group->name_count; ++index) {
        const char *consumer = consumer_group->names[index];
        if (strstr(consumer, "PREROUTING") == NULL && strstr(consumer, "OUTPUT") == NULL) {
            continue;
        }
        if (system_reconcile_local_bypass_consumer(system, family, consumer,
                begin_chain, end_chain, desired, changed) != 0) return -1;
    }
    return 0;
}

/* changed[family] reports whether that family's mangle bypass rules were rewritten. */
int asteriskd_supervisor_reconcile_iptables_local_bypass(
    struct asteriskd_system_supervisor *system, bool *changed) {
    changed[ASTERISKD_IP_FAMILY_IPV4] = false;
    changed[ASTERISKD_IP_FAMILY_IPV6] = false;
    if (!system_uses_iptables_local_bypass(system)) return 0;
    if (!system->local_address_snapshot_active) return -1;
    // Every bypass change of both families is committed by one restore per family.
    if (asteriskd_supervisor_rule_batch_begin(&system->rule_commands) != 0) return -1;
    int result = system_reconcile_iptables_local_family(
            system, ASTERISKD_IP_FAMILY_IPV4, &changed[ASTERISKD_IP_FAMILY_IPV4]) == 0 &&
        (!system->loaded_config.config.enable_ipv6 || system_reconcile_iptables_local_family(
            system, ASTERISKD_IP_FAMILY_IPV6, &changed[ASTERISKD_IP_FAMILY_IPV6]) == 0) &&
        asteriskd_supervisor_rule_batch_flush(system) == 0 ? 0 : -1;
    asteriskd_supervisor_rule_batch_destroy(&system->rule_commands);
    return result;
}

int asteriskd_supervisor_reconcile_b2s_local_maps(
    struct asteriskd_system_supervisor *system) {
    if (system->loaded_config.config.mode != ASTERISKD_MODE_BPF2SOCKS) return 0;
    const struct asteriskd_bpf_map_backend *backend = asteriskd_system_bpf_map_backend();
    if (!system->b2s_verified || backend == NULL) return -1;
    struct asteriskd_address_set addresses;
    char error[128U] = {0};
    const char *family = "ipv4";
    const char *path = asteriskd_supervisor_pin_path(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4);
    uint64_t object_id = asteriskd_supervisor_verified_pin_id(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4);
    if (path == NULL || object_id == 0U ||
        asteriskd_supervisor_collect_local_address_set(
            system, ASTERISKD_ADDRESS_IPV4, &addresses) != 0 ||
        asteriskd_bpf_local_map_reconcile(backend, path, object_id,
            &addresses, error, sizeof(error)) != 0) goto failed;
    if (!system->loaded_config.config.enable_ipv6) return 0;
    family = "ipv6";
    path = asteriskd_supervisor_pin_path(system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6);
    object_id = asteriskd_supervisor_verified_pin_id(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6);
    if (path != NULL && object_id != 0U &&
        asteriskd_supervisor_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV6, &addresses) == 0 &&
        asteriskd_bpf_local_map_reconcile(backend, path, object_id,
            &addresses, error, sizeof(error)) == 0) return 0;

failed:
    {
        char message[224U];
        int written = snprintf(message, sizeof(message),
            "bpf2socks local address map reconcile failed: family=%s pin=%d detail=%s",
            family, path != NULL && object_id != 0U ? 1 : 0,
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_HELPER, message);
        }
    }
    return -1;
}

static bool system_hotspot_interface_selected(
    const struct asteriskd_config *config, const char *name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        if (asteriskd_interface_matches_selector(
                name, config->hotspot_interface_prefixes[index])) return true;
    }
    return false;
}

static int system_clear_android_hotspot_offload_interface(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t priority) {
    // Probed and removed over rtnetlink; no tc process per interface and priority.
    uint32_t interface_index = if_nametoindex(name);
    bool present = false;
    return interface_index == 0U ? -1 : asteriskd_supervisor_rtnl_tether_offload(
        system, interface_index, priority, true, &present);
}

static void system_log_optional_hotspot_offload_cleanup_failure(
    struct asteriskd_system_supervisor *system, const char *name, const char *priority) {
    char message[192U];
    int written = snprintf(message, sizeof(message),
        "optional Android IPv6 tethering offload cleanup failed%s%s%s%s; continuing",
        name != NULL ? " for " : "", name != NULL ? name : "",
        priority != NULL ? " pref " : "", priority != NULL ? priority : "");
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_WARNING,
            ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_CAPABILITY_ADJUSTED, message);
    }
}

static int system_clear_android_hotspot_offload(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_hotspot_ipv6_offload_policy policy) {
    bool required = policy == ASTERISKD_HOTSPOT_IPV6_OFFLOAD_REMOVE_PREF1_REQUIRED;
    static const uint32_t priorities[] = {1U, 2U};
    static const char *const priority_names[] = {"1", "2"};
    size_t priority_count = required ? 1U : 2U;
    DIR *directory = opendir("/sys/class/net");
    if (directory == NULL) {
        if (!required) system_log_optional_hotspot_offload_cleanup_failure(
            system, NULL, NULL);
        return required ? -1 : 0;
    }
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!system_hotspot_interface_selected(
                &system->loaded_config.config, entry->d_name)) continue;
        for (size_t priority = 0U; priority < priority_count; ++priority) {
            if (system_clear_android_hotspot_offload_interface(
                    system, entry->d_name, priorities[priority]) == 0) continue;
            if (required) {
                result = -1;
                break;
            }
            system_log_optional_hotspot_offload_cleanup_failure(
                system, entry->d_name, priority_names[priority]);
        }
        if (result != 0) break;
    }
    (void)closedir(directory);
    return result;
}

static int system_tc_slot_for_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_resource_operation *prototype,
    enum asteriskd_tc_slot_state *slot) {
    bool present = false;
    if (asteriskd_supervisor_tc_probe_qdisc(system, &prototype->resource.tc_qdisc, &present) != 0) return -1;
    if (!present) *slot = ASTERISKD_TC_SLOT_ABSENT;
    else *slot = ASTERISKD_TC_SLOT_COMPATIBLE;
    return 0;
}

static int system_tc_slot_for_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_resource_operation *prototype,
    enum asteriskd_tc_slot_state *slot) {
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (asteriskd_supervisor_tc_probe_filter(system, &prototype->resource.tc_filter, &state) != 0) return -1;
    if (state == ASTERISKD_RULES_SLOT_ABSENT) *slot = ASTERISKD_TC_SLOT_ABSENT;
    else if (state == ASTERISKD_RULES_SLOT_OWNED) {
        *slot = ASTERISKD_TC_SLOT_OWNED;
    } else {
        *slot = ASTERISKD_TC_SLOT_FOREIGN;
    }
    return 0;
}

static int system_tc_apply_record(struct asteriskd_system_supervisor *system,
    const struct asteriskd_resource_operation *prototype) {
    char error[128U];
    if (prototype->kind == ASTERISKD_RESOURCE_OPERATION_SYSCTL) {
        return asteriskd_supervisor_effect_apply_sysctl(
            system, &prototype->resource.sysctl, error, sizeof(error));
    }
    struct asteriskd_resource_operation record = *prototype;
    return asteriskd_supervisor_apply_and_verify(
        system, &record, 1U, error, sizeof(error));
}

static int system_reconcile_hotspot_tc_interface(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t index) {
    struct asteriskd_tc_interface_probe probe;
    memset(&probe, 0, sizeof(probe));
    if (snprintf(probe.interface_name, sizeof(probe.interface_name), "%s", name) <= 0) return -1;
    probe.interface_index = index;
    struct asteriskd_sysctl_resource sysctl;
    memset(&sysctl, 0, sizeof(sysctl));
    sysctl.sysctl_id = ASTERISKD_SYSCTL_ROUTE_LOCALNET;
    if (snprintf(sysctl.interface_name, sizeof(sysctl.interface_name), "%s", name) <= 0) return -1;
    sysctl.interface_index = index;
    if (asteriskd_supervisor_sysctl_read(&sysctl, &probe.route_localnet_value) != 0) return -1;

    struct asteriskd_resource_operation qdisc;
    memset(&qdisc, 0, sizeof(qdisc));
    qdisc.kind = ASTERISKD_RESOURCE_OPERATION_TC_QDISC;
    qdisc.resource.tc_qdisc.qdisc_id = ASTERISKD_QDISC_HOTSPOT_CLSACT;
    qdisc.resource.tc_qdisc.interface_index = index;
    (void)snprintf(qdisc.resource.tc_qdisc.interface_name,
        sizeof(qdisc.resource.tc_qdisc.interface_name), "%s", name);
    if (system_tc_slot_for_qdisc(system, &qdisc, &probe.qdisc) != 0) return -1;

    struct asteriskd_resource_operation filter;
    memset(&filter, 0, sizeof(filter));
    filter.kind = ASTERISKD_RESOURCE_OPERATION_TC_FILTER;
    filter.resource.tc_filter.interface_index = index;
    (void)snprintf(filter.resource.tc_filter.interface_name,
        sizeof(filter.resource.tc_filter.interface_name), "%s", name);
    filter.resource.tc_filter.filter_id = ASTERISKD_FILTER_HOTSPOT_EGRESS;
    filter.resource.tc_filter.direction = ASTERISKD_TC_DIRECTION_EGRESS;
    filter.resource.tc_filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS;
    if (system_tc_slot_for_filter(system, &filter, &probe.egress) != 0) return -1;
    filter.resource.tc_filter.filter_id = ASTERISKD_FILTER_HOTSPOT_INGRESS;
    filter.resource.tc_filter.direction = ASTERISKD_TC_DIRECTION_INGRESS;
    filter.resource.tc_filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS;
    if (system_tc_slot_for_filter(system, &filter, &probe.ingress) != 0) return -1;

    struct asteriskd_tc_plan plan;
    char error[128U];
    if (asteriskd_tc_install_plan_build(&system->loaded_config.config,
            &probe, &plan, error, sizeof(error)) != 0) return -1;
    for (size_t operation = 0U; operation < plan.operation_count; ++operation) {
        if (system_tc_apply_record(system, &plan.operations[operation].operation) != 0) return -1;
    }
    return 0;
}

int asteriskd_supervisor_reconcile_hotspot_tc(struct asteriskd_system_supervisor *system) {
    bool bpf2socks = system->loaded_config.config.mode == ASTERISKD_MODE_BPF2SOCKS;
    enum asteriskd_hotspot_ipv6_offload_policy offload_policy =
        asteriskd_hotspot_ipv6_offload_policy_for(&system->loaded_config.config);
    if (offload_policy != ASTERISKD_HOTSPOT_IPV6_OFFLOAD_KEEP &&
        system_clear_android_hotspot_offload(system, offload_policy) != 0) return -1;
    if (!bpf2socks) return 0;
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    char handled[ASTERISKD_MAX_ADDRESSES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t handled_count = 0U;
    int result = 0;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_name == NULL || !system_hotspot_interface_selected(
                &system->loaded_config.config, entry->ifa_name)) continue;
        bool duplicate = false;
        for (size_t index = 0U; index < handled_count; ++index) {
            if (strcmp(handled[index], entry->ifa_name) == 0) duplicate = true;
        }
        if (duplicate) continue;
        if (handled_count >= ASTERISKD_MAX_ADDRESSES) {
            result = -1;
            break;
        }
        uint32_t interface_index = if_nametoindex(entry->ifa_name);
        if (interface_index == 0U || snprintf(handled[handled_count],
                sizeof(handled[handled_count]), "%s", entry->ifa_name) <= 0 ||
            system_reconcile_hotspot_tc_interface(
                system, entry->ifa_name, interface_index) != 0) {
            result = -1;
            break;
        }
        ++handled_count;
    }
    freeifaddrs(addresses);
    return result;
}

#endif

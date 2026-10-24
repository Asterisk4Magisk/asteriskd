// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

static const char *system_xtables_path(enum asteriskd_ip_family family) {
    return family == ASTERISKD_IP_FAMILY_IPV4
        ? "iptables" : family == ASTERISKD_IP_FAMILY_IPV6
            ? "ip6tables" : NULL;
}

const char *asteriskd_supervisor_table_name(enum asteriskd_ip_table table) {
    static const char *const names[] = {"filter", "nat", "mangle"};
    return table >= ASTERISKD_IP_TABLE_FILTER && table < ASTERISKD_IP_TABLE_COUNT
        ? names[table] : NULL;
}

static const char *system_builtin_name(enum asteriskd_builtin_chain chain) {
    static const char *const names[] = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT"};
    return chain >= ASTERISKD_BUILTIN_PREROUTING && chain < ASTERISKD_BUILTIN_COUNT
        ? names[chain] : NULL;
}

int asteriskd_supervisor_xtables_run(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, bool capture_stdout, int *exit_status) {
    const char *executable = system_xtables_path(family);
    const char *table_name = asteriskd_supervisor_table_name(table);
    if (executable == NULL || table_name == NULL || operation == NULL || chain == NULL ||
        chain[0] == '\0' || (argument_count != 0U && arguments == NULL) ||
        argument_count > 24U || exit_status == NULL) return -1;
    const char *argv[32U];
    size_t count = 0U;
    argv[count++] = executable;
    argv[count++] = "-w";
    argv[count++] = "100";
    argv[count++] = "-t";
    argv[count++] = table_name;
    argv[count++] = operation;
    argv[count++] = chain;
    for (size_t index = 0U; index < argument_count; ++index) {
        if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
        argv[count++] = arguments[index];
    }
    argv[count] = NULL;
    return asteriskd_supervisor_action_run_argv(system, argv, capture_stdout, exit_status);
}

int asteriskd_supervisor_xtables(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, int *exit_status) {
    return asteriskd_supervisor_xtables_run(system, family, table, operation, chain,
        arguments, argument_count, false, exit_status);
}

static int system_xtables_table(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    enum asteriskd_ip_table table,
    int *exit_status) {
    const char *executable = system_xtables_path(family);
    const char *table_name = asteriskd_supervisor_table_name(table);
    if (executable == NULL || table_name == NULL || exit_status == NULL) return -1;
    const char *argv[] = {
        executable, "-w", "100", "-t", table_name, "-S", NULL,
    };
    return asteriskd_supervisor_action_run_argv(system, argv, true, exit_status);
}

int asteriskd_supervisor_xtables_zero(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count) {
    const char *effective_operation = operation;
    if (system->verify_private_rules) {
        if (strcmp(operation, "-A") != 0) return -1;
        effective_operation = "-C";
        if (system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
            system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) {
            const struct system_rule_view *view =
                &system->rule_snapshot.xtables[family][table];
            size_t matches = 0U;
            size_t position = 0U;
            if (!view->present || asteriskd_xtables_rule_output_locate(
                    view->bytes, view->length, chain, arguments, argument_count,
                    &matches, &position) != 0 || matches != 1U) return -1;
            ++system->verified_private_rule_count;
            return 0;
        }
    }
    if (system->rule_commands.active) {
        if (system->verify_private_rules || system_xtables_path(family) == NULL ||
            asteriskd_supervisor_table_name(table) == NULL ||
            argument_count > 24U || (argument_count != 0U && arguments == NULL)) return -1;
        // Queued as an iptables-restore line for the table's single commit.
        const char *tokens[28U];
        size_t count = 0U;
        tokens[count++] = operation;
        tokens[count++] = chain;
        for (size_t index = 0U; index < argument_count; ++index) {
            if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
            tokens[count++] = arguments[index];
        }
        tokens[count] = NULL;
        return asteriskd_supervisor_rule_batch_append_line(
            &system->rule_commands.xtables[system->rule_commands.ip_started ? 1U : 0U]
                [family][table], tokens);
    }
    int exit_status = -1;
    int run_result = asteriskd_supervisor_xtables(system, family, table, effective_operation, chain,
        arguments, argument_count, &exit_status);
    int result = run_result == 0 && exit_status == 0 ? 0 : -1;
    if (result != 0) {
        const char *table_name = asteriskd_supervisor_table_name(table);
        char stderr_summary[256U];
        asteriskd_supervisor_action_stderr_summary(system, stderr_summary, sizeof(stderr_summary));
        char message[512U];
        int written = snprintf(message, sizeof(message),
            "xtables command failed: family=%s table=%s operation=%s chain=%s runner=%d "
            "exitStatus=%d stderr=%s",
            family == ASTERISKD_IP_FAMILY_IPV6 ? "ipv6" : "ipv4",
            table_name == NULL ? "invalid" : table_name, effective_operation, chain,
            run_result, exit_status, run_result == 0 ? stderr_summary : "none");
        if (written > 0 && (size_t)written < sizeof(message)) {
            asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_RULES, message);
        }
    }
    if (result == 0 && system->verify_private_rules) {
        ++system->verified_private_rule_count;
    }
    return result;
}

static bool system_cidr_matches_family(
    const char *cidr, enum asteriskd_ip_family family) {
    return cidr != NULL && ((strchr(cidr, ':') != NULL) ==
        (family == ASTERISKD_IP_FAMILY_IPV6));
}

static int system_append_jump(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *target) {
    const char *arguments[] = {"-j", target};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 2U);
}

static int system_canonical_cidr(enum asteriskd_ip_family family,
    const char *cidr, char *canonical, size_t capacity) {
    if (cidr == NULL || canonical == NULL || capacity == 0U) return -1;
    const char *slash = strrchr(cidr, '/');
    size_t address_length = slash == NULL ? 0U : (size_t)(slash - cidr);
    if (address_length == 0U || address_length >= INET6_ADDRSTRLEN) return -1;
    char address[INET6_ADDRSTRLEN];
    memcpy(address, cidr, address_length);
    address[address_length] = '\0';
    int native_family = family == ASTERISKD_IP_FAMILY_IPV4 ? AF_INET : AF_INET6;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } parsed;
    char normalized[INET6_ADDRSTRLEN];
    if (inet_pton(native_family, address, &parsed) != 1 ||
        inet_ntop(native_family, &parsed, normalized, sizeof(normalized)) == NULL) return -1;
    int written = snprintf(canonical, capacity, "%s%s", normalized, slash);
    return written > 0 && (size_t)written < capacity ? 0 : -1;
}

static int system_append_return_cidr(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *cidr) {
    char canonical[ASTERISKD_MAX_CIDR];
    if (system_canonical_cidr(
            family, cidr, canonical, sizeof(canonical)) != 0) return -1;
    const char *arguments[] = {"-d", canonical, "-j", "RETURN"};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 4U);
}

static int system_append_return_interface(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool input, const char *name) {
    const char *arguments[] = {input ? "-i" : "-o", name, "-j", "RETURN"};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 4U);
}

static int system_dns_owner_direct(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *kind, const char *owner) {
    if (!system->loaded_config.config.dns_enhancement) return 0;
    for (unsigned protocol_index = 0; protocol_index < 2; ++protocol_index) {
        const char *protocol = protocol_index ? "tcp" : "udp";
        const char *args[] = {"-p", protocol, "-m", protocol, "--dport", "53", "-m", "mark",
            "--mark", ASTERISKD_DNS_PROXY_DECISION_MATCH, "-m", "owner", kind, owner, "-j", "MARK",
            "--set-xmark", ASTERISKD_DNS_DIRECT_MATCH};
        if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                chain, args, sizeof(args) / sizeof(args[0])) != 0)
            return -1;
    }
    return 0;
}

static int system_append_uid_return(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, uint32_t uid, bool forced) {
    if (!forced) {
        // Forced bypass already returned this UID before DNS and ordinary routing.
        const struct asteriskd_config *config = &system->loaded_config.config;
        for (size_t i = 0U; i < config->bypass_uid_count; ++i)
            if (config->bypass_uids[i] == uid) return 0;
    }
    char uid_text[16U];
    if (snprintf(uid_text, sizeof(uid_text), "%" PRIu32, uid) <= 0) return -1;
    if (forced && system_dns_owner_direct(system,family,chain,"--uid-owner",uid_text) != 0) return -1;
    const char *arguments[] = {"-m", "owner", "--uid-owner", uid_text, "-j", "RETURN"};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 6U);
}

static int system_append_gid_return(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    if (system_dns_owner_direct(system,family,chain,"--gid-owner","3005") != 0) return -1;
    const char *arguments[] = {"-m", "owner", "--gid-owner", "3005", "-j", "RETURN"};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 6U);
}

static int system_append_ipsec_udp_bypass(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    const char *ike_arguments[] = {"-p", "udp", "-m", "udp", "--dport", "500", "-j", "RETURN"};
    const char *nat_t_arguments[] = {"-p", "udp", "-m", "udp", "--dport", "4500", "-j", "RETURN"};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
            "-A", chain, ike_arguments, 8U) == 0 &&
        asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
            "-A", chain, nat_t_arguments, 8U) == 0 ? 0 : -1;
}

static int system_append_mark(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *protocol,
    const char *uid, const char *input_interface, const char *destination,
    const char *bpf_path) {
    const char *arguments[24U];
    size_t count = 0U;
    char canonical_destination[ASTERISKD_MAX_CIDR];
    if (destination != NULL) {
        if (system_canonical_cidr(family, destination, canonical_destination,
                sizeof(canonical_destination)) != 0) return -1;
        arguments[count++] = "-d";
        arguments[count++] = canonical_destination;
    }
    if (input_interface != NULL) {
        arguments[count++] = "-i";
        arguments[count++] = input_interface;
    }
    arguments[count++] = "-p";
    arguments[count++] = protocol;
    if (uid != NULL) {
        arguments[count++] = "-m";
        arguments[count++] = "owner";
        arguments[count++] = "--uid-owner";
        arguments[count++] = uid;
    }
    if (bpf_path != NULL) {
        arguments[count++] = "-m";
        arguments[count++] = "bpf";
        arguments[count++] = "--object-pinned";
        arguments[count++] = bpf_path;
    }
    arguments[count++] = "-j";
    arguments[count++] = "MARK";
    arguments[count++] = "--set-xmark";
    arguments[count++] = ASTERISKD_ROUTE_MATCH;
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, count);
}

static int system_append_tproxy(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *protocol,
    const char *input_interface, const char *destination, bool require_mark,
    const char *bpf_path) {
    char port[8U];
    if (snprintf(port, sizeof(port), "%u",
            (unsigned)system->loaded_config.config.transparent_port) <= 0) return -1;
    const char *arguments[24U];
    size_t count = 0U;
    char canonical_destination[ASTERISKD_MAX_CIDR];
    if (destination != NULL) {
        if (system_canonical_cidr(family, destination, canonical_destination,
                sizeof(canonical_destination)) != 0) return -1;
        arguments[count++] = "-d";
        arguments[count++] = canonical_destination;
    }
    if (input_interface != NULL) {
        arguments[count++] = "-i";
        arguments[count++] = input_interface;
    }
    arguments[count++] = "-p";
    arguments[count++] = protocol;
    if (require_mark) {
        arguments[count++] = "-m";
        arguments[count++] = "mark";
        arguments[count++] = "--mark";
        arguments[count++] = ASTERISKD_ROUTE_MATCH;
    }
    if (bpf_path != NULL) {
        arguments[count++] = "-m";
        arguments[count++] = "bpf";
        arguments[count++] = "--object-pinned";
        arguments[count++] = bpf_path;
    }
    arguments[count++] = "-j";
    arguments[count++] = "TPROXY";
    arguments[count++] = "--on-port";
    arguments[count++] = port;
    arguments[count++] = "--on-ip";
    arguments[count++] = family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::";
    arguments[count++] = "--tproxy-mark";
    arguments[count++] = ASTERISKD_ROUTE_MATCH;
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, count);
}

static int system_append_dns_mark_protocol(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool bypass_core_gid,
    const char *protocol) {
    const char *plain[] = {"-p", protocol, "-m", protocol, "--dport", "53",
        "-j", "MARK", "--set-xmark", ASTERISKD_ROUTE_MATCH};
    const char *bypass[] = {"-p", protocol, "-m", "owner", "!", "--gid-owner", "3005",
        "-m", protocol, "--dport", "53", "-j", "MARK", "--set-xmark",
        ASTERISKD_DNS_PROXY_ROUTE_MATCH};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, bypass_core_gid ? bypass : plain,
        bypass_core_gid ? sizeof(bypass) / sizeof(bypass[0]) :
            sizeof(plain) / sizeof(plain[0]));
}

static int system_append_dns_mark(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool bypass_core_gid) {
    return system_append_dns_mark_protocol(system, family, chain, bypass_core_gid, "udp") == 0 &&
        system_append_dns_mark_protocol(system, family, chain, bypass_core_gid, "tcp") == 0 ? 0 : -1;
}

static int system_append_established_tcp6_dns(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *input_interface,
    bool require_mark) {
    if (family != ASTERISKD_IP_FAMILY_IPV6) return 0;
    // The SYN already created a request socket under the original DNS tuple.
    // Let TCP receive later packets directly: old IPv6 kernels leave the
    // request's no_srccheck unset, so TPROXY can drop its completing ACK.
    // Require a tuple socket: older kernels keep requests only on the listener.
    const char *match[] = {"-p", "tcp", "-m", "tcp", "--dport", "53",
        "!", "--tcp-flags", "FIN,SYN,RST,ACK", "SYN",
        "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "socket"};
    const char *arguments[24];
    size_t count = 0U;
    if (input_interface != NULL) {
        arguments[count++] = "-i"; arguments[count++] = input_interface;
    }
    memcpy(arguments + count, match, sizeof(match));
    count += sizeof(match) / sizeof(match[0]);
    if (require_mark) {
        arguments[count++] = "-m"; arguments[count++] = "mark";
        arguments[count++] = "--mark"; arguments[count++] = ASTERISKD_ROUTE_MATCH;
    } else {
        // Forwarded DNS has no OUTPUT mark; retain local routing when skipping TPROXY.
        const char *mark[] = {"-j", "MARK", "--set-xmark", ASTERISKD_ROUTE_MATCH};
        memcpy(arguments + count, mark, sizeof(mark));
        if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
                "-A", chain, arguments, count + 4U) != 0) return -1;
    }
    arguments[count++] = "-j"; arguments[count++] = "RETURN";
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, count);
}

static int system_append_dns_tproxy(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    char port[8U];
    if (snprintf(port, sizeof(port), "%u",
            (unsigned)system->loaded_config.config.transparent_port) <= 0) return -1;
    const char *arguments[] = {"-p", "udp", "-m", "udp", "--dport", "53",
        "-j", "TPROXY", "--on-port", port, "--on-ip",
        family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::",
        "--tproxy-mark", ASTERISKD_ROUTE_MATCH};
    if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
            "-A", chain, arguments, sizeof(arguments) / sizeof(arguments[0])) != 0) return -1;
    if (system_append_established_tcp6_dns(system, family, chain, NULL, false) != 0) return -1;
    const char *tcp[] = {"-p", "tcp", "-m", "tcp", "--dport", "53",
        "-j", "TPROXY", "--on-port", port, "--on-ip",
        family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::",
        "--tproxy-mark", ASTERISKD_ROUTE_MATCH};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, tcp, sizeof(tcp) / sizeof(tcp[0]));
}

static int system_populate_local_chain(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    int address_family = family == ASTERISKD_IP_FAMILY_IPV4
        ? ASTERISKD_ADDRESS_IPV4 : ASTERISKD_ADDRESS_IPV6;
    struct asteriskd_address_set live;
    const struct asteriskd_address_set *set = NULL;
    if (system->local_address_snapshot_active) {
        set = family == ASTERISKD_IP_FAMILY_IPV4
            ? &system->local_ipv4_snapshot : &system->local_ipv6_snapshot;
    } else if (asteriskd_supervisor_collect_local_address_set(system, address_family, &live) == 0) {
        set = &live;
    }
    if (set == NULL || set->family != address_family) return -1;
    char cidr[ASTERISKD_MAX_CIDR];
    for (size_t index = 0U; index < set->count; ++index) {
        int written = snprintf(cidr, sizeof(cidr), "%s/%u", set->values[index],
            family == ASTERISKD_IP_FAMILY_IPV4 ? 32U : 128U);
        if (written <= 0 || (size_t)written >= sizeof(cidr) ||
            system_append_return_cidr(system, family, chain, cidr) != 0) return -1;
    }
    return 0;
}

static int system_append_local_bypass_interval(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    const char *consumer_chain,
    const char *local_begin,
    const char *local_end) {
    return system_append_jump(system, family, consumer_chain, local_begin) == 0 &&
        system_populate_local_chain(system, family, consumer_chain) == 0 &&
        system_append_jump(system, family, consumer_chain, local_end) == 0 ? 0 : -1;
}

static int system_append_policy_output(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (config->matcher.enabled) {
        if (!config->dns_enhancement && system_append_gid_return(system, family, chain) != 0) return -1;
        enum asteriskd_pin_id pin = family == ASTERISKD_IP_FAMILY_IPV4
            ? ASTERISKD_PIN_MATCHER_OUTPUT_V4 : ASTERISKD_PIN_MATCHER_OUTPUT_V6;
        const char *path = asteriskd_supervisor_pin_path(system, pin);
        return path != NULL &&
            system_append_mark(system, family, chain, "tcp", NULL, NULL, NULL, path) == 0 &&
            system_append_mark(system, family, chain, "udp", NULL, NULL, NULL, path) == 0 ? 0 : -1;
    }
    if (!config->dns_enhancement && system_append_gid_return(system, family, chain) != 0) return -1;
    if (config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST) {
        for (size_t index = 0U; index < config->uid_count + 2U; ++index) {
            uint32_t uid = index < config->uid_count ? config->uids[index] :
                index == config->uid_count ? 0U : 1052U;
            char uid_text[16U];
            if (snprintf(uid_text, sizeof(uid_text), "%" PRIu32, uid) <= 0 ||
                system_append_mark(system, family, chain, "tcp", uid_text,
                    NULL, NULL, NULL) != 0 ||
                system_append_mark(system, family, chain, "udp", uid_text,
                    NULL, NULL, NULL) != 0) return -1;
        }
        return 0;
    }
    return system_append_mark(system, family, chain, "tcp", NULL, NULL, NULL, NULL) == 0 &&
        system_append_mark(system, family, chain, "udp", NULL, NULL, NULL, NULL) == 0 ? 0 : -1;
}

/* Resolver decisions terminate before ordinary application routing. */
static int system_dns_output_rule(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *protocol, const char *mark,
    const char *uid, bool select) {
    const char *args[20];
    size_t count = 0;
    args[count++] = "-p";
    args[count++] = protocol;
    args[count++] = "-m";
    args[count++] = protocol;
    args[count++] = "--dport";
    args[count++] = "53";
    if (mark) {
        args[count++] = "-m";
        args[count++] = "mark";
        args[count++] = "--mark";
        args[count++] = mark;
    }
    if (uid) {
        args[count++] = "-m";
        args[count++] = "owner";
        args[count++] = "--uid-owner";
        args[count++] = uid;
    }
    args[count++] = "-j";
    args[count++] = select ? "MARK" : "RETURN";
    if (select) {
        args[count++] = "--set-xmark";
        args[count++] = ASTERISKD_ROUTE_MATCH;
    }
    return asteriskd_supervisor_xtables_zero(
        system, family, ASTERISKD_IP_TABLE_MANGLE, "-A", chain, args, count);
}

static int system_enhanced_dns_output(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    const char *uid_chain =
        family == ASTERISKD_IP_FAMILY_IPV4 ? "ASTERISK_DNS_UID4" : "ASTERISK_DNS_UID6";
    for (unsigned protocol_index = 0; protocol_index < 2; ++protocol_index) {
        const char *protocol = protocol_index ? "tcp" : "udp";
        // The module already supplied the final proxy or direct mark.
        if (system_dns_output_rule(
                system, family, chain, protocol, ASTERISKD_DNS_CLASSIFIED_MATCH, NULL, false) != 0)
            return -1;
        // AID_DNS_TETHER forces both DNS transports after explicit marks and forced bypasses.
        if (system_dns_output_rule(system, family, chain, protocol, NULL, "1052", true) != 0 ||
            system_dns_output_rule(system, family, chain, protocol, NULL, "1052", false) != 0)
            return -1;
        // Application DNS uses the same early route as resolver DNS, but its
        // socket UID selects proxy/direct independently of destination CIDRs.
        if (config->matcher.enabled) {
            const char *path = asteriskd_supervisor_pin_path(system, ASTERISKD_PIN_MATCHER_DNS_UID);
            const char *select[] = {"-p", protocol, "-m", protocol, "--dport", "53", "-m", "bpf",
                "--object-pinned", path, "-j", "MARK", "--set-xmark",
                ASTERISKD_DNS_PROXY_ROUTE_MATCH};
            if (path == NULL ||
                asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                    chain, select, sizeof(select) / sizeof(select[0])) != 0)
                return -1;
            const char *direct[] = {"-p", protocol, "-m", protocol, "--dport", "53", "-m", "mark",
                "!", "--mark", ASTERISKD_DNS_PROXY_ROUTE_MATCH, "-j", "MARK", "--set-xmark",
                ASTERISKD_DNS_DIRECT_MATCH};
            if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                    chain, direct, sizeof(direct) / sizeof(direct[0])) != 0)
                return -1;
            // Direct DNS must not be selected again by ordinary forced-CIDR rules.
            if (system_dns_output_rule(system, family, chain, protocol, NULL, NULL, false) != 0)
                return -1;
        } else {
            // Goto returns to OUTPUT after UID classification, skipping application routing.
            const char *jump[] = {"-p", protocol, "-m", protocol, "--dport", "53", "-g", uid_chain};
            if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                    chain, jump, sizeof(jump) / sizeof(jump[0])) != 0)
                return -1;
        }
    }
    return 0;
}

static int system_populate_dns_uid_chain(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    bool whitelist = config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST;
    if (config->app_policy_mode != ASTERISKD_APP_POLICY_GLOBAL) {
        const char *direct[] = {"-j", "MARK", "--set-xmark", ASTERISKD_DNS_DIRECT_MATCH};
        if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                chain, direct, sizeof(direct) / sizeof(direct[0])) != 0)
            return -1;
        size_t count = config->uid_count + (whitelist ? 2U : 0U);
        for (size_t i = 0; i < count; ++i) {
            uint32_t uid = i < config->uid_count ? config->uids[i]
                : i == config->uid_count         ? 0U
                                                 : 1052U;
            char text[16];
            if (snprintf(text, sizeof(text), "%" PRIu32, uid) <= 0) return -1;
            const char *args[] = {"-m", "owner", "--uid-owner", text, "-j",
                whitelist ? "MARK" : "RETURN", "--set-xmark", ASTERISKD_DNS_PROXY_ROUTE_MATCH};
            if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                    chain, args, whitelist ? 8U : 6U) != 0)
                return -1;
        }
    }
    if (whitelist) return 0;
    const char *proxy[] = {"-j", "MARK", "--set-xmark", ASTERISKD_DNS_PROXY_ROUTE_MATCH};
    return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A", chain,
        proxy, sizeof(proxy) / sizeof(proxy[0]));
}

static int system_enhanced_dns_prerouting(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool tproxy) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    char port[8];
    snprintf(port, sizeof(port), "%u", config->transparent_port);
    for (unsigned protocol_index = 0; protocol_index < 2; ++protocol_index) {
        const char *protocol = protocol_index ? "tcp" : "udp";
        if (system_dns_output_rule(
                system, family, chain, protocol, ASTERISKD_DNS_DIRECT_MATCH, NULL, false) != 0)
            return -1;
        if (tproxy && protocol_index &&
            system_append_established_tcp6_dns(system, family, chain, "lo", true) != 0)
            return -1;
        const char *args[] = {"-i", "lo", "-p", protocol, "-m", protocol, "--dport", "53", "-m",
            "mark", "--mark", ASTERISKD_ROUTE_MATCH, "-j", "TPROXY", "--on-port", port, "--on-ip",
            family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::", "--tproxy-mark",
            ASTERISKD_ROUTE_MATCH};
        if (tproxy &&
            asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                chain, args, sizeof(args) / sizeof(args[0])) != 0)
            return -1;
        const char *local[] = {
            "-i", "lo", "-p", protocol, "-m", protocol, "--dport", "53", "-j", "RETURN"};
        if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE, "-A",
                chain, local, sizeof(local) / sizeof(local[0])) != 0)
            return -1;
    }
    // Hotspot DNS uses both transports; local unmarked queries already returned.
    for (size_t i = 0; i < config->hotspot_interface_prefix_count; ++i) {
        for (unsigned protocol_index = 0; protocol_index < 2; ++protocol_index) {
            const char *protocol = protocol_index ? "tcp" : "udp";
            if (tproxy && protocol_index &&
                system_append_established_tcp6_dns(
                    system, family, chain, config->hotspot_interface_prefixes[i], false) != 0)
                return -1;
            const char *args[20] = {"-i", config->hotspot_interface_prefixes[i], "-p", protocol,
                "-m", protocol, "--dport", "53", "-j"};
            size_t count = 9;
            if (tproxy) {
                args[count++] = "TPROXY";
                args[count++] = "--on-port";
                args[count++] = port;
                args[count++] = "--on-ip";
                args[count++] = family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::";
                args[count++] = "--tproxy-mark";
                args[count++] = ASTERISKD_ROUTE_MATCH;
            } else {
                args[count++] = "MARK";
                args[count++] = "--set-xmark";
                args[count++] = ASTERISKD_ROUTE_MATCH;
            }
            if (asteriskd_supervisor_xtables_zero(
                    system, family, ASTERISKD_IP_TABLE_MANGLE, "-A", chain, args, count) != 0)
                return -1;
        }
    }
    return 0;
}

static int system_populate_common_output_prefix(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (config->dns_enhancement && system_append_gid_return(system, family, chain) != 0) return -1;
    if (system_append_ipsec_udp_bypass(system, family, chain) != 0) return -1;
    for (size_t remaining = config->bypass_uid_count; remaining > 0U; --remaining) {
        if (system_append_uid_return(system, family, chain,
                config->bypass_uids[remaining - 1U], true) != 0) return -1;
    }
    if (config->dns_enhancement && system_enhanced_dns_output(system, family, chain) != 0) return -1;
    if (config->enable_local_dns && !config->dns_enhancement && system_append_dns_mark(system, family, chain, true) != 0) {
        return -1;
    }
    if (system_append_local_bypass_interval(
            system, family, chain, local_begin, local_end) != 0) return -1;
    for (size_t remaining = config->proxy_private_cidr_count; remaining > 0U; --remaining) {
        const char *cidr = config->proxy_private_cidrs[remaining - 1U];
        if (!system_cidr_matches_family(cidr, family)) continue;
        if (system_append_mark(system, family, chain, "tcp", NULL, NULL, cidr, NULL) != 0 ||
            system_append_mark(system, family, chain, "udp", NULL, NULL, cidr, NULL) != 0) return -1;
    }
    for (size_t index = 0U; index < config->bypass_private_cidr_count; ++index) {
        const char *cidr = config->bypass_private_cidrs[index];
        if (system_cidr_matches_family(cidr, family) &&
            system_append_return_cidr(system, family, chain, cidr) != 0) return -1;
    }
    return 0;
}

static int system_populate_tproxy_prerouting(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (config->dns_enhancement && system_enhanced_dns_prerouting(system, family, chain, true) != 0) return -1;
    if (config->enable_local_dns && !config->dns_enhancement && system_append_dns_tproxy(system, family, chain) != 0) return -1;
    if (family == ASTERISKD_IP_FAMILY_IPV6 && !config->enable_ipv6) return 0;
    if (system_append_ipsec_udp_bypass(system, family, chain) != 0) return -1;
    if (system_append_local_bypass_interval(
            system, family, chain, local_begin, local_end) != 0) return -1;
    for (size_t prefix_remaining = config->hotspot_interface_prefix_count;
         prefix_remaining > 0U; --prefix_remaining) {
        const char *interface_name = config->hotspot_interface_prefixes[prefix_remaining - 1U];
        for (size_t cidr_remaining = config->proxy_private_cidr_count;
             cidr_remaining > 0U; --cidr_remaining) {
            const char *cidr = config->proxy_private_cidrs[cidr_remaining - 1U];
            if (!system_cidr_matches_family(cidr, family)) continue;
            if (system_append_tproxy(system, family, chain, "udp", interface_name,
                    cidr, false, NULL) != 0 ||
                system_append_tproxy(system, family, chain, "tcp", interface_name,
                    cidr, false, NULL) != 0) return -1;
        }
    }
    for (size_t remaining = config->proxy_private_cidr_count; remaining > 0U; --remaining) {
        const char *cidr = config->proxy_private_cidrs[remaining - 1U];
        if (!system_cidr_matches_family(cidr, family)) continue;
        if (system_append_tproxy(system, family, chain, "udp", NULL,
                cidr, true, NULL) != 0 ||
            system_append_tproxy(system, family, chain, "tcp", NULL,
                cidr, true, NULL) != 0) return -1;
    }
    for (size_t index = 0U; index < config->bypass_private_cidr_count; ++index) {
        const char *cidr = config->bypass_private_cidrs[index];
        if (system_cidr_matches_family(cidr, family) &&
            system_append_return_cidr(system, family, chain, cidr) != 0) return -1;
    }
    if (system_append_tproxy(system, family, chain, "tcp", NULL, NULL, true, NULL) != 0 ||
        system_append_tproxy(system, family, chain, "udp", NULL, NULL, true, NULL) != 0) return -1;
    const char *matcher_path = NULL;
    if (config->matcher.enabled) {
        matcher_path = asteriskd_supervisor_pin_path(system, family == ASTERISKD_IP_FAMILY_IPV4
            ? ASTERISKD_PIN_MATCHER_PREROUTING_V4 : ASTERISKD_PIN_MATCHER_PREROUTING_V6);
        if (matcher_path == NULL) return -1;
    }
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        const char *interface_name = config->hotspot_interface_prefixes[index];
        if (system_append_tproxy(system, family, chain, "tcp", interface_name,
                NULL, false, matcher_path) != 0 ||
            system_append_tproxy(system, family, chain, "udp", interface_name,
                NULL, false, matcher_path) != 0) return -1;
    }
    return 0;
}

static int system_populate_tproxy_output(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *local_begin,
    const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (family == ASTERISKD_IP_FAMILY_IPV6 && !config->enable_ipv6) {
        if (!config->dns_enhancement && !config->enable_local_dns) return 0;
        if (system_append_gid_return(system, family, chain) != 0) return -1;
        for (size_t i = 0; i < config->bypass_uid_count; ++i)
            if (system_append_uid_return(system, family, chain, config->bypass_uids[i], true) != 0)
                return -1;
        if (!config->dns_enhancement) return system_append_dns_mark(system, family, chain, true);
        return system_enhanced_dns_output(system, family, chain);
    }
    if (system_populate_common_output_prefix(system, family, chain, local_begin, local_end) != 0)
        return -1;
    if (!config->matcher.enabled && config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST) {
        for (size_t remaining = config->uid_count; remaining > 0U; --remaining) {
            if (system_append_uid_return(
                    system, family, chain, config->uids[remaining - 1U], false) != 0)
                return -1;
        }
    }
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (system_append_return_interface(
                system, family, chain, false, config->ignored_interfaces[index]) != 0)
            return -1;
    }
    return system_append_policy_output(system, family, chain);
}

static int system_populate_tun_prerouting(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (config->dns_enhancement && system_enhanced_dns_prerouting(system, family, chain, false) != 0) return -1;
    if (config->enable_local_dns && !config->dns_enhancement && system_append_dns_mark(system, family, chain, false) != 0) {
        return -1;
    }
    if (family == ASTERISKD_IP_FAMILY_IPV6 && !config->enable_ipv6) return 0;
    if (system_append_ipsec_udp_bypass(system, family, chain) != 0) return -1;
    if (system_append_local_bypass_interval(
            system, family, chain, local_begin, local_end) != 0) return -1;
    for (size_t remaining = config->proxy_private_cidr_count; remaining > 0U; --remaining) {
        const char *cidr = config->proxy_private_cidrs[remaining - 1U];
        if (!system_cidr_matches_family(cidr, family)) continue;
        if (system_append_mark(system, family, chain, "tcp", NULL, NULL, cidr, NULL) != 0 ||
            system_append_mark(system, family, chain, "udp", NULL, NULL, cidr, NULL) != 0) return -1;
    }
    for (size_t index = 0U; index < config->bypass_private_cidr_count; ++index) {
        const char *cidr = config->bypass_private_cidrs[index];
        if (system_cidr_matches_family(cidr, family) &&
            system_append_return_cidr(system, family, chain, cidr) != 0) return -1;
    }
    const char *matcher_path = NULL;
    if (config->matcher.enabled) {
        matcher_path = asteriskd_supervisor_pin_path(system, family == ASTERISKD_IP_FAMILY_IPV4
            ? ASTERISKD_PIN_MATCHER_PREROUTING_V4 : ASTERISKD_PIN_MATCHER_PREROUTING_V6);
        if (matcher_path == NULL) return -1;
    }
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        const char *interface_name = config->hotspot_interface_prefixes[index];
        if (system_append_mark(system, family, chain, "tcp", NULL,
                interface_name, NULL, matcher_path) != 0 ||
            system_append_mark(system, family, chain, "udp", NULL,
                interface_name, NULL, matcher_path) != 0) return -1;
    }
    return 0;
}

static int system_populate_tun_output(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, const char *local_begin,
    const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    const char *tunnel = config->helper.value.hev.tunnel_name;
    if (family == ASTERISKD_IP_FAMILY_IPV6 && !config->enable_ipv6) {
        if (!config->dns_enhancement && !config->enable_local_dns) return 0;
        if (system_append_gid_return(system, family, chain) != 0) return -1;
        for (size_t i = 0; i < config->bypass_uid_count; ++i)
            if (system_append_uid_return(system, family, chain, config->bypass_uids[i], true) != 0)
                return -1;
        if (!config->dns_enhancement) return system_append_dns_mark(system, family, chain, true);
        return system_enhanced_dns_output(system, family, chain);
    }
    if (system_populate_common_output_prefix(system, family, chain, local_begin, local_end) != 0)
        return -1;
    if (!config->matcher.enabled && config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST) {
        for (size_t remaining = config->uid_count; remaining > 0U; --remaining) {
            if (system_append_uid_return(
                    system, family, chain, config->uids[remaining - 1U], false) != 0)
                return -1;
        }
    }
    if (system_append_return_interface(system, family, chain, false, tunnel) != 0) return -1;
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (system_append_return_interface(
                system, family, chain, false, config->ignored_interfaces[index]) != 0)
            return -1;
    }
    return system_append_policy_output(system, family, chain);
}

static int system_populate_private_chain(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group, const char *chain) {
    enum asteriskd_ip_family family = group->family;
    if (strcmp(chain, "ASTERISK_DNS_UID4") == 0 || strcmp(chain, "ASTERISK_DNS_UID6") == 0)
        return system_populate_dns_uid_chain(system, family, chain);
    const char *local_begin = family == ASTERISKD_IP_FAMILY_IPV4
        ? "ASTERISK_LOCAL4_BEGIN" : "ASTERISK_LOCAL6_BEGIN";
    const char *local_end = family == ASTERISKD_IP_FAMILY_IPV4
        ? "ASTERISK_LOCAL4_END" : "ASTERISK_LOCAL6_END";
    if (group->chain_id == ASTERISKD_CHAIN_LOCAL_BYPASS) {
        return 0;
    }
    if (group->chain_id == ASTERISKD_CHAIN_TPROXY) {
        if (strstr(chain, "PREROUTING") != NULL) {
            return system_populate_tproxy_prerouting(
                system, family, chain, local_begin, local_end);
        }
        if (strstr(chain, "OUTPUT") != NULL) {
            return system_populate_tproxy_output(system, family, chain,
                local_begin, local_end);
        }
        return -1;
    }
    if (group->chain_id == ASTERISKD_CHAIN_ROUTING) {
        if (strstr(chain, "PREROUTING") != NULL) {
            return system_populate_tun_prerouting(
                system, family, chain, local_begin, local_end);
        }
        if (strstr(chain, "OUTPUT") != NULL) {
            return system_populate_tun_output(system, family, chain, local_begin, local_end);
        }
        if (strstr(chain, "FORWARD") != NULL) {
            const struct asteriskd_config *config = &system->loaded_config.config;
            const char *tunnel = config->helper.value.hev.tunnel_name;
            bool dns_only = family == ASTERISKD_IP_FAMILY_IPV6 && !config->enable_ipv6;
            const char *input[] = {"-i", tunnel, "-j", "ACCEPT"};
            const char *output[] = {"-o", tunnel, "-j", "ACCEPT"};
            const char *dns_input[] = {
                "-i", tunnel, "-p", "udp", "-m", "udp", "--sport", "53", "-j", "ACCEPT",
            };
            const char *dns_output[] = {
                "-o", tunnel, "-p", "udp", "-m", "udp", "--dport", "53", "-j", "ACCEPT",
            };
            if (asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_FILTER,
                "-A", chain, dns_only ? dns_input : input, dns_only ? 10U : 4U) == 0 &&
                asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_FILTER,
                    "-A", chain, dns_only ? dns_output : output, dns_only ? 10U : 4U) == 0) {
                if (!dns_only) return 0;
                const char *tcp_input[] = {"-i", tunnel, "-p", "tcp", "-m", "tcp", "--sport", "53", "-j", "ACCEPT"};
                const char *tcp_output[] = {"-o", tunnel, "-p", "tcp", "-m", "tcp", "--dport", "53", "-j", "ACCEPT"};
                return asteriskd_supervisor_xtables_zero(system, family, ASTERISKD_IP_TABLE_FILTER,
                    "-A", chain, tcp_input, 10U) == 0 && asteriskd_supervisor_xtables_zero(system, family,
                    ASTERISKD_IP_TABLE_FILTER, "-A", chain, tcp_output, 10U) == 0 ? 0 : -1;
            }
            return -1;
        }
        return -1;
    }
    if (group->chain_id == ASTERISKD_CHAIN_FAKE_DNS) {
        const char *pool = system->loaded_config.config.fake_dns_ipv4_pool;
        const char *arguments[10U];
        size_t argument_count = asteriskd_xtables_fake_dns_arguments(pool, arguments);
        if (argument_count == 0U) return -1;
        return asteriskd_supervisor_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV4,
            ASTERISKD_IP_TABLE_NAT, "-A", chain, arguments,
            argument_count);
    }
    return -1;
}

int asteriskd_supervisor_create_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group) {
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                "-N", group->names[index], NULL, 0U) != 0) return -1;
    }
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (system_populate_private_chain(system, group, group->names[index]) != 0) return -1;
    }
    return 0;
}

static int system_verify_private_chain_contents(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group,
    const char *chain) {
    if (system->verify_private_rules) return -1;
    system->verify_private_rules = true;
    system->verified_private_rule_count = 0U;
    int populated = system_populate_private_chain(system, group, chain);
    size_t expected_rule_count = system->verified_private_rule_count;
    system->verify_private_rules = false;
    system->verified_private_rule_count = 0U;
    if (populated != 0) return -1;

    const char *observed = system->action_stdout;
    size_t observed_length = system->action_stdout_length;
    bool snapshot_active =
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY;
    if (snapshot_active) {
        const struct system_rule_view *view =
            &system->rule_snapshot.xtables[group->family][group->table];
        if (!view->present) return -1;
        observed = view->bytes;
        observed_length = view->length;
    } else {
        int exit_status = -1;
        if (asteriskd_supervisor_xtables_run(system, group->family, group->table,
                "-S", chain, NULL, 0U, true, &exit_status) != 0 ||
            exit_status != 0 || system->action_stdout_overflow) return -1;
        observed = system->action_stdout;
        observed_length = system->action_stdout_length;
    }
    if (asteriskd_xtables_private_chain_shape_valid(
            observed, observed_length,
            chain, expected_rule_count)) return 0;
    char message[256U];
    int written = snprintf(message, sizeof(message),
        "private chain shape mismatch: chain=%s expectedRules=%zu outputBytes=%zu",
        chain, expected_rule_count, observed_length);
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
            ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
    }
    return -1;
}

int asteriskd_supervisor_verify_private_group_contents(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group) {
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (system_verify_private_chain_contents(
                system, group, group->names[index]) != 0) return -1;
    }
    return 0;
}

int asteriskd_supervisor_remove_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group) {
    int result = 0;
    bool snapshot_active =
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY;
    const struct system_rule_view *view =
        &system->rule_snapshot.xtables[group->family][group->table];
    for (size_t remaining = group->name_count; remaining > 0U; --remaining) {
        const char *name = group->names[remaining - 1U];
        if (snapshot_active) {
            size_t declarations = 0U;
            size_t rules = 0U;
            if (!view->present || asteriskd_xtables_private_chain_counts(
                    view->bytes, view->length, name,
                    &declarations, &rules) != 0 || declarations > 1U) {
                result = -1;
                continue;
            }
            if (declarations == 0U && rules == 0U) continue;
            if (declarations != 1U) {
                result = -1;
                continue;
            }
        } else {
            int exit_status = -1;
            if (asteriskd_supervisor_xtables(system, group->family, group->table,
                    "-S", name, NULL, 0U, &exit_status) != 0) {
                result = -1;
                continue;
            }
            if (exit_status == 1) continue;
            if (exit_status != 0) {
                result = -1;
                continue;
            }
        }
        if (asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                "-F", name, NULL, 0U) != 0 ||
            asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                "-X", name, NULL, 0U) != 0) result = -1;
    }
    return result;
}

int asteriskd_supervisor_apply_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group) {
    for (size_t index = 0U; index < group->hook_count; ++index) {
        const struct asteriskd_traffic_hook *hook = &group->hooks[index];
        const char *chain = system_builtin_name(hook->builtin_chain);
        const char *arguments[ASTERISKD_XTABLES_MAX_HOOK_ARGUMENTS];
        size_t count = asteriskd_xtables_hook_arguments(hook, arguments);
        if (chain == NULL || count == 0U) return -1;
        if (hook->insert_at_head) {
            const char *insert[ASTERISKD_XTABLES_MAX_HOOK_ARGUMENTS + 1U];
            insert[0] = "1";
            memcpy(&insert[1], arguments, count * sizeof(arguments[0]));
            if (asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                    "-I", chain, insert, count + 1U) != 0) return -1;
        } else if (asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                "-A", chain, arguments, count) != 0) return -1;
    }
    return 0;
}

static int system_hook_match_count(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group,
    const struct asteriskd_traffic_hook *hook, size_t *matches, size_t *position) {
    const char *chain = system_builtin_name(hook->builtin_chain);
    const char *arguments[ASTERISKD_XTABLES_MAX_HOOK_ARGUMENTS];
    size_t count = asteriskd_xtables_hook_arguments(hook, arguments);
    if (chain == NULL || count == 0U || matches == NULL || position == NULL) return -1;
    const char *observed = system->action_stdout;
    size_t observed_length = system->action_stdout_length;
    bool snapshot_active =
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY;
    if (snapshot_active) {
        const struct system_rule_view *view =
            &system->rule_snapshot.xtables[group->family][group->table];
        if (!view->present) return -1;
        observed = view->bytes;
        observed_length = view->length;
    } else {
        int exit_status = -1;
        if (asteriskd_supervisor_xtables_run(system, group->family, group->table,
                "-S", chain, NULL, 0U, true, &exit_status) != 0 ||
            exit_status != 0 || system->action_stdout_overflow) return -1;
        observed = system->action_stdout;
        observed_length = system->action_stdout_length;
    }
    return asteriskd_xtables_rule_output_locate(
        observed, observed_length,
        chain, arguments, count, matches, position);
}

int asteriskd_supervisor_probe_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group, bool *all_present,
    bool *any_present) {
    *all_present = true;
    *any_present = false;
    for (size_t index = 0U; index < group->hook_count; ++index) {
        const struct asteriskd_traffic_hook *hook = &group->hooks[index];
        size_t matches = 0U;
        size_t position = 0U;
        if (system_hook_match_count(
                system, group, hook, &matches, &position) != 0 || matches > 1U) return -1;
        if (matches == 1U) *any_present = true;
        else *all_present = false;
    }
    return 0;
}

int asteriskd_supervisor_remove_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group) {
    int result = 0;
    for (size_t remaining = group->hook_count; remaining > 0U; --remaining) {
        const struct asteriskd_traffic_hook *hook = &group->hooks[remaining - 1U];
        const char *chain = system_builtin_name(hook->builtin_chain);
        const char *arguments[ASTERISKD_XTABLES_MAX_HOOK_ARGUMENTS];
        size_t count = asteriskd_xtables_hook_arguments(hook, arguments);
        size_t matches = 0U;
        size_t position = 0U;
        if (chain == NULL || count == 0U ||
            system_hook_match_count(system, group, hook, &matches, &position) != 0 ||
            matches > 1U || (matches == 1U && position == 0U)) {
            result = -1;
        } else if (matches == 1U) {
            if (asteriskd_supervisor_xtables_zero(system, group->family, group->table,
                    "-D", chain, arguments, count) != 0) result = -1;
        }
    }
    return result;
}

const struct asteriskd_private_chain_group *asteriskd_supervisor_find_private_group(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_iptables_chain_resource *resource) {
    for (size_t index = 0U; index < system->rules_runtime.plan.private_group_count; ++index) {
        const struct asteriskd_private_chain_group *group =
            &system->rules_runtime.plan.private_groups[index];
        if (group->family == resource->family && group->table == resource->table &&
            group->chain_id == resource->chain_id) return group;
    }
    return NULL;
}

const struct asteriskd_traffic_hook_group *asteriskd_supervisor_find_hook_group(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_iptables_rule_resource *resource) {
    for (size_t index = 0U; index < system->rules_runtime.plan.hook_group_count; ++index) {
        const struct asteriskd_traffic_hook_group *group =
            &system->rules_runtime.plan.hook_groups[index];
        if (group->family == resource->family && group->table == resource->table &&
            group->chain_id == resource->chain_id && group->rule_id == resource->rule_id) {
            return group;
        }
    }
    return NULL;
}

int asteriskd_supervisor_probe_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group, bool *all_present,
    bool *any_present) {
    *all_present = true;
    *any_present = false;
    bool snapshot_active =
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY;
    const struct system_rule_view *view =
        &system->rule_snapshot.xtables[group->family][group->table];
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (snapshot_active) {
            size_t declarations = 0U;
            size_t rules = 0U;
            if (!view->present || asteriskd_xtables_private_chain_counts(
                    view->bytes, view->length, group->names[index],
                    &declarations, &rules) != 0) return -1;
            if (declarations != 0U || rules != 0U) *any_present = true;
            if (declarations != 1U) *all_present = false;
            continue;
        }
        int exit_status = -1;
        if (asteriskd_supervisor_xtables(system, group->family, group->table, "-S",
                group->names[index], NULL, 0U, &exit_status) != 0 ||
            (exit_status != 0 && exit_status != 1)) return -1;
        if (exit_status == 0) *any_present = true;
        else *all_present = false;
    }
    return 0;
}

int asteriskd_supervisor_ip_command(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments,
    size_t argument_count, bool capture, int *exit_status) {
    if (argument_count > 20U || (argument_count != 0U && arguments == NULL) ||
        exit_status == NULL) return -1;
    // Served in process through rtnetlink; no ip(8) child is started.
    return asteriskd_supervisor_rtnl_ip(
        system, family, arguments, argument_count, capture, exit_status);
}

int asteriskd_supervisor_ip_zero(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments, size_t argument_count) {
    if (system->rule_commands.active) {
        if (family < ASTERISKD_IP_FAMILY_IPV4 ||
            family >= ASTERISKD_IP_FAMILY_COUNT || argument_count > 20U ||
            (argument_count != 0U && arguments == NULL)) return -1;
        const char *tokens[24U];
        size_t count = 0U;
        tokens[count++] = family == ASTERISKD_IP_FAMILY_IPV4 ? "4" : "6";
        for (size_t index = 0U; index < argument_count; ++index) {
            if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
            tokens[count++] = arguments[index];
        }
        tokens[count] = NULL;
        system->rule_commands.ip_started = true;
        return asteriskd_supervisor_rule_batch_append_line(&system->rule_commands.ip, tokens);
    }
    int exit_status = -1;
    return asteriskd_supervisor_ip_command(system, family, arguments, argument_count,
        false, &exit_status) == 0 && exit_status == 0 ? 0 : -1;
}

static void system_rule_view_destroy(struct system_rule_view *view) {
    if (view == NULL) return;
    free(view->bytes);
    memset(view, 0, sizeof(*view));
}

void asteriskd_supervisor_rule_snapshot_destroy(struct system_rule_snapshot *snapshot) {
    if (snapshot == NULL) return;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            system_rule_view_destroy(&snapshot->xtables[family][table]);
        }
        system_rule_view_destroy(&snapshot->ip_rules[family]);
        system_rule_view_destroy(&snapshot->ip_routes[family]);
    }
    snapshot->phase = SYSTEM_RULE_SNAPSHOT_NONE;
    snapshot->removal_ready = false;
}

static int system_rule_view_capture(
    const struct asteriskd_system_supervisor *system,
    struct system_rule_view *view) {
    if (system == NULL || view == NULL || system->action_stdout_overflow) return -1;
    system_rule_view_destroy(view);
    if (system->action_stdout_length != 0U) {
        view->bytes = malloc(system->action_stdout_length);
        if (view->bytes == NULL) return -1;
        memcpy(view->bytes, system->action_stdout, system->action_stdout_length);
    }
    view->length = system->action_stdout_length;
    view->present = true;
    return 0;
}

void asteriskd_supervisor_rule_view_destroy(struct system_rule_view *view) {
    system_rule_view_destroy(view);
}

/* Captures one complete "-S" table listing into a view. */
int asteriskd_supervisor_rule_view_capture_table(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    struct system_rule_view *view) {
    int exit_status = -1;
    if (system == NULL || view == NULL ||
        system_xtables_table(system, family, table, &exit_status) != 0 ||
        exit_status != 0 || system_rule_view_capture(system, view) != 0) {
        if (view != NULL) system_rule_view_destroy(view);
        return -1;
    }
    return 0;
}

/*
 * Fills the wanted tables of one family from a single iptables-save run, in
 * the same "-S" form a per-table listing produces. Tables it cannot provide
 * (failed run, truncated output, missing section) stay unfilled so the
 * caller lists them with "-S" instead.
 */
void asteriskd_supervisor_rule_views_capture_family(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const bool *wanted, struct system_rule_view *views, bool *filled) {
    const char *argv[] = {
        family == ASTERISKD_IP_FAMILY_IPV4 ? "iptables-save" : "ip6tables-save", NULL,
    };
    int exit_status = -1;
    for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) filled[table] = false;
    if (asteriskd_supervisor_action_run_argv(system, argv, true, &exit_status) != 0 ||
        exit_status != 0 || system->action_stdout_overflow) return;
    for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
        if (!wanted[table]) continue;
        struct asteriskd_byte_buffer listing = {0};
        if (asteriskd_xtables_save_table_listing(system->action_stdout,
                system->action_stdout_length,
                asteriskd_supervisor_table_name((enum asteriskd_ip_table)table),
                &listing) != 0 || listing.length == 0U) {
            asteriskd_byte_buffer_destroy(&listing);
            continue;
        }
        system_rule_view_destroy(&views[table]);
        views[table].bytes = (char *)listing.bytes;
        views[table].length = listing.length;
        views[table].present = true;
        filled[table] = true;
    }
}

/*
 * Re-reads the mangle listing of each family whose local bypass rules were
 * just rewritten. The bypass touches no other table, rule or route, so the
 * rest of the snapshot stays current. A family without a captured mangle
 * listing falls back to a full capture.
 */
int asteriskd_supervisor_rule_snapshot_refresh_mangle(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_rule_transaction_plan *plan, const bool *changed) {
    if (system == NULL || plan == NULL || changed == NULL) return -1;
    enum system_rule_snapshot_phase phase = system->rule_snapshot.phase;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        if (!changed[family]) continue;
        struct system_rule_view *view =
            &system->rule_snapshot.xtables[family][ASTERISKD_IP_TABLE_MANGLE];
        if (phase == SYSTEM_RULE_SNAPSHOT_NONE || !view->present) {
            return asteriskd_supervisor_rule_snapshot_capture(
                system, plan, SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY);
        }
        if (asteriskd_supervisor_rule_view_capture_table(system,
                (enum asteriskd_ip_family)family, ASTERISKD_IP_TABLE_MANGLE, view) != 0) {
            asteriskd_supervisor_rule_snapshot_destroy(&system->rule_snapshot);
            return -1;
        }
    }
    return 0;
}

int asteriskd_supervisor_rule_snapshot_capture(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_rule_transaction_plan *plan,
    enum system_rule_snapshot_phase phase) {
    if (system == NULL || plan == NULL ||
        (phase != SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY &&
         phase != SYSTEM_RULE_SNAPSHOT_AFTER_APPLY)) return -1;
    bool tables[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    bool rules[ASTERISKD_IP_FAMILY_COUNT];
    // Route listings cover only the tables the plan owns routes in.
    uint32_t route_tables[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_RULE_TRANSACTION_MAX_ROUTES];
    size_t route_table_count[ASTERISKD_IP_FAMILY_COUNT];
    memset(tables, 0, sizeof(tables));
    memset(rules, 0, sizeof(rules));
    memset(route_table_count, 0, sizeof(route_table_count));
    for (size_t index = 0U; index < plan->private_group_count; ++index) {
        const struct asteriskd_private_chain_group *group = &plan->private_groups[index];
        tables[group->family][group->table] = true;
    }
    for (size_t index = 0U; index < plan->hook_group_count; ++index) {
        const struct asteriskd_traffic_hook_group *group = &plan->hook_groups[index];
        tables[group->family][group->table] = true;
    }
    for (size_t index = 0U; index < plan->route_count; ++index) {
        const struct asteriskd_route_effect *effect = &plan->routes[index];
        if (effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) rules[effect->family] = true;
        if (effect->kind != ASTERISKD_ROUTE_EFFECT_ROUTE) continue;
        size_t *count = &route_table_count[effect->family];
        bool listed = false;
        for (size_t known = 0U; known < *count; ++known) {
            if (route_tables[effect->family][known] == effect->table) listed = true;
        }
        if (!listed) route_tables[effect->family][(*count)++] = effect->table;
    }
    asteriskd_supervisor_rule_snapshot_destroy(&system->rule_snapshot);
    const char *source = NULL;
    size_t failed_family = 0U;
    int exit_status = -1;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        failed_family = family;
        // Two or more tables of a family are read from one iptables-save run.
        bool filled[ASTERISKD_IP_TABLE_COUNT] = {false};
        size_t wanted_count = 0U;
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            if (tables[family][table]) ++wanted_count;
        }
        if (wanted_count >= 2U) {
            asteriskd_supervisor_rule_views_capture_family(system,
                (enum asteriskd_ip_family)family, tables[family],
                system->rule_snapshot.xtables[family], filled);
        }
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            if (!tables[family][table] || filled[table]) continue;
            source = asteriskd_supervisor_table_name((enum asteriskd_ip_table)table);
            exit_status = -1;
            if (system_xtables_table(system, (enum asteriskd_ip_family)family,
                    (enum asteriskd_ip_table)table, &exit_status) != 0 ||
                exit_status != 0 || system_rule_view_capture(system,
                    &system->rule_snapshot.xtables[family][table]) != 0) goto failed;
        }
        if (rules[family]) {
            const char *arguments[] = {"rule", "show"};
            source = "ip-rule";
            exit_status = -1;
            if (asteriskd_supervisor_ip_command(system, (enum asteriskd_ip_family)family,
                    arguments, 2U, true, &exit_status) != 0 ||
                exit_status != 0 || system_rule_view_capture(system,
                    &system->rule_snapshot.ip_rules[family]) != 0) goto failed;
        }
        if (route_table_count[family] != 0U) {
            source = "ip-route";
            exit_status = -1;
            if (asteriskd_supervisor_rtnl_route_render(system, (enum asteriskd_ip_family)family,
                    route_tables[family], route_table_count[family]) != 0 ||
                system_rule_view_capture(system,
                    &system->rule_snapshot.ip_routes[family]) != 0) goto failed;
        }
    }
    system->rule_snapshot.phase = phase;
    return 0;

failed:
    asteriskd_supervisor_rule_snapshot_destroy(&system->rule_snapshot);
    {
        char stderr_summary[256U];
        asteriskd_supervisor_action_stderr_summary(system, stderr_summary, sizeof(stderr_summary));
        char message[384U];
        int written = snprintf(message, sizeof(message),
            "rule snapshot capture failed: source=%s family=%s exitStatus=%d "
            "stdoutOverflow=%d stderr=%s",
            source == NULL ? "unknown" : source,
            failed_family == ASTERISKD_IP_FAMILY_IPV6 ? "ipv6" : "ipv4",
            exit_status, system->action_stdout_overflow ? 1 : 0, stderr_summary);
        if (written > 0 && (size_t)written < sizeof(message)) {
            asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_RULES, message);
        }
    }
    return -1;
}

#endif

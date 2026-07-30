// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int asteriskd_run_command(char *const arguments[], char *output, size_t output_size) {
    int pipe_fd[2] = {-1, -1};
    if (output != NULL && pipe(pipe_fd) != 0) return -1;
    pid_t child = fork();
    if (child < 0) {
        if (pipe_fd[0] >= 0) {
            (void)close(pipe_fd[0]);
            (void)close(pipe_fd[1]);
        }
        return -1;
    }
    if (child == 0) {
        if (output != NULL) {
            (void)close(pipe_fd[0]);
            (void)dup2(pipe_fd[1], STDOUT_FILENO);
            (void)close(pipe_fd[1]);
        }
        execvp(arguments[0], arguments);
        _exit(127);
    }
    if (output != NULL) {
        (void)close(pipe_fd[1]);
        size_t used = 0U;
        char buffer[1024];
        while (true) {
            ssize_t count = read(pipe_fd[0], buffer, sizeof(buffer));
            if (count <= 0) break;
            size_t available = used + 1U < output_size ? output_size - used - 1U : 0U;
            size_t copied = (size_t)count < available ? (size_t)count : available;
            if (copied > 0U) {
                memcpy(output + used, buffer, copied);
                used += copied;
            }
        }
        if (output_size > 0U) output[used] = '\0';
        (void)close(pipe_fd[0]);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static const char *iptables_program(int family) {
    return family == AF_INET6 ? "ip6tables" : "iptables";
}

static int iptables_chain_exists(int family, const char *chain) {
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-S", (char *)chain, NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static int iptables_ensure_chain(int family, const char *chain) {
    if (iptables_chain_exists(family, chain) == 0) return 0;
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-N", (char *)chain, NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static int iptables_flush_chain(int family, const char *chain) {
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-F", (char *)chain, NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static int iptables_list_chain(int family, const char *chain, char *output, size_t output_size) {
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-S", (char *)chain, NULL,
    };
    return asteriskd_run_command(arguments, output, output_size);
}

static int iptables_insert_return(
    int family,
    const char *chain,
    size_t rule_number,
    const char *address) {
    char cidr[80];
    char position[24];
    int prefix = family == AF_INET6 ? 128 : 32;
    int cidr_length = snprintf(cidr, sizeof(cidr), "%s/%d", address, prefix);
    int position_length = snprintf(position, sizeof(position), "%zu", rule_number);
    if (cidr_length <= 0 || (size_t)cidr_length >= sizeof(cidr) ||
        position_length <= 0 || (size_t)position_length >= sizeof(position)) {
        errno = EINVAL;
        return -1;
    }
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-I", (char *)chain, position,
        "-d", cidr, "-j", "RETURN", NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static int iptables_delete_return(int family, const char *chain, const char *address) {
    char cidr[80];
    int prefix = family == AF_INET6 ? 128 : 32;
    int length = snprintf(cidr, sizeof(cidr), "%s/%d", address, prefix);
    if (length <= 0 || (size_t)length >= sizeof(cidr)) {
        errno = EINVAL;
        return -1;
    }
    char *arguments[] = {
        (char *)iptables_program(family), "-w", "100", "-t", "mangle", "-D", (char *)chain,
        "-d", cidr, "-j", "RETURN", NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static int prepare_target(int family, const struct asteriskd_bypass_target *target) {
    if (!target->enabled) return 0;
    if (iptables_ensure_chain(family, target->begin_chain) != 0 ||
        iptables_ensure_chain(family, target->end_chain) != 0 ||
        iptables_flush_chain(family, target->begin_chain) != 0 ||
        iptables_flush_chain(family, target->end_chain) != 0) {
        return -1;
    }
    return 0;
}

int asteriskd_prepare_iptables_bypass(const struct asteriskd_config *config) {
    if (prepare_target(AF_INET, &config->ipv4_bypass) != 0) return -1;
    if (config->enable_ipv6 && prepare_target(AF_INET6, &config->ipv6_bypass) != 0) return -1;
    return 0;
}

static bool address_already_added(const struct asteriskd_address_set *set, const char *address) {
    for (size_t index = 0U; index < set->count; ++index) {
        if (strcmp(set->values[index], address) == 0) return true;
    }
    return false;
}

static int parse_host_cidr(int family, const char *cidr, char *address, size_t address_size) {
    char value[80];
    int length = snprintf(value, sizeof(value), "%s", cidr);
    if (length <= 0 || (size_t)length >= sizeof(value)) {
        errno = EINVAL;
        return -1;
    }
    char *slash = strchr(value, '/');
    if (slash == NULL || strchr(slash + 1, '/') != NULL) {
        errno = EINVAL;
        return -1;
    }
    *slash++ = '\0';
    const char *expected_prefix = family == AF_INET6 ? "128" : "32";
    if (strcmp(slash, expected_prefix) != 0) {
        errno = EINVAL;
        return -1;
    }
    unsigned char binary[sizeof(struct in6_addr)];
    if (inet_pton(family, value, binary) != 1 ||
        inet_ntop(family, binary, address, (socklen_t)address_size) == NULL) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int asteriskd_parse_iptables_bypass(
    const struct asteriskd_bypass_target *target,
    const char *consumer_chain,
    int family,
    const char *rules,
    struct asteriskd_address_set *addresses,
    size_t *end_rule_number) {
    if (target == NULL || !target->enabled || consumer_chain == NULL || rules == NULL ||
        addresses == NULL || end_rule_number == NULL ||
        (family != AF_INET && family != AF_INET6)) {
        errno = EINVAL;
        return -1;
    }
    memset(addresses, 0, sizeof(*addresses));
    addresses->family = family;
    *end_rule_number = 0U;

    char rule_prefix[ASTERISKD_MAX_CHAIN_NAME + 8U];
    char begin_rule[ASTERISKD_MAX_CHAIN_NAME * 2U + 16U];
    char end_rule[ASTERISKD_MAX_CHAIN_NAME * 2U + 16U];
    int prefix_length = snprintf(rule_prefix, sizeof(rule_prefix), "-A %s ", consumer_chain);
    int begin_length = snprintf(begin_rule, sizeof(begin_rule), "-A %s -j %s", consumer_chain, target->begin_chain);
    int end_length = snprintf(end_rule, sizeof(end_rule), "-A %s -j %s", consumer_chain, target->end_chain);
    if (prefix_length <= 0 || (size_t)prefix_length >= sizeof(rule_prefix) ||
        begin_length <= 0 || (size_t)begin_length >= sizeof(begin_rule) ||
        end_length <= 0 || (size_t)end_length >= sizeof(end_rule)) {
        errno = EINVAL;
        return -1;
    }

    bool begin_found = false;
    bool end_found = false;
    bool inside = false;
    size_t rule_number = 0U;
    const char *cursor = rules;
    while (*cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_length = line_end == NULL ? strlen(cursor) : (size_t)(line_end - cursor);
        if (line_length >= 512U) {
            errno = EINVAL;
            return -1;
        }
        char line[512];
        memcpy(line, cursor, line_length);
        line[line_length] = '\0';
        cursor = line_end == NULL ? cursor + line_length : line_end + 1;

        if (strncmp(line, rule_prefix, (size_t)prefix_length) != 0) continue;
        ++rule_number;
        if (strcmp(line, begin_rule) == 0) {
            if (begin_found || end_found) {
                errno = EINVAL;
                return -1;
            }
            begin_found = true;
            inside = true;
            continue;
        }
        if (strcmp(line, end_rule) == 0) {
            if (!inside || end_found) {
                errno = EINVAL;
                return -1;
            }
            end_found = true;
            inside = false;
            *end_rule_number = rule_number;
            continue;
        }
        if (!inside) continue;

        char destination_prefix[ASTERISKD_MAX_CHAIN_NAME + 12U];
        int destination_prefix_length = snprintf(
            destination_prefix,
            sizeof(destination_prefix),
            "-A %s -d ",
            consumer_chain);
        const char *return_suffix = " -j RETURN";
        if (destination_prefix_length <= 0 ||
            (size_t)destination_prefix_length >= sizeof(destination_prefix) ||
            strncmp(line, destination_prefix, (size_t)destination_prefix_length) != 0) {
            errno = EINVAL;
            return -1;
        }
        const char *cidr = line + destination_prefix_length;
        const char *suffix = strstr(cidr, return_suffix);
        if (suffix == NULL || suffix[strlen(return_suffix)] != '\0') {
            errno = EINVAL;
            return -1;
        }
        if (addresses->count >= ASTERISKD_MAX_ADDRESSES) {
            errno = ENOSPC;
            return -1;
        }
        char cidr_value[80];
        size_t cidr_length = (size_t)(suffix - cidr);
        if (cidr_length == 0U || cidr_length >= sizeof(cidr_value)) {
            errno = EINVAL;
            return -1;
        }
        memcpy(cidr_value, cidr, cidr_length);
        cidr_value[cidr_length] = '\0';
        char address[64];
        if (parse_host_cidr(family, cidr_value, address, sizeof(address)) != 0 ||
            address_already_added(addresses, address)) {
            errno = EINVAL;
            return -1;
        }
        (void)snprintf(addresses->values[addresses->count++], sizeof(addresses->values[0]), "%s", address);
    }
    if (!begin_found || !end_found || inside || *end_rule_number == 0U) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static bool address_sets_match(
    const struct asteriskd_address_set *left,
    const struct asteriskd_address_set *right) {
    if (left->family != right->family || left->count != right->count) return false;
    for (size_t index = 0U; index < left->count; ++index) {
        if (!address_already_added(right, left->values[index])) return false;
    }
    return true;
}

int asteriskd_collect_local_addresses(
    const struct asteriskd_config *config,
    int family,
    struct asteriskd_address_set *out) {
    memset(out, 0, sizeof(*out));
    out->family = family;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return -1;
    int result = 0;
    for (const struct ifaddrs *entry = interfaces; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != family ||
            !asteriskd_should_track_interface(config, entry->ifa_name)) {
            continue;
        }
        char address[64];
        const void *source = NULL;
        if (family == AF_INET) {
            const struct sockaddr_in *socket_address = (const struct sockaddr_in *)entry->ifa_addr;
            if (socket_address->sin_addr.s_addr == INADDR_ANY || IN_MULTICAST(ntohl(socket_address->sin_addr.s_addr))) continue;
            source = &socket_address->sin_addr;
        } else {
            const struct sockaddr_in6 *socket_address = (const struct sockaddr_in6 *)entry->ifa_addr;
            if (IN6_IS_ADDR_UNSPECIFIED(&socket_address->sin6_addr) || IN6_IS_ADDR_MULTICAST(&socket_address->sin6_addr)) continue;
            source = &socket_address->sin6_addr;
        }
        if (inet_ntop(family, source, address, sizeof(address)) == NULL) {
            result = -1;
            break;
        }
        if (!address_already_added(out, address)) {
            if (out->count >= ASTERISKD_MAX_ADDRESSES) {
                errno = ENOSPC;
                result = -1;
                break;
            }
            (void)snprintf(out->values[out->count++], sizeof(out->values[0]), "%s", address);
        }
    }
    freeifaddrs(interfaces);
    return result;
}

int asteriskd_reconcile_iptables_bypass(
    const struct asteriskd_bypass_target *target,
    int family,
    const struct asteriskd_address_set *addresses) {
    if (target == NULL || !target->enabled || addresses == NULL || addresses->family != family ||
        target->consumer_chain_count == 0U ||
        (family != AF_INET && family != AF_INET6)) {
        errno = EINVAL;
        return -1;
    }
    for (size_t consumer_index = 0U; consumer_index < target->consumer_chain_count; ++consumer_index) {
        const char *consumer = target->consumer_chains[consumer_index];
        size_t output_size = 128U * 1024U;
        char *rules = malloc(output_size);
        if (rules == NULL) return -1;
        int result = iptables_list_chain(family, consumer, rules, output_size);
        struct asteriskd_address_set current;
        size_t end_rule_number = 0U;
        if (result == 0) {
            result = asteriskd_parse_iptables_bypass(
                target,
                consumer,
                family,
                rules,
                &current,
                &end_rule_number);
        }
        free(rules);
        if (result != 0) return -1;

        for (size_t index = 0U; index < addresses->count; ++index) {
            if (!address_already_added(&current, addresses->values[index]) &&
                iptables_insert_return(
                    family,
                    consumer,
                    end_rule_number,
                    addresses->values[index]) != 0) {
                return -1;
            }
        }
        for (size_t index = 0U; index < current.count; ++index) {
            if (!address_already_added(addresses, current.values[index]) &&
                iptables_delete_return(family, consumer, current.values[index]) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

int asteriskd_clear_hotspot_ipv6_tc_offload(const struct asteriskd_config *config) {
    if (!config->enable_ipv6 || config->hotspot_interface_prefix_count == 0U) return 0;
    DIR *directory = opendir("/sys/class/net");
    if (directory == NULL) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        bool matched = false;
        for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
            if (asteriskd_interface_matches_prefix(entry->d_name, config->hotspot_interface_prefixes[index])) {
                matched = true;
                break;
            }
        }
        if (!matched) continue;
        char output[8192];
        char *show_arguments[] = {"tc", "filter", "show", "dev", entry->d_name, "ingress", "protocol", "ipv6", NULL};
        if (asteriskd_run_command(show_arguments, output, sizeof(output)) != 0) {
            result = -1;
            break;
        }
        if (strstr(output, "prog_offload_schedcls_tether_") == NULL) continue;
        char *delete_arguments[] = {
            "tc", "filter", "del", "dev", entry->d_name, "ingress", "protocol", "ipv6", "pref", "2", NULL,
        };
        if (asteriskd_run_command(delete_arguments, NULL, 0U) != 0) {
            result = -1;
            break;
        }
    }
    (void)closedir(directory);
    return result;
}

int asteriskd_sync_all(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    bool synchronize_ipv6_interfaces,
    bool synchronize_hotspot_interfaces,
    bool *addresses_changed) {
    if (addresses_changed == NULL) {
        errno = EINVAL;
        return -1;
    }
    *addresses_changed = false;
    if (config->disable_system_ipv6 && synchronize_ipv6_interfaces) {
        if (asteriskd_disable_system_ipv6_for_sync(config, state) != 0) return -1;
    }
    struct asteriskd_address_set ipv4_addresses;
    if (asteriskd_collect_local_addresses(config, AF_INET, &ipv4_addresses) != 0) return -1;
    struct asteriskd_address_set ipv6_addresses;
    memset(&ipv6_addresses, 0, sizeof(ipv6_addresses));
    ipv6_addresses.family = AF_INET6;
    if (config->enable_ipv6) {
        if (asteriskd_collect_local_addresses(config, AF_INET6, &ipv6_addresses) != 0) {
            return -1;
        }
    }
    bool changed = !state->has_synchronized_addresses ||
        !address_sets_match(&state->synchronized_ipv4_addresses, &ipv4_addresses) ||
        !address_sets_match(&state->synchronized_ipv6_addresses, &ipv6_addresses);
    if (changed) {
        if ((config->ipv4_bypass.enabled &&
             asteriskd_reconcile_iptables_bypass(&config->ipv4_bypass, AF_INET, &ipv4_addresses) != 0) ||
            (config->bpf_local_maps.enabled &&
             asteriskd_replace_lpm4_map(config->bpf_local_maps.ipv4_path, &ipv4_addresses) != 0) ||
            (config->enable_ipv6 && config->ipv6_bypass.enabled &&
             asteriskd_reconcile_iptables_bypass(&config->ipv6_bypass, AF_INET6, &ipv6_addresses) != 0) ||
            (config->bpf_local_maps.enabled &&
             asteriskd_replace_lpm6_map(config->bpf_local_maps.ipv6_path, &ipv6_addresses) != 0)) {
            return -1;
        }
        state->synchronized_ipv4_addresses = ipv4_addresses;
        state->synchronized_ipv6_addresses = ipv6_addresses;
        state->has_synchronized_addresses = true;
        *addresses_changed = true;
        asteriskd_log(state, "synchronized local addresses: ipv4=%zu ipv6=%zu", ipv4_addresses.count, ipv6_addresses.count);
    }
    if (config->enable_ipv6 && synchronize_hotspot_interfaces &&
        asteriskd_clear_hotspot_ipv6_tc_offload(config) != 0) {
        return -1;
    }
    if (config->bpf2socks_tc.enabled && synchronize_hotspot_interfaces &&
        asteriskd_bpf2socks_tc_sync(config, state) != 0) {
        return -1;
    }
    return 0;
}


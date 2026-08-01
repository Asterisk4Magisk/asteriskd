// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "asteriskd.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef RTMGRP_IPV6_IFADDR
#define RTMGRP_IPV6_IFADDR 0x100U
#endif

#define ASTERISKD_IPV6_CONF_DIR "/proc/sys/net/ipv6/conf"

static volatile sig_atomic_t stop_requested = 0;

static void on_signal(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
}

static long long monotonic_millis(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1LL;
    return (long long)value.tv_sec * 1000LL + value.tv_nsec / 1000000LL;
}

static bool is_system_ipv6_interface(const char *interface_name) {
    return asteriskd_ipv6_security_target(interface_name) &&
        strcmp(interface_name, ".") != 0 && strcmp(interface_name, "..") != 0;
}

static int sysctl_path(const char *interface_name, char *path, size_t path_size) {
    int count = snprintf(path, path_size, "%s/%s/disable_ipv6", ASTERISKD_IPV6_CONF_DIR, interface_name);
    if (count < 0 || (size_t)count >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int read_disable_ipv6(const char *interface_name, char *out) {
    char path[PATH_MAX];
    if (sysctl_path(interface_name, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[8];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    if (count <= 0) return -1;
    for (ssize_t index = 0; index < count; ++index) {
        if (buffer[index] == '0' || buffer[index] == '1') {
            *out = buffer[index];
            return 0;
        }
    }
    errno = EINVAL;
    return -1;
}

static int write_disable_ipv6(const char *interface_name, char value) {
    char path[PATH_MAX];
    if (sysctl_path(interface_name, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[] = {value, '\n'};
    ssize_t count = write(fd, buffer, sizeof(buffer));
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    if (count == (ssize_t)sizeof(buffer)) return 0;
    if (count >= 0) errno = EIO;
    return -1;
}

static int persist_ipv6_state(const struct asteriskd_config *config, const struct asteriskd_state *state) {
    char temporary_path[PATH_MAX];
    int count = snprintf(temporary_path, sizeof(temporary_path), "%s.tmp", config->state_path);
    if (count <= 0 || (size_t)count >= sizeof(temporary_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        int saved_errno = errno;
        (void)close(fd);
        (void)unlink(temporary_path);
        errno = saved_errno;
        return -1;
    }
    int result = 0;
    for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
        if (fprintf(file, "%s %c\n", state->ipv6_entries[index].interface_name, state->ipv6_entries[index].original_value) < 0) {
            result = -1;
            break;
        }
    }
    if (result == 0 && (fflush(file) != 0 || fsync(fileno(file)) != 0)) result = -1;
    int saved_errno = errno;
    if (fclose(file) != 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result == 0 && rename(temporary_path, config->state_path) != 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result == 0) {
        char parent_path[PATH_MAX];
        (void)snprintf(parent_path, sizeof(parent_path), "%s", config->state_path);
        char *separator = strrchr(parent_path, '/');
        if (separator == NULL) {
            result = -1;
            saved_errno = EINVAL;
        } else {
            *separator = '\0';
            int parent_fd = open(parent_path[0] == '\0' ? "/" : parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (parent_fd < 0 || fsync(parent_fd) != 0) {
                result = -1;
                saved_errno = errno;
            }
            if (parent_fd >= 0) (void)close(parent_fd);
        }
    }
    if (result != 0) (void)unlink(temporary_path);
    errno = saved_errno;
    return result;
}

static int capture_original_ipv6_value(
    struct asteriskd_state *state,
    const char *interface_name,
    unsigned int interface_index,
    char *out,
    bool *state_changed) {
    *state_changed = false;
    if (interface_index != 0U) {
        for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
            struct asteriskd_ipv6_state_entry *entry = &state->ipv6_entries[index];
            if (entry->interface_index != interface_index) continue;
            if (strcmp(entry->interface_name, interface_name) != 0) {
                (void)snprintf(entry->interface_name, sizeof(entry->interface_name), "%s", interface_name);
                *state_changed = true;
            }
            *out = entry->original_value;
            return 0;
        }
    }
    for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
        struct asteriskd_ipv6_state_entry *entry = &state->ipv6_entries[index];
        if (strcmp(entry->interface_name, interface_name) != 0) continue;
        if (entry->interface_index != 0U && interface_index != 0U &&
            entry->interface_index != interface_index) {
            if (read_disable_ipv6(interface_name, out) != 0) return -1;
            entry->original_value = *out;
            entry->interface_index = interface_index;
            *state_changed = true;
            return 0;
        }
        if (entry->interface_index == 0U) entry->interface_index = interface_index;
        *out = entry->original_value;
        return 0;
    }
    if (state->ipv6_entry_count >= ASTERISKD_MAX_INTERFACES ||
        read_disable_ipv6(interface_name, out) != 0) {
        return -1;
    }
    struct asteriskd_ipv6_state_entry *entry = &state->ipv6_entries[state->ipv6_entry_count++];
    (void)snprintf(entry->interface_name, sizeof(entry->interface_name), "%s", interface_name);
    entry->original_value = *out;
    entry->interface_index = interface_index;
    *state_changed = true;
    return 0;
}

int asteriskd_enforce_system_ipv6_interface(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const char *interface_name,
    unsigned int interface_index) {
    if (config == NULL || state == NULL || interface_name == NULL ||
        (strcmp(interface_name, "default") != 0 && !asteriskd_ipv6_security_target(interface_name))) {
        errno = EINVAL;
        return -1;
    }
    if (!config->disable_system_ipv6) return 0;
    char original = '\0';
    bool state_changed = false;
    if (capture_original_ipv6_value(state, interface_name, interface_index, &original, &state_changed) != 0) return -1;
    char current = '\0';
    if (read_disable_ipv6(interface_name, &current) != 0) return -1;
    if (asteriskd_ipv6_requires_write(original, current) && write_disable_ipv6(interface_name, '1') != 0) {
        return -1;
    }
    char verified = '\0';
    if (read_disable_ipv6(interface_name, &verified) != 0) return -1;
    if (verified != '1') {
        errno = EIO;
        return -1;
    }
    if (state_changed && persist_ipv6_state(config, state) != 0) {
        asteriskd_log(state, "IPv6 disabled for %s but original state persistence failed: %s", interface_name, strerror(errno));
    }
    return 0;
}

int asteriskd_disable_system_ipv6_for_sync(const struct asteriskd_config *config, struct asteriskd_state *state) {
    if (!config->disable_system_ipv6) return 0;
    if (asteriskd_enforce_system_ipv6_interface(config, state, "default", 0U) != 0) return -1;
    DIR *directory = opendir(ASTERISKD_IPV6_CONF_DIR);
    if (directory == NULL) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!is_system_ipv6_interface(entry->d_name)) continue;
        if (asteriskd_enforce_system_ipv6_interface(
                config,
                state,
                entry->d_name,
                if_nametoindex(entry->d_name)) != 0) {
            if (errno == ENOENT || errno == ENODEV) continue;
            result = -1;
            break;
        }
    }
    (void)closedir(directory);
    return result;
}

void asteriskd_retire_system_ipv6_interface(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const char *interface_name,
    unsigned int interface_index) {
    if (config == NULL || state == NULL || interface_name == NULL) return;
    for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
        const struct asteriskd_ipv6_state_entry *entry = &state->ipv6_entries[index];
        if (strcmp(entry->interface_name, interface_name) != 0 ||
            (entry->interface_index != 0U && interface_index != 0U &&
             entry->interface_index != interface_index)) {
            continue;
        }
        if (index + 1U < state->ipv6_entry_count) {
            memmove(
                &state->ipv6_entries[index],
                &state->ipv6_entries[index + 1U],
                (state->ipv6_entry_count - index - 1U) * sizeof(state->ipv6_entries[0]));
        }
        --state->ipv6_entry_count;
        memset(&state->ipv6_entries[state->ipv6_entry_count], 0, sizeof(state->ipv6_entries[0]));
        if (persist_ipv6_state(config, state) != 0) {
            asteriskd_log(state, "failed to persist retired IPv6 interface %s: %s", interface_name, strerror(errno));
        }
        return;
    }
}

int asteriskd_load_persisted_ipv6_state(
    const struct asteriskd_config *config,
    struct asteriskd_state *state) {
    if (config == NULL || state == NULL || !config->disable_system_ipv6) return 0;
    FILE *file = fopen(config->state_path, "r");
    if (file == NULL) return errno == ENOENT ? 0 : -1;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char value = '\0';
    int result = 0;
    while (fscanf(file, "%63s %c", interface_name, &value) == 2) {
        if (!asteriskd_ipv6_persisted_state_name(interface_name) ||
            (value != '0' && value != '1') || state->ipv6_entry_count >= ASTERISKD_MAX_INTERFACES) {
            errno = EINVAL;
            result = -1;
            break;
        }
        bool duplicate = false;
        for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
            duplicate = strcmp(state->ipv6_entries[index].interface_name, interface_name) == 0;
            if (duplicate) break;
        }
        if (duplicate) {
            errno = EINVAL;
            result = -1;
            break;
        }
        struct asteriskd_ipv6_state_entry *entry = &state->ipv6_entries[state->ipv6_entry_count++];
        (void)snprintf(entry->interface_name, sizeof(entry->interface_name), "%s", interface_name);
        entry->original_value = value;
        entry->interface_index = 0U;
    }
    int saved_errno = errno;
    (void)fclose(file);
    errno = saved_errno;
    return result;
}

static int restore_stale_ipv6_state(const struct asteriskd_config *config) {
    FILE *file = fopen(config->state_path, "r");
    if (file == NULL) return errno == ENOENT ? 0 : -1;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char value = '\0';
    int result = 0;
    while (fscanf(file, "%63s %c", interface_name, &value) == 2) {
        char path[PATH_MAX];
        if (!asteriskd_ipv6_persisted_state_name(interface_name) || (value != '0' && value != '1') ||
            sysctl_path(interface_name, path, sizeof(path)) != 0) {
            result = -1;
            break;
        }
        if (access(path, F_OK) == 0 && write_disable_ipv6(interface_name, value) != 0) {
            result = -1;
            break;
        }
    }
    (void)fclose(file);
    if (result == 0) (void)unlink(config->state_path);
    return result;
}

void asteriskd_restore_ipv6(const struct asteriskd_config *config, struct asteriskd_state *state) {
    if (!config->disable_system_ipv6) return;
    for (size_t index = 0U; index < state->ipv6_entry_count; ++index) {
        const char *interface_name = state->ipv6_entries[index].interface_name;
        unsigned int interface_index = state->ipv6_entries[index].interface_index;
        char path[PATH_MAX];
        bool generation_matches = strcmp(interface_name, "default") == 0 || interface_index == 0U ||
            if_nametoindex(interface_name) == interface_index;
        if (generation_matches && sysctl_path(interface_name, path, sizeof(path)) == 0 && access(path, F_OK) == 0 &&
            write_disable_ipv6(interface_name, state->ipv6_entries[index].original_value) != 0) {
            asteriskd_log(state, "failed to restore IPv6 for %s: %s", interface_name, strerror(errno));
        }
    }
    state->ipv6_entry_count = 0U;
    (void)unlink(config->state_path);
}

bool asteriskd_interface_matches_prefix(const char *interface_name, const char *prefix) {
    size_t length = strlen(prefix);
    if (length == 0U) return false;
    if (prefix[length - 1U] == '+') {
        return length > 1U && strncmp(interface_name, prefix, length - 1U) == 0;
    }
    return strcmp(interface_name, prefix) == 0;
}

bool asteriskd_should_track_interface(const struct asteriskd_config *config, const char *interface_name) {
    if (!is_system_ipv6_interface(interface_name)) return false;
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (strcmp(config->ignored_interfaces[index], interface_name) == 0) return false;
    }
    for (size_t index = 0U; index < config->virtual_interface_count; ++index) {
        if (strcmp(config->virtual_interfaces[index], interface_name) == 0) return false;
    }
    return true;
}

uint32_t asteriskd_netlink_groups(const struct asteriskd_config *config) {
    // Route netlink cannot subscribe by interface prefix. Avoid the broad link
    // multicast group entirely when neither IPv6 disabling nor hotspot TC work
    // needs interface lifecycle events.
    uint32_t groups = RTMGRP_IPV4_IFADDR;
    if (config->enable_ipv6 || config->disable_system_ipv6) groups |= RTMGRP_IPV6_IFADDR;
    if (config->disable_system_ipv6 ||
        ((config->enable_ipv6 || config->bpf2socks_tc.enabled) &&
         config->hotspot_interface_prefix_count > 0U)) {
        groups |= RTMGRP_LINK;
    }
    return groups;
}

static int open_netlink_socket(const struct asteriskd_config *config) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    int receive_buffer_size = 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer_size, sizeof(receive_buffer_size)) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    struct sockaddr_nl address;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = asteriskd_netlink_groups(config);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static bool link_interface_name(
    const struct nlmsghdr *message,
    const struct ifinfomsg *link,
    char *interface_name,
    size_t interface_name_size) {
    int remaining = IFLA_PAYLOAD(message);
    for (const struct rtattr *attribute = IFLA_RTA(link);
         RTA_OK(attribute, remaining);
         attribute = RTA_NEXT(attribute, remaining)) {
        if (attribute->rta_type != IFLA_IFNAME) continue;
        const char *value = RTA_DATA(attribute);
        size_t value_size = (size_t)RTA_PAYLOAD(attribute);
        size_t length = strnlen(value, value_size);
        if (length == 0U || length >= value_size || length >= interface_name_size) return false;
        memcpy(interface_name, value, length);
        interface_name[length] = '\0';
        return true;
    }
    return if_indextoname((unsigned int)link->ifi_index, interface_name) != NULL;
}

static bool is_hotspot_interface(const struct asteriskd_config *config, const char *interface_name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        if (asteriskd_interface_matches_prefix(interface_name, config->hotspot_interface_prefixes[index])) {
            return true;
        }
    }
    return false;
}

static void record_link_message(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const struct nlmsghdr *message,
    struct asteriskd_event_batch *events) {
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) return;
    const struct ifinfomsg *link = (const struct ifinfomsg *)NLMSG_DATA(message);
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    if (!link_interface_name(message, link, interface_name, sizeof(interface_name))) return;
    if (config->disable_system_ipv6) {
        if (message->nlmsg_type == RTM_DELLINK) {
            asteriskd_retire_system_ipv6_interface(
                config, state, interface_name, (unsigned int)link->ifi_index);
            bool pending_generation = state->hotspot_dnsmasq_interface_index != 0U && link->ifi_index > 0
                ? state->hotspot_dnsmasq_interface_index == (unsigned int)link->ifi_index
                : strcmp(state->hotspot_dnsmasq_interface, interface_name) == 0;
            if (state->hotspot_dnsmasq_rebuild_pending && pending_generation) {
                state->hotspot_dnsmasq_rebuild_pending = false;
                state->hotspot_dnsmasq_interface[0] = '\0';
                state->hotspot_dnsmasq_interface_index = 0U;
            }
        } else {
            if (asteriskd_enforce_system_ipv6_interface(config, state, "default", 0U) != 0) {
                asteriskd_log(state, "IPv6 fast-path failed for default after link event: %s", strerror(errno));
            }
            if (asteriskd_ipv6_security_target(interface_name) &&
                asteriskd_enforce_system_ipv6_interface(
                    config, state, interface_name, (unsigned int)link->ifi_index) != 0 &&
                errno != ENOENT && errno != ENODEV) {
                asteriskd_log(
                    state,
                    "IPv6 fast-path failed for link %s: %s",
                    interface_name,
                    strerror(errno));
            }
        }
    }
    bool relevant = config->disable_system_ipv6 ||
        (asteriskd_should_track_interface(config, interface_name) && is_hotspot_interface(config, interface_name));
    if (!relevant) return;
    asteriskd_event_batch_record_link(
        events,
        message->nlmsg_type == RTM_DELLINK ? ASTERISKD_EVENT_REMOVED : ASTERISKD_EVENT_UPDATED,
        interface_name);
}

static void record_address_message(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const struct nlmsghdr *message,
    struct asteriskd_event_batch *events) {
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg))) return;
    const struct ifaddrmsg *address_info = (const struct ifaddrmsg *)NLMSG_DATA(message);
    if (address_info->ifa_family != AF_INET && address_info->ifa_family != AF_INET6) return;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    if (if_indextoname(address_info->ifa_index, interface_name) == NULL) return;
    enum asteriskd_event_action action =
        message->nlmsg_type == RTM_DELADDR ? ASTERISKD_EVENT_REMOVED : ASTERISKD_EVENT_ADDED;
    if (config->disable_system_ipv6 &&
        asteriskd_ipv6_event_requires_enforcement(action, address_info->ifa_family, interface_name) &&
        asteriskd_enforce_system_ipv6_interface(
            config, state, interface_name, address_info->ifa_index) != 0 &&
        errno != ENOENT && errno != ENODEV) {
        asteriskd_log(
            state,
            "IPv6 fast-path failed for address on %s: %s",
            interface_name,
            strerror(errno));
    }
    if (asteriskd_hotspot_ipv6_event_requests_dnsmasq_rebuild(
            config, action, address_info->ifa_family, interface_name)) {
        state->hotspot_dnsmasq_rebuild_pending = true;
        (void)snprintf(
            state->hotspot_dnsmasq_interface,
            sizeof(state->hotspot_dnsmasq_interface),
            "%s",
            interface_name);
        state->hotspot_dnsmasq_interface_index = address_info->ifa_index;
    }
    bool tracked = asteriskd_should_track_interface(config, interface_name);
    bool security_relevant = config->disable_system_ipv6 &&
        address_info->ifa_family == AF_INET6 && asteriskd_ipv6_security_target(interface_name);
    if (!tracked && !security_relevant && !is_hotspot_interface(config, interface_name)) return;
    const void *address = NULL;
    int remaining = IFA_PAYLOAD(message);
    for (const struct rtattr *attribute = IFA_RTA(address_info);
         RTA_OK(attribute, remaining);
         attribute = RTA_NEXT(attribute, remaining)) {
        if (attribute->rta_type == IFA_LOCAL) {
            address = RTA_DATA(attribute);
            if (address_info->ifa_family == AF_INET) break;
        } else if (attribute->rta_type == IFA_ADDRESS && address == NULL) {
            address = RTA_DATA(attribute);
        }
    }
    if (address == NULL) return;
    char text[64];
    if (inet_ntop(address_info->ifa_family, address, text, sizeof(text)) == NULL) return;
    asteriskd_event_batch_record_address(
        events,
        action,
        address_info->ifa_family,
        interface_name,
        text);
}

static void record_netlink_message(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const struct nlmsghdr *message,
    struct asteriskd_event_batch *events) {
    switch (message->nlmsg_type) {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            record_link_message(config, state, message, events);
            return;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            record_address_message(config, state, message, events);
            return;
        default:
            return;
    }
}

static int drain_netlink_socket(
    int fd,
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    struct asteriskd_event_batch *events) {
    char buffer[65536];
    while (true) {
        struct sockaddr_nl source;
        struct iovec vector = {.iov_base = buffer, .iov_len = sizeof(buffer)};
        struct msghdr received;
        memset(&received, 0, sizeof(received));
        received.msg_name = &source;
        received.msg_namelen = sizeof(source);
        received.msg_iov = &vector;
        received.msg_iovlen = 1U;
        ssize_t count = recvmsg(fd, &received, MSG_DONTWAIT);
        if (count >= 0) {
            if (count == 0) return 0;
            if ((received.msg_flags & MSG_TRUNC) != 0) return 1;
            unsigned int remaining = (unsigned int)count;
            for (const struct nlmsghdr *message = (const struct nlmsghdr *)buffer;
                 NLMSG_OK(message, remaining);
                 message = NLMSG_NEXT(message, remaining)) {
                record_netlink_message(config, state, message, events);
            }
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == ENOBUFS) return 1;
        if (errno == EINTR) continue;
        return -1;
    }
}

static int write_pid_file(const struct asteriskd_state *state) {
    FILE *file = fopen(state->pid_path, "w");
    if (file == NULL) return -1;
    int result = fprintf(file, "%ld\n", (long)getpid()) < 0 || fclose(file) != 0 ? -1 : 0;
    return result;
}

static int write_ready_file(const struct asteriskd_state *state) {
    FILE *file = fopen(state->ready_path, "w");
    if (file == NULL) return -1;
    int result = fputs("ready\n", file) == EOF || fclose(file) != 0 ? -1 : 0;
    return result;
}

int asteriskd_prepare(const struct asteriskd_config *config, struct asteriskd_state *state) {
    (void)state;
    if (!config->disable_system_ipv6 && restore_stale_ipv6_state(config) != 0) return -1;
    if (asteriskd_bpf2socks_tc_prepare(config) != 0) return -1;
    return asteriskd_prepare_iptables_bypass(config);
}

int asteriskd_run(const struct asteriskd_config *config, struct asteriskd_state *state) {
    asteriskd_open_log(state);
    asteriskd_log(state, "starting asteriskd");
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)sigaction(SIGINT, &action, NULL);
    if (write_pid_file(state) != 0) asteriskd_fail_stop(config, state, "write pid");
    int netlink_fd = open_netlink_socket(config);
    if (netlink_fd < 0) asteriskd_fail_stop(config, state, "open netlink");
    if (asteriskd_load_persisted_ipv6_state(config, state) != 0) {
        asteriskd_fail_stop(config, state, "load persisted IPv6 state");
    }
    struct asteriskd_event_batch events;
    asteriskd_event_batch_init(&events);
    bool addresses_changed = false;
    if (asteriskd_sync_all(config, state, true, true, &addresses_changed) != 0) {
        asteriskd_fail_stop(config, state, "initial sync");
    }
    int startup_drain_result = drain_netlink_socket(netlink_fd, config, state, &events);
    if (startup_drain_result < 0) asteriskd_fail_stop(config, state, "initial netlink drain");
    if (startup_drain_result > 0) {
        events.truncated = true;
        if (asteriskd_disable_system_ipv6_for_sync(config, state) != 0) {
            asteriskd_fail_stop(config, state, "initial netlink reconciliation");
        }
    }
    if (events.count > 0U || events.truncated) {
        bool synchronize_ipv6_interfaces =
            config->disable_system_ipv6 && asteriskd_event_batch_has_link_event(&events);
        bool synchronize_hotspot_interfaces =
            (config->enable_ipv6 || config->bpf2socks_tc.enabled) &&
            (events.truncated || asteriskd_event_batch_has_hotspot_interface_event(&events, config));
        if (asteriskd_sync_all(
                config,
                state,
                synchronize_ipv6_interfaces,
                synchronize_hotspot_interfaces,
                &addresses_changed) != 0) {
            asteriskd_fail_stop(config, state, "initial queued event sync");
        }
        asteriskd_event_batch_init(&events);
    }
    if (write_ready_file(state) != 0) asteriskd_fail_stop(config, state, "write ready");

    long long sync_deadline = -1LL;
    if (state->hotspot_dnsmasq_rebuild_pending) {
        long long now = monotonic_millis();
        if (now < 0LL) asteriskd_fail_stop(config, state, "read startup monotonic clock");
        sync_deadline = now + ASTERISKD_SYNC_DEBOUNCE_MILLIS;
    }
    while (!stop_requested) {
        int timeout = -1;
        if (sync_deadline >= 0LL) {
            long long now = monotonic_millis();
            if (now < 0LL) asteriskd_fail_stop(config, state, "read monotonic clock");
            long long remaining = sync_deadline - now;
            timeout = remaining > 0LL ? (int)remaining : 0;
        }
        struct pollfd poll_fd = {.fd = netlink_fd, .events = POLLIN, .revents = 0};
        int result = poll(&poll_fd, 1U, timeout);
        if (stop_requested) break;
        if (result > 0 && (poll_fd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0) {
            size_t event_count_before = events.count;
            bool truncated_before = events.truncated;
            int drain_result = (poll_fd.revents & (POLLHUP | POLLNVAL)) != 0 ? -1 :
                drain_netlink_socket(netlink_fd, config, state, &events);
            if (drain_result < 0) {
                (void)close(netlink_fd);
                netlink_fd = open_netlink_socket(config);
                if (netlink_fd < 0) asteriskd_fail_stop(config, state, "reopen netlink");
                asteriskd_log(state, "route netlink socket recreated after error");
                drain_result = 1;
            }
            if (drain_result > 0) {
                events.truncated = true;
                asteriskd_log(state, "route netlink integrity loss; reconciling IPv6 once");
                if (asteriskd_disable_system_ipv6_for_sync(config, state) != 0) {
                    asteriskd_log(state, "IPv6 integrity reconciliation failed: %s", strerror(errno));
                }
            }
            if (events.count == event_count_before && events.truncated == truncated_before) continue;
            long long now = monotonic_millis();
            if (now < 0LL) asteriskd_fail_stop(config, state, "read monotonic clock");
            sync_deadline = now + ASTERISKD_SYNC_DEBOUNCE_MILLIS;
        } else if (result == 0 && sync_deadline >= 0LL) {
            bool synchronize_ipv6_interfaces =
                config->disable_system_ipv6 && asteriskd_event_batch_has_link_event(&events);
            bool synchronize_hotspot_interfaces =
                (config->enable_ipv6 || config->bpf2socks_tc.enabled) &&
                (events.truncated || asteriskd_event_batch_has_hotspot_interface_event(&events, config));
            bool addresses_changed = false;
            if (asteriskd_sync_all(
                    config,
                    state,
                    synchronize_ipv6_interfaces,
                    synchronize_hotspot_interfaces,
                    &addresses_changed) != 0) {
                asteriskd_fail_stop(config, state, "synchronize addresses");
            }
            if (state->hotspot_dnsmasq_rebuild_pending) {
                int rebuild_result = asteriskd_rebuild_tether_dnsmasq(
                    state,
                    state->hotspot_dnsmasq_interface,
                    state->hotspot_dnsmasq_interface_index);
                if (rebuild_result < 0) {
                    asteriskd_log(state, "failed to rebuild netd dnsmasq: %s", strerror(errno));
                }
                state->hotspot_dnsmasq_rebuild_pending = false;
                state->hotspot_dnsmasq_interface[0] = '\0';
                state->hotspot_dnsmasq_interface_index = 0U;
            }
            if (addresses_changed || synchronize_hotspot_interfaces) {
                asteriskd_log_event_batch(state, &events);
            }
            asteriskd_event_batch_init(&events);
            sync_deadline = -1LL;
        } else if (result < 0 && errno != EINTR) {
            asteriskd_fail_stop(config, state, "poll netlink");
        }
    }
    (void)close(netlink_fd);
    asteriskd_bpf2socks_tc_restore(config, state);
    asteriskd_restore_ipv6(config, state);
    (void)unlink(state->ready_path);
    (void)unlink(state->pid_path);
    asteriskd_log(state, "stopped asteriskd");
    asteriskd_close_log(state);
    return 0;
}


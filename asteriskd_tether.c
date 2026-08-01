// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ASTERISKD_NDC_PATH "/system/bin/ndc"

static bool process_is_root_netd(long pid) {
    char path[64];
    int count = snprintf(path, sizeof(path), "/proc/%ld/exe", pid);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    char executable[PATH_MAX];
    ssize_t length = readlink(path, executable, sizeof(executable) - 1U);
    if (length <= 0 || (size_t)length >= sizeof(executable)) return false;
    executable[length] = '\0';
    const char *basename = strrchr(executable, '/');
    basename = basename == NULL ? executable : basename + 1;
    if (strcmp(basename, "netd") != 0) return false;

    count = snprintf(path, sizeof(path), "/proc/%ld/status", pid);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    FILE *status = fopen(path, "r");
    if (status == NULL) return false;
    unsigned long real_uid = ULONG_MAX;
    char line[256];
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "Uid:%lu", &real_uid) == 1) break;
    }
    (void)fclose(status);
    return real_uid == 0UL;
}

static bool process_parent_is_netd(long pid) {
    char path[64];
    int count = snprintf(path, sizeof(path), "/proc/%ld/status", pid);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    FILE *status = fopen(path, "r");
    if (status == NULL) return false;
    long parent = -1L;
    char line[256];
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "PPid:%ld", &parent) == 1) break;
    }
    (void)fclose(status);
    return parent > 1L && process_is_root_netd(parent);
}

static int dnsmasq_pid(long *pid) {
    DIR *directory = opendir("/proc");
    if (directory == NULL) return -1;
    int result = -1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        errno = 0;
        long candidate = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            candidate <= 1L || candidate > INT_MAX) {
            continue;
        }
        char path[64];
        int count = snprintf(path, sizeof(path), "/proc/%ld/comm", candidate);
        if (count <= 0 || (size_t)count >= sizeof(path)) continue;
        FILE *comm = fopen(path, "r");
        if (comm == NULL) continue;
        char name[64] = {0};
        bool is_dnsmasq = fgets(name, sizeof(name), comm) != NULL &&
            (strcmp(name, "dnsmasq\n") == 0 || strcmp(name, "dnsmasq") == 0);
        (void)fclose(comm);
        if (is_dnsmasq && process_parent_is_netd(candidate)) {
            *pid = candidate;
            result = 0;
            break;
        }
    }
    (void)closedir(directory);
    if (result != 0) errno = ENOENT;
    return result;
}

static int ndc_tether_command(const char *operation, char *output, size_t output_size) {
    char *arguments[] = {ASTERISKD_NDC_PATH, "tether", (char *)operation, NULL};
    return asteriskd_run_command(arguments, output, output_size);
}

static bool tether_interface_is_active(const char *interface_name) {
    char output[1024];
    char *arguments[] = {ASTERISKD_NDC_PATH, "tether", "interface", "list", NULL};
    if (asteriskd_run_command(arguments, output, sizeof(output)) != 0) return false;
    char *line = output;
    while (line != NULL && *line != '\0') {
        char *next = strchr(line, '\n');
        if (next != NULL) *next++ = '\0';
        int code = 0;
        int status = 0;
        char listed_interface[ASTERISKD_MAX_INTERFACE_NAME];
        if (sscanf(line, "%d %d %63s", &code, &status, listed_interface) == 3 &&
            code == 111 && status == 0 && strcmp(listed_interface, interface_name) == 0) {
            return true;
        }
        line = next;
    }
    return false;
}

static bool interface_ipv6_is_disabled(const char *interface_name) {
    char path[PATH_MAX];
    int count = snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", interface_name);
    if (count <= 0 || (size_t)count >= sizeof(path)) return false;
    FILE *file = fopen(path, "r");
    if (file == NULL) return false;
    int value = fgetc(file);
    (void)fclose(file);
    return value == '1';
}

static bool interface_has_no_ipv6_address(const char *interface_name) {
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return false;
    bool has_ipv6 = false;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr != NULL && entry->ifa_addr->sa_family == AF_INET6 &&
            strcmp(entry->ifa_name, interface_name) == 0) {
            has_ipv6 = true;
            break;
        }
    }
    freeifaddrs(addresses);
    return !has_ipv6;
}

int asteriskd_rebuild_tether_dnsmasq(
    struct asteriskd_state *state,
    const char *interface_name,
    unsigned int interface_index) {
    if (access(ASTERISKD_NDC_PATH, X_OK) != 0) return 0;
    if (interface_name == NULL || interface_name[0] == '\0' || interface_index == 0U ||
        if_nametoindex(interface_name) != interface_index ||
        !interface_ipv6_is_disabled(interface_name) ||
        !interface_has_no_ipv6_address(interface_name) ||
        !tether_interface_is_active(interface_name)) {
        return 0;
    }
    long old_pid = -1L;
    if (dnsmasq_pid(&old_pid) != 0) return 0;
    char status[256];
    if (ndc_tether_command("status", status, sizeof(status)) != 0 ||
        strstr(status, "Tethering services started") == NULL) {
        return 0;
    }
    char command_output[256] = {0};
    if (ndc_tether_command("stop", command_output, sizeof(command_output)) != 0) {
        asteriskd_log(state, "ndc tether stop failed: %s", command_output);
        return -1;
    }
    if (ndc_tether_command("start", command_output, sizeof(command_output)) != 0 &&
        ndc_tether_command("start", command_output, sizeof(command_output)) != 0) {
        asteriskd_log(state, "ndc tether start failed: %s", command_output);
        return -1;
    }
    if (ndc_tether_command("status", status, sizeof(status)) != 0 ||
        strstr(status, "Tethering services started") == NULL ||
        !tether_interface_is_active(interface_name)) {
        errno = EIO;
        return -1;
    }
    long new_pid = -1L;
    if (dnsmasq_pid(&new_pid) != 0 || new_pid == old_pid) {
        errno = EIO;
        return -1;
    }
    asteriskd_log(state, "rebuilt netd dnsmasq after hotspot IPv6 change: old=%ld new=%ld", old_pid, new_pid);
    return 1;
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ASTERISKD_IPV4_CONF_DIR "/proc/sys/net/ipv4/conf"

static bool matches_hotspot(
    const struct asteriskd_config *config,
    const char *interface_name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        if (asteriskd_interface_matches_prefix(
                interface_name,
                config->hotspot_interface_prefixes[index])) {
            return true;
        }
    }
    return false;
}

static int route_localnet_path(
    const char *interface_name,
    char *path,
    size_t path_size) {
    int written = snprintf(
        path,
        path_size,
        "%s/%s/route_localnet",
        ASTERISKD_IPV4_CONF_DIR,
        interface_name);
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int read_route_localnet(const char *interface_name, char *out) {
    char path[PATH_MAX];
    if (route_localnet_path(interface_name, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[8];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    int saved = errno;
    (void)close(fd);
    errno = saved;
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

static int write_route_localnet(const char *interface_name, char value) {
    char path[PATH_MAX];
    if (route_localnet_path(interface_name, path, sizeof(path)) != 0) return -1;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buffer[] = {value, '\n'};
    ssize_t count = write(fd, buffer, sizeof(buffer));
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (count == (ssize_t)sizeof(buffer)) return 0;
    if (count >= 0) errno = EIO;
    return -1;
}

static int persist_route_localnet_state(
    const struct asteriskd_config *config,
    const struct asteriskd_state *state) {
    FILE *file = fopen(config->bpf2socks_tc.state_path, "w");
    if (file == NULL) return -1;
    for (size_t index = 0U; index < state->route_localnet_entry_count; ++index) {
        const struct asteriskd_route_localnet_state_entry *entry =
            &state->route_localnet_entries[index];
        if (fprintf(file, "%s %c\n", entry->interface_name, entry->original_value) < 0) {
            (void)fclose(file);
            return -1;
        }
    }
    if (fflush(file) != 0 || fsync(fileno(file)) != 0 || fclose(file) != 0) return -1;
    return 0;
}

static int capture_route_localnet(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const char *interface_name) {
    for (size_t index = 0U; index < state->route_localnet_entry_count; ++index) {
        if (strcmp(
                state->route_localnet_entries[index].interface_name,
                interface_name) == 0) {
            return 0;
        }
    }
    if (state->route_localnet_entry_count >= ASTERISKD_MAX_INTERFACES) {
        errno = ENOSPC;
        return -1;
    }
    char original = '\0';
    if (read_route_localnet(interface_name, &original) != 0) return -1;
    struct asteriskd_route_localnet_state_entry *entry =
        &state->route_localnet_entries[state->route_localnet_entry_count++];
    (void)snprintf(entry->interface_name, sizeof(entry->interface_name), "%s", interface_name);
    entry->original_value = original;
    return persist_route_localnet_state(config, state);
}

static int ensure_clsact(const char *interface_name) {
    char output[4096];
    char *show[] = {"tc", "qdisc", "show", "dev", (char *)interface_name, NULL};
    if (asteriskd_run_command(show, output, sizeof(output)) != 0) return -1;
    if (strstr(output, "qdisc clsact") != NULL) return 0;
    char *add[] = {"tc", "qdisc", "add", "dev", (char *)interface_name, "clsact", NULL};
    return asteriskd_run_command(add, NULL, 0U);
}

static int replace_filter(
    const struct asteriskd_config *config,
    const char *interface_name,
    const char *direction,
    const char *pin_path) {
    char preference[16];
    char handle[16];
    (void)snprintf(preference, sizeof(preference), "%u", config->bpf2socks_tc.preference);
    (void)snprintf(handle, sizeof(handle), "%u", config->bpf2socks_tc.handle);
    char *arguments[] = {
        "tc", "filter", "replace", "dev", (char *)interface_name, (char *)direction,
        "pref", preference, "handle", handle, "bpf", "da", "pinned", (char *)pin_path, NULL,
    };
    return asteriskd_run_command(arguments, NULL, 0U);
}

static void delete_owned_filter(
    const struct asteriskd_config *config,
    const char *interface_name,
    const char *direction) {
    char preference[16];
    char handle[16];
    (void)snprintf(preference, sizeof(preference), "%u", config->bpf2socks_tc.preference);
    (void)snprintf(handle, sizeof(handle), "%u", config->bpf2socks_tc.handle);
    char *arguments[] = {
        "tc", "filter", "del", "dev", (char *)interface_name, (char *)direction,
        "pref", preference, "handle", handle, "bpf", NULL,
    };
    (void)asteriskd_run_command(arguments, NULL, 0U);
}

static int for_each_hotspot(
    const struct asteriskd_config *config,
    int (*callback)(
        const struct asteriskd_config *,
        struct asteriskd_state *,
        const char *),
    struct asteriskd_state *state) {
    DIR *directory = opendir("/sys/class/net");
    if (directory == NULL) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (!matches_hotspot(config, entry->d_name)) continue;
        if (callback(config, state, entry->d_name) != 0) {
            result = -1;
            break;
        }
    }
    (void)closedir(directory);
    return result;
}

static int install_interface(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const char *interface_name) {
    if (capture_route_localnet(config, state, interface_name) != 0 ||
        write_route_localnet(interface_name, '1') != 0 ||
        ensure_clsact(interface_name) != 0 ||
        replace_filter(config, interface_name, "egress", config->bpf2socks_tc.egress_path) != 0 ||
        replace_filter(config, interface_name, "ingress", config->bpf2socks_tc.ingress_path) != 0) {
        return -1;
    }
    return 0;
}

static int delete_interface(
    const struct asteriskd_config *config,
    struct asteriskd_state *state,
    const char *interface_name) {
    (void)state;
    delete_owned_filter(config, interface_name, "ingress");
    delete_owned_filter(config, interface_name, "egress");
    return 0;
}

static int restore_stale_route_localnet(const struct asteriskd_config *config) {
    FILE *file = fopen(config->bpf2socks_tc.state_path, "r");
    if (file == NULL) return errno == ENOENT ? 0 : -1;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char value = '\0';
    int result = 0;
    while (fscanf(file, "%63s %c", interface_name, &value) == 2) {
        char path[PATH_MAX];
        if ((value != '0' && value != '1') ||
            route_localnet_path(interface_name, path, sizeof(path)) != 0) {
            result = -1;
            break;
        }
        if (access(path, F_OK) == 0 && write_route_localnet(interface_name, value) != 0) {
            result = -1;
            break;
        }
    }
    (void)fclose(file);
    if (result == 0) (void)unlink(config->bpf2socks_tc.state_path);
    return result;
}

int asteriskd_bpf2socks_tc_prepare(const struct asteriskd_config *config) {
    if (!config->bpf2socks_tc.enabled) return 0;
    if (restore_stale_route_localnet(config) != 0) return -1;
    return for_each_hotspot(config, delete_interface, NULL);
}

int asteriskd_bpf2socks_tc_sync(
    const struct asteriskd_config *config,
    struct asteriskd_state *state) {
    if (!config->bpf2socks_tc.enabled) return 0;
    if (access(config->bpf2socks_tc.ingress_path, R_OK) != 0 ||
        access(config->bpf2socks_tc.egress_path, R_OK) != 0) {
        return -1;
    }
    return for_each_hotspot(config, install_interface, state);
}

void asteriskd_bpf2socks_tc_restore(
    const struct asteriskd_config *config,
    struct asteriskd_state *state) {
    if (!config->bpf2socks_tc.enabled) return;
    (void)for_each_hotspot(config, delete_interface, state);
    for (size_t index = 0U; index < state->route_localnet_entry_count; ++index) {
        const struct asteriskd_route_localnet_state_entry *entry =
            &state->route_localnet_entries[index];
        char path[PATH_MAX];
        if (route_localnet_path(entry->interface_name, path, sizeof(path)) == 0 &&
            access(path, F_OK) == 0 &&
            write_route_localnet(entry->interface_name, entry->original_value) != 0) {
            asteriskd_log(
                state,
                "failed to restore route_localnet for %s: %s",
                entry->interface_name,
                strerror(errno));
        }
    }
    state->route_localnet_entry_count = 0U;
    (void)unlink(config->bpf2socks_tc.state_path);
}

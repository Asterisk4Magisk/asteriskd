// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

static const char *const capability_rules[] = {
    "allow netd * bpf { prog_run map_read map_write }",
    "allow netutils_wrapper * bpf { prog_run map_read map_write }",
};

static void capability_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) (void)snprintf(error, error_size, "%s", message);
}

static bool absolute_normal_path(const char *path) {
    if (path == NULL || path[0] != '/' || path[1] == '\0' ||
        strnlen(path, ASTERISKD_MAX_PATH) >= ASTERISKD_MAX_PATH) return false;
    const char *component = path + 1;
    while (*component != '\0') {
        const char *slash = strchr(component, '/');
        size_t length = slash == NULL ? strlen(component) : (size_t)(slash - component);
        if (length == 0U || (length == 1U && component[0] == '.') ||
            (length == 2U && component[0] == '.' && component[1] == '.')) return false;
        if (slash == NULL) break;
        component = slash + 1;
    }
    return true;
}

static int copy_path(char *destination, const char *source) {
    size_t length = source == NULL ? 0U : strnlen(source, ASTERISKD_MAX_PATH);
    if (length == 0U || length >= ASTERISKD_MAX_PATH) return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}

static int executable_candidate(
    const struct asteriskd_platform_capability_backend *backend,
    const char *path) {
    bool regular = false;
    bool executable = false;
    if (!absolute_normal_path(path) ||
        backend->inspect_executable(backend->context, path, &regular, &executable) != 0) return -1;
    return regular && executable ? 1 : 0;
}

static int path_candidate(
    const struct asteriskd_platform_capability_backend *backend,
    const char *name,
    char *path) {
    memset(path, 0, ASTERISKD_MAX_PATH);
    int found = backend->find_on_path(backend->context, name, path, ASTERISKD_MAX_PATH);
    if (found < 0) return -1;
    if (found == 0) return 0;
    return executable_candidate(backend, path);
}

static int fixed_candidate(
    const struct asteriskd_platform_capability_backend *backend,
    const char *fixed,
    char *path) {
    if (copy_path(path, fixed) != 0) return -1;
    return executable_candidate(backend, path);
}

static int discover_magisk_root(
    const struct asteriskd_platform_capability_backend *backend,
    char *root) {
    char magisk[ASTERISKD_MAX_PATH];
    int found = path_candidate(backend, "magisk", magisk);
    if (found <= 0) return found;
    const char *const argv[] = {magisk, "--path", NULL};
    int exit_code = 1;
    memset(root, 0, ASTERISKD_MAX_PATH);
    if (backend->execute(backend->context, argv, root, ASTERISKD_MAX_PATH, &exit_code) != 0 ||
        exit_code != 0) return 0;
    size_t length = strnlen(root, ASTERISKD_MAX_PATH);
    if (length == ASTERISKD_MAX_PATH) return 0;
    while (length != 0U && (root[length - 1U] == '\n' || root[length - 1U] == '\r' ||
        root[length - 1U] == ' ' || root[length - 1U] == '\t')) root[--length] = '\0';
    return absolute_normal_path(root) ? 1 : 0;
}

static int dynamic_candidate(
    const struct asteriskd_platform_capability_backend *backend,
    const char *root,
    const char *leaf,
    char *path) {
    int written = snprintf(path, ASTERISKD_MAX_PATH, "%s/%s", root, leaf);
    if (written <= 0 || (size_t)written >= ASTERISKD_MAX_PATH) return -1;
    return executable_candidate(backend, path);
}

static int select_tool(
    const struct asteriskd_platform_capability_backend *backend,
    enum asteriskd_capability_tool_kind *kind,
    char *path) {
    int found = path_candidate(backend, "magiskpolicy", path);
    if (found != 0) {
        if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY;
        return found;
    }
    found = path_candidate(backend, "supolicy", path);
    if (found != 0) {
        if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY;
        return found;
    }
    char root[ASTERISKD_MAX_PATH];
    found = discover_magisk_root(backend, root);
    if (found < 0) return -1;
    if (found > 0) {
        found = dynamic_candidate(backend, root, "magiskpolicy", path);
        if (found != 0) {
            if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY;
            return found;
        }
        found = dynamic_candidate(backend, root, "supolicy", path);
        if (found != 0) {
            if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY;
            return found;
        }
    }
    static const char *const live_fixed[] = {
        "/data/adb/magisk/magiskpolicy",
        "/data/adb/ap/bin/magiskpolicy",
    };
    for (size_t index = 0U; index < sizeof(live_fixed) / sizeof(live_fixed[0]); ++index) {
        found = fixed_candidate(backend, live_fixed[index], path);
        if (found != 0) {
            if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY;
            return found;
        }
    }
    found = path_candidate(backend, "ksud", path);
    if (found != 0) {
        if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_KSUD;
        return found;
    }
    static const char *const ksud_fixed[] = {
        "/data/adb/ksud",
        "/data/adb/ksu/bin/ksud",
    };
    for (size_t index = 0U; index < sizeof(ksud_fixed) / sizeof(ksud_fixed[0]); ++index) {
        found = fixed_candidate(backend, ksud_fixed[index], path);
        if (found != 0) {
            if (found > 0) *kind = ASTERISKD_CAPABILITY_TOOL_KSUD;
            return found;
        }
    }
    return 0;
}

static int execute_checked(
    const struct asteriskd_platform_capability_backend *backend,
    const char *const *argv) {
    char output[64];
    int exit_code = 1;
    return backend->execute(backend->context, argv, output, sizeof(output), &exit_code) == 0 &&
        exit_code == 0 ? 0 : -1;
}

int asteriskd_platform_capability_ensure(
    const struct asteriskd_config *config,
    const struct asteriskd_platform_capability_backend *backend,
    struct asteriskd_platform_capability_result *result,
    char *error,
    size_t error_size) {
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || backend == NULL || result == NULL || backend->find_on_path == NULL ||
        backend->inspect_executable == NULL || backend->execute == NULL) {
        capability_error(error, error_size, "invalid platform capability input");
        return ASTERISKD_CONFIG_INVALID;
    }
    result->required = config->matcher.enabled || config->mode == ASTERISKD_MODE_BPF2SOCKS;
    if (!result->required) return 0;
    int found = select_tool(backend, &result->tool_kind, result->tool_path);
    if (found <= 0) {
        capability_error(error, error_size, found < 0 ?
            "platform capability discovery failed" : "platform capability tool not found");
        return ASTERISKD_CONFIG_IO;
    }
    result->tool_found = true;
    for (size_t index = 0U; index < sizeof(capability_rules) / sizeof(capability_rules[0]); ++index) {
        int applied = -1;
        if (result->tool_kind == ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY) {
            const char *const argv[] = {result->tool_path, "--live", capability_rules[index], NULL};
            applied = execute_checked(backend, argv);
        } else {
            const char *const check[] = {
                result->tool_path, "sepolicy", "check", capability_rules[index], NULL,
            };
            const char *const patch[] = {
                result->tool_path, "sepolicy", "patch", capability_rules[index], NULL,
            };
            if (execute_checked(backend, check) == 0) applied = execute_checked(backend, patch);
        }
        if (applied != 0) {
            result->partial_application = result->applied_rule_count != 0U;
            capability_error(error, error_size, result->partial_application ?
                "platform capability partially applied" : "platform capability application failed");
            return ASTERISKD_CONFIG_IO;
        }
        ++result->applied_rule_count;
    }
    return 0;
}

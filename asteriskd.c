// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#endif

static uint32_t system_effective_uid(void *context) {
    (void)context;
#if defined(__linux__) || defined(__ANDROID__)
    return (uint32_t)geteuid();
#else
    return 0U;
#endif
}

static enum asteriskd_sync_result system_sync_path(
    void *context,
    const char *path,
    enum asteriskd_sync_target target) {
    (void)context;
    return asteriskd_sync_path(path, target);
}

static enum asteriskd_control_client_result system_control_client(
    void *context,
    enum asteriskd_control_method method,
    const char *request_id,
    asteriskd_control_line_sink sink,
    void *sink_context,
    struct asteriskd_control_response *response) {
    (void)context;
    return asteriskd_control_client_run(
        method, request_id, sink, sink_context, response);
}

static int system_run_start(
    void *context,
    const char *config_path,
    bool *has_early_result,
    struct asteriskd_control_result *early_result) {
    (void)context;
    return asteriskd_runtime_start_system(
        config_path, has_early_result, early_result);
}

static int recovery_result_message(
    struct asteriskd_recovery_result *result,
    const char *message) {
    size_t length = strlen(message);
    if (asteriskd_recovery_result_set_message(result, message, length) != 0 ||
        !asteriskd_recovery_result_valid(result)) {
        asteriskd_recovery_result_destroy(result);
        return -1;
    }
    return 0;
}

int asteriskd_recovery_classify_state_with_backend(
    const struct asteriskd_runtime_directory *directory,
    const struct asteriskd_state_file_backend *backend,
    void *backend_context,
    struct asteriskd_recovery_result *result) {
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (directory == NULL || result == NULL || !directory->owned || directory->fd < 0 ||
        directory->device == 0U || directory->inode == 0U) return -1;

    char error[256];
    struct asteriskd_state_store store;
    int initialized = backend == NULL ?
        asteriskd_state_store_init(
            &store, directory->fd, directory->device, directory->inode,
            error, sizeof(error)) :
        asteriskd_state_store_init_with_backend(
            &store, directory->fd, directory->device, directory->inode,
            backend, backend_context, error, sizeof(error));
    if (initialized != ASTERISKD_STATE_OK) {
        result->code = ASTERISKD_RECOVERY_INTERNAL_ERROR;
        return recovery_result_message(result, "state store initialization failed");
    }

    struct asteriskd_state_document state;
    memset(&state, 0, sizeof(state));
    int loaded = asteriskd_state_store_load(&store, &state, error, sizeof(error));
    int classified = 0;
    if (loaded == ASTERISKD_STATE_NOT_FOUND) {
        result->code = ASTERISKD_RECOVERY_CLEAN;
        result->has_core_owned_ebpf_boundary = true;
    } else if (loaded == ASTERISKD_STATE_OK &&
        asteriskd_state_is_canonical_stopped(&state)) {
        result->code = ASTERISKD_RECOVERY_CLEAN;
        result->has_identity = true;
        result->owner = state.owner;
        result->core_type = state.core_type;
        result->mode = state.mode;
        result->has_core_owned_ebpf_boundary = true;
    } else if (loaded == ASTERISKD_STATE_OK) {
        result->code = ASTERISKD_RECOVERY_REQUIRED;
        result->has_identity = true;
        result->owner = state.owner;
        result->core_type = state.core_type;
        result->mode = state.mode;
        result->has_core_owned_ebpf_boundary = true;
        result->core_owned_ebpf_boundary = state.recovery.core_owned_ebpf_boundary;
        classified = recovery_result_message(
            result, "dirty state requires runtime recovery");
    } else if (loaded == ASTERISKD_STATE_INVALID ||
        loaded == ASTERISKD_STATE_INCOMPATIBLE) {
        result->code = ASTERISKD_RECOVERY_REQUIRED;
        classified = recovery_result_message(
            result, "state evidence is incompatible or invalid");
    } else {
        result->code = ASTERISKD_RECOVERY_INTERNAL_ERROR;
        classified = recovery_result_message(result, "state read failed");
    }
    if (classified == 0 && !asteriskd_recovery_result_valid(result)) classified = -1;
    asteriskd_state_document_destroy(&state);
    asteriskd_state_store_close(&store);
    if (classified != 0) asteriskd_recovery_result_destroy(result);
    return classified;
}

int asteriskd_recovery_classify_state(
    const struct asteriskd_runtime_directory *directory,
    struct asteriskd_recovery_result *result) {
    return asteriskd_recovery_classify_state_with_backend(
        directory, NULL, NULL, result);
}

static int system_recovery_gate(
    void *context,
    const char *config_path,
    struct asteriskd_recovery_result *result) {
    (void)context;
    struct asteriskd_runtime_directory directory;
    char error[256U];
    if (asteriskd_runtime_directory_open(
            config_path, &directory, error, sizeof(error)) != 0) return -1;
    int classified = asteriskd_recovery_classify_state(&directory, result);
    asteriskd_runtime_directory_release(&directory);
    if (classified != 0) return -1;
    if (result->code != ASTERISKD_RECOVERY_REQUIRED || !result->has_identity) return 0;
    asteriskd_recovery_result_destroy(result);
    return asteriskd_runtime_recover_system(config_path, result);
}

static int system_write_fd(int fd, const char *bytes, size_t length) {
#if defined(__linux__) || defined(__ANDROID__)
    size_t offset = 0U;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > length - offset) return -1;
        offset += (size_t)count;
    }
    return 0;
#else
    FILE *stream = fd == 1 ? stdout : stderr;
    return fwrite(bytes, 1U, length, stream) == length && fflush(stream) == 0 ? 0 : -1;
#endif
}

static int system_write_stdout(void *context, const char *bytes, size_t length) {
    (void)context;
    return system_write_fd(1, bytes, length);
}

static int system_write_stderr(void *context, const char *bytes, size_t length) {
    (void)context;
    return system_write_fd(2, bytes, length);
}

static const struct asteriskd_cli_backend system_cli_backend = {
    .effective_uid = system_effective_uid,
    .sync_path = system_sync_path,
    .control_client = system_control_client,
    .run_start = system_run_start,
    .recovery_gate = system_recovery_gate,
    .write_stdout = system_write_stdout,
    .write_stderr = system_write_stderr,
};

int asteriskd_cli_main(int argc, const char *const *argv) {
    return asteriskd_cli_main_with_backend(argc, argv, &system_cli_backend, NULL);
}

#ifndef ASTERISKD_TESTING
int main(int argc, char **argv) {
    return asteriskd_cli_main(argc, (const char *const *)argv);
}
#endif

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

static int system_prepare_session(void) {
#if defined(__linux__) || defined(__ANDROID__)
    if (getpgrp() == getpid()) {
        pid_t pid = fork();
        if (pid < 0) {
            char message[96U];
            (void)snprintf(message, sizeof(message), "supervisor fork failed: errno=%d", errno);
            asteriskd_log_stderr(ASTERISKD_LOG_LEVEL_ERROR, ASTERISKD_COMPONENT_RUNTIME, message);
            return -1;
        }
        if (pid > 0) return 1;
    }
    if (setsid() < 0) {
        char message[96U];
        (void)snprintf(message, sizeof(message), "supervisor setsid failed: errno=%d", errno);
        asteriskd_log_stderr(ASTERISKD_LOG_LEVEL_ERROR, ASTERISKD_COMPONENT_RUNTIME, message);
        return -1;
    }
#endif
    return 0;
}

static void system_log_early_result(const char *mode, int status,
    bool has_result, const struct asteriskd_control_result *result) {
    if (!has_result) return;
    char message[384U];
    (void)snprintf(message, sizeof(message), "supervisor exited before ready: mode=%s status=%d code=%d detail=%.256s",
        mode, status, (int)result->code,
        result->has_message && result->message != NULL ? result->message : "unavailable");
    asteriskd_log_stderr(status == 0 ? ASTERISKD_LOG_LEVEL_INFO : ASTERISKD_LOG_LEVEL_ERROR,
        ASTERISKD_COMPONENT_RUNTIME, message);
}

static int system_run_start(
    void *context,
    const char *config_path,
    bool *has_early_result,
    struct asteriskd_control_result *early_result) {
    (void)context;
    int session = system_prepare_session();
    if (session != 0) return session < 0 ? -1 : 0;
    asteriskd_log_stderr(ASTERISKD_LOG_LEVEL_INFO, ASTERISKD_COMPONENT_RUNTIME,
        "entering supervisor runtime: mode=start");
    int status = asteriskd_runtime_start_system(
        config_path, has_early_result, early_result);
    system_log_early_result("start", status, *has_early_result, early_result);
    return status;
}

static int system_run_monitor(
    void *context,
    const char *config_path,
    bool *has_early_result,
    struct asteriskd_control_result *early_result) {
    (void)context;
    int session = system_prepare_session();
    if (session != 0) return session < 0 ? -1 : 0;
    asteriskd_log_stderr(ASTERISKD_LOG_LEVEL_INFO, ASTERISKD_COMPONENT_RUNTIME,
        "entering supervisor runtime: mode=monitor");
    int status = asteriskd_runtime_monitor_system(
        config_path, has_early_result, early_result);
    system_log_early_result("monitor", status, *has_early_result, early_result);
    return status;
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
    .control_client = system_control_client,
    .run_start = system_run_start,
    .run_monitor = system_run_monitor,
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

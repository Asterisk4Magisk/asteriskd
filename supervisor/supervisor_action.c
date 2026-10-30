// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

#define ASTERISKD_ACTION_IDENTITY_RETRY_MILLISECONDS 10U

static int system_periodic_deadline(
    int64_t now, int64_t caller_deadline, uint32_t interval,
    int64_t *iteration_deadline) {
    if (now < 0 || caller_deadline < 0 || interval == 0U || iteration_deadline == NULL) return -1;
    *iteration_deadline = caller_deadline;
    if (now >= caller_deadline) return 0;
    if (now <= INT64_MAX - (int64_t)interval) {
        int64_t periodic = now + (int64_t)interval;
        if (periodic < caller_deadline) *iteration_deadline = periodic;
    }
    return 0;
}

static int system_capability_path_search_result(bool found, bool valid_input) {
    return !valid_input ? -1 : found ? 1 : 0;
}

static int system_capability_inspect_error(int error_number) {
    return error_number == ENOENT || error_number == ENOTDIR ? 0 : -1;
}

static int system_action_post_setup(
    const struct asteriskd_child_setup_stream *setup,
    bool reaped,
    const struct asteriskd_child_exit_status *status,
    int *exit_status) {
    if (setup == NULL || status == NULL || exit_status == NULL ||
        !setup->complete || setup->fatal) return ASTERISKD_CONFIG_INVALID;
    if (!reaped) return 0;
    if (!status->has_exit_code || status->has_signal) return ASTERISKD_CONFIG_INVALID;
    *exit_status = status->exit_code;
    return 1;
}

static bool system_action_identity_wait_can_retry(
    bool cancelled, int64_t now_milliseconds, int64_t deadline_milliseconds) {
    return !cancelled && now_milliseconds >= 0 && deadline_milliseconds >= 0 &&
        now_milliseconds < deadline_milliseconds;
}

static int system_action_post_identity(
    int identity_result, int reap_result,
    const struct asteriskd_child_setup_stream *setup,
    bool reaped, const struct asteriskd_child_exit_status *status,
    int *exit_status) {
    if (identity_result == 0) return 0;
    if (reap_result == 0) return ASTERISKD_CONFIG_NOT_READY;
    if (reap_result < 0) return ASTERISKD_CONFIG_INVALID;
    int post_setup = system_action_post_setup(setup, reaped, status, exit_status);
    return post_setup > 0 ? post_setup : ASTERISKD_CONFIG_INVALID;
}

static bool system_action_setup_wait_done_state(
    const struct asteriskd_child_setup_stream *setup, bool reaped) {
    (void)reaped;
    return setup != NULL && (setup->complete || setup->fatal);
}

static bool system_action_io_drained_state(
    bool reaped, bool owns_setup, bool owns_stdout, bool owns_stderr) {
    return reaped && !owns_setup && !owns_stdout && !owns_stderr;
}

bool asteriskd_supervisor_action_should_cancel(
    bool stop_requested, bool cleanup_in_progress) {
    return !cleanup_in_progress && stop_requested;
}

static bool system_action_setup_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return system_action_setup_wait_done_state(
        &system->action_setup, system->action_reaped);
}

static bool system_action_exit_done(void *opaque) {
    return ((struct asteriskd_system_supervisor *)opaque)->action_reaped;
}

static bool system_action_io_drained_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return system_action_io_drained_state(
        system->action_reaped,
        system->action_process.owns_setup_status_fd,
        system->action_process.owns_stdout_fd,
        system->action_process.owns_stderr_fd);
}

int asteriskd_supervisor_pump_condition(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, asteriskd_runtime_predicate predicate) {
    for (;;) {
        if (predicate(system)) return 0;
        int64_t now = 0;
        if (asteriskd_supervisor_runtime_clock(system, &now) != 0 ||
            now >= deadline->monotonic_milliseconds) return -1;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system->runtime, deadline, &delta) != 0) return -1;
        if (asteriskd_supervisor_accept_pump_delta(system, &delta) != 0) return -1;
    }
}

int asteriskd_supervisor_pump_condition_periodic(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, uint32_t interval,
    asteriskd_runtime_predicate predicate) {
    if (deadline == NULL || !deadline->armed || predicate == NULL) return -1;
    for (;;) {
        if (predicate(system)) return 0;
        int64_t now = 0;
        if (asteriskd_supervisor_runtime_clock(system, &now) != 0 ||
            now >= deadline->monotonic_milliseconds) return -1;
        struct asteriskd_deadline iteration = {.armed = true};
        if (system_periodic_deadline(now, deadline->monotonic_milliseconds,
                interval, &iteration.monotonic_milliseconds) != 0) return -1;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system->runtime, &iteration, &delta) != 0) return -1;
        if (asteriskd_supervisor_accept_pump_delta(system, &delta) != 0) return -1;
    }
}

/* Wait for a started stop coordinator. Wake at the TERM grace deadline so
 * SIGKILL goes out on time and the reap still gets the full KILL window. */
int asteriskd_supervisor_pump_stop(struct asteriskd_system_supervisor *system) {
    const struct asteriskd_stop_coordinator *coordinator = &system->stop_coordinator;
    if (coordinator->kill_deadline_milliseconds > (uint64_t)INT64_MAX) return -1;
    const int64_t term_deadline = (int64_t)coordinator->term_deadline_milliseconds;
    const struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = (int64_t)coordinator->kill_deadline_milliseconds,
    };
    for (;;) {
        if (asteriskd_supervisor_stop_done(system)) return 0;
        int64_t now = 0;
        if (asteriskd_supervisor_runtime_clock(system, &now) != 0 ||
            now >= deadline.monotonic_milliseconds) return -1;
        struct asteriskd_deadline iteration = deadline;
        if (now < term_deadline) iteration.monotonic_milliseconds = term_deadline;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system->runtime, &iteration, &delta) != 0) return -1;
        if (asteriskd_supervisor_accept_pump_delta(system, &delta) != 0) return -1;
    }
}

static int system_action_signal_unverified(
    struct asteriskd_system_supervisor *system, int signal_number) {
    pid_t pid = (pid_t)system->action_process.pid;
    if (pid <= 0) return -1;
    pid_t process_group = getpgid(pid);
    int result = process_group == pid ? kill(-pid, signal_number) : kill(pid, signal_number);
    return result == 0 || errno == ESRCH ? 0 : -1;
}

static int system_action_cleanup(struct asteriskd_system_supervisor *system,
    const struct asteriskd_process_spec *spec) {
    if (!system->action_spawned || system->action_reaped) return 0;
    int64_t now = 0;
    if (asteriskd_supervisor_runtime_clock(system, &now) != 0 || now < 0 ||
        now > INT64_MAX - (int64_t)(ASTERISKD_PROCESS_TERM_GRACE_MILLIS +
            ASTERISKD_PROCESS_KILL_REAP_MILLIS)) return -1;

    if (system->action_identity_ready) {
        if (asteriskd_system_process_backends_init(&system->process_context,
                spec, spec, &system->readiness_backend, &system->stop_backend) != 0) return -1;
        asteriskd_stop_coordinator_init(&system->stop_coordinator);
        system->stopping_children = true;
        system->stop_result = asteriskd_stop_coordinator_begin(
            &system->stop_coordinator, NULL, &system->action_identity,
            &system->stop_backend, (uint64_t)now);
        if (system->stop_result == ASTERISKD_STOP_PENDING &&
            asteriskd_supervisor_pump_stop(system) != 0) {
            system->stop_result = ASTERISKD_STOP_FAILED;
        }
        system->stopping_children = false;
        if (system->stop_result != ASTERISKD_STOP_COMPLETE) return -1;
        system->action_reaped = true;
        system->action_exit = system->stop_coordinator.helper.exit_status;
        return 0;
    }

    if (system_action_signal_unverified(system, SIGTERM) != 0) return -1;
    struct asteriskd_deadline term_deadline = {
        .armed = true,
        .monotonic_milliseconds = now + ASTERISKD_PROCESS_TERM_GRACE_MILLIS,
    };
    if (asteriskd_supervisor_pump_condition(system, &term_deadline, system_action_exit_done) == 0 &&
        system->action_reaped) return 0;
    if (system_action_signal_unverified(system, SIGKILL) != 0) return -1;
    struct asteriskd_deadline kill_deadline = {
        .armed = true,
        .monotonic_milliseconds = term_deadline.monotonic_milliseconds +
            ASTERISKD_PROCESS_KILL_REAP_MILLIS,
    };
    return asteriskd_supervisor_pump_condition(system, &kill_deadline, system_action_exit_done) == 0 &&
        system->action_reaped ? 0 : -1;
}

static int system_action_reap_now(struct asteriskd_system_supervisor *system) {
    for (;;) {
        int status = 0;
        pid_t pid = waitpid((pid_t)system->action_process.pid, &status, WNOHANG);
        if (pid == 0) return 0;
        if (pid == (pid_t)system->action_process.pid) {
            asteriskd_supervisor_runtime_note_action_exit(system, status);
            return 1;
        }
        if (pid < 0 && errno == EINTR) continue;
        if (pid < 0 && errno == ECHILD && system->action_reaped) return 1;
        return -1;
    }
}

/* Failures during best-effort owned cleanup, or after a stop was requested, are
 * consequences of another cause; the terminal failure is logged as an error. */
void asteriskd_supervisor_log_failure(struct asteriskd_system_supervisor *system,
    enum asteriskd_component component, const char *message) {
    if (system == NULL || message == NULL || !system->logger.opened) return;
    bool secondary = system->owned_cleanup_in_progress ||
        (system->runtime != NULL && atomic_load_explicit(
            &system->runtime->lifecycle.stop_was_requested, memory_order_acquire));
    (void)asteriskd_log_line(&system->logger,
        secondary ? ASTERISKD_LOG_LEVEL_WARNING : ASTERISKD_LOG_LEVEL_ERROR,
        component, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
}

/* Collapse captured action stderr into one printable line for diagnostics. */
void asteriskd_supervisor_action_stderr_summary(
    const struct asteriskd_system_supervisor *system, char *out, size_t size) {
    if (out == NULL || size == 0U) return;
    size_t used = 0U;
    bool pending_space = false;
    for (size_t index = 0U; system != NULL && index < system->action_stderr_length &&
            used + 1U < size; ++index) {
        unsigned char byte = (unsigned char)system->action_stderr[index];
        if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n') {
            pending_space = used != 0U;
            continue;
        }
        if (pending_space) {
            out[used++] = ' ';
            pending_space = false;
            if (used + 1U >= size) break;
        }
        out[used++] = byte < 0x21U || byte >= 0x7fU ? '?' : (char)byte;
    }
    out[used] = '\0';
    if (used == 0U) {
        (void)snprintf(out, size, "%s", "none");
    } else if (system->action_stderr_length == sizeof(system->action_stderr) &&
        used + 4U < size) {
        memcpy(&out[used], "...", 4U);
    }
}

/*
 * Grows captured stdout to hold at least `wanted` bytes. A failed or
 * over-limit request keeps the current buffer, so callers see overflow.
 */
int asteriskd_supervisor_action_stdout_reserve(
    struct asteriskd_system_supervisor *system, size_t wanted) {
    if (system == NULL || wanted > ASTERISKD_ACTION_STDOUT_LIMIT) return -1;
    if (wanted <= system->action_stdout_capacity) return 0;
    size_t capacity = system->action_stdout_capacity == 0U
        ? ASTERISKD_ACTION_STDOUT_INITIAL : system->action_stdout_capacity;
    while (capacity < wanted) capacity *= 2U;
    if (capacity > ASTERISKD_ACTION_STDOUT_LIMIT) capacity = ASTERISKD_ACTION_STDOUT_LIMIT;
    char *bytes = realloc(system->action_stdout, capacity);
    if (bytes == NULL) return -1;
    system->action_stdout = bytes;
    system->action_stdout_capacity = capacity;
    return 0;
}

void asteriskd_supervisor_action_stdout_release(struct asteriskd_system_supervisor *system) {
    if (system == NULL) return;
    free(system->action_stdout);
    system->action_stdout = NULL;
    system->action_stdout_capacity = 0U;
    system->action_stdout_length = 0U;
}

int asteriskd_supervisor_action_run_spec(struct asteriskd_system_supervisor *system,
    const struct asteriskd_process_spec *spec, bool capture_stdout, int *exit_status) {
    if (system->action_spawned || spec == NULL || exit_status == NULL) {
        if (system != NULL && system->logger.opened) {
            char message[192U];
            int written = snprintf(message, sizeof(message),
                "action execution rejected: busy=%d spec=%d exitStatus=%d",
                system->action_spawned ? 1 : 0, spec != NULL ? 1 : 0,
                exit_status != NULL ? 1 : 0);
            if (written > 0 && (size_t)written < sizeof(message)) {
                (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                    ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
            }
        }
        return -1;
    }
    char error[128U] = {0};
    const char *failure_phase = "spawn";
    memset(&system->action_process, 0, sizeof(system->action_process));
    system->action_process.pid = -1;
    system->action_process.process_group_id = -1;
    system->action_process.pidfd = -1;
    system->action_process.stdout_fd = -1;
    system->action_process.stderr_fd = -1;
    system->action_process.setup_status_fd = -1;
    memset(&system->action_exit, 0, sizeof(system->action_exit));
    system->action_reaped = false;
    system->action_identity_ready = false;
    system->action_capture_stdout = capture_stdout;
    system->action_stdout_overflow = false;
    system->action_stdout_length = 0U;
    system->action_stderr_length = 0U;
    if (asteriskd_process_spawn_system(spec, &system->action_process,
            error, sizeof(error)) != 0) {
        char message[256U];
        int written = snprintf(message, sizeof(message),
            "action execution failed: phase=spawn detail=%s",
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger,
                system->owned_cleanup_in_progress ? ASTERISKD_LOG_LEVEL_WARNING : ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    system->action_spawned = true;
    asteriskd_child_setup_stream_init(&system->action_setup);
    int64_t now = 0;
    failure_phase = "setup-clock";
    if (asteriskd_supervisor_runtime_clock(system, &now) != 0) goto failed;
    struct asteriskd_deadline setup_deadline = {
        .armed = true,
        .monotonic_milliseconds = now +
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
    };
    failure_phase = "setup-wait";
    if (asteriskd_supervisor_pump_condition(system, &setup_deadline, system_action_setup_done) != 0) goto failed;
    int completed_exit = -1;
    failure_phase = "setup-result";
    int post_setup = system_action_post_setup(
        &system->action_setup, system->action_reaped, &system->action_exit, &completed_exit);
    if (post_setup < 0) goto failed;
    if (post_setup > 0) goto early_exit;
    failure_phase = "identity";
    int identity_result = asteriskd_process_identity_read(
            asteriskd_system_process_identity_backend(),
            system->action_process.pid, ASTERISKD_CHILD_HELPER,
            ASTERISKD_CHILD_TYPE_BPF2SOCKS, spec, &system->action_identity,
            error, sizeof(error));
    while (identity_result != 0) {
        int post_identity = system_action_post_identity(
            identity_result, system_action_reap_now(system), &system->action_setup,
            system->action_reaped, &system->action_exit, &completed_exit);
        if (post_identity > 0) goto early_exit;
        if (post_identity != ASTERISKD_CONFIG_NOT_READY ||
            asteriskd_supervisor_runtime_clock(system, &now) != 0 ||
            !system_action_identity_wait_can_retry(
                asteriskd_supervisor_action_should_cancel(atomic_load_explicit(
                    &system->runtime->lifecycle.stop_was_requested,
                    memory_order_acquire), system->cleanup_in_progress),
                now, setup_deadline.monotonic_milliseconds)) goto failed;
        struct asteriskd_deadline retry_deadline = {
            .armed = true,
        };
        if (system_periodic_deadline(
                now, setup_deadline.monotonic_milliseconds,
                ASTERISKD_ACTION_IDENTITY_RETRY_MILLISECONDS,
                &retry_deadline.monotonic_milliseconds) != 0) goto failed;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(
                system->runtime, &retry_deadline, &delta) != 0 ||
            asteriskd_supervisor_accept_pump_delta(system, &delta) != 0) goto failed;
        identity_result = asteriskd_process_identity_read(
            asteriskd_system_process_identity_backend(),
            system->action_process.pid, ASTERISKD_CHILD_HELPER,
            ASTERISKD_CHILD_TYPE_BPF2SOCKS, spec, &system->action_identity,
            error, sizeof(error));
    }
    system->action_identity_ready = true;
    failure_phase = "exit-clock";
    if (asteriskd_supervisor_runtime_clock(system, &now) != 0 || now > INT64_MAX - INT64_C(110000)) goto failed;
    struct asteriskd_deadline exit_deadline = {
        .armed = true,
        .monotonic_milliseconds = now + INT64_C(110000),
    };
    failure_phase = "cancelled";
    if (asteriskd_supervisor_action_should_cancel(atomic_load_explicit(
            &system->runtime->lifecycle.stop_was_requested,
            memory_order_acquire), system->cleanup_in_progress)) {
        goto failed;
    }
    failure_phase = "exit-wait";
    if (asteriskd_supervisor_pump_condition(system, &exit_deadline, system_action_exit_done) != 0 ||
        !system->action_reaped || !system->action_exit.has_exit_code ||
        system->action_exit.has_signal) goto failed;
    failure_phase = "exit-drain";
    if (asteriskd_supervisor_pump_condition(
            system, &exit_deadline, system_action_io_drained_done) != 0) goto failed;
    *exit_status = system->action_exit.exit_code;
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return 0;

early_exit:
    failure_phase = "early-exit-drain";
    if (asteriskd_supervisor_pump_condition(
            system, &setup_deadline, system_action_io_drained_done) != 0) goto failed;
    *exit_status = completed_exit;
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return 0;

failed:
    {
        char stderr_summary[256U];
        asteriskd_supervisor_action_stderr_summary(system, stderr_summary, sizeof(stderr_summary));
        char message[640U];
        int written = snprintf(message, sizeof(message),
            "action execution failed: phase=%s reaped=%d setupComplete=%d setupFatal=%d "
            "detail=%s stderr=%s",
            failure_phase, system->action_reaped ? 1 : 0,
            system->action_setup.complete ? 1 : 0,
            system->action_setup.fatal ? 1 : 0,
            error[0] == '\0' ? "unavailable" : error, stderr_summary);
        if (written > 0 && (size_t)written < sizeof(message)) {
            asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_RUNTIME, message);
        }
    }
    (void)system_action_cleanup(system, spec);
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return -1;
}

static int system_capability_find(
    void *opaque, const char *name, char *path, size_t capacity);

static int system_action_spec(const char *const *argv, struct asteriskd_process_spec *spec) {
    if (argv == NULL || argv[0] == NULL || argv[0][0] == '\0' || spec == NULL) return -1;
    const char *executable = argv[0];
    char *resolved = NULL;
    if (executable[0] != '/') {
        char path[ASTERISKD_MAX_PATH];
        if (system_capability_find(NULL, executable, path, sizeof(path)) != 1) return -1;
        resolved = realpath(path, NULL);
        if (resolved == NULL) return -1;
        executable = resolved;
    }
    memset(spec, 0, sizeof(*spec));
    int executable_length = snprintf(
        spec->executable_path, sizeof(spec->executable_path), "%s", executable);
    free(resolved);
    int directory_length = snprintf(
        spec->working_directory, sizeof(spec->working_directory), "%s", "/");
    if (executable_length <= 0 || (size_t)executable_length >= sizeof(spec->executable_path) ||
        directory_length <= 0 || (size_t)directory_length >= sizeof(spec->working_directory)) {
        return -1;
    }
    spec->uid = 0U;
    spec->gid = 0U;
    spec->output_mode = ASTERISKD_PROCESS_OUTPUT_CAPTURE;
    if (asteriskd_process_environment_rebuild(
            (const char *const *)environ, spec) != 0) goto failed;
    for (size_t index = 0U; argv[index] != NULL; ++index) {
        if (asteriskd_process_argument_add(spec, argv[index]) != 0) goto failed;
    }
    return 0;
failed:
    asteriskd_process_spec_destroy(spec);
    return -1;
}

int asteriskd_supervisor_action_run_argv(struct asteriskd_system_supervisor *system,
    const char *const *argv, bool capture_stdout, int *exit_status) {
    struct asteriskd_process_spec spec;
    memset(&spec, 0, sizeof(spec));
    if (system_action_spec(argv, &spec) != 0) return -1;
    int result = asteriskd_supervisor_action_run_spec(system, &spec, capture_stdout, exit_status);
    asteriskd_process_spec_destroy(&spec);
    return result;
}

/*
 * Appends one batch line of space-separated tokens. Tokens never contain
 * whitespace or quotes, so iptables-restore and the ip queue split them
 * exactly as the caller passed them.
 */
int asteriskd_supervisor_rule_batch_append_line(
    struct asteriskd_byte_buffer *batch, const char *const *tokens) {
    if (batch == NULL || tokens == NULL || tokens[0] == NULL) return -1;
    for (size_t index = 0U; tokens[index] != NULL; ++index) {
        const char *token = tokens[index];
        size_t length = strlen(token);
        if (length == 0U || strpbrk(token, " \t\r\n\"'\\") != NULL ||
            (index != 0U && asteriskd_byte_buffer_append(batch, " ", 1U) != 0) ||
            asteriskd_byte_buffer_append(batch, token, length) != 0) return -1;
    }
    return asteriskd_byte_buffer_append(batch, "\n", 1U);
}

void asteriskd_supervisor_rule_batch_destroy(struct system_rule_command_batch *batch) {
    if (batch == NULL) return;
    for (size_t stage = 0U; stage < SYSTEM_RULE_BATCH_STAGES; ++stage) {
        for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
            for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
                asteriskd_byte_buffer_destroy(&batch->xtables[stage][family][table]);
            }
        }
    }
    asteriskd_byte_buffer_destroy(&batch->ip);
    batch->ip_started = false;
    batch->active = false;
}

int asteriskd_supervisor_rule_batch_begin(struct system_rule_command_batch *batch) {
    if (batch == NULL || batch->active) return -1;
    asteriskd_supervisor_rule_batch_destroy(batch);
    batch->active = true;
    return 0;
}

static int system_action_run_document(
    struct asteriskd_system_supervisor *system,
    const char *const *argv,
    const struct asteriskd_byte_buffer *batch,
    int *exit_status) {
    if (system == NULL || argv == NULL || batch == NULL || batch->length == 0U ||
        exit_status == NULL) return -1;
    const struct asteriskd_anonymous_file_backend *backend =
        asteriskd_system_anonymous_file_backend();
    struct asteriskd_anonymous_document document = {
        .bytes = batch->bytes,
        .length = batch->length,
    };
    struct asteriskd_anonymous_file file;
    memset(&file, 0, sizeof(file));
    char error[128U];
    if (asteriskd_anonymous_file_create(
            backend, "asteriskd-rule-batch", &document,
            &file, error, sizeof(error)) != 0) return -1;
    struct asteriskd_process_spec spec;
    memset(&spec, 0, sizeof(spec));
    int result = -1;
    if (system_action_spec(argv, &spec) == 0) {
        spec.inherited_fds[0] = file.fd;
        spec.inherited_fd_targets[0] = 3;
        spec.inherited_fd_count = 1U;
        result = asteriskd_supervisor_action_run_spec(system, &spec, false, exit_status);
    }
    asteriskd_process_spec_destroy(&spec);
    if (asteriskd_anonymous_file_close(backend, &file) != 0) result = -1;
    return result;
}

static void system_rule_batch_log_failure(struct asteriskd_system_supervisor *system,
    const char *phase, const char *family, int exit_status) {
    char stderr_summary[256U];
    asteriskd_supervisor_action_stderr_summary(system, stderr_summary, sizeof(stderr_summary));
    char message[384U];
    int written = snprintf(message, sizeof(message),
        "rule batch commit failed: phase=%s family=%s exitStatus=%d stderr=%s",
        phase, family, exit_status, stderr_summary);
    if (written > 0 && (size_t)written < sizeof(message)) {
        asteriskd_supervisor_log_failure(system, ASTERISKD_COMPONENT_RULES, message);
    }
}

/* Commits one stage of one family through a single iptables-restore process. */
static int system_rule_batch_flush_xtables(struct asteriskd_system_supervisor *system,
    size_t stage, enum asteriskd_ip_family family) {
    const char *table_names[ASTERISKD_IP_TABLE_COUNT];
    for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
        table_names[table] = asteriskd_supervisor_table_name((enum asteriskd_ip_table)table);
    }
    struct asteriskd_byte_buffer document = {0};
    const char *family_name = family == ASTERISKD_IP_FAMILY_IPV4 ? "ipv4" : "ipv6";
    if (asteriskd_rule_batch_restore_render(table_names,
            system->rule_commands.xtables[stage][family], ASTERISKD_IP_TABLE_COUNT,
            &document.bytes, &document.length) != 0) {
        system_rule_batch_log_failure(system, "render", family_name, -1);
        return -1;
    }
    if (document.length == 0U) return 0;
    const char *argv[] = {
        family == ASTERISKD_IP_FAMILY_IPV4 ? "iptables-restore" : "ip6tables-restore",
        "-w", "100", "--noflush", "/proc/self/fd/3", NULL,
    };
    int exit_status = -1;
    int result = system_action_run_document(system, argv, &document, &exit_status);
    asteriskd_byte_buffer_destroy(&document);
    if (result == 0 && exit_status == 0) return 0;
    /* A run failure is already logged by the action runner. */
    if (result == 0) system_rule_batch_log_failure(system, "restore", family_name, exit_status);
    return -1;
}

/* Runs queued ip commands in order through rtnetlink. */
static int system_rule_batch_flush_ip(struct asteriskd_system_supervisor *system) {
    const struct asteriskd_byte_buffer *queue = &system->rule_commands.ip;
    size_t offset = 0U;
    while (offset < queue->length) {
        const unsigned char *newline = memchr(queue->bytes + offset, '\n', queue->length - offset);
        if (newline == NULL) return -1;
        size_t length = (size_t)(newline - (queue->bytes + offset));
        char line[512U];
        if (length == 0U || length >= sizeof(line)) return -1;
        memcpy(line, queue->bytes + offset, length);
        line[length] = '\0';
        offset += length + 1U;
        const char *tokens[24U];
        size_t count = 0U;
        char *cursor = NULL;
        for (char *token = strtok_r(line, " ", &cursor); token != NULL;
                token = strtok_r(NULL, " ", &cursor)) {
            if (count == sizeof(tokens) / sizeof(tokens[0])) return -1;
            tokens[count++] = token;
        }
        if (count < 3U || (strcmp(tokens[0], "4") != 0 && strcmp(tokens[0], "6") != 0)) return -1;
        enum asteriskd_ip_family family = tokens[0][0] == '4'
            ? ASTERISKD_IP_FAMILY_IPV4 : ASTERISKD_IP_FAMILY_IPV6;
        int exit_status = -1;
        if (asteriskd_supervisor_rtnl_ip(system, family, &tokens[1], count - 1U,
                false, &exit_status) != 0 || exit_status != 0) {
            system_rule_batch_log_failure(system, "ip",
                family == ASTERISKD_IP_FAMILY_IPV4 ? "ipv4" : "ipv6", exit_status);
            return -1;
        }
    }
    return 0;
}

/*
 * Commits the queued commands: private chains, then routing, then hooks.
 * Each table of each family is replaced atomically; a failed table leaves
 * earlier commits in place for the caller's cleanup, as before.
 */
int asteriskd_supervisor_rule_batch_flush(
    struct asteriskd_system_supervisor *system) {
    struct system_rule_command_batch *batch = &system->rule_commands;
    if (!batch->active) return -1;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        if (system_rule_batch_flush_xtables(system, 0U, (enum asteriskd_ip_family)family) != 0) {
            return -1;
        }
    }
    if (system_rule_batch_flush_ip(system) != 0) return -1;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        if (system_rule_batch_flush_xtables(system, 1U, (enum asteriskd_ip_family)family) != 0) {
            return -1;
        }
    }
    return 0;
}

static int system_capability_find(
    void *opaque, const char *name, char *path, size_t capacity) {
    (void)opaque;
    const char *environment = getenv("PATH");
    if (name == NULL || name[0] == '\0' || strchr(name, '/') != NULL ||
        environment == NULL || path == NULL || capacity == 0U) {
        return system_capability_path_search_result(false, false);
    }
    const char *cursor = environment;
    while (*cursor != '\0') {
        const char *separator = strchr(cursor, ':');
        size_t length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        if (length != 0U && length < ASTERISKD_MAX_PATH) {
            char directory[ASTERISKD_MAX_PATH];
            memcpy(directory, cursor, length);
            directory[length] = '\0';
            int written = snprintf(path, capacity, "%s/%s", directory, name);
            struct stat status;
            if (written > 0 && (size_t)written < capacity && stat(path, &status) == 0 &&
                S_ISREG(status.st_mode) && asteriskd_mode_is_executable((uint32_t)status.st_mode)) {
                return system_capability_path_search_result(true, true);
            }
        }
        if (separator == NULL) break;
        cursor = separator + 1;
    }
    return system_capability_path_search_result(false, true);
}

static int system_capability_inspect(
    void *opaque, const char *path, bool *regular, bool *executable) {
    (void)opaque;
    if (path == NULL || regular == NULL || executable == NULL) return -1;
    struct stat status;
    if (stat(path, &status) != 0) {
        *regular = false;
        *executable = false;
        return system_capability_inspect_error(errno);
    }
    *regular = S_ISREG(status.st_mode);
    *executable = *regular && asteriskd_mode_is_executable((uint32_t)status.st_mode);
    return 0;
}

static int system_capability_execute(
    void *opaque, const char *const *argv, char *error, size_t error_size, int *exit_status) {
    struct asteriskd_system_supervisor *system = opaque;
    if (asteriskd_supervisor_action_run_argv(system, argv, false, exit_status) != 0) {
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "capability command failed");
        }
        return -1;
    }
    return 0;
}

int asteriskd_supervisor_effect_capability(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_platform_capability_backend backend = {
        .context = system,
        .find_on_path = system_capability_find,
        .inspect_executable = system_capability_inspect,
        .execute = system_capability_execute,
    };
    struct asteriskd_platform_capability_result result;
    char error[256U];
    int prepared = asteriskd_platform_capability_ensure(
        &system->loaded_config.config, &backend, &result, error, sizeof(error));
    if (prepared != 0) return prepared;
    if (error[0] != '\0') {
        char message[320U];
        int written = snprintf(message, sizeof(message),
            "optional SELinux policy setup incomplete; continuing: %s", error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_WARNING,
                ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_CAPABILITY_ADJUSTED, message);
        }
    }
    return 0;
}

#endif

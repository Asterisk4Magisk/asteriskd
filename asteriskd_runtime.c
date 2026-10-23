// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd_supervisor.h"

void asteriskd_poll_builder_init(struct asteriskd_poll_builder *builder) {
    if (builder != NULL) memset(builder, 0, sizeof(*builder));
}

int asteriskd_poll_builder_add(
    struct asteriskd_poll_builder *builder, const struct asteriskd_poll_source *source) {
    if (builder == NULL || source == NULL || source->fd < 0 || source->events == 0 ||
        source->kind < ASTERISKD_POLL_SIGNAL ||
        source->kind >= ASTERISKD_POLL_SOURCE_KIND_COUNT || source->generation == 0U ||
        builder->count >= ASTERISKD_MAX_POLL_SOURCES) return ASTERISKD_CONFIG_INVALID;
    builder->sources[builder->count++] = *source;
    return 0;
}

bool asteriskd_process_poll_source_matches(
    const struct asteriskd_child_process *process, const struct asteriskd_poll_source *source) {
    if (process == NULL || source == NULL || process->pid <= 0 ||
        source->generation != (uint64_t)process->pid) return false;
    switch (source->kind) {
        case ASTERISKD_POLL_PROCESS_EXEC_ERROR:
            return process->owns_setup_status_fd && source->fd == process->setup_status_fd;
        case ASTERISKD_POLL_PROCESS_STDOUT:
            return process->owns_stdout_fd && source->fd == process->stdout_fd;
        case ASTERISKD_POLL_PROCESS_STDERR:
            return process->owns_stderr_fd && source->fd == process->stderr_fd;
        case ASTERISKD_POLL_PROCESS_PIDFD:
            return process->owns_pidfd && source->fd == process->pidfd;
        default:
            return false;
    }
}

void asteriskd_deadline_min(
    struct asteriskd_deadline *target, const struct asteriskd_deadline *candidate) {
    if (target == NULL || candidate == NULL || !candidate->armed) return;
    if (!target->armed || candidate->monotonic_milliseconds < target->monotonic_milliseconds) {
        *target = *candidate;
    }
}

static unsigned runtime_dispatch_priority(enum asteriskd_poll_source_kind);

void asteriskd_runtime_delta_init(struct asteriskd_runtime_delta *delta) {
    if (delta == NULL) return;
    memset(delta, 0, sizeof(*delta));
    delta->stop_reason = ASTERISKD_LIFECYCLE_REASON_NONE;
}

static bool runtime_backend_valid(const struct asteriskd_runtime_reactor_backend *backend) {
    return backend != NULL && backend->monotonic_milliseconds != NULL &&
        backend->prepare != NULL && backend->wait != NULL && backend->dispatch != NULL &&
        backend->expire != NULL;
}

int asteriskd_runtime_create(struct asteriskd_runtime **output,
    const struct asteriskd_runtime_reactor_backend *backend, void *backend_context) {
    if (output == NULL) return ASTERISKD_CONFIG_INVALID;
    *output = NULL;
    if (!runtime_backend_valid(backend)) return ASTERISKD_CONFIG_INVALID;
    struct asteriskd_runtime *runtime = calloc(1U, sizeof(*runtime));
    if (runtime == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    runtime->backend = *backend;
    runtime->backend_context = backend_context;
    *output = runtime;
    return 0;
}

static int64_t deadline_timeout(
    int64_t now, const struct asteriskd_deadline *deadline) {
    if (deadline == NULL || !deadline->armed) return -1;
    if (deadline->monotonic_milliseconds <= now) return 0;
    return deadline->monotonic_milliseconds - now;
}

static unsigned runtime_dispatch_priority(enum asteriskd_poll_source_kind kind) {
    switch (kind) {
        case ASTERISKD_POLL_SIGNAL: return 0U;
        case ASTERISKD_POLL_PROCESS_EXEC_ERROR:
        case ASTERISKD_POLL_PROCESS_STDOUT:
        case ASTERISKD_POLL_PROCESS_STDERR: return 1U;
        case ASTERISKD_POLL_PROCESS_PIDFD: return 2U;
        case ASTERISKD_POLL_CONTROL_LISTENER:
        case ASTERISKD_POLL_CONTROL_CLIENT: return 3U;
        case ASTERISKD_POLL_DNS:
        case ASTERISKD_POLL_NETWORK:
        case ASTERISKD_POLL_TC_NETLINK:
        case ASTERISKD_POLL_SERVICE_TIMER:
        case ASTERISKD_POLL_WIFI:
        case ASTERISKD_POLL_KEYGUARD: return 4U;
        default: return UINT_MAX;
    }
}

int asteriskd_runtime_pump_once(struct asteriskd_runtime *runtime,
    const struct asteriskd_deadline *caller_deadline, struct asteriskd_runtime_delta *delta) {
    if (runtime == NULL || delta == NULL || runtime->dispatching ||
        (caller_deadline != NULL && caller_deadline->armed &&
            caller_deadline->monotonic_milliseconds < 0)) return ASTERISKD_CONFIG_INVALID;

    asteriskd_runtime_delta_init(delta);
    runtime->dispatching = true;
    int result = ASTERISKD_CONFIG_IO;
    int64_t now = 0;
    struct asteriskd_poll_builder builder;
    struct asteriskd_deadline module_deadline = {0};
    short ready[ASTERISKD_MAX_POLL_SOURCES];
    asteriskd_poll_builder_init(&builder);
    memset(ready, 0, sizeof(ready));

    if (runtime->backend.monotonic_milliseconds(runtime->backend_context, &now) != 0 || now < 0)
        goto done;
    if (runtime->backend.prepare(
            runtime->backend_context, &builder, &module_deadline) != 0 ||
        builder.count > ASTERISKD_MAX_POLL_SOURCES ||
        (module_deadline.armed && module_deadline.monotonic_milliseconds < 0)) goto done;

    struct asteriskd_deadline wait_deadline = module_deadline;
    asteriskd_deadline_min(&wait_deadline, caller_deadline);
    int wait_result = runtime->backend.wait(runtime->backend_context, &builder,
        deadline_timeout(now, &wait_deadline), ready);
    if (wait_result == ASTERISKD_REACTOR_WAIT_ERROR) goto done;
    if (wait_result != ASTERISKD_REACTOR_WAIT_INTERRUPTED && wait_result < 0) goto done;

    if (wait_result != ASTERISKD_REACTOR_WAIT_INTERRUPTED) {
        size_t ready_count = 0U;
        for (unsigned priority = 0U; priority <= 4U; ++priority) {
            for (size_t index = 0U; index < builder.count; ++index) {
                if (ready[index] == 0 ||
                    runtime_dispatch_priority(builder.sources[index].kind) != priority) continue;
                ++ready_count;
                if (runtime->backend.dispatch(runtime->backend_context, &builder.sources[index],
                        ready[index], delta) != 0) goto done;
            }
        }
        if ((uint64_t)wait_result < (uint64_t)ready_count) goto done;
    }

    if (runtime->backend.monotonic_milliseconds(runtime->backend_context, &now) != 0 || now < 0)
        goto done;
    if (module_deadline.armed && now >= module_deadline.monotonic_milliseconds &&
        runtime->backend.expire(runtime->backend_context, now, delta) != 0) goto done;
    result = 0;

done:
    runtime->dispatching = false;
    return result;
}

static void runtime_delta_merge(
    struct asteriskd_runtime_delta *target, const struct asteriskd_runtime_delta *source) {
    const uint32_t service_actions = ASTERISKD_DELTA_SERVICE_PAUSE | ASTERISKD_DELTA_SERVICE_RESUME;
    if ((source->flags & service_actions) != 0U) target->flags &= ~service_actions;
    target->flags |= source->flags;
    if (target->stop_reason == ASTERISKD_LIFECYCLE_REASON_NONE &&
        source->stop_reason != ASTERISKD_LIFECYCLE_REASON_NONE) {
        target->stop_reason = source->stop_reason;
    }
    if (!target->has_child_exit && source->has_child_exit) {
        target->has_child_exit = true;
        target->child_role = source->child_role;
        target->child_exit = source->child_exit;
    }
    if (source->has_rules_summary) {
        target->has_rules_summary = true;
        target->rules_generation = source->rules_generation;
        target->rule_categories = source->rule_categories;
    }
    if (!target->has_error && source->has_error) {
        target->has_error = true;
        target->error_code = source->error_code;
        target->error_component = source->error_component;
        memcpy(target->error_message, source->error_message, sizeof(target->error_message));
    }
}

int asteriskd_runtime_pump_until(struct asteriskd_runtime *runtime,
    const struct asteriskd_deadline *deadline, asteriskd_runtime_predicate predicate,
    void *predicate_context, struct asteriskd_runtime_delta *delta) {
    if (runtime == NULL || deadline == NULL || !deadline->armed ||
        deadline->monotonic_milliseconds < 0 || predicate == NULL || delta == NULL ||
        runtime->dispatching) return ASTERISKD_CONFIG_INVALID;
    asteriskd_runtime_delta_init(delta);
    for (;;) {
        if (predicate(predicate_context)) return 0;
        int64_t now = 0;
        if (runtime->backend.monotonic_milliseconds(runtime->backend_context, &now) != 0 || now < 0)
            return ASTERISKD_CONFIG_IO;
        if (now >= deadline->monotonic_milliseconds) return ASTERISKD_CONFIG_IO;
        struct asteriskd_runtime_delta iteration;
        int result = asteriskd_runtime_pump_once(runtime, deadline, &iteration);
        if (result != 0) return result;
        runtime_delta_merge(delta, &iteration);
        if ((iteration.flags & (ASTERISKD_DELTA_STOP_REQUESTED |
                ASTERISKD_DELTA_CHILD_EXITED | ASTERISKD_DELTA_FATAL)) != 0U) return 0;
    }
}

static bool runtime_effects_valid(const struct asteriskd_runtime_effect_backend *effects,
    const struct asteriskd_config *config) {
    if (effects == NULL || effects->save_state == NULL || effects->publish_event == NULL ||
        effects->start_core == NULL || effects->wait_core == NULL ||
        effects->open_network == NULL || effects->apply_rules == NULL || effects->verify == NULL ||
        effects->network_immediate == NULL || effects->reconcile == NULL ||
        effects->quiesce_traffic == NULL ||
        effects->remove_rules == NULL || effects->close_network == NULL ||
        effects->stop_core == NULL || effects->restore_best_effort == NULL ||
        effects->release == NULL) return false;
    if (config->matcher.enabled &&
        (effects->ensure_platform_capability == NULL || effects->start_matcher == NULL ||
         effects->stop_matcher == NULL)) return false;
    if (config->helper.type != ASTERISKD_HELPER_NONE &&
        (effects->start_helper == NULL || effects->wait_helper == NULL ||
         effects->stop_helper == NULL)) return false;
    if (config->helper.type == ASTERISKD_HELPER_BPF2SOCKS &&
        effects->ensure_platform_capability == NULL) return false;
    return true;
}

static int runtime_save(struct asteriskd_runtime *runtime) {
    return runtime->effects->save_state(runtime->effects->context, runtime->state) == 0
        ? 0 : ASTERISKD_CONFIG_IO;
}

static int runtime_set_phase(struct asteriskd_runtime *runtime, enum asteriskd_phase phase) {
    if (asteriskd_state_set_phase(runtime->state, phase) != ASTERISKD_STATE_OK) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return runtime_save(runtime);
}

static int runtime_publish_event(
    struct asteriskd_runtime *runtime, enum asteriskd_control_event_type type) {
    struct asteriskd_control_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    if (asteriskd_control_snapshot_from_state(
            runtime->state, &runtime->live, &snapshot) != 0) return ASTERISKD_CONFIG_INVALID;
    const struct asteriskd_control_error *details = snapshot.has_error ? &snapshot.error : NULL;
    int result = runtime->effects->publish_event(
        runtime->effects->context, type, &snapshot, details, details != NULL);
    asteriskd_control_snapshot_destroy(&snapshot);
    return result == 0 ? 0 : ASTERISKD_CONFIG_IO;
}

static int runtime_save_child(
    struct asteriskd_runtime *runtime, const struct asteriskd_child_identity *identity) {
    char error[128U] = {0};
    if (asteriskd_state_set_child(
            runtime->state, identity, error, sizeof(error)) != ASTERISKD_STATE_OK) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return runtime_save(runtime);
}

static int runtime_lifecycle_acquire(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    asteriskd_state_clear_failure(runtime->state);
    return asteriskd_state_set_matcher(
        runtime->state, runtime->config->matcher.enabled, false);
}

static int runtime_lifecycle_start_core(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime_set_phase(runtime, ASTERISKD_PHASE_STARTING) != 0) return ASTERISKD_CONFIG_IO;
    if (!runtime->starting_event_published) {
        if (runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_STARTING) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
        runtime->starting_event_published = true;
    }
    struct asteriskd_child_identity identity;
    memset(&identity, 0, sizeof(identity));
    if (runtime->effects->start_core(runtime->effects->context, &identity) != 0) {
        return ASTERISKD_LIFECYCLE_START_FAILED;
    }
    return runtime_save_child(runtime, &identity);
}

static int runtime_lifecycle_wait_core(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->wait_core(runtime->effects->context);
}

static int runtime_lifecycle_capability(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->ensure_platform_capability(runtime->effects->context);
}

static int runtime_lifecycle_start_helper(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    struct asteriskd_child_identity identity;
    memset(&identity, 0, sizeof(identity));
    if (runtime->effects->start_helper(runtime->effects->context, &identity) != 0) {
        return ASTERISKD_LIFECYCLE_START_FAILED;
    }
    return runtime_save_child(runtime, &identity);
}

static int runtime_lifecycle_wait_helper(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->wait_helper(runtime->effects->context);
}

static int runtime_lifecycle_start_matcher(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->start_matcher(runtime->effects->context) != 0 ||
        asteriskd_state_set_matcher(runtime->state, true, true) != ASTERISKD_STATE_OK) {
        return ASTERISKD_LIFECYCLE_START_FAILED;
    }
    return runtime_save(runtime);
}

static int runtime_lifecycle_open_network(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->open_network(runtime->effects->context);
}

static int runtime_commit_rules(struct asteriskd_runtime *runtime, bool active,
    uint64_t generation, uint32_t categories, bool publish) {
    if (asteriskd_state_set_rules(
            runtime->state, active, generation, categories) != ASTERISKD_STATE_OK ||
        runtime_save(runtime) != 0) return ASTERISKD_CONFIG_IO;
    if (publish && active && !asteriskd_mode_core_managed(runtime->config->mode)) {
        return runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_RULES_CHANGED);
    }
    return 0;
}

static int runtime_lifecycle_apply_rules(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime_set_phase(runtime, ASTERISKD_PHASE_APPLYING_RULES) != 0) {
        return ASTERISKD_CONFIG_IO;
    }
    bool active = false;
    uint64_t generation = 0U;
    uint32_t categories = 0U;
    if (runtime->effects->apply_rules(
            runtime->effects->context, &active, &generation, &categories) != 0) {
        return ASTERISKD_LIFECYCLE_START_FAILED;
    }
    return runtime_commit_rules(runtime, active, generation, categories, true);
}

static int runtime_lifecycle_verify(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->verify(runtime->effects->context) != 0) {
        return ASTERISKD_LIFECYCLE_START_FAILED;
    }
    if (runtime_set_phase(runtime, ASTERISKD_PHASE_RUNNING) != 0) return ASTERISKD_CONFIG_IO;
    return runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_RUNNING);
}

bool asteriskd_runtime_lifecycle_stop_requested(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return atomic_load_explicit(
        &runtime->lifecycle.stop_was_requested, memory_order_acquire);
}

static int runtime_lifecycle_quiesce(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->quiesce_traffic(runtime->effects->context);
}

static int runtime_lifecycle_remove_rules(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->remove_rules(runtime->effects->context) != 0) return ASTERISKD_CONFIG_IO;
    return runtime_commit_rules(runtime, false, 0U, 0U, false);
}

static int runtime_lifecycle_close_network(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->close_network(runtime->effects->context);
}

static int runtime_lifecycle_stop_matcher(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->stop_matcher(runtime->effects->context) != 0 ||
        asteriskd_state_set_matcher(
            runtime->state, runtime->config->matcher.enabled, false) != ASTERISKD_STATE_OK) {
        return ASTERISKD_CONFIG_IO;
    }
    return runtime_save(runtime);
}

static int runtime_clear_child(struct asteriskd_runtime *runtime, enum asteriskd_child_role role) {
    if (asteriskd_state_clear_child(runtime->state, role) != ASTERISKD_STATE_OK) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return runtime_save(runtime);
}

static int runtime_lifecycle_stop_helper(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->stop_helper(runtime->effects->context) != 0) return ASTERISKD_CONFIG_IO;
    return runtime_clear_child(runtime, ASTERISKD_CHILD_HELPER);
}

static int runtime_lifecycle_stop_core(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->stop_core(runtime->effects->context) != 0) return ASTERISKD_CONFIG_IO;
    if (runtime_clear_child(runtime, ASTERISKD_CHILD_CORE) != 0) return ASTERISKD_CONFIG_IO;
    return 0;
}

static int runtime_lifecycle_restore_best_effort(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->restore_best_effort(runtime->effects->context);
}

static int runtime_lifecycle_release(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->release(runtime->effects->context);
}

static const struct asteriskd_lifecycle_backend runtime_lifecycle_backend = {
    .acquire = runtime_lifecycle_acquire,
    .start_core = runtime_lifecycle_start_core,
    .wait_core = runtime_lifecycle_wait_core,
    .ensure_platform_capability = runtime_lifecycle_capability,
    .start_helper = runtime_lifecycle_start_helper,
    .wait_helper = runtime_lifecycle_wait_helper,
    .start_matcher = runtime_lifecycle_start_matcher,
    .open_network = runtime_lifecycle_open_network,
    .apply_rules = runtime_lifecycle_apply_rules,
    .verify = runtime_lifecycle_verify,
    .stop_requested = asteriskd_runtime_lifecycle_stop_requested,
    .quiesce_traffic = runtime_lifecycle_quiesce,
    .remove_rules = runtime_lifecycle_remove_rules,
    .close_network = runtime_lifecycle_close_network,
    .stop_matcher = runtime_lifecycle_stop_matcher,
    .stop_helper = runtime_lifecycle_stop_helper,
    .stop_core = runtime_lifecycle_stop_core,
    .restore_best_effort = runtime_lifecycle_restore_best_effort,
    .release = runtime_lifecycle_release,
};

static int runtime_set_failure(struct asteriskd_runtime *runtime,
    enum asteriskd_failure_code code, enum asteriskd_component component,
    const char *message, const struct asteriskd_child_exit_status *child) {
    char error[128U];
    if (asteriskd_state_set_failure(runtime->state, code, component, message,
            child != NULL && child->has_exit_code,
            child != NULL && child->has_exit_code ? child->exit_code : 0,
            child != NULL && child->has_signal,
            child != NULL && child->has_signal ? child->signal_number : 0,
            error, sizeof(error)) != ASTERISKD_STATE_OK ||
        asteriskd_state_set_phase(runtime->state, ASTERISKD_PHASE_FAILED) != ASTERISKD_STATE_OK ||
        runtime_save(runtime) != 0) return ASTERISKD_CONFIG_IO;
    return 0;
}

int asteriskd_runtime_accept_delta(
    struct asteriskd_runtime *runtime, const struct asteriskd_runtime_delta *delta) {
    const uint32_t known = ASTERISKD_DELTA_STOP_REQUESTED | ASTERISKD_DELTA_CHILD_EXITED |
        ASTERISKD_DELTA_NETWORK_CHANGED | ASTERISKD_DELTA_RECONCILE_DUE |
        ASTERISKD_DELTA_RULES_CHANGED | ASTERISKD_DELTA_FATAL |
        ASTERISKD_DELTA_SERVICE_PAUSE | ASTERISKD_DELTA_SERVICE_RESUME;
    if (runtime == NULL || delta == NULL || (delta->flags & ~known) != 0U ||
        (((delta->flags & ASTERISKD_DELTA_STOP_REQUESTED) != 0U) !=
            (delta->stop_reason != ASTERISKD_LIFECYCLE_REASON_NONE)) ||
        (((delta->flags & ASTERISKD_DELTA_CHILD_EXITED) != 0U) != delta->has_child_exit) ||
        (((delta->flags & ASTERISKD_DELTA_RULES_CHANGED) != 0U) != delta->has_rules_summary) ||
        (((delta->flags & ASTERISKD_DELTA_FATAL) != 0U) != delta->has_error)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    runtime_delta_merge(&runtime->pending_delta, delta);
    if ((delta->flags & ASTERISKD_DELTA_STOP_REQUESTED) != 0U &&
        asteriskd_lifecycle_request_stop(&runtime->lifecycle, delta->stop_reason) ==
            ASTERISKD_CONFIG_INVALID) return ASTERISKD_CONFIG_INVALID;
    if ((delta->flags & ASTERISKD_DELTA_CHILD_EXITED) != 0U) {
        int status = delta->child_exit.has_exit_code ? delta->child_exit.exit_code :
            128 + delta->child_exit.signal_number;
        if (asteriskd_lifecycle_on_child_exit(
                &runtime->lifecycle, delta->child_role, status) == ASTERISKD_CONFIG_INVALID) {
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    if ((delta->flags & ASTERISKD_DELTA_FATAL) != 0U &&
        asteriskd_lifecycle_request_stop(
            &runtime->lifecycle, ASTERISKD_LIFECYCLE_REASON_RUNTIME_FAILED) ==
            ASTERISKD_CONFIG_INVALID) return ASTERISKD_CONFIG_INVALID;
    return 0;
}

static int runtime_process_delta(
    struct asteriskd_runtime *runtime, const struct asteriskd_runtime_delta *delta) {
    struct asteriskd_runtime_delta terminal = *delta;
    terminal.flags &= ASTERISKD_DELTA_STOP_REQUESTED |
        ASTERISKD_DELTA_CHILD_EXITED | ASTERISKD_DELTA_FATAL;
    if ((terminal.flags & ASTERISKD_DELTA_STOP_REQUESTED) == 0U) {
        terminal.stop_reason = ASTERISKD_LIFECYCLE_REASON_NONE;
    }
    if ((terminal.flags & ASTERISKD_DELTA_CHILD_EXITED) == 0U) {
        terminal.has_child_exit = false;
        terminal.child_role = ASTERISKD_CHILD_CORE;
        memset(&terminal.child_exit, 0, sizeof(terminal.child_exit));
    }
    terminal.has_rules_summary = false;
    terminal.rules_generation = 0U;
    terminal.rule_categories = 0U;
    if ((terminal.flags & ASTERISKD_DELTA_FATAL) == 0U) {
        terminal.has_error = false;
        terminal.error_code = ASTERISKD_FAILURE_START_FAILED;
        terminal.error_component = ASTERISKD_COMPONENT_RUNTIME;
        memset(terminal.error_message, 0, sizeof(terminal.error_message));
    }
    if (terminal.flags != 0U) return asteriskd_runtime_accept_delta(runtime, &terminal);

    if ((delta->flags & ASTERISKD_DELTA_SERVICE_PAUSE) != 0U &&
        runtime->state->phase == ASTERISKD_PHASE_RUNNING) {
        if (runtime_set_phase(runtime, ASTERISKD_PHASE_STOPPING) != 0 ||
            asteriskd_lifecycle_pause(&runtime->lifecycle,
                runtime->config->mode == ASTERISKD_MODE_BPF2SOCKS) != 0 ||
            runtime_set_phase(runtime, ASTERISKD_PHASE_PAUSED) != 0 ||
            runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_PAUSED) != 0) return ASTERISKD_CONFIG_IO;
    } else if ((delta->flags & ASTERISKD_DELTA_SERVICE_RESUME) != 0U &&
        runtime->state->phase == ASTERISKD_PHASE_PAUSED) {
        if (runtime_set_phase(runtime, ASTERISKD_PHASE_STARTING) != 0 ||
            runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_STARTING) != 0 ||
            asteriskd_lifecycle_resume(&runtime->lifecycle) != 0) return ASTERISKD_CONFIG_IO;
    }
    /* A suspended cycle must never reinstall traffic rules through a queued
     * network reconciliation. Reopening the network on resume takes a fresh snapshot. */
    if (runtime->state->phase == ASTERISKD_PHASE_PAUSED) return 0;

    if ((delta->flags & ASTERISKD_DELTA_NETWORK_CHANGED) != 0U &&
        runtime->effects->network_immediate(runtime->effects->context) != 0) {
        return ASTERISKD_CONFIG_IO;
    }
    if ((delta->flags & ASTERISKD_DELTA_RULES_CHANGED) != 0U) {
        if (runtime_commit_rules(runtime, true, delta->rules_generation,
                delta->rule_categories, true) != 0) return ASTERISKD_CONFIG_IO;
    }
    if ((delta->flags & ASTERISKD_DELTA_RECONCILE_DUE) != 0U) {
        uint64_t previous_generation = runtime->state->rules.generation;
        bool active = false;
        uint64_t generation = 0U;
        uint32_t categories = 0U;
        if (runtime->effects->reconcile(runtime->effects->context,
                &active, &generation, &categories) != 0 ||
            runtime_commit_rules(runtime, active, generation, categories,
                active && generation != previous_generation) != 0) {
            return ASTERISKD_CONFIG_IO;
        }
    }
    return 0;
}

static int runtime_process_deferred_delta(
    struct asteriskd_runtime *runtime, bool *processed) {
    if (runtime == NULL || processed == NULL) return ASTERISKD_CONFIG_INVALID;
    const uint32_t dynamic = ASTERISKD_DELTA_NETWORK_CHANGED |
        ASTERISKD_DELTA_RECONCILE_DUE | ASTERISKD_DELTA_RULES_CHANGED |
        ASTERISKD_DELTA_SERVICE_PAUSE | ASTERISKD_DELTA_SERVICE_RESUME;
    *processed = (runtime->pending_delta.flags & dynamic) != 0U;
    if (!*processed) return 0;
    struct asteriskd_runtime_delta delta;
    asteriskd_runtime_delta_init(&delta);
    delta.flags = runtime->pending_delta.flags & dynamic;
    if ((delta.flags & ASTERISKD_DELTA_RULES_CHANGED) != 0U) {
        delta.has_rules_summary = true;
        delta.rules_generation = runtime->pending_delta.rules_generation;
        delta.rule_categories = runtime->pending_delta.rule_categories;
    }
    runtime->pending_delta.flags &= ~dynamic;
    runtime->pending_delta.has_rules_summary = false;
    runtime->pending_delta.rules_generation = 0U;
    runtime->pending_delta.rule_categories = 0U;
    return runtime_process_delta(runtime, &delta);
}

static enum asteriskd_control_event_type runtime_failure_event(
    enum asteriskd_lifecycle_reason reason) {
    if (reason == ASTERISKD_LIFECYCLE_REASON_CORE_EXITED) {
        return ASTERISKD_CONTROL_EVENT_CORE_EXITED;
    }
    if (reason == ASTERISKD_LIFECYCLE_REASON_HELPER_EXITED) {
        return ASTERISKD_CONTROL_EVENT_HELPER_FAILED;
    }
    return ASTERISKD_CONTROL_EVENT_FAILED;
}

static enum asteriskd_component runtime_start_failure_component(const char *stage) {
    if (stage == NULL) return ASTERISKD_COMPONENT_RUNTIME;
    if (strcmp(stage, "start_core") == 0 || strcmp(stage, "wait_core") == 0) {
        return ASTERISKD_COMPONENT_CORE;
    }
    if (strcmp(stage, "start_helper") == 0 || strcmp(stage, "wait_helper") == 0) {
        return ASTERISKD_COMPONENT_HELPER;
    }
    if (strcmp(stage, "start_matcher") == 0) return ASTERISKD_COMPONENT_MATCHER;
    if (strcmp(stage, "open_network") == 0) return ASTERISKD_COMPONENT_NETWORK;
    if (strcmp(stage, "apply_rules") == 0 || strcmp(stage, "verify") == 0) {
        return ASTERISKD_COMPONENT_RULES;
    }
    if (strcmp(stage, "recover") == 0) return ASTERISKD_COMPONENT_STATE;
    return ASTERISKD_COMPONENT_RUNTIME;
}

static int runtime_start_failure_detail(
    int result, const char *stage, struct asteriskd_runtime_delta *delta) {
    if (delta == NULL) return ASTERISKD_CONFIG_INVALID;
    asteriskd_runtime_delta_init(delta);
    delta->has_error = true;
    delta->error_component = runtime_start_failure_component(stage);
    if (result == ASTERISKD_RUNTIME_EFFECT_READINESS_TIMEOUT) {
        delta->error_code = ASTERISKD_FAILURE_READINESS_TIMEOUT;
        (void)snprintf(delta->error_message, sizeof(delta->error_message), "%s",
            delta->error_component == ASTERISKD_COMPONENT_HELPER
                ? "required helper readiness timed out" : "required core readiness timed out");
        return 0;
    }
    delta->error_code = ASTERISKD_FAILURE_START_FAILED;
    if (stage == NULL || stage[0] == '\0') {
        (void)snprintf(delta->error_message, sizeof(delta->error_message), "%s",
            "runtime startup failed");
    } else {
        (void)snprintf(delta->error_message, sizeof(delta->error_message),
            "startup stage failed: %s", stage);
    }
    return 0;
}

static int runtime_record_terminal_failure(struct asteriskd_runtime *runtime,
    enum asteriskd_lifecycle_reason reason, const struct asteriskd_runtime_delta *delta) {
    if (reason == ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP ||
        reason == ASTERISKD_LIFECYCLE_REASON_SIGTERM ||
        reason == ASTERISKD_LIFECYCLE_REASON_SIGINT) return 0;
    enum asteriskd_failure_code code = ASTERISKD_FAILURE_START_FAILED;
    enum asteriskd_component component = ASTERISKD_COMPONENT_RUNTIME;
    const char *message = "runtime startup failed";
    const struct asteriskd_child_exit_status *child = NULL;
    if (reason == ASTERISKD_LIFECYCLE_REASON_CORE_EXITED ||
        reason == ASTERISKD_LIFECYCLE_REASON_HELPER_EXITED) {
        code = ASTERISKD_FAILURE_CHILD_EXITED;
        component = reason == ASTERISKD_LIFECYCLE_REASON_CORE_EXITED
            ? ASTERISKD_COMPONENT_CORE : ASTERISKD_COMPONENT_HELPER;
        message = reason == ASTERISKD_LIFECYCLE_REASON_CORE_EXITED
            ? "required core exited" : "required helper exited";
        if (delta != NULL && delta->has_child_exit) child = &delta->child_exit;
    } else if ((reason == ASTERISKD_LIFECYCLE_REASON_RUNTIME_FAILED ||
            reason == ASTERISKD_LIFECYCLE_REASON_START_FAILED) &&
        delta != NULL && delta->has_error && delta->error_code >= 0 &&
        delta->error_code < ASTERISKD_FAILURE_CODE_COUNT &&
        delta->error_component >= 0 && delta->error_component < ASTERISKD_COMPONENT_COUNT &&
        delta->error_message[0] != '\0') {
        code = delta->error_code;
        component = delta->error_component;
        message = delta->error_message;
    }
    if (runtime_set_failure(runtime, code, component, message, child) != 0) {
        return ASTERISKD_CONFIG_IO;
    }
    return runtime_publish_event(runtime, runtime_failure_event(reason));
}

static int runtime_finish(struct asteriskd_runtime *runtime,
    enum asteriskd_lifecycle_reason reason, const struct asteriskd_runtime_delta *delta) {
    bool abnormal = reason != ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP &&
        reason != ASTERISKD_LIFECYCLE_REASON_SIGTERM &&
        reason != ASTERISKD_LIFECYCLE_REASON_SIGINT;
    if (abnormal && runtime_record_terminal_failure(runtime, reason, delta) != 0) abnormal = true;
    if (runtime_set_phase(runtime, ASTERISKD_PHASE_STOPPING) != 0 ||
        runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_STOPPING) != 0) abnormal = true;
    int stopped = asteriskd_lifecycle_stop(&runtime->lifecycle);
    char error[128U];
    if (stopped == 0 && asteriskd_state_mark_stopped(
            runtime->state, error, sizeof(error)) == ASTERISKD_STATE_OK &&
        runtime_save(runtime) == 0) {
        if (runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_STOPPED) != 0) abnormal = true;
        return abnormal ? 1 : 0;
    }
    (void)runtime_set_failure(runtime, ASTERISKD_FAILURE_STOP_FAILED,
        ASTERISKD_COMPONENT_RUNTIME, "critical cleanup incomplete", NULL);
    (void)runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_FAILED);
    return 1;
}

bool asteriskd_runtime_remove_tc_before_helper_stop(enum asteriskd_mode mode) {
    return mode == ASTERISKD_MODE_BPF2SOCKS;
}

int asteriskd_runtime_supervise(struct asteriskd_runtime *runtime,
    const struct asteriskd_config *config, struct asteriskd_state_document *state,
    const struct asteriskd_control_live_context *live,
    const struct asteriskd_runtime_effect_backend *effects) {
    if (runtime == NULL || config == NULL || state == NULL || live == NULL ||
        live->supervisor_pid <= 0 || runtime->dispatching || runtime->supervising ||
        !state->initialized ||
        state->owner != config->owner ||
        state->core_type != config->core_type ||
        state->mode != config->mode ||
        !runtime_effects_valid(effects, config)) return ASTERISKD_CONFIG_INVALID;
    runtime->config = config;
    runtime->state = state;
    runtime->live = *live;
    runtime->effects = effects;
    runtime->supervising = true;
    runtime->starting_event_published = false;
    asteriskd_runtime_delta_init(&runtime->pending_delta);
    struct asteriskd_lifecycle_options options = {
        .has_helper = config->helper.type != ASTERISKD_HELPER_NONE,
        .has_matcher = config->matcher.enabled,
        .requires_platform_capability = config->matcher.enabled ||
            config->helper.type == ASTERISKD_HELPER_BPF2SOCKS,
        .core_managed_traffic = asteriskd_mode_core_managed(config->mode),
    };
    int started = asteriskd_lifecycle_start(
        &runtime->lifecycle, &runtime_lifecycle_backend, runtime, &options);
    if (started != 0) {
        enum asteriskd_lifecycle_reason reason = atomic_load_explicit(
            &runtime->lifecycle.terminal_reason, memory_order_acquire);
        if (reason == ASTERISKD_LIFECYCLE_REASON_NONE) reason = ASTERISKD_LIFECYCLE_REASON_START_FAILED;
        struct asteriskd_runtime_delta startup_failure;
        (void)runtime_start_failure_detail(
            started, runtime->lifecycle.failure_stage, &startup_failure);
        /* A child exit during startup must keep its status, or the failure
         * summary is rejected and the cycle ends without a recorded cause. */
        if (runtime->pending_delta.has_child_exit) {
            startup_failure.has_child_exit = true;
            startup_failure.child_role = runtime->pending_delta.child_role;
            startup_failure.child_exit = runtime->pending_delta.child_exit;
        }
        int result = runtime_finish(runtime, reason, &startup_failure);
        runtime->supervising = false;
        return result == 0 ? 1 : result;
    }

    int result = 0;
    for (;;) {
        enum asteriskd_lifecycle_reason reason = atomic_load_explicit(
            &runtime->lifecycle.terminal_reason, memory_order_acquire);
        if (reason != ASTERISKD_LIFECYCLE_REASON_NONE) {
            result = runtime_finish(runtime, reason, &runtime->pending_delta);
            break;
        }
        bool processed = false;
        if (runtime_process_deferred_delta(runtime, &processed) != 0) {
            struct asteriskd_runtime_delta fatal;
            asteriskd_runtime_delta_init(&fatal);
            fatal.flags = ASTERISKD_DELTA_FATAL;
            fatal.has_error = true;
            fatal.error_code = ASTERISKD_FAILURE_IO_ERROR;
            fatal.error_component = ASTERISKD_COMPONENT_NETWORK;
            (void)snprintf(fatal.error_message, sizeof(fatal.error_message), "%s",
                "deferred reconciliation failed");
            (void)asteriskd_runtime_accept_delta(runtime, &fatal);
            continue;
        }
        if (processed) continue;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(runtime, NULL, &delta) != 0 ||
            runtime_process_delta(runtime, &delta) != 0) {
            asteriskd_runtime_delta_init(&delta);
            delta.flags = ASTERISKD_DELTA_FATAL;
            delta.has_error = true;
            delta.error_code = ASTERISKD_FAILURE_IO_ERROR;
            delta.error_component = ASTERISKD_COMPONENT_RUNTIME;
            (void)snprintf(delta.error_message, sizeof(delta.error_message), "%s",
                "reactor dispatch failed");
            (void)asteriskd_runtime_accept_delta(runtime, &delta);
        }
        reason = atomic_load_explicit(
            &runtime->lifecycle.terminal_reason, memory_order_acquire);
        if (reason != ASTERISKD_LIFECYCLE_REASON_NONE) {
            result = runtime_finish(runtime, reason, &runtime->pending_delta);
            break;
        }
    }
    runtime->supervising = false;
    return result;
}

#if !defined(__linux__) && !defined(__ANDROID__)
int asteriskd_runtime_start_system(
    const char *config_path,
    bool *has_early_result,
    struct asteriskd_control_result *early_result) {
    (void)config_path;
    if (has_early_result == NULL || early_result == NULL) return -1;
    *has_early_result = true;
    memset(early_result, 0, sizeof(*early_result));
    early_result->code = ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR;
    if (asteriskd_control_result_set_message(
            early_result, "system runtime is unavailable on this host", 42U) != 0) return -1;
    return 1;
}

#endif

void asteriskd_runtime_destroy(struct asteriskd_runtime *runtime) {
    free(runtime);
}

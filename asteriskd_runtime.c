#include "asteriskd.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
#endif

struct asteriskd_runtime {
    struct asteriskd_runtime_reactor_backend backend;
    void *backend_context;
    bool dispatching;
    const struct asteriskd_config *config;
    struct asteriskd_state_document *state;
    struct asteriskd_control_live_context live;
    const struct asteriskd_runtime_effect_backend *effects;
    struct asteriskd_lifecycle lifecycle;
    struct asteriskd_runtime_delta pending_delta;
    bool supervising;
    bool starting_event_published;
};

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

static int runtime_periodic_deadline(
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

static bool runtime_startup_components_verified(
    bool core_identity_ready, bool core_reaped,
    bool helper_required, bool helper_identity_ready, bool helper_reaped,
    bool matcher_required, bool matcher_verified,
    bool rules_initialized, bool rules_verified) {
    return core_identity_ready && !core_reaped &&
        (!helper_required || (helper_identity_ready && !helper_reaped)) &&
        (!matcher_required || matcher_verified) && rules_initialized && rules_verified;
}

static unsigned runtime_dispatch_priority(enum asteriskd_poll_source_kind);

#if defined(ASTERISKD_TESTING)
unsigned asteriskd_test_runtime_dispatch_priority(
    enum asteriskd_poll_source_kind kind) {
    return runtime_dispatch_priority(kind);
}

int asteriskd_test_periodic_deadline(
    int64_t now, int64_t caller_deadline, uint32_t interval,
    int64_t *iteration_deadline) {
    return runtime_periodic_deadline(
        now, caller_deadline, interval, iteration_deadline);
}

bool asteriskd_test_startup_components_verified(
    bool core_identity_ready, bool core_reaped,
    bool helper_required, bool helper_identity_ready, bool helper_reaped,
    bool matcher_required, bool matcher_verified,
    bool rules_initialized, bool rules_verified) {
    return runtime_startup_components_verified(
        core_identity_ready, core_reaped,
        helper_required, helper_identity_ready, helper_reaped,
        matcher_required, matcher_verified, rules_initialized, rules_verified);
}
#endif

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
        case ASTERISKD_POLL_NETWORK:
        case ASTERISKD_POLL_TC_NETLINK:
        case ASTERISKD_POLL_SERVICE_TIMER:
        case ASTERISKD_POLL_WIFI: return 4U;
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
        effects->recover == NULL || effects->start_core == NULL || effects->wait_core == NULL ||
        effects->open_network == NULL || effects->apply_rules == NULL || effects->verify == NULL ||
        effects->network_immediate == NULL || effects->reconcile == NULL ||
        effects->quiesce_traffic == NULL ||
        effects->remove_rules == NULL || effects->close_network == NULL ||
        effects->stop_core == NULL || effects->restore == NULL || effects->release == NULL) return false;
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
    (void)opaque;
    return 0;
}

static bool runtime_recovered_ebpf_boundary_state(
    const struct asteriskd_state_document *state);

static int runtime_lifecycle_recover(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime->effects->recover(runtime->effects->context) != 0 ||
        (!asteriskd_state_is_canonical_stopped(runtime->state) &&
         !runtime_recovered_ebpf_boundary_state(runtime->state))) {
        return ASTERISKD_CONFIG_IO;
    }
    asteriskd_state_clear_failure(runtime->state);
    return asteriskd_state_set_matcher(
        runtime->state, runtime->config->matcher.enabled, false);
}

static int runtime_lifecycle_start_core(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    if (runtime_set_phase(runtime, ASTERISKD_PHASE_STARTING) != 0) return ASTERISKD_CONFIG_IO;
    if (runtime->config->mode == ASTERISKD_MODE_EBPF &&
        !runtime->state->recovery.core_owned_ebpf_boundary) {
        runtime->state->recovery.core_owned_ebpf_boundary = true;
        if (runtime_save(runtime) != 0) return ASTERISKD_CONFIG_IO;
    }
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
    if (publish && active && runtime->config->mode != ASTERISKD_MODE_EBPF) {
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

static bool runtime_lifecycle_stop_requested(void *opaque) {
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
    if (runtime->config->mode == ASTERISKD_MODE_EBPF) {
        runtime->state->recovery.core_owned_ebpf_boundary = false;
        if (runtime_save(runtime) != 0) return ASTERISKD_CONFIG_IO;
    }
    return 0;
}

static int runtime_lifecycle_restore(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->restore(runtime->effects->context);
}

static int runtime_lifecycle_release(void *opaque) {
    struct asteriskd_runtime *runtime = opaque;
    return runtime->effects->release(runtime->effects->context);
}

static const struct asteriskd_lifecycle_backend runtime_lifecycle_backend = {
    .acquire = runtime_lifecycle_acquire,
    .recover = runtime_lifecycle_recover,
    .start_core = runtime_lifecycle_start_core,
    .wait_core = runtime_lifecycle_wait_core,
    .ensure_platform_capability = runtime_lifecycle_capability,
    .start_helper = runtime_lifecycle_start_helper,
    .wait_helper = runtime_lifecycle_wait_helper,
    .start_matcher = runtime_lifecycle_start_matcher,
    .open_network = runtime_lifecycle_open_network,
    .apply_rules = runtime_lifecycle_apply_rules,
    .verify = runtime_lifecycle_verify,
    .stop_requested = runtime_lifecycle_stop_requested,
    .quiesce_traffic = runtime_lifecycle_quiesce,
    .remove_rules = runtime_lifecycle_remove_rules,
    .close_network = runtime_lifecycle_close_network,
    .stop_matcher = runtime_lifecycle_stop_matcher,
    .stop_helper = runtime_lifecycle_stop_helper,
    .stop_core = runtime_lifecycle_stop_core,
    .restore = runtime_lifecycle_restore,
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
        ASTERISKD_DELTA_RULES_CHANGED | ASTERISKD_DELTA_FATAL;
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
        ASTERISKD_DELTA_RECONCILE_DUE | ASTERISKD_DELTA_RULES_CHANGED;
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

static int system_capability_path_search_result(bool found, bool valid_input) {
    return !valid_input ? -1 : found ? 1 : 0;
}

static int system_capability_inspect_error(int error_number) {
    return error_number == ENOENT || error_number == ENOTDIR ? 0 : -1;
}

#if defined(ASTERISKD_TESTING)
int asteriskd_test_start_failure_detail(
    int result, const char *stage, struct asteriskd_runtime_delta *delta) {
    return runtime_start_failure_detail(result, stage, delta);
}

int asteriskd_test_capability_path_search_result(bool found, bool valid_input) {
    return system_capability_path_search_result(found, valid_input);
}

int asteriskd_test_capability_inspect_error(int error_number) {
    return system_capability_inspect_error(error_number);
}
#endif

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
        ASTERISKD_COMPONENT_RUNTIME, "cleanup incomplete; recovery evidence retained", NULL);
    (void)runtime_publish_event(runtime, ASTERISKD_CONTROL_EVENT_FAILED);
    return 1;
}

static bool runtime_recovered_ebpf_boundary_state(
    const struct asteriskd_state_document *state) {
    return state != NULL && state->initialized && state->phase == ASTERISKD_PHASE_FAILED &&
        state->owner == ASTERISKD_OWNER_BOX && state->core_type == ASTERISKD_CORE_SING_BOX &&
        state->mode == ASTERISKD_MODE_EBPF && state->recovery.core_owned_ebpf_boundary &&
        !state->children.core_present && !state->children.helper_present &&
        !state->matcher.configured && !state->matcher.active && !state->rules.active &&
        state->rules.generation == 0U && state->rules.categories == 0U;
}

int asteriskd_runtime_prepare_start_state(
    struct asteriskd_state_store *store,
    struct asteriskd_state_document *state,
    const struct asteriskd_config *config,
    char *error,
    size_t error_size) {
    if (store == NULL || state == NULL || config == NULL || !state->initialized) {
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "invalid start state");
        }
        return ASTERISKD_STATE_INVALID;
    }
    if (state->owner == config->owner && state->core_type == config->core_type &&
        state->mode == config->mode) return ASTERISKD_STATE_OK;
    if (state->owner != config->owner || state->core_type != config->core_type ||
        !asteriskd_state_is_canonical_stopped(state)) {
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "start state identity mismatch");
        }
        return ASTERISKD_STATE_INCOMPATIBLE;
    }

    struct asteriskd_state_document replacement;
    int initialized = asteriskd_state_document_init(
        &replacement, config->owner, config->core_type, config->mode);
    if (initialized != ASTERISKD_STATE_OK) return initialized;
    int saved = asteriskd_state_store_save(store, &replacement, error, error_size);
    if (saved != ASTERISKD_STATE_OK) {
        asteriskd_state_document_destroy(&replacement);
        return saved;
    }
    asteriskd_state_document_destroy(state);
    *state = replacement;
    return ASTERISKD_STATE_OK;
}

bool asteriskd_runtime_recover_before_helper_stop(enum asteriskd_mode mode) {
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
        state->core_type != config->core_type || state->mode != config->mode ||
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
        .standalone_ebpf = config->mode == ASTERISKD_MODE_EBPF,
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

#define ASTERISKD_ACTION_IDENTITY_RETRY_ATTEMPTS 10U
#define ASTERISKD_ACTION_IDENTITY_RETRY_NANOSECONDS 1000000L

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

static bool system_action_source_active_state(
    bool spawned, bool reaped, enum asteriskd_poll_source_kind kind) {
    (void)reaped;
    return spawned && kind >= ASTERISKD_POLL_PROCESS_EXEC_ERROR &&
        kind <= ASTERISKD_POLL_PROCESS_PIDFD;
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

#if defined(ASTERISKD_TESTING)
int asteriskd_test_action_post_setup(
    const struct asteriskd_child_setup_stream *setup,
    bool reaped,
    const struct asteriskd_child_exit_status *status,
    int *exit_status) {
    return system_action_post_setup(setup, reaped, status, exit_status);
}

int asteriskd_test_action_post_identity(
    int identity_result, int reap_result,
    const struct asteriskd_child_setup_stream *setup,
    bool reaped, const struct asteriskd_child_exit_status *status,
    int *exit_status) {
    return system_action_post_identity(
        identity_result, reap_result, setup, reaped, status, exit_status);
}

bool asteriskd_test_action_source_active(
    bool spawned, bool reaped, enum asteriskd_poll_source_kind kind) {
    return system_action_source_active_state(spawned, reaped, kind);
}

bool asteriskd_test_action_setup_wait_done(
    const struct asteriskd_child_setup_stream *setup, bool reaped) {
    return system_action_setup_wait_done_state(setup, reaped);
}

bool asteriskd_test_action_io_drained(
    bool reaped, bool owns_setup, bool owns_stdout, bool owns_stderr) {
    return system_action_io_drained_state(
        reaped, owns_setup, owns_stdout, owns_stderr);
}
#endif

static bool runtime_event_is_final(enum asteriskd_control_event_type type) {
    return type == ASTERISKD_CONTROL_EVENT_STOPPED ||
        type == ASTERISKD_CONTROL_EVENT_FAILED;
}

static bool action_should_cancel(
    bool stop_requested, bool recovery_cancelled,
    bool cleanup_in_progress, bool recovery_only) {
    return (recovery_only && recovery_cancelled) ||
        (!cleanup_in_progress && stop_requested);
}

#if defined(ASTERISKD_TESTING)
bool asteriskd_test_runtime_event_is_final(enum asteriskd_control_event_type type) {
    return runtime_event_is_final(type);
}

bool asteriskd_test_action_should_cancel(
    bool stop_requested, bool recovery_cancelled,
    bool cleanup_in_progress, bool recovery_only) {
    return action_should_cancel(
        stop_requested, recovery_cancelled, cleanup_in_progress, recovery_only);
}
#endif

#if defined(__linux__) || defined(__ANDROID__)
enum system_tc_netlink_query_kind {
    SYSTEM_TC_NETLINK_QUERY_NONE,
    SYSTEM_TC_NETLINK_QUERY_FOREIGN_FILTER,
    SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER,
    SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER,
    SYSTEM_TC_NETLINK_QUERY_QDISC,
};

struct system_text_batch {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
};

struct system_rule_command_batch {
    struct system_text_batch xtables;
    struct system_text_batch ip[ASTERISKD_IP_FAMILY_COUNT];
    bool active;
};

enum system_rule_snapshot_phase {
    SYSTEM_RULE_SNAPSHOT_NONE,
    SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY,
    SYSTEM_RULE_SNAPSHOT_NEEDS_VERIFY,
    SYSTEM_RULE_SNAPSHOT_AFTER_APPLY,
};

struct system_rule_view {
    char *bytes;
    size_t length;
    bool present;
};

struct system_rule_snapshot {
    struct system_rule_view xtables[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    struct system_rule_view ip_rules[ASTERISKD_IP_FAMILY_COUNT];
    struct system_rule_view ip_routes[ASTERISKD_IP_FAMILY_COUNT];
    enum system_rule_snapshot_phase phase;
};

struct asteriskd_system_supervisor {
    struct asteriskd_loaded_config loaded_config;
    struct asteriskd_logger logger;
    struct asteriskd_state_store store;
    struct asteriskd_state_document state;
    struct asteriskd_control_live_context live;
    struct asteriskd_control_server *control;
    struct asteriskd_runtime *runtime;
    int signal_fd;
    bool signal_fd_owned;
    int service_timer_fd;
    bool service_timer_fd_owned;
    struct asteriskd_wifi_monitor wifi_monitor;
    bool wifi_monitor_opened;
    struct asteriskd_service_control_runtime service_control;
    bool service_running;
    bool shutdown_requested;
    bool service_start_requested;
    bool stop_requested;
    bool stopping_children;
    struct asteriskd_process_spec core_spec;
    struct asteriskd_child_process core_process;
    struct asteriskd_child_setup_stream core_setup;
    struct asteriskd_child_identity core_identity;
    bool core_spec_ready;
    bool core_spawned;
    bool core_identity_ready;
    bool core_reaped;
    struct asteriskd_child_exit_status core_exit;
    struct asteriskd_helper_launch helper_launch;
    struct asteriskd_child_process helper_process;
    struct asteriskd_child_setup_stream helper_setup;
    struct asteriskd_child_identity helper_identity;
    bool helper_launch_ready;
    bool helper_spawned;
    bool helper_identity_ready;
    bool helper_reaped;
    struct asteriskd_child_exit_status helper_exit;
    struct asteriskd_readiness_tracker helper_readiness;
    int helper_readiness_result;
    struct asteriskd_matcher_launch matcher_launch;
    struct asteriskd_matcher_pin_plan matcher_pin_plan;
    struct asteriskd_matcher_verification matcher_verification;
    bool matcher_launch_ready;
    bool matcher_plan_ready;
    bool matcher_verified;
    struct asteriskd_bpf2_pin_plan bpf2_pin_plan;
    struct asteriskd_bpf2_verification bpf2_verification;
    bool bpf2_plan_ready;
    bool bpf2_verified;
    struct asteriskd_foreign_tc_probe foreign_tc_probe;
    char foreign_tc_source_path[ASTERISKD_MAX_PATH];
    uint64_t foreign_tc_pinned_object_id;
    bool foreign_tc_pin_active;
    int foreign_tc_netlink_fd;
    uint32_t foreign_tc_netlink_port_id;
    bool foreign_tc_netlink_fd_owned;
    bool foreign_tc_netlink_active;
    bool foreign_tc_netlink_done;
    bool foreign_tc_netlink_failed;
    bool foreign_tc_netlink_present;
    uint32_t foreign_tc_netlink_sequence;
    uint32_t foreign_tc_netlink_interface_index;
    enum system_tc_netlink_query_kind foreign_tc_netlink_query;
    struct asteriskd_foreign_tc_probe foreign_tc_netlink_probe;
    struct asteriskd_tc_filter_expectation tc_filter_netlink_expectation;
    enum asteriskd_rules_slot_state tc_filter_netlink_state;
    enum asteriskd_rules_slot_state tc_qdisc_netlink_state;
    enum asteriskd_wal_pin_batch_kind active_pin_batch;
    bool pin_batch_active;
    struct asteriskd_child_process action_process;
    struct asteriskd_child_setup_stream action_setup;
    struct asteriskd_child_identity action_identity;
    bool action_spawned;
    bool action_identity_ready;
    bool action_reaped;
    struct asteriskd_child_exit_status action_exit;
    bool action_capture_stdout;
    bool action_stdout_overflow;
    char action_stdout[65536U];
    size_t action_stdout_length;
    struct system_rule_command_batch rule_commands;
    struct system_rule_snapshot rule_snapshot;
    bool verify_private_rules;
    size_t verified_private_rule_count;
    struct asteriskd_system_process_context process_context;
    struct asteriskd_readiness_backend readiness_backend;
    struct asteriskd_stop_backend stop_backend;
    struct asteriskd_readiness_tracker readiness;
    int readiness_result;
    struct asteriskd_stop_coordinator stop_coordinator;
    int stop_result;
    bool ebpf_graceful_cleanup_verified;
    struct asteriskd_network_runtime network;
    bool network_opened;
    struct asteriskd_typed_wal_sink network_wal_sink;
    struct asteriskd_rules_runtime rules_runtime;
    struct asteriskd_rules_backend rules_backend;
    bool rules_initialized;
    bool rules_verified;
    bool local_address_snapshot_active;
    struct asteriskd_address_set local_ipv4_snapshot;
    struct asteriskd_address_set local_ipv6_snapshot;
    bool has_global_ipv6_address;
    bool recovery_only;
    bool recovery_cancelled;
    bool recovery_kill_escalated;
    bool cleanup_in_progress;
};

static int system_collect_local_address_set(
    struct asteriskd_system_supervisor *, int, struct asteriskd_address_set *);

static const char *system_pin_path(
    struct asteriskd_system_supervisor *, enum asteriskd_pin_id);
static const char *system_recovery_pin_path(
    struct asteriskd_system_supervisor *, const struct asteriskd_recovery_record *,
    char *, size_t);
static uint64_t system_verified_pin_id(
    const struct asteriskd_system_supervisor *, enum asteriskd_pin_id);
static const struct asteriskd_bpf2_verified_pin *system_bpf2_verified_pin(
    const struct asteriskd_system_supervisor *, enum asteriskd_pin_id);
static int system_foreign_tc_netlink_dispatch(struct asteriskd_system_supervisor *, short);

static int system_runtime_clock(void *opaque, int64_t *milliseconds) {
    (void)opaque;
    struct timespec now;
    if (milliseconds == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0) return -1;
    if ((uint64_t)now.tv_sec > (uint64_t)INT64_MAX / UINT64_C(1000)) return -1;
    *milliseconds = (int64_t)now.tv_sec * INT64_C(1000) + now.tv_nsec / 1000000L;
    return 0;
}

static int system_runtime_local_time(void *opaque, struct asteriskd_local_time *output) {
    (void)opaque;
    if (output == NULL) return -1;
    struct timespec now;
    struct tm local;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 ||
        localtime_r(&now.tv_sec, &local) == NULL) return -1;
    char offset[8U];
    if (strftime(offset, sizeof(offset), "%z", &local) != 5U ||
        (offset[0] != '+' && offset[0] != '-')) return -1;
    int hours = (offset[1] - '0') * 10 + offset[2] - '0';
    int minutes = (offset[3] - '0') * 10 + offset[4] - '0';
    if (hours > 23 || minutes > 59) return -1;
    int sign = offset[0] == '-' ? -1 : 1;
    *output = (struct asteriskd_local_time){
        .year = local.tm_year + 1900,
        .month = local.tm_mon + 1,
        .day = local.tm_mday,
        .hour = local.tm_hour,
        .minute = local.tm_min,
        .second = local.tm_sec,
        .millisecond = (int)(now.tv_nsec / 1000000L),
        .utc_offset_minutes = sign * (hours * 60 + minutes),
    };
    return 0;
}

static int system_runtime_add_source(struct asteriskd_poll_builder *builder, int fd,
    short events, enum asteriskd_poll_source_kind kind, uint32_t slot, uint64_t generation) {
    if (fd < 0) return 0;
    struct asteriskd_poll_source source = {
        .fd = fd,
        .events = events,
        .kind = kind,
        .slot = slot,
        .generation = generation,
    };
    return asteriskd_poll_builder_add(builder, &source);
}

static void system_runtime_min_deadline(
    struct asteriskd_deadline *deadline, uint64_t candidate) {
    if (candidate > (uint64_t)INT64_MAX) return;
    struct asteriskd_deadline next = {
        .armed = true,
        .monotonic_milliseconds = (int64_t)candidate,
    };
    asteriskd_deadline_min(deadline, &next);
}

static void system_service_apply_action(
    struct asteriskd_system_supervisor *system, enum asteriskd_service_action action) {
    if (action == ASTERISKD_SERVICE_ACTION_START && !system->service_running) {
        system->service_start_requested = true;
    } else if (action == ASTERISKD_SERVICE_ACTION_STOP && system->service_running) {
        system->stop_requested = true;
    } else if (action == ASTERISKD_SERVICE_ACTION_SHUTDOWN) {
        system->shutdown_requested = true;
        if (system->service_running) system->stop_requested = true;
    }
}

static int system_service_timer_arm(struct asteriskd_system_supervisor *system) {
    if (!system->service_timer_fd_owned || system->service_timer_fd < 0) return 0;
    struct itimerspec timer;
    memset(&timer, 0, sizeof(timer));
    const struct asteriskd_service_control_config *control =
        &system->loaded_config.config.service_control;
    if (control->enabled && control->schedule.enabled) {
        time_t now = time(NULL);
        time_t next_start = 0;
        time_t next_stop = 0;
        bool has_start = now != (time_t)-1 &&
            asteriskd_cron_next(&control->schedule.start, now, &next_start) == 0;
        bool has_stop = now != (time_t)-1 &&
            asteriskd_cron_next(&control->schedule.stop, now, &next_stop) == 0;
        time_t next = has_start && has_stop
            ? (next_start < next_stop ? next_start : next_stop)
            : has_start ? next_start : has_stop ? next_stop : 0;
        if (next > 0) timer.it_value.tv_sec = next;
    }
    return timerfd_settime(system->service_timer_fd,
        TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &timer, NULL);
}

static int system_service_reconcile_time(struct asteriskd_system_supervisor *system) {
    time_t now = time(NULL);
    if (now == (time_t)-1) return -1;
    system_service_apply_action(system,
        asteriskd_service_control_reconcile_time(&system->service_control, now));
    return system_service_timer_arm(system);
}

static int system_service_timer_dispatch(struct asteriskd_system_supervisor *system) {
    uint64_t expirations = 0U;
    ssize_t count;
    do {
        count = read(system->service_timer_fd, &expirations, sizeof(expirations));
    } while (count < 0 && errno == EINTR);
    if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ECANCELED) return -1;
    return system_service_reconcile_time(system);
}

static int system_service_wifi_dispatch(struct asteriskd_system_supervisor *system) {
    enum asteriskd_wifi_transition transition = ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED;
    struct asteriskd_wifi_identity identity;
    bool has_transition = false;
    char error[128U];
    if (asteriskd_wifi_monitor_handle(&system->wifi_monitor, &transition,
            &identity, &has_transition, error, sizeof(error)) != 0) return -1;
    if (has_transition) {
        system_service_apply_action(system,
            asteriskd_service_control_on_wifi(
                &system->service_control, transition, &identity));
    }
    return 0;
}

static int system_service_wifi_reconcile(
    struct asteriskd_system_supervisor *system, uint64_t now) {
    enum asteriskd_wifi_transition transition = ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED;
    struct asteriskd_wifi_identity identity;
    bool has_transition = false;
    char error[128U];
    if (asteriskd_wifi_monitor_take_reconcile(&system->wifi_monitor, now,
            &transition, &identity, &has_transition, error, sizeof(error)) != 0) return -1;
    if (has_transition) {
        system_service_apply_action(system,
            asteriskd_service_control_on_wifi(
                &system->service_control, transition, &identity));
    }
    return 0;
}

static int system_runtime_prepare(
    void *opaque, struct asteriskd_poll_builder *builder, struct asteriskd_deadline *deadline) {
    struct asteriskd_system_supervisor *system = opaque;
    if (system_runtime_add_source(builder, system->signal_fd, POLLIN,
            ASTERISKD_POLL_SIGNAL, 0U, 1U) != 0) return -1;
    if (system->service_timer_fd_owned &&
        system_runtime_add_source(builder, system->service_timer_fd, POLLIN,
            ASTERISKD_POLL_SERVICE_TIMER, 0U, 1U) != 0) return -1;
    if (system->wifi_monitor_opened &&
        system_runtime_add_source(builder, asteriskd_wifi_monitor_fd(&system->wifi_monitor), POLLIN,
            ASTERISKD_POLL_WIFI, 0U, 1U) != 0) return -1;
    uint64_t wifi_deadline = 0U;
    if (system->wifi_monitor_opened &&
        asteriskd_wifi_monitor_next_deadline(&system->wifi_monitor, &wifi_deadline)) {
        system_runtime_min_deadline(deadline, wifi_deadline);
    }
    if (system->core_spawned && !system->core_reaped) {
        uint64_t generation = (uint64_t)system->core_process.pid;
        if (system->core_process.owns_setup_status_fd &&
            system_runtime_add_source(builder, system->core_process.setup_status_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_EXEC_ERROR, 0U, generation) != 0) return -1;
        if (system->core_process.owns_stdout_fd &&
            system_runtime_add_source(builder, system->core_process.stdout_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDOUT, 0U, generation) != 0) return -1;
        if (system->core_process.owns_stderr_fd &&
            system_runtime_add_source(builder, system->core_process.stderr_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDERR, 0U, generation) != 0) return -1;
        if (system->core_process.owns_pidfd &&
            system_runtime_add_source(builder, system->core_process.pidfd, POLLIN,
                ASTERISKD_POLL_PROCESS_PIDFD, 0U, generation) != 0) return -1;
    }
    if (system->helper_spawned && !system->helper_reaped) {
        uint64_t generation = (uint64_t)system->helper_process.pid;
        if (system->helper_process.owns_setup_status_fd &&
            system_runtime_add_source(builder, system->helper_process.setup_status_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_EXEC_ERROR, 1U, generation) != 0) return -1;
        if (system->helper_process.owns_stdout_fd &&
            system_runtime_add_source(builder, system->helper_process.stdout_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDOUT, 1U, generation) != 0) return -1;
        if (system->helper_process.owns_stderr_fd &&
            system_runtime_add_source(builder, system->helper_process.stderr_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDERR, 1U, generation) != 0) return -1;
        if (system->helper_process.owns_pidfd &&
            system_runtime_add_source(builder, system->helper_process.pidfd, POLLIN,
                ASTERISKD_POLL_PROCESS_PIDFD, 1U, generation) != 0) return -1;
    }
    if (system->action_spawned) {
        uint64_t generation = (uint64_t)system->action_process.pid;
        if (system->action_process.owns_setup_status_fd &&
            system_runtime_add_source(builder, system->action_process.setup_status_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_EXEC_ERROR, 2U, generation) != 0) return -1;
        if (system->action_process.owns_stdout_fd &&
            system_runtime_add_source(builder, system->action_process.stdout_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDOUT, 2U, generation) != 0) return -1;
        if (system->action_process.owns_stderr_fd &&
            system_runtime_add_source(builder, system->action_process.stderr_fd, POLLIN,
                ASTERISKD_POLL_PROCESS_STDERR, 2U, generation) != 0) return -1;
        if (!system->action_reaped && system->action_process.owns_pidfd &&
            system_runtime_add_source(builder, system->action_process.pidfd, POLLIN,
                ASTERISKD_POLL_PROCESS_PIDFD, 2U, generation) != 0) return -1;
    }
    if (system->control != NULL) {
        struct asteriskd_control_interest interests[ASTERISKD_CONTROL_MAX_CLIENTS + 1U];
        size_t count = asteriskd_control_server_interests(
            system->control, interests, sizeof(interests) / sizeof(interests[0]));
        if (count > sizeof(interests) / sizeof(interests[0])) return -1;
        int listener = asteriskd_control_server_listener_fd(system->control);
        for (size_t index = 0U; index < count; ++index) {
            short events = (short)((interests[index].readable ? POLLIN : 0) |
                (interests[index].writable ? POLLOUT : 0));
            enum asteriskd_poll_source_kind kind = interests[index].fd == listener
                ? ASTERISKD_POLL_CONTROL_LISTENER : ASTERISKD_POLL_CONTROL_CLIENT;
            if (system_runtime_add_source(builder, interests[index].fd, events, kind,
                    (uint32_t)interests[index].fd,
                    (uint64_t)(unsigned)interests[index].fd + UINT64_C(1)) != 0) return -1;
        }
        uint64_t control_deadline = 0U;
        if (asteriskd_control_server_next_deadline(system->control, &control_deadline)) {
            system_runtime_min_deadline(deadline, control_deadline);
        }
    }
    if (system->network_opened && system->network.fd_owned &&
        system_runtime_add_source(builder, system->network.fd, POLLIN,
            ASTERISKD_POLL_NETWORK, 0U, 1U) != 0) return -1;
    if (system->foreign_tc_netlink_active && system->foreign_tc_netlink_fd_owned &&
        system_runtime_add_source(builder, system->foreign_tc_netlink_fd, POLLIN,
            ASTERISKD_POLL_TC_NETLINK, 0U,
            system->foreign_tc_netlink_sequence) != 0) return -1;
    uint64_t network_deadline = 0U;
    if (system->network_opened &&
        asteriskd_network_next_deadline(&system->network, &network_deadline)) {
        system_runtime_min_deadline(deadline, network_deadline);
    }
    if (system->logger.opened) {
        for (size_t role = 0U; role < 2U; ++role) {
            for (size_t stream = 0U; stream < ASTERISKD_LOG_STREAM_COUNT; ++stream) {
                const struct asteriskd_log_partial *partial = &system->logger.partials[role][stream];
                if (partial->has_first_byte &&
                    partial->first_byte_milliseconds <= UINT64_MAX -
                        ASTERISKD_LOG_PARTIAL_TIMEOUT_MILLIS) {
                    system_runtime_min_deadline(deadline,
                        partial->first_byte_milliseconds + ASTERISKD_LOG_PARTIAL_TIMEOUT_MILLIS);
                }
            }
        }
    }
    return 0;
}

static int system_runtime_wait(void *opaque, const struct asteriskd_poll_builder *builder,
    int64_t timeout_milliseconds, short *ready) {
    (void)opaque;
    struct pollfd descriptors[ASTERISKD_MAX_POLL_SOURCES];
    for (size_t index = 0U; index < builder->count; ++index) {
        descriptors[index] = (struct pollfd){
            .fd = builder->sources[index].fd,
            .events = builder->sources[index].events,
        };
    }
    int timeout = timeout_milliseconds < 0 ? -1 :
        timeout_milliseconds > INT_MAX ? INT_MAX : (int)timeout_milliseconds;
    int result = poll(descriptors, (nfds_t)builder->count, timeout);
    if (result < 0) return errno == EINTR
        ? ASTERISKD_REACTOR_WAIT_INTERRUPTED : ASTERISKD_REACTOR_WAIT_ERROR;
    for (size_t index = 0U; index < builder->count; ++index) ready[index] = descriptors[index].revents;
    return result;
}

static void system_runtime_fatal(struct asteriskd_runtime_delta *delta,
    enum asteriskd_component component, const char *message) {
    if ((delta->flags & ASTERISKD_DELTA_FATAL) != 0U) return;
    delta->flags |= ASTERISKD_DELTA_FATAL;
    delta->has_error = true;
    delta->error_code = ASTERISKD_FAILURE_IO_ERROR;
    delta->error_component = component;
    (void)snprintf(delta->error_message, sizeof(delta->error_message), "%s", message);
}

static void system_runtime_note_exit(struct asteriskd_system_supervisor *system,
    enum asteriskd_child_role role, int status, struct asteriskd_runtime_delta *delta) {
    bool *reaped = role == ASTERISKD_CHILD_CORE ? &system->core_reaped : &system->helper_reaped;
    struct asteriskd_child_exit_status *exit_status = role == ASTERISKD_CHILD_CORE
        ? &system->core_exit : &system->helper_exit;
    if (*reaped) return;
    *reaped = true;
    if (asteriskd_child_exit_status_from_wait(status, exit_status) != 0) {
        system_runtime_fatal(delta,
            role == ASTERISKD_CHILD_CORE ? ASTERISKD_COMPONENT_CORE : ASTERISKD_COMPONENT_HELPER,
            "invalid child wait status");
        return;
    }
    delta->flags |= ASTERISKD_DELTA_CHILD_EXITED;
    delta->has_child_exit = true;
    delta->child_role = role;
    delta->child_exit = *exit_status;
}

static void system_runtime_note_action_exit(
    struct asteriskd_system_supervisor *system, int status) {
    if (system->action_reaped) return;
    system->action_reaped = true;
    if (asteriskd_child_exit_status_from_wait(status, &system->action_exit) != 0) {
        memset(&system->action_exit, 0, sizeof(system->action_exit));
    }
}

static int system_runtime_reap_children(
    struct asteriskd_system_supervisor *system, struct asteriskd_runtime_delta *delta) {
    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid == 0) return 0;
        if (pid < 0) return errno == ECHILD ? 0 : -1;
        if (system->core_spawned && pid == (pid_t)system->core_process.pid) {
            system_runtime_note_exit(system, ASTERISKD_CHILD_CORE, status, delta);
        } else if (system->helper_spawned && pid == (pid_t)system->helper_process.pid) {
            system_runtime_note_exit(system, ASTERISKD_CHILD_HELPER, status, delta);
        } else if (system->action_spawned && pid == (pid_t)system->action_process.pid) {
            system_runtime_note_action_exit(system, status);
        }
    }
}

static int system_runtime_dispatch_signal(
    struct asteriskd_system_supervisor *system, struct asteriskd_runtime_delta *delta) {
    for (;;) {
        struct signalfd_siginfo info;
        ssize_t count = read(system->signal_fd, &info, sizeof(info));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (count != (ssize_t)sizeof(info)) return -1;
        if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) {
            system->shutdown_requested = true;
            if (system->service_running &&
                (delta->flags & ASTERISKD_DELTA_STOP_REQUESTED) == 0U) {
                delta->flags |= ASTERISKD_DELTA_STOP_REQUESTED;
                delta->stop_reason = info.ssi_signo == SIGTERM
                    ? ASTERISKD_LIFECYCLE_REASON_SIGTERM : ASTERISKD_LIFECYCLE_REASON_SIGINT;
            }
        } else if (info.ssi_signo == SIGCHLD && !system->stopping_children &&
            system_runtime_reap_children(system, delta) != 0) return -1;
    }
}

static void system_runtime_close_child_fd(int *fd, bool *owned) {
    if (*owned && *fd >= 0) (void)close(*fd);
    *fd = -1;
    *owned = false;
}

static int system_runtime_dispatch_setup(struct asteriskd_system_supervisor *system,
    uint32_t slot, struct asteriskd_runtime_delta *delta) {
    struct asteriskd_child_process *process = slot == 0U ? &system->core_process :
        slot == 1U ? &system->helper_process : &system->action_process;
    struct asteriskd_child_setup_stream *setup = slot == 0U ? &system->core_setup :
        slot == 1U ? &system->helper_setup : &system->action_setup;
    enum asteriskd_component component = slot == 0U
        ? ASTERISKD_COMPONENT_CORE : slot == 1U
            ? ASTERISKD_COMPONENT_HELPER : ASTERISKD_COMPONENT_RUNTIME;
    unsigned char bytes[128U];
    for (;;) {
        ssize_t count = read(process->setup_status_fd, bytes, sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        bool eof = count == 0;
        if (count < 0 || asteriskd_child_setup_stream_feed(setup,
                bytes, count > 0 ? (size_t)count : 0U, eof) < ASTERISKD_CHILD_SETUP_PENDING) {
            if (slot != 2U) {
                system_runtime_fatal(delta, component, "child exec setup failed");
            }
            return count < 0 ? -1 : 0;
        }
        if (eof) {
            system_runtime_close_child_fd(&process->setup_status_fd,
                &process->owns_setup_status_fd);
            return 0;
        }
    }
}

static int system_runtime_dispatch_log(struct asteriskd_system_supervisor *system,
    uint32_t slot, enum asteriskd_log_stream stream, struct asteriskd_runtime_delta *delta) {
    (void)delta;
    struct asteriskd_child_process *process = slot == 0U ? &system->core_process :
        slot == 1U ? &system->helper_process : &system->action_process;
    int *fd = stream == ASTERISKD_LOG_STREAM_STDOUT
        ? &process->stdout_fd : &process->stderr_fd;
    bool *owned = stream == ASTERISKD_LOG_STREAM_STDOUT
        ? &process->owns_stdout_fd : &process->owns_stderr_fd;
    unsigned char bytes[4096U];
    for (;;) {
        ssize_t count = read(*fd, bytes, sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (count > 0 && slot == 2U && stream == ASTERISKD_LOG_STREAM_STDOUT &&
            system->action_capture_stdout) {
            size_t available = sizeof(system->action_stdout) - system->action_stdout_length;
            size_t copied = (size_t)count < available ? (size_t)count : available;
            memcpy(&system->action_stdout[system->action_stdout_length], bytes, copied);
            system->action_stdout_length += copied;
            if (copied != (size_t)count) system->action_stdout_overflow = true;
        }
        if (count < 0) return -1;
        if (count == 0) {
            system_runtime_close_child_fd(fd, owned);
            return 0;
        }
    }
}

static int system_runtime_dispatch(void *opaque, const struct asteriskd_poll_source *source,
    short ready, struct asteriskd_runtime_delta *delta) {
    struct asteriskd_system_supervisor *system = opaque;
    if (source->kind >= ASTERISKD_POLL_PROCESS_EXEC_ERROR &&
        source->kind <= ASTERISKD_POLL_PROCESS_PIDFD) {
        struct asteriskd_child_process *process = source->slot == 0U ? &system->core_process :
            source->slot == 1U ? &system->helper_process :
                source->slot == 2U ? &system->action_process : NULL;
        bool active = source->slot == 0U ? system->core_spawned && !system->core_reaped :
            source->slot == 1U ? system->helper_spawned && !system->helper_reaped :
                source->slot == 2U && system_action_source_active_state(
                    system->action_spawned, system->action_reaped, source->kind);
        if (!active || !asteriskd_process_poll_source_matches(process, source)) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_RUNTIME,
                "stale child poll source");
            return 0;
        }
    }
    if (source->kind == ASTERISKD_POLL_SIGNAL) {
        if (system_runtime_dispatch_signal(system, delta) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_RUNTIME, "signal drain failed");
        }
    } else if (source->kind == ASTERISKD_POLL_PROCESS_EXEC_ERROR) {
        (void)system_runtime_dispatch_setup(system, source->slot, delta);
    } else if (source->kind == ASTERISKD_POLL_PROCESS_STDOUT) {
        (void)system_runtime_dispatch_log(
            system, source->slot, ASTERISKD_LOG_STREAM_STDOUT, delta);
    } else if (source->kind == ASTERISKD_POLL_PROCESS_STDERR) {
        (void)system_runtime_dispatch_log(
            system, source->slot, ASTERISKD_LOG_STREAM_STDERR, delta);
    } else if (source->kind == ASTERISKD_POLL_PROCESS_PIDFD && !system->stopping_children) {
        if (system_runtime_reap_children(system, delta) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_CORE, "core reap failed");
        }
    } else if ((source->kind == ASTERISKD_POLL_CONTROL_LISTENER ||
            source->kind == ASTERISKD_POLL_CONTROL_CLIENT) && system->control != NULL) {
        int64_t now = 0;
        if (system_runtime_clock(system, &now) != 0 ||
            asteriskd_control_server_dispatch(system->control, source->fd,
                (ready & POLLIN) != 0, (ready & POLLOUT) != 0,
                (ready & (POLLERR | POLLHUP | POLLNVAL)) != 0, (uint64_t)now) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_CONTROL, "control dispatch failed");
        }
    } else if (source->kind == ASTERISKD_POLL_NETWORK && system->network_opened) {
        int64_t now = 0;
        char error[128U];
        if (system_runtime_clock(system, &now) != 0 ||
            asteriskd_network_handle(
                &system->network, (uint64_t)now, error, sizeof(error)) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_NETWORK, "network drain failed");
        } else if (asteriskd_network_has_immediate(&system->network)) {
            delta->flags |= ASTERISKD_DELTA_NETWORK_CHANGED;
        }
    } else if (source->kind == ASTERISKD_POLL_TC_NETLINK &&
        system->foreign_tc_netlink_active) {
        if (source->generation != system->foreign_tc_netlink_sequence ||
            system_foreign_tc_netlink_dispatch(system, ready) != 0) {
            system->foreign_tc_netlink_failed = true;
            system->foreign_tc_netlink_done = true;
        }
    } else if (source->kind == ASTERISKD_POLL_SERVICE_TIMER) {
        if (system_service_timer_dispatch(system) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_RUNTIME,
                "service schedule dispatch failed");
        }
    } else if (source->kind == ASTERISKD_POLL_WIFI) {
        if (system_service_wifi_dispatch(system) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_NETWORK,
                "WiFi event dispatch failed");
        }
    }
    if (system->stop_requested &&
        (delta->flags & ASTERISKD_DELTA_STOP_REQUESTED) == 0U) {
        system->stop_requested = false;
        delta->flags |= ASTERISKD_DELTA_STOP_REQUESTED;
        delta->stop_reason = ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP;
    }
    return 0;
}

static int system_runtime_expire(
    void *opaque, int64_t now, struct asteriskd_runtime_delta *delta) {
    struct asteriskd_system_supervisor *system = opaque;
    if (system->control != NULL &&
        asteriskd_control_server_tick(system->control, (uint64_t)now) != 0) {
        system_runtime_fatal(delta, ASTERISKD_COMPONENT_CONTROL, "control deadline failed");
    }
    if (system->logger.opened &&
        asteriskd_log_flush_expired(&system->logger, (uint64_t)now) != 0) {
        system_runtime_fatal(delta, ASTERISKD_COMPONENT_LOG, "log deadline failed");
    }
    uint64_t network_deadline = 0U;
    if (system->network_opened &&
        asteriskd_network_next_deadline(&system->network, &network_deadline) &&
        (uint64_t)now >= network_deadline) {
        struct asteriskd_event_batch batch;
        bool integrity_loss = false;
        if (asteriskd_network_take_reconcile(
                &system->network, (uint64_t)now, &batch, &integrity_loss) != 0) {
            system_runtime_fatal(delta, ASTERISKD_COMPONENT_NETWORK,
                "network debounce failed");
        } else {
            delta->flags |= ASTERISKD_DELTA_RECONCILE_DUE;
            (void)integrity_loss;
        }
    }
    uint64_t wifi_deadline = 0U;
    if (system->wifi_monitor_opened &&
        asteriskd_wifi_monitor_next_deadline(&system->wifi_monitor, &wifi_deadline) &&
        (uint64_t)now >= wifi_deadline &&
        system_service_wifi_reconcile(system, (uint64_t)now) != 0) {
        system_runtime_fatal(delta, ASTERISKD_COMPONENT_NETWORK,
            "WiFi association reconcile failed");
    }
    return 0;
}

static struct asteriskd_runtime_reactor_backend system_runtime_reactor_backend(void) {
    const struct asteriskd_runtime_reactor_backend backend = {
        .monotonic_milliseconds = system_runtime_clock,
        .prepare = system_runtime_prepare,
        .wait = system_runtime_wait,
        .dispatch = system_runtime_dispatch,
        .expire = system_runtime_expire,
    };
    return backend;
}

static int system_runtime_snapshot(
    void *opaque, struct asteriskd_control_snapshot *snapshot) {
    struct asteriskd_system_supervisor *system = opaque;
    return asteriskd_control_snapshot_from_state(&system->state, &system->live, snapshot);
}

static int system_runtime_request_stop(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    if (!system->service_running && !system->recovery_only) return 1;
    system->stop_requested = true;
    if (system->recovery_only) system->recovery_cancelled = true;
    return 0;
}

static int system_runtime_request_shutdown(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    system->shutdown_requested = true;
    if (system->service_running || system->recovery_only) {
        system->stop_requested = true;
        if (system->recovery_only) system->recovery_cancelled = true;
    }
    return 0;
}

static int system_accept_pump_delta(struct asteriskd_system_supervisor *system,
    struct asteriskd_runtime_delta *delta) {
    if (system == NULL || delta == NULL) return -1;
    if (system->recovery_only && system->recovery_cancelled &&
        (delta->flags & ASTERISKD_DELTA_STOP_REQUESTED) != 0U) {
        delta->flags &= ~ASTERISKD_DELTA_STOP_REQUESTED;
        delta->stop_reason = ASTERISKD_LIFECYCLE_REASON_NONE;
    }
    return delta->flags == 0U ? 0 :
        asteriskd_runtime_accept_delta(system->runtime, delta);
}

static int system_pump_condition(struct asteriskd_system_supervisor *,
    const struct asteriskd_deadline *, asteriskd_runtime_predicate);
static int system_pump_condition_periodic(struct asteriskd_system_supervisor *,
    const struct asteriskd_deadline *, uint32_t, asteriskd_runtime_predicate);
static bool system_stop_done(void *);

static int system_effect_save(
    void *opaque, const struct asteriskd_state_document *state) {
    struct asteriskd_system_supervisor *system = opaque;
    char error[256U];
    return asteriskd_state_store_save(&system->store, state, error, sizeof(error));
}

static int system_effect_event(void *opaque, enum asteriskd_control_event_type type,
    const struct asteriskd_control_snapshot *snapshot,
    const struct asteriskd_control_error *details, bool has_details) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (has_details != (details != NULL) || system_runtime_clock(system, &now) != 0) return -1;
    return asteriskd_control_server_publish_event(
        system->control, type, snapshot, details,
        runtime_event_is_final(type), (uint64_t)now);
}

static int system_recover_state(struct asteriskd_system_supervisor *system);
static int system_effect_stop_core(void *opaque);

static int system_effect_recover(void *opaque) {
    return system_recover_state(opaque);
}

static bool system_core_setup_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return system->core_setup.complete || system->core_setup.fatal || system->core_reaped;
}

static int system_effect_start_core(
    void *opaque, struct asteriskd_child_identity *identity) {
    struct asteriskd_system_supervisor *system = opaque;
    char error[256U];
    if (!system->core_spec_ready && asteriskd_core_process_spec(
            &system->loaded_config.config, (const char *const *)environ,
            &system->core_spec, error, sizeof(error)) != 0) return -1;
    system->core_spec_ready = true;
    if (asteriskd_system_process_backends_init(&system->process_context,
            &system->core_spec, NULL, &system->readiness_backend,
            &system->stop_backend) != 0 ||
        asteriskd_readiness_preflight(&system->loaded_config.config,
            ASTERISKD_CHILD_CORE, &system->readiness_backend) != 0) return -1;
    if (asteriskd_process_spawn_system(
            &system->core_spec, &system->core_process, error, sizeof(error)) != 0) return -1;
    system->core_spawned = true;
    asteriskd_child_setup_stream_init(&system->core_setup);
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0 ||
        (uint64_t)now > UINT64_MAX - system->loaded_config.config.readiness_timeout_milliseconds) {
        return -1;
    }
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = now +
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
    };
    int pumped = system_pump_condition(
        system, &deadline, system_core_setup_done);
    if (pumped != 0 || !system->core_setup.complete || system->core_setup.fatal ||
        system->core_reaped) return -1;
    enum asteriskd_child_type type = system->loaded_config.config.core_type == ASTERISKD_CORE_XRAY
        ? ASTERISKD_CHILD_TYPE_XRAY :
        system->loaded_config.config.core_type == ASTERISKD_CORE_SING_BOX
            ? ASTERISKD_CHILD_TYPE_SING_BOX : ASTERISKD_CHILD_TYPE_MIHOMO;
    if (asteriskd_process_identity_read(asteriskd_system_process_identity_backend(),
            system->core_process.pid, ASTERISKD_CHILD_CORE, type, &system->core_spec,
            &system->core_identity, error, sizeof(error)) != 0) return -1;
    system->core_identity_ready = true;
    *identity = system->core_identity;
    return 0;
}

static bool system_core_readiness_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) {
        system->readiness_result = ASTERISKD_READINESS_IO;
        return true;
    }
    bool stop = system->recovery_cancelled || atomic_load_explicit(
        &system->runtime->lifecycle.stop_was_requested, memory_order_acquire);
    system->readiness_result = asteriskd_readiness_poll(
        &system->loaded_config.config, &system->readiness, &system->core_identity,
        &system->readiness_backend, (uint64_t)now, stop);
    return system->readiness_result != ASTERISKD_READINESS_PENDING;
}

static int system_effect_wait_core(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0 ||
        asteriskd_system_process_backends_init(&system->process_context,
            &system->core_spec, NULL, &system->readiness_backend, &system->stop_backend) != 0 ||
        asteriskd_readiness_init(&system->loaded_config.config, ASTERISKD_CHILD_CORE,
            (uint64_t)now, &system->readiness_backend, &system->readiness) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = (int64_t)system->readiness.deadline_milliseconds,
    };
    int pumped = system_pump_condition_periodic(system, &deadline,
        ASTERISKD_READINESS_POLL_INTERVAL_MILLIS, system_core_readiness_done);
    if (pumped == 0 && system->readiness_result == ASTERISKD_READINESS_READY) return 0;
    return system->readiness_result == ASTERISKD_READINESS_TIMEOUT
        ? ASTERISKD_RUNTIME_EFFECT_READINESS_TIMEOUT : -1;
}

static bool system_helper_setup_done(void *opaque);

static int system_start_helper_process(
    struct asteriskd_system_supervisor *system, struct asteriskd_child_identity *identity) {
    char error[256U];
    if (!system->helper_launch_ready && asteriskd_helper_launch_prepare(
            &system->loaded_config.config, (const char *const *)environ,
            asteriskd_system_anonymous_file_backend(), &system->helper_launch,
            error, sizeof(error)) != 0) return -1;
    system->helper_launch_ready = true;
    if (asteriskd_system_process_backends_init(&system->process_context,
            &system->core_spec, &system->helper_launch.process,
            &system->readiness_backend, &system->stop_backend) != 0 ||
        asteriskd_readiness_preflight(&system->loaded_config.config,
            ASTERISKD_CHILD_HELPER, &system->readiness_backend) != 0) return -1;
    if (asteriskd_process_spawn_system(&system->helper_launch.process,
            &system->helper_process, error, sizeof(error)) != 0) return -1;
    system->helper_spawned = true;
    asteriskd_child_setup_stream_init(&system->helper_setup);
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = now +
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
    };
    int pumped = system_pump_condition(
        system, &deadline, system_helper_setup_done);
    if (pumped != 0 || !system->helper_setup.complete || system->helper_setup.fatal ||
        system->helper_reaped) return -1;
    const struct asteriskd_anonymous_file_backend *anonymous =
        asteriskd_system_anonymous_file_backend();
    if (asteriskd_anonymous_file_close(anonymous, &system->helper_launch.config_file) != 0 ||
        asteriskd_anonymous_file_close(anonymous, &system->helper_launch.direct_ipv4_file) != 0 ||
        asteriskd_anonymous_file_close(anonymous, &system->helper_launch.direct_ipv6_file) != 0) {
        return -1;
    }
    enum asteriskd_child_type type = system->loaded_config.config.helper.type ==
        ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL
            ? ASTERISKD_CHILD_TYPE_HEV_SOCKS5_TUNNEL : ASTERISKD_CHILD_TYPE_BPF2SOCKS;
    if (asteriskd_process_identity_read(asteriskd_system_process_identity_backend(),
            system->helper_process.pid, ASTERISKD_CHILD_HELPER, type,
            &system->helper_launch.process, &system->helper_identity,
            error, sizeof(error)) != 0) return -1;
    system->helper_identity_ready = true;
    *identity = system->helper_identity;
    return 0;
}

static bool system_helper_setup_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return system->helper_setup.complete || system->helper_setup.fatal || system->helper_reaped;
}

static bool system_helper_readiness_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) {
        system->helper_readiness_result = ASTERISKD_READINESS_IO;
        return true;
    }
    bool stop = system->recovery_cancelled || atomic_load_explicit(
        &system->runtime->lifecycle.stop_was_requested, memory_order_acquire);
    system->helper_readiness_result = asteriskd_readiness_poll(
        &system->loaded_config.config, &system->helper_readiness, &system->helper_identity,
        &system->readiness_backend, (uint64_t)now, stop);
    return system->helper_readiness_result != ASTERISKD_READINESS_PENDING;
}

static int system_effect_wait_helper(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0 ||
        asteriskd_system_process_backends_init(&system->process_context,
            &system->core_spec, &system->helper_launch.process,
            &system->readiness_backend, &system->stop_backend) != 0 ||
        asteriskd_readiness_init(&system->loaded_config.config, ASTERISKD_CHILD_HELPER,
            (uint64_t)now, &system->readiness_backend, &system->helper_readiness) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = (int64_t)system->helper_readiness.deadline_milliseconds,
    };
    int pumped = system_pump_condition_periodic(system, &deadline,
        ASTERISKD_READINESS_POLL_INTERVAL_MILLIS, system_helper_readiness_done);
    if (pumped == 0 && system->helper_readiness_result == ASTERISKD_READINESS_READY) return 0;
    return system->helper_readiness_result == ASTERISKD_READINESS_TIMEOUT
        ? ASTERISKD_RUNTIME_EFFECT_READINESS_TIMEOUT : -1;
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

static int system_pump_condition(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, asteriskd_runtime_predicate predicate) {
    for (;;) {
        if (predicate(system)) return 0;
        int64_t now = 0;
        if (system_runtime_clock(system, &now) != 0 ||
            now >= deadline->monotonic_milliseconds) return -1;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system->runtime, deadline, &delta) != 0) return -1;
        if (system_accept_pump_delta(system, &delta) != 0) return -1;
    }
}

static int system_pump_condition_periodic(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, uint32_t interval,
    asteriskd_runtime_predicate predicate) {
    if (deadline == NULL || !deadline->armed || predicate == NULL) return -1;
    for (;;) {
        if (predicate(system)) return 0;
        int64_t now = 0;
        if (system_runtime_clock(system, &now) != 0 ||
            now >= deadline->monotonic_milliseconds) return -1;
        struct asteriskd_deadline iteration = {.armed = true};
        if (runtime_periodic_deadline(now, deadline->monotonic_milliseconds,
                interval, &iteration.monotonic_milliseconds) != 0) return -1;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system->runtime, &iteration, &delta) != 0) return -1;
        if (system_accept_pump_delta(system, &delta) != 0) return -1;
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
    if (system_runtime_clock(system, &now) != 0 || now < 0 ||
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
        if (system->stop_result == ASTERISKD_STOP_PENDING) {
            struct asteriskd_deadline deadline = {
                .armed = true,
                .monotonic_milliseconds =
                    (int64_t)system->stop_coordinator.kill_deadline_milliseconds,
            };
            if (system_pump_condition(system, &deadline, system_stop_done) != 0) {
                system->stop_result = ASTERISKD_STOP_FAILED;
            }
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
    if (system_pump_condition(system, &term_deadline, system_action_exit_done) == 0 &&
        system->action_reaped) return 0;
    if (system_action_signal_unverified(system, SIGKILL) != 0) return -1;
    struct asteriskd_deadline kill_deadline = {
        .armed = true,
        .monotonic_milliseconds = term_deadline.monotonic_milliseconds +
            ASTERISKD_PROCESS_KILL_REAP_MILLIS,
    };
    return system_pump_condition(system, &kill_deadline, system_action_exit_done) == 0 &&
        system->action_reaped ? 0 : -1;
}

static int system_action_reap_now(struct asteriskd_system_supervisor *system) {
    for (;;) {
        int status = 0;
        pid_t pid = waitpid((pid_t)system->action_process.pid, &status, WNOHANG);
        if (pid == 0) return 0;
        if (pid == (pid_t)system->action_process.pid) {
            system_runtime_note_action_exit(system, status);
            return 1;
        }
        if (pid < 0 && errno == EINTR) continue;
        if (pid < 0 && errno == ECHILD && system->action_reaped) return 1;
        return -1;
    }
}

static int system_action_run_spec(struct asteriskd_system_supervisor *system,
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
    if (asteriskd_process_spawn_system(spec, &system->action_process,
            error, sizeof(error)) != 0) {
        char message[256U];
        int written = snprintf(message, sizeof(message),
            "action execution failed: phase=spawn detail=%s",
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    system->action_spawned = true;
    asteriskd_child_setup_stream_init(&system->action_setup);
    int64_t now = 0;
    failure_phase = "setup-clock";
    if (system_runtime_clock(system, &now) != 0) goto failed;
    struct asteriskd_deadline setup_deadline = {
        .armed = true,
        .monotonic_milliseconds = now +
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
    };
    failure_phase = "setup-wait";
    if (system_pump_condition(system, &setup_deadline, system_action_setup_done) != 0) goto failed;
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
    for (unsigned int attempt = 0U; identity_result != 0; ++attempt) {
        int post_identity = system_action_post_identity(
            identity_result, system_action_reap_now(system), &system->action_setup,
            system->action_reaped, &system->action_exit, &completed_exit);
        if (post_identity > 0) goto early_exit;
        if (post_identity != ASTERISKD_CONFIG_NOT_READY ||
            attempt + 1U >= ASTERISKD_ACTION_IDENTITY_RETRY_ATTEMPTS) goto failed;
#if defined(__linux__) || defined(__ANDROID__)
        struct timespec retry_delay = {
            .tv_sec = 0,
            .tv_nsec = ASTERISKD_ACTION_IDENTITY_RETRY_NANOSECONDS,
        };
        while (nanosleep(&retry_delay, &retry_delay) != 0) {
            if (errno != EINTR) goto failed;
        }
#else
        goto failed;
#endif
        identity_result = asteriskd_process_identity_read(
            asteriskd_system_process_identity_backend(),
            system->action_process.pid, ASTERISKD_CHILD_HELPER,
            ASTERISKD_CHILD_TYPE_BPF2SOCKS, spec, &system->action_identity,
            error, sizeof(error));
    }
    system->action_identity_ready = true;
    failure_phase = "exit-clock";
    if (system_runtime_clock(system, &now) != 0 || now > INT64_MAX - INT64_C(110000)) goto failed;
    struct asteriskd_deadline exit_deadline = {
        .armed = true,
        .monotonic_milliseconds = now + INT64_C(110000),
    };
    failure_phase = "cancelled";
    if (action_should_cancel(atomic_load_explicit(
            &system->runtime->lifecycle.stop_was_requested,
            memory_order_acquire), system->recovery_cancelled,
            system->cleanup_in_progress, system->recovery_only)) {
        goto failed;
    }
    failure_phase = "exit-wait";
    if (system_pump_condition(system, &exit_deadline, system_action_exit_done) != 0 ||
        !system->action_reaped || !system->action_exit.has_exit_code ||
        system->action_exit.has_signal) goto failed;
    failure_phase = "exit-drain";
    if (system_pump_condition(
            system, &exit_deadline, system_action_io_drained_done) != 0) goto failed;
    *exit_status = system->action_exit.exit_code;
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return 0;

early_exit:
    failure_phase = "early-exit-drain";
    if (system_pump_condition(
            system, &setup_deadline, system_action_io_drained_done) != 0) goto failed;
    *exit_status = completed_exit;
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return 0;

failed:
    {
        char message[320U];
        int written = snprintf(message, sizeof(message),
            "action execution failed: phase=%s reaped=%d setupComplete=%d setupFatal=%d detail=%s",
            failure_phase, system->action_reaped ? 1 : 0,
            system->action_setup.complete ? 1 : 0,
            system->action_setup.fatal ? 1 : 0,
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RUNTIME, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
    }
    (void)system_action_cleanup(system, spec);
    asteriskd_child_process_close(&system->action_process);
    system->action_spawned = false;
    system->action_capture_stdout = false;
    return -1;
}

static int system_action_spec(const char *const *argv, struct asteriskd_process_spec *spec) {
    if (argv == NULL || argv[0] == NULL || argv[0][0] != '/' || spec == NULL) return -1;
    memset(spec, 0, sizeof(*spec));
    int executable_length = snprintf(
        spec->executable_path, sizeof(spec->executable_path), "%s", argv[0]);
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

static int system_action_run_argv(struct asteriskd_system_supervisor *system,
    const char *const *argv, bool capture_stdout, int *exit_status) {
    struct asteriskd_process_spec spec;
    memset(&spec, 0, sizeof(spec));
    if (system_action_spec(argv, &spec) != 0) return -1;
    int result = system_action_run_spec(system, &spec, capture_stdout, exit_status);
    asteriskd_process_spec_destroy(&spec);
    return result;
}

#define SYSTEM_RULE_BATCH_MAX_BYTES (8U * 1024U * 1024U)

static void system_text_batch_destroy(struct system_text_batch *batch) {
    if (batch == NULL) return;
    free(batch->bytes);
    memset(batch, 0, sizeof(*batch));
}

static int system_text_batch_append(
    struct system_text_batch *batch, const void *bytes, size_t length) {
    if (batch == NULL || (length != 0U && bytes == NULL) ||
        length > SYSTEM_RULE_BATCH_MAX_BYTES - batch->length) return -1;
    size_t required = batch->length + length;
    if (required > batch->capacity) {
        size_t capacity = batch->capacity == 0U ? 4096U : batch->capacity;
        while (capacity < required) {
            if (capacity > SYSTEM_RULE_BATCH_MAX_BYTES / 2U) {
                capacity = SYSTEM_RULE_BATCH_MAX_BYTES;
                break;
            }
            capacity *= 2U;
        }
        unsigned char *resized = realloc(batch->bytes, capacity);
        if (resized == NULL) return -1;
        batch->bytes = resized;
        batch->capacity = capacity;
    }
    if (length != 0U) memcpy(batch->bytes + batch->length, bytes, length);
    batch->length = required;
    return 0;
}

static int system_text_batch_append_byte(
    struct system_text_batch *batch, unsigned char byte) {
    return system_text_batch_append(batch, &byte, 1U);
}

static int system_rule_batch_append_shell_argument(
    struct system_text_batch *batch, const char *argument) {
    if (argument == NULL || argument[0] == '\0' ||
        system_text_batch_append_byte(batch, '\'') != 0) return -1;
    for (size_t index = 0U; argument[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)argument[index];
        if (byte == '\n' || byte == '\r' || byte == '\0') return -1;
        if (byte == '\'') {
            static const char escaped[] = "'\\''";
            if (system_text_batch_append(
                    batch, escaped, sizeof(escaped) - 1U) != 0) return -1;
        } else if (system_text_batch_append_byte(batch, byte) != 0) {
            return -1;
        }
    }
    return system_text_batch_append_byte(batch, '\'');
}

static int system_rule_batch_append_shell_command(
    struct system_text_batch *batch, const char *const *argv) {
    if (batch == NULL || argv == NULL || argv[0] == NULL) return -1;
    for (size_t index = 0U; argv[index] != NULL; ++index) {
        if (index != 0U && system_text_batch_append_byte(batch, ' ') != 0) return -1;
        if (system_rule_batch_append_shell_argument(batch, argv[index]) != 0) return -1;
    }
    return system_text_batch_append_byte(batch, '\n');
}

static int system_rule_batch_append_ip_command(
    struct system_text_batch *batch,
    const char *const *arguments, size_t argument_count) {
    if (batch == NULL || arguments == NULL || argument_count == 0U) return -1;
    for (size_t index = 0U; index < argument_count; ++index) {
        const char *argument = arguments[index];
        if (argument == NULL || argument[0] == '\0') return -1;
        if (index != 0U && system_text_batch_append_byte(batch, ' ') != 0) return -1;
        for (size_t byte_index = 0U; argument[byte_index] != '\0'; ++byte_index) {
            unsigned char byte = (unsigned char)argument[byte_index];
            if (byte <= 0x20U || byte >= 0x7fU ||
                system_text_batch_append_byte(batch, byte) != 0) return -1;
        }
    }
    return system_text_batch_append_byte(batch, '\n');
}

static void system_rule_batch_destroy(struct system_rule_command_batch *batch) {
    if (batch == NULL) return;
    system_text_batch_destroy(&batch->xtables);
    for (size_t index = 0U; index < ASTERISKD_IP_FAMILY_COUNT; ++index) {
        system_text_batch_destroy(&batch->ip[index]);
    }
    batch->active = false;
}

static int system_rule_batch_begin(struct system_rule_command_batch *batch) {
    static const char header[] = "set -eu\n";
    if (batch == NULL || batch->active) return -1;
    system_rule_batch_destroy(batch);
    batch->active = true;
    if (system_text_batch_append(
            &batch->xtables, header, sizeof(header) - 1U) == 0) return 0;
    system_rule_batch_destroy(batch);
    return -1;
}

static int system_action_run_document(
    struct asteriskd_system_supervisor *system,
    const char *const *argv,
    const struct system_text_batch *batch,
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
        result = system_action_run_spec(system, &spec, false, exit_status);
    }
    asteriskd_process_spec_destroy(&spec);
    if (asteriskd_anonymous_file_close(backend, &file) != 0) result = -1;
    return result;
}

static int system_rule_batch_reset_xtables(
    struct system_rule_command_batch *batch) {
    static const char header[] = "set -eu\n";
    system_text_batch_destroy(&batch->xtables);
    return system_text_batch_append(
        &batch->xtables, header, sizeof(header) - 1U);
}

static int system_rule_batch_flush_xtables(
    struct asteriskd_system_supervisor *system) {
    struct system_rule_command_batch *batch = &system->rule_commands;
    static const size_t header_length = sizeof("set -eu\n") - 1U;
    if (!batch->active || batch->xtables.length < header_length) return -1;
    if (batch->xtables.length == header_length) return 0;
    const char *argv[] = {"/system/bin/sh", "/proc/self/fd/3", NULL};
    int exit_status = -1;
    int result = system_action_run_document(
        system, argv, &batch->xtables, &exit_status);
    if (result != 0 || exit_status != 0) return -1;
    return system_rule_batch_reset_xtables(batch);
}

static int system_rule_batch_flush_ip(
    struct asteriskd_system_supervisor *system) {
    struct system_rule_command_batch *batch = &system->rule_commands;
    if (!batch->active) return -1;
    for (size_t index = 0U; index < ASTERISKD_IP_FAMILY_COUNT; ++index) {
        struct system_text_batch *commands = &batch->ip[index];
        if (commands->length == 0U) continue;
        const char *argv[] = {
            "/system/bin/ip",
            index == ASTERISKD_IP_FAMILY_IPV4 ? "-4" : "-6",
            "-batch",
            "/proc/self/fd/3",
            NULL,
        };
        int exit_status = -1;
        if (system_action_run_document(
                system, argv, commands, &exit_status) != 0 ||
            exit_status != 0) return -1;
        system_text_batch_destroy(commands);
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
            if (written > 0 && (size_t)written < capacity && lstat(path, &status) == 0 &&
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
    if (lstat(path, &status) != 0) {
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
    if (system_action_run_argv(system, argv, false, exit_status) != 0) {
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "capability command failed");
        }
        return -1;
    }
    return 0;
}

static int system_effect_capability(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_platform_capability_backend backend = {
        .context = system,
        .find_on_path = system_capability_find,
        .inspect_executable = system_capability_inspect,
        .execute = system_capability_execute,
    };
    struct asteriskd_platform_capability_result result;
    char error[256U];
    return asteriskd_platform_capability_ensure(
        &system->loaded_config.config, &backend, &result, error, sizeof(error));
}

static const char *system_xtables_path(enum asteriskd_ip_family family) {
    return family == ASTERISKD_IP_FAMILY_IPV4
        ? "/system/bin/iptables" : family == ASTERISKD_IP_FAMILY_IPV6
            ? "/system/bin/ip6tables" : NULL;
}

static const char *system_table_name(enum asteriskd_ip_table table) {
    static const char *const names[] = {"filter", "nat", "mangle"};
    return table >= ASTERISKD_IP_TABLE_FILTER && table < ASTERISKD_IP_TABLE_COUNT
        ? names[table] : NULL;
}

static const char *system_builtin_name(enum asteriskd_builtin_chain chain) {
    static const char *const names[] = {"PREROUTING", "INPUT", "FORWARD", "OUTPUT"};
    return chain >= ASTERISKD_BUILTIN_PREROUTING && chain < ASTERISKD_BUILTIN_COUNT
        ? names[chain] : NULL;
}

static int system_xtables_run(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, bool capture_stdout, int *exit_status) {
    const char *executable = system_xtables_path(family);
    const char *table_name = system_table_name(table);
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
    return system_action_run_argv(system, argv, capture_stdout, exit_status);
}

static int system_xtables(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, int *exit_status) {
    return system_xtables_run(system, family, table, operation, chain,
        arguments, argument_count, false, exit_status);
}

static int system_xtables_table(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    enum asteriskd_ip_table table,
    int *exit_status) {
    const char *executable = system_xtables_path(family);
    const char *table_name = system_table_name(table);
    if (executable == NULL || table_name == NULL || exit_status == NULL) return -1;
    const char *argv[] = {
        executable, "-w", "100", "-t", table_name, "-S", NULL,
    };
    return system_action_run_argv(system, argv, true, exit_status);
}

static int system_xtables_zero(struct asteriskd_system_supervisor *system,
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
        const char *executable = system_xtables_path(family);
        const char *table_name = system_table_name(table);
        if (system->verify_private_rules || executable == NULL || table_name == NULL ||
            argument_count > 24U || (argument_count != 0U && arguments == NULL)) return -1;
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
        return system_rule_batch_append_shell_command(
            &system->rule_commands.xtables, argv);
    }
    int exit_status = -1;
    int run_result = system_xtables(system, family, table, effective_operation, chain,
        arguments, argument_count, &exit_status);
    int result = run_result == 0 && exit_status == 0 ? 0 : -1;
    if (result != 0) {
        char message[256U];
        int written = snprintf(message, sizeof(message),
            "xtables command failed: family=%d table=%d operation=%s chain=%s runner=%d exit=%d",
            (int)family, (int)table, effective_operation, chain, run_result, exit_status);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
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
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
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
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 4U);
}

static int system_append_return_interface(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool input, const char *name) {
    const char *arguments[] = {input ? "-i" : "-o", name, "-j", "RETURN"};
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 4U);
}

static int system_append_uid_return(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, uint32_t uid) {
    char uid_text[16U];
    if (snprintf(uid_text, sizeof(uid_text), "%" PRIu32, uid) <= 0) return -1;
    const char *arguments[] = {"-m", "owner", "--uid-owner", uid_text, "-j", "RETURN"};
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 6U);
}

static int system_append_gid_return(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    const char *arguments[] = {"-m", "owner", "--gid-owner", "3005", "-j", "RETURN"};
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, 6U);
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
    arguments[count++] = "0x20000000/0x60000000";
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
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
        arguments[count++] = "0x20000000/0x60000000";
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
    arguments[count++] = "0x20000000/0x60000000";
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, count);
}

static int system_append_dns_mark(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain, bool bypass_core_gid) {
    const char *plain[] = {"-p", "udp", "-m", "udp", "--dport", "53",
        "-j", "MARK", "--set-xmark", "0x20000000/0x60000000"};
    const char *bypass[] = {"-p", "udp", "-m", "owner", "!", "--gid-owner", "3005",
        "-m", "udp", "--dport", "53", "-j", "MARK", "--set-xmark",
        "0x20000000/0x60000000"};
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, bypass_core_gid ? bypass : plain,
        bypass_core_gid ? sizeof(bypass) / sizeof(bypass[0]) :
            sizeof(plain) / sizeof(plain[0]));
}

static int system_append_dns_tproxy(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    char port[8U];
    if (snprintf(port, sizeof(port), "%u",
            (unsigned)system->loaded_config.config.transparent_port) <= 0) return -1;
    const char *arguments[] = {"-p", "udp", "-m", "udp", "--dport", "53",
        "-j", "TPROXY", "--on-port", port, "--on-ip",
        family == ASTERISKD_IP_FAMILY_IPV4 ? "0.0.0.0" : "::",
        "--tproxy-mark", "0x20000000/0x60000000"};
    return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
        "-A", chain, arguments, sizeof(arguments) / sizeof(arguments[0]));
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
    } else if (system_collect_local_address_set(system, address_family, &live) == 0) {
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
        if (system_append_gid_return(system, family, chain) != 0) return -1;
        enum asteriskd_pin_id pin = family == ASTERISKD_IP_FAMILY_IPV4
            ? ASTERISKD_PIN_MATCHER_OUTPUT_V4 : ASTERISKD_PIN_MATCHER_OUTPUT_V6;
        const char *path = system_pin_path(system, pin);
        return path != NULL &&
            system_append_mark(system, family, chain, "tcp", NULL, NULL, NULL, path) == 0 &&
            system_append_mark(system, family, chain, "udp", NULL, NULL, NULL, path) == 0 ? 0 : -1;
    }
    if (system_append_gid_return(system, family, chain) != 0) return -1;
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

static int system_populate_common_output_prefix(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    for (size_t remaining = config->bypass_uid_count; remaining > 0U; --remaining) {
        if (system_append_uid_return(system, family, chain,
                config->bypass_uids[remaining - 1U]) != 0) return -1;
    }
    if (config->enable_local_dns && system_append_dns_mark(system, family, chain, true) != 0) {
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
    if (config->enable_local_dns && system_append_dns_tproxy(system, family, chain) != 0) return -1;
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
        matcher_path = system_pin_path(system, family == ASTERISKD_IP_FAMILY_IPV4
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

static int system_populate_tproxy_output(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end, bool dummy) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (system_populate_common_output_prefix(
            system, family, chain, local_begin, local_end) != 0) return -1;
    if (!config->matcher.enabled && config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST) {
        for (size_t remaining = config->uid_count; remaining > 0U; --remaining) {
            if (system_append_uid_return(system, family, chain,
                    config->uids[remaining - 1U]) != 0) return -1;
        }
    }
    if (dummy && system_append_return_interface(system, family, chain, false, "xdummy") != 0) {
        return -1;
    }
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (system_append_return_interface(system, family, chain, false,
                config->ignored_interfaces[index]) != 0) return -1;
    }
    return system_append_policy_output(system, family, chain);
}

static int system_populate_tun_prerouting(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    if (config->enable_local_dns && system_append_dns_mark(system, family, chain, false) != 0) {
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
    const char *matcher_path = NULL;
    if (config->matcher.enabled) {
        matcher_path = system_pin_path(system, family == ASTERISKD_IP_FAMILY_IPV4
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

static int system_populate_tun_output(
    struct asteriskd_system_supervisor *system, enum asteriskd_ip_family family,
    const char *chain, const char *local_begin, const char *local_end) {
    const struct asteriskd_config *config = &system->loaded_config.config;
    const char *tunnel = config->mode == ASTERISKD_MODE_TUN
        ? config->tunnel_name : config->helper.value.hev.tunnel_name;
    if (system_populate_common_output_prefix(
            system, family, chain, local_begin, local_end) != 0) return -1;
    if (!config->matcher.enabled && config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST) {
        for (size_t remaining = config->uid_count; remaining > 0U; --remaining) {
            if (system_append_uid_return(system, family, chain,
                    config->uids[remaining - 1U]) != 0) return -1;
        }
    }
    if (system_append_return_interface(system, family, chain, false, tunnel) != 0) return -1;
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (system_append_return_interface(system, family, chain, false,
                config->ignored_interfaces[index]) != 0) return -1;
    }
    return system_append_policy_output(system, family, chain);
}

static int system_populate_dummy_chain(struct asteriskd_system_supervisor *system,
    const char *chain) {
    if (strcmp(chain, "ASTERISK_TPROXY6_DUMMY_PRE") == 0) {
        char port[8U];
        if (snprintf(port, sizeof(port), "%u",
                (unsigned)system->loaded_config.config.transparent_port) <= 0) return -1;
        const char *tcp[] = {"-i", "xdummy", "-p", "tcp", "-j", "TPROXY",
            "--on-ip", "::", "--on-port", port, "--tproxy-mark",
            "0x40000000/0x60000000"};
        const char *udp[] = {"-i", "xdummy", "-p", "udp", "-j", "TPROXY",
            "--on-ip", "::", "--on-port", port, "--tproxy-mark",
            "0x40000000/0x60000000"};
        return system_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV6,
            ASTERISKD_IP_TABLE_MANGLE, "-A", chain, tcp,
            sizeof(tcp) / sizeof(tcp[0])) == 0 &&
            system_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV6,
                ASTERISKD_IP_TABLE_MANGLE, "-A", chain, udp,
                sizeof(udp) / sizeof(udp[0])) == 0 ? 0 : -1;
    }
    if (strcmp(chain, "ASTERISK_TPROXY6_DUMMY") == 0) {
        const char *tcp[] = {"-p", "tcp", "-j", "MARK", "--set-xmark",
            "0x40000000/0x60000000"};
        const char *udp[] = {"-p", "udp", "-j", "MARK", "--set-xmark",
            "0x40000000/0x60000000"};
        return system_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV6,
            ASTERISKD_IP_TABLE_MANGLE, "-A", chain, tcp,
            sizeof(tcp) / sizeof(tcp[0])) == 0 &&
            system_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV6,
                ASTERISKD_IP_TABLE_MANGLE, "-A", chain, udp,
                sizeof(udp) / sizeof(udp[0])) == 0 ? 0 : -1;
    }
    return -1;
}

static int system_populate_private_chain(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group, const char *chain) {
    enum asteriskd_ip_family family = group->family;
    const char *local_begin = family == ASTERISKD_IP_FAMILY_IPV4
        ? "ASTERISKD_LOCAL4_BEGIN" : "ASTERISKD_LOCAL6_BEGIN";
    const char *local_end = family == ASTERISKD_IP_FAMILY_IPV4
        ? "ASTERISKD_LOCAL4_END" : "ASTERISKD_LOCAL6_END";
    if (group->chain_id == ASTERISKD_CHAIN_LOCAL_BYPASS) {
        return 0;
    }
    if (group->chain_id == ASTERISKD_CHAIN_TPROXY) {
        if (strstr(chain, "DUMMY") != NULL) return system_populate_dummy_chain(system, chain);
        if (strstr(chain, "PREROUTING") != NULL) {
            return system_populate_tproxy_prerouting(
                system, family, chain, local_begin, local_end);
        }
        if (strstr(chain, "OUTPUT") != NULL) {
            return system_populate_tproxy_output(system, family, chain,
                local_begin, local_end, !system->has_global_ipv6_address &&
                    family == ASTERISKD_IP_FAMILY_IPV6);
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
            const char *tunnel = config->mode == ASTERISKD_MODE_TUN
                ? config->tunnel_name : config->helper.value.hev.tunnel_name;
            const char *input[] = {"-i", tunnel, "-j", "ACCEPT"};
            const char *output[] = {"-o", tunnel, "-j", "ACCEPT"};
            return system_xtables_zero(system, family, ASTERISKD_IP_TABLE_FILTER,
                "-A", chain, input, 4U) == 0 &&
                system_xtables_zero(system, family, ASTERISKD_IP_TABLE_FILTER,
                    "-A", chain, output, 4U) == 0 ? 0 : -1;
        }
        return -1;
    }
    if (group->chain_id == ASTERISKD_CHAIN_FAKE_DNS) {
        const char *pool = system->loaded_config.config.fake_dns_ipv4_pool;
        const char *arguments[] = {"-d", pool, "-p", "icmp", "--icmp-type",
            "echo-request", "-j", "REDIRECT"};
        return system_xtables_zero(system, ASTERISKD_IP_FAMILY_IPV4,
            ASTERISKD_IP_TABLE_NAT, "-A", chain, arguments,
            sizeof(arguments) / sizeof(arguments[0]));
    }
    return -1;
}

static int system_create_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group) {
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (system_xtables_zero(system, group->family, group->table,
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
        if (system_xtables_run(system, group->family, group->table,
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

static int system_verify_private_group_contents(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group) {
    for (size_t index = 0U; index < group->name_count; ++index) {
        if (system_verify_private_chain_contents(
                system, group, group->names[index]) != 0) return -1;
    }
    return 0;
}

static int system_remove_private_group(struct asteriskd_system_supervisor *system,
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
            if (system_xtables(system, group->family, group->table,
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
        if (system_xtables_zero(system, group->family, group->table,
                "-F", name, NULL, 0U) != 0 ||
            system_xtables_zero(system, group->family, group->table,
                "-X", name, NULL, 0U) != 0) result = -1;
    }
    return result;
}

static int system_apply_hook_group(struct asteriskd_system_supervisor *system,
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
            if (system_xtables_zero(system, group->family, group->table,
                    "-I", chain, insert, count + 1U) != 0) return -1;
        } else if (system_xtables_zero(system, group->family, group->table,
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
        if (system_xtables_run(system, group->family, group->table,
                "-S", chain, NULL, 0U, true, &exit_status) != 0 ||
            exit_status != 0 || system->action_stdout_overflow) return -1;
        observed = system->action_stdout;
        observed_length = system->action_stdout_length;
    }
    return asteriskd_xtables_rule_output_locate(
        observed, observed_length,
        chain, arguments, count, matches, position);
}

static int system_probe_hook_group(struct asteriskd_system_supervisor *system,
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

static int system_remove_hook_group(struct asteriskd_system_supervisor *system,
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
            if (system_xtables_zero(system, group->family, group->table,
                    "-D", chain, arguments, count) != 0) result = -1;
        }
    }
    return result;
}

static const struct asteriskd_private_chain_group *system_find_private_group(
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

static const struct asteriskd_traffic_hook_group *system_find_hook_group(
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

static int system_probe_private_group(struct asteriskd_system_supervisor *system,
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
        if (system_xtables(system, group->family, group->table, "-S",
                group->names[index], NULL, 0U, &exit_status) != 0 ||
            (exit_status != 0 && exit_status != 1)) return -1;
        if (exit_status == 0) *any_present = true;
        else *all_present = false;
    }
    return 0;
}

static int system_ip_command(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments,
    size_t argument_count, bool capture, int *exit_status) {
    if (argument_count > 20U || (argument_count != 0U && arguments == NULL) ||
        exit_status == NULL) return -1;
    const char *argv[24U];
    size_t count = 0U;
    argv[count++] = "/system/bin/ip";
    argv[count++] = family == ASTERISKD_IP_FAMILY_IPV4 ? "-4" : "-6";
    for (size_t index = 0U; index < argument_count; ++index) {
        if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
        argv[count++] = arguments[index];
    }
    argv[count] = NULL;
    return system_action_run_argv(system, argv, capture, exit_status);
}

static int system_ip_zero(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments, size_t argument_count) {
    if (system->rule_commands.active) {
        if (family < ASTERISKD_IP_FAMILY_IPV4 ||
            family >= ASTERISKD_IP_FAMILY_COUNT) return -1;
        return system_rule_batch_append_ip_command(
            &system->rule_commands.ip[family], arguments, argument_count);
    }
    int exit_status = -1;
    return system_ip_command(system, family, arguments, argument_count,
        false, &exit_status) == 0 && exit_status == 0 ? 0 : -1;
}

static void system_rule_view_destroy(struct system_rule_view *view) {
    if (view == NULL) return;
    free(view->bytes);
    memset(view, 0, sizeof(*view));
}

static void system_rule_snapshot_destroy(struct system_rule_snapshot *snapshot) {
    if (snapshot == NULL) return;
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            system_rule_view_destroy(&snapshot->xtables[family][table]);
        }
        system_rule_view_destroy(&snapshot->ip_rules[family]);
        system_rule_view_destroy(&snapshot->ip_routes[family]);
    }
    snapshot->phase = SYSTEM_RULE_SNAPSHOT_NONE;
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

static int system_rule_snapshot_capture(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_rule_transaction_plan *plan,
    enum system_rule_snapshot_phase phase) {
    if (system == NULL || plan == NULL ||
        (phase != SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY &&
         phase != SYSTEM_RULE_SNAPSHOT_AFTER_APPLY)) return -1;
    bool tables[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    bool rules[ASTERISKD_IP_FAMILY_COUNT];
    bool routes[ASTERISKD_IP_FAMILY_COUNT];
    memset(tables, 0, sizeof(tables));
    memset(rules, 0, sizeof(rules));
    memset(routes, 0, sizeof(routes));
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
        if (effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE) routes[effect->family] = true;
    }
    system_rule_snapshot_destroy(&system->rule_snapshot);
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            if (!tables[family][table]) continue;
            int exit_status = -1;
            if (system_xtables_table(system, (enum asteriskd_ip_family)family,
                    (enum asteriskd_ip_table)table, &exit_status) != 0 ||
                exit_status != 0 || system_rule_view_capture(system,
                    &system->rule_snapshot.xtables[family][table]) != 0) goto failed;
        }
        if (rules[family]) {
            const char *arguments[] = {"rule", "show"};
            int exit_status = -1;
            if (system_ip_command(system, (enum asteriskd_ip_family)family,
                    arguments, 2U, true, &exit_status) != 0 ||
                exit_status != 0 || system_rule_view_capture(system,
                    &system->rule_snapshot.ip_rules[family]) != 0) goto failed;
        }
        if (routes[family]) {
            const char *arguments[] = {"route", "show", "table", "all"};
            int exit_status = -1;
            if (system_ip_command(system, (enum asteriskd_ip_family)family,
                    arguments, 4U, true, &exit_status) != 0 ||
                exit_status != 0 || system_rule_view_capture(system,
                    &system->rule_snapshot.ip_routes[family]) != 0) goto failed;
        }
    }
    system->rule_snapshot.phase = phase;
    return 0;

failed:
    system_rule_snapshot_destroy(&system->rule_snapshot);
    return -1;
}

static int system_tc_command(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count, bool capture,
    int *exit_status) {
    if (arguments == NULL || argument_count == 0U || argument_count > 20U ||
        exit_status == NULL) return -1;
    const char *argv[22U];
    argv[0] = "/system/bin/tc";
    for (size_t index = 0U; index < argument_count; ++index) {
        if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
        argv[index + 1U] = arguments[index];
    }
    argv[argument_count + 1U] = NULL;
    return system_action_run_argv(system, argv, capture, exit_status);
}

static int system_tc_zero(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count) {
    int exit_status = -1;
    return system_tc_command(system, arguments, argument_count,
        false, &exit_status) == 0 && exit_status == 0 ? 0 : -1;
}

static void system_foreign_tc_netlink_close(struct asteriskd_system_supervisor *system) {
    if (system->foreign_tc_netlink_fd_owned && system->foreign_tc_netlink_fd >= 0) {
        (void)close(system->foreign_tc_netlink_fd);
    }
    system->foreign_tc_netlink_fd = -1;
    system->foreign_tc_netlink_port_id = 0U;
    system->foreign_tc_netlink_fd_owned = false;
    system->foreign_tc_netlink_active = false;
    system->foreign_tc_netlink_query = SYSTEM_TC_NETLINK_QUERY_NONE;
}

static int system_tc_netlink_begin(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    enum system_tc_netlink_query_kind query, void *request, size_t request_size,
    struct nlmsghdr *header) {
    if (system->foreign_tc_netlink_active || interface_index == 0U ||
        query == SYSTEM_TC_NETLINK_QUERY_NONE || request == NULL ||
        request_size < sizeof(*header) || header == NULL) return -1;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    struct sockaddr_nl assigned;
    socklen_t assigned_length = sizeof(assigned);
    memset(&assigned, 0, sizeof(assigned));
    if (getsockname(fd, (struct sockaddr *)&assigned, &assigned_length) != 0 ||
        assigned_length < (socklen_t)sizeof(assigned) || assigned.nl_family != AF_NETLINK ||
        assigned.nl_pid == 0U) {
        int saved = errno;
        (void)close(fd);
        errno = saved == 0 ? EINVAL : saved;
        return -1;
    }
    ++system->foreign_tc_netlink_sequence;
    if (system->foreign_tc_netlink_sequence == 0U) ++system->foreign_tc_netlink_sequence;
    header->nlmsg_seq = system->foreign_tc_netlink_sequence;
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    ssize_t sent;
    do {
        sent = sendto(fd, request, request_size, 0,
            (const struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)request_size) {
        int saved = errno;
        (void)close(fd);
        errno = saved;
        return -1;
    }
    system->foreign_tc_netlink_fd = fd;
    system->foreign_tc_netlink_port_id = assigned.nl_pid;
    system->foreign_tc_netlink_fd_owned = true;
    system->foreign_tc_netlink_active = true;
    system->foreign_tc_netlink_done = false;
    system->foreign_tc_netlink_failed = false;
    system->foreign_tc_netlink_present = false;
    system->foreign_tc_netlink_interface_index = interface_index;
    system->foreign_tc_netlink_query = query;
    memset(&system->foreign_tc_netlink_probe, 0, sizeof(system->foreign_tc_netlink_probe));
    system->tc_filter_netlink_state = ASTERISKD_RULES_SLOT_ABSENT;
    system->tc_qdisc_netlink_state = ASTERISKD_RULES_SLOT_ABSENT;
    return 0;
}

static int system_foreign_tc_netlink_start(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    uint32_t parent, uint32_t priority, uint32_t protocol,
    enum system_tc_netlink_query_kind query) {
    if (interface_index == 0U || parent == 0U ||
        priority == 0U || protocol == 0U ||
        (query != SYSTEM_TC_NETLINK_QUERY_FOREIGN_FILTER &&
         query != SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER &&
         query != SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER)) return -1;
    struct {
        struct nlmsghdr header;
        struct tcmsg message;
    } request;
    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETTFILTER;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.message.tcm_family = AF_UNSPEC;
    request.message.tcm_ifindex = (int)interface_index;
    request.message.tcm_parent = parent;
    request.message.tcm_info = TC_H_MAKE(priority << 16U, htons((uint16_t)protocol));
    return system_tc_netlink_begin(system, interface_index, query,
        &request, sizeof(request), &request.header);
}

static int system_tc_qdisc_netlink_start(
    struct asteriskd_system_supervisor *system, uint32_t interface_index) {
    struct {
        struct nlmsghdr header;
        struct tcmsg message;
    } request;
    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = RTM_GETQDISC;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.message.tcm_family = AF_UNSPEC;
    request.message.tcm_ifindex = (int)interface_index;
    return system_tc_netlink_begin(system, interface_index,
        SYSTEM_TC_NETLINK_QUERY_QDISC, &request, sizeof(request), &request.header);
}

static int system_foreign_tc_netlink_dispatch(
    struct asteriskd_system_supervisor *system, short ready) {
    if ((ready & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        char message[96U];
        int written = snprintf(message, sizeof(message),
            "hotspot netlink poll failed: revents=0x%x", (unsigned short)ready);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    unsigned char buffer[65536U];
    for (;;) {
        struct sockaddr_nl sender;
        memset(&sender, 0, sizeof(sender));
        struct iovec vector = {.iov_base = buffer, .iov_len = sizeof(buffer)};
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &vector;
        message.msg_iovlen = 1U;
        ssize_t received = recvmsg(system->foreign_tc_netlink_fd, &message, MSG_TRUNC);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (received <= 0 || (size_t)received > sizeof(buffer) ||
            (message.msg_flags & MSG_TRUNC) != 0 || sender.nl_pid != 0U) return -1;
        char error[128U] = {0};
        int decoded = system->foreign_tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_FOREIGN_FILTER
            ? asteriskd_foreign_tc_netlink_decode(
                buffer, (size_t)received, system->foreign_tc_netlink_sequence,
                system->foreign_tc_netlink_port_id,
                system->foreign_tc_netlink_interface_index,
                &system->foreign_tc_netlink_probe,
                &system->foreign_tc_netlink_present,
                &system->foreign_tc_netlink_done, error, sizeof(error))
            : system->foreign_tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER
                ? asteriskd_tc_filter_netlink_decode(
                    buffer, (size_t)received, system->foreign_tc_netlink_sequence,
                    system->foreign_tc_netlink_port_id,
                    &system->tc_filter_netlink_expectation,
                    &system->tc_filter_netlink_state,
                    &system->foreign_tc_netlink_done, error, sizeof(error))
                : system->foreign_tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER
                    ? asteriskd_tc_filter_slot_netlink_decode(
                        buffer, (size_t)received, system->foreign_tc_netlink_sequence,
                        system->foreign_tc_netlink_port_id,
                        &system->tc_filter_netlink_expectation,
                        &system->tc_filter_netlink_state,
                        &system->foreign_tc_netlink_done, error, sizeof(error))
                : system->foreign_tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_QDISC
                    ? asteriskd_tc_qdisc_netlink_decode(
                        buffer, (size_t)received, system->foreign_tc_netlink_sequence,
                        system->foreign_tc_netlink_port_id,
                        system->foreign_tc_netlink_interface_index,
                        &system->tc_qdisc_netlink_state,
                        &system->foreign_tc_netlink_done, error, sizeof(error))
                    : -1;
        if (decoded != 0) {
            struct nlmsghdr first;
            memset(&first, 0, sizeof(first));
            if ((size_t)received >= sizeof(first)) memcpy(&first, buffer, sizeof(first));
            int32_t kernel_error = 0;
            if (first.nlmsg_type == NLMSG_ERROR &&
                first.nlmsg_len >= NLMSG_HDRLEN + sizeof(kernel_error) &&
                (size_t)received >= NLMSG_HDRLEN + sizeof(kernel_error)) {
                memcpy(&kernel_error, buffer + NLMSG_HDRLEN, sizeof(kernel_error));
            }
            char message[256U];
            int written = snprintf(message, sizeof(message),
                "hotspot netlink decode failed: query=%u bytes=%zd type=%u flags=0x%x"
                " sequence=%" PRIu32 " pid=%" PRIu32 " kernelError=%" PRId32
                " detail=%s", (unsigned)system->foreign_tc_netlink_query, received,
                (unsigned)first.nlmsg_type, (unsigned)first.nlmsg_flags,
                first.nlmsg_seq, first.nlmsg_pid, kernel_error,
                error[0] == '\0' ? "unavailable" : error);
            if (written > 0 && (size_t)written < sizeof(message)) {
                (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                    ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
            }
            return -1;
        }
        if (system->foreign_tc_netlink_done) return 0;
    }
}

static bool system_foreign_tc_netlink_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    if (action_should_cancel(atomic_load_explicit(
            &system->runtime->lifecycle.stop_was_requested, memory_order_acquire),
            system->recovery_cancelled, system->cleanup_in_progress,
            system->recovery_only)) {
        system->foreign_tc_netlink_failed = true;
        system->foreign_tc_netlink_done = true;
    }
    return system->foreign_tc_netlink_done;
}

static int system_foreign_tc_netlink_probe(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    struct asteriskd_foreign_tc_probe *probe, bool *present) {
    if (probe == NULL || present == NULL ||
        system_foreign_tc_netlink_start(system, interface_index,
            ASTERISKD_TC_PARENT_CLSACT_INGRESS,
            ASTERISKD_ANDROID_TETHER_TC_PRIORITY, ASTERISKD_ETH_PROTOCOL_IPV6,
            SYSTEM_TC_NETLINK_QUERY_FOREIGN_FILTER) != 0) return -1;
    int64_t now = 0;
    int result = -1;
    if (system_runtime_clock(system, &now) == 0 &&
        now <= INT64_MAX -
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = now +
                (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
        };
        if (system_pump_condition(
                system, &deadline, system_foreign_tc_netlink_done) == 0 &&
            system->foreign_tc_netlink_done && !system->foreign_tc_netlink_failed) {
            *probe = system->foreign_tc_netlink_probe;
            *present = system->foreign_tc_netlink_present;
            result = 0;
        }
    }
    system_foreign_tc_netlink_close(system);
    return result;
}

static int system_expected_tc_netlink_probe(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state) {
    if (resource == NULL || state == NULL ||
        resource->ownership != ASTERISKD_TC_OWNERSHIP_DAEMON ||
        resource->interface_index == 0U) return -1;
    enum asteriskd_pin_id pin_id =
        resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS
            ? ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS
            : resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS
                ? ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS : ASTERISKD_PIN_COUNT;
    const struct asteriskd_bpf2_verified_pin *verified =
        system_bpf2_verified_pin(system, pin_id);
    const char *name = asteriskd_bpf2_tc_filter_attachment_name(resource->program_id);
    uint32_t parent = resource->direction == ASTERISKD_TC_DIRECTION_INGRESS
        ? ASTERISKD_TC_PARENT_CLSACT_INGRESS
        : resource->direction == ASTERISKD_TC_DIRECTION_EGRESS
            ? ASTERISKD_TC_PARENT_CLSACT_EGRESS : 0U;
    if (name == NULL || parent == 0U) return -1;
    memset(&system->tc_filter_netlink_expectation, 0,
        sizeof(system->tc_filter_netlink_expectation));
    system->tc_filter_netlink_expectation.interface_index = resource->interface_index;
    system->tc_filter_netlink_expectation.parent = parent;
    system->tc_filter_netlink_expectation.protocol = ASTERISKD_ETH_PROTOCOL_ALL;
    system->tc_filter_netlink_expectation.priority = ASTERISKD_HOTSPOT_TC_PRIORITY;
    system->tc_filter_netlink_expectation.handle = ASTERISKD_HOTSPOT_TC_HANDLE;
    enum system_tc_netlink_query_kind query = SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER;
    if (verified != NULL && verified->object_id != 0U) {
        query = SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER;
        system->tc_filter_netlink_expectation.bpf_flags = ASTERISKD_TC_BPF_FLAG_ACT_DIRECT;
        system->tc_filter_netlink_expectation.bpf_flags_gen_mask = UINT32_C(0x3);
        system->tc_filter_netlink_expectation.program_object_id = verified->object_id;
        (void)snprintf(system->tc_filter_netlink_expectation.bpf_name,
            sizeof(system->tc_filter_netlink_expectation.bpf_name), "%s", name);
        memcpy(system->tc_filter_netlink_expectation.program_tag, verified->tag,
            sizeof(system->tc_filter_netlink_expectation.program_tag));
    }
    if (system_foreign_tc_netlink_start(system, resource->interface_index,
            parent, ASTERISKD_HOTSPOT_TC_PRIORITY, ASTERISKD_ETH_PROTOCOL_ALL,
            query) != 0) return -1;
    int64_t now = 0;
    int result = -1;
    if (system_runtime_clock(system, &now) == 0 &&
        now <= INT64_MAX -
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = now +
                (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
        };
        if (system_pump_condition(
                system, &deadline, system_foreign_tc_netlink_done) == 0 &&
            system->foreign_tc_netlink_done && !system->foreign_tc_netlink_failed) {
            *state = system->tc_filter_netlink_state;
            result = 0;
        }
    }
    system_foreign_tc_netlink_close(system);
    memset(&system->tc_filter_netlink_expectation, 0,
        sizeof(system->tc_filter_netlink_expectation));
    return result;
}

static int system_qdisc_netlink_probe(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    enum asteriskd_rules_slot_state *state) {
    if (state == NULL || system_tc_qdisc_netlink_start(
            system, interface_index) != 0) return -1;
    int64_t now = 0;
    int result = -1;
    if (system_runtime_clock(system, &now) == 0 &&
        now <= INT64_MAX -
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = now +
                (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
        };
        if (system_pump_condition(
                system, &deadline, system_foreign_tc_netlink_done) == 0 &&
            system->foreign_tc_netlink_done && !system->foreign_tc_netlink_failed) {
            *state = system->tc_qdisc_netlink_state;
            result = 0;
        }
    }
    system_foreign_tc_netlink_close(system);
    return result;
}

static enum asteriskd_pin_id system_tc_pin_id(enum asteriskd_program_id program_id) {
    return program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS
        ? ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS
        : program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS
            ? ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS : ASTERISKD_PIN_COUNT;
}

static const char *system_tc_direction(enum asteriskd_tc_direction direction) {
    return direction == ASTERISKD_TC_DIRECTION_INGRESS ? "ingress" :
        direction == ASTERISKD_TC_DIRECTION_EGRESS ? "egress" : NULL;
}

static int system_read_sysfs_value(
    const char *interface_name, const char *leaf, char *output, size_t capacity) {
    if (interface_name == NULL || leaf == NULL || output == NULL || capacity < 2U ||
        strchr(interface_name, '/') != NULL || strchr(leaf, '/') != NULL) return -1;
    char path[ASTERISKD_MAX_PATH];
    int length = snprintf(path, sizeof(path), "/sys/class/net/%s/%s", interface_name, leaf);
    if (length <= 0 || (size_t)length >= sizeof(path)) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;
    ssize_t count;
    do {
        count = read(fd, output, capacity - 1U);
    } while (count < 0 && errno == EINTR);
    int saved = errno;
    int closed = close(fd);
    errno = saved;
    if (count <= 0 || (size_t)count >= capacity || closed != 0) return -1;
    output[count] = '\0';
    if (output[count - 1] == '\n') output[count - 1] = '\0';
    return output[0] == '\0' ? -1 : 0;
}

static int system_parse_decimal_u32(const char *value, uint32_t *output) {
    if (value == NULL || output == NULL || value[0] == '\0') return -1;
    uint32_t result = 0U;
    for (size_t index = 0U; value[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < '0' || byte > '9') return -1;
        uint32_t digit = (uint32_t)(byte - '0');
        if (result > (UINT32_MAX - digit) / 10U) return -1;
        result = result * 10U + digit;
    }
    if (result == 0U) return -1;
    *output = result;
    return 0;
}

static int system_interface_identity(
    const char *interface_name, uint32_t interface_index,
    struct asteriskd_foreign_tc_probe *probe) {
    if (probe == NULL || if_nametoindex(interface_name) != interface_index) return -1;
    char value[128U];
    uint32_t reported_index = 0U;
    if (system_read_sysfs_value(interface_name, "ifindex", value, sizeof(value)) != 0 ||
        system_parse_decimal_u32(value, &reported_index) != 0 ||
        reported_index != interface_index ||
        system_read_sysfs_value(interface_name, "iflink", value, sizeof(value)) != 0 ||
        system_parse_decimal_u32(value, &probe->interface_link_index) != 0 ||
        system_read_sysfs_value(interface_name, "type", value, sizeof(value)) != 0 ||
        system_parse_decimal_u32(value, &probe->interface_hardware_type) != 0 ||
        system_read_sysfs_value(interface_name, "address", value, sizeof(value)) != 0) return -1;
    size_t output = 0U;
    for (size_t index = 0U; value[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte == ':') continue;
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')) ||
            output + 1U >= sizeof(probe->interface_address)) return -1;
        probe->interface_address[output++] = (char)byte;
    }
    if (output == 0U || (output & 1U) != 0U) return -1;
    probe->interface_address[output] = '\0';
    probe->interface_index = interface_index;
    (void)snprintf(probe->interface_name, sizeof(probe->interface_name), "%s", interface_name);
    return if_nametoindex(interface_name) == interface_index ? 0 : -1;
}

static bool system_foreign_interface_matches(
    const struct asteriskd_tc_filter_resource *resource) {
    struct asteriskd_foreign_tc_probe probe;
    memset(&probe, 0, sizeof(probe));
    return system_interface_identity(
        resource->interface_name, resource->interface_index, &probe) == 0 &&
        probe.interface_link_index == resource->interface_link_index &&
        probe.interface_hardware_type == resource->interface_hardware_type &&
        strcmp(probe.interface_address, resource->interface_address) == 0;
}

static int system_tc_probe_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource, bool *present) {
    if (resource == NULL || present == NULL ||
        if_nametoindex(resource->interface_name) != resource->interface_index) return -1;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (system_qdisc_netlink_probe(system, resource->interface_index, &state) != 0 ||
        state == ASTERISKD_RULES_SLOT_FOREIGN) return -1;
    *present = state == ASTERISKD_RULES_SLOT_OWNED;
    return 0;
}

static int system_tc_probe_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state) {
    if (resource == NULL || state == NULL ||
        if_nametoindex(resource->interface_name) != resource->interface_index) return -1;
    return system_expected_tc_netlink_probe(system, resource, state);
}

static const struct asteriskd_recovery_record *system_find_recovery_record(
    const struct asteriskd_system_supervisor *system, uint64_t record_id) {
    for (size_t index = 0U; index < system->state.recovery.record_count; ++index) {
        if (system->state.recovery.records[index].record_id == record_id) {
            return &system->state.recovery.records[index];
        }
    }
    return NULL;
}

static bool system_foreign_tc_probe_matches(
    const struct asteriskd_foreign_tc_probe *probe,
    const struct asteriskd_tc_filter_resource *resource, uint64_t expected_object_id) {
    return probe->chain == resource->chain && probe->protocol == resource->protocol &&
        probe->priority == resource->priority && probe->handle == resource->handle &&
        strcmp(probe->bpf_name, resource->bpf_name) == 0 &&
        probe->bpf_flags == resource->bpf_flags &&
        probe->bpf_flags_gen == resource->bpf_flags_gen &&
        probe->program_object_id == expected_object_id &&
        probe->program_type == ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS &&
        strcmp(probe->program_tag, resource->program_tag) == 0 &&
        probe->direct_action && !probe->unknown_attributes;
}

static int system_tc_probe_foreign_filter(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource, uint64_t expected_object_id,
    enum asteriskd_rules_slot_state *state) {
    if (resource == NULL || state == NULL ||
        resource->ownership != ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT ||
        resource->direction != ASTERISKD_TC_DIRECTION_INGRESS ||
        !system_foreign_interface_matches(resource)) return -1;
    struct asteriskd_foreign_tc_probe probe;
    bool present = false;
    if (system_foreign_tc_netlink_probe(
            system, resource->interface_index, &probe, &present) != 0) return -1;
    if (!present) {
        *state = ASTERISKD_RULES_SLOT_ABSENT;
        return 0;
    }
    *state = expected_object_id != 0U &&
        system_foreign_tc_probe_matches(&probe, resource, expected_object_id)
            ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_FOREIGN;
    return 0;
}

static int system_tc_delete_foreign_filter(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource) {
    const struct asteriskd_recovery_record *pin =
        system_find_recovery_record(system, resource->recovery_pin_record_id);
    uint64_t object_id = pin == NULL ? 0U : pin->resource.bpf_pin.object_id;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (pin == NULL || pin->kind != ASTERISKD_RECOVERY_BPF_PIN ||
        pin->resource.bpf_pin.pin_id != ASTERISKD_PIN_HOTSPOT_RECOVERY ||
        !pin->resource.bpf_pin.has_object_id ||
        system_tc_probe_foreign_filter(system, resource, object_id, &state) != 0) return -1;
    if (state == ASTERISKD_RULES_SLOT_ABSENT) return 0;
    if (state != ASTERISKD_RULES_SLOT_OWNED) return -1;
    char handle[16U];
    if (snprintf(handle, sizeof(handle), "0x%" PRIx32, resource->handle) <= 0) return -1;
    const char *arguments[] = {"filter", "del", "dev", resource->interface_name,
        "ingress", "protocol", "ipv6", "pref", "2", "handle", handle, "bpf"};
    return system_tc_zero(system, arguments, 12U);
}

static int system_tc_restore_foreign_filter(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource) {
    const struct asteriskd_recovery_record *pin =
        system_find_recovery_record(system, resource->recovery_pin_record_id);
    char path_storage[ASTERISKD_MAX_PATH];
    const char *path = pin == NULL ? NULL : system_recovery_pin_path(
        system, pin, path_storage, sizeof(path_storage));
    if (pin == NULL || path == NULL || pin->kind != ASTERISKD_RECOVERY_BPF_PIN ||
        !pin->resource.bpf_pin.has_object_id ||
        if_nametoindex(resource->interface_name) != resource->interface_index) return -1;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (system_tc_probe_foreign_filter(
            system, resource, pin->resource.bpf_pin.object_id, &state) != 0) return -1;
    if (state == ASTERISKD_RULES_SLOT_OWNED) return 0;
    if (state != ASTERISKD_RULES_SLOT_ABSENT) return -1;
    char handle[16U];
    if (snprintf(handle, sizeof(handle), "0x%" PRIx32, resource->handle) <= 0) return -1;
    const char *arguments[18U];
    size_t count = 0U;
    arguments[count++] = "filter";
    arguments[count++] = "add";
    arguments[count++] = "dev";
    arguments[count++] = resource->interface_name;
    arguments[count++] = "ingress";
    arguments[count++] = "protocol";
    arguments[count++] = "ipv6";
    arguments[count++] = "pref";
    arguments[count++] = "2";
    arguments[count++] = "handle";
    arguments[count++] = handle;
    arguments[count++] = "bpf";
    arguments[count++] = "da";
    arguments[count++] = "pinned";
    arguments[count++] = path;
    if ((resource->bpf_flags_gen & 1U) != 0U) arguments[count++] = "skip_hw";
    if ((resource->bpf_flags_gen & 2U) != 0U) arguments[count++] = "skip_sw";
    return system_tc_zero(system, arguments, count);
}

static int system_tc_apply_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource) {
    const char *arguments[] = {"qdisc", "add", "dev", resource->interface_name, "clsact"};
    return system_tc_zero(system, arguments, 5U);
}

static int system_tc_apply_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource) {
    const char *direction = system_tc_direction(resource->direction);
    enum asteriskd_pin_id pin_id = system_tc_pin_id(resource->program_id);
    const char *path = pin_id == ASTERISKD_PIN_COUNT ? NULL : system_pin_path(system, pin_id);
    if (direction == NULL || path == NULL) return -1;
    const char *arguments[] = {"filter", "add", "dev", resource->interface_name,
        direction, "protocol", "all", "pref", "1", "handle", "1",
        "bpf", "da", "pinned", path};
    return system_tc_zero(system, arguments, 15U);
}

static int system_tc_remove_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource) {
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    int probed = system_tc_probe_filter(system, resource, &state);
    if (probed != 0 || state == ASTERISKD_RULES_SLOT_FOREIGN) {
        char message[192U];
        int written = snprintf(message, sizeof(message),
            "TC filter cleanup probe failed: direction=%u probe=%d state=%u",
            (unsigned)resource->direction, probed, (unsigned)state);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    if (state == ASTERISKD_RULES_SLOT_ABSENT) return 0;
    const char *direction = system_tc_direction(resource->direction);
    const char *arguments[] = {"filter", "del", "dev", resource->interface_name,
        direction, "pref", "1", "handle", "1", "bpf"};
    int exit_status = -1;
    int result = system_tc_command(system, arguments, 10U, false, &exit_status);
    if (result != 0 || exit_status != 0) {
        char message[192U];
        int written = snprintf(message, sizeof(message),
            "TC filter cleanup command failed: direction=%u result=%d exit=%d",
            (unsigned)resource->direction, result, exit_status);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    return 0;
}

static int system_tc_inspect_qdisc_cleanup(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource, bool *present,
    enum asteriskd_tc_qdisc_cleanup_decision *decision) {
    if (present == NULL || decision == NULL ||
        system_tc_probe_qdisc(system, resource, present) != 0) return -1;
    *decision = ASTERISKD_TC_QDISC_CLEANUP_DELETE;
    if (!*present) return 0;
    const char *ingress[] = {"filter", "show", "dev", resource->interface_name, "ingress"};
    const char *egress[] = {"filter", "show", "dev", resource->interface_name, "egress"};
    int exit_status = -1;
    if (system_tc_command(system, ingress, 5U, true, &exit_status) != 0 ||
        exit_status != 0) return -1;
    bool ingress_occupied = system->action_stdout_length != 0U;
    if (system_tc_command(system, egress, 5U, true, &exit_status) != 0 ||
        exit_status != 0) return -1;
    bool egress_occupied = system->action_stdout_length != 0U;
    *decision = asteriskd_tc_qdisc_cleanup_decide(ingress_occupied, egress_occupied);
    return 0;
}

static int system_tc_remove_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource) {
    bool present = false;
    enum asteriskd_tc_qdisc_cleanup_decision decision;
    if (system_tc_inspect_qdisc_cleanup(
            system, resource, &present, &decision) != 0) return -1;
    if (asteriskd_tc_qdisc_cleanup_restored(present, decision)) return 0;
    const char *arguments[] = {"qdisc", "del", "dev", resource->interface_name, "clsact"};
    return system_tc_zero(system, arguments, 5U);
}

static int system_apply_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect) {
    char table[16U];
    char priority[16U];
    char mark[32U];
    if (snprintf(table, sizeof(table), "%" PRIu32, effect->table) <= 0 ||
        snprintf(priority, sizeof(priority), "%" PRIu32, effect->priority) <= 0 ||
        snprintf(mark, sizeof(mark), "0x%08" PRIx32 "/0x%08" PRIx32,
            effect->mark, effect->mark_mask) <= 0) return -1;
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) {
        const char *normal[] = {"rule", "add", "priority", priority,
            "fwmark", mark, "table", table};
        const char *inverted[] = {"rule", "add", "priority", priority,
            "not", "from", "all", "fwmark", mark, "table", table};
        return system_ip_zero(system, effect->family,
            effect->invert_from_all ? inverted : normal,
            effect->invert_from_all ? sizeof(inverted) / sizeof(inverted[0]) :
                sizeof(normal) / sizeof(normal[0]));
    }
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE) {
        const char *normal[] = {"route", "add", effect->destination,
            "dev", effect->interface_name, "table", table};
        const char *local[] = {"route", "add", "local", effect->destination,
            "dev", effect->interface_name, "table", table};
        return system_ip_zero(system, effect->family,
            effect->local_route ? local : normal,
            effect->local_route ? sizeof(local) / sizeof(local[0]) :
                sizeof(normal) / sizeof(normal[0]));
    }
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE) {
        const char *link[] = {"link", "add", effect->interface_name, "type", "dummy"};
        const char *address[] = {"addr", "add", effect->interface_address,
            "dev", effect->interface_name};
        const char *up[] = {"link", "set", effect->interface_name, "up"};
        return system_ip_zero(system, effect->family, link, 5U) == 0 &&
            system_ip_zero(system, effect->family, address, 5U) == 0 &&
            system_ip_zero(system, effect->family, up, 4U) == 0 ? 0 : -1;
    }
    return -1;
}

static bool system_dummy_effect_matches(
    const struct asteriskd_route_effect *effect, uint32_t expected_index) {
    if (effect == NULL || effect->kind != ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE ||
        effect->family != ASTERISKD_IP_FAMILY_IPV6 || expected_index == 0U ||
        if_nametoindex(effect->interface_name) != expected_index) return false;
    const char *slash = strchr(effect->interface_address, '/');
    if (slash == NULL || strcmp(slash, "/128") != 0 ||
        (size_t)(slash - effect->interface_address) >= INET6_ADDRSTRLEN) return false;
    char address[INET6_ADDRSTRLEN];
    size_t address_length = (size_t)(slash - effect->interface_address);
    memcpy(address, effect->interface_address, address_length);
    address[address_length] = '\0';
    struct in6_addr expected;
    if (inet_pton(AF_INET6, address, &expected) != 1) return false;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return false;
    bool up = false;
    bool found = false;
    for (const struct ifaddrs *entry = interfaces; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_name == NULL || strcmp(entry->ifa_name, effect->interface_name) != 0) {
            continue;
        }
        if ((entry->ifa_flags & IFF_UP) != 0U) up = true;
        if (entry->ifa_addr != NULL && entry->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)entry->ifa_addr;
            if (memcmp(&ipv6->sin6_addr, &expected, sizeof(expected)) == 0) found = true;
        }
    }
    freeifaddrs(interfaces);
    return up && found;
}

static const struct asteriskd_recovery_record *system_dummy_recovery_record(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect) {
    if (system == NULL || effect == NULL ||
        effect->kind != ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE) return NULL;
    const struct asteriskd_recovery_record *match = NULL;
    for (size_t index = 0U; index < system->state.recovery.record_count; ++index) {
        const struct asteriskd_recovery_record *record =
            &system->state.recovery.records[index];
        if (record->kind != ASTERISKD_RECOVERY_DUMMY_INTERFACE ||
            record->resource.dummy_interface.interface_id != effect->interface_id) continue;
        if (match != NULL) return NULL;
        match = record;
    }
    return match;
}

static bool system_dummy_recovery_identity_matches(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect) {
    const struct asteriskd_recovery_record *record =
        system_dummy_recovery_record(system, effect);
    if (record == NULL || record->resource.dummy_interface.original_presence) return false;
    if (record->status == ASTERISKD_RECOVERY_INTENT) return true;
    return record->status == ASTERISKD_RECOVERY_APPLIED &&
        record->resource.dummy_interface.has_interface_index &&
        system_dummy_effect_matches(
            effect, record->resource.dummy_interface.interface_index);
}

static int system_probe_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect, bool *present);
static int system_classify_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state);

static int system_remove_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect) {
    bool present = false;
    if (system_probe_route_effect(system, effect, &present) != 0) return -1;
    if (!present) return 0;
    char table[16U];
    char priority[16U];
    char mark[32U];
    if (snprintf(table, sizeof(table), "%" PRIu32, effect->table) <= 0 ||
        snprintf(priority, sizeof(priority), "%" PRIu32, effect->priority) <= 0 ||
        snprintf(mark, sizeof(mark), "0x%08" PRIx32 "/0x%08" PRIx32,
            effect->mark, effect->mark_mask) <= 0) return -1;
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) {
        const char *normal[] = {"rule", "del", "priority", priority,
            "fwmark", mark, "table", table};
        const char *inverted[] = {"rule", "del", "priority", priority,
            "not", "from", "all", "fwmark", mark, "table", table};
        return system_ip_zero(system, effect->family,
            effect->invert_from_all ? inverted : normal,
            effect->invert_from_all ? sizeof(inverted) / sizeof(inverted[0]) :
                sizeof(normal) / sizeof(normal[0]));
    }
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE) {
        const char *normal[] = {"route", "del", effect->destination,
            "dev", effect->interface_name, "table", table};
        const char *local[] = {"route", "del", "local", effect->destination,
            "dev", effect->interface_name, "table", table};
        return system_ip_zero(system, effect->family,
            effect->local_route ? local : normal,
            effect->local_route ? sizeof(local) / sizeof(local[0]) :
                sizeof(normal) / sizeof(normal[0]));
    }
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE) {
        if (!system_dummy_recovery_identity_matches(system, effect)) return -1;
        const char *arguments[] = {"link", "del", effect->interface_name, "type", "dummy"};
        return system_ip_zero(system, effect->family, arguments, 5U);
    }
    return -1;
}

static int system_probe_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect, bool *present) {
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (present == NULL || system_classify_route_effect(system, effect, &state) != 0 ||
        state == ASTERISKD_RULES_SLOT_FOREIGN) return -1;
    *present = state == ASTERISKD_RULES_SLOT_OWNED;
    return 0;
}

static int system_classify_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state) {
    if (system == NULL || effect == NULL || state == NULL) return -1;
    *state = ASTERISKD_RULES_SLOT_ABSENT;
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE) {
        uint32_t interface_index = if_nametoindex(effect->interface_name);
        *state = interface_index == 0U ? ASTERISKD_RULES_SLOT_ABSENT :
            system_dummy_effect_matches(effect, interface_index)
                ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_FOREIGN;
        return 0;
    }
    if (system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY ||
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) {
        const struct system_rule_view *view =
            effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE
                ? &system->rule_snapshot.ip_rules[effect->family]
                : &system->rule_snapshot.ip_routes[effect->family];
        if (!view->present) return -1;
        return effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE
            ? asteriskd_ip_rule_output_classify(
                view->bytes, view->length, effect, state)
            : asteriskd_ip_route_output_classify(
                view->bytes, view->length, effect, state);
    }
    char table[16U];
    char priority[16U];
    if (snprintf(table, sizeof(table), "%" PRIu32, effect->table) <= 0 ||
        snprintf(priority, sizeof(priority), "%" PRIu32, effect->priority) <= 0) return -1;
    int exit_status = -1;
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) {
        const char *arguments[] = {"rule", "show", "priority", priority};
        if (system_ip_command(system, effect->family, arguments, 4U,
                true, &exit_status) != 0 || exit_status != 0 ||
            system->action_stdout_overflow) return -1;
        return asteriskd_ip_rule_output_classify(
            system->action_stdout, system->action_stdout_length, effect, state);
    }
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE) {
        const char *arguments[] = {"route", "show", "table", table, effect->destination};
        if (system_ip_command(system, effect->family, arguments, 5U,
                true, &exit_status) != 0 || exit_status != 0 ||
            system->action_stdout_overflow) return -1;
        return asteriskd_ip_route_output_classify(
            system->action_stdout, system->action_stdout_length, effect, state);
    }
    return -1;
}

static const struct asteriskd_route_effect *system_find_route_effect(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *record) {
    for (size_t index = 0U; index < system->rules_runtime.plan.route_count; ++index) {
        const struct asteriskd_route_effect *effect = &system->rules_runtime.plan.routes[index];
        if (record->kind == ASTERISKD_RECOVERY_IP_RULE &&
            effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE &&
            effect->family == record->resource.ip_rule.family &&
            effect->ip_rule_id == record->resource.ip_rule.rule_id) return effect;
        if (record->kind == ASTERISKD_RECOVERY_ROUTE &&
            effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE &&
            effect->family == record->resource.route.family &&
            effect->route_id == record->resource.route.route_id) return effect;
        if (record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE &&
            effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE &&
            effect->interface_id == record->resource.dummy_interface.interface_id) return effect;
    }
    return NULL;
}

static int system_route_record(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect, struct asteriskd_recovery_record *record) {
    (void)system;
    memset(record, 0, sizeof(*record));
    record->status = ASTERISKD_RECOVERY_INTENT;
    if (effect->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE) {
        record->kind = ASTERISKD_RECOVERY_IP_RULE;
        record->resource.ip_rule.family = effect->family;
        record->resource.ip_rule.rule_id = effect->ip_rule_id;
    } else if (effect->kind == ASTERISKD_ROUTE_EFFECT_ROUTE) {
        record->kind = ASTERISKD_RECOVERY_ROUTE;
        record->resource.route.family = effect->family;
        record->resource.route.route_id = effect->route_id;
        if (snprintf(record->resource.route.interface_name,
                sizeof(record->resource.route.interface_name), "%s",
                effect->interface_name) <= 0) return -1;
        record->resource.route.interface_index = if_nametoindex(effect->interface_name);
        if (record->resource.route.interface_index == 0U) return -1;
    } else if (effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE) {
        record->kind = ASTERISKD_RECOVERY_DUMMY_INTERFACE;
        record->resource.dummy_interface.interface_id = effect->interface_id;
    } else {
        return -1;
    }
    return 0;
}

static const char *system_pin_path(
    struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id) {
    if (!system->matcher_plan_ready && system->loaded_config.config.matcher.enabled &&
        asteriskd_matcher_pin_plan_build(
            &system->loaded_config.config, &system->matcher_pin_plan) == 0) {
        system->matcher_plan_ready = true;
    }
    if (system->matcher_plan_ready) {
        for (size_t index = 0U; index < system->matcher_pin_plan.pin_count; ++index) {
            if (system->matcher_pin_plan.pins[index].pin_id == pin_id) {
                return system->matcher_pin_plan.pins[index].path;
            }
        }
    }
    if (!system->bpf2_plan_ready && system->loaded_config.config.mode == ASTERISKD_MODE_BPF2SOCKS &&
        asteriskd_bpf2_pin_plan_build(
            &system->loaded_config.config, &system->bpf2_pin_plan) == 0) {
        system->bpf2_plan_ready = true;
    }
    if (system->bpf2_plan_ready) {
        for (size_t index = 0U; index < system->bpf2_pin_plan.pin_count; ++index) {
            if (system->bpf2_pin_plan.pins[index].pin_id == pin_id) {
                return system->bpf2_pin_plan.pins[index].path;
            }
        }
    }
    return NULL;
}

static const char *system_recovery_pin_path(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *record,
    char *storage, size_t storage_size) {
    if (record == NULL || record->kind != ASTERISKD_RECOVERY_BPF_PIN) return NULL;
    if (record->resource.bpf_pin.pin_id != ASTERISKD_PIN_HOTSPOT_RECOVERY) {
        return system_pin_path(system, record->resource.bpf_pin.pin_id);
    }
    const char *owner = system->loaded_config.config.owner == ASTERISKD_OWNER_NG
        ? "asteriskng" : system->loaded_config.config.owner == ASTERISKD_OWNER_BOX
            ? "asteriskbox" : system->loaded_config.config.owner == ASTERISKD_OWNER_META
                ? "asteriskmeta" : NULL;
    if (owner == NULL || storage == NULL || storage_size == 0U || record->record_id == 0U ||
        snprintf(storage, storage_size, "/sys/fs/bpf/%s_hotspot_recovery_%" PRIu64,
            owner, record->record_id) <= 0 || strnlen(storage, storage_size) >= storage_size) {
        return NULL;
    }
    return storage;
}

static uint64_t system_recovery_pin_object_id(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *record) {
    char path_storage[ASTERISKD_MAX_PATH];
    const char *path = system_recovery_pin_path(
        system, record, path_storage, sizeof(path_storage));
    const struct asteriskd_bpf_program_backend *backend =
        asteriskd_system_bpf_program_backend();
    if (path == NULL || backend == NULL || backend->open_program == NULL ||
        backend->program_info == NULL || backend->close == NULL) return 0U;
    int fd = -1;
    struct asteriskd_bpf_program_info info;
    memset(&info, 0, sizeof(info));
    if (backend->open_program(backend->context, path, &fd) != 0 || fd < 0) return 0U;
    int inspected = backend->program_info(backend->context, fd, &info);
    int closed = backend->close(backend->context, fd);
    if (inspected != 0 || closed != 0 || info.object_id == 0U) return 0U;
    return info.object_id;
}

static uint64_t system_verified_pin_id(
    const struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id) {
    if (system->matcher_verified) {
        for (size_t index = 0U; index < system->matcher_verification.pin_count; ++index) {
            if (system->matcher_verification.pins[index].pin_id == pin_id) {
                return system->matcher_verification.pins[index].object_id;
            }
        }
    }
    if (system->bpf2_verified) {
        for (size_t index = 0U; index < system->bpf2_verification.pin_count; ++index) {
            if (system->bpf2_verification.pins[index].pin_id == pin_id) {
                return system->bpf2_verification.pins[index].object_id;
            }
        }
    }
    return 0U;
}

static const struct asteriskd_bpf2_verified_pin *system_bpf2_verified_pin(
    const struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id) {
    if (!system->bpf2_verified) return NULL;
    for (size_t index = 0U; index < system->bpf2_verification.pin_count; ++index) {
        if (system->bpf2_verification.pins[index].pin_id == pin_id) {
            return &system->bpf2_verification.pins[index];
        }
    }
    return NULL;
}

static int system_run_matcher_loader(struct asteriskd_system_supervisor *system) {
    int exit_status = -1;
    char error[256U];
    if (!system->matcher_launch_ready || !system->matcher_plan_ready ||
        system_action_run_spec(
            system, &system->matcher_launch.process, false, &exit_status) != 0 ||
        exit_status != 0 || asteriskd_matcher_verify(
            &system->loaded_config.config, &system->matcher_pin_plan,
            asteriskd_system_bpf_program_backend(), &system->matcher_verification,
            error, sizeof(error)) != 0) return -1;
    system->matcher_verified = true;
    return 0;
}

static bool system_bpf2_pins_ready(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    if (system->helper_reaped) return true;
    char error[128U];
    if (asteriskd_bpf2_verify(
            &system->loaded_config.config, &system->bpf2_pin_plan,
            asteriskd_system_bpf_program_backend(), &system->bpf2_verification,
            error, sizeof(error)) == 0) {
        system->bpf2_verified = true;
        return true;
    }
    return false;
}

static int system_start_and_verify_bpf2(struct asteriskd_system_supervisor *system) {
    if (system_start_helper_process(system, &system->helper_identity) != 0) return -1;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = now +
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
    };
    return system_pump_condition_periodic(system, &deadline,
            ASTERISKD_READINESS_POLL_INTERVAL_MILLIS, system_bpf2_pins_ready) == 0 &&
        system->bpf2_verified && !system->helper_reaped ? 0 : -1;
}

static int system_sysctl_open(
    const struct asteriskd_sysctl_resource *resource, int flags, int *output) {
    const char *root_path = resource->sysctl_id == ASTERISKD_SYSCTL_DISABLE_IPV6
        ? "/proc/sys/net/ipv6/conf" : "/proc/sys/net/ipv4/conf";
    const char *leaf = resource->sysctl_id == ASTERISKD_SYSCTL_DISABLE_IPV6
        ? "disable_ipv6" : "route_localnet";
    if (resource->interface_name[0] == '\0' || strchr(resource->interface_name, '/') != NULL ||
        strcmp(resource->interface_name, ".") == 0 ||
        strcmp(resource->interface_name, "..") == 0 || output == NULL) return -1;
    if (resource->interface_index != 0U &&
        if_nametoindex(resource->interface_name) != resource->interface_index) return 1;
    int root = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return errno == ENOENT || errno == ENODEV ? 1 : -1;
    int directory = openat(root, resource->interface_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    (void)close(root);
    if (directory < 0) {
        errno = saved;
        return errno == ENOENT || errno == ENODEV ? 1 : -1;
    }
    int fd = openat(directory, leaf, flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    saved = errno;
    (void)close(directory);
    if (fd < 0) {
        errno = saved;
        return errno == ENOENT || errno == ENODEV ? 1 : -1;
    }
    *output = fd;
    return 0;
}

static int system_sysctl_read(
    const struct asteriskd_sysctl_resource *resource, uint8_t *value) {
    int fd = -1;
    int opened = system_sysctl_open(resource, O_RDONLY, &fd);
    if (opened != 0) return opened;
    char bytes[3U] = {0, 0, 0};
    ssize_t count;
    do {
        count = pread(fd, bytes, sizeof(bytes), 0);
    } while (count < 0 && errno == EINTR);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    if (count < 1 || count > 2 || (bytes[0] != '0' && bytes[0] != '1') ||
        (count == 2 && bytes[1] != '\n')) return -1;
    *value = (uint8_t)(bytes[0] - '0');
    return 0;
}

static int system_sysctl_write(
    const struct asteriskd_sysctl_resource *resource, uint8_t value) {
    if (value > 1U) return -1;
    int fd = -1;
    int opened = system_sysctl_open(resource, O_WRONLY, &fd);
    if (opened != 0) return -1;
    char bytes[2U] = {(char)('0' + value), '\n'};
    ssize_t count;
    do {
        count = pwrite(fd, bytes, sizeof(bytes), 0);
    } while (count < 0 && errno == EINTR);
    int saved = errno;
    (void)close(fd);
    errno = saved;
    return count == (ssize_t)sizeof(bytes) ? 0 : -1;
}

static int system_wal_probe_original(void *opaque,
    const struct asteriskd_recovery_record *record,
    struct asteriskd_wal_original_delta *delta, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (record == NULL || delta == NULL) return -1;
    memset(delta, 0, sizeof(*delta));
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        uint8_t value = 0U;
        if (system_sysctl_read(&record->resource.sysctl, &value) != 0) return -1;
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_SYSCTL_VALUE;
        delta->original_value = value;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        char path_storage[ASTERISKD_MAX_PATH];
        const char *path = system_recovery_pin_path(
            system, record, path_storage, sizeof(path_storage));
        const struct asteriskd_bpf_pin_ownership_backend *backend =
            asteriskd_system_bpf_pin_ownership_backend();
        bool exists = true;
        uint64_t object_id = 0U;
        if (path == NULL || backend == NULL ||
            backend->probe(backend->context, path, &exists, &object_id) != 0 ||
            (exists && object_id == 0U) || (!exists && object_id != 0U)) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "cannot inspect BPF pin before mutation");
            }
            return -1;
        }
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = exists;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        bool present = false;
        if (system_tc_probe_qdisc(system, &record->resource.tc_qdisc, &present) != 0 ||
            present) return -1;
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = false;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER) {
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_DAEMON) {
            if (system_tc_probe_filter(system, &record->resource.tc_filter, &state) != 0 ||
                state != ASTERISKD_RULES_SLOT_ABSENT) return -1;
            delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
            delta->original_presence = false;
            return 0;
        }
        const struct asteriskd_recovery_record *pin = system_find_recovery_record(
            system, record->resource.tc_filter.recovery_pin_record_id);
        if (pin == NULL || pin->kind != ASTERISKD_RECOVERY_BPF_PIN ||
            !pin->resource.bpf_pin.has_object_id ||
            system_tc_probe_foreign_filter(system, &record->resource.tc_filter,
                pin->resource.bpf_pin.object_id, &state) != 0 ||
            state != ASTERISKD_RULES_SLOT_OWNED) return -1;
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = true;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &record->resource.iptables_chain);
        bool all_present = false;
        bool any_present = false;
        if (group == NULL || system_probe_private_group(
                system, group, &all_present, &any_present) != 0 ||
            any_present) return -1;
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = false;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &record->resource.iptables_rule);
        bool all_present = false;
        bool any_present = false;
        if (group == NULL || system_probe_hook_group(
                system, group, &all_present, &any_present) != 0 ||
            any_present) return -1;
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = false;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
        record->kind == ASTERISKD_RECOVERY_ROUTE ||
        record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, record);
        bool present = false;
        if (effect == NULL || system_probe_route_effect(system, effect, &present) != 0 || present) {
            return -1;
        }
        delta->kind = ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE;
        delta->original_presence = false;
        return 0;
    }
    return -1;
}

static bool system_rule_recovery_kind(enum asteriskd_recovery_kind kind) {
    return kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN ||
        kind == ASTERISKD_RECOVERY_IPTABLES_RULE ||
        kind == ASTERISKD_RECOVERY_IP_RULE ||
        kind == ASTERISKD_RECOVERY_ROUTE ||
        kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE;
}

static int system_wal_apply(void *opaque, const struct asteriskd_recovery_record *records,
    size_t count, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (records == NULL || count == 0U) return -1;
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_SYSCTL) {
        return system_sysctl_write(&records[0].resource.sysctl,
            records[0].resource.sysctl.desired_value);
    }
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_TC_QDISC) {
        return system_tc_apply_qdisc(system, &records[0].resource.tc_qdisc);
    }
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_TC_FILTER &&
        records[0].resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_DAEMON) {
        return system_tc_apply_filter(system, &records[0].resource.tc_filter);
    }
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_TC_FILTER &&
        records[0].resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT) {
        return system_tc_delete_foreign_filter(system, &records[0].resource.tc_filter);
    }
    bool rule_batch = system_rule_recovery_kind(records[0].kind);
    for (size_t index = 0U; rule_batch && index < count; ++index) {
        enum asteriskd_recovery_kind kind = records[index].kind;
        rule_batch = kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN ||
            kind == ASTERISKD_RECOVERY_IPTABLES_RULE ||
            kind == ASTERISKD_RECOVERY_IP_RULE ||
            kind == ASTERISKD_RECOVERY_ROUTE ||
            kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE;
    }
    if (rule_batch) {
        enum asteriskd_recovery_kind previous_kind = ASTERISKD_RECOVERY_KIND_COUNT;
        if (system_rule_batch_begin(&system->rule_commands) != 0) return -1;
        for (size_t index = 0U; index < count; ++index) {
            const struct asteriskd_recovery_record *record = &records[index];
            bool route = record->kind == ASTERISKD_RECOVERY_IP_RULE ||
                record->kind == ASTERISKD_RECOVERY_ROUTE ||
                record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE;
            bool previous_route = previous_kind == ASTERISKD_RECOVERY_IP_RULE ||
                previous_kind == ASTERISKD_RECOVERY_ROUTE ||
                previous_kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE;
            if (route && !previous_route &&
                system_rule_batch_flush_xtables(system) != 0) goto rule_batch_failed;
            if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE && previous_route &&
                system_rule_batch_flush_ip(system) != 0) goto rule_batch_failed;
            int result = -1;
            if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
                const struct asteriskd_private_chain_group *group =
                    system_find_private_group(system, &record->resource.iptables_chain);
                result = group == NULL ? -1 : system_create_private_group(system, group);
            } else if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
                const struct asteriskd_traffic_hook_group *group =
                    system_find_hook_group(system, &record->resource.iptables_rule);
                result = group == NULL ? -1 : system_apply_hook_group(system, group);
            } else if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
                record->kind == ASTERISKD_RECOVERY_ROUTE ||
                record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
                const struct asteriskd_route_effect *effect =
                    system_find_route_effect(system, record);
                result = effect == NULL ? -1 : system_apply_route_effect(system, effect);
            }
            if (result != 0) {
                if (error != NULL && error_size != 0U) {
                    (void)snprintf(error, error_size,
                        "rule WAL batch apply failed at index %zu", index);
                }
                goto rule_batch_failed;
            }
            previous_kind = record->kind;
        }
        if (previous_kind == ASTERISKD_RECOVERY_IP_RULE ||
            previous_kind == ASTERISKD_RECOVERY_ROUTE ||
            previous_kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
            if (system_rule_batch_flush_ip(system) != 0) goto rule_batch_failed;
        } else if (system_rule_batch_flush_xtables(system) != 0) {
            goto rule_batch_failed;
        }
        system_rule_batch_destroy(&system->rule_commands);
        system_rule_snapshot_destroy(&system->rule_snapshot);
        system->rule_snapshot.phase = SYSTEM_RULE_SNAPSHOT_NEEDS_VERIFY;
        return 0;
rule_batch_failed:
        system_rule_batch_destroy(&system->rule_commands);
        system_rule_snapshot_destroy(&system->rule_snapshot);
        return -1;
    }
    if (records[0].kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &records[0].resource.iptables_chain);
        if (group != NULL && system_create_private_group(system, group) == 0) return 0;
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "iptables private group creation failed");
        }
        return -1;
    }
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &records[0].resource.iptables_rule);
        if (group == NULL) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "iptables hook group is unknown");
            }
            return -1;
        }
        if (system_apply_hook_group(system, group) == 0) return 0;
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "iptables hook group apply failed");
        }
        return -1;
    }
    if (count == 1U && (records[0].kind == ASTERISKD_RECOVERY_IP_RULE ||
            records[0].kind == ASTERISKD_RECOVERY_ROUTE ||
            records[0].kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE)) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, &records[0]);
        return effect == NULL ? -1 : system_apply_route_effect(system, effect);
    }
    if (count == 1U && records[0].kind == ASTERISKD_RECOVERY_BPF_PIN &&
        records[0].resource.bpf_pin.pin_id == ASTERISKD_PIN_HOTSPOT_RECOVERY) {
        char path_storage[ASTERISKD_MAX_PATH];
        const char *path = system_recovery_pin_path(
            system, &records[0], path_storage, sizeof(path_storage));
        uint64_t object_id = 0U;
        if (!system->foreign_tc_pin_active || path == NULL ||
            asteriskd_foreign_tc_pin_clone(
                &system->foreign_tc_probe, system->foreign_tc_source_path, path,
                asteriskd_system_bpf_program_backend(), &object_id,
                error, error_size) != 0) return -1;
        system->foreign_tc_pinned_object_id = object_id;
        return 0;
    }
    for (size_t index = 0U; index < count; ++index) {
        if (records[index].kind != ASTERISKD_RECOVERY_BPF_PIN) return -1;
    }
    if (!system->pin_batch_active) return -1;
    bool matcher_batch = system->active_pin_batch == ASTERISKD_WAL_PIN_BATCH_MATCHER_IPV4 ||
        system->active_pin_batch == ASTERISKD_WAL_PIN_BATCH_MATCHER_DUAL_STACK;
    bool bpf2_batch = system->active_pin_batch == ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_IPV4 ||
        system->active_pin_batch == ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_DUAL_STACK;
    if ((!matcher_batch && !bpf2_batch) ||
        (matcher_batch ? system_run_matcher_loader(system) :
            system_start_and_verify_bpf2(system)) != 0) {
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s",
                matcher_batch ? "matcher loader or pin verification failed" :
                    "bpf2socks helper or pin verification failed");
        }
        return -1;
    }
    return 0;
}

static int system_wal_verify_applied(void *opaque,
    const struct asteriskd_recovery_record *record,
    struct asteriskd_wal_applied_identity_delta *delta, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (record == NULL || delta == NULL) return -1;
    memset(delta, 0, sizeof(*delta));
    if (system_rule_recovery_kind(record->kind) &&
        system->rule_snapshot.phase == SYSTEM_RULE_SNAPSHOT_NEEDS_VERIFY &&
        system_rule_snapshot_capture(system, &system->rules_runtime.plan,
            SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) != 0) return -1;
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        uint8_t value = 0U;
        return system_sysctl_read(&record->resource.sysctl, &value) == 0 &&
            value == record->resource.sysctl.desired_value ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        uint64_t object_id = record->resource.bpf_pin.pin_id == ASTERISKD_PIN_HOTSPOT_RECOVERY
            ? system_recovery_pin_object_id(system, record)
            : system_verified_pin_id(system, record->resource.bpf_pin.pin_id);
        if (object_id == 0U) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "verified BPF identity is missing");
            }
            return -1;
        }
        delta->has_object_id = true;
        delta->object_id = object_id;
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        bool present = false;
        return system_tc_probe_qdisc(system, &record->resource.tc_qdisc, &present) == 0 &&
            present ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER) {
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_DAEMON) {
            return system_tc_probe_filter(system, &record->resource.tc_filter, &state) == 0 &&
                state == ASTERISKD_RULES_SLOT_OWNED ? 0 : -1;
        }
        const struct asteriskd_recovery_record *pin = system_find_recovery_record(
            system, record->resource.tc_filter.recovery_pin_record_id);
        return pin != NULL && pin->kind == ASTERISKD_RECOVERY_BPF_PIN &&
            pin->resource.bpf_pin.has_object_id &&
            system_tc_probe_foreign_filter(system, &record->resource.tc_filter,
                pin->resource.bpf_pin.object_id, &state) == 0 &&
            state == ASTERISKD_RULES_SLOT_ABSENT ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &record->resource.iptables_chain);
        bool all_present = false;
        bool any_present = false;
        if (group == NULL) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "iptables private group is unknown");
            }
            return -1;
        }
        if (system_probe_private_group(system, group, &all_present, &any_present) != 0 ||
            !all_present) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "iptables private group probe failed");
            }
            return -1;
        }
        if (system_verify_private_group_contents(system, group) != 0) {
            if (error != NULL && error_size != 0U) {
                (void)snprintf(error, error_size, "%s", "iptables private group verification failed");
            }
            return -1;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &record->resource.iptables_rule);
        bool all_present = false;
        bool any_present = false;
        if (group != NULL && system_probe_hook_group(
                system, group, &all_present, &any_present) == 0 && all_present) return 0;
        if (error != NULL && error_size != 0U) {
            (void)snprintf(error, error_size, "%s", "iptables hook group verification failed");
        }
        return -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
        record->kind == ASTERISKD_RECOVERY_ROUTE ||
        record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, record);
        bool present = false;
        if (effect == NULL || system_probe_route_effect(system, effect, &present) != 0 ||
            !present) return -1;
        if (record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
            uint32_t index = if_nametoindex(effect->interface_name);
            if (index == 0U) return -1;
            delta->has_interface_index = true;
            delta->interface_index = index;
        }
        return 0;
    }
    return -1;
}

static int system_wal_probe_recovery(void *opaque,
    const struct asteriskd_recovery_record *record,
    enum asteriskd_wal_resource_state *state, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (record == NULL || state == NULL) return -1;
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        uint8_t value = 0U;
        int read_result = system_sysctl_read(&record->resource.sysctl, &value);
        if (read_result == 1) {
            *state = ASTERISKD_WAL_RESOURCE_ABSENT;
        } else if (read_result != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else if (value == record->resource.sysctl.original_value) {
            *state = ASTERISKD_WAL_RESOURCE_ORIGINAL;
        } else if (value == record->resource.sysctl.desired_value) {
            *state = ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT;
        } else {
            *state = ASTERISKD_WAL_RESOURCE_FOREIGN;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        char path_storage[ASTERISKD_MAX_PATH];
        const char *path = system_recovery_pin_path(
            system, record, path_storage, sizeof(path_storage));
        const struct asteriskd_bpf_pin_ownership_backend *backend =
            asteriskd_system_bpf_pin_ownership_backend();
        bool exists = true;
        uint64_t object_id = 0U;
        if (path == NULL || backend == NULL ||
            backend->probe(backend->context, path, &exists, &object_id) != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else if (!exists && object_id == 0U) {
            *state = ASTERISKD_WAL_RESOURCE_ABSENT;
        } else if (exists && object_id == record->resource.bpf_pin.object_id) {
            *state = ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT;
        } else {
            *state = ASTERISKD_WAL_RESOURCE_FOREIGN;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        if (if_nametoindex(record->resource.tc_qdisc.interface_name) !=
                record->resource.tc_qdisc.interface_index) {
            *state = ASTERISKD_WAL_RESOURCE_ABSENT;
            return 0;
        }
        bool present = false;
        if (system_tc_probe_qdisc(system, &record->resource.tc_qdisc, &present) != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else {
            *state = present ? ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT :
                ASTERISKD_WAL_RESOURCE_ABSENT;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER) {
        if (if_nametoindex(record->resource.tc_filter.interface_name) !=
                record->resource.tc_filter.interface_index) {
            *state = record->resource.tc_filter.ownership ==
                ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT
                    ? ASTERISKD_WAL_RESOURCE_ORIGINAL : ASTERISKD_WAL_RESOURCE_ABSENT;
            return 0;
        }
        enum asteriskd_rules_slot_state slot = ASTERISKD_RULES_SLOT_FOREIGN;
        int probed;
        if (record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT) {
            const struct asteriskd_recovery_record *pin = system_find_recovery_record(
                system, record->resource.tc_filter.recovery_pin_record_id);
            probed = pin == NULL || pin->kind != ASTERISKD_RECOVERY_BPF_PIN ||
                !pin->resource.bpf_pin.has_object_id ? -1 :
                system_tc_probe_foreign_filter(system, &record->resource.tc_filter,
                    pin->resource.bpf_pin.object_id, &slot);
        } else {
            probed = system_tc_probe_filter(system, &record->resource.tc_filter, &slot);
        }
        if (record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_DAEMON &&
            (probed != 0 || slot == ASTERISKD_RULES_SLOT_FOREIGN)) {
            enum asteriskd_pin_id pin_id = system_tc_pin_id(
                record->resource.tc_filter.program_id);
            char message[224U];
            int written = snprintf(message, sizeof(message),
                "TC filter recovery probe failed: direction=%u probe=%d state=%u verified=%d objectId=%" PRIu64,
                (unsigned)record->resource.tc_filter.direction, probed, (unsigned)slot,
                system->bpf2_verified ? 1 : 0,
                pin_id == ASTERISKD_PIN_COUNT ? UINT64_C(0) :
                    system_verified_pin_id(system, pin_id));
            if (written > 0 && (size_t)written < sizeof(message)) {
                (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                    ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
            }
        }
        if (probed != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else if (slot == ASTERISKD_RULES_SLOT_ABSENT) {
            *state = record->resource.tc_filter.ownership ==
                ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT
                    ? ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT : ASTERISKD_WAL_RESOURCE_ABSENT;
        } else if (slot == ASTERISKD_RULES_SLOT_OWNED) {
            *state = record->resource.tc_filter.ownership ==
                ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT
                    ? ASTERISKD_WAL_RESOURCE_ORIGINAL : ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT;
        } else {
            *state = ASTERISKD_WAL_RESOURCE_FOREIGN;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &record->resource.iptables_chain);
        bool all_present = false;
        bool any_present = false;
        if (group == NULL || system_probe_private_group(
                system, group, &all_present, &any_present) != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else {
            *state = any_present ? ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT :
                ASTERISKD_WAL_RESOURCE_ABSENT;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &record->resource.iptables_rule);
        bool all_present = false;
        bool any_present = false;
        if (group == NULL || system_probe_hook_group(
                system, group, &all_present, &any_present) != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else {
            *state = any_present ? ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT :
                ASTERISKD_WAL_RESOURCE_ABSENT;
        }
        return 0;
    }
    if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
        record->kind == ASTERISKD_RECOVERY_ROUTE ||
        record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, record);
        bool present = false;
        if (effect == NULL || system_probe_route_effect(system, effect, &present) != 0) {
            *state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        } else if (record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE && present &&
            !system_dummy_recovery_identity_matches(system, effect)) {
            *state = ASTERISKD_WAL_RESOURCE_FOREIGN;
        } else {
            *state = present ? ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT :
                ASTERISKD_WAL_RESOURCE_ABSENT;
        }
        return 0;
    }
    (void)error;
    (void)error_size;
    return -1;
}

static int system_wal_undo(void *opaque,
    const struct asteriskd_recovery_record *record, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (record == NULL) return -1;
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        return system_sysctl_write(&record->resource.sysctl,
            record->resource.sysctl.original_value);
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        char path_storage[ASTERISKD_MAX_PATH];
        const char *path = system_recovery_pin_path(
            system, record, path_storage, sizeof(path_storage));
        return path == NULL ? -1 : asteriskd_bpf_pin_cleanup_owned(
            path, record->resource.bpf_pin.object_id,
            asteriskd_system_bpf_pin_ownership_backend(), error, error_size);
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER &&
        record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_DAEMON) {
        return system_tc_remove_filter(system, &record->resource.tc_filter);
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER &&
        record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT) {
        return system_tc_restore_foreign_filter(system, &record->resource.tc_filter);
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        return system_tc_remove_qdisc(system, &record->resource.tc_qdisc);
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &record->resource.iptables_chain);
        return group == NULL ? -1 : system_remove_private_group(system, group);
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &record->resource.iptables_rule);
        return group == NULL ? -1 : system_remove_hook_group(system, group);
    }
    if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
        record->kind == ASTERISKD_RECOVERY_ROUTE ||
        record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, record);
        return effect == NULL ? -1 : system_remove_route_effect(system, effect);
    }
    return -1;
}

static int system_wal_verify_restored(void *opaque,
    const struct asteriskd_recovery_record *record, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (record == NULL) return -1;
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        uint8_t value = 0U;
        int result = system_sysctl_read(&record->resource.sysctl, &value);
        return result == 0 && value == record->resource.sysctl.original_value ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_BPF_PIN) {
        char path_storage[ASTERISKD_MAX_PATH];
        const char *path = system_recovery_pin_path(
            system, record, path_storage, sizeof(path_storage));
        const struct asteriskd_bpf_pin_ownership_backend *backend =
            asteriskd_system_bpf_pin_ownership_backend();
        bool exists = true;
        uint64_t object_id = 0U;
        return path != NULL && backend != NULL &&
            backend->probe(backend->context, path, &exists, &object_id) == 0 &&
            !exists && object_id == 0U ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_FILTER) {
        if (if_nametoindex(record->resource.tc_filter.interface_name) !=
                record->resource.tc_filter.interface_index) return 0;
        enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
        if (record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT) {
            const struct asteriskd_recovery_record *pin = system_find_recovery_record(
                system, record->resource.tc_filter.recovery_pin_record_id);
            return pin != NULL && pin->kind == ASTERISKD_RECOVERY_BPF_PIN &&
                pin->resource.bpf_pin.has_object_id &&
                system_tc_probe_foreign_filter(system, &record->resource.tc_filter,
                    pin->resource.bpf_pin.object_id, &state) == 0 &&
                state == ASTERISKD_RULES_SLOT_OWNED ? 0 : -1;
        }
        return system_tc_probe_filter(system, &record->resource.tc_filter, &state) == 0 &&
            state == ASTERISKD_RULES_SLOT_ABSENT ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        if (if_nametoindex(record->resource.tc_qdisc.interface_name) !=
                record->resource.tc_qdisc.interface_index) return 0;
        bool present = false;
        enum asteriskd_tc_qdisc_cleanup_decision decision;
        return system_tc_inspect_qdisc_cleanup(system,
                &record->resource.tc_qdisc, &present, &decision) == 0 &&
            asteriskd_tc_qdisc_cleanup_restored(present, decision) ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_CHAIN) {
        const struct asteriskd_private_chain_group *group =
            system_find_private_group(system, &record->resource.iptables_chain);
        bool all_present = false;
        bool any_present = false;
        return group != NULL && system_probe_private_group(
            system, group, &all_present, &any_present) == 0 && !any_present ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_IPTABLES_RULE) {
        const struct asteriskd_traffic_hook_group *group =
            system_find_hook_group(system, &record->resource.iptables_rule);
        bool all_present = false;
        bool any_present = false;
        return group != NULL && system_probe_hook_group(
            system, group, &all_present, &any_present) == 0 && !any_present ? 0 : -1;
    }
    if (record->kind == ASTERISKD_RECOVERY_IP_RULE ||
        record->kind == ASTERISKD_RECOVERY_ROUTE ||
        record->kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE) {
        const struct asteriskd_route_effect *effect = system_find_route_effect(system, record);
        bool present = true;
        return effect != NULL && system_probe_route_effect(system, effect, &present) == 0 &&
            !present ? 0 : -1;
    }
    (void)error;
    (void)error_size;
    return -1;
}

static const struct asteriskd_wal_effect_backend system_wal_backend = {
    .probe_original = system_wal_probe_original,
    .apply = system_wal_apply,
    .verify_applied = system_wal_verify_applied,
    .probe_recovery = system_wal_probe_recovery,
    .undo = system_wal_undo,
    .verify_restored = system_wal_verify_restored,
};

static bool system_rule_record_matches(
    const struct asteriskd_recovery_record *left,
    const struct asteriskd_recovery_record *right) {
    if (left == NULL || right == NULL || left->kind != right->kind) return false;
    switch (left->kind) {
        case ASTERISKD_RECOVERY_IPTABLES_CHAIN:
            return left->resource.iptables_chain.family == right->resource.iptables_chain.family &&
                left->resource.iptables_chain.table == right->resource.iptables_chain.table &&
                left->resource.iptables_chain.chain_id == right->resource.iptables_chain.chain_id;
        case ASTERISKD_RECOVERY_IPTABLES_RULE:
            return left->resource.iptables_rule.family == right->resource.iptables_rule.family &&
                left->resource.iptables_rule.table == right->resource.iptables_rule.table &&
                left->resource.iptables_rule.chain_id == right->resource.iptables_rule.chain_id &&
                left->resource.iptables_rule.rule_id == right->resource.iptables_rule.rule_id;
        case ASTERISKD_RECOVERY_IP_RULE:
            return left->resource.ip_rule.family == right->resource.ip_rule.family &&
                left->resource.ip_rule.rule_id == right->resource.ip_rule.rule_id;
        case ASTERISKD_RECOVERY_ROUTE:
            return left->resource.route.family == right->resource.route.family &&
                left->resource.route.route_id == right->resource.route.route_id &&
                strcmp(left->resource.route.interface_name,
                    right->resource.route.interface_name) == 0;
        case ASTERISKD_RECOVERY_DUMMY_INTERFACE:
            return left->resource.dummy_interface.interface_id ==
                right->resource.dummy_interface.interface_id;
        case ASTERISKD_RECOVERY_TC_QDISC:
            return left->resource.tc_qdisc.qdisc_id == right->resource.tc_qdisc.qdisc_id &&
                left->resource.tc_qdisc.interface_index ==
                    right->resource.tc_qdisc.interface_index &&
                strcmp(left->resource.tc_qdisc.interface_name,
                    right->resource.tc_qdisc.interface_name) == 0;
        case ASTERISKD_RECOVERY_TC_FILTER:
            return left->resource.tc_filter.ownership == right->resource.tc_filter.ownership &&
                left->resource.tc_filter.inverse == right->resource.tc_filter.inverse &&
                left->resource.tc_filter.filter_id == right->resource.tc_filter.filter_id &&
                left->resource.tc_filter.direction == right->resource.tc_filter.direction &&
                left->resource.tc_filter.interface_index ==
                    right->resource.tc_filter.interface_index &&
                strcmp(left->resource.tc_filter.interface_name,
                    right->resource.tc_filter.interface_name) == 0;
        case ASTERISKD_RECOVERY_SYSCTL:
            return left->resource.sysctl.sysctl_id == right->resource.sysctl.sysctl_id &&
                left->resource.sysctl.interface_index == right->resource.sysctl.interface_index &&
                strcmp(left->resource.sysctl.interface_name,
                    right->resource.sysctl.interface_name) == 0;
        default:
            return false;
    }
}

static const struct asteriskd_recovery_record *system_durable_rule_record(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *prototype) {
    for (size_t index = 0U; index < system->state.recovery.record_count; ++index) {
        const struct asteriskd_recovery_record *record =
            &system->state.recovery.records[index];
        if (system_rule_record_matches(record, prototype)) return record;
    }
    return NULL;
}

static int system_rules_wal_apply_plan(
    void *opaque, const struct asteriskd_rule_transaction_plan *plan) {
    struct asteriskd_system_supervisor *system = opaque;
    if (plan == NULL || plan->no_op) return plan != NULL ? 0 : -1;
    struct asteriskd_recovery_record records[
        ASTERISKD_RULE_TRANSACTION_MAX_GROUPS * 2U +
        ASTERISKD_RULE_TRANSACTION_MAX_ROUTES];
    size_t count = 0U;
    for (size_t index = 0U; index < plan->private_group_count; ++index) {
        records[count++] = plan->private_groups[index].recovery;
    }
    for (size_t index = 0U; index < plan->route_count; ++index) {
        if (system_route_record(system, &plan->routes[index], &records[count]) != 0) return -1;
        ++count;
    }
    for (size_t index = 0U; index < plan->hook_group_count; ++index) {
        records[count++] = plan->hook_groups[index].recovery;
    }
    if (count == 0U) return -1;
    if (system_rule_snapshot_capture(
            system, plan, SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY) != 0) return -1;
    char error[256U] = {0};
    int applied = count == 1U
        ? asteriskd_wal_apply(&system->store, &system->state, records,
            &system_wal_backend, system, error, sizeof(error))
        : asteriskd_wal_apply_batch(&system->store, &system->state, records, count,
            &system_wal_backend, system, error, sizeof(error));
    if (applied == ASTERISKD_STATE_OK) return 0;
    system_rule_snapshot_destroy(&system->rule_snapshot);
    char message[384U];
    int written = snprintf(message, sizeof(message),
        "rule transaction WAL failed: result=%d records=%zu detail=%s",
        applied, count, error[0] == '\0' ? "unavailable" : error);
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
            ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
    }
    return -1;
}

static int system_rules_wal_apply_private(
    void *opaque, const struct asteriskd_private_chain_group *group) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_recovery_record *durable =
        system_durable_rule_record(system, &group->recovery);
    if (durable != NULL) {
        if ((durable->kind != ASTERISKD_RECOVERY_IPTABLES_CHAIN) ||
            durable->resource.iptables_chain.original_presence) return -1;
        return system_create_private_group(system, group);
    }
    struct asteriskd_recovery_record record = group->recovery;
    char error[128U] = {0};
    int applied = asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, sizeof(error));
    if (applied == ASTERISKD_STATE_OK) return 0;
    char message[256U];
    int written = snprintf(message, sizeof(message),
        "private rules WAL failed: result=%d detail=%s", applied,
        error[0] == '\0' ? "unavailable" : error);
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
            ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
    }
    return -1;
}

static int system_rules_wal_apply_route(
    void *opaque, const struct asteriskd_route_effect *effect) {
    struct asteriskd_system_supervisor *system = opaque;
    struct asteriskd_recovery_record record;
    if (system_route_record(system, effect, &record) != 0) return -1;
    const struct asteriskd_recovery_record *durable =
        system_durable_rule_record(system, &record);
    if (durable != NULL) {
        bool original_presence = durable->kind == ASTERISKD_RECOVERY_IP_RULE
            ? durable->resource.ip_rule.original_presence
            : durable->kind == ASTERISKD_RECOVERY_ROUTE
                ? durable->resource.route.original_presence
                : durable->resource.dummy_interface.original_presence;
        return original_presence ? -1 : system_apply_route_effect(system, effect);
    }
    char error[128U];
    return asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, sizeof(error)) == ASTERISKD_STATE_OK ? 0 : -1;
}

static int system_rules_wal_apply_hook(
    void *opaque, const struct asteriskd_traffic_hook_group *group) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_recovery_record *durable =
        system_durable_rule_record(system, &group->recovery);
    if (durable != NULL) {
        if ((durable->kind != ASTERISKD_RECOVERY_IPTABLES_RULE) ||
            durable->resource.iptables_rule.original_presence) return -1;
        return system_apply_hook_group(system, group);
    }
    struct asteriskd_recovery_record record = group->recovery;
    char error[128U] = {0};
    int applied = asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, sizeof(error));
    if (applied == ASTERISKD_STATE_OK) return 0;
    char message[256U];
    int written = snprintf(message, sizeof(message),
        "hook rules WAL failed: result=%d family=%d table=%d detail=%s",
        applied, (int)group->family, (int)group->table,
        error[0] == '\0' ? "unavailable" : error);
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
            ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
    }
    return -1;
}

static int system_rules_probe_private(void *opaque,
    const struct asteriskd_private_chain_group *group,
    enum asteriskd_rules_slot_state *state) {
    struct asteriskd_system_supervisor *system = opaque;
    bool all_present = false;
    bool any_present = false;
    if (state == NULL || system_probe_private_group(
            system, group, &all_present, &any_present) != 0) return -1;
    if (!any_present) *state = ASTERISKD_RULES_SLOT_ABSENT;
    else if (all_present && system_durable_rule_record(system, &group->recovery) != NULL) {
        *state = system_verify_private_group_contents(system, group) == 0
            ? ASTERISKD_RULES_SLOT_OWNED : ASTERISKD_RULES_SLOT_FOREIGN;
    } else {
        *state = ASTERISKD_RULES_SLOT_FOREIGN;
    }
    return 0;
}

static int system_rules_probe_route(void *opaque,
    const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state) {
    struct asteriskd_system_supervisor *system = opaque;
    struct asteriskd_recovery_record record;
    if (state == NULL || system_route_record(system, effect, &record) != 0 ||
        system_classify_route_effect(system, effect, state) != 0) return -1;
    if (*state == ASTERISKD_RULES_SLOT_OWNED) {
        if (system_durable_rule_record(system, &record) == NULL ||
            (effect->kind == ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE &&
             !system_dummy_recovery_identity_matches(system, effect))) {
            *state = ASTERISKD_RULES_SLOT_FOREIGN;
        }
    }
    return 0;
}

static int system_rules_probe_hook(void *opaque,
    const struct asteriskd_traffic_hook_group *group,
    enum asteriskd_rules_slot_state *state) {
    struct asteriskd_system_supervisor *system = opaque;
    bool all_present = false;
    bool any_present = false;
    if (state == NULL || system_probe_hook_group(
            system, group, &all_present, &any_present) != 0) return -1;
    if (!any_present) *state = ASTERISKD_RULES_SLOT_ABSENT;
    else if (all_present && system_durable_rule_record(system, &group->recovery) != NULL) {
        *state = ASTERISKD_RULES_SLOT_OWNED;
    } else {
        *state = ASTERISKD_RULES_SLOT_FOREIGN;
    }
    return 0;
}

static int system_rules_remove_private(
    void *opaque, const struct asteriskd_private_chain_group *group) {
    return system_remove_private_group(opaque, group);
}

static int system_rules_remove_route(
    void *opaque, const struct asteriskd_route_effect *effect) {
    return system_remove_route_effect(opaque, effect);
}

static int system_rules_remove_hook(
    void *opaque, const struct asteriskd_traffic_hook_group *group) {
    return system_remove_hook_group(opaque, group);
}

static int system_rules_recover_record(
    void *opaque, const struct asteriskd_recovery_record *record) {
    enum asteriskd_wal_resource_state state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
    char error[128U];
    if (system_wal_probe_recovery(
            opaque, record, &state, error, sizeof(error)) != 0) return -1;
    if (state == ASTERISKD_WAL_RESOURCE_ORIGINAL ||
        state == ASTERISKD_WAL_RESOURCE_ABSENT) return 0;
    return state == ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT &&
        system_wal_undo(opaque, record, error, sizeof(error)) == 0 &&
        system_wal_verify_restored(opaque, record, error, sizeof(error)) == 0 ? 0 : -1;
}

static void system_rules_backend_init(struct asteriskd_system_supervisor *system) {
    asteriskd_rules_runtime_init(&system->rules_runtime);
    system->rules_backend = (struct asteriskd_rules_backend){
        .ctx = system,
        .wal_apply_plan = system_rules_wal_apply_plan,
        .wal_apply_private = system_rules_wal_apply_private,
        .wal_apply_route = system_rules_wal_apply_route,
        .wal_apply_hook = system_rules_wal_apply_hook,
        .probe_private = system_rules_probe_private,
        .probe_route = system_rules_probe_route,
        .probe_hook = system_rules_probe_hook,
        .wal_remove_private = system_rules_remove_private,
        .wal_remove_route = system_rules_remove_route,
        .wal_remove_hook = system_rules_remove_hook,
        .wal_recover_record = system_rules_recover_record,
    };
    system->rules_initialized = true;
}

static int system_network_wal_dispatch(void *opaque,
    const struct asteriskd_typed_wal_request *request, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    if (request == NULL || request->source != ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE ||
        request->action != ASTERISKD_TYPED_WAL_APPLY ||
        request->record.kind != ASTERISKD_RECOVERY_SYSCTL) return ASTERISKD_STATE_INVALID;
    struct asteriskd_recovery_record record = request->record;
    return asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, error_size);
}

static int system_apply_ipv6_guard(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t index) {
    struct asteriskd_recovery_record record;
    memset(&record, 0, sizeof(record));
    record.status = ASTERISKD_RECOVERY_INTENT;
    record.kind = ASTERISKD_RECOVERY_SYSCTL;
    record.resource.sysctl.sysctl_id = ASTERISKD_SYSCTL_DISABLE_IPV6;
    (void)snprintf(record.resource.sysctl.interface_name,
        sizeof(record.resource.sysctl.interface_name), "%s", name);
    record.resource.sysctl.interface_index = index;
    record.resource.sysctl.original_value = 0U;
    record.resource.sysctl.desired_value = 1U;
    uint8_t current = 0U;
    int read_result = system_sysctl_read(&record.resource.sysctl, &current);
    if (read_result == 1 || (read_result == 0 && current == 1U)) return 0;
    if (read_result != 0 || current != 0U) return -1;
    char error[128U];
    return asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, sizeof(error));
}

static int system_apply_initial_ipv6_guard(struct asteriskd_system_supervisor *system) {
    if (!system->loaded_config.config.disable_system_ipv6) return 0;
    if (system_apply_ipv6_guard(system, "default", 0U) != 0) return -1;
    DIR *directory = opendir("/proc/sys/net/ipv6/conf");
    if (directory == NULL) return -1;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
            strcmp(entry->d_name, "all") == 0 || strcmp(entry->d_name, "default") == 0 ||
            strcmp(entry->d_name, "lo") == 0) continue;
        unsigned index = if_nametoindex(entry->d_name);
        if (index == 0U || system_apply_ipv6_guard(system, entry->d_name, index) != 0) {
            result = -1;
            break;
        }
    }
    if (closedir(directory) != 0) result = -1;
    return result;
}

static int system_effect_start_matcher(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    const struct asteriskd_bpf_pin_ownership_backend *pin_backend =
        asteriskd_system_bpf_pin_ownership_backend();
    char error[256U];
    if (system->matcher_launch_ready || system->matcher_verified ||
        asteriskd_matcher_pin_plan_build(
            &system->loaded_config.config, &system->matcher_pin_plan) != 0) return -1;
    system->matcher_plan_ready = true;
    if (pin_backend == NULL || asteriskd_matcher_pin_preflight(
            &system->matcher_pin_plan, pin_backend, error, sizeof(error)) != 0 ||
        asteriskd_matcher_launch_prepare(
            &system->loaded_config.config, (const char *const *)environ,
            asteriskd_system_anonymous_file_backend(), &system->matcher_launch,
            error, sizeof(error)) != 0) return -1;
    system->matcher_launch_ready = true;
    struct asteriskd_recovery_record records[4U];
    size_t count = 0U;
    if (asteriskd_matcher_pin_records_build(
            &system->matcher_pin_plan, records, 4U, &count) != 0) return -1;
    system->active_pin_batch = system->loaded_config.config.enable_ipv6
        ? ASTERISKD_WAL_PIN_BATCH_MATCHER_DUAL_STACK
        : ASTERISKD_WAL_PIN_BATCH_MATCHER_IPV4;
    system->pin_batch_active = true;
    int result = asteriskd_wal_apply_pin_batch(
        &system->store, &system->state, system->active_pin_batch,
        records, count, &system_wal_backend, system, error, sizeof(error));
    system->pin_batch_active = false;
    int destroyed = asteriskd_matcher_launch_destroy(
        asteriskd_system_anonymous_file_backend(), &system->matcher_launch);
    system->matcher_launch_ready = false;
    return result == ASTERISKD_STATE_OK && destroyed == 0 ? 0 : -1;
}

static int system_effect_start_helper(
    void *opaque, struct asteriskd_child_identity *identity) {
    struct asteriskd_system_supervisor *system = opaque;
    if (identity == NULL) return -1;
    if (system->loaded_config.config.helper.type != ASTERISKD_HELPER_BPF2SOCKS) {
        return system_start_helper_process(system, identity);
    }
    const struct asteriskd_bpf_pin_ownership_backend *pin_backend =
        asteriskd_system_bpf_pin_ownership_backend();
    char error[256U];
    if (asteriskd_bpf2_pin_plan_build(
            &system->loaded_config.config, &system->bpf2_pin_plan) != 0) return -1;
    system->bpf2_plan_ready = true;
    if (pin_backend == NULL || asteriskd_bpf2_pin_preflight(
            &system->bpf2_pin_plan, pin_backend, error, sizeof(error)) != 0) return -1;
    struct asteriskd_recovery_record records[4U];
    size_t count = 0U;
    if (asteriskd_bpf2_pin_records_build(
            &system->bpf2_pin_plan, records, 4U, &count) != 0) return -1;
    system->active_pin_batch = system->loaded_config.config.enable_ipv6
        ? ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_DUAL_STACK
        : ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_IPV4;
    system->pin_batch_active = true;
    int result = asteriskd_wal_apply_pin_batch(
        &system->store, &system->state, system->active_pin_batch,
        records, count, &system_wal_backend, system, error, sizeof(error));
    system->pin_batch_active = false;
    if (result != ASTERISKD_STATE_OK || !system->helper_identity_ready) return -1;
    *identity = system->helper_identity;
    return 0;
}

static int system_effect_open_network(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    char error[128U];
    if (asteriskd_network_open(&system->loaded_config.config,
            asteriskd_system_network_backend(), &system->network,
            error, sizeof(error)) != 0) return -1;
    system->network_opened = true;
    system->network_wal_sink.dispatch = system_network_wal_dispatch;
    system->network_wal_sink.context = system;
    if (asteriskd_network_set_wal_sink(
            &system->network, &system->network_wal_sink) != 0) return -1;
    return system_apply_initial_ipv6_guard(system);
}

static int system_detect_global_ipv6(bool *present) {
    if (present == NULL) return -1;
    *present = false;
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != AF_INET6) continue;
        const struct in6_addr *address =
            &((const struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr;
        if (!IN6_IS_ADDR_UNSPECIFIED(address) && !IN6_IS_ADDR_LOOPBACK(address) &&
            !IN6_IS_ADDR_LINKLOCAL(address) && !IN6_IS_ADDR_MULTICAST(address)) {
            *present = true;
            break;
        }
    }
    freeifaddrs(addresses);
    return 0;
}

static int system_collect_local_address_set(
    struct asteriskd_system_supervisor *system,
    int family,
    struct asteriskd_address_set *set) {
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    struct asteriskd_interface_address candidates[ASTERISKD_MAX_ADDRESSES];
    size_t count = 0U;
    int native_family = family == ASTERISKD_ADDRESS_IPV4 ? AF_INET : AF_INET6;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_name == NULL ||
            entry->ifa_addr->sa_family != native_family) continue;
        if (count >= ASTERISKD_MAX_ADDRESSES) {
            freeifaddrs(addresses);
            return -1;
        }
        const void *raw = native_family == AF_INET
            ? (const void *)&((const struct sockaddr_in *)entry->ifa_addr)->sin_addr
            : (const void *)&((const struct sockaddr_in6 *)entry->ifa_addr)->sin6_addr;
        if (snprintf(candidates[count].interface_name,
                sizeof(candidates[count].interface_name), "%s", entry->ifa_name) <= 0 ||
            inet_ntop(native_family, raw, candidates[count].address,
                sizeof(candidates[count].address)) == NULL) {
            freeifaddrs(addresses);
            return -1;
        }
        ++count;
    }
    freeifaddrs(addresses);
    char error[128U];
    return asteriskd_local_address_set_build(&system->loaded_config.config,
        family, candidates, count, set, error, sizeof(error)) == 0 ? 0 : -1;
}

static bool system_uses_iptables_local_bypass(
    const struct asteriskd_system_supervisor *system) {
    enum asteriskd_mode mode = system->loaded_config.config.mode;
    return mode == ASTERISKD_MODE_TPROXY || mode == ASTERISKD_MODE_TUN ||
        mode == ASTERISKD_MODE_TUN2SOCKS;
}

static int system_capture_local_address_snapshot(
    struct asteriskd_system_supervisor *system) {
    system->local_address_snapshot_active = false;
    memset(&system->local_ipv4_snapshot, 0, sizeof(system->local_ipv4_snapshot));
    memset(&system->local_ipv6_snapshot, 0, sizeof(system->local_ipv6_snapshot));
    if (!system_uses_iptables_local_bypass(system)) return 0;
    if (system_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV4,
            &system->local_ipv4_snapshot) != 0) return -1;
    if (system->loaded_config.config.enable_ipv6) {
        if (system_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV6,
                &system->local_ipv6_snapshot) != 0) return -1;
    } else {
        system->local_ipv6_snapshot.family = ASTERISKD_ADDRESS_IPV6;
    }
    system->local_address_snapshot_active = true;
    return 0;
}

static void system_clear_local_address_snapshot(
    struct asteriskd_system_supervisor *system) {
    system->local_address_snapshot_active = false;
    memset(&system->local_ipv4_snapshot, 0, sizeof(system->local_ipv4_snapshot));
    memset(&system->local_ipv6_snapshot, 0, sizeof(system->local_ipv6_snapshot));
}

static int system_apply_local_bypass_plan(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    const char *consumer_chain,
    const struct asteriskd_local_bypass_plan *plan) {
    for (size_t index = 0U; index < plan->operation_count; ++index) {
        const struct asteriskd_local_bypass_operation *operation = &plan->operations[index];
        char cidr[ASTERISKD_MAX_CIDR];
        int written = snprintf(cidr, sizeof(cidr), "%s/%u", operation->address,
            family == ASTERISKD_IP_FAMILY_IPV4 ? 32U : 128U);
        if (written <= 0 || (size_t)written >= sizeof(cidr)) return -1;
        if (operation->kind == ASTERISKD_LOCAL_BYPASS_INSERT) {
            char position[24U];
            written = snprintf(position, sizeof(position), "%zu", operation->rule_number);
            const char *arguments[] = {position, "-d", cidr, "-j", "RETURN"};
            if (written <= 0 || (size_t)written >= sizeof(position) ||
                system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
                    "-I", consumer_chain, arguments,
                    sizeof(arguments) / sizeof(arguments[0])) != 0) return -1;
        } else if (operation->kind == ASTERISKD_LOCAL_BYPASS_DELETE) {
            const char *arguments[] = {"-d", cidr, "-j", "RETURN"};
            if (system_xtables_zero(system, family, ASTERISKD_IP_TABLE_MANGLE,
                    "-D", consumer_chain, arguments,
                    sizeof(arguments) / sizeof(arguments[0])) != 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

static int system_reconcile_local_bypass_consumer(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family,
    const char *consumer_chain,
    const char *begin_chain,
    const char *end_chain,
    const struct asteriskd_address_set *desired) {
    int exit_status = -1;
    if (system_xtables_run(system, family, ASTERISKD_IP_TABLE_MANGLE,
            "-S", consumer_chain, NULL, 0U, true, &exit_status) != 0 ||
        exit_status != 0 || system->action_stdout_overflow) return -1;
    struct asteriskd_local_bypass_plan plan;
    char error[160U];
    int address_family = family == ASTERISKD_IP_FAMILY_IPV4
        ? ASTERISKD_ADDRESS_IPV4 : ASTERISKD_ADDRESS_IPV6;
    if (asteriskd_local_bypass_plan_build(address_family, consumer_chain,
            begin_chain, end_chain, system->action_stdout, system->action_stdout_length,
            desired, &plan, error, sizeof(error)) != 0) {
        char message[256U];
        int written = snprintf(message, sizeof(message),
            "local bypass plan failed: chain=%s detail=%s", consumer_chain, error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    return system_apply_local_bypass_plan(system, family, consumer_chain, &plan);
}

static int system_reconcile_iptables_local_family(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family) {
    const struct asteriskd_private_chain_group *local_group = NULL;
    const struct asteriskd_private_chain_group *consumer_group = NULL;
    enum asteriskd_chain_id consumer_id = system->loaded_config.config.mode ==
        ASTERISKD_MODE_TPROXY ? ASTERISKD_CHAIN_TPROXY : ASTERISKD_CHAIN_ROUTING;
    for (size_t index = 0U; index < system->rules_runtime.plan.private_group_count; ++index) {
        const struct asteriskd_private_chain_group *group =
            &system->rules_runtime.plan.private_groups[index];
        if (group->family != family || group->table != ASTERISKD_IP_TABLE_MANGLE) continue;
        if (group->chain_id == ASTERISKD_CHAIN_LOCAL_BYPASS) local_group = group;
        else if (group->chain_id == consumer_id) consumer_group = group;
    }
    if (local_group == NULL || local_group->name_count != 2U || consumer_group == NULL) return -1;
    const char *begin_chain = NULL;
    const char *end_chain = NULL;
    for (size_t index = 0U; index < local_group->name_count; ++index) {
        const char *name = local_group->names[index];
        if (strstr(name, "_BEGIN") != NULL) begin_chain = name;
        else if (strstr(name, "_END") != NULL) end_chain = name;
    }
    if (begin_chain == NULL || end_chain == NULL) return -1;
    int address_family = family == ASTERISKD_IP_FAMILY_IPV4
        ? ASTERISKD_ADDRESS_IPV4 : ASTERISKD_ADDRESS_IPV6;
    const struct asteriskd_address_set *desired = family == ASTERISKD_IP_FAMILY_IPV4
        ? &system->local_ipv4_snapshot : &system->local_ipv6_snapshot;
    if (!system->local_address_snapshot_active || desired->family != address_family) return -1;
    for (size_t index = 0U; index < consumer_group->name_count; ++index) {
        const char *consumer = consumer_group->names[index];
        if (strstr(consumer, "PREROUTING") == NULL && strstr(consumer, "OUTPUT") == NULL) {
            continue;
        }
        if (system_reconcile_local_bypass_consumer(system, family, consumer,
                begin_chain, end_chain, desired) != 0) return -1;
    }
    return 0;
}

static int system_reconcile_iptables_local_bypass(
    struct asteriskd_system_supervisor *system) {
    if (!system_uses_iptables_local_bypass(system)) return 0;
    if (!system->local_address_snapshot_active) return -1;
    if (system_reconcile_iptables_local_family(
            system, ASTERISKD_IP_FAMILY_IPV4) != 0) return -1;
    return !system->loaded_config.config.enable_ipv6 ||
        system_reconcile_iptables_local_family(
            system, ASTERISKD_IP_FAMILY_IPV6) == 0 ? 0 : -1;
}

static int system_reconcile_bpf2_local_maps(
    struct asteriskd_system_supervisor *system) {
    if (system->loaded_config.config.mode != ASTERISKD_MODE_BPF2SOCKS) return 0;
    const struct asteriskd_bpf_map_backend *backend = asteriskd_system_bpf_map_backend();
    if (!system->bpf2_verified || backend == NULL) return -1;
    struct asteriskd_address_set addresses;
    char error[128U];
    const char *path = system_pin_path(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4);
    uint64_t object_id = system_verified_pin_id(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4);
    if (path == NULL || object_id == 0U ||
        system_collect_local_address_set(
            system, ASTERISKD_ADDRESS_IPV4, &addresses) != 0 ||
        asteriskd_bpf_local_map_reconcile(backend, path, object_id,
            &addresses, error, sizeof(error)) != 0) return -1;
    if (!system->loaded_config.config.enable_ipv6) return 0;
    path = system_pin_path(system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6);
    object_id = system_verified_pin_id(
        system, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6);
    return path != NULL && object_id != 0U &&
        system_collect_local_address_set(system, ASTERISKD_ADDRESS_IPV6, &addresses) == 0 &&
        asteriskd_bpf_local_map_reconcile(backend, path, object_id,
            &addresses, error, sizeof(error)) == 0 ? 0 : -1;
}

static bool system_hotspot_interface_selected(
    const struct asteriskd_config *config, const char *name) {
    for (size_t index = 0U; index < config->hotspot_interface_prefix_count; ++index) {
        const char *selector = config->hotspot_interface_prefixes[index];
        size_t length = strlen(selector);
        if (length != 0U && selector[length - 1U] == '+') {
            if (strncmp(name, selector, length - 1U) == 0) return true;
        } else if (strcmp(name, selector) == 0) {
            return true;
        }
    }
    return false;
}

static const struct asteriskd_recovery_record *system_foreign_filter_record(
    const struct asteriskd_system_supervisor *system, const char *name, uint32_t index) {
    for (size_t position = 0U; position < system->state.recovery.record_count; ++position) {
        const struct asteriskd_recovery_record *record =
            &system->state.recovery.records[position];
        if (record->kind == ASTERISKD_RECOVERY_TC_FILTER &&
            record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT &&
            record->resource.tc_filter.interface_index == index &&
            strcmp(record->resource.tc_filter.interface_name, name) == 0) return record;
    }
    return NULL;
}

static const struct asteriskd_recovery_record *system_hotspot_recovery_pin(
    const struct asteriskd_system_supervisor *system, uint64_t object_id) {
    for (size_t position = 0U; position < system->state.recovery.record_count; ++position) {
        const struct asteriskd_recovery_record *record =
            &system->state.recovery.records[position];
        if (record->kind == ASTERISKD_RECOVERY_BPF_PIN &&
            record->resource.bpf_pin.pin_id == ASTERISKD_PIN_HOTSPOT_RECOVERY &&
            record->resource.bpf_pin.has_object_id &&
            record->resource.bpf_pin.object_id == object_id) return record;
    }
    return NULL;
}

static int system_tc_probe_foreign_candidate(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t index,
    struct asteriskd_foreign_tc_probe *probe, bool *present,
    char *trusted_path, size_t trusted_path_size) {
    static const char *const trusted_paths[] = {
        "/sys/fs/bpf/tethering/prog_offload_schedcls_tether_upstream6_ether",
        "/sys/fs/bpf/tethering/prog_offload_schedcls_tether_upstream6_rawip",
        "/sys/fs/bpf/tethering/prog_offload_schedcls_tether_downstream6_ether",
        "/sys/fs/bpf/tethering/prog_offload_schedcls_tether_downstream6_rawip",
        "/sys/fs/bpf/prog_offload_schedcls_tether_upstream6_ether",
        "/sys/fs/bpf/prog_offload_schedcls_tether_upstream6_rawip",
        "/sys/fs/bpf/prog_offload_schedcls_tether_downstream6_ether",
        "/sys/fs/bpf/prog_offload_schedcls_tether_downstream6_rawip",
    };
    if (probe == NULL || present == NULL || trusted_path == NULL || trusted_path_size == 0U) {
        return -1;
    }
    memset(probe, 0, sizeof(*probe));
    *present = false;
    trusted_path[0] = '\0';
    char error[128U] = {0};
    if (system_foreign_tc_netlink_probe(system, index, probe, present) != 0) {
        char message[224U];
        int written = snprintf(message, sizeof(message),
            "hotspot filter probe failed: interface=%s index=%" PRIu32
            " stage=netlink done=%u failed=%u present=%u sequence=%" PRIu32,
            name, index, system->foreign_tc_netlink_done ? 1U : 0U,
            system->foreign_tc_netlink_failed ? 1U : 0U,
            system->foreign_tc_netlink_present ? 1U : 0U,
            system->foreign_tc_netlink_sequence);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    if (!*present) return 0;
    probe->parent = UINT32_C(0xfffffff2);
    if (system_interface_identity(name, index, probe) != 0 ||
        asteriskd_foreign_tc_trusted_pin_find(
            probe, trusted_paths, sizeof(trusted_paths) / sizeof(trusted_paths[0]),
            asteriskd_system_bpf_program_backend(), trusted_path, trusted_path_size,
            error, sizeof(error)) != 0) {
        char message[192U];
        int written = snprintf(message, sizeof(message),
            "hotspot filter probe failed: interface=%s index=%" PRIu32
            " stage=identity detail=%s", name, index,
            error[0] == '\0' ? "unavailable" : error);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    return 0;
}

static int system_reconcile_foreign_hotspot_filter(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t index) {
    const struct asteriskd_recovery_record *existing =
        system_foreign_filter_record(system, name, index);
    if (existing != NULL) {
        uint64_t filter_id = existing->record_id;
        uint64_t pin_id = existing->resource.tc_filter.recovery_pin_record_id;
        enum asteriskd_wal_resource_state state = ASTERISKD_WAL_RESOURCE_AMBIGUOUS;
        char error[128U];
        if (system_wal_probe_recovery(
                system, existing, &state, error, sizeof(error)) != 0) return -1;
        if (state == ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT) return 0;
        if (state != ASTERISKD_WAL_RESOURCE_ORIGINAL ||
            asteriskd_wal_recover_record_id(
                &system->store, &system->state, filter_id,
                &system_wal_backend, system, error, sizeof(error)) != ASTERISKD_STATE_OK) {
            return -1;
        }
        (void)pin_id;
    }
    struct asteriskd_foreign_tc_probe probe;
    bool present = false;
    char source_path[ASTERISKD_MAX_PATH];
    if (system_tc_probe_foreign_candidate(
            system, name, index, &probe, &present,
            source_path, sizeof(source_path)) != 0) return -1;
    if (!present) return 0;

    const struct asteriskd_recovery_record *pin =
        system_hotspot_recovery_pin(system, probe.program_object_id);
    uint64_t pin_record_id = pin == NULL
        ? system->state.recovery.next_record_id : pin->record_id;
    struct asteriskd_foreign_tc_plan plan;
    char error[256U];
    if (asteriskd_foreign_tc_plan_build(
            &probe, pin_record_id, &plan, error, sizeof(error)) != 0) return -1;
    if (pin == NULL) {
        struct asteriskd_recovery_record pin_record = plan.operations[0].recovery;
        pin_record.record_id = 0U;
        system->foreign_tc_probe = probe;
        (void)snprintf(system->foreign_tc_source_path,
            sizeof(system->foreign_tc_source_path), "%s", source_path);
        system->foreign_tc_pinned_object_id = 0U;
        system->foreign_tc_pin_active = true;
        int applied = asteriskd_wal_apply(
            &system->store, &system->state, &pin_record,
            &system_wal_backend, system, error, sizeof(error));
        system->foreign_tc_pin_active = false;
        memset(&system->foreign_tc_probe, 0, sizeof(system->foreign_tc_probe));
        memset(system->foreign_tc_source_path, 0, sizeof(system->foreign_tc_source_path));
        if (applied != ASTERISKD_STATE_OK ||
            pin_record.record_id != pin_record_id ||
            !pin_record.resource.bpf_pin.has_object_id ||
            pin_record.resource.bpf_pin.object_id != probe.program_object_id) return -1;
    }
    struct asteriskd_recovery_record filter = plan.operations[1].recovery;
    filter.record_id = 0U;
    return asteriskd_wal_apply(
        &system->store, &system->state, &filter,
        &system_wal_backend, system, error, sizeof(error)) == ASTERISKD_STATE_OK ? 0 : -1;
}

static int system_tc_slot_for_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *prototype,
    enum asteriskd_tc_slot_state *slot) {
    bool present = false;
    if (system_tc_probe_qdisc(system, &prototype->resource.tc_qdisc, &present) != 0) return -1;
    if (!present) *slot = ASTERISKD_TC_SLOT_ABSENT;
    else if (system_durable_rule_record(system, prototype) != NULL) {
        *slot = ASTERISKD_TC_SLOT_OWNED;
    } else {
        *slot = ASTERISKD_TC_SLOT_COMPATIBLE;
    }
    return 0;
}

static int system_tc_slot_for_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *prototype,
    enum asteriskd_tc_slot_state *slot) {
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (system_tc_probe_filter(system, &prototype->resource.tc_filter, &state) != 0) return -1;
    if (state == ASTERISKD_RULES_SLOT_ABSENT) *slot = ASTERISKD_TC_SLOT_ABSENT;
    else if (state == ASTERISKD_RULES_SLOT_OWNED &&
        system_durable_rule_record(system, prototype) != NULL) {
        *slot = ASTERISKD_TC_SLOT_OWNED;
    } else {
        *slot = ASTERISKD_TC_SLOT_FOREIGN;
    }
    return 0;
}

static int system_tc_apply_record(struct asteriskd_system_supervisor *system,
    const struct asteriskd_recovery_record *prototype) {
    const struct asteriskd_recovery_record *durable =
        system_durable_rule_record(system, prototype);
    char error[128U];
    if (durable != NULL) {
        struct asteriskd_wal_applied_identity_delta delta;
        return system_wal_apply(system, durable, 1U, error, sizeof(error)) == 0 &&
            system_wal_verify_applied(
                system, durable, &delta, error, sizeof(error)) == 0 ? 0 : -1;
    }
    struct asteriskd_recovery_record record = *prototype;
    return asteriskd_wal_apply(&system->store, &system->state, &record,
        &system_wal_backend, system, error, sizeof(error)) == ASTERISKD_STATE_OK ? 0 : -1;
}

static int system_reconcile_hotspot_tc_interface(
    struct asteriskd_system_supervisor *system, const char *name, uint32_t index) {
    struct asteriskd_tc_interface_probe probe;
    memset(&probe, 0, sizeof(probe));
    if (snprintf(probe.interface_name, sizeof(probe.interface_name), "%s", name) <= 0) return -1;
    probe.interface_index = index;
    struct asteriskd_sysctl_resource sysctl;
    memset(&sysctl, 0, sizeof(sysctl));
    sysctl.sysctl_id = ASTERISKD_SYSCTL_ROUTE_LOCALNET;
    if (snprintf(sysctl.interface_name, sizeof(sysctl.interface_name), "%s", name) <= 0) return -1;
    sysctl.interface_index = index;
    if (system_sysctl_read(&sysctl, &probe.route_localnet_value) != 0) return -1;

    struct asteriskd_recovery_record qdisc;
    memset(&qdisc, 0, sizeof(qdisc));
    qdisc.status = ASTERISKD_RECOVERY_INTENT;
    qdisc.kind = ASTERISKD_RECOVERY_TC_QDISC;
    qdisc.resource.tc_qdisc.qdisc_id = ASTERISKD_QDISC_HOTSPOT_CLSACT;
    qdisc.resource.tc_qdisc.interface_index = index;
    (void)snprintf(qdisc.resource.tc_qdisc.interface_name,
        sizeof(qdisc.resource.tc_qdisc.interface_name), "%s", name);
    if (system_tc_slot_for_qdisc(system, &qdisc, &probe.qdisc) != 0) return -1;

    struct asteriskd_recovery_record filter;
    memset(&filter, 0, sizeof(filter));
    filter.status = ASTERISKD_RECOVERY_INTENT;
    filter.kind = ASTERISKD_RECOVERY_TC_FILTER;
    filter.resource.tc_filter.ownership = ASTERISKD_TC_OWNERSHIP_DAEMON;
    filter.resource.tc_filter.inverse = ASTERISKD_TC_INVERSE_REMOVE;
    filter.resource.tc_filter.interface_index = index;
    filter.resource.tc_filter.program_type = ASTERISKD_PROGRAM_TYPE_SCHED_CLS;
    (void)snprintf(filter.resource.tc_filter.interface_name,
        sizeof(filter.resource.tc_filter.interface_name), "%s", name);
    filter.resource.tc_filter.filter_id = ASTERISKD_FILTER_HOTSPOT_EGRESS;
    filter.resource.tc_filter.direction = ASTERISKD_TC_DIRECTION_EGRESS;
    filter.resource.tc_filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS;
    if (system_tc_slot_for_filter(system, &filter, &probe.egress) != 0) return -1;
    filter.resource.tc_filter.filter_id = ASTERISKD_FILTER_HOTSPOT_INGRESS;
    filter.resource.tc_filter.direction = ASTERISKD_TC_DIRECTION_INGRESS;
    filter.resource.tc_filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS;
    if (system_tc_slot_for_filter(system, &filter, &probe.ingress) != 0) return -1;

    struct asteriskd_tc_plan plan;
    char error[128U];
    if (asteriskd_tc_install_plan_build(&system->loaded_config.config,
            &probe, &plan, error, sizeof(error)) != 0) return -1;
    for (size_t operation = 0U; operation < plan.operation_count; ++operation) {
        if (system_tc_apply_record(system, &plan.operations[operation].recovery) != 0) return -1;
    }
    return 0;
}

static int system_reconcile_hotspot_tc(struct asteriskd_system_supervisor *system) {
    bool bpf2socks = system->loaded_config.config.mode == ASTERISKD_MODE_BPF2SOCKS;
    bool foreign_ipv6 = system->loaded_config.config.enable_ipv6 &&
        system->loaded_config.config.mode != ASTERISKD_MODE_EBPF;
    if (!bpf2socks && !foreign_ipv6) return 0;
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    char handled[ASTERISKD_MAX_ADDRESSES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t handled_count = 0U;
    int result = 0;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_name == NULL || !system_hotspot_interface_selected(
                &system->loaded_config.config, entry->ifa_name)) continue;
        bool duplicate = false;
        for (size_t index = 0U; index < handled_count; ++index) {
            if (strcmp(handled[index], entry->ifa_name) == 0) duplicate = true;
        }
        if (duplicate) continue;
        if (handled_count >= ASTERISKD_MAX_ADDRESSES) {
            result = -1;
            break;
        }
        uint32_t interface_index = if_nametoindex(entry->ifa_name);
        if (interface_index == 0U || snprintf(handled[handled_count],
                sizeof(handled[handled_count]), "%s", entry->ifa_name) <= 0 ||
            (bpf2socks && system_reconcile_hotspot_tc_interface(
                system, entry->ifa_name, interface_index) != 0) ||
            (foreign_ipv6 && system_reconcile_foreign_hotspot_filter(
                system, entry->ifa_name, interface_index) != 0)) {
            result = -1;
            break;
        }
        ++handled_count;
    }
    freeifaddrs(addresses);
    return result;
}

static bool system_record_interface_generation_retired(
    const struct asteriskd_recovery_record *record) {
    const char *name = NULL;
    uint32_t expected_index = 0U;
    if (record->kind == ASTERISKD_RECOVERY_SYSCTL) {
        name = record->resource.sysctl.interface_name;
        expected_index = record->resource.sysctl.interface_index;
    } else if (record->kind == ASTERISKD_RECOVERY_TC_QDISC) {
        name = record->resource.tc_qdisc.interface_name;
        expected_index = record->resource.tc_qdisc.interface_index;
    } else if (record->kind == ASTERISKD_RECOVERY_TC_FILTER) {
        name = record->resource.tc_filter.interface_name;
        expected_index = record->resource.tc_filter.interface_index;
    } else {
        return false;
    }
    return expected_index > 0U && name != NULL && name[0] != '\0' &&
        if_nametoindex(name) != expected_index;
}

static int system_recover_retired_interface_records(
    struct asteriskd_system_supervisor *system) {
    size_t index = 0U;
    char error[128U];
    while (index < system->state.recovery.record_count) {
        const struct asteriskd_recovery_record *record =
            &system->state.recovery.records[index];
        if (!system_record_interface_generation_retired(record)) {
            ++index;
            continue;
        }
        uint64_t record_id = record->record_id;
        uint64_t recovery_pin_record_id =
            record->kind == ASTERISKD_RECOVERY_TC_FILTER &&
            record->resource.tc_filter.ownership == ASTERISKD_TC_OWNERSHIP_FOREIGN_SNAPSHOT
                ? record->resource.tc_filter.recovery_pin_record_id : 0U;
        int recovered = asteriskd_wal_recover_record_id(
            &system->store, &system->state, record_id,
            &system_wal_backend, system, error, sizeof(error));
        if (recovered != ASTERISKD_STATE_OK) return -1;
        if (recovery_pin_record_id != 0U) {
            recovered = asteriskd_wal_recover_record_id(
                &system->store, &system->state, recovery_pin_record_id,
                &system_wal_backend, system, error, sizeof(error));
            if (recovered != ASTERISKD_STATE_OK &&
                recovered != ASTERISKD_WAL_INCOMPLETE) return -1;
        }
    }
    return 0;
}

static uint32_t system_rule_categories(const struct asteriskd_config *config) {
    uint32_t categories = 0U;
    if (config->mode == ASTERISKD_MODE_TPROXY) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_TPROXY) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_ROUTING) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_LOCAL_BYPASS);
    } else if (config->mode == ASTERISKD_MODE_TUN ||
        config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_ROUTING) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_LOCAL_BYPASS);
    } else if (config->mode == ASTERISKD_MODE_BPF2SOCKS) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_BPF);
        if (config->hotspot_interface_prefix_count != 0U) {
            categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_TC) |
                ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_HOTSPOT);
        }
    }
    if (config->matcher.enabled) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_BPF);
    }
    if (config->hotspot_interface_prefix_count != 0U) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_HOTSPOT);
    }
    if (config->enable_local_dns) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_DNS);
    }
    if (config->enable_fake_dns) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_FAKE_DNS);
    }
    if (config->disable_system_ipv6) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_IPV6_GUARD);
    }
    return categories;
}

enum system_recovery_identity_state {
    SYSTEM_RECOVERY_IDENTITY_ABSENT,
    SYSTEM_RECOVERY_IDENTITY_MATCH,
    SYSTEM_RECOVERY_IDENTITY_MISMATCH,
    SYSTEM_RECOVERY_IDENTITY_UNREADABLE,
};

static bool system_recovery_identity_equal(
    const struct asteriskd_child_identity *left,
    const struct asteriskd_child_identity *right) {
    if (left->role != right->role || left->type != right->type ||
        left->pid != right->pid || left->process_group_id != right->process_group_id ||
        left->start_time_ticks != right->start_time_ticks ||
        left->exe_device != right->exe_device || left->exe_inode != right->exe_inode ||
        left->argc != right->argc) return false;
    for (size_t index = 0U; index < left->argc; ++index) {
        if (strcmp(left->argv[index], right->argv[index]) != 0) return false;
    }
    return true;
}

static enum system_recovery_identity_state system_recovery_identity_classify(
    const struct asteriskd_child_identity *identity,
    const struct asteriskd_process_spec *spec) {
    if (identity == NULL || spec == NULL || identity->pid <= 0 ||
        identity->process_group_id != identity->pid) return SYSTEM_RECOVERY_IDENTITY_UNREADABLE;
    errno = 0;
    if (kill(identity->pid, 0) != 0 && errno == ESRCH) return SYSTEM_RECOVERY_IDENTITY_ABSENT;
    if (errno != 0 && errno != EPERM) return SYSTEM_RECOVERY_IDENTITY_UNREADABLE;
    const struct asteriskd_process_identity_backend *backend =
        asteriskd_system_process_identity_backend();
    if (backend == NULL) return SYSTEM_RECOVERY_IDENTITY_UNREADABLE;
    char stat_text[4096U];
    size_t stat_length = 0U;
    uint64_t device = 0U;
    uint64_t inode = 0U;
    unsigned char cmdline[ASTERISKD_MAX_PROCESS_ARGV * ASTERISKD_MAX_CHILD_ARG + 1U];
    size_t cmdline_length = 0U;
    bool readable = backend->read_stat(backend->context, identity->pid,
            stat_text, sizeof(stat_text) - 1U, &stat_length) == 0 &&
        backend->read_exe_identity(
            backend->context, identity->pid, &device, &inode) == 0 &&
        backend->read_cmdline(backend->context, identity->pid,
            cmdline, sizeof(cmdline), &cmdline_length) == 0;
    if (!readable) {
        errno = 0;
        return kill(identity->pid, 0) != 0 && errno == ESRCH
            ? SYSTEM_RECOVERY_IDENTITY_ABSENT : SYSTEM_RECOVERY_IDENTITY_UNREADABLE;
    }
    struct asteriskd_child_identity observed;
    char error[64U];
    if (asteriskd_process_identity_read(backend, identity->pid,
            identity->role, identity->type, spec, &observed,
            error, sizeof(error)) != 0) return SYSTEM_RECOVERY_IDENTITY_MISMATCH;
    return system_recovery_identity_equal(identity, &observed)
        ? SYSTEM_RECOVERY_IDENTITY_MATCH : SYSTEM_RECOVERY_IDENTITY_MISMATCH;
}

static int system_recovery_spec_from_identity(
    const struct asteriskd_child_identity *identity,
    const struct asteriskd_config *config,
    struct asteriskd_process_spec *spec) {
    if (identity == NULL || config == NULL || spec == NULL || identity->argc == 0U ||
        identity->argc > ASTERISKD_MAX_CHILD_ARGV) return -1;
    memset(spec, 0, sizeof(*spec));
    if (snprintf(spec->executable_path, sizeof(spec->executable_path), "%s",
            identity->argv[0]) <= 0 ||
        snprintf(spec->working_directory, sizeof(spec->working_directory), "%s",
            config->working_directory) <= 0) return -1;
    spec->argc = identity->argc;
    for (size_t index = 0U; index < identity->argc; ++index) {
        if (snprintf(spec->argv[index], sizeof(spec->argv[index]), "%s",
                identity->argv[index]) <= 0) return -1;
    }
    return 0;
}

struct system_recovery_wait {
    struct asteriskd_system_supervisor *system;
    const struct asteriskd_child_identity *core;
    const struct asteriskd_process_spec *core_spec;
    const struct asteriskd_child_identity *helper;
    const struct asteriskd_process_spec *helper_spec;
    bool unreadable;
};

static bool system_recovery_children_gone(void *opaque) {
    struct system_recovery_wait *wait = opaque;
    const struct asteriskd_child_identity *identities[2U] = {wait->core, wait->helper};
    const struct asteriskd_process_spec *specs[2U] = {wait->core_spec, wait->helper_spec};
    bool gone = true;
    for (size_t index = 0U; index < 2U; ++index) {
        if (identities[index] == NULL) continue;
        enum system_recovery_identity_state state =
            system_recovery_identity_classify(identities[index], specs[index]);
        if (state == SYSTEM_RECOVERY_IDENTITY_MATCH) gone = false;
        else if (state == SYSTEM_RECOVERY_IDENTITY_UNREADABLE) wait->unreadable = true;
    }
    return gone || wait->unreadable;
}

static int system_recovery_signal_if_matching(
    const struct asteriskd_child_identity *identity,
    const struct asteriskd_process_spec *spec,
    int signal_number) {
    if (identity == NULL) return 0;
    enum system_recovery_identity_state state =
        system_recovery_identity_classify(identity, spec);
    if (state == SYSTEM_RECOVERY_IDENTITY_ABSENT ||
        state == SYSTEM_RECOVERY_IDENTITY_MISMATCH) return 0;
    if (state != SYSTEM_RECOVERY_IDENTITY_MATCH) return -1;
    return kill(-identity->process_group_id, signal_number);
}

static int system_recovery_stop_children(struct asteriskd_system_supervisor *system) {
    system->recovery_kill_escalated = false;
    const struct asteriskd_child_identity *core = system->state.children.core_present
        ? &system->state.children.core : NULL;
    const struct asteriskd_child_identity *helper = system->state.children.helper_present
        ? &system->state.children.helper : NULL;
    if (core == NULL && helper == NULL) return 0;
    struct asteriskd_process_spec core_spec;
    struct asteriskd_process_spec helper_spec;
    memset(&core_spec, 0, sizeof(core_spec));
    memset(&helper_spec, 0, sizeof(helper_spec));
    if ((core != NULL && system_recovery_spec_from_identity(
            core, &system->loaded_config.config, &core_spec) != 0) ||
        (helper != NULL && system_recovery_spec_from_identity(
            helper, &system->loaded_config.config, &helper_spec) != 0)) return -1;
    if (system_recovery_signal_if_matching(helper,
            helper == NULL ? NULL : &helper_spec, SIGTERM) != 0 ||
        system_recovery_signal_if_matching(core,
            core == NULL ? NULL : &core_spec, SIGTERM) != 0) return -1;
    struct system_recovery_wait wait = {
        .system = system,
        .core = core,
        .core_spec = core == NULL ? NULL : &core_spec,
        .helper = helper,
        .helper_spec = helper == NULL ? NULL : &helper_spec,
    };
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true,
        .monotonic_milliseconds = now + (int64_t)ASTERISKD_PROCESS_TERM_GRACE_MILLIS,
    };
    if (!system_recovery_children_gone(&wait)) {
        (void)system_pump_condition(system, &deadline, system_recovery_children_gone);
    }
    if (wait.unreadable) return -1;
    if (!system_recovery_children_gone(&wait)) {
        system->recovery_kill_escalated = true;
        if (system_recovery_signal_if_matching(helper,
                helper == NULL ? NULL : &helper_spec, SIGKILL) != 0 ||
            system_recovery_signal_if_matching(core,
                core == NULL ? NULL : &core_spec, SIGKILL) != 0 ||
            system_runtime_clock(system, &now) != 0) return -1;
        deadline.monotonic_milliseconds = now + (int64_t)ASTERISKD_PROCESS_KILL_REAP_MILLIS;
        (void)system_pump_condition(system, &deadline, system_recovery_children_gone);
    }
    if (wait.unreadable || !system_recovery_children_gone(&wait)) return -1;
    if (helper != NULL && asteriskd_state_clear_child(
            &system->state, ASTERISKD_CHILD_HELPER) != ASTERISKD_STATE_OK) return -1;
    if (core != NULL && asteriskd_state_clear_child(
            &system->state, ASTERISKD_CHILD_CORE) != ASTERISKD_STATE_OK) return -1;
    return system_effect_save(system, &system->state);
}

static bool system_recovery_used_dummy_ipv6(
    const struct asteriskd_state_document *state) {
    for (size_t index = 0U; index < state->recovery.record_count; ++index) {
        if (state->recovery.records[index].kind == ASTERISKD_RECOVERY_DUMMY_INTERFACE &&
            state->recovery.records[index].resource.dummy_interface.interface_id ==
                ASTERISKD_INTERFACE_IPV6_DUMMY) return true;
    }
    return false;
}

static int system_recovery_publish_event(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_control_event_type type) {
    struct asteriskd_control_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    if (asteriskd_control_snapshot_from_state(
            &system->state, &system->live, &snapshot) != 0) return -1;
    int result = system_effect_event(system, type, &snapshot,
        snapshot.has_error ? &snapshot.error : NULL, snapshot.has_error);
    asteriskd_control_snapshot_destroy(&snapshot);
    return result;
}

static int system_recover_ebpf_boundary(
    struct asteriskd_system_supervisor *system) {
    if (asteriskd_state_set_phase(&system->state, ASTERISKD_PHASE_STARTING) !=
            ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0 ||
        system_recovery_publish_event(system, ASTERISKD_CONTROL_EVENT_STARTING) != 0) return -1;
    struct asteriskd_child_identity identity;
    memset(&identity, 0, sizeof(identity));
    if (system_effect_start_core(system, &identity) != 0) {
        if (!system->core_spawned) return -1;
        goto cleanup_core;
    }
    if (asteriskd_state_set_child(&system->state, &identity, NULL, 0U) != ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0) goto cleanup_core;
    if (system_effect_wait_core(system) != 0 || system->recovery_cancelled) goto cleanup_core;

cleanup_core:
    if (asteriskd_state_set_phase(&system->state, ASTERISKD_PHASE_STOPPING) !=
            ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0 ||
        system_recovery_publish_event(system, ASTERISKD_CONTROL_EVENT_STOPPING) != 0 ||
        system_effect_stop_core(system) != 0) return -1;
    if (system->state.children.core_present && asteriskd_state_clear_child(
            &system->state, ASTERISKD_CHILD_CORE) != ASTERISKD_STATE_OK) return -1;
    system->state.recovery.core_owned_ebpf_boundary = false;
    if (system_effect_save(system, &system->state) != 0) return -1;
    char error[256U];
    if (asteriskd_wal_recover(&system->store, &system->state,
            &system_wal_backend, system, error, sizeof(error)) != ASTERISKD_STATE_OK ||
        asteriskd_state_mark_stopped(
            &system->state, error, sizeof(error)) != ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0 ||
        system_recovery_publish_event(system, ASTERISKD_CONTROL_EVENT_STOPPED) != 0) return -1;
    return 0;
}

static bool system_has_ebpf_boundary(
    const struct asteriskd_state_document *state) {
    return state != NULL && state->initialized &&
        state->owner == ASTERISKD_OWNER_BOX &&
        state->core_type == ASTERISKD_CORE_SING_BOX &&
        state->mode == ASTERISKD_MODE_EBPF &&
        state->recovery.core_owned_ebpf_boundary;
}

static int system_prepare_ebpf_boundary(
    struct asteriskd_system_supervisor *system) {
    if (!system_has_ebpf_boundary(&system->state)) return -1;
    if (asteriskd_state_set_phase(&system->state, ASTERISKD_PHASE_RECOVERING) !=
            ASTERISKD_STATE_OK || system_effect_save(system, &system->state) != 0) return -1;
    if ((system->state.children.core_present || system->state.children.helper_present) &&
        system_recovery_stop_children(system) != 0) return -1;
    if (system->recovery_kill_escalated) return -1;
    char error[128U];
    if (asteriskd_state_set_matcher(&system->state, false, false) != ASTERISKD_STATE_OK ||
        asteriskd_state_set_rules(&system->state, false, 0U, 0U) != ASTERISKD_STATE_OK) return -1;
    if (!system->state.failure.present && asteriskd_state_set_failure(
            &system->state, ASTERISKD_FAILURE_START_FAILED,
            ASTERISKD_COMPONENT_CORE, "core-owned eBPF cleanup pending",
            false, 0, false, 0, error, sizeof(error)) != ASTERISKD_STATE_OK) return -1;
    if (asteriskd_state_set_phase(&system->state, ASTERISKD_PHASE_FAILED) !=
            ASTERISKD_STATE_OK || system_effect_save(system, &system->state) != 0) return -1;
    return 0;
}

static int system_stopped_iptables_residue_inspect(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_rule_transaction_plan *plan,
    bool *present) {
    if (system == NULL || plan == NULL || present == NULL) return -1;
    *present = false;
    for (size_t group_index = 0U;
            group_index < plan->private_group_count; ++group_index) {
        const struct asteriskd_private_chain_group *group =
            &plan->private_groups[group_index];
        const struct system_rule_view *view =
            &system->rule_snapshot.xtables[group->family][group->table];
        if (!view->present) return -1;
        for (size_t name_index = 0U; name_index < group->name_count; ++name_index) {
            size_t declarations = 0U;
            size_t rules = 0U;
            const char *name = group->names[name_index];
            if (asteriskd_xtables_private_chain_counts(
                    view->bytes, view->length, name,
                    &declarations, &rules) != 0) return -1;
            if (declarations == 0U && rules == 0U) continue;
            if (declarations != 1U ||
                system_verify_private_chain_contents(system, group, name) != 0) return -1;
            *present = true;
        }
    }
    for (size_t group_index = 0U;
            group_index < plan->hook_group_count; ++group_index) {
        const struct asteriskd_traffic_hook_group *group =
            &plan->hook_groups[group_index];
        for (size_t hook_index = 0U; hook_index < group->hook_count; ++hook_index) {
            size_t matches = 0U;
            size_t position = 0U;
            if (system_hook_match_count(system, group, &group->hooks[hook_index],
                    &matches, &position) != 0 || matches > 1U) return -1;
            if (matches == 1U) *present = true;
        }
    }
    return 0;
}

static int system_cleanup_stopped_iptables_residue(
    struct asteriskd_system_supervisor *system) {
    if (!system->rules_initialized) system_rules_backend_init(system);
    if (system_detect_global_ipv6(&system->has_global_ipv6_address) != 0 ||
        asteriskd_rule_transaction_plan_build(
            &system->loaded_config.config, system->has_global_ipv6_address,
            &system->rules_runtime.plan) != 0) return -1;
    const struct asteriskd_rule_transaction_plan *plan = &system->rules_runtime.plan;
    if (plan->no_op) return 0;
    struct asteriskd_rule_transaction_plan snapshot_plan = *plan;
    snapshot_plan.route_count = 0U;
    if (system_rule_snapshot_capture(system, &snapshot_plan,
            SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY) != 0) return -1;
    bool present = false;
    if (system_stopped_iptables_residue_inspect(system, plan, &present) != 0) goto failed;
    if (!present) {
        system_rule_snapshot_destroy(&system->rule_snapshot);
        return 0;
    }
    if (system_rule_batch_begin(&system->rule_commands) != 0) goto failed;
    for (size_t remaining = plan->hook_group_count; remaining > 0U; --remaining) {
        if (system_remove_hook_group(
                system, &plan->hook_groups[remaining - 1U]) != 0) goto failed;
    }
    for (size_t remaining = plan->private_group_count; remaining > 0U; --remaining) {
        if (system_remove_private_group(
                system, &plan->private_groups[remaining - 1U]) != 0) goto failed;
    }
    if (system_rule_batch_flush_xtables(system) != 0) goto failed;
    system_rule_batch_destroy(&system->rule_commands);
    if (system_rule_snapshot_capture(system, &snapshot_plan,
            SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) != 0) goto failed;
    present = false;
    if (system_stopped_iptables_residue_inspect(system, plan, &present) != 0 || present) {
        goto failed;
    }
    system_rule_snapshot_destroy(&system->rule_snapshot);
    (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_INFO,
        ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC,
        "removed verified asteriskd iptables residue from stopped state");
    return 0;

failed:
    system_rule_batch_destroy(&system->rule_commands);
    system_rule_snapshot_destroy(&system->rule_snapshot);
    return -1;
}

static int system_cleanup_stopped_bpf2_tc_interface(
    struct asteriskd_system_supervisor *system,
    const char *name, uint32_t index) {
    struct asteriskd_tc_filter_resource filter;
    memset(&filter, 0, sizeof(filter));
    filter.ownership = ASTERISKD_TC_OWNERSHIP_DAEMON;
    filter.inverse = ASTERISKD_TC_INVERSE_REMOVE;
    filter.interface_index = index;
    filter.program_type = ASTERISKD_PROGRAM_TYPE_SCHED_CLS;
    if (snprintf(filter.interface_name,
            sizeof(filter.interface_name), "%s", name) <= 0) return -1;
    filter.filter_id = ASTERISKD_FILTER_HOTSPOT_EGRESS;
    filter.direction = ASTERISKD_TC_DIRECTION_EGRESS;
    filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS;
    if (system_tc_remove_filter(system, &filter) != 0) return -1;
    filter.filter_id = ASTERISKD_FILTER_HOTSPOT_INGRESS;
    filter.direction = ASTERISKD_TC_DIRECTION_INGRESS;
    filter.program_id = ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS;
    return system_tc_remove_filter(system, &filter);
}

static int system_cleanup_stopped_bpf2_tc(
    struct asteriskd_system_supervisor *system) {
    struct ifaddrs *addresses = NULL;
    if (getifaddrs(&addresses) != 0) return -1;
    char handled[ASTERISKD_MAX_ADDRESSES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t handled_count = 0U;
    int result = 0;
    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_name == NULL || !system_hotspot_interface_selected(
                &system->loaded_config.config, entry->ifa_name)) continue;
        bool duplicate = false;
        for (size_t index = 0U; index < handled_count; ++index) {
            if (strcmp(handled[index], entry->ifa_name) == 0) duplicate = true;
        }
        if (duplicate) continue;
        uint32_t interface_index = if_nametoindex(entry->ifa_name);
        if (handled_count >= ASTERISKD_MAX_ADDRESSES || interface_index == 0U ||
            snprintf(handled[handled_count], sizeof(handled[handled_count]),
                "%s", entry->ifa_name) <= 0 ||
            system_cleanup_stopped_bpf2_tc_interface(
                system, entry->ifa_name, interface_index) != 0) {
            result = -1;
            break;
        }
        ++handled_count;
    }
    freeifaddrs(addresses);
    return result;
}

static int system_cleanup_stopped_bpf_residue(
    struct asteriskd_system_supervisor *system) {
    const struct asteriskd_bpf_program_backend *program_backend =
        asteriskd_system_bpf_program_backend();
    const struct asteriskd_bpf_pin_ownership_backend *ownership_backend =
        asteriskd_system_bpf_pin_ownership_backend();
    char error[256U];
    bool removed = false;
    if (system->loaded_config.config.matcher.enabled) {
        if (asteriskd_matcher_pin_plan_build(
                &system->loaded_config.config, &system->matcher_pin_plan) != 0) return -1;
        system->matcher_plan_ready = true;
        struct asteriskd_matcher_verification verification;
        if (asteriskd_matcher_verify_residue(
                &system->loaded_config.config, &system->matcher_pin_plan,
                program_backend, ownership_backend, &verification,
                error, sizeof(error)) != 0) return -1;
        for (size_t index = 0U; index < verification.pin_count; ++index) {
            const char *path = system_pin_path(system, verification.pins[index].pin_id);
            if (path == NULL || asteriskd_bpf_pin_cleanup_owned(
                    path, verification.pins[index].object_id,
                    ownership_backend, error, sizeof(error)) != 0) return -1;
            removed = true;
        }
    }
    if (system->loaded_config.config.mode == ASTERISKD_MODE_BPF2SOCKS) {
        if (asteriskd_bpf2_pin_plan_build(
                &system->loaded_config.config, &system->bpf2_pin_plan) != 0) return -1;
        system->bpf2_plan_ready = true;
        if (asteriskd_bpf2_verify_residue(
                &system->loaded_config.config, &system->bpf2_pin_plan,
                program_backend, ownership_backend, &system->bpf2_verification,
                error, sizeof(error)) != 0) return -1;
        system->bpf2_verified = true;
        if (system->bpf2_verification.pin_count != 0U &&
            system_cleanup_stopped_bpf2_tc(system) != 0) return -1;
        for (size_t index = 0U;
                index < system->bpf2_verification.pin_count; ++index) {
            const struct asteriskd_bpf2_verified_pin *pin =
                &system->bpf2_verification.pins[index];
            const char *path = system_pin_path(system, pin->pin_id);
            if (path == NULL || asteriskd_bpf_pin_cleanup_owned(
                    path, pin->object_id, ownership_backend,
                    error, sizeof(error)) != 0) return -1;
            removed = true;
        }
        memset(&system->bpf2_verification, 0, sizeof(system->bpf2_verification));
        system->bpf2_verified = false;
    }
    if (removed) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_INFO,
            ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC,
            "removed verified asteriskd BPF residue from stopped state");
    }
    return 0;
}

static int system_recover_state(struct asteriskd_system_supervisor *system) {
    if (asteriskd_state_is_canonical_stopped(&system->state)) {
        return system_cleanup_stopped_iptables_residue(system) == 0
            ? system_cleanup_stopped_bpf_residue(system) : -1;
    }
    system->cleanup_in_progress = true;
    if (system_has_ebpf_boundary(&system->state)) {
        if (system_prepare_ebpf_boundary(system) != 0) return -1;
        return system->recovery_only ? system_recover_ebpf_boundary(system) : 0;
    }
    if (asteriskd_state_set_phase(
            &system->state, ASTERISKD_PHASE_RECOVERING) != ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0) return -1;
    system_rules_backend_init(system);
    bool recovery_has_global_ipv6 = !system_recovery_used_dummy_ipv6(&system->state);
    if (asteriskd_rule_transaction_plan_build(&system->loaded_config.config,
            recovery_has_global_ipv6, &system->rules_runtime.plan) != 0 ||
        asteriskd_rules_recover(system->state.recovery.records,
            system->state.recovery.record_count, &system->rules_backend) != 0 ||
        system_recovery_stop_children(system) != 0) return -1;
    char error[256U];
    if (asteriskd_wal_recover(&system->store, &system->state,
            &system_wal_backend, system, error, sizeof(error)) != ASTERISKD_STATE_OK ||
        asteriskd_state_set_matcher(&system->state,
            system->loaded_config.config.matcher.enabled, false) != ASTERISKD_STATE_OK ||
        asteriskd_state_set_rules(&system->state, false, 0U, 0U) != ASTERISKD_STATE_OK) return -1;
    if (system->recovery_only) {
        if (asteriskd_state_set_phase(&system->state, ASTERISKD_PHASE_STOPPING) !=
                ASTERISKD_STATE_OK ||
            system_effect_save(system, &system->state) != 0) return -1;
        if (system_recovery_publish_event(
                system, ASTERISKD_CONTROL_EVENT_STOPPING) != 0) return -1;
    }
    if (
        asteriskd_state_mark_stopped(&system->state, error, sizeof(error)) != ASTERISKD_STATE_OK ||
        system_effect_save(system, &system->state) != 0) return -1;
    if (system->recovery_only) {
        if (system_recovery_publish_event(
                system, ASTERISKD_CONTROL_EVENT_STOPPED) != 0) return -1;
    }
    return 0;
}

static int system_effect_rules(void *opaque, bool *active,
    uint64_t *generation, uint32_t *categories) {
    struct asteriskd_system_supervisor *system = opaque;
    if (active == NULL || generation == NULL || categories == NULL) return -1;
    system->rules_verified = false;
    if (!system->rules_initialized) system_rules_backend_init(system);
    if (system_detect_global_ipv6(&system->has_global_ipv6_address) != 0) return -1;
    if (system->network_opened && !system->network.no_op) {
        int64_t now = 0;
        char error[128U];
        if (system_runtime_clock(system, &now) != 0 ||
            asteriskd_network_handle(
                &system->network, (uint64_t)now, error, sizeof(error)) != 0 ||
            asteriskd_network_apply_immediate(
                &system->network, error, sizeof(error)) != 0 ||
            system_detect_global_ipv6(&system->has_global_ipv6_address) != 0) return -1;
    }
    const char *failed_stage = NULL;
    if (system_capture_local_address_snapshot(system) != 0) {
        failed_stage = "local-address-snapshot";
    } else if (asteriskd_rules_install(&system->rules_runtime,
            &system->loaded_config.config, system->has_global_ipv6_address,
            &system->rules_backend) != 0) {
        failed_stage = "install";
    } else if (system_reconcile_bpf2_local_maps(system) != 0) {
        failed_stage = "bpf2-local-map-reconcile";
    } else if (system_reconcile_hotspot_tc(system) != 0) {
        failed_stage = "hotspot-tc-reconcile";
    } else if (asteriskd_rules_verify(
            &system->rules_runtime, &system->rules_backend) != 0) {
        failed_stage = "verify";
    }
    system_rule_snapshot_destroy(&system->rule_snapshot);
    if (failed_stage != NULL) {
        char message[160U];
        int written = snprintf(message, sizeof(message),
            "rules apply failed: stage=%s", failed_stage);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    system->rules_verified = true;
    if (system->loaded_config.config.mode == ASTERISKD_MODE_EBPF) {
        *active = false;
        *generation = 0U;
        *categories = 0U;
    } else {
        *active = true;
        *generation = system->rules_runtime.generation;
        *categories = system_rule_categories(&system->loaded_config.config);
    }
    return 0;
}

static int system_effect_reconcile(void *opaque, bool *active,
    uint64_t *generation, uint32_t *categories) {
    struct asteriskd_system_supervisor *system = opaque;
    if (active == NULL || generation == NULL || categories == NULL ||
        !system->rules_initialized) return -1;
    system->rules_verified = false;
    const char *failed_stage = NULL;
    if (system_capture_local_address_snapshot(system) != 0) {
        failed_stage = "local-address-snapshot";
    } else if (system_recover_retired_interface_records(system) != 0) {
        failed_stage = "retired-interface-recovery";
    } else if (system_reconcile_iptables_local_bypass(system) != 0) {
        failed_stage = "iptables-local-bypass";
    } else if (system_rule_snapshot_capture(
            system, &system->rules_runtime.plan,
            SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY) != 0) {
        failed_stage = "rules-snapshot-before-reconcile";
    } else if (asteriskd_rules_reconcile(
            &system->rules_runtime, &system->rules_backend) != 0) {
        failed_stage = "rules-reconcile";
    } else if (system_rule_snapshot_capture(
            system, &system->rules_runtime.plan,
            SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) != 0) {
        failed_stage = "rules-snapshot-after-reconcile";
    } else if (system_reconcile_bpf2_local_maps(system) != 0) {
        failed_stage = "bpf2-local-map";
    } else if (system_reconcile_hotspot_tc(system) != 0) {
        failed_stage = "hotspot-tc";
    } else if (asteriskd_rules_verify(
            &system->rules_runtime, &system->rules_backend) != 0) {
        failed_stage = "rules-verify";
    }
    system_rule_snapshot_destroy(&system->rule_snapshot);
    system_clear_local_address_snapshot(system);
    if (failed_stage != NULL) {
        char message[160U];
        int written = snprintf(message, sizeof(message),
            "rules reconcile failed: stage=%s", failed_stage);
        if (written > 0 && (size_t)written < sizeof(message)) {
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
        }
        return -1;
    }
    system->rules_verified = true;
    if (system->loaded_config.config.mode == ASTERISKD_MODE_EBPF) {
        *active = false;
        *generation = 0U;
        *categories = 0U;
    } else {
        *active = true;
        *generation = system->rules_runtime.generation;
        *categories = system_rule_categories(&system->loaded_config.config);
    }
    return 0;
}

static int system_effect_network_immediate(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    char error[128U];
    return system->network_opened && asteriskd_network_apply_immediate(
        &system->network, error, sizeof(error)) == 0 ? 0 : -1;
}

static int system_effect_verify(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int result = runtime_startup_components_verified(
        system->core_identity_ready, system->core_reaped,
        system->loaded_config.config.helper.type != ASTERISKD_HELPER_NONE,
        system->helper_identity_ready, system->helper_reaped,
        system->loaded_config.config.matcher.enabled, system->matcher_verified,
        system->rules_initialized, system->rules_verified) ? 0 : -1;
    system_clear_local_address_snapshot(system);
    return result;
}

static bool system_stop_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) {
        system->stop_result = ASTERISKD_STOP_FAILED;
        return true;
    }
    system->stop_result = asteriskd_stop_coordinator_poll(
        &system->stop_coordinator, &system->stop_backend, (uint64_t)now);
    return system->stop_result != ASTERISKD_STOP_PENDING;
}

static int system_effect_stop_children(
    struct asteriskd_system_supervisor *system, bool include_helper) {
    const struct asteriskd_child_identity *core =
        system->core_spawned && !system->core_reaped ? &system->core_identity : NULL;
    const struct asteriskd_child_identity *helper = include_helper &&
        system->helper_spawned && !system->helper_reaped ? &system->helper_identity : NULL;
    if (core == NULL && helper == NULL) {
        if (include_helper) asteriskd_child_process_close(&system->helper_process);
        asteriskd_child_process_close(&system->core_process);
        return system->loaded_config.config.mode != ASTERISKD_MODE_EBPF ||
            system->ebpf_graceful_cleanup_verified ? 0 : -1;
    }
    if ((core != NULL && !system->core_identity_ready) ||
        (helper != NULL && !system->helper_identity_ready) ||
        asteriskd_system_process_backends_init(&system->process_context,
            &system->core_spec,
            system->helper_launch_ready ? &system->helper_launch.process : NULL,
            &system->readiness_backend, &system->stop_backend) != 0) return -1;
    int64_t now = 0;
    if (system_runtime_clock(system, &now) != 0) return -1;
    asteriskd_stop_coordinator_init(&system->stop_coordinator);
    system->stopping_children = true;
    system->stop_result = asteriskd_stop_coordinator_begin(
        &system->stop_coordinator, core, helper,
        &system->stop_backend, (uint64_t)now);
    if (system->stop_result == ASTERISKD_STOP_PENDING) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = (int64_t)system->stop_coordinator.kill_deadline_milliseconds,
        };
        if (system_pump_condition(system, &deadline, system_stop_done) != 0) {
            system->stop_result = ASTERISKD_STOP_FAILED;
        }
    }
    system->stopping_children = false;
    bool killed = system->stop_coordinator.core.kill_sent ||
        system->stop_coordinator.helper.kill_sent;
    if (system->stop_result == ASTERISKD_STOP_COMPLETE) {
        if (core != NULL) system->core_reaped = true;
        if (helper != NULL) system->helper_reaped = true;
    }
    if (system->loaded_config.config.mode == ASTERISKD_MODE_EBPF && core != NULL &&
        system->stop_result == ASTERISKD_STOP_COMPLETE && !killed) {
        system->ebpf_graceful_cleanup_verified = true;
    }
    if (include_helper) asteriskd_child_process_close(&system->helper_process);
    asteriskd_child_process_close(&system->core_process);
    return system->stop_result == ASTERISKD_STOP_COMPLETE && !killed ? 0 : -1;
}

static int system_effect_stop_helper(void *opaque) {
    return system_effect_stop_children(opaque, true);
}

static int system_effect_stop_core(void *opaque) {
    return system_effect_stop_children(opaque, false);
}

static int system_effect_quiesce(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    system->cleanup_in_progress = true;
    if (system->loaded_config.config.mode == ASTERISKD_MODE_EBPF) {
        return system_effect_stop_core(opaque);
    }
    if (!system->rules_initialized) return 0;
    bool cleanup_required = false;
    for (size_t index = 0U;
            index < system->rules_runtime.plan.hook_group_count; ++index) {
        if (system->rules_runtime.hook_cleanup_required[index]) {
            cleanup_required = true;
            break;
        }
    }
    if (!cleanup_required) return 0;
    struct asteriskd_rule_transaction_plan snapshot_plan =
        system->rules_runtime.plan;
    snapshot_plan.private_group_count = 0U;
    snapshot_plan.route_count = 0U;
    if (system_rule_snapshot_capture(system, &snapshot_plan,
            SYSTEM_RULE_SNAPSHOT_BEFORE_APPLY) != 0 ||
        system_rule_batch_begin(&system->rule_commands) != 0) goto failed;
    for (size_t remaining = system->rules_runtime.plan.hook_group_count;
            remaining > 0U; --remaining) {
        size_t index = remaining - 1U;
        if (system->rules_runtime.hook_cleanup_required[index]) {
            if (system_remove_hook_group(system,
                    &system->rules_runtime.plan.hook_groups[index]) != 0) goto failed;
        }
    }
    if (system_rule_batch_flush_xtables(system) != 0) goto failed;
    system_rule_batch_destroy(&system->rule_commands);
    if (system_rule_snapshot_capture(system, &snapshot_plan,
            SYSTEM_RULE_SNAPSHOT_AFTER_APPLY) != 0) goto failed;
    for (size_t index = 0U;
            index < system->rules_runtime.plan.hook_group_count; ++index) {
        if (!system->rules_runtime.hook_cleanup_required[index]) continue;
        bool all_present = false;
        bool any_present = false;
        if (system_probe_hook_group(system,
                &system->rules_runtime.plan.hook_groups[index],
                &all_present, &any_present) != 0 || any_present) goto failed;
        system->rules_runtime.hook_cleanup_required[index] = false;
    }
    system_rule_snapshot_destroy(&system->rule_snapshot);
    return 0;

failed:
    system_rule_batch_destroy(&system->rule_commands);
    system_rule_snapshot_destroy(&system->rule_snapshot);
    return -1;
}

static int system_effect_remove_rules(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    system->cleanup_in_progress = true;
    if (system->loaded_config.config.mode == ASTERISKD_MODE_EBPF) return 0;
    if (!system->rules_initialized || asteriskd_rules_remove(
            &system->rules_runtime, &system->rules_backend) != 0) return -1;
    if (asteriskd_runtime_recover_before_helper_stop(
            system->loaded_config.config.mode)) {
        char error[128U];
        if (asteriskd_wal_recover(&system->store, &system->state,
                &system_wal_backend, system, error, sizeof(error)) != ASTERISKD_STATE_OK) {
            return -1;
        }
    }
    return 0;
}

static int system_effect_noop(void *opaque) {
    (void)opaque;
    return 0;
}

static int system_effect_close_network(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    if (!system->network_opened) return 0;
    int result = asteriskd_network_close(&system->network);
    if (result == 0) system->network_opened = false;
    return result;
}

static int system_effect_restore(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    system->cleanup_in_progress = true;
    char error[128U];
    return asteriskd_wal_recover(&system->store, &system->state,
        &system_wal_backend, system, error, sizeof(error));
}

static struct asteriskd_runtime_effect_backend system_runtime_effects(
    struct asteriskd_system_supervisor *system) {
    const struct asteriskd_runtime_effect_backend effects = {
        .context = system,
        .save_state = system_effect_save,
        .publish_event = system_effect_event,
        .recover = system_effect_recover,
        .start_core = system_effect_start_core,
        .wait_core = system_effect_wait_core,
        .ensure_platform_capability = system_effect_capability,
        .start_helper = system_effect_start_helper,
        .wait_helper = system_effect_wait_helper,
        .start_matcher = system_effect_start_matcher,
        .open_network = system_effect_open_network,
        .apply_rules = system_effect_rules,
        .verify = system_effect_verify,
        .network_immediate = system_effect_network_immediate,
        .reconcile = system_effect_reconcile,
        .quiesce_traffic = system_effect_quiesce,
        .remove_rules = system_effect_remove_rules,
        .close_network = system_effect_close_network,
        .stop_matcher = system_effect_noop,
        .stop_helper = system_effect_stop_helper,
        .stop_core = system_effect_stop_core,
        .restore = system_effect_restore,
        .release = system_effect_noop,
    };
    return effects;
}

static int system_start_result(struct asteriskd_control_result *result,
    enum asteriskd_control_result_code code, const char *message,
    const struct asteriskd_control_snapshot *snapshot) {
    asteriskd_control_result_destroy(result);
    result->code = code;
    if (snapshot != NULL) {
        result->has_snapshot = true;
        if (asteriskd_control_snapshot_copy(&result->snapshot, snapshot) != 0) return -1;
    }
    return asteriskd_control_result_set_message(result, message, strlen(message));
}

static int system_probe_existing(struct asteriskd_control_result *result) {
    struct asteriskd_control_response response;
    memset(&response, 0, sizeof(response));
    enum asteriskd_control_client_result probed = asteriskd_control_client_run(
        ASTERISKD_CONTROL_METHOD_STATUS, "start", NULL, NULL, &response);
    int status;
    if (probed == ASTERISKD_CONTROL_CLIENT_OK && response.result.has_snapshot) {
        status = system_start_result(result, ASTERISKD_CONTROL_RESULT_ALREADY_RUNNING,
            "protocol-valid supervisor owns the runtime", &response.result.snapshot);
    } else {
        status = system_start_result(result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "control address is occupied without a valid supervisor response", NULL);
    }
    asteriskd_control_response_destroy(&response);
    return status;
}

static bool system_control_drained(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return asteriskd_control_server_drained(system->control);
}

static void system_child_process_defaults(struct asteriskd_child_process *process) {
    memset(process, 0, sizeof(*process));
    process->pid = -1;
    process->process_group_id = -1;
    process->pidfd = -1;
    process->stdout_fd = -1;
    process->stderr_fd = -1;
    process->setup_status_fd = -1;
}

static void system_runtime_cleanup_cycle(struct asteriskd_system_supervisor *system) {
    system_rule_batch_destroy(&system->rule_commands);
    system_rule_snapshot_destroy(&system->rule_snapshot);
    system_foreign_tc_netlink_close(system);
    if (system->network_opened) (void)asteriskd_network_close(&system->network);
    system->network_opened = false;
    asteriskd_child_process_close(&system->core_process);
    asteriskd_child_process_close(&system->helper_process);
    asteriskd_child_process_close(&system->action_process);
    if (system->core_spec_ready) asteriskd_process_spec_destroy(&system->core_spec);
    system->core_spec_ready = false;
    if (system->helper_launch_ready) {
        (void)asteriskd_helper_launch_destroy(
            asteriskd_system_anonymous_file_backend(), &system->helper_launch);
    }
    system->helper_launch_ready = false;
    if (system->matcher_launch_ready) {
        (void)asteriskd_matcher_launch_destroy(
            asteriskd_system_anonymous_file_backend(), &system->matcher_launch);
    }
    system->matcher_launch_ready = false;
}

static void system_runtime_reset_cycle(struct asteriskd_system_supervisor *system) {
    system_runtime_cleanup_cycle(system);
    size_t offset = offsetof(struct asteriskd_system_supervisor, stop_requested);
    memset((unsigned char *)system + offset, 0, sizeof(*system) - offset);
    system->foreign_tc_netlink_fd = -1;
    system_child_process_defaults(&system->core_process);
    system_child_process_defaults(&system->helper_process);
    system_child_process_defaults(&system->action_process);
}

static void system_runtime_cleanup(struct asteriskd_system_supervisor *system) {
    system_runtime_cleanup_cycle(system);
    if (system->control != NULL) {
        asteriskd_control_server_destroy(system->control);
        system->control = NULL;
    }
    if (system->signal_fd_owned && system->signal_fd >= 0) (void)close(system->signal_fd);
    system->signal_fd = -1;
    system->signal_fd_owned = false;
    if (system->service_timer_fd_owned && system->service_timer_fd >= 0) {
        (void)close(system->service_timer_fd);
    }
    system->service_timer_fd = -1;
    system->service_timer_fd_owned = false;
    if (system->wifi_monitor_opened) asteriskd_wifi_monitor_close(&system->wifi_monitor);
    system->wifi_monitor_opened = false;
    if (system->runtime != NULL) asteriskd_runtime_destroy(system->runtime);
    system->runtime = NULL;
    asteriskd_state_document_destroy(&system->state);
    asteriskd_state_store_close(&system->store);
    if (system->logger.opened) (void)asteriskd_log_close(&system->logger);
    asteriskd_loaded_config_release(&system->loaded_config);
}

static void system_runtime_finish_control_stop(
    struct asteriskd_system_supervisor *system) {
    struct asteriskd_control_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    struct asteriskd_control_result result;
    memset(&result, 0, sizeof(result));
    if (asteriskd_control_snapshot_from_state(&system->state, &system->live, &snapshot) == 0) {
        result.code = asteriskd_state_is_canonical_stopped(&system->state)
            ? ASTERISKD_CONTROL_RESULT_OK : ASTERISKD_CONTROL_RESULT_STOP_FAILED;
        result.has_snapshot = true;
        (void)asteriskd_control_snapshot_copy(&result.snapshot, &snapshot);
        if (result.code == ASTERISKD_CONTROL_RESULT_STOP_FAILED) {
            (void)asteriskd_control_result_set_message(&result, "cleanup incomplete", 18U);
        }
        int64_t now = 0;
        if (system_runtime_clock(system, &now) == 0) {
            (void)asteriskd_control_server_finish_stop(
                system->control, &result, (uint64_t)now);
        }
    }
    asteriskd_control_result_destroy(&result);
    asteriskd_control_snapshot_destroy(&snapshot);
}

static int system_runtime_run(const char *config_path, bool initial_start,
    bool *has_early_result, struct asteriskd_control_result *early_result) {
    if (has_early_result == NULL || early_result == NULL) return -1;
    *has_early_result = false;
    memset(early_result, 0, sizeof(*early_result));
    if (config_path == NULL) {
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "verified publication locks are required", NULL);
        return 1;
    }

    sigset_t blocked;
    sigset_t previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "failed to block supervisor signals", NULL);
        return 1;
    }

    struct asteriskd_system_supervisor system;
    memset(&system, 0, sizeof(system));
    system.signal_fd = -1;
    system.service_timer_fd = -1;
    system.wifi_monitor.fd = -1;
    system.foreign_tc_netlink_fd = -1;
    system_child_process_defaults(&system.core_process);
    system_child_process_defaults(&system.helper_process);
    system_child_process_defaults(&system.action_process);
    char error[256U];
    int loaded_config = asteriskd_config_load(
        config_path, &system.loaded_config, error, sizeof(error));
    if (loaded_config != 0) {
        *has_early_result = true;
        enum asteriskd_control_result_code code =
            loaded_config == ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION
                ? ASTERISKD_CONTROL_RESULT_UNSUPPORTED_COMBINATION
                : ASTERISKD_CONTROL_RESULT_CONFIG_INVALID;
        (void)system_start_result(early_result, code,
            loaded_config == ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION
                ? "unsupported owner/core/mode combination" : "invalid runtime configuration", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return asteriskd_control_result_exit_code(code);
    }

    system.signal_fd = signalfd(-1, &blocked, SFD_NONBLOCK | SFD_CLOEXEC);
    system.signal_fd_owned = system.signal_fd >= 0;
    int listener = -1;
    enum asteriskd_control_listener_result listened = system.signal_fd_owned
        ? asteriskd_control_listener_open(&listener) : ASTERISKD_CONTROL_LISTENER_ERROR;
    if (listened != ASTERISKD_CONTROL_LISTENER_OK) {
        *has_early_result = true;
        if (listened == ASTERISKD_CONTROL_LISTENER_IN_USE) {
            (void)system_probe_existing(early_result);
        } else {
            (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
                system.signal_fd_owned ? "control bind failed" : "signalfd initialization failed", NULL);
        }
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return asteriskd_control_result_exit_code(early_result->code);
    }

    struct asteriskd_clock_backend clock = {
        .local_time = system_runtime_local_time,
        .context = &system,
    };
    const unsigned char *secret = system.loaded_config.config.has_age_secret_key
        ? (const unsigned char *)system.loaded_config.config.age_secret_key : NULL;
    size_t secret_length = secret == NULL ? 0U : strlen((const char *)secret);
    if (asteriskd_log_open(&system.logger, system.loaded_config.config.log_path,
            secret, secret_length, &clock, error, sizeof(error)) != 0 ||
        asteriskd_state_store_init(&system.store, system.loaded_config.directory.fd,
            system.loaded_config.directory.device, system.loaded_config.directory.inode,
            error, sizeof(error)) != ASTERISKD_STATE_OK) {
        (void)close(listener);
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "runtime logger or state store initialization failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }

    int state_result = asteriskd_state_store_load(
        &system.store, &system.state, error, sizeof(error));
    if (state_result == ASTERISKD_STATE_NOT_FOUND) {
        state_result = asteriskd_state_document_init(&system.state,
            system.loaded_config.config.owner, system.loaded_config.config.core_type,
            system.loaded_config.config.mode);
    }
    if (state_result == ASTERISKD_STATE_OK) {
        state_result = asteriskd_runtime_prepare_start_state(
            &system.store, &system.state, &system.loaded_config.config,
            error, sizeof(error));
    }
    if (state_result == ASTERISKD_STATE_OK && !initial_start &&
        !asteriskd_state_is_canonical_stopped(&system.state)) {
        state_result = ASTERISKD_STATE_INCOMPATIBLE;
    }
    if (state_result != ASTERISKD_STATE_OK) {
        (void)close(listener);
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            state_result == ASTERISKD_STATE_INCOMPATIBLE
                ? "existing state requires explicit recovery"
                : "start state preparation failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }

    system.live.supervisor_pid = (int)getpid();
    system.live.ipv6_enabled = system.loaded_config.config.enable_ipv6;
    time_t service_now = time(NULL);
    if (service_now == (time_t)-1) {
        (void)close(listener);
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "service control clock initialization failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }
    system.service_running = initial_start;
    asteriskd_service_control_init(&system.service_control,
        &system.loaded_config.config.service_control, initial_start, service_now);
    const struct asteriskd_service_control_config *service =
        &system.loaded_config.config.service_control;
    if (service->enabled && service->schedule.enabled) {
        system.service_timer_fd = timerfd_create(
            CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
        system.service_timer_fd_owned = system.service_timer_fd >= 0;
    }
    if (service->enabled && service->wifi.enabled) {
        system.wifi_monitor_opened = asteriskd_wifi_monitor_open(
            &system.wifi_monitor, error, sizeof(error)) == 0;
    }
    if (system.wifi_monitor_opened) {
        enum asteriskd_wifi_transition transition;
        struct asteriskd_wifi_identity identity;
        if (asteriskd_wifi_monitor_baseline(
                &system.wifi_monitor, &transition, &identity) != 0) {
            system.wifi_monitor_opened = false;
        } else {
            (void)asteriskd_service_control_on_wifi(
                &system.service_control, transition, &identity);
        }
    }
    if ((service->enabled && service->schedule.enabled && !system.service_timer_fd_owned) ||
        (service->enabled && service->wifi.enabled && !system.wifi_monitor_opened) ||
        system_service_timer_arm(&system) != 0) {
        (void)close(listener);
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "service control event source initialization failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }
    struct asteriskd_control_callbacks callbacks = {
        .snapshot = system_runtime_snapshot,
        .request_stop = system_runtime_request_stop,
        .request_shutdown = system_runtime_request_shutdown,
        .context = &system,
    };
    if (asteriskd_control_server_create(&system.control, listener, &callbacks) != 0) {
        (void)close(listener);
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "control server initialization failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }
    struct asteriskd_runtime_reactor_backend reactor_backend = system_runtime_reactor_backend();
    if (asteriskd_runtime_create(&system.runtime, &reactor_backend, &system) != 0) {
        *has_early_result = true;
        (void)system_start_result(early_result, ASTERISKD_CONTROL_RESULT_START_FAILED,
            "reactor initialization failed", NULL);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return 1;
    }
    asteriskd_control_server_enable_accepting(system.control, true);
    struct asteriskd_runtime_effect_backend effects = system_runtime_effects(&system);
    int status = 0;
    bool should_start = initial_start;
    while (!system.shutdown_requested) {
        if (should_start || system.service_start_requested) {
            bool automatic_start = !should_start;
            if (!should_start) {
                system_runtime_reset_cycle(&system);
                if (asteriskd_runtime_prepare_start_state(
                        &system.store, &system.state, &system.loaded_config.config,
                        error, sizeof(error)) != ASTERISKD_STATE_OK) {
                    status = 1;
                    system.shutdown_requested = true;
                    break;
                }
            }
            should_start = false;
            system.service_start_requested = false;
            system.service_running = true;
            asteriskd_service_control_set_service_running(&system.service_control, true);
            int cycle_status = asteriskd_runtime_supervise(
                system.runtime, &system.loaded_config.config,
                &system.state, &system.live, &effects);
            system.service_running = false;
            asteriskd_service_control_set_service_running(&system.service_control, false);
            system_runtime_finish_control_stop(&system);
            if (cycle_status != 0) {
                status = cycle_status;
                if (!automatic_start || !asteriskd_state_is_canonical_stopped(&system.state)) {
                    system.shutdown_requested = true;
                }
            }
            if (!service->enabled) break;
            if (system.shutdown_requested) break;
            if (system_service_reconcile_time(&system) != 0) {
                status = 1;
                system.shutdown_requested = true;
            }
            continue;
        }
        if (!service->enabled) break;
        if (system_service_reconcile_time(&system) != 0) {
            status = 1;
            system.shutdown_requested = true;
            break;
        }
        if (system.service_start_requested) continue;
        struct asteriskd_runtime_delta delta;
        if (asteriskd_runtime_pump_once(system.runtime, NULL, &delta) != 0 ||
            (delta.flags & ASTERISKD_DELTA_FATAL) != 0U) {
            status = 1;
            system.shutdown_requested = true;
        }
    }
    system_runtime_finish_control_stop(&system);
    asteriskd_control_server_enable_accepting(system.control, false);
    if (!asteriskd_control_server_drained(system.control)) {
        int64_t now = 0;
        if (system_runtime_clock(&system, &now) == 0) {
            struct asteriskd_deadline deadline = {
                .armed = true,
                .monotonic_milliseconds = now + ASTERISKD_CONTROL_WATCH_STALL_MILLIS,
            };
            struct asteriskd_runtime_delta ignored;
            (void)asteriskd_runtime_pump_until(system.runtime, &deadline,
                system_control_drained, &system, &ignored);
        }
    }
    system_runtime_cleanup(&system);
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);
    return status;
}

int asteriskd_runtime_start_system(const char *config_path,
    bool *has_early_result, struct asteriskd_control_result *early_result) {
    return system_runtime_run(config_path, true, has_early_result, early_result);
}

int asteriskd_runtime_monitor_system(const char *config_path,
    bool *has_early_result, struct asteriskd_control_result *early_result) {
    return system_runtime_run(config_path, false, has_early_result, early_result);
}

static int system_recovery_result_fill(
    struct asteriskd_recovery_result *result,
    enum asteriskd_recovery_result_code code,
    const struct asteriskd_state_document *state,
    const char *message) {
    memset(result, 0, sizeof(*result));
    result->code = code;
    if (state != NULL) {
        result->has_identity = true;
        result->owner = state->owner;
        result->core_type = state->core_type;
        result->mode = state->mode;
        result->has_core_owned_ebpf_boundary = true;
        result->core_owned_ebpf_boundary = state->recovery.core_owned_ebpf_boundary;
    }
    if (message != NULL && asteriskd_recovery_result_set_message(
            result, message, strlen(message)) != 0) return -1;
    return asteriskd_recovery_result_valid(result) ? 0 : -1;
}

static int system_recovery_peer_result(struct asteriskd_recovery_result *result) {
    struct asteriskd_control_response response;
    memset(&response, 0, sizeof(response));
    enum asteriskd_control_client_result client = asteriskd_control_client_run(
        ASTERISKD_CONTROL_METHOD_STATUS, "recover", NULL, NULL, &response);
    int filled;
    if (client == ASTERISKD_CONTROL_CLIENT_OK && response.result.has_snapshot) {
        memset(result, 0, sizeof(*result));
        result->code = ASTERISKD_RECOVERY_ALREADY_RUNNING;
        result->has_identity = true;
        result->owner = response.result.snapshot.owner;
        result->core_type = response.result.snapshot.core_type;
        result->mode = response.result.snapshot.mode;
        static const char peer_message[] = "protocol-valid supervisor owns the runtime";
        filled = asteriskd_recovery_result_set_message(result,
            peer_message, sizeof(peer_message) - 1U) == 0 &&
            asteriskd_recovery_result_valid(result) ? 0 : -1;
    } else {
        filled = system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_REQUIRED, NULL,
            "control address is occupied without a valid supervisor response");
    }
    asteriskd_control_response_destroy(&response);
    return filled;
}

int asteriskd_runtime_recover_system(
    const char *config_path,
    struct asteriskd_recovery_result *result) {
    if (result != NULL) memset(result, 0, sizeof(*result));
    if (config_path == NULL || result == NULL) return -1;
    char error[256U];
    struct asteriskd_runtime_directory pre_directory;
    if (asteriskd_runtime_directory_open(
            config_path, &pre_directory, error, sizeof(error)) != 0) {
        return system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_INTERNAL_ERROR, NULL,
            "runtime directory initialization failed");
    }
    struct asteriskd_state_store pre_store;
    int initialized = asteriskd_state_store_init(&pre_store, pre_directory.fd,
        pre_directory.device, pre_directory.inode, error, sizeof(error));
    if (initialized != ASTERISKD_STATE_OK) {
        asteriskd_runtime_directory_release(&pre_directory);
        return system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_INTERNAL_ERROR, NULL,
            "state store initialization failed");
    }
    struct asteriskd_state_document pre_state;
    memset(&pre_state, 0, sizeof(pre_state));
    int loaded = asteriskd_state_store_load(
        &pre_store, &pre_state, error, sizeof(error));
    asteriskd_state_store_close(&pre_store);
    asteriskd_runtime_directory_release(&pre_directory);
    if (loaded != ASTERISKD_STATE_OK) {
        asteriskd_state_document_destroy(&pre_state);
        return system_recovery_result_fill(result, ASTERISKD_RECOVERY_REQUIRED, NULL,
            "state evidence cannot be safely recovered");
    }
    if (asteriskd_state_is_canonical_stopped(&pre_state)) {
        int filled = system_recovery_result_fill(
            result, ASTERISKD_RECOVERY_CLEAN, &pre_state, NULL);
        asteriskd_state_document_destroy(&pre_state);
        return filled;
    }

    struct asteriskd_system_supervisor system;
    memset(&system, 0, sizeof(system));
    system.signal_fd = -1;
    system.foreign_tc_netlink_fd = -1;
    system.core_process.pid = -1;
    system.core_process.process_group_id = -1;
    system.core_process.pidfd = -1;
    system.core_process.stdout_fd = -1;
    system.core_process.stderr_fd = -1;
    system.core_process.setup_status_fd = -1;
    system.helper_process.pid = -1;
    system.helper_process.process_group_id = -1;
    system.helper_process.pidfd = -1;
    system.helper_process.stdout_fd = -1;
    system.helper_process.stderr_fd = -1;
    system.helper_process.setup_status_fd = -1;
    system.action_process.pid = -1;
    system.action_process.process_group_id = -1;
    system.action_process.pidfd = -1;
    system.action_process.stdout_fd = -1;
    system.action_process.stderr_fd = -1;
    system.action_process.setup_status_fd = -1;
    if (asteriskd_config_load(config_path, &system.loaded_config,
            error, sizeof(error)) != 0 ||
        system.loaded_config.config.owner != pre_state.owner ||
        system.loaded_config.config.core_type != pre_state.core_type ||
        system.loaded_config.config.mode != pre_state.mode) {
        int filled = system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_REQUIRED, &pre_state,
            "dirty state requires its intact matching configuration");
        asteriskd_state_document_destroy(&pre_state);
        system_runtime_cleanup(&system);
        return filled;
    }
    struct asteriskd_state_document trusted_identity;
    memset(&trusted_identity, 0, sizeof(trusted_identity));
    trusted_identity.owner = pre_state.owner;
    trusted_identity.core_type = pre_state.core_type;
    trusted_identity.mode = pre_state.mode;
    trusted_identity.recovery.core_owned_ebpf_boundary =
        pre_state.recovery.core_owned_ebpf_boundary;
    asteriskd_state_document_destroy(&pre_state);

    sigset_t blocked;
    sigset_t previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
        system_runtime_cleanup(&system);
        return system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_INTERNAL_ERROR, NULL,
            "failed to block recovery signals");
    }
    system.signal_fd = signalfd(-1, &blocked, SFD_NONBLOCK | SFD_CLOEXEC);
    system.signal_fd_owned = system.signal_fd >= 0;
    int listener = -1;
    enum asteriskd_control_listener_result listened = system.signal_fd_owned
        ? asteriskd_control_listener_open(&listener) : ASTERISKD_CONTROL_LISTENER_ERROR;
    if (listened != ASTERISKD_CONTROL_LISTENER_OK) {
        int filled = listened == ASTERISKD_CONTROL_LISTENER_IN_USE
            ? system_recovery_peer_result(result)
            : system_recovery_result_fill(result,
                ASTERISKD_RECOVERY_INTERNAL_ERROR, NULL,
                "recovery control initialization failed");
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return filled;
    }

    struct asteriskd_clock_backend clock = {
        .local_time = system_runtime_local_time,
        .context = &system,
    };
    const unsigned char *secret = system.loaded_config.config.has_age_secret_key
        ? (const unsigned char *)system.loaded_config.config.age_secret_key : NULL;
    size_t secret_length = secret == NULL ? 0U : strlen((const char *)secret);
    if (asteriskd_log_open(&system.logger, system.loaded_config.config.log_path,
            secret, secret_length, &clock, error, sizeof(error)) != 0 ||
        asteriskd_state_store_init(&system.store, system.loaded_config.directory.fd,
            system.loaded_config.directory.device, system.loaded_config.directory.inode,
            error, sizeof(error)) != ASTERISKD_STATE_OK ||
        asteriskd_state_store_load(&system.store, &system.state,
            error, sizeof(error)) != ASTERISKD_STATE_OK) {
        (void)close(listener);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_REQUIRED, &trusted_identity,
            "recovery logger or state initialization failed");
    }
    system.live.supervisor_pid = (int)getpid();
    system.live.ipv6_enabled = system.loaded_config.config.enable_ipv6;
    struct asteriskd_control_callbacks callbacks = {
        .snapshot = system_runtime_snapshot,
        .request_stop = system_runtime_request_stop,
        .request_shutdown = system_runtime_request_shutdown,
        .context = &system,
    };
    struct asteriskd_runtime_reactor_backend reactor_backend = system_runtime_reactor_backend();
    if (asteriskd_control_server_create(&system.control, listener, &callbacks) != 0 ||
        asteriskd_runtime_create(&system.runtime, &reactor_backend, &system) != 0) {
        if (system.control == NULL) (void)close(listener);
        system_runtime_cleanup(&system);
        (void)sigprocmask(SIG_SETMASK, &previous, NULL);
        return system_recovery_result_fill(result,
            ASTERISKD_RECOVERY_INTERNAL_ERROR, NULL,
            "recovery reactor initialization failed");
    }
    asteriskd_control_server_enable_accepting(system.control, true);
    system.recovery_only = true;
    int recovered = system_recover_state(&system);
    struct asteriskd_state_document result_state = system.state;
    result_state.recovery.records = NULL;
    result_state.recovery.record_capacity = 0U;
    bool dedicated_recovered = recovered == 0 &&
        asteriskd_state_is_canonical_stopped(&system.state) && !system.recovery_cancelled;
    int filled = dedicated_recovered
        ? system_recovery_result_fill(result, ASTERISKD_RECOVERY_RECOVERED,
            &result_state, NULL)
        : system_recovery_result_fill(result, ASTERISKD_RECOVERY_REQUIRED,
            &result_state, system.recovery_cancelled
                ? "recovery was cancelled by a control stop"
                : "cleanup incomplete; recovery evidence retained");
    struct asteriskd_control_snapshot final_snapshot;
    struct asteriskd_control_result final_result;
    memset(&final_snapshot, 0, sizeof(final_snapshot));
    memset(&final_result, 0, sizeof(final_result));
    if (asteriskd_control_snapshot_from_state(
            &system.state, &system.live, &final_snapshot) == 0) {
        final_result.code = recovered == 0 && asteriskd_state_is_canonical_stopped(&system.state)
            ? ASTERISKD_CONTROL_RESULT_OK : ASTERISKD_CONTROL_RESULT_STOP_FAILED;
        final_result.has_snapshot = true;
        (void)asteriskd_control_snapshot_copy(&final_result.snapshot, &final_snapshot);
        if (final_result.code == ASTERISKD_CONTROL_RESULT_STOP_FAILED) {
            static const char incomplete[] = "cleanup incomplete";
            (void)asteriskd_control_result_set_message(
                &final_result, incomplete, sizeof(incomplete) - 1U);
        }
        int64_t now = 0;
        if (system_runtime_clock(&system, &now) == 0) {
            (void)asteriskd_control_server_finish_stop(
                system.control, &final_result, (uint64_t)now);
            asteriskd_control_server_enable_accepting(system.control, false);
            if (!asteriskd_control_server_drained(system.control)) {
                struct asteriskd_deadline deadline = {
                    .armed = true,
                    .monotonic_milliseconds = now + ASTERISKD_CONTROL_WATCH_STALL_MILLIS,
                };
                struct asteriskd_runtime_delta ignored;
                (void)asteriskd_runtime_pump_until(system.runtime, &deadline,
                    system_control_drained, &system, &ignored);
            }
        }
    }
    asteriskd_control_result_destroy(&final_result);
    asteriskd_control_snapshot_destroy(&final_snapshot);
    asteriskd_control_server_enable_accepting(system.control, false);
    system_runtime_cleanup(&system);
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);
    return filled;
}
#endif

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

int asteriskd_runtime_recover_system(
    const char *config_path,
    struct asteriskd_recovery_result *result) {
    (void)config_path;
    if (result == NULL) return -1;
    memset(result, 0, sizeof(*result));
    result->code = ASTERISKD_RECOVERY_INTERNAL_ERROR;
    static const char unavailable[] = "system recovery is unavailable on this host";
    return asteriskd_recovery_result_set_message(
        result, unavailable, sizeof(unavailable) - 1U);
}
#endif

void asteriskd_runtime_destroy(struct asteriskd_runtime *runtime) {
    free(runtime);
}

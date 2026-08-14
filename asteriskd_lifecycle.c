// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <string.h>

static void terminal_latch_lock(struct asteriskd_lifecycle *lifecycle) {
    bool expected = false;
    while (!atomic_compare_exchange_weak_explicit(
        &lifecycle->terminal_latch_locked,
        &expected,
        true,
        memory_order_acquire,
        memory_order_relaxed)) {
        expected = false;
    }
}

static void terminal_latch_unlock(struct asteriskd_lifecycle *lifecycle) {
    atomic_store_explicit(&lifecycle->terminal_latch_locked, false, memory_order_release);
}

static void set_first_reason_locked(
    struct asteriskd_lifecycle *lifecycle,
    enum asteriskd_lifecycle_reason reason) {
    if (atomic_load_explicit(&lifecycle->terminal_reason, memory_order_relaxed) ==
        ASTERISKD_LIFECYCLE_REASON_NONE) {
        atomic_store_explicit(&lifecycle->terminal_reason, reason, memory_order_relaxed);
    }
}

static void set_first_reason(
    struct asteriskd_lifecycle *lifecycle,
    enum asteriskd_lifecycle_reason reason) {
    terminal_latch_lock(lifecycle);
    set_first_reason_locked(lifecycle, reason);
    terminal_latch_unlock(lifecycle);
}

static void latch_stop_reason(
    struct asteriskd_lifecycle *lifecycle,
    enum asteriskd_lifecycle_reason reason) {
    terminal_latch_lock(lifecycle);
    set_first_reason_locked(lifecycle, reason);
    atomic_store_explicit(&lifecycle->stop_was_requested, true, memory_order_release);
    terminal_latch_unlock(lifecycle);
}

static bool stop_requested(struct asteriskd_lifecycle *lifecycle) {
    return atomic_load_explicit(&lifecycle->stop_was_requested, memory_order_acquire) ||
        (lifecycle->backend->stop_requested != NULL &&
         lifecycle->backend->stop_requested(lifecycle->backend_context));
}

static int stop_at(struct asteriskd_lifecycle *lifecycle, const char *stage) {
    latch_stop_reason(lifecycle, ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP);
    lifecycle->failure_stage = stage;
    return ASTERISKD_LIFECYCLE_STOP_REQUESTED;
}

static int call_effect(
    struct asteriskd_lifecycle *lifecycle,
    struct asteriskd_lifecycle_effect *effect,
    const char *stage,
    int (*callback)(void *)) {
    if (stop_requested(lifecycle)) return stop_at(lifecycle, stage);
    effect->attempted = true;
    effect->cleanup_required = true;
    int result = callback(lifecycle->backend_context);
    if (result == 0) effect->succeeded = true;
    if (result != 0) {
        lifecycle->failure_stage = stage;
        set_first_reason(lifecycle, ASTERISKD_LIFECYCLE_REASON_START_FAILED);
        return result;
    }
    if (stop_requested(lifecycle)) return stop_at(lifecycle, stage);
    return 0;
}

static int call_observer(
    struct asteriskd_lifecycle *lifecycle,
    const char *stage,
    int (*callback)(void *)) {
    if (stop_requested(lifecycle)) return stop_at(lifecycle, stage);
    int result = callback(lifecycle->backend_context);
    if (result != 0) {
        lifecycle->failure_stage = stage;
        set_first_reason(
            lifecycle,
            result == ASTERISKD_LIFECYCLE_CORE_EXITED ? ASTERISKD_LIFECYCLE_REASON_CORE_EXITED :
            result == ASTERISKD_LIFECYCLE_HELPER_EXITED ? ASTERISKD_LIFECYCLE_REASON_HELPER_EXITED :
            ASTERISKD_LIFECYCLE_REASON_START_FAILED);
        return result;
    }
    if (stop_requested(lifecycle)) return stop_at(lifecycle, stage);
    return 0;
}

static void clear_effect(struct asteriskd_lifecycle_effect *effect) {
    effect->cleanup_required = false;
    effect->succeeded = false;
}

static void try_inverse(
    struct asteriskd_lifecycle *lifecycle,
    struct asteriskd_lifecycle_effect *effect,
    int (*callback)(void *)) {
    if (effect->cleanup_required && callback != NULL && callback(lifecycle->backend_context) == 0) {
        clear_effect(effect);
    }
}

void asteriskd_lifecycle_init(struct asteriskd_lifecycle *lifecycle) {
    if (lifecycle != NULL) {
        memset(lifecycle, 0, sizeof(*lifecycle));
        atomic_init(&lifecycle->stop_was_requested, false);
        atomic_init(&lifecycle->terminal_latch_locked, false);
        atomic_init(&lifecycle->terminal_reason, ASTERISKD_LIFECYCLE_REASON_NONE);
        atomic_init(&lifecycle->has_child_exit_status, false);
        atomic_init(&lifecycle->child_exit_role, ASTERISKD_CHILD_CORE);
        atomic_init(&lifecycle->child_exit_status, 0);
        lifecycle->initialized = true;
    }
}

int asteriskd_lifecycle_stop(struct asteriskd_lifecycle *lifecycle) {
    if (lifecycle == NULL || lifecycle->backend == NULL) return 0;
    const struct asteriskd_lifecycle_backend *backend = lifecycle->backend;
    void *context = lifecycle->backend_context;
    if (lifecycle->traffic_may_be_active && backend->quiesce_traffic != NULL &&
            backend->quiesce_traffic(context) == 0) {
        lifecycle->traffic_may_be_active = false;
    }
    if (lifecycle->traffic_may_be_active) {
        lifecycle->starting = false;
        lifecycle->stopped = false;
        return ASTERISKD_LIFECYCLE_STOP_FAILED;
    }
    try_inverse(lifecycle, &lifecycle->rules, backend->remove_rules);
    if (lifecycle->rules.cleanup_required) {
        lifecycle->starting = false;
        lifecycle->stopped = false;
        return ASTERISKD_LIFECYCLE_STOP_FAILED;
    }
    try_inverse(lifecycle, &lifecycle->network, backend->close_network);
    try_inverse(lifecycle, &lifecycle->matcher, backend->stop_matcher);
    try_inverse(lifecycle, &lifecycle->helper, backend->stop_helper);
    try_inverse(lifecycle, &lifecycle->core, backend->stop_core);
    try_inverse(lifecycle, &lifecycle->recover, backend->restore);
    try_inverse(lifecycle, &lifecycle->acquire, backend->release);
    lifecycle->starting = false;
    bool remains = lifecycle->traffic_may_be_active || lifecycle->rules.cleanup_required ||
        lifecycle->network.cleanup_required || lifecycle->matcher.cleanup_required ||
        lifecycle->helper.cleanup_required || lifecycle->core.cleanup_required ||
        lifecycle->recover.cleanup_required || lifecycle->acquire.cleanup_required;
    lifecycle->stopped = !remains;
    return remains ? ASTERISKD_LIFECYCLE_STOP_FAILED : 0;
}

static bool backend_is_complete(
    const struct asteriskd_lifecycle_backend *backend,
    const struct asteriskd_lifecycle_options *options) {
    if (backend->acquire == NULL || backend->recover == NULL ||
        backend->start_core == NULL || backend->wait_core == NULL ||
        backend->open_network == NULL || backend->apply_rules == NULL || backend->verify == NULL ||
        backend->quiesce_traffic == NULL || backend->remove_rules == NULL ||
        backend->close_network == NULL || backend->stop_core == NULL ||
        backend->restore == NULL || backend->release == NULL) return false;
    if (options->requires_platform_capability && backend->ensure_platform_capability == NULL) return false;
    if (options->has_helper &&
        (backend->start_helper == NULL || backend->wait_helper == NULL || backend->stop_helper == NULL)) return false;
    if (options->has_matcher &&
        (backend->start_matcher == NULL || backend->stop_matcher == NULL)) return false;
    return true;
}

int asteriskd_lifecycle_start(
    struct asteriskd_lifecycle *lifecycle,
    const struct asteriskd_lifecycle_backend *backend,
    void *context,
    const struct asteriskd_lifecycle_options *options) {
    if (lifecycle == NULL || backend == NULL || options == NULL) return ASTERISKD_CONFIG_INVALID;
    asteriskd_lifecycle_init(lifecycle);
    if (!backend_is_complete(backend, options)) return ASTERISKD_CONFIG_INVALID;
    lifecycle->backend = backend;
    lifecycle->backend_context = context;
    lifecycle->options = *options;
    lifecycle->starting = true;
    int result = call_effect(lifecycle, &lifecycle->acquire, "acquire", backend->acquire);
    if (result == 0) result = call_effect(lifecycle, &lifecycle->recover, "recover", backend->recover);
    if (result == 0 && options->standalone_ebpf) lifecycle->traffic_may_be_active = true;
    if (result == 0) result = call_effect(lifecycle, &lifecycle->core, "start_core", backend->start_core);
    if (result == 0) result = call_observer(lifecycle, "wait_core", backend->wait_core);
    if (result == 0 && options->requires_platform_capability) {
        if (stop_requested(lifecycle)) {
            result = stop_at(lifecycle, "ensure_platform_capability");
        } else {
            lifecycle->platform_capability.attempted = true;
            result = backend->ensure_platform_capability(context);
            lifecycle->platform_capability.succeeded = result == 0;
            lifecycle->platform_capability.partial = result == ASTERISKD_LIFECYCLE_PARTIAL_FAILURE;
            if (result != 0) {
                lifecycle->failure_stage = "ensure_platform_capability";
                set_first_reason(lifecycle, ASTERISKD_LIFECYCLE_REASON_START_FAILED);
            } else if (stop_requested(lifecycle)) {
                result = stop_at(lifecycle, "ensure_platform_capability");
            }
        }
    }
    if (result == 0 && options->has_helper) {
        result = call_effect(lifecycle, &lifecycle->helper, "start_helper", backend->start_helper);
        if (result == 0) result = call_observer(lifecycle, "wait_helper", backend->wait_helper);
    }
    if (result == 0 && options->has_matcher) {
        result = call_effect(lifecycle, &lifecycle->matcher, "start_matcher", backend->start_matcher);
    }
    if (result == 0) result = call_effect(lifecycle, &lifecycle->network, "open_network", backend->open_network);
    if (result == 0) {
        lifecycle->traffic_may_be_active = true;
        result = call_effect(lifecycle, &lifecycle->rules, "apply_rules", backend->apply_rules);
    }
    if (result == 0) result = call_observer(lifecycle, "verify", backend->verify);
    if (result != 0) {
        lifecycle->starting = false;
        lifecycle->stopped = false;
        return result;
    }
    lifecycle->starting = false;
    lifecycle->stopped = false;
    return 0;
}

static bool request_reason_is_valid(enum asteriskd_lifecycle_reason reason) {
    return reason == ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP || reason == ASTERISKD_LIFECYCLE_REASON_SIGTERM ||
        reason == ASTERISKD_LIFECYCLE_REASON_SIGINT || reason == ASTERISKD_LIFECYCLE_REASON_RUNTIME_FAILED;
}

int asteriskd_lifecycle_request_stop(
    struct asteriskd_lifecycle *lifecycle,
    enum asteriskd_lifecycle_reason reason) {
    if (lifecycle == NULL || !lifecycle->initialized || !request_reason_is_valid(reason)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    latch_stop_reason(lifecycle, reason);
    return ASTERISKD_LIFECYCLE_STOP_REQUESTED;
}

int asteriskd_lifecycle_on_child_exit(
    struct asteriskd_lifecycle *lifecycle,
    enum asteriskd_child_role role,
    int status) {
    if (lifecycle == NULL || !lifecycle->initialized ||
        (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER)) {
        return ASTERISKD_CONFIG_INVALID;
    }
    if (role == ASTERISKD_CHILD_HELPER && !lifecycle->options.has_helper) return 0;
    terminal_latch_lock(lifecycle);
    if (!atomic_load_explicit(&lifecycle->has_child_exit_status, memory_order_relaxed)) {
        atomic_store_explicit(&lifecycle->child_exit_role, role, memory_order_relaxed);
        atomic_store_explicit(&lifecycle->child_exit_status, status, memory_order_relaxed);
        atomic_store_explicit(&lifecycle->has_child_exit_status, true, memory_order_release);
    }
    set_first_reason_locked(
        lifecycle,
        role == ASTERISKD_CHILD_CORE ? ASTERISKD_LIFECYCLE_REASON_CORE_EXITED : ASTERISKD_LIFECYCLE_REASON_HELPER_EXITED);
    atomic_store_explicit(&lifecycle->stop_was_requested, true, memory_order_release);
    terminal_latch_unlock(lifecycle);
    return role == ASTERISKD_CHILD_CORE ? ASTERISKD_LIFECYCLE_CORE_EXITED : ASTERISKD_LIFECYCLE_HELPER_EXITED;
}

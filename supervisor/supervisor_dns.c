// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

static int system_dns_activate(struct asteriskd_system_supervisor *system, uint64_t now);

#if defined(__linux__) || defined(__ANDROID__)

static bool system_dns_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return !system->dns.pending;
}

static int system_dns_wait(struct asteriskd_system_supervisor *system) {
    int64_t now = 0;
    if (asteriskd_supervisor_runtime_clock(system, &now) != 0) return -1;
    uint64_t timeout = SYSTEM_DNS_COMMAND_WAIT_MILLIS, boot_now = asteriskd_dns_monotime();
    if (system->dns_startup_deadline) {
        if (boot_now >= system->dns_startup_deadline) goto expired;
        if (timeout > system->dns_startup_deadline - boot_now)
            timeout = system->dns_startup_deadline - boot_now;
    }
    struct asteriskd_deadline deadline = {
        .armed = true, .monotonic_milliseconds = now + (int64_t)timeout};
    int pumped = asteriskd_supervisor_pump_condition(system, &deadline, system_dns_done);
    if (system->dns_startup_deadline && asteriskd_dns_monotime() >= system->dns_startup_deadline)
        goto expired;
    if (pumped != 0 || system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_FAILED ||
        system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_UNSUPPORTED)
        return -1;
    return 0;
expired:
    asteriskd_dns_fail(&system->dns, "DNS startup deadline expired");
    return -1;
}

/* supervisor/supervisor_dns.c */
static int system_dns_exchange(struct asteriskd_system_supervisor *system, uint16_t opcode) {
    if (system->dns.pending && system_dns_wait(system) != 0) return -1;
    uint64_t now = asteriskd_dns_monotime();
    if ((opcode == ASTERISKD_DNS_OP_ACTIVATE ? system_dns_activate(system, now)
                                             : asteriskd_dns_command(&system->dns, opcode,
                                                   &system->loaded_config.config, now)) != 0) {
        asteriskd_dns_fail(&system->dns, "cannot encode DNS command or UID policy");
        return -1;
    }
    if (system_dns_wait(system) != 0) return -1;
    // CACHE_ERROR already withdrew the policy. Startup may drain and retry a
    // fresh snapshot, but must never report this response as activation.
    if (opcode == ASTERISKD_DNS_OP_ACTIVATE && system->dns.topology_changed &&
        system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_DRAINING)
        return 1;
    if (opcode == ASTERISKD_DNS_OP_ACTIVATE && !asteriskd_dns_serving(system->dns.snapshot.phase)) {
        asteriskd_dns_fail(&system->dns, "DNS topology changed before startup activation");
        return -1;
    }
    return 0;
}

static bool system_dns_release_signalled(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    return system->dns.network_changed || system->dns.fd < 0;
}

// Between RELEASE retries, wait for the module's release event through the
// reactor instead of spinning on requests. Legacy modules keep a 20 ms retry.
static int system_dns_wait_release(struct asteriskd_system_supervisor *system, uint64_t until) {
    uint64_t current = asteriskd_dns_monotime();
    if (current >= until) return -1;
    uint64_t wait = until - current;
    if (!system->dns.drain_events && wait > SYSTEM_DNS_LEGACY_RELEASE_RETRY_MILLIS)
        wait = SYSTEM_DNS_LEGACY_RELEASE_RETRY_MILLIS;
    int64_t now = 0;
    if (asteriskd_supervisor_runtime_clock(system, &now) != 0) return -1;
    struct asteriskd_deadline deadline = {
        .armed = true, .monotonic_milliseconds = now + (int64_t)wait};
    if (asteriskd_supervisor_pump_condition(system, &deadline, system_dns_release_signalled) != 0 &&
        (system->dns.drain_events || asteriskd_dns_monotime() >= until))
        return -1;
    system->dns.network_changed = false;
    return 0;
}

static uint32_t system_dns_mode_bit(struct asteriskd_system_supervisor *system) {
    return system->loaded_config.config.mode == ASTERISKD_MODE_TPROXY   ? 1U
        : system->loaded_config.config.mode == ASTERISKD_MODE_TUN2SOCKS ? 2U
                                                                        : 4U;
}

static int system_dns_begin_generation(struct asteriskd_system_supervisor *system) {
    system->dns.snapshot.required = true;
    if (!system->dns_instance || system->dns_generation == UINT64_MAX) {
        asteriskd_dns_fail(&system->dns, "fresh DNS identity unavailable");
        return -1;
    }
    if (system->dns_generation < system->loaded_config.config.core_dns_generation)
        system->dns_generation = system->loaded_config.config.core_dns_generation - 1U;
    uint64_t generation = ++system->dns_generation;
    int result;
    if (system->dns.fd >= 0 && system->dns.suspended &&
        system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_INACTIVE && !system->dns.retained) {
        system->dns.snapshot.cycle_id = system->dns_cycle;
        system->dns.snapshot.generation = generation;
        system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_PREPARING;
        system->dns.suspended = false;
        result = asteriskd_dns_command(
            &system->dns, ASTERISKD_DNS_OP_HELLO, NULL, asteriskd_dns_monotime());
    } else
        result = asteriskd_dns_begin(&system->dns, system->dns_instance, system->dns_cycle,
            generation, asteriskd_dns_monotime());
    system->dns.busy = true;
    system->live.dns_enhancement = &system->dns.snapshot;
    return result;
}

static int system_dns_startup_failed(
    struct asteriskd_system_supervisor *system, const char *stage) {
    if (system->dns.prepare_retry) {
        asteriskd_dns_close(&system->dns);
        system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_FAILED;
    }
    char message[320U];
    int written = snprintf(message, sizeof(message),
        "DNS enhancement startup failed: stage=%s phase=%d op=%u result=%" PRIu32 " reason=%s",
        stage, (int)system->dns.snapshot.phase, (unsigned)system->dns.opcode, system->dns.result,
        system->dns.snapshot.reason[0] ? system->dns.snapshot.reason
                                       : "runtime wait or command setup failed");
    if (written > 0 && (size_t)written < sizeof(message)) {
        (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
            ASTERISKD_COMPONENT_NETWORK, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
    }
    return -1;
}

int asteriskd_supervisor_dns_prepare(struct asteriskd_system_supervisor *system) {
    if (!system->loaded_config.config.dns_enhancement) return 0;
    bool drain_logged = false;
    // A previous cycle draining in-flight queries does not consume attempts;
    // the startup deadline bounds that wait.
    for (unsigned attempt = 0;;) {
        if (system_dns_begin_generation(system) != 0)
            return system_dns_startup_failed(system, "connect");
        if (system_dns_wait(system) != 0) return system_dns_startup_failed(system, "capabilities");
        if (!(system->dns.result & system_dns_mode_bit(system))) {
            asteriskd_dns_close(&system->dns);
            system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_UNSUPPORTED;
            snprintf(system->dns.snapshot.reason, sizeof(system->dns.snapshot.reason),
                "module does not support selected mode: supported=0x%" PRIx32
                " required=0x%" PRIx32,
                system->dns.result, system_dns_mode_bit(system));
            return system_dns_startup_failed(system, "capabilities");
        }
        if (system_dns_exchange(system, ASTERISKD_DNS_OP_PREPARE) != 0)
            return system_dns_startup_failed(system, "prepare");
        if (!system->dns.prepare_retry) return 0;
        const bool draining = system->dns.prepare_draining;
        if (!draining || !drain_logged) {
            char message[256];
            if (draining)
                snprintf(message, sizeof(message),
                    "DNS prepare waiting for previous cycle to drain: %s",
                    system->dns.snapshot.reason);
            else
                snprintf(message, sizeof(message), "DNS prepare transient failure: attempt=%u %s",
                    attempt + 1, system->dns.snapshot.reason);
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_WARNING,
                ASTERISKD_COMPONENT_NETWORK, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
            drain_logged = drain_logged || draining;
        }
        if ((!draining && ++attempt == 3) || !system->dns_startup_deadline ||
            asteriskd_dns_monotime() >= system->dns_startup_deadline)
            break;
        // Wait through the reactor, so stop/child exit/control requests remain responsive.
        // Retry only after a resolver event (network change or drain completion).
        // The deadline bounds the operation; it is not a timer for probing whether
        // the network has become ready. Modules without drain events keep the
        // legacy 20 ms release cadence; PREPARE itself reaps their drained session.
        const bool legacy_drain = draining && !system->dns.drain_events;
        const uint64_t until = system->dns_startup_deadline;
        while (!system->dns.network_changed && asteriskd_dns_monotime() < until) {
            int64_t now = 0;
            if (asteriskd_supervisor_runtime_clock(system, &now) != 0)
                return system_dns_startup_failed(system, "retry-clock");
            uint64_t current = asteriskd_dns_monotime();
            if (current >= until) break;
            uint64_t remaining = until - current;
            if (legacy_drain && remaining > SYSTEM_DNS_LEGACY_RELEASE_RETRY_MILLIS)
                remaining = SYSTEM_DNS_LEGACY_RELEASE_RETRY_MILLIS;
            struct asteriskd_deadline deadline = {
                .armed = true, .monotonic_milliseconds = now + (int64_t)remaining};
            struct asteriskd_runtime_delta delta;
            if (asteriskd_runtime_pump_once(system->runtime, &deadline, &delta) != 0 ||
                asteriskd_supervisor_accept_pump_delta(system, &delta) != 0)
                return system_dns_startup_failed(system, "retry-interrupted");
            if (system->stop_requested || system->manual_stop_pending ||
                system->shutdown_requested || system->core_reaped || system->helper_reaped)
                return system_dns_startup_failed(system, "retry-interrupted");
            if (legacy_drain) break;
        }
        system->dns.network_changed = false;
        if (asteriskd_dns_monotime() >= system->dns_startup_deadline) break;
        // A drain wait leaves no retained resources of this session.
        if (draining) system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
        system->dns.suspended = true;
    }
    return system_dns_startup_failed(system, "prepare-retry-exhausted");
}

int asteriskd_supervisor_dns_withdraw(struct asteriskd_system_supervisor *system) {
    if (!system->dns.snapshot.required ||
        system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_DISABLED ||
        system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_UNSUPPORTED)
        return 0;
    system->dns.busy = true;
    if (system->dns.fd >= 0 && !system->dns.suspended &&
        system_dns_exchange(system, ASTERISKD_DNS_OP_DEACTIVATE) == 0) {
        uint64_t until = asteriskd_dns_monotime() + SYSTEM_DNS_WITHDRAW_BUDGET_MILLIS;
        while (system->dns.fd >= 0 && asteriskd_dns_monotime() < until) {
            if (system_dns_exchange(system, ASTERISKD_DNS_OP_RELEASE) != 0) break;
            if (system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_INACTIVE &&
                system->dns.retained == 0) {
                system->dns.suspended = true;
                return 0;
            }
            if (system_dns_wait_release(system, until) != 0) break;
        }
    } else if (system->dns.suspended)
        return 0;
    // Closing the owner connection requests withdrawal. A blocked companion
    // may process it later; teardown does not promise a timed revocation.
    asteriskd_dns_close(&system->dns);
    if (system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_FAILED)
        system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
    return 0;
}

int asteriskd_supervisor_runtime_request_dns(
    void *opaque, const struct asteriskd_control_request *request, bool poll) {
    struct asteriskd_system_supervisor *system = opaque;
    if (poll) {
        if (request->instance_id != system->dns_hot_request.instance_id ||
            request->cycle_id != system->dns_hot_request.cycle_id ||
            request->generation != system->dns_hot_request.generation ||
            strcmp(request->request_id, system->dns_hot_request.request_id))
            return -1;
        if (request->method == ASTERISKD_CONTROL_METHOD_DNS_ABORT) {
            if (system->state.phase == ASTERISKD_PHASE_STOPPED) return 1;
            if (system->state.phase == ASTERISKD_PHASE_FAILED && !system->runtime->supervising)
                return -1;
            return 0;
        }
        return system->dns_hot_result;
    }
    if (request->method == ASTERISKD_CONTROL_METHOD_DNS_ABORT) {
        bool current = request->instance_id == system->dns.snapshot.instance_id &&
            request->cycle_id == system->dns.snapshot.cycle_id &&
            request->generation == system->dns.snapshot.generation;
        bool operation =
            (system->dns_hot_stage ||
                (system->dns_hot_result == 1 &&
                    system->dns_hot_request.method == ASTERISKD_CONTROL_METHOD_DNS_RESUME &&
                    system->dns_hot_completed_generation == system->dns.snapshot.generation)) &&
            request->instance_id == system->dns.snapshot.instance_id &&
            request->cycle_id == system->dns.snapshot.cycle_id &&
            request->instance_id == system->dns_hot_request.instance_id &&
            request->cycle_id == system->dns_hot_request.cycle_id &&
            request->generation == system->dns_hot_request.generation;
        if (!system->loaded_config.config.dns_enhancement || (!current && !operation) ||
            !system->runtime || !system->runtime->supervising ||
            asteriskd_supervisor_runtime_request_stop(system) != 0)
            return -1;
        system->dns_regenerating = false;
        system->dns_hot_stage = SYSTEM_DNS_HOT_IDLE;
        system->dns_hot_result = 0;
        system->dns_hot_request = *request;
        system->dns.busy = true;
        return 0;
    }
    if (!system->loaded_config.config.dns_enhancement ||
        system->state.phase != ASTERISKD_PHASE_RUNNING || system->dns_hot_stage ||
        system->dns.busy || request->instance_id != system->dns.snapshot.instance_id ||
        request->cycle_id != system->dns.snapshot.cycle_id ||
        request->generation != system->dns.snapshot.generation)
        return -1;
    bool resume = request->method == ASTERISKD_CONTROL_METHOD_DNS_RESUME;
    if ((resume &&
            (!system->dns.suspended ||
                system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_INACTIVE)) ||
        (!resume && !asteriskd_dns_serving(system->dns.snapshot.phase)))
        return -1;
    system->dns_hot_completed_generation = 0;
    system->dns_regenerating = false;
    system->dns_hot_request = *request;
    system->dns_hot_result = 0;
    system->dns_hot_stage = resume ? SYSTEM_DNS_HOT_HELLO : SYSTEM_DNS_HOT_DEACTIVATE;
    system->dns_hot_deadline = asteriskd_dns_monotime() + SYSTEM_DNS_TRANSITION_BUDGET_MILLIS;
    system->dns.busy = true;
    return 0;
}

static bool system_dns_consumers_live(struct asteriskd_system_supervisor *system) {
    return !system->core_reaped && !system->helper_reaped && !system->stop_requested &&
        !system->manual_stop_pending && !system->shutdown_requested &&
        !system->cleanup_in_progress &&
        (!system->runtime ||
            (!(system->runtime->pending_delta.flags &
                 (ASTERISKD_DELTA_STOP_REQUESTED | ASTERISKD_DELTA_CHILD_EXITED |
                     ASTERISKD_DELTA_FATAL)) &&
                !asteriskd_runtime_lifecycle_stop_requested(system->runtime)));
}
static bool system_dns_consumers_current(struct asteriskd_system_supervisor *system) {
    return system->rules_verified && system_dns_consumers_live(system);
}
bool asteriskd_supervisor_dns_waiting_for_rules(struct asteriskd_system_supervisor *system) {
    return (system->dns_hot_stage == SYSTEM_DNS_HOT_HELLO ||
               system->dns_hot_stage == SYSTEM_DNS_HOT_ACTIVATE) &&
        system->rules_reconciling && !system->rules_verified && system_dns_consumers_live(system);
}
static int system_dns_complete(
    struct asteriskd_system_supervisor *system, int result, uint64_t now) {
    system->dns_hot_stage = SYSTEM_DNS_HOT_IDLE;
    system->dns_hot_result = result;
    system->dns.busy = false;
    // Queue the original request's immutable response in this dispatch, before
    // another request can replace dns_hot_request. Tick does not pump or write.
    return system->control ? asteriskd_control_server_tick(system->control, now) : 0;
}
static int system_dns_activate(struct asteriskd_system_supervisor *system, uint64_t now) {
    // Activation still requires live consumers and an acknowledged PREPARE.
    struct asteriskd_runtime_delta delta;
    asteriskd_runtime_delta_init(&delta);
    if (asteriskd_supervisor_runtime_reap_children(system, &delta) != 0 || delta.flags) return -1;
    // A paused/descheduled reactor must not activate with its old tick time.
    uint64_t current = asteriskd_dns_monotime();
    if (current > now) now = current;
    if (!system_dns_consumers_current(system) ||
        system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_PREPARED)
        return -1;
    return asteriskd_dns_command(&system->dns, ASTERISKD_DNS_OP_ACTIVATE, NULL, now);
}
int asteriskd_supervisor_dns_verify_startup(struct asteriskd_system_supervisor *system) {
    const uint64_t until = system->dns_startup_deadline;
    do {
        if (asteriskd_dns_monotime() >= until) break;
        int activated = system_dns_exchange(system, ASTERISKD_DNS_OP_ACTIVATE);
        if (activated <= 0) return activated;
        asteriskd_log_stderr(ASTERISKD_LOG_LEVEL_INFO, ASTERISKD_COMPONENT_NETWORK,
            "DNS topology changed during startup; draining and preparing a fresh snapshot");
        while (asteriskd_dns_monotime() < until) {
            if (system_dns_exchange(system, ASTERISKD_DNS_OP_RELEASE) != 0) return -1;
            if (system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_INACTIVE && !system->dns.retained)
                break;
            if (system_dns_wait_release(system, until) != 0) break;
        }
        if (asteriskd_dns_monotime() >= until || system->stop_requested ||
            system->manual_stop_pending || system->shutdown_requested)
            break;
        system->dns.suspended = true;
        system->dns.topology_changed = false;
        if (asteriskd_supervisor_dns_prepare(system) != 0) return -1;
    } while (asteriskd_dns_monotime() < until);
    asteriskd_dns_fail(&system->dns, "DNS startup topology did not stabilize before deadline");
    return -1;
}

int asteriskd_supervisor_dns_tick(
    struct asteriskd_system_supervisor *system, struct asteriskd_runtime_delta *delta) {
    if (!system->dns.snapshot.required) return 0;
    uint64_t now = asteriskd_dns_monotime();
    if (!now) return -1;
    if (asteriskd_dns_step(&system->dns, now) != 0 &&
        system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_FAILED &&
        system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_UNSUPPORTED)
        asteriskd_dns_fail(&system->dns, "DNS transport progress failed");
    if (system->dns.topology_changed && !system->dns_hot_stage && !system->cleanup_in_progress &&
        system->state.phase == ASTERISKD_PHASE_RUNNING) {
        system->dns.topology_changed = false;
        system->dns_regenerating = true;
        system->dns_drain_waiting = false;
        memset(&system->dns_hot_request, 0, sizeof(system->dns_hot_request));
        system->dns_hot_completed_generation = 0;
        system->dns_hot_stage = SYSTEM_DNS_HOT_RELEASE;
        system->dns_hot_result = 0;
        system->dns_hot_deadline = now + SYSTEM_DNS_TRANSITION_BUDGET_MILLIS;
        system->dns.busy = true;
    }
    // Network configuration may change again between PREPARE and ACTIVATE.
    // The authenticated CACHE_ERROR response has already withdrawn the policy.
    // Drain and prepare a fresh generation within the original operation budget.
    if (system->dns.topology_changed && system->dns_hot_stage == SYSTEM_DNS_HOT_ACTIVATED) {
        system->dns.topology_changed = false;
        system->dns_hot_stage = SYSTEM_DNS_HOT_RELEASE;
        system->dns_drain_waiting = false;
    }
    if (system->dns_hot_stage) {
        if (now >= system->dns_hot_deadline && system->dns_regenerating &&
            (system->dns_hot_stage == SYSTEM_DNS_HOT_WAIT_NETWORK ||
                (system->dns.drain_events &&
                    (system->dns_hot_stage == SYSTEM_DNS_HOT_RELEASE ||
                        system->dns_hot_stage == SYSTEM_DNS_HOT_RELEASED))) &&
            system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_FAILED &&
            system->dns.snapshot.phase != ASTERISKD_DNS_PHASE_UNSUPPORTED) {
            // A network-driven rebuild that only waits for in-flight queries or
            // the next network event is not a service failure. The policy is
            // withdrawn (selected queries stay guarded), so keep waiting for
            // events without any timer instead of stopping the service.
            system->dns_hot_deadline = UINT64_MAX;
            (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_WARNING,
                ASTERISKD_COMPONENT_NETWORK, ASTERISKD_LOG_EVENT_DIAGNOSTIC,
                system->dns_hot_stage == SYSTEM_DNS_HOT_WAIT_NETWORK
                    ? "DNS rebuild waiting for network event"
                    : "DNS rebuild waiting for in-flight queries to finish");
        }
        if (now >= system->dns_hot_deadline ||
            system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_FAILED ||
            system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_UNSUPPORTED)
            goto hot_failed;
        if (system->dns.pending) return 0;
        int stage = system->dns_hot_stage;
        if (stage == SYSTEM_DNS_HOT_DEACTIVATE) {
            if (asteriskd_dns_command(&system->dns, ASTERISKD_DNS_OP_DEACTIVATE, NULL, now) != 0)
                goto hot_failed;
            system->dns_hot_stage = SYSTEM_DNS_HOT_RELEASE;
        } else if (stage == SYSTEM_DNS_HOT_RELEASE) {
            if (system->dns_drain_waiting && system->dns.drain_events) {
                // RELEASE answered DRAINING; the module reports completion.
                if (!system->dns.network_changed) return 0;
                system->dns.network_changed = false;
            }
            system->dns_drain_waiting = false;
            if (asteriskd_dns_command(&system->dns, ASTERISKD_DNS_OP_RELEASE, NULL, now) != 0)
                goto hot_failed;
            system->dns_hot_stage = SYSTEM_DNS_HOT_RELEASED;
        } else if (stage == SYSTEM_DNS_HOT_RELEASED) {
            if (system->dns.retained ||
                system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_DRAINING) {
                system->dns_hot_stage = SYSTEM_DNS_HOT_RELEASE;
                system->dns_drain_waiting = true;
                return 0;
            }
            system->dns.suspended = true;
            system->dns.topology_changed = false;
            // Waiting may have disarmed the timeout; rebuilding has a fresh budget.
            if (system->dns_hot_deadline == UINT64_MAX)
                system->dns_hot_deadline = now + SYSTEM_DNS_TRANSITION_BUDGET_MILLIS;
            if (system->dns_regenerating ||
                system->dns_hot_request.method == ASTERISKD_CONTROL_METHOD_DNS_RESUME)
                system->dns_hot_stage = SYSTEM_DNS_HOT_HELLO;
            else
                return system_dns_complete(system, 1, now);
        } else if (stage == SYSTEM_DNS_HOT_HELLO) {
            if (asteriskd_supervisor_dns_waiting_for_rules(system)) return 0;
            if (!system_dns_consumers_current(system) || system_dns_begin_generation(system) != 0)
                goto hot_failed;
            system->dns_hot_stage = SYSTEM_DNS_HOT_PREPARE;
        } else if (stage == SYSTEM_DNS_HOT_PREPARE) {
            if (!(system->dns.result & system_dns_mode_bit(system)) ||
                asteriskd_dns_command(&system->dns, ASTERISKD_DNS_OP_PREPARE,
                    &system->loaded_config.config, now) != 0)
                goto hot_failed;
            system->dns_hot_stage = SYSTEM_DNS_HOT_ACTIVATE;
        } else if (stage == SYSTEM_DNS_HOT_ACTIVATE) {
            if (asteriskd_supervisor_dns_waiting_for_rules(system)) return 0;
            if (!system_dns_consumers_current(system)) goto hot_failed;
            if (system->dns.prepare_retry) {
                system->dns_hot_stage = SYSTEM_DNS_HOT_WAIT_NETWORK;
                return 0;
            }
            if (system_dns_activate(system, now) != 0) goto hot_failed;
            system->dns_hot_stage = SYSTEM_DNS_HOT_ACTIVATED;
        } else if (stage == SYSTEM_DNS_HOT_WAIT_NETWORK) {
            if (system->dns.network_changed) {
                system->dns.network_changed = false;
                if (system->dns.prepare_draining)
                    system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
                system->dns.suspended = true;
                system->dns_hot_stage = SYSTEM_DNS_HOT_HELLO;
                if (system->dns_hot_deadline == UINT64_MAX)
                    system->dns_hot_deadline = now + SYSTEM_DNS_TRANSITION_BUDGET_MILLIS;
            }
        } else if (stage == SYSTEM_DNS_HOT_ACTIVATED) {
            system->dns_hot_completed_generation =
                system->dns_regenerating ? 0 : system->dns.snapshot.generation;
            system->dns_regenerating = false;
            return system_dns_complete(system, 1, now);
        }
        return 0;
    }
    if (system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_FAILED && !system->dns.busy &&
        !system->cleanup_in_progress)
        asteriskd_supervisor_runtime_fatal(
            delta, ASTERISKD_COMPONENT_NETWORK, system->dns.snapshot.reason);
    return 0;
hot_failed:
    system->dns_regenerating = false;
    if (system->dns.snapshot.reason[0] &&
        (system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_FAILED ||
            system->dns.snapshot.phase == ASTERISKD_DNS_PHASE_UNSUPPORTED ||
            system->dns.prepare_retry)) {
        asteriskd_dns_close(&system->dns);
        system->dns.snapshot.phase = ASTERISKD_DNS_PHASE_FAILED;
    } else {
        char reason[192];
        snprintf(reason, sizeof(reason),
            "DNS hot transition %s: stage=%d phase=%d rulesVerified=%d reconciling=%d "
            "consumersLive=%d",
            now >= system->dns_hot_deadline ? "timed out" : "failed", system->dns_hot_stage,
            (int)system->dns.snapshot.phase, system->rules_verified, system->rules_reconciling,
            system_dns_consumers_live(system));
        asteriskd_dns_fail(&system->dns, reason);
    }
    asteriskd_supervisor_runtime_fatal(
        delta, ASTERISKD_COMPONENT_NETWORK, system->dns.snapshot.reason);
    return system_dns_complete(system, -1, now);
}

#endif

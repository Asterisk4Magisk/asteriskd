// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <string.h>

static bool asteriskd_wifi_identity_valid(
    const struct asteriskd_wifi_identity *identity) {
    return identity != NULL &&
        (!identity->has_ssid ||
            (identity->ssid_length > 0U &&
                identity->ssid_length <= ASTERISKD_MAX_WIFI_SSID_BYTES));
}

static bool asteriskd_wifi_identity_equal(
    const struct asteriskd_wifi_identity *left,
    const struct asteriskd_wifi_identity *right) {
    if (left->has_ssid != right->has_ssid ||
        left->has_bssid != right->has_bssid) {
        return false;
    }
    if (left->has_ssid &&
        (left->ssid_length != right->ssid_length ||
            memcmp(left->ssid, right->ssid, left->ssid_length) != 0)) {
        return false;
    }
    return !left->has_bssid ||
        memcmp(left->bssid, right->bssid, sizeof(left->bssid)) == 0;
}

void asteriskd_service_control_init(
    struct asteriskd_service_control_runtime *runtime,
    const struct asteriskd_service_control_config *config,
    bool service_running,
    time_t now) {
    if (runtime == NULL) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->config = config;
    runtime->desired_running = service_running;
    runtime->last_evaluated_time = now;
}

void asteriskd_service_control_set_service_running(
    struct asteriskd_service_control_runtime *runtime, bool running) {
    if (runtime == NULL) return;
    runtime->desired_running = running;
}

bool asteriskd_wifi_rule_matches(
    const struct asteriskd_wifi_rule_config *rule,
    const struct asteriskd_wifi_identity *identity) {
    size_t index;

    if (rule == NULL || rule->ssid_count > ASTERISKD_MAX_WIFI_IDENTIFIERS ||
        rule->bssid_count > ASTERISKD_MAX_WIFI_IDENTIFIERS) {
        return false;
    }
    if (rule->ssid_count == 0U && rule->bssid_count == 0U) return true;
    if (!asteriskd_wifi_identity_valid(identity)) return false;
    if (identity->has_ssid) {
        for (index = 0U; index < rule->ssid_count; ++index) {
            if (rule->ssids[index].length == identity->ssid_length &&
                memcmp(
                    rule->ssids[index].bytes,
                    identity->ssid,
                    identity->ssid_length) == 0) {
                return true;
            }
        }
    }
    if (identity->has_bssid) {
        for (index = 0U; index < rule->bssid_count; ++index) {
            if (memcmp(rule->bssids[index], identity->bssid, 6U) == 0) return true;
        }
    }
    return false;
}

static enum asteriskd_service_action asteriskd_service_control_apply(
    struct asteriskd_service_control_runtime *runtime,
    enum asteriskd_service_action action) {
    if (action == ASTERISKD_SERVICE_ACTION_START) {
        if (runtime->desired_running) return ASTERISKD_SERVICE_ACTION_NONE;
        runtime->desired_running = true;
        return action;
    }
    if (action == ASTERISKD_SERVICE_ACTION_STOP) {
        if (!runtime->desired_running) return ASTERISKD_SERVICE_ACTION_NONE;
        runtime->desired_running = false;
        return action;
    }
    return action;
}

static enum asteriskd_service_action asteriskd_service_control_rules(
    struct asteriskd_service_control_runtime *runtime,
    const struct asteriskd_wifi_rule_config *start,
    const struct asteriskd_wifi_rule_config *stop,
    const struct asteriskd_wifi_identity *identity) {
    bool stop_matches = stop->enabled && asteriskd_wifi_rule_matches(stop, identity);
    bool start_matches = start->enabled && asteriskd_wifi_rule_matches(start, identity);

    if (stop_matches) {
        return asteriskd_service_control_apply(
            runtime, ASTERISKD_SERVICE_ACTION_STOP);
    }
    if (start_matches) {
        return asteriskd_service_control_apply(
            runtime, ASTERISKD_SERVICE_ACTION_START);
    }
    return ASTERISKD_SERVICE_ACTION_NONE;
}

static void asteriskd_service_control_baseline(
    struct asteriskd_service_control_runtime *runtime,
    bool connected,
    const struct asteriskd_wifi_identity *identity) {
    runtime->wifi_baseline_established = true;
    runtime->wifi_connected = connected;
    memset(&runtime->previous_wifi, 0, sizeof(runtime->previous_wifi));
    if (connected && asteriskd_wifi_identity_valid(identity)) {
        runtime->previous_wifi = *identity;
    }
}

enum asteriskd_service_action asteriskd_service_control_on_wifi(
    struct asteriskd_service_control_runtime *runtime,
    enum asteriskd_wifi_transition transition,
    const struct asteriskd_wifi_identity *identity) {
    const struct asteriskd_wifi_identity *match_identity = identity;
    bool connected_transition;
    bool duplicate;

    if (runtime == NULL) return ASTERISKD_SERVICE_ACTION_NONE;
    connected_transition = transition == ASTERISKD_WIFI_TRANSITION_CONNECTED ||
        transition == ASTERISKD_WIFI_TRANSITION_ROAMED;
    if (transition == ASTERISKD_WIFI_TRANSITION_BASELINE_CONNECTED ||
        transition == ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED) {
        asteriskd_service_control_baseline(
            runtime,
            transition == ASTERISKD_WIFI_TRANSITION_BASELINE_CONNECTED,
            identity);
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    if (!runtime->wifi_baseline_established) {
        asteriskd_service_control_baseline(runtime, connected_transition, identity);
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    if (transition == ASTERISKD_WIFI_TRANSITION_DISCONNECTED) {
        if (runtime->wifi_connected) match_identity = &runtime->previous_wifi;
        duplicate = !runtime->wifi_connected;
        runtime->wifi_connected = false;
        memset(&runtime->previous_wifi, 0, sizeof(runtime->previous_wifi));
    } else if (connected_transition) {
        if (!asteriskd_wifi_identity_valid(identity)) return ASTERISKD_SERVICE_ACTION_NONE;
        duplicate = runtime->wifi_connected &&
            asteriskd_wifi_identity_equal(&runtime->previous_wifi, identity);
        runtime->wifi_connected = true;
        runtime->previous_wifi = *identity;
    } else {
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    if (duplicate || runtime->config == NULL || !runtime->config->enabled ||
        !runtime->config->wifi.enabled) {
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    if (connected_transition) {
        return asteriskd_service_control_rules(
            runtime,
            &runtime->config->wifi.connect_start,
            &runtime->config->wifi.connect_stop,
            match_identity);
    }
    return asteriskd_service_control_rules(
        runtime,
        &runtime->config->wifi.disconnect_start,
        &runtime->config->wifi.disconnect_stop,
        match_identity);
}

enum asteriskd_service_action asteriskd_service_control_reconcile_time(
    struct asteriskd_service_control_runtime *runtime, time_t now) {
    time_t latest_start = 0;
    time_t latest_stop = 0;
    bool has_start;
    bool has_stop;

    if (runtime == NULL) return ASTERISKD_SERVICE_ACTION_NONE;
    if (now <= runtime->last_evaluated_time) {
        runtime->last_evaluated_time = now;
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    if (runtime->config == NULL || !runtime->config->enabled ||
        !runtime->config->schedule.enabled) {
        runtime->last_evaluated_time = now;
        return ASTERISKD_SERVICE_ACTION_NONE;
    }
    has_start = asteriskd_cron_latest_between(
        &runtime->config->schedule.start,
        runtime->last_evaluated_time,
        now,
        &latest_start) == 0;
    has_stop = asteriskd_cron_latest_between(
        &runtime->config->schedule.stop,
        runtime->last_evaluated_time,
        now,
        &latest_stop) == 0;
    runtime->last_evaluated_time = now;
    if (!has_start && !has_stop) return ASTERISKD_SERVICE_ACTION_NONE;
    if (has_stop && (!has_start || latest_stop >= latest_start)) {
        return asteriskd_service_control_apply(
            runtime, ASTERISKD_SERVICE_ACTION_STOP);
    }
    return asteriskd_service_control_apply(runtime, ASTERISKD_SERVICE_ACTION_START);
}

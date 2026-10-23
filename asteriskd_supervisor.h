// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

/* Private interface shared by the asteriskd_supervisor*.c modules. */
#ifndef ASTERISKD_SUPERVISOR_H
#define ASTERISKD_SUPERVISOR_H

#include "asteriskd.h"
#include "bpf_cgroup_owned.h"
#include "asteriskd_keyguard.h"
#include "asteriskd_compat.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include "udp6_recovery_netlink.h"

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
#include <sys/syscall.h>
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

/* Runtime reactor state, owned by asteriskd_runtime.c. */
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

bool asteriskd_runtime_lifecycle_stop_requested(void *opaque);

#if defined(__linux__) || defined(__ANDROID__)
/* Supervisor-side waits for the DNS enhancement companion. */
#define SYSTEM_DNS_COMMAND_WAIT_MILLIS 2100
#define SYSTEM_DNS_WITHDRAW_BUDGET_MILLIS 5000
#define SYSTEM_DNS_TRANSITION_BUDGET_MILLIS 8000
#define SYSTEM_DNS_LEGACY_RELEASE_RETRY_MILLIS 20U

/* Steps of a hot DNS transition (suspend, resume or network rebuild). */
enum system_dns_hot_stage {
    SYSTEM_DNS_HOT_IDLE = 0,
    SYSTEM_DNS_HOT_DEACTIVATE = 1,
    SYSTEM_DNS_HOT_RELEASE = 2,
    SYSTEM_DNS_HOT_RELEASED = 3,
    SYSTEM_DNS_HOT_HELLO = 10,
    SYSTEM_DNS_HOT_PREPARE = 11,
    SYSTEM_DNS_HOT_ACTIVATE = 12,
    SYSTEM_DNS_HOT_ACTIVATED = 13,
    SYSTEM_DNS_HOT_WAIT_NETWORK = 14,
};

enum system_tc_netlink_query_kind {
    SYSTEM_TC_NETLINK_QUERY_NONE,
    SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER,
    SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER,
    SYSTEM_TC_NETLINK_QUERY_QDISC,
};

/*
 * Rule commands queued for one commit. iptables commands are kept as
 * iptables-restore lines per stage, family and table; stage 1 holds commands
 * queued after the first ip command, so hooks still follow routing. ip
 * commands are kept one per line as "<family> <arguments...>".
 */
#define SYSTEM_RULE_BATCH_STAGES 2U

struct system_rule_command_batch {
    struct asteriskd_byte_buffer
        xtables[SYSTEM_RULE_BATCH_STAGES][ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    struct asteriskd_byte_buffer ip;
    bool ip_started;
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
    struct asteriskd_keyguard_monitor *keyguard_monitor;
    struct asteriskd_service_control_runtime service_control;
    bool service_running;
    bool shutdown_requested;
    bool service_start_requested;
    bool service_pause_requested;
    bool service_resume_requested;
    struct asteriskd_effect_journal volatile_effects;
    uint64_t dns_instance, dns_cycle, dns_generation;
    struct asteriskd_dns_client dns;
    uint64_t dns_hot_deadline, dns_startup_deadline;
    uint64_t dns_hot_completed_generation;
    bool dns_regenerating, dns_drain_waiting;
    int dns_hot_stage, dns_hot_result;
    struct asteriskd_control_request dns_hot_request;
    bool stop_requested;
    bool automatic_stop_pending;
    bool manual_stop_pending;
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
    struct asteriskd_tun_compat_state tun_compatibility;
    struct asteriskd_matcher_launch matcher_launch;
    struct asteriskd_matcher_pin_plan matcher_pin_plan;
    struct asteriskd_matcher_verification matcher_verification;
    bool matcher_launch_ready;
    bool matcher_plan_ready;
    bool matcher_verified;
    struct asteriskd_b2s_pin_plan b2s_pin_plan;
    struct asteriskd_b2s_verification b2s_verification;
    bool b2s_plan_ready;
    bool b2s_verified;
    char b2s_verify_error[128U];
    int tc_netlink_fd;
    uint32_t tc_netlink_port_id;
    bool tc_netlink_fd_owned;
    bool tc_netlink_active;
    bool tc_netlink_done;
    bool tc_netlink_failed;
    uint32_t tc_netlink_sequence;
    uint32_t tc_netlink_interface_index;
    enum system_tc_netlink_query_kind tc_netlink_query;
    struct asteriskd_tc_filter_expectation tc_filter_netlink_expectation;
    enum asteriskd_rules_slot_state tc_filter_netlink_state;
    enum asteriskd_rules_slot_state tc_qdisc_netlink_state;
    enum asteriskd_pin_batch_kind active_pin_batch;
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
    /* Leading stderr bytes, reported only when an action fails. */
    char action_stderr[512U];
    size_t action_stderr_length;
    struct system_rule_command_batch rule_commands;
    struct system_rule_snapshot rule_snapshot;
    /* Table listings shared by one owned-resource reconciliation. */
    struct system_rule_view owned_xtables[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    bool owned_xtables_valid[ASTERISKD_IP_FAMILY_COUNT][ASTERISKD_IP_TABLE_COUNT];
    bool owned_snapshot_enabled;
    bool verify_private_rules;
    size_t verified_private_rule_count;
    struct asteriskd_system_process_context process_context;
    struct asteriskd_readiness_backend readiness_backend;
    struct asteriskd_stop_backend stop_backend;
    struct asteriskd_readiness_tracker readiness;
    int readiness_result;
    struct asteriskd_stop_coordinator stop_coordinator;
    int stop_result;
    struct asteriskd_network_runtime network;
    bool network_opened;
    struct asteriskd_network_effect_sink network_effect_sink;
    struct asteriskd_rules_runtime rules_runtime;
    struct asteriskd_rules_backend rules_backend;
    bool rules_initialized;
    bool rules_verified;
    bool rules_reconciling;
    bool local_address_snapshot_active;
    struct asteriskd_address_set local_ipv4_snapshot;
    struct asteriskd_address_set local_ipv6_snapshot;
    bool cleanup_in_progress;
    bool owned_cleanup_in_progress;
};

/* asteriskd_supervisor.c */
int asteriskd_supervisor_runtime_clock(void *opaque, int64_t *milliseconds);
void asteriskd_supervisor_runtime_fatal(struct asteriskd_runtime_delta *delta,
    enum asteriskd_component component, const char *message);
void asteriskd_supervisor_runtime_note_action_exit(
    struct asteriskd_system_supervisor *system, int status);
int asteriskd_supervisor_runtime_reap_children(
    struct asteriskd_system_supervisor *system, struct asteriskd_runtime_delta *delta);
int asteriskd_supervisor_runtime_request_stop(void *opaque);
int asteriskd_supervisor_accept_pump_delta(struct asteriskd_system_supervisor *system,
    struct asteriskd_runtime_delta *delta);
int asteriskd_supervisor_tun_compatibility_prepare(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_tun_compatibility_cleanup(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_start_helper_process(
    struct asteriskd_system_supervisor *system, struct asteriskd_child_identity *identity);
bool asteriskd_supervisor_stop_done(void *opaque);

/* asteriskd_supervisor_action.c */
bool asteriskd_supervisor_action_should_cancel(
    bool stop_requested, bool cleanup_in_progress);
int asteriskd_supervisor_pump_condition(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, asteriskd_runtime_predicate predicate);
int asteriskd_supervisor_pump_condition_periodic(struct asteriskd_system_supervisor *system,
    const struct asteriskd_deadline *deadline, uint32_t interval,
    asteriskd_runtime_predicate predicate);
void asteriskd_supervisor_log_failure(struct asteriskd_system_supervisor *system,
    enum asteriskd_component component, const char *message);
void asteriskd_supervisor_action_stderr_summary(
    const struct asteriskd_system_supervisor *system, char *out, size_t size);
int asteriskd_supervisor_action_run_spec(struct asteriskd_system_supervisor *system,
    const struct asteriskd_process_spec *spec, bool capture_stdout, int *exit_status);
int asteriskd_supervisor_action_run_argv(struct asteriskd_system_supervisor *system,
    const char *const *argv, bool capture_stdout, int *exit_status);
int asteriskd_supervisor_rule_batch_append_line(
    struct asteriskd_byte_buffer *batch, const char *const *tokens);
void asteriskd_supervisor_rule_batch_destroy(struct system_rule_command_batch *batch);
int asteriskd_supervisor_rule_batch_begin(struct system_rule_command_batch *batch);
int asteriskd_supervisor_rule_batch_flush(
    struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_effect_capability(void *opaque);

/* asteriskd_supervisor_rtnl.c */
int asteriskd_supervisor_rtnl_ip(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments,
    size_t argument_count, bool capture, int *exit_status);
int asteriskd_supervisor_rtnl_route_render(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const uint32_t *tables, size_t table_count);

/* asteriskd_supervisor_xtables.c */
const char *asteriskd_supervisor_table_name(enum asteriskd_ip_table table);
int asteriskd_supervisor_xtables_run(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, bool capture_stdout, int *exit_status);
int asteriskd_supervisor_xtables(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count, int *exit_status);
int asteriskd_supervisor_xtables_zero(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    const char *operation, const char *chain, const char *const *arguments,
    size_t argument_count);
int asteriskd_supervisor_create_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group);
int asteriskd_supervisor_verify_private_group_contents(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group);
int asteriskd_supervisor_remove_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group);
int asteriskd_supervisor_apply_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group);
int asteriskd_supervisor_probe_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group, bool *all_present,
    bool *any_present);
int asteriskd_supervisor_remove_hook_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_traffic_hook_group *group);
const struct asteriskd_private_chain_group *asteriskd_supervisor_find_private_group(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_iptables_chain_resource *resource);
const struct asteriskd_traffic_hook_group *asteriskd_supervisor_find_hook_group(
    const struct asteriskd_system_supervisor *system,
    const struct asteriskd_iptables_rule_resource *resource);
int asteriskd_supervisor_probe_private_group(struct asteriskd_system_supervisor *system,
    const struct asteriskd_private_chain_group *group, bool *all_present,
    bool *any_present);
int asteriskd_supervisor_ip_command(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments,
    size_t argument_count, bool capture, int *exit_status);
int asteriskd_supervisor_ip_zero(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments, size_t argument_count);
void asteriskd_supervisor_rule_snapshot_destroy(struct system_rule_snapshot *snapshot);
void asteriskd_supervisor_rule_view_destroy(struct system_rule_view *view);
int asteriskd_supervisor_rule_view_capture_table(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table,
    struct system_rule_view *view);
int asteriskd_supervisor_rule_snapshot_capture(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_rule_transaction_plan *plan,
    enum system_rule_snapshot_phase phase);

/* asteriskd_supervisor_tc.c */
int asteriskd_supervisor_tc_command(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count, bool capture,
    int *exit_status);
int asteriskd_supervisor_tc_zero(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count);
void asteriskd_supervisor_tc_netlink_close(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_tc_netlink_dispatch(
    struct asteriskd_system_supervisor *system, short ready);
int asteriskd_supervisor_expected_tc_netlink_probe(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state);
const char *asteriskd_supervisor_tc_direction(enum asteriskd_tc_direction direction);
int asteriskd_supervisor_tc_probe_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource, bool *present);
int asteriskd_supervisor_tc_probe_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state);
int asteriskd_supervisor_tc_apply_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource);
int asteriskd_supervisor_tc_apply_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource);

/* asteriskd_supervisor_rules.c */
int asteriskd_supervisor_remove_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect);
int asteriskd_supervisor_classify_route_effect(struct asteriskd_system_supervisor *system,
    const struct asteriskd_route_effect *effect,
    enum asteriskd_rules_slot_state *state);
const char *asteriskd_supervisor_pin_path(
    struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id);
uint64_t asteriskd_supervisor_verified_pin_id(
    const struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id);
const struct asteriskd_b2s_verified_pin *asteriskd_supervisor_b2s_verified_pin(
    const struct asteriskd_system_supervisor *system, enum asteriskd_pin_id pin_id);
int asteriskd_supervisor_sysctl_read(
    const struct asteriskd_sysctl_resource *resource, uint8_t *value);
struct asteriskd_effect_backend asteriskd_supervisor_effect_backend(
    struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_effect_apply_sysctl(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_sysctl_resource *resource,
    char *error, size_t error_size);
int asteriskd_supervisor_apply_and_verify(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_resource_operation *records,
    size_t count, char *error, size_t error_size);
void asteriskd_supervisor_rules_backend_init(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_network_effect_dispatch(void *opaque,
    const struct asteriskd_network_effect_request *request,
    char *error, size_t error_size);
int asteriskd_supervisor_sync_ipv6_guard(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_effect_rules(
    void *opaque, bool *active, uint64_t *generation, uint32_t *categories);

/* asteriskd_supervisor_network.c */
int asteriskd_supervisor_effect_start_matcher(void *opaque);
int asteriskd_supervisor_effect_start_helper(
    void *opaque, struct asteriskd_child_identity *identity);
int asteriskd_supervisor_effect_open_network(void *opaque);
int asteriskd_supervisor_collect_local_address_set(
    struct asteriskd_system_supervisor *system,
    int family,
    struct asteriskd_address_set *set);
int asteriskd_supervisor_capture_local_address_snapshot(
    struct asteriskd_system_supervisor *system);
void asteriskd_supervisor_clear_local_address_snapshot(
    struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_reconcile_iptables_local_bypass(
    struct asteriskd_system_supervisor *system, bool *changed);
int asteriskd_supervisor_reconcile_b2s_local_maps(
    struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_reconcile_hotspot_tc(struct asteriskd_system_supervisor *system);

/* asteriskd_supervisor_reconcile.c */
uint32_t asteriskd_supervisor_rule_categories(const struct asteriskd_config *config);
void asteriskd_supervisor_reconcile_error(
    char *error, size_t error_size, const char *message);
int asteriskd_supervisor_reconcile_remove_phase(
    void *opaque,
    enum asteriskd_reconcile_phase phase,
    char *error,
    size_t error_size);
int asteriskd_supervisor_reconcile_owned_resources(
    struct asteriskd_system_supervisor *system,
    char *error,
    size_t error_size);

/* asteriskd_supervisor_dns.c */
int asteriskd_supervisor_dns_exchange(struct asteriskd_system_supervisor *system, uint16_t opcode);
int asteriskd_supervisor_dns_prepare(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_dns_withdraw(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_runtime_request_dns(
    void *opaque, const struct asteriskd_control_request *request, bool poll);
bool asteriskd_supervisor_dns_waiting_for_rules(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_dns_activate(struct asteriskd_system_supervisor *system, uint64_t now);
int asteriskd_supervisor_dns_verify_startup(struct asteriskd_system_supervisor *system);
int asteriskd_supervisor_dns_tick(
    struct asteriskd_system_supervisor *system, struct asteriskd_runtime_delta *delta);

#endif

#endif

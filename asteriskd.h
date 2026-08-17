// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef ASTERISKD_H
#define ASTERISKD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <time.h>

struct asteriskd_recovery_record;

#define ASTERISKD_CONFIG_VERSION 3U
#define ASTERISKD_MAX_JSON_SIZE (8U * 1024U * 1024U)
#define ASTERISKD_JSON_MAX_TOKENS 262144U
#define ASTERISKD_JSON_MAX_DEPTH 64U
#define ASTERISKD_MAX_PATH 512U
#define ASTERISKD_MAX_SECRET_KEY 4096U
#define ASTERISKD_MAX_INTERFACES 64U
#define ASTERISKD_MAX_INTERFACE_NAME 64U
#define ASTERISKD_MAX_CIDRS 512U
#define ASTERISKD_MAX_DIRECT_CIDRS 32768U
#define ASTERISKD_MAX_CIDR 64U
#define ASTERISKD_MAX_UIDS 8192U
#define ASTERISKD_MAX_HOST 256U
#define ASTERISKD_MAX_TUNNEL_NAME 64U
#define ASTERISKD_MAX_ADDRESSES 256U
#define ASTERISKD_MAX_CHAIN_NAME 29U
#define ASTERISKD_MAX_NETWORK_EVENTS 16U
#define ASTERISKD_MAX_EMERGENCY_PROCESSES 8U
#define ASTERISKD_MAX_COMMAND_MARKER 256U
#define ASTERISKD_SYNC_DEBOUNCE_MILLIS 1500
#define ASTERISKD_STATE_VERSION 2U
#define ASTERISKD_STATE_LEAF "asteriskd.state"
#define ASTERISKD_LEGACY_ROUTE_LOCALNET_LEAF "asteriskd.state.route-localnet"
#define ASTERISKD_MAX_CHILD_ARGV 16U
#define ASTERISKD_MAX_PROCESS_ARGV 32U
#define ASTERISKD_MAX_CHILD_ARG 512U
#define ASTERISKD_MAX_STATE_MESSAGE 4096U
#define ASTERISKD_MAX_HEX_ID 129U
#define ASTERISKD_BPF_PROGRAM_TAG_HEX_LENGTH 16U
#define ASTERISKD_TC_BPF_FLAG_ACT_DIRECT UINT32_C(1)
#define ASTERISKD_TC_PARENT_CLSACT_INGRESS UINT32_C(0xfffffff2)
#define ASTERISKD_TC_PARENT_CLSACT_EGRESS UINT32_C(0xfffffff3)
#define ASTERISKD_TC_PARENT_CLSACT UINT32_C(0xfffffff1)
#define ASTERISKD_TC_HANDLE_CLSACT UINT32_C(0xffff0000)
#define ASTERISKD_LOG_MAX_CHILD_LINE 16384U
#define ASTERISKD_LOG_MAX_BUFFERED_PER_CHILD 65536U
#define ASTERISKD_LOG_PARTIAL_TIMEOUT_MILLIS 2000U
#define ASTERISKD_LOG_REDACTION "[REDACTED]"
#define ASTERISKD_CONTROL_PROTOCOL_VERSION 1U
#define ASTERISKD_CONTROL_MAX_PAYLOAD 65536U
#define ASTERISKD_CONTROL_REQUEST_TIMEOUT_MILLIS 2000U
#define ASTERISKD_CONTROL_MAX_REQUEST_ID 64U
#define ASTERISKD_CONTROL_MAX_CLIENTS 16U
#define ASTERISKD_CONTROL_WATCH_QUEUE_CAPACITY 262144U
#define ASTERISKD_CONTROL_WATCH_STALL_MILLIS 5000U
#define ASTERISKD_PROCESS_MAX_ENV 256U
#define ASTERISKD_PROCESS_MAX_INHERITED_ENV 1024U
#define ASTERISKD_PROCESS_MAX_ENV_ENTRY 8192U
#define ASTERISKD_PROCESS_MAX_INHERITED_FDS 8U
#define ASTERISKD_PROCESS_TERM_GRACE_MILLIS 3000U
#define ASTERISKD_PROCESS_KILL_REAP_MILLIS 1000U
#define ASTERISKD_PROCESS_EBPF_STABILITY_MILLIS 1000U
#define ASTERISKD_READINESS_POLL_INTERVAL_MILLIS 100U
#define ASTERISKD_ANONYMOUS_CREATE_CLOEXEC UINT32_C(0x1)
#define ASTERISKD_ANONYMOUS_CREATE_ALLOW_SEALING UINT32_C(0x2)
#define ASTERISKD_ANONYMOUS_SEAL_WRITE UINT32_C(0x1)
#define ASTERISKD_ANONYMOUS_SEAL_GROW UINT32_C(0x2)
#define ASTERISKD_ANONYMOUS_SEAL_SHRINK UINT32_C(0x4)
#define ASTERISKD_ANONYMOUS_SEAL_SEAL UINT32_C(0x8)
#define ASTERISKD_ANONYMOUS_REQUIRED_SEALS (ASTERISKD_ANONYMOUS_SEAL_WRITE | \
    ASTERISKD_ANONYMOUS_SEAL_GROW | ASTERISKD_ANONYMOUS_SEAL_SHRINK | \
    ASTERISKD_ANONYMOUS_SEAL_SEAL)
#define ASTERISKD_IPTABLES_WAIT_SECONDS 100U
#define ASTERISKD_ROUTE_RULE_PRIORITY 14599U
#define ASTERISKD_PRIMARY_MARK UINT32_C(0x20000000)
#define ASTERISKD_AUXILIARY_MARK UINT32_C(0x40000000)
#define ASTERISKD_MARK_MASK UINT32_C(0x60000000)
#define ASTERISKD_TPROXY_TABLE 160U
#define ASTERISKD_TPROXY_DUMMY_TABLE 164U
#define ASTERISKD_TUN_TABLE 168U
#define ASTERISKD_RULE_PLAN_MAX_OPERATIONS 32U
#define ASTERISKD_RULE_TRANSACTION_MAX_GROUPS 12U
#define ASTERISKD_RULE_TRANSACTION_MAX_NAMES 4U
#define ASTERISKD_RULE_TRANSACTION_MAX_HOOKS 4U
#define ASTERISKD_XTABLES_MAX_HOOK_ARGUMENTS 10U
#define ASTERISKD_RULE_TRANSACTION_MAX_ROUTES 8U
#define ASTERISKD_MAX_POLL_SOURCES 64U
#define ASTERISKD_MAX_NETWORK_IMMEDIATE_REQUESTS 64U
#define ASTERISKD_MAX_CRON_EXPRESSION 256U
#define ASTERISKD_MAX_WIFI_IDENTIFIERS 64U
#define ASTERISKD_MAX_WIFI_SSID_BYTES 32U

#define ASTERISKD_CONFIG_INVALID (-1)
#define ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION (-2)
#define ASTERISKD_CONFIG_NOT_READY (-3)
#define ASTERISKD_CONFIG_NO_MEMORY (-4)
#define ASTERISKD_CONFIG_IO (-5)
#define ASTERISKD_LIFECYCLE_START_FAILED (-1)
#define ASTERISKD_LIFECYCLE_STOP_REQUESTED (-2)
#define ASTERISKD_LIFECYCLE_PARTIAL_FAILURE (-3)
#define ASTERISKD_LIFECYCLE_STOP_FAILED (-4)
#define ASTERISKD_LIFECYCLE_CORE_EXITED (-5)
#define ASTERISKD_LIFECYCLE_HELPER_EXITED (-6)

#define ASTERISKD_STATE_OK 0
#define ASTERISKD_STATE_NOT_FOUND 1
#define ASTERISKD_STATE_INVALID (-20)
#define ASTERISKD_STATE_INCOMPATIBLE (-21)
#define ASTERISKD_STATE_IO (-22)
#define ASTERISKD_STATE_NO_MEMORY (-23)
#define ASTERISKD_STATE_WRITE_BLOCKED (-24)
#define ASTERISKD_WAL_INCOMPLETE (-25)

#define ASTERISKD_LOG_OK 0
#define ASTERISKD_LOG_INVALID (-30)
#define ASTERISKD_LOG_IO (-31)
#define ASTERISKD_LOG_NO_MEMORY (-32)

enum asteriskd_json_type {
    ASTERISKD_JSON_OBJECT,
    ASTERISKD_JSON_ARRAY,
    ASTERISKD_JSON_STRING,
    ASTERISKD_JSON_NUMBER,
    ASTERISKD_JSON_TRUE,
    ASTERISKD_JSON_FALSE,
    ASTERISKD_JSON_NULL,
};

struct asteriskd_cron_expression {
    uint64_t minutes;
    uint32_t hours;
    uint32_t days_of_month;
    uint16_t months;
    uint8_t days_of_week;
    bool any_day_of_month;
    bool any_day_of_week;
};

int asteriskd_cron_parse(const char *, struct asteriskd_cron_expression *);
bool asteriskd_cron_matches(
    const struct asteriskd_cron_expression *, const struct tm *);
int asteriskd_cron_next(
    const struct asteriskd_cron_expression *, time_t, time_t *);
int asteriskd_cron_latest_between(
    const struct asteriskd_cron_expression *, time_t, time_t, time_t *);

enum asteriskd_service_action {
    ASTERISKD_SERVICE_ACTION_NONE,
    ASTERISKD_SERVICE_ACTION_START,
    ASTERISKD_SERVICE_ACTION_STOP,
    ASTERISKD_SERVICE_ACTION_SHUTDOWN,
};

enum asteriskd_wifi_transition {
    ASTERISKD_WIFI_TRANSITION_BASELINE_CONNECTED,
    ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED,
    ASTERISKD_WIFI_TRANSITION_CONNECTED,
    ASTERISKD_WIFI_TRANSITION_ROAMED,
    ASTERISKD_WIFI_TRANSITION_DISCONNECTED,
};

struct asteriskd_wifi_identity {
    bool has_ssid;
    unsigned char ssid[ASTERISKD_MAX_WIFI_SSID_BYTES];
    size_t ssid_length;
    bool has_bssid;
    uint8_t bssid[6U];
};

struct asteriskd_wifi_ssid_config {
    unsigned char bytes[ASTERISKD_MAX_WIFI_SSID_BYTES];
    uint8_t length;
};

struct asteriskd_wifi_rule_config {
    bool enabled;
    struct asteriskd_wifi_ssid_config ssids[ASTERISKD_MAX_WIFI_IDENTIFIERS];
    size_t ssid_count;
    uint8_t bssids[ASTERISKD_MAX_WIFI_IDENTIFIERS][6U];
    size_t bssid_count;
};

struct asteriskd_schedule_control_config {
    bool enabled;
    struct asteriskd_cron_expression start;
    struct asteriskd_cron_expression stop;
};

struct asteriskd_wifi_control_config {
    bool enabled;
    struct asteriskd_wifi_rule_config connect_start;
    struct asteriskd_wifi_rule_config connect_stop;
    struct asteriskd_wifi_rule_config disconnect_start;
    struct asteriskd_wifi_rule_config disconnect_stop;
};

struct asteriskd_service_control_config {
    bool enabled;
    struct asteriskd_schedule_control_config schedule;
    struct asteriskd_wifi_control_config wifi;
};

struct asteriskd_service_control_runtime {
    const struct asteriskd_service_control_config *config;
    struct asteriskd_wifi_identity previous_wifi;
    bool wifi_baseline_established;
    bool wifi_connected;
    bool desired_running;
    time_t last_evaluated_time;
};

void asteriskd_service_control_init(
    struct asteriskd_service_control_runtime *,
    const struct asteriskd_service_control_config *, bool, time_t);
void asteriskd_service_control_set_service_running(
    struct asteriskd_service_control_runtime *, bool);
bool asteriskd_wifi_rule_matches(
    const struct asteriskd_wifi_rule_config *,
    const struct asteriskd_wifi_identity *);
enum asteriskd_service_action asteriskd_service_control_on_wifi(
    struct asteriskd_service_control_runtime *,
    enum asteriskd_wifi_transition,
    const struct asteriskd_wifi_identity *);
enum asteriskd_service_action asteriskd_service_control_reconcile_time(
    struct asteriskd_service_control_runtime *, time_t);

struct asteriskd_wifi_monitor {
    int fd;
    uint16_t family_id;
    uint32_t sequence;
    struct asteriskd_wifi_identity baseline_identity;
    uint64_t debounce_deadline_milliseconds;
    bool baseline_connected;
    bool debounce_armed;
    bool integrity_lost;
    bool opened;
};

int asteriskd_wifi_monitor_open(struct asteriskd_wifi_monitor *, char *, size_t);
int asteriskd_wifi_monitor_fd(const struct asteriskd_wifi_monitor *);
int asteriskd_wifi_monitor_baseline(
    const struct asteriskd_wifi_monitor *, enum asteriskd_wifi_transition *,
    struct asteriskd_wifi_identity *);
int asteriskd_wifi_monitor_handle(
    struct asteriskd_wifi_monitor *, enum asteriskd_wifi_transition *,
    struct asteriskd_wifi_identity *, bool *, char *, size_t);
bool asteriskd_wifi_monitor_next_deadline(
    const struct asteriskd_wifi_monitor *, uint64_t *);
int asteriskd_wifi_monitor_take_reconcile(
    struct asteriskd_wifi_monitor *, uint64_t, enum asteriskd_wifi_transition *,
    struct asteriskd_wifi_identity *, bool *, char *, size_t);
void asteriskd_wifi_monitor_close(struct asteriskd_wifi_monitor *);

struct asteriskd_json_token {
    enum asteriskd_json_type type;
    size_t start;
    size_t end;
    size_t parent;
    size_t child_count;
};

struct asteriskd_json_document {
    const char *source;
    size_t source_length;
    struct asteriskd_json_token *tokens;
    size_t token_count;
    size_t token_capacity;
};

enum asteriskd_owner {
    ASTERISKD_OWNER_NG,
    ASTERISKD_OWNER_BOX,
    ASTERISKD_OWNER_META,
};

enum asteriskd_core_type {
    ASTERISKD_CORE_XRAY,
    ASTERISKD_CORE_SING_BOX,
    ASTERISKD_CORE_MIHOMO,
};

enum asteriskd_mode {
    ASTERISKD_MODE_TPROXY,
    ASTERISKD_MODE_TUN,
    ASTERISKD_MODE_TUN2SOCKS,
    ASTERISKD_MODE_BPF2SOCKS,
    ASTERISKD_MODE_EBPF,
};

enum asteriskd_app_policy_mode {
    ASTERISKD_APP_POLICY_GLOBAL,
    ASTERISKD_APP_POLICY_BLACKLIST,
    ASTERISKD_APP_POLICY_WHITELIST,
};

enum asteriskd_helper_type {
    ASTERISKD_HELPER_NONE,
    ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL,
    ASTERISKD_HELPER_BPF2SOCKS,
};

struct asteriskd_matcher_config {
    bool enabled;
    char executable_path[ASTERISKD_MAX_PATH];
};

struct asteriskd_hev_helper_config {
    char executable_path[ASTERISKD_MAX_PATH];
    char socks_host[ASTERISKD_MAX_HOST];
    uint16_t socks_port;
    char tunnel_name[ASTERISKD_MAX_TUNNEL_NAME];
    uint32_t mtu;
    char ipv4_address[ASTERISKD_MAX_CIDR];
    bool has_ipv6_address;
    char ipv6_address[ASTERISKD_MAX_CIDR];
    bool multi_queue;
    bool tcp_fast_open;
    uint32_t tcp_read_write_timeout_milliseconds;
    uint32_t udp_read_write_timeout_milliseconds;
};

struct asteriskd_bpf_helper_config {
    char executable_path[ASTERISKD_MAX_PATH];
    char bridge_listen_address[ASTERISKD_MAX_HOST];
    uint16_t bridge_port;
    char socks_host[ASTERISKD_MAX_HOST];
    uint16_t socks_port;
    uint32_t worker_count;
    uint32_t tcp_buffer_size;
    uint32_t max_tcp_sessions;
    uint32_t tcp_connect_timeout_milliseconds;
    uint32_t tcp_idle_timeout_milliseconds;
    uint32_t udp_socket_buffer_size;
    uint32_t udp_batch_size;
    uint32_t max_udp_sessions;
    uint32_t max_udp_bindings;
    uint32_t udp_idle_timeout_seconds;
    uint32_t max_udp_pending_bytes;
    uint32_t dns_transaction_timeout_milliseconds;
};

struct asteriskd_helper_config {
    enum asteriskd_helper_type type;
    union {
        struct asteriskd_hev_helper_config hev;
        struct asteriskd_bpf_helper_config bpf;
    } value;
};

struct asteriskd_direct_cidrs {
    char (*ipv4)[ASTERISKD_MAX_CIDR];
    size_t ipv4_count;
    char (*ipv6)[ASTERISKD_MAX_CIDR];
    size_t ipv6_count;
};

struct asteriskd_config {
    uint32_t schema_version;
    uint32_t version;
    enum asteriskd_owner owner;
    enum asteriskd_core_type core_type;
    enum asteriskd_mode mode;
    char core_executable_path[ASTERISKD_MAX_PATH];
    char core_config_path[ASTERISKD_MAX_PATH];
    char state_path[ASTERISKD_MAX_PATH];
    char log_path[ASTERISKD_MAX_PATH];
    char working_directory[ASTERISKD_MAX_PATH];
    uint32_t readiness_timeout_milliseconds;
    bool has_age_secret_key;
    char age_secret_key[ASTERISKD_MAX_SECRET_KEY];

    bool enable_ipv6;
    bool disable_system_ipv6;
    bool enable_local_dns;
    bool enable_fake_dns;
    bool has_fake_dns_ipv4_pool;
    char fake_dns_ipv4_pool[ASTERISKD_MAX_CIDR];
    char ignored_interfaces[ASTERISKD_MAX_INTERFACES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t ignored_interface_count;
    char virtual_interfaces[ASTERISKD_MAX_INTERFACES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t virtual_interface_count;
    char hotspot_interface_prefixes[ASTERISKD_MAX_INTERFACES][ASTERISKD_MAX_INTERFACE_NAME];
    size_t hotspot_interface_prefix_count;
    char proxy_private_cidrs[ASTERISKD_MAX_CIDRS][ASTERISKD_MAX_CIDR];
    size_t proxy_private_cidr_count;
    char bypass_private_cidrs[ASTERISKD_MAX_CIDRS][ASTERISKD_MAX_CIDR];
    size_t bypass_private_cidr_count;
    enum asteriskd_app_policy_mode app_policy_mode;
    uint32_t *uids;
    size_t uid_count;
    uint32_t *bypass_uids;
    size_t bypass_uid_count;
    bool has_direct_cidr_paths;
    char direct_cidr_path_v4[ASTERISKD_MAX_PATH];
    char direct_cidr_path_v6[ASTERISKD_MAX_PATH];
    struct asteriskd_direct_cidrs *direct_cidrs;

    bool has_transparent_port;
    uint16_t transparent_port;
    bool has_tunnel_name;
    char tunnel_name[ASTERISKD_MAX_TUNNEL_NAME];
    struct asteriskd_matcher_config matcher;
    struct asteriskd_helper_config helper;
    struct asteriskd_service_control_config service_control;

};

enum asteriskd_rule_plan_operation_kind {
    ASTERISKD_RULE_PLAN_PREPARE_PRIVATE,
    ASTERISKD_RULE_PLAN_PREPARE_LOCAL_BYPASS,
    ASTERISKD_RULE_PLAN_PREPARE_MATCHER,
    ASTERISKD_RULE_PLAN_PREPARE_ROUTE,
    ASTERISKD_RULE_PLAN_PREPARE_DUMMY,
    ASTERISKD_RULE_PLAN_PREPARE_HELPER_TC,
    ASTERISKD_RULE_PLAN_POPULATE_POLICY,
    ASTERISKD_RULE_PLAN_POPULATE_DNS,
    ASTERISKD_RULE_PLAN_POPULATE_FAKE_DNS,
    ASTERISKD_RULE_PLAN_ACTIVATE_MAIN,
    ASTERISKD_RULE_PLAN_ACTIVATE_DNS,
    ASTERISKD_RULE_PLAN_ACTIVATE_FAKE_DNS,
    ASTERISKD_RULE_PLAN_QUIESCE_MAIN,
    ASTERISKD_RULE_PLAN_QUIESCE_DNS,
    ASTERISKD_RULE_PLAN_QUIESCE_FAKE_DNS,
    ASTERISKD_RULE_PLAN_REMOVE_PRIVATE,
};

struct asteriskd_rule_plan_operation {
    enum asteriskd_rule_plan_operation_kind kind;
    bool traffic_activation;
};

struct asteriskd_rule_plan {
    bool no_op;
    bool enable_ipv6;
    bool uses_matcher;
    bool uses_dummy_ipv6;
    bool dummy_output_policy_compatibility;
    bool uses_helper_tc;
    uint32_t iptables_wait_seconds;
    uint32_t route_rule_priority;
    uint32_t primary_mark;
    uint32_t auxiliary_mark;
    uint32_t mark_mask;
    uint32_t routing_table;
    char tunnel_name[ASTERISKD_MAX_TUNNEL_NAME];
    bool has_token_ipv6_route;
    char token_ipv6_prefix[ASTERISKD_MAX_CIDR];
    struct asteriskd_rule_plan_operation operations[ASTERISKD_RULE_PLAN_MAX_OPERATIONS];
    size_t operation_count;
    size_t first_activation;
};

int asteriskd_rule_plan_build(
    const struct asteriskd_config *, bool, struct asteriskd_rule_plan *);
int asteriskd_rule_quiesce_plan_build(
    const struct asteriskd_rule_plan *, struct asteriskd_rule_plan *);
size_t asteriskd_default_bypass_cidr_count(void);
const char *asteriskd_default_bypass_cidr(size_t);

enum asteriskd_packet_direction {
    ASTERISKD_PACKET_PREROUTING,
    ASTERISKD_PACKET_OUTPUT,
};

enum asteriskd_packet_protocol {
    ASTERISKD_PACKET_TCP,
    ASTERISKD_PACKET_UDP,
    ASTERISKD_PACKET_ICMP,
};

enum asteriskd_packet_action {
    ASTERISKD_PACKET_NONE,
    ASTERISKD_PACKET_RETURN,
    ASTERISKD_PACKET_MARK_PRIMARY,
    ASTERISKD_PACKET_TPROXY,
    ASTERISKD_PACKET_MARK_AUXILIARY,
    ASTERISKD_PACKET_DROP,
    ASTERISKD_PACKET_REJECT,
    ASTERISKD_PACKET_FAKE_DNS_REDIRECT,
};

struct asteriskd_packet_model_input {
    enum asteriskd_packet_direction direction;
    enum asteriskd_packet_protocol protocol;
    bool ipv6;
    bool destination_port_53;
    bool icmp_echo;
    bool bypass_uid;
    bool uid_listed;
    bool core_gid;
    bool local_address;
    bool proxy_private;
    bool bypass_private;
    bool primary_marked;
    bool output_virtual_interface;
    bool output_ignored_interface;
    bool hotspot_input;
    bool matcher_selected;
};

int asteriskd_packet_model_decide(
    const struct asteriskd_config *, const struct asteriskd_rule_plan *,
    const struct asteriskd_packet_model_input *, enum asteriskd_packet_action *);

struct asteriskd_lifecycle_backend {
    int (*acquire)(void *);
    int (*recover)(void *);
    int (*start_core)(void *);
    int (*wait_core)(void *);
    int (*ensure_platform_capability)(void *);
    int (*start_helper)(void *);
    int (*wait_helper)(void *);
    int (*start_matcher)(void *);
    int (*open_network)(void *);
    int (*apply_rules)(void *);
    int (*verify)(void *);
    bool (*stop_requested)(void *);
    int (*quiesce_traffic)(void *);
    int (*remove_rules)(void *);
    int (*close_network)(void *);
    int (*stop_matcher)(void *);
    int (*stop_helper)(void *);
    int (*stop_core)(void *);
    int (*restore)(void *);
    int (*release)(void *);
};

struct asteriskd_lifecycle_effect {
    bool attempted;
    bool cleanup_required;
    bool succeeded;
};

struct asteriskd_lifecycle_capability {
    bool attempted;
    bool succeeded;
    bool partial;
};

struct asteriskd_lifecycle_options {
    bool has_helper;
    bool has_matcher;
    bool requires_platform_capability;
    bool standalone_ebpf;
};

enum asteriskd_child_role {
    ASTERISKD_CHILD_CORE,
    ASTERISKD_CHILD_HELPER,
};

enum asteriskd_lifecycle_reason {
    ASTERISKD_LIFECYCLE_REASON_NONE,
    ASTERISKD_LIFECYCLE_REASON_CONTROL_STOP,
    ASTERISKD_LIFECYCLE_REASON_SIGTERM,
    ASTERISKD_LIFECYCLE_REASON_SIGINT,
    ASTERISKD_LIFECYCLE_REASON_START_FAILED,
    ASTERISKD_LIFECYCLE_REASON_RUNTIME_FAILED,
    ASTERISKD_LIFECYCLE_REASON_CORE_EXITED,
    ASTERISKD_LIFECYCLE_REASON_HELPER_EXITED,
};

struct asteriskd_lifecycle {
    const struct asteriskd_lifecycle_backend *backend;
    void *backend_context;
    struct asteriskd_lifecycle_effect acquire;
    struct asteriskd_lifecycle_effect recover;
    struct asteriskd_lifecycle_effect core;
    struct asteriskd_lifecycle_effect helper;
    struct asteriskd_lifecycle_effect matcher;
    struct asteriskd_lifecycle_effect network;
    struct asteriskd_lifecycle_effect rules;
    struct asteriskd_lifecycle_capability platform_capability;
    struct asteriskd_lifecycle_options options;
    bool initialized;
    bool traffic_may_be_active;
    atomic_bool stop_was_requested;
    bool starting;
    bool stopped;
    const char *failure_stage;
    atomic_bool terminal_latch_locked;
    _Atomic(enum asteriskd_lifecycle_reason) terminal_reason;
    atomic_bool has_child_exit_status;
    _Atomic(enum asteriskd_child_role) child_exit_role;
    atomic_int child_exit_status;
};

int asteriskd_json_parse(const char *, size_t, struct asteriskd_json_document *, char *, size_t);
void asteriskd_json_document_destroy(struct asteriskd_json_document *);
bool asteriskd_interface_selector_valid(const char *);
bool asteriskd_interface_matches_selector(const char *, const char *);
int asteriskd_config_parse(const char *, size_t, struct asteriskd_config *, char *, size_t);
int asteriskd_config_load_direct_cidrs(
    struct asteriskd_config *, const char *, size_t, const char *, size_t);
void asteriskd_config_destroy(struct asteriskd_config *);

struct asteriskd_runtime_directory {
    int fd;
    bool owned;
    uint64_t device;
    uint64_t inode;
    void (*close_owned_fd)(void *, int);
    void *close_context;
};

struct asteriskd_loaded_config {
    struct asteriskd_config config;
    struct asteriskd_runtime_directory directory;
    int config_fd;
    bool config_fd_owned;
    uint64_t config_device;
    uint64_t config_inode;
    void (*close_owned_fd)(void *, int);
    void *close_context;
};

struct asteriskd_config_load_backend {
    int (*open_directory)(void *, const char *, int *, uint64_t *, uint64_t *);
    int (*read_config)(void *, int, const char *, char **, size_t *, int *, uint64_t *, uint64_t *);
    int (*validate_files)(void *, const struct asteriskd_config *, int);
    int (*read_resource)(void *, int, const char *, char **, size_t *);
    void (*close_fd)(void *, int);
};

int asteriskd_config_load(const char *, struct asteriskd_loaded_config *, char *, size_t);
int asteriskd_config_load_with_backend(
    const char *,
    struct asteriskd_loaded_config *,
    const struct asteriskd_config_load_backend *,
    void *,
    char *,
    size_t);
void asteriskd_loaded_config_release(struct asteriskd_loaded_config *);
void asteriskd_runtime_directory_release(struct asteriskd_runtime_directory *);
int asteriskd_runtime_directory_open(
    const char *, struct asteriskd_runtime_directory *, char *, size_t);
bool asteriskd_mode_is_readable(uint32_t);
bool asteriskd_mode_is_writable(uint32_t);
bool asteriskd_mode_is_executable(uint32_t);

enum asteriskd_file_kind {
    ASTERISKD_FILE_REGULAR,
    ASTERISKD_FILE_DIRECTORY,
    ASTERISKD_FILE_FIFO,
    ASTERISKD_FILE_DEVICE,
    ASTERISKD_FILE_SYMLINK,
    ASTERISKD_FILE_OTHER,
};

bool asteriskd_file_requirements_valid(
    enum asteriskd_file_kind,
    uint32_t,
    enum asteriskd_file_kind,
    bool,
    bool,
    bool);
int asteriskd_file_requirements_validate(
    enum asteriskd_file_kind,
    uint32_t,
    enum asteriskd_file_kind,
    bool,
    bool,
    bool);
int asteriskd_load_config(const char *, struct asteriskd_config *, char *, size_t);

enum asteriskd_process_output_mode {
    ASTERISKD_PROCESS_OUTPUT_CAPTURE,
    ASTERISKD_PROCESS_OUTPUT_APPEND_CORE_LOG,
    ASTERISKD_PROCESS_OUTPUT_DISCARD,
    ASTERISKD_PROCESS_OUTPUT_COUNT,
};

struct asteriskd_process_spec {
    char executable_path[ASTERISKD_MAX_PATH];
    char working_directory[ASTERISKD_MAX_PATH];
    uint32_t uid;
    uint32_t gid;
    char argv[ASTERISKD_MAX_PROCESS_ARGV][ASTERISKD_MAX_CHILD_ARG];
    size_t argc;
    char **environment;
    size_t environment_count;
    int inherited_fds[ASTERISKD_PROCESS_MAX_INHERITED_FDS];
    int inherited_fd_targets[ASTERISKD_PROCESS_MAX_INHERITED_FDS];
    size_t inherited_fd_count;
    enum asteriskd_process_output_mode output_mode;
};

struct asteriskd_anonymous_document {
    unsigned char *bytes;
    size_t length;
};

struct asteriskd_helper_documents {
    struct asteriskd_anonymous_document config;
    bool has_direct_cidrs;
    struct asteriskd_anonymous_document direct_ipv4;
    struct asteriskd_anonymous_document direct_ipv6;
};

struct asteriskd_matcher_documents {
    struct asteriskd_anonymous_document policy;
    bool has_direct_cidrs;
    struct asteriskd_anonymous_document direct_ipv4;
    struct asteriskd_anonymous_document direct_ipv6;
};

struct asteriskd_anonymous_file {
    int fd;
    bool owned;
    size_t length;
};

struct asteriskd_anonymous_file_backend {
    void *context;
    int (*create)(void *, const char *, uint32_t, int *);
    ptrdiff_t (*write)(void *, int, const void *, size_t);
    int (*rewind)(void *, int);
    int (*add_seals)(void *, int, uint32_t);
    int (*get_seals)(void *, int, uint32_t *);
    int (*close)(void *, int);
};

struct asteriskd_helper_launch {
    struct asteriskd_process_spec process;
    struct asteriskd_anonymous_file config_file;
    bool has_direct_cidrs;
    struct asteriskd_anonymous_file direct_ipv4_file;
    struct asteriskd_anonymous_file direct_ipv6_file;
};

struct asteriskd_matcher_launch {
    struct asteriskd_process_spec process;
    struct asteriskd_anonymous_file policy_file;
    bool has_direct_cidrs;
    struct asteriskd_anonymous_file direct_ipv4_file;
    struct asteriskd_anonymous_file direct_ipv6_file;
};

int asteriskd_core_process_spec(
    const struct asteriskd_config *, const char *const *,
    struct asteriskd_process_spec *, char *, size_t);
void asteriskd_process_spec_destroy(struct asteriskd_process_spec *);
/* Shared adapter helpers; callers still own the enclosing process spec. */
int asteriskd_process_environment_rebuild(
    const char *const *, struct asteriskd_process_spec *);
int asteriskd_process_environment_add(
    struct asteriskd_process_spec *, const char *, const char *);
int asteriskd_process_argument_add(
    struct asteriskd_process_spec *, const char *);
int asteriskd_process_core_log_path(
    const struct asteriskd_process_spec *, char *, size_t);
int asteriskd_helper_render_documents(
    const struct asteriskd_config *, int, int,
    struct asteriskd_helper_documents *, char *, size_t);
void asteriskd_helper_documents_destroy(struct asteriskd_helper_documents *);
int asteriskd_helper_process_spec(
    const struct asteriskd_config *, const char *const *, int, int, int,
    struct asteriskd_process_spec *, char *, size_t);
int asteriskd_anonymous_file_create(
    const struct asteriskd_anonymous_file_backend *, const char *,
    const struct asteriskd_anonymous_document *, struct asteriskd_anonymous_file *,
    char *, size_t);
int asteriskd_anonymous_file_close(
    const struct asteriskd_anonymous_file_backend *, struct asteriskd_anonymous_file *);
const struct asteriskd_anonymous_file_backend *asteriskd_system_anonymous_file_backend(void);
int asteriskd_helper_launch_prepare(
    const struct asteriskd_config *, const char *const *,
    const struct asteriskd_anonymous_file_backend *,
    struct asteriskd_helper_launch *, char *, size_t);
int asteriskd_helper_launch_destroy(
    const struct asteriskd_anonymous_file_backend *, struct asteriskd_helper_launch *);
int asteriskd_matcher_render_documents(
    const struct asteriskd_config *, int, int,
    struct asteriskd_matcher_documents *, char *, size_t);
void asteriskd_matcher_documents_destroy(struct asteriskd_matcher_documents *);
int asteriskd_matcher_process_spec(
    const struct asteriskd_config *, const char *const *, int, int, int,
    struct asteriskd_process_spec *, char *, size_t);
int asteriskd_matcher_launch_prepare(
    const struct asteriskd_config *, const char *const *,
    const struct asteriskd_anonymous_file_backend *,
    struct asteriskd_matcher_launch *, char *, size_t);
int asteriskd_matcher_launch_destroy(
    const struct asteriskd_anonymous_file_backend *, struct asteriskd_matcher_launch *);

enum asteriskd_capability_tool_kind {
    ASTERISKD_CAPABILITY_TOOL_NONE,
    ASTERISKD_CAPABILITY_TOOL_LIVE_POLICY,
    ASTERISKD_CAPABILITY_TOOL_KSUD,
};

struct asteriskd_platform_capability_backend {
    void *context;
    int (*find_on_path)(void *, const char *, char *, size_t);
    int (*inspect_executable)(void *, const char *, bool *, bool *);
    int (*execute)(void *, const char *const *, char *, size_t, int *);
};

struct asteriskd_platform_capability_result {
    bool required;
    bool tool_found;
    bool partial_application;
    enum asteriskd_capability_tool_kind tool_kind;
    char tool_path[ASTERISKD_MAX_PATH];
    size_t applied_rule_count;
};

int asteriskd_platform_capability_ensure(
    const struct asteriskd_config *,
    const struct asteriskd_platform_capability_backend *,
    struct asteriskd_platform_capability_result *, char *, size_t);

struct asteriskd_child_setup_backend {
    void *context;
    int (*restore_signals)(void *);
    int (*create_session)(void *);
    int (*set_nofile_limit)(void *, uint64_t);
    int (*clear_supplementary_groups)(void *);
    int (*set_gid)(void *, uint32_t);
    int (*set_uid)(void *, uint32_t);
    int (*set_parent_death_signal)(void *, int);
    int (*get_parent_pid)(void *, int *);
    int (*prepare_descriptors)(void *, const struct asteriskd_process_spec *);
    int (*exec_process)(void *, const struct asteriskd_process_spec *);
};

int asteriskd_child_setup_run(
    const struct asteriskd_process_spec *, int,
    const struct asteriskd_child_setup_backend *, bool *, char *, size_t);

void asteriskd_lifecycle_init(struct asteriskd_lifecycle *);
int asteriskd_lifecycle_start(
    struct asteriskd_lifecycle *,
    const struct asteriskd_lifecycle_backend *,
    void *,
    const struct asteriskd_lifecycle_options *);
int asteriskd_lifecycle_stop(struct asteriskd_lifecycle *);
int asteriskd_lifecycle_request_stop(
    struct asteriskd_lifecycle *,
    enum asteriskd_lifecycle_reason);
int asteriskd_lifecycle_on_child_exit(struct asteriskd_lifecycle *, enum asteriskd_child_role, int);

enum asteriskd_phase {
    ASTERISKD_PHASE_VALIDATING,
    ASTERISKD_PHASE_ACQUIRING,
    ASTERISKD_PHASE_RECOVERING,
    ASTERISKD_PHASE_STARTING,
    ASTERISKD_PHASE_APPLYING_RULES,
    ASTERISKD_PHASE_RUNNING,
    ASTERISKD_PHASE_STOPPING,
    ASTERISKD_PHASE_STOPPED,
    ASTERISKD_PHASE_FAILED,
    ASTERISKD_PHASE_COUNT,
};

enum asteriskd_child_type {
    ASTERISKD_CHILD_TYPE_XRAY,
    ASTERISKD_CHILD_TYPE_SING_BOX,
    ASTERISKD_CHILD_TYPE_MIHOMO,
    ASTERISKD_CHILD_TYPE_HEV_SOCKS5_TUNNEL,
    ASTERISKD_CHILD_TYPE_BPF2SOCKS,
    ASTERISKD_CHILD_TYPE_COUNT,
};

enum asteriskd_component {
    ASTERISKD_COMPONENT_RUNTIME,
    ASTERISKD_COMPONENT_CORE,
    ASTERISKD_COMPONENT_HELPER,
    ASTERISKD_COMPONENT_MATCHER,
    ASTERISKD_COMPONENT_RULES,
    ASTERISKD_COMPONENT_NETWORK,
    ASTERISKD_COMPONENT_STATE,
    ASTERISKD_COMPONENT_LOG,
    ASTERISKD_COMPONENT_CONTROL,
    ASTERISKD_COMPONENT_COUNT,
};

enum asteriskd_failure_code {
    ASTERISKD_FAILURE_START_FAILED,
    ASTERISKD_FAILURE_READINESS_TIMEOUT,
    ASTERISKD_FAILURE_CHILD_EXITED,
    ASTERISKD_FAILURE_STATE_INVALID,
    ASTERISKD_FAILURE_STATE_INCOMPATIBLE,
    ASTERISKD_FAILURE_RESOURCE_COLLISION,
    ASTERISKD_FAILURE_IO_ERROR,
    ASTERISKD_FAILURE_STOP_FAILED,
    ASTERISKD_FAILURE_INTERNAL_ERROR,
    ASTERISKD_FAILURE_CODE_COUNT,
};

enum asteriskd_rule_category {
    ASTERISKD_RULE_CATEGORY_TPROXY,
    ASTERISKD_RULE_CATEGORY_ROUTING,
    ASTERISKD_RULE_CATEGORY_DNS,
    ASTERISKD_RULE_CATEGORY_FAKE_DNS,
    ASTERISKD_RULE_CATEGORY_LOCAL_BYPASS,
    ASTERISKD_RULE_CATEGORY_HOTSPOT,
    ASTERISKD_RULE_CATEGORY_TC,
    ASTERISKD_RULE_CATEGORY_BPF,
    ASTERISKD_RULE_CATEGORY_IPV6_GUARD,
    ASTERISKD_RULE_CATEGORY_COUNT,
};

#define ASTERISKD_RULE_CATEGORY_BIT(category) (UINT32_C(1) << (unsigned int)(category))
#define ASTERISKD_RULE_CATEGORY_ALL \
    ((UINT32_C(1) << (unsigned int)ASTERISKD_RULE_CATEGORY_COUNT) - UINT32_C(1))

struct asteriskd_child_identity {
    enum asteriskd_child_role role;
    enum asteriskd_child_type type;
    int pid;
    int process_group_id;
    uint64_t start_time_ticks;
    uint64_t exe_device;
    uint64_t exe_inode;
    char argv[ASTERISKD_MAX_PROCESS_ARGV][ASTERISKD_MAX_CHILD_ARG];
    size_t argc;
};

struct asteriskd_process_identity_backend {
    void *context;
    int (*read_stat)(void *, int, char *, size_t, size_t *);
    int (*read_exe_identity)(void *, int, uint64_t *, uint64_t *);
    int (*read_cmdline)(void *, int, unsigned char *, size_t, size_t *);
};

int asteriskd_process_identity_read(
    const struct asteriskd_process_identity_backend *, int,
    enum asteriskd_child_role, enum asteriskd_child_type,
    const struct asteriskd_process_spec *, struct asteriskd_child_identity *,
    char *, size_t);
const struct asteriskd_process_identity_backend *asteriskd_system_process_identity_backend(void);

enum asteriskd_readiness_result {
    ASTERISKD_READINESS_PENDING = 0,
    ASTERISKD_READINESS_READY = 1,
    ASTERISKD_READINESS_TIMEOUT = -1,
    ASTERISKD_READINESS_CONFLICT = -2,
    ASTERISKD_READINESS_CHILD_LOST = -3,
    ASTERISKD_READINESS_STOP_REQUESTED = -4,
    ASTERISKD_READINESS_IO = -5,
};

struct asteriskd_readiness_tracker {
    enum asteriskd_child_role role;
    enum asteriskd_mode mode;
    uint64_t deadline_milliseconds;
    bool stability_started;
    uint64_t stability_start_milliseconds;
    bool initialized;
};

struct asteriskd_readiness_backend {
    void *context;
    int (*identity_valid)(void *, const struct asteriskd_child_identity *, bool *);
    int (*listener_owned)(void *, const struct asteriskd_child_identity *, const char *, uint16_t, bool *);
    int (*interface_exists)(void *, const char *, bool *);
};

int asteriskd_readiness_preflight(
    const struct asteriskd_config *, enum asteriskd_child_role,
    const struct asteriskd_readiness_backend *);
int asteriskd_readiness_init(
    const struct asteriskd_config *, enum asteriskd_child_role, uint64_t,
    const struct asteriskd_readiness_backend *, struct asteriskd_readiness_tracker *);
int asteriskd_readiness_poll(
    const struct asteriskd_config *, struct asteriskd_readiness_tracker *,
    const struct asteriskd_child_identity *, const struct asteriskd_readiness_backend *,
    uint64_t, bool);
#if defined(ASTERISKD_TESTING)
int asteriskd_test_listener_table_line(
    const char *, uint16_t, size_t, const char *, uint64_t *);
#endif

struct asteriskd_child_exit_status {
    bool has_exit_code;
    int exit_code;
    bool has_signal;
    int signal_number;
};

struct asteriskd_child_process {
    int pid;
    int process_group_id;
    int pidfd;
    int stdout_fd;
    int stderr_fd;
    int setup_status_fd;
    bool owns_pidfd;
    bool owns_stdout_fd;
    bool owns_stderr_fd;
    bool owns_setup_status_fd;
};

enum asteriskd_child_setup_message_kind {
    ASTERISKD_CHILD_SETUP_WARNING_NOFILE = 1,
    ASTERISKD_CHILD_SETUP_FATAL = 2,
};

struct asteriskd_child_setup_message {
    uint32_t magic;
    uint32_t kind;
    int32_t error_number;
};

#define ASTERISKD_CHILD_SETUP_MESSAGE_MAGIC UINT32_C(0x41535432)

struct asteriskd_child_setup_stream {
    unsigned char partial[sizeof(struct asteriskd_child_setup_message)];
    size_t partial_length;
    bool nofile_warning;
    int nofile_error_number;
    bool fatal;
    int fatal_error_number;
    bool complete;
};

enum asteriskd_child_setup_stream_result {
    ASTERISKD_CHILD_SETUP_PENDING = 0,
    ASTERISKD_CHILD_SETUP_EXECUTED = 1,
    ASTERISKD_CHILD_SETUP_FAILED = -1,
    ASTERISKD_CHILD_SETUP_INVALID = -2,
};

int asteriskd_process_spawn_system(
    const struct asteriskd_process_spec *, struct asteriskd_child_process *, char *, size_t);
void asteriskd_child_process_close(struct asteriskd_child_process *);
int asteriskd_child_exit_status_from_wait(int, struct asteriskd_child_exit_status *);
void asteriskd_child_setup_stream_init(struct asteriskd_child_setup_stream *);
int asteriskd_child_setup_stream_feed(
    struct asteriskd_child_setup_stream *, const void *, size_t, bool);
#if defined(ASTERISKD_TESTING)
int asteriskd_test_action_post_setup(
    const struct asteriskd_child_setup_stream *, bool,
    const struct asteriskd_child_exit_status *, int *);
int asteriskd_test_action_post_identity(
    int, int, const struct asteriskd_child_setup_stream *, bool,
    const struct asteriskd_child_exit_status *, int *);
#endif

struct asteriskd_stop_role_state {
    bool present;
    bool cleanup_required;
    bool term_sent;
    bool kill_sent;
    bool signal_failed;
    bool reaped;
    struct asteriskd_child_identity identity;
    struct asteriskd_child_exit_status exit_status;
};

struct asteriskd_stop_coordinator {
    struct asteriskd_stop_role_state core;
    struct asteriskd_stop_role_state helper;
    uint64_t term_deadline_milliseconds;
    uint64_t kill_deadline_milliseconds;
    bool active;
    bool initialized;
};

struct asteriskd_stop_backend {
    void *context;
    int (*identity_valid)(void *, const struct asteriskd_child_identity *, bool *);
    int (*signal_group)(void *, const struct asteriskd_child_identity *, int);
    int (*reap)(void *, const struct asteriskd_child_identity *, bool *,
        struct asteriskd_child_exit_status *);
};

struct asteriskd_system_process_context {
    const struct asteriskd_process_identity_backend *identity_backend;
    const struct asteriskd_process_spec *core_spec;
    const struct asteriskd_process_spec *helper_spec;
};

enum asteriskd_stop_result {
    ASTERISKD_STOP_PENDING = 0,
    ASTERISKD_STOP_COMPLETE = 1,
    ASTERISKD_STOP_FAILED = -1,
};

void asteriskd_stop_coordinator_init(struct asteriskd_stop_coordinator *);
int asteriskd_stop_coordinator_begin(
    struct asteriskd_stop_coordinator *, const struct asteriskd_child_identity *,
    const struct asteriskd_child_identity *, const struct asteriskd_stop_backend *, uint64_t);
int asteriskd_stop_coordinator_poll(
    struct asteriskd_stop_coordinator *, const struct asteriskd_stop_backend *, uint64_t);
int asteriskd_system_process_backends_init(
    struct asteriskd_system_process_context *, const struct asteriskd_process_spec *,
    const struct asteriskd_process_spec *, struct asteriskd_readiness_backend *,
    struct asteriskd_stop_backend *);

enum asteriskd_recovery_status {
    ASTERISKD_RECOVERY_INTENT,
    ASTERISKD_RECOVERY_APPLIED,
};

enum asteriskd_recovery_kind {
    ASTERISKD_RECOVERY_IPTABLES_CHAIN,
    ASTERISKD_RECOVERY_IPTABLES_RULE,
    ASTERISKD_RECOVERY_IP_RULE,
    ASTERISKD_RECOVERY_ROUTE,
    ASTERISKD_RECOVERY_DUMMY_INTERFACE,
    ASTERISKD_RECOVERY_BPF_PIN,
    ASTERISKD_RECOVERY_TC_QDISC,
    ASTERISKD_RECOVERY_TC_FILTER,
    ASTERISKD_RECOVERY_SYSCTL,
    ASTERISKD_RECOVERY_TETHER_STATE,
    ASTERISKD_RECOVERY_KIND_COUNT,
};

enum asteriskd_ip_family {
    ASTERISKD_IP_FAMILY_IPV4,
    ASTERISKD_IP_FAMILY_IPV6,
    ASTERISKD_IP_FAMILY_COUNT,
};

enum asteriskd_ip_table {
    ASTERISKD_IP_TABLE_FILTER,
    ASTERISKD_IP_TABLE_NAT,
    ASTERISKD_IP_TABLE_MANGLE,
    ASTERISKD_IP_TABLE_COUNT,
};

enum asteriskd_chain_id {
    ASTERISKD_CHAIN_TPROXY,
    ASTERISKD_CHAIN_ROUTING,
    ASTERISKD_CHAIN_DNS,
    ASTERISKD_CHAIN_FAKE_DNS,
    ASTERISKD_CHAIN_LOCAL_BYPASS,
    ASTERISKD_CHAIN_HOTSPOT,
    ASTERISKD_CHAIN_COUNT,
};

enum asteriskd_rule_id {
    ASTERISKD_RULE_TPROXY_ENTRY,
    ASTERISKD_RULE_ROUTING_ENTRY,
    ASTERISKD_RULE_DNS_ENTRY,
    ASTERISKD_RULE_FAKE_DNS_ENTRY,
    ASTERISKD_RULE_LOCAL_BYPASS_ENTRY,
    ASTERISKD_RULE_HOTSPOT_ENTRY,
    ASTERISKD_RULE_COUNT,
};

enum asteriskd_ip_rule_id {
    ASTERISKD_IP_RULE_TPROXY,
    ASTERISKD_IP_RULE_TUNNEL,
    ASTERISKD_IP_RULE_TOKEN,
    ASTERISKD_IP_RULE_COUNT,
};

enum asteriskd_route_id {
    ASTERISKD_ROUTE_TPROXY,
    ASTERISKD_ROUTE_TUNNEL,
    ASTERISKD_ROUTE_TOKEN,
    ASTERISKD_ROUTE_COUNT,
};

enum asteriskd_interface_id {
    ASTERISKD_INTERFACE_IPV6_DUMMY,
    ASTERISKD_INTERFACE_COUNT,
};

enum asteriskd_pin_id {
    ASTERISKD_PIN_MATCHER_OUTPUT_V4,
    ASTERISKD_PIN_MATCHER_OUTPUT_V6,
    ASTERISKD_PIN_MATCHER_PREROUTING_V4,
    ASTERISKD_PIN_MATCHER_PREROUTING_V6,
    ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4,
    ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6,
    ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS,
    ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS,
    ASTERISKD_PIN_COUNT,
};

struct asteriskd_matcher_pin_expectation {
    enum asteriskd_pin_id pin_id;
    char path[ASTERISKD_MAX_PATH];
    char program_name[ASTERISKD_MAX_COMMAND_MARKER];
};

struct asteriskd_matcher_pin_plan {
    struct asteriskd_matcher_pin_expectation pins[4U];
    size_t pin_count;
};

int asteriskd_matcher_pin_plan_build(
    const struct asteriskd_config *, struct asteriskd_matcher_pin_plan *);
int asteriskd_matcher_pin_records_build(
    const struct asteriskd_matcher_pin_plan *, struct asteriskd_recovery_record *,
    size_t, size_t *);

enum asteriskd_qdisc_id {
    ASTERISKD_QDISC_HOTSPOT_CLSACT,
    ASTERISKD_QDISC_COUNT,
};

enum asteriskd_filter_id {
    ASTERISKD_FILTER_HOTSPOT_INGRESS,
    ASTERISKD_FILTER_HOTSPOT_EGRESS,
    ASTERISKD_FILTER_COUNT,
};

enum asteriskd_tc_direction {
    ASTERISKD_TC_DIRECTION_INGRESS,
    ASTERISKD_TC_DIRECTION_EGRESS,
    ASTERISKD_TC_DIRECTION_COUNT,
};

enum asteriskd_program_id {
    ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS,
    ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS,
    ASTERISKD_PROGRAM_COUNT,
};

enum asteriskd_sysctl_id {
    ASTERISKD_SYSCTL_DISABLE_IPV6,
    ASTERISKD_SYSCTL_ROUTE_LOCALNET,
    ASTERISKD_SYSCTL_COUNT,
};

enum asteriskd_tether_id {
    ASTERISKD_TETHER_DNSMASQ,
    ASTERISKD_TETHER_COUNT,
};

struct asteriskd_iptables_chain_resource {
    enum asteriskd_ip_family family;
    enum asteriskd_ip_table table;
    enum asteriskd_chain_id chain_id;
    bool original_presence;
};

struct asteriskd_iptables_rule_resource {
    enum asteriskd_ip_family family;
    enum asteriskd_ip_table table;
    enum asteriskd_chain_id chain_id;
    enum asteriskd_rule_id rule_id;
    bool has_interface;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool original_presence;
};

struct asteriskd_ip_rule_resource {
    enum asteriskd_ip_family family;
    enum asteriskd_ip_rule_id rule_id;
    bool original_presence;
};

struct asteriskd_route_resource {
    enum asteriskd_ip_family family;
    enum asteriskd_route_id route_id;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool original_presence;
};

struct asteriskd_dummy_interface_resource {
    enum asteriskd_interface_id interface_id;
    bool has_interface_index;
    uint32_t interface_index;
    bool original_presence;
};

struct asteriskd_bpf_pin_resource {
    enum asteriskd_pin_id pin_id;
    bool has_object_id;
    uint64_t object_id;
    bool original_presence;
};

struct asteriskd_tc_qdisc_resource {
    enum asteriskd_qdisc_id qdisc_id;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool original_presence;
};

struct asteriskd_tc_filter_resource {
    enum asteriskd_filter_id filter_id;
    enum asteriskd_tc_direction direction;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    enum asteriskd_program_id program_id;
    bool original_presence;
};

struct asteriskd_sysctl_resource {
    enum asteriskd_sysctl_id sysctl_id;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    uint8_t original_value;
    uint8_t desired_value;
};

struct asteriskd_tether_state_resource {
    enum asteriskd_tether_id tether_id;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool original_active;
    bool desired_active;
};

struct asteriskd_recovery_record {
    uint64_t record_id;
    enum asteriskd_recovery_status status;
    enum asteriskd_recovery_kind kind;
    union {
        struct asteriskd_iptables_chain_resource iptables_chain;
        struct asteriskd_iptables_rule_resource iptables_rule;
        struct asteriskd_ip_rule_resource ip_rule;
        struct asteriskd_route_resource route;
        struct asteriskd_dummy_interface_resource dummy_interface;
        struct asteriskd_bpf_pin_resource bpf_pin;
        struct asteriskd_tc_qdisc_resource tc_qdisc;
        struct asteriskd_tc_filter_resource tc_filter;
        struct asteriskd_sysctl_resource sysctl;
        struct asteriskd_tether_state_resource tether_state;
    } resource;
};

enum asteriskd_builtin_chain {
    ASTERISKD_BUILTIN_PREROUTING,
    ASTERISKD_BUILTIN_INPUT,
    ASTERISKD_BUILTIN_FORWARD,
    ASTERISKD_BUILTIN_OUTPUT,
    ASTERISKD_BUILTIN_COUNT,
};

enum asteriskd_hook_verdict {
    ASTERISKD_HOOK_JUMP,
    ASTERISKD_HOOK_DROP,
    ASTERISKD_HOOK_REJECT,
    ASTERISKD_HOOK_COUNT,
};

struct asteriskd_private_chain_group {
    enum asteriskd_ip_family family;
    enum asteriskd_ip_table table;
    enum asteriskd_chain_id chain_id;
    char names[ASTERISKD_RULE_TRANSACTION_MAX_NAMES][ASTERISKD_MAX_CHAIN_NAME];
    size_t name_count;
    struct asteriskd_recovery_record recovery;
};

struct asteriskd_traffic_hook {
    enum asteriskd_builtin_chain builtin_chain;
    bool insert_at_head;
    bool udp_destination_port_53;
    enum asteriskd_hook_verdict verdict;
    char jump_target[ASTERISKD_MAX_CHAIN_NAME];
};

struct asteriskd_traffic_hook_group {
    enum asteriskd_ip_family family;
    enum asteriskd_ip_table table;
    enum asteriskd_chain_id chain_id;
    enum asteriskd_rule_id rule_id;
    struct asteriskd_traffic_hook hooks[ASTERISKD_RULE_TRANSACTION_MAX_HOOKS];
    size_t hook_count;
    struct asteriskd_recovery_record recovery;
};

enum asteriskd_route_effect_kind {
    ASTERISKD_ROUTE_EFFECT_IP_RULE,
    ASTERISKD_ROUTE_EFFECT_ROUTE,
    ASTERISKD_ROUTE_EFFECT_DUMMY_INTERFACE,
};

struct asteriskd_route_effect {
    enum asteriskd_route_effect_kind kind;
    enum asteriskd_ip_family family;
    uint32_t table;
    uint32_t priority;
    uint32_t mark;
    uint32_t mark_mask;
    bool invert_from_all;
    bool local_route;
    enum asteriskd_ip_rule_id ip_rule_id;
    enum asteriskd_route_id route_id;
    enum asteriskd_interface_id interface_id;
    char destination[ASTERISKD_MAX_CIDR];
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char interface_address[ASTERISKD_MAX_CIDR];
};

struct asteriskd_rule_transaction_plan {
    bool no_op;
    struct asteriskd_private_chain_group private_groups[ASTERISKD_RULE_TRANSACTION_MAX_GROUPS];
    size_t private_group_count;
    struct asteriskd_route_effect routes[ASTERISKD_RULE_TRANSACTION_MAX_ROUTES];
    size_t route_count;
    struct asteriskd_traffic_hook_group hook_groups[ASTERISKD_RULE_TRANSACTION_MAX_GROUPS];
    size_t hook_group_count;
    bool hooks_are_last;
};

int asteriskd_rule_transaction_plan_build(
    const struct asteriskd_config *, bool, struct asteriskd_rule_transaction_plan *);
int asteriskd_rule_transaction_quiesce_plan_build(
    const struct asteriskd_rule_transaction_plan *, struct asteriskd_rule_transaction_plan *);
int asteriskd_tproxy_rule_transaction_plan_build(
    const struct asteriskd_config *, bool, struct asteriskd_rule_transaction_plan *);
int asteriskd_tun_rule_transaction_plan_build(
    const struct asteriskd_config *, struct asteriskd_rule_transaction_plan *);

enum asteriskd_rules_slot_state {
    ASTERISKD_RULES_SLOT_ABSENT,
    ASTERISKD_RULES_SLOT_OWNED,
    ASTERISKD_RULES_SLOT_FOREIGN,
};

int asteriskd_ip_rule_output_classify(
    const char *, size_t, const struct asteriskd_route_effect *,
    enum asteriskd_rules_slot_state *);
int asteriskd_ip_route_output_classify(
    const char *, size_t, const struct asteriskd_route_effect *,
    enum asteriskd_rules_slot_state *);

struct asteriskd_rules_backend {
    void *ctx;
    int (*wal_apply_plan)(void *, const struct asteriskd_rule_transaction_plan *);
    int (*wal_apply_private)(void *, const struct asteriskd_private_chain_group *);
    int (*wal_apply_route)(void *, const struct asteriskd_route_effect *);
    int (*wal_apply_hook)(void *, const struct asteriskd_traffic_hook_group *);
    int (*probe_private)(void *, const struct asteriskd_private_chain_group *,
        enum asteriskd_rules_slot_state *);
    int (*probe_route)(void *, const struct asteriskd_route_effect *,
        enum asteriskd_rules_slot_state *);
    int (*probe_hook)(void *, const struct asteriskd_traffic_hook_group *,
        enum asteriskd_rules_slot_state *);
    int (*wal_remove_private)(void *, const struct asteriskd_private_chain_group *);
    int (*wal_remove_route)(void *, const struct asteriskd_route_effect *);
    int (*wal_remove_hook)(void *, const struct asteriskd_traffic_hook_group *);
    int (*wal_recover_record)(void *, const struct asteriskd_recovery_record *);
};

struct asteriskd_rules_runtime {
    struct asteriskd_rule_transaction_plan plan;
    bool private_cleanup_required[ASTERISKD_RULE_TRANSACTION_MAX_GROUPS];
    bool route_cleanup_required[ASTERISKD_RULE_TRANSACTION_MAX_ROUTES];
    bool hook_cleanup_required[ASTERISKD_RULE_TRANSACTION_MAX_GROUPS];
    uint64_t generation;
    bool initialized;
    bool installed;
};

void asteriskd_rules_runtime_init(struct asteriskd_rules_runtime *);
bool asteriskd_xtables_private_chain_shape_valid(
    const char *, size_t, const char *, size_t);
size_t asteriskd_xtables_fake_dns_arguments(const char *, const char **);
int asteriskd_xtables_private_chain_counts(
    const char *, size_t, const char *, size_t *, size_t *);
size_t asteriskd_xtables_hook_arguments(
    const struct asteriskd_traffic_hook *, const char **);
int asteriskd_xtables_rule_output_count(
    const char *, size_t, const char *, const char *const *, size_t, size_t *);
int asteriskd_xtables_rule_output_locate(
    const char *, size_t, const char *, const char *const *, size_t, size_t *, size_t *);
int asteriskd_rules_recover(const struct asteriskd_recovery_record *, size_t,
    const struct asteriskd_rules_backend *);
int asteriskd_rules_install(struct asteriskd_rules_runtime *,
    const struct asteriskd_config *, bool, const struct asteriskd_rules_backend *);
int asteriskd_rules_verify(struct asteriskd_rules_runtime *,
    const struct asteriskd_rules_backend *);
int asteriskd_rules_remove(struct asteriskd_rules_runtime *,
    const struct asteriskd_rules_backend *);
int asteriskd_rules_reconcile(struct asteriskd_rules_runtime *,
    const struct asteriskd_rules_backend *);

enum asteriskd_poll_source_kind {
    ASTERISKD_POLL_SIGNAL,
    ASTERISKD_POLL_CONTROL_LISTENER,
    ASTERISKD_POLL_CONTROL_CLIENT,
    ASTERISKD_POLL_PROCESS_EXEC_ERROR,
    ASTERISKD_POLL_PROCESS_STDOUT,
    ASTERISKD_POLL_PROCESS_STDERR,
    ASTERISKD_POLL_PROCESS_PIDFD,
    ASTERISKD_POLL_NETWORK,
    ASTERISKD_POLL_TC_NETLINK,
    ASTERISKD_POLL_SERVICE_TIMER,
    ASTERISKD_POLL_WIFI,
    ASTERISKD_POLL_SOURCE_KIND_COUNT,
};

#if defined(ASTERISKD_TESTING)
bool asteriskd_test_action_source_active(
    bool, bool, enum asteriskd_poll_source_kind);
bool asteriskd_test_action_setup_wait_done(
    const struct asteriskd_child_setup_stream *, bool);
bool asteriskd_test_action_io_drained(bool, bool, bool, bool);
#endif

struct asteriskd_poll_source {
    int fd;
    short events;
    enum asteriskd_poll_source_kind kind;
    uint32_t slot;
    uint64_t generation;
};

struct asteriskd_poll_builder {
    struct asteriskd_poll_source sources[ASTERISKD_MAX_POLL_SOURCES];
    size_t count;
};

struct asteriskd_deadline {
    bool armed;
    int64_t monotonic_milliseconds;
};

enum asteriskd_runtime_delta_flag {
    ASTERISKD_DELTA_STOP_REQUESTED = UINT32_C(1) << 0,
    ASTERISKD_DELTA_CHILD_EXITED = UINT32_C(1) << 1,
    ASTERISKD_DELTA_NETWORK_CHANGED = UINT32_C(1) << 2,
    ASTERISKD_DELTA_RECONCILE_DUE = UINT32_C(1) << 3,
    ASTERISKD_DELTA_RULES_CHANGED = UINT32_C(1) << 4,
    ASTERISKD_DELTA_FATAL = UINT32_C(1) << 5,
};

struct asteriskd_runtime_delta {
    uint32_t flags;
    enum asteriskd_lifecycle_reason stop_reason;
    bool has_child_exit;
    enum asteriskd_child_role child_role;
    struct asteriskd_child_exit_status child_exit;
    bool has_rules_summary;
    uint64_t rules_generation;
    uint32_t rule_categories;
    bool has_error;
    enum asteriskd_failure_code error_code;
    enum asteriskd_component error_component;
    char error_message[256U];
};

#if defined(ASTERISKD_TESTING)
int asteriskd_test_start_failure_detail(
    int, const char *, struct asteriskd_runtime_delta *);
int asteriskd_test_capability_path_search_result(bool, bool);
int asteriskd_test_capability_inspect_error(int);
int asteriskd_test_periodic_deadline(int64_t, int64_t, uint32_t, int64_t *);
unsigned asteriskd_test_runtime_dispatch_priority(enum asteriskd_poll_source_kind);
bool asteriskd_test_startup_components_verified(
    bool, bool, bool, bool, bool, bool, bool, bool, bool);
#endif

enum asteriskd_reactor_wait_result {
    ASTERISKD_REACTOR_WAIT_ERROR = -1,
    ASTERISKD_REACTOR_WAIT_INTERRUPTED = -2,
};

struct asteriskd_runtime_reactor_backend {
    int (*monotonic_milliseconds)(void *, int64_t *);
    int (*prepare)(void *, struct asteriskd_poll_builder *, struct asteriskd_deadline *);
    int (*wait)(void *, const struct asteriskd_poll_builder *, int64_t, short *);
    int (*dispatch)(void *, const struct asteriskd_poll_source *, short,
        struct asteriskd_runtime_delta *);
    int (*expire)(void *, int64_t, struct asteriskd_runtime_delta *);
};

struct asteriskd_runtime;
typedef bool (*asteriskd_runtime_predicate)(void *);

void asteriskd_poll_builder_init(struct asteriskd_poll_builder *);
int asteriskd_poll_builder_add(
    struct asteriskd_poll_builder *, const struct asteriskd_poll_source *);
bool asteriskd_process_poll_source_matches(
    const struct asteriskd_child_process *, const struct asteriskd_poll_source *);
void asteriskd_deadline_min(struct asteriskd_deadline *, const struct asteriskd_deadline *);
void asteriskd_runtime_delta_init(struct asteriskd_runtime_delta *);
int asteriskd_runtime_create(
    struct asteriskd_runtime **, const struct asteriskd_runtime_reactor_backend *, void *);
int asteriskd_runtime_pump_once(
    struct asteriskd_runtime *, const struct asteriskd_deadline *,
    struct asteriskd_runtime_delta *);
int asteriskd_runtime_pump_until(
    struct asteriskd_runtime *, const struct asteriskd_deadline *,
    asteriskd_runtime_predicate, void *, struct asteriskd_runtime_delta *);
int asteriskd_runtime_accept_delta(
    struct asteriskd_runtime *, const struct asteriskd_runtime_delta *);
void asteriskd_runtime_destroy(struct asteriskd_runtime *);

enum asteriskd_route_slot_state {
    ASTERISKD_ROUTE_SLOT_ABSENT,
    ASTERISKD_ROUTE_SLOT_OWNED,
    ASTERISKD_ROUTE_SLOT_FOREIGN,
};

struct asteriskd_token_route_plan {
    bool create;
    char prefix[ASTERISKD_MAX_CIDR];
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool local_table;
    struct asteriskd_recovery_record recovery;
};

int asteriskd_bpf2_token_route_plan_build(
    const struct asteriskd_config *, enum asteriskd_route_slot_state, uint32_t,
    struct asteriskd_token_route_plan *, char *, size_t);

struct asteriskd_state_children {
    bool core_present;
    struct asteriskd_child_identity core;
    bool helper_present;
    struct asteriskd_child_identity helper;
};

struct asteriskd_state_matcher {
    bool configured;
    bool active;
};

struct asteriskd_state_rules {
    bool active;
    uint64_t generation;
    uint32_t categories;
};

struct asteriskd_state_recovery {
    uint64_t next_record_id;
    bool core_owned_ebpf_boundary;
    struct asteriskd_recovery_record *records;
    size_t record_count;
    size_t record_capacity;
};

struct asteriskd_state_failure {
    bool present;
    enum asteriskd_failure_code code;
    enum asteriskd_component component;
    char message[ASTERISKD_MAX_STATE_MESSAGE];
    bool has_exit_code;
    int exit_code;
    bool has_signal;
    int signal;
};

struct asteriskd_state_document {
    uint32_t schema_version;
    enum asteriskd_phase phase;
    enum asteriskd_owner owner;
    enum asteriskd_core_type core_type;
    enum asteriskd_mode mode;
    struct asteriskd_state_children children;
    struct asteriskd_state_matcher matcher;
    struct asteriskd_state_rules rules;
    struct asteriskd_state_recovery recovery;
    struct asteriskd_state_failure failure;
    bool initialized;
};

enum asteriskd_state_open_flags {
    ASTERISKD_STATE_OPEN_READ = 1U << 0,
    ASTERISKD_STATE_OPEN_WRITE = 1U << 1,
    ASTERISKD_STATE_OPEN_CREATE = 1U << 2,
    ASTERISKD_STATE_OPEN_EXCLUSIVE = 1U << 3,
    ASTERISKD_STATE_OPEN_NOFOLLOW = 1U << 4,
    ASTERISKD_STATE_OPEN_CLOEXEC = 1U << 5,
    ASTERISKD_STATE_OPEN_NONBLOCK = 1U << 6,
};

struct asteriskd_state_file_backend {
    int (*fstat_fd)(void *, int, uint64_t *, uint64_t *, enum asteriskd_file_kind *);
    int (*dup_cloexec)(void *, int, int *);
    int (*openat_fd)(void *, int, const char *, uint32_t, uint32_t, int *);
    ptrdiff_t (*read_fd)(void *, int, void *, size_t);
    ptrdiff_t (*write_fd)(void *, int, const void *, size_t);
    int (*fsync_fd)(void *, int);
    int (*close_fd)(void *, int);
    int (*renameat_fd)(void *, int, const char *, int, const char *);
    int (*unlinkat_fd)(void *, int, const char *);
};

struct asteriskd_state_store {
    int directory_fd;
    bool directory_fd_owned;
    uint64_t directory_device;
    uint64_t directory_inode;
    const struct asteriskd_state_file_backend *backend;
    void *backend_context;
    uint64_t temporary_sequence;
    bool initialized;
    bool write_blocked;
};

enum asteriskd_wal_resource_state {
    ASTERISKD_WAL_RESOURCE_ORIGINAL,
    ASTERISKD_WAL_RESOURCE_EXPECTED_EFFECT,
    ASTERISKD_WAL_RESOURCE_ABSENT,
    ASTERISKD_WAL_RESOURCE_FOREIGN,
    ASTERISKD_WAL_RESOURCE_AMBIGUOUS,
};

enum asteriskd_wal_pin_batch_kind {
    ASTERISKD_WAL_PIN_BATCH_MATCHER_IPV4,
    ASTERISKD_WAL_PIN_BATCH_MATCHER_DUAL_STACK,
    ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_IPV4,
    ASTERISKD_WAL_PIN_BATCH_BPF2SOCKS_DUAL_STACK,
};

struct asteriskd_wal_applied_identity_delta {
    bool has_interface_index;
    uint32_t interface_index;
    bool has_object_id;
    uint64_t object_id;
};

enum asteriskd_wal_original_delta_kind {
    ASTERISKD_WAL_ORIGINAL_DELTA_INVALID,
    ASTERISKD_WAL_ORIGINAL_DELTA_PRESENCE,
    ASTERISKD_WAL_ORIGINAL_DELTA_SYSCTL_VALUE,
    ASTERISKD_WAL_ORIGINAL_DELTA_TETHER_ACTIVE,
};

struct asteriskd_wal_original_delta {
    enum asteriskd_wal_original_delta_kind kind;
    bool original_presence;
    uint8_t original_value;
    bool original_active;
};

struct asteriskd_wal_effect_backend {
    int (*probe_original)(void *, const struct asteriskd_recovery_record *,
        struct asteriskd_wal_original_delta *, char *, size_t);
    int (*apply)(void *, const struct asteriskd_recovery_record *, size_t, char *, size_t);
    int (*verify_applied)(void *, const struct asteriskd_recovery_record *,
        struct asteriskd_wal_applied_identity_delta *, char *, size_t);
    int (*probe_recovery)(void *, const struct asteriskd_recovery_record *, enum asteriskd_wal_resource_state *, char *, size_t);
    int (*undo)(void *, const struct asteriskd_recovery_record *, char *, size_t);
    int (*verify_restored)(void *, const struct asteriskd_recovery_record *, char *, size_t);
};

int asteriskd_state_document_init(
    struct asteriskd_state_document *, enum asteriskd_owner, enum asteriskd_core_type, enum asteriskd_mode);
void asteriskd_state_document_destroy(struct asteriskd_state_document *);
int asteriskd_state_set_phase(struct asteriskd_state_document *, enum asteriskd_phase);
int asteriskd_state_set_child(
    struct asteriskd_state_document *, const struct asteriskd_child_identity *, char *, size_t);
int asteriskd_state_clear_child(struct asteriskd_state_document *, enum asteriskd_child_role);
int asteriskd_state_set_matcher(struct asteriskd_state_document *, bool, bool);
int asteriskd_state_set_rules(struct asteriskd_state_document *, bool, uint64_t, uint32_t);
int asteriskd_state_set_failure(
    struct asteriskd_state_document *, enum asteriskd_failure_code, enum asteriskd_component,
    const char *, bool, int, bool, int, char *, size_t);
void asteriskd_state_clear_failure(struct asteriskd_state_document *);
int asteriskd_state_append_recovery(
    struct asteriskd_state_document *, const struct asteriskd_recovery_record *, char *, size_t);
int asteriskd_state_mark_stopped(struct asteriskd_state_document *, char *, size_t);
bool asteriskd_state_is_canonical_stopped(const struct asteriskd_state_document *);
int asteriskd_state_serialize(
    const struct asteriskd_state_document *, char **, size_t *, char *, size_t);
int asteriskd_state_parse(
    const char *, size_t, struct asteriskd_state_document *, char *, size_t);
int asteriskd_state_store_init(
    struct asteriskd_state_store *, int, uint64_t, uint64_t, char *, size_t);
int asteriskd_state_store_init_with_backend(
    struct asteriskd_state_store *, int, uint64_t, uint64_t,
    const struct asteriskd_state_file_backend *, void *, char *, size_t);
int asteriskd_state_store_load(
    struct asteriskd_state_store *, struct asteriskd_state_document *, char *, size_t);
int asteriskd_state_store_save(
    struct asteriskd_state_store *, const struct asteriskd_state_document *, char *, size_t);
void asteriskd_state_store_close(struct asteriskd_state_store *);
int asteriskd_wal_apply(
    struct asteriskd_state_store *, struct asteriskd_state_document *,
    struct asteriskd_recovery_record *, const struct asteriskd_wal_effect_backend *, void *, char *, size_t);
int asteriskd_wal_apply_batch(
    struct asteriskd_state_store *, struct asteriskd_state_document *,
    struct asteriskd_recovery_record *, size_t,
    const struct asteriskd_wal_effect_backend *, void *, char *, size_t);
int asteriskd_wal_apply_pin_batch(
    struct asteriskd_state_store *, struct asteriskd_state_document *,
    enum asteriskd_wal_pin_batch_kind, struct asteriskd_recovery_record *, size_t,
    const struct asteriskd_wal_effect_backend *, void *, char *, size_t);
int asteriskd_wal_recover(
    struct asteriskd_state_store *, struct asteriskd_state_document *,
    const struct asteriskd_wal_effect_backend *, void *, char *, size_t);
int asteriskd_wal_recover_record_id(
    struct asteriskd_state_store *, struct asteriskd_state_document *, uint64_t,
    const struct asteriskd_wal_effect_backend *, void *, char *, size_t);

enum asteriskd_control_method {
    ASTERISKD_CONTROL_METHOD_STATUS,
    ASTERISKD_CONTROL_METHOD_STOP,
    ASTERISKD_CONTROL_METHOD_SHUTDOWN,
    ASTERISKD_CONTROL_METHOD_WATCH,
    ASTERISKD_CONTROL_METHOD_COUNT,
};

enum asteriskd_control_result_code {
    ASTERISKD_CONTROL_RESULT_OK,
    ASTERISKD_CONTROL_RESULT_ALREADY_RUNNING,
    ASTERISKD_CONTROL_RESULT_NOT_RUNNING,
    ASTERISKD_CONTROL_RESULT_PERMISSION_DENIED,
    ASTERISKD_CONTROL_RESULT_INVALID_REQUEST,
    ASTERISKD_CONTROL_RESULT_CONFIG_INVALID,
    ASTERISKD_CONTROL_RESULT_UNSUPPORTED_COMBINATION,
    ASTERISKD_CONTROL_RESULT_START_FAILED,
    ASTERISKD_CONTROL_RESULT_STOP_FAILED,
    ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
    ASTERISKD_CONTROL_RESULT_CODE_COUNT,
};

enum asteriskd_control_event_type {
    ASTERISKD_CONTROL_EVENT_STARTING,
    ASTERISKD_CONTROL_EVENT_RUNNING,
    ASTERISKD_CONTROL_EVENT_RULES_CHANGED,
    ASTERISKD_CONTROL_EVENT_STOPPING,
    ASTERISKD_CONTROL_EVENT_STOPPED,
    ASTERISKD_CONTROL_EVENT_CORE_EXITED,
    ASTERISKD_CONTROL_EVENT_HELPER_FAILED,
    ASTERISKD_CONTROL_EVENT_FAILED,
    ASTERISKD_CONTROL_EVENT_TYPE_COUNT,
};

enum asteriskd_control_decode_outcome {
    ASTERISKD_CONTROL_DECODE_VALID,
    ASTERISKD_CONTROL_DECODE_INVALID_REQUEST,
    ASTERISKD_CONTROL_DECODE_SILENT_REJECT,
};

struct asteriskd_control_request {
    char request_id[ASTERISKD_CONTROL_MAX_REQUEST_ID + 1U];
    enum asteriskd_control_method method;
};

struct asteriskd_control_error {
    enum asteriskd_failure_code code;
    enum asteriskd_component component;
    char *message;
    size_t message_length;
    bool has_exit_code;
    int exit_code;
    bool has_signal;
    int signal;
};

struct asteriskd_control_rules {
    bool active;
    uint64_t generation;
    uint32_t categories;
};

struct asteriskd_control_network {
    bool ipv4_ready;
    bool ipv6_enabled;
    bool ipv6_ready;
};

struct asteriskd_control_snapshot {
    enum asteriskd_phase phase;
    enum asteriskd_owner owner;
    enum asteriskd_core_type core_type;
    enum asteriskd_mode mode;
    int supervisor_pid;
    bool has_core_pid;
    int core_pid;
    enum asteriskd_helper_type helper_type;
    bool has_helper_pid;
    int helper_pid;
    bool matcher_configured;
    bool matcher_active;
    struct asteriskd_control_rules rules;
    struct asteriskd_control_network network;
    bool has_error;
    struct asteriskd_control_error error;
};

struct asteriskd_control_live_context {
    int supervisor_pid;
    bool ipv6_enabled;
};

struct asteriskd_control_result {
    enum asteriskd_control_result_code code;
    bool has_snapshot;
    struct asteriskd_control_snapshot snapshot;
    bool has_message;
    char *message;
    size_t message_length;
};

struct asteriskd_control_response {
    char request_id[ASTERISKD_CONTROL_MAX_REQUEST_ID + 1U];
    struct asteriskd_control_result result;
};

struct asteriskd_control_event {
    uint64_t sequence;
    enum asteriskd_control_event_type type;
    struct asteriskd_control_snapshot snapshot;
    bool has_details;
    struct asteriskd_control_error details;
};

int asteriskd_control_encode_request_line(
    const struct asteriskd_control_request *, char *, size_t, size_t *);
enum asteriskd_control_decode_outcome asteriskd_control_decode_request_payload(
    const char *, size_t, struct asteriskd_control_request *);
int asteriskd_control_encode_response_line(
    const struct asteriskd_control_response *, char *, size_t, size_t *);
int asteriskd_control_decode_response_payload(
    const char *, size_t, struct asteriskd_control_response *);
int asteriskd_control_encode_event_line(
    const struct asteriskd_control_event *, char *, size_t, size_t *);
int asteriskd_control_decode_event_payload(
    const char *, size_t, struct asteriskd_control_event *);
int asteriskd_control_snapshot_from_state(
    const struct asteriskd_state_document *, const struct asteriskd_control_live_context *,
    struct asteriskd_control_snapshot *);
bool asteriskd_control_snapshot_valid(const struct asteriskd_control_snapshot *);
bool asteriskd_control_result_valid(const struct asteriskd_control_result *);
int asteriskd_control_result_exit_code(enum asteriskd_control_result_code);
int asteriskd_control_error_set_message(
    struct asteriskd_control_error *, const char *, size_t);
int asteriskd_control_result_set_message(
    struct asteriskd_control_result *, const char *, size_t);
int asteriskd_control_snapshot_copy(
    struct asteriskd_control_snapshot *, const struct asteriskd_control_snapshot *);
void asteriskd_control_error_destroy(struct asteriskd_control_error *);
void asteriskd_control_snapshot_destroy(struct asteriskd_control_snapshot *);
void asteriskd_control_result_destroy(struct asteriskd_control_result *);
void asteriskd_control_response_destroy(struct asteriskd_control_response *);
void asteriskd_control_event_destroy(struct asteriskd_control_event *);

struct asteriskd_runtime_effect_backend {
    void *context;
    int (*save_state)(void *, const struct asteriskd_state_document *);
    int (*publish_event)(void *, enum asteriskd_control_event_type,
        const struct asteriskd_control_snapshot *, const struct asteriskd_control_error *, bool);
    int (*recover)(void *);
    int (*start_core)(void *, struct asteriskd_child_identity *);
    int (*wait_core)(void *);
    int (*ensure_platform_capability)(void *);
    int (*start_helper)(void *, struct asteriskd_child_identity *);
    int (*wait_helper)(void *);
    int (*start_matcher)(void *);
    int (*open_network)(void *);
    int (*apply_rules)(void *, bool *, uint64_t *, uint32_t *);
    int (*verify)(void *);
    int (*network_immediate)(void *);
    int (*reconcile)(void *, bool *, uint64_t *, uint32_t *);
    int (*quiesce_traffic)(void *);
    int (*remove_rules)(void *);
    int (*close_network)(void *);
    int (*stop_matcher)(void *);
    int (*stop_helper)(void *);
    int (*stop_core)(void *);
    int (*restore)(void *);
    int (*release)(void *);
};

enum asteriskd_runtime_effect_result {
    ASTERISKD_RUNTIME_EFFECT_READINESS_TIMEOUT = -100,
};

int asteriskd_runtime_prepare_start_state(
    struct asteriskd_state_store *, struct asteriskd_state_document *,
    const struct asteriskd_config *, char *, size_t);
bool asteriskd_runtime_recover_before_helper_stop(enum asteriskd_mode);
int asteriskd_runtime_supervise(
    struct asteriskd_runtime *, const struct asteriskd_config *,
    struct asteriskd_state_document *, const struct asteriskd_control_live_context *,
    const struct asteriskd_runtime_effect_backend *);
int asteriskd_runtime_start_system(
    const char *, bool *, struct asteriskd_control_result *);
int asteriskd_runtime_monitor_system(
    const char *, bool *, struct asteriskd_control_result *);

enum asteriskd_control_backend_result {
    ASTERISKD_CONTROL_BACKEND_OK = 0,
    ASTERISKD_CONTROL_BACKEND_ERROR = -1,
    ASTERISKD_CONTROL_BACKEND_AGAIN = -2,
    ASTERISKD_CONTROL_BACKEND_INTERRUPTED = -3,
};

enum asteriskd_control_listener_result {
    ASTERISKD_CONTROL_LISTENER_ERROR = -1,
    ASTERISKD_CONTROL_LISTENER_OK = 0,
    ASTERISKD_CONTROL_LISTENER_IN_USE = 1,
};

struct asteriskd_control_listener_backend {
    int (*open_stream)(void *, int *);
    enum asteriskd_control_listener_result (*bind_abstract)(
        void *, int, const unsigned char *, size_t);
    int (*listen_socket)(void *, int, int);
    int (*close_fd)(void *, int);
};

enum asteriskd_control_listener_result asteriskd_control_listener_open_with_backend(
    int *, const struct asteriskd_control_listener_backend *, void *);
enum asteriskd_control_listener_result asteriskd_control_listener_open(int *);

enum asteriskd_cli_command {
    ASTERISKD_CLI_START,
    ASTERISKD_CLI_MONITOR,
    ASTERISKD_CLI_STATUS,
    ASTERISKD_CLI_STOP,
    ASTERISKD_CLI_SHUTDOWN,
    ASTERISKD_CLI_WATCH,
};

struct asteriskd_cli_invocation {
    enum asteriskd_cli_command command;
    bool watch_until_running;
    char path[ASTERISKD_MAX_PATH];
};

int asteriskd_cli_parse(
    int, const char *const *, struct asteriskd_cli_invocation *);

enum asteriskd_control_connect_result {
    ASTERISKD_CONTROL_CONNECT_ERROR = -1,
    ASTERISKD_CONTROL_CONNECT_OK = 0,
    ASTERISKD_CONTROL_CONNECT_IN_PROGRESS = 1,
    ASTERISKD_CONTROL_CONNECT_ABSENT = 2,
};

enum asteriskd_control_wait_result {
    ASTERISKD_CONTROL_WAIT_ERROR = -1,
    ASTERISKD_CONTROL_WAIT_READY = 0,
    ASTERISKD_CONTROL_WAIT_TIMEOUT = 1,
    ASTERISKD_CONTROL_WAIT_INTERRUPTED = 2,
};

enum asteriskd_control_client_result {
    ASTERISKD_CONTROL_CLIENT_OK = 0,
    ASTERISKD_CONTROL_CLIENT_ABSENT = 1,
    ASTERISKD_CONTROL_CLIENT_TIMEOUT = 2,
    ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR = 3,
    ASTERISKD_CONTROL_CLIENT_IO_ERROR = 4,
};

struct asteriskd_control_client_backend {
    int (*monotonic_milliseconds)(void *, uint64_t *);
    enum asteriskd_control_connect_result (*connect_abstract)(
        void *, const unsigned char *, size_t, int *);
    enum asteriskd_control_connect_result (*finish_connect)(void *, int);
    enum asteriskd_control_wait_result (*wait_ready)(
        void *, int, bool, bool, uint64_t, bool *, bool *);
    ptrdiff_t (*read_fd)(void *, int, void *, size_t);
    ptrdiff_t (*write_fd)(void *, int, const void *, size_t);
    int (*close_fd)(void *, int);
};

enum asteriskd_control_sink_result {
    ASTERISKD_CONTROL_SINK_ERROR = -1,
    ASTERISKD_CONTROL_SINK_CONTINUE = 0,
    ASTERISKD_CONTROL_SINK_STOP = 1,
};

typedef int (*asteriskd_control_line_sink)(void *, const char *, size_t);

enum asteriskd_control_client_result asteriskd_control_client_run_with_backend(
    enum asteriskd_control_method, const char *,
    const struct asteriskd_control_client_backend *, void *,
    asteriskd_control_line_sink, void *, struct asteriskd_control_response *);
enum asteriskd_control_client_result asteriskd_control_client_run(
    enum asteriskd_control_method, const char *,
    asteriskd_control_line_sink, void *, struct asteriskd_control_response *);

struct asteriskd_cli_backend {
    uint32_t (*effective_uid)(void *);
    enum asteriskd_control_client_result (*control_client)(
        void *, enum asteriskd_control_method, const char *,
        asteriskd_control_line_sink, void *, struct asteriskd_control_response *);
    int (*run_start)(
        void *, const char *, bool *, struct asteriskd_control_result *);
    int (*run_monitor)(
        void *, const char *, bool *, struct asteriskd_control_result *);
    int (*write_stdout)(void *, const char *, size_t);
    int (*write_stderr)(void *, const char *, size_t);
};

int asteriskd_cli_main_with_backend(
    int, const char *const *, const struct asteriskd_cli_backend *, void *);
int asteriskd_cli_main(int, const char *const *);

struct asteriskd_control_transport_backend {
    int (*accept_client)(void *, int, int *, uint32_t *);
    ptrdiff_t (*read_client)(void *, int, void *, size_t);
    ptrdiff_t (*write_client)(void *, int, const void *, size_t);
    int (*close_fd)(void *, int);
};

struct asteriskd_control_callbacks {
    int (*snapshot)(void *, struct asteriskd_control_snapshot *);
    int (*request_stop)(void *);
    int (*request_shutdown)(void *);
    void *context;
};

struct asteriskd_control_interest {
    int fd;
    bool readable;
    bool writable;
};

struct asteriskd_control_server;

int asteriskd_control_server_create_with_backend(
    struct asteriskd_control_server **, int,
    const struct asteriskd_control_transport_backend *, void *,
    const struct asteriskd_control_callbacks *);
int asteriskd_control_server_create(
    struct asteriskd_control_server **, int,
    const struct asteriskd_control_callbacks *);
void asteriskd_control_server_enable_accepting(
    struct asteriskd_control_server *, bool);
int asteriskd_control_server_listener_fd(
    const struct asteriskd_control_server *);
size_t asteriskd_control_server_interests(
    const struct asteriskd_control_server *,
    struct asteriskd_control_interest *, size_t);
bool asteriskd_control_server_next_deadline(
    const struct asteriskd_control_server *, uint64_t *);
int asteriskd_control_server_dispatch(
    struct asteriskd_control_server *, int, bool, bool, bool, uint64_t);
int asteriskd_control_server_tick(
    struct asteriskd_control_server *, uint64_t);
int asteriskd_control_server_publish_event(
    struct asteriskd_control_server *, enum asteriskd_control_event_type,
    const struct asteriskd_control_snapshot *,
    const struct asteriskd_control_error *, bool, uint64_t);
int asteriskd_control_server_finish_stop(
    struct asteriskd_control_server *,
    const struct asteriskd_control_result *, uint64_t);
bool asteriskd_control_server_drained(
    const struct asteriskd_control_server *);
uint64_t asteriskd_control_server_sequence(
    const struct asteriskd_control_server *);
void asteriskd_control_server_destroy(
    struct asteriskd_control_server *);

enum asteriskd_typed_wal_source {
    ASTERISKD_TYPED_WAL_IPV6_IMMEDIATE,
    ASTERISKD_TYPED_WAL_IPV6_INTEGRITY,
    ASTERISKD_TYPED_WAL_TC_INTERFACE,
};

enum asteriskd_typed_wal_action {
    ASTERISKD_TYPED_WAL_APPLY,
    ASTERISKD_TYPED_WAL_REBIND_INTERFACE,
    ASTERISKD_TYPED_WAL_RETIRE_INTERFACE,
};

struct asteriskd_typed_wal_request {
    enum asteriskd_typed_wal_source source;
    enum asteriskd_typed_wal_action action;
    struct asteriskd_recovery_record record;
    uint64_t record_id;
    char previous_interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t previous_interface_index;
    uint32_t verified_interface_index;
    bool old_generation_absent_verified;
};

struct asteriskd_typed_wal_sink {
    int (*dispatch)(void *, const struct asteriskd_typed_wal_request *, char *, size_t);
    void *context;
};

int asteriskd_network_wal_ipv6_immediate(
    const struct asteriskd_typed_wal_sink *, const struct asteriskd_recovery_record *, char *, size_t);
int asteriskd_network_wal_ipv6_integrity(
    const struct asteriskd_typed_wal_sink *, const struct asteriskd_recovery_record *, char *, size_t);
int asteriskd_network_wal_tc_interface(
    const struct asteriskd_typed_wal_sink *, const struct asteriskd_recovery_record *, char *, size_t);
int asteriskd_network_wal_rename(
    const struct asteriskd_typed_wal_sink *, uint64_t, const char *, uint32_t,
    const char *, uint32_t, char *, size_t);
int asteriskd_network_wal_dellink(
    const struct asteriskd_typed_wal_sink *, uint64_t, const char *, uint32_t,
    bool, char *, size_t);

enum asteriskd_log_level {
    ASTERISKD_LOG_LEVEL_DEBUG,
    ASTERISKD_LOG_LEVEL_INFO,
    ASTERISKD_LOG_LEVEL_WARNING,
    ASTERISKD_LOG_LEVEL_ERROR,
    ASTERISKD_LOG_LEVEL_COUNT,
};

enum asteriskd_log_event {
    ASTERISKD_LOG_EVENT_STARTING,
    ASTERISKD_LOG_EVENT_RUNNING,
    ASTERISKD_LOG_EVENT_STOPPING,
    ASTERISKD_LOG_EVENT_STOPPED,
    ASTERISKD_LOG_EVENT_CHILD_OUTPUT,
    ASTERISKD_LOG_EVENT_STATE_LOADED,
    ASTERISKD_LOG_EVENT_STATE_SAVED,
    ASTERISKD_LOG_EVENT_STATE_INVALID,
    ASTERISKD_LOG_EVENT_RECOVERY,
    ASTERISKD_LOG_EVENT_NETWORK_CHANGED,
    ASTERISKD_LOG_EVENT_CAPABILITY_ADJUSTED,
    ASTERISKD_LOG_EVENT_IO_ERROR,
    ASTERISKD_LOG_EVENT_DIAGNOSTIC,
    ASTERISKD_LOG_EVENT_COUNT,
};

enum asteriskd_log_stream {
    ASTERISKD_LOG_STREAM_STDOUT,
    ASTERISKD_LOG_STREAM_STDERR,
    ASTERISKD_LOG_STREAM_COUNT,
};

struct asteriskd_local_time {
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int millisecond;
    int utc_offset_minutes;
};

struct asteriskd_clock_backend {
    int (*local_time)(void *, struct asteriskd_local_time *);
    void *context;
};

enum asteriskd_log_open_flags {
    ASTERISKD_LOG_OPEN_APPEND = 1U << 0,
    ASTERISKD_LOG_OPEN_CREATE = 1U << 1,
    ASTERISKD_LOG_OPEN_NOFOLLOW = 1U << 2,
    ASTERISKD_LOG_OPEN_CLOEXEC = 1U << 3,
    ASTERISKD_LOG_OPEN_DIRECTORY = 1U << 4,
    ASTERISKD_LOG_OPEN_NONBLOCK = 1U << 5,
};

struct asteriskd_log_file_metadata {
    enum asteriskd_file_kind kind;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
};

struct asteriskd_log_file_backend {
    int (*open_root)(void *, uint32_t, int *);
    int (*openat_fd)(void *, int, const char *, uint32_t, uint32_t, int *);
    int (*fstat_fd)(void *, int, struct asteriskd_log_file_metadata *);
    int (*fchown_fd)(void *, int, uint32_t, uint32_t);
    int (*fchmod_fd)(void *, int, uint32_t);
    ptrdiff_t (*write_fd)(void *, int, const void *, size_t);
    int (*close_fd)(void *, int);
};

int asteriskd_log_open_append_fd(
    const char *, int *, char *, size_t);
int asteriskd_log_open_append_fd_with_backend(
    const char *, const struct asteriskd_log_file_backend *, void *,
    int *, char *, size_t);

struct asteriskd_log_partial {
    unsigned char bytes[ASTERISKD_LOG_MAX_CHILD_LINE + ASTERISKD_MAX_SECRET_KEY - 1U];
    size_t kept_length;
    size_t raw_length;
    uint64_t first_byte_milliseconds;
    bool has_first_byte;
    bool last_raw_was_cr;
    bool truncated;
};

struct asteriskd_logger {
    int fd;
    bool fd_owned;
    int parent_fd;
    bool parent_fd_owned;
    uint32_t parent_mode;
    uint32_t parent_uid;
    uint32_t parent_gid;
    bool opened;
    bool failed;
    unsigned char age_secret[ASTERISKD_MAX_SECRET_KEY];
    size_t age_secret_length;
    struct asteriskd_clock_backend clock;
    const struct asteriskd_log_file_backend *file_backend;
    void *file_context;
    struct asteriskd_log_partial partials[2][ASTERISKD_LOG_STREAM_COUNT];
};

int asteriskd_log_open(
    struct asteriskd_logger *, const char *, const unsigned char *, size_t,
    const struct asteriskd_clock_backend *, char *, size_t);
int asteriskd_log_open_with_backend(
    struct asteriskd_logger *, const char *, const unsigned char *, size_t,
    const struct asteriskd_clock_backend *, const struct asteriskd_log_file_backend *, void *, char *, size_t);
int asteriskd_log_line(
    struct asteriskd_logger *, enum asteriskd_log_level, enum asteriskd_component,
    enum asteriskd_log_event, const char *);
int asteriskd_log_child_bytes(
    struct asteriskd_logger *, enum asteriskd_child_role, enum asteriskd_log_stream,
    const unsigned char *, size_t, uint64_t, bool);
int asteriskd_log_flush_expired(struct asteriskd_logger *, uint64_t);
size_t asteriskd_log_buffered_bytes(const struct asteriskd_logger *, enum asteriskd_child_role);
int asteriskd_log_close(struct asteriskd_logger *);

struct asteriskd_address_set {
    int family;
    char values[ASTERISKD_MAX_ADDRESSES][64];
    size_t count;
};

struct asteriskd_interface_address {
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char address[64U];
};

enum asteriskd_local_bypass_operation_kind {
    ASTERISKD_LOCAL_BYPASS_INSERT,
    ASTERISKD_LOCAL_BYPASS_DELETE,
};

struct asteriskd_local_bypass_operation {
    enum asteriskd_local_bypass_operation_kind kind;
    size_t rule_number;
    char address[64U];
};

#define ASTERISKD_LOCAL_BYPASS_MAX_OPERATIONS (ASTERISKD_MAX_ADDRESSES * 2U)

struct asteriskd_local_bypass_plan {
    struct asteriskd_local_bypass_operation
        operations[ASTERISKD_LOCAL_BYPASS_MAX_OPERATIONS];
    size_t operation_count;
};

int asteriskd_local_address_set_build(
    const struct asteriskd_config *, int,
    const struct asteriskd_interface_address *, size_t,
    struct asteriskd_address_set *, char *, size_t);
int asteriskd_local_bypass_plan_build(
    int, const char *, const char *, const char *,
    const char *, size_t, const struct asteriskd_address_set *,
    struct asteriskd_local_bypass_plan *, char *, size_t);

#define ASTERISKD_ADDRESS_IPV4 4
#define ASTERISKD_ADDRESS_IPV6 6

#define ASTERISKD_BPF_MAP_TYPE_LPM_TRIE 11U
#define ASTERISKD_BPF_MAP_TYPE_HASH 1U
#define ASTERISKD_BPF_PROGRAM_TYPE_SOCKET_FILTER 1U
#define ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS 3U
#define ASTERISKD_BPF_MAP_FLAG_NO_PREALLOC 1U
#define ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES 512U
#define ASTERISKD_MATCHER_UID_MAP_MAX_ENTRIES 8192U
#define ASTERISKD_MATCHER_DIRECT_MAP_MAX_ENTRIES 32768U
#define ASTERISKD_BPF_PROGRAM_TAG_SIZE 8U
#define ASTERISKD_BPF_PROGRAM_MAX_MAPS 16U

struct asteriskd_bpf_map_info {
    uint64_t object_id;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t flags;
};

struct asteriskd_bpf_map_backend {
    void *context;
    int (*open_pinned)(void *, const char *, int *);
    int (*get_info)(void *, int, struct asteriskd_bpf_map_info *);
    int (*update)(void *, int, const void *, size_t, const void *, size_t);
    int (*get_next)(void *, int, const void *, size_t, void *, bool *);
    int (*delete_key)(void *, int, const void *, size_t);
    int (*close)(void *, int);
};

int asteriskd_bpf_local_map_reconcile(
    const struct asteriskd_bpf_map_backend *, const char *, uint64_t,
    const struct asteriskd_address_set *, char *, size_t);
const struct asteriskd_bpf_map_backend *asteriskd_system_bpf_map_backend(void);

struct asteriskd_bpf_program_info {
    uint64_t object_id;
    uint32_t type;
    char name[ASTERISKD_MAX_INTERFACE_NAME];
    unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE];
    uint32_t map_ids[ASTERISKD_BPF_PROGRAM_MAX_MAPS];
    size_t map_count;
};

struct asteriskd_bpf_program_backend {
    void *context;
    int (*open_program)(void *, const char *, int *);
    int (*program_info)(void *, int, struct asteriskd_bpf_program_info *);
    int (*open_pinned_map)(void *, const char *, int *);
    int (*open_map)(void *, uint32_t, int *);
    int (*map_info)(void *, int, struct asteriskd_bpf_map_info *);
    int (*map_next)(void *, int, const void *, size_t, void *, bool *);
    int (*map_lookup)(void *, int, const void *, size_t, void *, size_t, bool *);
    int (*pin_program)(void *, int, const char *);
    int (*close)(void *, int);
};

struct asteriskd_matcher_verified_pin {
    enum asteriskd_pin_id pin_id;
    uint64_t object_id;
    unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE];
};

struct asteriskd_matcher_verification {
    struct asteriskd_matcher_verified_pin pins[4U];
    size_t pin_count;
};

int asteriskd_matcher_verify(
    const struct asteriskd_config *, const struct asteriskd_matcher_pin_plan *,
    const struct asteriskd_bpf_program_backend *, struct asteriskd_matcher_verification *,
    char *, size_t);

struct asteriskd_bpf2_pin_expectation {
    enum asteriskd_pin_id pin_id;
    char path[ASTERISKD_MAX_PATH];
    bool program;
    char program_name[ASTERISKD_MAX_INTERFACE_NAME];
};

struct asteriskd_bpf2_pin_plan {
    struct asteriskd_bpf2_pin_expectation pins[4U];
    size_t pin_count;
};

struct asteriskd_bpf2_verified_pin {
    enum asteriskd_pin_id pin_id;
    uint64_t object_id;
    unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE];
};

struct asteriskd_bpf2_verification {
    struct asteriskd_bpf2_verified_pin pins[4U];
    size_t pin_count;
};

int asteriskd_bpf2_pin_plan_build(
    const struct asteriskd_config *, struct asteriskd_bpf2_pin_plan *);
const char *asteriskd_bpf2_tc_filter_attachment_name(enum asteriskd_program_id);
int asteriskd_bpf2_pin_records_build(
    const struct asteriskd_bpf2_pin_plan *, struct asteriskd_recovery_record *,
    size_t, size_t *);

struct asteriskd_bpf_pin_ownership_backend {
    void *context;
    int (*probe)(void *, const char *, bool *, uint64_t *);
    int (*unlink_exact)(void *, const char *);
};

int asteriskd_matcher_pin_preflight(
    const struct asteriskd_matcher_pin_plan *,
    const struct asteriskd_bpf_pin_ownership_backend *, char *, size_t);
int asteriskd_bpf2_pin_preflight(
    const struct asteriskd_bpf2_pin_plan *,
    const struct asteriskd_bpf_pin_ownership_backend *, char *, size_t);
int asteriskd_bpf_pin_cleanup_owned(
    const char *, uint64_t, const struct asteriskd_bpf_pin_ownership_backend *, char *, size_t);
int asteriskd_matcher_verify_residue(
    const struct asteriskd_config *, const struct asteriskd_matcher_pin_plan *,
    const struct asteriskd_bpf_program_backend *,
    const struct asteriskd_bpf_pin_ownership_backend *,
    struct asteriskd_matcher_verification *, char *, size_t);
int asteriskd_bpf2_verify_residue(
    const struct asteriskd_config *, const struct asteriskd_bpf2_pin_plan *,
    const struct asteriskd_bpf_program_backend *,
    const struct asteriskd_bpf_pin_ownership_backend *,
    struct asteriskd_bpf2_verification *, char *, size_t);
const struct asteriskd_bpf_pin_ownership_backend *
    asteriskd_system_bpf_pin_ownership_backend(void);
int asteriskd_bpf2_verify(
    const struct asteriskd_config *, const struct asteriskd_bpf2_pin_plan *,
    const struct asteriskd_bpf_program_backend *, struct asteriskd_bpf2_verification *,
    char *, size_t);
const struct asteriskd_bpf_program_backend *asteriskd_system_bpf_program_backend(void);

#define ASTERISKD_NETWORK_GROUP_LINK UINT32_C(0x00000001)
#define ASTERISKD_NETWORK_GROUP_IPV4_ADDRESS UINT32_C(0x00000010)
#define ASTERISKD_NETWORK_GROUP_IPV6_ADDRESS UINT32_C(0x00000100)
#define ASTERISKD_NETWORK_RECEIVE_BUFFER_SIZE (1024U * 1024U)
#define ASTERISKD_NETWORK_SOCKET_RAW UINT32_C(0x1)
#define ASTERISKD_NETWORK_SOCKET_NONBLOCK UINT32_C(0x2)
#define ASTERISKD_NETWORK_SOCKET_CLOEXEC UINT32_C(0x4)

struct asteriskd_network_event;
struct asteriskd_event_batch;

enum asteriskd_network_receive_result {
    ASTERISKD_NETWORK_RECEIVE_DATA,
    ASTERISKD_NETWORK_RECEIVE_AGAIN,
    ASTERISKD_NETWORK_RECEIVE_INTERRUPTED,
    ASTERISKD_NETWORK_RECEIVE_ENOBUFS,
    ASTERISKD_NETWORK_RECEIVE_FATAL,
};

struct asteriskd_network_backend {
    void *context;
    int (*open)(void *, uint32_t, size_t, uint32_t, int *);
    enum asteriskd_network_receive_result (*receive)(
        void *, int, void *, size_t, size_t *, uint32_t *, bool *);
    int (*interface_name)(void *, uint32_t, char *, size_t);
    int (*ipv6_disabled)(void *, const char *, uint32_t, uint8_t *, bool *);
    int (*close)(void *, int);
};

struct asteriskd_network_runtime {
    const struct asteriskd_config *config;
    const struct asteriskd_network_backend *backend;
    int fd;
    bool fd_owned;
    bool no_op;
    uint32_t groups;
    struct asteriskd_event_batch *pending_batch_storage;
    bool deadline_present;
    uint64_t deadline_milliseconds;
    bool integrity_loss;
    const struct asteriskd_typed_wal_sink *wal_sink;
    struct asteriskd_typed_wal_request
        immediate_requests[ASTERISKD_MAX_NETWORK_IMMEDIATE_REQUESTS];
    size_t immediate_request_count;
};

int asteriskd_network_open(
    const struct asteriskd_config *, const struct asteriskd_network_backend *,
    struct asteriskd_network_runtime *, char *, size_t);
int asteriskd_network_note(
    struct asteriskd_network_runtime *, const struct asteriskd_network_event *,
    bool, uint64_t);
int asteriskd_network_handle(
    struct asteriskd_network_runtime *, uint64_t, char *, size_t);
bool asteriskd_network_next_deadline(
    const struct asteriskd_network_runtime *, uint64_t *);
int asteriskd_network_take_reconcile(
    struct asteriskd_network_runtime *, uint64_t,
    struct asteriskd_event_batch *, bool *);
int asteriskd_network_close(struct asteriskd_network_runtime *);
int asteriskd_network_set_wal_sink(
    struct asteriskd_network_runtime *, const struct asteriskd_typed_wal_sink *);
bool asteriskd_network_has_immediate(const struct asteriskd_network_runtime *);
int asteriskd_network_apply_immediate(
    struct asteriskd_network_runtime *, char *, size_t);
int asteriskd_network_reopen(
    struct asteriskd_network_runtime *, uint64_t, char *, size_t);
const struct asteriskd_network_backend *asteriskd_system_network_backend(void);

#define ASTERISKD_HOTSPOT_TC_PRIORITY 1U
#define ASTERISKD_HOTSPOT_TC_HANDLE 1U
#define ASTERISKD_ETH_PROTOCOL_IPV6 UINT32_C(0x86dd)
#define ASTERISKD_ETH_PROTOCOL_ALL UINT32_C(0x0003)

bool asteriskd_hotspot_tc_output_has_android_offload(const void *, size_t);

enum asteriskd_tc_slot_state {
    ASTERISKD_TC_SLOT_ABSENT,
    ASTERISKD_TC_SLOT_OWNED,
    ASTERISKD_TC_SLOT_COMPATIBLE,
    ASTERISKD_TC_SLOT_FOREIGN,
};

enum asteriskd_tc_qdisc_cleanup_decision {
    ASTERISKD_TC_QDISC_CLEANUP_DELETE,
    ASTERISKD_TC_QDISC_CLEANUP_RETAIN_SHARED,
};

enum asteriskd_tc_plan_operation_kind {
    ASTERISKD_TC_PLAN_SET_ROUTE_LOCALNET,
    ASTERISKD_TC_PLAN_CREATE_CLSACT,
    ASTERISKD_TC_PLAN_CREATE_EGRESS,
    ASTERISKD_TC_PLAN_CREATE_INGRESS,
    ASTERISKD_TC_PLAN_REMOVE_INGRESS,
    ASTERISKD_TC_PLAN_REMOVE_EGRESS,
    ASTERISKD_TC_PLAN_REMOVE_CLSACT,
    ASTERISKD_TC_PLAN_RESTORE_ROUTE_LOCALNET,
};

struct asteriskd_tc_interface_probe {
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    uint8_t route_localnet_value;
    enum asteriskd_tc_slot_state qdisc;
    enum asteriskd_tc_slot_state egress;
    enum asteriskd_tc_slot_state ingress;
};

struct asteriskd_tc_plan_operation {
    enum asteriskd_tc_plan_operation_kind kind;
    uint32_t priority;
    uint32_t handle;
    bool direct_action;
    struct asteriskd_recovery_record recovery;
};

struct asteriskd_tc_plan {
    struct asteriskd_tc_plan_operation operations[4U];
    size_t operation_count;
};

int asteriskd_tc_install_plan_build(
    const struct asteriskd_config *, const struct asteriskd_tc_interface_probe *,
    struct asteriskd_tc_plan *, char *, size_t);
int asteriskd_tc_cleanup_plan_build(
    const struct asteriskd_tc_plan *, struct asteriskd_tc_plan *);
enum asteriskd_tc_qdisc_cleanup_decision asteriskd_tc_qdisc_cleanup_decide(
    bool ingress_occupied, bool egress_occupied);
bool asteriskd_tc_qdisc_cleanup_restored(bool qdisc_present,
    enum asteriskd_tc_qdisc_cleanup_decision decision);

struct asteriskd_tc_filter_expectation {
    uint32_t interface_index;
    uint32_t parent;
    uint32_t protocol;
    uint32_t priority;
    uint32_t handle;
    char bpf_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t bpf_flags;
    uint32_t bpf_flags_gen;
    uint32_t bpf_flags_gen_mask;
    uint64_t program_object_id;
    unsigned char program_tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE];
};

int asteriskd_tc_filter_netlink_decode(
    const void *, size_t, uint32_t, uint32_t,
    const struct asteriskd_tc_filter_expectation *,
    enum asteriskd_rules_slot_state *, bool *, char *, size_t);
int asteriskd_tc_filter_slot_netlink_decode(
    const void *, size_t, uint32_t, uint32_t,
    const struct asteriskd_tc_filter_expectation *,
    enum asteriskd_rules_slot_state *, bool *, char *, size_t);
int asteriskd_tc_qdisc_netlink_decode(
    const void *, size_t, uint32_t, uint32_t, uint32_t,
    enum asteriskd_rules_slot_state *, bool *, char *, size_t);
enum asteriskd_event_action {
    ASTERISKD_EVENT_ADDED,
    ASTERISKD_EVENT_REMOVED,
    ASTERISKD_EVENT_UPDATED,
};

struct asteriskd_network_event {
    bool is_address;
    enum asteriskd_event_action action;
    int family;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    char address[64];
};

struct asteriskd_event_batch {
    struct asteriskd_network_event events[ASTERISKD_MAX_NETWORK_EVENTS];
    size_t count;
    bool truncated;
};

struct asteriskd_tether_probe {
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    bool ndc_executable;
    bool link_identity_matches;
    bool ipv6_disabled;
    bool no_ipv6_addresses;
    bool interface_active;
    bool status_started;
    bool dnsmasq_identity_valid;
    int64_t dnsmasq_pid;
};

struct asteriskd_tether_plan {
    bool required;
    char interface_name[ASTERISKD_MAX_INTERFACE_NAME];
    uint32_t interface_index;
    int64_t old_dnsmasq_pid;
    struct asteriskd_recovery_record recovery;
};

struct asteriskd_tether_backend {
    void *context;
    int (*stop)(void *);
    int (*start)(void *);
    int (*verify)(void *, const char *, uint32_t, int64_t, bool *, int64_t *);
};

int asteriskd_tether_plan_build(
    const struct asteriskd_config *, enum asteriskd_event_action, int,
    const struct asteriskd_tether_probe *, struct asteriskd_tether_plan *, char *, size_t);
int asteriskd_tether_plan_stop(
    const struct asteriskd_tether_plan *, const struct asteriskd_tether_backend *);
int asteriskd_tether_plan_restore(
    const struct asteriskd_tether_plan *, const struct asteriskd_tether_backend *);

#endif

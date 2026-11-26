// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef ASTERISKD_NETWORK_DNS_H
#define ASTERISKD_NETWORK_DNS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct asteriskd_config;

/* AEN1 control frame, see enhance/src/main/module/docs/control-protocol.md. */
#define ASTERISKD_DNS_FRAME_MAGIC 0x314e4541
#define ASTERISKD_DNS_FRAME_VERSION 1
#define ASTERISKD_DNS_HEADER_SIZE 40
#define ASTERISKD_DNS_COMMAND_TIMEOUT_MILLIS 2000
enum asteriskd_dns_opcode {
    ASTERISKD_DNS_OP_HELLO = 1,
    ASTERISKD_DNS_OP_PREPARE = 2,
    ASTERISKD_DNS_OP_ACTIVATE = 3,
    ASTERISKD_DNS_OP_CHECK = 4,
    ASTERISKD_DNS_OP_DEACTIVATE = 5,
    ASTERISKD_DNS_OP_RELEASE = 6,
    ASTERISKD_DNS_OP_ACK = 7,
    ASTERISKD_DNS_OP_ERROR = 8,
    ASTERISKD_DNS_OP_CAPABILITIES = 9,
    ASTERISKD_DNS_OP_INFO = 10,
    ASTERISKD_DNS_OP_INFO_RESPONSE = 11,
    ASTERISKD_DNS_OP_NETWORK_CHANGED = 12,
};
enum asteriskd_dns_result {
    ASTERISKD_DNS_RESULT_OK = 0,
    ASTERISKD_DNS_RESULT_INVALID = 1,
    ASTERISKD_DNS_RESULT_UNSUPPORTED = 2,
    ASTERISKD_DNS_RESULT_STALE = 3,
    ASTERISKD_DNS_RESULT_BUSY = 4,
    ASTERISKD_DNS_RESULT_CACHE_ERROR = 5,
    ASTERISKD_DNS_RESULT_DRAINING = 6,
    ASTERISKD_DNS_RESULT_EXHAUSTED = 7,
    ASTERISKD_DNS_RESULT_IO_ERROR = 8,
};
/* Module-side policy phase reported in ACK/ERROR bodies. */
enum asteriskd_dns_module_phase {
    ASTERISKD_DNS_MODULE_IDLE = 0,
    ASTERISKD_DNS_MODULE_PREPARED = 1,
    ASTERISKD_DNS_MODULE_ACTIVE = 2,
    ASTERISKD_DNS_MODULE_DRAINING = 3,
};

enum asteriskd_dns_phase {
    ASTERISKD_DNS_PHASE_DISABLED,
    ASTERISKD_DNS_PHASE_PREPARING,
    ASTERISKD_DNS_PHASE_PREPARED,
    ASTERISKD_DNS_PHASE_ACTIVE,
    ASTERISKD_DNS_PHASE_INACTIVE,
    ASTERISKD_DNS_PHASE_DRAINING,
    ASTERISKD_DNS_PHASE_UNSUPPORTED,
    ASTERISKD_DNS_PHASE_FAILED,
    ASTERISKD_DNS_PHASE_WAITING_NETWORK
};
static inline bool asteriskd_dns_serving(enum asteriskd_dns_phase phase) {
    return phase == ASTERISKD_DNS_PHASE_ACTIVE || phase == ASTERISKD_DNS_PHASE_WAITING_NETWORK;
}
struct asteriskd_dns_snapshot {
    bool required;
    enum asteriskd_dns_phase phase;
    uint64_t instance_id, cycle_id, generation;
    char reason[128];
};
#define ASTERISKD_DNS_MAX_ROUTES 64U
struct asteriskd_dns_route {
    uint32_t netid, mark, family, scope;
    unsigned char address[16];
};
struct asteriskd_dns_client {
    struct asteriskd_dns_snapshot snapshot;
    int fd;
    uint32_t request_id, result, retained;
    uint16_t opcode;
    uint64_t netd, deadline;
    bool pending, complete, connected, suspended, busy, topology_changed, network_changed;
    bool prepare_retry;
    // PREPARE answered BUSY while the previous session drains; transient.
    bool prepare_draining;
    // Module reports release progress with NETWORK_CHANGED; no drain timer.
    bool drain_events;
    unsigned char *tx;
    size_t tx_size, tx_offset, rx_size;
    unsigned char rx[68 + 32 * ASTERISKD_DNS_MAX_ROUTES];
    size_t route_count;
    struct asteriskd_dns_route routes[ASTERISKD_DNS_MAX_ROUTES];
};
void asteriskd_dns_init(struct asteriskd_dns_client *);
void asteriskd_dns_close(struct asteriskd_dns_client *);
int asteriskd_dns_begin(struct asteriskd_dns_client *, uint64_t, uint64_t, uint64_t, uint64_t);
int asteriskd_dns_command(
    struct asteriskd_dns_client *, uint16_t, const struct asteriskd_config *, uint64_t);
int asteriskd_dns_step(struct asteriskd_dns_client *, uint64_t);
void asteriskd_dns_fail(struct asteriskd_dns_client *, const char *);
uint64_t asteriskd_dns_monotime(void);
int asteriskd_dns_info(void);
#endif

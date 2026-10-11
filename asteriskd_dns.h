// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef ASTERISKD_DNS_H
#define ASTERISKD_DNS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
struct asteriskd_config;
enum asteriskd_dns_phase { DNS_DISABLED, DNS_PREPARING, DNS_PREPARED, DNS_ACTIVE,
    DNS_INACTIVE, DNS_DRAINING, DNS_UNSUPPORTED, DNS_FAILED };
struct asteriskd_dns_snapshot {
    bool required;
    enum asteriskd_dns_phase phase;
    uint64_t instance_id, cycle_id, generation;
    char reason[128];
};
#define ASTERISKD_DNS_MAX_ROUTES 64U
struct asteriskd_dns_route { uint32_t netid, mark, family, scope; unsigned char address[16]; };
struct asteriskd_dns_client {
    struct asteriskd_dns_snapshot snapshot;
    int fd;
    uint32_t request_id, result, retained;
    uint16_t opcode;
    uint64_t netd, deadline;
    bool pending, complete, connected, suspended, busy, topology_changed, network_changed;
    unsigned char *tx;
    size_t tx_size, tx_offset, rx_size;
    unsigned char rx[68+32*ASTERISKD_DNS_MAX_ROUTES];
    size_t route_count;
    struct asteriskd_dns_route routes[ASTERISKD_DNS_MAX_ROUTES];
};
void asteriskd_dns_init(struct asteriskd_dns_client *);
void asteriskd_dns_close(struct asteriskd_dns_client *);
int asteriskd_dns_begin(struct asteriskd_dns_client *, uint64_t, uint64_t, uint64_t, uint64_t);
int asteriskd_dns_command(struct asteriskd_dns_client *, uint16_t,
    const struct asteriskd_config *, uint64_t);
int asteriskd_dns_step(struct asteriskd_dns_client *, uint64_t);
int asteriskd_dns_accept(struct asteriskd_dns_client *, const unsigned char *, size_t, uint64_t);
void asteriskd_dns_fail(struct asteriskd_dns_client *, const char *);
uint64_t asteriskd_dns_monotime(void);
int asteriskd_dns_info(void);
#endif

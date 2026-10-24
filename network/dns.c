// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "asteriskd.h"
#include "network/dns.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__) || defined(__ANDROID__)
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#endif
static uint64_t dns_read_le(const unsigned char *bytes, size_t size) {
    uint64_t value = 0;
    for (size_t i = 0; i < size; ++i) value |= (uint64_t)bytes[i] << (8U * i);
    return value;
}
static void dns_write_le(unsigned char *bytes, uint64_t value, size_t size) {
    for (size_t i = 0; i < size; ++i) bytes[i] = (unsigned char)(value >> (8U * i));
}
void asteriskd_dns_init(struct asteriskd_dns_client *client) {
    memset(client, 0, sizeof(*client));
    client->fd = -1;
}
void asteriskd_dns_close(struct asteriskd_dns_client *client) {
#if defined(__linux__) || defined(__ANDROID__)
    if (client->fd >= 0) close(client->fd);
#endif
    client->fd = -1;
    client->connected = false;
    client->pending = false;
    free(client->tx);
    client->tx = NULL;
}
void asteriskd_dns_fail(struct asteriskd_dns_client *client, const char *reason) {
    asteriskd_dns_close(client);
    client->snapshot.phase = ASTERISKD_DNS_PHASE_FAILED;
    snprintf(client->snapshot.reason, sizeof(client->snapshot.reason), "%s", reason);
}
uint64_t asteriskd_dns_monotime(void) {
#if defined(__linux__) || defined(__ANDROID__)
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
#endif
    return 0;
}
static size_t uid_array(unsigned char *out, const uint32_t *uids, size_t count) {
    uint32_t *sorted = malloc((count ? count : 1) * sizeof(*sorted));
    if (!sorted) return SIZE_MAX;
    if (count) memcpy(sorted, uids, count * sizeof(*uids));
    qsort(sorted, count, sizeof(*sorted), asteriskd_compare_u32);
    size_t written = 0;
    for (size_t i = 0; i < count; ++i)
        if (i == 0 || sorted[i] != sorted[i - 1]) dns_write_le(out + 4 * written++, sorted[i], 4);
    free(sorted);
    return written;
}
int asteriskd_dns_command(struct asteriskd_dns_client *client, uint16_t opcode,
    const struct asteriskd_config *config, uint64_t now) {
    if (client->fd < 0 || client->pending || client->request_id == UINT32_MAX ||
        opcode < ASTERISKD_DNS_OP_HELLO || opcode > ASTERISKD_DNS_OP_RELEASE)
        return -1;
    size_t capacity = ASTERISKD_DNS_HEADER_SIZE +
        ((opcode == ASTERISKD_DNS_OP_ACTIVATE || opcode == ASTERISKD_DNS_OP_CHECK) ? 8 : 0);
    if (opcode == ASTERISKD_DNS_OP_PREPARE) {
        if (!config || config->uid_count > 8192 || config->bypass_uid_count > 8192) return -1;
        capacity += 48 + 4 * (config->uid_count + config->bypass_uid_count);
    }
    free(client->tx);
    client->tx = calloc(1, capacity);
    if (!client->tx) return -1;
    size_t body = 0;
    if (opcode == ASTERISKD_DNS_OP_ACTIVATE || opcode == ASTERISKD_DNS_OP_CHECK) {
        body = 8;
        dns_write_le(
            client->tx + ASTERISKD_DNS_HEADER_SIZE, now + ASTERISKD_DNS_COMMAND_TIMEOUT_MILLIS, 8);
    }
    if (opcode == ASTERISKD_DNS_OP_PREPARE) {
        unsigned char *payload = client->tx + ASTERISKD_DNS_HEADER_SIZE;
        uint32_t mode = config->mode == ASTERISKD_MODE_TPROXY ? 1
            : config->mode == ASTERISKD_MODE_TUN2SOCKS        ? 2
                                                              : 3;
        uint32_t policy = config->app_policy_mode == ASTERISKD_APP_POLICY_GLOBAL ? 3
            : config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST          ? 2
                                                                                 : 1;
        uint32_t port = mode == 1 ? config->transparent_port
            : mode == 2           ? config->helper.value.hev.socks_port
                                  : config->helper.value.bpf.socks_port;
        dns_write_le(payload, mode, 4);
        dns_write_le(payload + 4, policy, 4);
        dns_write_le(payload + 8, 2, 4);
        dns_write_le(payload + 12, port, 4);
        dns_write_le(payload + 16, ASTERISKD_DNS_MARK_MASK, 4);
        dns_write_le(payload + 20, ASTERISKD_DNS_PROXY_DECISION, 4);
        dns_write_le(payload + 24, ASTERISKD_DNS_DIRECT_MARK, 4);
        size_t listed_count = uid_array(payload + 48, config->uids, config->uid_count);
        if (listed_count == SIZE_MAX) return -1;
        size_t bypass_count = uid_array(
            payload + 48 + 4 * listed_count, config->bypass_uids, config->bypass_uid_count);
        if (bypass_count == SIZE_MAX) return -1;
        dns_write_le(payload + 28, listed_count, 4);
        dns_write_le(payload + 32, bypass_count, 4);
        dns_write_le(payload + 36, 0, 4);
        dns_write_le(payload + 40, client->netd, 8);
        body = 48 + 4 * (listed_count + bypass_count);
        client->snapshot.phase = ASTERISKD_DNS_PHASE_PREPARING;
        client->route_count = 0;
        client->prepare_retry = false;
        client->prepare_draining = false;
        client->snapshot.reason[0] = 0;
    }
    dns_write_le(client->tx, ASTERISKD_DNS_FRAME_MAGIC, 4);
    dns_write_le(client->tx + 4, ASTERISKD_DNS_FRAME_VERSION, 2);
    dns_write_le(client->tx + 6, opcode, 2);
    dns_write_le(client->tx + 8, body, 4);
    dns_write_le(client->tx + 12, ++client->request_id, 4);
    dns_write_le(client->tx + 16, client->snapshot.instance_id, 8);
    dns_write_le(client->tx + 24, client->snapshot.cycle_id, 8);
    dns_write_le(client->tx + 32, client->snapshot.generation, 8);
    client->opcode = opcode;
    client->tx_size = ASTERISKD_DNS_HEADER_SIZE + body;
    client->tx_offset = 0;
    client->deadline = now + ASTERISKD_DNS_COMMAND_TIMEOUT_MILLIS;
    client->pending = true;
    client->complete = false;
    client->result = 0;
    return 0;
}
int asteriskd_dns_begin(struct asteriskd_dns_client *client, uint64_t instance, uint64_t cycle,
    uint64_t generation, uint64_t now) {
    asteriskd_dns_close(client);
    asteriskd_dns_init(client);
    client->snapshot = (struct asteriskd_dns_snapshot){.required = true,
        .phase = ASTERISKD_DNS_PHASE_PREPARING,
        .instance_id = instance,
        .cycle_id = cycle,
        .generation = generation};
#if defined(__linux__) || defined(__ANDROID__)
    client->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const char name[] = "\0asterisk.enhance.dns";
    memcpy(address.sun_path, name, sizeof(name) - 1);
    if (client->fd < 0 ||
        (connect(client->fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) + sizeof(name) - 1) != 0 &&
            errno != EINPROGRESS)) {
        int saved_errno = errno;
        char reason[128];
        snprintf(reason, sizeof(reason), "companion unavailable: errno=%d (%s)", saved_errno,
            strerror(saved_errno));
        asteriskd_dns_fail(client, reason);
        return -1;
    }
    return asteriskd_dns_command(client, ASTERISKD_DNS_OP_HELLO, NULL, now);
#else
    (void)now;
    asteriskd_dns_fail(client, "companion requires Android");
    return -1;
#endif
}
static int dns_accept(
    struct asteriskd_dns_client *client, const unsigned char *frame, size_t length, uint64_t now) {
    if (!client->pending || now >= client->deadline || length < ASTERISKD_DNS_HEADER_SIZE ||
        dns_read_le(frame, 4) != ASTERISKD_DNS_FRAME_MAGIC ||
        dns_read_le(frame + 4, 2) != ASTERISKD_DNS_FRAME_VERSION ||
        dns_read_le(frame + 8, 4) != length - ASTERISKD_DNS_HEADER_SIZE ||
        dns_read_le(frame + 12, 4) != client->request_id ||
        dns_read_le(frame + 16, 8) != client->snapshot.instance_id ||
        dns_read_le(frame + 24, 8) != client->snapshot.cycle_id ||
        dns_read_le(frame + 32, 8) != client->snapshot.generation)
        goto invalid;
    if (client->opcode == ASTERISKD_DNS_OP_HELLO) {
        if (length != 88 || dns_read_le(frame + 6, 2) != ASTERISKD_DNS_OP_CAPABILITIES)
            goto invalid;
        const unsigned char *payload = frame + ASTERISKD_DNS_HEADER_SIZE;
        uint32_t flags = (uint32_t)dns_read_le(payload + 44, 4);
        client->netd = dns_read_le(payload, 8);
        if (!client->netd || dns_read_le(payload + 8, 4) != 7 || (flags & 6) != 6 ||
#if !defined(ASTERISKD_DNS_TEST_PROBE) || ASTERISKD_DNS_TEST_PROBE != 1
            (flags & 1) ||
#endif
            dns_read_le(payload + 20, 4) != ASTERISKD_DNS_MARK_MASK ||
            dns_read_le(payload + 24, 4) != ASTERISKD_DNS_PROXY_DECISION ||
            dns_read_le(payload + 28, 4) != ASTERISKD_DNS_DIRECT_MARK ||
            dns_read_le(payload + 32, 4) != 2 || dns_read_le(payload + 36, 4) != 0 ||
            dns_read_le(payload + 40, 4) != 0) {
            char reason[128];
            snprintf(reason, sizeof(reason),
                "incompatible capabilities: netd=%s revision=%u flags=0x%x consumer=%u marks=%s "
                "reserved=%s",
                client->netd ? "present" : "missing", (unsigned)dns_read_le(payload + 8, 4), flags,
                (unsigned)dns_read_le(payload + 32, 4),
                dns_read_le(payload + 20, 4) == ASTERISKD_DNS_MARK_MASK &&
                        dns_read_le(payload + 24, 4) == ASTERISKD_DNS_PROXY_DECISION &&
                        dns_read_le(payload + 28, 4) == ASTERISKD_DNS_DIRECT_MARK
                    ? "ok"
                    : "mismatch",
                dns_read_le(payload + 36, 4) == 0 && dns_read_le(payload + 40, 4) == 0 ? "ok"
                                                                                       : "nonzero");
            asteriskd_dns_fail(client, reason);
            return -1;
        }
        client->result =
            (uint32_t)dns_read_le(payload + 16, 4); // Supported mode mask, checked before PREPARE.
        client->drain_events = (flags & 8U) != 0;
        if (client->result == 0) {
            asteriskd_dns_close(client);
            client->snapshot.phase = ASTERISKD_DNS_PHASE_UNSUPPORTED;
            snprintf(client->snapshot.reason, sizeof(client->snapshot.reason),
                "module advertises no supported modes");
            return -1;
        }
    } else {
        if (length < 64 ||
            (dns_read_le(frame + 6, 2) != ASTERISKD_DNS_OP_ACK &&
                dns_read_le(frame + 6, 2) != ASTERISKD_DNS_OP_ERROR) ||
            dns_read_le(frame + ASTERISKD_DNS_HEADER_SIZE, 8) != client->netd ||
            dns_read_le(frame + 60, 4) != 0)
            goto invalid;
        client->result = (uint32_t)dns_read_le(frame + 48, 4);
        uint32_t phase = (uint32_t)dns_read_le(frame + 52, 4);
        client->retained = (uint32_t)dns_read_le(frame + 56, 4);
        if (client->opcode == ASTERISKD_DNS_OP_PREPARE &&
            client->result == ASTERISKD_DNS_RESULT_OK && phase == ASTERISKD_DNS_MODULE_PREPARED &&
            dns_read_le(frame + 6, 2) == ASTERISKD_DNS_OP_ACK) {
            if (length < 68) goto invalid;
            size_t count = (size_t)dns_read_le(frame + 64, 4);
            if (count > ASTERISKD_DNS_MAX_ROUTES || length != 68 + 32 * count ||
                (!count && client->retained))
                goto invalid;
            for (size_t i = 0; i < count; i++) {
                const unsigned char *payload = frame + 68 + 32 * i;
                struct asteriskd_dns_route *route = &client->routes[i];
                route->netid = (uint32_t)dns_read_le(payload, 4);
                route->mark = (uint32_t)dns_read_le(payload + 4, 4);
                route->family = (uint32_t)dns_read_le(payload + 8, 4);
                route->scope = (uint32_t)dns_read_le(payload + 12, 4);
                memcpy(route->address, payload + 16, 16);
                if (!route->netid || (route->mark & ASTERISKD_DNS_MARK_MASK) ||
                    (route->family != 4 && route->family != 6))
                    goto invalid;
                unsigned nonzero = 0;
                for (size_t j = 0; j < (route->family == 4 ? 4U : 16U); j++)
                    nonzero |= route->address[j];
                if (!nonzero ||
                    (route->family == 4 &&
                        (route->scope || route->address[0] >= 224 || route->address[0] == 0)) ||
                    (route->family == 6 &&
                        (route->address[0] == 255 ||
                            (route->address[0] == 0xfe && (route->address[1] & 0xc0) == 0x80 &&
                                !route->scope))))
                    goto invalid;
                if (route->family == 4)
                    for (size_t j = 4; j < 16; j++)
                        if (route->address[j]) goto invalid;
                for (size_t j = 0; j < i; j++)
                    if (!memcmp(route, &client->routes[j], sizeof(*route))) goto invalid;
            }
            client->route_count = count;
        } else if (length == 80 && client->opcode == ASTERISKD_DNS_OP_PREPARE &&
            client->result == ASTERISKD_DNS_RESULT_CACHE_ERROR &&
            dns_read_le(frame + 6, 2) == ASTERISKD_DNS_OP_ERROR) {
            uint32_t stage = (uint32_t)dns_read_le(frame + 64, 4),
                     detail = (uint32_t)dns_read_le(frame + 68, 4);
            int32_t error = (int32_t)(uint32_t)dns_read_le(frame + 72, 4);
            uint32_t network = (uint32_t)dns_read_le(frame + 76, 4);
            static const char *const stages[] = {"unknown", "discover", "read", "reserve",
                "configure", "check", "routes", "release"};
            static const char *const reasons[] = {"unknown", "not-ready", "changed", "private-dns",
                "nat64", "invalid-config", "backend", "capacity"};
            if (stage >= 8 || detail >= 8 ||
                (phase != ASTERISKD_DNS_MODULE_IDLE && phase != ASTERISKD_DNS_MODULE_DRAINING) ||
                client->retained > 64)
                goto invalid;
            snprintf(client->snapshot.reason, sizeof(client->snapshot.reason),
                "CACHE_ERROR stage=%s reason=%s error=%d network=%u phase=%u retained=%u",
                stages[stage], reasons[detail], error, network, phase, client->retained);
            // Only known transient failures on real networks, with complete cleanup.
            // Old/unknown errors and isolated-cache read failures remain terminal.
            client->prepare_retry = phase == ASTERISKD_DNS_MODULE_IDLE && client->retained == 0 &&
                network <= 0xffffU &&
                ((detail == 1 && (stage == 1 || stage == 2) && (error == 0 || error == -ENOENT)) ||
                    (detail == 2 && (stage == 5 || stage == 6) && error == -EAGAIN));
            client->pending = false;
            client->complete = true;
            if (client->prepare_retry) {
                client->snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
                return 0;
            }
            asteriskd_dns_close(client);
            client->snapshot.phase = ASTERISKD_DNS_PHASE_FAILED;
            return -1;
        } else if (length != 64 ||
            (client->opcode == ASTERISKD_DNS_OP_PREPARE &&
                client->result == ASTERISKD_DNS_RESULT_CACHE_ERROR))
            goto invalid;
        if (client->result == ASTERISKD_DNS_RESULT_DRAINING &&
            client->opcode == ASTERISKD_DNS_OP_RELEASE && phase == ASTERISKD_DNS_MODULE_DRAINING)
            client->snapshot.phase = ASTERISKD_DNS_PHASE_DRAINING;
        else if (client->result == ASTERISKD_DNS_RESULT_CACHE_ERROR &&
            (client->opcode == ASTERISKD_DNS_OP_ACTIVATE ||
                client->opcode == ASTERISKD_DNS_OP_CHECK) &&
            phase == ASTERISKD_DNS_MODULE_DRAINING &&
            dns_read_le(frame + 6, 2) == ASTERISKD_DNS_OP_ERROR) {
            // The module has already withdrawn the old policy. Keep the
            // authenticated connection for drain and a fresh network snapshot.
            client->snapshot.phase = ASTERISKD_DNS_PHASE_DRAINING;
            client->topology_changed = true;
        } else if (client->opcode == ASTERISKD_DNS_OP_PREPARE &&
            client->result == ASTERISKD_DNS_RESULT_BUSY && phase == ASTERISKD_DNS_MODULE_DRAINING &&
            dns_read_le(frame + 6, 2) == ASTERISKD_DNS_OP_ERROR) {
            // The previous owner's session is still auto-releasing in-flight
            // queries. Its caches are not ours; retry PREPARE after the drain event.
            snprintf(client->snapshot.reason, sizeof(client->snapshot.reason),
                "previous DNS cycle draining in-flight queries: retained=%u", client->retained);
            client->retained = 0;
            client->prepare_retry = true;
            client->prepare_draining = true;
            client->snapshot.phase = ASTERISKD_DNS_PHASE_DRAINING;
        } else if (client->result != ASTERISKD_DNS_RESULT_OK ||
            dns_read_le(frame + 6, 2) != ASTERISKD_DNS_OP_ACK) {
            static const char *const results[] = {"OK", "INVALID", "UNSUPPORTED", "STALE", "BUSY",
                "CACHE_ERROR", "DRAINING", "EXHAUSTED", "IO_ERROR"};
            char reason[128];
            snprintf(reason, sizeof(reason), "companion command %u result %u (%s) phase=%u",
                client->opcode, client->result,
                client->result < sizeof(results) / sizeof(results[0]) ? results[client->result]
                                                                      : "UNKNOWN",
                phase);
            asteriskd_dns_fail(client, reason);
            return -1;
        } else if (client->opcode == ASTERISKD_DNS_OP_PREPARE &&
            phase == ASTERISKD_DNS_MODULE_PREPARED)
            client->snapshot.phase = ASTERISKD_DNS_PHASE_PREPARED;
        else if ((client->opcode == ASTERISKD_DNS_OP_ACTIVATE ||
                     client->opcode == ASTERISKD_DNS_OP_CHECK) &&
            phase == ASTERISKD_DNS_MODULE_ACTIVE) {
            client->snapshot.phase = client->route_count ? ASTERISKD_DNS_PHASE_ACTIVE : ASTERISKD_DNS_PHASE_WAITING_NETWORK;
            snprintf(client->snapshot.reason, sizeof(client->snapshot.reason), "%s",
                client->route_count ? "" : "waiting for network");
        } else if (client->opcode == ASTERISKD_DNS_OP_DEACTIVATE &&
            (phase == ASTERISKD_DNS_MODULE_IDLE || phase == ASTERISKD_DNS_MODULE_DRAINING))
            client->snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
        else if (client->opcode == ASTERISKD_DNS_OP_RELEASE && phase == ASTERISKD_DNS_MODULE_IDLE &&
            client->retained == 0)
            client->snapshot.phase = ASTERISKD_DNS_PHASE_INACTIVE;
        else
            goto invalid;
    }
    client->pending = false;
    client->complete = true;
    return 0;
invalid:
    asteriskd_dns_fail(client, "late, stale or malformed companion response");
    return -1;
}
int asteriskd_dns_step(struct asteriskd_dns_client *client, uint64_t now) {
    if (!client->snapshot.required || client->fd < 0) return 0;
    if (client->pending && now >= client->deadline) {
        asteriskd_dns_fail(client, "companion command expired");
        return -1;
    }
#if defined(__linux__) || defined(__ANDROID__)
    if (!client->connected) {
        struct ucred peer;
        socklen_t count = sizeof(peer);
        if (getsockopt(client->fd, SOL_SOCKET, SO_PEERCRED, &peer, &count) != 0 ||
            count != sizeof(peer) || peer.uid != 0 || peer.pid <= 0) {
            asteriskd_dns_fail(client, "untrusted companion peer");
            return -1;
        }
        client->connected = true;
    }
    if (!client->pending && asteriskd_dns_serving(client->snapshot.phase) &&
        client->network_changed && !client->busy && !client->rx_size) {
        client->network_changed = false;
        if (asteriskd_dns_command(client, ASTERISKD_DNS_OP_CHECK, NULL, now) != 0) return -1;
    }
    if (client->pending && client->tx_offset < client->tx_size) {
        ssize_t count = send(client->fd, client->tx + client->tx_offset,
            client->tx_size - client->tx_offset, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count > 0)
            client->tx_offset += (size_t)count;
        else if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            goto io_error;
    }
    size_t need = client->rx_size < ASTERISKD_DNS_HEADER_SIZE
        ? ASTERISKD_DNS_HEADER_SIZE
        : ASTERISKD_DNS_HEADER_SIZE + (size_t)dns_read_le(client->rx + 8, 4);
    if (need > sizeof(client->rx) || need < client->rx_size) goto io_error;
    ssize_t count =
        recv(client->fd, client->rx + client->rx_size, need - client->rx_size, MSG_DONTWAIT);
    if (count > 0)
        client->rx_size += (size_t)count;
    else if (count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
        goto io_error;
    if (client->rx_size >= ASTERISKD_DNS_HEADER_SIZE) {
        need = ASTERISKD_DNS_HEADER_SIZE + (size_t)dns_read_le(client->rx + 8, 4);
        if (need > sizeof(client->rx)) goto io_error;
        if (client->rx_size == need) {
            if (need == ASTERISKD_DNS_HEADER_SIZE &&
                dns_read_le(client->rx, 4) == ASTERISKD_DNS_FRAME_MAGIC &&
                dns_read_le(client->rx + 4, 2) == ASTERISKD_DNS_FRAME_VERSION &&
                dns_read_le(client->rx + 6, 2) == ASTERISKD_DNS_OP_NETWORK_CHANGED &&
                dns_read_le(client->rx + 12, 4) == 1 && !dns_read_le(client->rx + 16, 8) &&
                !dns_read_le(client->rx + 24, 8) && !dns_read_le(client->rx + 32, 8)) {
                client->network_changed = true;
                client->rx_size = 0;
                return 0;
            }
            int result = dns_accept(client, client->rx, client->rx_size, now);
            client->rx_size = 0;
            return result;
        }
    }
    return 0;
io_error: {
    char reason[128];
    snprintf(reason, sizeof(reason), "companion I/O op=%u rx=%zu tx=%zu/%zu errno=%d",
        client->opcode, client->rx_size, client->tx_offset, client->tx_size, errno);
    asteriskd_dns_fail(client, reason);
    return -1;
}
#else
    (void)now;
    return -1;
#endif
}

/* One-shot read-only bridge. No supervisor/config/log/state/network initialization. */
#if defined(__linux__) || defined(__ANDROID__)
static int info_transfer(
    int fd, unsigned char *bytes, size_t length, bool sending, uint64_t deadline) {
    while (length) {
        uint64_t now = asteriskd_dns_monotime();
        if (now >= deadline) return -1;
        struct pollfd event = {.fd = fd, .events = sending ? POLLOUT : POLLIN};
        int ready = poll(&event, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t count = sending ? send(fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL)
                                : recv(fd, bytes, length, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) return -1;
        bytes += count;
        length -= (size_t)count;
    }
    return asteriskd_dns_monotime() < deadline ? 0 : -1;
}
#endif
int asteriskd_dns_info(void) {
#if defined(__linux__) || defined(__ANDROID__)
    if (geteuid() != 0) {
        puts("AE_ROOT_DENIED");
        return 0;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    const char name[] = "\0asterisk.enhance.dns";
    memcpy(address.sun_path, name, sizeof(name) - 1);
    bool valid = false;
    unsigned char frame[ASTERISKD_DNS_HEADER_SIZE + 512] = {0};
    const uint64_t deadline = asteriskd_dns_monotime() + ASTERISKD_DNS_COMMAND_TIMEOUT_MILLIS;
    if (fd >= 0 &&
        (connect(fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) + sizeof(name) - 1) == 0 ||
            errno == EINPROGRESS)) {
        struct ucred peer;
        socklen_t size = sizeof(peer);
        if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) && size == sizeof(peer) &&
            peer.uid == 0 && peer.pid > 1) {
            dns_write_le(frame, ASTERISKD_DNS_FRAME_MAGIC, 4);
            dns_write_le(frame + 4, ASTERISKD_DNS_FRAME_VERSION, 2);
            dns_write_le(frame + 6, ASTERISKD_DNS_OP_INFO, 2);
            dns_write_le(frame + 12, 1, 4);
            if (!info_transfer(fd, frame, ASTERISKD_DNS_HEADER_SIZE, true, deadline) &&
                !info_transfer(fd, frame, ASTERISKD_DNS_HEADER_SIZE, false, deadline)) {
                size_t length = (size_t)dns_read_le(frame + 8, 4);
                if (dns_read_le(frame, 4) == ASTERISKD_DNS_FRAME_MAGIC &&
                    dns_read_le(frame + 4, 2) == ASTERISKD_DNS_FRAME_VERSION &&
                    dns_read_le(frame + 6, 2) == ASTERISKD_DNS_OP_INFO_RESPONSE &&
                    dns_read_le(frame + 12, 4) == 1 && !dns_read_le(frame + 16, 8) &&
                    !dns_read_le(frame + 24, 8) && !dns_read_le(frame + 32, 8) && length > 0 &&
                    length <= 512 &&
                    !info_transfer(
                        fd, frame + ASTERISKD_DNS_HEADER_SIZE, length, false, deadline)) {
                    valid = length >= 10 &&
                        !memcmp(frame + ASTERISKD_DNS_HEADER_SIZE, "AE_INFO 1\n", 10) &&
                        frame[ASTERISKD_DNS_HEADER_SIZE - 1 + length] == '\n';
                    for (size_t i = ASTERISKD_DNS_HEADER_SIZE;
                        valid && i < ASTERISKD_DNS_HEADER_SIZE + length; ++i)
                        if (frame[i] != '\n' && (frame[i] < 32 || frame[i] > 126)) valid = false;
                    if (valid) fwrite(frame + ASTERISKD_DNS_HEADER_SIZE, 1, length, stdout);
                }
            }
        }
    }
    if (fd >= 0) close(fd);
    if (!valid) puts("AE_UNAVAILABLE");
#else
    puts("AE_UNAVAILABLE");
#endif
    return 0;
}

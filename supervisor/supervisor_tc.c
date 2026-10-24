// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

int asteriskd_supervisor_tc_command(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count, bool capture,
    int *exit_status) {
    if (arguments == NULL || argument_count == 0U || argument_count > 20U ||
        exit_status == NULL) return -1;
    const char *argv[22U];
    argv[0] = "tc";
    for (size_t index = 0U; index < argument_count; ++index) {
        if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
        argv[index + 1U] = arguments[index];
    }
    argv[argument_count + 1U] = NULL;
    return asteriskd_supervisor_action_run_argv(system, argv, capture, exit_status);
}

static int system_tc_zero(struct asteriskd_system_supervisor *system,
    const char *const *arguments, size_t argument_count) {
    int exit_status = -1;
    return asteriskd_supervisor_tc_command(system, arguments, argument_count,
        false, &exit_status) == 0 && exit_status == 0 ? 0 : -1;
}

void asteriskd_supervisor_tc_netlink_close(struct asteriskd_system_supervisor *system) {
    if (system->tc_netlink_fd_owned && system->tc_netlink_fd >= 0) {
        (void)close(system->tc_netlink_fd);
    }
    system->tc_netlink_fd = -1;
    system->tc_netlink_port_id = 0U;
    system->tc_netlink_fd_owned = false;
    system->tc_netlink_active = false;
    system->tc_netlink_query = SYSTEM_TC_NETLINK_QUERY_NONE;
}

static int system_tc_netlink_begin(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    enum system_tc_netlink_query_kind query, void *request, size_t request_size,
    struct nlmsghdr *header) {
    if (system->tc_netlink_active || interface_index == 0U ||
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
    ++system->tc_netlink_sequence;
    if (system->tc_netlink_sequence == 0U) ++system->tc_netlink_sequence;
    header->nlmsg_seq = system->tc_netlink_sequence;
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
    system->tc_netlink_fd = fd;
    system->tc_netlink_port_id = assigned.nl_pid;
    system->tc_netlink_fd_owned = true;
    system->tc_netlink_active = true;
    system->tc_netlink_done = false;
    system->tc_netlink_failed = false;
    system->tc_netlink_interface_index = interface_index;
    system->tc_netlink_query = query;
    system->tc_filter_netlink_state = ASTERISKD_RULES_SLOT_ABSENT;
    system->tc_qdisc_netlink_state = ASTERISKD_RULES_SLOT_ABSENT;
    return 0;
}

static int system_tc_filter_netlink_start(
    struct asteriskd_system_supervisor *system, uint32_t interface_index,
    uint32_t parent, uint32_t priority, uint32_t protocol,
    enum system_tc_netlink_query_kind query) {
    if (interface_index == 0U || parent == 0U ||
        priority == 0U || protocol == 0U ||
        (query != SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER &&
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

int asteriskd_supervisor_tc_netlink_dispatch(
    struct asteriskd_system_supervisor *system, short ready) {
    if ((ready & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        char message[96U];
        int written = snprintf(message, sizeof(message),
            "TC netlink poll failed: revents=0x%x", (unsigned short)ready);
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
        ssize_t received = recvmsg(system->tc_netlink_fd, &message, MSG_TRUNC);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (received <= 0 || (size_t)received > sizeof(buffer) ||
            (message.msg_flags & MSG_TRUNC) != 0 || sender.nl_pid != 0U) return -1;
        char error[128U] = {0};
        int decoded = system->tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_EXPECTED_FILTER
                ? asteriskd_tc_filter_netlink_decode(
                    buffer, (size_t)received, system->tc_netlink_sequence,
                    system->tc_netlink_port_id,
                    &system->tc_filter_netlink_expectation,
                    &system->tc_filter_netlink_state,
                    &system->tc_netlink_done, error, sizeof(error))
                : system->tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_SLOT_FILTER
                    ? asteriskd_tc_filter_slot_netlink_decode(
                        buffer, (size_t)received, system->tc_netlink_sequence,
                        system->tc_netlink_port_id,
                        &system->tc_filter_netlink_expectation,
                        &system->tc_filter_netlink_state,
                        &system->tc_netlink_done, error, sizeof(error))
                : system->tc_netlink_query == SYSTEM_TC_NETLINK_QUERY_QDISC
                    ? asteriskd_tc_qdisc_netlink_decode(
                        buffer, (size_t)received, system->tc_netlink_sequence,
                        system->tc_netlink_port_id,
                        system->tc_netlink_interface_index,
                        &system->tc_qdisc_netlink_state,
                        &system->tc_netlink_done, error, sizeof(error))
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
                "TC netlink decode failed: query=%u bytes=%zd type=%u flags=0x%x"
                " sequence=%" PRIu32 " pid=%" PRIu32 " kernelError=%" PRId32
                " detail=%s", (unsigned)system->tc_netlink_query, received,
                (unsigned)first.nlmsg_type, (unsigned)first.nlmsg_flags,
                first.nlmsg_seq, first.nlmsg_pid, kernel_error,
                error[0] == '\0' ? "unavailable" : error);
            if (written > 0 && (size_t)written < sizeof(message)) {
                (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_ERROR,
                    ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
            }
            return -1;
        }
        if (system->tc_netlink_done) return 0;
    }
}

static bool system_tc_netlink_done(void *opaque) {
    struct asteriskd_system_supervisor *system = opaque;
    if (asteriskd_supervisor_action_should_cancel(atomic_load_explicit(
            &system->runtime->lifecycle.stop_was_requested, memory_order_acquire),
            system->cleanup_in_progress)) {
        system->tc_netlink_failed = true;
        system->tc_netlink_done = true;
    }
    return system->tc_netlink_done;
}

int asteriskd_supervisor_expected_tc_netlink_probe(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state) {
    if (resource == NULL || state == NULL || resource->interface_index == 0U) return -1;
    enum asteriskd_pin_id pin_id =
        resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS
            ? ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS
            : resource->program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS
                ? ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS : ASTERISKD_PIN_COUNT;
    const struct asteriskd_b2s_verified_pin *verified =
        asteriskd_supervisor_b2s_verified_pin(system, pin_id);
    const char *name = asteriskd_b2s_tc_filter_attachment_name(resource->program_id);
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
    if (system_tc_filter_netlink_start(system, resource->interface_index,
            parent, ASTERISKD_HOTSPOT_TC_PRIORITY, ASTERISKD_ETH_PROTOCOL_ALL,
            query) != 0) return -1;
    int64_t now = 0;
    int result = -1;
    if (asteriskd_supervisor_runtime_clock(system, &now) == 0 &&
        now <= INT64_MAX -
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = now +
                (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
        };
        if (asteriskd_supervisor_pump_condition(
                system, &deadline, system_tc_netlink_done) == 0 &&
            system->tc_netlink_done && !system->tc_netlink_failed) {
            *state = system->tc_filter_netlink_state;
            result = 0;
        }
    }
    asteriskd_supervisor_tc_netlink_close(system);
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
    if (asteriskd_supervisor_runtime_clock(system, &now) == 0 &&
        now <= INT64_MAX -
            (int64_t)system->loaded_config.config.readiness_timeout_milliseconds) {
        struct asteriskd_deadline deadline = {
            .armed = true,
            .monotonic_milliseconds = now +
                (int64_t)system->loaded_config.config.readiness_timeout_milliseconds,
        };
        if (asteriskd_supervisor_pump_condition(
                system, &deadline, system_tc_netlink_done) == 0 &&
            system->tc_netlink_done && !system->tc_netlink_failed) {
            *state = system->tc_qdisc_netlink_state;
            result = 0;
        }
    }
    asteriskd_supervisor_tc_netlink_close(system);
    return result;
}

static enum asteriskd_pin_id system_tc_pin_id(enum asteriskd_program_id program_id) {
    return program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS
        ? ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS
        : program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS
            ? ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS : ASTERISKD_PIN_COUNT;
}

const char *asteriskd_supervisor_tc_direction(enum asteriskd_tc_direction direction) {
    return direction == ASTERISKD_TC_DIRECTION_INGRESS ? "ingress" :
        direction == ASTERISKD_TC_DIRECTION_EGRESS ? "egress" : NULL;
}

int asteriskd_supervisor_tc_probe_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource, bool *present) {
    if (resource == NULL || present == NULL ||
        if_nametoindex(resource->interface_name) != resource->interface_index) return -1;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    if (system_qdisc_netlink_probe(system, resource->interface_index, &state) != 0 ||
        state == ASTERISKD_RULES_SLOT_FOREIGN) return -1;
    *present = state == ASTERISKD_RULES_SLOT_OWNED;
    return 0;
}

int asteriskd_supervisor_tc_probe_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource,
    enum asteriskd_rules_slot_state *state) {
    if (resource == NULL || state == NULL ||
        if_nametoindex(resource->interface_name) != resource->interface_index) return -1;
    return asteriskd_supervisor_expected_tc_netlink_probe(system, resource, state);
}

int asteriskd_supervisor_tc_apply_qdisc(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_qdisc_resource *resource) {
    const char *arguments[] = {"qdisc", "add", "dev", resource->interface_name, "clsact"};
    return system_tc_zero(system, arguments, 5U);
}

int asteriskd_supervisor_tc_apply_filter(struct asteriskd_system_supervisor *system,
    const struct asteriskd_tc_filter_resource *resource) {
    const char *direction = asteriskd_supervisor_tc_direction(resource->direction);
    enum asteriskd_pin_id pin_id = system_tc_pin_id(resource->program_id);
    const char *path = pin_id == ASTERISKD_PIN_COUNT ? NULL : asteriskd_supervisor_pin_path(system, pin_id);
    if (direction == NULL || path == NULL) return -1;
    const char *arguments[] = {"filter", "add", "dev", resource->interface_name,
        direction, "protocol", "all", "pref", "1", "handle", "1",
        "bpf", "da", "pinned", path};
    return system_tc_zero(system, arguments, 15U);
}

#endif

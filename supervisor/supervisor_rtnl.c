// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

/*
 * In-process replacement for the `ip rule`/`ip route` commands asteriskd
 * issues. Requests use rtnetlink directly; listings are rendered in the
 * iproute2 text form that the rule and route classifiers already parse.
 * Attributes the classifiers do not know are rendered as an extra token, so
 * an unexpected object at an owned identity is still classified as foreign.
 */

#include "supervisor/supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <linux/fib_rules.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <stdarg.h>

#define RTNL_RECEIVE_BUFFER 65536U
#define RTNL_REQUEST_ATTRIBUTES 256U
#define RTNL_DUMP_ATTEMPTS 3

struct rtnl_output {
    char *bytes;
    size_t capacity;
    size_t length;
    bool overflow;
};

struct rtnl_request {
    struct nlmsghdr header;
    union {
        struct rtmsg route;
        struct fib_rule_hdr rule;
        struct rtgenmsg generic;
        struct tcmsg filter;
    } body;
    unsigned char attributes[RTNL_REQUEST_ATTRIBUTES];
};

struct rtnl_destination {
    bool present;
    unsigned char length;
    unsigned char address[16U];
};

typedef int (*rtnl_message_callback)(const struct nlmsghdr *, void *);

static uint32_t rtnl_sequence;

static void rtnl_printf(struct rtnl_output *output, const char *format, ...) {
    if (output == NULL || output->overflow) return;
    size_t available = output->capacity - output->length;
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(output->bytes + output->length, available, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= available) {
        output->overflow = true;
        return;
    }
    output->length += (size_t)written;
}

static int rtnl_address_family(enum asteriskd_ip_family family) {
    return family == ASTERISKD_IP_FAMILY_IPV4 ? AF_INET :
        family == ASTERISKD_IP_FAMILY_IPV6 ? AF_INET6 : AF_UNSPEC;
}

static size_t rtnl_address_bytes(int family) {
    return family == AF_INET ? 4U : 16U;
}

static int rtnl_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static int rtnl_attribute_add(struct rtnl_request *request, uint16_t type,
    const void *data, size_t length) {
    size_t attribute_length = RTA_LENGTH(length);
    size_t offset = NLMSG_ALIGN(request->header.nlmsg_len);
    if (offset + RTA_ALIGN(attribute_length) > sizeof(*request)) return -1;
    struct rtattr *attribute = (struct rtattr *)((unsigned char *)request + offset);
    attribute->rta_type = type;
    attribute->rta_len = (unsigned short)attribute_length;
    if (length != 0U) memcpy(RTA_DATA(attribute), data, length);
    request->header.nlmsg_len = (uint32_t)(offset + RTA_ALIGN(attribute_length));
    return 0;
}

static int rtnl_attribute_u32(struct rtnl_request *request, uint16_t type, uint32_t value) {
    return rtnl_attribute_add(request, type, &value, sizeof(value));
}

/*
 * Sends one request and consumes its replies. Returns 0 on success, a positive
 * errno when the kernel rejected the request, and -1 on a transport failure.
 */
static int rtnl_transact(int fd, struct nlmsghdr *request,
    rtnl_message_callback callback, void *context) {
    request->nlmsg_seq = ++rtnl_sequence;
    request->nlmsg_pid = 0U;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent;
    do {
        sent = sendto(fd, request, request->nlmsg_len, 0,
            (struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    if (sent < 0 || (size_t)sent != request->nlmsg_len) return -1;
    bool dump = (request->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP;
    static unsigned char buffer[RTNL_RECEIVE_BUFFER] __attribute__((aligned(8)));
    for (;;) {
        ssize_t received;
        do {
            received = recv(fd, buffer, sizeof(buffer), 0);
        } while (received < 0 && errno == EINTR);
        if (received <= 0) return -1;
        size_t remaining = (size_t)received;
        for (struct nlmsghdr *message = (struct nlmsghdr *)buffer;
                NLMSG_OK(message, remaining); message = NLMSG_NEXT(message, remaining)) {
            if (message->nlmsg_seq != request->nlmsg_seq) continue;
            if ((message->nlmsg_flags & NLM_F_DUMP_INTR) != 0U) return -1;
            if (message->nlmsg_type == NLMSG_DONE) return 0;
            if (message->nlmsg_type == NLMSG_ERROR) {
                if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -1;
                const struct nlmsgerr *error = NLMSG_DATA(message);
                if (error->error == 0) return dump ? -1 : 0;
                return error->error < 0 ? -error->error : -1;
            }
            if (callback != NULL && callback(message, context) != 0) return -1;
        }
        if (remaining != 0U) return -1;
    }
}

typedef void (*rtnl_dump_reset)(void *);

/* An interrupted dump is restarted after the caller discards its partial result. */
static int rtnl_dump(int fd, uint16_t type, int family,
    rtnl_message_callback callback, rtnl_dump_reset reset, void *context) {
    for (int attempt = 0; attempt < RTNL_DUMP_ATTEMPTS; ++attempt) {
        if (attempt != 0) reset(context);
        struct rtnl_request request;
        memset(&request, 0, sizeof(request));
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
        request.header.nlmsg_type = type;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.body.route.rtm_family = (unsigned char)family;
        int result = rtnl_transact(fd, &request.header, callback, context);
        if (result >= 0) return result;
    }
    return -1;
}

static void rtnl_output_reset(struct rtnl_output *output) {
    if (output == NULL) return;
    output->length = 0U;
    output->overflow = false;
}

static const char *rtnl_table_name(uint32_t table, char *buffer, size_t size) {
    if (table == RT_TABLE_DEFAULT) return "default";
    if (table == RT_TABLE_MAIN) return "main";
    if (table == RT_TABLE_LOCAL) return "local";
    (void)snprintf(buffer, size, "%" PRIu32, table);
    return buffer;
}

static void rtnl_render_address(struct rtnl_output *output, int family,
    const void *address, unsigned length, bool always_prefix) {
    char text[INET6_ADDRSTRLEN];
    if (inet_ntop(family, address, text, sizeof(text)) == NULL) {
        rtnl_printf(output, "x-address");
        return;
    }
    if (always_prefix || length != rtnl_address_bytes(family) * 8U) {
        rtnl_printf(output, "%s/%u", text, length);
    } else {
        rtnl_printf(output, "%s", text);
    }
}

/* Renders "PRIO:\tfrom all fwmark M/K lookup T" in iproute2 form. */
struct rtnl_rule_context {
    struct rtnl_output *output;
    int family;
};

static void rtnl_rule_reset(void *opaque) {
    rtnl_output_reset(((struct rtnl_rule_context *)opaque)->output);
}

static int rtnl_render_rule(const struct nlmsghdr *message, void *opaque) {
    struct rtnl_rule_context *context = opaque;
    struct rtnl_output *output = context->output;
    if (message->nlmsg_type != RTM_NEWRULE) return 0;
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct fib_rule_hdr))) return -1;
    const struct fib_rule_hdr *header = NLMSG_DATA(message);
    if (header->family != context->family) return 0;
    uint32_t priority = 0U;
    uint32_t table = header->table;
    bool has_mark = false;
    uint32_t mark = 0U;
    uint32_t mask = 0xffffffffU;
    const void *source = NULL;
    char extra[192U];
    size_t extra_length = 0U;
    extra[0] = '\0';
    int length = (int)(message->nlmsg_len - NLMSG_LENGTH(sizeof(*header)));
    for (const struct rtattr *attribute = (const struct rtattr *)((const unsigned char *)header +
                NLMSG_ALIGN(sizeof(*header)));
            RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length)) {
        size_t payload = RTA_PAYLOAD(attribute);
        const unsigned char *data = RTA_DATA(attribute);
        const char *name = NULL;
        switch (attribute->rta_type) {
            case FRA_PRIORITY:
                if (payload == 4U) memcpy(&priority, data, 4U);
                break;
            case FRA_TABLE:
                if (payload == 4U) memcpy(&table, data, 4U);
                break;
            case FRA_FWMARK:
                if (payload == 4U) memcpy(&mark, data, 4U);
                has_mark = true;
                break;
            case FRA_FWMASK:
                if (payload == 4U) memcpy(&mask, data, 4U);
                has_mark = true;
                break;
            case FRA_SRC:
                source = data;
                break;
            case FRA_PROTOCOL:
            case FRA_PAD:
                break;
            case FRA_SUPPRESS_PREFIXLEN:
            case FRA_SUPPRESS_IFGROUP: {
                // Kernels report these unconditionally; -1 means unset, as in iproute2.
                uint32_t value = 0U;
                if (payload == 4U) memcpy(&value, data, 4U);
                if (payload != 4U || value != UINT32_MAX) name = "suppress";
                break;
            }
            case FRA_IIFNAME: name = "iif"; break;
            case FRA_OIFNAME: name = "oif"; break;
            case FRA_DST: name = "to"; break;
            default: name = "attr"; break;
        }
        if (name != NULL && extra_length + 24U < sizeof(extra)) {
            int written = snprintf(extra + extra_length, sizeof(extra) - extra_length,
                "%s%s%u", extra_length == 0U ? "x-" : ",", name, attribute->rta_type);
            if (written > 0) extra_length += (size_t)written;
        }
    }
    rtnl_printf(output, "%" PRIu32 ":\t", priority);
    if ((header->flags & FIB_RULE_INVERT) != 0U) rtnl_printf(output, "not ");
    rtnl_printf(output, "from ");
    if (header->src_len != 0U && source != NULL) {
        rtnl_render_address(output, header->family, source, header->src_len, true);
    } else {
        rtnl_printf(output, "all");
    }
    if (header->tos != 0U || header->dst_len != 0U) {
        rtnl_printf(output, " %s", extra_length == 0U ? "x-selector" : "x-selector,");
    }
    if (has_mark) {
        if (mask != 0xffffffffU) rtnl_printf(output, " fwmark 0x%" PRIx32 "/0x%" PRIx32, mark, mask);
        else rtnl_printf(output, " fwmark 0x%" PRIx32, mark);
    }
    if (extra_length != 0U) rtnl_printf(output, " %s", extra);
    char table_text[16U];
    switch (header->action) {
        case FR_ACT_TO_TBL:
            rtnl_printf(output, " lookup %s", rtnl_table_name(table, table_text, sizeof(table_text)));
            break;
        case FR_ACT_GOTO: rtnl_printf(output, " goto"); break;
        case FR_ACT_NOP: rtnl_printf(output, " nop"); break;
        case FR_ACT_BLACKHOLE: rtnl_printf(output, " blackhole"); break;
        case FR_ACT_UNREACHABLE: rtnl_printf(output, " unreachable"); break;
        case FR_ACT_PROHIBIT: rtnl_printf(output, " prohibit"); break;
        default: rtnl_printf(output, " action%u", header->action); break;
    }
    rtnl_printf(output, "\n");
    return 0;
}

struct rtnl_route_filter {
    struct rtnl_output *output;
    int family;
    const uint32_t *tables;
    size_t table_count;
    struct rtnl_destination destination;
};

static bool rtnl_route_table_selected(const struct rtnl_route_filter *filter, uint32_t table) {
    if (filter->table_count == 0U) return true;
    for (size_t index = 0U; index < filter->table_count; ++index) {
        if (filter->tables[index] == table) return true;
    }
    return false;
}

static const char *rtnl_route_type_prefix(unsigned char type) {
    switch (type) {
        case RTN_UNICAST: return "";
        case RTN_LOCAL: return "local ";
        case RTN_BROADCAST: return "broadcast ";
        case RTN_ANYCAST: return "anycast ";
        case RTN_MULTICAST: return "multicast ";
        case RTN_BLACKHOLE: return "blackhole ";
        case RTN_UNREACHABLE: return "unreachable ";
        case RTN_PROHIBIT: return "prohibit ";
        case RTN_THROW: return "throw ";
        case RTN_NAT: return "nat ";
        default: return "x-type ";
    }
}

/* Parsed attributes of one route dump entry. */
struct rtnl_route_entry {
    const struct rtmsg *header;
    uint32_t table;
    const unsigned char *destination;
    const unsigned char *gateway;
    const unsigned char *preferred_source;
    bool has_oif;
    uint32_t oif;
    bool has_priority;
    uint32_t priority;
    bool has_preference;
    unsigned char preference;
    bool unknown;
};

static int rtnl_route_parse(const struct nlmsghdr *message, struct rtnl_route_entry *entry) {
    memset(entry, 0, sizeof(*entry));
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) return -1;
    const struct rtmsg *header = NLMSG_DATA(message);
    entry->header = header;
    entry->table = header->rtm_table;
    size_t address_length = rtnl_address_bytes(header->rtm_family);
    int length = (int)(message->nlmsg_len - NLMSG_LENGTH(sizeof(*header)));
    for (const struct rtattr *attribute = RTM_RTA(header); RTA_OK(attribute, length);
            attribute = RTA_NEXT(attribute, length)) {
        size_t payload = RTA_PAYLOAD(attribute);
        const unsigned char *data = RTA_DATA(attribute);
        switch (attribute->rta_type) {
            case RTA_TABLE:
                if (payload == 4U) memcpy(&entry->table, data, 4U);
                break;
            case RTA_DST:
                if (payload == address_length) entry->destination = data;
                else entry->unknown = true;
                break;
            case RTA_GATEWAY:
                if (payload == address_length) entry->gateway = data;
                else entry->unknown = true;
                break;
            case RTA_PREFSRC:
                if (payload == address_length) entry->preferred_source = data;
                else entry->unknown = true;
                break;
            case RTA_OIF:
                if (payload == 4U) {
                    memcpy(&entry->oif, data, 4U);
                    entry->has_oif = true;
                }
                break;
            case RTA_PRIORITY:
                if (payload == 4U) {
                    memcpy(&entry->priority, data, 4U);
                    entry->has_priority = true;
                }
                break;
            case RTA_PREF:
                if (payload == 1U) {
                    entry->preference = data[0];
                    entry->has_preference = true;
                }
                break;
            case RTA_CACHEINFO:
                break;
            case RTA_METRICS:
                // An empty metrics nest carries no route property.
                if (payload > 0U) entry->unknown = true;
                break;
            default:
                entry->unknown = true;
                break;
        }
    }
    return 0;
}

static bool rtnl_route_destination_matches(
    const struct rtnl_route_entry *entry, const struct rtnl_destination *destination) {
    if (!destination->present) return true;
    if (entry->header->rtm_dst_len != destination->length) return false;
    unsigned char observed[16U] = {0};
    size_t length = rtnl_address_bytes(entry->header->rtm_family);
    if (entry->destination != NULL) memcpy(observed, entry->destination, length);
    return memcmp(observed, destination->address, length) == 0;
}

static void rtnl_route_reset(void *opaque) {
    rtnl_output_reset(((struct rtnl_route_filter *)opaque)->output);
}

static int rtnl_render_route(const struct nlmsghdr *message, void *opaque) {
    struct rtnl_route_filter *filter = opaque;
    struct rtnl_output *output = filter->output;
    if (message->nlmsg_type != RTM_NEWROUTE) return 0;
    struct rtnl_route_entry entry;
    if (rtnl_route_parse(message, &entry) != 0) return -1;
    const struct rtmsg *header = entry.header;
    if (header->rtm_family != filter->family || (header->rtm_flags & RTM_F_CLONED) != 0U ||
        !rtnl_route_table_selected(filter, entry.table) ||
        !rtnl_route_destination_matches(&entry, &filter->destination)) return 0;
    rtnl_printf(output, "%s", rtnl_route_type_prefix(header->rtm_type));
    if (header->rtm_dst_len == 0U) {
        rtnl_printf(output, "default");
    } else if (entry.destination != NULL) {
        rtnl_render_address(output, header->rtm_family, entry.destination,
            header->rtm_dst_len, false);
    } else {
        rtnl_printf(output, "x-destination");
    }
    if (header->rtm_src_len != 0U) rtnl_printf(output, " x-source");
    if (entry.gateway != NULL) {
        rtnl_printf(output, " via ");
        rtnl_render_address(output, header->rtm_family, entry.gateway,
            (unsigned)rtnl_address_bytes(header->rtm_family) * 8U, false);
    }
    if (entry.has_oif) {
        char name[IF_NAMESIZE];
        if (if_indextoname(entry.oif, name) != NULL) rtnl_printf(output, " dev %s", name);
        else rtnl_printf(output, " dev if%" PRIu32, entry.oif);
    }
    rtnl_printf(output, " table %" PRIu32, entry.table);
    switch (header->rtm_protocol) {
        case RTPROT_BOOT: break;
        case RTPROT_KERNEL: rtnl_printf(output, " proto kernel"); break;
        case RTPROT_STATIC: rtnl_printf(output, " proto static"); break;
        default: rtnl_printf(output, " proto %u", header->rtm_protocol); break;
    }
    switch (header->rtm_scope) {
        case RT_SCOPE_UNIVERSE: break;
        case RT_SCOPE_LINK: rtnl_printf(output, " scope link"); break;
        case RT_SCOPE_HOST: rtnl_printf(output, " scope host"); break;
        default: rtnl_printf(output, " scope %u", header->rtm_scope); break;
    }
    if (entry.has_priority) rtnl_printf(output, " metric %" PRIu32, entry.priority);
    if (entry.preferred_source != NULL) {
        rtnl_printf(output, " src ");
        rtnl_render_address(output, header->rtm_family, entry.preferred_source,
            (unsigned)rtnl_address_bytes(header->rtm_family) * 8U, false);
    }
    if (entry.has_preference) {
        rtnl_printf(output, " pref %s", entry.preference == 0U ? "medium" :
            entry.preference == 1U ? "high" : entry.preference == 3U ? "low" : "x-pref");
    }
    if ((header->rtm_flags & RTNH_F_LINKDOWN) != 0U) rtnl_printf(output, " linkdown");
    if ((header->rtm_flags & RTNH_F_ONLINK) != 0U) rtnl_printf(output, " onlink");
    if ((header->rtm_flags & ~(unsigned)(RTNH_F_LINKDOWN | RTNH_F_ONLINK |
            RTM_F_NOTIFY)) != 0U || entry.unknown) rtnl_printf(output, " x-other");
    rtnl_printf(output, "\n");
    return 0;
}

static int rtnl_parse_destination(int family, const char *text,
    struct rtnl_destination *destination) {
    memset(destination, 0, sizeof(*destination));
    destination->present = true;
    if (strcmp(text, "default") == 0) return 0;
    char address[INET6_ADDRSTRLEN + 8U];
    if (snprintf(address, sizeof(address), "%s", text) >= (int)sizeof(address)) return -1;
    unsigned maximum = (unsigned)rtnl_address_bytes(family) * 8U;
    unsigned length = maximum;
    char *slash = strchr(address, '/');
    if (slash != NULL) {
        char *end = NULL;
        unsigned long parsed = strtoul(slash + 1, &end, 10);
        if (end == slash + 1 || *end != '\0' || parsed > maximum) return -1;
        length = (unsigned)parsed;
        *slash = '\0';
    }
    if (inet_pton(family, address, destination->address) != 1) return -1;
    destination->length = (unsigned char)length;
    return 0;
}

static int rtnl_parse_u32(const char *text, int base, uint32_t *value) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, base);
    if (text[0] == '\0' || end == text || *end != '\0' || errno != 0 ||
        parsed > UINT32_MAX) return -1;
    *value = (uint32_t)parsed;
    return 0;
}

static int rtnl_parse_mark(const char *text, uint32_t *mark, uint32_t *mask) {
    char buffer[32U];
    if (snprintf(buffer, sizeof(buffer), "%s", text) >= (int)sizeof(buffer)) return -1;
    char *slash = strchr(buffer, '/');
    *mask = 0xffffffffU;
    if (slash != NULL) {
        *slash = '\0';
        if (rtnl_parse_u32(slash + 1, 0, mask) != 0) return -1;
    }
    return rtnl_parse_u32(buffer, 0, mark);
}

/* rule add|del priority P [not from all] fwmark M/K table T */
static int rtnl_rule_change(int fd, int family, bool add,
    const char *const *arguments, size_t count) {
    size_t index = 0U;
    uint32_t priority = 0U;
    uint32_t mark = 0U;
    uint32_t mask = 0U;
    uint32_t table = 0U;
    bool invert = false;
    if (count < 6U || strcmp(arguments[index++], "priority") != 0 ||
        rtnl_parse_u32(arguments[index++], 10, &priority) != 0) return -1;
    if (index + 3U <= count && strcmp(arguments[index], "not") == 0) {
        if (strcmp(arguments[index + 1U], "from") != 0 ||
            strcmp(arguments[index + 2U], "all") != 0) return -1;
        invert = true;
        index += 3U;
    }
    if (index + 4U != count || strcmp(arguments[index++], "fwmark") != 0 ||
        rtnl_parse_mark(arguments[index++], &mark, &mask) != 0 ||
        strcmp(arguments[index++], "table") != 0 ||
        rtnl_parse_u32(arguments[index], 10, &table) != 0 || table == 0U) return -1;
    struct rtnl_request request;
    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
    request.header.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE : 0);
    request.body.rule.family = (unsigned char)family;
    request.body.rule.action = FR_ACT_TO_TBL;
    request.body.rule.table = table < 256U ? (unsigned char)table : RT_TABLE_UNSPEC;
    if (invert) request.body.rule.flags |= FIB_RULE_INVERT;
    if (rtnl_attribute_u32(&request, FRA_PRIORITY, priority) != 0 ||
        rtnl_attribute_u32(&request, FRA_FWMARK, mark) != 0 ||
        rtnl_attribute_u32(&request, FRA_FWMASK, mask) != 0 ||
        rtnl_attribute_u32(&request, FRA_TABLE, table) != 0) return -1;
    return rtnl_transact(fd, &request.header, NULL, NULL);
}

/* route add|del [local] DEST dev IF table T [src ADDRESS] */
static int rtnl_route_change(int fd, int family, bool add,
    const char *const *arguments, size_t count) {
    size_t index = 0U;
    bool local = false;
    if (index < count && strcmp(arguments[index], "local") == 0) {
        local = true;
        ++index;
    }
    struct rtnl_destination destination;
    uint32_t table = 0U;
    if (index + 5U > count ||
        rtnl_parse_destination(family, arguments[index++], &destination) != 0 ||
        strcmp(arguments[index++], "dev") != 0) return -1;
    unsigned interface_index = if_nametoindex(arguments[index++]);
    if (strcmp(arguments[index++], "table") != 0 ||
        rtnl_parse_u32(arguments[index++], 10, &table) != 0 || table == 0U) return -1;
    unsigned char source[16U];
    bool has_source = false;
    if (index + 2U == count && strcmp(arguments[index], "src") == 0) {
        if (inet_pton(family, arguments[index + 1U], source) != 1) return -1;
        has_source = true;
        index += 2U;
    }
    if (index != count) return -1;
    // A missing device is the same failure `ip` reports for an unknown name.
    if (interface_index == 0U) return ENODEV;
    struct rtnl_request request;
    memset(&request, 0, sizeof(request));
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.header.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
        (add ? NLM_F_CREATE | NLM_F_EXCL : 0);
    struct rtmsg *route = &request.body.route;
    route->rtm_family = (unsigned char)family;
    route->rtm_dst_len = destination.length;
    route->rtm_table = table < 256U ? (unsigned char)table : RT_TABLE_UNSPEC;
    // Mirrors iproute2: additions are boot-protocol routes; deletions match any scope.
    if (add) {
        route->rtm_protocol = RTPROT_BOOT;
        route->rtm_type = local ? RTN_LOCAL : RTN_UNICAST;
        route->rtm_scope = local ? RT_SCOPE_HOST : RT_SCOPE_LINK;
    } else {
        route->rtm_scope = RT_SCOPE_NOWHERE;
        route->rtm_type = local ? RTN_LOCAL : RTN_UNSPEC;
    }
    if ((destination.length != 0U && rtnl_attribute_add(&request, RTA_DST,
            destination.address, rtnl_address_bytes(family)) != 0) ||
        rtnl_attribute_u32(&request, RTA_OIF, interface_index) != 0 ||
        rtnl_attribute_u32(&request, RTA_TABLE, table) != 0 ||
        (has_source && rtnl_attribute_add(&request, RTA_PREFSRC,
            source, rtnl_address_bytes(family)) != 0)) return -1;
    return rtnl_transact(fd, &request.header, NULL, NULL);
}

/* Collects the routes of one table so they can be deleted after the dump. */
struct rtnl_flush_context {
    int family;
    uint32_t table;
    unsigned char *messages;
    size_t length;
    size_t capacity;
    bool failed;
};

static int rtnl_collect_route(const struct nlmsghdr *message, void *opaque) {
    struct rtnl_flush_context *context = opaque;
    if (message->nlmsg_type != RTM_NEWROUTE) return 0;
    struct rtnl_route_entry entry;
    if (rtnl_route_parse(message, &entry) != 0) return -1;
    if (entry.header->rtm_family != context->family || entry.table != context->table ||
        (entry.header->rtm_flags & RTM_F_CLONED) != 0U) return 0;
    size_t length = NLMSG_ALIGN(message->nlmsg_len);
    if (context->length + length > context->capacity) {
        size_t capacity = context->capacity == 0U ? 4096U : context->capacity * 2U;
        while (capacity < context->length + length) capacity *= 2U;
        unsigned char *messages = realloc(context->messages, capacity);
        if (messages == NULL) return -1;
        context->messages = messages;
        context->capacity = capacity;
    }
    memcpy(context->messages + context->length, message, message->nlmsg_len);
    context->length += length;
    return 0;
}

static void rtnl_flush_reset(void *opaque) {
    ((struct rtnl_flush_context *)opaque)->length = 0U;
}

static int rtnl_route_flush(int fd, int family, uint32_t table) {
    struct rtnl_flush_context context = {.family = family, .table = table};
    int result = rtnl_dump(fd, RTM_GETROUTE, family, rtnl_collect_route,
        rtnl_flush_reset, &context);
    size_t offset = 0U;
    while (result == 0 && offset < context.length) {
        struct nlmsghdr *message = (struct nlmsghdr *)(context.messages + offset);
        offset += NLMSG_ALIGN(message->nlmsg_len);
        message->nlmsg_type = RTM_DELROUTE;
        message->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        result = rtnl_transact(fd, message, NULL, NULL);
        if (result == ESRCH) result = 0;
    }
    free(context.messages);
    return result;
}

static void rtnl_record_error(struct asteriskd_system_supervisor *system, int error) {
    int written = snprintf(system->action_stderr, sizeof(system->action_stderr),
        "RTNETLINK answers: %s", strerror(error));
    system->action_stderr_length = written > 0 && (size_t)written < sizeof(system->action_stderr)
        ? (size_t)written : 0U;
}

int asteriskd_supervisor_rtnl_ip(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *arguments,
    size_t argument_count, bool capture, int *exit_status) {
    int address_family = rtnl_address_family(family);
    if (system == NULL || exit_status == NULL || address_family == AF_UNSPEC ||
        argument_count < 2U || arguments == NULL) return -1;
    for (size_t index = 0U; index < argument_count; ++index) {
        if (arguments[index] == NULL || arguments[index][0] == '\0') return -1;
    }
    struct rtnl_output output = {
        .bytes = system->action_stdout,
        .capacity = sizeof(system->action_stdout),
    };
    system->action_stdout_length = 0U;
    system->action_stdout_overflow = false;
    system->action_stderr_length = 0U;
    int fd = rtnl_open();
    if (fd < 0) return -1;
    const char *object = arguments[0];
    const char *verb = arguments[1];
    int result = -1;
    struct rtnl_output *output_pointer = capture ? &output : NULL;
    if (strcmp(object, "rule") == 0 && strcmp(verb, "show") == 0 && argument_count == 2U) {
        struct rtnl_rule_context context = {.output = output_pointer, .family = address_family};
        if (output_pointer != NULL) {
            result = rtnl_dump(fd, RTM_GETRULE, address_family, rtnl_render_rule,
                rtnl_rule_reset, &context);
        } else {
            result = 0;
        }
    } else if (strcmp(object, "rule") == 0 &&
        (strcmp(verb, "add") == 0 || strcmp(verb, "del") == 0)) {
        result = rtnl_rule_change(fd, address_family, strcmp(verb, "add") == 0,
            arguments + 2U, argument_count - 2U);
    } else if (strcmp(object, "route") == 0 && strcmp(verb, "show") == 0 &&
        (argument_count == 4U || argument_count == 5U) &&
        strcmp(arguments[2], "table") == 0) {
        uint32_t table = 0U;
        struct rtnl_route_filter filter = {
            .output = output_pointer, .family = address_family,
        };
        if (strcmp(arguments[3], "all") != 0) {
            if (rtnl_parse_u32(arguments[3], 10, &table) != 0) goto done;
            filter.tables = &table;
            filter.table_count = 1U;
        }
        if (argument_count == 5U &&
            rtnl_parse_destination(address_family, arguments[4], &filter.destination) != 0) goto done;
        result = output_pointer == NULL ? 0 :
            rtnl_dump(fd, RTM_GETROUTE, address_family, rtnl_render_route,
                rtnl_route_reset, &filter);
    } else if (strcmp(object, "route") == 0 &&
        (strcmp(verb, "add") == 0 || strcmp(verb, "del") == 0)) {
        result = rtnl_route_change(fd, address_family, strcmp(verb, "add") == 0,
            arguments + 2U, argument_count - 2U);
    } else if (strcmp(object, "route") == 0 && strcmp(verb, "flush") == 0 &&
        argument_count == 4U && strcmp(arguments[2], "table") == 0) {
        uint32_t table = 0U;
        if (rtnl_parse_u32(arguments[3], 10, &table) == 0 && table != 0U) {
            result = rtnl_route_flush(fd, address_family, table);
        }
    }
done:
    (void)close(fd);
    if (result < 0) return -1;
    if (capture) {
        system->action_stdout_length = output.length;
        system->action_stdout_overflow = output.overflow;
    }
    if (result > 0) rtnl_record_error(system, result);
    // `ip` exits with 2 when the kernel rejects a request.
    *exit_status = result == 0 ? 0 : 2;
    return 0;
}

int asteriskd_supervisor_rtnl_route_render(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const uint32_t *tables, size_t table_count) {
    int address_family = rtnl_address_family(family);
    if (system == NULL || address_family == AF_UNSPEC ||
        (table_count != 0U && tables == NULL)) return -1;
    struct rtnl_output output = {
        .bytes = system->action_stdout,
        .capacity = sizeof(system->action_stdout),
    };
    struct rtnl_route_filter filter = {
        .output = &output, .family = address_family,
        .tables = tables, .table_count = table_count,
    };
    int fd = rtnl_open();
    if (fd < 0) return -1;
    int result = rtnl_dump(fd, RTM_GETROUTE, address_family, rtnl_render_route,
        rtnl_route_reset, &filter);
    (void)close(fd);
    system->action_stdout_length = output.length;
    system->action_stdout_overflow = output.overflow;
    return result == 0 && !output.overflow ? 0 : -1;
}

struct rtnl_offload_filter {
    uint32_t interface_index;
    uint32_t info;
    bool present;
};

/* Flags an ingress IPv6 filter at the queried priority whose bpf program is a tether offload. */
static int rtnl_match_offload_filter(const struct nlmsghdr *message, void *opaque) {
    struct rtnl_offload_filter *filter = opaque;
    if (message->nlmsg_type != RTM_NEWTFILTER) return 0;
    if (message->nlmsg_len < NLMSG_LENGTH(sizeof(struct tcmsg))) return -1;
    const struct tcmsg *header = NLMSG_DATA(message);
    if (header->tcm_ifindex != (int)filter->interface_index ||
        header->tcm_parent != ASTERISKD_TC_PARENT_CLSACT_INGRESS ||
        header->tcm_info != filter->info) return 0;
    int length = (int)message->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*header));
    for (const struct rtattr *attribute = (const struct rtattr *)((const unsigned char *)header +
                NLMSG_ALIGN(sizeof(*header)));
            RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length)) {
        if (attribute->rta_type != TCA_OPTIONS) continue;
        int nested_length = (int)RTA_PAYLOAD(attribute);
        for (const struct rtattr *option = RTA_DATA(attribute); RTA_OK(option, nested_length);
                option = RTA_NEXT(option, nested_length)) {
            if (option->rta_type == TCA_BPF_NAME &&
                asteriskd_hotspot_tc_output_has_android_offload(
                    RTA_DATA(option), RTA_PAYLOAD(option))) filter->present = true;
        }
    }
    return 0;
}

static void rtnl_offload_reset(void *opaque) {
    ((struct rtnl_offload_filter *)opaque)->present = false;
}

/*
 * In-process replacement for the hotspot offload "tc filter show/del dev <if>
 * ingress protocol ipv6 pref <n>" pair: reports whether that ingress filter
 * runs an Android tether offload program and, when asked, deletes the whole
 * priority as tc would.
 */
int asteriskd_supervisor_rtnl_tether_offload(struct asteriskd_system_supervisor *system,
    uint32_t interface_index, uint32_t priority, bool remove, bool *present) {
    if (system == NULL || interface_index == 0U || priority == 0U ||
        priority > UINT16_MAX || present == NULL) return -1;
    struct rtnl_offload_filter filter = {
        .interface_index = interface_index,
        .info = TC_H_MAKE(priority << 16U, htons(ETH_P_IPV6)),
    };
    int fd = rtnl_open();
    if (fd < 0) return -1;
    int result = -1;
    for (int attempt = 0; attempt < RTNL_DUMP_ATTEMPTS && result < 0; ++attempt) {
        rtnl_offload_reset(&filter);
        struct rtnl_request request;
        memset(&request, 0, sizeof(request));
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
        request.header.nlmsg_type = RTM_GETTFILTER;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.body.filter.tcm_family = AF_UNSPEC;
        request.body.filter.tcm_ifindex = (int)interface_index;
        request.body.filter.tcm_parent = ASTERISKD_TC_PARENT_CLSACT_INGRESS;
        request.body.filter.tcm_info = filter.info;
        result = rtnl_transact(fd, &request.header, rtnl_match_offload_filter, &filter);
    }
    if (result == 0 && filter.present && remove) {
        struct rtnl_request request;
        memset(&request, 0, sizeof(request));
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
        request.header.nlmsg_type = RTM_DELTFILTER;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        request.body.filter.tcm_family = AF_UNSPEC;
        request.body.filter.tcm_ifindex = (int)interface_index;
        request.body.filter.tcm_parent = ASTERISKD_TC_PARENT_CLSACT_INGRESS;
        request.body.filter.tcm_info = filter.info;
        result = rtnl_transact(fd, &request.header, NULL, NULL);
    }
    (void)close(fd);
    if (result > 0) rtnl_record_error(system, result);
    *present = filter.present;
    return result == 0 ? 0 : -1;
}

#endif

// Copyright 2026, AsteriskAPP contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#if defined(__linux__) || defined(__ANDROID__)
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define WIFI_NETLINK_BUFFER_SIZE 65536U
#define WIFI_MAX_STATION_INTERFACES 16U
#define WIFI_DEBOUNCE_MILLISECONDS 350U
#define WIFI_NLA_ALIGNTO 4U
#define WIFI_NLA_ALIGN(length) (((length) + WIFI_NLA_ALIGNTO - 1U) & ~(WIFI_NLA_ALIGNTO - 1U))
#define WIFI_NLA_HEADER_LENGTH WIFI_NLA_ALIGN(sizeof(struct nlattr))

static void wifi_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size > 0U) (void)snprintf(error, error_size, "%s", message);
}

static bool wifi_attr_valid(const struct nlattr *attribute, size_t remaining) {
    return remaining >= sizeof(*attribute) && attribute->nla_len >= sizeof(*attribute) &&
        attribute->nla_len <= remaining;
}

static const void *wifi_attr_data(const struct nlattr *attribute) {
    return (const unsigned char *)attribute + WIFI_NLA_HEADER_LENGTH;
}

static size_t wifi_attr_data_length(const struct nlattr *attribute) {
    return attribute->nla_len - WIFI_NLA_HEADER_LENGTH;
}

static const struct nlattr *wifi_attr_next(const struct nlattr *attribute, size_t *remaining) {
    size_t consumed = WIFI_NLA_ALIGN(attribute->nla_len);
    if (consumed > *remaining) {
        *remaining = 0U;
        return NULL;
    }
    *remaining -= consumed;
    return (const struct nlattr *)((const unsigned char *)attribute + consumed);
}

static int wifi_open_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) return -1;
    struct sockaddr_nl address;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        (void)close(fd);
        return -1;
    }
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static int wifi_send_bytes(int fd, const void *bytes, size_t length) {
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    ssize_t sent;
    do {
        sent = sendto(fd, bytes, length, 0,
            (const struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)length ? 0 : -1;
}

static int wifi_send_family_request(int fd, uint32_t sequence) {
    unsigned char bytes[256U];
    memset(bytes, 0, sizeof(bytes));
    struct nlmsghdr *header = (struct nlmsghdr *)bytes;
    struct genlmsghdr *generic = (struct genlmsghdr *)(bytes + NLMSG_HDRLEN);
    header->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
    header->nlmsg_type = GENL_ID_CTRL;
    header->nlmsg_flags = NLM_F_REQUEST;
    header->nlmsg_seq = sequence;
    generic->cmd = CTRL_CMD_GETFAMILY;
    generic->version = 1U;
    struct nlattr *attribute = (struct nlattr *)(bytes + header->nlmsg_len);
    static const char family[] = "nl80211";
    attribute->nla_type = CTRL_ATTR_FAMILY_NAME;
    attribute->nla_len = (uint16_t)(WIFI_NLA_HEADER_LENGTH + sizeof(family));
    memcpy((unsigned char *)attribute + WIFI_NLA_HEADER_LENGTH, family, sizeof(family));
    header->nlmsg_len += (uint32_t)WIFI_NLA_ALIGN(attribute->nla_len);
    return wifi_send_bytes(fd, bytes, header->nlmsg_len);
}

static int wifi_parse_multicast_group(const struct nlattr *groups, uint32_t *group_id) {
    size_t remaining = wifi_attr_data_length(groups);
    const struct nlattr *group = wifi_attr_data(groups);
    while (wifi_attr_valid(group, remaining)) {
        const unsigned char *name = NULL;
        size_t name_length = 0U;
        uint32_t identifier = 0U;
        size_t nested_remaining = wifi_attr_data_length(group);
        const struct nlattr *entry = wifi_attr_data(group);
        while (wifi_attr_valid(entry, nested_remaining)) {
            uint16_t type = entry->nla_type & NLA_TYPE_MASK;
            if (type == CTRL_ATTR_MCAST_GRP_NAME) {
                name = wifi_attr_data(entry);
                name_length = wifi_attr_data_length(entry);
            } else if (type == CTRL_ATTR_MCAST_GRP_ID &&
                wifi_attr_data_length(entry) == sizeof(identifier)) {
                memcpy(&identifier, wifi_attr_data(entry), sizeof(identifier));
            }
            entry = wifi_attr_next(entry, &nested_remaining);
        }
        static const char mlme[] = "mlme";
        if (name != NULL && name_length == sizeof(mlme) &&
            memcmp(name, mlme, sizeof(mlme)) == 0 && identifier != 0U) {
            *group_id = identifier;
            return 0;
        }
        group = wifi_attr_next(group, &remaining);
    }
    return -1;
}

static int wifi_receive_family(int fd, uint32_t sequence, uint16_t *family_id, uint32_t *group_id) {
    unsigned char bytes[WIFI_NETLINK_BUFFER_SIZE];
    for (;;) {
        ssize_t count;
        do {
            count = recv(fd, bytes, sizeof(bytes), 0);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) return -1;
        size_t remaining = (size_t)count;
        for (struct nlmsghdr *header = (struct nlmsghdr *)bytes;
                NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence) continue;
            if (header->nlmsg_type == NLMSG_ERROR) return -1;
            if (header->nlmsg_type != GENL_ID_CTRL ||
                header->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) continue;
            size_t attribute_bytes = header->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
            const struct genlmsghdr *generic = NLMSG_DATA(header);
            const struct nlattr *attribute = (const struct nlattr *)
                ((const unsigned char *)generic + GENL_HDRLEN);
            while (wifi_attr_valid(attribute, attribute_bytes)) {
                uint16_t type = attribute->nla_type & NLA_TYPE_MASK;
                if (type == CTRL_ATTR_FAMILY_ID &&
                    wifi_attr_data_length(attribute) == sizeof(*family_id)) {
                    memcpy(family_id, wifi_attr_data(attribute), sizeof(*family_id));
                } else if (type == CTRL_ATTR_MCAST_GROUPS) {
                    (void)wifi_parse_multicast_group(attribute, group_id);
                }
                attribute = wifi_attr_next(attribute, &attribute_bytes);
            }
            if (*family_id != 0U && *group_id != 0U) return 0;
        }
    }
}

static int wifi_send_command(int fd, uint16_t family_id, uint8_t command,
    uint16_t flags, uint32_t sequence, uint32_t interface_index) {
    unsigned char bytes[256U];
    memset(bytes, 0, sizeof(bytes));
    struct nlmsghdr *header = (struct nlmsghdr *)bytes;
    struct genlmsghdr *generic = (struct genlmsghdr *)(bytes + NLMSG_HDRLEN);
    header->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
    header->nlmsg_type = family_id;
    header->nlmsg_flags = NLM_F_REQUEST | flags;
    header->nlmsg_seq = sequence;
    generic->cmd = command;
    generic->version = 1U;
    if (interface_index != 0U) {
        struct nlattr *attribute = (struct nlattr *)(bytes + header->nlmsg_len);
        attribute->nla_type = NL80211_ATTR_IFINDEX;
        attribute->nla_len = (uint16_t)(WIFI_NLA_HEADER_LENGTH + sizeof(interface_index));
        memcpy((unsigned char *)attribute + WIFI_NLA_HEADER_LENGTH,
            &interface_index, sizeof(interface_index));
        header->nlmsg_len += (uint32_t)WIFI_NLA_ALIGN(attribute->nla_len);
    }
    return wifi_send_bytes(fd, bytes, header->nlmsg_len);
}

static int wifi_receive_interfaces(int fd, uint16_t family_id, uint32_t sequence,
    uint32_t *interfaces, size_t *interface_count) {
    unsigned char bytes[WIFI_NETLINK_BUFFER_SIZE];
    for (;;) {
        ssize_t count;
        do {
            count = recv(fd, bytes, sizeof(bytes), 0);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) return -1;
        size_t remaining = (size_t)count;
        for (struct nlmsghdr *header = (struct nlmsghdr *)bytes;
                NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence) continue;
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *failure = NLMSG_DATA(header);
                return failure->error == 0 ? 0 : -1;
            }
            if (header->nlmsg_type != family_id ||
                header->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) continue;
            uint32_t interface_index = 0U;
            uint32_t interface_type = UINT32_MAX;
            const struct genlmsghdr *generic = NLMSG_DATA(header);
            size_t attribute_bytes = header->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
            const struct nlattr *attribute = (const struct nlattr *)
                ((const unsigned char *)generic + GENL_HDRLEN);
            while (wifi_attr_valid(attribute, attribute_bytes)) {
                uint16_t type = attribute->nla_type & NLA_TYPE_MASK;
                if (type == NL80211_ATTR_IFINDEX &&
                    wifi_attr_data_length(attribute) == sizeof(interface_index)) {
                    memcpy(&interface_index, wifi_attr_data(attribute), sizeof(interface_index));
                } else if (type == NL80211_ATTR_IFTYPE &&
                    wifi_attr_data_length(attribute) == sizeof(interface_type)) {
                    memcpy(&interface_type, wifi_attr_data(attribute), sizeof(interface_type));
                }
                attribute = wifi_attr_next(attribute, &attribute_bytes);
            }
            if (interface_index != 0U &&
                (interface_type == NL80211_IFTYPE_STATION ||
                    interface_type == NL80211_IFTYPE_P2P_CLIENT) &&
                *interface_count < WIFI_MAX_STATION_INTERFACES) {
                interfaces[(*interface_count)++] = interface_index;
            }
        }
    }
}

static void wifi_identity_parse_information_elements(
    const unsigned char *bytes, size_t length, struct asteriskd_wifi_identity *identity) {
    size_t offset = 0U;
    while (offset + 2U <= length) {
        uint8_t identifier = bytes[offset];
        size_t value_length = bytes[offset + 1U];
        offset += 2U;
        if (value_length > length - offset) return;
        if (identifier == 0U && value_length > 0U &&
            value_length <= ASTERISKD_MAX_WIFI_SSID_BYTES) {
            memcpy(identity->ssid, bytes + offset, value_length);
            identity->ssid_length = value_length;
            identity->has_ssid = true;
            return;
        }
        offset += value_length;
    }
}

static bool wifi_parse_associated_bss(
    const struct nlattr *bss, struct asteriskd_wifi_identity *identity) {
    struct asteriskd_wifi_identity candidate;
    memset(&candidate, 0, sizeof(candidate));
    uint32_t status = UINT32_MAX;
    const unsigned char *information_elements = NULL;
    size_t information_elements_length = 0U;
    size_t remaining = wifi_attr_data_length(bss);
    const struct nlattr *entry = wifi_attr_data(bss);
    while (wifi_attr_valid(entry, remaining)) {
        uint16_t type = entry->nla_type & NLA_TYPE_MASK;
        size_t length = wifi_attr_data_length(entry);
        if (type == NL80211_BSS_STATUS && length == sizeof(status)) {
            memcpy(&status, wifi_attr_data(entry), sizeof(status));
        } else if (type == NL80211_BSS_BSSID && length == sizeof(candidate.bssid)) {
            memcpy(candidate.bssid, wifi_attr_data(entry), sizeof(candidate.bssid));
            candidate.has_bssid = true;
        } else if (type == NL80211_BSS_INFORMATION_ELEMENTS ||
            type == NL80211_BSS_BEACON_IES) {
            information_elements = wifi_attr_data(entry);
            information_elements_length = length;
        }
        entry = wifi_attr_next(entry, &remaining);
    }
    if (status != NL80211_BSS_STATUS_ASSOCIATED &&
        status != NL80211_BSS_STATUS_IBSS_JOINED) return false;
    if (information_elements != NULL) {
        wifi_identity_parse_information_elements(
            information_elements, information_elements_length, &candidate);
    }
    *identity = candidate;
    return true;
}

static int wifi_receive_scan(int fd, uint16_t family_id, uint32_t sequence,
    bool *connected, struct asteriskd_wifi_identity *identity) {
    unsigned char bytes[WIFI_NETLINK_BUFFER_SIZE];
    for (;;) {
        ssize_t count;
        do {
            count = recv(fd, bytes, sizeof(bytes), 0);
        } while (count < 0 && errno == EINTR);
        if (count <= 0) return -1;
        size_t remaining = (size_t)count;
        for (struct nlmsghdr *header = (struct nlmsghdr *)bytes;
                NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence) continue;
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *failure = NLMSG_DATA(header);
                return failure->error == 0 ? 0 : -1;
            }
            if (header->nlmsg_type != family_id ||
                header->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN) continue;
            const struct genlmsghdr *generic = NLMSG_DATA(header);
            size_t attribute_bytes = header->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
            const struct nlattr *attribute = (const struct nlattr *)
                ((const unsigned char *)generic + GENL_HDRLEN);
            while (wifi_attr_valid(attribute, attribute_bytes)) {
                if ((attribute->nla_type & NLA_TYPE_MASK) == NL80211_ATTR_BSS &&
                    wifi_parse_associated_bss(attribute, identity)) {
                    *connected = true;
                }
                attribute = wifi_attr_next(attribute, &attribute_bytes);
            }
        }
    }
}

static int wifi_query_association(uint16_t family_id, bool *connected,
    struct asteriskd_wifi_identity *identity) {
    if (connected == NULL || identity == NULL) return -1;
    *connected = false;
    memset(identity, 0, sizeof(*identity));
    int fd = wifi_open_socket();
    if (fd < 0) return -1;
    uint32_t sequence = 1U;
    uint32_t interfaces[WIFI_MAX_STATION_INTERFACES];
    size_t interface_count = 0U;
    int result = wifi_send_command(fd, family_id, NL80211_CMD_GET_INTERFACE,
        NLM_F_DUMP, sequence, 0U);
    if (result == 0) {
        result = wifi_receive_interfaces(
            fd, family_id, sequence, interfaces, &interface_count);
    }
    for (size_t index = 0U; result == 0 && index < interface_count && !*connected; ++index) {
        ++sequence;
        result = wifi_send_command(fd, family_id, NL80211_CMD_GET_SCAN,
            NLM_F_DUMP, sequence, interfaces[index]);
        if (result == 0) {
            result = wifi_receive_scan(fd, family_id, sequence, connected, identity);
        }
    }
    (void)close(fd);
    return result;
}

static bool wifi_identity_equal(const struct asteriskd_wifi_identity *left,
    const struct asteriskd_wifi_identity *right) {
    if (left->has_ssid != right->has_ssid || left->has_bssid != right->has_bssid) return false;
    if (left->has_ssid && (left->ssid_length != right->ssid_length ||
        memcmp(left->ssid, right->ssid, left->ssid_length) != 0)) return false;
    return !left->has_bssid || memcmp(left->bssid, right->bssid, sizeof(left->bssid)) == 0;
}

static int wifi_monotonic_milliseconds(uint64_t *value) {
    struct timespec now;
    if (value == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0) return -1;
    uint64_t seconds = (uint64_t)now.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)(now.tv_nsec / 1000000L)) / 1000U) return -1;
    *value = seconds * 1000U + (uint64_t)(now.tv_nsec / 1000000L);
    return 0;
}

int asteriskd_wifi_monitor_open(
    struct asteriskd_wifi_monitor *monitor, char *error, size_t error_size) {
    if (monitor == NULL) return -1;
    memset(monitor, 0, sizeof(*monitor));
    monitor->fd = -1;
    int fd = wifi_open_socket();
    if (fd < 0) {
        wifi_error(error, error_size, "nl80211 socket unavailable");
        return -1;
    }
    uint32_t sequence = 1U;
    uint16_t family_id = 0U;
    uint32_t group_id = 0U;
    if (wifi_send_family_request(fd, sequence) != 0 ||
        wifi_receive_family(fd, sequence, &family_id, &group_id) != 0 ||
        setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
            &group_id, sizeof(group_id)) != 0) {
        (void)close(fd);
        wifi_error(error, error_size, "nl80211 MLME subscription failed");
        return -1;
    }
    if (wifi_query_association(family_id,
            &monitor->baseline_connected, &monitor->baseline_identity) != 0) {
        (void)close(fd);
        wifi_error(error, error_size, "nl80211 association baseline failed");
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)close(fd);
        wifi_error(error, error_size, "nl80211 nonblocking setup failed");
        return -1;
    }
    monitor->fd = fd;
    monitor->family_id = family_id;
    monitor->sequence = sequence;
    monitor->opened = true;
    return 0;
}

int asteriskd_wifi_monitor_fd(const struct asteriskd_wifi_monitor *monitor) {
    return monitor != NULL && monitor->opened ? monitor->fd : -1;
}

int asteriskd_wifi_monitor_baseline(const struct asteriskd_wifi_monitor *monitor,
    enum asteriskd_wifi_transition *transition, struct asteriskd_wifi_identity *identity) {
    if (monitor == NULL || !monitor->opened || transition == NULL || identity == NULL) return -1;
    *transition = monitor->baseline_connected
        ? ASTERISKD_WIFI_TRANSITION_BASELINE_CONNECTED
        : ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED;
    *identity = monitor->baseline_identity;
    return 0;
}

static bool wifi_command_is_relevant(uint8_t command) {
    return command == NL80211_CMD_CONNECT || command == NL80211_CMD_ASSOCIATE ||
        command == NL80211_CMD_ROAM || command == NL80211_CMD_DISCONNECT ||
        command == NL80211_CMD_DEAUTHENTICATE || command == NL80211_CMD_DISASSOCIATE;
}

static int wifi_arm_debounce(struct asteriskd_wifi_monitor *monitor, bool integrity_lost) {
    uint64_t now = 0U;
    if (wifi_monotonic_milliseconds(&now) != 0 ||
        now > UINT64_MAX - WIFI_DEBOUNCE_MILLISECONDS) return -1;
    monitor->debounce_deadline_milliseconds = now + WIFI_DEBOUNCE_MILLISECONDS;
    monitor->debounce_armed = true;
    monitor->integrity_lost = monitor->integrity_lost || integrity_lost;
    return 0;
}

int asteriskd_wifi_monitor_handle(struct asteriskd_wifi_monitor *monitor,
    enum asteriskd_wifi_transition *transition, struct asteriskd_wifi_identity *identity,
    bool *has_transition, char *error, size_t error_size) {
    if (has_transition != NULL) *has_transition = false;
    if (monitor == NULL || !monitor->opened || transition == NULL || identity == NULL ||
        has_transition == NULL) return -1;
    unsigned char bytes[WIFI_NETLINK_BUFFER_SIZE];
    bool relevant = false;
    bool integrity_lost = false;
    for (;;) {
        struct iovec vector = { .iov_base = bytes, .iov_len = sizeof(bytes) };
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &vector;
        message.msg_iovlen = 1U;
        ssize_t count = recvmsg(monitor->fd, &message, MSG_DONTWAIT);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (count < 0 && errno == ENOBUFS) {
            relevant = true;
            integrity_lost = true;
            break;
        }
        if (count < 0) {
            wifi_error(error, error_size, "nl80211 receive failed");
            return -1;
        }
        if (count == 0) break;
        if ((message.msg_flags & MSG_TRUNC) != 0) {
            relevant = true;
            integrity_lost = true;
            continue;
        }
        size_t remaining = (size_t)count;
        for (struct nlmsghdr *header = (struct nlmsghdr *)bytes;
                NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_OVERRUN) {
                relevant = true;
                integrity_lost = true;
            } else if (header->nlmsg_type == monitor->family_id &&
                header->nlmsg_len >= NLMSG_HDRLEN + GENL_HDRLEN) {
                const struct genlmsghdr *generic = NLMSG_DATA(header);
                relevant = relevant || wifi_command_is_relevant(generic->cmd);
            }
        }
    }
    if (relevant && wifi_arm_debounce(monitor, integrity_lost) != 0) {
        wifi_error(error, error_size, "nl80211 debounce clock failed");
        return -1;
    }
    return 0;
}

bool asteriskd_wifi_monitor_next_deadline(
    const struct asteriskd_wifi_monitor *monitor, uint64_t *deadline) {
    if (monitor == NULL || !monitor->opened || !monitor->debounce_armed || deadline == NULL) {
        return false;
    }
    *deadline = monitor->debounce_deadline_milliseconds;
    return true;
}

int asteriskd_wifi_monitor_take_reconcile(struct asteriskd_wifi_monitor *monitor,
    uint64_t now, enum asteriskd_wifi_transition *transition,
    struct asteriskd_wifi_identity *identity, bool *has_transition,
    char *error, size_t error_size) {
    if (has_transition != NULL) *has_transition = false;
    if (monitor == NULL || !monitor->opened || transition == NULL || identity == NULL ||
        has_transition == NULL) return -1;
    if (!monitor->debounce_armed || now < monitor->debounce_deadline_milliseconds) return 0;
    bool connected = false;
    struct asteriskd_wifi_identity current;
    if (wifi_query_association(monitor->family_id, &connected, &current) != 0) {
        wifi_error(error, error_size, "nl80211 association reconcile failed");
        return -1;
    }
    bool lost = monitor->integrity_lost;
    monitor->debounce_armed = false;
    monitor->integrity_lost = false;
    if (lost) {
        monitor->baseline_connected = connected;
        monitor->baseline_identity = current;
        *transition = connected
            ? ASTERISKD_WIFI_TRANSITION_BASELINE_CONNECTED
            : ASTERISKD_WIFI_TRANSITION_BASELINE_DISCONNECTED;
        *identity = current;
        *has_transition = true;
        return 0;
    }
    if (!monitor->baseline_connected && connected) {
        *transition = ASTERISKD_WIFI_TRANSITION_CONNECTED;
        *identity = current;
        *has_transition = true;
    } else if (monitor->baseline_connected && !connected) {
        *transition = ASTERISKD_WIFI_TRANSITION_DISCONNECTED;
        *identity = monitor->baseline_identity;
        *has_transition = true;
    } else if (monitor->baseline_connected && connected &&
        !wifi_identity_equal(&monitor->baseline_identity, &current)) {
        *transition = ASTERISKD_WIFI_TRANSITION_ROAMED;
        *identity = current;
        *has_transition = true;
    }
    monitor->baseline_connected = connected;
    monitor->baseline_identity = current;
    return 0;
}

void asteriskd_wifi_monitor_close(struct asteriskd_wifi_monitor *monitor) {
    if (monitor == NULL) return;
    if (monitor->opened && monitor->fd >= 0) (void)close(monitor->fd);
    memset(monitor, 0, sizeof(*monitor));
    monitor->fd = -1;
}

#else
int asteriskd_wifi_monitor_open(
    struct asteriskd_wifi_monitor *monitor, char *error, size_t error_size) {
    if (monitor != NULL) {
        memset(monitor, 0, sizeof(*monitor));
        monitor->fd = -1;
    }
    if (error != NULL && error_size > 0U) (void)snprintf(error, error_size, "%s", "unsupported");
    return -1;
}
int asteriskd_wifi_monitor_fd(const struct asteriskd_wifi_monitor *monitor) {
    (void)monitor;
    return -1;
}
int asteriskd_wifi_monitor_baseline(const struct asteriskd_wifi_monitor *monitor,
    enum asteriskd_wifi_transition *transition, struct asteriskd_wifi_identity *identity) {
    (void)monitor;
    (void)transition;
    (void)identity;
    return -1;
}
int asteriskd_wifi_monitor_handle(struct asteriskd_wifi_monitor *monitor,
    enum asteriskd_wifi_transition *transition, struct asteriskd_wifi_identity *identity,
    bool *has_transition, char *error, size_t error_size) {
    (void)monitor;
    (void)transition;
    (void)identity;
    (void)error;
    (void)error_size;
    if (has_transition != NULL) *has_transition = false;
    return -1;
}
bool asteriskd_wifi_monitor_next_deadline(
    const struct asteriskd_wifi_monitor *monitor, uint64_t *deadline) {
    (void)monitor;
    (void)deadline;
    return false;
}
int asteriskd_wifi_monitor_take_reconcile(struct asteriskd_wifi_monitor *monitor,
    uint64_t now, enum asteriskd_wifi_transition *transition,
    struct asteriskd_wifi_identity *identity, bool *has_transition,
    char *error, size_t error_size) {
    (void)monitor;
    (void)now;
    (void)transition;
    (void)identity;
    (void)error;
    (void)error_size;
    if (has_transition != NULL) *has_transition = false;
    return -1;
}
void asteriskd_wifi_monitor_close(struct asteriskd_wifi_monitor *monitor) {
    (void)monitor;
}
#endif

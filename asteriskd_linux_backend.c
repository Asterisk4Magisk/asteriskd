// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"
#include "asteriskd_compat.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int system_bpf(enum bpf_cmd command, union bpf_attr *attributes) {
    return (int)syscall(__NR_bpf, command, attributes, sizeof(*attributes));
}

static int system_bpf_open_path(void *context, const char *path, int *fd) {
    (void)context;
    if (path == NULL || fd == NULL) return -1;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.pathname = (uint64_t)(uintptr_t)path;
    int result = system_bpf(BPF_OBJ_GET, &attributes);
    if (result < 0) return -1;
    *fd = result;
    return 0;
}

static int system_bpf_map_info(void *context, int fd, struct asteriskd_bpf_map_info *info) {
    (void)context;
    if (fd < 0 || info == NULL) return -1;
    struct bpf_map_info raw;
    memset(&raw, 0, sizeof(raw));
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.info.bpf_fd = (uint32_t)fd;
    attributes.info.info_len = sizeof(raw);
    attributes.info.info = (uint64_t)(uintptr_t)&raw;
    if (system_bpf(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0) return -1;
    memset(info, 0, sizeof(*info));
    info->object_id = raw.id;
    info->type = raw.type;
    info->key_size = raw.key_size;
    info->value_size = raw.value_size;
    info->max_entries = raw.max_entries;
    info->flags = raw.map_flags;
    return 0;
}

static int system_bpf_map_update(
    void *context, int fd, const void *key, size_t key_size,
    const void *value, size_t value_size) {
    (void)context;
    (void)key_size;
    (void)value_size;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    attributes.value = (uint64_t)(uintptr_t)value;
    attributes.flags = BPF_ANY;
    return system_bpf(BPF_MAP_UPDATE_ELEM, &attributes);
}

static int system_bpf_map_next(
    void *context, int fd, const void *current, size_t key_size, void *next, bool *has_next) {
    (void)context;
    (void)key_size;
    if (has_next == NULL) return -1;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)fd;
    attributes.key = (uint64_t)(uintptr_t)current;
    attributes.next_key = (uint64_t)(uintptr_t)next;
    if (system_bpf(BPF_MAP_GET_NEXT_KEY, &attributes) == 0) {
        *has_next = true;
        return 0;
    }
    if (errno == ENOENT) {
        *has_next = false;
        return 0;
    }
    return -1;
}

static int system_bpf_map_lookup(
    void *context, int fd, const void *key, size_t key_size,
    void *value, size_t value_size, bool *found) {
    (void)context;
    (void)key_size;
    (void)value_size;
    if (found == NULL) return -1;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    attributes.value = (uint64_t)(uintptr_t)value;
    if (system_bpf(BPF_MAP_LOOKUP_ELEM, &attributes) == 0) {
        *found = true;
        return 0;
    }
    if (errno == ENOENT) {
        *found = false;
        return 0;
    }
    return -1;
}

static int system_bpf_map_delete(void *context, int fd, const void *key, size_t key_size) {
    (void)context;
    (void)key_size;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    return system_bpf(BPF_MAP_DELETE_ELEM, &attributes);
}

static int system_bpf_map_id(void *context, uint32_t id, int *fd) {
    (void)context;
    if (id == 0U || fd == NULL) return -1;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_id = id;
    int result = system_bpf(BPF_MAP_GET_FD_BY_ID, &attributes);
    if (result < 0) return -1;
    *fd = result;
    return 0;
}

static int system_bpf_program_info(
    void *context, int fd, struct asteriskd_bpf_program_info *info) {
    (void)context;
    if (fd < 0 || info == NULL) return -1;
    uint32_t map_ids[ASTERISKD_BPF_PROGRAM_MAX_MAPS];
    memset(map_ids, 0, sizeof(map_ids));
    struct bpf_prog_info raw;
    memset(&raw, 0, sizeof(raw));
    raw.nr_map_ids = ASTERISKD_BPF_PROGRAM_MAX_MAPS;
    raw.map_ids = (uint64_t)(uintptr_t)map_ids;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.info.bpf_fd = (uint32_t)fd;
    attributes.info.info_len = sizeof(raw);
    attributes.info.info = (uint64_t)(uintptr_t)&raw;
    if (system_bpf(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0 ||
        raw.nr_map_ids > ASTERISKD_BPF_PROGRAM_MAX_MAPS) return -1;
    memset(info, 0, sizeof(*info));
    info->object_id = raw.id;
    info->type = raw.type;
    memcpy(info->name, raw.name, sizeof(raw.name));
    info->name[sizeof(raw.name)] = '\0';
    memcpy(info->tag, raw.tag, sizeof(info->tag));
    memcpy(info->map_ids, map_ids, raw.nr_map_ids * sizeof(map_ids[0]));
    info->map_count = raw.nr_map_ids;
    return 0;
}

static int system_bpf_pin_program(void *context, int fd, const char *path) {
    (void)context;
    if (fd < 0 || path == NULL || path[0] != '/') return -1;
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.bpf_fd = (uint32_t)fd;
    attributes.pathname = (uint64_t)(uintptr_t)path;
    return system_bpf(BPF_OBJ_PIN, &attributes);
}

static int system_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static int system_bpf_pin_inspect_path(void *context, const char *path, bool *exists) {
    (void)context;
    if (path == NULL || exists == NULL) return -1;
    struct stat info;
    if (lstat(path, &info) == 0) {
        *exists = true;
        return 0;
    }
    if (errno == ENOENT) {
        *exists = false;
        return 0;
    }
    return -1;
}

static int system_bpf_pin_read_object_id(void *context, int fd, uint64_t *object_id) {
    (void)context;
    if (fd < 0 || object_id == NULL) return -1;
    struct {
        uint32_t type;
        uint32_t id;
    } raw;
    memset(&raw, 0, sizeof(raw));
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.info.bpf_fd = (uint32_t)fd;
    attributes.info.info_len = sizeof(raw);
    attributes.info.info = (uint64_t)(uintptr_t)&raw;
    if (system_bpf(BPF_OBJ_GET_INFO_BY_FD, &attributes) != 0 || raw.id == 0U) return -1;
    *object_id = raw.id;
    return 0;
}

static const struct asteriskd_bpf_pin_probe_backend bpf_pin_probe_backend = {
    .context = NULL,
    .inspect_path = system_bpf_pin_inspect_path,
    .open_pinned = system_bpf_open_path,
    .read_object_id = system_bpf_pin_read_object_id,
    .close_fd = system_close,
};

static const struct asteriskd_bpf_map_backend bpf_map_backend = {
    .context = NULL,
    .open_pinned = system_bpf_open_path,
    .get_info = system_bpf_map_info,
    .update = system_bpf_map_update,
    .get_next = system_bpf_map_next,
    .delete_key = system_bpf_map_delete,
    .close = system_close,
};

static const struct asteriskd_bpf_program_backend bpf_program_backend = {
    .context = NULL,
    .open_program = system_bpf_open_path,
    .program_info = system_bpf_program_info,
    .open_pinned_map = system_bpf_open_path,
    .open_map = system_bpf_map_id,
    .map_info = system_bpf_map_info,
    .map_next = system_bpf_map_next,
    .map_lookup = system_bpf_map_lookup,
    .pin_program = system_bpf_pin_program,
    .close = system_close,
};

static int system_bpf_pin_probe(
    void *context, const char *path, bool *exists, uint64_t *object_id) {
    (void)context;
    return asteriskd_bpf_pin_probe_with_backend(
        &bpf_pin_probe_backend, path, exists, object_id);
}

static int system_bpf_pin_unlink(void *context, const char *path) {
    (void)context;
    return unlink(path);
}

static const struct asteriskd_bpf_pin_ownership_backend bpf_pin_backend = {
    .context = NULL,
    .probe = system_bpf_pin_probe,
    .unlink_exact = system_bpf_pin_unlink,
};

const struct asteriskd_bpf_map_backend *asteriskd_system_bpf_map_backend(void) {
    return &bpf_map_backend;
}

const struct asteriskd_bpf_program_backend *asteriskd_system_bpf_program_backend(void) {
    return &bpf_program_backend;
}

const struct asteriskd_bpf_pin_ownership_backend *
asteriskd_system_bpf_pin_ownership_backend(void) {
    return &bpf_pin_backend;
}

static int system_network_open(
    void *context, uint32_t groups, size_t receive_buffer_size, uint32_t flags, int *fd) {
    (void)context;
    if (fd == NULL || receive_buffer_size > INT32_MAX || flags !=
        (ASTERISKD_NETWORK_SOCKET_RAW | ASTERISKD_NETWORK_SOCKET_NONBLOCK |
         ASTERISKD_NETWORK_SOCKET_CLOEXEC)) return -1;
    int socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (socket_fd < 0) return -1;
    int buffer_size = (int)receive_buffer_size;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) != 0) {
        int saved = errno;
        (void)close(socket_fd);
        errno = saved;
        return -1;
    }
    struct sockaddr_nl address;
    memset(&address, 0, sizeof(address));
    address.nl_family = AF_NETLINK;
    address.nl_groups = groups;
    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int saved = errno;
        (void)close(socket_fd);
        errno = saved;
        return -1;
    }
    *fd = socket_fd;
    return 0;
}

static enum asteriskd_network_receive_result system_network_receive(
    void *context, int fd, void *buffer, size_t capacity, size_t *length,
    uint32_t *sender_pid, bool *truncated) {
    (void)context;
    if (buffer == NULL || length == NULL || sender_pid == NULL || truncated == NULL) {
        return ASTERISKD_NETWORK_RECEIVE_FATAL;
    }
    struct sockaddr_nl sender;
    memset(&sender, 0, sizeof(sender));
    struct iovec vector = {.iov_base = buffer, .iov_len = capacity};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_name = &sender;
    message.msg_namelen = sizeof(sender);
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    ssize_t received = recvmsg(fd, &message, MSG_TRUNC);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return ASTERISKD_NETWORK_RECEIVE_AGAIN;
        if (errno == EINTR) return ASTERISKD_NETWORK_RECEIVE_INTERRUPTED;
        if (errno == ENOBUFS) return ASTERISKD_NETWORK_RECEIVE_ENOBUFS;
        return ASTERISKD_NETWORK_RECEIVE_FATAL;
    }
    *length = (size_t)received;
    *sender_pid = sender.nl_pid;
    *truncated = (message.msg_flags & MSG_TRUNC) != 0 || (size_t)received > capacity;
    return ASTERISKD_NETWORK_RECEIVE_DATA;
}

static int system_network_interface_name(
    void *context, uint32_t index, char *name, size_t capacity) {
    (void)context;
    if (name == NULL || capacity < IF_NAMESIZE || index == 0U) return -1;
    return if_indextoname(index, name) == NULL ? -1 : 0;
}

static int system_network_ipv6_disabled(
    void *context, const char *name, uint32_t index, uint8_t *value, bool *exists) {
    (void)context;
    if (name == NULL || value == NULL || exists == NULL || name[0] == '\0') return -1;
    *exists = false;
    if (index != 0U && if_nametoindex(name) != index) {
        errno = ENODEV;
        return 0;
    }
    int root = open("/proc/sys/net/ipv6/conf", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return errno == ENOENT || errno == ENODEV ? 0 : -1;
    int directory = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    (void)close(root);
    if (directory < 0) {
        errno = saved;
        return errno == ENOENT || errno == ENODEV ? 0 : -1;
    }
    int fd = openat(directory, "disable_ipv6", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    saved = errno;
    (void)close(directory);
    if (fd < 0) {
        errno = saved;
        return errno == ENOENT || errno == ENODEV ? 0 : -1;
    }
    char bytes[3U] = {0, 0, 0};
    ssize_t length;
    do {
        length = read(fd, bytes, sizeof(bytes));
    } while (length < 0 && errno == EINTR);
    saved = errno;
    (void)close(fd);
    if (length < 1 || (bytes[0] != '0' && bytes[0] != '1') ||
        (length > 1 && bytes[1] != '\n') || length > 2) {
        errno = length < 0 ? saved : EIO;
        return -1;
    }
    *value = (uint8_t)(bytes[0] - '0');
    *exists = true;
    return 0;
}

static const struct asteriskd_network_backend network_backend = {
    .context = NULL,
    .open = system_network_open,
    .receive = system_network_receive,
    .interface_name = system_network_interface_name,
    .ipv6_disabled = system_network_ipv6_disabled,
    .close = system_close,
};

const struct asteriskd_network_backend *asteriskd_system_network_backend(void) {
    return &network_backend;
}

#else

const struct asteriskd_bpf_map_backend *asteriskd_system_bpf_map_backend(void) { return NULL; }
const struct asteriskd_bpf_program_backend *asteriskd_system_bpf_program_backend(void) { return NULL; }
const struct asteriskd_network_backend *asteriskd_system_network_backend(void) { return NULL; }

#endif

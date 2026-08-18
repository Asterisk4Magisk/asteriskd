// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "asteriskd.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__ANDROID__)
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#endif

#define CONTROL_TOKEN_NONE SIZE_MAX

static const char *const control_method_names[] = {"status", "stop", "shutdown", "watch"};
static const char *const control_result_names[] = {
    "ok", "already_running", "not_running", "permission_denied", "invalid_request",
    "config_invalid", "unsupported_combination", "start_failed", "stop_failed", "internal_error",
};
static const char *const control_event_names[] = {
    "starting", "running", "rules-changed", "stopping", "stopped", "core-exited",
    "helper-failed", "failed",
};
static const char *const control_phase_names[] = {
    "validating", "acquiring", "starting", "applying-rules",
    "running", "stopping", "stopped", "failed",
};
static const char *const control_owner_names[] = {"asteriskng", "asteriskbox", "asteriskmeta"};
static const char *const control_core_names[] = {"xray", "sing-box", "mihomo"};
static const char *const control_mode_names[] = {"tproxy", "tun", "tun2socks", "bpf2socks", "ebpf"};
static const char *const control_helper_names[] = {NULL, "hev-socks5-tunnel", "bpf2socks"};
static const char *const control_component_names[] = {
    "runtime", "core", "helper", "matcher", "rules", "network", "state", "log", "control",
};
static const char *const control_failure_names[] = {
    "start_failed", "readiness_timeout", "child_exited", "state_invalid", "state_incompatible",
    "resource_collision", "io_error", "stop_failed", "internal_error",
};
static const char *const control_category_names[] = {
    "tproxy", "routing", "dns", "fake-dns", "local-bypass", "hotspot", "tc", "bpf", "ipv6-guard",
};
static const unsigned char control_abstract_name[] = "\0asteriskd.control";

static size_t control_bounded_length(const char *, size_t);
static uint64_t control_deadline_after(uint64_t, uint64_t);

struct control_builder {
    char *bytes;
    size_t capacity;
    size_t length;
    bool failed;
};

static bool control_listener_backend_complete(
    const struct asteriskd_control_listener_backend *backend) {
    return backend != NULL && backend->open_stream != NULL &&
        backend->bind_abstract != NULL && backend->listen_socket != NULL &&
        backend->close_fd != NULL;
}

enum asteriskd_control_listener_result asteriskd_control_listener_open_with_backend(
    int *out,
    const struct asteriskd_control_listener_backend *backend,
    void *context) {
    if (out != NULL) *out = -1;
    if (out == NULL || !control_listener_backend_complete(backend)) {
        return ASTERISKD_CONTROL_LISTENER_ERROR;
    }
    int fd = -1;
    if (backend->open_stream(context, &fd) != 0 || fd < 0) {
        if (fd >= 0) (void)backend->close_fd(context, fd);
        return ASTERISKD_CONTROL_LISTENER_ERROR;
    }
    enum asteriskd_control_listener_result bound = backend->bind_abstract(
        context, fd, control_abstract_name, sizeof(control_abstract_name) - 1U);
    if (bound != ASTERISKD_CONTROL_LISTENER_OK) {
        (void)backend->close_fd(context, fd);
        return bound == ASTERISKD_CONTROL_LISTENER_IN_USE
            ? ASTERISKD_CONTROL_LISTENER_IN_USE
            : ASTERISKD_CONTROL_LISTENER_ERROR;
    }
    if (backend->listen_socket(
            context, fd, (int)ASTERISKD_CONTROL_MAX_CLIENTS) != 0) {
        (void)backend->close_fd(context, fd);
        return ASTERISKD_CONTROL_LISTENER_ERROR;
    }
    *out = fd;
    return ASTERISKD_CONTROL_LISTENER_OK;
}

#if defined(__linux__) || defined(__ANDROID__)
static int control_system_listener_open(void *context, int *fd) {
    (void)context;
    int result = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd != NULL) *fd = result;
    return result < 0 ? -1 : 0;
}

static enum asteriskd_control_listener_result control_system_listener_bind(
    void *context,
    int fd,
    const unsigned char *name,
    size_t name_length) {
    (void)context;
    struct sockaddr_un address;
    if (fd < 0 || name == NULL || name_length == 0U ||
        name_length > sizeof(address.sun_path)) return ASTERISKD_CONTROL_LISTENER_ERROR;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, name, name_length);
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_length);
    if (bind(fd, (const struct sockaddr *)&address, length) == 0) {
        return ASTERISKD_CONTROL_LISTENER_OK;
    }
    return errno == EADDRINUSE
        ? ASTERISKD_CONTROL_LISTENER_IN_USE
        : ASTERISKD_CONTROL_LISTENER_ERROR;
}

static int control_system_listener_listen(void *context, int fd, int backlog) {
    (void)context;
    return listen(fd, backlog);
}

static int control_system_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static const struct asteriskd_control_listener_backend control_system_listener_backend = {
    .open_stream = control_system_listener_open,
    .bind_abstract = control_system_listener_bind,
    .listen_socket = control_system_listener_listen,
    .close_fd = control_system_close,
};

static int control_system_accept(void *context, int listener, int *fd, uint32_t *uid) {
    (void)context;
    int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (accepted < 0) {
        if (errno == EINTR) return ASTERISKD_CONTROL_BACKEND_INTERRUPTED;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return ASTERISKD_CONTROL_BACKEND_AGAIN;
        return ASTERISKD_CONTROL_BACKEND_ERROR;
    }
    struct ucred credentials;
    socklen_t credentials_length = (socklen_t)sizeof(credentials);
    if (getsockopt(accepted, SOL_SOCKET, SO_PEERCRED,
            &credentials, &credentials_length) != 0 ||
        credentials_length != sizeof(credentials) || credentials.uid > UINT32_MAX) {
        (void)close(accepted);
        return ASTERISKD_CONTROL_BACKEND_ERROR;
    }
    *fd = accepted;
    *uid = (uint32_t)credentials.uid;
    return ASTERISKD_CONTROL_BACKEND_OK;
}

static ptrdiff_t control_system_read(
    void *context,
    int fd,
    void *buffer,
    size_t size) {
    (void)context;
    ssize_t result = recv(fd, buffer, size, MSG_DONTWAIT);
    if (result >= 0) return (ptrdiff_t)result;
    if (errno == EINTR) return ASTERISKD_CONTROL_BACKEND_INTERRUPTED;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ASTERISKD_CONTROL_BACKEND_AGAIN;
    return ASTERISKD_CONTROL_BACKEND_ERROR;
}

static ptrdiff_t control_system_write(
    void *context,
    int fd,
    const void *buffer,
    size_t size) {
    (void)context;
    ssize_t result = send(fd, buffer, size, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (result >= 0) return (ptrdiff_t)result;
    if (errno == EINTR) return ASTERISKD_CONTROL_BACKEND_INTERRUPTED;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ASTERISKD_CONTROL_BACKEND_AGAIN;
    return ASTERISKD_CONTROL_BACKEND_ERROR;
}

static const struct asteriskd_control_transport_backend control_system_transport_backend = {
    .accept_client = control_system_accept,
    .read_client = control_system_read,
    .write_client = control_system_write,
    .close_fd = control_system_close,
};
#endif

enum asteriskd_control_listener_result asteriskd_control_listener_open(int *out) {
#if defined(__linux__) || defined(__ANDROID__)
    return asteriskd_control_listener_open_with_backend(
        out, &control_system_listener_backend, NULL);
#else
    if (out != NULL) *out = -1;
    return ASTERISKD_CONTROL_LISTENER_ERROR;
#endif
}

static bool control_cli_config_path_valid(const char *path, size_t *length) {
    if (path == NULL || length == NULL) return false;
    size_t size = control_bounded_length(path, ASTERISKD_MAX_PATH);
    if (size == 0U || size >= ASTERISKD_MAX_PATH || path[0] != '/' ||
        size == 1U || path[size - 1U] == '/') return false;
    size_t start = 1U;
    while (start < size) {
        size_t end = start;
        while (end < size && path[end] != '/') ++end;
        size_t component_length = end - start;
        if (component_length == 0U || component_length >= 256U ||
            (component_length == 1U && path[start] == '.') ||
            (component_length == 2U && path[start] == '.' && path[start + 1U] == '.')) {
            return false;
        }
        if (end < size && path[end + 1U] == '/') return false;
        start = end + 1U;
    }
    *length = size;
    return true;
}

int asteriskd_cli_parse(
    int argc,
    const char *const *argv,
    struct asteriskd_cli_invocation *invocation) {
    if (invocation != NULL) memset(invocation, 0, sizeof(*invocation));
    if (invocation == NULL || argv == NULL || argc < 2 || argv[1] == NULL) return -1;
    if (argc == 2) {
        if (strcmp(argv[1], "status") == 0) invocation->command = ASTERISKD_CLI_STATUS;
        else if (strcmp(argv[1], "stop") == 0) invocation->command = ASTERISKD_CLI_STOP;
        else if (strcmp(argv[1], "shutdown") == 0) invocation->command = ASTERISKD_CLI_SHUTDOWN;
        else if (strcmp(argv[1], "watch") == 0) invocation->command = ASTERISKD_CLI_WATCH;
        else goto invalid;
        return 0;
    }
    if (argc == 3 && argv[2] != NULL &&
        strcmp(argv[1], "watch") == 0 && strcmp(argv[2], "--until-running") == 0) {
        invocation->command = ASTERISKD_CLI_WATCH;
        invocation->watch_until_running = true;
        return 0;
    }
    if (argc != 4 || argv[2] == NULL || argv[3] == NULL) goto invalid;
    if (strcmp(argv[1], "start") == 0 && strcmp(argv[2], "--config") == 0) {
        invocation->command = ASTERISKD_CLI_START;
    } else if (strcmp(argv[1], "monitor") == 0 && strcmp(argv[2], "--config") == 0) {
        invocation->command = ASTERISKD_CLI_MONITOR;
    } else {
        goto invalid;
    }
    size_t path_length = 0U;
    if (!control_cli_config_path_valid(argv[3], &path_length)) goto invalid;
    static const char leaf[] = "asteriskd.json";
    if (path_length <= sizeof(leaf) ||
        memcmp(argv[3] + path_length - (sizeof(leaf) - 1U), leaf, sizeof(leaf)) != 0 ||
        argv[3][path_length - sizeof(leaf)] != '/') goto invalid;
    memcpy(invocation->path, argv[3], path_length + 1U);
    return 0;
invalid:
    memset(invocation, 0, sizeof(*invocation));
    return -1;
}

static size_t control_bounded_length(const char *value, size_t capacity) {
    if (value == NULL) return capacity;
    size_t length = 0U;
    while (length < capacity && value[length] != '\0') ++length;
    return length;
}

static bool control_utf8_valid(const char *bytes, size_t length, bool allow_nul) {
    if (bytes == NULL) return false;
    size_t index = 0U;
    while (index < length) {
        unsigned char first = (unsigned char)bytes[index++];
        if (first == 0U && !allow_nul) return false;
        if (first <= 0x7fU) continue;
        size_t continuation_count;
        uint32_t codepoint;
        uint32_t minimum;
        if (first >= 0xc2U && first <= 0xdfU) {
            continuation_count = 1U;
            codepoint = (uint32_t)(first & 0x1fU);
            minimum = 0x80U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuation_count = 2U;
            codepoint = (uint32_t)(first & 0x0fU);
            minimum = 0x800U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuation_count = 3U;
            codepoint = (uint32_t)(first & 0x07U);
            minimum = 0x10000U;
        } else {
            return false;
        }
        if (length - index < continuation_count) return false;
        for (size_t offset = 0U; offset < continuation_count; ++offset) {
            unsigned char next = (unsigned char)bytes[index++];
            if ((next & 0xc0U) != 0x80U) return false;
            codepoint = (codepoint << 6U) | (uint32_t)(next & 0x3fU);
        }
        if (codepoint < minimum || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) return false;
    }
    return true;
}

static bool control_bytes_are_zero(const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    for (size_t index = 0U; index < length; ++index) {
        if (cursor[index] != 0U) return false;
    }
    return true;
}

static bool control_message_valid(const char *message, size_t message_length) {
    return message != NULL && message_length > 0U && message_length <= ASTERISKD_CONTROL_MAX_PAYLOAD &&
        control_utf8_valid(message, message_length, true);
}

static bool control_request_id_valid(const char *request_id) {
    size_t length = control_bounded_length(request_id, ASTERISKD_CONTROL_MAX_REQUEST_ID + 1U);
    if (length == 0U || length > ASTERISKD_CONTROL_MAX_REQUEST_ID) return false;
    for (size_t index = 0U; index < length; ++index) {
        char value = request_id[index];
        if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-')) return false;
    }
    return true;
}

static void control_builder_bytes(struct control_builder *builder, const char *bytes, size_t length) {
    if (builder->failed) return;
    if (length > builder->capacity || builder->length > builder->capacity - length) {
        builder->failed = true;
        return;
    }
    memcpy(builder->bytes + builder->length, bytes, length);
    builder->length += length;
}

static void control_builder_raw(struct control_builder *builder, const char *value) {
    control_builder_bytes(builder, value, strlen(value));
}

static void control_builder_format(struct control_builder *builder, const char *format, ...) {
    if (builder->failed || builder->length >= builder->capacity) {
        builder->failed = true;
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(
        builder->bytes + builder->length, builder->capacity - builder->length, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= builder->capacity - builder->length) {
        builder->failed = true;
        return;
    }
    builder->length += (size_t)written;
}

static void control_builder_json_bytes(
    struct control_builder *builder,
    const char *value,
    size_t length) {
    static const char hexadecimal[] = "0123456789abcdef";
    if (value == NULL || !control_utf8_valid(value, length, true)) {
        builder->failed = true;
        return;
    }
    control_builder_raw(builder, "\"");
    for (size_t index = 0U; index < length; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte == '"' || byte == '\\') {
            char escaped[2] = {'\\', (char)byte};
            control_builder_bytes(builder, escaped, sizeof(escaped));
        } else if (byte == '\b') control_builder_raw(builder, "\\b");
        else if (byte == '\f') control_builder_raw(builder, "\\f");
        else if (byte == '\n') control_builder_raw(builder, "\\n");
        else if (byte == '\r') control_builder_raw(builder, "\\r");
        else if (byte == '\t') control_builder_raw(builder, "\\t");
        else if (byte < 0x20U) {
            char escaped[] = {'\\', 'u', '0', '0', hexadecimal[byte >> 4U], hexadecimal[byte & 0x0fU]};
            control_builder_bytes(builder, escaped, sizeof(escaped));
        } else {
            control_builder_bytes(builder, (const char *)&value[index], 1U);
        }
    }
    control_builder_raw(builder, "\"");
}

static void control_builder_json_string(struct control_builder *builder, const char *value) {
    size_t length = control_bounded_length(value, ASTERISKD_CONTROL_MAX_PAYLOAD + 1U);
    if (length > ASTERISKD_CONTROL_MAX_PAYLOAD) {
        builder->failed = true;
        return;
    }
    control_builder_json_bytes(builder, value, length);
}

static int control_builder_finish(struct control_builder *builder, size_t *out_length) {
    if (builder->failed || builder->length > ASTERISKD_CONTROL_MAX_PAYLOAD) return -1;
    control_builder_raw(builder, "\n");
    if (builder->failed || builder->length >= builder->capacity) return -1;
    builder->bytes[builder->length] = '\0';
    if (out_length != NULL) *out_length = builder->length;
    return 0;
}

static bool control_owner_core_valid(enum asteriskd_owner owner, enum asteriskd_core_type core) {
    return (owner == ASTERISKD_OWNER_NG && core == ASTERISKD_CORE_XRAY) ||
        (owner == ASTERISKD_OWNER_BOX && core == ASTERISKD_CORE_SING_BOX) ||
        (owner == ASTERISKD_OWNER_META && core == ASTERISKD_CORE_MIHOMO);
}

static bool control_combination_valid(
    enum asteriskd_owner owner,
    enum asteriskd_core_type core,
    enum asteriskd_mode mode) {
    if (!control_owner_core_valid(owner, core) || mode < 0 || mode > ASTERISKD_MODE_EBPF) return false;
    if (owner == ASTERISKD_OWNER_BOX) return true;
    if (owner == ASTERISKD_OWNER_NG) {
        return mode == ASTERISKD_MODE_TPROXY || mode == ASTERISKD_MODE_TUN2SOCKS ||
            mode == ASTERISKD_MODE_BPF2SOCKS;
    }
    return mode != ASTERISKD_MODE_EBPF;
}

static enum asteriskd_helper_type control_helper_for_mode(enum asteriskd_mode mode) {
    if (mode == ASTERISKD_MODE_TUN2SOCKS) return ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL;
    if (mode == ASTERISKD_MODE_BPF2SOCKS) return ASTERISKD_HELPER_BPF2SOCKS;
    return ASTERISKD_HELPER_NONE;
}

void asteriskd_control_error_destroy(struct asteriskd_control_error *error) {
    if (error == NULL) return;
    free(error->message);
    memset(error, 0, sizeof(*error));
}

void asteriskd_control_snapshot_destroy(struct asteriskd_control_snapshot *snapshot) {
    if (snapshot == NULL) return;
    asteriskd_control_error_destroy(&snapshot->error);
    memset(snapshot, 0, sizeof(*snapshot));
}

void asteriskd_control_result_destroy(struct asteriskd_control_result *result) {
    if (result == NULL) return;
    asteriskd_control_snapshot_destroy(&result->snapshot);
    free(result->message);
    memset(result, 0, sizeof(*result));
}

void asteriskd_control_response_destroy(struct asteriskd_control_response *response) {
    if (response == NULL) return;
    asteriskd_control_result_destroy(&response->result);
    memset(response, 0, sizeof(*response));
}

void asteriskd_control_event_destroy(struct asteriskd_control_event *event) {
    if (event == NULL) return;
    asteriskd_control_snapshot_destroy(&event->snapshot);
    asteriskd_control_error_destroy(&event->details);
    memset(event, 0, sizeof(*event));
}

static int control_copy_message(char **out, size_t *out_length, const char *message, size_t message_length) {
    if (out == NULL || out_length == NULL || !control_message_valid(message, message_length)) return -1;
    char *copy = malloc(message_length + 1U);
    if (copy == NULL) return -1;
    memcpy(copy, message, message_length);
    copy[message_length] = '\0';
    free(*out);
    *out = copy;
    *out_length = message_length;
    return 0;
}

int asteriskd_control_error_set_message(
    struct asteriskd_control_error *error,
    const char *message,
    size_t message_length) {
    if (error == NULL) return -1;
    return control_copy_message(&error->message, &error->message_length, message, message_length);
}

int asteriskd_control_result_set_message(
    struct asteriskd_control_result *result,
    const char *message,
    size_t message_length) {
    if (result == NULL || control_copy_message(
        &result->message, &result->message_length, message, message_length) != 0) return -1;
    result->has_message = true;
    return 0;
}

int asteriskd_control_snapshot_copy(
    struct asteriskd_control_snapshot *destination,
    const struct asteriskd_control_snapshot *source) {
    if (destination == NULL || source == NULL || destination == source ||
        !asteriskd_control_snapshot_valid(source)) return -1;
    struct asteriskd_control_snapshot copy = *source;
    copy.error.message = NULL;
    copy.error.message_length = 0U;
    if (source->has_error && control_copy_message(
        &copy.error.message, &copy.error.message_length,
        source->error.message, source->error.message_length) != 0) return -1;
    asteriskd_control_snapshot_destroy(destination);
    *destination = copy;
    return 0;
}

static bool control_error_valid(const struct asteriskd_control_error *error) {
    if (error == NULL || error->code < 0 || error->code >= ASTERISKD_FAILURE_CODE_COUNT ||
        error->component < 0 || error->component >= ASTERISKD_COMPONENT_COUNT ||
        !control_message_valid(error->message, error->message_length)) return false;
    if (error->code == ASTERISKD_FAILURE_CHILD_EXITED) {
        if (error->has_exit_code == error->has_signal) return false;
        if (error->has_exit_code && error->exit_code < 0) return false;
        if (error->has_signal && error->signal <= 0) return false;
        return error->has_exit_code ? error->signal == 0 : error->exit_code == 0;
    }
    return !error->has_exit_code && error->exit_code == 0 &&
        !error->has_signal && error->signal == 0;
}

bool asteriskd_control_snapshot_valid(const struct asteriskd_control_snapshot *snapshot) {
    if (snapshot == NULL || snapshot->phase < 0 || snapshot->phase >= ASTERISKD_PHASE_COUNT ||
        !control_combination_valid(snapshot->owner, snapshot->core_type, snapshot->mode) ||
        snapshot->supervisor_pid <= 0 || (snapshot->has_core_pid ? snapshot->core_pid <= 0 : snapshot->core_pid != 0) ||
        snapshot->helper_type != control_helper_for_mode(snapshot->mode) ||
        (snapshot->has_helper_pid ? snapshot->helper_pid <= 0 : snapshot->helper_pid != 0) ||
        (snapshot->has_helper_pid && snapshot->helper_type == ASTERISKD_HELPER_NONE) ||
        (snapshot->matcher_active && !snapshot->matcher_configured) ||
        (snapshot->rules.categories & ~ASTERISKD_RULE_CATEGORY_ALL) != 0U ||
        (!snapshot->rules.active &&
            (snapshot->rules.generation != 0U || snapshot->rules.categories != 0U)) ||
        (snapshot->rules.active &&
            (snapshot->rules.generation == 0U || snapshot->rules.categories == 0U)) ||
        (snapshot->has_error ? !control_error_valid(&snapshot->error) :
            !control_bytes_are_zero(&snapshot->error, sizeof(snapshot->error)))) return false;
    if (snapshot->phase == ASTERISKD_PHASE_RUNNING) {
        if (!snapshot->network.ipv4_ready || !snapshot->network.ipv6_ready ||
            !snapshot->has_core_pid || snapshot->has_error ||
            (snapshot->helper_type != ASTERISKD_HELPER_NONE && !snapshot->has_helper_pid) ||
            (snapshot->matcher_configured && !snapshot->matcher_active) ||
            (snapshot->mode != ASTERISKD_MODE_EBPF && !snapshot->rules.active)) return false;
    } else if (snapshot->network.ipv4_ready || snapshot->network.ipv6_ready) {
        return false;
    }
    if (snapshot->phase == ASTERISKD_PHASE_FAILED && !snapshot->has_error) return false;
    if (snapshot->mode == ASTERISKD_MODE_EBPF &&
        (snapshot->rules.active || snapshot->rules.generation != 0U || snapshot->rules.categories != 0U ||
         snapshot->matcher_configured || snapshot->matcher_active ||
         snapshot->helper_type != ASTERISKD_HELPER_NONE || snapshot->has_helper_pid)) return false;
    return true;
}

bool asteriskd_control_result_valid(const struct asteriskd_control_result *result) {
    if (result == NULL || result->code < 0 || result->code >= ASTERISKD_CONTROL_RESULT_CODE_COUNT ||
        (result->has_snapshot ? !asteriskd_control_snapshot_valid(&result->snapshot) :
            !control_bytes_are_zero(&result->snapshot, sizeof(result->snapshot))) ||
        (result->has_message ? !control_message_valid(result->message, result->message_length) :
            result->message != NULL || result->message_length != 0U)) return false;
    switch (result->code) {
        case ASTERISKD_CONTROL_RESULT_OK:
            return result->has_snapshot && !result->has_message;
        case ASTERISKD_CONTROL_RESULT_ALREADY_RUNNING:
            return result->has_snapshot && result->has_message;
        case ASTERISKD_CONTROL_RESULT_NOT_RUNNING:
        case ASTERISKD_CONTROL_RESULT_PERMISSION_DENIED:
        case ASTERISKD_CONTROL_RESULT_INVALID_REQUEST:
        case ASTERISKD_CONTROL_RESULT_CONFIG_INVALID:
        case ASTERISKD_CONTROL_RESULT_UNSUPPORTED_COMBINATION:
        case ASTERISKD_CONTROL_RESULT_START_FAILED:
            return !result->has_snapshot && result->has_message;
        case ASTERISKD_CONTROL_RESULT_STOP_FAILED:
            return result->has_snapshot && result->snapshot.phase == ASTERISKD_PHASE_FAILED && result->has_message;
        case ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR:
            return result->has_message;
        case ASTERISKD_CONTROL_RESULT_CODE_COUNT:
            return false;
    }
    return false;
}

int asteriskd_control_result_exit_code(enum asteriskd_control_result_code code) {
    switch (code) {
        case ASTERISKD_CONTROL_RESULT_OK: return 0;
        case ASTERISKD_CONTROL_RESULT_ALREADY_RUNNING: return 4;
        case ASTERISKD_CONTROL_RESULT_NOT_RUNNING: return 3;
        case ASTERISKD_CONTROL_RESULT_PERMISSION_DENIED: return 77;
        case ASTERISKD_CONTROL_RESULT_INVALID_REQUEST:
        case ASTERISKD_CONTROL_RESULT_CONFIG_INVALID:
        case ASTERISKD_CONTROL_RESULT_UNSUPPORTED_COMBINATION: return 64;
        case ASTERISKD_CONTROL_RESULT_START_FAILED:
        case ASTERISKD_CONTROL_RESULT_STOP_FAILED:
        case ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR:
        case ASTERISKD_CONTROL_RESULT_CODE_COUNT: return 1;
    }
    return 1;
}

int asteriskd_control_snapshot_from_state(
    const struct asteriskd_state_document *state,
    const struct asteriskd_control_live_context *live,
    struct asteriskd_control_snapshot *snapshot) {
    if (snapshot == NULL) return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (state == NULL || live == NULL || !state->initialized || live->supervisor_pid <= 0) return -1;
    snapshot->phase = state->phase;
    snapshot->owner = state->owner;
    snapshot->core_type = state->core_type;
    snapshot->mode = state->mode;
    snapshot->supervisor_pid = live->supervisor_pid;
    snapshot->helper_type = control_helper_for_mode(state->mode);
    snapshot->matcher_configured = state->matcher.configured;
    snapshot->matcher_active = state->matcher.active;
    snapshot->rules.active = state->rules.active;
    snapshot->rules.generation = state->rules.generation;
    snapshot->rules.categories = state->rules.categories;
    snapshot->network.ipv6_enabled = live->ipv6_enabled;
    snapshot->network.ipv4_ready = state->phase == ASTERISKD_PHASE_RUNNING;
    snapshot->network.ipv6_ready = state->phase == ASTERISKD_PHASE_RUNNING;
    if (state->children.core_present) {
        enum asteriskd_child_type expected = state->core_type == ASTERISKD_CORE_XRAY
            ? ASTERISKD_CHILD_TYPE_XRAY : state->core_type == ASTERISKD_CORE_SING_BOX
            ? ASTERISKD_CHILD_TYPE_SING_BOX : ASTERISKD_CHILD_TYPE_MIHOMO;
        if (state->children.core.type != expected || state->children.core.pid <= 0) return -1;
        snapshot->has_core_pid = true;
        snapshot->core_pid = state->children.core.pid;
    }
    if (state->children.helper_present) {
        enum asteriskd_child_type expected = snapshot->helper_type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL
            ? ASTERISKD_CHILD_TYPE_HEV_SOCKS5_TUNNEL : ASTERISKD_CHILD_TYPE_BPF2SOCKS;
        if (snapshot->helper_type == ASTERISKD_HELPER_NONE || state->children.helper.type != expected ||
            state->children.helper.pid <= 0) return -1;
        snapshot->has_helper_pid = true;
        snapshot->helper_pid = state->children.helper.pid;
    }
    if (state->failure.present) {
        snapshot->has_error = true;
        snapshot->error.code = state->failure.code;
        snapshot->error.component = state->failure.component;
        size_t message_length = control_bounded_length(
            state->failure.message, sizeof(state->failure.message));
        if (asteriskd_control_error_set_message(
            &snapshot->error, state->failure.message, message_length) != 0) {
            asteriskd_control_snapshot_destroy(snapshot);
            return -1;
        }
        snapshot->error.has_exit_code = state->failure.has_exit_code;
        snapshot->error.exit_code = state->failure.exit_code;
        snapshot->error.has_signal = state->failure.has_signal;
        snapshot->error.signal = state->failure.signal;
    }
    if (!asteriskd_control_snapshot_valid(snapshot)) {
        asteriskd_control_snapshot_destroy(snapshot);
        return -1;
    }
    return 0;
}

static void control_encode_error(
    struct control_builder *builder,
    bool present,
    const struct asteriskd_control_error *error) {
    if (!present) {
        control_builder_raw(builder, "null");
        return;
    }
    control_builder_raw(builder, "{\"code\":");
    control_builder_json_string(builder, control_failure_names[error->code]);
    control_builder_raw(builder, ",\"component\":");
    control_builder_json_string(builder, control_component_names[error->component]);
    control_builder_raw(builder, ",\"message\":");
    control_builder_json_bytes(builder, error->message, error->message_length);
    control_builder_raw(builder, ",\"exitCode\":");
    if (error->has_exit_code) control_builder_format(builder, "%d", error->exit_code);
    else control_builder_raw(builder, "null");
    control_builder_raw(builder, ",\"signal\":");
    if (error->has_signal) control_builder_format(builder, "%d", error->signal);
    else control_builder_raw(builder, "null");
    control_builder_raw(builder, "}");
}

static void control_encode_snapshot(
    struct control_builder *builder,
    const struct asteriskd_control_snapshot *snapshot) {
    control_builder_raw(builder, "{\"phase\":");
    control_builder_json_string(builder, control_phase_names[snapshot->phase]);
    control_builder_raw(builder, ",\"owner\":");
    control_builder_json_string(builder, control_owner_names[snapshot->owner]);
    control_builder_raw(builder, ",\"coreType\":");
    control_builder_json_string(builder, control_core_names[snapshot->core_type]);
    control_builder_raw(builder, ",\"mode\":");
    control_builder_json_string(builder, control_mode_names[snapshot->mode]);
    control_builder_format(builder, ",\"supervisorPid\":%d,\"corePid\":", snapshot->supervisor_pid);
    if (snapshot->has_core_pid) control_builder_format(builder, "%d", snapshot->core_pid);
    else control_builder_raw(builder, "null");
    control_builder_raw(builder, ",\"helperType\":");
    if (snapshot->helper_type == ASTERISKD_HELPER_NONE) control_builder_raw(builder, "null");
    else control_builder_json_string(builder, control_helper_names[snapshot->helper_type]);
    control_builder_raw(builder, ",\"helperPid\":");
    if (snapshot->has_helper_pid) control_builder_format(builder, "%d", snapshot->helper_pid);
    else control_builder_raw(builder, "null");
    control_builder_raw(builder, ",\"matcherConfigured\":");
    control_builder_raw(builder, snapshot->matcher_configured ? "true" : "false");
    control_builder_raw(builder, ",\"matcherActive\":");
    control_builder_raw(builder, snapshot->matcher_active ? "true" : "false");
    control_builder_raw(builder, ",\"rules\":{\"active\":");
    control_builder_raw(builder, snapshot->rules.active ? "true" : "false");
    control_builder_format(builder, ",\"generation\":%" PRIu64 ",\"categories\":[", snapshot->rules.generation);
    bool first = true;
    for (int category = 0; category < ASTERISKD_RULE_CATEGORY_COUNT; ++category) {
        if ((snapshot->rules.categories & ASTERISKD_RULE_CATEGORY_BIT(category)) == 0U) continue;
        if (!first) control_builder_raw(builder, ",");
        control_builder_json_string(builder, control_category_names[category]);
        first = false;
    }
    control_builder_raw(builder, "]},\"network\":{\"ipv4Ready\":");
    control_builder_raw(builder, snapshot->network.ipv4_ready ? "true" : "false");
    control_builder_raw(builder, ",\"ipv6Enabled\":");
    control_builder_raw(builder, snapshot->network.ipv6_enabled ? "true" : "false");
    control_builder_raw(builder, ",\"ipv6Ready\":");
    control_builder_raw(builder, snapshot->network.ipv6_ready ? "true" : "false");
    control_builder_raw(builder, "},\"error\":");
    control_encode_error(builder, snapshot->has_error, &snapshot->error);
    control_builder_raw(builder, "}");
}

int asteriskd_control_encode_request_line(
    const struct asteriskd_control_request *request,
    char *out,
    size_t out_size,
    size_t *out_length) {
    if (request == NULL || out == NULL || out_size == 0U || !control_request_id_valid(request->request_id) ||
        request->method < 0 || request->method >= ASTERISKD_CONTROL_METHOD_COUNT) return -1;
    struct control_builder builder = {.bytes = out, .capacity = out_size};
    control_builder_raw(&builder, "{\"protocolVersion\":1,\"requestId\":");
    control_builder_json_string(&builder, request->request_id);
    control_builder_raw(&builder, ",\"method\":");
    control_builder_json_string(&builder, control_method_names[request->method]);
    control_builder_raw(&builder, ",\"params\":{}}");
    return control_builder_finish(&builder, out_length);
}

int asteriskd_control_encode_response_line(
    const struct asteriskd_control_response *response,
    char *out,
    size_t out_size,
    size_t *out_length) {
    if (response == NULL || out == NULL || out_size == 0U ||
        !control_request_id_valid(response->request_id) || !asteriskd_control_result_valid(&response->result)) return -1;
    struct control_builder builder = {.bytes = out, .capacity = out_size};
    control_builder_raw(&builder, "{\"protocolVersion\":1,\"requestId\":");
    control_builder_json_string(&builder, response->request_id);
    control_builder_raw(&builder, ",\"result\":{\"code\":");
    control_builder_json_string(&builder, control_result_names[response->result.code]);
    control_builder_raw(&builder, ",\"snapshot\":");
    if (response->result.has_snapshot) control_encode_snapshot(&builder, &response->result.snapshot);
    else control_builder_raw(&builder, "null");
    control_builder_raw(&builder, ",\"message\":");
    if (response->result.has_message) control_builder_json_bytes(
        &builder, response->result.message, response->result.message_length);
    else control_builder_raw(&builder, "null");
    control_builder_raw(&builder, "}}");
    return control_builder_finish(&builder, out_length);
}

static bool control_event_valid(const struct asteriskd_control_event *event) {
    return event != NULL && event->sequence > 0U && event->type >= 0 &&
        event->type < ASTERISKD_CONTROL_EVENT_TYPE_COUNT &&
        asteriskd_control_snapshot_valid(&event->snapshot) &&
        (event->has_details ? control_error_valid(&event->details) :
            control_bytes_are_zero(&event->details, sizeof(event->details)));
}

int asteriskd_control_encode_event_line(
    const struct asteriskd_control_event *event,
    char *out,
    size_t out_size,
    size_t *out_length) {
    if (out == NULL || out_size == 0U || !control_event_valid(event)) return -1;
    struct control_builder builder = {.bytes = out, .capacity = out_size};
    control_builder_format(&builder, "{\"protocolVersion\":1,\"event\":{\"sequence\":%" PRIu64 ",\"type\":", event->sequence);
    control_builder_json_string(&builder, control_event_names[event->type]);
    control_builder_raw(&builder, ",\"snapshot\":");
    control_encode_snapshot(&builder, &event->snapshot);
    control_builder_raw(&builder, ",\"details\":");
    control_encode_error(&builder, event->has_details, &event->details);
    control_builder_raw(&builder, "}}");
    return control_builder_finish(&builder, out_length);
}

static size_t control_next_direct(
    const struct asteriskd_json_document *document,
    size_t parent,
    size_t start) {
    for (size_t index = start; index < document->token_count; ++index) {
        if (document->tokens[index].parent == parent) return index;
    }
    return CONTROL_TOKEN_NONE;
}

static int control_hex_digit(char value, uint32_t *out) {
    if (value >= '0' && value <= '9') *out = (uint32_t)(value - '0');
    else if (value >= 'a' && value <= 'f') *out = (uint32_t)(value - 'a' + 10);
    else if (value >= 'A' && value <= 'F') *out = (uint32_t)(value - 'A' + 10);
    else return -1;
    return 0;
}

static int control_append_utf8(uint32_t codepoint, char *out, size_t out_size, size_t *length) {
    unsigned char encoded[4];
    size_t count;
    if (codepoint <= 0x7fU) {
        encoded[0] = (unsigned char)codepoint;
        count = 1U;
    } else if (codepoint <= 0x7ffU) {
        encoded[0] = (unsigned char)(0xc0U | (codepoint >> 6U));
        encoded[1] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 2U;
    } else if (codepoint <= 0xffffU) {
        encoded[0] = (unsigned char)(0xe0U | (codepoint >> 12U));
        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 3U;
    } else {
        encoded[0] = (unsigned char)(0xf0U | (codepoint >> 18U));
        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 12U) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[3] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 4U;
    }
    if (count >= out_size - *length) return -1;
    memcpy(out + *length, encoded, count);
    *length += count;
    return 0;
}

static int control_decode_json_string_bytes(
    const struct asteriskd_json_document *document,
    size_t token_index,
    char *out,
    size_t out_size,
    size_t *decoded_length,
    bool allow_nul) {
    if (document == NULL || token_index >= document->token_count || out == NULL || out_size == 0U ||
        document->tokens[token_index].type != ASTERISKD_JSON_STRING) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    size_t length = 0U;
    for (size_t input = token->start; input < token->end; ++input) {
        unsigned char value = (unsigned char)document->source[input];
        if (value != '\\') {
            if ((value == 0U && !allow_nul) || length + 1U >= out_size) return -1;
            out[length++] = (char)value;
            continue;
        }
        if (++input >= token->end) return -1;
        value = (unsigned char)document->source[input];
        switch (value) {
            case '"': case '\\': case '/':
                if (length + 1U >= out_size) return -1;
                out[length++] = (char)value;
                break;
            case 'b': case 'f': case 'n': case 'r': case 't': {
                static const char decoded[] = {'\b', '\f', '\n', '\r', '\t'};
                static const char encoded[] = {'b', 'f', 'n', 'r', 't'};
                const char *found = strchr(encoded, (int)value);
                if (found == NULL || length + 1U >= out_size) return -1;
                out[length++] = decoded[(size_t)(found - encoded)];
                break;
            }
            case 'u': {
                if (input + 4U >= token->end) return -1;
                uint32_t codepoint = 0U;
                for (size_t offset = 1U; offset <= 4U; ++offset) {
                    uint32_t digit;
                    if (control_hex_digit(document->source[input + offset], &digit) != 0) return -1;
                    codepoint = codepoint * 16U + digit;
                }
                input += 4U;
                if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                    if (input + 6U >= token->end || document->source[input + 1U] != '\\' ||
                        document->source[input + 2U] != 'u') return -1;
                    uint32_t low = 0U;
                    for (size_t offset = 3U; offset <= 6U; ++offset) {
                        uint32_t digit;
                        if (control_hex_digit(document->source[input + offset], &digit) != 0) return -1;
                        low = low * 16U + digit;
                    }
                    if (low < 0xdc00U || low > 0xdfffU) return -1;
                    codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U) + low - 0xdc00U;
                    input += 6U;
                } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) {
                    return -1;
                }
                if ((codepoint == 0U && !allow_nul) ||
                    control_append_utf8(codepoint, out, out_size, &length) != 0) return -1;
                break;
            }
            default:
                return -1;
        }
    }
    out[length] = '\0';
    if (!control_utf8_valid(out, length, allow_nul)) return -1;
    if (decoded_length != NULL) *decoded_length = length;
    return 0;
}

static int control_decode_json_string(
    const struct asteriskd_json_document *document,
    size_t token_index,
    char *out,
    size_t out_size) {
    return control_decode_json_string_bytes(
        document, token_index, out, out_size, NULL, false);
}

static int control_decode_json_string_alloc(
    const struct asteriskd_json_document *document,
    size_t token_index,
    char **out,
    size_t *out_length) {
    if (document == NULL || token_index >= document->token_count || out == NULL || out_length == NULL ||
        document->tokens[token_index].type != ASTERISKD_JSON_STRING) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->end < token->start || token->end - token->start > ASTERISKD_CONTROL_MAX_PAYLOAD) return -1;
    size_t capacity = token->end - token->start + 1U;
    char *decoded = malloc(capacity);
    if (decoded == NULL) return -1;
    size_t length = 0U;
    if (control_decode_json_string_bytes(
            document, token_index, decoded, capacity, &length, true) != 0) {
        free(decoded);
        return -1;
    }
    if (!control_message_valid(decoded, length)) {
        free(decoded);
        return -1;
    }
    free(*out);
    *out = decoded;
    *out_length = length;
    return 0;
}

static bool control_token_string_equals(
    const struct asteriskd_json_document *document,
    size_t token,
    const char *value) {
    char decoded[128];
    return control_decode_json_string(document, token, decoded, sizeof(decoded)) == 0 && strcmp(decoded, value) == 0;
}

static int control_object_values(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *const *names,
    size_t name_count,
    size_t *values) {
    if (document == NULL || object >= document->token_count ||
        document->tokens[object].type != ASTERISKD_JSON_OBJECT ||
        document->tokens[object].child_count != name_count) return -1;
    for (size_t index = 0U; index < name_count; ++index) values[index] = CONTROL_TOKEN_NONE;
    size_t cursor = object + 1U;
    size_t pairs = 0U;
    while (true) {
        size_t key = control_next_direct(document, object, cursor);
        if (key == CONTROL_TOKEN_NONE) break;
        size_t value = control_next_direct(document, object, key + 1U);
        if (value == CONTROL_TOKEN_NONE || document->tokens[key].type != ASTERISKD_JSON_STRING) return -1;
        size_t found = CONTROL_TOKEN_NONE;
        for (size_t index = 0U; index < name_count; ++index) {
            if (control_token_string_equals(document, key, names[index])) {
                found = index;
                break;
            }
        }
        if (found == CONTROL_TOKEN_NONE || values[found] != CONTROL_TOKEN_NONE) return -1;
        values[found] = value;
        ++pairs;
        cursor = value + 1U;
    }
    return pairs == name_count ? 0 : -1;
}

static size_t control_count_named_values(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *name,
    size_t *last_value) {
    size_t count = 0U;
    size_t cursor = object + 1U;
    while (true) {
        size_t key = control_next_direct(document, object, cursor);
        if (key == CONTROL_TOKEN_NONE) break;
        size_t value = control_next_direct(document, object, key + 1U);
        if (value == CONTROL_TOKEN_NONE) return SIZE_MAX;
        if (control_token_string_equals(document, key, name)) {
            ++count;
            *last_value = value;
        }
        cursor = value + 1U;
    }
    return count;
}

static int control_parse_enum(
    const struct asteriskd_json_document *document,
    size_t token,
    const char *const *names,
    size_t count,
    int *out) {
    char decoded[128];
    if (control_decode_json_string(document, token, decoded, sizeof(decoded)) != 0) return -1;
    for (size_t index = 0U; index < count; ++index) {
        if (names[index] != NULL && strcmp(decoded, names[index]) == 0) {
            *out = (int)index;
            return 0;
        }
    }
    return -1;
}

static int control_parse_bool(
    const struct asteriskd_json_document *document,
    size_t token,
    bool *out) {
    if (token >= document->token_count) return -1;
    if (document->tokens[token].type == ASTERISKD_JSON_TRUE) {
        *out = true;
        return 0;
    }
    if (document->tokens[token].type == ASTERISKD_JSON_FALSE) {
        *out = false;
        return 0;
    }
    return -1;
}

static int control_parse_u64(
    const struct asteriskd_json_document *document,
    size_t token_index,
    uint64_t *out) {
    if (token_index >= document->token_count || document->tokens[token_index].type != ASTERISKD_JSON_NUMBER) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->start >= token->end) return -1;
    uint64_t value = 0U;
    for (size_t index = token->start; index < token->end; ++index) {
        char byte = document->source[index];
        if (byte < '0' || byte > '9') return -1;
        uint64_t digit = (uint64_t)(byte - '0');
        if (value > (UINT64_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    *out = value;
    return 0;
}

static int control_parse_int(
    const struct asteriskd_json_document *document,
    size_t token_index,
    int *out) {
    if (token_index >= document->token_count || document->tokens[token_index].type != ASTERISKD_JSON_NUMBER) return -1;
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->start >= token->end) return -1;
    size_t index = token->start;
    bool negative = document->source[index] == '-';
    if (negative && ++index == token->end) return -1;
    uint64_t value = 0U;
    for (; index < token->end; ++index) {
        char byte = document->source[index];
        if (byte < '0' || byte > '9') return -1;
        uint64_t digit = (uint64_t)(byte - '0');
        if (value > (uint64_t)INT_MAX + (negative ? 1U : 0U) ||
            value > (UINT64_MAX - digit) / 10U) return -1;
        value = value * 10U + digit;
    }
    if ((!negative && value > (uint64_t)INT_MAX) ||
        (negative && value > (uint64_t)INT_MAX + 1U)) return -1;
    *out = negative ? (value == (uint64_t)INT_MAX + 1U ? INT_MIN : -(int)value) : (int)value;
    return 0;
}

static bool control_token_is_null(const struct asteriskd_json_document *document, size_t token) {
    return token < document->token_count && document->tokens[token].type == ASTERISKD_JSON_NULL;
}

enum asteriskd_control_decode_outcome asteriskd_control_decode_request_payload(
    const char *payload,
    size_t payload_length,
    struct asteriskd_control_request *request) {
    if (request == NULL) return ASTERISKD_CONTROL_DECODE_SILENT_REJECT;
    memset(request, 0, sizeof(*request));
    if (payload == NULL || payload_length == 0U || payload_length > ASTERISKD_CONTROL_MAX_PAYLOAD) {
        return ASTERISKD_CONTROL_DECODE_SILENT_REJECT;
    }
    struct asteriskd_json_document document;
    char error[128];
    if (asteriskd_json_parse(payload, payload_length, &document, error, sizeof(error)) != 0 ||
        document.token_count == 0U || document.tokens[0].type != ASTERISKD_JSON_OBJECT) {
        asteriskd_json_document_destroy(&document);
        return ASTERISKD_CONTROL_DECODE_SILENT_REJECT;
    }
    size_t version_token = CONTROL_TOKEN_NONE;
    size_t request_id_token = CONTROL_TOKEN_NONE;
    size_t version_count = control_count_named_values(&document, 0U, "protocolVersion", &version_token);
    size_t request_id_count = control_count_named_values(&document, 0U, "requestId", &request_id_token);
    uint64_t version = 0U;
    bool trustworthy = version_count == 1U && request_id_count == 1U &&
        control_parse_u64(&document, version_token, &version) == 0 &&
        version == ASTERISKD_CONTROL_PROTOCOL_VERSION &&
        control_decode_json_string(
            &document, request_id_token, request->request_id, sizeof(request->request_id)) == 0 &&
        control_request_id_valid(request->request_id);
    if (!trustworthy) {
        memset(request, 0, sizeof(*request));
        asteriskd_json_document_destroy(&document);
        return ASTERISKD_CONTROL_DECODE_SILENT_REJECT;
    }
    static const char *const names[] = {"protocolVersion", "requestId", "method", "params"};
    size_t values[4];
    int method = 0;
    bool valid = control_object_values(&document, 0U, names, 4U, values) == 0 &&
        control_parse_u64(&document, values[0], &version) == 0 &&
        version == ASTERISKD_CONTROL_PROTOCOL_VERSION &&
        control_parse_enum(&document, values[2], control_method_names,
            ASTERISKD_CONTROL_METHOD_COUNT, &method) == 0 &&
        values[3] < document.token_count && document.tokens[values[3]].type == ASTERISKD_JSON_OBJECT &&
        document.tokens[values[3]].child_count == 0U;
    if (valid) request->method = (enum asteriskd_control_method)method;
    asteriskd_json_document_destroy(&document);
    return valid ? ASTERISKD_CONTROL_DECODE_VALID : ASTERISKD_CONTROL_DECODE_INVALID_REQUEST;
}

static int control_parse_nullable_int(
    const struct asteriskd_json_document *document,
    size_t token,
    bool *present,
    int *value) {
    if (control_token_is_null(document, token)) {
        *present = false;
        *value = 0;
        return 0;
    }
    if (control_parse_int(document, token, value) != 0) return -1;
    *present = true;
    return 0;
}

static int control_parse_error(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_control_error *error) {
    static const char *const names[] = {"code", "component", "message", "exitCode", "signal"};
    size_t values[5];
    int code;
    int component;
    memset(error, 0, sizeof(*error));
    if (control_object_values(document, object, names, 5U, values) != 0 ||
        control_parse_enum(document, values[0], control_failure_names,
            ASTERISKD_FAILURE_CODE_COUNT, &code) != 0 ||
        control_parse_enum(document, values[1], control_component_names,
            ASTERISKD_COMPONENT_COUNT, &component) != 0 ||
        control_decode_json_string_alloc(
            document, values[2], &error->message, &error->message_length) != 0 ||
        control_parse_nullable_int(document, values[3], &error->has_exit_code, &error->exit_code) != 0 ||
        control_parse_nullable_int(document, values[4], &error->has_signal, &error->signal) != 0) {
        asteriskd_control_error_destroy(error);
        return -1;
    }
    error->code = (enum asteriskd_failure_code)code;
    error->component = (enum asteriskd_component)component;
    if (!control_error_valid(error)) {
        asteriskd_control_error_destroy(error);
        return -1;
    }
    return 0;
}

static int control_parse_snapshot(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_control_snapshot *snapshot) {
    static const char *const names[] = {
        "phase", "owner", "coreType", "mode", "supervisorPid", "corePid", "helperType", "helperPid",
        "matcherConfigured", "matcherActive", "rules", "network", "error",
    };
    static const char *const rule_names[] = {"active", "generation", "categories"};
    static const char *const network_names[] = {"ipv4Ready", "ipv6Enabled", "ipv6Ready"};
    size_t values[13];
    size_t rule_values[3];
    size_t network_values[3];
    int phase;
    int owner;
    int core;
    int mode;
    memset(snapshot, 0, sizeof(*snapshot));
    if (control_object_values(document, object, names, 13U, values) != 0 ||
        control_parse_enum(document, values[0], control_phase_names, ASTERISKD_PHASE_COUNT, &phase) != 0 ||
        control_parse_enum(document, values[1], control_owner_names, 3U, &owner) != 0 ||
        control_parse_enum(document, values[2], control_core_names, 3U, &core) != 0 ||
        control_parse_enum(document, values[3], control_mode_names, 5U, &mode) != 0 ||
        control_parse_int(document, values[4], &snapshot->supervisor_pid) != 0 ||
        control_parse_nullable_int(document, values[5], &snapshot->has_core_pid, &snapshot->core_pid) != 0 ||
        control_parse_nullable_int(document, values[7], &snapshot->has_helper_pid, &snapshot->helper_pid) != 0 ||
        control_parse_bool(document, values[8], &snapshot->matcher_configured) != 0 ||
        control_parse_bool(document, values[9], &snapshot->matcher_active) != 0 ||
        control_object_values(document, values[10], rule_names, 3U, rule_values) != 0 ||
        control_parse_bool(document, rule_values[0], &snapshot->rules.active) != 0 ||
        control_parse_u64(document, rule_values[1], &snapshot->rules.generation) != 0 ||
        rule_values[2] >= document->token_count || document->tokens[rule_values[2]].type != ASTERISKD_JSON_ARRAY ||
        control_object_values(document, values[11], network_names, 3U, network_values) != 0 ||
        control_parse_bool(document, network_values[0], &snapshot->network.ipv4_ready) != 0 ||
        control_parse_bool(document, network_values[1], &snapshot->network.ipv6_enabled) != 0 ||
        control_parse_bool(document, network_values[2], &snapshot->network.ipv6_ready) != 0) return -1;
    snapshot->phase = (enum asteriskd_phase)phase;
    snapshot->owner = (enum asteriskd_owner)owner;
    snapshot->core_type = (enum asteriskd_core_type)core;
    snapshot->mode = (enum asteriskd_mode)mode;
    if (control_token_is_null(document, values[6])) {
        snapshot->helper_type = ASTERISKD_HELPER_NONE;
    } else {
        int helper;
        if (control_parse_enum(document, values[6], control_helper_names, 3U, &helper) != 0 || helper == 0) return -1;
        snapshot->helper_type = (enum asteriskd_helper_type)helper;
    }
    int previous_category = -1;
    size_t cursor = rule_values[2] + 1U;
    for (size_t index = 0U; index < document->tokens[rule_values[2]].child_count; ++index) {
        size_t token = control_next_direct(document, rule_values[2], cursor);
        int category;
        if (token == CONTROL_TOKEN_NONE || control_parse_enum(document, token, control_category_names,
            ASTERISKD_RULE_CATEGORY_COUNT, &category) != 0 || category <= previous_category) return -1;
        snapshot->rules.categories |= ASTERISKD_RULE_CATEGORY_BIT(category);
        previous_category = category;
        cursor = token + 1U;
    }
    if (control_token_is_null(document, values[12])) {
        snapshot->has_error = false;
    } else {
        snapshot->has_error = true;
        if (control_parse_error(document, values[12], &snapshot->error) != 0) return -1;
    }
    return asteriskd_control_snapshot_valid(snapshot) ? 0 : -1;
}

static int control_parse_payload(
    const char *payload,
    size_t payload_length,
    struct asteriskd_json_document *document) {
    if (payload == NULL || document == NULL || payload_length == 0U ||
        payload_length > ASTERISKD_CONTROL_MAX_PAYLOAD) return -1;
    char error[128];
    if (asteriskd_json_parse(payload, payload_length, document, error, sizeof(error)) != 0) return -1;
    if (document->token_count == 0U || document->tokens[0].type != ASTERISKD_JSON_OBJECT) {
        asteriskd_json_document_destroy(document);
        return -1;
    }
    return 0;
}

int asteriskd_control_decode_response_payload(
    const char *payload,
    size_t payload_length,
    struct asteriskd_control_response *response) {
    if (response == NULL) return -1;
    memset(response, 0, sizeof(*response));
    struct asteriskd_json_document document;
    if (control_parse_payload(payload, payload_length, &document) != 0) return -1;
    static const char *const root_names[] = {"protocolVersion", "requestId", "result"};
    static const char *const result_names[] = {"code", "snapshot", "message"};
    size_t root_values[3];
    size_t result_values[3];
    uint64_t version;
    int code;
    int result = -1;
    if (control_object_values(&document, 0U, root_names, 3U, root_values) != 0 ||
        control_parse_u64(&document, root_values[0], &version) != 0 ||
        version != ASTERISKD_CONTROL_PROTOCOL_VERSION ||
        control_decode_json_string(&document, root_values[1], response->request_id, sizeof(response->request_id)) != 0 ||
        !control_request_id_valid(response->request_id) ||
        control_object_values(&document, root_values[2], result_names, 3U, result_values) != 0 ||
        control_parse_enum(&document, result_values[0], control_result_names,
            ASTERISKD_CONTROL_RESULT_CODE_COUNT, &code) != 0) goto done;
    response->result.code = (enum asteriskd_control_result_code)code;
    if (control_token_is_null(&document, result_values[1])) {
        response->result.has_snapshot = false;
    } else {
        response->result.has_snapshot = true;
        if (control_parse_snapshot(&document, result_values[1], &response->result.snapshot) != 0) goto done;
    }
    if (control_token_is_null(&document, result_values[2])) {
        response->result.has_message = false;
    } else {
        response->result.has_message = true;
        if (control_decode_json_string_alloc(
                &document, result_values[2], &response->result.message,
                &response->result.message_length) != 0) goto done;
    }
    if (!asteriskd_control_result_valid(&response->result)) goto done;
    result = 0;
done:
    asteriskd_json_document_destroy(&document);
    if (result != 0) asteriskd_control_response_destroy(response);
    return result;
}

int asteriskd_control_decode_event_payload(
    const char *payload,
    size_t payload_length,
    struct asteriskd_control_event *event) {
    if (event == NULL) return -1;
    memset(event, 0, sizeof(*event));
    struct asteriskd_json_document document;
    if (control_parse_payload(payload, payload_length, &document) != 0) return -1;
    static const char *const root_names[] = {"protocolVersion", "event"};
    static const char *const event_names[] = {"sequence", "type", "snapshot", "details"};
    size_t root_values[2];
    size_t event_values[4];
    uint64_t version;
    int type;
    int result = -1;
    if (control_object_values(&document, 0U, root_names, 2U, root_values) != 0 ||
        control_parse_u64(&document, root_values[0], &version) != 0 ||
        version != ASTERISKD_CONTROL_PROTOCOL_VERSION ||
        control_object_values(&document, root_values[1], event_names, 4U, event_values) != 0 ||
        control_parse_u64(&document, event_values[0], &event->sequence) != 0 ||
        control_parse_enum(&document, event_values[1], control_event_names,
            ASTERISKD_CONTROL_EVENT_TYPE_COUNT, &type) != 0 ||
        control_parse_snapshot(&document, event_values[2], &event->snapshot) != 0) goto done;
    event->type = (enum asteriskd_control_event_type)type;
    if (control_token_is_null(&document, event_values[3])) {
        event->has_details = false;
    } else {
        event->has_details = true;
        if (control_parse_error(&document, event_values[3], &event->details) != 0) goto done;
    }
    if (!control_event_valid(event)) goto done;
    result = 0;
done:
    asteriskd_json_document_destroy(&document);
    if (result != 0) asteriskd_control_event_destroy(event);
    return result;
}

static bool control_client_backend_complete(
    const struct asteriskd_control_client_backend *backend) {
    return backend != NULL && backend->monotonic_milliseconds != NULL &&
        backend->connect_abstract != NULL && backend->finish_connect != NULL &&
        backend->wait_ready != NULL && backend->read_fd != NULL &&
        backend->write_fd != NULL && backend->close_fd != NULL;
}

static enum asteriskd_control_client_result control_client_wait(
    const struct asteriskd_control_client_backend *backend,
    void *context,
    int fd,
    bool want_read,
    bool want_write,
    uint64_t deadline) {
    for (;;) {
        bool readable = false;
        bool writable = false;
        enum asteriskd_control_wait_result waited = backend->wait_ready(
            context, fd, want_read, want_write, deadline, &readable, &writable);
        if (waited == ASTERISKD_CONTROL_WAIT_INTERRUPTED) continue;
        if (waited == ASTERISKD_CONTROL_WAIT_TIMEOUT) return ASTERISKD_CONTROL_CLIENT_TIMEOUT;
        if (waited != ASTERISKD_CONTROL_WAIT_READY ||
            (want_read && !readable) || (want_write && !writable)) {
            return ASTERISKD_CONTROL_CLIENT_IO_ERROR;
        }
        return ASTERISKD_CONTROL_CLIENT_OK;
    }
}

static enum asteriskd_control_client_result control_client_close_result(
    const struct asteriskd_control_client_backend *backend,
    void *context,
    int *fd,
    enum asteriskd_control_client_result result,
    struct asteriskd_control_response *response) {
    if (fd != NULL && *fd >= 0) {
        int closing = *fd;
        *fd = -1;
        if (backend->close_fd(context, closing) != 0) result = ASTERISKD_CONTROL_CLIENT_IO_ERROR;
    }
    if (result != ASTERISKD_CONTROL_CLIENT_OK && response != NULL) {
        asteriskd_control_response_destroy(response);
    }
    return result;
}

enum asteriskd_control_client_result asteriskd_control_client_run_with_backend(
    enum asteriskd_control_method method,
    const char *request_id,
    const struct asteriskd_control_client_backend *backend,
    void *context,
    asteriskd_control_line_sink sink,
    void *sink_context,
    struct asteriskd_control_response *response) {
    if (response != NULL) memset(response, 0, sizeof(*response));
    if (response == NULL || !control_client_backend_complete(backend) ||
        method < 0 || method >= ASTERISKD_CONTROL_METHOD_COUNT ||
        !control_request_id_valid(request_id)) return ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR;
    uint64_t started = 0U;
    if (backend->monotonic_milliseconds(context, &started) != 0) {
        return ASTERISKD_CONTROL_CLIENT_IO_ERROR;
    }
    uint64_t initial_deadline = control_deadline_after(
        started, ASTERISKD_CONTROL_REQUEST_TIMEOUT_MILLIS);
    int fd = -1;
    enum asteriskd_control_connect_result connected = backend->connect_abstract(
        context, control_abstract_name, sizeof(control_abstract_name) - 1U, &fd);
    if (connected == ASTERISKD_CONTROL_CONNECT_ABSENT) {
        return control_client_close_result(
            backend, context, &fd, ASTERISKD_CONTROL_CLIENT_ABSENT, response);
    }
    if (connected == ASTERISKD_CONTROL_CONNECT_IN_PROGRESS) {
        enum asteriskd_control_client_result waited = control_client_wait(
            backend, context, fd, false, true, initial_deadline);
        if (waited != ASTERISKD_CONTROL_CLIENT_OK) {
            return control_client_close_result(backend, context, &fd, waited, response);
        }
        connected = backend->finish_connect(context, fd);
    }
    if (connected != ASTERISKD_CONTROL_CONNECT_OK || fd < 0) {
        enum asteriskd_control_client_result result =
            connected == ASTERISKD_CONTROL_CONNECT_ABSENT
                ? ASTERISKD_CONTROL_CLIENT_ABSENT : ASTERISKD_CONTROL_CLIENT_IO_ERROR;
        return control_client_close_result(backend, context, &fd, result, response);
    }

    struct asteriskd_control_request request;
    memset(&request, 0, sizeof(request));
    memcpy(request.request_id, request_id, strlen(request_id) + 1U);
    request.method = method;
    char request_line[256U];
    size_t request_length = 0U;
    if (asteriskd_control_encode_request_line(
            &request, request_line, sizeof(request_line), &request_length) != 0) {
        return control_client_close_result(
            backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
    }
    size_t written = 0U;
    while (written < request_length) {
        ptrdiff_t count = backend->write_fd(
            context, fd, request_line + written, request_length - written);
        if (count == ASTERISKD_CONTROL_BACKEND_INTERRUPTED) continue;
        if (count == ASTERISKD_CONTROL_BACKEND_AGAIN || count == 0) {
            enum asteriskd_control_client_result waited = control_client_wait(
                backend, context, fd, false, true, initial_deadline);
            if (waited != ASTERISKD_CONTROL_CLIENT_OK) {
                return control_client_close_result(backend, context, &fd, waited, response);
            }
            continue;
        }
        if (count < 0 || (size_t)count > request_length - written) {
            return control_client_close_result(
                backend, context, &fd, ASTERISKD_CONTROL_CLIENT_IO_ERROR, response);
        }
        written += (size_t)count;
    }

    char line[ASTERISKD_CONTROL_MAX_PAYLOAD + 1U];
    size_t line_length = 0U;
    bool initial_received = false;
    bool watch_stream = false;
    bool final_event_received = false;
    uint64_t last_sequence = 0U;
    for (;;) {
        uint64_t read_deadline = initial_received || method == ASTERISKD_CONTROL_METHOD_STOP ||
            method == ASTERISKD_CONTROL_METHOD_SHUTDOWN
            ? UINT64_MAX : initial_deadline;
        enum asteriskd_control_client_result waited = control_client_wait(
            backend, context, fd, true, false, read_deadline);
        if (waited != ASTERISKD_CONTROL_CLIENT_OK) {
            return control_client_close_result(backend, context, &fd, waited, response);
        }
        unsigned char buffer[4096U];
        ptrdiff_t count = backend->read_fd(context, fd, buffer, sizeof(buffer));
        if (count == ASTERISKD_CONTROL_BACKEND_INTERRUPTED ||
            count == ASTERISKD_CONTROL_BACKEND_AGAIN) continue;
        if (count < 0 || (size_t)count > sizeof(buffer)) {
            return control_client_close_result(
                backend, context, &fd, ASTERISKD_CONTROL_CLIENT_IO_ERROR, response);
        }
        if (count == 0) {
            enum asteriskd_control_client_result result =
                line_length == 0U && initial_received &&
                (!watch_stream || final_event_received)
                    ? ASTERISKD_CONTROL_CLIENT_OK
                    : ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR;
            return control_client_close_result(backend, context, &fd, result, response);
        }
        for (size_t index = 0U; index < (size_t)count; ++index) {
            if (final_event_received) {
                return control_client_close_result(
                    backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
            }
            if (buffer[index] != '\n') {
                if (line_length >= ASTERISKD_CONTROL_MAX_PAYLOAD) {
                    return control_client_close_result(
                        backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
                }
                line[line_length++] = (char)buffer[index];
                continue;
            }
            if (!initial_received) {
                struct asteriskd_control_response decoded;
                memset(&decoded, 0, sizeof(decoded));
                if (asteriskd_control_decode_response_payload(
                        line, line_length, &decoded) != 0 ||
                    strcmp(decoded.request_id, request_id) != 0) {
                    asteriskd_control_response_destroy(&decoded);
                    return control_client_close_result(
                        backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
                }
                line[line_length] = '\n';
                int sink_result = sink == NULL
                    ? ASTERISKD_CONTROL_SINK_CONTINUE
                    : sink(sink_context, line, line_length + 1U);
                if (sink_result < ASTERISKD_CONTROL_SINK_CONTINUE ||
                    sink_result > ASTERISKD_CONTROL_SINK_STOP) {
                    asteriskd_control_response_destroy(&decoded);
                    return control_client_close_result(
                        backend, context, &fd, ASTERISKD_CONTROL_CLIENT_IO_ERROR, response);
                }
                *response = decoded;
                memset(&decoded, 0, sizeof(decoded));
                initial_received = true;
                watch_stream = method == ASTERISKD_CONTROL_METHOD_WATCH &&
                    response->result.code == ASTERISKD_CONTROL_RESULT_OK;
                line_length = 0U;
                if (sink_result == ASTERISKD_CONTROL_SINK_STOP) {
                    return control_client_close_result(
                        backend, context, &fd, ASTERISKD_CONTROL_CLIENT_OK, response);
                }
                if (!watch_stream) {
                    if (index + 1U != (size_t)count) {
                        return control_client_close_result(
                            backend, context, &fd,
                            ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
                    }
                    return control_client_close_result(
                        backend, context, &fd, ASTERISKD_CONTROL_CLIENT_OK, response);
                }
                continue;
            }
            struct asteriskd_control_event event;
            memset(&event, 0, sizeof(event));
            if (asteriskd_control_decode_event_payload(line, line_length, &event) != 0 ||
                event.sequence <= last_sequence) {
                asteriskd_control_event_destroy(&event);
                return control_client_close_result(
                    backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
            }
            last_sequence = event.sequence;
            bool terminal = event.type == ASTERISKD_CONTROL_EVENT_STOPPED ||
                event.type == ASTERISKD_CONTROL_EVENT_FAILED;
            if ((event.type == ASTERISKD_CONTROL_EVENT_STOPPED &&
                    event.snapshot.phase != ASTERISKD_PHASE_STOPPED) ||
                (event.type == ASTERISKD_CONTROL_EVENT_FAILED &&
                    event.snapshot.phase != ASTERISKD_PHASE_FAILED)) {
                asteriskd_control_event_destroy(&event);
                return control_client_close_result(
                    backend, context, &fd, ASTERISKD_CONTROL_CLIENT_PROTOCOL_ERROR, response);
            }
            line[line_length] = '\n';
            int sink_result = sink == NULL
                ? ASTERISKD_CONTROL_SINK_CONTINUE
                : sink(sink_context, line, line_length + 1U);
            if (sink_result < ASTERISKD_CONTROL_SINK_CONTINUE ||
                sink_result > ASTERISKD_CONTROL_SINK_STOP) {
                asteriskd_control_event_destroy(&event);
                return control_client_close_result(
                    backend, context, &fd, ASTERISKD_CONTROL_CLIENT_IO_ERROR, response);
            }
            asteriskd_control_event_destroy(&event);
            final_event_received = terminal;
            line_length = 0U;
            if (sink_result == ASTERISKD_CONTROL_SINK_STOP) {
                return control_client_close_result(
                    backend, context, &fd, ASTERISKD_CONTROL_CLIENT_OK, response);
            }
        }
    }
}

#if defined(__linux__) || defined(__ANDROID__)
static int control_system_monotonic_milliseconds(void *context, uint64_t *milliseconds) {
    (void)context;
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0 || milliseconds == NULL) return -1;
    uint64_t seconds = (uint64_t)value.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)value.tv_nsec / UINT64_C(1000000)) / UINT64_C(1000)) {
        *milliseconds = UINT64_MAX;
    } else {
        *milliseconds = seconds * UINT64_C(1000) +
            (uint64_t)value.tv_nsec / UINT64_C(1000000);
    }
    return 0;
}

static enum asteriskd_control_connect_result control_system_connect_result(int error) {
    if (error == 0) return ASTERISKD_CONTROL_CONNECT_OK;
    if (error == EINPROGRESS || error == EAGAIN || error == EALREADY) {
        return ASTERISKD_CONTROL_CONNECT_IN_PROGRESS;
    }
    if (error == ENOENT || error == ECONNREFUSED) return ASTERISKD_CONTROL_CONNECT_ABSENT;
    return ASTERISKD_CONTROL_CONNECT_ERROR;
}

static enum asteriskd_control_connect_result control_system_connect_abstract(
    void *context,
    const unsigned char *name,
    size_t name_length,
    int *fd) {
    (void)context;
    int connected_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd != NULL) *fd = connected_fd;
    if (connected_fd < 0 || fd == NULL || name == NULL || name_length == 0U) {
        return ASTERISKD_CONTROL_CONNECT_ERROR;
    }
    struct sockaddr_un address;
    if (name_length > sizeof(address.sun_path)) return ASTERISKD_CONTROL_CONNECT_ERROR;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, name, name_length);
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_length);
    if (connect(connected_fd, (const struct sockaddr *)&address, length) == 0) {
        return ASTERISKD_CONTROL_CONNECT_OK;
    }
    return control_system_connect_result(errno);
}

static enum asteriskd_control_connect_result control_system_finish_connect(
    void *context,
    int fd) {
    (void)context;
    int error = 0;
    socklen_t length = (socklen_t)sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 ||
        length != sizeof(error)) return ASTERISKD_CONTROL_CONNECT_ERROR;
    return control_system_connect_result(error);
}

static enum asteriskd_control_wait_result control_system_wait_ready(
    void *context,
    int fd,
    bool want_read,
    bool want_write,
    uint64_t deadline,
    bool *readable,
    bool *writable) {
    (void)context;
    if (readable == NULL || writable == NULL || want_read == want_write) {
        return ASTERISKD_CONTROL_WAIT_ERROR;
    }
    *readable = false;
    *writable = false;
    int timeout = -1;
    if (deadline != UINT64_MAX) {
        uint64_t now = 0U;
        if (control_system_monotonic_milliseconds(NULL, &now) != 0) {
            return ASTERISKD_CONTROL_WAIT_ERROR;
        }
        if (now > deadline) return ASTERISKD_CONTROL_WAIT_TIMEOUT;
        uint64_t remaining = deadline - now;
        timeout = remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
    }
    struct pollfd descriptor = {
        .fd = fd,
        .events = (short)(want_read ? POLLIN : POLLOUT),
    };
    int result = poll(&descriptor, 1U, timeout);
    if (result < 0) return errno == EINTR
        ? ASTERISKD_CONTROL_WAIT_INTERRUPTED : ASTERISKD_CONTROL_WAIT_ERROR;
    if (result == 0) return ASTERISKD_CONTROL_WAIT_TIMEOUT;
    if ((descriptor.revents & POLLNVAL) != 0) return ASTERISKD_CONTROL_WAIT_ERROR;
    if (want_read && (descriptor.revents & (POLLIN | POLLHUP | POLLERR)) != 0) *readable = true;
    if (want_write && (descriptor.revents & (POLLOUT | POLLHUP | POLLERR)) != 0) *writable = true;
    return (*readable || *writable)
        ? ASTERISKD_CONTROL_WAIT_READY : ASTERISKD_CONTROL_WAIT_ERROR;
}

static const struct asteriskd_control_client_backend control_system_client_backend = {
    .monotonic_milliseconds = control_system_monotonic_milliseconds,
    .connect_abstract = control_system_connect_abstract,
    .finish_connect = control_system_finish_connect,
    .wait_ready = control_system_wait_ready,
    .read_fd = control_system_read,
    .write_fd = control_system_write,
    .close_fd = control_system_close,
};
#endif

enum asteriskd_control_client_result asteriskd_control_client_run(
    enum asteriskd_control_method method,
    const char *request_id,
    asteriskd_control_line_sink sink,
    void *sink_context,
    struct asteriskd_control_response *response) {
#if defined(__linux__) || defined(__ANDROID__)
    return asteriskd_control_client_run_with_backend(
        method, request_id, &control_system_client_backend, NULL,
        sink, sink_context, response);
#else
    if (response != NULL) memset(response, 0, sizeof(*response));
    (void)method;
    (void)request_id;
    (void)sink;
    (void)sink_context;
    return ASTERISKD_CONTROL_CLIENT_IO_ERROR;
#endif
}

static bool control_cli_backend_complete(const struct asteriskd_cli_backend *backend) {
    return backend != NULL && backend->effective_uid != NULL &&
        backend->control_client != NULL &&
        backend->run_start != NULL && backend->run_monitor != NULL &&
        backend->write_stdout != NULL && backend->write_stderr != NULL;
}

struct control_cli_sink {
    const struct asteriskd_cli_backend *backend;
    void *context;
    size_t lines;
    bool until_running;
};

static bool control_cli_watch_complete(
    bool initial,
    const char *line,
    size_t length) {
    if (length == 0U || line[length - 1U] != '\n') return false;
    if (initial) {
        struct asteriskd_control_response response;
        memset(&response, 0, sizeof(response));
        if (asteriskd_control_decode_response_payload(line, length - 1U, &response) != 0) {
            return false;
        }
        bool complete = response.result.has_snapshot &&
            (response.result.snapshot.phase == ASTERISKD_PHASE_RUNNING ||
                response.result.snapshot.phase == ASTERISKD_PHASE_FAILED ||
                response.result.snapshot.phase == ASTERISKD_PHASE_STOPPED);
        asteriskd_control_response_destroy(&response);
        return complete;
    }
    struct asteriskd_control_event event;
    memset(&event, 0, sizeof(event));
    if (asteriskd_control_decode_event_payload(line, length - 1U, &event) != 0) return false;
    bool complete = event.snapshot.phase == ASTERISKD_PHASE_RUNNING ||
        event.snapshot.phase == ASTERISKD_PHASE_FAILED ||
        event.snapshot.phase == ASTERISKD_PHASE_STOPPED;
    asteriskd_control_event_destroy(&event);
    return complete;
}

static int control_cli_line_sink(void *context, const char *line, size_t length) {
    struct control_cli_sink *sink = context;
    if (sink == NULL || sink->backend->write_stdout(
            sink->context, line, length) != 0) return ASTERISKD_CONTROL_SINK_ERROR;
    bool initial = sink->lines == 0U;
    ++sink->lines;
    return sink->until_running && control_cli_watch_complete(initial, line, length)
        ? ASTERISKD_CONTROL_SINK_STOP : ASTERISKD_CONTROL_SINK_CONTINUE;
}

static int control_cli_write_response(
    const struct asteriskd_cli_backend *backend,
    void *context,
    const char *request_id,
    enum asteriskd_control_result_code code,
    const struct asteriskd_control_snapshot *snapshot,
    const char *message) {
    struct asteriskd_control_response response;
    memset(&response, 0, sizeof(response));
    memcpy(response.request_id, request_id, strlen(request_id) + 1U);
    response.result.code = code;
    if (snapshot != NULL) {
        response.result.has_snapshot = true;
        if (asteriskd_control_snapshot_copy(&response.result.snapshot, snapshot) != 0) goto failed;
    }
    if (message != NULL && asteriskd_control_result_set_message(
            &response.result, message, strlen(message)) != 0) goto failed;
    char *line = malloc(ASTERISKD_CONTROL_MAX_PAYLOAD + 2U);
    if (line == NULL) goto failed;
    size_t length = 0U;
    if (asteriskd_control_encode_response_line(
            &response, line, ASTERISKD_CONTROL_MAX_PAYLOAD + 2U, &length) != 0 ||
        backend->write_stdout(context, line, length) != 0) {
        free(line);
        goto failed;
    }
    free(line);
    asteriskd_control_response_destroy(&response);
    return asteriskd_control_result_exit_code(code);
failed:
    asteriskd_control_response_destroy(&response);
    return 1;
}

static int control_cli_usage(
    const struct asteriskd_cli_backend *backend,
    void *context) {
    static const char usage[] =
        "usage: asteriskd start|monitor --config ABSOLUTE_PATH | status | stop | shutdown | "
        "watch [--until-running]\n";
    (void)backend->write_stderr(context, usage, sizeof(usage) - 1U);
    return 64;
}

static int control_cli_run_control(
    const struct asteriskd_cli_backend *backend,
    void *context,
    enum asteriskd_control_method method,
    const char *request_id,
    bool until_running) {
    struct control_cli_sink sink = {
        .backend = backend,
        .context = context,
        .until_running = until_running,
    };
    struct asteriskd_control_response response;
    memset(&response, 0, sizeof(response));
    enum asteriskd_control_client_result result = backend->control_client(
        context, method, request_id, control_cli_line_sink, &sink, &response);
    if (result == ASTERISKD_CONTROL_CLIENT_OK) {
        int exit_code = asteriskd_control_result_exit_code(response.result.code);
        asteriskd_control_response_destroy(&response);
        return exit_code;
    }
    asteriskd_control_response_destroy(&response);
    if (sink.lines != 0U) return 1;
    if (result == ASTERISKD_CONTROL_CLIENT_ABSENT) {
        return control_cli_write_response(
            backend, context, request_id, ASTERISKD_CONTROL_RESULT_NOT_RUNNING,
            NULL, "supervisor is not running");
    }
    return control_cli_write_response(
        backend, context, request_id, ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
        NULL, result == ASTERISKD_CONTROL_CLIENT_TIMEOUT
            ? "control request timed out" : "control request failed");
}

int asteriskd_cli_main_with_backend(
    int argc,
    const char *const *argv,
    const struct asteriskd_cli_backend *backend,
    void *context) {
    if (!control_cli_backend_complete(backend)) return 1;
    struct asteriskd_cli_invocation invocation;
    if (asteriskd_cli_parse(argc, argv, &invocation) != 0) {
        return control_cli_usage(backend, context);
    }
    if (backend->effective_uid(context) != 0U) {
        const char *request_id = invocation.command == ASTERISKD_CLI_START ? "start" :
            invocation.command == ASTERISKD_CLI_MONITOR ? "monitor" :
            invocation.command == ASTERISKD_CLI_STATUS ? "status" :
            invocation.command == ASTERISKD_CLI_STOP ? "stop" :
            invocation.command == ASTERISKD_CLI_SHUTDOWN ? "shutdown" : "watch";
        return control_cli_write_response(
            backend, context, request_id, ASTERISKD_CONTROL_RESULT_PERMISSION_DENIED,
            NULL, "root permission required");
    }
    if (invocation.command == ASTERISKD_CLI_STATUS) {
        return control_cli_run_control(
            backend, context, ASTERISKD_CONTROL_METHOD_STATUS, "status", false);
    }
    if (invocation.command == ASTERISKD_CLI_STOP) {
        return control_cli_run_control(
            backend, context, ASTERISKD_CONTROL_METHOD_STOP, "stop", false);
    }
    if (invocation.command == ASTERISKD_CLI_SHUTDOWN) {
        return control_cli_run_control(
            backend, context, ASTERISKD_CONTROL_METHOD_SHUTDOWN, "shutdown", false);
    }
    if (invocation.command == ASTERISKD_CLI_WATCH) {
        return control_cli_run_control(
            backend, context, ASTERISKD_CONTROL_METHOD_WATCH, "watch",
            invocation.watch_until_running);
    }

    if (invocation.command == ASTERISKD_CLI_START ||
        invocation.command == ASTERISKD_CLI_MONITOR) {
        bool has_early_result = false;
        struct asteriskd_control_result early_result;
        memset(&early_result, 0, sizeof(early_result));
        int status = (invocation.command == ASTERISKD_CLI_START
            ? backend->run_start : backend->run_monitor)(
                context, invocation.path, &has_early_result, &early_result);
        const char *request_id = invocation.command == ASTERISKD_CLI_START ? "start" : "monitor";
        if (has_early_result && asteriskd_control_result_valid(&early_result)) {
            status = control_cli_write_response(
                backend, context, request_id, early_result.code,
                early_result.has_snapshot ? &early_result.snapshot : NULL,
                early_result.has_message ? early_result.message : NULL);
        } else if (has_early_result || status < 0) {
            status = control_cli_write_response(
                backend, context, request_id, ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
                NULL, "runtime start failed before initialization");
        }
        asteriskd_control_result_destroy(&early_result);
        return status;
    }

    return 1;
}

struct control_server_client {
    int fd;
    bool active;
    bool request_processed;
    bool watch;
    bool pending_stop;
    bool close_after_flush;
    size_t watch_initial_remaining;
    char request_id[ASTERISKD_CONTROL_MAX_REQUEST_ID + 1U];
    unsigned char input[ASTERISKD_CONTROL_MAX_PAYLOAD + 1U];
    size_t input_length;
    char *output;
    size_t output_start;
    size_t output_length;
    uint64_t request_deadline;
    uint64_t last_write_progress;
};

struct asteriskd_control_server {
    int listener_fd;
    bool accepting;
    const struct asteriskd_control_transport_backend *transport;
    void *transport_context;
    struct asteriskd_control_callbacks callbacks;
    struct control_server_client clients[ASTERISKD_CONTROL_MAX_CLIENTS];
    uint64_t sequence;
};

static uint64_t control_deadline_after(uint64_t now, uint64_t delay) {
    return now > UINT64_MAX - delay ? UINT64_MAX : now + delay;
}

static bool control_transport_complete(
    const struct asteriskd_control_transport_backend *transport) {
    return transport != NULL && transport->accept_client != NULL &&
        transport->read_client != NULL && transport->write_client != NULL &&
        transport->close_fd != NULL;
}

static void control_server_client_close(
    struct asteriskd_control_server *server,
    struct control_server_client *client) {
    if (server == NULL || client == NULL || !client->active) return;
    int fd = client->fd;
    char *output = client->output;
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    free(output);
    (void)server->transport->close_fd(server->transport_context, fd);
}

static size_t control_server_active_clients(
    const struct asteriskd_control_server *server) {
    size_t count = 0U;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        if (server->clients[index].active) ++count;
    }
    return count;
}

static struct control_server_client *control_server_find_client(
    struct asteriskd_control_server *server,
    int fd) {
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        if (server->clients[index].active && server->clients[index].fd == fd) {
            return &server->clients[index];
        }
    }
    return NULL;
}

static struct control_server_client *control_server_free_client(
    struct asteriskd_control_server *server) {
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        if (!server->clients[index].active) return &server->clients[index];
    }
    return NULL;
}

static int control_server_enqueue(
    struct asteriskd_control_server *server,
    struct control_server_client *client,
    const char *bytes,
    size_t length,
    uint64_t now) {
    (void)server;
    if (client == NULL || !client->active || bytes == NULL || length == 0U ||
        length > ASTERISKD_CONTROL_WATCH_QUEUE_CAPACITY - client->output_length) return -1;
    if (client->output == NULL) {
        client->output = malloc(ASTERISKD_CONTROL_WATCH_QUEUE_CAPACITY);
        if (client->output == NULL) return -1;
    }
    if (client->output_start != 0U &&
        client->output_start + client->output_length + length >
            ASTERISKD_CONTROL_WATCH_QUEUE_CAPACITY) {
        memmove(client->output, client->output + client->output_start,
            client->output_length);
        client->output_start = 0U;
    }
    if (client->output_start + client->output_length + length >
        ASTERISKD_CONTROL_WATCH_QUEUE_CAPACITY) return -1;
    bool was_empty = client->output_length == 0U;
    memcpy(client->output + client->output_start + client->output_length, bytes, length);
    client->output_length += length;
    if (was_empty) client->last_write_progress = now;
    return 0;
}

static int control_server_encode_response(
    struct control_server_client *client,
    enum asteriskd_control_result_code code,
    const struct asteriskd_control_snapshot *snapshot,
    const char *message,
    size_t message_length,
    char **line,
    size_t *line_length) {
    struct asteriskd_control_response response;
    memset(&response, 0, sizeof(response));
    memcpy(response.request_id, client->request_id,
        sizeof(response.request_id));
    response.result.code = code;
    if (snapshot != NULL) {
        response.result.has_snapshot = true;
        if (asteriskd_control_snapshot_copy(
                &response.result.snapshot, snapshot) != 0) goto failed;
    }
    if (message != NULL) {
        if (asteriskd_control_result_set_message(
                &response.result, message, message_length) != 0) goto failed;
    }
    char *encoded = malloc(ASTERISKD_CONTROL_MAX_PAYLOAD + 2U);
    if (encoded == NULL) goto failed;
    if (asteriskd_control_encode_response_line(
            &response, encoded, ASTERISKD_CONTROL_MAX_PAYLOAD + 2U,
            line_length) != 0) {
        free(encoded);
        goto failed;
    }
    *line = encoded;
    asteriskd_control_response_destroy(&response);
    return 0;
failed:
    asteriskd_control_response_destroy(&response);
    return -1;
}

static int control_server_queue_response(
    struct asteriskd_control_server *server,
    struct control_server_client *client,
    enum asteriskd_control_result_code code,
    const struct asteriskd_control_snapshot *snapshot,
    const char *message,
    uint64_t now,
    bool close_after_flush) {
    char *line = NULL;
    size_t line_length = 0U;
    size_t message_length = message == NULL ? 0U : strlen(message);
    if (control_server_encode_response(
            client, code, snapshot, message, message_length,
            &line, &line_length) != 0 ||
        control_server_enqueue(server, client, line, line_length, now) != 0) {
        free(line);
        return -1;
    }
    free(line);
    client->close_after_flush = close_after_flush;
    return 0;
}

static int control_server_snapshot(
    struct asteriskd_control_server *server,
    struct asteriskd_control_snapshot *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    if (server->callbacks.snapshot(
            server->callbacks.context, snapshot) != 0 ||
        !asteriskd_control_snapshot_valid(snapshot)) {
        asteriskd_control_snapshot_destroy(snapshot);
        return -1;
    }
    return 0;
}

static int control_server_process_request(
    struct asteriskd_control_server *server,
    struct control_server_client *client,
    uint64_t now) {
    struct asteriskd_control_request request;
    enum asteriskd_control_decode_outcome outcome =
        asteriskd_control_decode_request_payload(
            (const char *)client->input, client->input_length, &request);
    client->request_processed = true;
    if (outcome == ASTERISKD_CONTROL_DECODE_SILENT_REJECT) {
        control_server_client_close(server, client);
        return 0;
    }
    memcpy(client->request_id, request.request_id,
        sizeof(client->request_id));
    if (outcome == ASTERISKD_CONTROL_DECODE_INVALID_REQUEST) {
        if (control_server_queue_response(
                server, client, ASTERISKD_CONTROL_RESULT_INVALID_REQUEST,
                NULL, "invalid request", now, true) != 0) {
            control_server_client_close(server, client);
        }
        return 0;
    }
    if (request.method == ASTERISKD_CONTROL_METHOD_STOP) {
        int requested = server->callbacks.request_stop(server->callbacks.context);
        if (requested == 0) {
            client->pending_stop = true;
            return 0;
        }
        struct asteriskd_control_snapshot snapshot;
        bool has_snapshot = control_server_snapshot(server, &snapshot) == 0;
        if (requested > 0) {
            if (control_server_queue_response(
                    server, client, ASTERISKD_CONTROL_RESULT_OK,
                    has_snapshot ? &snapshot : NULL, NULL, now, true) != 0) {
                control_server_client_close(server, client);
            }
            if (has_snapshot) asteriskd_control_snapshot_destroy(&snapshot);
            return 0;
        }
        if (control_server_queue_response(
                server, client, ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
                has_snapshot ? &snapshot : NULL, "stop request failed", now, true) != 0) {
            control_server_client_close(server, client);
        }
        if (has_snapshot) asteriskd_control_snapshot_destroy(&snapshot);
        return 0;
    }
    if (request.method == ASTERISKD_CONTROL_METHOD_SHUTDOWN) {
        if (server->callbacks.request_shutdown(server->callbacks.context) == 0) {
            client->pending_stop = true;
            return 0;
        }
        struct asteriskd_control_snapshot snapshot;
        bool has_snapshot = control_server_snapshot(server, &snapshot) == 0;
        if (control_server_queue_response(
                server, client, ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
                has_snapshot ? &snapshot : NULL, "shutdown request failed", now, true) != 0) {
            control_server_client_close(server, client);
        }
        if (has_snapshot) asteriskd_control_snapshot_destroy(&snapshot);
        return 0;
    }
    struct asteriskd_control_snapshot snapshot;
    if (control_server_snapshot(server, &snapshot) != 0) {
        if (control_server_queue_response(
                server, client, ASTERISKD_CONTROL_RESULT_INTERNAL_ERROR,
                NULL, "snapshot unavailable", now, true) != 0) {
            control_server_client_close(server, client);
        }
        return 0;
    }
    if (control_server_queue_response(
            server, client, ASTERISKD_CONTROL_RESULT_OK, &snapshot,
            NULL, now, request.method != ASTERISKD_CONTROL_METHOD_WATCH) != 0) {
        asteriskd_control_snapshot_destroy(&snapshot);
        control_server_client_close(server, client);
        return 0;
    }
    client->watch = request.method == ASTERISKD_CONTROL_METHOD_WATCH;
    if (client->watch) client->watch_initial_remaining = client->output_length;
    asteriskd_control_snapshot_destroy(&snapshot);
    return 0;
}

static int control_server_read_client(
    struct asteriskd_control_server *server,
    struct control_server_client *client,
    uint64_t now) {
    unsigned char buffer[4096];
    while (client->active) {
        ptrdiff_t read_result = server->transport->read_client(
            server->transport_context, client->fd, buffer, sizeof(buffer));
        if (read_result == ASTERISKD_CONTROL_BACKEND_INTERRUPTED) continue;
        if (read_result == ASTERISKD_CONTROL_BACKEND_AGAIN) return 0;
        if (read_result <= 0 || (size_t)read_result > sizeof(buffer)) {
            control_server_client_close(server, client);
            return 0;
        }
        size_t count = (size_t)read_result;
        if (client->request_processed) {
            control_server_client_close(server, client);
            return 0;
        }
        for (size_t index = 0U; index < count; ++index) {
            if (buffer[index] == '\n') {
                if (index + 1U != count) {
                    control_server_client_close(server, client);
                    return 0;
                }
                return control_server_process_request(server, client, now);
            }
            if (client->input_length >= ASTERISKD_CONTROL_MAX_PAYLOAD) {
                control_server_client_close(server, client);
                return 0;
            }
            client->input[client->input_length++] = buffer[index];
        }
    }
    return 0;
}

static int control_server_write_client(
    struct asteriskd_control_server *server,
    struct control_server_client *client,
    uint64_t now) {
    while (client->active && client->output_length != 0U) {
        ptrdiff_t write_result = server->transport->write_client(
            server->transport_context, client->fd,
            client->output + client->output_start, client->output_length);
        if (write_result == ASTERISKD_CONTROL_BACKEND_INTERRUPTED) continue;
        if (write_result == ASTERISKD_CONTROL_BACKEND_AGAIN || write_result == 0) return 0;
        if (write_result < 0 || (size_t)write_result > client->output_length) {
            control_server_client_close(server, client);
            return 0;
        }
        size_t written = (size_t)write_result;
        client->output_start += written;
        client->output_length -= written;
        if (client->watch_initial_remaining != 0U) {
            if (written >= client->watch_initial_remaining) {
                client->watch_initial_remaining = 0U;
            } else {
                client->watch_initial_remaining -= written;
            }
        }
        client->last_write_progress = now;
        if (client->output_length == 0U) client->output_start = 0U;
    }
    if (client->active && client->output_length == 0U && client->close_after_flush) {
        control_server_client_close(server, client);
    }
    return 0;
}

static int control_server_accept_clients(
    struct asteriskd_control_server *server,
    uint64_t now) {
    while (server->accepting) {
        int fd = -1;
        uint32_t uid = UINT32_MAX;
        int accepted = server->transport->accept_client(
            server->transport_context, server->listener_fd, &fd, &uid);
        if (accepted != ASTERISKD_CONTROL_BACKEND_OK) {
            if (fd >= 0) {
                (void)server->transport->close_fd(server->transport_context, fd);
            }
            if (accepted == ASTERISKD_CONTROL_BACKEND_INTERRUPTED) continue;
            if (accepted == ASTERISKD_CONTROL_BACKEND_AGAIN) return 0;
            return -1;
        }
        if (fd < 0) return -1;
        struct control_server_client *client = control_server_free_client(server);
        if (uid != 0U || client == NULL ||
            control_server_active_clients(server) >= ASTERISKD_CONTROL_MAX_CLIENTS) {
            (void)server->transport->close_fd(server->transport_context, fd);
            continue;
        }
        memset(client, 0, sizeof(*client));
        client->fd = fd;
        client->active = true;
        client->request_deadline = control_deadline_after(
            now, ASTERISKD_CONTROL_REQUEST_TIMEOUT_MILLIS);
    }
    return 0;
}

int asteriskd_control_server_create_with_backend(
    struct asteriskd_control_server **out,
    int listener_fd,
    const struct asteriskd_control_transport_backend *transport,
    void *transport_context,
    const struct asteriskd_control_callbacks *callbacks) {
    if (out != NULL) *out = NULL;
    if (out == NULL || listener_fd < 0 || !control_transport_complete(transport) ||
        callbacks == NULL || callbacks->snapshot == NULL ||
        callbacks->request_stop == NULL || callbacks->request_shutdown == NULL) return -1;
    struct asteriskd_control_server *server = calloc(1U, sizeof(*server));
    if (server == NULL) return -1;
    server->listener_fd = listener_fd;
    server->transport = transport;
    server->transport_context = transport_context;
    server->callbacks = *callbacks;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        server->clients[index].fd = -1;
    }
    *out = server;
    return 0;
}

int asteriskd_control_server_create(
    struct asteriskd_control_server **out,
    int listener_fd,
    const struct asteriskd_control_callbacks *callbacks) {
#if defined(__linux__) || defined(__ANDROID__)
    return asteriskd_control_server_create_with_backend(
        out, listener_fd, &control_system_transport_backend, NULL, callbacks);
#else
    if (out != NULL) *out = NULL;
    (void)listener_fd;
    (void)callbacks;
    return -1;
#endif
}

void asteriskd_control_server_enable_accepting(
    struct asteriskd_control_server *server,
    bool accepting) {
    if (server != NULL) server->accepting = accepting;
}

void asteriskd_control_server_close_listener(
    struct asteriskd_control_server *server) {
    if (server == NULL) return;
    server->accepting = false;
    int listener = server->listener_fd;
    server->listener_fd = -1;
    if (listener >= 0) {
        (void)server->transport->close_fd(
            server->transport_context, listener);
    }
}

int asteriskd_control_server_listener_fd(
    const struct asteriskd_control_server *server) {
    return server == NULL ? -1 : server->listener_fd;
}

size_t asteriskd_control_server_interests(
    const struct asteriskd_control_server *server,
    struct asteriskd_control_interest *out,
    size_t capacity) {
    if (server == NULL) return 0U;
    size_t count = 0U;
    if (server->accepting) {
        if (out != NULL && count < capacity) {
            out[count] = (struct asteriskd_control_interest){
                .fd = server->listener_fd, .readable = true,
            };
        }
        ++count;
    }
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        const struct control_server_client *client = &server->clients[index];
        if (!client->active) continue;
        if (out != NULL && count < capacity) {
            out[count] = (struct asteriskd_control_interest){
                .fd = client->fd,
                .readable = true,
                .writable = client->output_length != 0U,
            };
        }
        ++count;
    }
    return count;
}

bool asteriskd_control_server_next_deadline(
    const struct asteriskd_control_server *server,
    uint64_t *out) {
    if (server == NULL || out == NULL) return false;
    bool present = false;
    uint64_t deadline = 0U;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        const struct control_server_client *client = &server->clients[index];
        if (!client->active) continue;
        uint64_t candidate;
        bool has_candidate;
        if (!client->request_processed ||
            (client->watch && client->watch_initial_remaining != 0U) ||
            (!client->watch && !client->pending_stop && client->output_length != 0U)) {
            candidate = client->request_deadline;
            has_candidate = true;
        } else if (client->watch && client->output_length != 0U) {
            candidate = control_deadline_after(
                client->last_write_progress,
                ASTERISKD_CONTROL_WATCH_STALL_MILLIS);
            has_candidate = true;
        } else {
            has_candidate = false;
            candidate = 0U;
        }
        if (has_candidate && (!present || candidate < deadline)) {
            present = true;
            deadline = candidate;
        }
    }
    if (present) *out = deadline;
    return present;
}

int asteriskd_control_server_dispatch(
    struct asteriskd_control_server *server,
    int fd,
    bool readable,
    bool writable,
    bool error,
    uint64_t now) {
    if (server == NULL || fd < 0) return -1;
    if (fd == server->listener_fd) {
        if (error) return -1;
        return readable ? control_server_accept_clients(server, now) : 0;
    }
    struct control_server_client *client = control_server_find_client(server, fd);
    if (client == NULL) return -1;
    if (error) {
        control_server_client_close(server, client);
        return 0;
    }
    int result = 0;
    if (readable) result = control_server_read_client(server, client, now);
    if (result == 0 && client->active && writable) {
        result = control_server_write_client(server, client, now);
    }
    return result;
}

int asteriskd_control_server_tick(
    struct asteriskd_control_server *server,
    uint64_t now) {
    if (server == NULL) return -1;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        struct control_server_client *client = &server->clients[index];
        if (!client->active) continue;
        bool request_deadline_active = !client->request_processed ||
            (client->watch && client->watch_initial_remaining != 0U) ||
            (!client->watch && !client->pending_stop && client->output_length != 0U);
        bool expired_request = request_deadline_active && now >= client->request_deadline;
        bool stalled_output = client->watch &&
            client->watch_initial_remaining == 0U && client->output_length != 0U &&
            now >= control_deadline_after(
                client->last_write_progress,
                ASTERISKD_CONTROL_WATCH_STALL_MILLIS);
        if (expired_request || stalled_output) {
            control_server_client_close(server, client);
        }
    }
    return 0;
}

int asteriskd_control_server_publish_event(
    struct asteriskd_control_server *server,
    enum asteriskd_control_event_type type,
    const struct asteriskd_control_snapshot *snapshot,
    const struct asteriskd_control_error *details,
    bool final,
    uint64_t now) {
    if (server == NULL || snapshot == NULL || server->sequence == UINT64_MAX ||
        (final && type != ASTERISKD_CONTROL_EVENT_STOPPED &&
            type != ASTERISKD_CONTROL_EVENT_FAILED)) return -1;
    struct asteriskd_control_event event;
    memset(&event, 0, sizeof(event));
    event.sequence = server->sequence + 1U;
    event.type = type;
    event.snapshot = *snapshot;
    if (details != NULL) {
        event.has_details = true;
        event.details = *details;
    }
    if (!control_event_valid(&event)) return -1;
    char *line = malloc(ASTERISKD_CONTROL_MAX_PAYLOAD + 2U);
    if (line == NULL) return -1;
    size_t line_length = 0U;
    if (asteriskd_control_encode_event_line(
            &event, line, ASTERISKD_CONTROL_MAX_PAYLOAD + 2U,
            &line_length) != 0) {
        free(line);
        return -1;
    }
    server->sequence = event.sequence;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        struct control_server_client *client = &server->clients[index];
        if (!client->active || !client->watch) continue;
        if (control_server_enqueue(
                server, client, line, line_length, now) != 0) {
            control_server_client_close(server, client);
            continue;
        }
        if (final) client->close_after_flush = true;
    }
    free(line);
    return 0;
}

int asteriskd_control_server_finish_stop(
    struct asteriskd_control_server *server,
    const struct asteriskd_control_result *result,
    uint64_t now) {
    if (server == NULL || !asteriskd_control_result_valid(result) ||
        (result->code == ASTERISKD_CONTROL_RESULT_OK &&
            result->snapshot.phase != ASTERISKD_PHASE_STOPPED) ||
        (result->code != ASTERISKD_CONTROL_RESULT_OK &&
            result->code != ASTERISKD_CONTROL_RESULT_STOP_FAILED)) return -1;
    int status = 0;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        struct control_server_client *client = &server->clients[index];
        if (!client->active || !client->pending_stop) continue;
        char *line = NULL;
        size_t line_length = 0U;
        if (control_server_encode_response(
                client, result->code,
                result->has_snapshot ? &result->snapshot : NULL,
                result->has_message ? result->message : NULL,
                result->has_message ? result->message_length : 0U,
                &line, &line_length) != 0 ||
            control_server_enqueue(server, client, line, line_length, now) != 0) {
            free(line);
            control_server_client_close(server, client);
            status = -1;
            continue;
        }
        free(line);
        client->pending_stop = false;
        client->close_after_flush = true;
        client->request_deadline = control_deadline_after(
            now, ASTERISKD_CONTROL_REQUEST_TIMEOUT_MILLIS);
    }
    return status;
}

bool asteriskd_control_server_drained(
    const struct asteriskd_control_server *server) {
    return server != NULL && control_server_active_clients(server) == 0U;
}

uint64_t asteriskd_control_server_sequence(
    const struct asteriskd_control_server *server) {
    return server == NULL ? 0U : server->sequence;
}

void asteriskd_control_server_destroy(
    struct asteriskd_control_server *server) {
    if (server == NULL) return;
    for (size_t index = 0U; index < ASTERISKD_CONTROL_MAX_CLIENTS; ++index) {
        control_server_client_close(server, &server->clients[index]);
    }
    if (server->listener_fd >= 0) {
        (void)server->transport->close_fd(
            server->transport_context, server->listener_fd);
    }
    free(server);
}

#ifdef ASTERISKD_TESTING
struct control_listener_close_test_context {
    int listener_closes;
    int client_closes;
};

static int control_listener_close_test_fd(void *opaque, int fd) {
    struct control_listener_close_test_context *context = opaque;
    if (fd == 10) ++context->listener_closes;
    if (fd == 11) ++context->client_closes;
    return 0;
}

bool asteriskd_test_listener_closes_before_client_drain(void) {
    static const struct asteriskd_control_transport_backend transport = {
        .close_fd = control_listener_close_test_fd,
    };
    struct control_listener_close_test_context context;
    memset(&context, 0, sizeof(context));
    struct asteriskd_control_server *server = calloc(1U, sizeof(*server));
    if (server == NULL) return false;
    server->listener_fd = 10;
    server->accepting = true;
    server->transport = &transport;
    server->transport_context = &context;
    server->clients[0].active = true;
    server->clients[0].fd = 11;

    asteriskd_control_server_close_listener(server);
    bool released_before_drain = server->listener_fd == -1 &&
        !server->accepting && context.listener_closes == 1 &&
        context.client_closes == 0 && !asteriskd_control_server_drained(server);
    asteriskd_control_server_destroy(server);
    return released_before_drain && context.listener_closes == 1 &&
        context.client_closes == 1;
}
#endif

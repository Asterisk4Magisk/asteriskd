// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "asteriskd.h"

#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static const char *const phase_names[] = {
    "validating", "acquiring", "starting", "applying-rules",
    "running", "stopping", "stopped", "failed",
};

static const char *const owner_names[] = {"asteriskng", "asteriskbox", "asteriskmeta"};
static const char *const core_names[] = {"xray", "sing-box", "mihomo"};
static const char *const mode_names[] = {"tproxy", "tun", "tun2socks", "bpf2socks", "ebpf"};
static const char *const child_role_names[] = {"core", "helper"};
static const char *const child_type_names[] = {
    "xray", "sing-box", "mihomo", "hev-socks5-tunnel", "bpf2socks",
};
static const char *const component_names[] = {
    "runtime", "core", "helper", "matcher", "rules", "network", "state", "log", "control",
};
static const char *const failure_names[] = {
    "start_failed", "readiness_timeout", "child_exited", "state_invalid", "state_incompatible",
    "resource_collision", "io_error", "stop_failed", "internal_error",
};
static const char *const category_names[] = {
    "tproxy", "routing", "dns", "fake-dns", "local-bypass", "hotspot", "tc", "bpf", "ipv6-guard",
};

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (error == NULL || error_size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static bool owner_core_valid(enum asteriskd_owner owner, enum asteriskd_core_type core) {
    return (owner == ASTERISKD_OWNER_NG && core == ASTERISKD_CORE_XRAY) ||
        (owner == ASTERISKD_OWNER_BOX && core == ASTERISKD_CORE_SING_BOX) ||
        (owner == ASTERISKD_OWNER_META && core == ASTERISKD_CORE_MIHOMO);
}

static bool bytes_are_zero(const void *bytes, size_t length) {
    const unsigned char *cursor = bytes;
    for (size_t index = 0U; index < length; ++index) {
        if (cursor[index] != 0U) return false;
    }
    return true;
}

static bool child_identity_is_zero(const struct asteriskd_child_identity *child) {
    return child->role == 0 && child->type == 0 && child->pid == 0 &&
        child->process_group_id == 0 && child->start_time_ticks == 0U &&
        child->exe_device == 0U && child->exe_inode == 0U && child->argc == 0U &&
        bytes_are_zero(child->argv, sizeof(child->argv));
}

static bool child_type_matches_core(enum asteriskd_child_type type, enum asteriskd_core_type core) {
    return (type == ASTERISKD_CHILD_TYPE_XRAY && core == ASTERISKD_CORE_XRAY) ||
        (type == ASTERISKD_CHILD_TYPE_SING_BOX && core == ASTERISKD_CORE_SING_BOX) ||
        (type == ASTERISKD_CHILD_TYPE_MIHOMO && core == ASTERISKD_CORE_MIHOMO);
}

static bool child_valid(
    const struct asteriskd_state_document *document,
    const struct asteriskd_child_identity *child,
    enum asteriskd_child_role slot) {
    if (child == NULL || (slot != ASTERISKD_CHILD_CORE && slot != ASTERISKD_CHILD_HELPER) ||
        child->role != slot || child->type < 0 || child->type >= ASTERISKD_CHILD_TYPE_COUNT ||
        child->pid <= 0 || child->process_group_id != child->pid || child->start_time_ticks == 0U ||
        child->exe_inode == 0U || child->argc == 0U || child->argc > ASTERISKD_MAX_CHILD_ARGV) return false;
    for (size_t index = 0U; index < child->argc; ++index) {
        size_t length = strnlen(child->argv[index], ASTERISKD_MAX_CHILD_ARG);
        if (length == 0U || length >= ASTERISKD_MAX_CHILD_ARG) return false;
    }
    if (slot == ASTERISKD_CHILD_CORE) return child_type_matches_core(child->type, document->core_type);
    if (document->mode == ASTERISKD_MODE_TUN2SOCKS) {
        return child->type == ASTERISKD_CHILD_TYPE_HEV_SOCKS5_TUNNEL;
    }
    if (document->mode == ASTERISKD_MODE_BPF2SOCKS) return child->type == ASTERISKD_CHILD_TYPE_BPF2SOCKS;
    return false;
}

static bool failure_valid(const struct asteriskd_state_failure *failure) {
    if (!failure->present) {
        return failure->code == 0 && failure->component == 0 &&
            bytes_are_zero(failure->message, sizeof(failure->message)) &&
            !failure->has_exit_code && failure->exit_code == 0 &&
            !failure->has_signal && failure->signal == 0;
    }
    if (failure->code < 0 || failure->code >= ASTERISKD_FAILURE_CODE_COUNT ||
        failure->component < 0 || failure->component >= ASTERISKD_COMPONENT_COUNT ||
        failure->message[0] == '\0' ||
        strnlen(failure->message, sizeof(failure->message)) >= sizeof(failure->message)) return false;
    if ((!failure->has_exit_code && failure->exit_code != 0) ||
        (!failure->has_signal && failure->signal != 0)) return false;
    if (failure->code == ASTERISKD_FAILURE_CHILD_EXITED) {
        return failure->has_exit_code != failure->has_signal &&
            (!failure->has_exit_code || failure->exit_code >= 0) &&
            (!failure->has_signal || failure->signal > 0);
    }
    return !failure->has_exit_code && !failure->has_signal;
}

static bool document_valid(const struct asteriskd_state_document *document) {
    if (document == NULL || !document->initialized || document->schema_version != ASTERISKD_STATE_VERSION ||
        document->phase < 0 || document->phase >= ASTERISKD_PHASE_COUNT ||
        document->owner < 0 || document->owner > ASTERISKD_OWNER_META ||
        document->core_type < 0 || document->core_type > ASTERISKD_CORE_MIHOMO ||
        document->mode < 0 || document->mode > ASTERISKD_MODE_EBPF ||
        !owner_core_valid(document->owner, document->core_type) ||
        !failure_valid(&document->failure) ||
        (document->matcher.active && !document->matcher.configured) ||
        (document->matcher.configured &&
         document->mode != ASTERISKD_MODE_TPROXY && document->mode != ASTERISKD_MODE_TUN &&
         document->mode != ASTERISKD_MODE_TUN2SOCKS) ||
        (document->rules.categories & ~ASTERISKD_RULE_CATEGORY_ALL) != 0U) return false;
    if (document->children.core_present &&
        !child_valid(document, &document->children.core, ASTERISKD_CHILD_CORE)) return false;
    if (!document->children.core_present && !child_identity_is_zero(&document->children.core)) return false;
    if (document->children.helper_present &&
        !child_valid(document, &document->children.helper, ASTERISKD_CHILD_HELPER)) return false;
    if (!document->children.helper_present && !child_identity_is_zero(&document->children.helper)) return false;
    if (document->children.helper_present !=
        (document->mode == ASTERISKD_MODE_TUN2SOCKS || document->mode == ASTERISKD_MODE_BPF2SOCKS) &&
        document->phase == ASTERISKD_PHASE_RUNNING) return false;
    if (document->phase == ASTERISKD_PHASE_RUNNING && !document->children.core_present) return false;
    if (document->phase == ASTERISKD_PHASE_RUNNING &&
        (document->failure.present ||
         (document->mode != ASTERISKD_MODE_EBPF && !document->rules.active) ||
         (document->matcher.configured && !document->matcher.active))) return false;
    if (document->phase == ASTERISKD_PHASE_FAILED && !document->failure.present) return false;
    if (!document->rules.active &&
        (document->rules.generation != 0U || document->rules.categories != 0U)) return false;
    if (document->rules.active &&
        (document->rules.generation == 0U || document->rules.categories == 0U)) return false;
    if (document->mode == ASTERISKD_MODE_EBPF &&
        (document->matcher.configured || document->matcher.active || document->rules.active ||
         document->rules.generation != 0U || document->rules.categories != 0U ||
         document->children.helper_present)) return false;
    if (document->mode == ASTERISKD_MODE_EBPF && document->children.core_present &&
        (document->owner != ASTERISKD_OWNER_BOX ||
         document->core_type != ASTERISKD_CORE_SING_BOX)) return false;
    if (document->owner == ASTERISKD_OWNER_BOX &&
        document->core_type == ASTERISKD_CORE_SING_BOX && document->mode == ASTERISKD_MODE_EBPF) {
        if (document->children.helper_present ||
            document->matcher.configured || document->matcher.active || document->rules.active ||
            document->rules.generation != 0U || document->rules.categories != 0U) return false;
    }
    if (document->phase == ASTERISKD_PHASE_STOPPED &&
        (document->children.core_present || document->children.helper_present || document->matcher.active ||
         document->rules.active || document->rules.generation != 0U ||
         document->rules.categories != 0U)) return false;
    return true;
}

int asteriskd_state_document_init(
    struct asteriskd_state_document *document,
    enum asteriskd_owner owner,
    enum asteriskd_core_type core,
    enum asteriskd_mode mode) {
    if (document == NULL) return ASTERISKD_STATE_INVALID;
    memset(document, 0, sizeof(*document));
    if (owner < 0 || owner > ASTERISKD_OWNER_META || core < 0 || core > ASTERISKD_CORE_MIHOMO ||
        mode < 0 || mode > ASTERISKD_MODE_EBPF || !owner_core_valid(owner, core)) {
        return ASTERISKD_STATE_INVALID;
    }
    document->schema_version = ASTERISKD_STATE_VERSION;
    document->phase = ASTERISKD_PHASE_STOPPED;
    document->owner = owner;
    document->core_type = core;
    document->mode = mode;
    document->initialized = true;
    return ASTERISKD_STATE_OK;
}

void asteriskd_state_document_destroy(struct asteriskd_state_document *document) {
    if (document == NULL) return;
    memset(document, 0, sizeof(*document));
}

int asteriskd_state_set_phase(struct asteriskd_state_document *document, enum asteriskd_phase phase) {
    if (document == NULL || !document->initialized || phase < 0 || phase >= ASTERISKD_PHASE_COUNT) {
        return ASTERISKD_STATE_INVALID;
    }
    document->phase = phase;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_child(
    struct asteriskd_state_document *document,
    const struct asteriskd_child_identity *child,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || child == NULL ||
        !child_valid(document, child, child->role)) {
        set_error(error, error_size, "invalid child identity");
        return ASTERISKD_STATE_INVALID;
    }
    if (child->role == ASTERISKD_CHILD_CORE) {
        document->children.core = *child;
        document->children.core_present = true;
    } else {
        document->children.helper = *child;
        document->children.helper_present = true;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_clear_child(
    struct asteriskd_state_document *document,
    enum asteriskd_child_role role) {
    if (document == NULL || !document->initialized ||
        (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER)) return ASTERISKD_STATE_INVALID;
    if (role == ASTERISKD_CHILD_CORE) {
        memset(&document->children.core, 0, sizeof(document->children.core));
        document->children.core_present = false;
    } else {
        memset(&document->children.helper, 0, sizeof(document->children.helper));
        document->children.helper_present = false;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_matcher(
    struct asteriskd_state_document *document,
    bool configured,
    bool active) {
    if (document == NULL || !document->initialized || active > configured ||
        (configured && !(document->mode == ASTERISKD_MODE_TPROXY || document->mode == ASTERISKD_MODE_TUN ||
                         document->mode == ASTERISKD_MODE_TUN2SOCKS))) return ASTERISKD_STATE_INVALID;
    document->matcher.configured = configured;
    document->matcher.active = active;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_rules(
    struct asteriskd_state_document *document,
    bool active,
    uint64_t generation,
    uint32_t categories) {
    if (document == NULL || !document->initialized ||
        (categories & ~ASTERISKD_RULE_CATEGORY_ALL) != 0U ||
        (!active && (generation != 0U || categories != 0U)) ||
        (active && (generation == 0U || categories == 0U)) ||
        (document->mode == ASTERISKD_MODE_EBPF && active)) return ASTERISKD_STATE_INVALID;
    document->rules.active = active;
    document->rules.generation = generation;
    document->rules.categories = categories;
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_set_failure(
    struct asteriskd_state_document *document,
    enum asteriskd_failure_code code,
    enum asteriskd_component component,
    const char *message,
    bool has_exit_code,
    int exit_code,
    bool has_signal,
    int signal_value,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || code < 0 || code >= ASTERISKD_FAILURE_CODE_COUNT ||
        component < 0 || component >= ASTERISKD_COMPONENT_COUNT || message == NULL || message[0] == '\0' ||
        strnlen(message, ASTERISKD_MAX_STATE_MESSAGE) >= ASTERISKD_MAX_STATE_MESSAGE) {
        set_error(error, error_size, "invalid failure summary");
        return ASTERISKD_STATE_INVALID;
    }
    struct asteriskd_state_failure failure;
    memset(&failure, 0, sizeof(failure));
    failure.present = true;
    failure.code = code;
    failure.component = component;
    (void)snprintf(failure.message, sizeof(failure.message), "%s", message);
    failure.has_exit_code = has_exit_code;
    failure.exit_code = has_exit_code ? exit_code : 0;
    failure.has_signal = has_signal;
    failure.signal = has_signal ? signal_value : 0;
    if (!failure_valid(&failure)) {
        set_error(error, error_size, "invalid failure process result");
        return ASTERISKD_STATE_INVALID;
    }
    document->failure = failure;
    return ASTERISKD_STATE_OK;
}

void asteriskd_state_clear_failure(struct asteriskd_state_document *document) {
    if (document != NULL && document->initialized) memset(&document->failure, 0, sizeof(document->failure));
}

int asteriskd_state_mark_stopped(
    struct asteriskd_state_document *document,
    char *error,
    size_t error_size) {
    if (document == NULL || !document->initialized || document->children.core_present ||
        document->children.helper_present || document->matcher.active || document->rules.active ||
        document->rules.generation != 0U || document->rules.categories != 0U) {
        set_error(error, error_size, "live telemetry remains");
        return ASTERISKD_STATE_INVALID;
    }
    enum asteriskd_phase previous = document->phase;
    document->phase = ASTERISKD_PHASE_STOPPED;
    if (!document_valid(document)) {
        document->phase = previous;
        set_error(error, error_size, "invalid stopped state");
        return ASTERISKD_STATE_INVALID;
    }
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

bool asteriskd_state_is_stopped(const struct asteriskd_state_document *document) {
    return document_valid(document) && document->phase == ASTERISKD_PHASE_STOPPED;
}

struct string_builder {
    char *bytes;
    size_t length;
    size_t capacity;
    int result;
};

static void builder_reserve(struct string_builder *builder, size_t extra) {
    if (builder->result != ASTERISKD_STATE_OK) return;
    if (extra > ASTERISKD_MAX_JSON_SIZE - builder->length) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    size_t needed = builder->length + extra + 1U;
    if (needed <= builder->capacity) return;
    size_t capacity = builder->capacity == 0U ? 1024U : builder->capacity;
    while (capacity < needed) {
        if (capacity > ASTERISKD_MAX_JSON_SIZE / 2U) {
            capacity = ASTERISKD_MAX_JSON_SIZE + 1U;
            break;
        }
        capacity *= 2U;
    }
    if (capacity > ASTERISKD_MAX_JSON_SIZE + 1U) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    char *bytes = realloc(builder->bytes, capacity);
    if (bytes == NULL) {
        builder->result = ASTERISKD_STATE_NO_MEMORY;
        return;
    }
    builder->bytes = bytes;
    builder->capacity = capacity;
}

static void builder_raw(struct string_builder *builder, const char *value) {
    size_t length = strlen(value);
    builder_reserve(builder, length);
    if (builder->result != ASTERISKD_STATE_OK) return;
    memcpy(builder->bytes + builder->length, value, length);
    builder->length += length;
    builder->bytes[builder->length] = '\0';
}

static void builder_format(struct string_builder *builder, const char *format, ...) {
    if (builder->result != ASTERISKD_STATE_OK) return;
    char buffer[512];
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= sizeof(buffer)) {
        builder->result = ASTERISKD_STATE_INVALID;
        return;
    }
    builder_reserve(builder, (size_t)count);
    if (builder->result != ASTERISKD_STATE_OK) return;
    memcpy(builder->bytes + builder->length, buffer, (size_t)count);
    builder->length += (size_t)count;
    builder->bytes[builder->length] = '\0';
}

static void builder_json_string(struct string_builder *builder, const char *value) {
    builder_raw(builder, "\"");
    for (const unsigned char *cursor = (const unsigned char *)value;
         builder->result == ASTERISKD_STATE_OK && *cursor != '\0'; ++cursor) {
        unsigned char ch = *cursor;
        switch (ch) {
            case '"': builder_raw(builder, "\\\""); break;
            case '\\': builder_raw(builder, "\\\\"); break;
            case '\b': builder_raw(builder, "\\b"); break;
            case '\f': builder_raw(builder, "\\f"); break;
            case '\n': builder_raw(builder, "\\n"); break;
            case '\r': builder_raw(builder, "\\r"); break;
            case '\t': builder_raw(builder, "\\t"); break;
            default:
                if (ch < 0x20U || ch == 0x7fU) builder_format(builder, "\\u%04x", (unsigned int)ch);
                else {
                    builder_reserve(builder, 1U);
                    if (builder->result == ASTERISKD_STATE_OK) {
                        builder->bytes[builder->length++] = (char)ch;
                        builder->bytes[builder->length] = '\0';
                    }
                }
                break;
        }
    }
    builder_raw(builder, "\"");
}

static const char *boolean_name(bool value) { return value ? "true" : "false"; }

static void serialize_child(
    struct string_builder *builder,
    bool present,
    const struct asteriskd_child_identity *child) {
    if (!present) {
        builder_raw(builder, "null");
        return;
    }
    builder_raw(builder, "{\"role\":");
    builder_json_string(builder, child_role_names[child->role]);
    builder_raw(builder, ",\"type\":");
    builder_json_string(builder, child_type_names[child->type]);
    builder_format(builder, ",\"pid\":%d,\"processGroupId\":%d,\"startTimeTicks\":%" PRIu64
        ",\"exeDevice\":%" PRIu64 ",\"exeInode\":%" PRIu64 ",\"argv\":[",
        child->pid, child->process_group_id, child->start_time_ticks, child->exe_device, child->exe_inode);
    for (size_t index = 0U; index < child->argc; ++index) {
        if (index != 0U) builder_raw(builder, ",");
        builder_json_string(builder, child->argv[index]);
    }
    builder_raw(builder, "]}");
}

int asteriskd_state_serialize(
    const struct asteriskd_state_document *document,
    char **out,
    size_t *out_length,
    char *error,
    size_t error_size) {
    if (out != NULL) *out = NULL;
    if (out_length != NULL) *out_length = 0U;
    if (out == NULL || out_length == NULL || !document_valid(document)) {
        set_error(error, error_size, "invalid state document");
        return ASTERISKD_STATE_INVALID;
    }
    struct string_builder builder = {.result = ASTERISKD_STATE_OK};
    builder_raw(&builder, "{\"schemaVersion\":2,\"phase\":"); builder_json_string(&builder, phase_names[document->phase]);
    builder_raw(&builder, ",\"owner\":"); builder_json_string(&builder, owner_names[document->owner]);
    builder_raw(&builder, ",\"coreType\":"); builder_json_string(&builder, core_names[document->core_type]);
    builder_raw(&builder, ",\"mode\":"); builder_json_string(&builder, mode_names[document->mode]);
    builder_raw(&builder, ",\"children\":{\"core\":");
    serialize_child(&builder, document->children.core_present, &document->children.core);
    builder_raw(&builder, ",\"helper\":");
    serialize_child(&builder, document->children.helper_present, &document->children.helper);
    builder_raw(&builder, "},\"matcher\":{\"configured\":");
    builder_raw(&builder, boolean_name(document->matcher.configured));
    builder_raw(&builder, ",\"active\":"); builder_raw(&builder, boolean_name(document->matcher.active));
    builder_raw(&builder, "},\"rules\":{\"active\":"); builder_raw(&builder, boolean_name(document->rules.active));
    builder_format(&builder, ",\"generation\":%" PRIu64 ",\"categories\":[", document->rules.generation);
    bool first = true;
    for (int category = 0; category < (int)ASTERISKD_RULE_CATEGORY_COUNT; ++category) {
        if ((document->rules.categories & ASTERISKD_RULE_CATEGORY_BIT(category)) == 0U) continue;
        if (!first) builder_raw(&builder, ",");
        builder_json_string(&builder, category_names[category]);
        first = false;
    }
    builder_raw(&builder, "]},\"failure\":");
    if (!document->failure.present) {
        builder_raw(&builder, "null");
    } else {
        builder_raw(&builder, "{\"code\":"); builder_json_string(&builder, failure_names[document->failure.code]);
        builder_raw(&builder, ",\"component\":"); builder_json_string(&builder, component_names[document->failure.component]);
        builder_raw(&builder, ",\"message\":"); builder_json_string(&builder, document->failure.message);
        builder_raw(&builder, ",\"exitCode\":");
        if (document->failure.has_exit_code) builder_format(&builder, "%d", document->failure.exit_code);
        else builder_raw(&builder, "null");
        builder_raw(&builder, ",\"signal\":");
        if (document->failure.has_signal) builder_format(&builder, "%d", document->failure.signal);
        else builder_raw(&builder, "null");
        builder_raw(&builder, "}");
    }
    builder_raw(&builder, "}");
    if (builder.result != ASTERISKD_STATE_OK) {
        free(builder.bytes);
        set_error(error, error_size, builder.result == ASTERISKD_STATE_NO_MEMORY ? "out of memory" : "state too large");
        return builder.result;
    }
    *out = builder.bytes;
    *out_length = builder.length;
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

#ifndef _WIN32
static enum asteriskd_file_kind system_file_kind(mode_t mode) {
    if (S_ISREG(mode)) return ASTERISKD_FILE_REGULAR;
    if (S_ISDIR(mode)) return ASTERISKD_FILE_DIRECTORY;
    if (S_ISFIFO(mode)) return ASTERISKD_FILE_FIFO;
    if (S_ISCHR(mode) || S_ISBLK(mode)) return ASTERISKD_FILE_DEVICE;
    if (S_ISLNK(mode)) return ASTERISKD_FILE_SYMLINK;
    return ASTERISKD_FILE_OTHER;
}

static int system_fstat(
    void *context,
    int fd,
    uint64_t *device,
    uint64_t *inode,
    enum asteriskd_file_kind *kind) {
    (void)context;
    struct stat status;
    if (fstat(fd, &status) != 0) return -1;
    *device = (uint64_t)status.st_dev;
    *inode = (uint64_t)status.st_ino;
    *kind = system_file_kind(status.st_mode);
    return 0;
}

static int system_dup(void *context, int fd, int *out) {
    (void)context;
    *out = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return *out >= 0 ? 0 : -1;
}

static int system_openat(
    void *context,
    int directory_fd,
    const char *name,
    uint32_t flags,
    uint32_t mode,
    int *out) {
    (void)context;
    int system_flags = 0;
    if ((flags & ASTERISKD_STATE_OPEN_WRITE) != 0U) system_flags |= O_WRONLY;
    else system_flags |= O_RDONLY;
    if ((flags & ASTERISKD_STATE_OPEN_CREATE) != 0U) system_flags |= O_CREAT;
    if ((flags & ASTERISKD_STATE_OPEN_EXCLUSIVE) != 0U) system_flags |= O_EXCL;
    if ((flags & ASTERISKD_STATE_OPEN_NOFOLLOW) != 0U) system_flags |= O_NOFOLLOW;
    if ((flags & ASTERISKD_STATE_OPEN_CLOEXEC) != 0U) system_flags |= O_CLOEXEC;
    if ((flags & ASTERISKD_STATE_OPEN_NONBLOCK) != 0U) system_flags |= O_NONBLOCK;
    if ((flags & ASTERISKD_STATE_OPEN_TRUNCATE) != 0U) system_flags |= O_TRUNC;
    *out = openat(directory_fd, name, system_flags, (mode_t)mode);
    return *out >= 0 ? 0 : -1;
}

static ptrdiff_t system_read(void *context, int fd, void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)read(fd, bytes, length);
}

static ptrdiff_t system_write(void *context, int fd, const void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)write(fd, bytes, length);
}

static int system_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static const struct asteriskd_state_file_backend system_state_backend = {
    .fstat_fd = system_fstat,
    .dup_cloexec = system_dup,
    .openat_fd = system_openat,
    .read_fd = system_read,
    .write_fd = system_write,
    .close_fd = system_close,
};
#endif

static bool file_backend_complete(const struct asteriskd_state_file_backend *backend) {
    return backend != NULL && backend->fstat_fd != NULL && backend->dup_cloexec != NULL &&
        backend->openat_fd != NULL && backend->read_fd != NULL && backend->write_fd != NULL &&
        backend->close_fd != NULL;
}

int asteriskd_state_store_init_with_backend(
    struct asteriskd_state_store *store,
    int runtime_directory_fd,
    uint64_t expected_device,
    uint64_t expected_inode,
    const struct asteriskd_state_file_backend *backend,
    void *context,
    char *error,
    size_t error_size) {
    if (store != NULL) {
        memset(store, 0, sizeof(*store));
        store->directory_fd = -1;
    }
    if (store == NULL || runtime_directory_fd < 0 || expected_inode == 0U ||
        !file_backend_complete(backend)) {
        set_error(error, error_size, "invalid state store arguments");
        return ASTERISKD_STATE_INVALID;
    }
    uint64_t source_device, source_inode;
    enum asteriskd_file_kind source_kind;
    if (backend->fstat_fd(context, runtime_directory_fd, &source_device, &source_inode, &source_kind) != 0) {
        set_error(error, error_size, "state directory stat failed");
        return ASTERISKD_STATE_IO;
    }
    if (source_kind != ASTERISKD_FILE_DIRECTORY || source_device != expected_device ||
        source_inode != expected_inode) {
        set_error(error, error_size, "state directory identity mismatch");
        return ASTERISKD_STATE_INVALID;
    }
    int duplicate = -1;
    int duplicate_result = backend->dup_cloexec(context, runtime_directory_fd, &duplicate);
    if (duplicate_result != 0 || duplicate < 0) {
        if (duplicate >= 0) (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "state directory duplicate failed");
        return ASTERISKD_STATE_IO;
    }
    uint64_t duplicate_device, duplicate_inode;
    enum asteriskd_file_kind duplicate_kind;
    if (backend->fstat_fd(context, duplicate, &duplicate_device, &duplicate_inode, &duplicate_kind) != 0) {
        (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "duplicated state directory stat failed");
        return ASTERISKD_STATE_IO;
    }
    if (duplicate_kind != ASTERISKD_FILE_DIRECTORY || duplicate_device != source_device ||
        duplicate_inode != source_inode) {
        (void)backend->close_fd(context, duplicate);
        set_error(error, error_size, "duplicated state directory identity mismatch");
        return ASTERISKD_STATE_INVALID;
    }
    store->directory_fd = duplicate;
    store->directory_fd_owned = true;
    store->directory_device = source_device;
    store->directory_inode = source_inode;
    store->backend = backend;
    store->backend_context = context;
    store->initialized = true;
    set_error(error, error_size, "ok");
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_store_init(
    struct asteriskd_state_store *store,
    int runtime_directory_fd,
    uint64_t expected_device,
    uint64_t expected_inode,
    char *error,
    size_t error_size) {
#ifdef _WIN32
    if (store != NULL) {
        memset(store, 0, sizeof(*store));
        store->directory_fd = -1;
    }
    (void)runtime_directory_fd;
    (void)expected_device;
    (void)expected_inode;
    set_error(error, error_size, "real state store requires Linux; use injected host backend");
    return ASTERISKD_STATE_IO;
#else
    return asteriskd_state_store_init_with_backend(
        store, runtime_directory_fd, expected_device, expected_inode,
        &system_state_backend, NULL, error, error_size);
#endif
}

void asteriskd_state_store_close(struct asteriskd_state_store *store) {
    if (store == NULL) return;
    if (store->directory_fd_owned && store->directory_fd >= 0 && store->backend != NULL &&
        store->backend->close_fd != NULL) {
        (void)store->backend->close_fd(store->backend_context, store->directory_fd);
    }
    memset(store, 0, sizeof(*store));
    store->directory_fd = -1;
}

static int verify_store_directory(struct asteriskd_state_store *store) {
    if (store == NULL || !store->initialized || !store->directory_fd_owned ||
        store->directory_fd < 0 || !file_backend_complete(store->backend)) return ASTERISKD_STATE_INVALID;
    uint64_t device, inode;
    enum asteriskd_file_kind kind;
    if (store->backend->fstat_fd(
            store->backend_context, store->directory_fd, &device, &inode, &kind) != 0) {
        return ASTERISKD_STATE_IO;
    }
    return kind == ASTERISKD_FILE_DIRECTORY && device == store->directory_device &&
        inode == store->directory_inode ? ASTERISKD_STATE_OK : ASTERISKD_STATE_INVALID;
}

static int write_all(
    struct asteriskd_state_store *store,
    int fd,
    const char *bytes,
    size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ptrdiff_t count = store->backend->write_fd(
            store->backend_context, fd, bytes + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return ASTERISKD_STATE_IO;
        }
        if (count == 0 || (size_t)count > length - offset) return ASTERISKD_STATE_IO;
        offset += (size_t)count;
    }
    return ASTERISKD_STATE_OK;
}

int asteriskd_state_store_save(
    struct asteriskd_state_store *store,
    const struct asteriskd_state_document *state,
    char *error,
    size_t error_size) {
    if (store == NULL || !store->initialized) return ASTERISKD_STATE_INVALID;
    char *json = NULL;
    size_t length = 0U;
    int result = asteriskd_state_serialize(state, &json, &length, error, error_size);
    if (result != ASTERISKD_STATE_OK) return result;
    result = verify_store_directory(store);
    if (result != ASTERISKD_STATE_OK) {
        free(json);
        return result;
    }
    int fd = -1;
    uint32_t flags = ASTERISKD_STATE_OPEN_WRITE | ASTERISKD_STATE_OPEN_CREATE |
        ASTERISKD_STATE_OPEN_TRUNCATE | ASTERISKD_STATE_OPEN_CLOEXEC;
    if (store->backend->openat_fd(
            store->backend_context, store->directory_fd, ASTERISKD_STATE_LEAF,
            flags, 0600U, &fd) != 0 || fd < 0) {
        if (fd >= 0) (void)store->backend->close_fd(store->backend_context, fd);
        free(json);
        set_error(error, error_size, "open state failed");
        return ASTERISKD_STATE_IO;
    }
    uint64_t device, inode;
    enum asteriskd_file_kind kind;
    if (store->backend->fstat_fd(
            store->backend_context, fd, &device, &inode, &kind) != 0 ||
        kind != ASTERISKD_FILE_REGULAR) {
        result = ASTERISKD_STATE_IO;
    } else {
        result = write_all(store, fd, json, length);
    }
    if (store->backend->close_fd(store->backend_context, fd) != 0 && result == ASTERISKD_STATE_OK) {
        result = ASTERISKD_STATE_IO;
    }
    free(json);
    set_error(error, error_size, result == ASTERISKD_STATE_OK ? "ok" : "state save failed");
    return result;
}

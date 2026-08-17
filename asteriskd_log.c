// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "asteriskd.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <io.h>
#endif

#define LOG_MAX_SERIALIZED (256U * 1024U)

static const char *const level_names[] = {"debug", "info", "warning", "error"};
static const char *const component_names[] = {
    "runtime", "core", "helper", "matcher", "rules", "network", "state", "log", "control",
};
static const char *const event_names[] = {
    "starting", "running", "stopping", "stopped", "child-output", "state-loaded",
    "state-saved", "state-invalid", "recovery", "network-changed", "capability-adjusted",
    "io-error", "diagnostic",
};
static const char *const stream_names[] = {"stdout", "stderr"};

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (error == NULL || error_size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static const char *core_start_failure_stage_name(
    enum asteriskd_core_start_failure_stage stage) {
    switch (stage) {
        case ASTERISKD_CORE_START_FAILURE_PROCESS_SPEC: return "process-spec";
        case ASTERISKD_CORE_START_FAILURE_BACKEND_INIT: return "backend-init";
        case ASTERISKD_CORE_START_FAILURE_READINESS_PREFLIGHT: return "readiness-preflight";
        case ASTERISKD_CORE_START_FAILURE_SPAWN: return "spawn";
        case ASTERISKD_CORE_START_FAILURE_CLOCK: return "clock";
        case ASTERISKD_CORE_START_FAILURE_SETUP_WAIT: return "setup-wait";
        case ASTERISKD_CORE_START_FAILURE_SETUP_RESULT: return "setup-result";
        case ASTERISKD_CORE_START_FAILURE_IDENTITY: return "identity";
        default: return NULL;
    }
}

int asteriskd_core_start_diagnostic_format(
    const struct asteriskd_core_start_diagnostic *diagnostic,
    char *output,
    size_t output_size) {
    if (diagnostic == NULL || output == NULL || output_size == 0U ||
        diagnostic->setup_error_number < 0 || diagnostic->detail == NULL ||
        strchr(diagnostic->detail, '\n') != NULL || strchr(diagnostic->detail, '\r') != NULL) {
        return ASTERISKD_LOG_INVALID;
    }
    const char *stage = core_start_failure_stage_name(diagnostic->stage);
    if (stage == NULL) return ASTERISKD_LOG_INVALID;
    int count = snprintf(output, output_size,
        "core start failed: stage=%s setupComplete=%d setupFatal=%d "
        "setupErrno=%d reaped=%d detail=%s",
        stage,
        diagnostic->setup_complete ? 1 : 0,
        diagnostic->setup_fatal ? 1 : 0,
        diagnostic->setup_error_number,
        diagnostic->reaped ? 1 : 0,
        diagnostic->detail);
    return count >= 0 && (size_t)count < output_size
        ? ASTERISKD_LOG_OK : ASTERISKD_LOG_INVALID;
}

struct log_builder {
    char *bytes;
    size_t length;
    size_t capacity;
    int result;
};

static void builder_reserve(struct log_builder *builder, size_t extra) {
    if (builder->result != ASTERISKD_LOG_OK) return;
    if (extra > LOG_MAX_SERIALIZED - builder->length) {
        builder->result = ASTERISKD_LOG_INVALID;
        return;
    }
    size_t needed = builder->length + extra + 1U;
    if (needed <= builder->capacity) return;
    size_t capacity = builder->capacity == 0U ? 1024U : builder->capacity;
    while (capacity < needed) {
        if (capacity > LOG_MAX_SERIALIZED / 2U) {
            capacity = LOG_MAX_SERIALIZED + 1U;
            break;
        }
        capacity *= 2U;
    }
    if (capacity > LOG_MAX_SERIALIZED + 1U) {
        builder->result = ASTERISKD_LOG_INVALID;
        return;
    }
    char *bytes = realloc(builder->bytes, capacity);
    if (bytes == NULL) {
        builder->result = ASTERISKD_LOG_NO_MEMORY;
        return;
    }
    builder->bytes = bytes;
    builder->capacity = capacity;
}

static void builder_bytes(struct log_builder *builder, const void *bytes, size_t length) {
    builder_reserve(builder, length);
    if (builder->result != ASTERISKD_LOG_OK) return;
    memcpy(builder->bytes + builder->length, bytes, length);
    builder->length += length;
    builder->bytes[builder->length] = '\0';
}

static void builder_raw(struct log_builder *builder, const char *text) {
    builder_bytes(builder, text, strlen(text));
}

static void builder_format(struct log_builder *builder, const char *format, ...) {
    if (builder->result != ASTERISKD_LOG_OK) return;
    char bytes[128];
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(bytes, sizeof(bytes), format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= sizeof(bytes)) {
        builder->result = ASTERISKD_LOG_INVALID;
        return;
    }
    builder_bytes(builder, bytes, (size_t)count);
}

static bool valid_utf8_sequence(const unsigned char *bytes, size_t length, size_t *count) {
    if (length == 0U) return false;
    unsigned char first = bytes[0];
    uint32_t codepoint;
    size_t needed;
    if (first < 0x80U) {
        *count = 1U;
        return true;
    }
    if (first >= 0xc2U && first <= 0xdfU) {
        needed = 2U;
        codepoint = first & 0x1fU;
    } else if (first >= 0xe0U && first <= 0xefU) {
        needed = 3U;
        codepoint = first & 0x0fU;
    } else if (first >= 0xf0U && first <= 0xf4U) {
        needed = 4U;
        codepoint = first & 0x07U;
    } else {
        return false;
    }
    if (needed > length) return false;
    for (size_t index = 1U; index < needed; ++index) {
        if ((bytes[index] & 0xc0U) != 0x80U) return false;
        codepoint = (codepoint << 6U) | (uint32_t)(bytes[index] & 0x3fU);
    }
    if ((needed == 3U && codepoint < 0x800U) || (needed == 4U && codepoint < 0x10000U) ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU) return false;
    *count = needed;
    return true;
}

static void builder_json_bytes(
    struct log_builder *builder,
    const unsigned char *bytes,
    size_t length) {
    builder_raw(builder, "\"");
    size_t index = 0U;
    while (index < length && builder->result == ASTERISKD_LOG_OK) {
        unsigned char ch = bytes[index];
        switch (ch) {
            case '"': builder_raw(builder, "\\\""); ++index; continue;
            case '\\': builder_raw(builder, "\\\\"); ++index; continue;
            case '\b': builder_raw(builder, "\\b"); ++index; continue;
            case '\f': builder_raw(builder, "\\f"); ++index; continue;
            case '\n': builder_raw(builder, "\\n"); ++index; continue;
            case '\r': builder_raw(builder, "\\r"); ++index; continue;
            case '\t': builder_raw(builder, "\\t"); ++index; continue;
            default: break;
        }
        if (ch < 0x20U || ch == 0x7fU) {
            builder_format(builder, "\\u%04x", (unsigned int)ch);
            ++index;
            continue;
        }
        size_t count;
        if (valid_utf8_sequence(bytes + index, length - index, &count)) {
            builder_bytes(builder, bytes + index, count);
            index += count;
        } else {
            builder_raw(builder, "\\ufffd");
            ++index;
        }
    }
    builder_raw(builder, "\"");
}

static int redact_bytes(
    const unsigned char *bytes,
    size_t length,
    size_t visible_length,
    const unsigned char *secret,
    size_t secret_length,
    unsigned char **out,
    size_t *out_length) {
    *out = NULL;
    *out_length = 0U;
    if (visible_length > length || length > LOG_MAX_SERIALIZED) return ASTERISKD_LOG_INVALID;
    bool *redacted = NULL;
    if (length != 0U) {
        redacted = calloc(length, sizeof(*redacted));
        if (redacted == NULL) return ASTERISKD_LOG_NO_MEMORY;
    }
    if (secret_length != 0U && secret_length <= length) {
        for (size_t start = 0U; start + secret_length <= length; ++start) {
            if (memcmp(bytes + start, secret, secret_length) != 0) continue;
            for (size_t offset = 0U; offset < secret_length; ++offset) redacted[start + offset] = true;
        }
    }
    size_t marker_length = strlen(ASTERISKD_LOG_REDACTION);
    size_t plain_count = 0U;
    size_t redacted_runs = 0U;
    size_t index = 0U;
    while (index < visible_length) {
        if (!redacted[index]) {
            ++plain_count;
            ++index;
            continue;
        }
        ++redacted_runs;
        while (index < length && redacted[index]) ++index;
    }
    if (plain_count > LOG_MAX_SERIALIZED ||
        (marker_length != 0U &&
         redacted_runs > (LOG_MAX_SERIALIZED - plain_count) / marker_length)) {
        free(redacted);
        return ASTERISKD_LOG_INVALID;
    }
    size_t result_length = plain_count + redacted_runs * marker_length;
    unsigned char *result = malloc(result_length + 1U);
    if (result == NULL) {
        free(redacted);
        return ASTERISKD_LOG_NO_MEMORY;
    }
    size_t output = 0U;
    index = 0U;
    while (index < visible_length) {
        if (!redacted[index]) {
            result[output++] = bytes[index++];
            continue;
        }
        memcpy(result + output, ASTERISKD_LOG_REDACTION, marker_length);
        output += marker_length;
        while (index < length && redacted[index]) ++index;
    }
    result[output] = '\0';
    free(redacted);
    *out = result;
    *out_length = output;
    return ASTERISKD_LOG_OK;
}

static bool local_time_valid(const struct asteriskd_local_time *value) {
    return value->year >= 1970 && value->year <= 9999 && value->month >= 1 && value->month <= 12 &&
        value->day >= 1 && value->day <= 31 && value->hour >= 0 && value->hour <= 23 &&
        value->minute >= 0 && value->minute <= 59 && value->second >= 0 && value->second <= 60 &&
        value->millisecond >= 0 && value->millisecond <= 999 &&
        value->utc_offset_minutes >= -1439 && value->utc_offset_minutes <= 1439;
}

#ifndef _WIN32
static int system_local_time(void *context, struct asteriskd_local_time *out) {
    (void)context;
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) return -1;
    struct tm local;
    if (localtime_r(&now.tv_sec, &local) == NULL) return -1;
    int offset = (int)(local.tm_gmtoff / 60);
    *out = (struct asteriskd_local_time){
        .year = local.tm_year + 1900,
        .month = local.tm_mon + 1,
        .day = local.tm_mday,
        .hour = local.tm_hour,
        .minute = local.tm_min,
        .second = local.tm_sec,
        .millisecond = (int)(now.tv_nsec / 1000000L),
        .utc_offset_minutes = offset,
    };
    return 0;
}

static const struct asteriskd_clock_backend system_clock_backend = {
    .local_time = system_local_time,
    .context = NULL,
};

static int system_log_open_root(void *context, uint32_t flags, int *fd) {
    (void)context;
    uint32_t required = ASTERISKD_LOG_OPEN_DIRECTORY | ASTERISKD_LOG_OPEN_NOFOLLOW |
        ASTERISKD_LOG_OPEN_CLOEXEC;
    if (flags != required || fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    int opened = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (opened < 0) return -1;
    *fd = opened;
    return 0;
}

static int system_log_openat(
    void *context,
    int parent_fd,
    const char *name,
    uint32_t flags,
    uint32_t mode,
    int *fd) {
    (void)context;
    if (name == NULL || name[0] == '\0' || strchr(name, '/') != NULL || fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    uint32_t directory_flags = ASTERISKD_LOG_OPEN_DIRECTORY | ASTERISKD_LOG_OPEN_NOFOLLOW |
        ASTERISKD_LOG_OPEN_CLOEXEC;
    uint32_t file_flags = ASTERISKD_LOG_OPEN_APPEND | ASTERISKD_LOG_OPEN_CREATE |
        ASTERISKD_LOG_OPEN_NONBLOCK | ASTERISKD_LOG_OPEN_NOFOLLOW |
        ASTERISKD_LOG_OPEN_CLOEXEC;
    int opened;
    if (flags == directory_flags && mode == 0U) {
        opened = openat(parent_fd, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } else if (flags == file_flags && mode == 0600U) {
        opened = openat(
            parent_fd, name,
            O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC,
            0600);
    } else {
        errno = EINVAL;
        return -1;
    }
    if (opened < 0) return -1;
    *fd = opened;
    return 0;
}

static int system_log_fstat(
    void *context,
    int fd,
    struct asteriskd_log_file_metadata *metadata) {
    (void)context;
    struct stat status;
    if (metadata == NULL || fstat(fd, &status) != 0) return -1;
    if (S_ISDIR(status.st_mode)) metadata->kind = ASTERISKD_FILE_DIRECTORY;
    else if (S_ISREG(status.st_mode)) metadata->kind = ASTERISKD_FILE_REGULAR;
    else metadata->kind = ASTERISKD_FILE_OTHER;
    metadata->mode = (uint32_t)(status.st_mode & 07777);
    metadata->uid = (uint32_t)status.st_uid;
    metadata->gid = (uint32_t)status.st_gid;
    return 0;
}

static int system_log_fchown(void *context, int fd, uint32_t uid, uint32_t gid) {
    (void)context;
    return fchown(fd, (uid_t)uid, (gid_t)gid);
}

static int system_log_fchmod(void *context, int fd, uint32_t mode) {
    (void)context;
    return fchmod(fd, (mode_t)mode);
}

static ptrdiff_t system_log_write(void *context, int fd, const void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)write(fd, bytes, length);
}

static int system_log_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static const struct asteriskd_log_file_backend system_log_backend = {
    .open_root = system_log_open_root,
    .openat_fd = system_log_openat,
    .fstat_fd = system_log_fstat,
    .fchown_fd = system_log_fchown,
    .fchmod_fd = system_log_fchmod,
    .write_fd = system_log_write,
    .close_fd = system_log_close,
};
#endif

static bool file_backend_complete(const struct asteriskd_log_file_backend *backend) {
    return backend != NULL && backend->open_root != NULL && backend->openat_fd != NULL &&
        backend->fstat_fd != NULL && backend->fchown_fd != NULL && backend->fchmod_fd != NULL &&
        backend->write_fd != NULL && backend->close_fd != NULL;
}

static bool lexical_log_path_valid(const char *path) {
    if (path == NULL || path[0] != '/' || path[1] == '\0' ||
        strnlen(path, ASTERISKD_MAX_PATH) >= ASTERISKD_MAX_PATH) return false;
    const char *component = path + 1;
    while (*component != '\0') {
        const char *slash = strchr(component, '/');
        size_t length = slash == NULL ? strlen(component) : (size_t)(slash - component);
        if (length == 0U ||
            (length == 1U && component[0] == '.') ||
            (length == 2U && component[0] == '.' && component[1] == '.')) return false;
        if (slash == NULL) return true;
        component = slash + 1;
    }
    return false;
}

static int open_log_no_follow(
    const char *path,
    const struct asteriskd_log_file_backend *backend,
    void *context,
    int *out,
    int *parent_out,
    struct asteriskd_log_file_metadata *parent_metadata_out) {
    uint32_t directory_flags = ASTERISKD_LOG_OPEN_DIRECTORY | ASTERISKD_LOG_OPEN_NOFOLLOW |
        ASTERISKD_LOG_OPEN_CLOEXEC;
    int current = -1;
    int open_result = backend->open_root(context, directory_flags, &current);
    if (open_result != 0 || current < 0) {
        if (current >= 0) (void)backend->close_fd(context, current);
        return ASTERISKD_LOG_IO;
    }
    struct asteriskd_log_file_metadata current_metadata;
    if (backend->fstat_fd(context, current, &current_metadata) != 0 ||
        current_metadata.kind != ASTERISKD_FILE_DIRECTORY) {
        (void)backend->close_fd(context, current);
        return ASTERISKD_LOG_IO;
    }
    const char *component = path + 1;
    while (true) {
        const char *slash = strchr(component, '/');
        size_t length = slash == NULL ? strlen(component) : (size_t)(slash - component);
        char name[ASTERISKD_MAX_PATH];
        memcpy(name, component, length);
        name[length] = '\0';
        int next = -1;
        uint32_t flags = slash == NULL ?
            (ASTERISKD_LOG_OPEN_APPEND | ASTERISKD_LOG_OPEN_CREATE |
             ASTERISKD_LOG_OPEN_NONBLOCK | ASTERISKD_LOG_OPEN_NOFOLLOW |
             ASTERISKD_LOG_OPEN_CLOEXEC) : directory_flags;
        uint32_t mode = slash == NULL ? 0600U : 0U;
        open_result = backend->openat_fd(context, current, name, flags, mode, &next);
        if (open_result != 0 || next < 0) {
            if (next >= 0) (void)backend->close_fd(context, next);
            (void)backend->close_fd(context, current);
            return ASTERISKD_LOG_IO;
        }
        struct asteriskd_log_file_metadata next_metadata;
        enum asteriskd_file_kind expected = slash == NULL ?
            ASTERISKD_FILE_REGULAR : ASTERISKD_FILE_DIRECTORY;
        if (backend->fstat_fd(context, next, &next_metadata) != 0 ||
            next_metadata.kind != expected) {
            (void)backend->close_fd(context, next);
            (void)backend->close_fd(context, current);
            return ASTERISKD_LOG_IO;
        }
        if (slash == NULL) {
            if ((next_metadata.uid != current_metadata.uid ||
                 next_metadata.gid != current_metadata.gid) &&
                backend->fchown_fd(
                    context, next, current_metadata.uid, current_metadata.gid) != 0) {
                (void)backend->close_fd(context, next);
                (void)backend->close_fd(context, current);
                return ASTERISKD_LOG_IO;
            }
            if (backend->fchmod_fd(context, next, 0600U) != 0) {
                (void)backend->close_fd(context, next);
                (void)backend->close_fd(context, current);
                return ASTERISKD_LOG_IO;
            }
            struct asteriskd_log_file_metadata verified;
            if (backend->fstat_fd(context, next, &verified) != 0 ||
                verified.kind != ASTERISKD_FILE_REGULAR || verified.mode != 0600U ||
                verified.uid != current_metadata.uid || verified.gid != current_metadata.gid) {
                (void)backend->close_fd(context, next);
                (void)backend->close_fd(context, current);
                return ASTERISKD_LOG_IO;
            }
            *out = next;
            *parent_out = current;
            *parent_metadata_out = current_metadata;
            return ASTERISKD_LOG_OK;
        }
        if (backend->close_fd(context, current) != 0) {
            (void)backend->close_fd(context, next);
            return ASTERISKD_LOG_IO;
        }
        current = next;
        current_metadata = next_metadata;
        component = slash + 1;
    }
}

int asteriskd_log_open_append_fd_with_backend(
    const char *path,
    const struct asteriskd_log_file_backend *file_backend,
    void *file_context,
    int *out,
    char *error,
    size_t error_size) {
    if (out != NULL) *out = -1;
    if (out == NULL || !lexical_log_path_valid(path) ||
        !file_backend_complete(file_backend)) {
        set_error(error, error_size, "invalid append log arguments");
        return ASTERISKD_LOG_INVALID;
    }
    int fd = -1;
    int parent_fd = -1;
    struct asteriskd_log_file_metadata parent_metadata;
    memset(&parent_metadata, 0, sizeof(parent_metadata));
    if (open_log_no_follow(path, file_backend, file_context, &fd, &parent_fd,
            &parent_metadata) != ASTERISKD_LOG_OK) {
        set_error(error, error_size, "open append log failed");
        return ASTERISKD_LOG_IO;
    }
    if (file_backend->close_fd(file_context, parent_fd) != 0) {
        (void)file_backend->close_fd(file_context, fd);
        set_error(error, error_size, "close append log parent failed");
        return ASTERISKD_LOG_IO;
    }
    *out = fd;
    return ASTERISKD_LOG_OK;
}

int asteriskd_log_open_append_fd(
    const char *path,
    int *out,
    char *error,
    size_t error_size) {
#ifndef _WIN32
    return asteriskd_log_open_append_fd_with_backend(
        path, &system_log_backend, NULL, out, error, error_size);
#else
    if (out != NULL) *out = -1;
    (void)path;
    set_error(error, error_size, "system append log is unavailable");
    return ASTERISKD_LOG_IO;
#endif
}

int asteriskd_log_open_with_backend(
    struct asteriskd_logger *logger,
    const char *path,
    const unsigned char *secret,
    size_t secret_length,
    const struct asteriskd_clock_backend *clock,
    const struct asteriskd_log_file_backend *file_backend,
    void *file_context,
    char *error,
    size_t error_size) {
    if (logger != NULL) {
        memset(logger, 0, sizeof(*logger));
        logger->fd = -1;
        logger->parent_fd = -1;
    }
    if (logger == NULL || !lexical_log_path_valid(path) || clock == NULL ||
        clock->local_time == NULL || !file_backend_complete(file_backend) ||
        secret_length >= ASTERISKD_MAX_SECRET_KEY || (secret_length != 0U && secret == NULL) ||
        (secret_length != 0U &&
         (memchr(secret, '\r', secret_length) != NULL || memchr(secret, '\n', secret_length) != NULL))) {
        set_error(error, error_size, "invalid logger arguments");
        return ASTERISKD_LOG_INVALID;
    }
    int fd = -1;
    int parent_fd = -1;
    struct asteriskd_log_file_metadata parent_metadata;
    memset(&parent_metadata, 0, sizeof(parent_metadata));
    if (open_log_no_follow(
            path, file_backend, file_context, &fd, &parent_fd,
            &parent_metadata) != ASTERISKD_LOG_OK) {
        set_error(error, error_size, "open structured log failed");
        return ASTERISKD_LOG_IO;
    }
    logger->fd = fd;
    logger->fd_owned = true;
    logger->parent_fd = parent_fd;
    logger->parent_fd_owned = true;
    logger->parent_mode = parent_metadata.mode;
    logger->parent_uid = parent_metadata.uid;
    logger->parent_gid = parent_metadata.gid;
    logger->opened = true;
    logger->clock = *clock;
    logger->file_backend = file_backend;
    logger->file_context = file_context;
    if (secret_length != 0U) memcpy(logger->age_secret, secret, secret_length);
    logger->age_secret_length = secret_length;
    set_error(error, error_size, "ok");
    return ASTERISKD_LOG_OK;
}

int asteriskd_log_open(
    struct asteriskd_logger *logger,
    const char *path,
    const unsigned char *secret,
    size_t secret_length,
    const struct asteriskd_clock_backend *clock,
    char *error,
    size_t error_size) {
#ifdef _WIN32
    (void)path;
    (void)secret;
    (void)secret_length;
    (void)clock;
    if (logger != NULL) {
        memset(logger, 0, sizeof(*logger));
        logger->fd = -1;
    }
    set_error(error, error_size, "real structured log requires Linux; use injected host backend");
    return ASTERISKD_LOG_IO;
#else
    const struct asteriskd_clock_backend *selected_clock = clock == NULL ? &system_clock_backend : clock;
    return asteriskd_log_open_with_backend(
        logger, path, secret, secret_length, selected_clock,
        &system_log_backend, NULL, error, error_size);
#endif
}

static int logger_write_all(struct asteriskd_logger *logger, const char *bytes, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ptrdiff_t count = logger->file_backend->write_fd(
            logger->file_context, logger->fd, bytes + offset, length - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            logger->failed = true;
            return ASTERISKD_LOG_IO;
        }
        if (count == 0 || (size_t)count > length - offset) {
            logger->failed = true;
            return ASTERISKD_LOG_IO;
        }
        offset += (size_t)count;
    }
    return ASTERISKD_LOG_OK;
}

static int write_log_object(
    struct asteriskd_logger *logger,
    enum asteriskd_log_level level,
    enum asteriskd_component component,
    enum asteriskd_log_event event,
    bool has_stream,
    enum asteriskd_log_stream stream,
    const unsigned char *message,
    size_t message_length,
    size_t visible_message_length,
    bool truncated) {
    if (logger == NULL || !logger->opened || logger->failed || level < 0 || level >= ASTERISKD_LOG_LEVEL_COUNT ||
        component < 0 || component >= ASTERISKD_COMPONENT_COUNT || event < 0 || event >= ASTERISKD_LOG_EVENT_COUNT ||
        (has_stream && (stream < 0 || stream >= ASTERISKD_LOG_STREAM_COUNT)) ||
        visible_message_length > message_length ||
        (message_length != 0U && message == NULL)) return logger != NULL && logger->failed ? ASTERISKD_LOG_IO : ASTERISKD_LOG_INVALID;
    unsigned char *redacted = NULL;
    size_t redacted_length = 0U;
    int result = redact_bytes(
        message, message_length, visible_message_length,
        logger->age_secret, logger->age_secret_length,
        &redacted, &redacted_length);
    if (result != ASTERISKD_LOG_OK) return result;
    if (truncated) {
        static const unsigned char marker[] = "[truncated]";
        size_t marker_length = sizeof(marker) - 1U;
        if (redacted_length > LOG_MAX_SERIALIZED - marker_length) {
            free(redacted);
            return ASTERISKD_LOG_INVALID;
        }
        unsigned char *grown = realloc(redacted, redacted_length + marker_length);
        if (grown == NULL) {
            free(redacted);
            return ASTERISKD_LOG_NO_MEMORY;
        }
        redacted = grown;
        memcpy(redacted + redacted_length, marker, marker_length);
        redacted_length += marker_length;
    }
    struct asteriskd_local_time now;
    if (logger->clock.local_time(logger->clock.context, &now) != 0 || !local_time_valid(&now)) {
        free(redacted);
        logger->failed = true;
        return ASTERISKD_LOG_IO;
    }
    int offset = now.utc_offset_minutes;
    char sign = offset < 0 ? '-' : '+';
    unsigned int magnitude = (unsigned int)(offset < 0 ? -offset : offset);
    struct log_builder builder = {.result = ASTERISKD_LOG_OK};
    builder_format(&builder,
        "{\"timestamp\":\"%04d-%02d-%02dT%02d:%02d:%02d.%03d%c%02u:%02u\",\"level\":\"%s\"," 
        "\"component\":\"%s\",\"event\":\"%s\",\"stream\":",
        now.year, now.month, now.day, now.hour, now.minute, now.second, now.millisecond,
        sign, magnitude / 60U, magnitude % 60U, level_names[level], component_names[component], event_names[event]);
    if (has_stream) {
        builder_format(&builder, "\"%s\"", stream_names[stream]);
    } else {
        builder_raw(&builder, "null");
    }
    builder_raw(&builder, ",\"message\":");
    builder_json_bytes(&builder, redacted, redacted_length);
    builder_format(&builder, ",\"truncated\":%s}\n", truncated ? "true" : "false");
    free(redacted);
    if (builder.result != ASTERISKD_LOG_OK) {
        free(builder.bytes);
        return builder.result;
    }
    result = logger_write_all(logger, builder.bytes, builder.length);
    free(builder.bytes);
    return result;
}

int asteriskd_log_line(
    struct asteriskd_logger *logger,
    enum asteriskd_log_level level,
    enum asteriskd_component component,
    enum asteriskd_log_event event,
    const char *message) {
    if (message == NULL) return ASTERISKD_LOG_INVALID;
    size_t message_length = strlen(message);
    return write_log_object(
        logger, level, component, event, false, ASTERISKD_LOG_STREAM_STDOUT,
        (const unsigned char *)message, message_length, message_length, false);
}

static void partial_reset(struct asteriskd_log_partial *partial) {
    memset(partial, 0, sizeof(*partial));
}

static int emit_partial(
    struct asteriskd_logger *logger,
    enum asteriskd_child_role role,
    enum asteriskd_log_stream stream,
    bool emit_empty) {
    struct asteriskd_log_partial *partial = &logger->partials[role][stream];
    if (!emit_empty && !partial->has_first_byte) return ASTERISKD_LOG_OK;
    size_t visible_length = partial->raw_length < ASTERISKD_LOG_MAX_CHILD_LINE ?
        partial->raw_length : ASTERISKD_LOG_MAX_CHILD_LINE;
    if (visible_length > partial->kept_length) return ASTERISKD_LOG_INVALID;
    int result = write_log_object(
        logger,
        ASTERISKD_LOG_LEVEL_INFO,
        role == ASTERISKD_CHILD_CORE ? ASTERISKD_COMPONENT_CORE : ASTERISKD_COMPONENT_HELPER,
        ASTERISKD_LOG_EVENT_CHILD_OUTPUT,
        true,
        stream,
        partial->bytes,
        partial->kept_length,
        visible_length,
        partial->truncated);
    partial_reset(partial);
    return result;
}

static void partial_append(
    struct asteriskd_log_partial *partial,
    unsigned char byte,
    uint64_t now_milliseconds,
    size_t capture_limit) {
    if (!partial->has_first_byte) {
        partial->has_first_byte = true;
        partial->first_byte_milliseconds = now_milliseconds;
    }
    if (partial->kept_length < capture_limit) {
        partial->bytes[partial->kept_length++] = byte;
    }
    if (partial->raw_length != SIZE_MAX) ++partial->raw_length;
    partial->last_raw_was_cr = byte == '\r';
    partial->truncated = partial->raw_length > ASTERISKD_LOG_MAX_CHILD_LINE;
}

int asteriskd_log_child_bytes(
    struct asteriskd_logger *logger,
    enum asteriskd_child_role role,
    enum asteriskd_log_stream stream,
    const unsigned char *bytes,
    size_t length,
    uint64_t now_milliseconds,
    bool eof) {
    if (logger == NULL || !logger->opened || logger->failed ||
        (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER) ||
        stream < 0 || stream >= ASTERISKD_LOG_STREAM_COUNT || (length != 0U && bytes == NULL)) {
        return logger != NULL && logger->failed ? ASTERISKD_LOG_IO : ASTERISKD_LOG_INVALID;
    }
    struct asteriskd_log_partial *partial = &logger->partials[role][stream];
    size_t redaction_overlap = logger->age_secret_length == 0U ?
        0U : logger->age_secret_length - 1U;
    size_t capture_limit = ASTERISKD_LOG_MAX_CHILD_LINE + redaction_overlap;
    for (size_t index = 0U; index < length; ++index) {
        if (bytes[index] != '\n') {
            partial_append(partial, bytes[index], now_milliseconds, capture_limit);
            continue;
        }
        if (partial->raw_length != 0U && partial->last_raw_was_cr) {
            size_t raw_before = partial->raw_length;
            bool terminal_cr_was_kept = raw_before != SIZE_MAX &&
                partial->kept_length == raw_before;
            if (partial->raw_length != SIZE_MAX) --partial->raw_length;
            if (terminal_cr_was_kept && partial->kept_length != 0U &&
                partial->bytes[partial->kept_length - 1U] == '\r') --partial->kept_length;
            partial->truncated = partial->raw_length > ASTERISKD_LOG_MAX_CHILD_LINE;
        }
        int result = emit_partial(logger, role, stream, true);
        if (result != ASTERISKD_LOG_OK) return result;
        partial = &logger->partials[role][stream];
    }
    if (eof) return emit_partial(logger, role, stream, false);
    return ASTERISKD_LOG_OK;
}

int asteriskd_log_flush_expired(struct asteriskd_logger *logger, uint64_t now_milliseconds) {
    if (logger == NULL || !logger->opened || logger->failed) {
        return logger != NULL && logger->failed ? ASTERISKD_LOG_IO : ASTERISKD_LOG_INVALID;
    }
    for (int role = 0; role < 2; ++role) {
        for (int stream = 0; stream < (int)ASTERISKD_LOG_STREAM_COUNT; ++stream) {
            struct asteriskd_log_partial *partial = &logger->partials[role][stream];
            if (!partial->has_first_byte || now_milliseconds < partial->first_byte_milliseconds ||
                now_milliseconds - partial->first_byte_milliseconds < ASTERISKD_LOG_PARTIAL_TIMEOUT_MILLIS) continue;
            int result = emit_partial(
                logger, (enum asteriskd_child_role)role, (enum asteriskd_log_stream)stream, false);
            if (result != ASTERISKD_LOG_OK) return result;
        }
    }
    return ASTERISKD_LOG_OK;
}

size_t asteriskd_log_buffered_bytes(
    const struct asteriskd_logger *logger,
    enum asteriskd_child_role role) {
    if (logger == NULL || (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER)) return 0U;
    size_t total = 0U;
    for (int stream = 0; stream < (int)ASTERISKD_LOG_STREAM_COUNT; ++stream) {
        total += logger->partials[role][stream].kept_length;
    }
    return total;
}

int asteriskd_log_close(struct asteriskd_logger *logger) {
    if (logger == NULL) return ASTERISKD_LOG_INVALID;
    if (!logger->opened) return logger->failed ? ASTERISKD_LOG_IO : ASTERISKD_LOG_OK;
    int result = logger->failed ? ASTERISKD_LOG_IO : ASTERISKD_LOG_OK;
    if (!logger->failed) {
        for (int role = 0; role < 2; ++role) {
            for (int stream = 0; stream < (int)ASTERISKD_LOG_STREAM_COUNT; ++stream) {
                int flush = emit_partial(
                    logger, (enum asteriskd_child_role)role, (enum asteriskd_log_stream)stream, false);
                if (flush != ASTERISKD_LOG_OK) result = flush;
            }
        }
    }
    if (logger->fd_owned && logger->fd >= 0 && logger->file_backend != NULL &&
        logger->file_backend->close_fd(logger->file_context, logger->fd) != 0) {
        result = ASTERISKD_LOG_IO;
    }
    if (logger->parent_fd_owned && logger->parent_fd >= 0 && logger->file_backend != NULL &&
        logger->file_backend->close_fd(logger->file_context, logger->parent_fd) != 0) {
        result = ASTERISKD_LOG_IO;
    }
    logger->fd = -1;
    logger->fd_owned = false;
    logger->parent_fd = -1;
    logger->parent_fd_owned = false;
    logger->opened = false;
    if (result != ASTERISKD_LOG_OK) logger->failed = true;
    return result;
}

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "asteriskd.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/memfd.h>
#include <net/if.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <io.h>
#endif

static size_t process_bounded_length(const char *value, size_t capacity) {
    if (value == NULL) return capacity;
    size_t length = 0U;
    while (length < capacity && value[length] != '\0') ++length;
    return length;
}

static bool process_env_key_equals(const char *entry, size_t key_length, const char *key) {
    return strlen(key) == key_length && memcmp(entry, key, key_length) == 0;
}

static bool process_env_blocked(const char *entry, size_t key_length) {
    static const char *const blocked[] = {
        "XRAY_LOCATION_ASSET", "SING_BOX_LOCATION_ASSET", "MIHOMO_LOCATION_ASSET",
        "CLASH_AGE_SECRET_KEY", "BPF2SOCKS_DEBUG_STATS",
        "LD_PRELOAD", "LD_LIBRARY_PATH",
    };
    for (size_t index = 0U; index < sizeof(blocked) / sizeof(blocked[0]); ++index) {
        if (process_env_key_equals(entry, key_length, blocked[index])) return true;
    }
    return false;
}

static bool process_env_has_key(
    const struct asteriskd_process_spec *spec,
    const char *entry,
    size_t key_length) {
    for (size_t index = 0U; index < spec->environment_count; ++index) {
        const char *existing = spec->environment[index];
        const char *separator = strchr(existing, '=');
        if (separator != NULL && (size_t)(separator - existing) == key_length &&
            memcmp(existing, entry, key_length) == 0) return true;
    }
    return false;
}

static int process_env_append_owned(
    struct asteriskd_process_spec *spec,
    const char *entry,
    size_t length) {
    if (spec->environment == NULL || spec->environment_count >= ASTERISKD_PROCESS_MAX_ENV ||
        length == 0U || length >= ASTERISKD_PROCESS_MAX_ENV_ENTRY) return -1;
    char *copy = malloc(length + 1U);
    if (copy == NULL) return -1;
    memcpy(copy, entry, length);
    copy[length] = '\0';
    spec->environment[spec->environment_count++] = copy;
    spec->environment[spec->environment_count] = NULL;
    return 0;
}

int asteriskd_process_environment_rebuild(
    const char *const *inherited,
    struct asteriskd_process_spec *spec) {
    if (spec == NULL || spec->environment != NULL || spec->environment_count != 0U) return -1;
    spec->environment = calloc(ASTERISKD_PROCESS_MAX_ENV + 1U, sizeof(*spec->environment));
    if (spec->environment == NULL) return -1;
    if (inherited == NULL) return 0;
    size_t index = 0U;
    for (; index < ASTERISKD_PROCESS_MAX_INHERITED_ENV && inherited[index] != NULL; ++index) {
        const char *entry = inherited[index];
        size_t length = process_bounded_length(entry, ASTERISKD_PROCESS_MAX_ENV_ENTRY);
        if (length == 0U || length >= ASTERISKD_PROCESS_MAX_ENV_ENTRY) return -1;
        const char *separator = memchr(entry, '=', length);
        if (separator == NULL || separator == entry) return -1;
        size_t key_length = (size_t)(separator - entry);
        if (process_env_blocked(entry, key_length) || process_env_has_key(spec, entry, key_length)) continue;
        if (process_env_append_owned(spec, entry, length) != 0) return -1;
    }
    return index == ASTERISKD_PROCESS_MAX_INHERITED_ENV ? -1 : 0;
}

int asteriskd_process_environment_add(
    struct asteriskd_process_spec *spec,
    const char *key,
    const char *value) {
    if (spec == NULL || key == NULL || value == NULL || strchr(key, '=') != NULL || key[0] == '\0') return -1;
    size_t key_length = process_bounded_length(key, ASTERISKD_PROCESS_MAX_ENV_ENTRY);
    size_t value_length = process_bounded_length(value, ASTERISKD_PROCESS_MAX_ENV_ENTRY);
    if (key_length >= ASTERISKD_PROCESS_MAX_ENV_ENTRY || value_length >= ASTERISKD_PROCESS_MAX_ENV_ENTRY ||
        key_length + value_length + 1U >= ASTERISKD_PROCESS_MAX_ENV_ENTRY ||
        process_env_has_key(spec, key, key_length)) return -1;
    size_t length = key_length + value_length + 1U;
    char *entry = malloc(length + 1U);
    if (entry == NULL) return -1;
    memcpy(entry, key, key_length);
    entry[key_length] = '=';
    memcpy(entry + key_length + 1U, value, value_length);
    entry[length] = '\0';
    if (spec->environment == NULL || spec->environment_count >= ASTERISKD_PROCESS_MAX_ENV) {
        free(entry);
        return -1;
    }
    spec->environment[spec->environment_count++] = entry;
    spec->environment[spec->environment_count] = NULL;
    return 0;
}

int asteriskd_process_argument_add(struct asteriskd_process_spec *spec, const char *argument) {
    if (spec == NULL || spec->argc >= ASTERISKD_MAX_PROCESS_ARGV) return -1;
    size_t length = process_bounded_length(argument, ASTERISKD_MAX_CHILD_ARG);
    if (length == 0U || length >= ASTERISKD_MAX_CHILD_ARG) return -1;
    memcpy(spec->argv[spec->argc], argument, length + 1U);
    ++spec->argc;
    return 0;
}

int asteriskd_process_core_log_path(
    const struct asteriskd_process_spec *spec,
    char *path,
    size_t path_size) {
    if (path != NULL && path_size != 0U) path[0] = '\0';
    if (spec == NULL || path == NULL || path_size == 0U ||
        spec->output_mode != ASTERISKD_PROCESS_OUTPUT_APPEND_CORE_LOG) {
        return ASTERISKD_CONFIG_INVALID;
    }
    size_t directory_length = process_bounded_length(
        spec->working_directory, sizeof(spec->working_directory));
    static const char suffix[] = "/logs/error.log";
    if (directory_length == 0U || directory_length >= sizeof(spec->working_directory) ||
        spec->working_directory[0] != '/' ||
        directory_length > path_size - 1U ||
        sizeof(suffix) - 1U > path_size - directory_length - 1U) {
        return ASTERISKD_CONFIG_INVALID;
    }
    memcpy(path, spec->working_directory, directory_length);
    memcpy(path + directory_length, suffix, sizeof(suffix));
    return 0;
}

void asteriskd_process_spec_destroy(struct asteriskd_process_spec *spec) {
    if (spec == NULL) return;
    if (spec->environment != NULL) {
        for (size_t index = 0U; index < spec->environment_count; ++index) {
            free(spec->environment[index]);
        }
        free(spec->environment);
    }
    memset(spec, 0, sizeof(*spec));
}

static void anonymous_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) {
        size_t length = strlen(message);
        if (length >= error_size) length = error_size - 1U;
        memcpy(error, message, length);
        error[length] = '\0';
    }
}

int asteriskd_anonymous_file_close(
    const struct asteriskd_anonymous_file_backend *backend,
    struct asteriskd_anonymous_file *file) {
    if (file == NULL) return ASTERISKD_CONFIG_INVALID;
    int result = 0;
    if (file->owned) {
        if (backend == NULL || backend->close == NULL ||
            backend->close(backend->context, file->fd) != 0) result = ASTERISKD_CONFIG_IO;
    }
    memset(file, 0, sizeof(*file));
    return result;
}

int asteriskd_anonymous_file_create(
    const struct asteriskd_anonymous_file_backend *backend,
    const char *name,
    const struct asteriskd_anonymous_document *document,
    struct asteriskd_anonymous_file *file,
    char *error,
    size_t error_size) {
    if (file != NULL) memset(file, 0, sizeof(*file));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (backend == NULL || name == NULL || name[0] == '\0' || document == NULL ||
        file == NULL || (document->length != 0U && document->bytes == NULL) ||
        backend->create == NULL || backend->write == NULL || backend->rewind == NULL ||
        backend->add_seals == NULL || backend->get_seals == NULL || backend->close == NULL) {
        anonymous_error(error, error_size, "invalid anonymous file input");
        return ASTERISKD_CONFIG_INVALID;
    }
    int fd = -1;
    uint32_t create_flags = ASTERISKD_ANONYMOUS_CREATE_CLOEXEC |
        ASTERISKD_ANONYMOUS_CREATE_ALLOW_SEALING;
    if (backend->create(backend->context, name, create_flags, &fd) != 0 || fd < 0) {
        if (fd >= 0) (void)backend->close(backend->context, fd);
        anonymous_error(error, error_size, "anonymous file creation failed");
        return ASTERISKD_CONFIG_IO;
    }
    file->fd = fd;
    file->owned = true;
    file->length = document->length;
    size_t offset = 0U;
    while (offset < document->length) {
        ptrdiff_t count = backend->write(
            backend->context, fd, document->bytes + offset, document->length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || (size_t)count > document->length - offset) goto io_failure;
        offset += (size_t)count;
    }
    if (backend->rewind(backend->context, fd) != 0 ||
        backend->add_seals(backend->context, fd, ASTERISKD_ANONYMOUS_REQUIRED_SEALS) != 0) goto io_failure;
    uint32_t observed_seals = 0U;
    if (backend->get_seals(backend->context, fd, &observed_seals) != 0 ||
        observed_seals != ASTERISKD_ANONYMOUS_REQUIRED_SEALS) goto io_failure;
    return 0;

io_failure:
    (void)asteriskd_anonymous_file_close(backend, file);
    anonymous_error(error, error_size, "anonymous file preparation failed");
    return ASTERISKD_CONFIG_IO;
}

#if defined(__linux__)
static int system_anonymous_create(void *context, const char *name, uint32_t flags, int *fd) {
    (void)context;
    unsigned int native_flags = 0U;
    if ((flags & ASTERISKD_ANONYMOUS_CREATE_CLOEXEC) != 0U) native_flags |= MFD_CLOEXEC;
    if ((flags & ASTERISKD_ANONYMOUS_CREATE_ALLOW_SEALING) != 0U) native_flags |= MFD_ALLOW_SEALING;
    long result = syscall(__NR_memfd_create, name, native_flags);
    if (result < 0 || result > INT32_MAX) return -1;
    *fd = (int)result;
    return 0;
}

static ptrdiff_t system_anonymous_write(void *context, int fd, const void *bytes, size_t length) {
    (void)context;
    return (ptrdiff_t)write(fd, bytes, length);
}

static int system_anonymous_rewind(void *context, int fd) {
    (void)context;
    return lseek(fd, 0, SEEK_SET) == 0 ? 0 : -1;
}

static int system_anonymous_add_seals(void *context, int fd, uint32_t seals) {
    (void)context;
    int native_seals = 0;
    if ((seals & ASTERISKD_ANONYMOUS_SEAL_WRITE) != 0U) native_seals |= F_SEAL_WRITE;
    if ((seals & ASTERISKD_ANONYMOUS_SEAL_GROW) != 0U) native_seals |= F_SEAL_GROW;
    if ((seals & ASTERISKD_ANONYMOUS_SEAL_SHRINK) != 0U) native_seals |= F_SEAL_SHRINK;
    if ((seals & ASTERISKD_ANONYMOUS_SEAL_SEAL) != 0U) native_seals |= F_SEAL_SEAL;
    return fcntl(fd, F_ADD_SEALS, native_seals);
}

static int system_anonymous_get_seals(void *context, int fd, uint32_t *seals) {
    (void)context;
    int native_seals = fcntl(fd, F_GET_SEALS);
    if (native_seals < 0) return -1;
    uint32_t result = 0U;
    if ((native_seals & F_SEAL_WRITE) != 0) result |= ASTERISKD_ANONYMOUS_SEAL_WRITE;
    if ((native_seals & F_SEAL_GROW) != 0) result |= ASTERISKD_ANONYMOUS_SEAL_GROW;
    if ((native_seals & F_SEAL_SHRINK) != 0) result |= ASTERISKD_ANONYMOUS_SEAL_SHRINK;
    if ((native_seals & F_SEAL_SEAL) != 0) result |= ASTERISKD_ANONYMOUS_SEAL_SEAL;
    *seals = result;
    return 0;
}

static int system_anonymous_close(void *context, int fd) {
    (void)context;
    return close(fd);
}

static const struct asteriskd_anonymous_file_backend system_anonymous_backend = {
    .context = NULL,
    .create = system_anonymous_create,
    .write = system_anonymous_write,
    .rewind = system_anonymous_rewind,
    .add_seals = system_anonymous_add_seals,
    .get_seals = system_anonymous_get_seals,
    .close = system_anonymous_close,
};
#endif

const struct asteriskd_anonymous_file_backend *asteriskd_system_anonymous_file_backend(void) {
#if defined(__linux__)
    return &system_anonymous_backend;
#else
    return NULL;
#endif
}

int asteriskd_child_setup_run(
    const struct asteriskd_process_spec *spec,
    int captured_parent_pid,
    const struct asteriskd_child_setup_backend *backend,
    bool *rlimit_warning,
    char *error,
    size_t error_size) {
    if (rlimit_warning != NULL) *rlimit_warning = false;
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (spec == NULL || captured_parent_pid <= 0 || backend == NULL ||
        backend->restore_signals == NULL || backend->create_session == NULL ||
        backend->set_nofile_limit == NULL || backend->clear_supplementary_groups == NULL ||
        backend->set_gid == NULL || backend->set_uid == NULL ||
        backend->set_parent_death_signal == NULL || backend->get_parent_pid == NULL ||
        backend->prepare_descriptors == NULL || backend->exec_process == NULL) {
        anonymous_error(error, error_size, "invalid child setup input");
        return ASTERISKD_CONFIG_INVALID;
    }
    if (backend->restore_signals(backend->context) != 0) goto failed;
    if (backend->create_session(backend->context) != 0) goto failed;
    if (backend->set_nofile_limit(backend->context, UINT64_C(1000000)) != 0 &&
        rlimit_warning != NULL) *rlimit_warning = true;
    if (backend->clear_supplementary_groups(backend->context) != 0) goto failed;
    if (backend->set_gid(backend->context, spec->gid) != 0) goto failed;
    if (backend->set_uid(backend->context, spec->uid) != 0) goto failed;
    if (backend->set_parent_death_signal(backend->context, SIGTERM) != 0) goto failed;
    int observed_parent_pid = -1;
    if (backend->get_parent_pid(backend->context, &observed_parent_pid) != 0 ||
        observed_parent_pid != captured_parent_pid) goto failed;
    if (backend->prepare_descriptors(backend->context, spec) != 0) goto failed;
    if (backend->exec_process(backend->context, spec) != 0) goto failed;
    return 0;

failed:
    anonymous_error(error, error_size, "child setup failed");
    return ASTERISKD_CONFIG_IO;
}

struct process_stat_snapshot {
    char state;
    int process_group_id;
    int session_id;
    uint64_t start_time_ticks;
};

static int process_parse_stat(
    char *text,
    size_t length,
    int expected_pid,
    struct process_stat_snapshot *snapshot) {
    if (text == NULL || snapshot == NULL || length == 0U || length >= 4096U) return -1;
    text[length] = '\0';
    char *end = NULL;
    errno = 0;
    long pid = strtol(text, &end, 10);
    if (errno != 0 || end == text || pid != expected_pid || *end != ' ') return -1;
    char *right_parenthesis = strrchr(end + 1, ')');
    if (right_parenthesis == NULL || right_parenthesis[1] != ' ' ||
        right_parenthesis[2] == '\0' || right_parenthesis[3] != ' ') return -1;
    snapshot->state = right_parenthesis[2];
    if (snapshot->state == 'Z' || snapshot->state == 'X' || snapshot->state == 'x') return -1;
    char *cursor = right_parenthesis + 4;
    int64_t values[19U];
    for (size_t index = 0U; index < 19U; ++index) {
        errno = 0;
        char *number_end = NULL;
        long long value = strtoll(cursor, &number_end, 10);
        if (errno != 0 || number_end == cursor ||
            (*number_end != ' ' && *number_end != '\0')) return -1;
        values[index] = (int64_t)value;
        cursor = *number_end == ' ' ? number_end + 1 : number_end;
    }
    if (values[1] <= 0 || values[1] > INT32_MAX ||
        values[2] <= 0 || values[2] > INT32_MAX || values[18] <= 0) return -1;
    snapshot->process_group_id = (int)values[1];
    snapshot->session_id = (int)values[2];
    snapshot->start_time_ticks = (uint64_t)values[18];
    return 0;
}

int asteriskd_process_identity_read(
    const struct asteriskd_process_identity_backend *backend,
    int pid,
    enum asteriskd_child_role role,
    enum asteriskd_child_type type,
    const struct asteriskd_process_spec *spec,
    struct asteriskd_child_identity *identity,
    char *error,
    size_t error_size) {
    if (identity != NULL) memset(identity, 0, sizeof(*identity));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (backend == NULL || pid <= 0 ||
        (role != ASTERISKD_CHILD_CORE && role != ASTERISKD_CHILD_HELPER) ||
        type < ASTERISKD_CHILD_TYPE_XRAY || type >= ASTERISKD_CHILD_TYPE_COUNT ||
        spec == NULL || spec->argc == 0U || spec->argc > ASTERISKD_MAX_PROCESS_ARGV ||
        identity == NULL || backend->read_stat == NULL ||
        backend->read_exe_identity == NULL || backend->read_cmdline == NULL) {
        anonymous_error(error, error_size, "invalid process identity input");
        return ASTERISKD_CONFIG_INVALID;
    }
    char stat_text[4096U];
    size_t stat_length = 0U;
    struct process_stat_snapshot first;
    memset(&first, 0, sizeof(first));
    if (backend->read_stat(
            backend->context, pid, stat_text, sizeof(stat_text) - 1U, &stat_length) != 0 ||
        stat_length >= sizeof(stat_text) ||
        process_parse_stat(stat_text, stat_length, pid, &first) != 0 ||
        first.process_group_id != pid || first.session_id != pid) goto mismatch;
    uint64_t device = 0U;
    uint64_t inode = 0U;
    if (backend->read_exe_identity(backend->context, pid, &device, &inode) != 0 ||
        device == 0U || inode == 0U) goto mismatch;
    unsigned char cmdline[ASTERISKD_MAX_PROCESS_ARGV * ASTERISKD_MAX_CHILD_ARG + 1U];
    size_t cmdline_length = 0U;
    if (backend->read_cmdline(
            backend->context, pid, cmdline, sizeof(cmdline), &cmdline_length) != 0 ||
        cmdline_length == 0U || cmdline_length >= sizeof(cmdline)) goto mismatch;
    size_t offset = 0U;
    for (size_t index = 0U; index < spec->argc; ++index) {
        size_t expected_length = strnlen(spec->argv[index], ASTERISKD_MAX_CHILD_ARG);
        if (expected_length == 0U || expected_length >= ASTERISKD_MAX_CHILD_ARG ||
            expected_length + 1U > cmdline_length - offset ||
            memcmp(cmdline + offset, spec->argv[index], expected_length) != 0 ||
            cmdline[offset + expected_length] != '\0') goto mismatch;
        offset += expected_length + 1U;
    }
    if (offset != cmdline_length) goto mismatch;
    struct process_stat_snapshot second;
    memset(&second, 0, sizeof(second));
    if (backend->read_stat(
            backend->context, pid, stat_text, sizeof(stat_text) - 1U, &stat_length) != 0 ||
        stat_length >= sizeof(stat_text) ||
        process_parse_stat(stat_text, stat_length, pid, &second) != 0 ||
        second.process_group_id != first.process_group_id ||
        second.session_id != first.session_id ||
        second.start_time_ticks != first.start_time_ticks) goto mismatch;
    identity->role = role;
    identity->type = type;
    identity->pid = pid;
    identity->process_group_id = first.process_group_id;
    identity->start_time_ticks = first.start_time_ticks;
    identity->exe_device = device;
    identity->exe_inode = inode;
    identity->argc = spec->argc;
    for (size_t index = 0U; index < spec->argc; ++index) {
        memcpy(identity->argv[index], spec->argv[index], strlen(spec->argv[index]) + 1U);
    }
    return 0;

mismatch:
    memset(identity, 0, sizeof(*identity));
    anonymous_error(error, error_size, "process identity mismatch");
    return ASTERISKD_CONFIG_IO;
}

#if defined(__linux__)
static int system_read_proc_file(
    const char *path,
    unsigned char *out,
    size_t capacity,
    size_t *length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t offset = 0U;
    int result = 0;
    while (offset < capacity) {
        ssize_t count = read(fd, out + offset, capacity - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            result = -1;
            break;
        }
        if (count == 0) break;
        offset += (size_t)count;
    }
    if (result == 0 && offset == capacity) {
        unsigned char extra;
        ssize_t count;
        do {
            count = read(fd, &extra, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 0) result = -1;
    }
    int saved_errno = errno;
    if (close(fd) != 0 && result == 0) result = -1;
    errno = saved_errno;
    if (result == 0) *length = offset;
    return result;
}

static int system_proc_path(char *path, size_t capacity, int pid, const char *leaf) {
    int count = snprintf(path, capacity, "/proc/%d/%s", pid, leaf);
    return count > 0 && (size_t)count < capacity ? 0 : -1;
}

static int system_identity_read_stat(void *context, int pid, char *out, size_t capacity, size_t *length) {
    (void)context;
    char path[64];
    if (system_proc_path(path, sizeof(path), pid, "stat") != 0) return -1;
    return system_read_proc_file(path, (unsigned char *)out, capacity, length);
}

static int system_identity_read_exe(void *context, int pid, uint64_t *device, uint64_t *inode) {
    (void)context;
    char path[64];
    if (system_proc_path(path, sizeof(path), pid, "exe") != 0) return -1;
    struct stat status;
    if (stat(path, &status) != 0 || !S_ISREG(status.st_mode)) return -1;
    *device = (uint64_t)status.st_dev;
    *inode = (uint64_t)status.st_ino;
    return 0;
}

static int system_identity_read_cmdline(
    void *context, int pid, unsigned char *out, size_t capacity, size_t *length) {
    (void)context;
    char path[64];
    if (system_proc_path(path, sizeof(path), pid, "cmdline") != 0) return -1;
    return system_read_proc_file(path, out, capacity, length);
}

static const struct asteriskd_process_identity_backend system_identity_backend = {
    .context = NULL,
    .read_stat = system_identity_read_stat,
    .read_exe_identity = system_identity_read_exe,
    .read_cmdline = system_identity_read_cmdline,
};
#endif

const struct asteriskd_process_identity_backend *asteriskd_system_process_identity_backend(void) {
#if defined(__linux__)
    return &system_identity_backend;
#else
    return NULL;
#endif
}

static const char *readiness_interface_name(
    const struct asteriskd_config *config,
    enum asteriskd_child_role role) {
    if (role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_TUN) {
        return config->tunnel_name;
    }
    if (role == ASTERISKD_CHILD_HELPER && config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        return config->helper.value.hev.tunnel_name;
    }
    return NULL;
}

static bool readiness_role_valid(
    const struct asteriskd_config *config, enum asteriskd_child_role role) {
    return role == ASTERISKD_CHILD_CORE ||
        (role == ASTERISKD_CHILD_HELPER &&
            (config->mode == ASTERISKD_MODE_TUN2SOCKS ||
             config->mode == ASTERISKD_MODE_BPF2SOCKS));
}

int asteriskd_readiness_preflight(
    const struct asteriskd_config *config,
    enum asteriskd_child_role role,
    const struct asteriskd_readiness_backend *backend) {
    if (config == NULL || backend == NULL || backend->interface_exists == NULL ||
        !readiness_role_valid(config, role)) return ASTERISKD_CONFIG_INVALID;
    const char *interface_name = readiness_interface_name(config, role);
    if (interface_name == NULL) return 0;
    bool exists = false;
    if (backend->interface_exists(
            backend->context, interface_name, &exists) != 0) return ASTERISKD_READINESS_IO;
    return exists ? ASTERISKD_READINESS_CONFLICT : 0;
}

int asteriskd_readiness_init(
    const struct asteriskd_config *config,
    enum asteriskd_child_role role,
    uint64_t now_milliseconds,
    const struct asteriskd_readiness_backend *backend,
    struct asteriskd_readiness_tracker *tracker) {
    if (tracker != NULL) memset(tracker, 0, sizeof(*tracker));
    if (config == NULL || tracker == NULL || backend == NULL ||
        backend->identity_valid == NULL || backend->listener_owned == NULL ||
        backend->interface_exists == NULL ||
        !readiness_role_valid(config, role) ||
        now_milliseconds > UINT64_MAX - config->readiness_timeout_milliseconds) {
        return ASTERISKD_CONFIG_INVALID;
    }
    tracker->role = role;
    tracker->mode = config->mode;
    tracker->deadline_milliseconds = now_milliseconds + config->readiness_timeout_milliseconds;
    tracker->initialized = true;
    return 0;
}

int asteriskd_readiness_poll(
    const struct asteriskd_config *config,
    struct asteriskd_readiness_tracker *tracker,
    const struct asteriskd_child_identity *identity,
    const struct asteriskd_readiness_backend *backend,
    uint64_t now_milliseconds,
    bool stop_requested) {
    if (config == NULL || tracker == NULL || identity == NULL || backend == NULL ||
        !tracker->initialized || tracker->mode != config->mode ||
        backend->identity_valid == NULL || backend->listener_owned == NULL ||
        backend->interface_exists == NULL) return ASTERISKD_CONFIG_INVALID;
    if (stop_requested) return ASTERISKD_READINESS_STOP_REQUESTED;
    bool identity_valid = false;
    if (backend->identity_valid(backend->context, identity, &identity_valid) != 0) {
        return ASTERISKD_READINESS_IO;
    }
    if (!identity_valid) return ASTERISKD_READINESS_CHILD_LOST;
    bool ready = false;
    if (tracker->role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_TPROXY) {
        const char *host = config->core_type == ASTERISKD_CORE_MIHOMO ?
            "127.0.0.1" : "0.0.0.0";
        if (backend->listener_owned(
                backend->context, identity, host, config->transparent_port, &ready) != 0) {
            return ASTERISKD_READINESS_IO;
        }
    } else if (tracker->role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_TUN) {
        if (backend->interface_exists(
                backend->context, config->tunnel_name, &ready) != 0) return ASTERISKD_READINESS_IO;
    } else if (tracker->role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        const struct asteriskd_hev_helper_config *hev = &config->helper.value.hev;
        if (backend->listener_owned(
                backend->context, identity, hev->socks_host, hev->socks_port, &ready) != 0) {
            return ASTERISKD_READINESS_IO;
        }
    } else if (tracker->role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_BPF2SOCKS) {
        const struct asteriskd_bpf_helper_config *bpf = &config->helper.value.bpf;
        if (backend->listener_owned(
                backend->context, identity, bpf->socks_host, bpf->socks_port, &ready) != 0) {
            return ASTERISKD_READINESS_IO;
        }
    } else if (tracker->role == ASTERISKD_CHILD_CORE && config->mode == ASTERISKD_MODE_EBPF) {
        ready = true;
    } else if (tracker->role == ASTERISKD_CHILD_HELPER && config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        if (backend->interface_exists(
                backend->context, config->helper.value.hev.tunnel_name, &ready) != 0) {
            return ASTERISKD_READINESS_IO;
        }
    } else if (tracker->role == ASTERISKD_CHILD_HELPER && config->mode == ASTERISKD_MODE_BPF2SOCKS) {
        const struct asteriskd_bpf_helper_config *bpf = &config->helper.value.bpf;
        if (backend->listener_owned(
                backend->context, identity, bpf->bridge_listen_address, bpf->bridge_port,
                &ready) != 0) return ASTERISKD_READINESS_IO;
    } else {
        return ASTERISKD_CONFIG_INVALID;
    }
    if (ready) return ASTERISKD_READINESS_READY;
    return now_milliseconds >= tracker->deadline_milliseconds ?
        ASTERISKD_READINESS_TIMEOUT : ASTERISKD_READINESS_PENDING;
}

void asteriskd_stop_coordinator_init(struct asteriskd_stop_coordinator *coordinator) {
    if (coordinator == NULL) return;
    memset(coordinator, 0, sizeof(*coordinator));
    coordinator->initialized = true;
}

static int stop_backend_valid(const struct asteriskd_stop_backend *backend) {
    return backend != NULL && backend->identity_valid != NULL &&
        backend->signal_group != NULL && backend->reap != NULL;
}

static void stop_role_assign(
    struct asteriskd_stop_role_state *role,
    const struct asteriskd_child_identity *identity) {
    memset(role, 0, sizeof(*role));
    if (identity != NULL) {
        role->present = true;
        role->cleanup_required = true;
        role->identity = *identity;
    }
}

static bool stop_role_validate_term(
    struct asteriskd_stop_role_state *role,
    const struct asteriskd_stop_backend *backend) {
    if (!role->present || !role->cleanup_required) return false;
    role->term_sent = false;
    role->kill_sent = false;
    role->signal_failed = false;
    bool valid = false;
    if (backend->identity_valid(backend->context, &role->identity, &valid) != 0 || !valid) {
        role->signal_failed = true;
        return false;
    }
    return true;
}

static void stop_role_send_term(
    struct asteriskd_stop_role_state *role,
    const struct asteriskd_stop_backend *backend,
    bool valid) {
    if (!valid) return;
    if (backend->signal_group(backend->context, &role->identity, SIGTERM) != 0) {
        role->signal_failed = true;
        return;
    }
    role->term_sent = true;
}

int asteriskd_stop_coordinator_begin(
    struct asteriskd_stop_coordinator *coordinator,
    const struct asteriskd_child_identity *core,
    const struct asteriskd_child_identity *helper,
    const struct asteriskd_stop_backend *backend,
    uint64_t now_milliseconds) {
    if (coordinator == NULL || !coordinator->initialized || coordinator->active ||
        !stop_backend_valid(backend) ||
        now_milliseconds > UINT64_MAX - ASTERISKD_PROCESS_TERM_GRACE_MILLIS ||
        now_milliseconds + ASTERISKD_PROCESS_TERM_GRACE_MILLIS >
            UINT64_MAX - ASTERISKD_PROCESS_KILL_REAP_MILLIS) return ASTERISKD_CONFIG_INVALID;
    if (!coordinator->core.present && !coordinator->helper.present) {
        stop_role_assign(&coordinator->core, core);
        stop_role_assign(&coordinator->helper, helper);
    }
    if (!coordinator->core.cleanup_required && !coordinator->helper.cleanup_required) {
        return ASTERISKD_STOP_COMPLETE;
    }
    coordinator->term_deadline_milliseconds =
        now_milliseconds + ASTERISKD_PROCESS_TERM_GRACE_MILLIS;
    coordinator->kill_deadline_milliseconds =
        coordinator->term_deadline_milliseconds + ASTERISKD_PROCESS_KILL_REAP_MILLIS;
    coordinator->active = true;
    bool helper_valid = stop_role_validate_term(&coordinator->helper, backend);
    bool core_valid = stop_role_validate_term(&coordinator->core, backend);
    stop_role_send_term(&coordinator->helper, backend, helper_valid);
    stop_role_send_term(&coordinator->core, backend, core_valid);
    return ASTERISKD_STOP_PENDING;
}

static int stop_role_reap(
    struct asteriskd_stop_role_state *role,
    const struct asteriskd_stop_backend *backend) {
    if (!role->present || !role->cleanup_required) return 0;
    bool reaped = false;
    struct asteriskd_child_exit_status status;
    memset(&status, 0, sizeof(status));
    if (backend->reap(
            backend->context, &role->identity, &reaped, &status) != 0) return -1;
    if (reaped) {
        role->reaped = true;
        role->exit_status = status;
        role->cleanup_required = false;
        role->signal_failed = false;
    }
    return 0;
}

static void stop_role_kill(
    struct asteriskd_stop_role_state *role,
    const struct asteriskd_stop_backend *backend) {
    if (!role->present || !role->cleanup_required || role->kill_sent) return;
    bool valid = false;
    if (backend->identity_valid(backend->context, &role->identity, &valid) != 0 || !valid ||
        backend->signal_group(backend->context, &role->identity, 9) != 0) {
        role->signal_failed = true;
        return;
    }
    role->kill_sent = true;
    role->signal_failed = false;
}

int asteriskd_stop_coordinator_poll(
    struct asteriskd_stop_coordinator *coordinator,
    const struct asteriskd_stop_backend *backend,
    uint64_t now_milliseconds) {
    if (coordinator == NULL || !coordinator->initialized || !coordinator->active ||
        !stop_backend_valid(backend)) return ASTERISKD_CONFIG_INVALID;
    if (stop_role_reap(&coordinator->helper, backend) != 0 ||
        stop_role_reap(&coordinator->core, backend) != 0) {
        coordinator->active = false;
        return ASTERISKD_STOP_FAILED;
    }
    if (!coordinator->helper.cleanup_required && !coordinator->core.cleanup_required) {
        coordinator->active = false;
        return ASTERISKD_STOP_COMPLETE;
    }
    if (now_milliseconds >= coordinator->term_deadline_milliseconds) {
        stop_role_kill(&coordinator->helper, backend);
        stop_role_kill(&coordinator->core, backend);
    }
    if (now_milliseconds >= coordinator->kill_deadline_milliseconds) {
        if (stop_role_reap(&coordinator->helper, backend) != 0 ||
            stop_role_reap(&coordinator->core, backend) != 0) {
            coordinator->active = false;
            return ASTERISKD_STOP_FAILED;
        }
        coordinator->active = false;
        return !coordinator->helper.cleanup_required && !coordinator->core.cleanup_required ?
            ASTERISKD_STOP_COMPLETE : ASTERISKD_STOP_FAILED;
    }
    return ASTERISKD_STOP_PENDING;
}

int asteriskd_child_exit_status_from_wait(
    int wait_status,
    struct asteriskd_child_exit_status *status) {
    if (status != NULL) memset(status, 0, sizeof(*status));
    if (status == NULL || wait_status < 0) return ASTERISKD_CONFIG_INVALID;
    unsigned low = (unsigned)wait_status & 0x7FU;
    if (low == 0U) {
        status->has_exit_code = true;
        status->exit_code = ((unsigned)wait_status >> 8U) & 0xFFU;
        return 0;
    }
    if (low == 0x7FU) return ASTERISKD_CONFIG_INVALID;
    status->has_signal = true;
    status->signal_number = (int)low;
    return 0;
}

static int process_close_fd(int fd) {
#if defined(__linux__)
    return close(fd);
#elif defined(_WIN32)
    return _close(fd);
#else
    (void)fd;
    return -1;
#endif
}

void asteriskd_child_process_close(struct asteriskd_child_process *child) {
    if (child == NULL) return;
    if (child->owns_pidfd) (void)process_close_fd(child->pidfd);
    if (child->owns_stdout_fd) (void)process_close_fd(child->stdout_fd);
    if (child->owns_stderr_fd) (void)process_close_fd(child->stderr_fd);
    if (child->owns_setup_status_fd) (void)process_close_fd(child->setup_status_fd);
    memset(child, 0, sizeof(*child));
}

void asteriskd_child_setup_stream_init(struct asteriskd_child_setup_stream *stream) {
    if (stream == NULL) return;
    memset(stream, 0, sizeof(*stream));
}

int asteriskd_child_setup_stream_feed(
    struct asteriskd_child_setup_stream *stream,
    const void *bytes,
    size_t length,
    bool eof) {
    if (stream == NULL || stream->complete || (length != 0U && bytes == NULL) ||
        (stream->fatal && length != 0U)) return ASTERISKD_CHILD_SETUP_INVALID;
    const unsigned char *cursor = bytes;
    while (length != 0U) {
        size_t available = sizeof(stream->partial) - stream->partial_length;
        size_t amount = length < available ? length : available;
        memcpy(stream->partial + stream->partial_length, cursor, amount);
        stream->partial_length += amount;
        cursor += amount;
        length -= amount;
        if (stream->partial_length != sizeof(stream->partial)) continue;
        struct asteriskd_child_setup_message message;
        memcpy(&message, stream->partial, sizeof(message));
        stream->partial_length = 0U;
        memset(stream->partial, 0, sizeof(stream->partial));
        if (message.magic != ASTERISKD_CHILD_SETUP_MESSAGE_MAGIC || message.error_number <= 0) {
            stream->complete = true;
            return ASTERISKD_CHILD_SETUP_INVALID;
        }
        if (message.kind == ASTERISKD_CHILD_SETUP_WARNING_NOFILE && !stream->nofile_warning && !stream->fatal) {
            stream->nofile_warning = true;
            stream->nofile_error_number = message.error_number;
        } else if (message.kind == ASTERISKD_CHILD_SETUP_FATAL && !stream->fatal) {
            stream->fatal = true;
            stream->fatal_error_number = message.error_number;
            if (length != 0U) {
                stream->complete = true;
                return ASTERISKD_CHILD_SETUP_INVALID;
            }
            if (!eof) return ASTERISKD_CHILD_SETUP_FAILED;
        } else {
            stream->complete = true;
            return ASTERISKD_CHILD_SETUP_INVALID;
        }
    }
    if (!eof) return stream->fatal ? ASTERISKD_CHILD_SETUP_FAILED : ASTERISKD_CHILD_SETUP_PENDING;
    stream->complete = true;
    if (stream->partial_length != 0U) return ASTERISKD_CHILD_SETUP_INVALID;
    return stream->fatal ? ASTERISKD_CHILD_SETUP_FAILED : ASTERISKD_CHILD_SETUP_EXECUTED;
}

#if defined(__linux__)
struct system_child_setup_context {
    int captured_parent_pid;
    int stdout_fd;
    int stderr_fd;
    int status_fd;
    int last_errno;
};

static void system_child_message(
    struct system_child_setup_context *context,
    enum asteriskd_child_setup_message_kind kind,
    int error_number) {
    struct asteriskd_child_setup_message message = {
        .magic = ASTERISKD_CHILD_SETUP_MESSAGE_MAGIC,
        .kind = (uint32_t)kind,
        .error_number = error_number,
    };
    const unsigned char *bytes = (const unsigned char *)&message;
    size_t offset = 0U;
    while (offset < sizeof(message)) {
        ssize_t count = write(context->status_fd, bytes + offset, sizeof(message) - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        offset += (size_t)count;
    }
}

static int system_child_restore_signals(void *opaque) {
    struct system_child_setup_context *context = opaque;
    sigset_t empty;
    if (sigemptyset(&empty) != 0 || sigprocmask(SIG_SETMASK, &empty, NULL) != 0) {
        context->last_errno = errno;
        return -1;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask) != 0) {
        context->last_errno = errno;
        return -1;
    }
    for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP) continue;
        if (sigaction(signal_number, &action, NULL) != 0 && errno != EINVAL) {
            context->last_errno = errno;
            return -1;
        }
    }
    return 0;
}

static int system_child_create_session(void *opaque) {
    struct system_child_setup_context *context = opaque;
    if (setsid() < 0) {
        context->last_errno = errno;
        return -1;
    }
    return 0;
}

static int system_child_set_nofile(void *opaque, uint64_t value) {
    struct system_child_setup_context *context = opaque;
    struct rlimit limit = {(rlim_t)value, (rlim_t)value};
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
        int error_number = errno;
        system_child_message(context, ASTERISKD_CHILD_SETUP_WARNING_NOFILE, error_number);
        return -1;
    }
    return 0;
}

static int system_child_clear_groups(void *opaque) {
    struct system_child_setup_context *context = opaque;
    if (setgroups(0U, NULL) != 0) {
        context->last_errno = errno;
        return -1;
    }
    return 0;
}

static int system_child_set_gid(void *opaque, uint32_t gid) {
    struct system_child_setup_context *context = opaque;
    if (setresgid((gid_t)gid, (gid_t)gid, (gid_t)gid) != 0) {
        context->last_errno = errno;
        return -1;
    }
    return 0;
}

static int system_child_set_uid(void *opaque, uint32_t uid) {
    struct system_child_setup_context *context = opaque;
    if (setresuid((uid_t)uid, (uid_t)uid, (uid_t)uid) != 0) {
        context->last_errno = errno;
        return -1;
    }
    return 0;
}

static int system_child_set_pdeathsig(void *opaque, int signal_number) {
    struct system_child_setup_context *context = opaque;
    if (prctl(PR_SET_PDEATHSIG, signal_number, 0UL, 0UL, 0UL) != 0) {
        context->last_errno = errno;
        return -1;
    }
    return 0;
}

static int system_child_getppid(void *opaque, int *pid) {
    (void)opaque;
    *pid = (int)getppid();
    return 0;
}

static int system_child_stage_fd(
    struct system_child_setup_context *context,
    int source) {
    int staged = fcntl(source, F_DUPFD_CLOEXEC, 16);
    if (staged < 0) context->last_errno = errno;
    return staged;
}

static void system_child_close_if_distinct(int fd, int keep) {
    if (fd >= 0 && fd != keep) (void)close(fd);
}

static int system_child_prepare_descriptors(
    void *opaque,
    const struct asteriskd_process_spec *spec) {
    struct system_child_setup_context *context = opaque;
    int original_status = context->status_fd;
    int staged_status = system_child_stage_fd(context, original_status);
    if (staged_status < 0) return -1;
    context->status_fd = staged_status;
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd < 0) {
        context->last_errno = errno;
        return -1;
    }
    int staged_stdin = system_child_stage_fd(context, null_fd);
    int staged_stdout = system_child_stage_fd(context, context->stdout_fd);
    int staged_stderr = system_child_stage_fd(context, context->stderr_fd);
    int staged_inherited[ASTERISKD_PROCESS_MAX_INHERITED_FDS];
    for (size_t index = 0U; index < ASTERISKD_PROCESS_MAX_INHERITED_FDS; ++index) {
        staged_inherited[index] = -1;
    }
    if (staged_stdin < 0 || staged_stdout < 0 || staged_stderr < 0) goto failed;
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        staged_inherited[index] = system_child_stage_fd(context, spec->inherited_fds[index]);
        if (staged_inherited[index] < 0) goto failed;
    }
    (void)close(original_status);
    (void)close(null_fd);
    system_child_close_if_distinct(context->stdout_fd, STDOUT_FILENO);
    if (context->stderr_fd != context->stdout_fd) {
        system_child_close_if_distinct(context->stderr_fd, STDERR_FILENO);
    }
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        if (spec->inherited_fds[index] > STDERR_FILENO) (void)close(spec->inherited_fds[index]);
    }
    if (chdir(spec->working_directory) != 0 || dup2(staged_stdin, STDIN_FILENO) < 0 ||
        dup2(staged_stdout, STDOUT_FILENO) < 0 || dup2(staged_stderr, STDERR_FILENO) < 0) {
        context->last_errno = errno;
        goto failed;
    }
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        if (dup2(staged_inherited[index], spec->inherited_fd_targets[index]) < 0) {
            context->last_errno = errno;
            goto failed;
        }
    }
    (void)close(staged_stdin);
    (void)close(staged_stdout);
    (void)close(staged_stderr);
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        (void)close(staged_inherited[index]);
    }
    (void)close(8);
    (void)close(9);
    return 0;

failed:
    if (staged_stdin >= 0) (void)close(staged_stdin);
    if (staged_stdout >= 0) (void)close(staged_stdout);
    if (staged_stderr >= 0) (void)close(staged_stderr);
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        if (staged_inherited[index] >= 0) (void)close(staged_inherited[index]);
    }
    (void)close(null_fd);
    return -1;
}

static int system_child_exec(void *opaque, const struct asteriskd_process_spec *spec) {
    struct system_child_setup_context *context = opaque;
    char *argv[ASTERISKD_MAX_PROCESS_ARGV + 1U];
    for (size_t index = 0U; index < spec->argc; ++index) argv[index] = (char *)spec->argv[index];
    argv[spec->argc] = NULL;
    execve(spec->executable_path, argv, spec->environment);
    context->last_errno = errno;
    return -1;
}

static int system_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void system_spawn_close_pipe(int pipe_fds[2U]) {
    if (pipe_fds[0] >= 0) (void)close(pipe_fds[0]);
    if (pipe_fds[1] >= 0) (void)close(pipe_fds[1]);
    pipe_fds[0] = -1;
    pipe_fds[1] = -1;
}

static void system_spawn_close_fd(int *fd) {
    if (fd != NULL && *fd >= 0) (void)close(*fd);
    if (fd != NULL) *fd = -1;
}
#endif

int asteriskd_process_spawn_system(
    const struct asteriskd_process_spec *spec,
    struct asteriskd_child_process *child,
    char *error,
    size_t error_size) {
    if (child != NULL) {
        memset(child, 0, sizeof(*child));
        child->pid = -1;
        child->process_group_id = -1;
        child->pidfd = -1;
        child->stdout_fd = -1;
        child->stderr_fd = -1;
        child->setup_status_fd = -1;
    }
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (spec == NULL || child == NULL || spec->argc == 0U ||
        spec->environment == NULL || spec->inherited_fd_count > ASTERISKD_PROCESS_MAX_INHERITED_FDS ||
        spec->output_mode < ASTERISKD_PROCESS_OUTPUT_CAPTURE ||
        spec->output_mode >= ASTERISKD_PROCESS_OUTPUT_COUNT) {
        anonymous_error(error, error_size, "invalid spawn input");
        return ASTERISKD_CONFIG_INVALID;
    }
#if defined(__linux__)
    int stdout_pipe[2U] = {-1, -1};
    int stderr_pipe[2U] = {-1, -1};
    int status_pipe[2U] = {-1, -1};
    int output_fd = -1;
    bool capture = spec->output_mode == ASTERISKD_PROCESS_OUTPUT_CAPTURE;
    if (capture) {
        if (pipe2(stdout_pipe, O_CLOEXEC) != 0 || pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
            system_set_nonblocking(stdout_pipe[0]) != 0 ||
            system_set_nonblocking(stderr_pipe[0]) != 0) goto spawn_failed;
    } else if (spec->output_mode == ASTERISKD_PROCESS_OUTPUT_APPEND_CORE_LOG) {
        char path[ASTERISKD_MAX_PATH];
        if (asteriskd_process_core_log_path(spec, path, sizeof(path)) != 0 ||
            asteriskd_log_open_append_fd(
                path, &output_fd, error, error_size) != ASTERISKD_LOG_OK) goto spawn_failed;
    } else {
        output_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (output_fd < 0) goto spawn_failed;
    }
    if (pipe2(status_pipe, O_CLOEXEC) != 0 ||
        system_set_nonblocking(status_pipe[0]) != 0) goto spawn_failed;
    int captured_parent_pid = (int)getpid();
    pid_t pid = fork();
    if (pid < 0) goto spawn_failed;
    if (pid == 0) {
        (void)close(stdout_pipe[0]);
        (void)close(stderr_pipe[0]);
        (void)close(status_pipe[0]);
        struct system_child_setup_context context = {
            .captured_parent_pid = captured_parent_pid,
            .stdout_fd = capture ? stdout_pipe[1] : output_fd,
            .stderr_fd = capture ? stderr_pipe[1] : output_fd,
            .status_fd = status_pipe[1],
            .last_errno = 0,
        };
        struct asteriskd_child_setup_backend backend = {
            .context = &context,
            .restore_signals = system_child_restore_signals,
            .create_session = system_child_create_session,
            .set_nofile_limit = system_child_set_nofile,
            .clear_supplementary_groups = system_child_clear_groups,
            .set_gid = system_child_set_gid,
            .set_uid = system_child_set_uid,
            .set_parent_death_signal = system_child_set_pdeathsig,
            .get_parent_pid = system_child_getppid,
            .prepare_descriptors = system_child_prepare_descriptors,
            .exec_process = system_child_exec,
        };
        bool warning = false;
        char child_error[1U];
        (void)asteriskd_child_setup_run(
            spec, captured_parent_pid, &backend, &warning, child_error, sizeof(child_error));
        system_child_message(&context, ASTERISKD_CHILD_SETUP_FATAL,
            context.last_errno == 0 ? EIO : context.last_errno);
        _exit(127);
    }
    system_spawn_close_fd(&stdout_pipe[1]);
    system_spawn_close_fd(&stderr_pipe[1]);
    system_spawn_close_fd(&output_fd);
    (void)close(status_pipe[1]);
    status_pipe[1] = -1;
    child->pid = (int)pid;
    child->process_group_id = (int)pid;
    child->stdout_fd = capture ? stdout_pipe[0] : -1;
    child->stderr_fd = capture ? stderr_pipe[0] : -1;
    child->setup_status_fd = status_pipe[0];
    child->owns_stdout_fd = capture;
    child->owns_stderr_fd = capture;
    child->owns_setup_status_fd = true;
    stdout_pipe[0] = -1;
    stderr_pipe[0] = -1;
    status_pipe[0] = -1;
#ifdef __NR_pidfd_open
    long pidfd = syscall(__NR_pidfd_open, pid, 0U);
    if (pidfd >= 0 && pidfd <= INT32_MAX) {
        child->pidfd = (int)pidfd;
        child->owns_pidfd = true;
    }
#endif
    return 0;

spawn_failed:
    system_spawn_close_pipe(stdout_pipe);
    system_spawn_close_pipe(stderr_pipe);
    system_spawn_close_pipe(status_pipe);
    system_spawn_close_fd(&output_fd);
    anonymous_error(error, error_size, "process spawn failed");
    return ASTERISKD_CONFIG_IO;
#else
    anonymous_error(error, error_size, "system process spawn is unavailable");
    return ASTERISKD_CONFIG_IO;
#endif
}

struct process_listener_table {
    const char *path;
    const char *address;
};

static int process_listener_table_spec(
    const char *host,
    size_t table_index,
    struct process_listener_table *table) {
    if (host == NULL || table == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(table, 0, sizeof(*table));
    if (strcmp(host, "0.0.0.0") == 0) {
        if (table_index == 0U) {
            table->path = "/proc/net/tcp";
            table->address = "00000000";
            return 0;
        }
        if (table_index == 1U) {
            table->path = "/proc/net/tcp6";
            table->address = "00000000000000000000000000000000";
            return 0;
        }
        return ASTERISKD_CONFIG_INVALID;
    }
    if (strcmp(host, "127.0.0.1") == 0 && table_index == 0U) {
        table->path = "/proc/net/tcp";
        table->address = "0100007F";
        return 0;
    }
    return ASTERISKD_CONFIG_INVALID;
}

static int process_listener_table_line(
    const struct process_listener_table *table,
    uint16_t port,
    const char *line,
    uint64_t *inode) {
    if (inode != NULL) *inode = 0U;
    if (table == NULL || table->address == NULL || line == NULL || inode == NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
    char expected_local[65U];
    int result = snprintf(
        expected_local, sizeof(expected_local), "%s:%04X", table->address, (unsigned)port);
    if (result <= 0 || (size_t)result >= sizeof(expected_local)) return ASTERISKD_CONFIG_INVALID;
    char local[65U];
    char state[3U];
    unsigned long long observed_inode = 0ULL;
    int fields = sscanf(line,
        " %*u: %64s %*64s %2s %*s %*s %*s %*u %*u %llu",
        local, state, &observed_inode);
    if (fields != 3 || strcmp(state, "0A") != 0 ||
        strcmp(local, expected_local) != 0 || observed_inode == 0ULL) return 0;
    *inode = (uint64_t)observed_inode;
    return 1;
}

#if defined(ASTERISKD_TESTING)
int asteriskd_test_listener_table_line(
    const char *host,
    uint16_t port,
    size_t table_index,
    const char *line,
    uint64_t *inode) {
    if (inode != NULL) *inode = 0U;
    struct process_listener_table table;
    if (process_listener_table_spec(host, table_index, &table) != 0) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return process_listener_table_line(&table, port, line, inode);
}
#endif

#if defined(__linux__)
static const struct asteriskd_process_spec *system_context_spec(
    const struct asteriskd_system_process_context *context,
    enum asteriskd_child_role role) {
    return role == ASTERISKD_CHILD_CORE ? context->core_spec : context->helper_spec;
}

static bool system_identity_equal(
    const struct asteriskd_child_identity *left,
    const struct asteriskd_child_identity *right) {
    if (left->role != right->role || left->type != right->type || left->pid != right->pid ||
        left->process_group_id != right->process_group_id ||
        left->start_time_ticks != right->start_time_ticks || left->exe_device != right->exe_device ||
        left->exe_inode != right->exe_inode || left->argc != right->argc) return false;
    for (size_t index = 0U; index < left->argc; ++index) {
        if (strcmp(left->argv[index], right->argv[index]) != 0) return false;
    }
    return true;
}

static int system_context_identity_valid(
    void *opaque,
    const struct asteriskd_child_identity *identity,
    bool *valid) {
    struct asteriskd_system_process_context *context = opaque;
    const struct asteriskd_process_spec *spec = system_context_spec(context, identity->role);
    *valid = false;
    if (spec == NULL) return 0;
    struct asteriskd_child_identity observed;
    char error[1U];
    int result = asteriskd_process_identity_read(
        context->identity_backend, identity->pid, identity->role, identity->type,
        spec, &observed, error, sizeof(error));
    if (result == 0) *valid = system_identity_equal(identity, &observed);
    return result == ASTERISKD_CONFIG_INVALID ? -1 : 0;
}

static int system_context_interface_exists(void *opaque, const char *name, bool *exists) {
    (void)opaque;
    errno = 0;
    unsigned int index = if_nametoindex(name);
    if (index == 0U && errno != 0 && errno != ENODEV && errno != ENXIO) return -1;
    *exists = index != 0U;
    return 0;
}

static bool system_proc_pid_name(const char *name, int *pid) {
    if (name == NULL || name[0] == '\0') return false;
    uint64_t value = 0U;
    for (const unsigned char *cursor = (const unsigned char *)name; *cursor != '\0'; ++cursor) {
        if (!isdigit(*cursor) || value > (uint64_t)INT32_MAX / 10U) return false;
        value = value * 10U + (uint64_t)(*cursor - '0');
        if (value > INT32_MAX) return false;
    }
    if (value == 0U) return false;
    *pid = (int)value;
    return true;
}

static int system_member_stat(int pid, struct process_stat_snapshot *snapshot) {
    char path[64];
    char text[4096U];
    size_t length = 0U;
    if (system_proc_path(path, sizeof(path), pid, "stat") != 0 ||
        system_read_proc_file(path, (unsigned char *)text, sizeof(text) - 1U, &length) != 0) return -1;
    return process_parse_stat(text, length, pid, snapshot);
}

static bool system_fd_table_has_inode(int pid, uint64_t inode) {
    char directory_path[64];
    int count = snprintf(directory_path, sizeof(directory_path), "/proc/%d/fd", pid);
    if (count <= 0 || (size_t)count >= sizeof(directory_path)) return false;
    DIR *directory = opendir(directory_path);
    if (directory == NULL) return false;
    char expected[64];
    count = snprintf(expected, sizeof(expected), "socket:[%" PRIu64 "]", inode);
    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(directory)) != NULL) {
        int fd_number;
        if (!system_proc_pid_name(entry->d_name, &fd_number)) continue;
        char link_path[96];
        count = snprintf(link_path, sizeof(link_path), "%s/%d", directory_path, fd_number);
        if (count <= 0 || (size_t)count >= sizeof(link_path)) continue;
        char target[64];
        ssize_t target_length = readlink(link_path, target, sizeof(target) - 1U);
        if (target_length <= 0 || (size_t)target_length >= sizeof(target)) continue;
        target[target_length] = '\0';
        found = strcmp(target, expected) == 0;
    }
    (void)closedir(directory);
    return found;
}

static bool system_group_has_inode(
    const struct asteriskd_child_identity *leader,
    uint64_t inode) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) return false;
    bool found = false;
    struct dirent *entry;
    while (!found && (entry = readdir(proc)) != NULL) {
        int pid;
        if (!system_proc_pid_name(entry->d_name, &pid)) continue;
        struct process_stat_snapshot first;
        if (system_member_stat(pid, &first) != 0 ||
            first.process_group_id != leader->process_group_id ||
            first.session_id != leader->process_group_id) continue;
        if (!system_fd_table_has_inode(pid, inode)) continue;
        struct process_stat_snapshot second;
        if (system_member_stat(pid, &second) == 0 &&
            second.process_group_id == first.process_group_id &&
            second.session_id == first.session_id &&
            second.start_time_ticks == first.start_time_ticks) found = true;
    }
    (void)closedir(proc);
    return found;
}

static int system_collect_listener_inodes(
    const char *host,
    uint16_t port,
    uint64_t *inodes,
    size_t capacity,
    size_t *count) {
    *count = 0U;
    for (size_t table_index = 0U;; ++table_index) {
        struct process_listener_table table;
        if (process_listener_table_spec(host, table_index, &table) != 0) {
            return table_index == 0U ? -1 : 0;
        }
        FILE *file = fopen(table.path, "re");
        if (file == NULL) {
            if (table_index > 0U && errno == ENOENT) continue;
            return -1;
        }
        char line[1024U];
        while (fgets(line, sizeof(line), file) != NULL) {
            uint64_t inode = 0U;
            int matched = process_listener_table_line(&table, port, line, &inode);
            if (matched < 0 || (matched == 1 && *count >= capacity)) {
                (void)fclose(file);
                return -1;
            }
            if (matched == 1) inodes[(*count)++] = inode;
        }
        bool failed = ferror(file) != 0;
        int close_result = fclose(file);
        if (failed || close_result != 0) return -1;
    }
}

static int system_context_listener_owned(
    void *opaque,
    const struct asteriskd_child_identity *identity,
    const char *host,
    uint16_t port,
    bool *owned) {
    *owned = false;
    bool valid = false;
    if (system_context_identity_valid(opaque, identity, &valid) != 0 || !valid) return 0;
    uint64_t inodes[64U];
    size_t count = 0U;
    if (system_collect_listener_inodes(host, port, inodes,
            sizeof(inodes) / sizeof(inodes[0]), &count) != 0) return -1;
    for (size_t index = 0U; index < count && !*owned; ++index) {
        *owned = system_group_has_inode(identity, inodes[index]);
    }
    valid = false;
    if (system_context_identity_valid(opaque, identity, &valid) != 0 || !valid) *owned = false;
    return 0;
}

static int system_context_signal_group(
    void *opaque,
    const struct asteriskd_child_identity *identity,
    int signal_number) {
    if (identity->pid <= 0 || identity->process_group_id != identity->pid) return -1;
    bool valid = false;
    if (system_context_identity_valid(opaque, identity, &valid) != 0 || !valid) return -1;
    return kill(-identity->process_group_id, signal_number);
}

static int system_context_reap(
    void *opaque,
    const struct asteriskd_child_identity *identity,
    bool *reaped,
    struct asteriskd_child_exit_status *status) {
    (void)opaque;
    int wait_status = 0;
    pid_t result = waitpid((pid_t)identity->pid, &wait_status, WNOHANG);
    if (result < 0) return -1;
    *reaped = result == (pid_t)identity->pid;
    if (!*reaped) {
        memset(status, 0, sizeof(*status));
        return 0;
    }
    return asteriskd_child_exit_status_from_wait(wait_status, status) == 0 ? 0 : -1;
}
#endif

int asteriskd_system_process_backends_init(
    struct asteriskd_system_process_context *context,
    const struct asteriskd_process_spec *core_spec,
    const struct asteriskd_process_spec *helper_spec,
    struct asteriskd_readiness_backend *readiness,
    struct asteriskd_stop_backend *stop) {
    if (context != NULL) memset(context, 0, sizeof(*context));
    if (readiness != NULL) memset(readiness, 0, sizeof(*readiness));
    if (stop != NULL) memset(stop, 0, sizeof(*stop));
    if (context == NULL || core_spec == NULL || readiness == NULL || stop == NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
#if defined(__linux__)
    context->identity_backend = asteriskd_system_process_identity_backend();
    context->core_spec = core_spec;
    context->helper_spec = helper_spec;
    readiness->context = context;
    readiness->identity_valid = system_context_identity_valid;
    readiness->listener_owned = system_context_listener_owned;
    readiness->interface_exists = system_context_interface_exists;
    stop->context = context;
    stop->identity_valid = system_context_identity_valid;
    stop->signal_group = system_context_signal_group;
    stop->reap = system_context_reap;
    return 0;
#else
    (void)helper_spec;
    return ASTERISKD_CONFIG_IO;
#endif
}

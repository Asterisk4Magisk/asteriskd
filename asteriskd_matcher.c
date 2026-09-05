// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct matcher_writer {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
    int result;
};

static void matcher_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) (void)snprintf(error, error_size, "%s", message);
}

static int writer_reserve(struct matcher_writer *writer, size_t additional) {
    if (writer->result != 0) return writer->result;
    if (additional > ASTERISKD_MAX_JSON_SIZE || writer->length > ASTERISKD_MAX_JSON_SIZE - additional) {
        writer->result = ASTERISKD_CONFIG_INVALID;
        return writer->result;
    }
    size_t needed = writer->length + additional + 1U;
    if (needed <= writer->capacity) return 0;
    size_t capacity = writer->capacity == 0U ? 256U : writer->capacity;
    while (capacity < needed) {
        if (capacity > (ASTERISKD_MAX_JSON_SIZE + 1U) / 2U) {
            capacity = ASTERISKD_MAX_JSON_SIZE + 1U;
            break;
        }
        capacity *= 2U;
    }
    unsigned char *bytes = realloc(writer->bytes, capacity);
    if (bytes == NULL) {
        writer->result = ASTERISKD_CONFIG_NO_MEMORY;
        return writer->result;
    }
    writer->bytes = bytes;
    writer->capacity = capacity;
    return 0;
}

static void writer_bytes(struct matcher_writer *writer, const char *bytes, size_t length) {
    if (writer_reserve(writer, length) != 0) return;
    memcpy(writer->bytes + writer->length, bytes, length);
    writer->length += length;
    writer->bytes[writer->length] = '\0';
}

static void writer_literal(struct matcher_writer *writer, const char *literal) {
    writer_bytes(writer, literal, strlen(literal));
}

static void writer_format(struct matcher_writer *writer, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    va_list copy;
    va_copy(copy, arguments);
    int count = vsnprintf(NULL, 0U, format, copy);
    va_end(copy);
    if (count < 0 || writer_reserve(writer, (size_t)count) != 0) {
        va_end(arguments);
        if (count < 0) writer->result = ASTERISKD_CONFIG_INVALID;
        return;
    }
    int written = vsnprintf(
        (char *)writer->bytes + writer->length,
        writer->capacity - writer->length,
        format,
        arguments);
    va_end(arguments);
    if (written != count) {
        writer->result = ASTERISKD_CONFIG_INVALID;
        return;
    }
    writer->length += (size_t)count;
}

static int writer_take(
    struct matcher_writer *writer,
    struct asteriskd_anonymous_document *document) {
    if (writer->result != 0) {
        int result = writer->result;
        free(writer->bytes);
        memset(writer, 0, sizeof(*writer));
        return result;
    }
    if (writer->bytes == NULL) {
        writer->bytes = calloc(1U, 1U);
        if (writer->bytes == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    }
    document->bytes = writer->bytes;
    document->length = writer->length;
    memset(writer, 0, sizeof(*writer));
    return 0;
}

static int uint32_compare(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static int render_uid_array(
    struct matcher_writer *writer,
    const uint32_t *values,
    size_t count,
    bool add_whitelist_system_uids) {
    if (count > SIZE_MAX / sizeof(uint32_t) - 2U) return ASTERISKD_CONFIG_INVALID;
    size_t capacity = count + (add_whitelist_system_uids ? 2U : 0U);
    uint32_t *sorted = capacity == 0U ? NULL : malloc(capacity * sizeof(*sorted));
    if (capacity != 0U && sorted == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    if (count != 0U) memcpy(sorted, values, count * sizeof(*sorted));
    size_t length = count;
    if (add_whitelist_system_uids) {
        sorted[length++] = 0U;
        sorted[length++] = 1052U;
    }
    qsort(sorted, length, sizeof(*sorted), uint32_compare);
    writer_literal(writer, "[");
    bool first = true;
    for (size_t index = 0U; index < length; ++index) {
        if (index != 0U && sorted[index] == sorted[index - 1U]) continue;
        if (!first) writer_literal(writer, ",");
        writer_format(writer, "%u", sorted[index]);
        first = false;
    }
    writer_literal(writer, "]");
    free(sorted);
    return writer->result;
}

static int render_direct_family(
    const char values[][ASTERISKD_MAX_CIDR],
    size_t count,
    struct asteriskd_anonymous_document *document) {
    struct matcher_writer writer = {0};
    for (size_t index = 0U; index < count; ++index) {
        writer_literal(&writer, values[index]);
        writer_literal(&writer, "\n");
    }
    return writer_take(&writer, document);
}

void asteriskd_matcher_documents_destroy(struct asteriskd_matcher_documents *documents) {
    if (documents == NULL) return;
    free(documents->direct_ipv6.bytes);
    free(documents->direct_ipv4.bytes);
    free(documents->policy.bytes);
    memset(documents, 0, sizeof(*documents));
}

int asteriskd_matcher_render_documents(
    const struct asteriskd_config *config,
    int direct_ipv4_fd,
    int direct_ipv6_fd,
    struct asteriskd_matcher_documents *documents,
    char *error,
    size_t error_size) {
    if (documents != NULL) memset(documents, 0, sizeof(*documents));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || documents == NULL || !config->matcher.enabled ||
        (config->mode != ASTERISKD_MODE_TPROXY &&
         config->mode != ASTERISKD_MODE_TUN2SOCKS)) {
        matcher_error(error, error_size, "invalid matcher document configuration");
        return ASTERISKD_CONFIG_INVALID;
    }
    const char *root = asteriskd_owned_resource_catalog()->bpf_root;
    if (config->direct_cidrs != NULL &&
        (direct_ipv4_fd < 0 || direct_ipv6_fd < 0)) {
        matcher_error(error, error_size, "invalid matcher descriptor configuration");
        return ASTERISKD_CONFIG_INVALID;
    }
    int mode = config->app_policy_mode == ASTERISKD_APP_POLICY_BLACKLIST ? 0 :
        config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST ? 1 : 2;
    struct matcher_writer writer = {0};
    writer_format(&writer, "{\"version\":1,\"mode\":%d,\"uids\":", mode);
    int result = render_uid_array(&writer, config->uids, config->uid_count,
        config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST);
    if (result == 0) {
        writer_literal(&writer, ",\"bypassUids\":");
        result = render_uid_array(&writer, config->bypass_uids, config->bypass_uid_count, false);
    }
    if (result == 0) {
        writer_format(&writer,
            ",\"bypassDirectCidrs\":%s,\"enableIpv6\":%s,"
            "\"directCidrPathV4\":\"%s\",\"directCidrPathV6\":\"%s\","
            "\"xtOutputV4ProgramPath\":\"%s/xt_output_v4\","
            "\"xtOutputV6ProgramPath\":\"%s/xt_output_v6\","
            "\"xtPreroutingV4ProgramPath\":\"%s/xt_prerouting_v4\","
            "\"xtPreroutingV6ProgramPath\":\"%s/xt_prerouting_v6\"}\n",
            config->direct_cidrs != NULL ? "true" : "false",
            config->enable_ipv6 ? "true" : "false",
            config->direct_cidrs != NULL ? "/proc/self/fd/4" : "",
            config->direct_cidrs != NULL ? "/proc/self/fd/5" : "",
            root, root, root, root);
        result = writer_take(&writer, &documents->policy);
    }
    if (result == 0 && config->direct_cidrs != NULL) {
        result = render_direct_family((const char (*)[ASTERISKD_MAX_CIDR])config->direct_cidrs->ipv4,
            config->direct_cidrs->ipv4_count, &documents->direct_ipv4);
        if (result == 0) result = render_direct_family(
            (const char (*)[ASTERISKD_MAX_CIDR])config->direct_cidrs->ipv6,
            config->direct_cidrs->ipv6_count, &documents->direct_ipv6);
        if (result == 0) documents->has_direct_cidrs = true;
    }
    if (result != 0) {
        free(writer.bytes);
        asteriskd_matcher_documents_destroy(documents);
        matcher_error(error, error_size, result == ASTERISKD_CONFIG_NO_MEMORY ?
            "matcher document allocation failed" : "invalid matcher document configuration");
    }
    return result;
}

static int copy_path(char *destination, size_t capacity, const char *source) {
    size_t length = source == NULL ? 0U : strnlen(source, capacity);
    if (length == 0U || length >= capacity) return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}

static int process_add_fd(struct asteriskd_process_spec *spec, int source, int target) {
    if (source < 0 || target < 0 ||
        spec->inherited_fd_count >= ASTERISKD_PROCESS_MAX_INHERITED_FDS) return -1;
    for (size_t index = 0U; index < spec->inherited_fd_count; ++index) {
        if (spec->inherited_fds[index] == source || spec->inherited_fd_targets[index] == target) return -1;
    }
    spec->inherited_fds[spec->inherited_fd_count] = source;
    spec->inherited_fd_targets[spec->inherited_fd_count] = target;
    ++spec->inherited_fd_count;
    return 0;
}

int asteriskd_matcher_process_spec(
    const struct asteriskd_config *config,
    const char *const *inherited_environment,
    int policy_fd,
    int direct_ipv4_fd,
    int direct_ipv6_fd,
    struct asteriskd_process_spec *spec,
    char *error,
    size_t error_size) {
    if (spec != NULL) memset(spec, 0, sizeof(*spec));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || spec == NULL || !config->matcher.enabled || policy_fd < 0 ||
        copy_path(spec->working_directory, sizeof(spec->working_directory), config->working_directory) != 0 ||
        copy_path(spec->executable_path, sizeof(spec->executable_path),
            config->matcher.executable_path) != 0 ||
        asteriskd_process_environment_rebuild(inherited_environment, spec) != 0 ||
        asteriskd_process_argument_add(spec, spec->executable_path) != 0 ||
        asteriskd_process_argument_add(spec, "--start") != 0 ||
        asteriskd_process_argument_add(spec, "--policy") != 0 ||
        asteriskd_process_argument_add(spec, "/proc/self/fd/3") != 0 ||
        process_add_fd(spec, policy_fd, 3) != 0) goto invalid;
    spec->uid = 0U;
    spec->gid = 0U;
    spec->output_mode = ASTERISKD_PROCESS_OUTPUT_DISCARD;
    spec->unlimited_locked_memory = true;
    if (config->direct_cidrs != NULL &&
        (process_add_fd(spec, direct_ipv4_fd, 4) != 0 ||
         process_add_fd(spec, direct_ipv6_fd, 5) != 0)) goto invalid;
    return 0;

invalid:
    matcher_error(error, error_size, "invalid matcher process configuration");
    asteriskd_process_spec_destroy(spec);
    return ASTERISKD_CONFIG_INVALID;
}

int asteriskd_matcher_launch_destroy(
    const struct asteriskd_anonymous_file_backend *backend,
    struct asteriskd_matcher_launch *launch) {
    if (launch == NULL) return ASTERISKD_CONFIG_INVALID;
    int result = 0;
    if (asteriskd_anonymous_file_close(backend, &launch->direct_ipv6_file) != 0) result = ASTERISKD_CONFIG_IO;
    if (asteriskd_anonymous_file_close(backend, &launch->direct_ipv4_file) != 0) result = ASTERISKD_CONFIG_IO;
    if (asteriskd_anonymous_file_close(backend, &launch->policy_file) != 0) result = ASTERISKD_CONFIG_IO;
    asteriskd_process_spec_destroy(&launch->process);
    memset(launch, 0, sizeof(*launch));
    return result;
}

int asteriskd_matcher_launch_prepare(
    const struct asteriskd_config *config,
    const char *const *inherited_environment,
    const struct asteriskd_anonymous_file_backend *backend,
    struct asteriskd_matcher_launch *launch,
    char *error,
    size_t error_size) {
    if (launch != NULL) memset(launch, 0, sizeof(*launch));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || backend == NULL || launch == NULL) {
        matcher_error(error, error_size, "invalid matcher launch input");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_matcher_documents documents = {0};
    int result = asteriskd_matcher_render_documents(config, 4, 5, &documents, error, error_size);
    if (result != 0) return result;
    result = asteriskd_anonymous_file_create(
        backend, "asteriskd.matcher.policy", &documents.policy,
        &launch->policy_file, error, error_size);
    if (result == 0 && documents.has_direct_cidrs) {
        result = asteriskd_anonymous_file_create(
            backend, "asteriskd.direct.ipv4", &documents.direct_ipv4,
            &launch->direct_ipv4_file, error, error_size);
        if (result == 0) result = asteriskd_anonymous_file_create(
            backend, "asteriskd.direct.ipv6", &documents.direct_ipv6,
            &launch->direct_ipv6_file, error, error_size);
        if (result == 0) launch->has_direct_cidrs = true;
    }
    if (result == 0) result = asteriskd_matcher_process_spec(
        config, inherited_environment, launch->policy_file.fd,
        launch->has_direct_cidrs ? launch->direct_ipv4_file.fd : -1,
        launch->has_direct_cidrs ? launch->direct_ipv6_file.fd : -1,
        &launch->process, error, error_size);
    asteriskd_matcher_documents_destroy(&documents);
    if (result != 0) (void)asteriskd_matcher_launch_destroy(backend, launch);
    return result;
}

int asteriskd_matcher_pin_plan_build(
    const struct asteriskd_config *config,
    struct asteriskd_matcher_pin_plan *plan) {
    if (plan != NULL) memset(plan, 0, sizeof(*plan));
    if (config == NULL || plan == NULL || !config->matcher.enabled) return ASTERISKD_CONFIG_INVALID;
    static const enum asteriskd_pin_id ids[] = {
        ASTERISKD_PIN_MATCHER_OUTPUT_V4, ASTERISKD_PIN_MATCHER_OUTPUT_V6,
        ASTERISKD_PIN_MATCHER_PREROUTING_V4, ASTERISKD_PIN_MATCHER_PREROUTING_V6,
    };
    static const char *const names[] = {
        "ast_xt_out4", "ast_xt_out6", "ast_xt_pre4", "ast_xt_pre6",
    };
    static const size_t ipv4_indices[] = {0U, 2U};
    size_t count = config->enable_ipv6 ? 4U : 2U;
    for (size_t index = 0U; index < count; ++index) {
        size_t source = config->enable_ipv6 ? index : ipv4_indices[index];
        struct asteriskd_matcher_pin_expectation *pin = &plan->pins[index];
        pin->pin_id = ids[source];
        if (copy_path(pin->path, sizeof(pin->path),
                asteriskd_owned_pin_path(ids[source])) != 0 ||
            copy_path(pin->program_name, sizeof(pin->program_name), names[source]) != 0) {
            memset(plan, 0, sizeof(*plan));
            return ASTERISKD_CONFIG_INVALID;
        }
    }
    plan->pin_count = count;
    return 0;
}

int asteriskd_matcher_pin_records_build(
    const struct asteriskd_matcher_pin_plan *plan, struct asteriskd_resource_operation *records,
    size_t capacity, size_t *count) {
    if (count != NULL) *count = 0U;
    if (plan == NULL || records == NULL || count == NULL ||
        (plan->pin_count != 2U && plan->pin_count != 4U) || capacity < plan->pin_count) {
        return ASTERISKD_CONFIG_INVALID;
    }
    memset(records, 0, capacity * sizeof(*records));
    for (size_t index = 0U; index < plan->pin_count; ++index) {
        records[index].kind = ASTERISKD_RESOURCE_OPERATION_BPF_PIN;
        records[index].resource.bpf_pin.pin_id = plan->pins[index].pin_id;
        records[index].resource.bpf_pin.original_presence = false;
    }
    *count = plan->pin_count;
    return 0;
}

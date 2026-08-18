// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct helper_writer {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
    int result;
};

static void helper_error(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) (void)snprintf(error, error_size, "%s", message);
}

static int writer_reserve(struct helper_writer *writer, size_t additional) {
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

static void writer_bytes(struct helper_writer *writer, const char *bytes, size_t length) {
    if (bytes == NULL || writer_reserve(writer, length) != 0) return;
    memcpy(writer->bytes + writer->length, bytes, length);
    writer->length += length;
    writer->bytes[writer->length] = '\0';
}

static void writer_literal(struct helper_writer *writer, const char *value) {
    writer_bytes(writer, value, strlen(value));
}

static void writer_format(struct helper_writer *writer, const char *format, ...) {
    char buffer[1024];
    va_list arguments;
    va_start(arguments, format);
    int count = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (count < 0 || (size_t)count >= sizeof(buffer)) {
        writer->result = ASTERISKD_CONFIG_INVALID;
        return;
    }
    writer_bytes(writer, buffer, (size_t)count);
}

static void writer_json_string(struct helper_writer *writer, const char *value) {
    writer_literal(writer, "\"");
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != '\0' && writer->result == 0) {
        unsigned char byte = *cursor++;
        switch (byte) {
            case '\"': writer_literal(writer, "\\\""); break;
            case '\\': writer_literal(writer, "\\\\"); break;
            case '\b': writer_literal(writer, "\\b"); break;
            case '\f': writer_literal(writer, "\\f"); break;
            case '\n': writer_literal(writer, "\\n"); break;
            case '\r': writer_literal(writer, "\\r"); break;
            case '\t': writer_literal(writer, "\\t"); break;
            default:
                if (byte < 0x20U) writer_format(writer, "\\u%04x", (unsigned)byte);
                else writer_bytes(writer, (const char *)&byte, 1U);
                break;
        }
    }
    writer_literal(writer, "\"");
}

static void writer_yaml_string(struct helper_writer *writer, const char *value) {
    writer_literal(writer, "'");
    for (const char *cursor = value; *cursor != '\0'; ++cursor) {
        writer_bytes(writer, cursor, 1U);
        if (*cursor == '\'') writer_literal(writer, "'");
    }
    writer_literal(writer, "'");
}

static int writer_take(struct helper_writer *writer, struct asteriskd_anonymous_document *document) {
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

static int render_hev(const struct asteriskd_config *config, struct asteriskd_anonymous_document *document) {
    const struct asteriskd_hev_helper_config *hev = &config->helper.value.hev;
    struct helper_writer writer = {0};
    writer_literal(&writer, "tunnel:\n  name: ");
    writer_yaml_string(&writer, hev->tunnel_name);
    writer_format(&writer, "\n  mtu: %u\n  multi-queue: %s\n  ipv4: ", hev->mtu, hev->multi_queue ? "true" : "false");
    writer_yaml_string(&writer, hev->ipv4_address);
    if (hev->has_ipv6_address) {
        writer_literal(&writer, "\n  ipv6: ");
        writer_yaml_string(&writer, hev->ipv6_address);
    }
    writer_format(&writer, "\nsocks5:\n  port: %u\n  address: ", (unsigned)hev->socks_port);
    writer_yaml_string(&writer, hev->socks_host);
    writer_format(&writer,
        "\n  udp: 'udp'\n  tcp-fastopen: %s\nmisc:\n"
        "  tcp-read-write-timeout: %u\n  udp-read-write-timeout: %u\n"
        "  log-file: ",
        hev->tcp_fast_open ? "true" : "false", hev->tcp_read_write_timeout_milliseconds,
        hev->udp_read_write_timeout_milliseconds);
    char log_path[ASTERISKD_MAX_PATH];
    int log_length = snprintf(log_path, sizeof(log_path), "%s/logs/tun2socks.log",
        config->working_directory);
    if (log_length <= 0 || (size_t)log_length >= sizeof(log_path)) {
        free(writer.bytes);
        return ASTERISKD_CONFIG_INVALID;
    }
    writer_yaml_string(&writer, log_path);
    writer_literal(&writer, "\n  log-level: warn\n");
    return writer_take(&writer, document);
}

static void writer_string_array(struct helper_writer *writer, const char values[][ASTERISKD_MAX_INTERFACE_NAME], size_t count) {
    writer_literal(writer, "[");
    for (size_t index = 0U; index < count; ++index) {
        if (index != 0U) writer_literal(writer, ",");
        writer_json_string(writer, values[index]);
    }
    writer_literal(writer, "]");
}

static void writer_cidr_array(struct helper_writer *writer, const char values[][ASTERISKD_MAX_CIDR], size_t count, bool ipv6) {
    writer_literal(writer, "[");
    bool first = true;
    for (size_t index = 0U; index < count; ++index) {
        if ((strchr(values[index], ':') != NULL) != ipv6) continue;
        if (!first) writer_literal(writer, ",");
        writer_json_string(writer, values[index]);
        first = false;
    }
    writer_literal(writer, "]");
}

static int compare_u32(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static int render_policy_uids(struct helper_writer *writer, const struct asteriskd_config *config) {
    size_t capacity = config->uid_count + (config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST ? 2U : 0U);
    uint32_t *uids = capacity == 0U ? NULL : malloc(capacity * sizeof(*uids));
    if (capacity != 0U && uids == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    if (config->uid_count != 0U) memcpy(uids, config->uids, config->uid_count * sizeof(*uids));
    size_t count = config->uid_count;
    if (config->app_policy_mode == ASTERISKD_APP_POLICY_WHITELIST) {
        uids[count++] = 0U;
        uids[count++] = 1052U;
    }
    if (count > 1U) qsort(uids, count, sizeof(*uids), compare_u32);
    writer_literal(writer, "[");
    bool first = true;
    uint32_t previous = 0U;
    for (size_t index = 0U; index < count; ++index) {
        if (index != 0U && uids[index] == previous) continue;
        if (!first) writer_literal(writer, ",");
        writer_format(writer, "%u", uids[index]);
        previous = uids[index];
        first = false;
    }
    writer_literal(writer, "]");
    free(uids);
    return writer->result;
}

static void writer_uid_array(struct helper_writer *writer, const uint32_t *values, size_t count) {
    writer_literal(writer, "[");
    for (size_t index = 0U; index < count; ++index) {
        if (index != 0U) writer_literal(writer, ",");
        writer_format(writer, "%u", values[index]);
    }
    writer_literal(writer, "]");
}

static int render_direct_family(const char values[][ASTERISKD_MAX_CIDR], size_t count, struct asteriskd_anonymous_document *document) {
    struct helper_writer writer = {0};
    for (size_t index = 0U; index < count; ++index) {
        writer_literal(&writer, values[index]);
        writer_literal(&writer, "\n");
    }
    return writer_take(&writer, document);
}

static unsigned policy_mode(enum asteriskd_app_policy_mode mode) {
    switch (mode) {
        case ASTERISKD_APP_POLICY_BLACKLIST: return 0U;
        case ASTERISKD_APP_POLICY_WHITELIST: return 1U;
        case ASTERISKD_APP_POLICY_GLOBAL: return 2U;
    }
    return 3U;
}

static int render_bpf(const struct asteriskd_config *config, int direct_ipv4_fd, int direct_ipv6_fd, struct asteriskd_helper_documents *documents) {
    const struct asteriskd_bpf_helper_config *bpf = &config->helper.value.bpf;
    const char *pin_namespace = asteriskd_owned_resource_catalog()->bpf2_root;
    if (policy_mode(config->app_policy_mode) > 2U) return ASTERISKD_CONFIG_INVALID;
    bool direct = config->direct_cidrs != NULL;
    if (direct && (direct_ipv4_fd < 0 || direct_ipv6_fd < 0 || direct_ipv4_fd == direct_ipv6_fd)) return ASTERISKD_CONFIG_INVALID;
    if (direct) {
        int result = render_direct_family(config->direct_cidrs->ipv4, config->direct_cidrs->ipv4_count, &documents->direct_ipv4);
        if (result == 0) result = render_direct_family(config->direct_cidrs->ipv6, config->direct_cidrs->ipv6_count, &documents->direct_ipv6);
        if (result != 0) return result;
        documents->has_direct_cidrs = true;
    }

    struct helper_writer writer = {0};
    writer_literal(&writer, "{\"version\":1,\"bridgeListenAddress\":");
    writer_json_string(&writer, bpf->bridge_listen_address);
    writer_format(&writer, ",\"bridgePort\":%u", (unsigned)bpf->bridge_port);
    writer_literal(&writer, ",\"tokenIpv4Prefix\":\"127.128.0.0/9\",\"tokenIpv6Prefix\":\"fd7a:7374:6572:6973::/64\",\"pinnedObjectDir\":");
    writer_json_string(&writer, pin_namespace);
    writer_literal(&writer, ",\"cgroupPath\":\"/sys/fs/cgroup\"");
    writer_format(&writer,
        ",\"workerCount\":%u,\"tcpBufferSize\":%u,\"maxTcpSessions\":%u,\"tcpConnectTimeoutMilliseconds\":%u"
        ",\"tcpIdleTimeoutMilliseconds\":%u,\"udpSocketBufferSize\":%u,\"udpBatchSize\":%u,\"maxUdpSessions\":%u"
        ",\"maxUdpBindings\":%u,\"udpIdleTimeoutSeconds\":%u,\"maxUdpPendingBytes\":%u,\"dnsTransactionTimeoutMilliseconds\":%u",
        bpf->worker_count, bpf->tcp_buffer_size, bpf->max_tcp_sessions, bpf->tcp_connect_timeout_milliseconds,
        bpf->tcp_idle_timeout_milliseconds, bpf->udp_socket_buffer_size, bpf->udp_batch_size, bpf->max_udp_sessions,
        bpf->max_udp_bindings, bpf->udp_idle_timeout_seconds, bpf->max_udp_pending_bytes,
        bpf->dns_transaction_timeout_milliseconds);
    writer_literal(&writer, ",\"socksHost\":");
    writer_json_string(&writer, bpf->socks_host);
    writer_format(&writer, ",\"socksPort\":%u,\"enableIpv6\":%s,\"enableDnsHijack\":%s",
        (unsigned)bpf->socks_port, config->enable_ipv6 ? "true" : "false", config->enable_local_dns ? "true" : "false");
    writer_literal(&writer, ",\"hotspotInterfacePrefixes\":");
    writer_string_array(&writer, config->hotspot_interface_prefixes, config->hotspot_interface_prefix_count);
    writer_literal(&writer, ",\"ignoredInterfaces\":");
    writer_string_array(&writer, config->ignored_interfaces, config->ignored_interface_count);
    writer_literal(&writer, ",\"proxyPrivateCidrsV4\":");
    writer_cidr_array(&writer, config->proxy_private_cidrs, config->proxy_private_cidr_count, false);
    writer_literal(&writer, ",\"bypassPrivateCidrsV4\":");
    writer_cidr_array(&writer, config->bypass_private_cidrs, config->bypass_private_cidr_count, false);
    writer_literal(&writer, ",\"proxyPrivateCidrsV6\":");
    writer_cidr_array(&writer, config->proxy_private_cidrs, config->proxy_private_cidr_count, true);
    writer_literal(&writer, ",\"bypassPrivateCidrsV6\":");
    writer_cidr_array(&writer, config->bypass_private_cidrs, config->bypass_private_cidr_count, true);
    writer_format(&writer, ",\"policy\":{\"mode\":%u,\"uids\":", policy_mode(config->app_policy_mode));
    int result = render_policy_uids(&writer, config);
    writer_literal(&writer, ",\"bypassUids\":");
    writer_uid_array(&writer, config->bypass_uids, config->bypass_uid_count);
    writer_format(&writer, ",\"bypassDirectCidrs\":%s,\"directCidrPathV4\":", direct ? "true" : "false");
    char path[64];
    if (direct) (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", direct_ipv4_fd); else path[0] = '\0';
    writer_json_string(&writer, path);
    writer_literal(&writer, ",\"directCidrPathV6\":");
    if (direct) (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", direct_ipv6_fd); else path[0] = '\0';
    writer_json_string(&writer, path);
    writer_literal(&writer, "},\"debugStats\":false}\n");
    if (result == 0) result = writer_take(&writer, &documents->config); else free(writer.bytes);
    return result;
}

void asteriskd_helper_documents_destroy(struct asteriskd_helper_documents *documents) {
    if (documents == NULL) return;
    free(documents->config.bytes);
    free(documents->direct_ipv4.bytes);
    free(documents->direct_ipv6.bytes);
    memset(documents, 0, sizeof(*documents));
}

int asteriskd_helper_render_documents(const struct asteriskd_config *config, int direct_ipv4_fd, int direct_ipv6_fd,
    struct asteriskd_helper_documents *documents, char *error, size_t error_size) {
    if (documents != NULL) memset(documents, 0, sizeof(*documents));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || documents == NULL) {
        helper_error(error, error_size, "invalid helper document input");
        return ASTERISKD_CONFIG_INVALID;
    }
    int result;
    if (config->helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) result = render_hev(config, &documents->config);
    else if (config->helper.type == ASTERISKD_HELPER_BPF2SOCKS) result = render_bpf(config, direct_ipv4_fd, direct_ipv6_fd, documents);
    else result = ASTERISKD_CONFIG_INVALID;
    if (result != 0) {
        asteriskd_helper_documents_destroy(documents);
        helper_error(error, error_size, result == ASTERISKD_CONFIG_NO_MEMORY ?
            "helper document allocation failed" : "invalid helper document configuration");
    }
    return result;
}

static int helper_copy_path(char *destination, size_t capacity, const char *source) {
    if (destination == NULL || source == NULL) return -1;
    size_t length = strnlen(source, capacity);
    if (length == 0U || length >= capacity) return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}

static int helper_add_fd(
    struct asteriskd_process_spec *spec,
    int source,
    int target) {
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

int asteriskd_helper_process_spec(
    const struct asteriskd_config *config,
    const char *const *inherited_environment,
    int config_fd,
    int direct_ipv4_fd,
    int direct_ipv6_fd,
    struct asteriskd_process_spec *spec,
    char *error,
    size_t error_size) {
    if (spec != NULL) memset(spec, 0, sizeof(*spec));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || spec == NULL || config_fd < 0 ||
        helper_copy_path(spec->working_directory, sizeof(spec->working_directory),
            config != NULL ? config->working_directory : NULL) != 0) goto invalid;
    spec->uid = 0U;
    const char *executable = NULL;
    if (config->helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) {
        executable = config->helper.value.hev.executable_path;
        spec->gid = 0U;
        spec->output_mode = ASTERISKD_PROCESS_OUTPUT_DISCARD;
    } else if (config->helper.type == ASTERISKD_HELPER_BPF2SOCKS) {
        executable = config->helper.value.bpf.executable_path;
        spec->gid = 3005U;
        spec->output_mode = ASTERISKD_PROCESS_OUTPUT_APPEND_CORE_LOG;
    } else {
        goto invalid;
    }
    if (helper_copy_path(spec->executable_path, sizeof(spec->executable_path), executable) != 0 ||
        asteriskd_process_environment_rebuild(inherited_environment, spec) != 0 ||
        asteriskd_process_argument_add(spec, spec->executable_path) != 0 ||
        helper_add_fd(spec, config_fd, 3) != 0) goto invalid;
    if (config->helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) {
        if (asteriskd_process_argument_add(spec, "/proc/self/fd/3") != 0) goto invalid;
    } else {
        if (asteriskd_process_argument_add(spec, "--start") != 0 ||
            asteriskd_process_argument_add(spec, "--config") != 0 ||
            asteriskd_process_argument_add(spec, "/proc/self/fd/3") != 0 ||
            asteriskd_process_argument_add(spec, "--pid") != 0 ||
            asteriskd_process_argument_add(spec, "/dev/null") != 0) goto invalid;
        if (config->direct_cidrs != NULL) {
            if (helper_add_fd(spec, direct_ipv4_fd, 4) != 0 ||
                helper_add_fd(spec, direct_ipv6_fd, 5) != 0) goto invalid;
        }
    }
    return 0;

invalid:
    helper_error(error, error_size, "invalid helper process configuration");
    asteriskd_process_spec_destroy(spec);
    return ASTERISKD_CONFIG_INVALID;
}

int asteriskd_helper_launch_destroy(
    const struct asteriskd_anonymous_file_backend *backend,
    struct asteriskd_helper_launch *launch) {
    if (launch == NULL) return ASTERISKD_CONFIG_INVALID;
    int result = 0;
    if (asteriskd_anonymous_file_close(backend, &launch->direct_ipv6_file) != 0) result = ASTERISKD_CONFIG_IO;
    if (asteriskd_anonymous_file_close(backend, &launch->direct_ipv4_file) != 0) result = ASTERISKD_CONFIG_IO;
    if (asteriskd_anonymous_file_close(backend, &launch->config_file) != 0) result = ASTERISKD_CONFIG_IO;
    asteriskd_process_spec_destroy(&launch->process);
    memset(launch, 0, sizeof(*launch));
    return result;
}

int asteriskd_helper_launch_prepare(
    const struct asteriskd_config *config,
    const char *const *inherited_environment,
    const struct asteriskd_anonymous_file_backend *backend,
    struct asteriskd_helper_launch *launch,
    char *error,
    size_t error_size) {
    if (launch != NULL) memset(launch, 0, sizeof(*launch));
    if (error != NULL && error_size != 0U) error[0] = '\0';
    if (config == NULL || backend == NULL || launch == NULL) {
        helper_error(error, error_size, "invalid helper launch input");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_helper_documents documents;
    memset(&documents, 0, sizeof(documents));
    int result = asteriskd_helper_render_documents(
        config, 4, 5, &documents, error, error_size);
    if (result != 0) return result;
    result = asteriskd_anonymous_file_create(
        backend, "asteriskd.helper.config", &documents.config,
        &launch->config_file, error, error_size);
    if (result == 0 && documents.has_direct_cidrs) {
        result = asteriskd_anonymous_file_create(
            backend, "asteriskd.direct.ipv4", &documents.direct_ipv4,
            &launch->direct_ipv4_file, error, error_size);
        if (result == 0) result = asteriskd_anonymous_file_create(
            backend, "asteriskd.direct.ipv6", &documents.direct_ipv6,
            &launch->direct_ipv6_file, error, error_size);
        if (result == 0) launch->has_direct_cidrs = true;
    }
    if (result == 0) result = asteriskd_helper_process_spec(
        config, inherited_environment, launch->config_file.fd,
        launch->has_direct_cidrs ? launch->direct_ipv4_file.fd : -1,
        launch->has_direct_cidrs ? launch->direct_ipv6_file.fd : -1,
        &launch->process, error, error_size);
    asteriskd_helper_documents_destroy(&documents);
    if (result != 0) (void)asteriskd_helper_launch_destroy(backend, launch);
    return result;
}

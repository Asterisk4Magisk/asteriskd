// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef _WIN32
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#include "asteriskd.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_pton InetPtonA
#define inet_ntop InetNtopA
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define TOKEN_NONE SIZE_MAX

static void set_message(char *message, size_t message_size, const char *format, ...) {
    if (message == NULL || message_size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(message, message_size, format, arguments);
    va_end(arguments);
}

bool asteriskd_mode_is_readable(uint32_t mode) { return (mode & 0444U) != 0U; }
bool asteriskd_mode_is_writable(uint32_t mode) { return (mode & 0222U) != 0U; }
bool asteriskd_mode_is_executable(uint32_t mode) { return (mode & 0111U) != 0U; }

bool asteriskd_file_requirements_valid(
    enum asteriskd_file_kind actual,
    uint32_t mode,
    enum asteriskd_file_kind expected,
    bool readable,
    bool writable,
    bool executable) {
    return actual == expected &&
        (!readable || asteriskd_mode_is_readable(mode)) &&
        (!writable || asteriskd_mode_is_writable(mode)) &&
        (!executable || asteriskd_mode_is_executable(mode));
}

int asteriskd_file_requirements_validate(
    enum asteriskd_file_kind actual,
    uint32_t mode,
    enum asteriskd_file_kind expected,
    bool readable,
    bool writable,
    bool executable) {
    return asteriskd_file_requirements_valid(
        actual, mode, expected, readable, writable, executable) ? 0 : ASTERISKD_CONFIG_INVALID;
}

void asteriskd_config_destroy(struct asteriskd_config *config) {
    if (config == NULL) return;
    free(config->uids);
    free(config->bypass_uids);
    if (config->direct_cidrs != NULL) {
        free(config->direct_cidrs->ipv4);
        free(config->direct_cidrs->ipv6);
        free(config->direct_cidrs);
    }
    memset(config, 0, sizeof(*config));
}

static int copy_string(const struct asteriskd_json_document *, size_t, char *, size_t);

static bool token_equals(
    const struct asteriskd_json_document *document,
    size_t token_index,
    const char *value) {
    char decoded[128];
    return copy_string(document, token_index, decoded, sizeof(decoded)) == 0 && strcmp(decoded, value) == 0;
}

static size_t next_direct(
    const struct asteriskd_json_document *document,
    size_t parent,
    size_t start) {
    for (size_t index = start; index < document->token_count; ++index) {
        if (document->tokens[index].parent == parent) return index;
    }
    return TOKEN_NONE;
}

static int object_fields(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *const *names,
    size_t name_count,
    size_t *values) {
    if (document->tokens[object].type != ASTERISKD_JSON_OBJECT || name_count > 64U) return -1;
    for (size_t index = 0U; index < name_count; ++index) values[index] = TOKEN_NONE;
    size_t cursor = object + 1U;
    size_t pairs = 0U;
    while (true) {
        size_t key = next_direct(document, object, cursor);
        if (key == TOKEN_NONE) break;
        size_t value = next_direct(document, object, key + 1U);
        if (value == TOKEN_NONE || document->tokens[key].type != ASTERISKD_JSON_STRING) return -1;
        size_t field = TOKEN_NONE;
        for (size_t index = 0U; index < name_count; ++index) {
            if (token_equals(document, key, names[index])) {
                field = index;
                break;
            }
        }
        if (field == TOKEN_NONE || values[field] != TOKEN_NONE) return -1;
        values[field] = value;
        ++pairs;
        cursor = value + 1U;
    }
    if (pairs != name_count || document->tokens[object].child_count != name_count) return -1;
    return 0;
}

static int find_field(
    const struct asteriskd_json_document *document,
    size_t object,
    const char *name,
    size_t *out) {
    size_t cursor = object + 1U;
    while (true) {
        size_t key = next_direct(document, object, cursor);
        if (key == TOKEN_NONE) return -1;
        size_t value = next_direct(document, object, key + 1U);
        if (value == TOKEN_NONE) return -1;
        if (token_equals(document, key, name)) {
            *out = value;
            return 0;
        }
        cursor = value + 1U;
    }
}

static int copy_string(
    const struct asteriskd_json_document *document,
    size_t token_index,
    char *out,
    size_t out_size) {
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->type != ASTERISKD_JSON_STRING || out_size == 0U) return -1;
    size_t output = 0U;
    for (size_t input = token->start; input < token->end; ++input) {
        unsigned char value = (unsigned char)document->source[input];
        if (value == '\\') {
            if (++input >= token->end) return -1;
            value = (unsigned char)document->source[input];
            switch (value) {
                case '"': case '\\': case '/': break;
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                case 'u': {
                    if (input + 4U >= token->end) return -1;
                    uint32_t codepoint = 0U;
                    for (size_t offset = 1U; offset <= 4U; ++offset) {
                        char hex = document->source[input + offset];
                        uint32_t digit = hex >= '0' && hex <= '9' ? (uint32_t)(hex - '0') :
                            hex >= 'a' && hex <= 'f' ? (uint32_t)(hex - 'a' + 10) :
                            hex >= 'A' && hex <= 'F' ? (uint32_t)(hex - 'A' + 10) : UINT32_MAX;
                        if (digit == UINT32_MAX) return -1;
                        codepoint = codepoint * 16U + digit;
                    }
                    input += 4U;
                    if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
                        if (input + 6U >= token->end || document->source[input + 1U] != '\\' || document->source[input + 2U] != 'u') return -1;
                        uint32_t low = 0U;
                        for (size_t offset = 3U; offset <= 6U; ++offset) {
                            char hex = document->source[input + offset];
                            uint32_t digit = hex >= '0' && hex <= '9' ? (uint32_t)(hex - '0') :
                                hex >= 'a' && hex <= 'f' ? (uint32_t)(hex - 'a' + 10) :
                                hex >= 'A' && hex <= 'F' ? (uint32_t)(hex - 'A' + 10) : UINT32_MAX;
                            if (digit == UINT32_MAX) return -1;
                            low = low * 16U + digit;
                        }
                        if (low < 0xDC00U || low > 0xDFFFU) return -1;
                        codepoint = 0x10000U + ((codepoint - 0xD800U) << 10U) + (low - 0xDC00U);
                        input += 6U;
                    } else if (codepoint >= 0xDC00U && codepoint <= 0xDFFFU) {
                        return -1;
                    }
                    if (codepoint == 0U) return -1;
                    unsigned char encoded[4];
                    size_t encoded_length;
                    if (codepoint <= 0x7FU) {
                        encoded[0] = (unsigned char)codepoint;
                        encoded_length = 1U;
                    } else if (codepoint <= 0x7FFU) {
                        encoded[0] = (unsigned char)(0xC0U | (codepoint >> 6U));
                        encoded[1] = (unsigned char)(0x80U | (codepoint & 0x3FU));
                        encoded_length = 2U;
                    } else if (codepoint <= 0xFFFFU) {
                        encoded[0] = (unsigned char)(0xE0U | (codepoint >> 12U));
                        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3FU));
                        encoded[2] = (unsigned char)(0x80U | (codepoint & 0x3FU));
                        encoded_length = 3U;
                    } else {
                        encoded[0] = (unsigned char)(0xF0U | (codepoint >> 18U));
                        encoded[1] = (unsigned char)(0x80U | ((codepoint >> 12U) & 0x3FU));
                        encoded[2] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3FU));
                        encoded[3] = (unsigned char)(0x80U | (codepoint & 0x3FU));
                        encoded_length = 4U;
                    }
                    if (output + encoded_length >= out_size) return -1;
                    memcpy(out + output, encoded, encoded_length);
                    output += encoded_length;
                    continue;
                }
                default: return -1;
            }
        }
        if (output + 1U >= out_size) return -1;
        out[output++] = (char)value;
    }
    out[output] = '\0';
    return 0;
}

static int parse_bool(const struct asteriskd_json_document *document, size_t token, bool *out) {
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

static int parse_u32(
    const struct asteriskd_json_document *document,
    size_t token_index,
    uint32_t *out) {
    const struct asteriskd_json_token *token = &document->tokens[token_index];
    if (token->type != ASTERISKD_JSON_NUMBER || token->end <= token->start) return -1;
    uint64_t value = 0U;
    for (size_t index = token->start; index < token->end; ++index) {
        char digit = document->source[index];
        if (digit < '0' || digit > '9') return -1;
        value = value * 10U + (uint64_t)(digit - '0');
        if (value > UINT32_MAX) return -1;
    }
    *out = (uint32_t)value;
    return 0;
}

static bool path_is_normal(const char *path) {
    size_t length = strlen(path);
    if (length == 0U || length >= ASTERISKD_MAX_PATH || path[0] != '/' ||
        path[length - 1U] == '/' || strstr(path, "//") != NULL ||
        strchr(path, '\r') != NULL || strchr(path, '\n') != NULL) {
        return false;
    }
    const char *component = path + 1;
    while (*component != '\0') {
        const char *slash = strchr(component, '/');
        size_t part_length = slash == NULL ? strlen(component) : (size_t)(slash - component);
        if ((part_length == 1U && component[0] == '.') ||
            (part_length == 2U && component[0] == '.' && component[1] == '.')) return false;
        if (slash == NULL) break;
        component = slash + 1;
    }
    return true;
}

static bool interface_is_valid(const char *value, bool prefix) {
    size_t length = strlen(value);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME || (prefix && length == 1U && value[0] == '+')) return false;
    for (size_t index = 0U; index < length; ++index) {
        char ch = value[index];
        if (prefix && ch == '+' && index + 1U == length) continue;
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-')) return false;
    }
    return true;
}

static int parse_string_array(
    const struct asteriskd_json_document *document,
    size_t array,
    char *out,
    size_t stride,
    size_t maximum,
    bool interfaces,
    bool prefixes,
    size_t *count) {
    if (document->tokens[array].type != ASTERISKD_JSON_ARRAY ||
        document->tokens[array].child_count > maximum) return -1;
    *count = 0U;
    size_t cursor = array + 1U;
    while (true) {
        size_t token = next_direct(document, array, cursor);
        if (token == TOKEN_NONE) break;
        char *destination = out + *count * stride;
        if (copy_string(document, token, destination, stride) != 0 ||
            (interfaces && !interface_is_valid(destination, prefixes))) return -1;
        for (size_t previous = 0U; previous < *count; ++previous) {
            if (strcmp(destination, out + previous * stride) == 0) return -1;
        }
        ++*count;
        cursor = token + 1U;
    }
    return 0;
}

static int format_ipv6_canonical(
    const unsigned char bytes[16],
    char *output,
    size_t output_size) {
    uint16_t words[8];
    for (size_t index = 0U; index < 8U; ++index) {
        words[index] = (uint16_t)(((uint16_t)bytes[index * 2U] << 8U) |
            (uint16_t)bytes[index * 2U + 1U]);
    }
    size_t best_start = 8U;
    size_t best_length = 0U;
    for (size_t index = 0U; index < 8U;) {
        if (words[index] != 0U) {
            ++index;
            continue;
        }
        size_t start = index;
        while (index < 8U && words[index] == 0U) ++index;
        size_t length = index - start;
        if (length >= 2U && length > best_length) {
            best_start = start;
            best_length = length;
        }
    }

    size_t used = 0U;
    for (size_t index = 0U; index < 8U;) {
        if (index == best_start) {
            if (used + 2U >= output_size) return -1;
            output[used++] = ':';
            output[used++] = ':';
            index += best_length;
            continue;
        }
        if (used > 0U && output[used - 1U] != ':') {
            if (used + 1U >= output_size) return -1;
            output[used++] = ':';
        }
        int written = snprintf(output + used, output_size - used, "%x", words[index]);
        if (written <= 0 || (size_t)written >= output_size - used) return -1;
        used += (size_t)written;
        ++index;
    }
    if (used == 0U || used >= output_size) return -1;
    output[used] = '\0';
    return 0;
}

static int normalize_cidr(
    const char *value,
    int required_family,
    char *output,
    size_t output_size,
    int *family_out) {
    const char *slash = strrchr(value, '/');
    if (slash == NULL || slash == value || slash[1] == '\0') return -1;
    size_t address_length = (size_t)(slash - value);
    if (address_length >= ASTERISKD_MAX_CIDR) return -1;
    char address[ASTERISKD_MAX_CIDR];
    memcpy(address, value, address_length);
    address[address_length] = '\0';
    char *end = NULL;
    unsigned long prefix = strtoul(slash + 1, &end, 10);
    if (*end != '\0') return -1;
    int family = strchr(address, ':') == NULL ? AF_INET : AF_INET6;
    unsigned long maximum = family == AF_INET ? 32UL : 128UL;
    if (required_family != 0 && family != required_family) return -1;
    if (prefix > maximum) return -1;
    unsigned char bytes[16] = {0};
    if (inet_pton(family, address, bytes) != 1) return -1;
    size_t byte_count = family == AF_INET ? 4U : 16U;
    for (size_t bit = (size_t)prefix; bit < byte_count * 8U; ++bit) {
        bytes[bit / 8U] &= (unsigned char)~(0x80U >> (bit % 8U));
    }
    char normalized[ASTERISKD_MAX_CIDR];
    if (family == AF_INET) {
        int written = snprintf(normalized, sizeof(normalized), "%u.%u.%u.%u",
            (unsigned)bytes[0], (unsigned)bytes[1], (unsigned)bytes[2], (unsigned)bytes[3]);
        if (written <= 0 || (size_t)written >= sizeof(normalized)) return -1;
    } else if (format_ipv6_canonical(bytes, normalized, sizeof(normalized)) != 0) {
        return -1;
    }
    int result = snprintf(output, output_size, "%s/%lu", normalized, prefix);
    if (result < 0 || (size_t)result >= output_size) return -1;
    if (family_out != NULL) *family_out = family;
    return 0;
}

static int canonical_cidr(const char *value, int required_family, int *family_out) {
    char canonical[ASTERISKD_MAX_CIDR];
    return normalize_cidr(
        value, required_family, canonical, sizeof(canonical), family_out) == 0 &&
        strcmp(canonical, value) == 0 ? 0 : -1;
}

static int validate_cidr_array(
    char values[][ASTERISKD_MAX_CIDR],
    size_t count) {
    for (size_t index = 0U; index < count; ++index) {
        if (canonical_cidr(values[index], 0, NULL) != 0) return -1;
        for (size_t previous = 0U; previous < index; ++previous) {
            if (strcmp(values[index], values[previous]) == 0) return -1;
        }
    }
    return 0;
}

static int parse_uid_array(
    const struct asteriskd_json_document *document,
    size_t array,
    uint32_t **out,
    size_t *count) {
    if (document->tokens[array].type != ASTERISKD_JSON_ARRAY ||
        document->tokens[array].child_count > ASTERISKD_MAX_UIDS) return -1;
    *count = document->tokens[array].child_count;
    if (*count == 0U) return 0;
    if (*count > SIZE_MAX / sizeof(**out)) return -1;
    *out = calloc(*count, sizeof(**out));
    if (*out == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    size_t cursor = array + 1U;
    for (size_t index = 0U; index < *count; ++index) {
        size_t token = next_direct(document, array, cursor);
        if (token == TOKEN_NONE || parse_u32(document, token, &(*out)[index]) != 0 ||
            (*out)[index] > INT32_MAX || (index > 0U && (*out)[index] <= (*out)[index - 1U])) return -1;
        cursor = token + 1U;
    }
    return 0;
}

static int compare_cidr(const void *left, const void *right) {
    return strcmp((const char *)left, (const char *)right);
}

static int parse_direct_resource_family(
    const char *data,
    size_t length,
    int family,
    char (**out)[ASTERISKD_MAX_CIDR],
    size_t *count) {
    if (data == NULL && length != 0U) return ASTERISKD_CONFIG_INVALID;
    *count = 0U;
    *out = calloc(ASTERISKD_MAX_DIRECT_CIDRS, sizeof(**out));
    if (*out == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    size_t cursor = 0U;
    while (cursor < length) {
        size_t end = cursor;
        while (end < length && data[end] != '\n') ++end;
        size_t content_end = end;
        const char *comment = memchr(data + cursor, '#', content_end - cursor);
        if (comment != NULL) content_end = (size_t)(comment - data);
        while (cursor < content_end && isspace((unsigned char)data[cursor])) ++cursor;
        while (content_end > cursor && isspace((unsigned char)data[content_end - 1U])) --content_end;
        if (content_end > cursor) {
            size_t value_length = content_end - cursor;
            if (value_length >= ASTERISKD_MAX_CIDR || *count >= ASTERISKD_MAX_DIRECT_CIDRS) {
                return ASTERISKD_CONFIG_INVALID;
            }
            char value[ASTERISKD_MAX_CIDR];
            memcpy(value, data + cursor, value_length);
            value[value_length] = '\0';
            if (normalize_cidr(value, family, (*out)[*count], ASTERISKD_MAX_CIDR, NULL) != 0) {
                return ASTERISKD_CONFIG_INVALID;
            }
            ++*count;
        }
        cursor = end < length ? end + 1U : length;
    }
    qsort(*out, *count, sizeof(**out), compare_cidr);
    size_t unique = 0U;
    for (size_t index = 0U; index < *count; ++index) {
        if (unique == 0U || strcmp((*out)[unique - 1U], (*out)[index]) != 0) {
            if (unique != index) memcpy((*out)[unique], (*out)[index], ASTERISKD_MAX_CIDR);
            ++unique;
        }
    }
    *count = unique;
    if (*count == 0U) {
        free(*out);
        *out = NULL;
    }
    return 0;
}

int asteriskd_config_load_direct_cidrs(
    struct asteriskd_config *config,
    const char *ipv4,
    size_t ipv4_length,
    const char *ipv6,
    size_t ipv6_length) {
    if (!config->has_direct_cidr_paths || config->direct_cidrs != NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
    config->direct_cidrs = calloc(1U, sizeof(*config->direct_cidrs));
    if (config->direct_cidrs == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    int result = parse_direct_resource_family(
        ipv4, ipv4_length, AF_INET,
        &config->direct_cidrs->ipv4, &config->direct_cidrs->ipv4_count);
    if (result == 0 && config->enable_ipv6) {
        result = parse_direct_resource_family(
            ipv6, ipv6_length, AF_INET6,
            &config->direct_cidrs->ipv6, &config->direct_cidrs->ipv6_count);
    }
    if (result != 0) return result;
    return config->direct_cidrs->ipv4_count + config->direct_cidrs->ipv6_count == 0U ?
        ASTERISKD_CONFIG_INVALID : 0;
}

static int parse_enum_string(
    const struct asteriskd_json_document *document,
    size_t token,
    const char *const *names,
    size_t count,
    int *out) {
    char value[32];
    if (copy_string(document, token, value, sizeof(value)) != 0) return -1;
    for (size_t index = 0U; index < count; ++index) {
        if (strcmp(value, names[index]) == 0) {
            *out = (int)index;
            return 0;
        }
    }
    return -1;
}

static int parse_core(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {"workingDirectory", "readinessTimeoutMilliseconds", "ageSecretKey"};
    size_t values[3];
    if (object_fields(document, object, names, 3U, values) != 0 ||
        copy_string(document, values[0], config->working_directory, sizeof(config->working_directory)) != 0 ||
        !path_is_normal(config->working_directory) ||
        parse_u32(document, values[1], &config->readiness_timeout_milliseconds) != 0 ||
        config->readiness_timeout_milliseconds < 100U || config->readiness_timeout_milliseconds > 60000U) return -1;
    if (document->tokens[values[2]].type == ASTERISKD_JSON_NULL) return 0;
    config->has_age_secret_key = true;
    if (copy_string(document, values[2], config->age_secret_key, sizeof(config->age_secret_key)) != 0 ||
        config->age_secret_key[0] == '\0' || strchr(config->age_secret_key, '\r') != NULL ||
        strchr(config->age_secret_key, '\n') != NULL) return -1;
    return 0;
}

static int parse_policy(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {
        "mode", "uids", "bypassUids", "directCidrPathV4", "directCidrPathV6",
    };
    static const char *const modes[] = {"global", "blacklist", "whitelist"};
    size_t values[5];
    int mode = 0;
    if (object_fields(document, object, names, 5U, values) != 0 ||
        parse_enum_string(document, values[0], modes, 3U, &mode) != 0) return -1;
    config->app_policy_mode = (enum asteriskd_app_policy_mode)mode;
    int result = parse_uid_array(document, values[1], &config->uids, &config->uid_count);
    if (result == 0) result = parse_uid_array(document, values[2], &config->bypass_uids, &config->bypass_uid_count);
    if (result != 0) return result;
    bool ipv4_null = document->tokens[values[3]].type == ASTERISKD_JSON_NULL;
    bool ipv6_null = document->tokens[values[4]].type == ASTERISKD_JSON_NULL;
    if (ipv4_null != ipv6_null) return -1;
    if (!ipv4_null) {
        if (copy_string(document, values[3], config->direct_cidr_path_v4,
                sizeof(config->direct_cidr_path_v4)) != 0 ||
            copy_string(document, values[4], config->direct_cidr_path_v6,
                sizeof(config->direct_cidr_path_v6)) != 0 ||
            !path_is_normal(config->direct_cidr_path_v4) ||
            !path_is_normal(config->direct_cidr_path_v6)) return -1;
        config->has_direct_cidr_paths = true;
    }
    return config->app_policy_mode == ASTERISKD_APP_POLICY_GLOBAL && config->uid_count != 0U ? -1 : 0;
}

static int parse_network(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {
        "enableIpv6", "disableSystemIpv6", "enableLocalDns", "enableFakeDns", "fakeDnsIpv4Pool",
        "ignoredInterfaces", "virtualInterfaces", "hotspotInterfacePrefixes", "proxyPrivateCidrs",
        "bypassPrivateCidrs", "appPolicy",
    };
    size_t values[11];
    if (object_fields(document, object, names, 11U, values) != 0 ||
        parse_bool(document, values[0], &config->enable_ipv6) != 0 ||
        parse_bool(document, values[1], &config->disable_system_ipv6) != 0 ||
        parse_bool(document, values[2], &config->enable_local_dns) != 0 ||
        parse_bool(document, values[3], &config->enable_fake_dns) != 0) return -1;
    if (document->tokens[values[4]].type != ASTERISKD_JSON_NULL) {
        config->has_fake_dns_ipv4_pool = true;
        if (copy_string(document, values[4], config->fake_dns_ipv4_pool, sizeof(config->fake_dns_ipv4_pool)) != 0) return -1;
    }
    if (parse_string_array(document, values[5], (char *)config->ignored_interfaces, ASTERISKD_MAX_INTERFACE_NAME, ASTERISKD_MAX_INTERFACES, false, false, &config->ignored_interface_count) != 0) return -1;
    for (size_t index = 0U; index < config->ignored_interface_count; ++index) {
        if (!asteriskd_interface_selector_valid(config->ignored_interfaces[index])) return -1;
    }
    if (parse_string_array(document, values[6], (char *)config->virtual_interfaces, ASTERISKD_MAX_INTERFACE_NAME, ASTERISKD_MAX_INTERFACES, true, false, &config->virtual_interface_count) != 0 ||
        parse_string_array(document, values[7], (char *)config->hotspot_interface_prefixes, ASTERISKD_MAX_INTERFACE_NAME, ASTERISKD_MAX_INTERFACES, true, true, &config->hotspot_interface_prefix_count) != 0 ||
        parse_string_array(document, values[8], (char *)config->proxy_private_cidrs, ASTERISKD_MAX_CIDR, ASTERISKD_MAX_CIDRS, false, false, &config->proxy_private_cidr_count) != 0 ||
        parse_string_array(document, values[9], (char *)config->bypass_private_cidrs, ASTERISKD_MAX_CIDR, ASTERISKD_MAX_CIDRS, false, false, &config->bypass_private_cidr_count) != 0 ||
        config->proxy_private_cidr_count + config->bypass_private_cidr_count > ASTERISKD_MAX_CIDRS ||
        validate_cidr_array(config->proxy_private_cidrs, config->proxy_private_cidr_count) != 0 ||
        validate_cidr_array(config->bypass_private_cidrs, config->bypass_private_cidr_count) != 0) return -1;
    return parse_policy(document, values[10], config);
}

static int parse_wifi_ssids(
    const struct asteriskd_json_document *document,
    size_t array,
    struct asteriskd_wifi_rule_config *rule) {
    size_t cursor;

    if (document->tokens[array].type != ASTERISKD_JSON_ARRAY ||
        document->tokens[array].child_count > ASTERISKD_MAX_WIFI_IDENTIFIERS) {
        return -1;
    }
    rule->ssid_count = 0U;
    cursor = array + 1U;
    while (rule->ssid_count < document->tokens[array].child_count) {
        char decoded[ASTERISKD_MAX_WIFI_SSID_BYTES + 1U];
        size_t token = next_direct(document, array, cursor);
        size_t length;
        size_t previous;
        if (token == TOKEN_NONE ||
            copy_string(document, token, decoded, sizeof(decoded)) != 0) {
            return -1;
        }
        length = strlen(decoded);
        if (length == 0U || length > ASTERISKD_MAX_WIFI_SSID_BYTES) return -1;
        for (previous = 0U; previous < rule->ssid_count; ++previous) {
            if (rule->ssids[previous].length == length &&
                memcmp(rule->ssids[previous].bytes, decoded, length) == 0) {
                return -1;
            }
        }
        memcpy(rule->ssids[rule->ssid_count].bytes, decoded, length);
        rule->ssids[rule->ssid_count].length = (uint8_t)length;
        ++rule->ssid_count;
        cursor = token + 1U;
    }
    return 0;
}

static int parse_bssid_octet(char high, char low, uint8_t *result) {
    unsigned int high_value;
    unsigned int low_value;
    high_value = high >= '0' && high <= '9'
        ? (unsigned int)(high - '0')
        : high >= 'a' && high <= 'f' ? (unsigned int)(high - 'a' + 10) : UINT_MAX;
    low_value = low >= '0' && low <= '9'
        ? (unsigned int)(low - '0')
        : low >= 'a' && low <= 'f' ? (unsigned int)(low - 'a' + 10) : UINT_MAX;
    if (high_value == UINT_MAX || low_value == UINT_MAX) return -1;
    *result = (uint8_t)((high_value << 4U) | low_value);
    return 0;
}

static int parse_bssid(const char *value, uint8_t result[6U]) {
    size_t index;
    if (strlen(value) != 17U) return -1;
    for (index = 0U; index < 6U; ++index) {
        size_t offset = index * 3U;
        if (parse_bssid_octet(value[offset], value[offset + 1U], &result[index]) != 0 ||
            (index < 5U && value[offset + 2U] != ':')) {
            return -1;
        }
    }
    return 0;
}

static int parse_wifi_bssids(
    const struct asteriskd_json_document *document,
    size_t array,
    struct asteriskd_wifi_rule_config *rule) {
    size_t cursor;

    if (document->tokens[array].type != ASTERISKD_JSON_ARRAY ||
        document->tokens[array].child_count > ASTERISKD_MAX_WIFI_IDENTIFIERS) {
        return -1;
    }
    rule->bssid_count = 0U;
    cursor = array + 1U;
    while (rule->bssid_count < document->tokens[array].child_count) {
        char decoded[18U];
        size_t token = next_direct(document, array, cursor);
        size_t previous;
        if (token == TOKEN_NONE ||
            copy_string(document, token, decoded, sizeof(decoded)) != 0 ||
            parse_bssid(decoded, rule->bssids[rule->bssid_count]) != 0) {
            return -1;
        }
        for (previous = 0U; previous < rule->bssid_count; ++previous) {
            if (memcmp(
                    rule->bssids[previous],
                    rule->bssids[rule->bssid_count],
                    6U) == 0) {
                return -1;
            }
        }
        ++rule->bssid_count;
        cursor = token + 1U;
    }
    return 0;
}

static int parse_wifi_rule(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_wifi_rule_config *rule) {
    static const char *const names[] = {"enabled", "ssids", "bssids"};
    size_t values[3];
    if (object_fields(document, object, names, 3U, values) != 0 ||
        parse_bool(document, values[0], &rule->enabled) != 0 ||
        parse_wifi_ssids(document, values[1], rule) != 0 ||
        parse_wifi_bssids(document, values[2], rule) != 0) {
        return -1;
    }
    return 0;
}

static int parse_schedule_control(
    const struct asteriskd_json_document *document,
    size_t object,
    bool master_enabled,
    struct asteriskd_schedule_control_config *schedule) {
    static const char *const names[] = {"enabled", "startCron", "stopCron"};
    char start[ASTERISKD_MAX_CRON_EXPRESSION + 1U];
    char stop[ASTERISKD_MAX_CRON_EXPRESSION + 1U];
    size_t values[3];
    if (object_fields(document, object, names, 3U, values) != 0 ||
        parse_bool(document, values[0], &schedule->enabled) != 0 ||
        copy_string(document, values[1], start, sizeof(start)) != 0 ||
        copy_string(document, values[2], stop, sizeof(stop)) != 0) {
        return -1;
    }
    if (master_enabled && schedule->enabled &&
        (asteriskd_cron_parse(start, &schedule->start) != 0 ||
            asteriskd_cron_parse(stop, &schedule->stop) != 0)) {
        return -1;
    }
    return 0;
}

static int parse_wifi_control(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_wifi_control_config *wifi) {
    static const char *const names[] = {
        "enabled", "connectStart", "connectStop", "disconnectStart", "disconnectStop",
    };
    size_t values[5];
    if (object_fields(document, object, names, 5U, values) != 0 ||
        parse_bool(document, values[0], &wifi->enabled) != 0 ||
        parse_wifi_rule(document, values[1], &wifi->connect_start) != 0 ||
        parse_wifi_rule(document, values[2], &wifi->connect_stop) != 0 ||
        parse_wifi_rule(document, values[3], &wifi->disconnect_start) != 0 ||
        parse_wifi_rule(document, values[4], &wifi->disconnect_stop) != 0 ||
        (wifi->connect_start.enabled && wifi->connect_stop.enabled) ||
        (wifi->disconnect_start.enabled && wifi->disconnect_stop.enabled)) {
        return -1;
    }
    return 0;
}

static int parse_service_control(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_service_control_config *service_control) {
    static const char *const names[] = {"enabled", "schedule", "wifi"};
    size_t values[3];
    if (object_fields(document, object, names, 3U, values) != 0 ||
        parse_bool(document, values[0], &service_control->enabled) != 0 ||
        parse_schedule_control(
            document, values[1], service_control->enabled,
            &service_control->schedule) != 0 ||
        parse_wifi_control(document, values[2], &service_control->wifi) != 0) {
        return -1;
    }
    return 0;
}

static int parse_mode_options(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {"transparentPort", "tunnelName"};
    size_t values[2];
    if (object_fields(document, object, names, 2U, values) != 0) return -1;
    if (document->tokens[values[0]].type != ASTERISKD_JSON_NULL) {
        uint32_t port = 0U;
        if (parse_u32(document, values[0], &port) != 0 || port == 0U || port > 65535U) return -1;
        config->has_transparent_port = true;
        config->transparent_port = (uint16_t)port;
    }
    if (document->tokens[values[1]].type != ASTERISKD_JSON_NULL) {
        config->has_tunnel_name = true;
        if (copy_string(document, values[1], config->tunnel_name, sizeof(config->tunnel_name)) != 0 ||
            !interface_is_valid(config->tunnel_name, false)) return -1;
    }
    return 0;
}

static int parse_matcher(
    const struct asteriskd_json_document *document,
    size_t token,
    struct asteriskd_config *config) {
    if (document->tokens[token].type == ASTERISKD_JSON_NULL) return 0;
    static const char *const names[] = {"executablePath"};
    size_t values[1];
    if (object_fields(document, token, names, 1U, values) != 0 ||
        copy_string(document, values[0], config->matcher.executable_path, sizeof(config->matcher.executable_path)) != 0 ||
        !path_is_normal(config->matcher.executable_path)) return -1;
    config->matcher.enabled = true;
    return 0;
}

static int parse_port(const struct asteriskd_json_document *document, size_t token, uint16_t *out) {
    uint32_t value = 0U;
    if (parse_u32(document, token, &value) != 0 || value == 0U || value > 65535U) return -1;
    *out = (uint16_t)value;
    return 0;
}

static int parse_hev(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {
        "type", "executablePath", "socksHost", "socksPort", "tunnelName", "mtu", "ipv4Address",
        "ipv6Address", "multiQueue", "tcpFastOpen", "tcpReadWriteTimeoutMilliseconds",
        "udpReadWriteTimeoutMilliseconds",
    };
    size_t values[12];
    struct asteriskd_hev_helper_config *hev = &config->helper.value.hev;
    if (object_fields(document, object, names, 12U, values) != 0 || !token_equals(document, values[0], "hev-socks5-tunnel") ||
        copy_string(document, values[1], hev->executable_path, sizeof(hev->executable_path)) != 0 || !path_is_normal(hev->executable_path) ||
        copy_string(document, values[2], hev->socks_host, sizeof(hev->socks_host)) != 0 || strcmp(hev->socks_host, "127.0.0.1") != 0 ||
        parse_port(document, values[3], &hev->socks_port) != 0 ||
        copy_string(document, values[4], hev->tunnel_name, sizeof(hev->tunnel_name)) != 0 || !interface_is_valid(hev->tunnel_name, false) ||
        parse_u32(document, values[5], &hev->mtu) != 0 || hev->mtu < 576U || hev->mtu > 65535U ||
        copy_string(document, values[6], hev->ipv4_address, sizeof(hev->ipv4_address)) != 0 || strchr(hev->ipv4_address, '/') != NULL ||
        inet_pton(AF_INET, hev->ipv4_address, (unsigned char[4]){0}) != 1 ||
        parse_bool(document, values[8], &hev->multi_queue) != 0 || parse_bool(document, values[9], &hev->tcp_fast_open) != 0 ||
        parse_u32(document, values[10], &hev->tcp_read_write_timeout_milliseconds) != 0 || hev->tcp_read_write_timeout_milliseconds < 1000U || hev->tcp_read_write_timeout_milliseconds > 86400000U ||
        parse_u32(document, values[11], &hev->udp_read_write_timeout_milliseconds) != 0 || hev->udp_read_write_timeout_milliseconds < 1000U || hev->udp_read_write_timeout_milliseconds > 86400000U) return -1;
    if (document->tokens[values[7]].type != ASTERISKD_JSON_NULL) {
        hev->has_ipv6_address = true;
        if (copy_string(document, values[7], hev->ipv6_address, sizeof(hev->ipv6_address)) != 0 ||
            strchr(hev->ipv6_address, '/') != NULL || inet_pton(AF_INET6, hev->ipv6_address, (unsigned char[16]){0}) != 1) return -1;
    }
    config->helper.type = ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL;
    return 0;
}

static int parse_bpf(
    const struct asteriskd_json_document *document,
    size_t object,
    struct asteriskd_config *config) {
    static const char *const names[] = {
        "type", "executablePath", "bridgeListenAddress", "bridgePort", "socksHost", "socksPort",
        "workerCount", "tcpBufferSize", "maxTcpSessions", "tcpConnectTimeoutMilliseconds",
        "tcpIdleTimeoutMilliseconds", "udpSocketBufferSize", "udpBatchSize", "maxUdpSessions",
        "maxUdpBindings", "udpIdleTimeoutSeconds", "maxUdpPendingBytes", "dnsTransactionTimeoutMilliseconds",
    };
    size_t values[18];
    struct asteriskd_bpf_helper_config *bpf = &config->helper.value.bpf;
    if (object_fields(document, object, names, 18U, values) != 0 || !token_equals(document, values[0], "bpf2socks") ||
        copy_string(document, values[1], bpf->executable_path, sizeof(bpf->executable_path)) != 0 || !path_is_normal(bpf->executable_path) ||
        copy_string(document, values[2], bpf->bridge_listen_address, sizeof(bpf->bridge_listen_address)) != 0 || strcmp(bpf->bridge_listen_address, "0.0.0.0") != 0 ||
        parse_port(document, values[3], &bpf->bridge_port) != 0 || copy_string(document, values[4], bpf->socks_host, sizeof(bpf->socks_host)) != 0 || strcmp(bpf->socks_host, "127.0.0.1") != 0 ||
        parse_port(document, values[5], &bpf->socks_port) != 0 || bpf->bridge_port == bpf->socks_port ||
        parse_u32(document, values[6], &bpf->worker_count) != 0 || bpf->worker_count > 256U ||
        parse_u32(document, values[7], &bpf->tcp_buffer_size) != 0 || bpf->tcp_buffer_size < 4096U || bpf->tcp_buffer_size > 16777216U ||
        parse_u32(document, values[8], &bpf->max_tcp_sessions) != 0 || bpf->max_tcp_sessions < 1U || bpf->max_tcp_sessions > 1048576U ||
        parse_u32(document, values[9], &bpf->tcp_connect_timeout_milliseconds) != 0 || bpf->tcp_connect_timeout_milliseconds < 100U || bpf->tcp_connect_timeout_milliseconds > 60000U ||
        parse_u32(document, values[10], &bpf->tcp_idle_timeout_milliseconds) != 0 || bpf->tcp_idle_timeout_milliseconds < 1000U || bpf->tcp_idle_timeout_milliseconds > 86400000U ||
        parse_u32(document, values[11], &bpf->udp_socket_buffer_size) != 0 || bpf->udp_socket_buffer_size < 4096U || bpf->udp_socket_buffer_size > 16777216U ||
        parse_u32(document, values[12], &bpf->udp_batch_size) != 0 || bpf->udp_batch_size < 1U || bpf->udp_batch_size > 1024U ||
        parse_u32(document, values[13], &bpf->max_udp_sessions) != 0 || bpf->max_udp_sessions < 1U || bpf->max_udp_sessions > 1048576U ||
        parse_u32(document, values[14], &bpf->max_udp_bindings) != 0 || bpf->max_udp_bindings < 1U || bpf->max_udp_bindings > 4194304U ||
        parse_u32(document, values[15], &bpf->udp_idle_timeout_seconds) != 0 || bpf->udp_idle_timeout_seconds < 1U || bpf->udp_idle_timeout_seconds > 86400U ||
        parse_u32(document, values[16], &bpf->max_udp_pending_bytes) != 0 || bpf->max_udp_pending_bytes < 65536U || bpf->max_udp_pending_bytes > 1073741824U ||
        parse_u32(document, values[17], &bpf->dns_transaction_timeout_milliseconds) != 0 || bpf->dns_transaction_timeout_milliseconds < 100U || bpf->dns_transaction_timeout_milliseconds > 60000U) return -1;
    config->helper.type = ASTERISKD_HELPER_BPF2SOCKS;
    return 0;
}

static int parse_helper(
    const struct asteriskd_json_document *document,
    size_t token,
    struct asteriskd_config *config) {
    if (document->tokens[token].type == ASTERISKD_JSON_NULL) return 0;
    if (document->tokens[token].type != ASTERISKD_JSON_OBJECT) return -1;
    size_t type = TOKEN_NONE;
    if (find_field(document, token, "type", &type) != 0) return -1;
    if (token_equals(document, type, "hev-socks5-tunnel")) return parse_hev(document, token, config);
    if (token_equals(document, type, "bpf2socks")) return parse_bpf(document, token, config);
    return -1;
}

static int validate_cross_fields(struct asteriskd_config *config) {
    if (config->mode == ASTERISKD_MODE_EBPF && config->readiness_timeout_milliseconds < 1000U) return -1;
    if (config->core_type != ASTERISKD_CORE_MIHOMO && config->has_age_secret_key) return -1;
    if (config->enable_ipv6 && config->disable_system_ipv6) return -1;
    if (config->enable_fake_dns) {
        const char *slash = strrchr(config->fake_dns_ipv4_pool, '/');
        if (!config->has_fake_dns_ipv4_pool || canonical_cidr(config->fake_dns_ipv4_pool, AF_INET, NULL) != 0 || slash == NULL) return -1;
        unsigned long prefix = strtoul(slash + 1, NULL, 10);
        if (prefix < 1UL || prefix > 30UL) return -1;
    } else if (config->has_fake_dns_ipv4_pool) return -1;
    if ((config->mode == ASTERISKD_MODE_TPROXY) != config->has_transparent_port ||
        (config->mode == ASTERISKD_MODE_TUN) != config->has_tunnel_name) return -1;
    if (config->mode != ASTERISKD_MODE_TPROXY && config->has_transparent_port) return -1;
    if (config->mode != ASTERISKD_MODE_TUN && config->has_tunnel_name) return -1;
    if ((config->mode == ASTERISKD_MODE_TUN2SOCKS && config->helper.type != ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) ||
        (config->mode == ASTERISKD_MODE_BPF2SOCKS && config->helper.type != ASTERISKD_HELPER_BPF2SOCKS) ||
        ((config->mode == ASTERISKD_MODE_TPROXY || config->mode == ASTERISKD_MODE_TUN || config->mode == ASTERISKD_MODE_EBPF) && config->helper.type != ASTERISKD_HELPER_NONE)) return -1;
    if (config->matcher.enabled && !(config->mode == ASTERISKD_MODE_TPROXY || config->mode == ASTERISKD_MODE_TUN || config->mode == ASTERISKD_MODE_TUN2SOCKS)) return -1;
    bool direct_consumer = config->matcher.enabled ^ (config->mode == ASTERISKD_MODE_BPF2SOCKS);
    if (config->has_direct_cidr_paths && !direct_consumer) return -1;
    if (config->helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) {
        struct asteriskd_hev_helper_config *hev = &config->helper.value.hev;
        if (config->enable_ipv6 != hev->has_ipv6_address || (config->enable_ipv6 && hev->mtu < 1280U)) return -1;
    }
    if (config->mode == ASTERISKD_MODE_EBPF &&
        (config->enable_local_dns || config->enable_fake_dns || config->has_fake_dns_ipv4_pool ||
         config->ignored_interface_count != 0U || config->virtual_interface_count != 0U ||
         config->hotspot_interface_prefix_count != 0U || config->proxy_private_cidr_count != 0U ||
         config->bypass_private_cidr_count != 0U || config->app_policy_mode != ASTERISKD_APP_POLICY_GLOBAL ||
         config->uid_count != 0U || config->bypass_uid_count != 0U || config->has_direct_cidr_paths ||
         config->matcher.enabled || config->helper.type != ASTERISKD_HELPER_NONE ||
         config->has_transparent_port || config->has_tunnel_name)) return -1;
    return 0;
}

static bool supported(const struct asteriskd_config *config) {
    if (config->owner == ASTERISKD_OWNER_NG && config->core_type == ASTERISKD_CORE_XRAY) {
        return config->mode == ASTERISKD_MODE_TPROXY || config->mode == ASTERISKD_MODE_TUN2SOCKS || config->mode == ASTERISKD_MODE_BPF2SOCKS;
    }
    if (config->owner == ASTERISKD_OWNER_BOX && config->core_type == ASTERISKD_CORE_SING_BOX) return true;
    if (config->owner == ASTERISKD_OWNER_META && config->core_type == ASTERISKD_CORE_MIHOMO) return config->mode != ASTERISKD_MODE_EBPF;
    return false;
}

static int validate_topology(const struct asteriskd_config *config) {
    const char *directory = config->owner == ASTERISKD_OWNER_NG ? "xray" : config->owner == ASTERISKD_OWNER_BOX ? "sing-box" : "clash";
    const char *executable = config->owner == ASTERISKD_OWNER_NG ? "xray" : config->owner == ASTERISKD_OWNER_BOX ? "sing-box" : "mihomo";
    const char *config_name = config->owner == ASTERISKD_OWNER_META ? "config.yaml" : "config.json";
    const char *basename = strrchr(config->working_directory, '/');
    if (basename == NULL || strcmp(basename + 1, directory) != 0) return -1;
    char expected[ASTERISKD_MAX_PATH];
    int length = snprintf(expected, sizeof(expected), "%s/%s", config->working_directory, executable);
    if (length < 0 || (size_t)length >= sizeof(expected) || strcmp(expected, config->core_executable_path) != 0) return -1;
    length = snprintf(expected, sizeof(expected), "%s/%s", config->working_directory, config_name);
    if (length < 0 || (size_t)length >= sizeof(expected) || strcmp(expected, config->core_config_path) != 0) return -1;
    length = snprintf(expected, sizeof(expected), "%s/asteriskd.state", config->working_directory);
    if (length < 0 || (size_t)length >= sizeof(expected) || strcmp(expected, config->state_path) != 0) return -1;
    length = snprintf(expected, sizeof(expected), "%s/logs/asteriskd.log", config->working_directory);
    if (length < 0 || (size_t)length >= sizeof(expected) || strcmp(expected, config->log_path) != 0) return -1;
    if (!config->has_direct_cidr_paths) return 0;
    length = snprintf(expected, sizeof(expected), "%s/direct-cidr-v4.txt", config->working_directory);
    if (length < 0 || (size_t)length >= sizeof(expected) ||
        strcmp(expected, config->direct_cidr_path_v4) != 0) return -1;
    length = snprintf(expected, sizeof(expected), "%s/direct-cidr-v6.txt", config->working_directory);
    return length >= 0 && (size_t)length < sizeof(expected) &&
        strcmp(expected, config->direct_cidr_path_v6) == 0 ? 0 : -1;
}

int asteriskd_config_parse(
    const char *json,
    size_t length,
    struct asteriskd_config *config,
    char *message,
    size_t message_size) {
    if (config == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(config, 0, sizeof(*config));
    struct asteriskd_json_document document;
    int result = asteriskd_json_parse(json, length, &document, message, message_size);
    if (result != 0) return result;
    static const char *const root_names_v2[] = {
        "schemaVersion", "owner", "coreType", "coreExecutablePath", "coreConfigPath", "statePath",
        "logPath", "mode", "core", "network", "modeOptions", "matcher", "helper",
    };
    static const char *const root_names_v3[] = {
        "schemaVersion", "owner", "coreType", "coreExecutablePath", "coreConfigPath", "statePath",
        "logPath", "mode", "core", "network", "modeOptions", "matcher", "helper", "serviceControl",
    };
    static const char *const owners[] = {"asteriskng", "asteriskbox", "asteriskmeta"};
    static const char *const cores[] = {"xray", "sing-box", "mihomo"};
    static const char *const modes[] = {"tproxy", "tun", "tun2socks", "bpf2socks", "ebpf"};
    size_t values[14];
    size_t schema_token = TOKEN_NONE;
    uint32_t schema = 0U;
    int owner = 0, core = 0, mode = 0;
    if (document.tokens[0].type != ASTERISKD_JSON_OBJECT ||
        find_field(&document, 0U, "schemaVersion", &schema_token) != 0 ||
        parse_u32(&document, schema_token, &schema) != 0 ||
        (schema != 2U && schema != ASTERISKD_CONFIG_VERSION) ||
        (schema == 2U
            ? object_fields(&document, 0U, root_names_v2, 13U, values)
            : object_fields(&document, 0U, root_names_v3, 14U, values)) != 0 ||
        copy_string(&document, values[3], config->core_executable_path, sizeof(config->core_executable_path)) != 0 || !path_is_normal(config->core_executable_path) ||
        copy_string(&document, values[4], config->core_config_path, sizeof(config->core_config_path)) != 0 || !path_is_normal(config->core_config_path) ||
        copy_string(&document, values[5], config->state_path, sizeof(config->state_path)) != 0 || !path_is_normal(config->state_path) ||
        copy_string(&document, values[6], config->log_path, sizeof(config->log_path)) != 0 || !path_is_normal(config->log_path)) goto invalid;
    config->schema_version = schema;
    config->version = schema;
    if (parse_enum_string(&document, values[1], owners, 3U, &owner) != 0 ||
        parse_enum_string(&document, values[2], cores, 3U, &core) != 0 ||
        parse_enum_string(&document, values[7], modes, 5U, &mode) != 0) goto invalid;
    config->owner = (enum asteriskd_owner)owner;
    config->core_type = (enum asteriskd_core_type)core;
    config->mode = (enum asteriskd_mode)mode;
    result = parse_core(&document, values[8], config);
    if (result == 0) result = parse_network(&document, values[9], config);
    if (result == 0) result = parse_mode_options(&document, values[10], config);
    if (result == 0) result = parse_matcher(&document, values[11], config);
    if (result == 0) result = parse_helper(&document, values[12], config);
    if (result == 0 && schema == 3U) {
        result = parse_service_control(&document, values[13], &config->service_control);
    }
    if (result == ASTERISKD_CONFIG_NO_MEMORY) goto no_memory;
    if (result != 0 || validate_cross_fields(config) != 0) goto invalid;
    if (!supported(config)) {
        asteriskd_json_document_destroy(&document);
        asteriskd_config_destroy(config);
        set_message(message, message_size, "unsupported combination");
        return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
    }
    if (validate_topology(config) != 0) goto invalid;
    asteriskd_json_document_destroy(&document);
    set_message(message, message_size, "ok");
    return 0;
no_memory:
    asteriskd_json_document_destroy(&document);
    asteriskd_config_destroy(config);
    set_message(message, message_size, "out of memory");
    return ASTERISKD_CONFIG_NO_MEMORY;
invalid:
    asteriskd_json_document_destroy(&document);
    asteriskd_config_destroy(config);
    set_message(message, message_size, "invalid config");
    return ASTERISKD_CONFIG_INVALID;
}

void asteriskd_runtime_directory_release(struct asteriskd_runtime_directory *directory) {
    if (directory == NULL) return;
    if (directory->owned && directory->fd >= 0) {
        if (directory->close_owned_fd != NULL) {
            directory->close_owned_fd(directory->close_context, directory->fd);
        } else {
#ifdef _WIN32
            (void)_close(directory->fd);
#else
            (void)close(directory->fd);
#endif
        }
    }
    memset(directory, 0, sizeof(*directory));
    directory->fd = -1;
}

void asteriskd_loaded_config_release(struct asteriskd_loaded_config *loaded) {
    if (loaded == NULL) return;
    if (loaded->config_fd_owned && loaded->config_fd >= 0) {
        if (loaded->close_owned_fd != NULL) {
            loaded->close_owned_fd(loaded->close_context, loaded->config_fd);
        } else {
#ifdef _WIN32
            (void)_close(loaded->config_fd);
#else
            (void)close(loaded->config_fd);
#endif
        }
    }
    asteriskd_runtime_directory_release(&loaded->directory);
    asteriskd_config_destroy(&loaded->config);
    memset(loaded, 0, sizeof(*loaded));
    loaded->directory.fd = -1;
    loaded->config_fd = -1;
}

static int load_direct_resources_with_backend(
    struct asteriskd_config *config,
    int directory_fd,
    const struct asteriskd_config_load_backend *backend,
    void *context) {
    if (!config->has_direct_cidr_paths) return 0;
    if (backend->read_resource == NULL) return ASTERISKD_CONFIG_INVALID;
    char *ipv4 = NULL;
    size_t ipv4_length = 0U;
    char *ipv6 = NULL;
    size_t ipv6_length = 0U;
    int result = backend->read_resource(
        context, directory_fd, config->direct_cidr_path_v4, &ipv4, &ipv4_length);
    if (result == 0 && (ipv4 == NULL && ipv4_length != 0U)) result = ASTERISKD_CONFIG_INVALID;
    if (result == 0 && ipv4_length > ASTERISKD_MAX_JSON_SIZE) result = ASTERISKD_CONFIG_INVALID;
    if (result == 0 && config->enable_ipv6) {
        result = backend->read_resource(
            context, directory_fd, config->direct_cidr_path_v6, &ipv6, &ipv6_length);
        if (result == 0 && (ipv6 == NULL && ipv6_length != 0U)) result = ASTERISKD_CONFIG_INVALID;
        if (result == 0 && ipv6_length > ASTERISKD_MAX_JSON_SIZE) result = ASTERISKD_CONFIG_INVALID;
    }
    if (result == 0) {
        result = asteriskd_config_load_direct_cidrs(
            config, ipv4, ipv4_length, ipv6, ipv6_length);
    }
    free(ipv4);
    free(ipv6);
    return result;
}

int asteriskd_config_load_with_backend(
    const char *path,
    struct asteriskd_loaded_config *loaded,
    const struct asteriskd_config_load_backend *backend,
    void *context,
    char *message,
    size_t message_size) {
    if (loaded != NULL) {
        memset(loaded, 0, sizeof(*loaded));
        loaded->directory.fd = -1;
        loaded->config_fd = -1;
    }
    if (loaded == NULL || backend == NULL || backend->open_directory == NULL ||
        backend->read_config == NULL || backend->validate_files == NULL || backend->close_fd == NULL) {
        return ASTERISKD_CONFIG_INVALID;
    }
    loaded->close_owned_fd = backend->close_fd;
    loaded->close_context = context;
    loaded->directory.close_owned_fd = backend->close_fd;
    loaded->directory.close_context = context;
    if (path == NULL || !path_is_normal(path) ||
        strcmp(strrchr(path, '/') + 1, "asteriskd.json") != 0) {
        set_message(message, message_size, "invalid config path");
        return ASTERISKD_CONFIG_INVALID;
    }
    int result = backend->open_directory(context, path, &loaded->directory.fd,
        &loaded->directory.device, &loaded->directory.inode);
    loaded->directory.owned = loaded->directory.fd >= 0;
    if (result == 0 && loaded->directory.fd < 0) result = ASTERISKD_CONFIG_INVALID;
    if (result != 0) {
        asteriskd_loaded_config_release(loaded);
        set_message(message, message_size, "directory open failed");
        return result;
    }
    char *json = NULL;
    size_t length = 0U;
    result = backend->read_config(
        context,
        loaded->directory.fd,
        path,
        &json,
        &length,
        &loaded->config_fd,
        &loaded->config_device,
        &loaded->config_inode);
    loaded->config_fd_owned = loaded->config_fd >= 0;
    if (result == 0 && loaded->config_fd < 0) result = ASTERISKD_CONFIG_INVALID;
    if (result == 0 && json == NULL && length != 0U) result = ASTERISKD_CONFIG_INVALID;
    if (result == 0 && length > ASTERISKD_MAX_JSON_SIZE) result = ASTERISKD_CONFIG_INVALID;
    if (result == 0) result = asteriskd_config_parse(json, length, &loaded->config, message, message_size);
    free(json);
    if (result == 0) result = backend->validate_files(context, &loaded->config, loaded->directory.fd);
    if (result == 0) result = load_direct_resources_with_backend(
        &loaded->config, loaded->directory.fd, backend, context);
    if (result != 0) {
        asteriskd_loaded_config_release(loaded);
        return result;
    }
    return 0;
}

#ifndef _WIN32
static enum asteriskd_file_kind file_kind(mode_t mode) {
    if (S_ISREG(mode)) return ASTERISKD_FILE_REGULAR;
    if (S_ISDIR(mode)) return ASTERISKD_FILE_DIRECTORY;
    if (S_ISFIFO(mode)) return ASTERISKD_FILE_FIFO;
    if (S_ISCHR(mode) || S_ISBLK(mode)) return ASTERISKD_FILE_DEVICE;
    if (S_ISLNK(mode)) return ASTERISKD_FILE_SYMLINK;
    return ASTERISKD_FILE_OTHER;
}

static bool same_inode(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int path_open_error(int error, int missing_result) {
    if (error == ENOENT) return missing_result;
    if (error == ELOOP || error == ENOTDIR || error == EACCES || error == EPERM) {
        return ASTERISKD_CONFIG_INVALID;
    }
    return ASTERISKD_CONFIG_IO;
}

static int checked_stat(
    int fd,
    enum asteriskd_file_kind expected,
    bool readable,
    bool writable,
    bool executable,
    struct stat *out) {
    struct stat status;
    if (fstat(fd, &status) != 0) return ASTERISKD_CONFIG_IO;
    int result = asteriskd_file_requirements_validate(
            file_kind(status.st_mode),
            (uint32_t)status.st_mode,
            expected,
            readable,
            writable,
            executable);
    if (result != 0) return result;
    if (out != NULL) *out = status;
    return 0;
}

static int open_parent_walk(const char *path, int *parent_fd, char *leaf) {
    if (!path_is_normal(path) || parent_fd == NULL || leaf == NULL) return ASTERISKD_CONFIG_INVALID;
    int current = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return path_open_error(errno, ASTERISKD_CONFIG_INVALID);
    int result = checked_stat(current, ASTERISKD_FILE_DIRECTORY, false, false, true, NULL);
    const char *component = path + 1;
    while (result == 0) {
        const char *slash = strchr(component, '/');
        size_t length = slash == NULL ? strlen(component) : (size_t)(slash - component);
        if (length == 0U || length >= ASTERISKD_MAX_PATH) {
            result = ASTERISKD_CONFIG_INVALID;
            break;
        }
        if (slash == NULL) {
            memcpy(leaf, component, length);
            leaf[length] = '\0';
            *parent_fd = current;
            return 0;
        }
        char name[ASTERISKD_MAX_PATH];
        memcpy(name, component, length);
        name[length] = '\0';
        int next = openat(current, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            result = path_open_error(errno, ASTERISKD_CONFIG_INVALID);
            break;
        }
        result = checked_stat(next, ASTERISKD_FILE_DIRECTORY, false, false, true, NULL);
        close(current);
        current = next;
        component = slash + 1;
    }
    close(current);
    return result;
}

static int open_verified_absolute(
    const char *path,
    enum asteriskd_file_kind expected,
    bool readable,
    bool writable,
    bool executable,
    bool allow_missing,
    bool writable_parent,
    int access_flags,
    int missing_result,
    int *out,
    struct stat *out_status) {
    int parent_fd = -1;
    char leaf[ASTERISKD_MAX_PATH];
    int result = open_parent_walk(path, &parent_fd, leaf);
    if (result != 0) return result;
    if (writable_parent) {
        result = checked_stat(parent_fd, ASTERISKD_FILE_DIRECTORY, false, true, true, NULL);
    }
    int probe_fd = -1;
    if (result == 0) {
        probe_fd = openat(parent_fd, leaf, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (probe_fd < 0) {
            int saved = errno;
            if (allow_missing && saved == ENOENT) {
                close(parent_fd);
                if (out != NULL) *out = -1;
                return 0;
            }
            result = path_open_error(saved, missing_result);
        }
    }
    struct stat probed;
    if (result == 0) {
        result = checked_stat(probe_fd, expected, readable, writable, executable, &probed);
    }
    int access_fd = -1;
    if (result == 0) {
        int flags = access_flags | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC;
        if (expected == ASTERISKD_FILE_DIRECTORY) flags |= O_DIRECTORY;
        access_fd = openat(parent_fd, leaf, flags);
        if (access_fd < 0) result = path_open_error(errno, missing_result);
    }
    struct stat accessed;
    if (result == 0) {
        result = checked_stat(access_fd, expected, readable, writable, executable, &accessed);
        if (result == 0 && !same_inode(&probed, &accessed)) result = ASTERISKD_CONFIG_INVALID;
    }
    if (probe_fd >= 0) close(probe_fd);
    close(parent_fd);
    if (result != 0) {
        if (access_fd >= 0) close(access_fd);
        return result;
    }
    if (out_status != NULL) *out_status = accessed;
    if (out != NULL) *out = access_fd;
    else close(access_fd);
    return 0;
}

static int open_verified_child(
    int directory_fd,
    const char *name,
    enum asteriskd_file_kind expected,
    bool readable,
    bool writable,
    bool executable,
    int access_flags,
    int missing_result,
    int *out,
    struct stat *out_status) {
    int probe_fd = openat(directory_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (probe_fd < 0) return path_open_error(errno, missing_result);
    struct stat probed;
    int result = checked_stat(probe_fd, expected, readable, writable, executable, &probed);
    int access_fd = -1;
    if (result == 0) {
        access_fd = openat(directory_fd, name, access_flags | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (access_fd < 0) result = path_open_error(errno, missing_result);
    }
    struct stat accessed;
    if (result == 0) {
        result = checked_stat(access_fd, expected, readable, writable, executable, &accessed);
        if (result == 0 && !same_inode(&probed, &accessed)) result = ASTERISKD_CONFIG_INVALID;
    }
    close(probe_fd);
    if (result != 0) {
        if (access_fd >= 0) close(access_fd);
        return result;
    }
    if (out_status != NULL) *out_status = accessed;
    if (out != NULL) *out = access_fd;
    else close(access_fd);
    return 0;
}

static int validate_regular_path(
    const char *path,
    bool readable,
    bool writable,
    bool executable,
    bool allow_missing,
    bool writable_parent) {
    int access_flags = readable && writable ? O_RDWR : writable ? O_WRONLY : O_RDONLY;
    return open_verified_absolute(
        path,
        ASTERISKD_FILE_REGULAR,
        readable,
        writable,
        executable,
        allow_missing,
        writable_parent,
        access_flags,
        ASTERISKD_CONFIG_INVALID,
        NULL,
        NULL);
}

static int validate_loaded_paths(const struct asteriskd_config *config, int runtime_directory_fd) {
    int directory_fd = -1;
    struct stat expected, actual;
    int result = open_verified_absolute(
        config->working_directory,
        ASTERISKD_FILE_DIRECTORY,
        true,
        true,
        true,
        false,
        false,
        O_RDONLY,
        ASTERISKD_CONFIG_INVALID,
        &directory_fd,
        &expected);
    if (result == 0 && (fstat(runtime_directory_fd, &actual) != 0 || !same_inode(&expected, &actual))) {
        result = ASTERISKD_CONFIG_INVALID;
    }
    if (directory_fd >= 0) close(directory_fd);
    if (result == 0) result = validate_regular_path(config->core_config_path, true, false, false, false, false);
    if (result == 0) result = validate_regular_path(config->state_path, true, true, false, true, true);
    if (result == 0) result = validate_regular_path(config->log_path, false, true, false, true, true);
    if (result == 0 && config->matcher.enabled) {
        result = validate_regular_path(config->matcher.executable_path, true, false, true, false, false);
    }
    const char *helper = NULL;
    if (config->helper.type == ASTERISKD_HELPER_HEV_SOCKS5_TUNNEL) helper = config->helper.value.hev.executable_path;
    if (config->helper.type == ASTERISKD_HELPER_BPF2SOCKS) helper = config->helper.value.bpf.executable_path;
    if (result == 0 && helper != NULL) result = validate_regular_path(helper, true, false, true, false, false);
    return result;
}

static int read_fd_bounded(int fd, char **out, size_t *length) {
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        (uint64_t)status.st_size > ASTERISKD_MAX_JSON_SIZE) return ASTERISKD_CONFIG_INVALID;
    size_t size = (size_t)status.st_size;
    char *data = malloc(size == 0U ? 1U : size);
    if (data == NULL) return ASTERISKD_CONFIG_NO_MEMORY;
    size_t offset = 0U;
    while (offset < size) {
        ssize_t count = pread(fd, data + offset, size - offset, (off_t)offset);
        if (count <= 0) {
            free(data);
            return ASTERISKD_CONFIG_IO;
        }
        offset += (size_t)count;
    }
    *out = data;
    *length = size;
    return 0;
}

static int read_direct_resource_child(
    int directory_fd,
    const char *name,
    char **out,
    size_t *length) {
    int fd = -1;
    int result = open_verified_child(
        directory_fd,
        name,
        ASTERISKD_FILE_REGULAR,
        true,
        false,
        false,
        O_RDONLY,
        ASTERISKD_CONFIG_INVALID,
        &fd,
        NULL);
    if (result == 0) result = read_fd_bounded(fd, out, length);
    if (fd >= 0) close(fd);
    return result;
}

static int load_direct_resources_linux(
    struct asteriskd_config *config,
    int directory_fd) {
    if (!config->has_direct_cidr_paths) return 0;
    char *ipv4 = NULL;
    size_t ipv4_length = 0U;
    char *ipv6 = NULL;
    size_t ipv6_length = 0U;
    int result = read_direct_resource_child(
        directory_fd, "direct-cidr-v4.txt", &ipv4, &ipv4_length);
    if (result == 0 && config->enable_ipv6) {
        result = read_direct_resource_child(
            directory_fd, "direct-cidr-v6.txt", &ipv6, &ipv6_length);
    }
    if (result == 0) {
        result = asteriskd_config_load_direct_cidrs(
            config, ipv4, ipv4_length, ipv6, ipv6_length);
    }
    free(ipv4);
    free(ipv6);
    return result;
}

static int parent_path(const char *path, char *out, size_t out_size) {
    const char *slash = strrchr(path, '/');
    if (slash == NULL || slash == path || (size_t)(slash - path) >= out_size) return -1;
    size_t length = (size_t)(slash - path);
    memcpy(out, path, length);
    out[length] = '\0';
    return 0;
}

int asteriskd_runtime_directory_open(
    const char *path,
    struct asteriskd_runtime_directory *directory_handle,
    char *message,
    size_t message_size) {
    if (directory_handle == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(directory_handle, 0, sizeof(*directory_handle));
    directory_handle->fd = -1;
    char directory[ASTERISKD_MAX_PATH];
    if (path == NULL || !path_is_normal(path) ||
        parent_path(path, directory, sizeof(directory)) != 0 ||
        strcmp(strrchr(path, '/') + 1, "asteriskd.json") != 0) {
        set_message(message, message_size, "invalid config path");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct stat path_directory_status;
    int result = open_verified_absolute(
        directory,
        ASTERISKD_FILE_DIRECTORY,
        true,
        true,
        true,
        false,
        false,
        O_RDONLY,
        ASTERISKD_CONFIG_IO,
        &directory_handle->fd,
        &path_directory_status);
    directory_handle->owned = directory_handle->fd >= 0;
    if (result != 0) {
        asteriskd_runtime_directory_release(directory_handle);
        return result;
    }
    directory_handle->device = (uint64_t)path_directory_status.st_dev;
    directory_handle->inode = (uint64_t)path_directory_status.st_ino;
    return 0;
}

int asteriskd_config_load(
    const char *path,
    struct asteriskd_loaded_config *loaded,
    char *message,
    size_t message_size) {
    if (loaded == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(loaded, 0, sizeof(*loaded));
    loaded->directory.fd = -1;
    loaded->config_fd = -1;
    int result = asteriskd_runtime_directory_open(
        path, &loaded->directory, message, message_size);
    if (result != 0) return result;
    struct stat config_status;
    result = open_verified_child(
        loaded->directory.fd,
        "asteriskd.json",
        ASTERISKD_FILE_REGULAR,
        true,
        false,
        false,
        O_RDONLY,
        ASTERISKD_CONFIG_IO,
        &loaded->config_fd,
        &config_status);
    loaded->config_fd_owned = loaded->config_fd >= 0;
    if (result != 0) {
        asteriskd_loaded_config_release(loaded);
        return result;
    }
    char *json = NULL;
    size_t length = 0U;
    result = read_fd_bounded(loaded->config_fd, &json, &length);
    if (result == 0) result = asteriskd_config_parse(json, length, &loaded->config, message, message_size);
    free(json);
    int verify_fd = -1;
    struct stat verify_status;
    if (result == 0) {
        result = open_verified_child(
            loaded->directory.fd,
            "asteriskd.json",
            ASTERISKD_FILE_REGULAR,
            true,
            false,
            false,
            O_RDONLY,
            ASTERISKD_CONFIG_INVALID,
            &verify_fd,
            &verify_status);
        if (result == 0 && !same_inode(&config_status, &verify_status)) result = ASTERISKD_CONFIG_INVALID;
    }
    if (verify_fd >= 0) close(verify_fd);
    if (result == 0) result = validate_loaded_paths(&loaded->config, loaded->directory.fd);
    if (result == 0) result = load_direct_resources_linux(&loaded->config, loaded->directory.fd);
    if (result != 0) {
        asteriskd_loaded_config_release(loaded);
        return result;
    }
    loaded->config_device = (uint64_t)config_status.st_dev;
    loaded->config_inode = (uint64_t)config_status.st_ino;
    return 0;
}
#else
int asteriskd_config_load(
    const char *path,
    struct asteriskd_loaded_config *loaded,
    char *message,
    size_t message_size) {
    (void)path;
    if (loaded != NULL) {
        memset(loaded, 0, sizeof(*loaded));
        loaded->directory.fd = -1;
        loaded->config_fd = -1;
    }
    set_message(message, message_size, "real config load requires Linux; use injected host seam");
    return ASTERISKD_CONFIG_IO;
}

int asteriskd_runtime_directory_open(
    const char *path,
    struct asteriskd_runtime_directory *directory,
    char *message,
    size_t message_size) {
    (void)path;
    if (directory != NULL) {
        memset(directory, 0, sizeof(*directory));
        directory->fd = -1;
    }
    set_message(message, message_size, "real directory open requires Linux");
    return ASTERISKD_CONFIG_IO;
}
#endif

int asteriskd_load_config(
    const char *path,
    struct asteriskd_config *config,
    char *message,
    size_t message_size) {
    if (config == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(config, 0, sizeof(*config));
    struct asteriskd_loaded_config loaded;
    int result = asteriskd_config_load(path, &loaded, message, message_size);
    if (result != 0) return result;
    *config = loaded.config;
    memset(&loaded.config, 0, sizeof(loaded.config));
    asteriskd_loaded_config_release(&loaded);
    return 0;
}

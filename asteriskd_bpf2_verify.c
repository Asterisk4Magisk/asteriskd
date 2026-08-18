#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

const char *asteriskd_bpf2_tc_filter_attachment_name(enum asteriskd_program_id program_id) {
    return program_id == ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS
        ? "tc_ingress:[*fsobj]"
        : program_id == ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS
            ? "tc_egress:[*fsobj]" : NULL;
}

static bool tag_nonzero(const unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE]) {
    for (size_t index = 0U; index < ASTERISKD_BPF_PROGRAM_TAG_SIZE; ++index) {
        if (tag[index] != 0U) return true;
    }
    return false;
}

static void set_error(char *error, size_t capacity, const char *message) {
    if (error != NULL && capacity != 0U) (void)snprintf(error, capacity, "%s", message);
}

static int append_pin(
    struct asteriskd_bpf2_pin_plan *plan, enum asteriskd_pin_id pin_id,
    const char *root, const char *leaf, bool program, const char *program_name) {
    if (plan->pin_count >= sizeof(plan->pins) / sizeof(plan->pins[0])) return -1;
    struct asteriskd_bpf2_pin_expectation *pin = &plan->pins[plan->pin_count++];
    pin->pin_id = pin_id;
    int written = snprintf(pin->path, sizeof(pin->path), "%s/%s", root, leaf);
    if (written <= 0 || (size_t)written >= sizeof(pin->path)) return -1;
    pin->program = program;
    if (program) {
        written = snprintf(pin->program_name, sizeof(pin->program_name), "%s", program_name);
        if (written <= 0 || (size_t)written >= sizeof(pin->program_name)) return -1;
    }
    return 0;
}

int asteriskd_bpf2_pin_plan_build(
    const struct asteriskd_config *config, struct asteriskd_bpf2_pin_plan *plan) {
    if (plan != NULL) memset(plan, 0, sizeof(*plan));
    if (config == NULL || plan == NULL || config->mode != ASTERISKD_MODE_BPF2SOCKS ||
        config->helper.type != ASTERISKD_HELPER_BPF2SOCKS) return ASTERISKD_CONFIG_INVALID;
    const char *root = asteriskd_owned_resource_catalog()->bpf2_root;
    if (append_pin(plan, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4,
        root, "local_addr_v4", false, NULL) != 0 ||
        (config->enable_ipv6 && append_pin(plan, ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6,
            root, "local_addr_v6", false, NULL) != 0) ||
        append_pin(plan, ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS,
            root, "tc_ingress", true, "b2s_tc_in") != 0 ||
        append_pin(plan, ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS,
            root, "tc_egress", true, "b2s_tc_out") != 0) {
        memset(plan, 0, sizeof(*plan));
        return ASTERISKD_CONFIG_INVALID;
    }
    return 0;
}

int asteriskd_bpf2_pin_records_build(
    const struct asteriskd_bpf2_pin_plan *plan, struct asteriskd_resource_operation *records,
    size_t capacity, size_t *count) {
    if (count != NULL) *count = 0U;
    if (plan == NULL || records == NULL || count == NULL ||
        (plan->pin_count != 3U && plan->pin_count != 4U) || capacity < plan->pin_count) {
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

static bool backend_valid(const struct asteriskd_bpf_program_backend *backend) {
    return backend != NULL && backend->open_program != NULL && backend->program_info != NULL &&
        backend->open_pinned_map != NULL && backend->map_info != NULL && backend->close != NULL;
}

static int verify_map_pin(
    const struct asteriskd_bpf2_pin_expectation *pin,
    const struct asteriskd_bpf_program_backend *backend, uint64_t *object_id) {
    int fd = -1;
    int result = ASTERISKD_CONFIG_IO;
    if (backend->open_pinned_map(backend->context, pin->path, &fd) != 0 || fd < 0) return result;
    struct asteriskd_bpf_map_info info;
    memset(&info, 0, sizeof(info));
    uint32_t key_size = pin->pin_id == ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4 ? 8U : 20U;
    if (backend->map_info(backend->context, fd, &info) == 0 && info.object_id != 0U &&
        info.type == ASTERISKD_BPF_MAP_TYPE_LPM_TRIE && info.key_size == key_size &&
        info.value_size == 1U && info.max_entries == ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES &&
        info.flags == ASTERISKD_BPF_MAP_FLAG_NO_PREALLOC) {
        *object_id = info.object_id;
        result = 0;
    }
    if (backend->close(backend->context, fd) != 0 && result == 0) result = ASTERISKD_CONFIG_IO;
    return result;
}

static int verify_program_pin(
    const struct asteriskd_bpf2_pin_expectation *pin,
    const struct asteriskd_bpf_program_backend *backend,
    uint64_t *object_id, unsigned char tag[ASTERISKD_BPF_PROGRAM_TAG_SIZE]) {
    int fd = -1;
    int result = ASTERISKD_CONFIG_IO;
    if (backend->open_program(backend->context, pin->path, &fd) != 0 || fd < 0) return result;
    struct asteriskd_bpf_program_info info;
    memset(&info, 0, sizeof(info));
    if (backend->program_info(backend->context, fd, &info) == 0 && info.object_id != 0U &&
        info.type == ASTERISKD_BPF_PROGRAM_TYPE_SCHED_CLS &&
        strcmp(info.name, pin->program_name) == 0 && tag_nonzero(info.tag) &&
        info.map_count <= ASTERISKD_BPF_PROGRAM_MAX_MAPS) {
        *object_id = info.object_id;
        memcpy(tag, info.tag, ASTERISKD_BPF_PROGRAM_TAG_SIZE);
        result = 0;
    }
    if (backend->close(backend->context, fd) != 0 && result == 0) result = ASTERISKD_CONFIG_IO;
    return result;
}

static int verify_pins(
    const struct asteriskd_config *config, const struct asteriskd_bpf2_pin_plan *plan,
    const struct asteriskd_bpf_program_backend *backend,
    const struct asteriskd_bpf_pin_ownership_backend *ownership,
    bool allow_absent, struct asteriskd_bpf2_verification *verification,
    char *error, size_t error_capacity) {
    if (verification != NULL) memset(verification, 0, sizeof(*verification));
    if (error != NULL && error_capacity != 0U) error[0] = '\0';
    size_t expected_count = config != NULL && config->enable_ipv6 ? 4U : 3U;
    if (config == NULL || plan == NULL || verification == NULL || !backend_valid(backend) ||
        (allow_absent && (ownership == NULL || ownership->probe == NULL)) ||
        config->mode != ASTERISKD_MODE_BPF2SOCKS ||
        config->helper.type != ASTERISKD_HELPER_BPF2SOCKS || plan->pin_count != expected_count) {
        set_error(error, error_capacity, "invalid bpf2socks pin verification input");
        return ASTERISKD_CONFIG_INVALID;
    }
    struct asteriskd_bpf2_verification result;
    memset(&result, 0, sizeof(result));
    for (size_t index = 0U; index < plan->pin_count; ++index) {
        uint64_t expected_object_id = 0U;
        if (allow_absent) {
            bool exists = true;
            if (ownership->probe(ownership->context, plan->pins[index].path,
                    &exists, &expected_object_id) != 0 ||
                (!exists && expected_object_id != 0U)) {
                set_error(error, error_capacity, "bpf2socks residue probe failed");
                return ASTERISKD_CONFIG_IO;
            }
            if (!exists) continue;
        }
        struct asteriskd_bpf2_verified_pin *verified = &result.pins[result.pin_count];
        verified->pin_id = plan->pins[index].pin_id;
        int pin_result = plan->pins[index].program ?
            verify_program_pin(&plan->pins[index], backend, &verified->object_id, verified->tag) :
            verify_map_pin(&plan->pins[index], backend, &verified->object_id);
        if (pin_result != 0 ||
            (allow_absent && verified->object_id != expected_object_id)) {
            set_error(error, error_capacity, "bpf2socks pin verification failed");
            return pin_result;
        }
        ++result.pin_count;
    }
    *verification = result;
    return 0;
}

int asteriskd_bpf2_verify(
    const struct asteriskd_config *config, const struct asteriskd_bpf2_pin_plan *plan,
    const struct asteriskd_bpf_program_backend *backend,
    struct asteriskd_bpf2_verification *verification, char *error, size_t error_capacity) {
    return verify_pins(config, plan, backend, NULL, false,
        verification, error, error_capacity);
}

int asteriskd_bpf2_verify_residue(
    const struct asteriskd_config *config, const struct asteriskd_bpf2_pin_plan *plan,
    const struct asteriskd_bpf_program_backend *backend,
    const struct asteriskd_bpf_pin_ownership_backend *ownership,
    struct asteriskd_bpf2_verification *verification, char *error, size_t error_capacity) {
    return verify_pins(config, plan, backend, ownership, true,
        verification, error, error_capacity);
}

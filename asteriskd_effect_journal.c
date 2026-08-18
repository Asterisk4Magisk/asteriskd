#include "asteriskd.h"

#include <stdio.h>
#include <string.h>

static void effect_error_clear(char *error, size_t error_size) {
    if (error != NULL && error_size != 0U) {
        error[0] = '\0';
    }
}

static void effect_error_copy(
    char *destination, size_t destination_size, const char *source) {
    if (destination == NULL || destination_size == 0U) {
        return;
    }
    (void)snprintf(destination, destination_size, "%s",
        source != NULL ? source : "");
}

static bool effect_backend_valid(const struct asteriskd_effect_backend *backend) {
    return backend != NULL &&
        backend->probe_original != NULL &&
        backend->apply != NULL &&
        backend->verify_applied != NULL &&
        backend->undo != NULL &&
        backend->verify_restored != NULL;
}

static bool effect_interface_equal(
    const char *left_name, uint32_t left_index,
    const char *right_name, uint32_t right_index) {
    return left_index == right_index && strcmp(left_name, right_name) == 0;
}

static bool effect_identity_equal(
    const struct asteriskd_effect *left,
    const struct asteriskd_effect *right) {
    if (left->kind != right->kind) {
        return false;
    }
    switch (left->kind) {
        case ASTERISKD_EFFECT_BPF_PIN:
            return left->resource.bpf_pin.pin_id ==
                right->resource.bpf_pin.pin_id;
        case ASTERISKD_EFFECT_TC_QDISC:
            return left->resource.tc_qdisc.qdisc_id ==
                    right->resource.tc_qdisc.qdisc_id &&
                effect_interface_equal(
                    left->resource.tc_qdisc.interface_name,
                    left->resource.tc_qdisc.interface_index,
                    right->resource.tc_qdisc.interface_name,
                    right->resource.tc_qdisc.interface_index);
        case ASTERISKD_EFFECT_TC_FILTER:
            return left->resource.tc_filter.filter_id ==
                    right->resource.tc_filter.filter_id &&
                left->resource.tc_filter.direction ==
                    right->resource.tc_filter.direction &&
                effect_interface_equal(
                    left->resource.tc_filter.interface_name,
                    left->resource.tc_filter.interface_index,
                    right->resource.tc_filter.interface_name,
                    right->resource.tc_filter.interface_index);
        case ASTERISKD_EFFECT_SYSCTL:
            return left->resource.sysctl.sysctl_id ==
                    right->resource.sysctl.sysctl_id &&
                effect_interface_equal(
                    left->resource.sysctl.interface_name,
                    left->resource.sysctl.interface_index,
                    right->resource.sysctl.interface_name,
                    right->resource.sysctl.interface_index);
        case ASTERISKD_EFFECT_TETHER_STATE:
            return left->resource.tether_state.tether_id ==
                    right->resource.tether_state.tether_id &&
                effect_interface_equal(
                    left->resource.tether_state.interface_name,
                    left->resource.tether_state.interface_index,
                    right->resource.tether_state.interface_name,
                    right->resource.tether_state.interface_index);
    }
    return false;
}

static void effect_reuse_original(
    struct asteriskd_effect *effect,
    const struct asteriskd_effect *existing) {
    switch (effect->kind) {
        case ASTERISKD_EFFECT_BPF_PIN:
            effect->resource.bpf_pin.original_presence =
                existing->resource.bpf_pin.original_presence;
            break;
        case ASTERISKD_EFFECT_TC_QDISC:
            effect->resource.tc_qdisc.original_presence =
                existing->resource.tc_qdisc.original_presence;
            break;
        case ASTERISKD_EFFECT_TC_FILTER:
            effect->resource.tc_filter.original_presence =
                existing->resource.tc_filter.original_presence;
            break;
        case ASTERISKD_EFFECT_SYSCTL:
            effect->resource.sysctl.original_value =
                existing->resource.sysctl.original_value;
            break;
        case ASTERISKD_EFFECT_TETHER_STATE:
            effect->resource.tether_state.original_active =
                existing->resource.tether_state.original_active;
            break;
    }
}

static size_t effect_find(
    const struct asteriskd_effect_journal *journal,
    const struct asteriskd_effect *effect) {
    size_t index;
    for (index = 0U; index < journal->count; ++index) {
        if (effect_identity_equal(&journal->entries[index], effect)) {
            return index;
        }
    }
    return journal->count;
}

static void effect_remove(
    struct asteriskd_effect_journal *journal, size_t index) {
    if (index + 1U < journal->count) {
        memmove(&journal->entries[index], &journal->entries[index + 1U],
            (journal->count - index - 1U) * sizeof(journal->entries[0]));
    }
    --journal->count;
    memset(&journal->entries[journal->count], 0,
        sizeof(journal->entries[journal->count]));
}

int asteriskd_effect_journal_apply(
    struct asteriskd_effect_journal *journal,
    const struct asteriskd_effect *effect,
    const struct asteriskd_effect_backend *backend,
    char *error, size_t error_size) {
    struct asteriskd_effect candidate;
    size_t existing_index;
    int result;

    effect_error_clear(error, error_size);
    if (journal == NULL || effect == NULL || !effect_backend_valid(backend)) {
        effect_error_copy(error, error_size, "invalid effect journal arguments");
        return -1;
    }
    candidate = *effect;
    existing_index = effect_find(journal, &candidate);
    if (existing_index < journal->count) {
        effect_reuse_original(&candidate, &journal->entries[existing_index]);
    } else {
        if (journal->count >= ASTERISKD_MAX_VOLATILE_EFFECTS) {
            effect_error_copy(error, error_size, "effect journal is full");
            return -1;
        }
        result = backend->probe_original(
            backend->context, &candidate, error, error_size);
        if (result != 0) {
            return result;
        }
    }
    result = backend->apply(backend->context, &candidate, error, error_size);
    if (result != 0) {
        return result;
    }
    result = backend->verify_applied(
        backend->context, &candidate, error, error_size);
    if (result != 0) {
        char cleanup_error[128U];
        if (backend->undo(backend->context, &candidate,
                cleanup_error, sizeof(cleanup_error)) == 0) {
            (void)backend->verify_restored(backend->context, &candidate,
                cleanup_error, sizeof(cleanup_error));
        }
        return result;
    }
    if (existing_index < journal->count) {
        journal->entries[existing_index] = candidate;
    } else {
        journal->entries[journal->count] = candidate;
        ++journal->count;
    }
    return 0;
}

int asteriskd_effect_journal_rollback(
    struct asteriskd_effect_journal *journal,
    const struct asteriskd_effect_backend *backend,
    char *error, size_t error_size) {
    char local_error[128U];
    char first_error[128U] = {0};
    size_t index;
    int first_result = 0;

    effect_error_clear(error, error_size);
    if (journal == NULL || !effect_backend_valid(backend)) {
        effect_error_copy(error, error_size, "invalid effect journal arguments");
        return -1;
    }
    index = journal->count;
    while (index != 0U) {
        int result;
        --index;
        effect_error_clear(local_error, sizeof(local_error));
        result = backend->undo(backend->context, &journal->entries[index],
            local_error, sizeof(local_error));
        if (result == 0) {
            result = backend->verify_restored(
                backend->context, &journal->entries[index],
                local_error, sizeof(local_error));
        }
        if (result == 0) {
            effect_remove(journal, index);
        } else if (first_result == 0) {
            first_result = result;
            effect_error_copy(first_error, sizeof(first_error), local_error);
        }
    }
    if (first_result != 0) {
        effect_error_copy(error, error_size, first_error);
    }
    return first_result;
}

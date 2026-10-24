// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd_supervisor.h"

#if defined(__linux__) || defined(__ANDROID__)

uint32_t asteriskd_supervisor_rule_categories(const struct asteriskd_config *config) {
    uint32_t categories = 0U;
    if (config->mode == ASTERISKD_MODE_TPROXY) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_TPROXY) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_ROUTING) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_LOCAL_BYPASS);
    } else if (config->mode == ASTERISKD_MODE_TUN2SOCKS) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_ROUTING) |
            ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_LOCAL_BYPASS);
    } else if (config->mode == ASTERISKD_MODE_BPF2SOCKS) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_BPF);
        if (config->hotspot_interface_prefix_count != 0U) {
            categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_TC) |
                ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_HOTSPOT);
        }
    }
    if (config->matcher.enabled) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_BPF);
    }
    if (config->hotspot_interface_prefix_count != 0U) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_HOTSPOT);
    }
    if (config->enable_local_dns) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_DNS);
    }
    if (config->enable_fake_dns) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_FAKE_DNS);
    }
    if (config->disable_system_ipv6) {
        categories |= ASTERISKD_RULE_CATEGORY_BIT(ASTERISKD_RULE_CATEGORY_IPV6_GUARD);
    }
    return categories;
}

void asteriskd_supervisor_reconcile_error(
    char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

static size_t system_owned_hook_arguments(
    const struct asteriskd_owned_hook *hook,
    const char **arguments,
    size_t capacity) {
    if (hook == NULL || arguments == NULL) return 0U;
    if (hook->dns_destination_protocol != ASTERISKD_DNS_NONE) {
        if (hook->dns_destination_protocol != ASTERISKD_DNS_TCP && hook->dns_destination_protocol != ASTERISKD_DNS_UDP) return 0U;
        if (capacity < 6U) return 0U;
        arguments[0] = "-p";
        arguments[1] = hook->dns_destination_protocol == ASTERISKD_DNS_TCP ? "tcp" : "udp";
        arguments[2] = "--dport";
        arguments[3] = "53";
        arguments[4] = "-j";
        arguments[5] = hook->target;
        return 6U;
    }
    if (capacity < 2U) return 0U;
    arguments[0] = "-j";
    arguments[1] = hook->target;
    return 2U;
}

static const struct asteriskd_owned_chain *system_owned_hook_target_chain(
    const struct asteriskd_owned_hook *hook) {
    const struct asteriskd_owned_resource_catalog *catalog =
        asteriskd_owned_resource_catalog();

    if (hook == NULL) return NULL;
    for (size_t index = 0U; index < catalog->chain_count; ++index) {
        const struct asteriskd_owned_chain *candidate = &catalog->chains[index];
        if (candidate->family == hook->family && candidate->table == hook->table &&
            strcmp(candidate->name, hook->target) == 0) return candidate;
    }
    return NULL;
}

static bool system_owned_hook_rule_probe_required(
    const struct asteriskd_owned_hook *hook, bool target_chain_present) {
    return system_owned_hook_target_chain(hook) == NULL || target_chain_present;
}

static int system_owned_chain_presence(
    struct asteriskd_system_supervisor *,
    const struct asteriskd_owned_chain *, bool *);

/*
 * Owned-resource reconciliation reads each table once and answers every
 * presence probe from that listing. The first probe of a family reads all of
 * its unlisted tables from one iptables-save run. A mutation invalidates the
 * table, which is listed again on its next probe. Without a listing, probes
 * use the per-object commands as before.
 */
static const struct system_rule_view *system_owned_view(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table) {
    if (!system->owned_snapshot_enabled) return NULL;
    struct system_rule_view *view = &system->owned_xtables[family][table];
    if (!system->owned_xtables_valid[family][table]) {
        bool wanted[ASTERISKD_IP_TABLE_COUNT];
        bool filled[ASTERISKD_IP_TABLE_COUNT];
        for (size_t other = 0U; other < ASTERISKD_IP_TABLE_COUNT; ++other) {
            wanted[other] = !system->owned_xtables_valid[family][other];
        }
        asteriskd_supervisor_rule_views_capture_family(
            system, family, wanted, system->owned_xtables[family], filled);
        for (size_t other = 0U; other < ASTERISKD_IP_TABLE_COUNT; ++other) {
            if (filled[other]) system->owned_xtables_valid[family][other] = true;
        }
    }
    if (!system->owned_xtables_valid[family][table]) {
        if (asteriskd_supervisor_rule_view_capture_table(system, family, table, view) != 0) {
            return NULL;
        }
        system->owned_xtables_valid[family][table] = true;
    }
    return view;
}

static void system_owned_view_invalidate(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, enum asteriskd_ip_table table) {
    system->owned_xtables_valid[family][table] = false;
}

static void system_owned_snapshot_release(struct asteriskd_system_supervisor *system) {
    for (size_t family = 0U; family < ASTERISKD_IP_FAMILY_COUNT; ++family) {
        for (size_t table = 0U; table < ASTERISKD_IP_TABLE_COUNT; ++table) {
            asteriskd_supervisor_rule_view_destroy(&system->owned_xtables[family][table]);
            system->owned_xtables_valid[family][table] = false;
        }
    }
    system->owned_snapshot_enabled = false;
}

static bool system_listing_token_follows(const char *line, size_t length,
    const char *needle) {
    size_t needle_length = strlen(needle);
    for (size_t offset = 0U; offset + needle_length <= length; ++offset) {
        if (memcmp(line + offset, needle, needle_length) == 0 &&
            (offset + needle_length == length || line[offset + needle_length] == ' ')) {
            return true;
        }
    }
    return false;
}

/*
 * Counts listing lines that are this hook in "-S" form (exact) and lines that
 * reach the same verdict in the same builtin chain (loose). Equal counts
 * prove the listing has no differently spelled variant of the hook.
 */
static int system_owned_hook_listing_counts(const struct system_rule_view *view,
    const struct asteriskd_owned_hook *hook, size_t *exact, size_t *loose) {
    const char *arguments[10U];
    size_t count = 0U;
    const char *protocol = hook->dns_destination_protocol == ASTERISKD_DNS_TCP ? "tcp" : "udp";
    bool dns = hook->dns_destination_protocol != ASTERISKD_DNS_NONE;
    if (dns) {
        arguments[count++] = "-p";
        arguments[count++] = protocol;
        arguments[count++] = "-m";
        arguments[count++] = protocol;
        arguments[count++] = "--dport";
        arguments[count++] = "53";
    }
    arguments[count++] = "-j";
    arguments[count++] = hook->target;
    if (strcmp(hook->target, "REJECT") == 0) {
        arguments[count++] = "--reject-with";
        arguments[count++] = hook->family == ASTERISKD_IP_FAMILY_IPV6
            ? "icmp6-port-unreachable" : "icmp-port-unreachable";
    }
    size_t position = 0U;
    if (view->length == 0U || asteriskd_xtables_rule_output_locate(view->bytes, view->length,
            hook->builtin_chain, arguments, count, exact, &position) != 0) return -1;
    char prefix[ASTERISKD_MAX_CHAIN_NAME + 8U];
    char verdict[ASTERISKD_MAX_CHAIN_NAME + 8U];
    if (snprintf(prefix, sizeof(prefix), "-A %s ", hook->builtin_chain) >= (int)sizeof(prefix) ||
        snprintf(verdict, sizeof(verdict), " -j %s", hook->target) >= (int)sizeof(verdict)) {
        return -1;
    }
    size_t prefix_length = strlen(prefix);
    *loose = 0U;
    size_t offset = 0U;
    while (offset < view->length) {
        const char *line = view->bytes + offset;
        const char *newline = memchr(line, '\n', view->length - offset);
        size_t length = newline == NULL ? view->length - offset : (size_t)(newline - line);
        offset += length + 1U;
        if (length < prefix_length || memcmp(line, prefix, prefix_length) != 0) continue;
        if (!system_listing_token_follows(line, length, verdict)) continue;
        if (dns && !system_listing_token_follows(line, length, " --dport 53")) continue;
        ++*loose;
    }
    return 0;
}

static int system_reconcile_hook(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_owned_hook *hook,
    bool remove) {
    const char *arguments[6U];
    size_t argument_count = system_owned_hook_arguments(
        hook, arguments, sizeof(arguments) / sizeof(arguments[0]));
    size_t attempt;

    if (argument_count == 0U) return -1;
    const struct asteriskd_owned_chain *target_chain =
        system_owned_hook_target_chain(hook);
    if (target_chain != NULL) {
        bool target_present = false;
        if (system_owned_chain_presence(system, target_chain, &target_present) != 0) return -1;
        if (!system_owned_hook_rule_probe_required(hook, target_present)) return 0;
    }
    const struct system_rule_view *view = system_owned_view(system, hook->family, hook->table);
    size_t exact = 0U;
    size_t loose = 0U;
    if (view != NULL &&
        system_owned_hook_listing_counts(view, hook, &exact, &loose) == 0 && exact == loose) {
        if (exact == 0U) return 0;
        if (!remove) return -1;
    }
    // A present or ambiguous hook is checked and removed by the kernel's own matching.
    for (attempt = 0U; attempt < 64U; ++attempt) {
        int exit_status = -1;
        if (asteriskd_supervisor_xtables(system, hook->family, hook->table,
                "-C", hook->builtin_chain, arguments, argument_count,
                &exit_status) != 0) return -1;
        if (exit_status == 1) return 0;
        if (exit_status != 0 || !remove) return -1;
        system_owned_view_invalidate(system, hook->family, hook->table);
        if (asteriskd_supervisor_xtables(system, hook->family, hook->table,
                "-D", hook->builtin_chain, arguments, argument_count,
                &exit_status) != 0 || exit_status != 0) return -1;
    }
    return -1;
}

static int system_reconcile_hooks(
    struct asteriskd_system_supervisor *system, bool remove) {
    const struct asteriskd_owned_resource_catalog *catalog =
        asteriskd_owned_resource_catalog();
    size_t index;
    int result = 0;

    for (index = 0U; index < catalog->hook_count; ++index) {
        if (system_reconcile_hook(system, &catalog->hooks[index], remove) != 0) {
            result = -1;
        }
    }
    return result;
}

static int system_owned_chain_presence(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_owned_chain *chain,
    bool *present) {
    int exit_status = -1;

    if (present == NULL) return -1;
    const struct system_rule_view *view = system_owned_view(system, chain->family, chain->table);
    if (view != NULL) {
        size_t declarations = 0U;
        size_t rules = 0U;
        if (view->length != 0U && asteriskd_xtables_private_chain_counts(
                view->bytes, view->length, chain->name, &declarations, &rules) == 0) {
            *present = declarations != 0U || rules != 0U;
            return 0;
        }
    }
    if (asteriskd_supervisor_xtables(system, chain->family, chain->table,
            "-S", chain->name, NULL, 0U, &exit_status) != 0 ||
        (exit_status != 0 && exit_status != 1)) return -1;
    *present = exit_status == 0;
    return 0;
}

static int system_reconcile_private_chains(
    struct asteriskd_system_supervisor *system, bool remove) {
    const struct asteriskd_owned_resource_catalog *catalog =
        asteriskd_owned_resource_catalog();
    size_t index;
    int result = 0;

    for (index = 0U; index < catalog->chain_count; ++index) {
        const struct asteriskd_owned_chain *chain = &catalog->chains[index];
        bool present = false;
        int exit_status = -1;

        if (system_owned_chain_presence(system, chain, &present) != 0) {
            result = -1;
            continue;
        }
        if (!present) continue;
        if (!remove) {
            result = -1;
            continue;
        }
        system_owned_view_invalidate(system, chain->family, chain->table);
        if (asteriskd_supervisor_xtables(system, chain->family, chain->table,
                "-F", chain->name, NULL, 0U, &exit_status) != 0 ||
            exit_status != 0) result = -1;
    }
    if (!remove) return result;

    for (index = catalog->chain_count; index > 0U; --index) {
        const struct asteriskd_owned_chain *chain = &catalog->chains[index - 1U];
        bool present = false;
        int exit_status = -1;

        if (system_owned_chain_presence(system, chain, &present) != 0) {
            result = -1;
            continue;
        }
        if (!present) continue;
        system_owned_view_invalidate(system, chain->family, chain->table);
        if (asteriskd_supervisor_xtables(system, chain->family, chain->table,
                "-X", chain->name, NULL, 0U, &exit_status) != 0 ||
            exit_status != 0) result = -1;
    }
    return result;
}

static int system_owned_policy_rule_count(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_owned_policy_rule *rule,
    size_t *count) {
    const char *arguments[] = {"rule", "show"};
    int exit_status = -1;

    if (count == NULL ||
        asteriskd_supervisor_ip_command(system, rule->family, arguments,
            sizeof(arguments) / sizeof(arguments[0]), true, &exit_status) != 0 ||
        exit_status != 0 || system->action_stdout_overflow) return -1;
    return asteriskd_owned_policy_rule_output_count(
        system->action_stdout, system->action_stdout_length, rule, count);
}

static int system_reconcile_policy_rule(
    struct asteriskd_system_supervisor *system,
    const struct asteriskd_owned_policy_rule *rule,
    bool remove) {
    char table[16U];
    char priority[16U];
    char mark[32U];
    const char *normal[] = {
        "rule", "del", "priority", priority,
        "fwmark", mark, "table", table,
    };
    const char *inverted[] = {
        "rule", "del", "priority", priority,
        "not", "from", "all", "fwmark", mark, "table", table,
    };
    const char *const *arguments = rule->invert_from_all ? inverted : normal;
    size_t argument_count = rule->invert_from_all
        ? sizeof(inverted) / sizeof(inverted[0])
        : sizeof(normal) / sizeof(normal[0]);
    size_t attempt;

    if (snprintf(table, sizeof(table), "%" PRIu32, rule->table) <= 0 ||
        snprintf(priority, sizeof(priority), "%" PRIu32, rule->priority) <= 0 ||
        snprintf(mark, sizeof(mark), "0x%08" PRIx32 "/0x%08" PRIx32,
            rule->mark, rule->mark_mask) <= 0) return -1;

    for (attempt = 0U; attempt < 64U; ++attempt) {
        size_t count = 0U;
        int exit_status = -1;

        if (system_owned_policy_rule_count(system, rule, &count) != 0) return -1;
        if (count == 0U) return 0;
        if (!remove ||
            asteriskd_supervisor_ip_command(system, rule->family, arguments,
                argument_count, false, &exit_status) != 0 ||
            exit_status != 0) return -1;
    }
    return -1;
}

struct system_owned_route_table {
    enum asteriskd_ip_family family;
    uint32_t table;
};

static const struct system_owned_route_table system_owned_route_tables[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TUN_TABLE},
};

static int system_reconcile_route_table(
    struct asteriskd_system_supervisor *system,
    const struct system_owned_route_table *owned,
    bool remove) {
    char table[16U];
    const char *show[] = {"route", "show", "table", table};
    const char *flush[] = {"route", "flush", "table", table};
    int exit_status = -1;

    if (snprintf(table, sizeof(table), "%" PRIu32, owned->table) <= 0 ||
        asteriskd_supervisor_ip_command(system, owned->family, show,
            sizeof(show) / sizeof(show[0]), true, &exit_status) != 0 ||
        exit_status != 0 || system->action_stdout_overflow) return -1;
    if (system->action_stdout_length == 0U) return 0;
    if (!remove ||
        asteriskd_supervisor_ip_command(system, owned->family, flush,
            sizeof(flush) / sizeof(flush[0]), false, &exit_status) != 0 ||
        exit_status != 0) return -1;
    return 0;
}

static void system_owned_token_effect(struct asteriskd_route_effect *effect) {
    const struct asteriskd_owned_token_route *token =
        &asteriskd_owned_resource_catalog()->token_route;

    memset(effect, 0, sizeof(*effect));
    effect->kind = ASTERISKD_ROUTE_EFFECT_ROUTE;
    effect->family = token->family;
    effect->table = token->table;
    effect->local_route = true;
    effect->route_id = ASTERISKD_ROUTE_TOKEN;
    (void)snprintf(effect->destination, sizeof(effect->destination),
        "%s", token->destination);
    (void)snprintf(effect->interface_name, sizeof(effect->interface_name),
        "%s", token->interface_name);
}

static int system_reconcile_token_route(
    struct asteriskd_system_supervisor *system, bool remove) {
    struct asteriskd_route_effect effect;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_ABSENT;
    size_t attempt;

    system_owned_token_effect(&effect);
    for (attempt = 0U; attempt < 64U; ++attempt) {
        if (asteriskd_supervisor_classify_route_effect(system, &effect, &state) != 0 ||
            state == ASTERISKD_RULES_SLOT_FOREIGN) return -1;
        if (state == ASTERISKD_RULES_SLOT_ABSENT) return 0;
        if (!remove || asteriskd_supervisor_remove_route_effect(system, &effect) != 0) return -1;
    }
    return -1;
}

static int system_reconcile_policy_routing(
    struct asteriskd_system_supervisor *system, bool remove) {
    const struct asteriskd_owned_resource_catalog *catalog =
        asteriskd_owned_resource_catalog();
    size_t index;
    int result = 0;

    for (index = 0U; index < catalog->policy_rule_count; ++index) {
        if (system_reconcile_policy_rule(
                system, &catalog->policy_rules[index], remove) != 0) result = -1;
    }
    for (index = 0U;
         index < sizeof(system_owned_route_tables) /
             sizeof(system_owned_route_tables[0]);
         ++index) {
        if (system_reconcile_route_table(
                system, &system_owned_route_tables[index], remove) != 0) result = -1;
    }
    if (system_reconcile_token_route(system, remove) != 0) result = -1;
    return result;
}

struct system_owned_bpf_pin {
    int directory_fd;
    int object_fd;
    const char *leaf;
    const char *program_name;
    uint32_t program_type;
    uint32_t map_key_size;
    uint32_t object_id;
    struct stat status;
};

static bool system_bpf_same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode;
}

static int system_bpf_catalog_open(struct system_owned_bpf_pin *pin) {
    struct stat current;
    char path[ASTERISKD_MAX_PATH];
    union bpf_attr attr;
    int written;

    if (pin->directory_fd < 0) return 0;
    if (fstatat(pin->directory_fd, pin->leaf, &pin->status,
            AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISREG(pin->status.st_mode)) { errno = ESTALE; return -1; }
    written = snprintf(path, sizeof(path), "/proc/self/fd/%d/%s",
        pin->directory_fd, pin->leaf);
    if (written <= 0 || (size_t)written >= sizeof(path)) return -1;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uintptr_t)path;
    pin->object_fd = asterisk_cgroup_sys(BPF_OBJ_GET, &attr);
    if (pin->object_fd < 0) return -1;
    if (pin->map_key_size != 0U) {
        struct bpf_map_info info;
        memset(&info, 0, sizeof(info));
        memset(&attr, 0, sizeof(attr));
        attr.info.bpf_fd = (uint32_t)pin->object_fd;
        attr.info.info_len = sizeof(info);
        attr.info.info = (uintptr_t)&info;
        if (asterisk_cgroup_sys(BPF_OBJ_GET_INFO_BY_FD, &attr) != 0 ||
            info.id == 0U || info.type != BPF_MAP_TYPE_LPM_TRIE ||
            info.key_size != pin->map_key_size || info.value_size != 1U ||
            info.max_entries != ASTERISKD_BPF_LOCAL_MAP_MAX_ENTRIES ||
            info.map_flags != BPF_F_NO_PREALLOC) return -1;
        pin->object_id = info.id;
    } else {
        struct bpf_prog_info info;
        if (asterisk_cgroup_info(pin->object_fd, &info) != 0 ||
            info.id == 0U || info.type != pin->program_type ||
            memcmp(info.name, pin->program_name,
                strlen(pin->program_name) + 1U) != 0) return -1;
        if (pin->program_type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR) {
            bool tag_present = false;
            for (size_t i = 0U; i < sizeof(info.tag); ++i) {
                if (info.tag[i] != 0U) tag_present = true;
            }
            if (!tag_present) return -1;
        }
        pin->object_id = info.id;
    }
    if (fstatat(pin->directory_fd, pin->leaf, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        !system_bpf_same_inode(&pin->status, &current)) return -1;
    return 0;
}

/* Only the fixed catalog is inspected. Directory FDs prevent a substituted
 * bpf2socks symlink from redirecting cleanup. Unknown children are never read.
 * The final ID/inode checks narrow replacement races; unlink and cgroup QUERY
 * -> DETACH still cannot be made atomic against an unrelated privileged writer. */
static int system_reconcile_owned_bpf_catalog(const char *path, bool remove) {
    enum { cgroup_count = sizeof(asterisk_cgroup_programs) /
        sizeof(asterisk_cgroup_programs[0]), pin_count = ASTERISKD_PIN_COUNT + cgroup_count };
    struct system_owned_bpf_pin pins[pin_count];
    struct asteriskd_matcher_pin_plan matcher;
    struct asteriskd_b2s_pin_plan b2s;
    struct asteriskd_config config;
    struct stat root_status, b2s_status, current;
    int root_fd = -1, b2s_fd = -1, result = -1;
    char b2s_path[64U];

    memset(pins, 0, sizeof(pins));
    for (size_t i = 0U; i < pin_count; ++i) pins[i].object_fd = -1;
    root_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(root_fd, &root_status) != 0) goto done;
    b2s_fd = openat(root_fd, "bpf2socks",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (b2s_fd < 0 && errno != ENOENT) goto done;
    if (b2s_fd >= 0 && fstat(b2s_fd, &b2s_status) != 0) goto done;
    memset(&config, 0, sizeof(config));
    config.enable_ipv6 = true;
    config.matcher.enabled = true;
    config.dns_enhancement = true;
    config.mode = ASTERISKD_MODE_BPF2SOCKS;
    config.helper.type = ASTERISKD_HELPER_BPF2SOCKS;
    if (asteriskd_matcher_pin_plan_build(&config, &matcher) != 0 ||
        asteriskd_b2s_pin_plan_build(&config, &b2s) != 0) goto done;
    for (size_t i = 0U; i < ASTERISKD_PIN_COUNT; ++i) {
        const char *owned_path = asteriskd_owned_pin_path((enum asteriskd_pin_id)i);
        const char *leaf = owned_path == NULL ? NULL : strrchr(owned_path, '/');
        if (leaf == NULL || leaf[1] == '\0') goto done;
        pins[i].leaf = leaf + 1;
        pins[i].directory_fd = i < matcher.pin_count ? root_fd : b2s_fd;
        if (i < matcher.pin_count) {
            pins[i].program_name = matcher.pins[i].program_name;
            pins[i].program_type = BPF_PROG_TYPE_SOCKET_FILTER;
        } else {
            const struct asteriskd_b2s_pin_expectation *expected =
                &b2s.pins[i - matcher.pin_count];
            pins[i].program_name = expected->program_name;
            pins[i].program_type = BPF_PROG_TYPE_SCHED_CLS;
            if (!expected->program) pins[i].map_key_size =
                i == ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4 ? 8U : 20U;
        }
    }
    for (size_t i = 0U; i < cgroup_count; ++i) {
        struct system_owned_bpf_pin *pin = &pins[ASTERISKD_PIN_COUNT + i];
        pin->directory_fd = b2s_fd;
        pin->leaf = asterisk_cgroup_programs[i].pin;
        pin->program_name = asterisk_cgroup_programs[i].name;
        pin->program_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR;
    }
    for (size_t i = 0U; i < pin_count; ++i) {
        if (!remove) {
            if (pins[i].directory_fd < 0) continue;
            if (fstatat(pins[i].directory_fd, pins[i].leaf, &current,
                    AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) goto done;
        } else if (system_bpf_catalog_open(&pins[i]) != 0) goto done;
    }
    if (!remove) { result = 0; goto done; }
    if (b2s_fd >= 0) {
        if (snprintf(b2s_path, sizeof(b2s_path), "/proc/self/fd/%d", b2s_fd) <= 0 ||
            asterisk_cgroup_detach_pins("/sys/fs/cgroup", b2s_path) != 0) goto done;
    }
    for (size_t i = 0U; i < pin_count; ++i) {
        if (pins[i].object_fd < 0) continue;
        struct system_owned_bpf_pin check = pins[i];
        check.object_fd = -1;
        int checked = system_bpf_catalog_open(&check);
        if (check.object_fd >= 0 && close(check.object_fd) != 0) checked = -1;
        if (checked != 0 || check.object_fd < 0 ||
            check.object_id != pins[i].object_id ||
            !system_bpf_same_inode(&check.status, &pins[i].status)) goto done;
        if (unlinkat(pins[i].directory_fd, pins[i].leaf, 0) != 0) goto done;
    }
    if (b2s_fd >= 0) {
        if (fstatat(root_fd, "bpf2socks", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
            !system_bpf_same_inode(&current, &b2s_status)) goto done;
        if (unlinkat(root_fd, "bpf2socks", AT_REMOVEDIR) != 0 &&
            errno != ENOTEMPTY && errno != EEXIST) goto done;
    }
    if (lstat(path, &current) != 0 || !system_bpf_same_inode(&current, &root_status)) goto done;
    if (rmdir(path) != 0 && errno != ENOTEMPTY && errno != EEXIST) goto done;
    result = 0;
done:
    for (size_t i = 0U; i < pin_count; ++i) {
        if (pins[i].object_fd >= 0 && close(pins[i].object_fd) != 0) result = -1;
    }
    if (b2s_fd >= 0 && close(b2s_fd) != 0) result = -1;
    if (close(root_fd) != 0) result = -1;
    return result;
}

static int system_remove_owned_bpf_tree(const char *path) {
    return system_reconcile_owned_bpf_catalog(path, true);
}

static int system_reconcile_bpf_pins(
    struct asteriskd_system_supervisor *system, bool remove) {
    const char *root = asteriskd_owned_resource_catalog()->bpf_root;
    (void)system;
    return remove ? system_remove_owned_bpf_tree(root)
        : system_reconcile_owned_bpf_catalog(root, false);
}

static int system_prepare_owned_tc_identity(
    struct asteriskd_system_supervisor *system) {
    struct asteriskd_config config;
    char error[256U];

    memset(&config, 0, sizeof(config));
    config.mode = ASTERISKD_MODE_BPF2SOCKS;
    config.helper.type = ASTERISKD_HELPER_BPF2SOCKS;
    config.enable_ipv6 = true;
    memset(&system->b2s_pin_plan, 0, sizeof(system->b2s_pin_plan));
    memset(&system->b2s_verification, 0, sizeof(system->b2s_verification));
    if (asteriskd_b2s_pin_plan_build(
            &config, &system->b2s_pin_plan) != 0 ||
        asteriskd_b2s_verify_residue(
            &config, &system->b2s_pin_plan,
            asteriskd_system_bpf_program_backend(),
            asteriskd_system_bpf_pin_ownership_backend(),
            &system->b2s_verification, error, sizeof(error)) != 0) return -1;
    system->b2s_plan_ready = true;
    system->b2s_verified = true;
    return 0;
}

static int system_reconcile_tc_filter(
    struct asteriskd_system_supervisor *system,
    const char *interface_name,
    uint32_t interface_index,
    enum asteriskd_tc_direction direction,
    enum asteriskd_program_id program_id,
    bool remove) {
    struct asteriskd_tc_filter_resource filter;
    enum asteriskd_rules_slot_state state = ASTERISKD_RULES_SLOT_FOREIGN;
    const char *direction_name;
    const char *arguments[10U];
    int exit_status = -1;

    memset(&filter, 0, sizeof(filter));
    filter.interface_index = interface_index;
    filter.direction = direction;
    filter.program_id = program_id;
    filter.filter_id = direction == ASTERISKD_TC_DIRECTION_INGRESS
        ? ASTERISKD_FILTER_HOTSPOT_INGRESS
        : ASTERISKD_FILTER_HOTSPOT_EGRESS;
    if (snprintf(filter.interface_name, sizeof(filter.interface_name),
            "%s", interface_name) <= 0 ||
        asteriskd_supervisor_expected_tc_netlink_probe(system, &filter, &state) != 0) return -1;
    if (state == ASTERISKD_RULES_SLOT_ABSENT ||
        state == ASTERISKD_RULES_SLOT_FOREIGN) return 0;
    if (!remove) return -1;

    direction_name = asteriskd_supervisor_tc_direction(direction);
    if (direction_name == NULL) return -1;
    arguments[0] = "filter";
    arguments[1] = "del";
    arguments[2] = "dev";
    arguments[3] = interface_name;
    arguments[4] = direction_name;
    arguments[5] = "pref";
    arguments[6] = "1";
    arguments[7] = "handle";
    arguments[8] = "1";
    arguments[9] = "bpf";
    if (asteriskd_supervisor_tc_command(system, arguments,
            sizeof(arguments) / sizeof(arguments[0]),
            false, &exit_status) != 0 || exit_status != 0 ||
        asteriskd_supervisor_expected_tc_netlink_probe(system, &filter, &state) != 0 ||
        state != ASTERISKD_RULES_SLOT_ABSENT) return -1;
    return 0;
}

static int system_reconcile_tc_filters(
    struct asteriskd_system_supervisor *system, bool remove) {
    DIR *directory = opendir("/sys/class/net");
    struct dirent *entry;
    int result = udp6_recovery_reconcile(remove);

    if (directory == NULL) return -1;
    while ((entry = readdir(directory)) != NULL) {
        uint32_t interface_index;
        size_t length = strnlen(
            entry->d_name, ASTERISKD_MAX_INTERFACE_NAME);

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME) {
            result = -1;
            continue;
        }
        interface_index = if_nametoindex(entry->d_name);
        if (interface_index == 0U) {
            result = -1;
            continue;
        }
        if (system_reconcile_tc_filter(system, entry->d_name, interface_index,
                ASTERISKD_TC_DIRECTION_INGRESS,
                ASTERISKD_PROGRAM_BPF2SOCKS_INGRESS, remove) != 0) result = -1;
        if (system_reconcile_tc_filter(system, entry->d_name, interface_index,
                ASTERISKD_TC_DIRECTION_EGRESS,
                ASTERISKD_PROGRAM_BPF2SOCKS_EGRESS, remove) != 0) {
            result = -1;
        }
    }
    if (closedir(directory) != 0) result = -1;
    return result;
}

/*
 * Detaches owned TC filters before the bpf2socks helper stops. The traffic
 * hooks were already removed from the in-memory rule plan, so only TC state
 * is probed here instead of the whole quiesce catalog.
 */
int asteriskd_supervisor_reconcile_remove_tc_filters(
    struct asteriskd_system_supervisor *system, char *error, size_t error_size) {
    if (system == NULL) return -1;
    int identity = system_prepare_owned_tc_identity(system);
    int filters = system_reconcile_tc_filters(system, true);
    if (identity == 0 && filters == 0) return 0;
    char detail[128U];
    (void)snprintf(detail, sizeof(detail),
        "tc detach incomplete: bpf-identity=%d tc-filters=%d", identity, filters);
    asteriskd_supervisor_reconcile_error(error, error_size, detail);
    return -1;
}

int asteriskd_supervisor_reconcile_remove_phase(
    void *opaque,
    enum asteriskd_reconcile_phase phase,
    char *error,
    size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;
    int result = -1;

    if (system == NULL) return -1;
    switch (phase) {
        case ASTERISKD_RECONCILE_QUIESCE: {
            int hooks = system_reconcile_hooks(system, true);
            int identity = system_prepare_owned_tc_identity(system);
            int filters = system_reconcile_tc_filters(system, true);
            if (hooks != 0 || identity != 0 || filters != 0) {
                char detail[128U];
                (void)snprintf(detail, sizeof(detail),
                    "quiesce incomplete: hooks=%d bpf-identity=%d tc-filters=%d",
                    hooks, identity, filters);
                asteriskd_supervisor_reconcile_error(error, error_size, detail);
                return -1;
            }
            result = 0;
            break;
        }
        case ASTERISKD_RECONCILE_PRIVATE_CHAINS:
            result = system_reconcile_private_chains(system, true);
            break;
        case ASTERISKD_RECONCILE_POLICY_ROUTING:
            result = system_reconcile_policy_routing(system, true);
            break;
        case ASTERISKD_RECONCILE_BPF_PINS:
            result = system_reconcile_bpf_pins(system, true);
            break;
        case ASTERISKD_RECONCILE_PHASE_COUNT:
            result = -1;
            break;
    }
    if (result != 0) {
        static const char *const names[] = {
            "quiesce", "private-chains", "policy-routing", "bpf-pins",
        };
        char message[128U];
        int written = snprintf(message, sizeof(message),
            "owned resource reconcile failed: phase=%s",
            phase >= ASTERISKD_RECONCILE_QUIESCE &&
                    phase < ASTERISKD_RECONCILE_PHASE_COUNT
                ? names[phase] : "invalid");
        asteriskd_supervisor_reconcile_error(error, error_size,
            written > 0 && (size_t)written < sizeof(message)
                ? message : "owned resource reconcile failed");
    }
    return result;
}

static int system_reconcile_verify_absent(
    void *opaque, char *error, size_t error_size) {
    struct asteriskd_system_supervisor *system = opaque;

    if (system == NULL) {
        asteriskd_supervisor_reconcile_error(error, error_size, "owned resource verification failed");
        return -1;
    }
    /* Probe every class so the warning names all resources still present. */
    int hooks = system_reconcile_hooks(system, false);
    int filters = system_reconcile_tc_filters(system, false);
    int chains = system_reconcile_private_chains(system, false);
    int routing = system_reconcile_policy_routing(system, false);
    int pins = system_reconcile_bpf_pins(system, false);
    if (hooks != 0 || filters != 0 || chains != 0 || routing != 0 || pins != 0) {
        char detail[160U];
        (void)snprintf(detail, sizeof(detail),
            "owned resource verification failed: hooks=%d tc-filters=%d "
            "private-chains=%d policy-routing=%d bpf-pins=%d",
            hooks, filters, chains, routing, pins);
        asteriskd_supervisor_reconcile_error(error, error_size, detail);
        return -1;
    }
    return 0;
}

static void system_reconcile_warn(void *opaque,
    enum asteriskd_reconcile_phase phase, const char *detail) {
    struct asteriskd_system_supervisor *system = opaque;
    static const char *const names[] = {
        "quiesce", "private-chains", "policy-routing", "bpf-pins", "verification",
    };
    char message[384U];
    (void)snprintf(message, sizeof(message),
        "owned resource cleanup incomplete; continuing: phase=%s detail=%.256s",
        phase >= ASTERISKD_RECONCILE_QUIESCE && phase <= ASTERISKD_RECONCILE_PHASE_COUNT
            ? names[phase] : "invalid", detail);
    (void)asteriskd_log_line(&system->logger, ASTERISKD_LOG_LEVEL_WARNING,
        ASTERISKD_COMPONENT_RULES, ASTERISKD_LOG_EVENT_DIAGNOSTIC, message);
}

static struct asteriskd_reconcile_backend system_reconcile_backend(
    struct asteriskd_system_supervisor *system) {
    const struct asteriskd_reconcile_backend backend = {
        .context = system,
        .remove_phase = asteriskd_supervisor_reconcile_remove_phase,
        .verify_absent = system_reconcile_verify_absent,
        .warn = system_reconcile_warn,
    };
    return backend;
}

static int system_reconcile_owned_resources_after_listener(
    struct asteriskd_system_supervisor *system,
    enum asteriskd_control_listener_result listener_result,
    char *error,
    size_t error_size) {
    struct asteriskd_reconcile_backend backend =
        system_reconcile_backend(system);
    struct asteriskd_reconcile_report report;

    asteriskd_supervisor_rule_batch_destroy(&system->rule_commands);
    asteriskd_supervisor_rule_snapshot_destroy(&system->rule_snapshot);
    system->owned_cleanup_in_progress = true;
    system->owned_snapshot_enabled = true;
    int result = asteriskd_reconcile_after_listener(
        listener_result, &backend, &report, error, error_size);
    system_owned_snapshot_release(system);
    system->owned_cleanup_in_progress = false;
    return result;
}

int asteriskd_supervisor_reconcile_owned_resources(
    struct asteriskd_system_supervisor *system,
    char *error,
    size_t error_size) {
    return system_reconcile_owned_resources_after_listener(
        system, ASTERISKD_CONTROL_LISTENER_OK, error, error_size);
}

#endif

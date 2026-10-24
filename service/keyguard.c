// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "service/keyguard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __ANDROID__
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/system_properties.h>

// Load every symbol lazily: the daemon must still run on pre-29 Android where
// libbinder_ndk does not exist. Platform polling APIs are not public NDK APIs.
// clang-format off
#define BINDER_APIS(X) \
    X(AIBinder_Class_define) \
    X(AIBinder_associateClass) \
    X(AIBinder_new) \
    X(AIBinder_getUserData) \
    X(AIBinder_decStrong) \
    X(AIBinder_prepareTransaction) \
    X(AIBinder_transact) \
    X(AParcel_writeStrongBinder) \
    X(AParcel_readStatusHeader) \
    X(AParcel_readBool) \
    X(AParcel_delete) \
    X(AStatus_isOk) \
    X(AStatus_delete) \
    X(AIBinder_DeathRecipient_new) \
    X(AIBinder_DeathRecipient_delete) \
    X(AIBinder_linkToDeath) \
    X(AIBinder_unlinkToDeath)
// clang-format on
static AIBinder_Class *(*api_AIBinder_Class_define)(
    const char *, AIBinder_Class_onCreate, AIBinder_Class_onDestroy, AIBinder_Class_onTransact);
static bool (*api_AIBinder_associateClass)(AIBinder *, const AIBinder_Class *);
static AIBinder *(*api_AIBinder_new)(const AIBinder_Class *, void *);
static void *(*api_AIBinder_getUserData)(AIBinder *);
static void (*api_AIBinder_decStrong)(AIBinder *);
static binder_status_t (*api_AIBinder_prepareTransaction)(AIBinder *, AParcel **);
static binder_status_t (*api_AIBinder_transact)(
    AIBinder *, transaction_code_t, AParcel **, AParcel **, binder_flags_t);
static binder_status_t (*api_AParcel_writeStrongBinder)(AParcel *, AIBinder *);
static binder_status_t (*api_AParcel_readStatusHeader)(const AParcel *, AStatus **);
static binder_status_t (*api_AParcel_readBool)(const AParcel *, bool *);
static void (*api_AParcel_delete)(AParcel *);
static bool (*api_AStatus_isOk)(const AStatus *);
static void (*api_AStatus_delete)(AStatus *);
static AIBinder_DeathRecipient *(*api_AIBinder_DeathRecipient_new)(void (*)(void *));
static void (*api_AIBinder_DeathRecipient_delete)(AIBinder_DeathRecipient *);
static binder_status_t (*api_AIBinder_linkToDeath)(AIBinder *, AIBinder_DeathRecipient *, void *);
static binder_status_t (*api_AIBinder_unlinkToDeath)(AIBinder *, AIBinder_DeathRecipient *, void *);
static AIBinder *(*api_check_service)(const char *);
static bool (*api_set_max_threads)(uint32_t);
static binder_status_t (*api_setup_polling)(int *);
static binder_status_t (*api_handle_polled_commands)(void);
static void *binder_library;
static AIBinder_Class *window_class, *listener_class;

struct asteriskd_keyguard_monitor {
    AIBinder *window, *listener;
    AIBinder_DeathRecipient *death;
    int ids[3], fd;
    bool registered, priming, dead;
    asteriskd_keyguard_changed changed;
    void *context;
};
static struct asteriskd_keyguard_monitor *active_monitor;

static void *binder_on_create(void *data) {
    return data;
}
static void binder_on_destroy(void *data) {
    (void)data;
}
static void window_binder_died(void *cookie) {
    if (active_monitor == cookie) active_monitor->dead = true;
}
static binder_status_t listener_on_transact(
    AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out) {
    (void)out;
    if (code != FIRST_CALL_TRANSACTION) return STATUS_UNKNOWN_TRANSACTION;
    bool locked;
    binder_status_t result = api_AParcel_readBool(in, &locked);
    struct asteriskd_keyguard_monitor *monitor = api_AIBinder_getUserData(binder);
    if (result == STATUS_OK && active_monitor == monitor && monitor->registered &&
        !monitor->priming)
        monitor->changed(monitor->context, locked, false);
    return result;
}
static binder_status_t window_on_transact(
    AIBinder *binder, transaction_code_t code, const AParcel *in, AParcel *out) {
    (void)binder;
    (void)code;
    (void)in;
    (void)out;
    return STATUS_UNKNOWN_TRANSACTION;
}
static bool load_binder(void) {
    if (!binder_library) binder_library = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
    if (!binder_library) return false;
#define LOAD(name)                                                                                 \
    api_##name = (__typeof__(api_##name))dlsym(binder_library, #name);                             \
    if (!api_##name) return false;
    BINDER_APIS(LOAD)
#undef LOAD
    api_check_service = (void *)dlsym(binder_library, "AServiceManager_checkService");
    api_set_max_threads =
        (void *)dlsym(binder_library, "ABinderProcess_setThreadPoolMaxThreadCount");
    api_setup_polling = (void *)dlsym(binder_library, "ABinderProcess_setupPolling");
    api_handle_polled_commands =
        (void *)dlsym(binder_library, "ABinderProcess_handlePolledCommands");
    return api_check_service && api_set_max_threads && api_setup_polling &&
        api_handle_polled_commands;
}
static bool window_call(
    struct asteriskd_keyguard_monitor *monitor, int code, bool listener, bool *locked) {
    AParcel *in = NULL, *out = NULL;
    AStatus *status = NULL;
    binder_status_t result = api_AIBinder_prepareTransaction(monitor->window, &in);
    if (result == STATUS_OK && listener)
        result = api_AParcel_writeStrongBinder(in, monitor->listener);
    if (result == STATUS_OK) result = api_AIBinder_transact(monitor->window, code, &in, &out, 0);
    if (result == STATUS_OK) result = api_AParcel_readStatusHeader(out, &status);
    bool ok = result == STATUS_OK && status && api_AStatus_isOk(status);
    if (ok && locked) ok = api_AParcel_readBool(out, locked) == STATUS_OK;
    if (status) api_AStatus_delete(status);
    if (in) api_AParcel_delete(in);
    if (out) api_AParcel_delete(out);
    return ok;
}

int asteriskd_keyguard_open(struct asteriskd_keyguard_monitor **out,
    asteriskd_keyguard_changed on_change, void *context, char *error, size_t size) {
    *out = NULL;
    char sdk[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", sdk);
    if (atoi(sdk) < 33) {
        snprintf(error, size, "lock screen control requires Android 13 or later");
        return -1;
    }
    if (active_monitor || !load_binder()) {
        snprintf(error, size, "native lock screen Binder APIs unavailable");
        return -1;
    }
    struct asteriskd_keyguard_monitor *monitor = calloc(1, sizeof(*monitor));
    if (!monitor) return -1;
    monitor->fd = -1;
    monitor->priming = true;
    monitor->changed = on_change;
    monitor->context = context;
    const char *reason = "system lock screen transaction constants unavailable";
    if (asteriskd_keyguard_resolve_ids(monitor->ids)) goto fail;
    reason = "native lock screen Binder initialization failed";
    if (!api_set_max_threads(0) || !(monitor->window = api_check_service("window"))) goto fail;
    if (!window_class)
        window_class = api_AIBinder_Class_define(
            "android.view.IWindowManager", binder_on_create, binder_on_destroy, window_on_transact);
    if (!listener_class)
        listener_class =
            api_AIBinder_Class_define("com.android.internal.policy.IKeyguardLockedStateListener",
                binder_on_create, binder_on_destroy, listener_on_transact);
    if (!window_class || !listener_class ||
        !api_AIBinder_associateClass(monitor->window, window_class))
        goto fail;
    monitor->listener = api_AIBinder_new(listener_class, monitor);
    monitor->death = api_AIBinder_DeathRecipient_new(window_binder_died);
    if (!monitor->listener || !monitor->death || api_setup_polling(&monitor->fd) != STATUS_OK)
        goto fail;
    active_monitor = monitor;
    if (api_AIBinder_linkToDeath(monitor->window, monitor->death, monitor) != STATUS_OK) goto fail;
    reason = "lock screen listener registration denied or unsupported";
    if (!window_call(monitor, monitor->ids[1], true, NULL)) goto fail;
    monitor->registered = true;
    bool locked;
    // Drain registration-time notifications before establishing the baseline.
    // The synchronous query can itself dispatch Binder callbacks while priming.
    struct pollfd pending = {monitor->fd, POLLIN, 0};
    if ((poll(&pending, 1, 0) > 0 && api_handle_polled_commands() != STATUS_OK) ||
        !window_call(monitor, monitor->ids[0], false, &locked) || monitor->dead)
        goto fail;
    monitor->changed(monitor->context, locked, true);
    monitor->priming = false;
    *out = monitor;
    return 0;
fail:
    snprintf(error, size, "%s", reason);
    asteriskd_keyguard_close(monitor);
    return -1;
}
int asteriskd_keyguard_fd(const struct asteriskd_keyguard_monitor *monitor) {
    return monitor ? monitor->fd : -1;
}
int asteriskd_keyguard_dispatch(struct asteriskd_keyguard_monitor *monitor) {
    if (!monitor || monitor->dead || api_handle_polled_commands() != STATUS_OK || monitor->dead)
        return -1;
    return 0;
}
void asteriskd_keyguard_close(struct asteriskd_keyguard_monitor *monitor) {
    if (!monitor) return;
    if (monitor->registered && !monitor->dead)
        (void)window_call(monitor, monitor->ids[2], true, NULL);
    monitor->registered = false;
    if (active_monitor == monitor) active_monitor = NULL;
    if (monitor->window && monitor->death)
        (void)api_AIBinder_unlinkToDeath(monitor->window, monitor->death, monitor);
    if (monitor->death) api_AIBinder_DeathRecipient_delete(monitor->death);
    if (monitor->listener) api_AIBinder_decStrong(monitor->listener);
    if (monitor->window) api_AIBinder_decStrong(monitor->window);
    // fd is owned by libbinder. Its process-global classes/library remain live.
    free(monitor);
}
#else
int asteriskd_keyguard_open(struct asteriskd_keyguard_monitor **out,
    asteriskd_keyguard_changed on_change, void *context, char *error, size_t size) {
    (void)on_change;
    (void)context;
    *out = NULL;
    snprintf(error, size, "lock screen control requires Android 13 or later");
    return -1;
}
int asteriskd_keyguard_fd(const struct asteriskd_keyguard_monitor *monitor) {
    (void)monitor;
    return -1;
}
int asteriskd_keyguard_dispatch(struct asteriskd_keyguard_monitor *monitor) {
    (void)monitor;
    return -1;
}
void asteriskd_keyguard_close(struct asteriskd_keyguard_monitor *monitor) {
    (void)monitor;
}
#endif

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "asteriskd_keyguard.h"
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
#define BINDER_APIS(X) \
 X(AIBinder_Class_define) X(AIBinder_associateClass) X(AIBinder_new) \
 X(AIBinder_getUserData) X(AIBinder_decStrong) X(AIBinder_prepareTransaction) \
 X(AIBinder_transact) X(AParcel_writeStrongBinder) X(AParcel_readStatusHeader) \
 X(AParcel_readBool) X(AParcel_delete) X(AStatus_isOk) X(AStatus_delete) \
 X(AIBinder_DeathRecipient_new) X(AIBinder_DeathRecipient_delete) \
 X(AIBinder_linkToDeath) X(AIBinder_unlinkToDeath)
static AIBinder_Class *(*api_AIBinder_Class_define)(const char *, AIBinder_Class_onCreate,
    AIBinder_Class_onDestroy, AIBinder_Class_onTransact);
static bool (*api_AIBinder_associateClass)(AIBinder *, const AIBinder_Class *);
static AIBinder *(*api_AIBinder_new)(const AIBinder_Class *, void *);
static void *(*api_AIBinder_getUserData)(AIBinder *);
static void (*api_AIBinder_decStrong)(AIBinder *);
static binder_status_t (*api_AIBinder_prepareTransaction)(AIBinder *, AParcel **);
static binder_status_t (*api_AIBinder_transact)(AIBinder *, transaction_code_t, AParcel **, AParcel **, binder_flags_t);
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
static AIBinder *(*check_service)(const char *);
static bool (*max_threads)(uint32_t);
static binder_status_t (*setup_polling)(int *);
static binder_status_t (*handle_commands)(void);
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
static struct asteriskd_keyguard_monitor *active;

static void *created(void *data) { return data; }
static void destroyed(void *data) { (void)data; }
static void died(void *cookie) {
    if (active == cookie) active->dead = true;
}
static binder_status_t changed(AIBinder *b, transaction_code_t code,
    const AParcel *in, AParcel *out) {
    (void)out;
    if (code != FIRST_CALL_TRANSACTION) return STATUS_UNKNOWN_TRANSACTION;
    bool locked;
    binder_status_t rc = api_AParcel_readBool(in,&locked);
    struct asteriskd_keyguard_monitor *m = api_AIBinder_getUserData(b);
    if (rc == STATUS_OK && active == m && m->registered && !m->priming)
        m->changed(m->context,locked,false);
    return rc;
}
static binder_status_t unused(AIBinder *b, transaction_code_t code,
    const AParcel *in, AParcel *out) {
    (void)b; (void)code; (void)in; (void)out;
    return STATUS_UNKNOWN_TRANSACTION;
}
static bool load_binder(void) {
    if (!binder_library) binder_library = dlopen("libbinder_ndk.so",RTLD_NOW|RTLD_LOCAL);
    if (!binder_library) return false;
#define LOAD(name) api_##name = (__typeof__(api_##name))dlsym(binder_library,#name); if (!api_##name) return false;
    BINDER_APIS(LOAD)
#undef LOAD
    check_service = (void *)dlsym(binder_library,"AServiceManager_checkService");
    max_threads = (void *)dlsym(binder_library,"ABinderProcess_setThreadPoolMaxThreadCount");
    setup_polling = (void *)dlsym(binder_library,"ABinderProcess_setupPolling");
    handle_commands = (void *)dlsym(binder_library,"ABinderProcess_handlePolledCommands");
    return check_service && max_threads && setup_polling && handle_commands;
}
static bool rpc(struct asteriskd_keyguard_monitor *m, int code, bool listener, bool *locked) {
    AParcel *in = NULL, *out = NULL;
    AStatus *status = NULL;
    binder_status_t rc = api_AIBinder_prepareTransaction(m->window,&in);
    if (rc == STATUS_OK && listener) rc = api_AParcel_writeStrongBinder(in,m->listener);
    if (rc == STATUS_OK) rc = api_AIBinder_transact(m->window,code,&in,&out,0);
    if (rc == STATUS_OK) rc = api_AParcel_readStatusHeader(out,&status);
    bool ok = rc == STATUS_OK && status && api_AStatus_isOk(status);
    if (ok && locked) ok = api_AParcel_readBool(out,locked) == STATUS_OK;
    if (status) api_AStatus_delete(status);
    if (in) api_AParcel_delete(in);
    if (out) api_AParcel_delete(out);
    return ok;
}

int asteriskd_keyguard_open(struct asteriskd_keyguard_monitor **out,
    asteriskd_keyguard_changed on_change, void *context, char *error, size_t size) {
    *out = NULL;
    char sdk[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk",sdk);
    if (atoi(sdk) < 33) {
        snprintf(error,size,"lock screen control requires Android 13 or later"); return -1;
    }
    if (active || !load_binder()) {
        snprintf(error,size,"native lock screen Binder APIs unavailable"); return -1;
    }
    struct asteriskd_keyguard_monitor *m = calloc(1,sizeof(*m));
    if (!m) return -1;
    m->fd = -1; m->priming = true; m->changed = on_change; m->context = context;
    const char *reason = "system lock screen transaction constants unavailable";
    if (asteriskd_keyguard_resolve_ids(m->ids)) goto fail;
    reason = "native lock screen Binder initialization failed";
    if (!max_threads(0) || !(m->window = check_service("window"))) goto fail;
    if (!window_class) window_class = api_AIBinder_Class_define("android.view.IWindowManager",created,destroyed,unused);
    if (!listener_class) listener_class = api_AIBinder_Class_define(
        "com.android.internal.policy.IKeyguardLockedStateListener",created,destroyed,changed);
    if (!window_class || !listener_class || !api_AIBinder_associateClass(m->window,window_class)) goto fail;
    m->listener = api_AIBinder_new(listener_class,m);
    m->death = api_AIBinder_DeathRecipient_new(died);
    if (!m->listener || !m->death || setup_polling(&m->fd) != STATUS_OK) goto fail;
    active = m;
    if (api_AIBinder_linkToDeath(m->window,m->death,m) != STATUS_OK) goto fail;
    reason = "lock screen listener registration denied or unsupported";
    if (!rpc(m,m->ids[1],true,NULL)) goto fail;
    m->registered = true;
    bool locked;
    // Drain registration-time notifications before establishing the baseline.
    // The synchronous query can itself dispatch Binder callbacks while priming.
    struct pollfd pending = {m->fd,POLLIN,0};
    if ((poll(&pending,1,0) > 0 && handle_commands() != STATUS_OK) ||
        !rpc(m,m->ids[0],false,&locked) || m->dead) goto fail;
    m->changed(m->context,locked,true);
    m->priming = false;
    *out = m;
    return 0;
fail:
    snprintf(error,size,"%s",reason);
    asteriskd_keyguard_close(m);
    return -1;
}
int asteriskd_keyguard_fd(const struct asteriskd_keyguard_monitor *m) { return m ? m->fd : -1; }
int asteriskd_keyguard_dispatch(struct asteriskd_keyguard_monitor *m) {
    if (!m || m->dead || handle_commands() != STATUS_OK || m->dead) return -1;
    return 0;
}
void asteriskd_keyguard_close(struct asteriskd_keyguard_monitor *m) {
    if (!m) return;
    if (m->registered && !m->dead) (void)rpc(m,m->ids[2],true,NULL);
    m->registered = false;
    if (active == m) active = NULL;
    if (m->window && m->death) (void)api_AIBinder_unlinkToDeath(m->window,m->death,m);
    if (m->death) api_AIBinder_DeathRecipient_delete(m->death);
    if (m->listener) api_AIBinder_decStrong(m->listener);
    if (m->window) api_AIBinder_decStrong(m->window);
    // fd is owned by libbinder. Its process-global classes/library remain live.
    free(m);
}
#else
int asteriskd_keyguard_open(struct asteriskd_keyguard_monitor **out,
    asteriskd_keyguard_changed changed, void *context, char *error, size_t size) {
    (void)changed; (void)context; *out = NULL;
    snprintf(error,size,"lock screen control requires Android 13 or later"); return -1;
}
int asteriskd_keyguard_fd(const struct asteriskd_keyguard_monitor *m) { (void)m; return -1; }
int asteriskd_keyguard_dispatch(struct asteriskd_keyguard_monitor *m) { (void)m; return -1; }
void asteriskd_keyguard_close(struct asteriskd_keyguard_monitor *m) { (void)m; }
#endif

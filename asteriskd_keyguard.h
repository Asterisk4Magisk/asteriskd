// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef ASTERISKD_KEYGUARD_H
#define ASTERISKD_KEYGUARD_H
#include <stdbool.h>
#include <stddef.h>
struct asteriskd_keyguard_monitor;
typedef void (*asteriskd_keyguard_changed)(void *, bool locked, bool baseline);
int asteriskd_keyguard_open(struct asteriskd_keyguard_monitor **,
    asteriskd_keyguard_changed, void *, char *, size_t);
int asteriskd_keyguard_fd(const struct asteriskd_keyguard_monitor *);
int asteriskd_keyguard_dispatch(struct asteriskd_keyguard_monitor *);
void asteriskd_keyguard_close(struct asteriskd_keyguard_monitor *);
int asteriskd_keyguard_resolve_ids(int ids[3]);
int asteriskd_keyguard_ids_from_dex(const void *, size_t, int ids[3]);
#endif

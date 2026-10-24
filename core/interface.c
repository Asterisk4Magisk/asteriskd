// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <string.h>

#define ASTERISKD_MAX_INTERFACE_SELECTOR_LENGTH 15U

static bool interface_selector_character_valid(unsigned char byte) {
    return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') || byte == '_' || byte == '.' || byte == '-';
}

bool asteriskd_interface_selector_valid(const char *selector) {
    if (selector == NULL) return false;
    size_t length = strnlen(selector, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length > ASTERISKD_MAX_INTERFACE_SELECTOR_LENGTH ||
        length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    size_t ordinary_length = selector[length - 1U] == '+' ? length - 1U : length;
    if (ordinary_length == 0U) return false;
    for (size_t index = 0U; index < ordinary_length; ++index) {
        if (!interface_selector_character_valid((unsigned char)selector[index])) return false;
    }
    return true;
}

bool asteriskd_interface_matches_selector(const char *name, const char *selector) {
    if (name == NULL || selector == NULL) return false;
    size_t length = strnlen(selector, ASTERISKD_MAX_INTERFACE_NAME);
    if (length == 0U || length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    return selector[length - 1U] == '+' ?
        length > 1U && strncmp(name, selector, length - 1U) == 0 : strcmp(name, selector) == 0;
}

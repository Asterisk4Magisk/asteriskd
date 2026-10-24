// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void asteriskd_error_copy(char *error, size_t error_size, const char *message) {
    if (error != NULL && error_size != 0U) (void)snprintf(error, error_size, "%s", message);
}

void asteriskd_error_vformat(char *error, size_t error_size, const char *format, va_list arguments) {
    if (error == NULL || error_size == 0U) return;
    int written = vsnprintf(error, error_size, format, arguments);
    if (written < 0 || (size_t)written >= error_size) error[error_size - 1U] = '\0';
}

void asteriskd_error_format(char *error, size_t error_size, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    asteriskd_error_vformat(error, error_size, format, arguments);
    va_end(arguments);
}

size_t asteriskd_bounded_length(const char *value, size_t capacity) {
    if (value == NULL) return capacity;
    size_t length = 0U;
    while (length < capacity && value[length] != '\0') ++length;
    return length;
}

int asteriskd_copy_string(char *destination, size_t capacity, const char *source) {
    if (destination == NULL || source == NULL) return -1;
    size_t length = strnlen(source, capacity);
    if (length == 0U || length >= capacity) return -1;
    memcpy(destination, source, length + 1U);
    return 0;
}

int asteriskd_compare_u32(const void *left, const void *right) {
    uint32_t left_value = *(const uint32_t *)left;
    uint32_t right_value = *(const uint32_t *)right;
    return left_value < right_value ? -1 : left_value > right_value ? 1 : 0;
}

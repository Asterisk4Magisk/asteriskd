// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include <stdbool.h>
#include <stddef.h>

bool asteriskd_hotspot_tc_output_has_android_offload(
    const void *output, size_t output_length) {
    static const char marker[] = "prog_offload_schedcls_tether_";
    const size_t marker_length = sizeof(marker) - 1U;
    if (output == NULL || output_length < marker_length) return false;
    const unsigned char *bytes = output;
    for (size_t offset = 0U; offset <= output_length - marker_length; ++offset) {
        size_t matched = 0U;
        while (matched < marker_length &&
            bytes[offset + matched] == (unsigned char)marker[matched]) ++matched;
        if (matched == marker_length) return true;
    }
    return false;
}

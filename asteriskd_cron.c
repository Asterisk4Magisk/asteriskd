// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

#define ASTERISKD_CRON_SEARCH_YEARS 8

struct asteriskd_cron_field {
    unsigned int minimum;
    unsigned int maximum;
    bool day_of_week;
};

static bool asteriskd_cron_uint(
    const char *value, size_t length, unsigned int *result) {
    unsigned int parsed = 0U;
    size_t index;

    if (value == NULL || result == NULL || length == 0U) return false;
    for (index = 0U; index < length; ++index) {
        unsigned int digit;
        if (value[index] < '0' || value[index] > '9') return false;
        digit = (unsigned int)(value[index] - '0');
        if (parsed > (UINT_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *result = parsed;
    return true;
}

static void asteriskd_cron_set(
    uint64_t *mask, unsigned int value, const struct asteriskd_cron_field *field) {
    unsigned int normalized = value;
    if (field->day_of_week && normalized == 7U) normalized = 0U;
    if (field->day_of_week) {
        *mask |= UINT64_C(1) << normalized;
    } else {
        *mask |= UINT64_C(1) << (normalized - field->minimum);
    }
}

static bool asteriskd_cron_term(
    const char *value,
    size_t length,
    const struct asteriskd_cron_field *field,
    uint64_t *mask,
    bool *wildcard) {
    const char *slash;
    const char *dash;
    size_t base_length;
    unsigned int first;
    unsigned int last;
    unsigned int step = 1U;
    unsigned int current;

    if (length == 0U) return false;
    slash = memchr(value, '/', length);
    if (slash != NULL) {
        size_t step_length = length - (size_t)(slash - value) - 1U;
        if (step_length == 0U ||
            memchr(slash + 1, '/', step_length) != NULL ||
            !asteriskd_cron_uint(slash + 1, step_length, &step) || step == 0U) {
            return false;
        }
        base_length = (size_t)(slash - value);
    } else {
        base_length = length;
    }
    if (base_length == 0U) return false;

    if (base_length == 1U && value[0] == '*') {
        first = field->minimum;
        last = field->maximum;
        *wildcard = true;
    } else {
        dash = memchr(value, '-', base_length);
        if (dash != NULL) {
            size_t first_length = (size_t)(dash - value);
            size_t last_length = base_length - first_length - 1U;
            if (first_length == 0U || last_length == 0U ||
                memchr(dash + 1, '-', last_length) != NULL ||
                !asteriskd_cron_uint(value, first_length, &first) ||
                !asteriskd_cron_uint(dash + 1, last_length, &last)) {
                return false;
            }
        } else {
            if (!asteriskd_cron_uint(value, base_length, &first)) return false;
            last = slash != NULL ? field->maximum : first;
        }
    }

    if (first < field->minimum || first > field->maximum ||
        last < field->minimum || last > field->maximum || first > last) {
        return false;
    }
    current = first;
    for (;;) {
        asteriskd_cron_set(mask, current, field);
        if (last - current < step) break;
        current += step;
    }
    return true;
}

static bool asteriskd_cron_field_parse(
    const char *value,
    size_t length,
    const struct asteriskd_cron_field *field,
    uint64_t *mask,
    bool *wildcard) {
    size_t offset = 0U;

    *mask = 0U;
    *wildcard = false;
    while (offset < length) {
        const char *comma = memchr(value + offset, ',', length - offset);
        size_t term_length = comma == NULL
            ? length - offset
            : (size_t)(comma - (value + offset));
        if (!asteriskd_cron_term(
                value + offset, term_length, field, mask, wildcard)) {
            return false;
        }
        if (comma == NULL) break;
        offset += term_length + 1U;
        if (offset == length) return false;
    }
    return *mask != 0U;
}

int asteriskd_cron_parse(
    const char *value, struct asteriskd_cron_expression *expression) {
    static const struct asteriskd_cron_field fields[5] = {
        {0U, 59U, false},
        {0U, 23U, false},
        {1U, 31U, false},
        {1U, 12U, false},
        {0U, 7U, true},
    };
    uint64_t masks[5];
    bool wildcards[5];
    size_t field_index = 0U;
    size_t offset = 0U;
    size_t length;

    if (value == NULL || expression == NULL) return -1;
    length = strlen(value);
    if (length == 0U || length > ASTERISKD_MAX_CRON_EXPRESSION) return -1;
    while (offset < length) {
        size_t start;
        while (offset < length && isspace((unsigned char)value[offset])) ++offset;
        if (offset == length) break;
        if (field_index == 5U) return -1;
        start = offset;
        while (offset < length && !isspace((unsigned char)value[offset])) ++offset;
        if (!asteriskd_cron_field_parse(
                value + start, offset - start, &fields[field_index],
                &masks[field_index], &wildcards[field_index])) {
            return -1;
        }
        ++field_index;
    }
    if (field_index != 5U) return -1;

    memset(expression, 0, sizeof(*expression));
    expression->minutes = masks[0];
    expression->hours = (uint32_t)masks[1];
    expression->days_of_month = (uint32_t)masks[2];
    expression->months = (uint16_t)masks[3];
    expression->days_of_week = (uint8_t)masks[4];
    expression->any_day_of_month = wildcards[2];
    expression->any_day_of_week = wildcards[4];
    return 0;
}

static bool asteriskd_cron_mask_has(
    uint64_t mask, unsigned int value, unsigned int minimum) {
    return (mask & (UINT64_C(1) << (value - minimum))) != 0U;
}

static bool asteriskd_cron_day_matches(
    const struct asteriskd_cron_expression *expression, const struct tm *value) {
    bool day_of_month;
    bool day_of_week;

    day_of_month = value->tm_mday >= 1 && value->tm_mday <= 31 &&
        asteriskd_cron_mask_has(
            expression->days_of_month, (unsigned int)value->tm_mday, 1U);
    day_of_week = value->tm_wday >= 0 && value->tm_wday <= 6 &&
        (expression->days_of_week & (UINT8_C(1) << value->tm_wday)) != 0U;
    if (expression->any_day_of_month && expression->any_day_of_week) return true;
    if (expression->any_day_of_month) return day_of_week;
    if (expression->any_day_of_week) return day_of_month;
    return day_of_month || day_of_week;
}

bool asteriskd_cron_matches(
    const struct asteriskd_cron_expression *expression, const struct tm *value) {
    if (expression == NULL || value == NULL ||
        value->tm_min < 0 || value->tm_min > 59 ||
        value->tm_hour < 0 || value->tm_hour > 23 ||
        value->tm_mon < 0 || value->tm_mon > 11) {
        return false;
    }
    return asteriskd_cron_mask_has(
            expression->minutes, (unsigned int)value->tm_min, 0U) &&
        asteriskd_cron_mask_has(
            expression->hours, (unsigned int)value->tm_hour, 0U) &&
        asteriskd_cron_mask_has(
            expression->months, (unsigned int)value->tm_mon + 1U, 1U) &&
        asteriskd_cron_day_matches(expression, value);
}

static bool asteriskd_cron_localtime(time_t epoch, struct tm *value) {
#if defined(_WIN32)
    return localtime_s(value, &epoch) == 0;
#else
    return localtime_r(&epoch, value) != NULL;
#endif
}

static bool asteriskd_cron_same_minute(
    const struct tm *value,
    int year,
    int month,
    int day,
    int hour,
    int minute) {
    return value->tm_year == year && value->tm_mon == month &&
        value->tm_mday == day && value->tm_hour == hour &&
        value->tm_min == minute && value->tm_sec == 0;
}

static void asteriskd_cron_candidate(
    int year,
    int month,
    int day,
    int hour,
    int minute,
    time_t lower_exclusive,
    time_t upper_inclusive,
    bool find_latest,
    bool *found,
    time_t *best) {
    static const int dst_values[3] = {-1, 0, 1};
    size_t index;

    for (index = 0U; index < 3U; ++index) {
        struct tm candidate;
        struct tm round_trip;
        time_t epoch;
        memset(&candidate, 0, sizeof(candidate));
        candidate.tm_year = year;
        candidate.tm_mon = month;
        candidate.tm_mday = day;
        candidate.tm_hour = hour;
        candidate.tm_min = minute;
        candidate.tm_isdst = dst_values[index];
        epoch = mktime(&candidate);
        if (epoch == (time_t)-1 || epoch <= lower_exclusive ||
            epoch > upper_inclusive ||
            !asteriskd_cron_localtime(epoch, &round_trip) ||
            !asteriskd_cron_same_minute(
                &round_trip, year, month, day, hour, minute)) {
            continue;
        }
        if (!*found || (find_latest ? epoch > *best : epoch < *best)) {
            *found = true;
            *best = epoch;
        }
    }
}

static bool asteriskd_cron_date_matches(
    const struct asteriskd_cron_expression *expression, const struct tm *day) {
    return day->tm_mon >= 0 && day->tm_mon <= 11 &&
        asteriskd_cron_mask_has(
            expression->months, (unsigned int)day->tm_mon + 1U, 1U) &&
        asteriskd_cron_day_matches(expression, day);
}

static bool asteriskd_cron_advance_day(struct tm *day, int direction) {
    time_t epoch;
    day->tm_hour = 12;
    day->tm_min = 0;
    day->tm_sec = 0;
    day->tm_isdst = -1;
    day->tm_mday += direction;
    epoch = mktime(day);
    return epoch != (time_t)-1 && asteriskd_cron_localtime(epoch, day);
}

int asteriskd_cron_next(
    const struct asteriskd_cron_expression *expression,
    time_t after,
    time_t *next) {
    struct tm day;
    int final_year;

    if (expression == NULL || next == NULL ||
        !asteriskd_cron_localtime(after, &day)) {
        return -1;
    }
    final_year = day.tm_year + ASTERISKD_CRON_SEARCH_YEARS;
    for (;;) {
        bool found = false;
        time_t best = 0;
        int hour;
        if (day.tm_year > final_year) return -1;
        if (asteriskd_cron_date_matches(expression, &day)) {
            for (hour = 0; hour <= 23; ++hour) {
                int minute;
                if (!asteriskd_cron_mask_has(
                        expression->hours, (unsigned int)hour, 0U)) {
                    continue;
                }
                for (minute = 0; minute <= 59; ++minute) {
                    if (!asteriskd_cron_mask_has(
                            expression->minutes, (unsigned int)minute, 0U)) {
                        continue;
                    }
                    asteriskd_cron_candidate(
                        day.tm_year, day.tm_mon, day.tm_mday, hour, minute,
                        after, (time_t)INT64_MAX, false, &found, &best);
                }
            }
        }
        if (found) {
            *next = best;
            return 0;
        }
        if (!asteriskd_cron_advance_day(&day, 1)) return -1;
    }
}

int asteriskd_cron_latest_between(
    const struct asteriskd_cron_expression *expression,
    time_t after,
    time_t through,
    time_t *latest) {
    struct tm day;
    struct tm lower_day;

    if (expression == NULL || latest == NULL || through <= after ||
        !asteriskd_cron_localtime(through, &day) ||
        !asteriskd_cron_localtime(after, &lower_day)) {
        return -1;
    }
    for (;;) {
        bool found = false;
        time_t best = 0;
        int hour;
        if (day.tm_year < lower_day.tm_year - ASTERISKD_CRON_SEARCH_YEARS) return -1;
        if (asteriskd_cron_date_matches(expression, &day)) {
            for (hour = 23; hour >= 0; --hour) {
                int minute;
                if (!asteriskd_cron_mask_has(
                        expression->hours, (unsigned int)hour, 0U)) {
                    continue;
                }
                for (minute = 59; minute >= 0; --minute) {
                    if (!asteriskd_cron_mask_has(
                            expression->minutes, (unsigned int)minute, 0U)) {
                        continue;
                    }
                    asteriskd_cron_candidate(
                        day.tm_year, day.tm_mon, day.tm_mday, hour, minute,
                        after, through, true, &found, &best);
                }
            }
        }
        if (found) {
            *latest = best;
            return 0;
        }
        if (day.tm_year == lower_day.tm_year &&
            day.tm_yday <= lower_day.tm_yday) {
            return -1;
        }
        if (!asteriskd_cron_advance_day(&day, -1)) return -1;
    }
}

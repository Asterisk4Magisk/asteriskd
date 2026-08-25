// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd_compat.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define ASTERISKD_TUN_MAJOR 10U
#define ASTERISKD_TUN_MINOR 200U

static int tun_error(char *error, size_t capacity, const char *format, ...) {
    if (error != NULL && capacity != 0U) {
        va_list arguments;
        va_start(arguments, format);
        int written = vsnprintf(error, capacity, format, arguments);
        va_end(arguments);
        if (written < 0 || (size_t)written >= capacity) error[capacity - 1U] = '\0';
    }
    return -1;
}

static int tun_lstat(const char *path, struct stat *info, bool *exists) {
    int result;
    do {
        result = lstat(path, info);
    } while (result != 0 && errno == EINTR);
    if (result == 0) {
        *exists = true;
        return 0;
    }
    if (errno == ENOENT) {
        memset(info, 0, sizeof(*info));
        *exists = false;
        return 0;
    }
    return -1;
}

static bool tun_paths_valid(const struct asteriskd_tun_compat_paths *paths) {
    return paths != NULL && paths->tun_device != NULL && paths->tun_device[0] == '/' &&
        paths->network_directory != NULL && paths->network_directory[0] == '/' &&
        paths->compatibility_path != NULL && paths->compatibility_path[0] == '/' &&
        strcmp(paths->tun_device, paths->network_directory) != 0 &&
        strcmp(paths->tun_device, paths->compatibility_path) != 0 &&
        strcmp(paths->network_directory, paths->compatibility_path) != 0;
}

static bool tun_character_device(const struct stat *info) {
    return S_ISCHR(info->st_mode) &&
        (unsigned int)major(info->st_rdev) == ASTERISKD_TUN_MAJOR &&
        (unsigned int)minor(info->st_rdev) == ASTERISKD_TUN_MINOR;
}

static int tun_path_is_character_device(const char *path, bool *matches) {
    struct stat info;
    int result;
    do {
        result = stat(path, &info);
    } while (result != 0 && errno == EINTR);
    if (result != 0) return -1;
    *matches = tun_character_device(&info);
    return 0;
}

static int tun_link_matches(const char *path, const char *target, bool *matches) {
    char bytes[512U];
    ssize_t length;
    do {
        length = readlink(path, bytes, sizeof(bytes));
    } while (length < 0 && errno == EINTR);
    if (length < 0 || (size_t)length >= sizeof(bytes)) return -1;
    size_t target_length = strlen(target);
    *matches = (size_t)length == target_length && memcmp(bytes, target, target_length) == 0;
    return 0;
}

void asteriskd_tun_compat_state_init(struct asteriskd_tun_compat_state *state) {
    if (state != NULL) memset(state, 0, sizeof(*state));
}

int asteriskd_tun_compat_prepare(
    const struct asteriskd_tun_compat_paths *paths,
    struct asteriskd_tun_compat_state *state, char *error, size_t error_capacity) {
    if (error != NULL && error_capacity != 0U) error[0] = '\0';
    if (!tun_paths_valid(paths) || state == NULL || state->directory_created ||
        state->link_created) return tun_error(error, error_capacity, "invalid TUN compatibility state");

    struct stat info;
    bool exists = false;
    if (tun_lstat(paths->tun_device, &info, &exists) != 0) {
        return tun_error(error, error_capacity, "TUN device inspection failed: errno=%d", errno);
    }
    if (!exists || !tun_character_device(&info)) {
        return tun_error(error, error_capacity, "TUN device is not character device 10:200");
    }

    if (tun_lstat(paths->network_directory, &info, &exists) != 0) {
        return tun_error(error, error_capacity, "TUN directory inspection failed: errno=%d", errno);
    }
    if (!exists) {
        int result;
        do {
            result = mkdir(paths->network_directory, 0755);
        } while (result != 0 && errno == EINTR);
        if (result == 0) {
            state->directory_created = true;
        } else if (errno != EEXIST) {
            return tun_error(error, error_capacity, "TUN directory creation failed: errno=%d", errno);
        }
        if (tun_lstat(paths->network_directory, &info, &exists) != 0) {
            return tun_error(error, error_capacity, "created TUN directory inspection failed: errno=%d", errno);
        }
    }
    if (!exists || !S_ISDIR(info.st_mode)) {
        return tun_error(error, error_capacity, "TUN compatibility directory is not a real directory");
    }

    if (tun_lstat(paths->compatibility_path, &info, &exists) != 0) {
        return tun_error(error, error_capacity, "TUN compatibility path inspection failed: errno=%d", errno);
    }
    if (!exists) {
        int result;
        do {
            result = symlink(paths->tun_device, paths->compatibility_path);
        } while (result != 0 && errno == EINTR);
        bool created = result == 0;
        if (!created && errno != EEXIST) {
            return tun_error(error, error_capacity, "TUN compatibility link creation failed: errno=%d", errno);
        }
        if (tun_lstat(paths->compatibility_path, &info, &exists) != 0 || !exists) {
            return tun_error(error, error_capacity, "created TUN link inspection failed: errno=%d", errno);
        }
        if (created) {
            bool matches = false;
            if (!S_ISLNK(info.st_mode) ||
                tun_link_matches(paths->compatibility_path, paths->tun_device, &matches) != 0 ||
                !matches) {
                return tun_error(error, error_capacity, "created TUN link identity mismatch");
            }
            state->link_created = true;
            state->link_device = (uint64_t)info.st_dev;
            state->link_inode = (uint64_t)info.st_ino;
            return 0;
        }
    }

    if (tun_character_device(&info)) return 0;
    if (S_ISLNK(info.st_mode)) {
        bool matches = false;
        if (tun_path_is_character_device(paths->compatibility_path, &matches) == 0 &&
            matches) return 0;
    }
    return tun_error(error, error_capacity, "TUN compatibility path conflicts with an existing object");
}

int asteriskd_tun_compat_cleanup(
    const struct asteriskd_tun_compat_paths *paths,
    struct asteriskd_tun_compat_state *state, char *error, size_t error_capacity) {
    if (error != NULL && error_capacity != 0U) error[0] = '\0';
    if (!tun_paths_valid(paths) || state == NULL) {
        return tun_error(error, error_capacity, "invalid TUN compatibility cleanup state");
    }

    if (state->link_created) {
        struct stat info;
        bool exists = false;
        if (tun_lstat(paths->compatibility_path, &info, &exists) != 0) {
            return tun_error(error, error_capacity, "TUN link cleanup inspection failed: errno=%d", errno);
        }
        if (exists) {
            bool matches = false;
            if (!S_ISLNK(info.st_mode) || (uint64_t)info.st_dev != state->link_device ||
                (uint64_t)info.st_ino != state->link_inode ||
                tun_link_matches(paths->compatibility_path, paths->tun_device, &matches) != 0 ||
                !matches) {
                return tun_error(error, error_capacity, "TUN link changed before cleanup");
            }
            int result;
            do {
                result = unlink(paths->compatibility_path);
            } while (result != 0 && errno == EINTR);
            if (result != 0 && errno != ENOENT) {
                return tun_error(error, error_capacity, "TUN link cleanup failed: errno=%d", errno);
            }
        }
        state->link_created = false;
        state->link_device = 0U;
        state->link_inode = 0U;
    }

    if (state->directory_created) {
        int result;
        do {
            result = rmdir(paths->network_directory);
        } while (result != 0 && errno == EINTR);
        if (result != 0 && errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST) {
            return tun_error(error, error_capacity, "TUN directory cleanup failed: errno=%d", errno);
        }
        state->directory_created = false;
    }
    return 0;
}

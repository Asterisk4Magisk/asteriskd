// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "supervisor/supervisor.h"

#if defined(__ANDROID__)
/* A `cmd` stuck early in boot must not hold the control socket, a lock or the signalfd. */
static void notify_close_inherited_descriptors(void) {
#ifdef __NR_close_range
    if (syscall(__NR_close_range, 3U, ~0U, 0U) == 0) return;
#endif
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) return;
    int directory_fd = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long fd = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || fd < 3L || fd == directory_fd) continue;
        (void)close((int)fd);
    }
    (void)closedir(directory);
}

static void notify_exec_broadcast(const char *component) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    (void)sigemptyset(&action.sa_mask);
    for (int signal_number = 1; signal_number < NSIG; ++signal_number) {
        if (signal_number == SIGKILL || signal_number == SIGSTOP) continue;
        (void)sigaction(signal_number, &action, NULL);
    }
    sigset_t empty;
    (void)sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    (void)setsid();
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0) {
        (void)dup2(null_fd, STDIN_FILENO);
        (void)dup2(null_fd, STDOUT_FILENO);
        (void)dup2(null_fd, STDERR_FILENO);
    }
    notify_close_inherited_descriptors();
    char *const argv[] = {"cmd", "activity", "broadcast", "-n", (char *)component, NULL};
    (void)execve("/system/bin/cmd", argv, environ);
    _exit(127);
}
#endif

int asteriskd_supervisor_notify_runtime_event(const struct asteriskd_config *config) {
#if defined(__ANDROID__)
    if (config == NULL || !config->has_runtime_event_receiver) return 0;
    /* The intermediate child exits at once so the supervisor never waits on `cmd`. */
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (fork() == 0) notify_exec_broadcast(config->runtime_event_receiver);
        _exit(0);
    }
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return 0;
#else
    (void)config;
    return 0;
#endif
}

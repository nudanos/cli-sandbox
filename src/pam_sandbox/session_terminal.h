/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SANDBOX_SESSION_TERMINAL_H
#define SANDBOX_SESSION_TERMINAL_H
#include <limits.h>
#include <sys/types.h>

struct sandbox_terminal {
    char name[NAME_MAX + 1];
    dev_t device;
};

int sandbox_terminal_capture(struct sandbox_terminal *tty, int fd);
int sandbox_terminal_install(const struct sandbox_terminal *tty, const char *devdir);
#endif

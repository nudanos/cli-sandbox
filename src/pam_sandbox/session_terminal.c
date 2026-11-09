/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session_terminal.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static int valid_name(const char *name)
{
    return name[0] && strcmp(name, ".") && strcmp(name, "..") &&
        !strchr(name, '/') && strlen(name) <= NAME_MAX;
}

static int capture_device(struct sandbox_terminal *tty, int fd, const char *path)
{
    struct stat source, actual;
    int sourcefd;

    memset(tty, 0, sizeof(*tty));
    if (strncmp(path, "/dev/", 5) || !valid_name(path + 5)) {
        errno = EINVAL;
        return -1;
    }
    sourcefd = open(path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (sourcefd < 0)
        return -1;
    int r = fstat(sourcefd, &source);
    int saved_errno = errno;
    close(sourcefd);
    if (r < 0) {
        errno = saved_errno;
        return -1;
    }
    if (fstat(fd, &actual) < 0)
        return -1;
    if (!S_ISCHR(source.st_mode) || !S_ISCHR(actual.st_mode) ||
        source.st_dev != actual.st_dev || source.st_ino != actual.st_ino ||
        source.st_rdev != actual.st_rdev) {
        errno = ENODEV;
        return -1;
    }
    strcpy(tty->name, path + 5);
    tty->device = actual.st_rdev;
    return 0;
}

int sandbox_terminal_capture(struct sandbox_terminal *tty, int fd)
{
    char path[PATH_MAX];
    memset(tty, 0, sizeof(*tty));

    /* SSH's PTY is already provided by nspawn. Only a controlling terminal
     * can require login to reopen its original physical device after chroot.
     * Never accept PAM_TTY (which need not describe an open host device).
     */
    if (!isatty(fd) || tcgetsid(fd) != getsid(0))
        return 0;
    int r = ttyname_r(fd, path, sizeof(path));
    if (r) {
        errno = r;
        return -1;
    }
    if (!strncmp(path, "/dev/pts/", 9)) {
        const char *n = path + 9;
        if (*n && strspn(n, "0123456789") == strlen(n))
            return 0;
        errno = EINVAL;
        return -1;
    }
    return capture_device(tty, fd, path);
}

int sandbox_terminal_install(const struct sandbox_terminal *tty, const char *devdir)
{
    struct stat st;
    int r = -1;
    if (!tty->name[0])
        return 0;
    if (!valid_name(tty->name)) {
        errno = EINVAL;
        return -1;
    }
    int devfd = open(devdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (devfd < 0)
        return -1;
    if (fstat(devfd, &st) < 0)
        goto out;
    if (st.st_uid != 0 || (st.st_mode & 0022)) {
        errno = EPERM;
        goto out;
    }

    /* login reopens the path while privileged. Keep this distinct inode
     * root:root 000 even when login chowns/chmods the original host fd0.
     * This prevents stale console ownership in a surviving user sandbox.
     */
    if (mknodat(devfd, tty->name, S_IFCHR, tty->device) == 0) {
        if (fchownat(devfd, tty->name, 0, 0, AT_SYMLINK_NOFOLLOW) < 0)
            goto out;
    } else if (errno != EEXIST) {
        goto out;
    }
    if (fstatat(devfd, tty->name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        goto out;
    /* Never repair an existing alias: administrator binds and unexpected
     * symlinks, devices, ownership or permissions must fail closed.
     */
    if (!S_ISCHR(st.st_mode) || st.st_rdev != tty->device ||
        st.st_uid != 0 || st.st_gid != 0 || (st.st_mode & 07777)) {
        errno = EPERM;
        goto out;
    }
    r = 0;
out:
    {
        int saved_errno = errno;
        close(devfd);
        errno = saved_errno;
    }
    return r;
}

/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pty.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

/* Include the production helper to exercise its source-path validation too. */
#include "../src/pam_sandbox/session_terminal.c"

static void capture_checks(void)
{
    struct sandbox_terminal tty;
    int nullfd = open("/dev/null", O_RDWR);
    int zerofd = open("/dev/zero", O_RDWR);
    assert(nullfd >= 0 && zerofd >= 0);
    assert(sandbox_terminal_capture(&tty, nullfd) == 0 && !tty.name[0]);
    assert(capture_device(&tty, nullfd, "/dev/null") == 0);
    assert(!strcmp(tty.name, "null"));
    assert(capture_device(&tty, zerofd, "/dev/null") == -1);
    assert(capture_device(&tty, nullfd, "/dev/stdin") == -1);
    assert(capture_device(&tty, nullfd, "/tmp/null") == -1);
    assert(capture_device(&tty, nullfd, "/dev/../null") == -1);
    close(nullfd); close(zerofd);

    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        int master, slave;
        assert(setsid() >= 0);
        assert(openpty(&master, &slave, NULL, NULL, NULL) == 0);
        assert(ioctl(slave, TIOCSCTTY, 0) == 0);
        assert(tcgetsid(slave) == getsid(0));
        assert(sandbox_terminal_capture(&tty, slave) == 0 && !tty.name[0]);
        _exit(0);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void alias_checks(void)
{
    char dir[] = "/dev/.sandbox-terminal-test-XXXXXX";
    char path[512], link[512];
    struct stat st;
    struct sandbox_terminal tty = { .name = "ttyS0", .device = makedev(1, 3) };
    assert(mkdtemp(dir));
    assert(chmod(dir, 0755) == 0);
    snprintf(path, sizeof(path), "%s/ttyS0", dir);
    snprintf(link, sizeof(link), "%s-link", dir);

    assert(sandbox_terminal_install(&tty, dir) == 0);
    assert(lstat(path, &st) == 0); /* RED: baseline leaves the terminal absent. */
    assert(S_ISCHR(st.st_mode) && st.st_rdev == tty.device);
    assert(st.st_uid == 0 && st.st_gid == 0 && (st.st_mode & 07777) == 0);
    int fd = open(path, O_RDWR);
    assert(fd >= 0); close(fd);
    assert(sandbox_terminal_install(&tty, dir) == 0);

    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(setgroups(0, NULL) == 0);
        assert(setgid(65534) == 0 && setuid(65534) == 0);
        errno = 0;
        assert(open(path, O_RDWR) == -1 && errno == EACCES);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);

    assert(chmod(path, 0600) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(chmod(path, 0) == 0 && chown(path, 65534, 0) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(unlink(path) == 0);
    assert(symlink("/dev/null", path) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(unlink(path) == 0);
    assert(mknod(path, S_IFCHR, makedev(1, 5)) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(unlink(path) == 0);
    assert(chmod(dir, 0777) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(chmod(dir, 0755) == 0 && chown(dir, 65534, 0) == 0);
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(chown(dir, 0, 0) == 0);
    assert(symlink(dir, link) == 0);
    assert(sandbox_terminal_install(&tty, link) == -1);
    assert(unlink(link) == 0);
    strcpy(tty.name, "../escape");
    assert(sandbox_terminal_install(&tty, dir) == -1);
    strcpy(tty.name, ".");
    assert(sandbox_terminal_install(&tty, dir) == -1);
    assert(rmdir(dir) == 0);
}

int main(void)
{
    capture_checks();
    /* A private /dev also disappears if an assertion aborts the test. Root
     * cases require a disposable Linux VM with mount/mknod capabilities.
     */
    if (geteuid() == 0 && !getenv("FAKEROOTKEY")) {
        assert(unshare(CLONE_NEWNS) == 0);
        assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
        assert(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755") == 0);
        alias_checks();
    } else
        puts("SKIP root-only device and ownership checks");
    puts("session terminal checks passed");
    return 0;
}

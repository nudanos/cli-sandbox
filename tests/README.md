# Session terminal regression

`make check` verifies controlling-PTY exclusion and physical-device path identity
validation. Run it as real root in a disposable Linux VM to additionally verify
device creation, privileged reopen, unprivileged denial and fail-closed metadata
checks. These cases require mount namespace and device creation capabilities;
fakeroot and ordinary unprivileged builds explicitly skip them. Root cases mount
a private temporary `/dev`, so an assertion failure cannot leave test devices in
the VM's original `/dev`.

The PAM module captures fd0's controlling terminal before changing namespaces.
Canonical `/dev/pts/N` terminals keep the existing SSH behavior. A physical
terminal must resolve to the same character-device inode as fd0; PAM_TTY is never
used. After chroot, PAM creates only that device's basename beneath a root-owned,
non-writable `/dev`. The new inode remains root:root mode000 so privileged login
can reopen it without granting later sandbox processes access to a reused console.
Existing aliases must match the device and those restrictive ownership/mode
requirements. Custom administrator terminal binds may therefore be rejected.

The C test is not a substitute for real serial getty and SSH sessions. Acceptance
also checks the actual login reopen, device access policy, namespace boundaries,
cross-user console reuse while an earlier SSH session survives, and teardown.

#!/bin/bash
# Copyright (c) 2018 AT&T intellectual property.
# All rights reserved
#
# SPDX-License-Identifier: GPL-2.0-only

PAM_PROFILE=sandbox
PAM_PROFILE_SRC=/opt/vyatta/share/pam-configs/${PAM_PROFILE}
PAM_PROFILE_DST=/usr/share/pam-configs/${PAM_PROFILE}
PAM_SESSION=/etc/pam.d/common-session
PAM_CHECK=/opt/vyatta/sbin/pam-sandbox-check
PROG=$0

err_exit()
{
	echo "${PROG}: ${1}" >&2
	exit 1
}

update_pam()
{
	DEBIAN_FRONTEND=noninteractive pam-auth-update "$@"
}

sandbox_active()
{
	grep -Eq '^[[:space:]]*-?session[[:space:]]+[^#]*[[:space:]/]pam_sandbox\.so([[:space:]]|$)' "$PAM_SESSION"
}

session_reaches()
{
	# Accept the managed Debian stack. Reject early success or a jump that
	# can skip the isolation rule. Debian's initial jump over pam_deny is safe.
	awk -v target="$2" '
	{
		sub(/#.*/, "")
		if (sub(/\\[[:space:]]*$/, " ")) {
			continued = continued $0
			next
		}
		rule = continued $0
		continued = ""
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", rule)
		gsub(/[[:space:]]+/, " ", rule)
		control = tolower(rule)
		if (debian_jump && control ~ /^-?session /) {
			if (rule != "session requisite pam_deny.so") exit
			debian_jump = 0
			next
		}
		if ((target == "module" && rule == "session required pam_sandbox.so") ||
		    (target == "include" && (rule == "@include common-session" ||
		     (control ~ /^-?session (include|substack) common-session$/ && rule ~ / common-session$/)))) {
			reached = 1
			exit
		}
		if (target == "module" && rule == "session [default=1] pam_permit.so") {
			debian_jump = 1
			next
		}
		if (rule ~ /^@include common-(auth|account|password)$/) next
		if (control ~ /^@include |^-?session (sufficient|include|substack) /) exit
		if (match(control, /^-?session \[[^]]*\]/) &&
		    substr(control, RSTART, RLENGTH) ~ /=[[:space:]]*(done|[0-9]+)([[:space:]]|\])/) exit
	}
	END { exit !reached }
	' "$1"
}

check_prerequisites()
{
	[ -r /etc/os-release ] || err_exit "cannot determine the operating system"
	# shellcheck source=/dev/null
	. /etc/os-release
	case ${ID:-} in
		debian|danos|vyatta) ;;
		*) err_exit "user isolation requires a supported Debian PAM and systemd integration" ;;
	esac
	[ -r "$PAM_PROFILE_SRC" ] || err_exit "missing PAM profile $PAM_PROFILE_SRC"
	if [ ! -x /usr/bin/systemd-nspawn ] || [ ! -x /opt/vyatta/sbin/cli-sandbox ] ||
		[ ! -x /opt/vyatta/sbin/cli_sandbox_init ] ||
		[ ! -r /etc/cli-sandbox/nspawn-templates/cli_sandbox.nspawn ] ||
		[ ! -r /var/lib/sandbox/etc/os-release ] || [ ! -x /var/lib/sandbox/bin/vbash ]; then
		err_exit "sandbox runtime or root filesystem is incomplete"
	fi
	systemctl cat cli-sandbox@.service systemd-machined.service >/dev/null ||
		err_exit "sandbox systemd units are unavailable"
	local arch module_dir
	arch=$(dpkg --print-architecture) || err_exit "cannot determine the PAM module architecture"
	module_dir=$(dpkg-query --listfiles "libpam-modules:$arch" | sed -n 's|/pam_unix\.so$||p')
	if [ -z "$module_dir" ] || [ ! -r "$module_dir/pam_sandbox.so" ]; then
		err_exit "PAM module pam_sandbox.so is unavailable in the native PAM directory"
	fi
	if [ ! -r "/var/lib/sandbox$module_dir/pam_vyatta_passwd.so" ] &&
		[ ! -r "$module_dir/pam_vyatta_passwd.so" ]; then
		err_exit "sandbox password renewal module is unavailable"
	fi
	local service service_file
	for service in login sshd; do
		service_file=/etc/pam.d/$service
		[ -f "$service_file" ] || service_file=/usr/lib/pam.d/$service
		# SSH may be absent on a native installation that uses the console.
		if [ "$service" = sshd ] && [ ! -e "$service_file" ] && [ ! -x /usr/sbin/sshd ]; then
			continue
		fi
		session_reaches "$service_file" include ||
			err_exit "$service_file does not use the managed PAM session stack"
	done
}

action=${1:-enable}
command -v pam-auth-update >/dev/null || err_exit "pam-auth-update is unavailable"
[ -r "$PAM_SESSION" ] || err_exit "cannot read $PAM_SESSION"
"$PAM_CHECK" --outside-common-session || err_exit 'review local PAM session rules'
case ${action} in
	disable)
		update_pam --disable "$PAM_PROFILE" || err_exit "could not disable the PAM profile"
		[ -r "$PAM_SESSION" ] || err_exit "cannot read $PAM_SESSION"
		"$PAM_CHECK" || err_exit 'review local PAM session rules'
		if [ ! -L "$PAM_PROFILE_DST" ] && cmp -s "$PAM_PROFILE_SRC" "$PAM_PROFILE_DST"; then
			rm -f "$PAM_PROFILE_DST" || err_exit "could not remove $PAM_PROFILE_DST"
		fi
		echo "User Isolation Disabled"
		;;
	enable)
		check_prerequisites
		was_active=false
		if sandbox_active; then
			was_active=true
		fi
		created=false
		if [ ! -e "$PAM_PROFILE_DST" ] && [ ! -L "$PAM_PROFILE_DST" ]; then
			install -m 644 "$PAM_PROFILE_SRC" "$PAM_PROFILE_DST" ||
				err_exit "could not install $PAM_PROFILE_DST"
			created=true
		elif [ -L "$PAM_PROFILE_DST" ] || ! cmp -s "$PAM_PROFILE_SRC" "$PAM_PROFILE_DST"; then
			err_exit "$PAM_PROFILE_DST differs from the packaged profile"
		fi
		if ! update_pam --enable "$PAM_PROFILE" || ! session_reaches "$PAM_SESSION" module; then
			if ! "$was_active" && sandbox_active; then
				update_pam --disable "$PAM_PROFILE" ||
					err_exit "could not roll back the PAM profile; review $PAM_SESSION"
			fi
			# Remove a newly staged profile only after confirming it isn't live.
			if "$created" && [ -r "$PAM_SESSION" ] && ! sandbox_active; then
				rm -f "$PAM_PROFILE_DST" || err_exit "could not roll back $PAM_PROFILE_DST"
			fi
			err_exit "could not activate the PAM profile; review $PAM_SESSION"
		fi
		echo "User Isolation Enabled"
		;;
	*)
		err_exit "error: unknown argument '${1}'"
		;;
esac

exit 0

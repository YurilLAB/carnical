#!/bin/sh
# Create the honeytoken files that deploy/auditd/carnical.rules watches. Run once, as root, after the directories exist
# (systemd-tmpfiles --create) and before the audit rules are loaded.
#
# A honeytoken is a file that looks worth stealing and that nothing legitimate ever reads. An attacker who has a foothold looks
# for exactly this kind of file (a backup of the customer database, an old copy of a key, an .env backup), so a read of one is an
# incident with no false positives. They hold nothing real: the contents are random bytes with a plausible header, and the
# values in the .env copy are marked so that the owner who finds one in a log knows what it is.
set -eu

umask 077

make() { # owner path
	owner=$1
	path=$2
	if [ -e "$path" ]; then
		echo "exists, left alone: $path"
		return
	fi
	cat >"$path"
	chown "$owner:$owner" "$path"
	chmod 0600 "$path"
	echo "created: $path"
}

# A "backup" of the customer database: the SQLite header followed by random bytes, about the size of a small one.
{
	printf 'SQLite format 3\000'
	head -c 262144 /dev/urandom
} | make carnical-ctl /var/lib/carnical/ctl/customers-backup.sqlite

# An old environment file with keys in it, every value marked as a honeytoken.
make carnical-portal /var/lib/carnical/portal/.env.bak <<'EOF'
# copied before the last upgrade
DATABASE_URL=postgres://portal:CARNICAL-HONEY-DO-NOT-USE@127.0.0.1:5432/portal
SESSION_SECRET=CARNICAL-HONEY-0000000000000000000000000000
PAYMENT_API_KEY=CARNICAL-HONEY-sk_live_0000000000000000
EOF

# The "previous" signing key, which was never a key.
{
	printf -- '-----BEGIN PRIVATE KEY-----\n'
	head -c 96 /dev/urandom | base64
	printf -- '-----END PRIVATE KEY-----\n'
} | make carnical-signer /var/lib/carnical/signer/signing-key.old

echo
echo "Load the audit rules next:   augenrules --load"
echo "A read of any of these shows up as:   ausearch -k carnical_honey -i"

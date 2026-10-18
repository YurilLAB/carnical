#!/bin/sh
# Fetch the address lists search engines publish for their crawlers, check each with carnical, and move each that passes
# into place. A running edge reads a replaced list within a minute (-bots-ranges); a list that fails to download or to
# check is left as it was, and the script exits 1 so that the timer's unit shows the failure.
#
#   refresh.sh [DIR]      DIR defaults to /var/lib/carnical/ranges; CARNICAL names the binary.
#
# Amazon publishes Amazonbot's addresses only on a web page (developer.amazon.com/amazonbot/ip-addresses/): copy its JSON
# into DIR/amazonbot.json by hand, or leave Amazonbot to DNS.
set -eu

dir=${1:-/var/lib/carnical/ranges}
carnical=${CARNICAL:-/usr/local/bin/carnical}
umask 022
failed=0

# fetch ENGINE FILE URL
fetch() {
	new="$dir/.$2.new"
	if ! curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
		--max-time 60 --max-filesize 4194304 --output "$new" "$3"; then
		echo "refresh: $2: download from $3 failed; the list in place is kept" >&2
		rm -f "$new"
		failed=1
		return
	fi
	# The same checks the edge makes when it reads the list: the JSON form or one range a line, nothing wider than a /16
	# (IPv4) or a /32 (IPv6), at most 4 MiB. The upstream is a placeholder that -check does not connect to.
	if ! out=$("$carnical" -check -upstream http://127.0.0.1:9 -origin-allow 127.0.0.1/32 -bots fake \
		-bots-ranges "$1=$new" 2>&1); then
		echo "refresh: $2: the list from $3 did not pass the check; the list in place is kept" >&2
		printf '%s\n' "$out" >&2
		rm -f "$new"
		failed=1
		return
	fi
	chmod 0644 "$new"
	mv -f "$new" "$dir/$2"
	echo "refresh: $2 updated from $3"
}

fetch google common-crawlers.json https://developers.google.com/static/crawling/ipranges/common-crawlers.json
fetch google-special special-crawlers.json https://developers.google.com/static/crawling/ipranges/special-crawlers.json
fetch bing bingbot.json https://www.bing.com/toolbox/bingbot.json
fetch apple applebot.json https://search.developer.apple.com/applebot.json
exit "$failed"

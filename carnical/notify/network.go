// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"time"

	"github.com/YurilLAB/coraza/carnical/netwatch"
)

// FromNetwork is the message for an event of carnical-netwatch, read from its state file: the record has been checked
// (netwatch.ReadState), and holds only counts, ports and kinds.
func FromNetwork(st netwatch.State, site string) Message {
	rec := *st.Attack
	rec.Started = rec.Started.UTC() // the watch writes its own time zone; a message is in UTC
	if rec.Ended != nil {
		end := rec.Ended.UTC()
		rec.Ended = &end
	}
	return Message{Event: Event(st.Event), At: st.At.UTC(), Site: site, Text: rec.Text(st.Event, site),
		Subject: "network " + rec.Started.UTC().Format(time.RFC3339Nano), Network: &rec}
}

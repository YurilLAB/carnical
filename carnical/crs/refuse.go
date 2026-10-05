package crs

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// A few things the engine can do from inside a rule are not things a web application firewall that hosts other people's
// sites should ever do, whoever wrote the rule:
//
//   - @inspectFile runs a program on the host with the matched value as its argument;
//   - the exec action runs a program on the host;
//   - the setenv action changes the environment of the whole process, with a value taken from the request, so one site's
//     visitor could set what every other site's rules and the proxy itself see;
//   - @rbl opens network connections to names built from the request, and leaves a goroutine behind when it times out;
//   - @geoLookup is a stub that matches everything.
//
// Rules are ours (the Core Rule Set and what the policy compiler writes), so none of these is used today. They are
// replaced here with versions that refuse to compile, so that a rule using one fails when the rule set is built and the
// site is never served with it. Registration is process-wide and runs after the engine's own, which is why it lives in
// an init function of a package every user of the rule set imports.
func init() {
	for _, name := range []string{"inspectFile", "rbl", "geoLookup"} {
		plugins.RegisterOperator(name, func(plugintypes.OperatorOptions) (plugintypes.Operator, error) {
			return nil, fmt.Errorf("the @%s operator is not available", name)
		})
	}
	for _, name := range []string{"exec", "setenv"} {
		plugins.RegisterAction(name, func() plugintypes.Action { return refusedAction{name} })
	}
}

type refusedAction struct{ name string }

func (a refusedAction) Init(plugintypes.RuleMetadata, string) error {
	return fmt.Errorf("the %s action is not available", a.name)
}

func (refusedAction) Evaluate(plugintypes.RuleMetadata, plugintypes.TransactionState) {}

func (refusedAction) Type() plugintypes.ActionType { return plugintypes.ActionTypeNondisruptive }

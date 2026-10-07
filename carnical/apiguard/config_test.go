// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Config)
		want   string // "" means valid, else a part of the error
	}{
		{"the zero value is valid", func(c *Config) { *c = Config{} }, ""},
		{"the defaults are valid", func(c *Config) { *c = DefaultConfig() }, ""},
		{"a mode that does not exist", func(c *Config) { c.Mode = 9 }, "mode"},
		{"a negative mode", func(c *Config) { c.Modes.Rate = -1 }, "modes.rate"},
		{"a group mode that does not exist", func(c *Config) { c.Modes.Spec = 7 }, "modes.spec"},
		{"a method in lower case", func(c *Config) { c.Methods = []string{"get"} }, "methods"},
		{"a method that is not a name", func(c *Config) { c.Methods = []string{"GET /"} }, "methods"},
		{"a method listed twice", func(c *Config) { c.Methods = []string{"GET", "GET"} }, "twice"},
		{"a body limit for something that is not a method", func(c *Config) { c.BodyLimits = map[string]int64{"post it": 1} }, "bodyLimits"},
		{"a negative body limit", func(c *Config) { c.BodyLimits = map[string]int64{"POST": -1} }, "bodyLimits"},
		{"an absurd body limit", func(c *Config) { c.BodyLimits = map[string]int64{"POST": 1 << 40} }, "bodyLimits"},
		{"a body limit of zero is allowed", func(c *Config) { c.BodyLimits = map[string]int64{"GET": 0} }, ""},
		{"a negative default body limit", func(c *Config) { c.DefaultBodyLimit = -5 }, "defaultBodyLimit"},
		{"a limit with a burst and no period", func(c *Config) { c.Rate.Sustained = Limit{Burst: 5} }, "period"},
		{"a limit with a period and no burst", func(c *Config) { c.Rate.Burst = Limit{Per: time.Second} }, "burst"},
		{"a period of years", func(c *Config) { c.Rate.Sustained = Limit{Burst: 5, Per: 24 * 365 * time.Hour} }, "period"},
		{"a negative burst", func(c *Config) { c.Rate.AuthBurst = Limit{Burst: -1, Per: time.Second} }, "burst"},
		{"a burst larger than the sustained bucket", func(c *Config) {
			c.Rate.Sustained = Limit{Burst: 10, Per: time.Minute}
			c.Rate.Burst = Limit{Burst: 50, Per: time.Second}
		}, "burst limit cannot"},
		{"a burst slower than the sustained rate", func(c *Config) {
			c.Rate.Sustained = Limit{Burst: 600, Per: time.Second}
			c.Rate.Burst = Limit{Burst: 10, Per: time.Minute}
		}, "at least as fast"},
		{"an authentication burst larger than its bucket", func(c *Config) {
			c.Rate.AuthSustained = Limit{Burst: 5, Per: time.Minute}
			c.Rate.AuthBurst = Limit{Burst: 6, Per: time.Second}
		}, "authentication burst"},
		{"a negative address factor", func(c *Config) { c.Rate.AddrFactor = -1 }, "addrFactor"},
		{"an address factor of a million", func(c *Config) { c.Rate.AddrFactor = 1_000_000 }, "addrFactor"},
		{"too many keys", func(c *Config) { c.Rate.MaxKeys = maxMaxKeys + 1 }, "maxKeys"},
		{"a negative key count", func(c *Config) { c.Rate.MaxKeys = -1 }, "maxKeys"},
		{"learning that needs no observations", func(c *Config) { c.Learn.MinObservations = -3 }, "minObservations"},
		{"more required clients than the evidence can follow", func(c *Config) { c.Learn.MinClients = maxSlots + 1 }, "minClients"},
		{"a client share over a hundred percent", func(c *Config) { c.Learn.MaxClientShare = 101 }, "maxClientShare"},
		{"learning observation ceiling", func(c *Config) { c.Learn.MinObservations = 1_000_000 }, ""},
		{"learning observation overflow", func(c *Config) { c.Learn.MinObservations = 1_000_001 }, "minObservations"},
		{"required observation ceiling", func(c *Config) { c.Learn.RequiredMinObservations = 1_000_000 }, ""},
		{"required observation overflow", func(c *Config) { c.Learn.RequiredMinObservations = 1_000_001 }, "requiredMinObservations"},
		{"negative required observations", func(c *Config) { c.Learn.RequiredMinObservations = -1 }, "requiredMinObservations"},
		{"minimum client share", func(c *Config) { c.Learn.MaxClientShare = 1 }, ""},
		{"maximum client share", func(c *Config) { c.Learn.MaxClientShare = 100 }, ""},
		{"negative client share", func(c *Config) { c.Learn.MaxClientShare = -1 }, "maxClientShare"},
		{"minimum required percentage", func(c *Config) { c.Learn.RequiredPercent = 50 }, ""},
		{"maximum required percentage", func(c *Config) { c.Learn.RequiredPercent = 100 }, ""},
		{"excessive required percentage", func(c *Config) { c.Learn.RequiredPercent = 101 }, "requiredPercent"},
		{"negative required percentage", func(c *Config) { c.Learn.RequiredPercent = -1 }, "requiredPercent"},
		{"agreement count ceiling", func(c *Config) { c.Discovery.AgreeMinimum = 1_000_000 }, ""},
		{"excessive agreement count", func(c *Config) { c.Discovery.AgreeMinimum = 1_000_001 }, "agreeMinimum"},
		{"a required percentage that makes everything optional", func(c *Config) { c.Learn.RequiredPercent = 10 }, "requiredPercent"},
		{"more routes than the model can hold", func(c *Config) { c.Learn.MaxRoutes = MaxRoutes + 1 }, "maxRoutes"},
		{"fewer than two distinct values", func(c *Config) { c.Learn.DistinctValues = 1 }, "distinctValues"},
		{"a negative time to live", func(c *Config) { c.Learn.RouteTTL = -time.Hour }, "time to live"},
		{"a document limit above the hard cap", func(c *Config) { c.Discovery.MaxDocumentBytes = MaxDocumentBytes + 1 }, "maxDocumentBytes"},
		{"a negative agreement count", func(c *Config) { c.Discovery.AgreeMinimum = -1 }, "agreeMinimum"},
		{"a fetch allowed longer than the whole discovery", func(c *Config) {
			c.Discovery.FetchTimeout = time.Minute
			c.Discovery.Timeout = time.Second
		}, "longer than"},
		{"a negative timeout", func(c *Config) { c.Discovery.Timeout = -1 }, "negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.change(&c)
			err := c.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
			if tt.want == "" {
				g, err := New(c)
				if err != nil {
					t.Fatalf("New refused valid config: %v", err)
				}
				if err := g.SetConfig(c); err != nil {
					t.Fatalf("SetConfig refused valid config: %v", err)
				}
			}
			// A refused configuration must also be refused by New and SetConfig.
			if tt.want != "" {
				if _, err := New(c); err == nil {
					t.Error("New accepted it")
				}
				g, _ := testGuard(t, nil)
				if err := g.SetConfig(c); err == nil {
					t.Error("SetConfig accepted it")
				}
			}
		})
	}
}

func TestTheDefaultsAreWhatTheDocumentationSays(t *testing.T) {
	g, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config()
	want := Modes{Methods: ModeEnforce, BodySize: ModeEnforce, AuthRate: ModeEnforce, Rate: ModeMonitor, Format: ModeMonitor,
		MassAssign: ModeEnforce, Spec: ModeMonitor, Learned: ModeMonitor}
	if c.Modes != want || c.Mode != ModeEnforce {
		t.Fatalf("modes = %+v, mode = %v", c.Modes, c.Mode)
	}
	if c.Learn.MinObservations != 30 || c.Learn.MinClients != 3 || c.Learn.MaxClientShare != 20 || c.Learn.RequiredPercent != 95 || c.Learn.RequiredMinObservations != 20 || c.Learn.DistinctValues != 8 {
		t.Fatalf("learn = %+v", c.Learn)
	}
	if c.Discovery.AgreeMinimum != 20 || c.Discovery.ManualPromotion || c.Discovery.MaxDocumentBytes != 5<<20 {
		t.Fatalf("discovery = %+v", c.Discovery)
	}
	if strings.Join(c.Methods, " ") != "GET HEAD OPTIONS POST PUT PATCH DELETE" {
		t.Fatalf("methods = %v", c.Methods)
	}
	// Naming one body limit keeps the others, and naming one mode keeps the other defaults.
	g2, _ := New(Config{BodyLimits: map[string]int64{"post": 5}, Modes: Modes{Spec: ModeEnforce}})
	c2 := g2.Config()
	if c2.BodyLimits["POST"] != 5 || c2.BodyLimits["PUT"] != 1<<20 || c2.Modes.Spec != ModeEnforce || c2.Modes.Methods != ModeEnforce || c2.Modes.Rate != ModeMonitor {
		t.Fatalf("config = %+v", c2)
	}
}

func TestParseConfigIsStrict(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty object", `{}`, true},
		{"modes by name", `{"modes":{"spec":"enforce","rate":"off"}}`, true},
		{"a misspelt field", `{"modess":{}}`, false},
		{"a field of a nested object that does not exist", `{"rate":{"sustainedd":{"burst":1,"per":1000000}}}`, false},
		{"a mode that does not exist", `{"modes":{"spec":"yes"}}`, false},
		{"a mode as a number", `{"modes":{"spec":3}}`, false},
		{"a value out of range", `{"learn":{"maxClientShare":500}}`, false},
		{"data after the object", `{} {}`, false},
		{"not JSON", `modes: enforce`, false},
		{"too large", `{"methods":["` + strings.Repeat("A", 2<<20) + `"]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	c, err := ParseConfig([]byte(`{"modes":{"spec":"enforce"},"rate":{"burst":{"burst":10,"per":1000000000},"sustained":{"burst":100,"per":60000000000}}}`))
	if err != nil || c.Modes.Spec != ModeEnforce || c.Rate.Burst.Burst != 10 {
		t.Fatalf("c = %+v, err = %v", c, err)
	}
}

func TestSettingModesAtRunTime(t *testing.T) {
	g, _ := testGuard(t, nil)
	if res := g.Inspect(mk("TRACE", "/api/x")); !blocked(res) {
		t.Fatal("setup")
	}
	if err := g.SetMode(ModeMonitor); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("TRACE", "/api/x")); blocked(res) || len(res.Verdicts) == 0 {
		t.Fatalf("monitor must report and not block: %+v", res.Verdicts)
	}
	if err := g.SetMode(ModeOff); err != nil {
		t.Fatal(err)
	}
	if res := g.Inspect(mk("TRACE", "/api/x")); len(res.Verdicts) != 0 {
		t.Fatalf("off must say nothing: %+v", res.Verdicts)
	}
	if err := g.SetMode(Mode(42)); err == nil {
		t.Fatal("a mode that does not exist was accepted")
	}
	if g.Config().Mode != ModeOff {
		t.Fatal("a refused change altered the configuration")
	}
}

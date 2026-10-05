// SPDX-License-Identifier: Apache-2.0

package apiguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Mode says what a protection does when it finds something.
type Mode int

const (
	// ModeDefault is the zero value: use the documented default for this protection. It is what a Config that says nothing gets.
	ModeDefault Mode = iota
	// ModeOff does nothing: no verdict, and for the learned model, no learning.
	ModeOff
	// ModeLearn observes and records and says nothing. It only means something for the learned model; for the other protections
	// it is the same as off.
	ModeLearn
	// ModeMonitor reports what it finds as a verdict that does not block, so the proxy logs it and lets the request go on.
	ModeMonitor
	// ModeEnforce reports what it finds as a verdict that blocks.
	ModeEnforce
)

var modeNames = [...]string{ModeDefault: "default", ModeOff: "off", ModeLearn: "learn", ModeMonitor: "monitor", ModeEnforce: "enforce"}

func (m Mode) String() string {
	if m < 0 || int(m) >= len(modeNames) {
		return fmt.Sprintf("mode(%d)", int(m))
	}
	return modeNames[m]
}

// MarshalText writes the mode as its name.
func (m Mode) MarshalText() ([]byte, error) {
	if m < 0 || int(m) >= len(modeNames) {
		return nil, fmt.Errorf("unknown mode %d", int(m))
	}
	return []byte(modeNames[m]), nil
}

// UnmarshalText reads a mode by name; an unknown name is an error, not the default.
func (m *Mode) UnmarshalText(b []byte) error {
	for i, n := range modeNames {
		if string(b) == n {
			*m = Mode(i)
			return nil
		}
	}
	return fmt.Errorf("unknown mode %q (use off, learn, monitor or enforce)", clean(string(b), 20))
}

// Modes sets what each protection does. Every field left at ModeDefault takes the default shown.
//
// The defaults are chosen so that a site with no configuration is protected against the clear-cut abuse at once and is only
// watched for the rest:
//
//	Methods      enforce  a method that is not on the allow-list is not an API method
//	BodySize     enforce  a body larger than any real request to that method
//	AuthRate     enforce  too many attempts at login, token, password reset and the like (credential stuffing)
//	Rate         monitor  too many requests from one client
//	Format       monitor  no Content-Type, an unseen one, or a body that is not the JSON it says it is
//	MassAssign   enforce  a privileged property, but it blocks only where the description or what was learned says clients never
//	             send it; elsewhere the finding is a warning (see docs/apiguard.md for why)
//	Spec         monitor  a request that does not fit the API's description (level 1)
//	Learned      monitor  a request that does not fit what the guard learned (level 2)
//
// The owner promotes Spec and Learned to enforce, per site, when the findings in monitor have been read.
type Modes struct {
	Methods    Mode `json:"methods,omitempty"`
	BodySize   Mode `json:"bodySize,omitempty"`
	AuthRate   Mode `json:"authRate,omitempty"`
	Rate       Mode `json:"rate,omitempty"`
	Format     Mode `json:"format,omitempty"`
	MassAssign Mode `json:"massAssign,omitempty"`
	Spec       Mode `json:"spec,omitempty"`
	Learned    Mode `json:"learned,omitempty"`
}

// defaultModes is the table above.
var defaultModes = Modes{Methods: ModeEnforce, BodySize: ModeEnforce, AuthRate: ModeEnforce, Rate: ModeMonitor, Format: ModeMonitor,
	MassAssign: ModeEnforce, Spec: ModeMonitor, Learned: ModeMonitor}

// RateConfig sets the per-client limits. A zero field takes the default.
type RateConfig struct {
	// Sustained is the long-run rate and Burst the short one, both for one client (an address with the credential it presents).
	Sustained Limit `json:"sustained"`
	Burst     Limit `json:"burst"`
	// AuthSustained and AuthBurst are the limits on authentication endpoints, kept for the address alone, because a client
	// guessing credentials changes the credential with every try.
	AuthSustained Limit `json:"authSustained"`
	AuthBurst     Limit `json:"authBurst"`
	// AddrFactor multiplies the general limits for the address as a whole, which is counted as well as the client when a
	// credential is presented, so that changing the credential does not escape the limit. Several users behind one address
	// share it, which is why it is a multiple.
	AddrFactor int `json:"addrFactor"`
	// MaxKeys is how many clients are followed at once.
	MaxKeys int `json:"maxKeys"`
}

// LearnConfig sets what the guard needs before it believes what it saw, and how much it may remember.
type LearnConfig struct {
	// MinObservations, MinClients and MaxClientShare (percent) are the evidence rule: a route or a parameter is enforceable when it
	// has been seen this often, from this many different clients, with none of them more than this share.
	MinObservations int `json:"minObservations"`
	MinClients      int `json:"minClients"`
	MaxClientShare  int `json:"maxClientShare"`
	// RequiredMinObservations and RequiredPercent say when a property is required: seen in at least this percent of at least
	// this many objects.
	RequiredMinObservations int `json:"requiredMinObservations"`
	RequiredPercent         int `json:"requiredPercent"`
	// MaxRoutes, MaxPositions and MaxNodes bound memory: learned routes, path positions followed, and body shape and parameter
	// records in all.
	MaxRoutes    int `json:"maxRoutes"`
	MaxPositions int `json:"maxPositions"`
	MaxNodes     int `json:"maxNodes"`
	// DistinctValues is how many different words a path position may hold before it is read as a parameter, once enough has
	// been seen there.
	DistinctValues int `json:"distinctValues"`
	// LearningTTL and RouteTTL are how long a route may go unseen before it is forgotten, while it is still being learned and
	// after it became enforceable.
	LearningTTL time.Duration `json:"learningTTL"`
	RouteTTL    time.Duration `json:"routeTTL"`
}

// DiscoveryConfig sets how a described model is found and promoted.
type DiscoveryConfig struct {
	// ManualPromotion turns off the automatic rule: by default a discovered description becomes active when it has agreed with
	// AgreeMinimum observed requests, and with this set it waits for Promote.
	ManualPromotion bool `json:"manualPromotion,omitempty"`
	// AgreeMinimum is how many requests, answered below 400, a candidate must fit before it is promoted. Those requests are held
	// to the same evidence rule as learned knowledge (several clients, none with too large a share).
	AgreeMinimum int `json:"agreeMinimum"`
	// MaxDocumentBytes is the largest description that is read; it can be lowered, never raised above MaxDocumentBytes.
	MaxDocumentBytes int `json:"maxDocumentBytes"`
	// FetchTimeout limits one fetch and Timeout all of a discovery.
	FetchTimeout time.Duration `json:"fetchTimeout"`
	Timeout      time.Duration `json:"timeout"`
}

// Config sets up one Guard. The zero value is valid and means "all the defaults".
type Config struct {
	// Mode caps everything: ModeOff switches the guard off, ModeLearn only learns, ModeMonitor never blocks whatever Modes say,
	// and ModeEnforce (the default) lets each protection act as its own mode says.
	Mode  Mode  `json:"mode,omitempty"`
	Modes Modes `json:"modes"`

	// Methods are the methods an API request may use (default GET HEAD OPTIONS POST PUT PATCH DELETE).
	Methods []string `json:"methods,omitempty"`
	// BodyLimits is the largest body, in bytes, for each method. A method not listed uses DefaultBodyLimit.
	BodyLimits       map[string]int64 `json:"bodyLimits,omitempty"`
	DefaultBodyLimit int64            `json:"defaultBodyLimit,omitempty"`

	Rate      RateConfig      `json:"rate"`
	Learn     LearnConfig     `json:"learn"`
	Discovery DiscoveryConfig `json:"discovery"`

	// RefuseUnknownParams makes a query parameter that a described route does not list a finding. Off by default, because
	// clients add parameters (cache busters, tracking) that the description never lists.
	RefuseUnknownParams bool `json:"refuseUnknownParams,omitempty"`

	// Clock gives the time. Nil means the system clock; tests give their own.
	Clock func() time.Time `json:"-"`
}

const (
	maxBodyLimit = 64 << 20
	maxMaxKeys   = 10_000_000
)

// allowedMethodNames is the default allow-list.
var defaultMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// DefaultConfig returns the configuration a new site gets, with every field filled in.
func DefaultConfig() Config {
	return Config{
		Mode:    ModeEnforce,
		Modes:   defaultModes,
		Methods: slices.Clone(defaultMethods),
		BodyLimits: map[string]int64{
			"GET": 16 << 10, "HEAD": 0, "OPTIONS": 4 << 10, "DELETE": 16 << 10,
			"POST": 1 << 20, "PUT": 1 << 20, "PATCH": 1 << 20,
		},
		DefaultBodyLimit: 64 << 10,
		Rate: RateConfig{
			Sustained:     Limit{Burst: 1200, Per: time.Minute},
			Burst:         Limit{Burst: 40, Per: time.Second},
			AuthSustained: Limit{Burst: 30, Per: time.Minute},
			AuthBurst:     Limit{Burst: 10, Per: 10 * time.Second},
			AddrFactor:    4,
			MaxKeys:       100_000,
		},
		Learn: LearnConfig{
			MinObservations: 30, MinClients: 3, MaxClientShare: 20,
			RequiredMinObservations: 20, RequiredPercent: 95,
			MaxRoutes: 2000, MaxPositions: 4096, MaxNodes: 200_000,
			DistinctValues: 8,
			LearningTTL:    7 * 24 * time.Hour, RouteTTL: 30 * 24 * time.Hour,
		},
		Discovery: DiscoveryConfig{
			AgreeMinimum: 20, MaxDocumentBytes: MaxDocumentBytes,
			FetchTimeout: 10 * time.Second, Timeout: 60 * time.Second,
		},
	}
}

// withDefaults fills every unset field from DefaultConfig. A field that was set is left alone, so Validate sees what was asked for.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Mode == ModeDefault {
		c.Mode = d.Mode
	}
	fill := func(m *Mode, def Mode) {
		if *m == ModeDefault {
			*m = def
		}
	}
	fill(&c.Modes.Methods, d.Modes.Methods)
	fill(&c.Modes.BodySize, d.Modes.BodySize)
	fill(&c.Modes.AuthRate, d.Modes.AuthRate)
	fill(&c.Modes.Rate, d.Modes.Rate)
	fill(&c.Modes.Format, d.Modes.Format)
	fill(&c.Modes.MassAssign, d.Modes.MassAssign)
	fill(&c.Modes.Spec, d.Modes.Spec)
	fill(&c.Modes.Learned, d.Modes.Learned)
	if len(c.Methods) == 0 {
		c.Methods = d.Methods
	}
	// A method's limit that the owner did not give is the default's, so naming one limit does not drop the others.
	limits := make(map[string]int64, len(d.BodyLimits))
	for k, v := range d.BodyLimits {
		limits[k] = v
	}
	for k, v := range c.BodyLimits {
		limits[strings.ToUpper(k)] = v
	}
	c.BodyLimits = limits
	if c.DefaultBodyLimit == 0 {
		c.DefaultBodyLimit = d.DefaultBodyLimit
	}
	lim := func(l *Limit, def Limit) {
		if l.Burst == 0 && l.Per == 0 {
			*l = def
		}
	}
	lim(&c.Rate.Sustained, d.Rate.Sustained)
	lim(&c.Rate.Burst, d.Rate.Burst)
	lim(&c.Rate.AuthSustained, d.Rate.AuthSustained)
	lim(&c.Rate.AuthBurst, d.Rate.AuthBurst)
	if c.Rate.AddrFactor == 0 {
		c.Rate.AddrFactor = d.Rate.AddrFactor
	}
	if c.Rate.MaxKeys == 0 {
		c.Rate.MaxKeys = d.Rate.MaxKeys
	}
	ints := []struct {
		p *int
		d int
	}{
		{&c.Learn.MinObservations, d.Learn.MinObservations}, {&c.Learn.MinClients, d.Learn.MinClients},
		{&c.Learn.MaxClientShare, d.Learn.MaxClientShare}, {&c.Learn.RequiredMinObservations, d.Learn.RequiredMinObservations},
		{&c.Learn.RequiredPercent, d.Learn.RequiredPercent}, {&c.Learn.MaxRoutes, d.Learn.MaxRoutes},
		{&c.Learn.MaxPositions, d.Learn.MaxPositions}, {&c.Learn.MaxNodes, d.Learn.MaxNodes},
		{&c.Learn.DistinctValues, d.Learn.DistinctValues}, {&c.Discovery.AgreeMinimum, d.Discovery.AgreeMinimum},
		{&c.Discovery.MaxDocumentBytes, d.Discovery.MaxDocumentBytes},
	}
	for _, f := range ints {
		if *f.p == 0 {
			*f.p = f.d
		}
	}
	if c.Learn.LearningTTL == 0 {
		c.Learn.LearningTTL = d.Learn.LearningTTL
	}
	if c.Learn.RouteTTL == 0 {
		c.Learn.RouteTTL = d.Learn.RouteTTL
	}
	if c.Discovery.FetchTimeout == 0 {
		c.Discovery.FetchTimeout = d.Discovery.FetchTimeout
	}
	if c.Discovery.Timeout == 0 {
		c.Discovery.Timeout = d.Discovery.Timeout
	}
	return c
}

// Validate checks a configuration strictly: a mode that does not exist, a limit that is negative or absurd, a method that is not a
// method, a burst that is larger than the sustained limit it sits inside, a learning rule that cannot be met. Fields left at their
// zero value mean "the default" and are valid. Validate does not change the Config.
func (c Config) Validate() error {
	modes := []struct {
		name string
		m    Mode
	}{
		{"mode", c.Mode}, {"modes.methods", c.Modes.Methods}, {"modes.bodySize", c.Modes.BodySize}, {"modes.authRate", c.Modes.AuthRate},
		{"modes.rate", c.Modes.Rate}, {"modes.format", c.Modes.Format}, {"modes.massAssign", c.Modes.MassAssign},
		{"modes.spec", c.Modes.Spec}, {"modes.learned", c.Modes.Learned},
	}
	for _, m := range modes {
		if m.m < ModeDefault || m.m > ModeEnforce {
			return fmt.Errorf("%s: %d is not a mode", m.name, int(m.m))
		}
	}
	seen := map[string]bool{}
	for _, m := range c.Methods {
		if !validMethodToken(m) {
			return fmt.Errorf("methods: %q is not an upper-case method name", clean(m, 20))
		}
		if seen[m] {
			return fmt.Errorf("methods: %s is listed twice", m)
		}
		seen[m] = true
	}
	for m, n := range c.BodyLimits {
		if !validMethodToken(strings.ToUpper(m)) {
			return fmt.Errorf("bodyLimits: %q is not a method name", clean(m, 20))
		}
		if n < 0 || n > maxBodyLimit {
			return fmt.Errorf("bodyLimits[%s]: %d is outside 0 to %d", clean(m, 20), n, int64(maxBodyLimit))
		}
	}
	if c.DefaultBodyLimit < 0 || c.DefaultBodyLimit > maxBodyLimit {
		return fmt.Errorf("defaultBodyLimit: %d is outside 0 to %d", c.DefaultBodyLimit, int64(maxBodyLimit))
	}
	if err := c.Rate.validate(); err != nil {
		return err
	}
	if err := c.Learn.validate(); err != nil {
		return err
	}
	return c.Discovery.validate()
}

func (l Limit) validate(name string) error {
	if l.Burst == 0 && l.Per == 0 {
		return nil
	}
	if l.Burst < 1 || l.Burst > 10_000_000 {
		return fmt.Errorf("rate.%s: burst %d is outside 1 to 10,000,000", name, l.Burst)
	}
	if l.Per < time.Millisecond || l.Per > 24*time.Hour {
		return fmt.Errorf("rate.%s: the period %v is outside 1ms to 24h", name, l.Per)
	}
	return nil
}

func (r RateConfig) validate() error {
	for _, l := range []struct {
		n string
		l Limit
	}{{"sustained", r.Sustained}, {"burst", r.Burst}, {"authSustained", r.AuthSustained}, {"authBurst", r.AuthBurst}} {
		if err := l.l.validate(l.n); err != nil {
			return err
		}
	}
	d := DefaultConfig().Rate
	pick := func(l, def Limit) Limit {
		if l.Burst == 0 && l.Per == 0 {
			return def
		}
		return l
	}
	s, b := pick(r.Sustained, d.Sustained), pick(r.Burst, d.Burst)
	if b.Burst > s.Burst {
		return errors.New("rate: the burst limit cannot allow more requests than the sustained limit's bucket holds")
	}
	if b.rate() < s.rate() {
		return errors.New("rate: the burst limit must be at least as fast as the sustained limit, or it is the only one that applies")
	}
	as, ab := pick(r.AuthSustained, d.AuthSustained), pick(r.AuthBurst, d.AuthBurst)
	if ab.Burst > as.Burst {
		return errors.New("rate: the authentication burst limit cannot allow more requests than the authentication sustained limit's bucket holds")
	}
	if r.AddrFactor < 0 || r.AddrFactor > 1000 {
		return fmt.Errorf("rate.addrFactor: %d is outside 1 to 1000", r.AddrFactor)
	}
	if r.MaxKeys < 0 || r.MaxKeys > maxMaxKeys {
		return fmt.Errorf("rate.maxKeys: %d is outside 1 to %d", r.MaxKeys, maxMaxKeys)
	}
	return nil
}

func (l LearnConfig) validate() error {
	in := func(name string, v, lo, hi int) error {
		if v != 0 && (v < lo || v > hi) {
			return fmt.Errorf("learn.%s: %d is outside %d to %d", name, v, lo, hi)
		}
		return nil
	}
	for _, c := range []struct {
		n         string
		v, lo, hi int
	}{
		{"minObservations", l.MinObservations, 1, 1_000_000}, {"minClients", l.MinClients, 1, maxSlots},
		{"maxClientShare", l.MaxClientShare, 1, 100}, {"requiredMinObservations", l.RequiredMinObservations, 1, 1_000_000},
		{"requiredPercent", l.RequiredPercent, 50, 100}, {"maxRoutes", l.MaxRoutes, 1, MaxRoutes},
		{"maxPositions", l.MaxPositions, 1, 1_000_000}, {"maxNodes", l.MaxNodes, 100, 5_000_000},
		{"distinctValues", l.DistinctValues, 2, 64},
	} {
		if err := in(c.n, c.v, c.lo, c.hi); err != nil {
			return err
		}
	}
	if l.LearningTTL < 0 || l.RouteTTL < 0 {
		return errors.New("learn: a time to live cannot be negative")
	}
	return nil
}

func (d DiscoveryConfig) validate() error {
	if d.AgreeMinimum < 0 || d.AgreeMinimum > 1_000_000 {
		return fmt.Errorf("discovery.agreeMinimum: %d is outside 1 to 1,000,000", d.AgreeMinimum)
	}
	if d.MaxDocumentBytes < 0 || d.MaxDocumentBytes > MaxDocumentBytes {
		return fmt.Errorf("discovery.maxDocumentBytes: %d is outside 1 to %d", d.MaxDocumentBytes, MaxDocumentBytes)
	}
	if d.FetchTimeout < 0 || d.Timeout < 0 {
		return errors.New("discovery: a timeout cannot be negative")
	}
	if d.FetchTimeout > d.Timeout && d.Timeout != 0 {
		return errors.New("discovery: one fetch cannot be allowed longer than the whole discovery")
	}
	return nil
}

// ParseConfig reads a configuration from JSON, strictly: a field that is not part of the configuration is an error, so a
// misspelt setting is found instead of ignored. What the document leaves out takes the default.
func ParseConfig(data []byte) (Config, error) {
	if len(data) > 1<<20 {
		return Config{}, errors.New("the configuration is larger than 1 MiB")
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("the configuration is not valid: %w", err)
	}
	if dec.More() {
		return Config{}, errors.New("the configuration has data after the object")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// effective is the mode a protection really runs in, given the guard-wide cap.
func effective(master, own Mode) Mode {
	return min(master, own)
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

const maxSiteConfigBytes = 64 << 10

// loadSiteConfig uses registered CLI types and validators rather than a second
// set of defaults. Explicit CLI flags override file settings. Files are operator
// configuration, never customer-submitted or automatically fetched.
func loadSiteConfig(path string, flags *flag.FlagSet) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("site configuration: %w", err)
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("site configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxSiteConfigBytes {
		return errors.New("site configuration must be a regular file of at most 64 KiB (no symlinks)")
	}
	file, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("site configuration: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.New("site configuration changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSiteConfigBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxSiteConfigBytes || !utf8.Valid(data) {
		return errors.New("site configuration is too large or is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("site configuration must be a JSON object")
	}
	seen := map[string]bool{}
	values := map[string]string{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return errors.New("invalid site configuration field")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return errors.New("duplicate site configuration field")
		}
		seen[name] = true
		switch name {
		case "version":
			value, err := dec.Token()
			if err != nil || value != json.Number("1") {
				return errors.New("site configuration version must be 1")
			}
		case "flags":
			value, err := dec.Token()
			if err != nil || value != json.Delim('{') {
				return errors.New("site configuration flags must be an object")
			}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return errors.New("invalid site configuration flag")
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("invalid site configuration flag")
				}
				if _, duplicate := values[name]; duplicate {
					return fmt.Errorf("duplicate site configuration flag %q", name)
				}
				setting := flags.Lookup(name)
				if setting == nil || name == "config" || name == "check" || name == "check-origin" || name == "check-origin-http" || name == "probe" || name == "version" {
					return fmt.Errorf("unsupported site configuration flag %q", name)
				}
				value, err := dec.Token()
				if err != nil {
					return fmt.Errorf("invalid site configuration flag %q", name)
				}
				text, err := siteFlagValue(setting, value)
				if err != nil {
					return fmt.Errorf("site configuration flag %q: %w", name, err)
				}
				values[name] = text
			}
			if token, err := dec.Token(); err != nil || token != json.Delim('}') {
				return errors.New("invalid site configuration flags")
			}
		default:
			return fmt.Errorf("unknown site configuration field %q", name)
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid site configuration object")
	}
	if !seen["version"] || !seen["flags"] {
		return errors.New("site configuration requires version and flags")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data in site configuration")
	}
	explicit := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	for name, value := range values {
		if !explicit[name] {
			if err := flags.Set(name, value); err != nil {
				return fmt.Errorf("invalid site configuration flag %q", name)
			}
		}
	}
	return nil
}

func siteFlagValue(setting *flag.Flag, value any) (string, error) {
	getter, ok := setting.Value.(flag.Getter)
	if !ok {
		return "", errors.New("unsupported flag type")
	}
	switch getter.Get().(type) {
	case string:
		if text, ok := value.(string); ok {
			return text, nil
		}
		return "", errors.New("must be a JSON string")
	case bool:
		if b, ok := value.(bool); ok {
			return strconv.FormatBool(b), nil
		}
		return "", errors.New("must be a JSON boolean")
	case time.Duration:
		if text, ok := value.(string); ok {
			if _, err := time.ParseDuration(text); err == nil {
				return text, nil
			}
		}
		return "", errors.New("must be a duration string such as 2s")
	case int, int64:
		if n, ok := value.(json.Number); ok {
			bits := 64
			if _, native := getter.Get().(int); native {
				bits = strconv.IntSize
			}
			if _, err := strconv.ParseInt(string(n), 10, bits); err == nil {
				return string(n), nil
			}
		}
		return "", errors.New("must be a representable JSON integer")
	case float64:
		if n, ok := value.(json.Number); ok {
			if _, err := strconv.ParseFloat(string(n), 64); err == nil {
				return string(n), nil
			}
		}
		return "", errors.New("must be a finite JSON number")
	default:
		return "", errors.New("unsupported flag type")
	}
}

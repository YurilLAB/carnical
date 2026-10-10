// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Private settings contain infrastructure details and references to credentials,
// never the contents of the credential files themselves.
func privateSiteFlag(name string) bool {
	switch name {
	case "upstream", "upstream-host", "origin-allow", "trusted-proxies", "tls-cert", "tls-key",
		"origin-client-cert", "origin-client-key", "origin-ca-file", "api-spec":
		return true
	default:
		return false
	}
}

type sitePrivate struct {
	KeyID  string `json:"key-id"`
	Sealed string `json:"sealed"`
}

type siteDocument struct {
	Version int            `json:"version"`
	Flags   map[string]any `json:"flags"`
	Private *sitePrivate   `json:"private,omitempty"`
}

func validateSiteKeyID(id string) error {
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id {
		return errors.New("invalid site encryption key ID")
	}
	return nil
}

func siteKeyPath(id string) (string, error) {
	if err := validateSiteKeyID(id); err != nil {
		return "", err
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errors.New("cannot find the user configuration directory; use -config-key-file")
	}
	return filepath.Join(dir, "carnical", "keys", id+".key"), nil
}

func siteCipher(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("site encryption key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// The standard library generates and prefixes the nonce, avoiding caller
	// nonce reuse. Each setup also creates an independent random 256-bit key.
	return cipher.NewGCMWithRandomNonce(block)
}

func sealSiteSettings(settings map[string]any, id string, key []byte) (*sitePrivate, error) {
	plain, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	aead, err := siteCipher(key)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nil, plain, []byte("carnical/site/v1/private/"+id)) // #nosec G407 -- NewGCMWithRandomNonce requires nil and generates a fresh 96-bit nonce inside Seal.
	return &sitePrivate{KeyID: id, Sealed: base64.StdEncoding.EncodeToString(sealed)}, nil
}

func openSiteSettings(private *sitePrivate, keyPath string) ([]byte, error) {
	if err := validateSiteKeyID(private.KeyID); err != nil {
		return nil, err
	}
	if keyPath == "" {
		var err error
		keyPath, err = siteKeyPath(private.KeyID)
		if err != nil {
			return nil, err
		}
	}
	key, err := readSiteFile(keyPath, 32, true)
	if err != nil {
		return nil, fmt.Errorf("site encryption key: %w", err)
	}
	defer clear(key)
	aead, err := siteCipher(key)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(private.Sealed)
	if err != nil || len(sealed) < aead.Overhead() {
		return nil, errors.New("invalid encrypted site settings")
	}
	plain, err := aead.Open(nil, nil, sealed, []byte("carnical/site/v1/private/"+private.KeyID))
	if err != nil {
		return nil, errors.New("cannot authenticate encrypted site settings (wrong key or changed data)")
	}
	return plain, nil
}

// readSiteFile pins the parent directory and checks the opened file's identity.
// The separate key additionally needs private permissions/ACLs.
func readSiteFile(path string, limit int64, private bool) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("must be a regular file within the size limit (no symlinks)")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	if private {
		if err := checkPrivateSiteFile(file); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("cannot read file within the size limit")
	}
	return data, nil
}

// writeNewSiteFile creates exclusively and secures the empty file before any
// contents are written. It never truncates an existing configuration or key.
func writeNewSiteFile(path string, data []byte) (err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	file, err := createSiteFile(root, name)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	defer func() {
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil && statErr == nil {
			current, lookupErr := root.Lstat(name)
			if lookupErr == nil && os.SameFile(info, current) {
				err = errors.Join(err, root.Remove(name))
			}
		}
	}()
	if statErr != nil {
		return statErr
	}
	if err := protectSiteFile(file); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func newSiteKeyID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	return hex.EncodeToString(id), nil
}

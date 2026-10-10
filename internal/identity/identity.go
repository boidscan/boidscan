// Package identity loads or creates the node's Ed25519 key.
package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/boidscan/boidscan/pkg/sig"
)

type Key struct {
	priv ed25519.PrivateKey
	id   string
}

func New(priv ed25519.PrivateKey) *Key {
	return &Key{priv: priv, id: sig.EncodeID(priv.Public().(ed25519.PublicKey))}
}

func Generate() (*Key, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return New(priv), nil
}

func (k *Key) ID() string { return k.id }

func (k *Key) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// Load reads the key at path, creating it first if it does not exist. The
// serve and scan processes may race on the first start; the link makes
// creation atomic so both end up with the same key.
func Load(path string) (*Key, error) {
	if k, err := read(path); !errors.Is(err, fs.ErrNotExist) {
		return k, err
	}
	k, err := Generate()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(tmp.Name(), path); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return read(path)
}

func read(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", path)
	}
	return New(priv), nil
}

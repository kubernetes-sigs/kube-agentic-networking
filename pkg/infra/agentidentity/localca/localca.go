/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package localca implements a CA whose state can be stored in a local file or
// Kubernetes secret.
package localca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"k8s.io/klog/v2"
)

// PoolWatcher loads a CA pool state file when constructed, and then watches the
// file state.  Every time the file is updated, it will parse the new pool
// definition, and begin using it if it is valid.
type PoolWatcher struct {
	filename string

	lock sync.Mutex
	pool *Pool
}

func NewPoolWatcher(filename string) (*PoolWatcher, error) {
	pw := &PoolWatcher{
		filename: filename,
	}

	if err := pw.Reload(); err != nil {
		return nil, fmt.Errorf("while loading initial CA pool state: %w", err)
	}

	return pw, nil
}

func (w *PoolWatcher) Reload() error {
	poolBytes, err := os.ReadFile(w.filename)
	if err != nil {
		return fmt.Errorf("while reading CA pool state: %w", err)
	}

	pool, err := Unmarshal(poolBytes)
	if err != nil {
		return fmt.Errorf("while unmarshaling SPIFFE ca pool state: %w", err)
	}

	w.lock.Lock()
	defer w.lock.Unlock()
	w.pool = pool

	return nil
}

func (w *PoolWatcher) Pool() *Pool {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.pool
}

// Run blocks the current goroutine, watching fsnotify events and reloading the
// CA state as needed.  If it fails to parse the new CA state, the old CA state
// is retained and an error is logged.
func (w *PoolWatcher) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error(err, "Fatal error while creating fsnotify.Watcher")
		return
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			logger.Error(err, "Error closing fsnotify.Watcher")
		}
	}()

	if err := watcher.Add(w.filename); err != nil {
		logger.Error(err, "Fatal error while adding watched path")
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-watcher.Events:
			if !ok {
				return
			}
			if evt.Has(fsnotify.Write) {
				logger.Info("CA pool file updated")

				if err := w.Reload(); err != nil {
					logger.Error(err, "Failed to load updated CA pool state; retaining existing state")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Error(err, "Fatal error from watcher.Errors")
			return
		}
	}
}

type Pool struct {
	CAs []*CA
}

type CA struct {
	ID                       string
	SigningKey               crypto.PrivateKey
	RootCertificate          *x509.Certificate
	IntermediateCertificates []*x509.Certificate
}

type serializedPool struct {
	CAs []*serializedCA
}
type serializedCA struct {
	ID                          string
	SigningKeyPKCS8             []byte
	RootCertificateDER          []byte
	IntermediateCertificatesDER [][]byte
}

// Marshal writes the given Pool to JSON.
func Marshal(ca *Pool) ([]byte, error) {
	wire := &serializedPool{}

	for _, ca := range ca.CAs {
		caWire := &serializedCA{}

		caWire.ID = ca.ID

		signingKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(ca.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("while serializing signing key to PKCS#8: %w", err)
		}

		caWire.SigningKeyPKCS8 = signingKeyPKCS8
		caWire.RootCertificateDER = ca.RootCertificate.Raw
		for _, intermediate := range ca.IntermediateCertificates {
			caWire.IntermediateCertificatesDER = append(caWire.IntermediateCertificatesDER, intermediate.Raw)
		}

		wire.CAs = append(wire.CAs, caWire)
	}

	wireBytes, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("while marshaling to JSON: %w", err)
	}

	return wireBytes, nil
}

// Unmarshal loads a pool from JSON.
func Unmarshal(wireBytes []byte) (*Pool, error) {
	var err error
	wire := &serializedPool{}

	if err := json.Unmarshal(wireBytes, wire); err != nil {
		return nil, fmt.Errorf("while unmarshaling JSON: %w", err)
	}

	pool := &Pool{}

	for _, wireCA := range wire.CAs {
		ca := &CA{
			ID: wireCA.ID,
		}

		ca.SigningKey, err = x509.ParsePKCS8PrivateKey(wireCA.SigningKeyPKCS8)
		if err != nil {
			return nil, fmt.Errorf("while parsing signing key: %w", err)
		}

		ca.RootCertificate, err = x509.ParseCertificate(wireCA.RootCertificateDER)
		if err != nil {
			return nil, fmt.Errorf("while parsing root certificate: %w", err)
		}

		for _, intermediateDER := range wireCA.IntermediateCertificatesDER {
			intermediateCert, err := x509.ParseCertificate(intermediateDER)
			if err != nil {
				return nil, fmt.Errorf("while parsing intermediate certificate: %w", err)
			}
			ca.IntermediateCertificates = append(ca.IntermediateCertificates, intermediateCert)
		}

		pool.CAs = append(pool.CAs, ca)
	}

	return pool, nil
}

// GenerateED25519CA creates new CA based on an ED25519 root key.
func GenerateED25519CA(id string) (*CA, error) {
	rootPubKey, rootPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("while generating root key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	rootTemplate := &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPubKey, rootPrivKey)
	if err != nil {
		return nil, fmt.Errorf("while generating root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("while parsing root certificate: %w", err)
	}

	return &CA{
		ID:              id,
		SigningKey:      rootPrivKey,
		RootCertificate: rootCert,
		// No intermediates.
	}, nil
}

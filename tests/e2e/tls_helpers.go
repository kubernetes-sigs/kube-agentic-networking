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

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

// generateCA creates a new CA for testing.
func generateCA(caID string) (*localca.CA, error) {
	return localca.GenerateED25519CA(caID)
}

// generateServerCert generates a server leaf certificate signed by the provided CA.
func generateServerCert(ca *localca.CA, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	serverPubKey, serverPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject:               pkix.Name{CommonName: "agentic-net-gateway"},
		DNSNames:              dnsNames,
	}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca.RootCertificate, serverPubKey, ca.SigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(serverPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	return certPEM, keyPEM, nil
}

// generateClientCert generates a client certificate signed by the provided CA.
func generateClientCert(ca *localca.CA) (certPEM, keyPEM []byte, err error) {
	clientPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate client key: %w", err)
	}
	clientPubKey := &clientPrivKey.PublicKey

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	clientTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Subject:               pkix.Name{CommonName: "test-client"},
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, ca.RootCertificate, clientPubKey, ca.SigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	// Append CA cert to client cert chain
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertificate.Raw})
	certPEM = append(certPEM, caCertPEM...)

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(clientPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	return certPEM, keyPEM, nil
}

// createTLSSecret creates a standard TLS Secret in Kubernetes.
func createTLSSecret(kc kubernetes.Interface, namespace, name string, certPEM, keyPEM []byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	_, err := kc.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	return err
}

// createCACertConfigMap creates a ConfigMap containing the CA certificate.
func createCACertConfigMap(kc kubernetes.Interface, namespace, name string, caCertPEM []byte) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string]string{
			"ca.crt": string(caCertPEM),
		},
	}

	_, err := kc.CoreV1().ConfigMaps(namespace).Create(context.TODO(), cm, metav1.CreateOptions{})
	return err
}

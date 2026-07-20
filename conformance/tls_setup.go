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

package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

// PrepareTLSResources reads the default agentic identity CA and prepares
// the Gateway server certificate Secret and client CA ConfigMap in the target namespace.
func PrepareTLSResources(ctx context.Context, clientset kubernetes.Interface, namespace string) error {
	// 1. Get default CA from system namespace
	ca, err := getAgenticIdentityDefaultCA(ctx, clientset)
	if err != nil {
		return fmt.Errorf("failed to get default CA: %w", err)
	}

	// 2. Generate server cert for Gateway
	// We use the Gateway service name or IP if known, but for conformance we can use common names
	dnsNames := []string{
		"conformance-primary",
		fmt.Sprintf("conformance-primary.%s", namespace),
		fmt.Sprintf("conformance-primary.%s.svc", namespace),
		fmt.Sprintf("conformance-primary.%s.svc.cluster.local", namespace),
	}
	serverCert, serverKey, err := generateServerCert(ca, dnsNames)
	if err != nil {
		return fmt.Errorf("failed to generate server cert: %w", err)
	}

	// 3. Create Secret for server cert
	err = createTLSSecret(ctx, clientset, namespace, "gateway-server-cert", serverCert, serverKey)
	if err != nil {
		return fmt.Errorf("failed to create server secret: %w", err)
	}

	// 4. Create ConfigMap for client CA
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertificate.Raw})
	err = createCACertConfigMap(ctx, clientset, namespace, "gateway-client-ca", caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to create client CA ConfigMap: %w", err)
	}

	return nil
}

func getAgenticIdentityDefaultCA(ctx context.Context, kc kubernetes.Interface) (*localca.CA, error) {
	secret, err := kc.CoreV1().Secrets("agentic-net-system").Get(ctx, "agentic-identity-ca-pool", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret agentic-identity-ca-pool: %w", err)
	}
	poolBytes, ok := secret.Data["ca-pool.json"]
	if !ok {
		return nil, fmt.Errorf("secret agentic-identity-ca-pool missing key ca-pool.json")
	}
	pool, err := localca.Unmarshal(poolBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CA pool: %w", err)
	}
	if len(pool.CAs) == 0 {
		return nil, fmt.Errorf("CA pool is empty")
	}
	return pool.CAs[0], nil
}

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
		Subject:               pkix.Name{CommonName: "conformance-primary"},
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

func createTLSSecret(ctx context.Context, kc kubernetes.Interface, namespace, name string, certPEM, keyPEM []byte) error {
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

	_, err := kc.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = kc.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

func createCACertConfigMap(ctx context.Context, kc kubernetes.Interface, namespace, name string, caCertPEM []byte) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Data: map[string]string{
			corev1.ServiceAccountRootCAKey: string(caCertPEM),
		},
	}

	_, err := kc.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = kc.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

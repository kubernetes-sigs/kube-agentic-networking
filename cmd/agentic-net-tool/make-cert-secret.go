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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/google/subcommands"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"

	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

type MakeCertSecretCommand struct {
	kubeConfig string

	caPoolSecretNamespace string
	caPoolSecretName      string

	namespace string
	name      string
	usage     string // "client" or "server"
}

var _ subcommands.Command = (*MakeCertSecretCommand)(nil)

func (*MakeCertSecretCommand) Name() string {
	return "make-cert-secret"
}

func (*MakeCertSecretCommand) Synopsis() string {
	return "Make a new secret that contains a client or server certificate signed by the in-cluster private CA"
}

func (*MakeCertSecretCommand) Usage() string {
	return ``
}

func (c *MakeCertSecretCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")

	f.StringVar(&c.caPoolSecretNamespace, "ca-pool-secret-namespace", "", "Namespace of the CA pool secret")
	f.StringVar(&c.caPoolSecretName, "ca-pool-secret-name", "", "Name of the CA pool secret")

	f.StringVar(&c.namespace, "namespace", "", "Create the secret in this namespace")
	f.StringVar(&c.name, "name", "", "Create the secret with this name")
	f.StringVar(&c.usage, "usage", "client", "Usage of the certificate ('client' or 'server')")
}

func (c *MakeCertSecretCommand) Execute(ctx context.Context, _ *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		klog.ErrorS(err, "Error while executing")
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *MakeCertSecretCommand) do(ctx context.Context) error {
	if c.usage != "client" && c.usage != "server" {
		return fmt.Errorf("invalid usage %q, must be 'client' or 'server'", c.usage)
	}

	// use the current context in kubeconfig
	kconfig, err := clientcmd.BuildConfigFromFlags("", c.kubeConfig)
	if err != nil {
		return fmt.Errorf("while reading kubeconfig: %w", err)
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	// 1. Fetch CA pool secret
	caSecret, err := kc.CoreV1().Secrets(c.caPoolSecretNamespace).Get(ctx, c.caPoolSecretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("while fetching CA pool secret: %w", err)
	}

	poolBytes, ok := caSecret.Data["ca-pool.json"]
	if !ok {
		return fmt.Errorf("CA pool secret does not contain 'ca-pool.json'")
	}

	// 2. Unmarshal CA pool
	pool, err := localca.Unmarshal(poolBytes)
	if err != nil {
		return fmt.Errorf("while unmarshaling CA pool: %w", err)
	}

	if len(pool.CAs) == 0 {
		return fmt.Errorf("CA pool is empty")
	}

	ca := pool.CAs[0]

	// 3. Generate subject key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("while generating subject key: %w", err)
	}

	// 4. Create certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("while generating serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Minute)
	// TODO: evaluate the use case of making the expiration configurable.
	// For now, it is set to 1 year.
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}

	if c.usage == "client" {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// 5. Sign certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.RootCertificate, pubKey, ca.SigningKey)
	if err != nil {
		return fmt.Errorf("while signing certificate: %w", err)
	}

	// 6. Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("while marshaling private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})

	// 7. Create secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      c.name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: privPEM,
		},
	}

	_, err = kc.CoreV1().Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("while creating TLS secret: %w", err)
	}

	return nil
}

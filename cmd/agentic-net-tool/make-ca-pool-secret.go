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
	"flag"
	"fmt"
	"path/filepath"

	"github.com/google/subcommands"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

type MakeCAPoolSecretCommand struct {
	kubeConfig string

	caID string

	namespace string
	name      string
}

var _ subcommands.Command = (*MakeCAPoolSecretCommand)(nil)

func (*MakeCAPoolSecretCommand) Name() string {
	return "make-ca-pool-secret"
}

func (*MakeCAPoolSecretCommand) Synopsis() string {
	return "Make a new secret that contains a CA pool to be used by a signing controller"
}

func (*MakeCAPoolSecretCommand) Usage() string {
	return ``
}

func (c *MakeCAPoolSecretCommand) SetFlags(f *flag.FlagSet) {
	kubeConfigDefault := ""
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}

	f.StringVar(&c.kubeConfig, "kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")

	f.StringVar(&c.caID, "ca-id", "", "The ID of the initial CA in the Pool")

	f.StringVar(&c.namespace, "namespace", "", "Create the secret in this namespace")
	f.StringVar(&c.name, "name", "", "Create the secret with this name")
}

func (c *MakeCAPoolSecretCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.do(ctx); err != nil {
		klog.ErrorS(err, "Error while executing")
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *MakeCAPoolSecretCommand) do(ctx context.Context) error {
	// use the current context in kubeconfig
	kconfig, err := clientcmd.BuildConfigFromFlags("", c.kubeConfig)
	if err != nil {
		return fmt.Errorf("while reading kubeconfig: %w", err)
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return fmt.Errorf("while creating Kubernetes client: %w", err)
	}

	ca, err := localca.GenerateED25519CA(c.caID)
	if err != nil {
		return fmt.Errorf("while generating CA: %w", err)
	}

	pool := &localca.Pool{
		CAs: []*localca.CA{
			ca,
		},
	}

	poolBytes, err := localca.Marshal(pool)
	if err != nil {
		return fmt.Errorf("while marshaling pool: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      c.name,
		},
		Data: map[string][]byte{
			"ca-pool.json": poolBytes,
		},
	}

	_, err = kc.CoreV1().Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("while uploading pool state to secret: %w", err)
	}

	return nil
}

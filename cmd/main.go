/*
Copyright 2025 The Kubernetes Authors.

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
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/controller"
	discovery "sigs.k8s.io/kube-agentic-networking/pkg/dicovery"
)

const (
	workerCount = 2
)

var (
	masterURL  string
	kubeconfig string
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// set up signals so we handle the shutdown signal gracefully
	ctx := context.Background()
	logger := klog.FromContext(ctx)

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		logger.Error(err, "Error building kubeconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building kubernetes clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	gatewayClientset, err := gatewayclient.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building Gateway API clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	agenticClientset, err := agenticclient.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building Agentic Networking clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
	sharedKubeInformers := kubeinformers.NewSharedInformerFactory(kubeClient, 60*time.Second)
	sharedGwInformers := gatewayinformers.NewSharedInformerFactory(gatewayClientset, 60*time.Second)
	sharedAgenticInformers := agenticinformers.NewSharedInformerFactory(agenticClientset, 60*time.Second)

	jwtIssuer, err := discovery.JWTIssuer(cfg)
	if err != nil {
		logger.Error(err, "Error discovering JWT issuer")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
	c, err := controller.New(
		ctx,
		jwtIssuer,
		kubeClient,
		gatewayClientset,
		agenticClientset,
		sharedKubeInformers.Core().V1().Namespaces(),
		sharedKubeInformers.Core().V1().Services(),
		sharedKubeInformers.Core().V1().Secrets(),
		sharedGwInformers.Gateway().V1().GatewayClasses(),
		sharedGwInformers.Gateway().V1().Gateways(),
		sharedGwInformers.Gateway().V1().HTTPRoutes(),
		sharedAgenticInformers.Agentic().V0alpha0().XBackends(),
		sharedAgenticInformers.Agentic().V0alpha0().XAccessPolicies())
	if err != nil {
		logger.Error(err, "Error creating controller")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(ctx.done())
	// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
	sharedKubeInformers.Start(ctx.Done())
	sharedGwInformers.Start(ctx.Done())
	sharedAgenticInformers.Start(ctx.Done())

	if err = c.Run(ctx, workerCount); err != nil {
		logger.Error(err, "Error running controller")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}

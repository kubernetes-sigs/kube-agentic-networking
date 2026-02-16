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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/types"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/controller"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/agenticidentitysigner"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/signercontroller"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/rendezvous"
)

var (
	kubeconfig   = flag.String("kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster. Leaving empty assumes in-cluster configuration.")
	apiServerURL = flag.String("apiserver-url", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster. Leaving empty assumes in-cluster configuration.")
	proxyImage   = flag.String("proxy-image", "", "The image of the envoy proxy.")
	workerCount  = flag.Int("worker-count", 2, "Number of workers for the controller")
	resyncPeriod = flag.Duration("resync-period", 10*time.Minute, "Informer resync period")

	shardingNamespace       = flag.String("sharding-pod-namespace", "", "(Work Sharding) The namespace the controller is running in")
	shardingPodName         = flag.String("sharding-pod-name", "", "(Work Sharding) The pod name of the controller")
	shardingPodUID          = flag.String("sharding-pod-uid", "", "(Work Sharding) The pod UID of the controller")
	shardingApplicationName = flag.String("sharding-application-name", "", "(Work Sharding) The application name to disambiguate Leases")

	enableAgenticIdentitySigner = flag.Bool("enable-agentic-identity-signer", false, fmt.Sprintf("Run controller for %s", agenticidentitysigner.Name))
	agenticIdentityTrustDomain  = flag.String("agentic-identity-trust-domain", "", "The SPIFFE trust domain for issued certificates")
	agenticIdentityCAPoolFile   = flag.String("agentic-identity-ca-pool", "", fmt.Sprintf("File that contains the CA pool state for %s", agenticidentitysigner.Name))
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// set up signals so we handle the shutdown signal gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	finishGroup := sync.WaitGroup{}

	if *proxyImage == "" {
		klog.ErrorS(fmt.Errorf("--proxy-image cannot be empty"), "Startup error")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	cfg, err := clientcmd.BuildConfigFromFlags(*apiServerURL, *kubeconfig)
	if err != nil {
		klog.ErrorS(err, "Error while building kubeconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "Error while initializing Kubernetes clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	gatewayClientset, err := gatewayclient.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "Error while building Gateway clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	agenticClientset, err := agenticclient.NewForConfig(cfg)
	if err != nil {
		klog.ErrorS(err, "Error while building Agentic Networking clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
	sharedKubeInformers := kubeinformers.NewSharedInformerFactory(kubeClient, *resyncPeriod)
	sharedGwInformers := gatewayinformers.NewSharedInformerFactory(gatewayClientset, *resyncPeriod)
	sharedAgenticInformers := agenticinformers.NewSharedInformerFactory(agenticClientset, *resyncPeriod)

	c, err := controller.New(
		ctx,
		*agenticIdentityTrustDomain,
		*proxyImage,
		kubeClient,
		gatewayClientset,
		agenticClientset,
		sharedKubeInformers.Core().V1().Namespaces(),
		sharedKubeInformers.Core().V1().Services(),
		sharedKubeInformers.Core().V1().Secrets(),
		sharedGwInformers.Gateway().V1().GatewayClasses(),
		sharedGwInformers.Gateway().V1().Gateways(),
		sharedGwInformers.Gateway().V1().HTTPRoutes(),
		sharedGwInformers.Gateway().V1beta1().ReferenceGrants(),
		sharedAgenticInformers.Agentic().V0alpha0().XBackends(),
		sharedAgenticInformers.Agentic().V0alpha0().XAccessPolicies())
	if err != nil {
		klog.ErrorS(err, "Error while creating agentic networking controller")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	finishGroup.Go(func() {
		if err := c.Run(ctx, *workerCount); err != nil {
			klog.ErrorS(err, "Error running the agentic networking controller")
		}
	})

	hasher := rendezvous.New(
		kubeClient,
		*shardingNamespace,
		*shardingApplicationName,
		*shardingPodName,
		types.UID(*shardingPodUID),
		clock.RealClock{},
	)
	finishGroup.Go(func() {
		if err := hasher.Run(ctx); err != nil {
			klog.ErrorS(err, "Error running the rendezvous hasher")
		}
	})

	if *enableAgenticIdentitySigner {
		if *agenticIdentityTrustDomain == "" {
			klog.ErrorS(nil, "--agentic-identity-trust-domain must be set")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}

		poolWatcher, err := localca.NewPoolWatcher(*agenticIdentityCAPoolFile)
		if err != nil {
			klog.ErrorS(err, "Error while creating CA pool watcher")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		finishGroup.Go(func() { poolWatcher.Run(ctx) })

		impl := agenticidentitysigner.NewImpl(*agenticIdentityTrustDomain, poolWatcher, clock.RealClock{})
		controller, err := signercontroller.New(clock.RealClock{}, impl, kubeClient, hasher)
		if err != nil {
			klog.ErrorS(err, "Error creating agentic identity signer controller")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
		finishGroup.Go(func() {
			if err := controller.Run(ctx); err != nil {
				klog.ErrorS(err, "Error running the agentic identity signer")
			}
		})
	}

	// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(ctx.done())
	// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
	sharedKubeInformers.Start(ctx.Done())
	sharedGwInformers.Start(ctx.Done())
	sharedAgenticInformers.Start(ctx.Done())

	// Block until we get a shutdown signal
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	<-signalCh

	// Give all controllers a chance for orderly shutdown.  If they take too
	// long, the process will get SIGKILLed, so this will not block forever.
	klog.InfoS("Cancelling root context and shutting down all subsystems")
	cancel()
	finishGroup.Wait()

	klog.FlushAndExit(klog.ExitFlushTimeout, 0)
}

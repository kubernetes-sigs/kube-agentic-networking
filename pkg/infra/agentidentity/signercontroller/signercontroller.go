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

package signercontroller

import (
	"context"
	"errors"
	"fmt"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	certinformersv1beta1 "k8s.io/client-go/informers/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	certlistersv1beta1 "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/rendezvous"
)

type SignerImpl interface {
	SignerName() string
	DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle
	MakeCert(context.Context, *certsv1beta1.PodCertificateRequest) (*certsv1beta1.PodCertificateRequest, error)
}

type Hasher interface {
	AssignedToThisReplica(ctx context.Context, item string) bool
}

// Controller is an in-memory signing controller for PodCertificateRequests.
type Controller struct {
	clock clock.PassiveClock

	kc          kubernetes.Interface
	pcrInformer cache.SharedIndexInformer
	pcrQueue    workqueue.TypedRateLimitingInterface[string]

	hasher Hasher

	handler SignerImpl
}

// New creates a new Controller.
func New(clock clock.PassiveClock, handler SignerImpl, kc kubernetes.Interface, hasher Hasher) (*Controller, error) {
	pcrInformer := certinformersv1beta1.NewFilteredPodCertificateRequestInformer(kc, metav1.NamespaceAll, 24*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("spec.signerName", handler.SignerName()).String()
		},
	)

	sc := &Controller{
		clock:       clock,
		kc:          kc,
		pcrInformer: pcrInformer,
		pcrQueue:    workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		handler:     handler,
		hasher:      hasher,
	}

	_, err := sc.pcrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		DeleteFunc: func(old any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("while registering event handlers: %w", err)
	}

	return sc, nil
}

func (c *Controller) Run(ctx context.Context) error {
	defer c.pcrQueue.ShutDown()
	go c.pcrInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrInformer.HasSynced) {
		return fmt.Errorf("caches never synced")
	}

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	go wait.JitterUntilWithContext(ctx, c.ensureBundle, 1*time.Minute, 1.0, true)
	<-ctx.Done()

	return nil
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	logger := klog.FromContext(ctx)

	key, quit := c.pcrQueue.Get()
	if quit {
		return false
	}
	defer c.pcrQueue.Done(key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.Error(err, "Error splitting key into namespace and name", "key", key)
		return true
	}

	pcr, err := certlistersv1beta1.NewPodCertificateRequestLister(c.pcrInformer.GetIndexer()).PodCertificateRequests(namespace).Get(name)
	if k8serrors.IsNotFound(err) {
		c.pcrQueue.Forget(key)
		return true
	} else if err != nil {
		logger.Error(err, "Error retrieving PodCertificateRequest", "key", key)
		return true
	}

	err = c.handlePCR(ctx, pcr)
	if errors.Is(err, rendezvous.ErrNotAssigned) {
		c.pcrQueue.AddRateLimited(key)
		return true
	}
	if err != nil {
		logger.Error(err, "Error handling PodCertificateRequest", "key", key)
		c.pcrQueue.AddRateLimited(key)
		return true
	}

	c.pcrQueue.Forget(key)
	return true
}

func (c *Controller) handlePCR(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	logger := klog.FromContext(ctx)

	if pcr.Spec.SignerName != c.handler.SignerName() {
		// Return nil, since we are not going to magically start supporting this
		// signer name by retaining the cert in the workqueue.
		return nil
	}

	// PodCertificateRequests don't have an approval stage, and the node
	// restriction / isolation check is handled by kube-apiserver.

	for _, cond := range pcr.Status.Conditions {
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeIssued {
			return nil
		}
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeDenied {
			return nil
		}
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeFailed {
			return nil
		}
	}

	if !c.hasher.AssignedToThisReplica(ctx, pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name) {
		return rendezvous.ErrNotAssigned
	}

	logger.Info("Processing PCR", "key", pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name)

	pcr = pcr.DeepCopy()
	pcr, err := c.handler.MakeCert(ctx, pcr)
	if err != nil {
		return fmt.Errorf("while converting PodCertificateRequest to x509.Certificate chain: %w", err)
	}

	_, err = c.kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating PodCertificateRequest: %w", err)
	}

	return nil
}

func (c *Controller) ensureBundle(ctx context.Context) {
	logger := klog.FromContext(ctx)

	// Only one replica should try to maintain the trust bundles.
	if !c.hasher.AssignedToThisReplica(ctx, "maintain-trust-bundles") {
		return
	}

	wantCTBs := c.handler.DesiredClusterTrustBundles()

	for _, wantCTB := range wantCTBs {
		ctb, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, wantCTB.ObjectMeta.Name, metav1.GetOptions{})
		if k8serrors.IsNotFound(err) {
			_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, wantCTB, metav1.CreateOptions{})
			if err != nil {
				logger.Error(err, "Error creating ClusterTrustBundle", "key", wantCTB.ObjectMeta.Name)
				return
			}
			return
		} else if err != nil {
			logger.Error(err, "Error getting ClusterTrustBundle", "key", wantCTB.ObjectMeta.Name)
			return
		}

		if apiequality.Semantic.DeepEqual(wantCTB.Labels, ctb.Labels) && apiequality.Semantic.DeepEqual(wantCTB.Spec, ctb.Spec) {
			logger.Info("ClusterTrustBundle already in correct state", "key", wantCTB.ObjectMeta.Name)
			return
		}

		ctb = ctb.DeepCopy()
		ctb.ObjectMeta.Labels = wantCTB.Labels
		ctb.Spec.TrustBundle = wantCTB.Spec.TrustBundle

		_, err = c.kc.CertificatesV1beta1().ClusterTrustBundles().Update(ctx, ctb, metav1.UpdateOptions{})
		if err != nil {
			logger.Error(err, "Error updating ClusterTrustBundle", "key", wantCTB.ObjectMeta.Name)
			return
		}
	}
}

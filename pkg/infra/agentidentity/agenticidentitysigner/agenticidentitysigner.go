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

package agenticidentitysigner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/signercontroller"
)

const Name = "kube-agentic-networking.sigs.k8s.io/identity"

const CTBPrefix = "kube-agentic-networking.sigs.k8s.io:identity:"

type caSource interface {
	Pool() *localca.Pool
}

type Impl struct {
	spiffeTrustDomain string
	caSource          caSource
	clock             clock.PassiveClock
}

func NewImpl(spiffeTrustDomain string, caSource caSource, clock clock.PassiveClock) *Impl {
	return &Impl{
		spiffeTrustDomain: spiffeTrustDomain,
		caSource:          caSource,
		clock:             clock,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

func (h *Impl) DesiredClusterTrustBundles() []*certsv1beta1.ClusterTrustBundle {
	name := CTBPrefix + "primary-bundle"

	curPool := h.caSource.Pool()

	wantTrustBundle := bytes.Buffer{}
	for _, ca := range curPool.CAs {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.RootCertificate.Raw,
		})
		_, _ = wantTrustBundle.Write(block)
	}

	wantCTB := &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kube-agentic-networking.sigs.k8s.io/canarying":             "live",
				"kube-agentic-networking.sigs.k8s.io/workload-trust-domain": h.spiffeTrustDomain,
				"kube-agentic-networking.sigs.k8s.io/peer-trust-domain":     h.spiffeTrustDomain,
			},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  Name,
			TrustBundle: wantTrustBundle.String(),
		},
	}

	return []*certsv1beta1.ClusterTrustBundle{
		wantCTB,
	}
}

func (h *Impl) MakeCert(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) (*certsv1beta1.PodCertificateRequest, error) {
	curPool := h.caSource.Pool()

	lifetime := 24 * time.Hour
	requestedLifetime := time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	if requestedLifetime < lifetime {
		lifetime = requestedLifetime
	}

	notBefore := h.clock.Now().Add(-2 * time.Minute)
	notAfter := notBefore.Add(lifetime)
	beginRefreshAt := notAfter.Add(-12 * time.Hour)

	spiffeURI := &url.URL{
		Scheme: "spiffe",
		Host:   h.spiffeTrustDomain,
		Path:   path.Join("ns", pcr.ObjectMeta.Namespace, "sa", pcr.Spec.ServiceAccountName),
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	// TODO: Once Kubernetes 1.36 releases, try to read Spec.StubPKCS10Request
	// first, then fall back to PKIXPublicKey.  PKIXPublicKey will not be
	// carried forward to v1 PodCertificateRequest.
	subjectPublicKey, err := x509.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return nil, fmt.Errorf("while parsing PKIX public key: %w", err)
	}

	subjectCertDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		curPool.CAs[0].RootCertificate,
		subjectPublicKey,
		curPool.CAs[0].SigningKey,
	)
	if err != nil {
		return nil, fmt.Errorf("while signing subject cert: %w", err)
	}

	chainDER := [][]byte{subjectCertDER}
	for _, intermed := range curPool.CAs[0].IntermediateCertificates {
		chainDER = append(chainDER, intermed.Raw)
	}

	chainPEM := &bytes.Buffer{}
	for _, certDER := range chainDER {
		err = pem.Encode(chainPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		if err != nil {
			return nil, fmt.Errorf("while encoding certificate to PEM: %w", err)
		}
	}

	pcr = pcr.DeepCopy()
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               certsv1beta1.PodCertificateRequestConditionTypeIssued,
			Status:             metav1.ConditionTrue,
			Reason:             "Issued",
			Message:            "Successfully issued",
			LastTransitionTime: metav1.NewTime(h.clock.Now()),
		},
	}
	pcr.Status.CertificateChain = chainPEM.String()
	pcr.Status.NotBefore = ptr.To(metav1.NewTime(notBefore))
	pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(beginRefreshAt))
	pcr.Status.NotAfter = ptr.To(metav1.NewTime(notAfter))

	return pcr, nil
}

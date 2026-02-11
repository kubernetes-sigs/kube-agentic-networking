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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	testclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/kube-agentic-networking/pkg/infra/agentidentity/localca"
)

type fakeCASource struct {
	pool *localca.Pool
}

var _ caSource = (*fakeCASource)(nil)

func (f *fakeCASource) Pool() *localca.Pool {
	return f.pool
}

func TestCertificateIssuance(t *testing.T) {
	_, caCert, caPrivKey := mustMakeCA(t)
	caSource := &fakeCASource{
		pool: &localca.Pool{
			CAs: []*localca.CA{
				{
					ID:              "1",
					SigningKey:      caPrivKey,
					RootCertificate: caCert,
				},
			},
		},
	}

	podUID1 := "pod-uid-1"
	_, _, ed25519PubPKIX1, ed25519Proof1, _ := mustMakeEd25519KeyAndProof(t, []byte(podUID1), []string{})

	testCases := []struct {
		name      string
		pcr       *certsv1beta1.PodCertificateRequest
		wantPCR   *certsv1beta1.PodCertificateRequest
		wantCerts []*x509.Certificate
	}{
		{
			name: "",
			pcr: &certsv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pcr-1",
				},
				Spec: certsv1beta1.PodCertificateRequestSpec{
					SignerName:           Name,
					PodName:              "pod-1",
					PodUID:               types.UID(podUID1),
					ServiceAccountName:   "sa-1",
					ServiceAccountUID:    "sa-1-uid",
					NodeName:             "node-1",
					NodeUID:              "node-uid-1",
					MaxExpirationSeconds: ptr.To[int32](24 * 60 * 60),
					PKIXPublicKey:        ed25519PubPKIX1,
					ProofOfPossession:    ed25519Proof1,
				},
			},
			wantPCR: &certsv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-1",
					Name:      "pcr-1",
				},
				Spec: certsv1beta1.PodCertificateRequestSpec{
					SignerName:           Name,
					PodName:              "pod-1",
					PodUID:               types.UID(podUID1),
					ServiceAccountName:   "sa-1",
					ServiceAccountUID:    "sa-1-uid",
					NodeName:             "node-1",
					NodeUID:              "node-uid-1",
					MaxExpirationSeconds: ptr.To[int32](24 * 60 * 60),
					PKIXPublicKey:        ed25519PubPKIX1,
					ProofOfPossession:    ed25519Proof1,
				},
				Status: certsv1beta1.PodCertificateRequestStatus{
					Conditions: []metav1.Condition{
						{
							Type:               "Issued",
							Status:             "True",
							Reason:             "Issued",
							Message:            "Successfully issued",
							LastTransitionTime: metav1.NewTime(mustRFC3339(t, "1970-01-01T00:00:00Z")),
						},
					},
					NotBefore:      ptr.To(metav1.NewTime(mustRFC3339(t, "1969-12-31T23:58:00Z"))),
					BeginRefreshAt: ptr.To(metav1.NewTime(mustRFC3339(t, "1970-01-01T11:58:00Z"))),
					NotAfter:       ptr.To(metav1.NewTime(mustRFC3339(t, "1970-01-01T23:58:00Z"))),
				},
			},
			wantCerts: []*x509.Certificate{
				{
					URIs: []*url.URL{
						{
							Scheme: "spiffe",
							Host:   "cluster1.myorg.example",
							Path:   "ns/ns-1/sa/sa-1",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()

			signer := &Impl{
				spiffeTrustDomain: "cluster1.myorg.example",
				caSource:          caSource,
				clock:             testclock.NewFakePassiveClock(mustRFC3339(t, "1970-01-01T00:00:00Z")),
			}

			gotPCR, err := signer.MakeCert(ctx, tc.pcr)
			if err != nil {
				t.Fatalf("Unexpected error issuing PCR: %v", err)
			}

			gotPCRNoCert := gotPCR.DeepCopy()
			gotPCRNoCert.Status.CertificateChain = ""
			if diff := cmp.Diff(gotPCRNoCert, tc.wantPCR); diff != "" {
				t.Fatalf("Got bad PCR; diff (-got +want)\n%s", diff)
			}

			var gotCerts []*x509.Certificate
			rest := []byte(gotPCR.Status.CertificateChain)
			for {
				var block *pem.Block
				block, rest = pem.Decode(rest)
				if block == nil {
					break
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatalf("Unexpected error parsing issued certificate")
				}

				// Blank out fields we don't care about diffing.
				cert.Raw = nil
				cert.RawIssuer = nil
				cert.RawSubject = nil
				cert.RawSubjectPublicKeyInfo = nil
				cert.RawTBSCertificate = nil
				cert.SerialNumber = nil

				gotCerts = append(gotCerts, cert)
			}

			if diff := cmp.Diff(gotCerts, tc.wantCerts); diff != "" {
				t.Fatalf("Got bad certificates; diff (-got +want)\n%s", diff)
			}
		})
	}

}

func mustRFC3339(t *testing.T, ts string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("Failed to parse timestamp: %v", err)
	}
	return parsed
}

func mustMakeCA(t *testing.T) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error while generating CA signing key: %v", err)
	}

	caCertTemplate := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotBefore:             mustRFC3339(t, "1970-01-01T00:00:00Z"),
		NotAfter:              mustRFC3339(t, "1971-01-01T00:00:00Z"),
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, signPub, signPriv)
	if err != nil {
		t.Fatalf("Error while creating CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Error while parsing CA certificate: %v", err)
	}

	return caCertDER, caCert, signPriv
}

func mustMakeEd25519KeyAndProof(t *testing.T, toBeSigned []byte, pkcs10DNSSANS []string) (ed25519.PrivateKey, ed25519.PublicKey, []byte, []byte, []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error while generating ed25519 key: %v", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("Error while marshaling PKIX public key: %v", err)
	}
	sig := ed25519.Sign(priv, toBeSigned)

	pkcs10DER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: pkcs10DNSSANS}, priv)
	if err != nil {
		t.Fatalf("Error while creating PKCS#10 certificate signing request: %v", err)
	}

	return priv, pub, pubPKIX, sig, pkcs10DER
}

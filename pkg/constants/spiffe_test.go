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

package constants

import "testing"

func TestSpiffeTrustBundleFileName(t *testing.T) {
	tests := []struct {
		trustDomain string
		want        string
	}{
		{
			trustDomain: "cluster.local",
			want:        "cluster.local.trust-bundle.pem",
		},
		{
			trustDomain: "example.com",
			want:        "example.com.trust-bundle.pem",
		},
	}

	for _, tt := range tests {
		got := SpiffeTrustBundleFileName(tt.trustDomain)
		if got != tt.want {
			t.Errorf("SpiffeTrustBundleFileName(%q) = %q, want %q", tt.trustDomain, got, tt.want)
		}
	}
}

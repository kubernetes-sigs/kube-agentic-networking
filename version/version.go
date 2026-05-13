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

package version

var (
	// CommitSHA is the git hash of the latest commit in the build.
	CommitSHA string

	// BuildRef is the build ref from the _PULL_BASE_REF from cloud build trigger.
	BuildRef string
)

const (
	// BundleVersionAnnotation is the annotation key used in the Kube Agentic Networking CRDs to specify
	// the installed version.
	BundleVersionAnnotation = "agentic.networking.x-k8s.io/bundle-version"

	// BundleVersion is the value used for labeling the version of kube-agentic-networking.
	BundleVersion = "v0.0.0-dev"
)

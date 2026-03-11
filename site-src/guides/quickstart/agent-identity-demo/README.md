# Agent Identity Demo

This demo illustrates how to configure a Kubernetes workload (AI Agent) to receive an mTLS identity certificate signed by the Kube Agentic Networking (KAN) identity signer.

## Overview

KAN uses native Kubernetes identity features (available in v1.35+) to provision cryptographically secure SPIFFE identities to workloads without requiring a sidecar for certificate management. This is achieved using a **Projected Volume** that combines:

1.  **PodCertificate**: Automatically generates a private key and requests a signed certificate from the KAN signer.
2.  **ClusterTrustBundle**: Mounts the necessary CA certificates to verify the identity of the KAN Gateway.

## Configuration

To enable mTLS for your agent, you must add a projected volume and a corresponding volume mount to your Pod specification.

### 1. Define the Volume

Add the following volume to your Pod spec. It specifies the official KAN signer and the required labels for retrieving the trust bundle.

```yaml
volumes:
- name: agent-identity-mtls
  projected:
    sources:
    - clusterTrustBundle:
        signerName: kube-agentic-networking.sigs.k8s.io/identity
        labelSelector:
          matchLabels:
            "kube-agentic-networking.sigs.k8s.io/canarying":             "live"
            "kube-agentic-networking.sigs.k8s.io/workload-trust-domain": "cluster.local"
            "kube-agentic-networking.sigs.k8s.io/peer-trust-domain":     "cluster.local"
        path: cluster.local.trust-bundle.pem
    - podCertificate:
        signerName: kube-agentic-networking.sigs.k8s.io/identity
        keyType: ECDSAP256
        credentialBundlePath: credential-bundle.pem
```

### 2. Define the Volume Mount

Mount the volume into your container. The standard path used by KAN agents is `/run/agent-identity-mtls`.

```yaml
volumeMounts:
- name: agent-identity-mtls
  mountPath: /run/agent-identity-mtls
  readOnly: true
```

## Resulting File Structure

Once the Pod is running, the following files will be available at the mount path:

*   `/run/agent-identity-mtls/credential-bundle.pem`: Contains both the workload's signed certificate and its private key.
*   `/run/agent-identity-mtls/cluster.local.trust-bundle.pem`: Contains the CA trust bundle for verifying peer identities.

## Running the Demo

1.  Ensure the KAN Controller is running in your cluster.
2.  Apply the demo manifest:
    ```bash
    kubectl apply -f quickstart/agent-identity-demo/agent-identity-demo.yaml
    ```
3.  Wait for the client pod to be ready:
    ```bash
    kubectl wait --for=condition=Ready pod -l app=client -n agent-identity-demo
    ```
4.  Verify the certificates are mounted:
    ```bash
    kubectl exec -it deployment/client -n agent-identity-demo -- ls /run/agent-identity-mtls
    ```
5.  Check the SPIFFE ID in the certificate (requires openssl installed locally):
    ```bash
    kubectl exec -n agent-identity-demo deployment/client -- cat /run/agent-identity-mtls/credential-bundle.pem | openssl x509 -text -noout | grep "URI"
    ```

# Connecting the adk-agent to Ollama on Linux

When running the `adk-agent` inside a Kubernetes Deployment on a kind cluster on a Linux machine, you may encounter connection errors when trying to communicate with an Ollama instance running directly on the Linux host (e.g., `127.0.0.1:11434`).

## The Problem

By default, Ollama binds to `127.0.0.1` (localhost), meaning it only accepts connections originating from the host itself. It ignores traffic coming from the Docker/kind network. Furthermore, inside a kind pod, `localhost` refers to the pod itself, not the Linux host.

## The Solution

To allow the `adk-agent` pod to communicate with the host's Ollama instance, you need to configure Ollama to listen on all network interfaces.

### Step 1: Configure Ollama to listen on all interfaces

If you are running Ollama as a systemd service (the default setup on Linux):

1.  Edit the Ollama systemd service configuration:

    ```shell
    sudo systemctl edit ollama
    ```

2.  Add the following lines under the `[Service]` section to set the `OLLAMA_HOST` environment variable:

    ```ini
    [Service]
    Environment="OLLAMA_HOST=0.0.0.0"
    ```

3.  Reload the systemd daemon and restart the Ollama service:

    ```shell
    sudo systemctl daemon-reload
    sudo systemctl restart ollama
    ```

4.  Verify that Ollama is now listening on all interfaces (`0.0.0.0:11434` or `:::11434`):

    ```shell
    ss -tlnp | grep 11434
    ```

### Step 2: Find the Linux host's IP on the Docker bridge

```shell
ip addr show docker0 | grep -Po 'inet \K[\d.]+'
```

### Step 3: Configure adk-agent to reach the host

The `adk-agent` deployment uses the `OLLAMA_BASE_URL` environment variable to connect to Ollama.

In your `deployment.yaml`:

```yaml
- name: OLLAMA_BASE_URL
  value: "http://<IP-OF-Docker-bridge>:11434"
```

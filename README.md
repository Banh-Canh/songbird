# Songbird

`songbird` is a command-line interface (CLI) tool for verifying network connectivity in a Kubernetes cluster by evaluating **Network Policies**. It helps you quickly determine if a specific pod can communicate with a target IP and port, considering both ingress and egress rules.

This tool is especially useful for troubleshooting connectivity issues in environments where Network Policies are used to secure traffic.

---

## 🚀 Getting Started

<img align=left src="public/gopher-songbird.png" width="170vw" />

<br/><br/>
To use `songbird`, you must have a `kubeconfig` file configured in your environment that provides access to your Kubernetes cluster. The CLI automatically uses this file to connect to the cluster.
<br/><br/>

---

## 📖 Usage

The main command is `check`, which evaluates connectivity based on your specified parameters.

### `check`

The `check` command inspects all pods in a given namespace (or all namespaces) to see if they are allowed to connect to a specified IP address and port according to your Network Policies.

#### Arguments and Flags

| Flag          | Shorthand | Description                                                                                  | Required | Example      |
| :------------ | :-------- | :------------------------------------------------------------------------------------------- | :------- | :----------- |
| `--address`   | `-a`      | The target IP address to check connectivity against. This can be a pod's IP or any other IP. | Yes      | `10.1.0.225` |
| `--port`      | `-p`      | The target port number for the connection.                                                   | Yes      | `40`         |
| `--direction` | `-d`      | The traffic direction to check. Options are `ingress`, `egress`, or `all`.                   | No       | `ingress`    |
| `--namespace` | `-n`      | The specific namespace to check pods in. If omitted, all namespaces will be checked.         | No       | `default`    |

See --help or the docs/ for more informations.

#### Example

This example checks if any pod in the `flux-system` namespace can send **egress** and receive **ingress** traffic to/from the IP `10.1.0.225` on port `40`.

```bash
songbird check -a 10.1.0.225 -p 40 -d all -n flux-system
NAMESPACE    POD                                       DIRECTION  TARGET      PORT  STATUS
flux-system  flux-operator-86fdfcd59-p2vvq             to         10.1.0.225  40    DENIED ❌
flux-system  flux-operator-86fdfcd59-p2vvq             from       10.1.0.225  40    ALLOWED ✅
flux-system  helm-controller-cdcf95449-489mp           to         10.1.0.225  40    DENIED ❌
flux-system  helm-controller-cdcf95449-489mp           from       10.1.0.225  40    DENIED ❌
flux-system  kustomize-controller-86447b847-7ndxm      to         10.1.0.225  40    DENIED ❌
flux-system  kustomize-controller-86447b847-7ndxm      from       10.1.0.225  40    DENIED ❌
flux-system  notification-controller-55d7f99bf9-j6gh9  to         10.1.0.225  40    DENIED ❌
flux-system  notification-controller-55d7f99bf9-j6gh9  from       10.1.0.225  40    DENIED ❌
flux-system  source-controller-ffb777895-g28tj         to         10.1.0.225  40    DENIED ❌
flux-system  source-controller-ffb777895-g28tj         from       10.1.0.225  40    DENIED ❌
```

This example checks if any pod in the `flux-system` namespace can receive **ingress** traffic from the IP `10.1.0.225` on port `44`.

```bash
songbird check -a 10.1.0.225 -d ingress -n flux-system -p 40
NAMESPACE    POD                                       DIRECTION  TARGET      PORT  STATUS
flux-system  flux-operator-86fdfcd59-p2vvq             from       10.1.0.225  40    ALLOWED ✅
flux-system  helm-controller-cdcf95449-489mp           from       10.1.0.225  40    DENIED ❌
flux-system  kustomize-controller-86447b847-7ndxm      from       10.1.0.225  40    DENIED ❌
flux-system  notification-controller-55d7f99bf9-j6gh9  from       10.1.0.225  40    DENIED ❌
flux-system  source-controller-ffb777895-g28tj         from       10.1.0.225  40    DENIED ❌
```

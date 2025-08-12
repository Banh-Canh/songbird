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

See [Documentations](docs/songbird.md).

#### Example

This example checks if any pod in the `flux-system` namespace can send **egress** and receive **ingress** traffic to/from the IP `1.1.1.1` on port `53`.

```bash
songbird check -a 1.1.1.1 -p 53 -o wide -n flux-system                                                                                nix-shell
NAMESPACE    POD                                       DIRECTION  TARGET   PORT  NETWORK_POLICIES                                                                                STATUS
flux-system  flux-operator-6dc5986d74-nsl7v            to         1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              ALLOWED ✅
flux-system  flux-operator-6dc5986d74-nsl7v            from       1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  helm-controller-cdcf95449-knmb2           to         1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              ALLOWED ✅
flux-system  helm-controller-cdcf95449-knmb2           from       1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  kustomize-controller-86447b847-t8t5x      to         1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              ALLOWED ✅
flux-system  kustomize-controller-86447b847-t8t5x      from       1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  notification-controller-55d7f99bf9-kp2j6  to         1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, flux-system/allow-webhooks, dmp/deny-all  ALLOWED ✅
flux-system  notification-controller-55d7f99bf9-kp2j6  from       1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, flux-system/allow-webhooks, dmp/deny-all  DENIED ❌
flux-system  source-controller-ffb777895-gv7c7         to         1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              ALLOWED ✅
flux-system  source-controller-ffb777895-gv7c7         from       1.1.1.1  53    flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
```

This example checks if any pod in the `flux-system` namespace can receive **ingress** traffic from the pod `zitadel-6b5d5d9cff-65rzv` in namespace `zitadel` on port `443`.

```bash
songbird check -P zitadel/zitadel-6b5d5d9cff-65rzv -p 443 -o wide -n flux-system -d ingress
NAMESPACE    POD                                       DIRECTION  TARGET      PORT  NETWORK_POLICIES                                                                                STATUS
flux-system  flux-operator-6dc5986d74-nsl7v            from       10.244.3.5  443   flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  helm-controller-cdcf95449-knmb2           from       10.244.3.5  443   flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  kustomize-controller-86447b847-t8t5x      from       10.244.3.5  443   flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
flux-system  notification-controller-55d7f99bf9-kp2j6  from       10.244.3.5  443   flux-system/allow-egress, flux-system/allow-scraping, flux-system/allow-webhooks, dmp/deny-all  ALLOWED ✅
flux-system  source-controller-ffb777895-gv7c7         from       10.244.3.5  443   flux-system/allow-egress, flux-system/allow-scraping, dmp/deny-all                              DENIED ❌
```

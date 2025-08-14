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

## Requirements

Songbird will require admnistators to have least the following permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: songbird-network-checker
rules:
  - apiGroups: ['']
    resources: ['pods', 'namespaces']
    verbs: ['get', 'list', 'watch']
  - apiGroups: ['networking.k8s.io']
    resources: ['networkpolicies']
    verbs: ['get', 'list', 'watch']
```

## 📖 Usage

The main command is `check`, which evaluates connectivity based on your specified parameters.

### `check`

The `check` command inspects all pods in a given namespace (or all namespaces) to see if they are allowed to connect to a specified IP address and port according to your Network Policies.

#### Arguments and Flags

See [Documentations](docs/songbird.md).

#### Example

This example checks if any pod in the `flux-system` namespace can send **egress** and receive **ingress** traffic to/from the IP `1.1.1.1` on port `53`.
It should test both side, so if it says allowed, you can be sure that the traffic is not blocked by any network policy.

```bash
songbird check -a 1.1.1.1 -p 53 -o wide -n flux-system
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

This example checks if any pod in the `fluent` namespace can receive **ingress** or **egress** traffic from the pod `debug` in namespace `monitoring` on port `443`. It is filtered to show only denied result.

```bash
songbird netpol check -P monitoring/debug -n fluent -p 8443 --denied-only                                                                  nix-shell
NAMESPACE  POD    DIRECTION  TARGET            PORT  STATUS
fluent     debug  from       monitoring/debug  8443  DENIED ❌
```

This example show the yaml affecting a pod.

```bash
songbird show flux-system/flux-operator-86fdfcd59-p2vvq -o yaml
---
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"annotations":{},"name":"allow-ingress-to-flux-operator","namespace":"flux-system"},"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ark"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"island"}}}],"ports":[{"port":40,"protocol":"TCP"}]}],"podSelector":{"matchLabels":{"app.kubernetes.io/name":"flux-operator"}},"policyTypes":["Ingress"]}}
  creationTimestamp: "2025-08-11T20:29:09Z"
  generation: 4
  managedFields:
  - apiVersion: networking.k8s.io/v1
    fieldsType: FieldsV1
    fieldsV1:
      f:metadata:
        f:annotations:
          .: {}
          f:kubectl.kubernetes.io/last-applied-configuration: {}
      f:spec:
        f:ingress: {}
        f:podSelector: {}
        f:policyTypes: {}
    manager: kubectl-client-side-apply
    operation: Update
    time: "2025-08-11T20:29:09Z"
  name: allow-ingress-to-flux-operator
  namespace: flux-system
[...]
```

This example generate a netpol yaml for you to use

```bash
songbird create flux-system/flux-operator-86fdfcd59-p2vvq -a 1.1.1.1/32 -p 53
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: allow-flux-operator-86fdfcd59-p2vvq-from-ip-on-53
  namespace: flux-system
spec:
  egress:
  - ports:
    - port: 53
    to:
    - ipBlock:
        cidr: 1.1.1.1/32
  ingress:
  - from:
    - ipBlock:
        cidr: 1.1.1.1/32
    ports:
    - port: 53
  podSelector:
    matchLabels:
      app.kubernetes.io/name: flux-operator
  policyTypes:
  - Ingress
  - Egress
```

This example generate a netpol yaml for you to use, using pod name input

```bash
songbird create flux-system/flux-operator-6dc5986d74-nsl7v -P zitadel/zitadel-6b5d5d9cff-65rzv -p 443
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  creationTimestamp: null
  name: allow-flux-operator-6dc5986d74-nsl7v-zitadel-6b5d5d9cff-65rzv-on-443
  namespace: flux-system
spec:
  egress:
  - ports:
    - port: 443
    to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: zitadel
      podSelector:
        matchLabels:
          app.kubernetes.io/component: start
          app.kubernetes.io/instance: zitadel
          app.kubernetes.io/managed-by: Helm
          app.kubernetes.io/name: zitadel
          app.kubernetes.io/version: v2.68.1
          helm.sh/chart: zitadel-8.13.4
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: zitadel
      podSelector:
        matchLabels:
          app.kubernetes.io/component: start
          app.kubernetes.io/instance: zitadel
          app.kubernetes.io/managed-by: Helm
          app.kubernetes.io/name: zitadel
          app.kubernetes.io/version: v2.68.1
          helm.sh/chart: zitadel-8.13.4
    ports:
    - port: 443
  podSelector:
    matchLabels:
      app.kubernetes.io/name: flux-operator
  policyTypes:
  - Ingress
  - Egress
```

This example show how to run a query on the internal coredns of your kubernetes cluster.

```bash
songbird dns lookup kubernetes.default
Name:    kubernetes.default.svc.bealv.local
Address: 172.17.0.1
```

This example show how to run a simple check test on your kubernetes dns.
For now, it only show pods that can't access it due to netpol restrictions.

```bash
songbird dns check                                                                                                                      nix-shell
NAMESPACE   POD                                                   DIRECTION  TARGET                                PORT  STATUS
monitoring  debug                                                 to         kube-system/coredns-796d84c46b-7mtj9  53    DENIED ❌
monitoring  grafana-operator-controller-manager-6474b685bc-hzncq  to         kube-system/coredns-796d84c46b-7mtj9  53    DENIED ❌
```

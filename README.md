# Songbird 🐦

`songbird` is a comprehensive command-line interface (CLI) tool for **Kubernetes network troubleshooting**. It helps you analyze network connectivity, diagnose Network Policy configurations, and resolve DNS issues in Kubernetes clusters.

<img align=left src="public/gopher-songbird.png" width="170vw" />

<br/><br/>

## ✨ Key Features

- **🔍 Network Policy Analysis**: Test connectivity between pods and external IPs
- **🎯 Interactive Fuzzy Finder**: Use fzf-style menus for easy resource selection  
- **🔧 DNS Troubleshooting**: Query CoreDNS and check DNS connectivity
- **📋 Policy Generation**: Auto-generate NetworkPolicy YAML configurations
- **📊 Multiple Output Formats**: Table, wide, and JSON output support

<br/><br/>

---

## 🔧 Installation & Setup

### Prerequisites

- **kubeconfig**: Configured access to your Kubernetes cluster
- **RBAC Permissions**: See [RBAC Requirements](#-rbac-requirements) below

### Quick Start

1. Ensure your `kubeconfig` is properly configured
2. Apply the required RBAC permissions to your cluster
3. Run songbird commands directly

---

## 🛡️ RBAC Requirements

Songbird requires specific Kubernetes permissions depending on which features you use. Below are the minimum required permissions for each command group.

### Comprehensive RBAC (All Features)

For full songbird functionality, use this ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: songbird-full-access
rules:
  # Core resources for all network policy operations
  - apiGroups: ['']
    resources: ['pods', 'namespaces']
    verbs: ['get', 'list', 'watch']
  # Network policies for connectivity analysis
  - apiGroups: ['networking.k8s.io']
    resources: ['networkpolicies']
    verbs: ['get', 'list', 'watch']
  # Port forwarding for DNS lookups (requires pods/portforward)
  - apiGroups: ['']
    resources: ['pods/portforward']
    verbs: ['create']
  # ConfigMaps for cluster domain detection
  - apiGroups: ['']
    resources: ['configmaps']
    verbs: ['get', 'list']
```

### Command-Specific RBAC

#### Network Policy Commands (`netpol check`, `netpol show`, `netpol create`)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: songbird-netpol-access
rules:
  - apiGroups: ['']
    resources: ['pods', 'namespaces']
    verbs: ['get', 'list', 'watch']
  - apiGroups: ['networking.k8s.io']
    resources: ['networkpolicies']
    verbs: ['get', 'list', 'watch']
```

#### DNS Commands (`dns check`)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: songbird-dns-check-access
rules:
  - apiGroups: ['']
    resources: ['pods', 'namespaces']
    verbs: ['get', 'list', 'watch']
  - apiGroups: ['networking.k8s.io']
    resources: ['networkpolicies']
    verbs: ['get', 'list', 'watch']
```

#### DNS Lookup Command (`dns lookup`)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: songbird-dns-lookup-access
rules:
  - apiGroups: ['']
    resources: ['pods']
    verbs: ['get', 'list']
  - apiGroups: ['']
    resources: ['pods/portforward']
    verbs: ['create']
  - apiGroups: ['']
    resources: ['configmaps']
    verbs: ['get', 'list']
```

### Binding the ClusterRole

Create a ClusterRoleBinding to assign permissions to users or service accounts:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: songbird-binding
subjects:
- kind: User
  name: your-username  # Replace with actual username
  apiGroup: rbac.authorization.k8s.io
# Or for a service account:
# - kind: ServiceAccount
#   name: songbird-sa
#   namespace: default
roleRef:
  kind: ClusterRole
  name: songbird-full-access  # Use appropriate ClusterRole name
  apiGroup: rbac.authorization.k8s.io
```

## 📖 Command Reference

Songbird provides two main command groups for different types of network troubleshooting:

### Available Commands

```bash
songbird [command]

Available Commands:
  netpol      Troubleshoot Kubernetes Network Policies  
  dns         Troubleshoot and query DNS records
  help        Help about any command

Flags:
  -h, --help               help for songbird
  -l, --log-level string   Override log level (debug, info)
  -v, --version            display version information
```

### Network Policy Commands (`netpol`)

#### `netpol check`
Evaluate network policies to check connectivity between pods and IP addresses.

**Usage:**
```bash
songbird netpol check [flags]
```

**Key Flags:**
- `-a, --address string`: IP address to check connectivity to
- `-P, --pod string`: Target pod in format 'namespace/podname' 
- `-p, --port int`: Port number to check (required)
- `-n, --namespace string`: Namespace to filter source pods
- `-d, --direction string`: Traffic direction (ingress, egress, all) (default "all")
- `-o, --output string`: Output format (wide, json)
- `--denied-only`: Show only denied connections

#### `netpol show`
Display NetworkPolicies affecting a specific pod.

**Usage:**
```bash  
songbird netpol show <namespace>/<podname> [flags]
```

**Flags:**
- `-o, --output string`: Output format (yaml for full policy details)

#### `netpol create`
Generate NetworkPolicy YAML to allow connectivity.

**Usage:**
```bash
songbird netpol create <namespace>/<podname> [flags]
```

**Key Flags:**
- `-P, --peer-pod string`: Peer pod in format 'namespace/podname'
- `-a, --address string`: IP address or CIDR block (e.g., 192.168.1.10/32)
- `-p, --port int`: Port number (required)
- `-d, --direction string`: Traffic direction (ingress, egress, all) (default "all")

### DNS Commands (`dns`)

#### `dns check`  
Check connectivity to CoreDNS pods on port 53.

**Usage:**
```bash
songbird dns check [flags]
```

**Flags:**
- `-n, --namespace string`: Namespace to filter source pods
- `-o, --output string`: Output format (wide, json)

#### `dns lookup`
Perform DNS queries using port-forward to CoreDNS.

**Usage:**
```bash
songbird dns lookup <domain-name>
```

**Examples:**
```bash
songbird dns lookup kubernetes.default
songbird dns lookup my-service.my-namespace
```

---

## 📚 Examples & Use Cases

### Network Policy Testing Examples

#### Example 1: Check Connectivity to External IP

Check if any pod in the `flux-system` namespace can send **egress** and receive **ingress** traffic to/from the IP `1.1.1.1` on port `53`.

**Command:**
```bash
songbird netpol check -a 1.1.1.1 -p 53 -o wide -n flux-system
```

**Output:**
```
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

#### Example 2: Check Pod-to-Pod Connectivity (Denied Only)

Check if any pod in the `fluent` namespace can receive **ingress** or **egress** traffic from the pod `debug` in namespace `monitoring` on port `8443`, showing only denied results.

**Command:**
```bash
songbird netpol check -P monitoring/debug -n fluent -p 8443 --denied-only
```

**Output:**
```
NAMESPACE  POD    DIRECTION  TARGET            PORT  STATUS
fluent     debug  from       monitoring/debug  8443  DENIED ❌
```

#### Example 3: Show Network Policies Affecting a Pod

Display the YAML of network policies affecting a specific pod.

**Command:**
```bash
songbird show flux-system/flux-operator-86fdfcd59-p2vvq -o yaml
```

**Output:**
```yaml
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

#### Example 4: Inspect Network Policies Affecting a Pod

Display the YAML of network policies affecting a specific pod.

**Command:**
```bash
songbird netpol show flux-system/flux-operator-86fdfcd59-p2vvq -o yaml
```

**Output:**
```yaml
---
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy"...}
  creationTimestamp: "2025-08-11T20:29:09Z"
  name: allow-ingress-to-flux-operator
  namespace: flux-system
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ark
  podSelector:
    matchLabels:
      app.kubernetes.io/name: flux-operator
  policyTypes:
  - Ingress
```

#### Example 5: Advanced JSON Output

Get machine-readable output for scripts and automation.

**Command:**
```bash
songbird netpol check -P monitoring/grafana -n flux-system -p 3000 -o json
```

**Output:**
```json
[
  {
    "namespace": "monitoring",
    "pod": "grafana",
    "direction": "egress to",
    "target": "flux-system/flux-operator-6dc5986d74-nsl7v",
    "port": 3000,
    "network_policies": ["monitoring/allow-grafana-egress"],
    "status": "ALLOWED ✅"
  }
]
```

### Network Policy Generation Examples

#### Example 6: Generate Network Policy for IP Access

Generate a NetworkPolicy YAML to allow a pod to communicate with a specific IP.

**Command:**
```bash
songbird netpol create flux-system/flux-operator-86fdfcd59-p2vvq -a 1.1.1.1/32 -p 53
```

**Output:**
```yaml
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

#### Example 7: Generate Network Policy for Pod-to-Pod Access

Generate a NetworkPolicy YAML to allow pod-to-pod communication.

**Command:**
```bash
songbird netpol create flux-system/flux-operator-6dc5986d74-nsl7v -P zitadel/zitadel-6b5d5d9cff-65rzv -p 443
```

**Output:**
```yaml
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

### DNS Troubleshooting Examples

#### Example 8: DNS Lookup

Query the internal CoreDNS of your Kubernetes cluster.

**Command:**
```bash
songbird dns lookup kubernetes.default
```

**Output:**
```
Name:    kubernetes.default.svc.bealv.local
Address: 172.17.0.1
```

#### Example 9: DNS Connectivity Check

Check DNS connectivity and show pods that can't access CoreDNS due to network policy restrictions.

**Command:**
```bash
songbird dns check
```

**Output:**
```
NAMESPACE   POD                                                   DIRECTION  TARGET                                PORT  STATUS
monitoring  debug                                                 to         kube-system/coredns-796d84c46b-7mtj9  53    DENIED ❌
monitoring  grafana-operator-controller-manager-6474b685bc-hzncq  to         kube-system/coredns-796d84c46b-7mtj9  53    DENIED ❌
```

---

## 🎯 Interactive Mode

Songbird supports both direct command-line usage and an **interactive fuzzy finder mode** for easier navigation. The interactive mode uses `fzf`-style menus to help you select namespaces and pods.

### Interactive Mode Usage

#### Full Interactive Mode

Start full interactive mode without specifying source or target:

```bash
songbird netpol check -p 80 -d all
```

This will launch fuzzy finder menus for both source and destination selection.

#### Semi-Interactive Mode

Use interactive source selection with a specific target:

```bash
songbird netpol check -a 10.1.0.225 -p 80 -d all
```

This will show a fuzzy finder menu for source namespace selection only.

### Interactive Menu Examples

When you run interactive mode, you'll see fuzzy finder menus like this:

#### Namespace Selection Menu
```
❯ Source namespace > _
  default
  flux-system
  kube-public 
  kube-system
  monitoring
  zitadel

┌─ Preview ─────────────────────────────────┐
│ Namespace: flux-system                    │
│ Status: Active                            │
│                                          │
└──────────────────────────────────────────┘
```

#### Pod Selection Menu  
```
❯ source pod > flux-operator
  flux-operator-6dc5986d74-nsl7v
  helm-controller-cdcf95449-knmb2
  kustomize-controller-86447b847-t8t5x
  notification-controller-55d7f99bf9-kp2j6
  source-controller-ffb777895-gv7c7

┌─ Preview ─────────────────────────────────┐
│ Pod: flux-operator-6dc5986d74-nsl7v       │
│ IP: 10.42.1.18                            │
│ Status: Running                           │
│ Ready: 1/1                                │
│                                          │
└──────────────────────────────────────────┘
```

### Extended Examples

#### Example 1: Interactive Pod-to-Pod Connectivity Check

Start interactive mode to check connectivity between pods.

**Command:**
```bash
songbird netpol check -p 443 -d all
```

This will:
1. Show source namespace selection (fuzzy finder)
2. Show source pod selection (fuzzy finder)  
3. Show destination namespace selection (fuzzy finder)
4. Display connectivity results for all pods in destination namespace

**Output:**
```
NAMESPACE    POD                          DIRECTION     TARGET                    PORT  STATUS
flux-system  flux-operator-6dc5986d74     egress to     monitoring/grafana        443   ALLOWED ✅
flux-system  flux-operator-6dc5986d74     ingress from  monitoring/grafana        443   DENIED ❌
```

#### Example 2: Check Connectivity to External Service

Interactive source selection with external IP target.

**Command:**
```bash
songbird netpol check -a 8.8.8.8 -p 53 -d egress -o wide
```

This will:
1. Show source namespace selection (fuzzy finder)
2. Check egress connectivity from all pods in selected namespace to 8.8.8.8:53

**Output:**
```
NAMESPACE     POD                       DIRECTION  TARGET   PORT  NETWORK_POLICIES                 STATUS
flux-system   flux-operator-6dc59       egress to  8.8.8.8  53    flux-system/allow-dns-egress     ALLOWED ✅
flux-system   helm-controller-cdcf9     egress to  8.8.8.8  53    flux-system/allow-dns-egress     ALLOWED ✅
```

#### Example 3: Troubleshooting Blocked Communication

Show only denied connections for troubleshooting.

**Command:**
```bash
songbird netpol check -p 443 -d all --denied-only
```

This will:
1. Use interactive mode to select source and destination
2. Show only blocked connections that need attention

**Output:**
```
NAMESPACE   POD       DIRECTION     TARGET              PORT  STATUS
default     web-app   egress to     database/postgres   443   DENIED ❌
default     web-app   ingress from  database/postgres   443   DENIED ❌
```

#### Example 4: JSON Output for Automation

Get machine-readable output for scripts/automation.

**Command:**
```bash
songbird netpol check -P monitoring/grafana -n flux-system -p 3000 -o json
```

**Output:**
```json
[
  {
    "namespace": "monitoring",
    "pod": "grafana",
    "direction": "egress to",
    "target": "flux-system/flux-operator-6dc5986d74-nsl7v",
    "port": 3000,
    "network_policies": ["monitoring/allow-grafana-egress"],
    "status": "ALLOWED ✅"
  }
]
```

### Tips for Interactive Mode

- **Type to filter**: In fuzzy finder menus, start typing to filter results
- **Navigation**: Use arrow keys or `Ctrl+j/k` to navigate
- **Preview**: The right panel shows details about the selected resource
- **Exit**: Press `Esc` or `Ctrl+C` to cancel selection
- **Select**: Press `Enter` to select the highlighted item

### Common Troubleshooting Workflows

1. **Pod Can't Connect to External Service**:
   ```bash
   # Check if network policies block the connection
   songbird netpol check -a 8.8.8.8 -p 53 -n my-namespace --denied-only
   
   # Generate policy to allow the connection
   songbird netpol create my-namespace/my-pod -a 8.8.8.8/32 -p 53
   ```

2. **Pod-to-Pod Communication Issues**:
   ```bash
   # Use interactive mode to test connectivity
   songbird netpol check -p 80 -d all
   
   # Generate policy for specific pod-to-pod communication
   songbird netpol create source-ns/source-pod -P target-ns/target-pod -p 80
   ```

3. **DNS Resolution Problems**:
   ```bash
   # Test DNS connectivity
   songbird dns check
   
   # Look up specific service
   songbird dns lookup my-service.my-namespace
   ```

4. **Security Audit**:
   ```bash
   # Check what policies affect a critical pod
   songbird netpol show production/api-server -o yaml
   
   # Identify which pods can access external networks
   songbird netpol check -a 0.0.0.0/0 -p 443 --denied-only
   ```

---

## 🤝 Contributing

Issues and pull requests are welcome! Please check the [GitHub repository](https://github.com/Banh-Canh/songbird) for contributing guidelines.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

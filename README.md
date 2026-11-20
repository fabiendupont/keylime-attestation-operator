# attestation-operator

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

Keylime easily deployable on Kubernetes/Openshift.

**NOTE:** This project is a work in progress.

## Pre-requisites:
* Running `Kubernetes` cluster (evidently)
* If one wishes to deploy `agents` (which are deployed by default) the following additional requirements should be in place:
    * All workers nodes should have TPM devices (e.g., `ls /dev/tpm*` should exit with 0)
    * For **unprivileged** pods, K8s version `1.26` or later is required and [k8s-tpm-device-plugin](https://github.com/githedgehog/k8s-tpm-device-plugin) shall be installed beforehand. 
    * IMPORTANT: the default mode of operation for this helm chart is to deploy containers with a DameonSet with **privileged** pods.

## Initial deployment
a) `git clone https://github.com/keylime/attestation-operator.git; cd attestation-operator`

b) `make help`
```
Usage:
  make <target>

General
  help             Display this help.

Development
  manifests        Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
  generate         Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
  fmt              Run go fmt against code.
  vet              Run go vet against code.
  test             Run tests.
  build            Build manager binary.
  run              Run a controller from your host.

Development Deployment
  install          Install CRDs into the K8s cluster specified in ~/.kube/config.
  uninstall        Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
  deploy           Deploy controller to the K8s cluster specified in ~/.kube/config.
  undeploy         Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.

Development Build Dependencies
  install-dependencies  Downloads and installs all dependencies to LOCALBIN
  clean-dependencies  Removes all downloaded dependencies from LOCALBIN
  kustomize        Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
  controller-gen   Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
  envtest          Download envtest-setup locally if necessary.
  helmify          Download helmify locally if necessary.

Build
  docker-build     Builds the application in a docker container and creates a docker image
  docker-push      Pushes a previously built docker container
  helm             Builds all helm charts
  helm-clean       Cleans all packaged helm charts
  helm-keylime     Builds the keylime helm chart
  helm-keylime-clean  Cleans the packaged keylime helm chart
  helm-keylime-undeploy  Undeploy the keylime helm chart
  helm-keylime-deploy  Deploy the keylime helm chart
  helm-keylime-update  Update the deployed keylime helm chart
  helm-keylime-debug  Attempt to debug the keylime helm chart, without deploying it
  helm-keylime-push  Builds AND pushes the keylime helm chart
  helm-keylime-test  Basic testing for the keylime helm chart
  helm-crds        Builds the keylime-crds helm chart
  helm-crds-clean  Cleans the packaged keylime-crds helm chart
  helm-crds-push   Builds AND pushes the keylime-crds helm chart
  helm-controller  Builds the keylime-controller helm chart
  helm-controller-push  Builds AND pushes the keylime-controller helm chart
```
c) `make helm-keylime`

d) `make helm-deploy` will deploy an initial barebones (but functional) deployment with 1 `registrar` (a `Deployment` with a single pod), 1 `verifier` (a `Deployment` with. a single pod), each backed by their own private `sqlite` (in-pod) database and `agents` on every node (as a `DaemonSet`)

e) `make helm-undeploy` will remove the whole deployment

## Deploying a controller

### Deployment/cleanup of the operator through OLM v1 (ClusterExtension)
The operator is packaged for **OLM v1** (ClusterExtension + ClusterCatalog /
catalogd), available on OpenShift 4.22+ / OLM 5.0. The bundle remains a
registry+v1 bundle (CSV), served through a catalog image
served from the `catalog/` directory instead of the deprecated sqlite index.
OLM v0 installs (CatalogSource + Subscription) are no longer supported.

To build and push the images:
```bash
make podman-build podman-push
make podman-bundle-build podman-bundle-push
make podman-catalog-build podman-catalog-push
```
The bundle image (`...-bundle:v0.2.0`) and the catalog image
(`...-catalog:v0.2.0`) are both defined in the
`catalog/` directory; see [`config/olm-v1/`](config/olm-v1/README.md) for
the install manifests and step-by-step instructions:
```bash
oc apply -f config/olm-v1/clustercatalog.yaml
oc -n keylime apply -f config/olm-v1/rbac.yaml
oc apply -f config/olm-v1/clusterextension.yaml
```
Note that, unlike OLM v0, OLM v1 does not generate RBAC for the operator:
the ServiceAccount referenced by the ClusterExtension (`rbac.yaml` above)
must be created beforehand.

To remove the operator:
```bash
oc delete clusterextension/attestation-operator
oc delete clustercatalog/attestation-operator
oc -n keylime delete -f config/olm-v1/rbac.yaml
```

### Deployment of the operator through operator-sdk (development only)
For quick development iterations (no OLM involved), the operator can also be
run through `operator-sdk`:
```bash
operator-sdk run bundle quay.io/{quay_user}/attestation-operator-bundle:v0.1.0 --namespace keylime
operator-sdk cleanup attestation-operator --namespace keylime
```

## Deploying the keylime operands

The operator can deploy and configure the keylime components
themselves through the namespaced `Keylime` CR (one instance per trust domain
/ node pool):

```bash
oc apply -f config/samples/attestation_v1alpha1_keylime.yaml
```

This deploys:

- the **verifier** as a `StatefulSet` whose SQLite database lives on a PVC
  (`spec.verifier.storageSize`, default 1Gi) — enrollments survive restarts,
- the **registrar** as a `Deployment` with its own PVC,
- optionally, the **keylime agent** as a `DaemonSet` (`spec.agent.enabled`,
  default false, with `nodeSelector`/`tolerations` for node pool isolation),
- `Service`s with stable DNS names (`<name>-verifier.<namespace>.svc:8881`,
  `<name>-registrar.<namespace>.svc:8890/8891`),
- server certificates with correct SANs, signed by a CA that is either
  brought by the user (`spec.tls.caSecretRef`, a secret with `ca.crt` and
  `ca.key`) or generated by the operator. Additional trusted client CAs can
  be configured with `spec.tls.trustedClientCASecretRefs` (e.g. to trust a
  legacy CA during a migration, keeping existing client certificates valid).
  No `InsecureSkipVerify` is needed anywhere: the SANs match the service DNS
  names,
- `ConfigMap`s rendering the keylime configuration (`verifier.conf.d` /
  `registrar.conf.d` snippets) from the spec: database
  (`sqlite` on PVC, default, or `external` with URLs from a secret ref),
  trust stores (`tpmCertStore`, `spdmCertStore`, `corimSigners` as secret or
  configmap refs mounted into the verifier) and appraisal
  (`appraisal.corim` for the verifier's `spdm_corim` setting).

Status reports per-operand conditions (`VerifierReady`, `RegistrarReady`,
`AgentReady`, `Ready`), the service endpoints and the CA fingerprint.

The operator's own registrar/verifier URLs remain configured through the
`KEYLIME_REGISTRAR_URL` / `KEYLIME_VERIFIER_URL` environment variables of the
operator deployment; pointing them at the operand services is a manual step.

## Customizing the deployment.

By default, the `Makefile` looks for a yaml file on the path set by
the environment variable `HELM_CHART_CUSTOM_VALUES` (default
`values.yaml`)

### Registrars and verifiers: minimal deployment

This configuration deploys registrar, tenant and verifier pods. The
services are made available externally (i.e. the deployment can be
used to verify another cluster).

```
tags:
  init: true
  registrar: true
  verifier: true
  agent: false
  tenant: true

global:
  service:
    registrar:
      type: NodePort
    verifier:
      type: NodePort
```

### Registrars and verifiers: using a mysql server

This configuration deploys a `verifier` and `registrar` sharing a
`MySQL` database (password will be automatically generated and
preserved across (`helm` updates)

The mysql server is deployed as part of the helm chart (that is, no
extra work is required).

```
global:
  database:
    mysql:
      enable: true
```

### Registrars and verifiers: using an external mysql server

An external managed MySQL database can be used also for the `verifier` and `registrar`:

```
global:
  database:
    mysql:
      external: true
mysql:
  auth:
    externalIP: "10.103.4.2"
    externalUser: "keylime"
    externalPassword: "TikBue7mQS"
```

### Registars and verifiers: overriding site specifig configuration


This configuration demonstrates how to override Keylime configuration
parameters. Keylime allows configuration to be overridden by
environment variables.

```
global:
  configmap:
    configParams:
      KEYLIME_AGENT_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_AGENT_ENABLE_INSECURE_PAYLOAD: 'True'
      KEYLIME_AGENT_RUN_AS: root:root
      KEYLIME_AGENT_TPM_ENCRYPTION_ALG: rsa
      KEYLIME_AGENT_TPM_HASH_ALG: sha256
      KEYLIME_AGENT_TPM_OWNERPASSWORD: temp4now
      KEYLIME_AGENT_TPM_SIGNING_ALG: rsassa
      KEYLIME_CA_CERT_CA_NAME: feykimeluckers
      KEYLIME_CA_CERT_CRL_DIST: http://100.64.255.11:3808/crl
      KEYLIME_CA_CERT_LOCALITY: YKT
      KEYLIME_CA_CERT_ORGANIZATION: IBM
      KEYLIME_CA_CERT_ORG_UNIT: k5l
      KEYLIME_CA_CERT_STATE: NY
      KEYLIME_CA_PASSWORD: temp4now
      KEYLIME_REGISTRAR_AUTO_MIGRATE_DB: 'True'
      KEYLIME_REGISTRAR_DATABASE_POOL_SZ_OVFL: 40,80
      KEYLIME_TENANT_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_TENANT_MAX_PAYLOAD_SIZE: '1048576'
      KEYLIME_TENANT_REQUIRE_EK_CERT: 'True'
      KEYLIME_VERIFIER_AUTO_MIGRATE_DB: 'True'
      KEYLIME_VERIFIER_DATABASE_POOL_SZ_OVFL: 40,80
      KEYLIME_VERIFIER_ENABLE_AGENT_MTLS: 'False'
      KEYLIME_VERIFIER_QUOTE_INTERVAL: '5'
```

### Keylime agent: deploy agents in privileged pods.

This configuration deploys Keylime `agents` in the cluster in a daemon
set. The pods running the keylime `agent` are privileged. We do not
recommend running this configuration in production mode, but may help
with debugging keylime.


```
tags:
  agent: true

global:
  service:
    agent:
      privileged: true
```

### Keylime agent: deploy agents in unprivileged pods

This configuration deploys Keylime `agents` in the cluster, but the pods
running it are unprivileged. The keylime `agent` needs access to
the TPM device and to parts of the `securityfs` file system. Both of
these are provided by the TPM device plugin, which is turned on
automatically with unprivileged `agent` pods.

In addition, the effective group ID of the keylime `agent` pod has to
match the group ID of the TPM device. Kubernetes does not allow
`runAsGroup` to take symbolic values.


TODO instructions for mounting the MBA and IMA logs in nonstandard places.

```
tags:
  agent: true

global:
  service:
    agent:
      privileged: false

keylime-agent:
  unprivsecurityContext:
    readOnlyRootFilesystem: true
    privileged: false
    capabilities:
      drop:
      - ALL
    runAsGroup: 109    <---- make this match the group ID of group <tss> on the hosts running the agent.
```

### Deploy with custom images (e.g. from a local registry)

This configuration is for those of us debugging custom (self-built)
keylime images. We imagine this to be the standard way to do Keylime
development.

```
global:
  service:
    agent:
      initImage:
        repository: localhost/custom-agent-initImage
        tag: latest
      image:
        repository: localhost/custom-agent-image
        tag: latest
    registrar:
      image:
        repository: localhost/custom-registrar-image
        tag: latest
    verifier:
      image:
        repository: localhost/custom-verifier-image
        tag: latest
    tenant:
      image:
        repository: localhost/custom-tenant-image
        tag: latest
```

### Deploy multiple Verifiers and registrars

For both availability and scalability reasons (scale-out), multiple `verifiers`
and `registrars` can be deployed. Please do notice that this configuration
cannot operate with a `sqlite` backend (i.e. either `mysql:external` or
`mysql:enable` has to be set to `true `). When adding a new `agent` to a
`verifier`, one of the multiple ones (exposed via multiple services, one per
pod in the `StatefulSet`) has to be selected. The utility `kt`, used by `make
helm-keylime-test` shows an example on how to pick a `verifier` based on an
`agent` UUID.

```
global:
  database:
    mysql:
      enable: true
  service:
    registrar:
      replicas: 2
      type: "LoadBalancer"
    verifier:
      replicas: 3
      type: "LoadBalancer"    
```

### Deploy in "developer mode"

As a convenience during development, each individual service can be set to
"developer mode", resulting in a `pod` with a long sleep time (7 days or
604,800 seconds). The developer can then access the `pod` (via `kubectl exec
-i`) and perform multiple iterations of code change followed by service
(re)start (e.g., `keylime_verifier`)

```
global:
  service:
    registrar:
      developer: false
    verifier:
      developer: true
    agent:
      developer: true
```

## Out-of-band attestation signals and node health

The `AttestationTarget` CR drives the out-of-band (SPDM/Redfish) attestation
of a machine's BMC: the operator provisions one collector Deployment per
target, which pushes measurements to the verifier of the referenced `Keylime`
CR. See `config/samples/` for a complete example.

### Health computation

A target is **unhealthy** when:

- its agent's attestation evaluation is `fail` (the verifier's appraisal
  rejected the measurements), or
- it is **stale**: its `lastSuccessfulAttestation` is older than
  `spec.staleThresholdSeconds` (default: 3x `spec.intervalSeconds`). A dead
  collector silently means no attestation, which must not read as healthy.

The target's health is recorded as the `AttestationHealthy` status condition
(`status.components[]` additionally lists the components covered by the
latest attestation, from the verifier's evidence items). NOTE: the verifier's
v3 API only reports an attestation-level verdict; per-component verdicts are
not available there, so a failing component set cannot be isolated from the
API today.

### Node conditions

When a target with a resolved node mapping becomes unhealthy, the operator
sets a node condition on every mapped node:

```
AttestationFailed=True  reason=AttestationEvaluationFailed|AttestationStale
```

with a message naming the `AttestationTarget`, its namespace and the failure
mode; it is cleared (`AttestationFailed=False`, reason `AttestationPassed`)
when the target is healthy again. A Kubernetes Event is emitted on the node
whenever the condition changes. The node status is only patched when the
condition actually changes, so the operator never fights other writers.

Nodes are resolved with the following precedence:

1. **MachineAPI**: BaremetalHosts whose BMC address matches the target's
   BMC host (when the metal3 CRDs are installed) and the nodes they
   provisioned;
2. **manual fallback** (`spec.nodes`): a list of node names for clusters
   without the MachineAPI — e.g. a management cluster attesting
   externally-managed bare metal.

The source used is recorded in `status.machineMapping.source`.

### Remediation: the operator emits a signal, it does not remediate

The operator's contract ends at the node condition. Remediation belongs to
**Workload Availability**: install the Node Health Check Operator and create
a `NodeHealthCheck` watching `AttestationFailed=True`, paired with a
remediation template of the admin's choosing (Self Node Remediation, Fence
Agents Remediation, ...):

```bash
oc apply -f config/olm-v1/nodehealthcheck.yaml
```

The shipped example pairs the check with the Self Node Remediation
template; the NodeHealthCheck webhook requires a minHealthy/maxUnhealthy
value and a remediation template, so a purely template-less
detection-only CR is rejected — see the file's comments for the verified
detection-only patterns (an inert template kind, or `spec.pauseRequests`). For NVL72-style
racks, tray-level granularity starts at **one AttestationTarget per rack**,
with the failing components named in the condition message (once the
verifier reports per-evidence-item results) — enabling the admin to fence a
single tray instead of the whole rack.

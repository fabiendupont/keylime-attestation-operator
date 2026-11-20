# OLM v1 packaging of the attestation-operator

This directory contains example manifests for installing the
attestation-operator with **OLM v1** (ClusterExtension / ClusterCatalog /
catalogd), available on OpenShift 4.22+ / OLM 5.0. OLM v0 installs
(CatalogSource + Subscription) are no longer supported.

## Files

- `clustercatalog.yaml` — ClusterCatalog serving the operator catalog
  image built from [`catalog/`](../../catalog).
- `rbac.yaml` — the install ServiceAccount (`attestation-operator-installer`)
  with its ClusterRole and ClusterRoleBinding. OLM v1 does not provision the
  install-time identity: the ServiceAccount referenced by the
  ClusterExtension must exist beforehand and must hold (directly or via a
  bound role) every permission the bundle content needs, because Kubernetes
  RBAC escalation prevention rejects granting permissions the ServiceAccount
  does not itself have.
- `clusterextension.yaml` — the ClusterExtension installing the operator into
  the `keylime` namespace from the `alpha` channel.

## Install

```sh
oc apply -f config/olm-v1/clustercatalog.yaml
oc -n keylime apply -f config/olm-v1/rbac.yaml
oc apply -f config/olm-v1/clusterextension.yaml
```

Wait for the ClusterCatalog to report serving and the ClusterExtension to
install:

```sh
oc wait --for=condition=Serving=True clustercatalog/attestation-operator
oc wait --for=condition=Installed=True clusterextension/attestation-operator
```

Notes learned from a real v0 → v1 migration:

- The operator deployment mounts two Secrets from the Keylime Helm release
  (`hhkl-keylime-certs` and `hhkl-keylime-tpm-cert-store`); the Keylime
  tenant stack must therefore be installed in the `keylime` namespace before
  the ClusterExtension is created.
- Do NOT pre-create the operator's own ServiceAccount
  (`attestation-operator-controller-manager`), ClusterRoles or the Agent
  CRD: operator-controller refuses to adopt resources it does not own. When
  migrating from an OLM v0 install, delete the v0 Subscription, CSV and any
  leftover OLM-managed ClusterRoles/CRDs first (the operator re-creates the
  Agent CRs from the registrar state after the CRD is re-created by OLM v1).

## Uninstall

```sh
oc delete clusterextension/attestation-operator
oc delete clustercatalog/attestation-operator
oc -n keylime delete -f config/olm-v1/rbac.yaml
```

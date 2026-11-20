/*
Copyright 2023 Keylime Authors.

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

package attestation

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attestationv1alpha1 "github.com/keylime/attestation-operator/api/attestation/v1alpha1"
)

const (
	defaultCollectorImage = "quay.io/fdupont-redhat/keylime-oob-attest:master-oob"

	collectorTLSVolumeName   = "collector-tls"
	collectorTLSMountDir     = "/etc/keylime/oob"
	collectorCertFile        = "client-cert.crt"
	collectorKeyFile         = "client-private.pem"
	collectorCAFile          = "ca.crt"
	bmcCAVolumeName          = "bmc-ca"
	bmcCAMountDir            = "/etc/keylime/bmc-ca"
	certChainVolumeName      = "cert-chain"
	certChainMountDir        = "/etc/keylime/spdm"
	certChainFile            = "cert-chain.blob"
	oobConfigVolumeName      = "oob-config"
	oobConfigMountDir        = "/etc/keylime/oob-config"
	oobConfigFile            = "oob.conf"
	swtpmSocketDir           = "/swtpm"
	swtpmSocketVolumeName    = "swtpm"
	swtpmStateVolName        = "swtpm-state"
	swtpmStateDefaultStorage = "300Mi"

	// registrarPlainPort is the registrar's plain HTTP port; the collector
	// registers over it (the TLS port serves the API clients).
	registrarPlainPort = "8890"
)

// collectorParams carries everything the rendering of the collector
// Deployment resolves from outside the AttestationTarget spec itself.
type collectorParams struct {
	// AgentUUID is the (explicit or derived) agent UUID of the target.
	AgentUUID string

	// VerifierHost / RegistrarHost are the service hostnames of the
	// referenced Keylime CR's operands; VerifierPort is parsed from the
	// Keylime CR's status (the registrar is always reached over its fixed
	// plain port).
	VerifierHost  string
	VerifierPort  string
	RegistrarHost string

	// Credentials are the BMC Redfish credentials (nil to use the
	// collector image's defaults).
	Credentials *bmcCredentials

	// BMCCAFilename is the file name of the mounted BMC CA certificate;
	// empty means the BMC connection is insecure.
	BMCCAFilename string

	// CertChainKey is set when the target references an SPDM certificate
	// chain blob (mounted from a secret).
	CertChainKey string

	// Image is the collector container image.
	Image string
}

type bmcCredentials struct {
	Username string
	Password string
}

// collectorObjectMeta returns the metadata for an object owned by the
// AttestationTarget CR.
func collectorObjectMeta(target *attestationv1alpha1.AttestationTarget, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: target.Namespace,
		Labels:    collectorLabels(target),
	}
}

// collectorLabels returns the labels (and deployment selector) of a
// collector and its pod.
func collectorLabels(target *attestationv1alpha1.AttestationTarget) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "attestation-target",
		"app.kubernetes.io/instance":   target.Name,
		"app.kubernetes.io/component":  "collector",
		"app.kubernetes.io/part-of":    "keylime",
		"app.kubernetes.io/managed-by": "attestation-operator",
	}
}

// renderCollectorDeployment renders the collector Deployment of a target:
// one collector container plus a swtpm sidecar providing the collector's TPM
// identity (used for registrar registration, verifier enrollment and session
// authentication).
func renderCollectorDeployment(target *attestationv1alpha1.AttestationTarget, params collectorParams) *appsv1.Deployment {
	interval := target.Spec.IntervalSeconds
	if interval == 0 {
		interval = 300
	}
	image := params.Image
	if image == "" {
		image = defaultCollectorImage
	}

	collectorArgs := []string{
		"--agent-uuid", params.AgentUUID,
		"--bmc-host", target.Spec.BMC.Host,
		"--verifier-host", params.VerifierHost,
		"--verifier-port", params.VerifierPort,
		"--registrar-host", params.RegistrarHost,
		"--registrar-port", registrarPlainPort,
		"--swtpm-socket", swtpmSocketDir + "/tpm.sock",
		"--tls-cert", collectorTLSMountDir + "/" + collectorCertFile,
		"--tls-key", collectorTLSMountDir + "/" + collectorKeyFile,
		"--tls-ca-cert", collectorTLSMountDir + "/" + collectorCAFile,
		"--enroll",
		"--interval", fmt.Sprintf("%d", interval),
	}
	if params.BMCCAFilename != "" {
		collectorArgs = append(collectorArgs, "--bmc-ca-cert", bmcCAMountDir+"/"+params.BMCCAFilename)
	} else if target.Spec.BMC.Insecure {
		collectorArgs = append(collectorArgs, "--insecure")
	}
	if params.CertChainKey != "" {
		collectorArgs = append(collectorArgs, "--cert-chain", certChainMountDir+"/"+certChainFile)
	}

	// The collector reads its BMC credentials from a keylime config file
	// (KEYLIME_OOB_CONFIG) rather than from command line arguments, so that
	// they never appear in the pod spec; the file is rendered by the
	// controller into an owned secret from the referenced credentials
	// secret.
	var env []corev1.EnvVar
	if params.Credentials != nil {
		env = append(env, corev1.EnvVar{
			Name:  "KEYLIME_OOB_CONFIG",
			Value: oobConfigMountDir + "/" + oobConfigFile,
		})
	}

	// The swtpm sidecar keeps a lock on its state directory: a rolling
	// update starts the new pod while the old one still holds the lock and
	// the new swtpm never comes up (observed on the test cluster). The
	// deployment therefore always uses the Recreate strategy: the old pod
	// is fully terminated before the new one starts.
	strategy := appsv1.DeploymentStrategy{
		Type: appsv1.RecreateDeploymentStrategyType,
	}

	volumes := []corev1.Volume{
		{
			Name: swtpmSocketVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: swtpmStateVolName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: collectorSwtpmStatePVCName(target),
				},
			},
		},
		{
			Name: collectorTLSVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  collectorClientTLSSecretName(target),
					DefaultMode: int32Ptr(0o400),
				},
			},
		},
	}
	collectorMounts := []corev1.VolumeMount{
		{Name: swtpmSocketVolumeName, MountPath: swtpmSocketDir},
		{Name: collectorTLSVolumeName, MountPath: collectorTLSMountDir, ReadOnly: true},
	}
	if params.Credentials != nil {
		volumes = append(volumes, corev1.Volume{
			Name: oobConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  collectorConfigSecretName(target),
					DefaultMode: int32Ptr(0o400),
				},
			},
		})
		collectorMounts = append(collectorMounts, corev1.VolumeMount{
			Name: oobConfigVolumeName, MountPath: oobConfigMountDir, ReadOnly: true,
		})
	}
	if ref := target.Spec.BMC.CACertRef; ref != nil {
		fileName := sanitize(ref.Key)
		if fileName != "" {
			if ref.ConfigMapName != "" {
				volumes = append(volumes, corev1.Volume{
					Name: bmcCAVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: ref.ConfigMapName},
							Items:                []corev1.KeyToPath{{Key: ref.Key, Path: fileName}},
						},
					},
				})
			} else {
				volumes = append(volumes, corev1.Volume{
					Name: bmcCAVolumeName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: ref.SecretName,
							Items:      []corev1.KeyToPath{{Key: ref.Key, Path: fileName}},
							DefaultMode: int32Ptr(0o400),
						},
					},
				})
			}
			collectorMounts = append(collectorMounts, corev1.VolumeMount{
				Name: bmcCAVolumeName, MountPath: bmcCAMountDir, ReadOnly: true,
			})
		}
	}
	if params.CertChainKey != "" {
		volumes = append(volumes, corev1.Volume{
			Name: certChainVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  target.Spec.SPDMCertChain.SecretRef,
					Items:       []corev1.KeyToPath{{Key: params.CertChainKey, Path: certChainFile}},
					DefaultMode: int32Ptr(0o400),
				},
			},
		})
		collectorMounts = append(collectorMounts, corev1.VolumeMount{
			Name: certChainVolumeName, MountPath: certChainMountDir, ReadOnly: true,
		})
	}

	deployment := &appsv1.Deployment{ObjectMeta: collectorObjectMeta(target, collectorDeploymentName(target))}
	deployment.Spec.Replicas = int32Ptr(1)
	deployment.Spec.Selector = &metav1.LabelSelector{MatchLabels: collectorLabels(target)}
	deployment.Spec.Strategy = strategy
	deployment.Spec.Template = corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: collectorLabels(target)},
		Spec: corev1.PodSpec{
			// Service link environment variables (e.g. KEYLIME_VERIFIER_PORT)
			// collide with keylime's env-based config override mechanism and
			// end up as config values (observed on the test cluster).
			EnableServiceLinks: boolPtr(false),
			Containers: []corev1.Container{
				{
					Name:            "collector",
					Image:           image,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args:            collectorArgs,
					Env:             env,
					VolumeMounts:    collectorMounts,
				},
				{
					Name:  "swtpm",
					Image: image,
					Command: []string{
						"/bin/sh", "-c",
						"exec swtpm socket --tpm2 \\\n" +
							"  --tpmstate dir=/swtpm-state \\\n" +
							"  --server type=unixio,path=" + swtpmSocketDir + "/tpm.sock \\\n" +
							"  --ctrl type=unixio,path=" + swtpmSocketDir + "/tpm.sock.ctrl \\\n" +
							"  --flags not-need-init\n",
					},
					ImagePullPolicy: corev1.PullIfNotPresent,
					VolumeMounts: []corev1.VolumeMount{
						{Name: swtpmSocketVolumeName, MountPath: swtpmSocketDir},
						{Name: swtpmStateVolName, MountPath: "/swtpm-state"},
					},
				},
			},
			Volumes: volumes,
		},
	}
	return deployment
}

// renderSwtpmStatePVC renders the PVC holding the swtpm state of the
// collector (the TPM identity survives collector pod restarts this way).
func renderSwtpmStatePVC(target *attestationv1alpha1.AttestationTarget) *corev1.PersistentVolumeClaim {
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: collectorObjectMeta(target, collectorSwtpmStatePVCName(target))}
	pvc.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	pvc.Spec.Resources.Requests = corev1.ResourceList{
		corev1.ResourceStorage: mustParseQuantity(swtpmStateDefaultStorage),
	}
	return pvc
}

// renderCollectorConfigSecret renders the keylime "oob" config file holding
// the BMC credentials, as an owned secret of the target.
func renderCollectorConfigSecret(target *attestationv1alpha1.AttestationTarget, creds bmcCredentials) *corev1.Secret {
	secret := &corev1.Secret{ObjectMeta: collectorObjectMeta(target, collectorConfigSecretName(target))}
	var b strings.Builder
	b.WriteString("# Rendered by the attestation-operator from spec.bmc.credentialsSecretRef.\n")
	b.WriteString("[oob]\n")
	fmt.Fprintf(&b, "bmc_username = %s\n", creds.Username)
	fmt.Fprintf(&b, "bmc_password = %s\n", creds.Password)
	secret.StringData = map[string]string{oobConfigFile: b.String()}
	return secret
}

func collectorDeploymentName(target *attestationv1alpha1.AttestationTarget) string {
	return target.Name + "-collector"
}

func collectorSwtpmStatePVCName(target *attestationv1alpha1.AttestationTarget) string {
	return target.Name + "-swtpm-state"
}

func collectorClientTLSSecretName(target *attestationv1alpha1.AttestationTarget) string {
	return target.Name + "-client-tls"
}

func collectorConfigSecretName(target *attestationv1alpha1.AttestationTarget) string {
	return target.Name + "-collector-config"
}

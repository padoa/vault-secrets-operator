package controllers

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	ricobergerdev1alpha1 "github.com/ricoberger/vault-secrets-operator/api/v1alpha1"
)

var (
	// vaultSecretStatusCondition mirrors external-secrets' externalsecret_status_condition: one series per
	// condition status, 1 for the current one and 0 for the other.
	vaultSecretStatusCondition = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vaultsecret_status_condition",
		Help: "Status condition of a VaultSecret (1 when the condition has this status).",
	}, []string{"namespace", "name", "engine", "condition", "status"})

	// vaultSecretExpirationTimestamp is the expiry of the certificate or database credentials currently served
	// by the Kubernetes Secret, so a renewal that keeps failing shows up before the secret expires.
	vaultSecretExpirationTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vaultsecret_expiration_timestamp_seconds",
		Help: "Unix time at which the PKI certificate or database credentials held by the VaultSecret's Secret expire.",
	}, []string{"namespace", "name", "engine"})
)

func init() {
	metrics.Registry.MustRegister(vaultSecretStatusCondition, vaultSecretExpirationTimestamp)
}

func engineOf(instance *ricobergerdev1alpha1.VaultSecret) ricobergerdev1alpha1.SecretEngine {
	if instance.Spec.SecretEngine == "" {
		return ricobergerdev1alpha1.KVEngine
	}
	return instance.Spec.SecretEngine
}

var (
	allEngines  = []ricobergerdev1alpha1.SecretEngine{ricobergerdev1alpha1.KVEngine, ricobergerdev1alpha1.PKIEngine, ricobergerdev1alpha1.DatabaseEngine}
	allStatuses = []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse}
)

// deleteVaultSecretMetrics drops every series of a VaultSecret, used once the object is gone.
func deleteVaultSecretMetrics(namespace, name string) {
	// client_golang v1.12 has no DeletePartialMatch: enumerate the finite label combinations instead.
	for _, engine := range allEngines {
		for _, status := range allStatuses {
			vaultSecretStatusCondition.DeleteLabelValues(namespace, name, string(engine), conditionTypeSecretCreated, string(status))
		}
		vaultSecretExpirationTimestamp.DeleteLabelValues(namespace, name, string(engine))
	}
}

// recordVaultSecretMetrics publishes the state of a VaultSecret after a reconcile. It reads the Secret back
// rather than tracking expiry along each code path, so the gauge reflects what workloads actually mount,
// including when a renewal failed and the old secret is still served.
func (r *VaultSecretReconciler) recordVaultSecretMetrics(ctx context.Context, instance *ricobergerdev1alpha1.VaultSecret) {
	engine := engineOf(instance)

	// The engine can change on an existing object: start from a clean slate for this object.
	deleteVaultSecretMetrics(instance.Namespace, instance.Name)

	for _, condition := range instance.Status.Conditions {
		for _, status := range allStatuses {
			value := 0.0
			if condition.Status == status {
				value = 1
			}
			vaultSecretStatusCondition.WithLabelValues(instance.Namespace, instance.Name, string(engine), condition.Type, string(status)).Set(value)
		}
	}

	if engine != ricobergerdev1alpha1.PKIEngine && engine != ricobergerdev1alpha1.DatabaseEngine {
		return
	}

	secret, err := r.getExistingSecret(ctx, instance.Name, instance.Namespace)
	if err != nil || secret == nil {
		return
	}

	if expiresAt := secretExpiration(engine, secret); expiresAt != nil {
		vaultSecretExpirationTimestamp.WithLabelValues(instance.Namespace, instance.Name, string(engine)).Set(float64(expiresAt.Unix()))
	}
}

// secretExpiration returns when the content of a PKI or database Secret expires, or nil when it cannot tell
// (for example a templated PKI secret that keeps neither the certificate nor the expiration key).
func secretExpiration(engine ricobergerdev1alpha1.SecretEngine, secret *corev1.Secret) *time.Time {
	switch engine {
	case ricobergerdev1alpha1.PKIEngine:
		expiresAt, err := getExpirationFromSecret(secret)
		if err != nil {
			return nil
		}
		return expiresAt
	case ricobergerdev1alpha1.DatabaseEngine:
		value, ok := secret.Annotations[annotationExpiration]
		if !ok {
			return nil
		}
		expiresAt, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return nil
		}
		return &expiresAt
	}
	return nil
}

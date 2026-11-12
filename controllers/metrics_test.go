package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ricobergerdev1alpha1 "github.com/ricoberger/vault-secrets-operator/api/v1alpha1"
)

func newMetricsTestReconciler(t *testing.T, objects ...runtime.Object) *VaultSecretReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := ricobergerdev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return &VaultSecretReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build(),
		Scheme: scheme,
	}
}

func newMetricsTestVaultSecret(name string, engine ricobergerdev1alpha1.SecretEngine, status metav1.ConditionStatus) *ricobergerdev1alpha1.VaultSecret {
	return &ricobergerdev1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec:       ricobergerdev1alpha1.VaultSecretSpec{SecretEngine: engine},
		Status: ricobergerdev1alpha1.VaultSecretStatus{Conditions: []metav1.Condition{{
			Type:   conditionTypeSecretCreated,
			Status: status,
		}}},
	}
}

func TestRecordVaultSecretMetricsPKIFailing(t *testing.T) {
	expiresAt := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pki-failing", Namespace: "ns"},
		Data:       map[string][]byte{"tls.crt": createTestCertificate(expiresAt)},
	}
	instance := newMetricsTestVaultSecret("pki-failing", ricobergerdev1alpha1.PKIEngine, metav1.ConditionFalse)
	r := newMetricsTestReconciler(t, secret)

	r.recordVaultSecretMetrics(context.Background(), instance)
	defer deleteVaultSecretMetrics("ns", "pki-failing")

	if got := testutil.ToFloat64(vaultSecretStatusCondition.WithLabelValues("ns", "pki-failing", "pki", conditionTypeSecretCreated, "False")); got != 1 {
		t.Errorf("status False = %v, want 1", got)
	}
	if got := testutil.ToFloat64(vaultSecretStatusCondition.WithLabelValues("ns", "pki-failing", "pki", conditionTypeSecretCreated, "True")); got != 0 {
		t.Errorf("status True = %v, want 0", got)
	}
	if got := testutil.ToFloat64(vaultSecretExpirationTimestamp.WithLabelValues("ns", "pki-failing", "pki")); got != float64(expiresAt.Unix()) {
		t.Errorf("expiration = %v, want %v", got, expiresAt.Unix())
	}
}

func TestRecordVaultSecretMetricsDatabase(t *testing.T) {
	expiresAt := time.Now().Add(720 * time.Hour).Truncate(time.Second)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "db", Namespace: "ns",
		Annotations: map[string]string{annotationExpiration: expiresAt.Format(time.RFC3339)},
	}}
	instance := newMetricsTestVaultSecret("db", ricobergerdev1alpha1.DatabaseEngine, metav1.ConditionTrue)
	r := newMetricsTestReconciler(t, secret)

	r.recordVaultSecretMetrics(context.Background(), instance)
	defer deleteVaultSecretMetrics("ns", "db")

	if got := testutil.ToFloat64(vaultSecretExpirationTimestamp.WithLabelValues("ns", "db", "database")); got != float64(expiresAt.Unix()) {
		t.Errorf("expiration = %v, want %v", got, expiresAt.Unix())
	}
}

func TestRecordVaultSecretMetricsKVHasNoExpiration(t *testing.T) {
	instance := newMetricsTestVaultSecret("kv", "", metav1.ConditionTrue)
	r := newMetricsTestReconciler(t)

	r.recordVaultSecretMetrics(context.Background(), instance)
	defer deleteVaultSecretMetrics("ns", "kv")

	if got := testutil.ToFloat64(vaultSecretStatusCondition.WithLabelValues("ns", "kv", "kv", conditionTypeSecretCreated, "True")); got != 1 {
		t.Errorf("status True = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(vaultSecretExpirationTimestamp); n != 0 {
		t.Errorf("expiration series = %d, want 0", n)
	}
}

func TestDeleteVaultSecretMetrics(t *testing.T) {
	instance := newMetricsTestVaultSecret("gone", ricobergerdev1alpha1.PKIEngine, metav1.ConditionTrue)
	r := newMetricsTestReconciler(t)
	r.recordVaultSecretMetrics(context.Background(), instance)

	deleteVaultSecretMetrics("ns", "gone")

	if n := testutil.CollectAndCount(vaultSecretStatusCondition); n != 0 {
		t.Errorf("status series = %d, want 0", n)
	}
}

func TestRecordVaultSecretMetricsEngineChange(t *testing.T) {
	r := newMetricsTestReconciler(t)
	r.recordVaultSecretMetrics(context.Background(), newMetricsTestVaultSecret("switch", "", metav1.ConditionTrue))
	r.recordVaultSecretMetrics(context.Background(), newMetricsTestVaultSecret("switch", ricobergerdev1alpha1.PKIEngine, metav1.ConditionTrue))
	defer deleteVaultSecretMetrics("ns", "switch")

	// Only the pki pair is left: True and False.
	if n := testutil.CollectAndCount(vaultSecretStatusCondition); n != 2 {
		t.Errorf("status series = %d, want 2", n)
	}
}

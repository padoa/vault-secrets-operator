package controllers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/hashicorp/vault/api"

	ricobergerdev1alpha1 "github.com/ricoberger/vault-secrets-operator/api/v1alpha1"
	"github.com/ricoberger/vault-secrets-operator/vault"

	"github.com/Masterminds/sprig"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	conditionTypeSecretCreated  = "SecretCreated"
	conditionReasonFetchFailed  = "FetchFailed"
	conditionReasonCreated      = "Created"
	conditionReasonCreateFailed = "CreateFailed"
	conditionReasonUpdated      = "Updated"
	conditionReasonUpdateFailed = "UpdateFailed"
	conditionReasonMergeFailed  = "MergeFailed"
	conditionInvalidResource    = "InvalidResource"
)

// VaultSecretReconciler reconciles a VaultSecret object
type VaultSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=ricoberger.de,resources=vaultsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ricoberger.de,resources=vaultsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=ricoberger.de,resources=vaultsecrets/finalizers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.7.0/pkg/reconcile
func (r *VaultSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logr.FromContext(ctx)

	// Set reconciliation if the vault-secret does not specify a version.
	reconcileResult := ctrl.Result{}
	if vault.ReconciliationTime > 0 {
		reconcileResult = ctrl.Result{
			RequeueAfter: time.Second * time.Duration(vault.ReconciliationTime),
		}
	}

	// Fetch the VaultSecret instance
	instance := &ricobergerdev1alpha1.VaultSecret{}

	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return ctrl.Result{}, err
	}

	// Get secret from Vault.
	// If the VaultSecret contains the vaultRole property we are creating a new client with the specified Vault Role to
	// get the secret.
	// When the property isn't set we are using the shared client. It is also possible that the shared client is nil, so
	// that we have to check for this first. This could happen since we do not return an error when we initializing the
	// client during start up, to not require a default Vault Role.
	var data map[string][]byte

	var vaultClient *vault.Client

	if instance.Spec.VaultRole != "" {
		log.WithValues("vaultRole", instance.Spec.VaultRole).Info("Create client to get secret from Vault")
		vaultClient, err = vault.CreateClient(instance.Spec.VaultRole)
		if err != nil {
			// Error creating the Vault client - requeue the request.
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}
	} else {
		log.Info("Use shared client to get secret from Vault")
		if vault.SharedClient == nil {
			err = fmt.Errorf("shared client not initialized and vaultRole property missing")
			log.Error(err, "Could not get secret from Vault")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		} else {
			vaultClient = vault.SharedClient
		}
	}

	var expiresAt *time.Time
	var requeueAfter time.Duration

	// KV secret
	if instance.Spec.SecretEngine == "" || instance.Spec.SecretEngine == ricobergerdev1alpha1.KVEngine {
		secret, err := vaultClient.GetSecret(instance.Spec.Path, instance.Spec.Version, instance.Spec.VaultNamespace)
		if err != nil {
			log.Error(err, "Could not get secret from vault")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		data, err = vaultClient.KVRenderData(secret, instance.Spec.Keys, instance.Spec.IsBinary)
		if err != nil {
			log.Error(err, "Could not render secret data")
			r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		// PKI secret
	} else if instance.Spec.SecretEngine == ricobergerdev1alpha1.PKIEngine {
		if err := ValidatePKI(instance); err != nil {
			log.Error(err, "Resource validation failed")
			r.updateConditions(ctx, instance, conditionInvalidResource, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		existingSecret, err := r.getExistingSecret(ctx, instance.Name, instance.Namespace)
		if err != nil {
			log.Error(err, "Error checking for existing secret")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		certificateTTL := vaultClient.GetDefaultPKITTL()
		if instance.Spec.EngineOptions != nil {
			if ttl, ok := instance.Spec.EngineOptions["ttl"]; ok && ttl != "" {
				parsedTTL, err := time.ParseDuration(ttl)
				if err != nil {
					log.Error(err, "Could not parse certificate TTL for PKI secret")
				} else {
					certificateTTL = parsedTTL
				}
			}
		}

		// Determine renewal decision
		renewalThreshold := vaultClient.GetPKIRenewalThreshold()
		renewalJitter := vaultClient.GetPKIRenewalJitter()
		needsRenewal, renewalDate := needsCertificateRenewal(ctx, existingSecret, certificateTTL, renewalThreshold, renewalJitter)

		if !needsRenewal {
			log.Info(fmt.Sprintf("No renewal required for PKI %s, will renew around %s", instance.Name, renewalDate.String()))
			reconcileResult.RequeueAfter = time.Until(*renewalDate)
			return reconcileResult, nil
		}

		// Generate new certificate
		log.Info(fmt.Sprintf("Generating new PKI certificate for %s", instance.Name))
		var secret *api.Secret
		secret, expiresAt, err = vaultClient.GetCertificate(instance.Spec.Path, instance.Spec.Role, instance.Spec.EngineOptions)
		if err != nil {
			log.Error(err, "Could not get certificate from vault")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		data, err = vaultClient.PKIRenderData(secret)
		if err != nil {
			log.Error(err, "Could not render certificate data")
			r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		// Database secret
	} else if instance.Spec.SecretEngine == ricobergerdev1alpha1.DatabaseEngine {
		if err := ValidateDatabase(instance); err != nil {
			log.Error(err, "Resource validation failed")
			r.updateConditions(ctx, instance, conditionInvalidResource, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		var secret *api.Secret
		secret, expiresAt, err = vaultClient.GetDatabaseCreds(instance.Spec.Path, instance.Spec.Role)
		if err != nil {
			log.Error(err, "Could not get database credentials from vault")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		data, err = vaultClient.DatabaseRenderData(secret)
		if err != nil {
			log.Error(err, "Could not render database data")
			r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		requeueAfter = expiresAt.Sub(time.Now()) - vaultClient.DatabaseRenew
	}

	if expiresAt != nil {
		reconcileResult.RequeueAfter = time.Until(*expiresAt)
		log.Info(fmt.Sprintf("Secret %s will expire on %s", instance.Name, expiresAt.String()))
		log.Info(fmt.Sprintf("Secret %s will be renewed on %s", instance.Name, time.Now().Add(requeueAfter).String()))
	}

	// Define a new Secret object
	secret, err := newSecretForCR(instance, data)
	if err != nil {
		// Error while creating the Kubernetes secret - requeue the request.
		log.Error(err, "Could not create Kubernetes secret")
		r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
		return ctrl.Result{}, err
	}

	// Set VaultSecret instance as the owner and controller
	err = ctrl.SetControllerReference(instance, secret, r.Scheme)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Check if this Secret already exists
	found, err := r.getExistingSecret(ctx, secret.Name, secret.Namespace)
	if err != nil {
		log.Error(err, "Could not check for existing secret")
		r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
		return ctrl.Result{}, err
	}

	if found == nil {
		log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.Create(ctx, secret)
		if err != nil {
			log.Error(err, "Could not create secret")
			r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}

		// Secret created successfully - requeue only if no version is specified
		r.updateConditions(ctx, instance, conditionReasonCreated, "Secret was created", metav1.ConditionTrue)
		return reconcileResult, nil
	}

	// Secret already exists, update the secret
	// Merge -> Checks the existing data keys and merge them into the updated secret
	// Replace -> Do not check the data keys and replace the secret
	if instance.Spec.ReconcileStrategy == "Merge" {
		secret = mergeSecretData(secret, found)

		log.Info("Updating a Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.Update(ctx, secret)
		if err != nil {
			log.Error(err, "Could not update secret")
			r.updateConditions(ctx, instance, conditionReasonMergeFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}
		r.updateConditions(ctx, instance, conditionReasonUpdated, "Secret was updated", metav1.ConditionTrue)
	} else {
		log.Info("Updating a Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.Update(ctx, secret)
		if err != nil {
			log.Error(err, "Could not update secret")
			r.updateConditions(ctx, instance, conditionReasonUpdateFailed, err.Error(), metav1.ConditionFalse)
			return ctrl.Result{}, err
		}
		r.updateConditions(ctx, instance, conditionReasonUpdated, "Secret was updated", metav1.ConditionTrue)
	}

	return reconcileResult, nil
}

func (r *VaultSecretReconciler) updateConditions(ctx context.Context, instance *ricobergerdev1alpha1.VaultSecret, reason, message string, status metav1.ConditionStatus) {
	//instance.Status.Expires = true
	//instance.Status.ExpiresAt = time.Now().Add(time.Second * 30).String()
	instance.Status.Conditions = []metav1.Condition{{
		Type:               conditionTypeSecretCreated,
		Status:             status,
		ObservedGeneration: instance.GetGeneration(),
		LastTransitionTime: metav1.NewTime(time.Now()),
		Reason:             reason,
		Message:            message,
	}}

	err := r.Status().Update(ctx, instance)
	if err != nil {
		logr.FromContext(ctx).Error(err, "Could not update status")
	}
}

func computeRenewalDate(expiresAt *time.Time, certificateDuration time.Duration, renewalThreshold float64, renewalJitter float64) *time.Time {
	// Generate final renewal lifetime percentage with jitter
	// jitter ranges from -renewalJitter to +renewalJitter
	jitter := 0.0
	if renewalJitter > 0 {
		jitter = (rand.Float64() - 0.5) * 2 * renewalJitter
	}

	finalRenewalPercentage := renewalThreshold + jitter

	if finalRenewalPercentage > 1 || finalRenewalPercentage < 0 {
		panic(fmt.Sprintf("finalRenewalPercentage is out of bounds: %f", finalRenewalPercentage))
	}

	maxRemainingTimeBeforeRenewal := time.Duration(float64(certificateDuration) * finalRenewalPercentage)
	renewalDate := expiresAt.Add(-maxRemainingTimeBeforeRenewal)

	return &renewalDate
}

// needsCertificateRenewal determines if a PKI certificate needs renewal
// in case of an error, we return true to always renew the certificate just to be safe
func needsCertificateRenewal(ctx context.Context, existingSecret *corev1.Secret, certificateDuration time.Duration, renewalThreshold float64, renewalJitter float64) (needsRenewal bool, renewalDate *time.Time) {
	log := logr.FromContext(ctx)
	if existingSecret == nil {
		// No existing secret found, renewal required
		return true, nil
	}

	expiresAt, err := getExpirationFromSecret(existingSecret)
	if err != nil {
		log.Error(err, "could not parse expiration for existing secret, renewal required")
		return true, nil
	}

	renewalDate = computeRenewalDate(expiresAt, certificateDuration, renewalThreshold, renewalJitter)

	// Check if current date is after this threshold
	now := time.Now()
	needsRenewal = now.After(*renewalDate)

	return needsRenewal, renewalDate
}

// getExistingSecret retrieves an existing Kubernetes secret, returning nil if not found
func (r *VaultSecretReconciler) getExistingSecret(ctx context.Context, name, namespace string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: name, Namespace: namespace}

	err := r.Get(ctx, secretKey, secret)
	if err != nil && errors.IsNotFound(err) {
		return nil, nil // Not found, but not an error
	} else if err != nil {
		return nil, err // Actual error
	}

	return secret, nil
}

// getExpirationFromSecret extracts the expiration time from a PKI secret
func getExpirationFromSecret(secret *corev1.Secret) (*time.Time, error) {
	// First, try to get expiration field directly (primary method)
	if expirationData, exists := secret.Data["expiration"]; exists {
		if expirationUnix, err := strconv.ParseInt(string(expirationData), 10, 64); err == nil {
			expirationTime := time.Unix(expirationUnix, 0)
			return &expirationTime, nil
		}
	}

	// Fallback: parse X.509 certificate for expiration
	certData := getCertificateData(secret)
	if certData == nil {
		return nil, fmt.Errorf("no expiration field or certificate data found in secret")
	}

	expirationTime, err := parseCertificateExpiration(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}

	return expirationTime, nil
}

// getCertificateData extracts certificate data from a secret
func getCertificateData(secret *corev1.Secret) []byte {
	// For the moment, we always template certificato to tls.crt key. If this change, you might need to edit this function.
	if certData, exists := secret.Data["tls.crt"]; exists {
		return certData
	}
	if certData, exists := secret.Data["certificate"]; exists {
		return certData
	}
	return nil
}

// parseCertificateExpiration parses X.509 certificate expiration from PEM data
func parseCertificateExpiration(certData []byte) (*time.Time, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %v", err)
	}

	return &cert.NotAfter, nil
}

// ignorePredicate is used to ignore updates to CR status in which case metadata.Generation does not change.
func ignorePredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 6, // We launch a dice, it want to 6
		}).
		For(&ricobergerdev1alpha1.VaultSecret{}).
		Owns(&corev1.Secret{}).
		WithEventFilter(ignorePredicate()).
		Complete(r)
}

// Context provided to the templating engine

type templateVaultContext struct {
	Path    string
	Address string
}

type templateContext struct {
	Secrets     map[string]string
	Vault       templateVaultContext
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// runTemplate executes a template with the given secrets map, filled with the Vault secrets
func runTemplate(cr *ricobergerdev1alpha1.VaultSecret, tmpl string, secrets map[string][]byte) ([]byte, error) {
	// Set up the context
	sd := templateContext{
		Secrets: make(map[string]string, len(secrets)),
		Vault: templateVaultContext{
			Path:    cr.Spec.Path,
			Address: os.Getenv("VAULT_ADDRESS"),
		},
		Namespace:   cr.Namespace,
		Labels:      cr.Labels,
		Annotations: cr.Annotations,
	}

	// For templating, these should all be strings, convert
	for k, v := range secrets {
		sd.Secrets[k] = string(v)
	}

	// We need to exclude some functions for security reasons and proper working of the operator, don't use TxtFuncMap:
	// - no environment-variable related functions to prevent secrets from accessing the VAULT environment variables
	// - no filesystem functions? Directory functions don't actually allow access to the FS, so they're OK.
	// - no other non-idempotent functions like random and crypto functions
	funcmap := sprig.HermeticTxtFuncMap()
	delete(funcmap, "genPrivateKey")
	delete(funcmap, "genCA")
	delete(funcmap, "genSelfSignedCert")
	delete(funcmap, "genSignedCert")
	delete(funcmap, "htpasswd") // bcrypt strings contain salt

	tmplParser := template.New("data").Funcs(funcmap)

	// use other delimiters to prevent clashing with Helm templates
	tmplParser.Delims("{%", "%}")

	t, err := tmplParser.Parse(tmpl)
	if err != nil {
		return nil, err
	}

	var bout bytes.Buffer
	err = t.Execute(&bout, sd)
	if err != nil {
		return nil, err
	}

	return bout.Bytes(), nil
}

// newSecretForCR returns a secret with the same name/namespace as the CR. The secret will include all labels and
// annotations from the CR.
func newSecretForCR(cr *ricobergerdev1alpha1.VaultSecret, data map[string][]byte) (*corev1.Secret, error) {
	labels := map[string]string{}
	for k, v := range cr.ObjectMeta.Labels {
		labels[k] = v
	}

	annotations := map[string]string{}
	for k, v := range cr.ObjectMeta.Annotations {
		annotations[k] = v
	}

	if cr.Spec.Templates != nil {
		newdata := make(map[string][]byte)
		for k, v := range cr.Spec.Templates {
			templated, err := runTemplate(cr, v, data)
			if err != nil {
				return nil, fmt.Errorf("template error: %w", err)
			}
			newdata[k] = templated
		}
		data = newdata
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: data,
		Type: cr.Spec.Type,
	}, nil
}

func mergeSecretData(new, found *corev1.Secret) *corev1.Secret {
	for key, value := range found.Data {
		if _, ok := new.Data[key]; !ok {
			new.Data[key] = value
		}
	}

	return new
}

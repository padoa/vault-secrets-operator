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

	// Annotation key for storing VaultSecret spec hash
	annotationSpecHash      = "vault-secrets-operator.ricoberger.de/vaultsecret-spec-hash"
	annotationLeaseID       = "vault-secrets-operator.ricoberger.de/lease-id"
	annotationLeaseDuration = "vault-secrets-operator.ricoberger.de/lease-duration"
	annotationRenewable     = "vault-secrets-operator.ricoberger.de/renewable"
	annotationExpiration    = "vault-secrets-operator.ricoberger.de/expiration"
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

	// Data is the data to be added to the Kubernetes secret
	var data map[string][]byte

	// ExtraAnnotations are the extra annotations to be added to the Kubernetes secret
	var extraAnnotations map[string]string

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

		if existingSecret != nil {
			// Check if spec has changed by comparing hashes
			currentSpecHash := instance.Spec.Hash()

			storedHash, exists := existingSecret.Annotations[annotationSpecHash]
			if exists && storedHash != currentSpecHash {
				log.Info(fmt.Sprintf("Spec changed for PKI %s, regenerating certificate", instance.Name))
				// Force regeneration by continuing to certificate generation
			} else {
				// Spec hasn't changed or annotation doesn't exist, use time-based renewal logic
				// We don't want to trigger a PKI request storm for all existing secrets without the annotation, so we only
				// add it during the next necessary renewal.
				renewalThreshold := vaultClient.GetPKIRenewalThreshold()
				renewalJitter := vaultClient.GetPKIRenewalJitter()
				needsRenewal, renewalDate, expiresAt := needsCertificateRenewal(ctx, existingSecret, certificateTTL, renewalThreshold, renewalJitter)

				if !needsRenewal {
					log.Info(fmt.Sprintf("No renewal required for PKI %s, will expire on %s, will renew around %s", instance.Name, expiresAt.String(), renewalDate.String()))
					reconcileResult.RequeueAfter = time.Until(*renewalDate)
					return reconcileResult, nil
				}
				log.Info(fmt.Sprintf("Renewal required for PKI %s, will expire on %s", instance.Name, expiresAt.String()))
			}
		}

		// Generate new certificate
		log.Info(fmt.Sprintf("Generating new PKI certificate for %s", instance.Name))
		var secret *api.Secret
		secret, expiresAt, err := vaultClient.GetCertificate(instance.Spec.Path, instance.Spec.Role, instance.Spec.EngineOptions)
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

		log.Info(fmt.Sprintf("PKI Secret %s created, will expire on %s", instance.Name, expiresAt.String()))
		// Do not set requeue now, will be set the next time we check the secret

		// Database secret
	} else if instance.Spec.SecretEngine == ricobergerdev1alpha1.DatabaseEngine {
		var dbReconcileResult ctrl.Result
		data, extraAnnotations, dbReconcileResult, err = r.handleDatabaseSecret(ctx, instance, vaultClient)
		if err != nil {
			return ctrl.Result{}, err
		}
		// If renewal is not needed, return early with requeue time
		if data == nil {
			return dbReconcileResult, nil
		}
		// Merge reconcile result if needed
		if dbReconcileResult.RequeueAfter > 0 {
			reconcileResult.RequeueAfter = dbReconcileResult.RequeueAfter
		}
	}

	// Define a new Secret object
	log.Info(fmt.Sprintf("Generating Kubernetes secret for %s with data: %+v", instance.Name, data))
	secret, err := newSecretForCR(instance, data, extraAnnotations)
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

// computeRenewalDate calculates when a secret should be renewed based on expiration time,
// duration, renewal threshold, and jitter. Works for both PKI certificates and database credentials.
// jitter ranges from -renewalJitter to +renewalJitter to add randomness and prevent renewal storms.
func computeRenewalDate(expiresAt *time.Time, duration time.Duration, renewalThreshold float64, renewalJitter float64) *time.Time {
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

	maxRemainingTimeBeforeRenewal := time.Duration(float64(duration) * finalRenewalPercentage)
	renewalDate := expiresAt.Add(-maxRemainingTimeBeforeRenewal)

	return &renewalDate
}

// needsCertificateRenewal determines if a PKI certificate needs renewal
// in case of an error, we return true to always renew the certificate just to be safe
func needsCertificateRenewal(ctx context.Context, existingSecret *corev1.Secret, certificateDuration time.Duration, renewalThreshold float64, renewalJitter float64) (needsRenewal bool, renewalDate, expiresAt *time.Time) {
	log := logr.FromContext(ctx)
	if existingSecret == nil {
		// No existing secret found, renewal required
		return true, nil, nil
	}

	expiresAt, err := getExpirationFromSecret(existingSecret)
	if err != nil {
		log.Error(err, "could not parse expiration for existing secret, renewal required")
		return true, nil, nil
	}

	renewalDate = computeRenewalDate(expiresAt, certificateDuration, renewalThreshold, renewalJitter)

	// Check if current date is after this threshold
	now := time.Now()
	needsRenewal = now.After(*renewalDate)

	return needsRenewal, renewalDate, expiresAt
}

// needsDatabaseRenewal determines if a Database credentials needs renewal
// in case of an error, we return true to always renew the database credentials just to be safe
func needsDatabaseRenewal(expiresAt *time.Time, databaseDuration time.Duration, renewalThreshold float64, renewalJitter float64) (needsRenewal bool, renewalDate *time.Time) {
	renewalDate = computeRenewalDate(expiresAt, databaseDuration, renewalThreshold, renewalJitter)

	// Check if current date is after this threshold
	now := time.Now()
	needsRenewal = now.After(*renewalDate)

	return needsRenewal, renewalDate
}

// parseDatabaseAnnotations extracts and parses database secret annotations
func parseDatabaseAnnotations(existingSecret *corev1.Secret) (duration time.Duration, expiresAt time.Time, err error) {
	durationStr, durationExists := existingSecret.Annotations[annotationLeaseDuration]
	if !durationExists {
		return 0, time.Time{}, fmt.Errorf("lease duration annotation not found")
	}

	durationInt, err := strconv.Atoi(durationStr)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("could not parse lease duration: %w", err)
	}
	if durationInt <= 0 {
		return 0, time.Time{}, fmt.Errorf("lease duration must be positive, got: %d", durationInt)
	}
	duration = time.Duration(durationInt) * time.Second

	expirationStr, expirationExists := existingSecret.Annotations[annotationExpiration]
	if !expirationExists {
		return 0, time.Time{}, fmt.Errorf("expiration time annotation not found")
	}

	expiresAt, err = time.Parse(time.RFC3339, expirationStr)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("could not parse expiration time: %w", err)
	}

	return duration, expiresAt, nil
}

// checkDatabaseSecretRenewal determines if a database secret needs renewal
// Returns (needsRenewal, renewalDate, expiresAt, error)
// If renewal is not needed, renewalDate will be set for requeue scheduling
func checkDatabaseSecretRenewal(ctx context.Context, instance *ricobergerdev1alpha1.VaultSecret, existingSecret *corev1.Secret, vaultClient *vault.Client) (needsRenewal bool, renewalDate *time.Time, expiresAt *time.Time, err error) {
	log := logr.FromContext(ctx)

	if existingSecret == nil {
		// No existing secret found, renewal required
		return true, nil, nil, nil
	}

	// Check if spec has changed by comparing hashes
	currentSpecHash := instance.Spec.Hash()
	storedHash, hashExists := existingSecret.Annotations[annotationSpecHash]
	_, expirationExists := existingSecret.Annotations[annotationExpiration]
	_, durationExists := existingSecret.Annotations[annotationLeaseDuration]

	if !expirationExists {
		log.Info(fmt.Sprintf("Expiration time annotation not found in Kubernetes secret %s, renewal required", instance.Name))
		return true, nil, nil, nil
	}

	if !durationExists {
		log.Info(fmt.Sprintf("Lease duration annotation not found in Kubernetes secret %s, renewal required", instance.Name))
		return true, nil, nil, nil
	}

	if !hashExists {
		log.Info(fmt.Sprintf("Spec hash annotation not found in Kubernetes secret %s, renewal required", instance.Name))
		return true, nil, nil, nil
	}

	if storedHash != currentSpecHash {
		log.Info(fmt.Sprintf("Spec changed for Database secret %s, regenerating creds", instance.Name))
		return true, nil, nil, nil
	}

	// Parse annotations
	databaseDuration, expiresAtParsed, err := parseDatabaseAnnotations(existingSecret)
	if err != nil {
		return true, nil, nil, err
	}

	expiresAt = &expiresAtParsed

	// Check if renewal is needed based on threshold and jitter
	renewalThreshold := vaultClient.GetDatabaseRenewalThreshold()
	renewalJitter := vaultClient.GetDatabaseRenewalJitter()
	needsRenewal, renewalDate = needsDatabaseRenewal(expiresAt, databaseDuration, renewalThreshold, renewalJitter)

	return needsRenewal, renewalDate, expiresAt, nil
}

// handleDatabaseSecret processes database secret creation/renewal
// Returns (data, extraAnnotations, reconcileResult, error)
func (r *VaultSecretReconciler) handleDatabaseSecret(ctx context.Context, instance *ricobergerdev1alpha1.VaultSecret, vaultClient *vault.Client) (map[string][]byte, map[string]string, ctrl.Result, error) {
	log := logr.FromContext(ctx)
	reconcileResult := ctrl.Result{}

	// Validate database resource
	if err := ValidateDatabase(instance); err != nil {
		log.Error(err, "Resource validation failed")
		r.updateConditions(ctx, instance, conditionInvalidResource, err.Error(), metav1.ConditionFalse)
		return nil, nil, ctrl.Result{}, err
	}

	// Get existing secret in Kubernetes to check hash
	existingSecret, err := r.getExistingSecret(ctx, instance.Name, instance.Namespace)
	if err != nil {
		log.Error(err, "Error checking for existing secret")
		r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
		return nil, nil, ctrl.Result{}, err
	}

	// Check if existing secret exists and if it needs renewal
	if existingSecret != nil {
		needsRenewal, renewalDate, expiresAt, err := checkDatabaseSecretRenewal(ctx, instance, existingSecret, vaultClient)
		if err != nil {
			log.Error(err, "Error checking database secret renewal")
			r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
			return nil, nil, ctrl.Result{}, err
		}

		if !needsRenewal {
			log.Info(fmt.Sprintf("No renewal required for Database secret %s, will expire on %s, will renew around %s", instance.Name, expiresAt.String(), renewalDate.String()))
			reconcileResult.RequeueAfter = time.Until(*renewalDate)
			return nil, nil, reconcileResult, nil
		}

		log.Info(fmt.Sprintf("Renewal required for Database secret %s, will expire on %s", instance.Name, expiresAt.String()))
	}

	// Generate new database credentials
	log.Info(fmt.Sprintf("Generating new database credentials for %s", instance.Name))

	// Generate dynamic database credentials from Vault
	creds, err := vaultClient.GetDatabaseCreds(instance.Spec.Path, instance.Spec.Role)
	if err != nil {
		log.Error(err, "Could not get database credentials from vault")
		r.updateConditions(ctx, instance, conditionReasonFetchFailed, err.Error(), metav1.ConditionFalse)
		return nil, nil, ctrl.Result{}, err
	}

	// Render database credentials into data map for Kubernetes secret
	data, err := vaultClient.DatabaseRenderData(creds)
	if err != nil {
		log.Error(err, "Could not render database data")
		r.updateConditions(ctx, instance, conditionReasonCreateFailed, err.Error(), metav1.ConditionFalse)
		return nil, nil, ctrl.Result{}, err
	}

	// Add lease metadata to extra annotations
	extraAnnotations := map[string]string{
		annotationLeaseID:       creds.LeaseID,
		annotationLeaseDuration: strconv.Itoa(creds.LeaseDuration),
		annotationRenewable:     strconv.FormatBool(creds.Renewable),
		annotationExpiration:    time.Now().Add(time.Duration(creds.LeaseDuration) * time.Second).Format(time.RFC3339),
	}

	return data, extraAnnotations, reconcileResult, nil
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
func (r *VaultSecretReconciler) SetupWithManager(mgr ctrl.Manager, maxConcurrentReconciles int) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: maxConcurrentReconciles,
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
func newSecretForCR(cr *ricobergerdev1alpha1.VaultSecret, data map[string][]byte, extraAnnotations map[string]string) (*corev1.Secret, error) {
	// Copy labels
	labels := map[string]string{}
	for k, v := range cr.ObjectMeta.Labels {
		labels[k] = v
	}

	// Copy annotations
	annotations := map[string]string{}
	for k, v := range cr.ObjectMeta.Annotations {
		annotations[k] = v
	}

	// Add spec hash for PKI & Database engines
	if cr.Spec.SecretEngine == ricobergerdev1alpha1.PKIEngine ||
		cr.Spec.SecretEngine == ricobergerdev1alpha1.DatabaseEngine {

		annotations[annotationSpecHash] = cr.Spec.Hash()
	}

	// Apply templating if needed
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

	// Add extra annotations ONLY if not empty
	if len(extraAnnotations) > 0 {
		for k, v := range extraAnnotations {
			annotations[k] = v
		}
	}

	// Build the Secret
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

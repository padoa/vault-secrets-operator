package v1alpha1

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestVaultSecretSpec_Hash(t *testing.T) {
	t.Run("deterministic behavior", func(t *testing.T) {
		spec := VaultSecretSpec{
			Path:         "pki/dev/db/v1/ica/v1",
			Role:         "server",
			SecretEngine: PKIEngine,
			EngineOptions: map[string]string{
				"common_name": "example.com",
				"ttl":         "5m",
				"alt_names":   "www.example.com,api.example.com",
			},
			ReconcileStrategy: "Replace",
			Templates: map[string]string{
				"ca.crt":  "{% .Secrets.issuing_ca %}",
				"tls.crt": "{% .Secrets.certificate %}",
				"tls.key": "{% .Secrets.private_key %}",
			},
			Type: corev1.SecretTypeOpaque,
		}

		// Generate hash multiple times to ensure deterministic behavior
		hash1 := spec.Hash()
		hash2 := spec.Hash()
		hash3 := spec.Hash()

		if hash1 != hash2 || hash1 != hash3 {
			t.Errorf("Hash function is not deterministic: hash1=%s, hash2=%s, hash3=%s", hash1, hash2, hash3)
		}

		if hash1 == "" {
			t.Error("Hash function should not return empty string")
		}
	})

	t.Run("map order independence", func(t *testing.T) {
		// Create identical specs with maps populated in different orders
		spec1 := VaultSecretSpec{
			Path:         "pki/dev/db/v1/ica/v1",
			Role:         "server",
			SecretEngine: PKIEngine,
			EngineOptions: map[string]string{
				"common_name": "example.com",
				"ttl":         "5m",
				"alt_names":   "www.example.com",
			},
			Templates: map[string]string{
				"ca.crt":  "{% .Secrets.issuing_ca %}",
				"tls.crt": "{% .Secrets.certificate %}",
				"tls.key": "{% .Secrets.private_key %}",
			},
			Type: corev1.SecretTypeOpaque,
		}

		spec2 := VaultSecretSpec{
			Path:         "pki/dev/db/v1/ica/v1",
			Role:         "server",
			SecretEngine: PKIEngine,
			Type:         corev1.SecretTypeOpaque,
		}
		// Populate maps in different order
		spec2.EngineOptions = make(map[string]string)
		spec2.EngineOptions["ttl"] = "5m"
		spec2.EngineOptions["alt_names"] = "www.example.com"
		spec2.EngineOptions["common_name"] = "example.com"

		spec2.Templates = make(map[string]string)
		spec2.Templates["tls.key"] = "{% .Secrets.private_key %}"
		spec2.Templates["ca.crt"] = "{% .Secrets.issuing_ca %}"
		spec2.Templates["tls.crt"] = "{% .Secrets.certificate %}"

		hash1 := spec1.Hash()
		hash2 := spec2.Hash()

		if hash1 != hash2 {
			t.Errorf("Hash function is affected by map insertion order: hash1=%s, hash2=%s", hash1, hash2)
		}
	})

	t.Run("different specs produce different hashes", func(t *testing.T) {
		baseSpec := VaultSecretSpec{
			Path:         "pki/dev/db/v1/ica/v1",
			Role:         "server",
			SecretEngine: PKIEngine,
			EngineOptions: map[string]string{
				"common_name": "example.com",
				"ttl":         "5m",
			},
			Type: corev1.SecretTypeOpaque,
		}

		// Test different variations
		variations := []struct {
			name string
			spec VaultSecretSpec
		}{
			{
				name: "different path",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Path = "pki/prod/db/v1/ica/v1"
					return s
				}(),
			},
			{
				name: "different role",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Role = "client"
					return s
				}(),
			},
			{
				name: "different engine options",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.EngineOptions = map[string]string{
						"common_name": "example.com",
						"ttl":         "10m", // Changed from 5m
					}
					return s
				}(),
			},
			{
				name: "additional engine option",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.EngineOptions = map[string]string{
						"common_name": "example.com",
						"ttl":         "5m",
						"alt_names":   "www.example.com", // Added
					}
					return s
				}(),
			},
			{
				name: "different secret engine",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.SecretEngine = KVEngine
					return s
				}(),
			},
			{
				name: "different type",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Type = corev1.SecretTypeTLS
					return s
				}(),
			},
			{
				name: "with templates",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Templates = map[string]string{
						"tls.crt": "{% .Secrets.certificate %}",
					}
					return s
				}(),
			},
			{
				name: "different reconcile strategy",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.ReconcileStrategy = "Merge"
					return s
				}(),
			},
			{
				name: "with vault namespace",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.VaultNamespace = "test-ns"
					return s
				}(),
			},
			{
				name: "with vault role",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.VaultRole = "test-role"
					return s
				}(),
			},
			{
				name: "with keys",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Keys = []string{"key1", "key2"}
					return s
				}(),
			},
			{
				name: "with version",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.Version = 42
					return s
				}(),
			},
			{
				name: "with binary flag",
				spec: func() VaultSecretSpec {
					s := baseSpec
					s.IsBinary = true
					return s
				}(),
			},
		}

		baseHash := baseSpec.Hash()

		for _, variation := range variations {
			t.Run(variation.name, func(t *testing.T) {
				variationHash := variation.spec.Hash()
				if baseHash == variationHash {
					t.Errorf("Variation '%s' produced same hash as base spec. Base: %s, Variation: %s",
						variation.name, baseHash, variationHash)
				}
			})
		}
	})

	t.Run("empty maps vs nil maps", func(t *testing.T) {
		spec1 := VaultSecretSpec{
			Path:          "test",
			SecretEngine:  PKIEngine,
			Type:          corev1.SecretTypeOpaque,
			EngineOptions: nil,
			Templates:     nil,
		}

		spec2 := VaultSecretSpec{
			Path:          "test",
			SecretEngine:  PKIEngine,
			Type:          corev1.SecretTypeOpaque,
			EngineOptions: make(map[string]string),
			Templates:     make(map[string]string),
		}

		hash1 := spec1.Hash()
		hash2 := spec2.Hash()

		// Both should produce the same hash since JSON marshaling treats nil and empty maps the same
		if hash1 != hash2 {
			t.Errorf("nil maps and empty maps should produce same hash: hash1=%s, hash2=%s", hash1, hash2)
		}
	})

	t.Run("empty slices vs nil slices", func(t *testing.T) {
		spec1 := VaultSecretSpec{
			Path:         "test",
			SecretEngine: PKIEngine,
			Type:         corev1.SecretTypeOpaque,
			Keys:         nil,
		}

		spec2 := VaultSecretSpec{
			Path:         "test",
			SecretEngine: PKIEngine,
			Type:         corev1.SecretTypeOpaque,
			Keys:         []string{},
		}

		hash1 := spec1.Hash()
		hash2 := spec2.Hash()

		// Both should produce the same hash since JSON marshaling treats nil and empty slices the same
		if hash1 != hash2 {
			t.Errorf("nil slices and empty slices should produce same hash: hash1=%s, hash2=%s", hash1, hash2)
		}
	})
}

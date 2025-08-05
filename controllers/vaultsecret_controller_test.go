package controllers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestComputeRenewalDate(t *testing.T) {
	// Use fixed times to make tests predictable
	baseTime := time.Date(2024, 1, 1, 19, 0, 0, 0, time.UTC)

	tests := []struct {
		name                   string
		expiresAt              time.Time
		certificateDuration    time.Duration
		renewalThreshold       float64
		renewalJitter          float64
		expectedRenewalDateMin time.Time
		expectedRenewalDateMax time.Time
		description            string
	}{
		{
			name:                   "renew now, no jitter",
			expiresAt:              baseTime.Add(3 * time.Hour),
			certificateDuration:    10 * time.Hour, // 24h total duration
			renewalThreshold:       0.3,            // 30% threshold
			renewalJitter:          0.0,            // No jitter
			expectedRenewalDateMin: baseTime,
			expectedRenewalDateMax: baseTime, // Same (no jitter)
			description:            "Should renew now",
		},
		{
			name:                   "renew before, no jitter",
			expiresAt:              baseTime.Add(2 * time.Hour),
			certificateDuration:    10 * time.Hour, // 24h total duration
			renewalThreshold:       0.3,            // 30% threshold
			renewalJitter:          0.0,            // No jitter
			expectedRenewalDateMin: baseTime.Add(-1 * time.Hour),
			expectedRenewalDateMax: baseTime.Add(-1 * time.Hour), // Same (no jitter)
			description:            "Should have renewed 1 hour ago",
		},
		{
			name:                   "renew in future, no jitter",
			expiresAt:              baseTime.Add(10 * time.Hour), // Expires at baseTime + 10h
			certificateDuration:    10 * time.Hour,               // 10h total duration
			renewalThreshold:       0.3,                          // 30% threshold
			renewalJitter:          0.0,                          // No jitter
			expectedRenewalDateMin: baseTime.Add(7 * time.Hour),  // Should renew when 3h remain (30% of 10h)
			expectedRenewalDateMax: baseTime.Add(7 * time.Hour),  // Same (no jitter)
			description:            "Should renew 7 hours from now (3 hours before expiration)",
		},
		{
			name:                   "small jitter - still within bounds",
			expiresAt:              baseTime.Add(6 * time.Hour),
			certificateDuration:    10 * time.Hour,                             // 10h total duration
			renewalThreshold:       0.4,                                        // 40% threshold (4h before expiration normally)
			renewalJitter:          0.05,                                       // 5% jitter (±0.5h)
			expectedRenewalDateMin: baseTime.Add(1*time.Hour + 30*time.Minute), // Min: 35% of 10h = 3.5h before exp
			expectedRenewalDateMax: baseTime.Add(2*time.Hour + 30*time.Minute), // Max: 45% of 10h = 4.5h before exp
			description:            "Should renew between 1.5h and 2.5h from now (40% ± 5% jitter)",
		},
		{
			name:                   "jitter case - should always renew",
			expiresAt:              baseTime.Add(4 * time.Hour),
			certificateDuration:    10 * time.Hour,               // 10h total duration
			renewalThreshold:       0.5,                          // 50% threshold (5h before expiration normally)
			renewalJitter:          0.2,                          // 20% jitter (±2h)
			expectedRenewalDateMin: baseTime.Add(-3 * time.Hour), // Min: 30% of 10h = 3h before exp → already past
			expectedRenewalDateMax: baseTime.Add(1 * time.Hour),  // Max: 70% of 10h = 7h before exp → 1h from now
			description:            "With large jitter, should have range from past to future",
		},
		{
			name:                   "jitter case - never renew scenario",
			expiresAt:              baseTime.Add(20 * time.Hour),                // Far future expiration
			certificateDuration:    10 * time.Hour,                              // 10h total duration
			renewalThreshold:       0.1,                                         // 10% threshold (1h before expiration normally)
			renewalJitter:          0.05,                                        // 5% jitter (±0.5h)
			expectedRenewalDateMin: baseTime.Add(18*time.Hour + 30*time.Minute), // Min: 5% of 10h = 0.5h before exp
			expectedRenewalDateMax: baseTime.Add(19*time.Hour + 30*time.Minute), // Max: 15% of 10h = 1.5h before exp
			description:            "Should renew far in future (between 18.5h and 19.5h from now)",
		},
		{
			name:                   "large jitter test",
			expiresAt:              baseTime.Add(8 * time.Hour),
			certificateDuration:    10 * time.Hour,                             // 10h total duration
			renewalThreshold:       0.3,                                        // 30% threshold (3h before expiration normally)
			renewalJitter:          0.15,                                       // 15% jitter (±1.5h)
			expectedRenewalDateMin: baseTime.Add(3*time.Hour + 30*time.Minute), // Min: 15% of 10h = 1.5h before exp
			expectedRenewalDateMax: baseTime.Add(6*time.Hour + 30*time.Minute), // Max: 45% of 10h = 4.5h before exp
			description:            "Should renew between 3.5h and 6.5h from now (30% ± 15% jitter)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			renewalDate := computeRenewalDate(&tt.expiresAt, tt.certificateDuration, tt.renewalThreshold, tt.renewalJitter)

			// Verify renewal date is within expected bounds
			if renewalDate.Before(tt.expectedRenewalDateMin) {
				t.Errorf("Renewal date %v is before minimum expected %v. %s",
					renewalDate.Format(time.RFC3339),
					tt.expectedRenewalDateMin.Format(time.RFC3339),
					tt.description)
			}
			if renewalDate.After(tt.expectedRenewalDateMax) {
				t.Errorf("Renewal date %v is after maximum expected %v. %s",
					renewalDate.Format(time.RFC3339),
					tt.expectedRenewalDateMax.Format(time.RFC3339),
					tt.description)
			}

			// Verify renewal date is between certificate start and expiration
			certStart := tt.expiresAt.Add(-tt.certificateDuration)
			if renewalDate.Before(certStart) {
				t.Errorf("Renewal date %v is before certificate start %v", renewalDate, certStart)
			}
			if renewalDate.After(tt.expiresAt) {
				t.Errorf("Renewal date %v is after certificate expiration %v", renewalDate, tt.expiresAt)
			}
		})
	}
}

func TestNeedsCertificateRenewal(t *testing.T) {
	ctx := context.Background()
	// Set up a logger for the context - using a simple background context
	// The function will create its own logger via logr.FromContext

	tests := []struct {
		name                string
		existingSecret      *corev1.Secret
		certificateDuration time.Duration
		renewalThreshold    float64
		renewalJitter       float64
		expectedRenewal     bool
		description         string
	}{
		{
			name:                "No existing secret",
			existingSecret:      nil,
			certificateDuration: 24 * time.Hour,
			renewalThreshold:    0.3,
			renewalJitter:       0.0,
			expectedRenewal:     true,
			description:         "Should renew when no secret exists",
		},
		{
			name: "Secret with future expiration - no renewal needed",
			existingSecret: createSecretWithExpiration(
				time.Now().Add(20 * time.Hour), // Expires in 20 hours
			),
			certificateDuration: 24 * time.Hour, // Total duration is 24 hours
			renewalThreshold:    0.3,            // Renew at 30% = when 7.2 hours remain
			renewalJitter:       0.0,
			expectedRenewal:     false,
			description:         "Should not renew when 20 hours remain (>7.2 hour threshold)",
		},
		{
			name: "Secret with near expiration - renewal needed",
			existingSecret: createSecretWithExpiration(
				time.Now().Add(5 * time.Hour), // Expires in 5 hours
			),
			certificateDuration: 24 * time.Hour, // Total duration is 24 hours
			renewalThreshold:    0.3,            // Renew at 30% = when 7.2 hours remain
			renewalJitter:       0.0,
			expectedRenewal:     true,
			description:         "Should renew when 5 hours remain (<7.2 hour threshold)",
		},
		{
			name: "Secret expired - renewal needed",
			existingSecret: createSecretWithExpiration(
				time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
			),
			certificateDuration: 24 * time.Hour,
			renewalThreshold:    0.3,
			renewalJitter:       0.0,
			expectedRenewal:     true,
			description:         "Should renew when certificate is expired",
		},
		{
			name: "Secret with high threshold - early renewal",
			existingSecret: createSecretWithExpiration(
				time.Now().Add(50 * time.Hour), // Expires in 50 hours
			),
			certificateDuration: 100 * time.Hour, // Total duration is 100 hours
			renewalThreshold:    0.8,             // Renew at 80% = when 20 hours remain
			renewalJitter:       0.0,
			expectedRenewal:     true,
			description:         "Should renew when 50 hours remain (<80 hour threshold)",
		},
		{
			name: "Secret with invalid expiration data",
			existingSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"expiration": []byte("invalid-timestamp"),
				},
			},
			certificateDuration: 24 * time.Hour,
			renewalThreshold:    0.3,
			renewalJitter:       0.0,
			expectedRenewal:     true,
			description:         "Should renew when expiration data is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needsRenewal, renewalDate, _ := needsCertificateRenewal(
				ctx,
				tt.existingSecret,
				tt.certificateDuration,
				tt.renewalThreshold,
				tt.renewalJitter,
			)

			if needsRenewal != tt.expectedRenewal {
				t.Errorf("Expected needsRenewal=%v, got %v. %s", tt.expectedRenewal, needsRenewal, tt.description)
			}

			// When renewal is not needed, renewalDate should be set
			if !needsRenewal && renewalDate == nil {
				t.Errorf("Expected renewalDate to be set when renewal is not needed")
			}

			// When renewal is needed and there's a valid secret, renewalDate might still be set
			// When there's no secret or invalid data, renewalDate should be nil
			if needsRenewal && tt.existingSecret == nil && renewalDate != nil {
				t.Errorf("Expected renewalDate to be nil when no existing secret")
			}
		})
	}
}

func TestGetExpirationFromSecret(t *testing.T) {
	tests := []struct {
		name        string
		secret      *corev1.Secret
		expectError bool
		description string
	}{
		{
			name:        "Valid Unix timestamp in expiration field",
			secret:      createSecretWithExpiration(time.Now().Add(24 * time.Hour)),
			expectError: false,
			description: "Should parse valid Unix timestamp",
		},
		{
			name: "Invalid expiration timestamp",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"expiration": []byte("not-a-timestamp"),
				},
			},
			expectError: true,
			description: "Should fail with invalid timestamp",
		},
		{
			name: "Valid certificate with tls.crt",
			secret: func() *corev1.Secret {
				cert := createTestCertificate(time.Now().Add(48 * time.Hour))
				return &corev1.Secret{
					Data: map[string][]byte{
						"tls.crt": cert,
					},
				}
			}(),
			expectError: false,
			description: "Should parse expiration from X.509 certificate",
		},
		{
			name: "Valid certificate with certificate key",
			secret: func() *corev1.Secret {
				cert := createTestCertificate(time.Now().Add(72 * time.Hour))
				return &corev1.Secret{
					Data: map[string][]byte{
						"certificate": cert,
					},
				}
			}(),
			expectError: false,
			description: "Should parse expiration from certificate field",
		},
		{
			name: "No expiration or certificate data",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"some-other-field": []byte("data"),
				},
			},
			expectError: true,
			description: "Should fail when no expiration or certificate data",
		},
		{
			name: "Invalid certificate data",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt": []byte("not-a-certificate"),
				},
			},
			expectError: true,
			description: "Should fail with invalid certificate data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt, err := getExpirationFromSecret(tt.secret)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but none occurred. %s", tt.description)
				}
				if expiresAt != nil {
					t.Errorf("Expected nil expiration time when error occurs")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. %s", err, tt.description)
				}
				if expiresAt == nil {
					t.Errorf("Expected expiration time but got nil. %s", tt.description)
				} else {
					// Verify expiration time is reasonable (in the future)
					if expiresAt.Before(time.Now()) {
						t.Errorf("Expiration time %v is in the past", expiresAt)
					}
				}
			}
		})
	}
}

func TestGetCertificateData(t *testing.T) {
	testCert := []byte("test-certificate-data")

	tests := []struct {
		name     string
		secret   *corev1.Secret
		expected []byte
	}{
		{
			name: "Certificate in tls.crt field",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt": testCert,
				},
			},
			expected: testCert,
		},
		{
			name: "Certificate in certificate field",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"certificate": testCert,
				},
			},
			expected: testCert,
		},
		{
			name: "Prefer tls.crt over certificate",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"tls.crt":     testCert,
					"certificate": []byte("other-cert"),
				},
			},
			expected: testCert,
		},
		{
			name: "No certificate data",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"other-field": []byte("data"),
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCertificateData(tt.secret)
			if string(result) != string(tt.expected) {
				t.Errorf("Expected %s, got %s", string(tt.expected), string(result))
			}
		})
	}
}

func TestParseCertificateExpiration(t *testing.T) {
	// Create a valid test certificate
	validCert := createTestCertificate(time.Now().Add(48 * time.Hour))

	tests := []struct {
		name        string
		certData    []byte
		expectError bool
		description string
	}{
		{
			name:        "Valid PEM certificate",
			certData:    validCert,
			expectError: false,
			description: "Should parse valid PEM certificate",
		},
		{
			name:        "Invalid PEM data",
			certData:    []byte("not-a-certificate"),
			expectError: true,
			description: "Should fail with invalid PEM data",
		},
		{
			name:        "Empty certificate data",
			certData:    []byte(""),
			expectError: true,
			description: "Should fail with empty data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt, err := parseCertificateExpiration(tt.certData)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but none occurred. %s", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v. %s", err, tt.description)
				}
				if expiresAt == nil {
					t.Errorf("Expected expiration time but got nil")
				}
			}
		})
	}
}

// Helper functions

func createSecretWithExpiration(expiresAt time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"expiration": []byte(strconv.FormatInt(expiresAt.Unix(), 10)),
		},
	}
}

func createTestCertificate(expiresAt time.Time) []byte {
	// Create a simple test certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-certificate",
		},
		NotBefore:   time.Now(),
		NotAfter:    expiresAt,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: nil,
	}

	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}

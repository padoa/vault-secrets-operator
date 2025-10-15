package vault

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/api"
	"time"
)

// GetCertificate retrieves a certificate from Vault PKI and returns the secret data along with its expiration time.
// For wildcard certificates or other special cases where expiration is not directly available,
// it attempts to parse the expiration from the certificate itself.
func (c *Client) GetCertificate(path string, role string, options map[string]string) (*api.Secret, *time.Time, error) {
	optionsI := make(map[string]interface{}, len(options))
	for k, v := range options {
		optionsI[k] = v
	}

	secret, err := c.client.Logical().Write(path+"/issue/"+role, optionsI)
	if err != nil {
		return nil, nil, err
	}

	if secret == nil {
		return nil, nil, fmt.Errorf("certificate is nil")
	}

	// Try to get expiration from Vault response
	// For some certificate types (e.g., wildcards), expiration may not be directly available
	var expiresAt *time.Time
	if expData, exists := secret.Data["expiration"]; exists && expData != nil {
		if exp, err := expData.(json.Number).Int64(); err == nil {
			expirationTime := time.Unix(exp, 0)
			expiresAt = &expirationTime
		}
	}

	// If expiration not available from Vault response, try to parse from certificate
	if expiresAt == nil {
		if certData, exists := secret.Data["certificate"]; exists {
			if certStr, ok := certData.(string); ok {
				parsedExpiry, err := parseCertificateExpirationFromPEM([]byte(certStr))
				if err == nil {
					expiresAt = parsedExpiry
				}
			}
		}
	}

	return secret, expiresAt, nil
}

// PKIRenderData converts a Vault PKI secret response into a map of byte arrays
// containing certificate data including the certificate, private key, issuing CA, and metadata.
func (c *Client) PKIRenderData(secret *api.Secret) (map[string][]byte, error) {
	return convertData(secret.Data, []string{
		"certificate",
		"expiration",
		"issuing_ca",
		"private_key",
		"private_key_type",
		"serial_number"}, false)
}

// parseCertificateExpirationFromPEM extracts the expiration date from a PEM-encoded certificate
func parseCertificateExpirationFromPEM(certData []byte) (*time.Time, error) {
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

package vault

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// RequestToken is a function to request a new Vault token, specific for auth method.
type RequestToken func(*Client) error

// Client is the structure of our global client for Vault.
type Client struct {
	// client is the API client for requests against Vault.
	client *api.Client
	// tokenLeaseDuration is the lease duration of the token for the interaction with vault.
	tokenLeaseDuration int
	// renewToken is whether the operator should renew its own token
	// to be used when a service external to the operator renews the token itself
	// defaults to true
	renewToken bool
	// tokenRenewalInterval is the time between two successive vault token renewals.
	tokenRenewalInterval float64
	// tokenRenewalRetryInterval is the time until a failed vault token renewal is retried.
	tokenRenewalRetryInterval float64
	// tokenMaxTTL is the maximum lifetime for the token in seconds, after that time a new token
	// must be requested. Zero means the tokens lives and can be renewed forever.
	tokenMaxTTL int
	// requestToken is a function to request a new Vault token, specific for auth method.
	requestToken RequestToken
	// vault namespace
	rootVaultNamespace string
	// failedRenewTokenAttempts is the number of failed renew token attempts, if the renew token function fails 5 times
	// the liveness probe will fail, to force a restart of the operator.
	failedRenewTokenAttempts int
	// PKIRenew minimum remaining period of validity before certificate renewal
	PKIRenew time.Duration
	// DatabaseRenew is the minimum remaining period of validity before credential renewal
	DatabaseRenew time.Duration
}

// PerformRenewToken returns whether the operator should renew its token
func (c *Client) PerformRenewToken() bool {
	return c.renewToken
}

// RenewToken renews the provided token after the half of the lease duration is
// passed, retrying every 30 seconds in case of errors.
func (c *Client) RenewToken() {
	started := time.Now()
	for {
		// Set the namespace to the value from the VAULT_NAMESPACE environment
		// variable, because the namespace will always change, when a secret is
		// requested.
		if c.rootVaultNamespace != "" {
			c.client.SetNamespace(c.rootVaultNamespace)
		}

		// Request a new token if the actual token lifetime more than the specified maximum
		// lifetime.
		elapsed := time.Now().Sub(started).Seconds()
		if c.tokenMaxTTL > 0 && elapsed >= float64(c.tokenMaxTTL) && c.requestToken != nil {
			log.Info("Request new Vault token")
			err := c.requestToken(c)
			if err != nil {
				log.Error(err, "Could not request a new token")
				c.failedRenewTokenAttempts = c.failedRenewTokenAttempts + 1
				time.Sleep(time.Duration(c.tokenRenewalRetryInterval) * time.Second)
			} else {
				c.failedRenewTokenAttempts = 0
				started = time.Now()
				time.Sleep(time.Duration(c.tokenRenewalInterval) * time.Second)
			}
			continue
		}

		log.Info("Renew Vault token")
		_, err := c.client.Auth().Token().RenewSelf(c.tokenLeaseDuration)
		if err != nil {
			log.Error(err, "Could not renew token")
			c.failedRenewTokenAttempts = c.failedRenewTokenAttempts + 1
			time.Sleep(time.Duration(c.tokenRenewalRetryInterval) * time.Second)
		} else {
			c.failedRenewTokenAttempts = 0
			time.Sleep(time.Duration(c.tokenRenewalInterval) * time.Second)
		}
	}
}

// GetHealth checks if the failedRenewTokenAttempts hits the given thresholds. If this is the case an error is returned.
func (c *Client) GetHealth(threshold int) error {
	if c.failedRenewTokenAttempts >= threshold {
		return fmt.Errorf("Renew Vault token failed %d times", c.failedRenewTokenAttempts)
	}

	return nil
}

// RenewLease renews a secret lease and returns the time at which it will expire.
func (c *Client) RenewLease(leaseId string, increment int) (*time.Time, error) {
	secret, err := c.client.Sys().Renew(leaseId, increment)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second)

	return &expiresAt, nil
}

func (c *Client) RevokeLease(leaseId string) error {
	return c.client.Sys().Revoke(leaseId)
}

// contains checks if a given key is in a slice of keys.
func contains(key string, keys []string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}

	return false
}

// Renders the secret data for a Kubernetes secret. We only add the provided
// keys to the resulting data or if there are no keys provided we add all
// keys of the secret.
// To support nested secret values we check the type of the value first. If
// The type is 'map[string]interface{}' we marshal the value to a JSON
// string, which can be used for the Kubernetes secret.
func convertData(secretData map[string]interface{}, keys []string, isBinary bool) (map[string][]byte, error) {
	var err error
	data := make(map[string][]byte)
	for key, value := range secretData {
		if value == nil {
			continue
		}
		if len(keys) == 0 || contains(key, keys) {
			switch value.(type) {
			case map[string]interface{}:
				jsonString, err := json.Marshal(value)
				if err != nil {
					return nil, err
				}
				data[key] = []byte(jsonString)
			case string:
				if isBinary {
					data[key], err = b64.StdEncoding.DecodeString(value.(string))
					if err != nil {
						return nil, err
					}
				} else {
					data[key] = []byte(value.(string))
				}
			case json.Number:
				data[key] = []byte(value.(json.Number))
			case bool:
				data[key] = []byte(fmt.Sprintf("%t", value.(bool)))
			default:
				return nil, fmt.Errorf("could not parse secret value")
			}
		}
	}

	return data, nil
}

// kvPreflightVersionRequest checks which version of the key values secrets
// engine is used for the given path.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L44
func (c *Client) kvPreflightVersionRequest(path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := c.client.CurrentWrappingLookupFunc()
	c.client.SetWrappingLookupFunc(nil)
	defer c.client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := c.client.OutputCurlString()
	c.client.SetOutputCurlString(false)
	defer c.client.SetOutputCurlString(currentOutputCurlString)

	r := c.client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := c.client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

// isKVv2 returns true if a KVv2 is used for the given path and false if a KVv1
// secret engine is used.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L99
func (c *Client) isKVv2(path string) (string, bool, error) {
	mountPath, version, err := c.kvPreflightVersionRequest(path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

// addPrefixToVKVPath adds the given prefix to the given path.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L108
func (c *Client) addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}

func (c *Client) GetPKIRenew() time.Duration {
	return c.PKIRenew
}

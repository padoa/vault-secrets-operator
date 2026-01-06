package vault

import (
	"encoding/json"
	"testing"
)

func TestConvertDataWithArrays(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		keys     []string
		expected map[string]string
		wantErr  bool
	}{
		{
			name: "handle array of strings (ca_chain)",
			input: map[string]interface{}{
				"certificate": "cert1",
				"ca_chain": []interface{}{
					"-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----",
					"-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----",
				},
			},
			keys: []string{"certificate", "ca_chain"},
			expected: map[string]string{
				"certificate": "cert1",
				"ca_chain":    "-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----",
			},
			wantErr: false,
		},
		{
			name: "handle array with mixed types",
			input: map[string]interface{}{
				"mixed": []interface{}{
					"string",
					123,
					true,
				},
			},
			keys:    []string{"mixed"},
			wantErr: false,
		},
		{
			name: "handle empty array",
			input: map[string]interface{}{
				"empty": []interface{}{},
			},
			keys: []string{"empty"},
			expected: map[string]string{
				"empty": "",
			},
			wantErr: false,
		},
		{
			name: "handle map",
			input: map[string]interface{}{
				"nested": map[string]interface{}{
					"key": "value",
				},
			},
			keys:    []string{"nested"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertData(tt.input, tt.keys, false)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check expected values
			for key, expectedValue := range tt.expected {
				actualValue, ok := result[key]
				if !ok {
					t.Errorf("convertData() missing key %s", key)
					continue
				}
				if string(actualValue) != expectedValue {
					t.Errorf("convertData() key %s = %v, want %v", key, string(actualValue), expectedValue)
				}
			}

			// For mixed array, verify it's valid JSON
			if tt.name == "handle array with mixed types" {
				var jsonData interface{}
				if err := json.Unmarshal(result["mixed"], &jsonData); err != nil {
					t.Errorf("convertData() mixed array should produce valid JSON: %v", err)
				}
			}

			// For nested map, verify it's valid JSON
			if tt.name == "handle map" {
				var jsonData map[string]interface{}
				if err := json.Unmarshal(result["nested"], &jsonData); err != nil {
					t.Errorf("convertData() map should produce valid JSON: %v", err)
				}
				if jsonData["key"] != "value" {
					t.Errorf("convertData() map content mismatch")
				}
			}
		})
	}
}

package ruleswatcher

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// filterAdmissionRules
// ---------------------------------------------------------------------------

func TestFilterAdmissionRules(t *testing.T) {
	admissionExpr := armotypes.RuleExpression{
		EventType:  "k8s-admission",
		Expression: `event.Operation == "CREATE"`,
	}
	execExpr := armotypes.RuleExpression{
		EventType:  "exec",
		Expression: `true`,
	}

	tests := []struct {
		name     string
		input    []armotypes.RuntimeRule
		wantIDs  []string
	}{
		{
			name: "keeps enabled rule with admission expression",
			input: []armotypes.RuntimeRule{
				{
					ID:      "rule-enabled-admission",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{admissionExpr},
					},
				},
			},
			wantIDs: []string{"rule-enabled-admission"},
		},
		{
			name: "drops disabled rule even if it has admission expression",
			input: []armotypes.RuntimeRule{
				{
					ID:      "rule-disabled-admission",
					Enabled: false,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{admissionExpr},
					},
				},
			},
			wantIDs: []string{},
		},
		{
			name: "drops enabled rule with non-admission expression only",
			input: []armotypes.RuntimeRule{
				{
					ID:      "rule-enabled-exec",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{execExpr},
					},
				},
			},
			wantIDs: []string{},
		},
		{
			name: "keeps rule that has both admission and exec expressions",
			input: []armotypes.RuntimeRule{
				{
					ID:      "rule-mixed",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{execExpr, admissionExpr},
					},
				},
			},
			wantIDs: []string{"rule-mixed"},
		},
		{
			name: "filters correctly from a mixed set",
			input: []armotypes.RuntimeRule{
				{
					ID:      "keep-1",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{admissionExpr},
					},
				},
				{
					ID:      "drop-disabled",
					Enabled: false,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{admissionExpr},
					},
				},
				{
					ID:      "drop-exec-only",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{execExpr},
					},
				},
				{
					ID:      "keep-2",
					Enabled: true,
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{admissionExpr},
					},
				},
			},
			wantIDs: []string{"keep-1", "keep-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterAdmissionRules(tt.input)
			gotIDs := make([]string, len(got))
			for i, r := range got {
				gotIDs[i] = r.ID
			}
			assert.Equal(t, tt.wantIDs, gotIDs)
		})
	}
}

func TestFilterAdmissionRules_Empty(t *testing.T) {
	t.Run("nil input returns empty slice", func(t *testing.T) {
		got := filterAdmissionRules(nil)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty slice returns empty slice", func(t *testing.T) {
		got := filterAdmissionRules([]armotypes.RuntimeRule{})
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}

// ---------------------------------------------------------------------------
// extractRulesFromCRD
// ---------------------------------------------------------------------------

func TestExtractRulesFromCRD(t *testing.T) {
	t.Run("extracts rules from valid CRD map", func(t *testing.T) {
		crd := map[string]interface{}{
			"apiVersion": "kubescape.io/v1",
			"kind":       "Rule",
			"metadata": map[string]interface{}{
				"name": "test-rule",
			},
			"spec": map[string]interface{}{
				"rules": []interface{}{
					map[string]interface{}{
						"id":      "rule-1",
						"name":    "Test Rule 1",
						"enabled": true,
						"expressions": map[string]interface{}{
							"ruleExpression": []interface{}{
								map[string]interface{}{
									"eventType":  "k8s-admission",
									"expression": `event.Operation == "CREATE"`,
								},
							},
						},
					},
					map[string]interface{}{
						"id":      "rule-2",
						"name":    "Test Rule 2",
						"enabled": false,
						"expressions": map[string]interface{}{
							"ruleExpression": []interface{}{
								map[string]interface{}{
									"eventType":  "exec",
									"expression": `true`,
								},
							},
						},
					},
				},
			},
		}

		rules, err := extractRulesFromCRD(crd)
		require.NoError(t, err)
		require.Len(t, rules, 2)

		assert.Equal(t, "rule-1", rules[0].ID)
		assert.Equal(t, "Test Rule 1", rules[0].Name)
		assert.True(t, rules[0].Enabled)
		require.Len(t, rules[0].Expressions.RuleExpression, 1)
		assert.Equal(t, armotypes.EventType("k8s-admission"), rules[0].Expressions.RuleExpression[0].EventType)

		assert.Equal(t, "rule-2", rules[1].ID)
		assert.False(t, rules[1].Enabled)
	})

	t.Run("returns nil for CRD without spec", func(t *testing.T) {
		crd := map[string]interface{}{
			"apiVersion": "kubescape.io/v1",
			"kind":       "Rule",
		}
		rules, err := extractRulesFromCRD(crd)
		require.NoError(t, err)
		assert.Nil(t, rules)
	})

	t.Run("returns empty for spec with no rules", func(t *testing.T) {
		crd := map[string]interface{}{
			"spec": map[string]interface{}{},
		}
		rules, err := extractRulesFromCRD(crd)
		require.NoError(t, err)
		assert.Empty(t, rules)
	})
}

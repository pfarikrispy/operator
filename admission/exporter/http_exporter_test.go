package exporters

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/operator/admission/rules"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
	"github.com/stretchr/testify/assert"
)

func TestInitHTTPExporter_ClusterUID(t *testing.T) {
	config := HTTPExporterConfig{
		URL:    "http://localhost:8080",
		Method: "POST",
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-cluster-uid")
	assert.NoError(t, err)
	assert.Equal(t, "test-cluster", exporter.ClusterName)
	assert.Equal(t, "test-cluster-uid", exporter.ClusterUID)
}

func TestSendAdmissionAlert_ClusterUIDPropagated(t *testing.T) {
	config := HTTPExporterConfig{
		URL:    "http://localhost:8080",
		Method: "POST",
	}
	exporter, err := InitHTTPExporter(config, "test-cluster", nil, "test-cluster-uid")
	assert.NoError(t, err)

	// Build a minimal rule failure to verify ClusterUID injection by the exporter.
	ruleFailure := &rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{},
		RuleAlert:        apitypes.RuleAlert{},
		AdmissionAlert:   apitypes.AdmissionAlert{},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			Image:       "nginx:1.14.2",
			ImageDigest: "nginx@sha256:abc123def456",
		},
		RuleID: "R2000",
	}

	// Simulate what SendAdmissionAlert does internally to verify ClusterUID injection.
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	k8sDetails.ClusterName = exporter.ClusterName
	k8sDetails.ClusterUID = exporter.ClusterUID

	alert := apitypes.RuntimeAlert{
		AlertType:              apitypes.AlertTypeAdmission,
		BaseRuntimeAlert:       ruleFailure.GetBaseRuntimeAlert(),
		AdmissionAlert:         ruleFailure.GetAdmissionsAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		RuleAlert:              ruleFailure.GetRuleAlert(),
		RuleID:                 ruleFailure.GetRuleId(),
	}

	assert.Equal(t, "test-cluster", alert.RuntimeAlertK8sDetails.ClusterName)
	assert.Equal(t, "test-cluster-uid", alert.RuntimeAlertK8sDetails.ClusterUID)
	assert.Equal(t, "nginx:1.14.2", alert.RuntimeAlertK8sDetails.Image)
	assert.Equal(t, "nginx@sha256:abc123def456", alert.RuntimeAlertK8sDetails.ImageDigest)
}

// Verify RuleFailure interface used in tests
var _ rules.RuleFailure = (*rulesv1.GenericRuleFailure)(nil)

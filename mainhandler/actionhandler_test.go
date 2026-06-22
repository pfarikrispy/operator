package mainhandler

import (
	"context"
	"testing"

	"github.com/armosec/armoapi-go/apis"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/operator/config"
	"github.com/kubescape/operator/mainhandler/remediators"
	"github.com/kubescape/operator/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func boolPtr(b bool) *bool { return &b }

func newTestConfig(serviceConfig config.Config) config.IConfig {
	return config.NewOperatorConfig(config.CapabilitiesConfig{}, utilsmetadata.ClusterConfig{}, &beUtils.Credentials{}, serviceConfig)
}

func newActionHandlerForTest(t *testing.T, client kubernetes.Interface, cfg config.IConfig, args apis.OperatorActionArgs) *ActionHandler {
	t.Helper()
	argsMap, err := args.ToArgs()
	require.NoError(t, err)
	return &ActionHandler{
		k8sAPI: utils.NewK8sInterfaceFake(client),
		config: cfg,
		sessionObj: &utils.SessionObj{
			Command: &apis.Command{CommandName: apis.TypeOperatorAction, Args: argsMap},
		},
	}
}

func capturePatchDryRun(client *k8sfake.Clientset, resource string, out *[]string) {
	client.PrependReactor("patch", resource, func(action clienttesting.Action) (bool, runtime.Object, error) {
		*out = action.(clienttesting.PatchActionImpl).PatchOptions.DryRun
		return false, nil, nil
	})
}

// Omitting dryRun must default to a safe server-side dry-run, never a real write.
func TestHandleOperatorAction_AnnotateDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
		// DryRun intentionally nil
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a command without dryRun must default to server-side dry-run")
}

// Explicit dryRun=false (the CLI's --confirm) performs a real write.
func TestHandleOperatorAction_AnnotateConfirmWrites(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		Reason: "C-0016",
		DryRun: boolPtr(false),
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Empty(t, dryRun, "a confirmed action must not request dry-run")

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "true", got.Annotations[remediators.AnnotationRemediated])
	assert.Equal(t, "C-0016", got.Annotations[remediators.AnnotationReason])
}

func TestHandleOperatorAction_RevertRemovesAnnotations(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "payments",
		Name:        "api",
		Annotations: map[string]string{remediators.AnnotationRemediated: "true", remediators.AnnotationReason: "C-0016"},
	}})

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionRevert,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		DryRun: boolPtr(false), // --confirm: revert is a real write
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))

	got, err := client.AppsV1().Deployments("payments").Get(context.Background(), "api", metav1.GetOptions{})
	require.NoError(t, err)
	_, ok := got.Annotations[remediators.AnnotationRemediated]
	assert.False(t, ok)
}

// Revert must honor the safe-by-default contract: with dryRun unset it previews
// (server-side dry-run) and must not actually remove the annotations.
func TestHandleOperatorAction_RevertDefaultsToDryRun(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "payments",
		Name:        "api",
		Annotations: map[string]string{remediators.AnnotationRemediated: "true", remediators.AnnotationReason: "C-0016"},
	}})
	var dryRun []string
	capturePatchDryRun(client, "deployments", &dryRun)

	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionRevert,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		// DryRun intentionally nil
	})

	require.NoError(t, ah.handleOperatorAction(context.Background()))
	assert.Equal(t, []string{metav1.DryRunAll}, dryRun, "a revert without dryRun must default to server-side dry-run")
}

// A namespaced target with no namespace must be rejected up front rather than
// slipping past the excluded-namespace rail and failing late at the API server.
func TestHandleOperatorAction_NamespacedKindRequiresNamespace(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Name: "api"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a namespace")
}

func TestHandleOperatorAction_ExcludedNamespaceRejected(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	cfg := newTestConfig(config.Config{Namespace: "kubescape", ExcludeNamespaces: []string{"payments"}})

	ah := newActionHandlerForTest(t, client, cfg, apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
	})

	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "excluded from remediation")
}

func TestHandleOperatorAction_SelectorTargetingNotYetSupported(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action:   apis.OperatorActionAnnotate,
		Selector: &apis.OperatorActionSelector{Control: "C-0016", MinSeverity: "High"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "selector targeting is not supported yet")
}

func TestHandleOperatorAction_TargetRequired(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a target is required")
}

func TestHandleOperatorAction_UnimplementedActions(t *testing.T) {
	client := k8sfake.NewClientset()
	cfg := newTestConfig(config.Config{Namespace: "kubescape"})
	for _, action := range []apis.OperatorActionType{apis.OperatorActionQuarantine, apis.OperatorActionCordon} {
		ah := newActionHandlerForTest(t, client, cfg, apis.OperatorActionArgs{
			Action: action,
			Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		})
		err := ah.handleOperatorAction(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented yet")
	}
}

func TestHandleOperatorAction_UnknownAction(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionType("teleport"),
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown action")
}

// A malformed ttl must be rejected up front, not trusted (see armoapi-go#655).
func TestHandleOperatorAction_InvalidTTLRejected(t *testing.T) {
	client := k8sfake.NewClientset()
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		TTL:    "banana",
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ttl")
}

// A well-formed ttl must still be fenced (auto-revert is a later phase) rather
// than silently accepted, so a caller is not misled into expecting auto-revert.
func TestHandleOperatorAction_ValidTTLNotYetSupported(t *testing.T) {
	client := k8sfake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "api"}})
	ah := newActionHandlerForTest(t, client, newTestConfig(config.Config{Namespace: "kubescape"}), apis.OperatorActionArgs{
		Action: apis.OperatorActionAnnotate,
		Target: &apis.OperatorActionTarget{Kind: "Deployment", Namespace: "payments", Name: "api"},
		TTL:    "24h",
	})
	err := ah.handleOperatorAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl/auto-revert is not supported yet")
}

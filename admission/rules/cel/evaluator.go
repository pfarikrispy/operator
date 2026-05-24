package cel

import (
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	admissioncel "github.com/kubescape/operator/admission/cel"
	"github.com/kubescape/operator/admission/rules"
	rulesv1 "github.com/kubescape/operator/admission/rules/v1"
	"github.com/kubescape/operator/objectcache"
	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Compile-time assertion that CelRuleEvaluator implements rules.RuleEvaluator.
var _ rules.RuleEvaluator = (*CelRuleEvaluator)(nil)

// CelRuleEvaluator wraps a single armotypes.RuntimeRule and evaluates it against
// k8s admission events using the shared AdmissionCEL engine.
type CelRuleEvaluator struct {
	rule       apitypes.RuntimeRule
	celEngine  *admissioncel.AdmissionCEL
	parameters map[string]interface{}
}

// newCelRuleEvaluator is the package-internal constructor used by CelRuleCreator.
func newCelRuleEvaluator(rule apitypes.RuntimeRule, celEngine *admissioncel.AdmissionCEL) *CelRuleEvaluator {
	return &CelRuleEvaluator{
		rule:      rule,
		celEngine: celEngine,
	}
}

// ID returns the rule's unique identifier.
func (e *CelRuleEvaluator) ID() string {
	return e.rule.ID
}

// Name returns the rule's human-readable name.
func (e *CelRuleEvaluator) Name() string {
	return e.rule.Name
}

// SetParameters stores per-binding parameter overrides.
func (e *CelRuleEvaluator) SetParameters(parameters map[string]interface{}) {
	e.parameters = parameters
}

// GetParameters returns the per-binding parameter overrides.
func (e *CelRuleEvaluator) GetParameters() map[string]interface{} {
	return e.parameters
}

// ProcessEvent evaluates the rule's CEL expressions against the admission event.
// Returns nil when the rule does not fire for this event. Returns a RuleFailure
// when the rule matches.
func (e *CelRuleEvaluator) ProcessEvent(attrs admission.Attributes, access objectcache.KubernetesCache) rules.RuleFailure {
	if attrs == nil {
		return nil
	}

	// Build CEL event and evaluation context.
	celEvent := admissioncel.NewAdmissionCelEvent(attrs)
	evalCtx := e.celEngine.CreateEvalContext(celEvent)

	// Evaluate the rule's match expressions for the k8s-admission event type.
	matched, err := e.celEngine.EvaluateRuleWithContext(
		evalCtx,
		apitypes.EventTypeK8sAdmission,
		e.rule.Expressions.RuleExpression,
	)
	if err != nil {
		logger.L().Error("CelRuleEvaluator: failed to evaluate rule expressions",
			helpers.String("ruleID", e.rule.ID),
			helpers.Error(err))
		return nil
	}
	if !matched {
		return nil
	}

	// Evaluate the alert name from the Message expression; fall back to rule name.
	alertName := e.rule.Name
	if e.rule.Expressions.Message != "" {
		msg, err := e.celEngine.EvaluateStringExpression(evalCtx, e.rule.Expressions.Message)
		if err != nil {
			logger.L().Warning("CelRuleEvaluator: failed to evaluate message expression",
				helpers.String("ruleID", e.rule.ID),
				helpers.Error(err))
		} else if msg != "" {
			alertName = msg
		}
	}

	// Evaluate the unique ID expression.
	uniqueID := ""
	if e.rule.Expressions.UniqueID != "" {
		uid, err := e.celEngine.EvaluateStringExpression(evalCtx, e.rule.Expressions.UniqueID)
		if err != nil {
			logger.L().Warning("CelRuleEvaluator: failed to evaluate uniqueID expression",
				helpers.String("ruleID", e.rule.ID),
				helpers.Error(err))
		} else {
			uniqueID = uid
		}
	}

	failure := &rulesv1.GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: alertName,
			Severity:  e.rule.Severity,
			Timestamp: time.Now(),
			UniqueID:  uniqueID,
		},
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: e.rule.Description,
		},
		AdmissionAlert: buildAdmissionAlert(attrs),
		RuleID:         e.rule.ID,
	}

	// Enrich with K8s details when a cache is available. Skip for kinds
	// where enrichment is not meaningful — enrichK8sDetails resolves a
	// running Pod via clientset.CoreV1().Pods(ns).Get(...), which only
	// makes sense for Pod CRUD or Pod subresource events. Other kinds
	// (NetworkPolicy, RoleBinding, …) would either return a NotFound or
	// fetch an unrelated Pod that happens to share the request name.
	if access != nil && enrichmentApplicable(attrs) {
		enrichK8sDetails(failure, attrs, access)
	}

	return failure
}

// enrichmentApplicable reports whether the K8s Pod enrichment pipeline makes
// sense for this admission event. True for Pod CRUD and Pod subresources
// (exec, portforward, attach) — all addressed by name in the pods collection.
// False for unrelated kinds whose name does not correspond to a Pod.
func enrichmentApplicable(attrs admission.Attributes) bool {
	if attrs.GetResource().Resource == "pods" {
		return true
	}
	switch attrs.GetKind().Kind {
	case "PodExecOptions", "PodPortForwardOptions", "PodAttachOptions":
		return true
	}
	return false
}

// buildAdmissionAlert constructs an apitypes.AdmissionAlert from admission.Attributes.
func buildAdmissionAlert(attrs admission.Attributes) apitypes.AdmissionAlert {
	alert := apitypes.AdmissionAlert{
		Kind:             attrs.GetKind(),
		RequestNamespace: attrs.GetNamespace(),
		ObjectName:       attrs.GetName(),
		Resource:         attrs.GetResource(),
		Subresource:      attrs.GetSubresource(),
		Operation:        attrs.GetOperation(),
		DryRun:           attrs.IsDryRun(),
	}

	// Attach user info if available.
	if ui := attrs.GetUserInfo(); ui != nil {
		alert.UserInfo = &user.DefaultInfo{
			Name:   ui.GetName(),
			UID:    ui.GetUID(),
			Groups: ui.GetGroups(),
			Extra:  ui.GetExtra(),
		}
	}

	// Attach object if it is an *unstructured.Unstructured.
	if obj := attrs.GetObject(); obj != nil {
		if u, ok := obj.(*unstructured.Unstructured); ok {
			alert.Object = u
		}
	}

	// Attach old object if it is an *unstructured.Unstructured.
	if old := attrs.GetOldObject(); old != nil {
		if u, ok := old.(*unstructured.Unstructured); ok {
			alert.OldObject = u
		}
	}

	return alert
}

// enrichK8sDetails populates RuntimeAlertK8sDetails on the failure using the
// Kubernetes API. Errors are logged and silently skipped — enrichment is
// best-effort and must never cause the rule to suppress a genuine match.
func enrichK8sDetails(failure *rulesv1.GenericRuleFailure, attrs admission.Attributes, access objectcache.KubernetesCache) {
	clientset := access.GetClientset()

	pod, workloadKind, workloadName, workloadNamespace, workloadUID, nodeName, err :=
		rulesv1.GetControllerDetails(attrs, clientset)
	if err != nil {
		logger.L().Warning("CelRuleEvaluator: could not get controller details",
			helpers.String("pod", attrs.GetName()),
			helpers.Error(err))
		return
	}

	k8sDetails := apitypes.RuntimeAlertK8sDetails{
		PodName:           attrs.GetName(),
		PodNamespace:      attrs.GetNamespace(),
		Namespace:         attrs.GetNamespace(),
		NodeName:          nodeName,
		WorkloadName:      workloadName,
		WorkloadNamespace: workloadNamespace,
		WorkloadKind:      workloadKind,
		WorkloadUID:       workloadUID,
	}

	// Resolve container details for exec-to-pod events.
	if attrs.GetKind().Kind == "PodExecOptions" {
		containerName, err := rulesv1.GetContainerNameFromExecToPodEvent(attrs)
		if err != nil {
			logger.L().Warning("CelRuleEvaluator: could not get container name from exec event",
				helpers.Error(err))
		}
		k8sDetails.ContainerName = containerName
		k8sDetails.ContainerID = rulesv1.GetContainerID(pod, containerName)
		k8sDetails.Image = rulesv1.GetContainerImage(pod, containerName)
		k8sDetails.ImageDigest = rulesv1.GetContainerImageDigest(pod, containerName)
	}

	failure.RuntimeAlertK8sDetails = k8sDetails
}

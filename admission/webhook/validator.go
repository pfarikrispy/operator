package webhook

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	exporters "github.com/kubescape/operator/admission/exporter"
	"github.com/kubescape/operator/admission/rulebinding"
	"github.com/kubescape/operator/objectcache"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/client-go/kubernetes"
)

type AdmissionValidator struct {
	kubernetesClient *k8sinterface.KubernetesApi
	objectCache      objectcache.ObjectCache
	exporter         exporters.Exporter
	ruleBindingCache rulebinding.RuleBindingCache

	// selfSubject is the operator's own admission subject
	// (system:serviceaccount:<ns>:<sa>). When set, requests with a matching
	// UserInfo.Name are dropped before rule evaluation to prevent positive
	// feedback loops from the operator's own API writes. Empty when the
	// service account token cannot be parsed at startup.
	selfSubject string
}

func NewAdmissionValidator(kubernetesClient *k8sinterface.KubernetesApi, objectCache objectcache.ObjectCache, exporter exporters.Exporter, ruleBindingCache rulebinding.RuleBindingCache) *AdmissionValidator {
	av := &AdmissionValidator{
		kubernetesClient: kubernetesClient,
		objectCache:      objectCache,
		exporter:         exporter,
		ruleBindingCache: ruleBindingCache,
	}

	subject, err := readSelfSubject(defaultServiceAccountTokenPath)
	if err != nil {
		logger.L().Warning("self-pod short-circuit disabled: could not read service account token",
			helpers.Error(err))
	} else {
		av.selfSubject = subject
		logger.L().Info("self-pod short-circuit enabled",
			helpers.String("selfSubject", subject))
	}

	return av
}

// SetSelfSubject overrides the operator's self subject. Exposed for tests.
func (av *AdmissionValidator) SetSelfSubject(subject string) {
	av.selfSubject = subject
}

func (av *AdmissionValidator) GetClientset() kubernetes.Interface {
	return av.objectCache.GetKubernetesCache().GetClientset()
}

// isSelfRequest reports whether the admission request originated from the
// operator's own ServiceAccount. Used to short-circuit feedback loops.
func (av *AdmissionValidator) isSelfRequest(attrs admission.Attributes) bool {
	if av.selfSubject == "" {
		return false
	}
	ui := attrs.GetUserInfo()
	if ui == nil {
		return false
	}
	return ui.GetName() == av.selfSubject
}

// We are implementing the Validate method from the ValidationInterface interface.
func (av *AdmissionValidator) Validate(ctx context.Context, attrs admission.Attributes, o admission.ObjectInterfaces) (err error) {
	// Drop requests from the operator's own ServiceAccount before any
	// processing. This is a hard guarantee against positive feedback loops,
	// not an optimization.
	if av.isSelfRequest(attrs) {
		return nil
	}

	if attrs.GetObject() != nil {
		var object *unstructured.Unstructured
		// Fetch the resource if it is a pod and the object is not a pod.
		if attrs.GetResource().Resource == "pods" && attrs.GetKind().Kind != "Pod" {
			object, err = av.fetchResource(ctx, attrs)
			if err != nil {
				return admission.NewForbidden(attrs, fmt.Errorf("failed to fetch resource: %w", err))
			}
		} else {
			object = attrs.GetObject().(*unstructured.Unstructured)
		}

		rules := av.ruleBindingCache.ListRulesForObject(ctx, object)
		for _, rule := range rules {
			failure := rule.ProcessEvent(attrs, av)
			if failure != nil {
				logger.L().Info("Rule matched",
					helpers.String("ruleID", failure.GetRuleId()),
					helpers.Interface("failure", failure))
				av.exporter.SendAdmissionAlert(failure)
			}
		}
	}

	return nil
}

// Fetch resource/objects from the Kubernetes API based on the given attributes.
func (av *AdmissionValidator) fetchResource(ctx context.Context, attrs admission.Attributes) (*unstructured.Unstructured, error) {
	// Get the GVR
	gvr := schema.GroupVersionResource{
		Group:    attrs.GetResource().Group,
		Version:  attrs.GetResource().Version,
		Resource: attrs.GetResource().Resource,
	}

	// Fetch the resource
	resource, err := av.kubernetesClient.DynamicClient.Resource(gvr).Namespace(attrs.GetNamespace()).Get(ctx, attrs.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource: %w", err)
	}

	return resource, nil
}

// We are implementing the Handles method from the ValidationInterface interface.
// This method returns true if this admission controller can handle the given operation, we accept all operations.
func (av *AdmissionValidator) Handles(operation admission.Operation) bool {
	return true
}

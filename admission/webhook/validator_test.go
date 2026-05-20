package webhook

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/kubescape/operator/admission/rules"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// countingRuleBindingCache records how many times ListRulesForObject is called.
// Used to verify that short-circuited requests never reach rule evaluation.
type countingRuleBindingCache struct {
	calls atomic.Int64
}

func (c *countingRuleBindingCache) ListRulesForObject(_ context.Context, _ *unstructured.Unstructured) []rules.RuleEvaluator {
	c.calls.Add(1)
	return nil
}

func newSelfTestAttributes(username string) admission.Attributes {
	// Use NetworkPolicy CREATE — this avoids the special pods/exec fetchResource
	// branch in Validate which would require a mocked dynamic client.
	gvk := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
	}}
	userInfo := &user.DefaultInfo{Name: username}
	return admission.NewAttributesRecord(obj, nil, gvk, "default", "test-netpol", gvr, "",
		admission.Create, nil, false, userInfo)
}

func TestValidator_SelfPodShortCircuit(t *testing.T) {
	const selfSubject = "system:serviceaccount:kubescape:operator"

	tests := []struct {
		name             string
		configuredSubj   string
		requestUsername  string
		wantCacheReached bool
	}{
		{
			name:             "request from operator SA is short-circuited",
			configuredSubj:   selfSubject,
			requestUsername:  selfSubject,
			wantCacheReached: false,
		},
		{
			name:             "request from kubernetes-admin reaches cache",
			configuredSubj:   selfSubject,
			requestUsername:  "kubernetes-admin",
			wantCacheReached: true,
		},
		{
			name:             "request from a different SA reaches cache",
			configuredSubj:   selfSubject,
			requestUsername:  "system:serviceaccount:default:builder",
			wantCacheReached: true,
		},
		{
			name:             "empty self subject disables the short-circuit",
			configuredSubj:   "",
			requestUsername:  selfSubject,
			wantCacheReached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &countingRuleBindingCache{}
			av := &AdmissionValidator{
				ruleBindingCache: cache,
			}
			av.SetSelfSubject(tt.configuredSubj)

			attrs := newSelfTestAttributes(tt.requestUsername)
			if err := av.Validate(context.Background(), attrs, nil); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}

			gotReached := cache.calls.Load() > 0
			if gotReached != tt.wantCacheReached {
				t.Errorf("ListRulesForObject reached=%v, want %v (calls=%d)",
					gotReached, tt.wantCacheReached, cache.calls.Load())
			}
		})
	}
}

// stubKindAcceptor accepts only the kinds in the set.
type stubKindAcceptor struct {
	accepted map[string]struct{}
}

func (s stubKindAcceptor) Accepts(kind string) bool {
	_, ok := s.accepted[kind]
	return ok
}

func TestValidator_KindAcceptorPreFilter(t *testing.T) {
	tests := []struct {
		name             string
		acceptor         KindAcceptor
		wantCacheReached bool
	}{
		{
			name:             "nil acceptor — every Kind passes through",
			acceptor:         nil,
			wantCacheReached: true,
		},
		{
			name:             "acceptor includes NetworkPolicy — reaches cache",
			acceptor:         stubKindAcceptor{accepted: map[string]struct{}{"NetworkPolicy": {}}},
			wantCacheReached: true,
		},
		{
			name:             "acceptor excludes NetworkPolicy — short-circuited",
			acceptor:         stubKindAcceptor{accepted: map[string]struct{}{"Pod": {}}},
			wantCacheReached: false,
		},
		{
			name:             "empty acceptor — short-circuited",
			acceptor:         stubKindAcceptor{accepted: map[string]struct{}{}},
			wantCacheReached: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &countingRuleBindingCache{}
			av := &AdmissionValidator{ruleBindingCache: cache}
			av.SetKindAcceptor(tt.acceptor)

			attrs := newSelfTestAttributes("kubernetes-admin")
			if err := av.Validate(context.Background(), attrs, nil); err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}

			gotReached := cache.calls.Load() > 0
			if gotReached != tt.wantCacheReached {
				t.Errorf("ListRulesForObject reached=%v, want %v", gotReached, tt.wantCacheReached)
			}
		})
	}
}

func TestValidator_SelfPodShortCircuit_NilUserInfo(t *testing.T) {
	cache := &countingRuleBindingCache{}
	av := &AdmissionValidator{
		ruleBindingCache: cache,
	}
	av.SetSelfSubject("system:serviceaccount:kubescape:operator")

	gvk := schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvr := schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "networking.k8s.io/v1",
		"kind":       "NetworkPolicy",
	}}
	// Pass nil userInfo — should not short-circuit, should reach the cache.
	attrs := admission.NewAttributesRecord(obj, nil, gvk, "default", "test-netpol", gvr, "",
		admission.Create, nil, false, nil)

	if err := av.Validate(context.Background(), attrs, nil); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if cache.calls.Load() == 0 {
		t.Error("request with nil UserInfo was short-circuited; expected to reach the cache")
	}
}

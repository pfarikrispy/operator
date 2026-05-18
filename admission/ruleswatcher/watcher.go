package ruleswatcher

import (
	"context"
	"encoding/json"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/watcher"
	admissioncel "github.com/kubescape/operator/admission/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuleSyncer receives a filtered set of k8s-admission rules and applies them.
type RuleSyncer interface {
	SyncRules(rules []armotypes.RuntimeRule)
}

// RBCacheRefresher triggers a cache refresh after rules are synced.
type RBCacheRefresher interface {
	RefreshRules()
}

// RulesWatcher implements watcher.Adaptor, watching the Rules CRD and syncing
// any k8s-admission rules to the provided RuleSyncer.
type RulesWatcher struct {
	k8sClient      k8sclient.K8sClientInterface
	ruleSyncer     RuleSyncer
	cacheRefresher RBCacheRefresher
	watchResources []watcher.WatchResource
}

var _ watcher.Adaptor = (*RulesWatcher)(nil)

// NewRulesWatcher creates a RulesWatcher that watches the Rules CRD and
// delegates matching rules to ruleSyncer. If cacheRefresher is non-nil it is
// called after every sync.
func NewRulesWatcher(k8sClient k8sclient.K8sClientInterface, ruleSyncer RuleSyncer, cacheRefresher RBCacheRefresher) *RulesWatcher {
	return &RulesWatcher{
		k8sClient:      k8sClient,
		ruleSyncer:     ruleSyncer,
		cacheRefresher: cacheRefresher,
		watchResources: []watcher.WatchResource{
			watcher.NewWatchResource(typesv1.RuleGvr, metav1.ListOptions{}),
		},
	}
}

// WatchResources implements watcher.Adaptor.
func (w *RulesWatcher) WatchResources() []watcher.WatchResource {
	return w.watchResources
}

// AddHandler implements watcher.Adaptor. Any add event triggers a full sync.
func (w *RulesWatcher) AddHandler(ctx context.Context, _ runtime.Object) {
	w.syncAllRules(ctx)
}

// ModifyHandler implements watcher.Adaptor. Any modify event triggers a full sync.
func (w *RulesWatcher) ModifyHandler(ctx context.Context, _ runtime.Object) {
	w.syncAllRules(ctx)
}

// DeleteHandler implements watcher.Adaptor. Any delete event triggers a full sync.
func (w *RulesWatcher) DeleteHandler(ctx context.Context, _ runtime.Object) {
	w.syncAllRules(ctx)
}

// syncAllRules lists all Rules CRDs, extracts k8s-admission rules, and syncs
// them to the RuleSyncer.
func (w *RulesWatcher) syncAllRules(ctx context.Context) {
	list, err := w.k8sClient.GetDynamicClient().Resource(typesv1.RuleGvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		logger.L().Error("failed to list Rules CRDs", helpers.Error(err))
		return
	}

	var allRules []armotypes.RuntimeRule
	for i := range list.Items {
		rules, err := extractRulesFromCRD(list.Items[i].Object)
		if err != nil {
			logger.L().Warning("failed to extract rules from CRD",
				helpers.String("name", list.Items[i].GetName()),
				helpers.Error(err))
			continue
		}
		allRules = append(allRules, rules...)
	}

	filtered := filterAdmissionRules(allRules)
	w.ruleSyncer.SyncRules(filtered)

	if w.cacheRefresher != nil {
		w.cacheRefresher.RefreshRules()
	}
}

// specWrapper is the top-level CRD spec shape expected from the Rules CRD.
type specWrapper struct {
	Rules []armotypes.RuntimeRule `json:"rules"`
}

// extractRulesFromCRD marshals the "spec" field of a CRD object map to JSON
// and unmarshals it into a slice of RuntimeRule values.
func extractRulesFromCRD(crd map[string]interface{}) ([]armotypes.RuntimeRule, error) {
	specRaw, ok := crd["spec"]
	if !ok {
		return nil, nil
	}

	data, err := json.Marshal(specRaw)
	if err != nil {
		return nil, err
	}

	var wrapper specWrapper
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, err
	}

	return wrapper.Rules, nil
}

// filterAdmissionRules returns only rules that are enabled and have at least
// one expression with EventType == k8s-admission.
func filterAdmissionRules(rules []armotypes.RuntimeRule) []armotypes.RuntimeRule {
	if len(rules) == 0 {
		return []armotypes.RuntimeRule{}
	}

	var result []armotypes.RuntimeRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if hasAdmissionExpression(r) {
			result = append(result, r)
		}
	}
	if result == nil {
		return []armotypes.RuntimeRule{}
	}
	return result
}

// hasAdmissionExpression reports whether the rule contains at least one
// expression with EventType == k8s-admission.
func hasAdmissionExpression(r armotypes.RuntimeRule) bool {
	for _, expr := range r.Expressions.RuleExpression {
		if expr.EventType == admissioncel.EventTypeK8sAdmission {
			return true
		}
	}
	return false
}

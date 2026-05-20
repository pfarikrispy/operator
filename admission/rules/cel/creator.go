package cel

import (
	"sync"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	admissioncel "github.com/kubescape/operator/admission/cel"
	"github.com/kubescape/operator/admission/rules"
)

// CelRuleCreator implements rules.RuleCreator backed by a []armotypes.RuntimeRule
// that can be replaced atomically via SyncRules.
type CelRuleCreator struct {
	mu         sync.RWMutex
	rules      []armotypes.RuntimeRule
	kindFilter *KindFilter
	celEngine  *admissioncel.AdmissionCEL
}

var _ rules.RuleCreator = (*CelRuleCreator)(nil)

// NewCelRuleCreator returns a new CelRuleCreator with no rules loaded yet.
func NewCelRuleCreator(celEngine *admissioncel.AdmissionCEL) *CelRuleCreator {
	return &CelRuleCreator{
		celEngine: celEngine,
		// Empty creator accepts nothing — the kind filter starts non-wildcard
		// with an empty set so the validator drops events until the first
		// SyncRules call. (No rules => nothing to evaluate anyway.)
		kindFilter: &KindFilter{kinds: map[string]struct{}{}},
	}
}

// SyncRules replaces the internal rule set with a copy of the provided slice.
// It is safe to call concurrently.
func (c *CelRuleCreator) SyncRules(rules []armotypes.RuntimeRule) {
	copied := make([]armotypes.RuntimeRule, len(rules))
	copy(copied, rules)
	filter := buildKindFilter(copied)

	c.mu.Lock()
	c.rules = copied
	c.kindFilter = filter
	c.mu.Unlock()
}

// KindFilter returns the current set of Kinds at least one loaded rule could
// match. Used by the validator to skip evaluation for unrelated admission
// events. The returned filter is a snapshot; callers must not mutate it.
func (c *CelRuleCreator) KindFilter() *KindFilter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.kindFilter
}

// Accepts reports whether at least one currently-loaded rule could match an
// admission event of the given Kind. Always reads the latest filter snapshot,
// so it stays correct across SyncRules calls without callers having to refresh.
func (c *CelRuleCreator) Accepts(kind string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.kindFilter.Accepts(kind)
}

// CreateRuleByID returns a RuleEvaluator for the rule with the given ID, or nil
// if no matching rule exists.
func (c *CelRuleCreator) CreateRuleByID(id string) rules.RuleEvaluator {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, r := range c.rules {
		if r.ID == id {
			return newCelRuleEvaluator(r, c.celEngine)
		}
	}
	return nil
}

// CreateRuleByName returns a RuleEvaluator for the first rule whose Name matches,
// or nil if no matching rule exists.
func (c *CelRuleCreator) CreateRuleByName(name string) rules.RuleEvaluator {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, r := range c.rules {
		if r.Name == name {
			return newCelRuleEvaluator(r, c.celEngine)
		}
	}
	return nil
}

// CreateRulesByTags returns evaluators for all rules that have at least one tag
// in common with the requested tags set.
func (c *CelRuleCreator) CreateRulesByTags(tags []string) []rules.RuleEvaluator {
	if len(tags) == 0 {
		return nil
	}

	tagSet := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		tagSet[t] = struct{}{}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []rules.RuleEvaluator
	for _, r := range c.rules {
		if ruleMatchesTags(r, tagSet) {
			result = append(result, newCelRuleEvaluator(r, c.celEngine))
		}
	}
	return result
}

// CreateAllRules returns evaluators for every loaded rule.
func (c *CelRuleCreator) CreateAllRules() []rules.RuleEvaluator {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]rules.RuleEvaluator, len(c.rules))
	for i, r := range c.rules {
		result[i] = newCelRuleEvaluator(r, c.celEngine)
	}
	return result
}

// ruleMatchesTags reports whether any of the rule's tags appear in tagSet.
func ruleMatchesTags(r armotypes.RuntimeRule, tagSet map[string]struct{}) bool {
	for _, t := range r.Tags {
		if _, ok := tagSet[t]; ok {
			return true
		}
	}
	return false
}

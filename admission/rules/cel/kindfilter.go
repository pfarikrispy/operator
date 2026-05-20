package cel

import (
	"regexp"

	armotypes "github.com/armosec/armoapi-go/armotypes"
)

// KindFilter is the set of admission Kinds that at least one currently-loaded
// rule could match. It is built from the loaded rule expressions at SyncRules
// time and used by the validator to skip CEL evaluation for events no rule
// targets.
//
// The filter is *conservative*: if an expression cannot be statically resolved
// to a finite set of Kinds (e.g. it uses ||, has no event.Kind == constraint,
// or uses set membership / regex), the filter falls back to wildcard mode and
// accepts every Kind. Correctness is preserved at the cost of skipping the
// optimization.
type KindFilter struct {
	wildcard bool
	kinds    map[string]struct{}
}

// Accepts reports whether at least one loaded rule could match an admission
// event of the given Kind. Wildcard filters accept every Kind.
func (f *KindFilter) Accepts(kind string) bool {
	if f == nil || f.wildcard {
		return true
	}
	_, ok := f.kinds[kind]
	return ok
}

// IsWildcard reports whether the filter accepts every Kind.
func (f *KindFilter) IsWildcard() bool {
	return f == nil || f.wildcard
}

// Kinds returns the set of admission Kinds this filter explicitly accepts.
// Returns nil for wildcard filters.
func (f *KindFilter) Kinds() []string {
	if f == nil || f.wildcard {
		return nil
	}
	out := make([]string, 0, len(f.kinds))
	for k := range f.kinds {
		out = append(out, k)
	}
	return out
}

// kindEqualsRHS matches: event.Kind == "X" or event.Kind == 'X'.
var kindEqualsRHS = regexp.MustCompile(`event\.Kind\s*==\s*["']([^"']+)["']`)

// kindEqualsLHS matches: "X" == event.Kind or 'X' == event.Kind.
var kindEqualsLHS = regexp.MustCompile(`["']([^"']+)["']\s*==\s*event\.Kind`)

// disjunctionToken matches the CEL OR operator. When present in an expression,
// we cannot safely narrow to a finite Kind set without parsing the AST, so the
// filter falls back to wildcard.
var disjunctionToken = regexp.MustCompile(`\|\|`)

// buildKindFilter returns a KindFilter covering the admission expressions of
// the given rules. Only RuleExpression entries with EventType k8s-admission
// are considered (other event types are not evaluated by this operator).
func buildKindFilter(rs []armotypes.RuntimeRule) *KindFilter {
	f := &KindFilter{kinds: map[string]struct{}{}}

	for _, r := range rs {
		for _, expr := range r.Expressions.RuleExpression {
			if expr.EventType != armotypes.EventTypeK8sAdmission {
				continue
			}
			if f.absorbExpression(expr.Expression) {
				// One unresolvable expression poisons the whole filter.
				return &KindFilter{wildcard: true}
			}
		}
	}

	// If no expression contributed any kind constraints, the filter would
	// match nothing — which is wrong. Treat as wildcard.
	if len(f.kinds) == 0 {
		return &KindFilter{wildcard: true}
	}
	return f
}

// absorbExpression adds Kind constraints from one CEL expression into the
// filter. Returns true if the expression is unresolvable and the caller should
// fall back to wildcard mode.
func (f *KindFilter) absorbExpression(expr string) (unresolvable bool) {
	if disjunctionToken.MatchString(expr) {
		return true
	}

	var found bool
	for _, m := range kindEqualsRHS.FindAllStringSubmatch(expr, -1) {
		f.kinds[m[1]] = struct{}{}
		found = true
	}
	for _, m := range kindEqualsLHS.FindAllStringSubmatch(expr, -1) {
		f.kinds[m[1]] = struct{}{}
		found = true
	}
	return !found
}

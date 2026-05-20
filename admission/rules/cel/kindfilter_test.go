package cel

import (
	"sort"
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
)

func makeRule(id string, exprs ...armotypes.RuleExpression) armotypes.RuntimeRule {
	return armotypes.RuntimeRule{
		ID: id,
		Expressions: armotypes.RuleExpressions{
			RuleExpression: exprs,
		},
	}
}

func admExpr(expr string) armotypes.RuleExpression {
	return armotypes.RuleExpression{
		EventType:  armotypes.EventTypeK8sAdmission,
		Expression: expr,
	}
}

func TestKindFilter_Accepts(t *testing.T) {
	tests := []struct {
		name      string
		rules     []armotypes.RuntimeRule
		wildcard  bool
		wantKinds []string
		// (kind, accept) probes
		probes []struct {
			kind   string
			accept bool
		}
	}{
		{
			name: "single rule with single Kind on the RHS",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions"`)),
			},
			wantKinds: []string{"PodExecOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"Pod", false},
				{"NetworkPolicy", false},
			},
		},
		{
			name: "Kind on the LHS",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`"PodExecOptions" == event.Kind`)),
			},
			wantKinds: []string{"PodExecOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"Pod", false},
			},
		},
		{
			name: "single quotes",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == 'NetworkPolicy'`)),
			},
			wantKinds: []string{"NetworkPolicy"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"NetworkPolicy", true},
				{"Pod", false},
			},
		},
		{
			name: "conjunction with extra constraints (CREATE)",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "NetworkPolicy" && event.Operation == "CREATE"`)),
			},
			wantKinds: []string{"NetworkPolicy"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"NetworkPolicy", true},
				{"Pod", false},
			},
		},
		{
			name: "two rules cover two different Kinds",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions"`)),
				makeRule("R2", admExpr(`event.Kind == "PodPortForwardOptions"`)),
			},
			wantKinds: []string{"PodExecOptions", "PodPortForwardOptions"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"PodPortForwardOptions", true},
				{"Pod", false},
			},
		},
		{
			name: "rule with disjunction => wildcard (conservative)",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Kind == "PodExecOptions" || event.Operation == "CREATE"`)),
			},
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"PodExecOptions", true},
				{"AnythingElse", true},
			},
		},
		{
			name: "rule with no Kind constraint => wildcard",
			rules: []armotypes.RuntimeRule{
				makeRule("R1", admExpr(`event.Operation == "CREATE"`)),
			},
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
				{"Secret", true},
			},
		},
		{
			name:     "empty rule set => wildcard",
			rules:    nil,
			wildcard: true,
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
			},
		},
		{
			name: "non-admission expressions are ignored",
			rules: []armotypes.RuntimeRule{
				{
					ID: "R1",
					Expressions: armotypes.RuleExpressions{
						RuleExpression: []armotypes.RuleExpression{
							{EventType: armotypes.EventTypeExec, Expression: `true`},
							{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod"`},
						},
					},
				},
			},
			wantKinds: []string{"Pod"},
			probes: []struct {
				kind   string
				accept bool
			}{
				{"Pod", true},
				{"NetworkPolicy", false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := buildKindFilter(tt.rules)

			if f.IsWildcard() != tt.wildcard {
				t.Errorf("IsWildcard = %v, want %v", f.IsWildcard(), tt.wildcard)
			}

			if !tt.wildcard {
				got := f.Kinds()
				sort.Strings(got)
				want := append([]string(nil), tt.wantKinds...)
				sort.Strings(want)
				if !equalSlices(got, want) {
					t.Errorf("Kinds = %v, want %v", got, want)
				}
			}

			for _, p := range tt.probes {
				if f.Accepts(p.kind) != p.accept {
					t.Errorf("Accepts(%q) = %v, want %v", p.kind, f.Accepts(p.kind), p.accept)
				}
			}
		})
	}
}

func TestKindFilter_NilSafety(t *testing.T) {
	var f *KindFilter
	if !f.Accepts("AnyKind") {
		t.Error("nil KindFilter should accept all kinds")
	}
	if !f.IsWildcard() {
		t.Error("nil KindFilter should report wildcard")
	}
	if f.Kinds() != nil {
		t.Error("nil KindFilter Kinds() should return nil")
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

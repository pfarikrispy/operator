package cel

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	admissioncel "github.com/kubescape/operator/admission/cel"
)

// newTestCelEngine creates a real AdmissionCEL engine for tests.
func newTestCelEngine(t *testing.T) *admissioncel.AdmissionCEL {
	t.Helper()
	engine, err := admissioncel.NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}
	return engine
}

// testRules is a fixed set of RuntimeRules used across creator tests.
var testRules = []armotypes.RuntimeRule{
	{
		ID:          "R3000",
		Name:        "Exec to pod",
		Description: "Detects exec to pod",
		Tags:        []string{"exec", "pod"},
		Severity:    armotypes.RuleSeverityHigh,
		Expressions: armotypes.RuleExpressions{
			Message:  `"Exec detected on pod: " + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	},
	{
		ID:          "R3001",
		Name:        "Port forward",
		Description: "Detects port-forward to pod",
		Tags:        []string{"network", "pod"},
		Severity:    armotypes.RuleSeverityMed,
		Expressions: armotypes.RuleExpressions{
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodPortForwardOptions"`},
			},
		},
	},
	{
		ID:          "R3002",
		Name:        "Privileged pod",
		Description: "Detects creation of a privileged pod",
		Tags:        []string{"security"},
		Severity:    armotypes.RuleSeverityCritical,
		Expressions: armotypes.RuleExpressions{
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod"`},
			},
		},
	},
}

func TestSyncAndCreateByID(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	ev := creator.CreateRuleByID("R3000")
	if ev == nil {
		t.Fatal("expected non-nil evaluator for R3000")
	}
	if ev.ID() != "R3000" {
		t.Errorf("ID = %q, want R3000", ev.ID())
	}
	if ev.Name() != "Exec to pod" {
		t.Errorf("Name = %q, want 'Exec to pod'", ev.Name())
	}
}

func TestCreateByID_NotFound(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	ev := creator.CreateRuleByID("NONEXISTENT")
	if ev != nil {
		t.Errorf("expected nil for non-existent ID, got %v", ev)
	}
}

func TestCreateByName(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	ev := creator.CreateRuleByName("Port forward")
	if ev == nil {
		t.Fatal("expected non-nil evaluator for 'Port forward'")
	}
	if ev.ID() != "R3001" {
		t.Errorf("ID = %q, want R3001", ev.ID())
	}
}

func TestCreateByName_NotFound(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	ev := creator.CreateRuleByName("Does not exist")
	if ev != nil {
		t.Errorf("expected nil for non-existent name, got %v", ev)
	}
}

func TestCreateByTags_SingleMatch(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	evals := creator.CreateRulesByTags([]string{"security"})
	if len(evals) != 1 {
		t.Fatalf("expected 1 evaluator for tag 'security', got %d", len(evals))
	}
	if evals[0].ID() != "R3002" {
		t.Errorf("ID = %q, want R3002", evals[0].ID())
	}
}

func TestCreateByTags_MultipleMatches(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	// Both R3000 and R3001 have the "pod" tag.
	evals := creator.CreateRulesByTags([]string{"pod"})
	if len(evals) != 2 {
		t.Fatalf("expected 2 evaluators for tag 'pod', got %d", len(evals))
	}
}

func TestCreateByTags_AnyMatch(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	// "exec" matches R3000, "security" matches R3002.
	evals := creator.CreateRulesByTags([]string{"exec", "security"})
	if len(evals) != 2 {
		t.Fatalf("expected 2 evaluators, got %d", len(evals))
	}
}

func TestCreateByTags_NoMatch(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	evals := creator.CreateRulesByTags([]string{"nonexistent"})
	if len(evals) != 0 {
		t.Errorf("expected empty slice for unknown tag, got %d evaluators", len(evals))
	}
}

func TestCreateByTags_EmptyTags(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	evals := creator.CreateRulesByTags(nil)
	if len(evals) != 0 {
		t.Errorf("expected nil/empty for nil tags, got %d evaluators", len(evals))
	}
}

func TestCreateAllRules(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	evals := creator.CreateAllRules()
	if len(evals) != len(testRules) {
		t.Fatalf("CreateAllRules: got %d evaluators, want %d", len(evals), len(testRules))
	}
	// Verify IDs are preserved in order.
	for i, ev := range evals {
		if ev.ID() != testRules[i].ID {
			t.Errorf("evals[%d].ID = %q, want %q", i, ev.ID(), testRules[i].ID)
		}
	}
}

func TestCreateAllRules_EmptySet(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	// No SyncRules called — should return empty slice.
	evals := creator.CreateAllRules()
	if len(evals) != 0 {
		t.Errorf("expected empty slice before SyncRules, got %d", len(evals))
	}
}

func TestKindFilter_IsRebuiltOnSync(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))

	// Before any SyncRules call, the filter is empty and accepts nothing.
	// (No rules => no events to evaluate.)
	if creator.KindFilter().Accepts("PodExecOptions") {
		t.Error("empty creator should not accept any Kind")
	}

	// Sync a single rule pinned to PodExecOptions.
	creator.SyncRules([]armotypes.RuntimeRule{
		makeRule("R1", admExpr(`event.Kind == "PodExecOptions"`)),
	})
	f := creator.KindFilter()
	if !f.Accepts("PodExecOptions") {
		t.Error("after sync, PodExecOptions should be accepted")
	}
	if f.Accepts("Secret") {
		t.Error("after sync of single-kind rule, Secret must not be accepted")
	}

	// Replace with a wildcard rule (no Kind constraint).
	creator.SyncRules([]armotypes.RuntimeRule{
		makeRule("R2", admExpr(`event.Operation == "CREATE"`)),
	})
	if !creator.KindFilter().IsWildcard() {
		t.Error("after sync of wildcard rule, filter should be wildcard")
	}
}

// TestSyncRules_EvictsProgramsForRemovedRules ensures the CEL engine's program
// cache does not grow monotonically as rules come and go. After a SyncRules
// that drops a rule, expressions referenced only by the dropped rule must be
// evicted, while expressions still in use must survive.
func TestSyncRules_EvictsProgramsForRemovedRules(t *testing.T) {
	engine := newTestCelEngine(t)
	creator := NewCelRuleCreator(engine)

	// Two rules — each with its own expression, message, and uniqueID.
	r1 := armotypes.RuntimeRule{
		ID: "R-A",
		Expressions: armotypes.RuleExpressions{
			Message:  `"A: " + event.Name`,
			UniqueID: `event.Namespace + "/A/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}
	r2 := armotypes.RuntimeRule{
		ID: "R-B",
		Expressions: armotypes.RuleExpressions{
			Message:  `"B: " + event.Name`,
			UniqueID: `event.Namespace + "/B/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "NetworkPolicy"`},
			},
		},
	}
	creator.SyncRules([]armotypes.RuntimeRule{r1, r2})

	// Force compilation of every expression by evaluating both rules.
	evA := creator.CreateRuleByID("R-A")
	evB := creator.CreateRuleByID("R-B")
	attrsA := newEvalTestAttributes("PodExecOptions", "p", "ns", "CONNECT", "exec",
		map[string]interface{}{"kind": "PodExecOptions"})
	attrsB := newEvalTestAttributes("NetworkPolicy", "np", "ns", "CREATE", "",
		map[string]interface{}{"kind": "NetworkPolicy"})
	_ = evA.ProcessEvent(attrsA, nil)
	_ = evB.ProcessEvent(attrsB, nil)

	// 6 entries seeded: 2 rules × (match + message + uniqueID).
	if got := engine.ProgramCacheSize(); got != 6 {
		t.Fatalf("after seeding both rules: ProgramCacheSize = %d, want 6", got)
	}

	// Drop R-B; only R-A's three expressions should remain.
	creator.SyncRules([]armotypes.RuntimeRule{r1})
	if got := engine.ProgramCacheSize(); got != 3 {
		t.Errorf("after dropping R-B: ProgramCacheSize = %d, want 3", got)
	}

	// Drop everything.
	creator.SyncRules(nil)
	if got := engine.ProgramCacheSize(); got != 0 {
		t.Errorf("after dropping all rules: ProgramCacheSize = %d, want 0", got)
	}
}

func TestSyncRulesReplaces(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))
	creator.SyncRules(testRules)

	// Replace with a single-rule set.
	replacement := []armotypes.RuntimeRule{
		{ID: "R9999", Name: "Replacement rule", Tags: []string{"new"}},
	}
	creator.SyncRules(replacement)

	evals := creator.CreateAllRules()
	if len(evals) != 1 {
		t.Fatalf("after SyncRules replacement: got %d evaluators, want 1", len(evals))
	}
	if evals[0].ID() != "R9999" {
		t.Errorf("ID = %q, want R9999", evals[0].ID())
	}

	// Old rules must no longer be accessible.
	if ev := creator.CreateRuleByID("R3000"); ev != nil {
		t.Error("old rule R3000 still accessible after SyncRules replacement")
	}
}

func TestSyncRulesIsolation(t *testing.T) {
	creator := NewCelRuleCreator(newTestCelEngine(t))

	// Mutating the original slice after SyncRules must not affect the creator.
	original := []armotypes.RuntimeRule{
		{ID: "R1", Name: "Rule One"},
	}
	creator.SyncRules(original)

	// Mutate the original slice.
	original[0].ID = "MUTATED"

	ev := creator.CreateRuleByID("R1")
	if ev == nil {
		t.Fatal("expected evaluator for R1 after mutation of original slice")
	}
}

package cel

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
)

func newExecEvent() *AdmissionCelEvent {
	attrs := newTestAttributes("PodExecOptions", "my-pod", "default", "CONNECT", "exec",
		map[string]interface{}{
			"command":   []interface{}{"/bin/sh"},
			"container": "main",
		})
	return NewAdmissionCelEvent(attrs)
}

func TestMatchSimpleKind(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if !ok {
		t.Error("expected true for matching kind")
	}
}

func TestNoMatch_DifferentKind(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if ok {
		t.Error("expected false for non-matching kind")
	}
}

func TestSkipDifferentEventType(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	// Expression is for "exec" event type, but we evaluate with "k8s-admission".
	// No expressions match, so the result should be false.
	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeExec, Expression: `event.Kind == "PodExecOptions"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if ok {
		t.Error("expected false when no expressions match event type")
	}
}

func TestMultipleExpressions_AllTrue(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Namespace == "default"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if !ok {
		t.Error("expected true when all expressions match")
	}
}

func TestMultipleExpressions_ShortCircuit(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	// First expression is false — should short-circuit without evaluating the second.
	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Kind == "Pod"`},
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.Namespace == "default"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if ok {
		t.Error("expected false when first expression is false")
	}
}

func TestUserInfoAccess(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.UserInfo.Username == "test-user"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if !ok {
		t.Error("expected true for matching username")
	}
}

func TestObjectFieldAccess(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	// Object/OldObject/Options are top-level map variables, not struct fields,
	// because cel-go NativeTypes doesn't support map[string]interface{}.
	ok, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `object["container"] == "main"`},
	})
	if err != nil {
		t.Fatalf("EvaluateRuleWithContext: %v", err)
	}
	if !ok {
		t.Error("expected true for matching object field")
	}
}

func TestMessageExpression(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	msg, err := engine.EvaluateStringExpression(ctx, `"Exec to pod: " + event.Name`)
	if err != nil {
		t.Fatalf("EvaluateStringExpression: %v", err)
	}
	want := "Exec to pod: my-pod"
	if msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestCompileError(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	_, err = engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: `event.nonExistentField == "x"`},
	})
	if err == nil {
		t.Fatal("expected error for non-existent field, got nil")
	}
}

func TestProgramCaching(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}

	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	expr := `event.Kind == "PodExecOptions"`

	// Evaluate twice — cache should hold exactly one entry for this expression.
	for i := 0; i < 2; i++ {
		_, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
			{EventType: armotypes.EventTypeK8sAdmission, Expression: expr},
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if size := engine.ProgramCacheSize(); size != 1 {
		t.Errorf("ProgramCacheSize = %d, want 1", size)
	}
}

func TestRetainOnly(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}
	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	// Seed three programs into the cache.
	exprs := []string{
		`event.Kind == "PodExecOptions"`,
		`event.Kind == "PodPortForwardOptions"`,
		`event.Kind == "NetworkPolicy"`,
	}
	for _, expr := range exprs {
		_, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
			{EventType: armotypes.EventTypeK8sAdmission, Expression: expr},
		})
		if err != nil {
			t.Fatalf("eval %q: %v", expr, err)
		}
	}
	if size := engine.ProgramCacheSize(); size != 3 {
		t.Fatalf("after seed: ProgramCacheSize = %d, want 3", size)
	}

	// Retain only the first two — the third must be evicted.
	engine.RetainOnly(exprs[:2])
	if size := engine.ProgramCacheSize(); size != 2 {
		t.Errorf("after RetainOnly([0:2]): ProgramCacheSize = %d, want 2", size)
	}

	// Re-evaluating a retained expression must not recompile (count stays).
	_, err = engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: exprs[0]},
	})
	if err != nil {
		t.Fatalf("re-eval retained expr: %v", err)
	}
	if size := engine.ProgramCacheSize(); size != 2 {
		t.Errorf("after re-eval retained: ProgramCacheSize = %d, want 2", size)
	}

	// Re-evaluating an evicted expression must recompile (count goes up).
	_, err = engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: exprs[2]},
	})
	if err != nil {
		t.Fatalf("re-eval evicted expr: %v", err)
	}
	if size := engine.ProgramCacheSize(); size != 3 {
		t.Errorf("after re-eval evicted: ProgramCacheSize = %d, want 3", size)
	}

	// Clearing the active set evicts everything.
	engine.RetainOnly(nil)
	if size := engine.ProgramCacheSize(); size != 0 {
		t.Errorf("after RetainOnly(nil): ProgramCacheSize = %d, want 0", size)
	}
}

// TestCompileFailure_ReturnsErrorEveryCall verifies that a broken CEL
// expression surfaces a compilation error on every evaluation, not just the
// first one. The previous implementation cached compile failures as nil and
// silently treated them as "no match", hiding misconfigured rules from
// operators.
func TestCompileFailure_ReturnsErrorEveryCall(t *testing.T) {
	engine, err := NewAdmissionCEL()
	if err != nil {
		t.Fatalf("NewAdmissionCEL: %v", err)
	}
	event := newExecEvent()
	ctx := engine.CreateEvalContext(event)

	// Syntactically invalid CEL — cannot compile.
	badExpr := `event.Kind === "Pod"` // CEL has no === operator
	exprs := []armotypes.RuleExpression{
		{EventType: armotypes.EventTypeK8sAdmission, Expression: badExpr},
	}

	for i := 0; i < 3; i++ {
		_, err := engine.EvaluateRuleWithContext(ctx, armotypes.EventTypeK8sAdmission, exprs)
		if err == nil {
			t.Fatalf("call %d: expected compile error, got nil — broken rules must not be silently ignored", i+1)
		}
	}

	// Cache must contain exactly one entry (the failed compile is cached so we
	// don't re-attempt every event), but every lookup must still return the
	// error.
	if size := engine.ProgramCacheSize(); size != 1 {
		t.Errorf("ProgramCacheSize = %d after 3 failed evals, want 1 (one cached failure)", size)
	}

	// EvaluateStringExpression must follow the same contract.
	if _, err := engine.EvaluateStringExpression(ctx, badExpr); err == nil {
		t.Error("EvaluateStringExpression: expected compile error, got nil")
	}
}

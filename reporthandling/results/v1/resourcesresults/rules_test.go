package resourcesresults

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	apisv1 "github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/stretchr/testify/assert"
)

func TestSetGetRuleName(t *testing.T) {
	r := ResourceAssociatedRule{}
	id := "my-rule"
	r.SetName(id)
	assert.Equal(t, id, r.GetName())
}

func TestRuleStatusIsFrameworkScoped(t *testing.T) {
	exception := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "NSA",
				ControlID:     "C-0034",
				RuleName:      "R1",
			},
		},
	}

	newRule := func() ResourceAssociatedRule {
		return ResourceAssociatedRule{
			Name:      "R1",
			Status:    apisv1.StatusFailed,
			Exception: []armotypes.PostureExceptionPolicy{exception},
		}
	}

	t.Run("NSA exception does not suppress MITRE failure", func(t *testing.T) {
		rule := newRule()

		assert.Equal(t, apisv1.StatusPassed, rule.GetStatus(&helpersv1.Filters{
			FrameworkNames: []string{"NSA"},
		}).Status())
		assert.Equal(t, apisv1.StatusFailed, rule.GetStatus(nil).Status())

		assert.Equal(t, apisv1.StatusFailed, rule.GetStatus(&helpersv1.Filters{
			FrameworkNames: []string{"MITRE"},
		}).Status())
	})

	t.Run("framework evaluation order does not change result", func(t *testing.T) {
		evaluate := func(order []string) map[string][2]string {
			rule := newRule()
			statuses := make(map[string][2]string, len(order))
			for _, framework := range order {
				status := rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{framework}})
				statuses[framework] = [2]string{string(status.Status()), string(status.GetSubStatus())}
			}
			assert.Equal(t, apisv1.StatusFailed, rule.Status)
			return statuses
		}

		assert.Equal(t, evaluate([]string{"NSA", "MITRE"}), evaluate([]string{"MITRE", "NSA"}))
	})
}

func TestRuleStatusFoldsSelectedFrameworkViews(t *testing.T) {
	rule := ResourceAssociatedRule{
		Name:   "R1",
		Status: apisv1.StatusFailed,
		Exception: []armotypes.PostureExceptionPolicy{{
			PosturePolicies: []armotypes.PosturePolicy{{
				FrameworkName: "NSA",
				ControlID:     "C-0034",
				RuleName:      "R1",
			}},
		}},
	}

	status := rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA", "MITRE", "NSA"}})

	assert.Equal(t, apisv1.StatusFailed, status.Status())
	assert.Equal(t, apisv1.SubStatusException, status.GetSubStatus())
	assert.Equal(t, apisv1.StatusFailed, rule.Status, "view calculation must preserve the raw evaluation")
}

func TestRuleStatusUsesRegexFrameworkScope(t *testing.T) {
	rule := ResourceAssociatedRule{
		Name:   "R1",
		Status: apisv1.StatusFailed,
		Exception: []armotypes.PostureExceptionPolicy{{
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "MIT.*", RuleName: "R1"}},
		}},
	}

	status := rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}})
	assert.Equal(t, apisv1.StatusPassed, status.Status())
	assert.Equal(t, apisv1.SubStatusException, status.GetSubStatus())
}

func TestRuleStatusSelectedFrameworkAggregate(t *testing.T) {
	policy := func(framework string, actions ...armotypes.PostureExceptionPolicyActions) armotypes.PostureExceptionPolicy {
		return armotypes.PostureExceptionPolicy{
			Actions: actions,
			PosturePolicies: []armotypes.PosturePolicy{{
				FrameworkName: framework, ControlID: "C-0034", RuleName: "R1",
			}},
		}
	}
	tests := []struct {
		name              string
		frameworks        []string
		exceptions        []armotypes.PostureExceptionPolicy
		expectedStatus    apisv1.ScanningStatus
		expectedSubStatus apisv1.ScanningSubStatus
	}{
		{
			name: "only selected framework is excepted", frameworks: []string{"NSA"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("NSA", armotypes.Disable)},
			expectedStatus: apisv1.StatusPassed, expectedSubStatus: apisv1.SubStatusException,
		},
		{
			name: "one selected framework remains failed", frameworks: []string{"NSA", "MITRE"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("NSA", armotypes.Disable)},
			expectedStatus: apisv1.StatusFailed, expectedSubStatus: apisv1.SubStatusException,
		},
		{
			name: "all selected frameworks are excepted", frameworks: []string{"NSA", "MITRE"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("NSA", armotypes.Disable), policy("MITRE", armotypes.Disable)},
			expectedStatus: apisv1.StatusPassed, expectedSubStatus: apisv1.SubStatusException,
		},
		{
			name: "framework agnostic exception applies to every selected framework", frameworks: []string{"NSA", "MITRE"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("", armotypes.Disable)},
			expectedStatus: apisv1.StatusPassed, expectedSubStatus: apisv1.SubStatusException,
		},
		{
			name: "alert only acknowledges but does not suppress", frameworks: []string{"NSA", "MITRE"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("NSA", armotypes.AlertOnly)},
			expectedStatus: apisv1.StatusFailed, expectedSubStatus: apisv1.SubStatusException,
		},
		{
			name: "empty action keeps historical suppressing behavior", frameworks: []string{"NSA"},
			exceptions:     []armotypes.PostureExceptionPolicy{policy("NSA")},
			expectedStatus: apisv1.StatusPassed, expectedSubStatus: apisv1.SubStatusException,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ResourceAssociatedRule{Name: "R1", Status: apisv1.StatusFailed, Exception: tt.exceptions}
			status := rule.getStatus(&helpersv1.Filters{FrameworkNames: tt.frameworks}, "C-0034")
			assert.Equal(t, tt.expectedStatus, status.Status())
			assert.Equal(t, tt.expectedSubStatus, status.GetSubStatus())
		})
	}
}

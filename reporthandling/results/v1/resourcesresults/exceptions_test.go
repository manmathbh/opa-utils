package resourcesresults

import (
	"github.com/armosec/armoapi-go/identifiers"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockExceptionDeploymentC0087() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: "DeploymentC0087",
		},
		Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{
			{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes: map[string]string{
					identifiers.AttributeKind: "Deployment",
				},
			},
		},
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID: "C-0087",
			},
		},
	}
}

func mockExceptionUnitestDeploymentC0087() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: "unitestDeploymentC0087",
		},
		Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{
			{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes: map[string]string{
					identifiers.AttributeCluster: "unitest",
					identifiers.AttributeKind:    "Deployment",
				},
			},
		},
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID: "C-0087",
			},
		},
	}
}

func mockExceptionUnitestC0088() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: "unitestC0088",
		},
		Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{
			{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes: map[string]string{
					identifiers.AttributeCluster: "unitest",
				},
			},
		},
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID: "C-0088",
			},
		},
	}
}

func mockExceptionDeploymentC0089() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PortalBase: armotypes.PortalBase{
			Name: "Deployment0089",
		},
		Actions: []armotypes.PostureExceptionPolicyActions{armotypes.AlertOnly},
		Resources: []identifiers.PortalDesignator{
			{
				DesignatorType: identifiers.DesignatorAttributes,
				Attributes: map[string]string{
					identifiers.AttributeKind: "Deployment",
				},
			},
		},
		PosturePolicies: []armotypes.PosturePolicy{
			{
				ControlID: "C-0089",
			},
		},
	}
}

func mockControlsList() map[string]reporthandling.Control {
	return map[string]reporthandling.Control{
		"C-0087": {},
		"C-0088": {},
		"C-0089": {},
	}
}

// withActions overrides the action on a mock policy. The suppression tests below
// pin it to Disable so they keep exercising which exceptions match, independently
// of what each action then does to the status.
func withActions(policy *armotypes.PostureExceptionPolicy, actions ...armotypes.PostureExceptionPolicyActions) *armotypes.PostureExceptionPolicy {
	policy.Actions = actions
	return policy
}

func TestSetExceptions(t *testing.T) {
	w := workloadinterface.NewWorkloadMock(nil)
	processor := exceptions.NewProcessor()

	exceptions := []armotypes.PostureExceptionPolicy{}
	exceptions = append(exceptions, *withActions(mockExceptionDeploymentC0087(), armotypes.Disable))
	exceptions = append(exceptions, *withActions(mockExceptionUnitestDeploymentC0087(), armotypes.Disable))
	exceptions = append(exceptions, *withActions(mockExceptionUnitestC0088(), armotypes.Disable))
	exceptions = append(exceptions, *withActions(mockExceptionDeploymentC0089(), armotypes.Disable))
	c := mockControlsList()
	// simple test
	result1 := mockResultFailed()
	result1.SetExceptions(w, exceptions, "", c, WithExceptionsProcessor(processor))
	assert.Equal(t, 2, result1.ListControlsIDs(nil).Passed())
	assert.Equal(t, 1, result1.ListControlsIDs(nil).Failed())

	// without option to reuse the processor
	result1.SetExceptions(w, exceptions, "", c)
	assert.Equal(t, 2, result1.ListControlsIDs(nil).Passed())
	assert.Equal(t, 1, result1.ListControlsIDs(nil).Failed())

	// test cluster name
	result2 := mockResultFailed()
	result2.SetExceptions(w, exceptions, "unitest", c, WithExceptionsProcessor(processor))
	assert.Equal(t, 3, result2.ListControlsIDs(nil).Passed())
	assert.Equal(t, 0, result2.ListControlsIDs(nil).Failed())

	// test wrong cluster name
	result3 := mockResultFailed()
	result3.SetExceptions(w, exceptions, "unitest2", c, WithExceptionsProcessor(processor))
	assert.Equal(t, 2, result3.ListControlsIDs(nil).Passed())
	assert.Equal(t, 1, result3.ListControlsIDs(nil).Failed())
}

func TestSetExceptionsKeepsRuleStatusForFrameworkScopedEvaluation(t *testing.T) {
	// Framework scoping behaves the same for both actions: the exception applies to
	// the framework it names and not to any other. What differs is the status the
	// applied exception then produces.
	tests := []struct {
		name           string
		action         armotypes.PostureExceptionPolicyActions
		expectedStatus apis.ScanningStatus
	}{
		{
			name:           "disable suppresses the finding",
			action:         armotypes.Disable,
			expectedStatus: apis.StatusPassed,
		},
		{
			name:           "alertOnly acknowledges the finding but keeps it failing",
			action:         armotypes.AlertOnly,
			expectedStatus: apis.StatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := workloadinterface.NewWorkloadMock(nil)
			policy := withActions(mockExceptionDeploymentC0087(), tt.action)
			policy.PosturePolicies[0].FrameworkName = "NSA"
			policy.PosturePolicies[0].RuleName = "ruleA"

			result := Result{AssociatedControls: []ResourceAssociatedControl{{
				ControlID: "C-0087",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []ResourceAssociatedRule{
					*mockResourceAssociatedRuleA(),
				},
			}}}

			result.SetExceptions(w, []armotypes.PostureExceptionPolicy{*policy}, "", map[string]reporthandling.Control{"C-0087": {}})

			control := result.AssociatedControls[0]
			rule := control.ResourceAssociatedRules[0]
			assert.Equal(t, apis.StatusFailed, rule.Status, "exceptions must not overwrite the raw rule status")

			assert.Equal(t, apis.StatusFailed, control.GetStatus(nil).Status(),
				"a framework-scoped exception must not suppress the raw/global view")
			assert.Equal(t, apis.SubStatusUnknown, control.GetStatus(nil).GetSubStatus())

			// The exception names NSA, so it applies there and nowhere else.
			nsa := control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}})
			assert.Equal(t, tt.expectedStatus, nsa.Status())
			assert.Equal(t, apis.SubStatusException, nsa.GetSubStatus())

			mitre := control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}})
			assert.Equal(t, apis.StatusFailed, mitre.Status())
			assert.Equal(t, apis.SubStatusUnknown, mitre.GetSubStatus(),
				"an exception scoped to another framework must not annotate this one")
		})
	}
}

func TestSetExceptionsPreservesPolicyTupleCorrelation(t *testing.T) {
	w := workloadinterface.NewWorkloadMock(nil)
	exception := armotypes.PostureExceptionPolicy{
		Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
		PosturePolicies: []armotypes.PosturePolicy{
			{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"},
			{FrameworkName: "MITRE", ControlID: "C-0034", RuleName: "R2"},
		},
	}
	result := Result{AssociatedControls: []ResourceAssociatedControl{{
		ControlID: "C-0034",
		Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
		ResourceAssociatedRules: []ResourceAssociatedRule{{
			Name: "R1", Status: apis.StatusFailed,
		}},
	}}}

	result.SetExceptions(w, []armotypes.PostureExceptionPolicy{exception}, "", map[string]reporthandling.Control{"C-0034": {}})

	rule := result.AssociatedControls[0].ResourceAssociatedRules[0]
	assert.Equal(t, apis.StatusPassed, rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}}).Status())
	assert.Equal(t, apis.StatusFailed, rule.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}}).Status())
	require.Len(t, rule.Exception, 1)
	require.Len(t, rule.Exception[0].PosturePolicies, 1)
	assert.Equal(t, "NSA", rule.Exception[0].PosturePolicies[0].FrameworkName)
	assert.Len(t, exception.PosturePolicies, 2, "SetExceptions must not mutate the caller-owned exception")
}

package resourcesresults

import (
	"encoding/json"
	"testing"

	_ "embed"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/stretchr/testify/assert"
)

func TestSetGetControlID(t *testing.T) {
	r := ResourceAssociatedControl{}
	id := "C-0078"
	r.SetID(id)
	assert.Equal(t, id, r.GetID())
}

func TestSetStatus(t *testing.T) {
	r1 := mockResourceAssociatedControlPassed()
	r1.SetStatus(reporthandling.Control{})
	assert.Equal(t, apis.StatusPassed, r1.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusUnknown, r1.GetSubStatus())
	assert.True(t, r1.GetStatus(nil).IsPassed())
	assert.False(t, r1.GetStatus(nil).IsFailed())
	assert.False(t, r1.GetStatus(nil).IsSkipped())

	r2 := mockResourceAssociatedControlFailed()
	r2.SetStatus(reporthandling.Control{})
	assert.Equal(t, apis.StatusFailed, r2.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusUnknown, r2.GetSubStatus())
	assert.False(t, r2.GetStatus(nil).IsPassed())
	assert.True(t, r2.GetStatus(nil).IsFailed())
	assert.False(t, r2.GetStatus(nil).IsSkipped())

	r3 := mockResourceAssociatedControlException()
	r3.SetStatus(reporthandling.Control{})
	assert.Equal(t, apis.StatusPassed, r3.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusException, r3.GetSubStatus())
	assert.True(t, r3.GetStatus(nil).IsPassed())
	assert.False(t, r3.GetStatus(nil).IsFailed())
	assert.False(t, r3.GetStatus(nil).IsSkipped())

	r4 := mockResourceAssociatedControlConfiguration()
	r4.SetStatus(*mockControlWithActionRequiredConfiguration())
	assert.Equal(t, apis.StatusSkipped, r4.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusConfiguration, r4.GetSubStatus())
	assert.False(t, r4.GetStatus(nil).IsPassed())
	assert.False(t, r4.GetStatus(nil).IsFailed())
	assert.True(t, r4.GetStatus(nil).IsSkipped())

	r5 := mockResourceAssociatedControlFailed()
	r5.SetStatus(*mockControlWithActionRequiredManualReview())
	assert.Equal(t, apis.StatusSkipped, r5.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusManualReview, r5.GetSubStatus())
	assert.False(t, r5.GetStatus(nil).IsPassed())
	assert.False(t, r5.GetStatus(nil).IsFailed())
	assert.True(t, r5.GetStatus(nil).IsSkipped())

	r6 := mockResourceAssociatedControlFailed()
	r6.SetStatus(*mockControlWithActionRequiredRequiresReview())
	assert.Equal(t, apis.StatusSkipped, r6.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusRequiresReview, r6.GetSubStatus())
	assert.False(t, r6.GetStatus(nil).IsPassed())
	assert.False(t, r6.GetStatus(nil).IsFailed())
	assert.True(t, r6.GetStatus(nil).IsSkipped())

	// notEvaluated must not be overwritten by configuration even when configs are missing.
	// A GVR collection gap (RBAC denied, missing CRD) takes precedence over a missing-config skip.
	r7 := mockResourceAssociatedControlNotEvaluated()
	r7.SetStatus(*mockControlWithActionRequiredConfiguration())
	assert.Equal(t, apis.StatusSkipped, r7.GetStatus(nil).Status())
	assert.Equal(t, apis.SubStatusNotEvaluated, r7.GetSubStatus())
	assert.Equal(t, string(apis.SubStatusNotEvaluatedInfo), r7.GetStatus(nil).Info())
	assert.True(t, r7.GetStatus(nil).IsSkipped())

}

func TestControlStatusIsFrameworkScoped(t *testing.T) {
	exception := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "NSA",
				ControlID:     "C-0034",
				RuleName:      "R1",
			},
		},
	}

	control := ResourceAssociatedControl{
		ControlID: "C-0034",
		Status: apis.StatusInfo{
			InnerStatus: apis.StatusFailed,
		},
		ResourceAssociatedRules: []ResourceAssociatedRule{
			{
				Name:      "R1",
				Status:    apis.StatusFailed,
				Exception: []armotypes.PostureExceptionPolicy{exception},
			},
		},
	}

	t.Run("NSA exception produces passed with exception", func(t *testing.T) {
		status := control.GetStatus(&helpersv1.Filters{
			FrameworkNames: []string{"NSA"},
		})

		assert.Equal(t, apis.StatusPassed, status.Status())
	})

	t.Run("MITRE remains failed", func(t *testing.T) {
		status := control.GetStatus(&helpersv1.Filters{
			FrameworkNames: []string{"MITRE"},
		})

		assert.Equal(t, apis.StatusFailed, status.Status())
	})

	t.Run("aggregate remains failed", func(t *testing.T) {
		status := control.GetStatus(nil)

		assert.Equal(t, apis.StatusFailed, status.Status())
	})
}

func TestFilteredControlStatusPreservesActionRequired(t *testing.T) {
	exception := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA"}},
	}

	tests := []struct {
		name             string
		action           *reporthandling.Control
		wantNSA          apis.ScanningStatus
		wantMITRE        apis.ScanningStatus
		wantMITRESubstat apis.ScanningSubStatus
	}{
		{"requires review", mockControlWithActionRequiredRequiresReview(), apis.StatusPassed, apis.StatusSkipped, apis.SubStatusRequiresReview},
		{"manual review", mockControlWithActionRequiredManualReview(), apis.StatusPassed, apis.StatusSkipped, apis.SubStatusManualReview},
		{"configuration", mockControlWithActionRequiredConfiguration(), apis.StatusSkipped, apis.StatusSkipped, apis.SubStatusConfiguration},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := ResourceAssociatedControl{ResourceAssociatedRules: []ResourceAssociatedRule{{
				Status:    apis.StatusFailed,
				Exception: []armotypes.PostureExceptionPolicy{exception},
			}}}
			control.SetStatus(*tt.action)

			nsaStatus := control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}})
			assert.Equal(t, tt.wantNSA, nsaStatus.Status())

			mitreStatus := control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}})
			assert.Equal(t, tt.wantMITRE, mitreStatus.Status())
			assert.Equal(t, tt.wantMITRESubstat, mitreStatus.GetSubStatus())
		})
	}
}

func TestFilteredControlStatusPreservesActionRequiredAfterJSONRoundTrip(t *testing.T) {
	exception := armotypes.PostureExceptionPolicy{
		Actions:         []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
		PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"}},
	}
	tests := []struct {
		name             string
		action           *reporthandling.Control
		wantNSA          apis.ScanningStatus
		wantNSASubStatus apis.ScanningSubStatus
		wantMITRE        apis.ScanningStatus
		wantMITRESubstat apis.ScanningSubStatus
	}{
		{"requires review", mockControlWithActionRequiredRequiresReview(), apis.StatusPassed, apis.SubStatusException, apis.StatusSkipped, apis.SubStatusRequiresReview},
		{"manual review", mockControlWithActionRequiredManualReview(), apis.StatusPassed, apis.SubStatusException, apis.StatusSkipped, apis.SubStatusManualReview},
		{"configuration", mockControlWithActionRequiredConfiguration(), apis.StatusSkipped, apis.SubStatusConfiguration, apis.StatusSkipped, apis.SubStatusConfiguration},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := ResourceAssociatedControl{
				ControlID: "C-0034",
				ResourceAssociatedRules: []ResourceAssociatedRule{{
					Name: "R1", Status: apis.StatusFailed, Exception: []armotypes.PostureExceptionPolicy{exception},
				}},
			}
			control.SetStatus(*tt.action)

			payload, err := json.Marshal(control)
			assert.NoError(t, err)
			assert.NotContains(t, string(payload), "actionRequired")

			var roundTripped ResourceAssociatedControl
			assert.NoError(t, json.Unmarshal(payload, &roundTripped))

			nsa := roundTripped.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}})
			assert.Equal(t, tt.wantNSA, nsa.Status())
			assert.Equal(t, tt.wantNSASubStatus, nsa.GetSubStatus())

			mitre := roundTripped.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}})
			assert.Equal(t, tt.wantMITRE, mitre.Status())
			assert.Equal(t, tt.wantMITRESubstat, mitre.GetSubStatus())
		})
	}
}

func TestOldControlFrameworkStatusDoesNotMutateRules(t *testing.T) {
	control := ResourceAssociatedControl{ResourceAssociatedRules: []ResourceAssociatedRule{{
		Status: apis.StatusFailed,
		Exception: []armotypes.PostureExceptionPolicy{{
			PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: "NSA"}},
		}},
	}}}

	assert.Equal(t, apis.StatusPassed, control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}}).Status())
	assert.Equal(t, apis.StatusFailed, control.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}}).Status())
	assert.Equal(t, apis.StatusFailed, control.ResourceAssociatedRules[0].Status)
}

func TestOldControlJSONPreservesExceptionTupleCorrelation(t *testing.T) {
	legacyControl := ResourceAssociatedControl{
		ControlID: "C-0034",
		ResourceAssociatedRules: []ResourceAssociatedRule{{
			Name: "R1", Status: apis.StatusFailed,
			Exception: []armotypes.PostureExceptionPolicy{{
				Actions: []armotypes.PostureExceptionPolicyActions{armotypes.Disable},
				PosturePolicies: []armotypes.PosturePolicy{
					{FrameworkName: "NSA", ControlID: "C-0034", RuleName: "R1"},
					{FrameworkName: "MITRE", ControlID: "C-0034", RuleName: "R2"},
				},
			}},
		}},
	}

	payload, err := json.Marshal(legacyControl)
	assert.NoError(t, err)
	var decoded ResourceAssociatedControl
	assert.NoError(t, json.Unmarshal(payload, &decoded))
	assert.Len(t, decoded.ResourceAssociatedRules[0].Exception[0].PosturePolicies, 2, "legacy JSON remains unpruned on disk")

	nsa := decoded.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"NSA"}})
	assert.Equal(t, apis.StatusPassed, nsa.Status())
	assert.Equal(t, apis.SubStatusException, nsa.GetSubStatus())

	mitre := decoded.GetStatus(&helpersv1.Filters{FrameworkNames: []string{"MITRE"}})
	assert.Equal(t, apis.StatusFailed, mitre.Status(), "MITRE/R2 must not except MITRE/R1")
	assert.Equal(t, apis.SubStatusUnknown, mitre.GetSubStatus())
}

func TestSetStatusAddsSubStatusInfo(t *testing.T) {
	tests := []struct {
		name    string
		control *ResourceAssociatedControl
		source  reporthandling.Control
		want    string
	}{
		{
			name:    "not evaluated rule",
			control: mockResourceAssociatedControlNotEvaluated(),
			source:  reporthandling.Control{},
			want:    string(apis.SubStatusNotEvaluatedInfo),
		},
		{
			name:    "configuration action",
			control: mockResourceAssociatedControlConfiguration(),
			source:  *mockControlWithActionRequiredConfiguration(),
			want:    string(apis.SubStatusConfigurationInfo),
		},
		{
			name:    "manual review action",
			control: mockResourceAssociatedControlFailed(),
			source:  *mockControlWithActionRequiredManualReview(),
			want:    string(apis.SubStatusManualReviewInfo),
		},
		{
			name:    "requires review action",
			control: mockResourceAssociatedControlFailed(),
			source:  *mockControlWithActionRequiredRequiresReview(),
			want:    string(apis.SubStatusRequiresReviewInfo),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.control.SetStatus(test.source)
			assert.Equal(t, test.want, test.control.GetStatus(nil).Info())
		})
	}
}

func TestResourceAssociatedControl_SetName(t *testing.T) {
	type fields struct {
		ControlID               string
		Name                    string
		ResourceAssociatedRules []ResourceAssociatedRule
	}
	type args struct {
		name string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "TestResourceAssociatedControl_SetName",
			fields: struct {
				ControlID               string
				Name                    string
				ResourceAssociatedRules []ResourceAssociatedRule
			}{
				ControlID:               "C-0078",
				Name:                    "TestResourceAssociatedControl_SetName",
				ResourceAssociatedRules: []ResourceAssociatedRule{},
			},
			args: struct{ name string }{name: "TestResourceAssociatedControl_SetName"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := &ResourceAssociatedControl{
				ControlID:               tt.fields.ControlID,
				Name:                    tt.fields.Name,
				ResourceAssociatedRules: tt.fields.ResourceAssociatedRules,
			}
			control.SetName(tt.args.name)
		})
	}
}

//go:embed testdata/old_resource_associated_controls.json
var oldResourceAssociatedControlsTestData []byte

func Test_GetStatusAndSubStatus_OldResourceAssociatedControls(t *testing.T) {
	controls := []ResourceAssociatedControl{}
	err := json.Unmarshal([]byte(oldResourceAssociatedControlsTestData), &controls)
	assert.NoError(t, err)

	controlIdToExpectedStatus := map[string]string{
		// C-0054 carries two alertOnly exceptions, which acknowledge the finding
		// without suppressing it, so the control keeps failing.
		"C-0054": "failed", // failed w/ exception
		"C-0067": "failed", // failed
		"C-0002": "passed", // passed
	}

	controlIdToExpectedSubStatus := map[string]string{
		"C-0054": "w/exceptions", // failed w/ exception
		"C-0067": "",             // failed
		"C-0002": "",             // passed
	}

	for _, control := range controls {
		assert.True(t, control.isOldControl())
		assert.Equal(t, controlIdToExpectedStatus[control.ControlID], string(control.GetStatus(nil).Status()))
		assert.Equal(t, controlIdToExpectedSubStatus[control.ControlID], string(control.GetSubStatus()))
	}
}

//go:embed testdata/new_resource_associated_controls.json
var newResourceAssociatedControlsTestData []byte

func Test_GetStatusAndSubStatus_NewResourceAssociatedControls(t *testing.T) {
	controls := []ResourceAssociatedControl{}
	err := json.Unmarshal([]byte(newResourceAssociatedControlsTestData), &controls)
	assert.NoError(t, err)

	controlIdToExpectedStatus := map[string]string{
		"C-0053": "passed", // passed w/ exception
		"C-0014": "passed", // passed
		"C-0212": "failed", // failed
	}

	controlIdToExpectedSubStatus := map[string]string{
		"C-0053": "w/exceptions", // passed w/ exception
		"C-0014": "",             // passed
		"C-0212": "",             // failed
	}

	for _, control := range controls {
		assert.False(t, control.isOldControl())
		assert.Equal(t, controlIdToExpectedStatus[control.ControlID], string(control.GetStatus(nil).Status()))
		assert.Equal(t, controlIdToExpectedSubStatus[control.ControlID], string(control.GetSubStatus()))
	}
}

func TestControlMissingAllConfigurations(t *testing.T) {
	tests := []struct {
		name    string
		control *ResourceAssociatedControl
		want    bool
	}{
		{
			name: "TestControlNoConfigurations",
			control: &ResourceAssociatedControl{
				ResourceAssociatedRules: []ResourceAssociatedRule{
					{
						ControlConfigurations: map[string][]string{},
					},
				},
			},
			want: true,
		}, {
			name: "TestControlOneEmptyConfiguration",
			control: &ResourceAssociatedControl{
				ResourceAssociatedRules: []ResourceAssociatedRule{
					{
						ControlConfigurations: map[string][]string{
							"EmptyConfiguration": {},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "TestControlOneNonEmptyConfiguration",
			control: &ResourceAssociatedControl{
				ResourceAssociatedRules: []ResourceAssociatedRule{
					{
						ControlConfigurations: map[string][]string{
							"NonEmptyConfiguration": {
								"key", "value",
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "TestControlMultipleConfigurations",
			control: &ResourceAssociatedControl{
				ResourceAssociatedRules: []ResourceAssociatedRule{
					{
						ControlConfigurations: map[string][]string{
							"EmptyConfiguration": {},
							"NonEmptyConfiguration": {
								"key", "value",
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controlMissingAllConfigurations(tt.control); got != tt.want {
				t.Errorf("Control.missingAllConfigurations() = %v, want %v", got, tt.want)
			}
		})
	}
}

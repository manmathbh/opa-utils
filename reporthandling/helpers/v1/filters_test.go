package helpers

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"
)

func mockNSAFW() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "NSA",
			},
		},
	}

}

func mockMITREFW() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "MITRE",
			},
		},
	}

}

func mockEmptyFW() *armotypes.PostureExceptionPolicy {
	return &armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "",
			},
		},
	}

}
func TestFilterExceptions(t *testing.T) {
	f := Filters{}
	exceptions := []armotypes.PostureExceptionPolicy{
		*mockEmptyFW(),
		*mockMITREFW(),
	}
	exceptions2 := f.FilterExceptions(exceptions)
	assert.Len(t, exceptions2, 1, "an empty filter selects only framework-agnostic exceptions")

	exceptions = append(exceptions, *mockNSAFW())
	f.FrameworkNames = []string{"NSA"}
	exceptions3 := f.FilterExceptions(exceptions)
	assert.Equal(t, len(exceptions)-1, len(exceptions3))

	f.FrameworkNames = []string{"NSA", "MITRE"}
	exceptions4 := f.FilterExceptions(exceptions)
	assert.Equal(t, len(exceptions), len(exceptions4))

	f.FrameworkNames = []string{}
	exceptions5 := f.FilterExceptions(exceptions)
	assert.Len(t, exceptions5, 1, "an empty filter selects only framework-agnostic exceptions")

	exceptions6 := []armotypes.PostureExceptionPolicy{
		*mockMITREFW(),
	}
	f.FrameworkNames = []string{"NSA"}
	exceptions7 := f.FilterExceptions(exceptions6)
	assert.Equal(t, 0, len(exceptions7))
}

func TestFilterExceptionsPreservesPolicyTuple(t *testing.T) {
	exception := armotypes.PostureExceptionPolicy{
		PosturePolicies: []armotypes.PosturePolicy{
			{
				FrameworkName: "NSA",
				ControlID:     "C-0034",
				RuleName:      "R1",
			},
			{
				FrameworkName: "MITRE",
				ControlID:     "C-0034",
				RuleName:      "R2",
			},
		},
	}

	f := Filters{
		FrameworkNames: []string{"MITRE"},
	}

	filtered := f.FilterExceptions(
		[]armotypes.PostureExceptionPolicy{exception},
	)

	assert.Len(t, filtered, 1)
	assert.Len(t, filtered[0].PosturePolicies, 1)

	assert.Equal(t, "MITRE", filtered[0].PosturePolicies[0].FrameworkName)
	assert.Equal(t, "C-0034", filtered[0].PosturePolicies[0].ControlID)
	assert.Equal(t, "R2", filtered[0].PosturePolicies[0].RuleName)
}

func TestFilterExceptionsUsesProcessorFrameworkMatching(t *testing.T) {
	tests := []struct {
		name          string
		policyPattern string
		framework     string
		wantMatch     bool
	}{
		{name: "case insensitive", policyPattern: "mitre", framework: "MITRE", wantMatch: true},
		{name: "anchored regex", policyPattern: "MIT.*", framework: "MITRE", wantMatch: true},
		{name: "anchored regex rejects prefix", policyPattern: "MIT.*", framework: "XMITRE", wantMatch: false},
		{name: "invalid regex still matches exact text", policyPattern: "[invalid", framework: "[INVALID", wantMatch: true},
		{name: "invalid regex mismatch", policyPattern: "[invalid", framework: "MITRE", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exception := armotypes.PostureExceptionPolicy{
				PosturePolicies: []armotypes.PosturePolicy{{FrameworkName: tt.policyPattern}},
			}
			filtered := (&Filters{FrameworkNames: []string{tt.framework}}).FilterExceptions(
				[]armotypes.PostureExceptionPolicy{exception},
			)
			if tt.wantMatch {
				assert.Len(t, filtered, 1)
			} else {
				assert.Empty(t, filtered)
			}
		})
	}
}

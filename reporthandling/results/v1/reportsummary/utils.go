package reportsummary

import (
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
)

func calculateStatus(counters *StatusCounters) apis.ScanningStatus {

	if counters.Failed() != 0 {
		return apis.StatusFailed
	}
	if counters.Skipped() != 0 {
		return apis.StatusSkipped
	}

	return apis.StatusPassed
}

// statusWithControlSubStatuses keeps the cached summary status for backwards
// compatibility and derives its effective substatus from serialized control
// statuses. This preserves status+substatus views across JSON without adding a
// new summary field.
func statusWithControlSubStatuses(status apis.ScanningStatus, controls ControlSummaries) *helpersv1.Status {
	subStatus := apis.SubStatusUnknown
	for _, control := range controls {
		_, subStatus = apis.CompareStatusAndSubStatus(status, status, subStatus, control.GetStatus().GetSubStatus())
	}

	return helpersv1.NewStatusWithSubStatus(status, subStatus)
}

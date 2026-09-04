package resourcesresults

import (
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
)

// GetID get control ID
func (control *ResourceAssociatedControl) GetID() string {
	return control.ControlID
}

// SetID set control ID
func (control *ResourceAssociatedControl) SetID(id string) {
	control.ControlID = id
}

// GetID get control ID
func (control *ResourceAssociatedControl) GetName() string {
	return control.Name
}

// SetID set control ID
func (control *ResourceAssociatedControl) SetName(name string) {
	control.Name = name
}

// =============================== Status ====================================

// isOldControl checks if a control has no status set - this is for backward compatibility with old reports
func (control *ResourceAssociatedControl) isOldControl() bool {
	return control.Status.InnerStatus == "" && control.Status.InnerInfo == ""
}

// Status get control status
func (control *ResourceAssociatedControl) GetStatus(f *helpersv1.Filters) apis.IStatus {
	if control.isOldControl() {
		return control.rulesStatus(f)
	}

	if f != nil {
		status := control.rulesStatus(f)
		return control.applyActionRequiredStatus(status)
	}

	return &control.Status
}

// GetSubStatus get control sub status
func (control *ResourceAssociatedControl) GetSubStatus() apis.ScanningSubStatus {
	if control.isOldControl() {
		return control.rulesStatus(nil).GetSubStatus()
	}
	return control.Status.SubStatus
}

func (control *ResourceAssociatedControl) rulesStatus(f *helpersv1.Filters) apis.IStatus {
	status := apis.StatusPassed
	subStatus := apis.SubStatusUnknown
	for i := range control.ResourceAssociatedRules {
		ruleStatus := control.ResourceAssociatedRules[i].getStatus(f, control.GetID())
		status, subStatus = apis.CompareStatusAndSubStatus(status, ruleStatus.Status(), subStatus, ruleStatus.GetSubStatus())
	}
	return &apis.StatusInfo{
		InnerStatus: status,
		SubStatus:   subStatus,
		InnerInfo:   apis.SubStatusInfo(subStatus),
	}
}

func (control *ResourceAssociatedControl) applyActionRequiredStatus(status apis.IStatus) apis.IStatus {
	actionRequired := control.effectiveActionRequired()
	if status.Status() == apis.StatusFailed {
		switch actionRequired {
		case apis.SubStatusRequiresReview, apis.SubStatusManualReview:
			return &apis.StatusInfo{
				InnerStatus: apis.StatusSkipped,
				SubStatus:   actionRequired,
				InnerInfo:   apis.SubStatusInfo(actionRequired),
			}
		}
	}

	if actionRequired == apis.SubStatusConfiguration &&
		controlMissingAllConfigurations(control) && status.GetSubStatus() != apis.SubStatusNotEvaluated {
		return &apis.StatusInfo{
			InnerStatus: apis.StatusSkipped,
			SubStatus:   apis.SubStatusConfiguration,
			InnerInfo:   apis.SubStatusInfo(apis.SubStatusConfiguration),
		}
	}

	return status
}

func (control *ResourceAssociatedControl) effectiveActionRequired() apis.ScanningSubStatus {
	if control.actionRequired != apis.SubStatusUnknown {
		return control.actionRequired
	}

	switch control.Status.SubStatus {
	case apis.SubStatusConfiguration, apis.SubStatusManualReview, apis.SubStatusRequiresReview:
		return control.Status.SubStatus
	default:
		return apis.SubStatusUnknown
	}
}

// SetStatus set control status and sub status
/*
	SetStatus set control status and sub status according to the following logic:
	1. Calculate control status with all the resource associated rules:
		1.1 if the status is failed and the control contains attributes of actionRequired: requires/manual review,
			the status is skipped and the sub status is requires/manual review
		1.2 if the control contains attributes of actionRequired: configuration and the configuration is not set,
			the status is skipped and the sub status is configuration
*/
func (control *ResourceAssociatedControl) SetStatus(c reporthandling.Control) {
	// calculate the status with all the resource associated rules
	status := apis.StatusPassed
	subStatus := apis.SubStatusUnknown
	statusInfo := ""
	rulesStatus := control.rulesStatus(nil)
	status = rulesStatus.Status()
	subStatus = rulesStatus.GetSubStatus()
	actionRequiredStr := c.GetActionRequiredAttribute()
	control.actionRequired = apis.ScanningSubStatus(actionRequiredStr)
	if actionRequiredStr == "" {
		control.Status.InnerStatus = status
		control.Status.SubStatus = subStatus
		control.Status.InnerInfo = apis.SubStatusInfo(subStatus)
		return
	}

	// If the control type is requires review, the status is skipped and the sub status is requires review
	actionRequired := apis.ScanningSubStatus(actionRequiredStr)
	if status == apis.StatusFailed && actionRequired == apis.SubStatusRequiresReview {
		status = apis.StatusSkipped
		subStatus = apis.SubStatusRequiresReview
	}

	// If the control type is manual review, the status is skipped and the sub status is manual review
	if status == apis.StatusFailed && actionRequired == apis.SubStatusManualReview {
		status = apis.StatusSkipped
		subStatus = apis.SubStatusManualReview
	}

	// If the control type is configuration and the configuration is not set, the status is skipped and the sub status is configuration.
	// Do not overwrite notEvaluated: a GVR collection gap takes precedence over a missing-config skip.
	if actionRequired == apis.SubStatusConfiguration && controlMissingAllConfigurations(control) && subStatus != apis.SubStatusNotEvaluated {
		status = apis.StatusSkipped
		subStatus = apis.SubStatusConfiguration
	}
	statusInfo = apis.SubStatusInfo(subStatus)

	control.Status.InnerStatus = status
	control.Status.InnerInfo = statusInfo
	control.Status.SubStatus = subStatus

}

// ListRules return list of rules
func (control *ResourceAssociatedControl) ListRules() []ResourceAssociatedRule {
	return control.ResourceAssociatedRules
}

// controlMissingAllConfiguration returns true if all control configurations are missing
func controlMissingAllConfigurations(control *ResourceAssociatedControl) bool {
	for _, rule := range control.ResourceAssociatedRules {
		if len(rule.ControlConfigurations) == 0 {
			return true
		}
		for _, configuration := range rule.ControlConfigurations {
			if len(configuration) != 0 {
				return false
			}
		}
	}
	return true
}

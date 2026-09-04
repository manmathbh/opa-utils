package resourcesresults

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
)

// GetName get rule name
func (rule *ResourceAssociatedRule) GetName() string {
	return rule.Name
}

// SetName set rule name
func (rule *ResourceAssociatedRule) SetName(n string) {
	rule.Name = n
}

// =============================== Status ====================================

// GetStatus get rule status
func (rule *ResourceAssociatedRule) GetStatus(f *helpersv1.Filters) apis.IStatus {
	return rule.getStatus(f, "")
}

func (rule *ResourceAssociatedRule) getStatus(f *helpersv1.Filters, controlID string) apis.IStatus {
	if rule.Status != apis.StatusFailed {
		return rule.statusInfo()
	}

	frameworkNames := []string(nil)
	if f != nil {
		frameworkNames = f.ListFrameworkNames()
	}

	if len(frameworkNames) == 0 {
		return rule.statusWithExceptions(exceptions.FilterExceptionsByFrameworks(rule.Exception, nil, controlID, rule.GetName()))
	}

	status := apis.StatusUnknown
	subStatus := apis.SubStatusUnknown
	seenFrameworks := make(map[string]struct{}, len(frameworkNames))
	for _, frameworkName := range frameworkNames {
		if _, ok := seenFrameworks[frameworkName]; ok {
			continue
		}
		seenFrameworks[frameworkName] = struct{}{}

		frameworkStatus := rule.statusWithExceptions(exceptions.FilterExceptionsByFrameworks(rule.Exception, []string{frameworkName}, controlID, rule.GetName()))
		status, subStatus = apis.CompareStatusAndSubStatus(status, frameworkStatus.Status(), subStatus, frameworkStatus.GetSubStatus())
	}

	return &apis.StatusInfo{
		InnerStatus: status,
		SubStatus:   subStatus,
		InnerInfo:   apis.SubStatusInfo(subStatus),
	}
}

func (rule *ResourceAssociatedRule) statusWithExceptions(matchingExceptions []armotypes.PostureExceptionPolicy) apis.IStatus {
	if len(matchingExceptions) > 0 {
		// An alertOnly exception acknowledges the finding without suppressing it, so
		// the rule keeps failing and still counts against the compliance score. Only
		// a disable action removes the finding from the results.
		if allExceptionsAlertOnly(matchingExceptions) {
			return &apis.StatusInfo{
				InnerStatus: apis.StatusFailed,
				SubStatus:   apis.SubStatusException,
			}
		}
		return &apis.StatusInfo{
			InnerStatus: apis.StatusPassed,
			SubStatus:   apis.SubStatusException,
		}
	}

	return rule.statusInfo()
}

// allExceptionsAlertOnly reports whether every matched exception asked only to
// acknowledge the finding rather than suppress it.
//
// This is deliberately conservative. A policy that is not explicitly alertOnly,
// which includes a disable action and a policy carrying no actions at all, keeps
// the historical suppressing behaviour, so only an exception that opted in to
// alertOnly changes how the finding is reported.
func allExceptionsAlertOnly(exceptions []armotypes.PostureExceptionPolicy) bool {
	if len(exceptions) == 0 {
		return false
	}
	for i := range exceptions {
		if !exceptions[i].IsAlertOnly() {
			return false
		}
	}
	return true
}

func (rule *ResourceAssociatedRule) statusInfo() apis.IStatus {
	return &apis.StatusInfo{
		InnerStatus: rule.Status,
		SubStatus:   rule.SubStatus,
		InnerInfo:   apis.SubStatusInfo(rule.SubStatus),
	}
}

// GetSubStatus get rule sub status
func (rule *ResourceAssociatedRule) GetSubStatus() apis.ScanningSubStatus {
	return rule.SubStatus
}

// SetStatus set rule status and sub status
func (rule *ResourceAssociatedRule) SetStatus(s apis.ScanningStatus, _ *helpersv1.Filters) {
	rule.Status = s
}

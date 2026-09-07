package helpers

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/exceptions"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// Filters fields that might take effect on the resource status. If this objects is empty or nil, the status will be as determined by pre-defined logic
type Filters struct {
	FrameworkNames []string // Framework name may effect the status
}

// ListFrameworkNames list the framework name in filter object. Removes empty names
func (f *Filters) ListFrameworkNames() []string {
	fn := []string{}
	for i := range f.FrameworkNames {
		if f.FrameworkNames[i] != "" {
			fn = append(fn, f.FrameworkNames[i])
		}
	}
	return fn
}

// // FilterPassed fields that might take effect on the resource status. If this objects is empty or nil, the status will be as determined by pre-defined logic
// type FilterPassed struct {
// }

// // FilterFailed fields that might take effect on the resource status. If this objects is empty or nil, the status will be as determined by pre-defined logic
// type FilterFailed struct {
// 	FrameworkName string // Framework name may effect the status
// }

// // FilterExcluded fields that might take effect on the resource status. If this objects is empty or nil, the status will be as determined by pre-defined logic
// type FilterExcluded struct {
// 	FrameworkName string // Framework name may effect the status
// }

// // FilterSkipped fields that might take effect on the resource status. If this objects is empty or nil, the status will be as determined by pre-defined logic
// type FilterSkipped struct {
// 	FrameworkName string // Framework name may effect the status
// }

// FilterExceptions returns exceptions containing only posture policies
// that match the configured framework filters.
func (f *Filters) FilterExceptions(exceptionPolicies []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	return exceptions.FilterExceptionsByFrameworks(exceptionPolicies, f.ListFrameworkNames(), "", "")
}

// ListingFilters filter list based on filters. If nil of empty list, the list will be ignored
type ListingFilters struct {
	FrameworkNames []string              // Framework name may effect the status
	ControlsNames  []string              // Framework name may effect the status
	ControlsIDs    []string              // Framework name may effect the status
	Statuses       []apis.ScanningStatus // Framework name may effect the status
}

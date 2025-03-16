/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resource

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/kubernetes/pkg/apis/resource"
	"k8s.io/kubernetes/pkg/features"
)

// AuthorizedForAdmin checks if the request is authorized to get admin access to devices
// based on namespace label
func AuthorizedForAdmin(ctx context.Context, deviceRequests []resource.DeviceRequest, namespaceName string, nsClient v1.NamespaceInterface, oldDeviceRequests []resource.DeviceRequest) field.ErrorList {
	var allErrs field.ErrorList
	adminRequested := false

	if !utilfeature.DefaultFeatureGate.Enabled(features.DRAAdminAccess) {
		// No need to validate unless feature gate is enabled
		return allErrs
	}

	// no need to check old request since spec is immutable

	for i := range deviceRequests {
		value := deviceRequests[i].AdminAccess
		if value != nil && *value {
			adminRequested = true
			break
		}
	}
	if !adminRequested {
		// No need to validate unless admin access is requested
		return allErrs
	}

	// Retrieve the namespace object from the store
	ns, err := nsClient.Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return append(allErrs, field.Forbidden(field.NewPath(""), "admin access to devices is not allowed when namespace object is not retrievable"))
	}
	if ns.Labels[resource.DRAAdminNamespaceLabelKey] != "true" {
		return append(allErrs, field.Forbidden(field.NewPath(""), fmt.Sprintf("admin access to devices is not allowed in namespace without the `%s: true` label", resource.DRAAdminNamespaceLabelKey)))
	}

	return allErrs
}

// AuthorizedForAdminStatus checks if the request status is authorized to get admin access to devices
// based on namespace label
func AuthorizedForAdminStatus(ctx context.Context, newStatus resource.ResourceClaimStatus, namespaceName string, nsClient v1.NamespaceInterface) field.ErrorList {
	var allErrs field.ErrorList
	adminRequested := false

	if !utilfeature.DefaultFeatureGate.Enabled(features.DRAAdminAccess) {
		// No need to validate unless feature gate is enabled
		return allErrs
	}

	// no need to check old request since status.Allocation is immutable

	if newStatus.Allocation == nil {
		return allErrs
	}
	for i := range newStatus.Allocation.Devices.Results {
		value := newStatus.Allocation.Devices.Results[i].AdminAccess
		if value != nil && *value {
			adminRequested = true
			break
		}
	}
	if !adminRequested {
		// No need to validate unless admin access is requested
		return allErrs
	}

	// Retrieve the namespace object from the store
	ns, err := nsClient.Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return append(allErrs, field.Forbidden(field.NewPath(""), "admin access to devices is not allowed when namespace object is not retrievable"))
	}
	if ns.Labels[resource.DRAAdminNamespaceLabelKey] != "true" {
		return append(allErrs, field.Forbidden(field.NewPath(""), fmt.Sprintf("admin access to devices is not allowed in namespace without the `%s: true` label", resource.DRAAdminNamespaceLabelKey)))
	}

	return allErrs
}

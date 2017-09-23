package activitylogalertsapi

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator 1.0.1.0
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.

import (
	"github.com/Azure/go-autorest/autorest"
)

// ActivityLogAlert is an Azure activity log alert.
type ActivityLogAlert struct {
	Scopes      *[]string                       `json:"scopes,omitempty"`
	Enabled     *bool                           `json:"enabled,omitempty"`
	Condition   *ActivityLogAlertAllOfCondition `json:"condition,omitempty"`
	Actions     *ActivityLogAlertActionList     `json:"actions,omitempty"`
	Description *string                         `json:"description,omitempty"`
}

// ActivityLogAlertActionGroup is a pointer to an Azure Action Group.
type ActivityLogAlertActionGroup struct {
	ActionGroupID     *string             `json:"actionGroupId,omitempty"`
	WebhookProperties *map[string]*string `json:"webhookProperties,omitempty"`
}

// ActivityLogAlertActionList is a list of activity log alert actions.
type ActivityLogAlertActionList struct {
	ActionGroups *[]ActivityLogAlertActionGroup `json:"actionGroups,omitempty"`
}

// ActivityLogAlertAllOfCondition is an Activity Log alert condition that is
// met when all its member conditions are met.
type ActivityLogAlertAllOfCondition struct {
	AllOf *[]ActivityLogAlertLeafCondition `json:"allOf,omitempty"`
}

// ActivityLogAlertLeafCondition is an Activity Log alert condition that is met
// by comparing an activity log field and value.
type ActivityLogAlertLeafCondition struct {
	Field  *string `json:"field,omitempty"`
	Equals *string `json:"equals,omitempty"`
}

// ActivityLogAlertList is a list of activity log alerts.
type ActivityLogAlertList struct {
	autorest.Response `json:"-"`
	Value             *[]ActivityLogAlertResource `json:"value,omitempty"`
	NextLink          *string                     `json:"nextLink,omitempty"`
}

// ActivityLogAlertPatch is an Azure activity log alert for patch operations.
type ActivityLogAlertPatch struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// ActivityLogAlertPatchBody is an activity log alert object for the body of
// patch operations.
type ActivityLogAlertPatchBody struct {
	Tags                   *map[string]*string `json:"tags,omitempty"`
	*ActivityLogAlertPatch `json:"properties,omitempty"`
}

// ActivityLogAlertResource is an activity log alert resource.
type ActivityLogAlertResource struct {
	autorest.Response `json:"-"`
	ID                *string             `json:"id,omitempty"`
	Name              *string             `json:"name,omitempty"`
	Type              *string             `json:"type,omitempty"`
	Location          *string             `json:"location,omitempty"`
	Tags              *map[string]*string `json:"tags,omitempty"`
	*ActivityLogAlert `json:"properties,omitempty"`
}

// ErrorResponse is describes the format of Error response.
type ErrorResponse struct {
	Code    *string `json:"code,omitempty"`
	Message *string `json:"message,omitempty"`
}

// Resource is an azure resource object
type Resource struct {
	ID       *string             `json:"id,omitempty"`
	Name     *string             `json:"name,omitempty"`
	Type     *string             `json:"type,omitempty"`
	Location *string             `json:"location,omitempty"`
	Tags     *map[string]*string `json:"tags,omitempty"`
}

package servicebus

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
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"net/http"
)

// RulesClient is the azure Service Bus client
type RulesClient struct {
	ManagementClient
}

// NewRulesClient creates an instance of the RulesClient client.
func NewRulesClient(subscriptionID string) RulesClient {
	return NewRulesClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewRulesClientWithBaseURI creates an instance of the RulesClient client.
func NewRulesClientWithBaseURI(baseURI string, subscriptionID string) RulesClient {
	return RulesClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// CreateOrUpdate creates a new rule and updates an existing rule
//
// resourceGroupName is name of the Resource group within the Azure
// subscription. namespaceName is the namespace name topicName is the topic
// name. subscriptionName is the subscription name. ruleName is the rule name.
// parameters is parameters supplied to create a rule.
func (client RulesClient) CreateOrUpdate(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string, parameters Rule) (result Rule, err error) {
	if err := validation.Validate([]validation.Validation{
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: namespaceName,
			Constraints: []validation.Constraint{{Target: "namespaceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "namespaceName", Name: validation.MinLength, Rule: 6, Chain: nil}}},
		{TargetValue: topicName,
			Constraints: []validation.Constraint{{Target: "topicName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "topicName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: subscriptionName,
			Constraints: []validation.Constraint{{Target: "subscriptionName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "subscriptionName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: ruleName,
			Constraints: []validation.Constraint{{Target: "ruleName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "ruleName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewErrorWithValidationError(err, "servicebus.RulesClient", "CreateOrUpdate")
	}

	req, err := client.CreateOrUpdatePreparer(resourceGroupName, namespaceName, topicName, subscriptionName, ruleName, parameters)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "CreateOrUpdate", nil, "Failure preparing request")
		return
	}

	resp, err := client.CreateOrUpdateSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "CreateOrUpdate", resp, "Failure sending request")
		return
	}

	result, err = client.CreateOrUpdateResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "CreateOrUpdate", resp, "Failure responding to request")
	}

	return
}

// CreateOrUpdatePreparer prepares the CreateOrUpdate request.
func (client RulesClient) CreateOrUpdatePreparer(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string, parameters Rule) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"namespaceName":     autorest.Encode("path", namespaceName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"ruleName":          autorest.Encode("path", ruleName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"subscriptionName":  autorest.Encode("path", subscriptionName),
		"topicName":         autorest.Encode("path", topicName),
	}

	const APIVersion = "2017-04-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsJSON(),
		autorest.AsPut(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}", pathParameters),
		autorest.WithJSON(parameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// CreateOrUpdateSender sends the CreateOrUpdate request. The method will close the
// http.Response Body if it receives an error.
func (client RulesClient) CreateOrUpdateSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req)
}

// CreateOrUpdateResponder handles the response to the CreateOrUpdate request. The method always
// closes the http.Response Body.
func (client RulesClient) CreateOrUpdateResponder(resp *http.Response) (result Rule, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// Delete deletes an existing rule.
//
// resourceGroupName is name of the Resource group within the Azure
// subscription. namespaceName is the namespace name topicName is the topic
// name. subscriptionName is the subscription name. ruleName is the rule name.
func (client RulesClient) Delete(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string) (result autorest.Response, err error) {
	if err := validation.Validate([]validation.Validation{
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: namespaceName,
			Constraints: []validation.Constraint{{Target: "namespaceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "namespaceName", Name: validation.MinLength, Rule: 6, Chain: nil}}},
		{TargetValue: topicName,
			Constraints: []validation.Constraint{{Target: "topicName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "topicName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: subscriptionName,
			Constraints: []validation.Constraint{{Target: "subscriptionName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "subscriptionName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: ruleName,
			Constraints: []validation.Constraint{{Target: "ruleName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "ruleName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewErrorWithValidationError(err, "servicebus.RulesClient", "Delete")
	}

	req, err := client.DeletePreparer(resourceGroupName, namespaceName, topicName, subscriptionName, ruleName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Delete", nil, "Failure preparing request")
		return
	}

	resp, err := client.DeleteSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Delete", resp, "Failure sending request")
		return
	}

	result, err = client.DeleteResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Delete", resp, "Failure responding to request")
	}

	return
}

// DeletePreparer prepares the Delete request.
func (client RulesClient) DeletePreparer(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"namespaceName":     autorest.Encode("path", namespaceName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"ruleName":          autorest.Encode("path", ruleName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"subscriptionName":  autorest.Encode("path", subscriptionName),
		"topicName":         autorest.Encode("path", topicName),
	}

	const APIVersion = "2017-04-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// DeleteSender sends the Delete request. The method will close the
// http.Response Body if it receives an error.
func (client RulesClient) DeleteSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req)
}

// DeleteResponder handles the response to the Delete request. The method always
// closes the http.Response Body.
func (client RulesClient) DeleteResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusNoContent, http.StatusOK),
		autorest.ByClosing())
	result.Response = resp
	return
}

// Get retrieves the description for the specified rule.
//
// resourceGroupName is name of the Resource group within the Azure
// subscription. namespaceName is the namespace name topicName is the topic
// name. subscriptionName is the subscription name. ruleName is the rule name.
func (client RulesClient) Get(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string) (result Rule, err error) {
	if err := validation.Validate([]validation.Validation{
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: namespaceName,
			Constraints: []validation.Constraint{{Target: "namespaceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "namespaceName", Name: validation.MinLength, Rule: 6, Chain: nil}}},
		{TargetValue: topicName,
			Constraints: []validation.Constraint{{Target: "topicName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "topicName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: subscriptionName,
			Constraints: []validation.Constraint{{Target: "subscriptionName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "subscriptionName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: ruleName,
			Constraints: []validation.Constraint{{Target: "ruleName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "ruleName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewErrorWithValidationError(err, "servicebus.RulesClient", "Get")
	}

	req, err := client.GetPreparer(resourceGroupName, namespaceName, topicName, subscriptionName, ruleName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Get", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Get", resp, "Failure sending request")
		return
	}

	result, err = client.GetResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "Get", resp, "Failure responding to request")
	}

	return
}

// GetPreparer prepares the Get request.
func (client RulesClient) GetPreparer(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, ruleName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"namespaceName":     autorest.Encode("path", namespaceName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"ruleName":          autorest.Encode("path", ruleName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"subscriptionName":  autorest.Encode("path", subscriptionName),
		"topicName":         autorest.Encode("path", topicName),
	}

	const APIVersion = "2017-04-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules/{ruleName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// GetSender sends the Get request. The method will close the
// http.Response Body if it receives an error.
func (client RulesClient) GetSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req)
}

// GetResponder handles the response to the Get request. The method always
// closes the http.Response Body.
func (client RulesClient) GetResponder(resp *http.Response) (result Rule, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListBySubscriptions list all the rules within given topic-subscription
//
// resourceGroupName is name of the Resource group within the Azure
// subscription. namespaceName is the namespace name topicName is the topic
// name. subscriptionName is the subscription name.
func (client RulesClient) ListBySubscriptions(resourceGroupName string, namespaceName string, topicName string, subscriptionName string) (result RuleListResult, err error) {
	if err := validation.Validate([]validation.Validation{
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: namespaceName,
			Constraints: []validation.Constraint{{Target: "namespaceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "namespaceName", Name: validation.MinLength, Rule: 6, Chain: nil}}},
		{TargetValue: topicName,
			Constraints: []validation.Constraint{{Target: "topicName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "topicName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: subscriptionName,
			Constraints: []validation.Constraint{{Target: "subscriptionName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "subscriptionName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewErrorWithValidationError(err, "servicebus.RulesClient", "ListBySubscriptions")
	}

	req, err := client.ListBySubscriptionsPreparer(resourceGroupName, namespaceName, topicName, subscriptionName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListBySubscriptionsSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", resp, "Failure sending request")
		return
	}

	result, err = client.ListBySubscriptionsResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", resp, "Failure responding to request")
	}

	return
}

// ListBySubscriptionsPreparer prepares the ListBySubscriptions request.
func (client RulesClient) ListBySubscriptionsPreparer(resourceGroupName string, namespaceName string, topicName string, subscriptionName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"namespaceName":     autorest.Encode("path", namespaceName),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"subscriptionName":  autorest.Encode("path", subscriptionName),
		"topicName":         autorest.Encode("path", topicName),
	}

	const APIVersion = "2017-04-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceBus/namespaces/{namespaceName}/topics/{topicName}/subscriptions/{subscriptionName}/rules", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare(&http.Request{})
}

// ListBySubscriptionsSender sends the ListBySubscriptions request. The method will close the
// http.Response Body if it receives an error.
func (client RulesClient) ListBySubscriptionsSender(req *http.Request) (*http.Response, error) {
	return autorest.SendWithSender(client, req)
}

// ListBySubscriptionsResponder handles the response to the ListBySubscriptions request. The method always
// closes the http.Response Body.
func (client RulesClient) ListBySubscriptionsResponder(resp *http.Response) (result RuleListResult, err error) {
	err = autorest.Respond(
		resp,
		client.ByInspecting(),
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListBySubscriptionsNextResults retrieves the next set of results, if any.
func (client RulesClient) ListBySubscriptionsNextResults(lastResults RuleListResult) (result RuleListResult, err error) {
	req, err := lastResults.RuleListResultPreparer()
	if err != nil {
		return result, autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}

	resp, err := client.ListBySubscriptionsSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", resp, "Failure sending next results request")
	}

	result, err = client.ListBySubscriptionsResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "servicebus.RulesClient", "ListBySubscriptions", resp, "Failure responding to next results request")
	}

	return
}

// ListBySubscriptionsComplete gets all elements from the list without paging.
func (client RulesClient) ListBySubscriptionsComplete(resourceGroupName string, namespaceName string, topicName string, subscriptionName string, cancel <-chan struct{}) (<-chan Rule, <-chan error) {
	resultChan := make(chan Rule)
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			close(resultChan)
			close(errChan)
		}()
		list, err := client.ListBySubscriptions(resourceGroupName, namespaceName, topicName, subscriptionName)
		if err != nil {
			errChan <- err
			return
		}
		if list.Value != nil {
			for _, item := range *list.Value {
				select {
				case <-cancel:
					return
				case resultChan <- item:
					// Intentionally left blank
				}
			}
		}
		for list.NextLink != nil {
			list, err = client.ListBySubscriptionsNextResults(list)
			if err != nil {
				errChan <- err
				return
			}
			if list.Value != nil {
				for _, item := range *list.Value {
					select {
					case <-cancel:
						return
					case resultChan <- item:
						// Intentionally left blank
					}
				}
			}
		}
	}()
	return resultChan, errChan
}

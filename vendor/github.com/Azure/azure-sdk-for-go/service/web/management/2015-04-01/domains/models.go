package domains

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
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	"net/http"
)

// AzureResourceType enumerates the values for azure resource type.
type AzureResourceType string

const (
	// TrafficManager specifies the traffic manager state for azure resource
	// type.
	TrafficManager AzureResourceType = "TrafficManager"
	// Website specifies the website state for azure resource type.
	Website AzureResourceType = "Website"
)

// CustomHostNameDNSRecordType enumerates the values for custom host name dns
// record type.
type CustomHostNameDNSRecordType string

const (
	// A specifies the a state for custom host name dns record type.
	A CustomHostNameDNSRecordType = "A"
	// CName specifies the c name state for custom host name dns record type.
	CName CustomHostNameDNSRecordType = "CName"
)

// DNSType enumerates the values for dns type.
type DNSType string

const (
	// AzureDNS specifies the azure dns state for dns type.
	AzureDNS DNSType = "AzureDns"
	// DefaultDomainRegistrarDNS specifies the default domain registrar dns
	// state for dns type.
	DefaultDomainRegistrarDNS DNSType = "DefaultDomainRegistrarDns"
)

// DomainType enumerates the values for domain type.
type DomainType string

const (
	// Regular specifies the regular state for domain type.
	Regular DomainType = "Regular"
	// SoftDeleted specifies the soft deleted state for domain type.
	SoftDeleted DomainType = "SoftDeleted"
)

// HostNameType enumerates the values for host name type.
type HostNameType string

const (
	// Managed specifies the managed state for host name type.
	Managed HostNameType = "Managed"
	// Verified specifies the verified state for host name type.
	Verified HostNameType = "Verified"
)

// ProvisioningState enumerates the values for provisioning state.
type ProvisioningState string

const (
	// Canceled specifies the canceled state for provisioning state.
	Canceled ProvisioningState = "Canceled"
	// Deleting specifies the deleting state for provisioning state.
	Deleting ProvisioningState = "Deleting"
	// Failed specifies the failed state for provisioning state.
	Failed ProvisioningState = "Failed"
	// InProgress specifies the in progress state for provisioning state.
	InProgress ProvisioningState = "InProgress"
	// Succeeded specifies the succeeded state for provisioning state.
	Succeeded ProvisioningState = "Succeeded"
)

// Status enumerates the values for status.
type Status string

const (
	// StatusActive specifies the status active state for status.
	StatusActive Status = "Active"
	// StatusAwaiting specifies the status awaiting state for status.
	StatusAwaiting Status = "Awaiting"
	// StatusCancelled specifies the status cancelled state for status.
	StatusCancelled Status = "Cancelled"
	// StatusConfiscated specifies the status confiscated state for status.
	StatusConfiscated Status = "Confiscated"
	// StatusDisabled specifies the status disabled state for status.
	StatusDisabled Status = "Disabled"
	// StatusExcluded specifies the status excluded state for status.
	StatusExcluded Status = "Excluded"
	// StatusExpired specifies the status expired state for status.
	StatusExpired Status = "Expired"
	// StatusFailed specifies the status failed state for status.
	StatusFailed Status = "Failed"
	// StatusHeld specifies the status held state for status.
	StatusHeld Status = "Held"
	// StatusJSONConverterFailed specifies the status json converter failed
	// state for status.
	StatusJSONConverterFailed Status = "JsonConverterFailed"
	// StatusLocked specifies the status locked state for status.
	StatusLocked Status = "Locked"
	// StatusParked specifies the status parked state for status.
	StatusParked Status = "Parked"
	// StatusPending specifies the status pending state for status.
	StatusPending Status = "Pending"
	// StatusReserved specifies the status reserved state for status.
	StatusReserved Status = "Reserved"
	// StatusReverted specifies the status reverted state for status.
	StatusReverted Status = "Reverted"
	// StatusSuspended specifies the status suspended state for status.
	StatusSuspended Status = "Suspended"
	// StatusTransferred specifies the status transferred state for status.
	StatusTransferred Status = "Transferred"
	// StatusUnknown specifies the status unknown state for status.
	StatusUnknown Status = "Unknown"
	// StatusUnlocked specifies the status unlocked state for status.
	StatusUnlocked Status = "Unlocked"
	// StatusUnparked specifies the status unparked state for status.
	StatusUnparked Status = "Unparked"
	// StatusUpdated specifies the status updated state for status.
	StatusUpdated Status = "Updated"
)

// Address is address information for domain registration.
type Address struct {
	Address1   *string `json:"address1,omitempty"`
	Address2   *string `json:"address2,omitempty"`
	City       *string `json:"city,omitempty"`
	Country    *string `json:"country,omitempty"`
	PostalCode *string `json:"postalCode,omitempty"`
	State      *string `json:"state,omitempty"`
}

// AvailablilityCheckResult is domain availablility check result.
type AvailablilityCheckResult struct {
	autorest.Response `json:"-"`
	Name              *string    `json:"name,omitempty"`
	Available         *bool      `json:"available,omitempty"`
	DomainType        DomainType `json:"domainType,omitempty"`
}

// Collection is collection of domains.
type Collection struct {
	autorest.Response `json:"-"`
	Value             *[]Domain `json:"value,omitempty"`
	NextLink          *string   `json:"nextLink,omitempty"`
}

// CollectionPreparer prepares a request to retrieve the next set of results. It returns
// nil if no more results exist.
func (client Collection) CollectionPreparer() (*http.Request, error) {
	if client.NextLink == nil || len(to.String(client.NextLink)) <= 0 {
		return nil, nil
	}
	return autorest.Prepare(&http.Request{},
		autorest.AsJSON(),
		autorest.AsGet(),
		autorest.WithBaseURL(to.String(client.NextLink)))
}

// Contact is contact information for domain registration. If 'Domain Privacy'
// option is not selected then the contact information is made publicly
// available through the Whois
// directories as per ICANN requirements.
type Contact struct {
	AddressMailing *Address `json:"addressMailing,omitempty"`
	Email          *string  `json:"email,omitempty"`
	Fax            *string  `json:"fax,omitempty"`
	JobTitle       *string  `json:"jobTitle,omitempty"`
	NameFirst      *string  `json:"nameFirst,omitempty"`
	NameLast       *string  `json:"nameLast,omitempty"`
	NameMiddle     *string  `json:"nameMiddle,omitempty"`
	Organization   *string  `json:"organization,omitempty"`
	Phone          *string  `json:"phone,omitempty"`
}

// ControlCenterSsoRequest is single sign-on request information for domain
// management.
type ControlCenterSsoRequest struct {
	autorest.Response  `json:"-"`
	URL                *string `json:"url,omitempty"`
	PostParameterKey   *string `json:"postParameterKey,omitempty"`
	PostParameterValue *string `json:"postParameterValue,omitempty"`
}

// Domain is information about a domain.
type Domain struct {
	autorest.Response `json:"-"`
	ID                *string             `json:"id,omitempty"`
	Name              *string             `json:"name,omitempty"`
	Kind              *string             `json:"kind,omitempty"`
	Location          *string             `json:"location,omitempty"`
	Type              *string             `json:"type,omitempty"`
	Tags              *map[string]*string `json:"tags,omitempty"`
	*DomainProperties `json:"properties,omitempty"`
}

// DomainProperties is domain resource specific properties
type DomainProperties struct {
	ContactAdmin                *Contact          `json:"contactAdmin,omitempty"`
	ContactBilling              *Contact          `json:"contactBilling,omitempty"`
	ContactRegistrant           *Contact          `json:"contactRegistrant,omitempty"`
	ContactTech                 *Contact          `json:"contactTech,omitempty"`
	RegistrationStatus          Status            `json:"registrationStatus,omitempty"`
	ProvisioningState           ProvisioningState `json:"provisioningState,omitempty"`
	NameServers                 *[]string         `json:"nameServers,omitempty"`
	Privacy                     *bool             `json:"privacy,omitempty"`
	CreatedTime                 *date.Time        `json:"createdTime,omitempty"`
	ExpirationTime              *date.Time        `json:"expirationTime,omitempty"`
	LastRenewedTime             *date.Time        `json:"lastRenewedTime,omitempty"`
	AutoRenew                   *bool             `json:"autoRenew,omitempty"`
	ReadyForDNSRecordManagement *bool             `json:"readyForDnsRecordManagement,omitempty"`
	ManagedHostNames            *[]HostName       `json:"managedHostNames,omitempty"`
	Consent                     *PurchaseConsent  `json:"consent,omitempty"`
	DomainNotRenewableReasons   *[]string         `json:"domainNotRenewableReasons,omitempty"`
	DNSType                     DNSType           `json:"dnsType,omitempty"`
	DNSZoneID                   *string           `json:"dnsZoneId,omitempty"`
	TargetDNSType               DNSType           `json:"targetDnsType,omitempty"`
	AuthCode                    *string           `json:"authCode,omitempty"`
}

// HostName is details of a hostname derived from a domain.
type HostName struct {
	Name                        *string                     `json:"name,omitempty"`
	SiteNames                   *[]string                   `json:"siteNames,omitempty"`
	AzureResourceName           *string                     `json:"azureResourceName,omitempty"`
	AzureResourceType           AzureResourceType           `json:"azureResourceType,omitempty"`
	CustomHostNameDNSRecordType CustomHostNameDNSRecordType `json:"customHostNameDnsRecordType,omitempty"`
	HostNameType                HostNameType                `json:"hostNameType,omitempty"`
}

// NameIdentifier is identifies an object.
type NameIdentifier struct {
	Name *string `json:"name,omitempty"`
}

// NameIdentifierCollection is collection of domain name identifiers.
type NameIdentifierCollection struct {
	autorest.Response `json:"-"`
	Value             *[]NameIdentifier `json:"value,omitempty"`
	NextLink          *string           `json:"nextLink,omitempty"`
}

// NameIdentifierCollectionPreparer prepares a request to retrieve the next set of results. It returns
// nil if no more results exist.
func (client NameIdentifierCollection) NameIdentifierCollectionPreparer() (*http.Request, error) {
	if client.NextLink == nil || len(to.String(client.NextLink)) <= 0 {
		return nil, nil
	}
	return autorest.Prepare(&http.Request{},
		autorest.AsJSON(),
		autorest.AsGet(),
		autorest.WithBaseURL(to.String(client.NextLink)))
}

// OwnershipIdentifier is domain ownership Identifier.
type OwnershipIdentifier struct {
	autorest.Response              `json:"-"`
	ID                             *string             `json:"id,omitempty"`
	Name                           *string             `json:"name,omitempty"`
	Kind                           *string             `json:"kind,omitempty"`
	Location                       *string             `json:"location,omitempty"`
	Type                           *string             `json:"type,omitempty"`
	Tags                           *map[string]*string `json:"tags,omitempty"`
	*OwnershipIdentifierProperties `json:"properties,omitempty"`
}

// OwnershipIdentifierProperties is domainOwnershipIdentifier resource specific
// properties
type OwnershipIdentifierProperties struct {
	OwnershipID *string `json:"ownershipId,omitempty"`
}

// OwnershipIdentifierCollection is collection of domain ownership identifiers.
type OwnershipIdentifierCollection struct {
	autorest.Response `json:"-"`
	Value             *[]OwnershipIdentifier `json:"value,omitempty"`
	NextLink          *string                `json:"nextLink,omitempty"`
}

// OwnershipIdentifierCollectionPreparer prepares a request to retrieve the next set of results. It returns
// nil if no more results exist.
func (client OwnershipIdentifierCollection) OwnershipIdentifierCollectionPreparer() (*http.Request, error) {
	if client.NextLink == nil || len(to.String(client.NextLink)) <= 0 {
		return nil, nil
	}
	return autorest.Prepare(&http.Request{},
		autorest.AsJSON(),
		autorest.AsGet(),
		autorest.WithBaseURL(to.String(client.NextLink)))
}

// PurchaseConsent is domain purchase consent object, representing acceptance
// of applicable legal agreements.
type PurchaseConsent struct {
	AgreementKeys *[]string  `json:"agreementKeys,omitempty"`
	AgreedBy      *string    `json:"agreedBy,omitempty"`
	AgreedAt      *date.Time `json:"agreedAt,omitempty"`
}

// RecommendationSearchParameters is domain recommendation search parameters.
type RecommendationSearchParameters struct {
	Keywords                 *string `json:"keywords,omitempty"`
	MaxDomainRecommendations *int32  `json:"maxDomainRecommendations,omitempty"`
}

// Resource is azure resource.
type Resource struct {
	ID       *string             `json:"id,omitempty"`
	Name     *string             `json:"name,omitempty"`
	Kind     *string             `json:"kind,omitempty"`
	Location *string             `json:"location,omitempty"`
	Type     *string             `json:"type,omitempty"`
	Tags     *map[string]*string `json:"tags,omitempty"`
}

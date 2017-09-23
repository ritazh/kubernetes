package redis

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
	"github.com/Azure/go-autorest/autorest/to"
	"net/http"
)

// KeyType enumerates the values for key type.
type KeyType string

const (
	// Primary specifies the primary state for key type.
	Primary KeyType = "Primary"
	// Secondary specifies the secondary state for key type.
	Secondary KeyType = "Secondary"
)

// RebootType enumerates the values for reboot type.
type RebootType string

const (
	// AllNodes specifies the all nodes state for reboot type.
	AllNodes RebootType = "AllNodes"
	// PrimaryNode specifies the primary node state for reboot type.
	PrimaryNode RebootType = "PrimaryNode"
	// SecondaryNode specifies the secondary node state for reboot type.
	SecondaryNode RebootType = "SecondaryNode"
)

// SkuFamily enumerates the values for sku family.
type SkuFamily string

const (
	// C specifies the c state for sku family.
	C SkuFamily = "C"
	// P specifies the p state for sku family.
	P SkuFamily = "P"
)

// SkuName enumerates the values for sku name.
type SkuName string

const (
	// Basic specifies the basic state for sku name.
	Basic SkuName = "Basic"
	// Premium specifies the premium state for sku name.
	Premium SkuName = "Premium"
	// Standard specifies the standard state for sku name.
	Standard SkuName = "Standard"
)

// AccessKeys is redis cache access keys.
type AccessKeys struct {
	PrimaryKey   *string `json:"primaryKey,omitempty"`
	SecondaryKey *string `json:"secondaryKey,omitempty"`
}

// CreateOrUpdateParameters is parameters supplied to the CreateOrUpdate Redis
// operation.
type CreateOrUpdateParameters struct {
	ID          *string             `json:"id,omitempty"`
	Name        *string             `json:"name,omitempty"`
	Type        *string             `json:"type,omitempty"`
	Location    *string             `json:"location,omitempty"`
	Tags        *map[string]*string `json:"tags,omitempty"`
	*Properties `json:"properties,omitempty"`
}

// ListKeysResult is the response of Redis list keys operation.
type ListKeysResult struct {
	autorest.Response `json:"-"`
	PrimaryKey        *string `json:"primaryKey,omitempty"`
	SecondaryKey      *string `json:"secondaryKey,omitempty"`
}

// ListResult is the response of list Redis operation.
type ListResult struct {
	autorest.Response `json:"-"`
	Value             *[]ResourceType `json:"value,omitempty"`
	NextLink          *string         `json:"nextLink,omitempty"`
}

// ListResultPreparer prepares a request to retrieve the next set of results. It returns
// nil if no more results exist.
func (client ListResult) ListResultPreparer() (*http.Request, error) {
	if client.NextLink == nil || len(to.String(client.NextLink)) <= 0 {
		return nil, nil
	}
	return autorest.Prepare(&http.Request{},
		autorest.AsJSON(),
		autorest.AsGet(),
		autorest.WithBaseURL(to.String(client.NextLink)))
}

// Properties is parameters supplied to CreateOrUpdate Redis operation.
type Properties struct {
	RedisVersion       *string             `json:"redisVersion,omitempty"`
	Sku                *Sku                `json:"sku,omitempty"`
	RedisConfiguration *map[string]*string `json:"redisConfiguration,omitempty"`
	EnableNonSslPort   *bool               `json:"enableNonSslPort,omitempty"`
	TenantSettings     *map[string]*string `json:"tenantSettings,omitempty"`
	ShardCount         *int32              `json:"shardCount,omitempty"`
	VirtualNetwork     *string             `json:"virtualNetwork,omitempty"`
	Subnet             *string             `json:"subnet,omitempty"`
	StaticIP           *string             `json:"staticIP,omitempty"`
}

// ReadableProperties is parameters describing a Redis instance
type ReadableProperties struct {
	RedisVersion       *string             `json:"redisVersion,omitempty"`
	Sku                *Sku                `json:"sku,omitempty"`
	RedisConfiguration *map[string]*string `json:"redisConfiguration,omitempty"`
	EnableNonSslPort   *bool               `json:"enableNonSslPort,omitempty"`
	TenantSettings     *map[string]*string `json:"tenantSettings,omitempty"`
	ShardCount         *int32              `json:"shardCount,omitempty"`
	VirtualNetwork     *string             `json:"virtualNetwork,omitempty"`
	Subnet             *string             `json:"subnet,omitempty"`
	StaticIP           *string             `json:"staticIP,omitempty"`
	ProvisioningState  *string             `json:"provisioningState,omitempty"`
	HostName           *string             `json:"hostName,omitempty"`
	Port               *int32              `json:"port,omitempty"`
	SslPort            *int32              `json:"sslPort,omitempty"`
}

// ReadablePropertiesWithAccessKey is properties generated only in response to
// CreateOrUpdate Redis operation.
type ReadablePropertiesWithAccessKey struct {
	RedisVersion       *string             `json:"redisVersion,omitempty"`
	Sku                *Sku                `json:"sku,omitempty"`
	RedisConfiguration *map[string]*string `json:"redisConfiguration,omitempty"`
	EnableNonSslPort   *bool               `json:"enableNonSslPort,omitempty"`
	TenantSettings     *map[string]*string `json:"tenantSettings,omitempty"`
	ShardCount         *int32              `json:"shardCount,omitempty"`
	VirtualNetwork     *string             `json:"virtualNetwork,omitempty"`
	Subnet             *string             `json:"subnet,omitempty"`
	StaticIP           *string             `json:"staticIP,omitempty"`
	ProvisioningState  *string             `json:"provisioningState,omitempty"`
	HostName           *string             `json:"hostName,omitempty"`
	Port               *int32              `json:"port,omitempty"`
	SslPort            *int32              `json:"sslPort,omitempty"`
	AccessKeys         *AccessKeys         `json:"accessKeys,omitempty"`
}

// RebootParameters is specifies which Redis node(s) to reboot.
type RebootParameters struct {
	RebootType RebootType `json:"rebootType,omitempty"`
	ShardID    *int32     `json:"shardId,omitempty"`
}

// RegenerateKeyParameters is specifies which Redis access keys to reset.
type RegenerateKeyParameters struct {
	KeyType KeyType `json:"keyType,omitempty"`
}

// Resource is
type Resource struct {
	ID       *string             `json:"id,omitempty"`
	Name     *string             `json:"name,omitempty"`
	Type     *string             `json:"type,omitempty"`
	Location *string             `json:"location,omitempty"`
	Tags     *map[string]*string `json:"tags,omitempty"`
}

// ResourceType is a single Redis item in List or Get Operation.
type ResourceType struct {
	autorest.Response   `json:"-"`
	ID                  *string             `json:"id,omitempty"`
	Name                *string             `json:"name,omitempty"`
	Type                *string             `json:"type,omitempty"`
	Location            *string             `json:"location,omitempty"`
	Tags                *map[string]*string `json:"tags,omitempty"`
	*ReadableProperties `json:"properties,omitempty"`
}

// ResourceWithAccessKey is a Redis item in CreateOrUpdate Operation response.
type ResourceWithAccessKey struct {
	autorest.Response                `json:"-"`
	ID                               *string             `json:"id,omitempty"`
	Name                             *string             `json:"name,omitempty"`
	Type                             *string             `json:"type,omitempty"`
	Location                         *string             `json:"location,omitempty"`
	Tags                             *map[string]*string `json:"tags,omitempty"`
	*ReadablePropertiesWithAccessKey `json:"properties,omitempty"`
}

// Sku is sKU parameters supplied to the create Redis operation.
type Sku struct {
	Name     SkuName   `json:"name,omitempty"`
	Family   SkuFamily `json:"family,omitempty"`
	Capacity *int32    `json:"capacity,omitempty"`
}

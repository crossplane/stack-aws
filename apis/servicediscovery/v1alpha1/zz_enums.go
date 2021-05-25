/*
Copyright 2021 The Crossplane Authors.

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

// Code generated by ack-generate. DO NOT EDIT.

package v1alpha1

type CustomHealthStatus string

const (
	CustomHealthStatus_HEALTHY   CustomHealthStatus = "HEALTHY"
	CustomHealthStatus_UNHEALTHY CustomHealthStatus = "UNHEALTHY"
)

type FilterCondition string

const (
	FilterCondition_EQ      FilterCondition = "EQ"
	FilterCondition_IN      FilterCondition = "IN"
	FilterCondition_BETWEEN FilterCondition = "BETWEEN"
)

type HealthCheckType string

const (
	HealthCheckType_HTTP  HealthCheckType = "HTTP"
	HealthCheckType_HTTPS HealthCheckType = "HTTPS"
	HealthCheckType_TCP   HealthCheckType = "TCP"
)

type HealthStatus string

const (
	HealthStatus_HEALTHY   HealthStatus = "HEALTHY"
	HealthStatus_UNHEALTHY HealthStatus = "UNHEALTHY"
	HealthStatus_UNKNOWN   HealthStatus = "UNKNOWN"
)

type HealthStatusFilter string

const (
	HealthStatusFilter_HEALTHY   HealthStatusFilter = "HEALTHY"
	HealthStatusFilter_UNHEALTHY HealthStatusFilter = "UNHEALTHY"
	HealthStatusFilter_ALL       HealthStatusFilter = "ALL"
)

type NamespaceFilterName string

const (
	NamespaceFilterName_TYPE NamespaceFilterName = "TYPE"
)

type NamespaceType string

const (
	NamespaceType_DNS_PUBLIC  NamespaceType = "DNS_PUBLIC"
	NamespaceType_DNS_PRIVATE NamespaceType = "DNS_PRIVATE"
	NamespaceType_HTTP        NamespaceType = "HTTP"
)

type OperationFilterName string

const (
	OperationFilterName_NAMESPACE_ID OperationFilterName = "NAMESPACE_ID"
	OperationFilterName_SERVICE_ID   OperationFilterName = "SERVICE_ID"
	OperationFilterName_STATUS       OperationFilterName = "STATUS"
	OperationFilterName_TYPE         OperationFilterName = "TYPE"
	OperationFilterName_UPDATE_DATE  OperationFilterName = "UPDATE_DATE"
)

type OperationStatus string

const (
	OperationStatus_SUBMITTED OperationStatus = "SUBMITTED"
	OperationStatus_PENDING   OperationStatus = "PENDING"
	OperationStatus_SUCCESS   OperationStatus = "SUCCESS"
	OperationStatus_FAIL      OperationStatus = "FAIL"
)

type OperationTargetType string

const (
	OperationTargetType_NAMESPACE OperationTargetType = "NAMESPACE"
	OperationTargetType_SERVICE   OperationTargetType = "SERVICE"
	OperationTargetType_INSTANCE  OperationTargetType = "INSTANCE"
)

type OperationType string

const (
	OperationType_CREATE_NAMESPACE    OperationType = "CREATE_NAMESPACE"
	OperationType_DELETE_NAMESPACE    OperationType = "DELETE_NAMESPACE"
	OperationType_UPDATE_SERVICE      OperationType = "UPDATE_SERVICE"
	OperationType_REGISTER_INSTANCE   OperationType = "REGISTER_INSTANCE"
	OperationType_DEREGISTER_INSTANCE OperationType = "DEREGISTER_INSTANCE"
)

type RecordType string

const (
	RecordType_SRV   RecordType = "SRV"
	RecordType_A     RecordType = "A"
	RecordType_AAAA  RecordType = "AAAA"
	RecordType_CNAME RecordType = "CNAME"
)

type RoutingPolicy string

const (
	RoutingPolicy_MULTIVALUE RoutingPolicy = "MULTIVALUE"
	RoutingPolicy_WEIGHTED   RoutingPolicy = "WEIGHTED"
)

type ServiceFilterName string

const (
	ServiceFilterName_NAMESPACE_ID ServiceFilterName = "NAMESPACE_ID"
)

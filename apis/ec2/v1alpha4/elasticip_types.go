/*
Copyright 2020 The Crossplane Authors.

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

package v1alpha4

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1alpha1 "github.com/crossplane/crossplane-runtime/apis/core/v1alpha1"

	ec2v1beta1 "github.com/crossplane/provider-aws/apis/ec2/v1beta1"
)

// ElasticIPParameters define the desired state of an AWS Elastic IP
type ElasticIPParameters struct {
	// [EC2-VPC] The Elastic IP address to recover or an IPv4 address from an address
	// pool.
	// +optional
	// +immutable
	Address *string `json:"address,omitempty"`

	// The ID of a customer-owned address pool. Use this parameter to let Amazon
	// EC2 select an address from the address pool. Alternatively, specify a specific
	// address from the address pool
	// +optional
	// +immutable
	CustomerOwnedIPv4Pool *string `json:"customerOwnedIPv4Pool,omitempty"`

	// Set to vpc to allocate the address for use with instances in a VPC.
	// Default: The address is for use with instances in EC2-Classic.
	// +optional
	// +immutable
	// +kubebuilder:validation:Enum=vpc;standard
	Domain string `json:"domain,omitempty"`

	// The location from which the IP address is advertised. Use this parameter
	// to limit the address to this location.
	//
	// A network border group is a unique set of Availability Zones or Local Zones
	// from where AWS advertises IP addresses and limits the addresses to the group.
	// IP addresses cannot move between network border groups.
	//
	// Use DescribeAvailabilityZones (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAvailabilityZones.html)
	// to view the network border groups.
	//
	// You cannot use a network border group with EC2 Classic. If you attempt this
	// operation on EC2 classic, you will receive an InvalidParameterCombination
	// error. For more information, see Error Codes (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html).
	// +optional
	// +immutable
	NetworkBorderGroup *string `json:"networkBorderGroup,omitempty"`

	// The ID of an address pool that you own. Use this parameter to let Amazon
	// EC2 select an address from the address pool. To specify a specific address
	// from the address pool, use the Address parameter instead.
	// +optional
	// +immutable
	PublicIPv4Pool *string `json:"publicIpv4Pool,omitempty"`

	// Tags represents to current ec2 tags.
	// +optional
	Tags []ec2v1beta1.Tag `json:"tags,omitempty"`
}

// A ElasticIPSpec defines the desired state of a ElasticIP.
type ElasticIPSpec struct {
	runtimev1alpha1.ResourceSpec `json:",inline"`
	ForProvider                  ElasticIPParameters `json:"forProvider"`
}

// ElasticIPObservation keeps the state for the external resource
type ElasticIPObservation struct {
	// The ID representing the allocation of the address for use with EC2-VPC.
	AllocationID string `json:"allocationID,omitempty"`

	// The ID representing the association of the address with an instance in a
	// VPC.
	AssociationID string `json:"associationId,omitempty"`

	// The customer-owned IP address.
	CustomerOwnedIP string `json:"customerOwnedIp,omitempty"`

	// The ID of the customer-owned address pool.
	CustomerOwnedIPv4Pool string `json:"customerOwnedIpv4Pool,omitempty"`

	// Indicates whether this Elastic IP address is for use with instances in EC2-Classic
	// (standard) or instances in a VPC (vpc).
	Domain string `json:"domain"`

	// The ID of the instance that the address is associated with (if any).
	InstanceID string `json:"instanceId,omitempty"`

	// The name of the location from which the IP address is advertised.
	NetworkBorderGroup string `json:"networkBorderGroup,omitempty"`

	// The ID of the network interface.
	NetworkInterfaceID string `json:"networkInterfaceId"`

	// The ID of the AWS account that owns the network interface.
	NetworkInterfaceOwnerID string `json:"networkInterfaceOwnerId,omitempty"`

	// The private IP address associated with the Elastic IP address.
	PrivateIPAddress string `json:"privateIpAddress"`

	// The Elastic IP address.
	PublicIP string `json:"publicIp"`

	// The ID of an address pool.
	PublicIPv4Pool string `json:"publicIpv4Pool,omitempty"`
}

// A ElasticIPStatus represents the observed state of a ElasticIP.
type ElasticIPStatus struct {
	runtimev1alpha1.ResourceStatus `json:",inline"`
	AtProvider                     ElasticIPObservation `json:"atProvider"`
}

// +kubebuilder:object:root=true

// A ElasticIP is a managed resource that represents an AWS VPC Security
// Group.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="ID",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="IP",type="string",JSONPath=".status.atProvider.publicIp"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type ElasticIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ElasticIPSpec   `json:"spec"`
	Status ElasticIPStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ElasticIPList contains a list of ElasticIPs
type ElasticIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ElasticIP `json:"items"`
}

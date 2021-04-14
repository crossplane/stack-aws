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

package vpcpeeringconnection

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/ec2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane/provider-aws/apis/ec2/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeVpcPeeringConnectionsInput returns input for read
// operation.
func GenerateDescribeVpcPeeringConnectionsInput(cr *svcapitypes.VPCPeeringConnection) *svcsdk.DescribeVpcPeeringConnectionsInput {
	res := &svcsdk.DescribeVpcPeeringConnectionsInput{}

	if cr.Spec.ForProvider.DryRun != nil {
		res.SetDryRun(*cr.Spec.ForProvider.DryRun)
	}

	return res
}

// GenerateVPCPeeringConnection returns the current state in the form of *svcapitypes.VPCPeeringConnection.
func GenerateVPCPeeringConnection(resp *svcsdk.DescribeVpcPeeringConnectionsOutput) *svcapitypes.VPCPeeringConnection {
	cr := &svcapitypes.VPCPeeringConnection{}

	found := false
	for _, elem := range resp.VpcPeeringConnections {
		if elem.AccepterVpcInfo != nil {
			f0 := &svcapitypes.VPCPeeringConnectionVPCInfo{}
			if elem.AccepterVpcInfo.CidrBlock != nil {
				f0.CIDRBlock = elem.AccepterVpcInfo.CidrBlock
			}
			if elem.AccepterVpcInfo.CidrBlockSet != nil {
				f0f1 := []*svcapitypes.CIDRBlock{}
				for _, f0f1iter := range elem.AccepterVpcInfo.CidrBlockSet {
					f0f1elem := &svcapitypes.CIDRBlock{}
					if f0f1iter.CidrBlock != nil {
						f0f1elem.CIDRBlock = f0f1iter.CidrBlock
					}
					f0f1 = append(f0f1, f0f1elem)
				}
				f0.CIDRBlockSet = f0f1
			}
			if elem.AccepterVpcInfo.Ipv6CidrBlockSet != nil {
				f0f2 := []*svcapitypes.IPv6CIDRBlock{}
				for _, f0f2iter := range elem.AccepterVpcInfo.Ipv6CidrBlockSet {
					f0f2elem := &svcapitypes.IPv6CIDRBlock{}
					if f0f2iter.Ipv6CidrBlock != nil {
						f0f2elem.IPv6CIDRBlock = f0f2iter.Ipv6CidrBlock
					}
					f0f2 = append(f0f2, f0f2elem)
				}
				f0.IPv6CIDRBlockSet = f0f2
			}
			if elem.AccepterVpcInfo.OwnerId != nil {
				f0.OwnerID = elem.AccepterVpcInfo.OwnerId
			}
			if elem.AccepterVpcInfo.PeeringOptions != nil {
				f0f4 := &svcapitypes.VPCPeeringConnectionOptionsDescription{}
				if elem.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
					f0f4.AllowDNSResolutionFromRemoteVPC = elem.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
				}
				if elem.AccepterVpcInfo.PeeringOptions.AllowEgressFromLocalClassicLinkToRemoteVpc != nil {
					f0f4.AllowEgressFromLocalClassicLinkToRemoteVPC = elem.AccepterVpcInfo.PeeringOptions.AllowEgressFromLocalClassicLinkToRemoteVpc
				}
				if elem.AccepterVpcInfo.PeeringOptions.AllowEgressFromLocalVpcToRemoteClassicLink != nil {
					f0f4.AllowEgressFromLocalVPCToRemoteClassicLink = elem.AccepterVpcInfo.PeeringOptions.AllowEgressFromLocalVpcToRemoteClassicLink
				}
				f0.PeeringOptions = f0f4
			}
			if elem.AccepterVpcInfo.Region != nil {
				f0.Region = elem.AccepterVpcInfo.Region
			}
			if elem.AccepterVpcInfo.VpcId != nil {
				f0.VPCID = elem.AccepterVpcInfo.VpcId
			}
			cr.Status.AtProvider.AccepterVPCInfo = f0
		}
		if elem.ExpirationTime != nil {
			cr.Status.AtProvider.ExpirationTime = &metav1.Time{*elem.ExpirationTime}
		}
		if elem.RequesterVpcInfo != nil {
			f2 := &svcapitypes.VPCPeeringConnectionVPCInfo{}
			if elem.RequesterVpcInfo.CidrBlock != nil {
				f2.CIDRBlock = elem.RequesterVpcInfo.CidrBlock
			}
			if elem.RequesterVpcInfo.CidrBlockSet != nil {
				f2f1 := []*svcapitypes.CIDRBlock{}
				for _, f2f1iter := range elem.RequesterVpcInfo.CidrBlockSet {
					f2f1elem := &svcapitypes.CIDRBlock{}
					if f2f1iter.CidrBlock != nil {
						f2f1elem.CIDRBlock = f2f1iter.CidrBlock
					}
					f2f1 = append(f2f1, f2f1elem)
				}
				f2.CIDRBlockSet = f2f1
			}
			if elem.RequesterVpcInfo.Ipv6CidrBlockSet != nil {
				f2f2 := []*svcapitypes.IPv6CIDRBlock{}
				for _, f2f2iter := range elem.RequesterVpcInfo.Ipv6CidrBlockSet {
					f2f2elem := &svcapitypes.IPv6CIDRBlock{}
					if f2f2iter.Ipv6CidrBlock != nil {
						f2f2elem.IPv6CIDRBlock = f2f2iter.Ipv6CidrBlock
					}
					f2f2 = append(f2f2, f2f2elem)
				}
				f2.IPv6CIDRBlockSet = f2f2
			}
			if elem.RequesterVpcInfo.OwnerId != nil {
				f2.OwnerID = elem.RequesterVpcInfo.OwnerId
			}
			if elem.RequesterVpcInfo.PeeringOptions != nil {
				f2f4 := &svcapitypes.VPCPeeringConnectionOptionsDescription{}
				if elem.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
					f2f4.AllowDNSResolutionFromRemoteVPC = elem.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
				}
				if elem.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalClassicLinkToRemoteVpc != nil {
					f2f4.AllowEgressFromLocalClassicLinkToRemoteVPC = elem.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalClassicLinkToRemoteVpc
				}
				if elem.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalVpcToRemoteClassicLink != nil {
					f2f4.AllowEgressFromLocalVPCToRemoteClassicLink = elem.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalVpcToRemoteClassicLink
				}
				f2.PeeringOptions = f2f4
			}
			if elem.RequesterVpcInfo.Region != nil {
				f2.Region = elem.RequesterVpcInfo.Region
			}
			if elem.RequesterVpcInfo.VpcId != nil {
				f2.VPCID = elem.RequesterVpcInfo.VpcId
			}
			cr.Status.AtProvider.RequesterVPCInfo = f2
		}
		if elem.Status != nil {
			f3 := &svcapitypes.VPCPeeringConnectionStateReason{}
			if elem.Status.Code != nil {
				f3.Code = elem.Status.Code
			}
			if elem.Status.Message != nil {
				f3.Message = elem.Status.Message
			}
			cr.Status.AtProvider.Status = f3
		}
		if elem.Tags != nil {
			f4 := []*svcapitypes.Tag{}
			for _, f4iter := range elem.Tags {
				f4elem := &svcapitypes.Tag{}
				if f4iter.Key != nil {
					f4elem.Key = f4iter.Key
				}
				if f4iter.Value != nil {
					f4elem.Value = f4iter.Value
				}
				f4 = append(f4, f4elem)
			}
			cr.Status.AtProvider.Tags = f4
		}
		if elem.VpcPeeringConnectionId != nil {
			cr.Status.AtProvider.VPCPeeringConnectionID = elem.VpcPeeringConnectionId
		}
		found = true
		break
	}
	if !found {
		return cr
	}

	return cr
}

// GenerateCreateVpcPeeringConnectionInput returns a create input.
func GenerateCreateVpcPeeringConnectionInput(cr *svcapitypes.VPCPeeringConnection) *svcsdk.CreateVpcPeeringConnectionInput {
	res := &svcsdk.CreateVpcPeeringConnectionInput{}

	if cr.Spec.ForProvider.DryRun != nil {
		res.SetDryRun(*cr.Spec.ForProvider.DryRun)
	}
	if cr.Spec.ForProvider.PeerOwnerID != nil {
		res.SetPeerOwnerId(*cr.Spec.ForProvider.PeerOwnerID)
	}
	if cr.Spec.ForProvider.PeerRegion != nil {
		res.SetPeerRegion(*cr.Spec.ForProvider.PeerRegion)
	}
	if cr.Spec.ForProvider.PeerVPCID != nil {
		res.SetPeerVpcId(*cr.Spec.ForProvider.PeerVPCID)
	}
	if cr.Spec.ForProvider.TagSpecifications != nil {
		f4 := []*svcsdk.TagSpecification{}
		for _, f4iter := range cr.Spec.ForProvider.TagSpecifications {
			f4elem := &svcsdk.TagSpecification{}
			if f4iter.ResourceType != nil {
				f4elem.SetResourceType(*f4iter.ResourceType)
			}
			if f4iter.Tags != nil {
				f4elemf1 := []*svcsdk.Tag{}
				for _, f4elemf1iter := range f4iter.Tags {
					f4elemf1elem := &svcsdk.Tag{}
					if f4elemf1iter.Key != nil {
						f4elemf1elem.SetKey(*f4elemf1iter.Key)
					}
					if f4elemf1iter.Value != nil {
						f4elemf1elem.SetValue(*f4elemf1iter.Value)
					}
					f4elemf1 = append(f4elemf1, f4elemf1elem)
				}
				f4elem.SetTags(f4elemf1)
			}
			f4 = append(f4, f4elem)
		}
		res.SetTagSpecifications(f4)
	}
	if cr.Spec.ForProvider.VPCID != nil {
		res.SetVpcId(*cr.Spec.ForProvider.VPCID)
	}

	return res
}

// GenerateDeleteVpcPeeringConnectionInput returns a deletion input.
func GenerateDeleteVpcPeeringConnectionInput(cr *svcapitypes.VPCPeeringConnection) *svcsdk.DeleteVpcPeeringConnectionInput {
	res := &svcsdk.DeleteVpcPeeringConnectionInput{}

	if cr.Spec.ForProvider.DryRun != nil {
		res.SetDryRun(*cr.Spec.ForProvider.DryRun)
	}
	if cr.Status.AtProvider.VPCPeeringConnectionID != nil {
		res.SetVpcPeeringConnectionId(*cr.Status.AtProvider.VPCPeeringConnectionID)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "UNKNOWN"
}

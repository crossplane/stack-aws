// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CIDRBlock) DeepCopyInto(out *CIDRBlock) {
	*out = *in
	if in.CIDRBlock != nil {
		in, out := &in.CIDRBlock, &out.CIDRBlock
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CIDRBlock.
func (in *CIDRBlock) DeepCopy() *CIDRBlock {
	if in == nil {
		return nil
	}
	out := new(CIDRBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomVPCPeeringConnectionParameters) DeepCopyInto(out *CustomVPCPeeringConnectionParameters) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomVPCPeeringConnectionParameters.
func (in *CustomVPCPeeringConnectionParameters) DeepCopy() *CustomVPCPeeringConnectionParameters {
	if in == nil {
		return nil
	}
	out := new(CustomVPCPeeringConnectionParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPv6CIDRBlock) DeepCopyInto(out *IPv6CIDRBlock) {
	*out = *in
	if in.IPv6CIDRBlock != nil {
		in, out := &in.IPv6CIDRBlock, &out.IPv6CIDRBlock
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPv6CIDRBlock.
func (in *IPv6CIDRBlock) DeepCopy() *IPv6CIDRBlock {
	if in == nil {
		return nil
	}
	out := new(IPv6CIDRBlock)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Tag) DeepCopyInto(out *Tag) {
	*out = *in
	if in.Key != nil {
		in, out := &in.Key, &out.Key
		*out = new(string)
		**out = **in
	}
	if in.Value != nil {
		in, out := &in.Value, &out.Value
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Tag.
func (in *Tag) DeepCopy() *Tag {
	if in == nil {
		return nil
	}
	out := new(Tag)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TagSpecification) DeepCopyInto(out *TagSpecification) {
	*out = *in
	if in.ResourceType != nil {
		in, out := &in.ResourceType, &out.ResourceType
		*out = new(string)
		**out = **in
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make([]*Tag, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Tag)
				(*in).DeepCopyInto(*out)
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TagSpecification.
func (in *TagSpecification) DeepCopy() *TagSpecification {
	if in == nil {
		return nil
	}
	out := new(TagSpecification)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnection) DeepCopyInto(out *VPCPeeringConnection) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnection.
func (in *VPCPeeringConnection) DeepCopy() *VPCPeeringConnection {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnection)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *VPCPeeringConnection) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionList) DeepCopyInto(out *VPCPeeringConnectionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]VPCPeeringConnection, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionList.
func (in *VPCPeeringConnectionList) DeepCopy() *VPCPeeringConnectionList {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *VPCPeeringConnectionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionObservation) DeepCopyInto(out *VPCPeeringConnectionObservation) {
	*out = *in
	if in.AccepterVPCInfo != nil {
		in, out := &in.AccepterVPCInfo, &out.AccepterVPCInfo
		*out = new(VPCPeeringConnectionVPCInfo)
		(*in).DeepCopyInto(*out)
	}
	if in.ExpirationTime != nil {
		in, out := &in.ExpirationTime, &out.ExpirationTime
		*out = (*in).DeepCopy()
	}
	if in.RequesterVPCInfo != nil {
		in, out := &in.RequesterVPCInfo, &out.RequesterVPCInfo
		*out = new(VPCPeeringConnectionVPCInfo)
		(*in).DeepCopyInto(*out)
	}
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(VPCPeeringConnectionStateReason)
		(*in).DeepCopyInto(*out)
	}
	if in.Tags != nil {
		in, out := &in.Tags, &out.Tags
		*out = make([]*Tag, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(Tag)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.VPCPeeringConnectionID != nil {
		in, out := &in.VPCPeeringConnectionID, &out.VPCPeeringConnectionID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionObservation.
func (in *VPCPeeringConnectionObservation) DeepCopy() *VPCPeeringConnectionObservation {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionOptionsDescription) DeepCopyInto(out *VPCPeeringConnectionOptionsDescription) {
	*out = *in
	if in.AllowDNSResolutionFromRemoteVPC != nil {
		in, out := &in.AllowDNSResolutionFromRemoteVPC, &out.AllowDNSResolutionFromRemoteVPC
		*out = new(bool)
		**out = **in
	}
	if in.AllowEgressFromLocalClassicLinkToRemoteVPC != nil {
		in, out := &in.AllowEgressFromLocalClassicLinkToRemoteVPC, &out.AllowEgressFromLocalClassicLinkToRemoteVPC
		*out = new(bool)
		**out = **in
	}
	if in.AllowEgressFromLocalVPCToRemoteClassicLink != nil {
		in, out := &in.AllowEgressFromLocalVPCToRemoteClassicLink, &out.AllowEgressFromLocalVPCToRemoteClassicLink
		*out = new(bool)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionOptionsDescription.
func (in *VPCPeeringConnectionOptionsDescription) DeepCopy() *VPCPeeringConnectionOptionsDescription {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionOptionsDescription)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionParameters) DeepCopyInto(out *VPCPeeringConnectionParameters) {
	*out = *in
	if in.PeerOwnerID != nil {
		in, out := &in.PeerOwnerID, &out.PeerOwnerID
		*out = new(string)
		**out = **in
	}
	if in.PeerRegion != nil {
		in, out := &in.PeerRegion, &out.PeerRegion
		*out = new(string)
		**out = **in
	}
	if in.PeerVPCID != nil {
		in, out := &in.PeerVPCID, &out.PeerVPCID
		*out = new(string)
		**out = **in
	}
	if in.TagSpecifications != nil {
		in, out := &in.TagSpecifications, &out.TagSpecifications
		*out = make([]*TagSpecification, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(TagSpecification)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.VPCID != nil {
		in, out := &in.VPCID, &out.VPCID
		*out = new(string)
		**out = **in
	}
	out.CustomVPCPeeringConnectionParameters = in.CustomVPCPeeringConnectionParameters
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionParameters.
func (in *VPCPeeringConnectionParameters) DeepCopy() *VPCPeeringConnectionParameters {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionSpec) DeepCopyInto(out *VPCPeeringConnectionSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionSpec.
func (in *VPCPeeringConnectionSpec) DeepCopy() *VPCPeeringConnectionSpec {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionStateReason) DeepCopyInto(out *VPCPeeringConnectionStateReason) {
	*out = *in
	if in.Code != nil {
		in, out := &in.Code, &out.Code
		*out = new(string)
		**out = **in
	}
	if in.Message != nil {
		in, out := &in.Message, &out.Message
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionStateReason.
func (in *VPCPeeringConnectionStateReason) DeepCopy() *VPCPeeringConnectionStateReason {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionStateReason)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionStatus) DeepCopyInto(out *VPCPeeringConnectionStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionStatus.
func (in *VPCPeeringConnectionStatus) DeepCopy() *VPCPeeringConnectionStatus {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VPCPeeringConnectionVPCInfo) DeepCopyInto(out *VPCPeeringConnectionVPCInfo) {
	*out = *in
	if in.CIDRBlock != nil {
		in, out := &in.CIDRBlock, &out.CIDRBlock
		*out = new(string)
		**out = **in
	}
	if in.CIDRBlockSet != nil {
		in, out := &in.CIDRBlockSet, &out.CIDRBlockSet
		*out = make([]*CIDRBlock, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(CIDRBlock)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.IPv6CIDRBlockSet != nil {
		in, out := &in.IPv6CIDRBlockSet, &out.IPv6CIDRBlockSet
		*out = make([]*IPv6CIDRBlock, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IPv6CIDRBlock)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	if in.OwnerID != nil {
		in, out := &in.OwnerID, &out.OwnerID
		*out = new(string)
		**out = **in
	}
	if in.PeeringOptions != nil {
		in, out := &in.PeeringOptions, &out.PeeringOptions
		*out = new(VPCPeeringConnectionOptionsDescription)
		(*in).DeepCopyInto(*out)
	}
	if in.Region != nil {
		in, out := &in.Region, &out.Region
		*out = new(string)
		**out = **in
	}
	if in.VPCID != nil {
		in, out := &in.VPCID, &out.VPCID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VPCPeeringConnectionVPCInfo.
func (in *VPCPeeringConnectionVPCInfo) DeepCopy() *VPCPeeringConnectionVPCInfo {
	if in == nil {
		return nil
	}
	out := new(VPCPeeringConnectionVPCInfo)
	in.DeepCopyInto(out)
	return out
}

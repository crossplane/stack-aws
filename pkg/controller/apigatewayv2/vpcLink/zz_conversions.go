/*
Copyright 2019 The Crossplane Authors.

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

package vpcLink

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/apigatewayv2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	svcapitypes "github.com/crossplane/provider-aws/apis/apigatewayv2/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.
// TODO(muvaf): We can generate one-time boilerplate for these hooks but currently
// ACK doesn't support not generating if file exists.
// GenerateGetVpcLinksInput returns input for read
// operation.
func GenerateGetVpcLinksInput(cr *svcapitypes.VPCLink) *svcsdk.GetVpcLinksInput {
	res := preGenerateGetVpcLinksInput(cr, &svcsdk.GetVpcLinksInput{})

	return postGenerateGetVpcLinksInput(cr, res)
}

// GenerateVPCLink returns the current state in the form of *svcapitypes.VPCLink.
func GenerateVPCLink(resp *svcsdk.GetVpcLinksOutput) *svcapitypes.VPCLink {
	cr := &svcapitypes.VPCLink{}

	found := false
	for _, elem := range resp.Items {
		if elem.CreatedDate != nil {
			cr.Status.AtProvider.CreatedDate = &metav1.Time{*elem.CreatedDate}
		}
		if elem.Name != nil {
			cr.Spec.ForProvider.Name = elem.Name
		}
		if elem.SecurityGroupIds != nil {
			f2 := []*string{}
			for _, f2iter := range elem.SecurityGroupIds {
				var f2elem string
				f2elem = *f2iter
				f2 = append(f2, &f2elem)
			}
			cr.Spec.ForProvider.SecurityGroupIDs = f2
		}
		if elem.SubnetIds != nil {
			f3 := []*string{}
			for _, f3iter := range elem.SubnetIds {
				var f3elem string
				f3elem = *f3iter
				f3 = append(f3, &f3elem)
			}
			cr.Spec.ForProvider.SubnetIDs = f3
		}
		if elem.Tags != nil {
			f4 := map[string]*string{}
			for f4key, f4valiter := range elem.Tags {
				var f4val string
				f4val = *f4valiter
				f4[f4key] = &f4val
			}
			cr.Spec.ForProvider.Tags = f4
		}
		if elem.VpcLinkId != nil {
			cr.Status.AtProvider.VPCLinkID = elem.VpcLinkId
		}
		if elem.VpcLinkStatus != nil {
			cr.Status.AtProvider.VPCLinkStatus = elem.VpcLinkStatus
		}
		if elem.VpcLinkStatusMessage != nil {
			cr.Status.AtProvider.VPCLinkStatusMessage = elem.VpcLinkStatusMessage
		}
		if elem.VpcLinkVersion != nil {
			cr.Status.AtProvider.VPCLinkVersion = elem.VpcLinkVersion
		}
		found = true
		break
	}
	if !found {
		return cr
	}

	return cr
}

// GenerateCreateVpcLinkInput returns a create input.
func GenerateCreateVpcLinkInput(cr *svcapitypes.VPCLink) *svcsdk.CreateVpcLinkInput {
	res := preGenerateCreateVpcLinkInput(cr, &svcsdk.CreateVpcLinkInput{})

	if cr.Spec.ForProvider.Name != nil {
		res.SetName(*cr.Spec.ForProvider.Name)
	}
	if cr.Spec.ForProvider.SecurityGroupIDs != nil {
		f1 := []*string{}
		for _, f1iter := range cr.Spec.ForProvider.SecurityGroupIDs {
			var f1elem string
			f1elem = *f1iter
			f1 = append(f1, &f1elem)
		}
		res.SetSecurityGroupIds(f1)
	}
	if cr.Spec.ForProvider.SubnetIDs != nil {
		f2 := []*string{}
		for _, f2iter := range cr.Spec.ForProvider.SubnetIDs {
			var f2elem string
			f2elem = *f2iter
			f2 = append(f2, &f2elem)
		}
		res.SetSubnetIds(f2)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f3 := map[string]*string{}
		for f3key, f3valiter := range cr.Spec.ForProvider.Tags {
			var f3val string
			f3val = *f3valiter
			f3[f3key] = &f3val
		}
		res.SetTags(f3)
	}

	return postGenerateCreateVpcLinkInput(cr, res)
}

// GenerateDeleteVpcLinkInput returns a deletion input.
func GenerateDeleteVpcLinkInput(cr *svcapitypes.VPCLink) *svcsdk.DeleteVpcLinkInput {
	res := preGenerateDeleteVpcLinkInput(cr, &svcsdk.DeleteVpcLinkInput{})

	if cr.Status.AtProvider.VPCLinkID != nil {
		res.SetVpcLinkId(*cr.Status.AtProvider.VPCLinkID)
	}

	return postGenerateDeleteVpcLinkInput(cr, res)
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "NotFoundException"
}
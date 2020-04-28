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

package v1beta1

import (
	"context"

	"github.com/crossplane/crossplane-runtime/pkg/reference"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"

	aws "github.com/crossplane/provider-aws/pkg/clients"
)

// SecurityGroupName returns the spec.groupName of a SecurityGroup.
func SecurityGroupName() reference.ExtractValueFn {
	return func(mg resource.Managed) string {
		sg, ok := mg.(*SecurityGroup)
		if !ok {
			return ""
		}
		return sg.Spec.ForProvider.GroupName
	}
}

// ResolveReferences of this InternetGateway
func (mg *InternetGateway) ResolveReferences(ctx context.Context, c client.Reader) error {
	r := reference.NewAPIResolver(c, mg)

	// Resolve spec.vpcID
	rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
		CurrentValue: aws.StringValue(mg.Spec.ForProvider.VPCID),
		Reference:    mg.Spec.ForProvider.VPCIDRef,
		Selector:     mg.Spec.ForProvider.VPCIDSelector,
		To:           reference.To{Managed: &VPC{}, List: &VPCList{}},
		Extract:      reference.ExternalName(),
	})
	if err != nil {
		return err
	}
	mg.Spec.ForProvider.VPCID = aws.String(rsp.ResolvedValue)
	mg.Spec.ForProvider.VPCIDRef = rsp.ResolvedReference

	return nil
}

// ResolveReferences of this RouteTable
func (mg *RouteTable) ResolveReferences(ctx context.Context, c client.Reader) error {
	r := reference.NewAPIResolver(c, mg)

	// Resolve spec.vpcID
	rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
		CurrentValue: aws.StringValue(mg.Spec.ForProvider.VPCID),
		Reference:    mg.Spec.ForProvider.VPCIDRef,
		Selector:     mg.Spec.ForProvider.VPCIDSelector,
		To:           reference.To{Managed: &VPC{}, List: &VPCList{}},
		Extract:      reference.ExternalName(),
	})
	if err != nil {
		return err
	}
	mg.Spec.ForProvider.VPCID = aws.String(rsp.ResolvedValue)
	mg.Spec.ForProvider.VPCIDRef = rsp.ResolvedReference

	// Resolve spec.routes[].gatewayID
	for i := range mg.Spec.ForProvider.Routes {
		rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
			CurrentValue: mg.Spec.ForProvider.Routes[i].GatewayID,
			Reference:    mg.Spec.ForProvider.Routes[i].GatewayIDRef,
			Selector:     mg.Spec.ForProvider.Routes[i].GatewayIDSelector,
			To:           reference.To{Managed: &InternetGateway{}, List: &InternetGatewayList{}},
			Extract:      reference.ExternalName(),
		})
		if err != nil {
			return err
		}
		mg.Spec.ForProvider.Routes[i].GatewayID = rsp.ResolvedValue
		mg.Spec.ForProvider.Routes[i].GatewayIDRef = rsp.ResolvedReference
	}

	// Resolve spec.associations[].subnetID
	for i := range mg.Spec.ForProvider.Associations {
		rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
			CurrentValue: mg.Spec.ForProvider.Associations[i].SubnetID,
			Reference:    mg.Spec.ForProvider.Associations[i].SubnetIDRef,
			Selector:     mg.Spec.ForProvider.Associations[i].SubnetIDSelector,
			To:           reference.To{Managed: &Subnet{}, List: &SubnetList{}},
			Extract:      reference.ExternalName(),
		})
		if err != nil {
			return err
		}
		mg.Spec.ForProvider.Associations[i].SubnetID = rsp.ResolvedValue
		mg.Spec.ForProvider.Associations[i].SubnetIDRef = rsp.ResolvedReference
	}

	return nil
}

// ResolveReferences of this SecurityGroup
func (mg *SecurityGroup) ResolveReferences(ctx context.Context, c client.Reader) error {
	r := reference.NewAPIResolver(c, mg)

	// Resolve spec.vpcID
	rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
		CurrentValue: reference.FromPtrValue(mg.Spec.ForProvider.VPCID),
		Reference:    mg.Spec.ForProvider.VPCIDRef,
		Selector:     mg.Spec.ForProvider.VPCIDSelector,
		To:           reference.To{Managed: &VPC{}, List: &VPCList{}},
		Extract:      reference.ExternalName(),
	})
	if err != nil {
		return err
	}
	mg.Spec.ForProvider.VPCID = reference.ToPtrValue(rsp.ResolvedValue)
	mg.Spec.ForProvider.VPCIDRef = rsp.ResolvedReference

	return nil
}

// ResolveReferences of this Subnet
func (mg *Subnet) ResolveReferences(ctx context.Context, c client.Reader) error {
	r := reference.NewAPIResolver(c, mg)

	// Resolve spec.vpcID
	rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
		CurrentValue: aws.StringValue(mg.Spec.ForProvider.VPCID),
		Reference:    mg.Spec.ForProvider.VPCIDRef,
		Selector:     mg.Spec.ForProvider.VPCIDSelector,
		To:           reference.To{Managed: &VPC{}, List: &VPCList{}},
		Extract:      reference.ExternalName(),
	})
	if err != nil {
		return err
	}
	mg.Spec.ForProvider.VPCID = aws.String(rsp.ResolvedValue)
	mg.Spec.ForProvider.VPCIDRef = rsp.ResolvedReference

	return nil
}

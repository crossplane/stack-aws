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

package v1alpha1

import (
	"context"

	ec2 "github.com/crossplane/provider-aws/apis/ec2/v1beta1"

	"github.com/crossplane/crossplane-runtime/pkg/reference"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResolveReferences of this Cluster
func (mg *Cluster) ResolveReferences(ctx context.Context, c client.Reader) error {
	r := reference.NewAPIResolver(c, mg)

	// Resolve spec.forProvider.brokerNodeGroupInfo.clientSubnets
	mrsp, err := r.ResolveMultiple(ctx, reference.MultiResolutionRequest{
		CurrentValues: reference.FromPtrValues(mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.ClientSubnets),
		References:    mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.ClientSubnetRefs,
		Selector:      mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.ClientSubnetSelector,
		To:            reference.To{Managed: &ec2.Subnet{}, List: &ec2.SubnetList{}},
		Extract:       reference.ExternalName(),
	})
	if err != nil {
		return errors.Wrap(err, "spec.forProvider.brokerNodeGroupInfo.clientSubnets")
	}
	mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.ClientSubnets = reference.ToPtrValues(mrsp.ResolvedValues)
	mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.ClientSubnetRefs = mrsp.ResolvedReferences

	// Resolve spec.forProvider.brokerNodeGroupInfo.securityGroups
	mrsp, err = r.ResolveMultiple(ctx, reference.MultiResolutionRequest{
		CurrentValues: reference.FromPtrValues(mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.SecurityGroups),
		References:    mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.SecurityGroupRefs,
		Selector:      mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.SecurityGroupSelector,
		To:            reference.To{Managed: &ec2.SecurityGroup{}, List: &ec2.SecurityGroupList{}},
		Extract:       reference.ExternalName(),
	})
	if err != nil {
		return errors.Wrap(err, "spec.forProvider.brokerNodeGroupInfo.securityGroups")
	}
	mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.SecurityGroups = reference.ToPtrValues(mrsp.ResolvedValues)
	mg.Spec.ForProvider.CustomBrokerNodeGroupInfo.SecurityGroupRefs = mrsp.ResolvedReferences

	// Resolve spec.forProvider.configurationInfo.arn
	rsp, err := r.Resolve(ctx, reference.ResolutionRequest{
		CurrentValue: reference.FromPtrValue(mg.Spec.ForProvider.CustomConfigurationInfo.ARN),
		Reference:    mg.Spec.ForProvider.CustomConfigurationInfo.ARNRef,
		Selector:     mg.Spec.ForProvider.CustomConfigurationInfo.ARNSelector,
		To:           reference.To{Managed: &Configuration{}, List: &ConfigurationList{}},
		Extract:      reference.ExternalName(),
	})
	if err != nil {
		return errors.Wrap(err, "spec.forProvider.configurationInfo.arn")
	}
	mg.Spec.ForProvider.CustomConfigurationInfo.ARN = reference.ToPtrValue(rsp.ResolvedValue)
	mg.Spec.ForProvider.CustomConfigurationInfo.ARNRef = rsp.ResolvedReference

	return nil
}

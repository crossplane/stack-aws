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

package secret

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/secretsmanager"

	svcapitypes "github.com/crossplane/provider-aws/apis/secretsmanager/v1alpha1"
	awsclients "github.com/crossplane/provider-aws/pkg/clients"
)

// GenerateDescribeSecretInput returns input for read
// operation.
func GenerateDescribeSecretInput(cr *svcapitypes.Secret) *svcsdk.DescribeSecretInput {
	res := &svcsdk.DescribeSecretInput{}

	return res
}

// GenerateSecret returns the current state in the form of *svcapitypes.Secret.
func GenerateSecret(resp *svcsdk.DescribeSecretOutput) *svcapitypes.Secret {
	cr := &svcapitypes.Secret{}

	if resp.ARN != nil {
		cr.Status.AtProvider.ARN = resp.ARN
	}

	return cr
}

func lateInitialize(cr *svcapitypes.Secret, resp *svcsdk.DescribeSecretOutput) error {
	cr.Spec.ForProvider.Description = awsclients.LateInitializeStringPtr(cr.Spec.ForProvider.Description, resp.Description)
	cr.Spec.ForProvider.KMSKeyID = awsclients.LateInitializeStringPtr(cr.Spec.ForProvider.KMSKeyID, resp.KmsKeyId)
	if len(resp.Tags) != 0 && len(cr.Spec.ForProvider.Tags) == 0 {
		cr.Spec.ForProvider.Tags = make([]*svcapitypes.Tag, len(resp.Tags))
		for i0 := range resp.Tags {
			if resp.Tags[i0] != nil {
				if cr.Spec.ForProvider.Tags[i0] == nil {
					cr.Spec.ForProvider.Tags[i0] = &svcapitypes.Tag{}
				}
				cr.Spec.ForProvider.Tags[i0].Key = awsclients.LateInitializeStringPtr(cr.Spec.ForProvider.Tags[i0].Key, resp.Tags[i0].Key)
				cr.Spec.ForProvider.Tags[i0].Value = awsclients.LateInitializeStringPtr(cr.Spec.ForProvider.Tags[i0].Value, resp.Tags[i0].Value)
			}
		}
	}
	return nil
}

func basicUpToDateCheck(cr *svcapitypes.Secret, resp *svcsdk.DescribeSecretOutput) bool {
	if awsclients.StringValue(cr.Spec.ForProvider.Description) != awsclients.StringValue(resp.Description) {
		return false
	}
	if awsclients.StringValue(cr.Spec.ForProvider.KMSKeyID) != awsclients.StringValue(resp.KmsKeyId) {
		return false
	}
	return true
}

// GenerateCreateSecretInput returns a create input.
func GenerateCreateSecretInput(cr *svcapitypes.Secret) *svcsdk.CreateSecretInput {
	res := &svcsdk.CreateSecretInput{}

	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.KMSKeyID != nil {
		res.SetKmsKeyId(*cr.Spec.ForProvider.KMSKeyID)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f2 := []*svcsdk.Tag{}
		for _, f2iter := range cr.Spec.ForProvider.Tags {
			f2elem := &svcsdk.Tag{}
			if f2iter.Key != nil {
				f2elem.SetKey(*f2iter.Key)
			}
			if f2iter.Value != nil {
				f2elem.SetValue(*f2iter.Value)
			}
			f2 = append(f2, f2elem)
		}
		res.SetTags(f2)
	}

	return res
}

// GenerateUpdateSecretInput returns an update input.
func GenerateUpdateSecretInput(cr *svcapitypes.Secret) *svcsdk.UpdateSecretInput {
	res := &svcsdk.UpdateSecretInput{}

	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.KMSKeyID != nil {
		res.SetKmsKeyId(*cr.Spec.ForProvider.KMSKeyID)
	}

	return res
}

// GenerateDeleteSecretInput returns a deletion input.
func GenerateDeleteSecretInput(cr *svcapitypes.Secret) *svcsdk.DeleteSecretInput {
	res := &svcsdk.DeleteSecretInput{}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}

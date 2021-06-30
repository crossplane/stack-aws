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

package user

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/transfer"

	svcapitypes "github.com/crossplane/provider-aws/apis/transfer/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeUserInput returns input for read
// operation.
func GenerateDescribeUserInput(cr *svcapitypes.User) *svcsdk.DescribeUserInput {
	res := &svcsdk.DescribeUserInput{}

	if cr.Spec.ForProvider.ServerID != nil {
		res.SetServerId(*cr.Spec.ForProvider.ServerID)
	}
	if cr.Spec.ForProvider.UserName != nil {
		res.SetUserName(*cr.Spec.ForProvider.UserName)
	}

	return res
}

// GenerateUser returns the current state in the form of *svcapitypes.User.
func GenerateUser(resp *svcsdk.DescribeUserOutput) *svcapitypes.User {
	cr := &svcapitypes.User{}

	return cr
}

// GenerateCreateUserInput returns a create input.
func GenerateCreateUserInput(cr *svcapitypes.User) *svcsdk.CreateUserInput {
	res := &svcsdk.CreateUserInput{}

	if cr.Spec.ForProvider.HomeDirectory != nil {
		res.SetHomeDirectory(*cr.Spec.ForProvider.HomeDirectory)
	}
	if cr.Spec.ForProvider.HomeDirectoryMappings != nil {
		f1 := []*svcsdk.HomeDirectoryMapEntry{}
		for _, f1iter := range cr.Spec.ForProvider.HomeDirectoryMappings {
			f1elem := &svcsdk.HomeDirectoryMapEntry{}
			if f1iter.Entry != nil {
				f1elem.SetEntry(*f1iter.Entry)
			}
			if f1iter.Target != nil {
				f1elem.SetTarget(*f1iter.Target)
			}
			f1 = append(f1, f1elem)
		}
		res.SetHomeDirectoryMappings(f1)
	}
	if cr.Spec.ForProvider.HomeDirectoryType != nil {
		res.SetHomeDirectoryType(*cr.Spec.ForProvider.HomeDirectoryType)
	}
	if cr.Spec.ForProvider.Policy != nil {
		res.SetPolicy(*cr.Spec.ForProvider.Policy)
	}
	if cr.Spec.ForProvider.PosixProfile != nil {
		f4 := &svcsdk.PosixProfile{}
		if cr.Spec.ForProvider.PosixProfile.Gid != nil {
			f4.SetGid(*cr.Spec.ForProvider.PosixProfile.Gid)
		}
		if cr.Spec.ForProvider.PosixProfile.SecondaryGids != nil {
			f4f1 := []*int64{}
			for _, f4f1iter := range cr.Spec.ForProvider.PosixProfile.SecondaryGids {
				var f4f1elem int64
				f4f1elem = *f4f1iter
				f4f1 = append(f4f1, &f4f1elem)
			}
			f4.SetSecondaryGids(f4f1)
		}
		if cr.Spec.ForProvider.PosixProfile.Uid != nil {
			f4.SetUid(*cr.Spec.ForProvider.PosixProfile.Uid)
		}
		res.SetPosixProfile(f4)
	}
	if cr.Spec.ForProvider.Role != nil {
		res.SetRole(*cr.Spec.ForProvider.Role)
	}
	if cr.Spec.ForProvider.ServerID != nil {
		res.SetServerId(*cr.Spec.ForProvider.ServerID)
	}
	if cr.Spec.ForProvider.SshPublicKeyBody != nil {
		res.SetSshPublicKeyBody(*cr.Spec.ForProvider.SshPublicKeyBody)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f8 := []*svcsdk.Tag{}
		for _, f8iter := range cr.Spec.ForProvider.Tags {
			f8elem := &svcsdk.Tag{}
			if f8iter.Key != nil {
				f8elem.SetKey(*f8iter.Key)
			}
			if f8iter.Value != nil {
				f8elem.SetValue(*f8iter.Value)
			}
			f8 = append(f8, f8elem)
		}
		res.SetTags(f8)
	}
	if cr.Spec.ForProvider.UserName != nil {
		res.SetUserName(*cr.Spec.ForProvider.UserName)
	}

	return res
}

// GenerateUpdateUserInput returns an update input.
func GenerateUpdateUserInput(cr *svcapitypes.User) *svcsdk.UpdateUserInput {
	res := &svcsdk.UpdateUserInput{}

	if cr.Spec.ForProvider.HomeDirectory != nil {
		res.SetHomeDirectory(*cr.Spec.ForProvider.HomeDirectory)
	}
	if cr.Spec.ForProvider.HomeDirectoryMappings != nil {
		f1 := []*svcsdk.HomeDirectoryMapEntry{}
		for _, f1iter := range cr.Spec.ForProvider.HomeDirectoryMappings {
			f1elem := &svcsdk.HomeDirectoryMapEntry{}
			if f1iter.Entry != nil {
				f1elem.SetEntry(*f1iter.Entry)
			}
			if f1iter.Target != nil {
				f1elem.SetTarget(*f1iter.Target)
			}
			f1 = append(f1, f1elem)
		}
		res.SetHomeDirectoryMappings(f1)
	}
	if cr.Spec.ForProvider.HomeDirectoryType != nil {
		res.SetHomeDirectoryType(*cr.Spec.ForProvider.HomeDirectoryType)
	}
	if cr.Spec.ForProvider.Policy != nil {
		res.SetPolicy(*cr.Spec.ForProvider.Policy)
	}
	if cr.Spec.ForProvider.PosixProfile != nil {
		f4 := &svcsdk.PosixProfile{}
		if cr.Spec.ForProvider.PosixProfile.Gid != nil {
			f4.SetGid(*cr.Spec.ForProvider.PosixProfile.Gid)
		}
		if cr.Spec.ForProvider.PosixProfile.SecondaryGids != nil {
			f4f1 := []*int64{}
			for _, f4f1iter := range cr.Spec.ForProvider.PosixProfile.SecondaryGids {
				var f4f1elem int64
				f4f1elem = *f4f1iter
				f4f1 = append(f4f1, &f4f1elem)
			}
			f4.SetSecondaryGids(f4f1)
		}
		if cr.Spec.ForProvider.PosixProfile.Uid != nil {
			f4.SetUid(*cr.Spec.ForProvider.PosixProfile.Uid)
		}
		res.SetPosixProfile(f4)
	}
	if cr.Spec.ForProvider.Role != nil {
		res.SetRole(*cr.Spec.ForProvider.Role)
	}
	if cr.Spec.ForProvider.ServerID != nil {
		res.SetServerId(*cr.Spec.ForProvider.ServerID)
	}
	if cr.Spec.ForProvider.UserName != nil {
		res.SetUserName(*cr.Spec.ForProvider.UserName)
	}

	return res
}

// GenerateDeleteUserInput returns a deletion input.
func GenerateDeleteUserInput(cr *svcapitypes.User) *svcsdk.DeleteUserInput {
	res := &svcsdk.DeleteUserInput{}

	if cr.Spec.ForProvider.ServerID != nil {
		res.SetServerId(*cr.Spec.ForProvider.ServerID)
	}
	if cr.Spec.ForProvider.UserName != nil {
		res.SetUserName(*cr.Spec.ForProvider.UserName)
	}

	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "ResourceNotFoundException"
}

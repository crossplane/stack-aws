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

package globalcluster

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/rds"

	svcapitypes "github.com/crossplane/provider-aws/apis/rds/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeGlobalClustersInput returns input for read
// operation.
func GenerateDescribeGlobalClustersInput(cr *svcapitypes.GlobalCluster) *svcsdk.DescribeGlobalClustersInput {
	res := &svcsdk.DescribeGlobalClustersInput{}


	return res
}

// GenerateGlobalCluster returns the current state in the form of *svcapitypes.GlobalCluster.
func GenerateGlobalCluster(resp *svcsdk.DescribeGlobalClustersOutput) *svcapitypes.GlobalCluster {
	cr := &svcapitypes.GlobalCluster{}

	found := false
	for _, elem := range resp.GlobalClusters {
		if elem.DatabaseName != nil {
			cr.Spec.ForProvider.DatabaseName = elem.DatabaseName
		} else {
			cr.Spec.ForProvider.DatabaseName = nil
		}
		if elem.DeletionProtection != nil {
			cr.Spec.ForProvider.DeletionProtection = elem.DeletionProtection
		} else {
			cr.Spec.ForProvider.DeletionProtection = nil
		}
		if elem.Engine != nil {
			cr.Spec.ForProvider.Engine = elem.Engine
		} else {
			cr.Spec.ForProvider.Engine = nil
		}
		if elem.EngineVersion != nil {
			cr.Spec.ForProvider.EngineVersion = elem.EngineVersion
		} else {
			cr.Spec.ForProvider.EngineVersion = nil
		}
		if elem.GlobalClusterArn != nil {
			cr.Status.AtProvider.GlobalClusterARN = elem.GlobalClusterArn
		} else {
			cr.Status.AtProvider.GlobalClusterARN = nil
		}
		if elem.GlobalClusterIdentifier != nil {
			cr.Status.AtProvider.GlobalClusterIdentifier = elem.GlobalClusterIdentifier
		} else {
			cr.Status.AtProvider.GlobalClusterIdentifier = nil
		}
		if elem.GlobalClusterMembers != nil {
			f6 := []*svcapitypes.GlobalClusterMember{}
			for _, f6iter := range elem.GlobalClusterMembers {
				f6elem := &svcapitypes.GlobalClusterMember{}
				if f6iter.DBClusterArn != nil {
					f6elem.DBClusterARN = f6iter.DBClusterArn
				}
				if f6iter.GlobalWriteForwardingStatus != nil {
					f6elem.GlobalWriteForwardingStatus = f6iter.GlobalWriteForwardingStatus
				}
				if f6iter.IsWriter != nil {
					f6elem.IsWriter = f6iter.IsWriter
				}
				if f6iter.Readers != nil {
					f6elemf3 := []*string{}
					for _, f6elemf3iter := range f6iter.Readers {
						var f6elemf3elem string
						f6elemf3elem = *f6elemf3iter
						f6elemf3 = append(f6elemf3, &f6elemf3elem)
					}
					f6elem.Readers = f6elemf3
				}
				f6 = append(f6, f6elem)
			}
			cr.Status.AtProvider.GlobalClusterMembers = f6
		} else {
			cr.Status.AtProvider.GlobalClusterMembers = nil
		}
		if elem.GlobalClusterResourceId != nil {
			cr.Status.AtProvider.GlobalClusterResourceID = elem.GlobalClusterResourceId
		} else {
			cr.Status.AtProvider.GlobalClusterResourceID = nil
		}
		if elem.Status != nil {
			cr.Status.AtProvider.Status = elem.Status
		} else {
			cr.Status.AtProvider.Status = nil
		}
		if elem.StorageEncrypted != nil {
			cr.Spec.ForProvider.StorageEncrypted = elem.StorageEncrypted
		} else {
			cr.Spec.ForProvider.StorageEncrypted = nil
		}
		found = true
		break
	}
	if !found {
		return cr
	}

return cr
}

// GenerateCreateGlobalClusterInput returns a create input.
func GenerateCreateGlobalClusterInput(cr *svcapitypes.GlobalCluster) *svcsdk.CreateGlobalClusterInput {
	res := &svcsdk.CreateGlobalClusterInput{}

	if cr.Spec.ForProvider.DatabaseName != nil {
		res.SetDatabaseName(*cr.Spec.ForProvider.DatabaseName)
	}
	if cr.Spec.ForProvider.DeletionProtection != nil {
		res.SetDeletionProtection(*cr.Spec.ForProvider.DeletionProtection)
	}
	if cr.Spec.ForProvider.Engine != nil {
		res.SetEngine(*cr.Spec.ForProvider.Engine)
	}
	if cr.Spec.ForProvider.EngineVersion != nil {
		res.SetEngineVersion(*cr.Spec.ForProvider.EngineVersion)
	}
	if cr.Spec.ForProvider.SourceDBClusterIdentifier != nil {
		res.SetSourceDBClusterIdentifier(*cr.Spec.ForProvider.SourceDBClusterIdentifier)
	}
	if cr.Spec.ForProvider.StorageEncrypted != nil {
		res.SetStorageEncrypted(*cr.Spec.ForProvider.StorageEncrypted)
	}

	return res
}
// GenerateModifyGlobalClusterInput returns an update input.
func GenerateModifyGlobalClusterInput(cr *svcapitypes.GlobalCluster) *svcsdk.ModifyGlobalClusterInput {
	res := &svcsdk.ModifyGlobalClusterInput{}

	if cr.Spec.ForProvider.DeletionProtection != nil {
		res.SetDeletionProtection(*cr.Spec.ForProvider.DeletionProtection)
	}
	if cr.Spec.ForProvider.EngineVersion != nil {
		res.SetEngineVersion(*cr.Spec.ForProvider.EngineVersion)
	}

	return res
}

// GenerateDeleteGlobalClusterInput returns a deletion input.
func GenerateDeleteGlobalClusterInput(cr *svcapitypes.GlobalCluster) *svcsdk.DeleteGlobalClusterInput {
	res := &svcsdk.DeleteGlobalClusterInput{}


	return res
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "GlobalClusterNotFoundFault" 
}
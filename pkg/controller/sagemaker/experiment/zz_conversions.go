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

// Code generated by ack-generate. DO NOT EDIT.

package experiment

import (
	"github.com/aws/aws-sdk-go/aws/awserr"
	svcsdk "github.com/aws/aws-sdk-go/service/sagemaker"

	svcapitypes "github.com/crossplane/provider-aws/apis/sagemaker/v1alpha1"
)

// NOTE(muvaf): We return pointers in case the function needs to start with an
// empty object, hence need to return a new pointer.

// GenerateDescribeExperimentInput returns input for read
// operation.
func GenerateDescribeExperimentInput(cr *svcapitypes.Experiment) *svcsdk.DescribeExperimentInput {
	res := preGenerateDescribeExperimentInput(cr, &svcsdk.DescribeExperimentInput{})

	if cr.Spec.ForProvider.ExperimentName != nil {
		res.SetExperimentName(*cr.Spec.ForProvider.ExperimentName)
	}

	return postGenerateDescribeExperimentInput(cr, res)
}

// GenerateExperiment returns the current state in the form of *svcapitypes.Experiment.
func GenerateExperiment(resp *svcsdk.DescribeExperimentOutput) *svcapitypes.Experiment {
	cr := &svcapitypes.Experiment{}

	if resp.ExperimentArn != nil {
		cr.Status.AtProvider.ExperimentARN = resp.ExperimentArn
	}

	return cr
}

// GenerateCreateExperimentInput returns a create input.
func GenerateCreateExperimentInput(cr *svcapitypes.Experiment) *svcsdk.CreateExperimentInput {
	res := preGenerateCreateExperimentInput(cr, &svcsdk.CreateExperimentInput{})

	if cr.Spec.ForProvider.Description != nil {
		res.SetDescription(*cr.Spec.ForProvider.Description)
	}
	if cr.Spec.ForProvider.DisplayName != nil {
		res.SetDisplayName(*cr.Spec.ForProvider.DisplayName)
	}
	if cr.Spec.ForProvider.ExperimentName != nil {
		res.SetExperimentName(*cr.Spec.ForProvider.ExperimentName)
	}
	if cr.Spec.ForProvider.Tags != nil {
		f3 := []*svcsdk.Tag{}
		for _, f3iter := range cr.Spec.ForProvider.Tags {
			f3elem := &svcsdk.Tag{}
			if f3iter.Key != nil {
				f3elem.SetKey(*f3iter.Key)
			}
			if f3iter.Value != nil {
				f3elem.SetValue(*f3iter.Value)
			}
			f3 = append(f3, f3elem)
		}
		res.SetTags(f3)
	}

	return postGenerateCreateExperimentInput(cr, res)
}

// GenerateDeleteExperimentInput returns a deletion input.
func GenerateDeleteExperimentInput(cr *svcapitypes.Experiment) *svcsdk.DeleteExperimentInput {
	res := preGenerateDeleteExperimentInput(cr, &svcsdk.DeleteExperimentInput{})

	if cr.Spec.ForProvider.ExperimentName != nil {
		res.SetExperimentName(*cr.Spec.ForProvider.ExperimentName)
	}

	return postGenerateDeleteExperimentInput(cr, res)
}

// IsNotFound returns whether the given error is of type NotFound or not.
func IsNotFound(err error) bool {
	awsErr, ok := err.(awserr.Error)
	return ok && awsErr.Code() == "UNKNOWN"
}

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

package v1alpha1

import (
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// HyperParameterTuningJobParameters defines the desired state of HyperParameterTuningJob
type HyperParameterTuningJobParameters struct {
	// Region is which region the HyperParameterTuningJob will be created.
	// +kubebuilder:validation:Required
	Region string `json:"region"`

	// The HyperParameterTuningJobConfig object that describes the tuning job, including
	// the search strategy, the objective metric used to evaluate training jobs,
	// ranges of parameters to search, and resource limits for the tuning job. For
	// more information, see How Hyperparameter Tuning Works (https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-how-it-works.html).
	// +kubebuilder:validation:Required
	HyperParameterTuningJobConfig *HyperParameterTuningJobConfig `json:"hyperParameterTuningJobConfig"`

	// The name of the tuning job. This name is the prefix for the names of all
	// training jobs that this tuning job launches. The name must be unique within
	// the same AWS account and AWS Region. The name must have { } to { } characters.
	// Valid characters are a-z, A-Z, 0-9, and : + = @ _ % - (hyphen). The name
	// is not case sensitive.
	// +kubebuilder:validation:Required
	HyperParameterTuningJobName *string `json:"hyperParameterTuningJobName"`

	// An array of key-value pairs. You can use tags to categorize your AWS resources
	// in different ways, for example, by purpose, owner, or environment. For more
	// information, see AWS Tagging Strategies (https://aws.amazon.com/answers/account-management/aws-tagging-strategies/).
	//
	// Tags that you specify for the tuning job are also added to all training jobs
	// that the tuning job launches.
	Tags []*Tag `json:"tags,omitempty"`

	// The HyperParameterTrainingJobDefinition object that describes the training
	// jobs that this tuning job launches, including static hyperparameters, input
	// data configuration, output data configuration, resource configuration, and
	// stopping condition.
	TrainingJobDefinition *HyperParameterTrainingJobDefinition `json:"trainingJobDefinition,omitempty"`

	// A list of the HyperParameterTrainingJobDefinition objects launched for this
	// tuning job.
	TrainingJobDefinitions []*HyperParameterTrainingJobDefinition `json:"trainingJobDefinitions,omitempty"`

	// Specifies the configuration for starting the hyperparameter tuning job using
	// one or more previous tuning jobs as a starting point. The results of previous
	// tuning jobs are used to inform which combinations of hyperparameters to search
	// over in the new tuning job.
	//
	// All training jobs launched by the new hyperparameter tuning job are evaluated
	// by using the objective metric. If you specify IDENTICAL_DATA_AND_ALGORITHM
	// as the WarmStartType value for the warm start configuration, the training
	// job that performs the best in the new tuning job is compared to the best
	// training jobs from the parent tuning jobs. From these, the training job that
	// performs the best as measured by the objective metric is returned as the
	// overall best training job.
	//
	// All training jobs launched by parent hyperparameter tuning jobs and the new
	// hyperparameter tuning jobs count against the limit of training jobs for the
	// tuning job.
	WarmStartConfig *HyperParameterTuningJobWarmStartConfig `json:"warmStartConfig,omitempty"`
}

// HyperParameterTuningJobSpec defines the desired state of HyperParameterTuningJob
type HyperParameterTuningJobSpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       HyperParameterTuningJobParameters `json:"forProvider"`
}

// HyperParameterTuningJobObservation defines the observed state of HyperParameterTuningJob
type HyperParameterTuningJobObservation struct {
	// The Amazon Resource Name (ARN) of the tuning job. Amazon SageMaker assigns
	// an ARN to a hyperparameter tuning job when you create it.
	HyperParameterTuningJobARN *string `json:"hyperParameterTuningJobARN,omitempty"`
}

// HyperParameterTuningJobStatus defines the observed state of HyperParameterTuningJob.
type HyperParameterTuningJobStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          HyperParameterTuningJobObservation `json:"atProvider"`
}

// +kubebuilder:object:root=true

// HyperParameterTuningJob is the Schema for the HyperParameterTuningJobs API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,aws}
type HyperParameterTuningJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HyperParameterTuningJobSpec   `json:"spec,omitempty"`
	Status            HyperParameterTuningJobStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HyperParameterTuningJobList contains a list of HyperParameterTuningJobs
type HyperParameterTuningJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HyperParameterTuningJob `json:"items"`
}

// Repository type metadata.
var (
	HyperParameterTuningJobKind             = "HyperParameterTuningJob"
	HyperParameterTuningJobGroupKind        = schema.GroupKind{Group: Group, Kind: HyperParameterTuningJobKind}.String()
	HyperParameterTuningJobKindAPIVersion   = HyperParameterTuningJobKind + "." + GroupVersion.String()
	HyperParameterTuningJobGroupVersionKind = GroupVersion.WithKind(HyperParameterTuningJobKind)
)

func init() {
	SchemeBuilder.Register(&HyperParameterTuningJob{}, &HyperParameterTuningJobList{})
}

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

// Code generated by angryjet. DO NOT EDIT.

package v1alpha1

import (
	runtimev1alpha1 "github.com/crossplane/crossplane-runtime/apis/core/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// GetBindingPhase of this CacheCluster.
func (mg *CacheCluster) GetBindingPhase() runtimev1alpha1.BindingPhase {
	return mg.Status.GetBindingPhase()
}

// GetClaimReference of this CacheCluster.
func (mg *CacheCluster) GetClaimReference() *corev1.ObjectReference {
	return mg.Spec.ClaimReference
}

// GetClassReference of this CacheCluster.
func (mg *CacheCluster) GetClassReference() *corev1.ObjectReference {
	return mg.Spec.ClassReference
}

// GetCondition of this CacheCluster.
func (mg *CacheCluster) GetCondition(ct runtimev1alpha1.ConditionType) runtimev1alpha1.Condition {
	return mg.Status.GetCondition(ct)
}

// GetProviderReference of this CacheCluster.
func (mg *CacheCluster) GetProviderReference() runtimev1alpha1.Reference {
	return mg.Spec.ProviderReference
}

// GetReclaimPolicy of this CacheCluster.
func (mg *CacheCluster) GetReclaimPolicy() runtimev1alpha1.ReclaimPolicy {
	return mg.Spec.ReclaimPolicy
}

// GetWriteConnectionSecretToReference of this CacheCluster.
func (mg *CacheCluster) GetWriteConnectionSecretToReference() *runtimev1alpha1.SecretReference {
	return mg.Spec.WriteConnectionSecretToReference
}

// SetBindingPhase of this CacheCluster.
func (mg *CacheCluster) SetBindingPhase(p runtimev1alpha1.BindingPhase) {
	mg.Status.SetBindingPhase(p)
}

// SetClaimReference of this CacheCluster.
func (mg *CacheCluster) SetClaimReference(r *corev1.ObjectReference) {
	mg.Spec.ClaimReference = r
}

// SetClassReference of this CacheCluster.
func (mg *CacheCluster) SetClassReference(r *corev1.ObjectReference) {
	mg.Spec.ClassReference = r
}

// SetConditions of this CacheCluster.
func (mg *CacheCluster) SetConditions(c ...runtimev1alpha1.Condition) {
	mg.Status.SetConditions(c...)
}

// SetProviderReference of this CacheCluster.
func (mg *CacheCluster) SetProviderReference(r runtimev1alpha1.Reference) {
	mg.Spec.ProviderReference = r
}

// SetReclaimPolicy of this CacheCluster.
func (mg *CacheCluster) SetReclaimPolicy(r runtimev1alpha1.ReclaimPolicy) {
	mg.Spec.ReclaimPolicy = r
}

// SetWriteConnectionSecretToReference of this CacheCluster.
func (mg *CacheCluster) SetWriteConnectionSecretToReference(r *runtimev1alpha1.SecretReference) {
	mg.Spec.WriteConnectionSecretToReference = r
}

// GetBindingPhase of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetBindingPhase() runtimev1alpha1.BindingPhase {
	return mg.Status.GetBindingPhase()
}

// GetClaimReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetClaimReference() *corev1.ObjectReference {
	return mg.Spec.ClaimReference
}

// GetClassReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetClassReference() *corev1.ObjectReference {
	return mg.Spec.ClassReference
}

// GetCondition of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetCondition(ct runtimev1alpha1.ConditionType) runtimev1alpha1.Condition {
	return mg.Status.GetCondition(ct)
}

// GetProviderReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetProviderReference() runtimev1alpha1.Reference {
	return mg.Spec.ProviderReference
}

// GetReclaimPolicy of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetReclaimPolicy() runtimev1alpha1.ReclaimPolicy {
	return mg.Spec.ReclaimPolicy
}

// GetWriteConnectionSecretToReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) GetWriteConnectionSecretToReference() *runtimev1alpha1.SecretReference {
	return mg.Spec.WriteConnectionSecretToReference
}

// SetBindingPhase of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetBindingPhase(p runtimev1alpha1.BindingPhase) {
	mg.Status.SetBindingPhase(p)
}

// SetClaimReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetClaimReference(r *corev1.ObjectReference) {
	mg.Spec.ClaimReference = r
}

// SetClassReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetClassReference(r *corev1.ObjectReference) {
	mg.Spec.ClassReference = r
}

// SetConditions of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetConditions(c ...runtimev1alpha1.Condition) {
	mg.Status.SetConditions(c...)
}

// SetProviderReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetProviderReference(r runtimev1alpha1.Reference) {
	mg.Spec.ProviderReference = r
}

// SetReclaimPolicy of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetReclaimPolicy(r runtimev1alpha1.ReclaimPolicy) {
	mg.Spec.ReclaimPolicy = r
}

// SetWriteConnectionSecretToReference of this CacheSubnetGroup.
func (mg *CacheSubnetGroup) SetWriteConnectionSecretToReference(r *runtimev1alpha1.SecretReference) {
	mg.Spec.WriteConnectionSecretToReference = r
}

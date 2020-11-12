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

package apiMapping

import (
	"context"

	svcsdk "github.com/aws/aws-sdk-go/service/apigatewayv2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	svcapitypes "github.com/crossplane/provider-aws/apis/apigatewayv2/v1alpha1"
)

// SetupAPIMapping adds a controller that reconciles APIMapping.
func SetupAPIMapping(mgr ctrl.Manager, l logging.Logger) error {
	name := managed.ControllerName(svcapitypes.APIMappingGroupKind)
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&svcapitypes.APIMapping{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.APIMappingGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient()}),
			managed.WithReferenceResolver(managed.NewAPISimpleReferenceResolver(mgr.GetClient())),
			managed.WithConnectionPublishers(),
			managed.WithLogger(l.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name)))))
}

func (*external) preObserve(context.Context, *svcapitypes.APIMapping) error {
	return nil
}
func (*external) postObserve(_ context.Context, _ *svcapitypes.APIMapping, _ *svcsdk.GetApiMappingsOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	return obs, err
}

func (*external) filterList(_ *svcapitypes.APIMapping, list *svcsdk.GetApiMappingsOutput) *svcsdk.GetApiMappingsOutput {
	return list
}

func (*external) preCreate(context.Context, *svcapitypes.APIMapping) error {
	return nil
}

func (*external) postCreate(_ context.Context, _ *svcapitypes.APIMapping, _ *svcsdk.CreateApiMappingOutput, cre managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	return cre, err
}

func (*external) preUpdate(context.Context, *svcapitypes.APIMapping) error {
	return nil
}

func (*external) postUpdate(_ context.Context, _ *svcapitypes.APIMapping, upd managed.ExternalUpdate, err error) (managed.ExternalUpdate, error) {
	return upd, err
}
func lateInitialize(*svcapitypes.APIMappingParameters, *svcsdk.GetApiMappingsOutput) error {
	return nil
}

func preGenerateGetApiMappingsInput(_ *svcapitypes.APIMapping, obj *svcsdk.GetApiMappingsInput) *svcsdk.GetApiMappingsInput {
	return obj
}

func postGenerateGetApiMappingsInput(_ *svcapitypes.APIMapping, obj *svcsdk.GetApiMappingsInput) *svcsdk.GetApiMappingsInput {
	return obj
}

func preGenerateCreateApiMappingInput(_ *svcapitypes.APIMapping, obj *svcsdk.CreateApiMappingInput) *svcsdk.CreateApiMappingInput {
	return obj
}

func postGenerateCreateApiMappingInput(_ *svcapitypes.APIMapping, obj *svcsdk.CreateApiMappingInput) *svcsdk.CreateApiMappingInput {
	return obj
}

func preGenerateDeleteApiMappingInput(_ *svcapitypes.APIMapping, obj *svcsdk.DeleteApiMappingInput) *svcsdk.DeleteApiMappingInput {
	return obj
}

func postGenerateDeleteApiMappingInput(_ *svcapitypes.APIMapping, obj *svcsdk.DeleteApiMappingInput) *svcsdk.DeleteApiMappingInput {
	return obj
}

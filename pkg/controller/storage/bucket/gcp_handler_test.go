/*
Copyright 2018 The Crossplane Authors.

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

package bucket

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/crossplaneio/crossplane/pkg/apis/core/v1alpha1"
	"github.com/crossplaneio/crossplane/pkg/apis/gcp"
	"github.com/crossplaneio/crossplane/pkg/apis/gcp/storage/v1alpha1"
	storagev1alpha1 "github.com/crossplaneio/crossplane/pkg/apis/storage/v1alpha1"
	"github.com/crossplaneio/crossplane/pkg/meta"
	"github.com/crossplaneio/crossplane/pkg/test"
)

const (
	ns   = "default"
	name = "testBucket"
)

var (
	objectMeta = metav1.ObjectMeta{
		Namespace: ns,
		Name:      name,
	}
)

func init() {
	_ = gcp.AddToScheme(scheme.Scheme)
}

func TestGCSBucketHandler_Find(t *testing.T) {
	nn := types.NamespacedName{Namespace: ns, Name: name}

	type args struct {
		n types.NamespacedName
		c client.Client
	}
	type want struct {
		err error
		res corev1alpha1.Resource
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "ErrorRetrieving",
			args: args{
				n: nn,
				c: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
						return errors.New("test-get-error")
					},
				},
			},
			want: want{
				err: errors.Wrapf(errors.New("test-get-error"),
					"cannot find gcs bucket instance %s", nn),
			},
		},
		{
			name: "Success",
			args: args{
				n: nn,
				c: fake.NewFakeClient(&v1alpha1.Bucket{ObjectMeta: objectMeta}),
			},
			want: want{
				res: corev1alpha1.Resource(&v1alpha1.Bucket{ObjectMeta: objectMeta}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &GCSBucketHandler{}
			got, err := h.Find(tt.args.n, tt.args.c)
			if diff := cmp.Diff(err, tt.want.err, test.EquateErrors()); diff != "" {
				t.Errorf("GCSBucketHandler.Find() error = %v, wantErr %v\n%s", err, tt.want.err, diff)
			}
			if diff := cmp.Diff(got, tt.want.res); diff != "" {
				t.Errorf("GCSBucketHandler.Find() = %v, want %v\n%s", got, tt.want.res, diff)
			}
		})
	}
}

func TestGCSBucketHandler_Provision(t *testing.T) {
	objectMeta := metav1.ObjectMeta{
		Namespace: ns,
		Name:      name,
		UID:       types.UID("test-uid"),
	}
	class := &corev1alpha1.ResourceClass{
		ObjectMeta: objectMeta,
	}
	claim := &storagev1alpha1.Bucket{
		ObjectMeta: objectMeta,
	}
	type args struct {
		class *corev1alpha1.ResourceClass
		claim corev1alpha1.ResourceClaim
		c     client.Client
	}
	type want struct {
		err error
		res corev1alpha1.Resource
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "CreateSuccessful",
			args: args{
				class: class,
				claim: claim,
				c:     test.NewMockClient(),
			},
			want: want{
				res: &v1alpha1.Bucket{
					TypeMeta: metav1.TypeMeta{
						APIVersion: v1alpha1.APIVersion,
						Kind:       v1alpha1.BucketKind,
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns,
						Name:      fmt.Sprintf("gcs-%s", claim.GetUID()),
						OwnerReferences: []metav1.OwnerReference{
							meta.AsOwner(meta.ReferenceTo(claim, storagev1alpha1.BucketGroupVersionKind)),
						},
					},
					Spec: v1alpha1.BucketSpec{
						ClassRef: meta.ReferenceTo(class, corev1alpha1.ResourceClassGroupVersionKind),
						ClaimRef: meta.ReferenceTo(claim, storagev1alpha1.BucketGroupVersionKind),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &GCSBucketHandler{}
			got, err := h.Provision(tt.args.class, tt.args.claim, tt.args.c)
			if diff := cmp.Diff(err, tt.want.err, test.EquateErrors()); diff != "" {
				t.Errorf("GCSBucketHandler.Provision() error = %v, wantErr %v\n%s", err, tt.want.err, diff)
				return
			}
			if diff := cmp.Diff(got, tt.want.res); diff != "" {
				t.Errorf("GCSBucketHandler.Provision() = \n%+v, want \n%+v\n%s", got, tt.want.res, diff)
			}
		})
	}
}

func TestGCSBucketHandler_SetBindStatus(t *testing.T) {
	nn := types.NamespacedName{Namespace: ns, Name: name}
	type args struct {
		n     types.NamespacedName
		c     client.Client
		bound bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "GetErrorNotFoundAndNotBound",
			args: args{
				n:     nn,
				c:     fake.NewFakeClient(),
				bound: false,
			},
		},
		{
			name: "GetErrorNotFoundAndBound",
			args: args{
				n:     nn,
				c:     fake.NewFakeClient(),
				bound: true,
			},
			wantErr: errors.Wrapf(errors.New("buckets.storage.gcp.crossplane.io \"testBucket\" not found"),
				"cannot get bucket default/testBucket"),
		},
		{
			name: "UpdateError",
			args: args{
				n: nn,
				c: &test.MockClient{
					MockGet: func(ctx context.Context, key client.ObjectKey, obj runtime.Object) error {
						return nil
					},
					MockUpdate: func(ctx context.Context, obj runtime.Object) error {
						return errors.New("test-update-error")
					},
				},
				bound: true,
			},
			wantErr: errors.Wrapf(errors.New("test-update-error"),
				"cannot update bucket %s", nn),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &GCSBucketHandler{}
			err := h.SetBindStatus(tt.args.n, tt.args.c, tt.args.bound)
			if diff := cmp.Diff(err, tt.wantErr, test.EquateErrors()); diff != "" {
				t.Errorf("GCSBucketHandler.SetBindStatus() error = %v, wantErr %v\n%s", err, tt.wantErr, diff)
			}
		})
	}
}

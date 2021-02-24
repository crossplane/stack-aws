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

package s3

import (
	"context"
	"fmt"
	"testing"

	"github.com/crossplane/provider-aws/pkg/controller/s3/bucket"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awss3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	"github.com/crossplane/provider-aws/apis/s3/v1beta1"
	awsclient "github.com/crossplane/provider-aws/pkg/clients"
	"github.com/crossplane/provider-aws/pkg/clients/s3"
	"github.com/crossplane/provider-aws/pkg/clients/s3/fake"
	s3Testing "github.com/crossplane/provider-aws/pkg/controller/s3/testing"
)

var (
	// an arbitrary managed resource
	unexpectedItem resource.Managed
	errBoom        = errors.New("boom")
)

type args struct {
	s3   s3.BucketClient
	kube client.Client
	cr   resource.Managed
}

func TestObserve(t *testing.T) {

	type want struct {
		cr     resource.Managed
		result managed.ExternalObservation
		err    error
	}

	cases := map[string]struct {
		args
		want
	}{
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				s3: &fake.MockBucketClient{
					MockHeadBucket: func(ctx context.Context, input *awss3.HeadBucketInput, opts []func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
						return nil, errBoom
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr:  s3Testing.Bucket(),
				err: awsclient.Wrap(errBoom, errHead),
			},
		},
		"ResourceDoesNotExist": {
			args: args{
				s3: &fake.MockBucketClient{
					MockHeadBucket: func(ctx context.Context, input *awss3.HeadBucketInput, opts []func(*awss3.Options)) (*awss3.HeadBucketOutput, error) {
						return nil, &awss3types.NoSuchBucket{}
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(),
			},
		},
		"ValidInputNoLateInitialize": {
			args: args{
				s3: s3Testing.Client(),
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.Available()),
					s3Testing.WithArn(fmt.Sprintf("arn:aws:s3:::%s", s3Testing.BucketName)),
				),
				result: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
					ConnectionDetails: map[string][]byte{
						xpv1.ResourceCredentialsSecretEndpointKey: []byte(s3Testing.BucketName),
						ResourceCredentialsSecretRegionKey:        []byte(s3Testing.Region),
					},
				},
			},
		},
		"ValidInputNoLateInitializeUpdateACLFail": {
			args: args{
				s3: s3Testing.Client(s3Testing.WithPutACL(func(ctx context.Context, input *awss3.PutBucketAclInput, opts []func(*awss3.Options)) (*awss3.PutBucketAclOutput, error) {
					return nil, errBoom
				})),
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithArn(fmt.Sprintf("arn:aws:s3:::%s", s3Testing.BucketName)),
				),
				err: errBoom,
				result: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false,
				},
			},
		},
		"ValidInputLateInitialize": {
			args: args{
				kube: &test.MockClient{
					MockUpdate: test.NewMockUpdateFn(nil),
				},
				s3: s3Testing.Client(
					s3Testing.WithGetRequestPayment(func(ctx context.Context, input *awss3.GetBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.GetBucketRequestPaymentOutput, error) {
						return &awss3.GetBucketRequestPaymentOutput{Payer: awss3types.PayerRequester}, nil
					},
					),
				),
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.Available()),
					s3Testing.WithArn(fmt.Sprintf("arn:aws:s3:::%s", s3Testing.BucketName)),
					s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"}),
				),
				result: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
					ConnectionDetails: map[string][]byte{
						xpv1.ResourceCredentialsSecretEndpointKey: []byte(s3Testing.BucketName),
						ResourceCredentialsSecretRegionKey:        []byte(s3Testing.Region),
					},
				},
			},
		},
		"ValidInputLateInitializeKubeErr": {
			args: args{
				kube: &test.MockClient{
					MockUpdate: test.NewMockUpdateFn(errBoom),
				},
				s3: s3Testing.Client(
					s3Testing.WithGetRequestPayment(func(ctx context.Context, input *awss3.GetBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.GetBucketRequestPaymentOutput, error) {
						return &awss3.GetBucketRequestPaymentOutput{Payer: awss3types.PayerRequester}, nil
					},
					),
				),
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithArn(fmt.Sprintf("arn:aws:s3:::%s", s3Testing.BucketName)),
					s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"}),
				),
				result: managed.ExternalObservation{
					ResourceExists:   false,
					ResourceUpToDate: false,
				},
				err: errors.Wrap(errBoom, errKubeUpdateFailed),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{s3client: tc.s3, subresourceClients: bucket.NewSubresourceClients(tc.s3), kube: tc.kube}
			o, err := e.Observe(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, o); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestCreate(t *testing.T) {

	type want struct {
		cr     resource.Managed
		result managed.ExternalCreation
		err    error
	}

	cases := map[string]struct {
		args
		want
	}{
		"VaildInput": {
			args: args{
				s3: &fake.MockBucketClient{
					MockCreateBucket: func(ctx context.Context, input *awss3.CreateBucketInput, opts []func(*awss3.Options)) (*awss3.CreateBucketOutput, error) {
						return &awss3.CreateBucketOutput{}, nil
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(s3Testing.WithConditions(xpv1.Creating())),
			},
		},
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				s3: &fake.MockBucketClient{
					MockCreateBucket: func(ctx context.Context, input *awss3.CreateBucketInput, opts []func(*awss3.Options)) (*awss3.CreateBucketOutput, error) {
						return nil, errBoom
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr:  s3Testing.Bucket(s3Testing.WithConditions(xpv1.Creating())),
				err: awsclient.Wrap(errBoom, errCreate),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{s3client: tc.s3}
			o, err := e.Create(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, o); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestUpdate(t *testing.T) {

	type want struct {
		cr     resource.Managed
		result managed.ExternalUpdate
		err    error
	}

	cases := map[string]struct {
		args
		want
	}{
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ValidInputNoUpdate": {
			args: args{
				s3: s3Testing.Client(),
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr:     s3Testing.Bucket(s3Testing.WithConditions(xpv1.ReconcileSuccess())),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputUpdateNeededSuccess": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithGetRequestPayment(func(ctx context.Context, input *awss3.GetBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.GetBucketRequestPaymentOutput, error) {
						return &awss3.GetBucketRequestPaymentOutput{Payer: awss3types.PayerBucketOwner}, nil

					}),
					s3Testing.WithPutRequestPayment(func(ctx context.Context, input *awss3.PutBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.PutBucketRequestPaymentOutput, error) {
						return &awss3.PutBucketRequestPaymentOutput{}, nil
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"})),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.ReconcileSuccess()),
					s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"}),
				),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputUpdateNeededFailed": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithGetRequestPayment(func(ctx context.Context, input *awss3.GetBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.GetBucketRequestPaymentOutput, error) {
						return &awss3.GetBucketRequestPaymentOutput{Payer: awss3types.PayerBucketOwner}, nil

					}),
					s3Testing.WithPutRequestPayment(func(ctx context.Context, input *awss3.PutBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.PutBucketRequestPaymentOutput, error) {
						return nil, errBoom
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"})),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"}),
				),
				err:    errors.Wrap(awsclient.Wrap(errBoom, "cannot put Bucket payment"), errCreateOrUpdate),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputUpdateNeededObserveFailed": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithGetRequestPayment(func(ctx context.Context, input *awss3.GetBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.GetBucketRequestPaymentOutput, error) {
						return nil, errBoom

					}),
					s3Testing.WithPutRequestPayment(func(ctx context.Context, input *awss3.PutBucketRequestPaymentInput, opts []func(*awss3.Options)) (*awss3.PutBucketRequestPaymentOutput, error) {
						return &awss3.PutBucketRequestPaymentOutput{}, nil
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"})),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.ReconcileError(awsclient.Wrap(errBoom, "cannot get request payment configuration"))),
					s3Testing.WithPayerConfig(&v1beta1.PaymentConfiguration{Payer: "Requester"}),
				),
				err:    awsclient.Wrap(errBoom, "cannot get request payment configuration"),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputDeleteNeededSuccess": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithDeleteSSE(func(ctx context.Context, input *awss3.DeleteBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketEncryptionOutput, error) {
						return &awss3.DeleteBucketEncryptionOutput{}, nil
					}),
					s3Testing.WithGetSSE(func(ctx context.Context, input *awss3.GetBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
						return &awss3.GetBucketEncryptionOutput{
							ServerSideEncryptionConfiguration: &awss3types.ServerSideEncryptionConfiguration{
								Rules: []awss3types.ServerSideEncryptionRule{
									{
										ApplyServerSideEncryptionByDefault: &awss3types.ServerSideEncryptionByDefault{
											KMSMasterKeyID: aws.String("key-id"),
											SSEAlgorithm:   awss3types.ServerSideEncryptionAes256,
										},
									},
								},
							},
						}, nil
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithSSEConfig(nil)),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.ReconcileSuccess()),
					s3Testing.WithSSEConfig(nil),
				),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputDeleteNeededFailed": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithDeleteSSE(func(ctx context.Context, input *awss3.DeleteBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketEncryptionOutput, error) {
						return nil, errBoom
					}),
					s3Testing.WithGetSSE(func(ctx context.Context, input *awss3.GetBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
						return &awss3.GetBucketEncryptionOutput{
							ServerSideEncryptionConfiguration: &awss3types.ServerSideEncryptionConfiguration{
								Rules: []awss3types.ServerSideEncryptionRule{
									{
										ApplyServerSideEncryptionByDefault: &awss3types.ServerSideEncryptionByDefault{
											KMSMasterKeyID: aws.String("key-id"),
											SSEAlgorithm:   awss3types.ServerSideEncryptionAes256,
										},
									},
								},
							},
						}, nil
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithSSEConfig(nil)),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithSSEConfig(nil),
				),
				err:    errors.Wrap(awsclient.Wrap(errBoom, "cannot delete Bucket encryption configuration"), errDelete),
				result: managed.ExternalUpdate{},
			},
		},
		"ValidInputDeleteNeededObserveFailed": {
			args: args{
				s3: s3Testing.Client(
					s3Testing.WithDeleteSSE(func(ctx context.Context, input *awss3.DeleteBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketEncryptionOutput, error) {
						return &awss3.DeleteBucketEncryptionOutput{}, nil
					}),
					s3Testing.WithGetSSE(func(ctx context.Context, input *awss3.GetBucketEncryptionInput, opts []func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
						return nil, errBoom
					}),
				),
				cr: s3Testing.Bucket(s3Testing.WithSSEConfig(nil)),
			},
			want: want{
				cr: s3Testing.Bucket(
					s3Testing.WithConditions(xpv1.ReconcileError(awsclient.Wrap(errBoom, "cannot get Bucket encryption configuration"))),
					s3Testing.WithSSEConfig(nil),
				),
				err:    awsclient.Wrap(errBoom, "cannot get Bucket encryption configuration"),
				result: managed.ExternalUpdate{},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{s3client: tc.s3, subresourceClients: bucket.NewSubresourceClients(tc.s3)}
			o, err := e.Update(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.result, o); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestDelete(t *testing.T) {

	type want struct {
		cr  resource.Managed
		err error
	}

	cases := map[string]struct {
		args
		want
	}{
		"VaildInput": {
			args: args{
				s3: &fake.MockBucketClient{
					MockDeleteBucket: func(ctx context.Context, input *awss3.DeleteBucketInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketOutput, error) {
						return &awss3.DeleteBucketOutput{}, nil
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(s3Testing.WithConditions(xpv1.Deleting())),
			},
		},
		"InValidInput": {
			args: args{
				cr: unexpectedItem,
			},
			want: want{
				cr:  unexpectedItem,
				err: errors.New(errUnexpectedObject),
			},
		},
		"ClientError": {
			args: args{
				s3: &fake.MockBucketClient{
					MockDeleteBucket: func(ctx context.Context, input *awss3.DeleteBucketInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketOutput, error) {
						return nil, errBoom
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr:  s3Testing.Bucket(s3Testing.WithConditions(xpv1.Deleting())),
				err: errBoom,
			},
		},
		"ResourceDoesNotExist": {
			args: args{
				s3: &fake.MockBucketClient{
					MockDeleteBucket: func(ctx context.Context, input *awss3.DeleteBucketInput, opts []func(*awss3.Options)) (*awss3.DeleteBucketOutput, error) {
						return nil, &awss3types.NoSuchBucket{}
					},
				},
				cr: s3Testing.Bucket(),
			},
			want: want{
				cr: s3Testing.Bucket(s3Testing.WithConditions(xpv1.Deleting())),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{s3client: tc.s3}
			err := e.Delete(context.Background(), tc.args.cr)

			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.want.cr, tc.args.cr, test.EquateConditions()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

// /*
// Copyright 2019 The Crossplane Authors.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

package hostedzone

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	runtimev1alpha1 "github.com/crossplane/crossplane-runtime/apis/core/v1alpha1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	"github.com/crossplane/provider-aws/apis/route53/v1alpha1"
	"github.com/crossplane/provider-aws/apis/v1alpha3"
	awsclients "github.com/crossplane/provider-aws/pkg/clients"
	"github.com/crossplane/provider-aws/pkg/clients/hostedzone"
	"github.com/crossplane/provider-aws/pkg/clients/hostedzone/fake"
)

const (
	providerName = "aws-creds"
)

var (
	unexpectedItem resource.Managed
	uuid                 = "a96abeca-8da3-40fc-a2d5-08d72084eb65"
	errBoom              = errors.New("Some random error")
	id                   = "/hostedzone/XXXXXXXXXXXXXXXXXXX"
	rrCount        int64 = 2
	c                    = new(string)
	b                    = new(bool)
)

type zoneModifier func(*v1alpha1.HostedZone)

type args struct {
	kube    client.Client
	route53 hostedzone.Client
	cr      resource.Managed
}

func withExternalName(s string) zoneModifier {
	return func(r *v1alpha1.HostedZone) { meta.SetExternalName(r, s) }
}

func withConditions(c ...runtimev1alpha1.Condition) zoneModifier {
	return func(r *v1alpha1.HostedZone) { r.Status.ConditionedStatus.Conditions = c }
}

func withStatus(id string, rr int64) zoneModifier {
	return func(r *v1alpha1.HostedZone) {
		r.Status.AtProvider = v1alpha1.HostedZoneObservation{
			DelegationSet: v1alpha1.DelegationSet{
				NameServers: []string{
					"ns-2048.awsdns-64.com",
					"ns-2049.awsdns-65.net",
					"ns-2050.awsdns-66.org",
					"ns-2051.awsdns-67.co.uk",
				},
			},
			HostedZone: v1alpha1.HostedZoneResponse{
				CallerReference:        uuid,
				ID:                     id,
				ResourceRecordSetCount: rr,
			},
		}
	}
}

func withComment(c string) zoneModifier {
	return func(r *v1alpha1.HostedZone) { r.Spec.ForProvider.Config.Comment = &c }
}

func zoneTester(m ...zoneModifier) *v1alpha1.HostedZone {
	cr := &v1alpha1.HostedZone{
		Spec: v1alpha1.HostedZoneSpec{
			ResourceSpec: runtimev1alpha1.ResourceSpec{
				ProviderReference: runtimev1alpha1.Reference{Name: providerName},
			},
			ForProvider: v1alpha1.HostedZoneParameters{
				Config: &v1alpha1.Config{
					Comment:     c,
					PrivateZone: b,
				},
				Name: id,
			},
		},
	}
	for _, f := range m {
		f(cr)
	}
	return cr
}

func TestConnect(t *testing.T) {

	type args struct {
		cr          *v1alpha1.HostedZone
		kube        client.Client
		newClientFn func(ctx context.Context, credentials []byte, region string, auth awsclients.AuthMethod) (hostedzone.Client, error)
	}
	type want struct {
		err error
	}

	cases := map[string]struct {
		args
		want
	}{
		"CannotGetProvider": {
			args: args{
				kube: &test.MockClient{MockGet: test.NewMockGetFn(errBoom)},
				cr:   zoneTester(),
			},
			want: want{
				err: errors.Wrap(errBoom, errGetProvider),
			},
		},
		"CannotGetProviderSecret": {
			args: args{
				kube: &test.MockClient{MockGet: func(_ context.Context, _ client.ObjectKey, obj runtime.Object) error {
					switch o := obj.(type) {
					case *v1.Secret:
						return errBoom
					case *v1alpha3.Provider:
						p := &v1alpha3.Provider{Spec: v1alpha3.ProviderSpec{ProviderSpec: runtimev1alpha1.ProviderSpec{CredentialsSecretRef: &runtimev1alpha1.SecretKeySelector{}}}}
						p.DeepCopyInto(o)
					}
					return nil
				}},
				cr: zoneTester(),
			},
			want: want{
				err: errors.Wrap(errBoom, errGetProviderSecret),
			},
		},
		"Successful": {
			args: args{
				kube: &test.MockClient{MockGet: func(_ context.Context, _ client.ObjectKey, obj runtime.Object) error {
					if o, ok := obj.(*v1alpha3.Provider); ok {
						p := &v1alpha3.Provider{Spec: v1alpha3.ProviderSpec{ProviderSpec: runtimev1alpha1.ProviderSpec{CredentialsSecretRef: &runtimev1alpha1.SecretKeySelector{}}}}
						p.DeepCopyInto(o)
					}
					return nil
				}},
				newClientFn: func(_ context.Context, _ []byte, _ string, _ awsclients.AuthMethod) (hostedzone.Client, error) {
					return nil, nil
				},
				cr: zoneTester(),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := &connector{kube: tc.kube, newClientFn: tc.newClientFn}
			_, err := c.Connect(context.Background(), tc.args.cr)
			if diff := cmp.Diff(tc.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
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
		"VaildInput": {
			args: args{
				kube: &test.MockClient{
					MockStatusUpdate: test.NewMockStatusUpdateFn(nil),
				},
				route53: &fake.MockHostedZoneClient{
					MockGetHostedZoneRequest: func(input *awsroute53.GetHostedZoneInput) awsroute53.GetHostedZoneRequest {
						return awsroute53.GetHostedZoneRequest{
							Request: &aws.Request{
								HTTPRequest: &http.Request{},
								Data: &awsroute53.GetHostedZoneOutput{
									DelegationSet: &awsroute53.DelegationSet{
										NameServers: []string{
											"ns-2048.awsdns-64.com",
											"ns-2049.awsdns-65.net",
											"ns-2050.awsdns-66.org",
											"ns-2051.awsdns-67.co.uk",
										},
									},
									HostedZone: &awsroute53.HostedZone{
										CallerReference:        &uuid,
										Id:                     &id,
										ResourceRecordSetCount: &rrCount,
										Config: &awsroute53.HostedZoneConfig{
											Comment:     c,
											PrivateZone: b,
										},
									},
									VPCs: make([]awsroute53.VPC, 0),
								},
								Retryer: aws.NoOpRetryer{},
							},
						}
					},
				},
				cr: zoneTester(
					withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withStatus(id, rrCount)),
			},
			want: want{
				cr: zoneTester(
					withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withStatus(id, rrCount),
					withConditions(runtimev1alpha1.Available())),
				result: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				},
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
		"ResourceDoesNotExist": {
			args: args{
				route53: &fake.MockHostedZoneClient{
					MockGetHostedZoneRequest: func(input *awsroute53.GetHostedZoneInput) awsroute53.GetHostedZoneRequest {
						return awsroute53.GetHostedZoneRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{}, Error: awserr.New(awsroute53.ErrCodeNoSuchHostedZone, "", nil), Retryer: aws.NoOpRetryer{}},
						}
					},
				},
				cr: zoneTester(),
			},
			want: want{
				cr:     zoneTester(),
				result: managed.ExternalObservation{},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{kube: test.NewMockClient(), client: tc.route53}
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
		"ValidInput": {
			args: args{
				kube: &test.MockClient{
					MockStatusUpdate: test.NewMockStatusUpdateFn(nil),
				},
				route53: &fake.MockHostedZoneClient{
					MockCreateHostedZoneRequest: func(input *awsroute53.CreateHostedZoneInput) awsroute53.CreateHostedZoneRequest {
						return awsroute53.CreateHostedZoneRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{},
								Data: &awsroute53.CreateHostedZoneOutput{
									DelegationSet: &awsroute53.DelegationSet{
										NameServers: []string{
											"ns-2048.awsdns-64.com",
											"ns-2049.awsdns-65.net",
											"ns-2050.awsdns-66.org",
											"ns-2051.awsdns-67.co.uk",
										},
									},
									HostedZone: &awsroute53.HostedZone{
										CallerReference:        &uuid,
										Id:                     &id,
										ResourceRecordSetCount: &rrCount,
										Config: &awsroute53.HostedZoneConfig{
											Comment:     c,
											PrivateZone: b,
										},
									},
									Location: aws.String(fmt.Sprintf("%s%s", "https://route53.amazonaws.com/2013-04-01/", id)),
								},
								Retryer: aws.NoOpRetryer{},
							},
						}
					},
				},
				cr: zoneTester(withExternalName(strings.SplitAfter(id, "/hostedzone/")[1])),
			},
			want: want{
				cr: zoneTester(
					withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withConditions(runtimev1alpha1.Creating())),
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
				route53: &fake.MockHostedZoneClient{
					MockCreateHostedZoneRequest: func(input *awsroute53.CreateHostedZoneInput) awsroute53.CreateHostedZoneRequest {
						return awsroute53.CreateHostedZoneRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{}, Error: errBoom, Retryer: aws.NoOpRetryer{}},
						}
					},
				},
				cr: zoneTester(),
			},
			want: want{
				cr:  zoneTester(withConditions(runtimev1alpha1.Creating())),
				err: errors.Wrap(errBoom, errCreate),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{kube: test.NewMockClient(), client: tc.route53}
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
		"VaildInput": {
			args: args{
				route53: &fake.MockHostedZoneClient{
					MockUpdateHostedZoneCommentRequest: func(input *awsroute53.UpdateHostedZoneCommentInput) awsroute53.UpdateHostedZoneCommentRequest {
						return awsroute53.UpdateHostedZoneCommentRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{},
								Data: &awsroute53.UpdateHostedZoneCommentOutput{
									HostedZone: &awsroute53.HostedZone{
										CallerReference:        &uuid,
										Id:                     &id,
										ResourceRecordSetCount: &rrCount,
										Config: &awsroute53.HostedZoneConfig{
											Comment:     c,
											PrivateZone: b,
										},
									},
								},
								Retryer: aws.NoOpRetryer{},
							},
						}
					},
				},
				cr: zoneTester(withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withComment("New Comment")),
			},
			want: want{
				cr: zoneTester(withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withComment("New Comment")),
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
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{client: tc.route53}
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
				route53: &fake.MockHostedZoneClient{
					MockDeleteHostedZoneRequest: func(input *awsroute53.DeleteHostedZoneInput) awsroute53.DeleteHostedZoneRequest {
						return awsroute53.DeleteHostedZoneRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{}, Data: &awsroute53.DeleteHostedZoneOutput{}, Retryer: aws.NoOpRetryer{}},
						}
					},
				},
				cr: zoneTester(withExternalName(strings.SplitAfter(id, "/hostedzone/")[1])),
			},
			want: want{
				cr: zoneTester(withExternalName(strings.SplitAfter(id, "/hostedzone/")[1]),
					withConditions(runtimev1alpha1.Deleting())),
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
				route53: &fake.MockHostedZoneClient{
					MockDeleteHostedZoneRequest: func(input *awsroute53.DeleteHostedZoneInput) awsroute53.DeleteHostedZoneRequest {
						return awsroute53.DeleteHostedZoneRequest{
							Request: &aws.Request{HTTPRequest: &http.Request{}, Error: errBoom, Retryer: aws.NoOpRetryer{}},
						}
					},
				},
				cr: zoneTester(),
			},
			want: want{
				cr:  zoneTester(withConditions(runtimev1alpha1.Deleting())),
				err: errors.Wrap(errBoom, errDelete),
			},
		},
		"ResourceDoesNotExist": {
			args: args{
				route53: &fake.MockHostedZoneClient{
					MockDeleteHostedZoneRequest: func(input *awsroute53.DeleteHostedZoneInput) awsroute53.DeleteHostedZoneRequest {
						return awsroute53.DeleteHostedZoneRequest{
							Request: &aws.Request{Retryer: aws.NoOpRetryer{}, HTTPRequest: &http.Request{}, Error: awserr.New(awsroute53.ErrCodeNoSuchHostedZone, "", nil)},
						}
					},
				},
				cr: zoneTester(),
			},
			want: want{
				cr: zoneTester(withConditions(runtimev1alpha1.Deleting())),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{client: tc.route53}
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

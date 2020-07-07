/*
Copyright 2019 The Crossplane Authors.

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
package resourcerecordset

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/meta"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	awsroute53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	runtimev1alpha1 "github.com/crossplane/crossplane-runtime/apis/core/v1alpha1"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"

	"github.com/crossplane/provider-aws/apis/route53/v1alpha1"
	"github.com/crossplane/provider-aws/pkg/clients/resourcerecordset"
	"github.com/crossplane/provider-aws/pkg/clients/resourcerecordset/fake"
)

const (
	providerName = "aws-creds"
	testRegion   = "us-east-1"
)

var (
	mockExternalClient external
	mockClient         fake.MockResourceRecordSetClient

	unexpectedItem resource.Managed
	errBoom        = errors.New("Some random error")
	rrName         = "crossplane.io"
	rrtype         = aws.String("A")
	TTL            = aws.Int64(300)
	rRecords       = make([]v1alpha1.ResourceRecord, 1)
	zoneID         = aws.String("/hostedzone/XXXXXXXXXXXXXXXXXXX")

	changeFn = func(*awsroute53.ChangeResourceRecordSetsInput) awsroute53.ChangeResourceRecordSetsRequest {
		return awsroute53.ChangeResourceRecordSetsRequest{
			Request: &aws.Request{
				HTTPRequest: &http.Request{},
				Data:        &awsroute53.ChangeResourceRecordSetsOutput{},
				Error:       nil,
				Retryer:     aws.NoOpRetryer{},
			},
		}
	}
	changeErrFn = func(*awsroute53.ChangeResourceRecordSetsInput) awsroute53.ChangeResourceRecordSetsRequest {
		return awsroute53.ChangeResourceRecordSetsRequest{
			Request: &aws.Request{HTTPRequest: &http.Request{}, Error: errBoom, Retryer: aws.NoOpRetryer{}},
		}
	}
)

type rrModifier func(*v1alpha1.ResourceRecordSet)

type args struct {
	kube    client.Client
	route53 resourcerecordset.Client
	cr      resource.Managed
}

func withConditions(c ...runtimev1alpha1.Condition) rrModifier {
	return func(r *v1alpha1.ResourceRecordSet) { r.Status.ConditionedStatus.Conditions = c }
}

func rrTester(m ...rrModifier) *v1alpha1.ResourceRecordSet {
	for i := range rRecords {
		rRecords[i].Value = aws.String("0.0.0.0")
	}
	cr := &v1alpha1.ResourceRecordSet{
		ObjectMeta: v1.ObjectMeta{
			Name: rrName,
		},
		Spec: v1alpha1.ResourceRecordSetSpec{
			ResourceSpec: runtimev1alpha1.ResourceSpec{
				ProviderReference: runtimev1alpha1.Reference{Name: providerName},
			},
			ForProvider: v1alpha1.ResourceRecordSetParameters{
				Type:            rrtype,
				TTL:             TTL,
				ResourceRecords: rRecords,
				ZoneID:          zoneID,
			},
		},
	}
	meta.SetExternalName(cr, cr.GetName())
	for _, f := range m {
		f(cr)
	}
	return cr
}

func TestMain(m *testing.M) {
	mockClient = fake.MockResourceRecordSetClient{}
	mockExternalClient = external{
		client: &mockClient,
		kube: &test.MockClient{
			MockUpdate: test.NewMockUpdateFn(nil),
		},
	}

	os.Exit(m.Run())
}

func TestConnect(t *testing.T) {

	type args struct {
		cr          resource.Managed
		newClientFn func(*aws.Config) resourcerecordset.Client
		awsConfigFn func(context.Context, client.Reader, runtimev1alpha1.Reference) (*aws.Config, error)
	}
	type want struct {
		err error
	}

	cases := map[string]struct {
		args
		want
	}{
		"ValidInput": {
			args: args{
				newClientFn: func(config *aws.Config) resourcerecordset.Client {
					if diff := cmp.Diff(testRegion, config.Region); diff != "" {
						t.Errorf("r: -want, +got:\n%s", diff)
					}
					return nil
				},
				awsConfigFn: func(_ context.Context, _ client.Reader, p runtimev1alpha1.Reference) (*aws.Config, error) {
					if diff := cmp.Diff(providerName, p.Name); diff != "" {
						t.Errorf("r: -want, +got:\n%s", diff)
					}
					return &aws.Config{Region: testRegion}, nil
				},
				cr: rrTester(),
			},
			want: want{
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := &connector{newClientFn: tc.newClientFn, awsConfigFn: tc.awsConfigFn}
			_, err := c.Connect(context.Background(), tc.args.cr)
			if diff := cmp.Diff(tc.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}

func TestObserve(t *testing.T) {

	name := rrName + "."
	rrSet := awsroute53.ResourceRecordSet{
		Name: &name,
		Type: route53.RRType("A"),
		TTL:  TTL,
		ResourceRecords: []route53.ResourceRecord{
			{
				Value: aws.String("0.0.0.0"),
			},
		},
	}

	type want struct {
		cr     resource.Managed
		result managed.ExternalObservation
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
				route53: &fake.MockResourceRecordSetClient{
					MockListResourceRecordSetsRequest: func(*route53.ListResourceRecordSetsInput) awsroute53.ListResourceRecordSetsRequest {
						return route53.ListResourceRecordSetsRequest{
							Request: &aws.Request{
								HTTPRequest: &http.Request{},
								Data: &route53.ListResourceRecordSetsOutput{
									ResourceRecordSets: []awsroute53.ResourceRecordSet{rrSet},
								},
								Error:   nil,
								Retryer: aws.NoOpRetryer{},
							},
						}
					},
				},
				cr: rrTester(),
			},
			want: want{
				cr: rrTester(withConditions(runtimev1alpha1.Available())),
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
				route53: &fake.MockResourceRecordSetClient{
					MockListResourceRecordSetsRequest: func(*awsroute53.ListResourceRecordSetsInput) awsroute53.ListResourceRecordSetsRequest {
						return awsroute53.ListResourceRecordSetsRequest{
							Request: &aws.Request{
								Retryer:     aws.NoOpRetryer{},
								HTTPRequest: &http.Request{},
								Data: &route53.ListResourceRecordSetsOutput{
									ResourceRecordSets: []awsroute53.ResourceRecordSet{{
										Name: aws.String(""),
										Type: route53.RRType(""),
										TTL:  aws.Int64(0),
										ResourceRecords: []route53.ResourceRecord{
											{
												Value: aws.String(""),
											},
										},
									}},
								},
								Error: nil,
							},
						}
					},
				},
				cr: rrTester(),
			},
			want: want{
				cr: rrTester(),
				result: managed.ExternalObservation{
					ResourceExists: false,
				},
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
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr: rrTester(withConditions(runtimev1alpha1.Creating())),
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
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeErrFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr:  rrTester(withConditions(runtimev1alpha1.Creating())),
				err: errors.Wrap(errBoom, errCreate),
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := &external{client: tc.route53}
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
		"ValidInput": {
			args: args{
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr: rrTester(),
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
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeErrFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr:  rrTester(),
				err: errors.Wrap(errBoom, errUpdate),
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
		"ValidInput": {
			args: args{
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr: rrTester(withConditions(runtimev1alpha1.Deleting())),
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
				route53: &fake.MockResourceRecordSetClient{
					MockChangeResourceRecordSetsRequest: changeErrFn,
				},
				cr: rrTester(),
			},
			want: want{
				cr:  rrTester(withConditions(runtimev1alpha1.Deleting())),
				err: errors.Wrap(errBoom, errDelete),
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
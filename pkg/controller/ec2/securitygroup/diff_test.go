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

package securitygroup

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestDiffPermissions(t *testing.T) {
	type testCase struct {
		name string

		want, have  []awsec2.IpPermission
		add, remove []awsec2.IpPermission
	}

	cases := []testCase{
		{
			name:   "Same",
			want:   sgPersmissions(port100, cidr),
			have:   sgPersmissions(port100, cidr),
			add:    nil,
			remove: nil,
		},
		{
			name:   "Add",
			want:   sgPersmissions(port100, cidr),
			have:   nil,
			add:    sgPersmissions(port100, cidr),
			remove: nil,
		},
		{
			name:   "Remove",
			want:   nil,
			have:   sgPersmissions(port100, cidr),
			add:    nil,
			remove: sgPersmissions(port100, cidr),
		},
		{
			name:   "Replace",
			want:   sgPersmissions(99, cidr),
			have:   sgPersmissions(port100, cidr),
			add:    sgPersmissions(99, cidr),
			remove: sgPersmissions(port100, cidr),
		},
		{
			name:   "Add block",
			want:   sgPersmissions(port100, cidr, "192.168.0.1/32"),
			have:   sgPersmissions(port100, cidr),
			add:    sgPersmissions(port100, "192.168.0.1/32"),
			remove: nil,
		},
		{
			name:   "Remove block",
			want:   sgPersmissions(port100, cidr),
			have:   sgPersmissions(port100, cidr, "192.168.0.1/32"),
			add:    nil,
			remove: sgPersmissions(port100, "192.168.0.1/32"),
		},
		{
			name:   "Replace block",
			want:   sgPersmissions(port100, cidr, "172.240.1.1/32", "192.168.0.1/32"),
			have:   sgPersmissions(port100, cidr, "172.240.2.2/32", "192.168.0.1/32"),
			add:    sgPersmissions(port100, "172.240.1.1/32"),
			remove: sgPersmissions(port100, "172.240.2.2/32"),
		},
		{
			name:   "Dedupe want",
			want:   append(sgPersmissions(port100, cidr, "172.240.1.1/32", "172.240.1.1/32", "192.168.0.1/32"), sgPersmissions(port100, cidr, "172.240.1.1/32", "172.240.1.1/32", "192.168.0.1/32")...),
			have:   sgPersmissions(port100, cidr, "172.240.2.2/32", "192.168.0.1/32"),
			add:    sgPersmissions(port100, "172.240.1.1/32"),
			remove: sgPersmissions(port100, "172.240.2.2/32"),
		},
		{
			name:   "Merge want",
			want:   append(sgPersmissions(port100, "192.168.0.1/32"), sgPersmissions(port100, "172.240.1.1/32")...),
			have:   nil,
			add:    sgPersmissions(port100, "192.168.0.1/32", "172.240.1.1/32"),
			remove: nil,
		},
		{
			name:   "Ignore order",
			want:   sgPersmissions(port100, "172.240.1.1/32", "192.168.0.1/32", cidr),
			have:   sgPersmissions(port100, "192.168.0.1/32", cidr, "172.240.1.1/32"),
			add:    nil,
			remove: nil,
		},
		{
			name: "Ignore protocol case",
			want: []awsec2.IpPermission{
				{
					IpProtocol: aws.String("TCP"),
					FromPort:   &port100,
					ToPort:     &port100,
					IpRanges:   []awsec2.IpRange{{CidrIp: aws.String(cidr)}},
				},
			},
			have: []awsec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   &port100,
					ToPort:     &port100,
					IpRanges:   []awsec2.IpRange{{CidrIp: aws.String(cidr)}},
				},
			},
			add:    nil,
			remove: nil,
		},
	}

	sortIPRanges := cmpopts.SortSlices(func(a, b awsec2.IpRange) bool { return aws.StringValue(a.CidrIp) > aws.StringValue(b.CidrIp) })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			add, remove := diffPermissions(tc.want, tc.have)

			if diff := cmp.Diff(tc.add, add, sortIPRanges); diff != "" {
				t.Errorf("r add: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.remove, remove, sortIPRanges); diff != "" {
				t.Errorf("r remove: -want, +got:\n%s", diff)
			}
		})
	}
}

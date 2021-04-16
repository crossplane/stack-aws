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
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
)

type ruleKey struct {
	protocol string // lower case
	fromPort int64  // -1 for nil
	toPort   int64  // -1 for nil
}

func getInt64Key(port *int64) int64 {
	if port == nil {
		return -1
	}
	return *port
}

func getKey(perm awsec2.IpPermission) ruleKey {
	return ruleKey{
		protocol: strings.ToLower(aws.StringValue(perm.IpProtocol)),
		fromPort: getInt64Key(perm.FromPort),
		toPort:   getInt64Key(perm.ToPort),
	}
}
func getKey2(perm IPPermissionMap) ruleKey {
	return ruleKey{
		protocol: strings.ToLower(aws.StringValue(perm.IPProtocol)),
		fromPort: getInt64Key(perm.FromPort),
		toPort:   getInt64Key(perm.ToPort),
	}
}

type stringInterner map[string]*string

func (si stringInterner) Intern(s *string) *string {
	if s == nil {
		return nil
	}

	if interned, ok := si[*s]; ok {
		return interned
	}
	si[*s] = s
	return s
}

func (si stringInterner) InternIPRange(i awsec2.IpRange) awsec2.IpRange {
	return awsec2.IpRange{
		CidrIp:      si.Intern(i.CidrIp),
		Description: si.Intern(i.Description),
	}
}

type IPPermissionMap struct {
	FromPort   *int64
	ToPort     *int64
	IPProtocol *string

	ipRanges map[awsec2.IpRange]struct{}

	//	Ipv6Ranges []Ipv6Range
	//	PrefixListIds []PrefixListId
	//	UserIdGroupPairs []UserIdGroupPair
}

func (i *IPPermissionMap) Merge(m awsec2.IpPermission, interner stringInterner) {
	i.FromPort = m.FromPort
	i.ToPort = m.ToPort
	i.IPProtocol = m.IpProtocol

	if len(m.IpRanges) > 0 {
		if i.ipRanges == nil {
			i.ipRanges = make(map[awsec2.IpRange]struct{})
		}

		for _, r := range m.IpRanges {
			i.ipRanges[interner.InternIPRange(r)] = struct{}{}
		}
	}
	//	Ipv6Ranges []Ipv6Range
	//	PrefixListIds []PrefixListId
	//	UserIdGroupPairs []UserIdGroupPair
}

/*
func (i IPPermissionMap) IPRanges() []awsec2.IpRange {
	ret := make([]awsec2.IpRange, 0, len(i.ipRanges))
	for r := range i.ipRanges {
		ret = append(ret, r)
	}
	return ret
    }
*/

func (i IPPermissionMap) Diff(other IPPermissionMap) (add awsec2.IpPermission, remove awsec2.IpPermission) {
	add.IpProtocol = i.IPProtocol
	add.FromPort = i.FromPort
	add.ToPort = i.ToPort
	remove = add

	add.IpRanges = i.diffRanges(other)
	remove.IpRanges = other.diffRanges(i)

	return add, remove
}

func (i IPPermissionMap) diffRanges(other IPPermissionMap) []awsec2.IpRange {
	var ret []awsec2.IpRange
	for r := range i.ipRanges {
		if _, ok := other.ipRanges[r]; !ok {
			ret = append(ret, r)
		}
	}
	return ret
}

func convertToMaps(rules []awsec2.IpPermission, interner stringInterner) map[ruleKey]*IPPermissionMap {
	ret := make(map[ruleKey]*IPPermissionMap)

	for _, rule := range rules {
		k := getKey(rule)
		normalized, ok := ret[k]
		if !ok {
			normalized = &IPPermissionMap{}
			ret[k] = normalized
		}

		normalized.Merge(rule, interner)
	}

	return ret
}

func diffPermissions(want, have []awsec2.IpPermission) (add, remove []awsec2.IpPermission) { // nolint:gocyclo
	interner := stringInterner(make(map[string]*string))

	wantMap := convertToMaps(want, interner)
	haveMap := convertToMaps(have, interner)

	for _, have := range haveMap {
		want, ok := wantMap[getKey2(*have)]
		if !ok {
			want = &IPPermissionMap{}
		}

		removeRules, addRules := have.Diff(*want)

		if addRules.IpRanges != nil || addRules.Ipv6Ranges != nil || addRules.UserIdGroupPairs != nil || addRules.PrefixListIds != nil {
			add = append(add, addRules)
		}

		if removeRules.IpRanges != nil || removeRules.Ipv6Ranges != nil || removeRules.UserIdGroupPairs != nil || removeRules.PrefixListIds != nil {
			remove = append(remove, removeRules)
		}

	}

	for _, want := range wantMap {
		_, ok := haveMap[getKey2(*want)]
		if !ok {
			addRules, _ := want.Diff(IPPermissionMap{})
			add = append(add, addRules)
		}
	}

	return // nolint:nakedret
}

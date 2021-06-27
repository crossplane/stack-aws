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

// ruleKey represents the unique tuple (protocol, from-to port) in a
// format supported as a map key
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
func getKeyFromMap(perm ipPermissionMap) ruleKey {
	return ruleKey{
		protocol: strings.ToLower(aws.StringValue(perm.IPProtocol)),
		fromPort: getInt64Key(perm.FromPort),
		toPort:   getInt64Key(perm.ToPort),
	}
}

// stringInterner converts aws objects to objects where all string
// pointers have the same value
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

func (si stringInterner) internIPRange(i awsec2.IpRange) awsec2.IpRange {
	return awsec2.IpRange{
		CidrIp:      si.Intern(i.CidrIp),
		Description: si.Intern(i.Description),
	}
}

func (si stringInterner) internIPv6Range(i awsec2.Ipv6Range) awsec2.Ipv6Range {
	return awsec2.Ipv6Range{
		CidrIpv6:    si.Intern(i.CidrIpv6),
		Description: si.Intern(i.Description),
	}
}

func (si stringInterner) internPrefixListID(i awsec2.PrefixListId) awsec2.PrefixListId {
	return awsec2.PrefixListId{
		PrefixListId: si.Intern(i.PrefixListId),
		Description:  si.Intern(i.Description),
	}
}

func (si stringInterner) internUserIDGroupPair(i awsec2.UserIdGroupPair) awsec2.UserIdGroupPair {
	return awsec2.UserIdGroupPair{
		Description:            si.Intern(i.Description),
		GroupId:                si.Intern(i.GroupId),
		GroupName:              si.Intern(i.GroupName),
		PeeringStatus:          si.Intern(i.PeeringStatus),
		UserId:                 si.Intern(i.UserId),
		VpcId:                  si.Intern(i.VpcId),
		VpcPeeringConnectionId: si.Intern(i.VpcPeeringConnectionId),
	}
}

type ipPermissionMap struct {
	FromPort   *int64
	ToPort     *int64
	IPProtocol *string

	ipRanges        map[awsec2.IpRange]struct{}
	ipv6Ranges      map[awsec2.Ipv6Range]struct{}
	prefixListIDs   map[awsec2.PrefixListId]struct{}
	userIDGroupPair map[awsec2.UserIdGroupPair]struct{}
}

// Merge adds rules from the permission set m into this permission
// set. The caller must ensure that the permission set is for the same
// protocol and port range.
func (i *ipPermissionMap) Merge(m awsec2.IpPermission, interner stringInterner) { // nolint:gocyclo
	i.FromPort = m.FromPort
	i.ToPort = m.ToPort
	i.IPProtocol = m.IpProtocol

	if len(m.IpRanges) > 0 {
		if i.ipRanges == nil {
			i.ipRanges = make(map[awsec2.IpRange]struct{})
		}

		for _, r := range m.IpRanges {
			i.ipRanges[interner.internIPRange(r)] = struct{}{}
		}
	}

	if len(m.Ipv6Ranges) > 0 {
		if i.ipv6Ranges == nil {
			i.ipv6Ranges = make(map[awsec2.Ipv6Range]struct{})
		}

		for _, r := range m.Ipv6Ranges {
			i.ipv6Ranges[interner.internIPv6Range(r)] = struct{}{}
		}
	}

	if len(m.PrefixListIds) > 0 {
		if i.prefixListIDs == nil {
			i.prefixListIDs = make(map[awsec2.PrefixListId]struct{})
		}

		for _, r := range m.PrefixListIds {
			i.prefixListIDs[interner.internPrefixListID(r)] = struct{}{}
		}
	}

	if len(m.UserIdGroupPairs) > 0 {
		if i.userIDGroupPair == nil {
			i.userIDGroupPair = make(map[awsec2.UserIdGroupPair]struct{})
		}

		for _, r := range m.UserIdGroupPairs {
			i.userIDGroupPair[interner.internUserIDGroupPair(r)] = struct{}{}
		}
	}
}

// Diff returns rules that should be added or removed.
func (i ipPermissionMap) Diff(other ipPermissionMap) (add awsec2.IpPermission, remove awsec2.IpPermission) {
	add.IpProtocol = i.IPProtocol
	add.FromPort = i.FromPort
	add.ToPort = i.ToPort
	remove = add

	add.IpRanges = i.diffRanges(other)
	remove.IpRanges = other.diffRanges(i)

	add.Ipv6Ranges = i.diffIPv6Ranges(other)
	remove.Ipv6Ranges = other.diffIPv6Ranges(i)

	add.PrefixListIds = i.diffPrefixListIDs(other)
	remove.PrefixListIds = other.diffPrefixListIDs(i)

	add.UserIdGroupPairs = i.diffUserIDGroupPair(other)
	remove.UserIdGroupPairs = other.diffUserIDGroupPair(i)

	return add, remove
}

func (i ipPermissionMap) diffRanges(other ipPermissionMap) []awsec2.IpRange {
	var ret []awsec2.IpRange
	for r := range i.ipRanges {
		if _, ok := other.ipRanges[r]; !ok {
			ret = append(ret, r)
		}
	}
	return ret
}

func (i ipPermissionMap) diffIPv6Ranges(other ipPermissionMap) []awsec2.Ipv6Range {
	var ret []awsec2.Ipv6Range
	for r := range i.ipv6Ranges {
		if _, ok := other.ipv6Ranges[r]; !ok {
			ret = append(ret, r)
		}
	}
	return ret
}

func (i ipPermissionMap) diffPrefixListIDs(other ipPermissionMap) []awsec2.PrefixListId {
	var ret []awsec2.PrefixListId
	for r := range i.prefixListIDs {
		if _, ok := other.prefixListIDs[r]; !ok {
			ret = append(ret, r)
		}
	}
	return ret
}

func (i ipPermissionMap) diffUserIDGroupPair(other ipPermissionMap) []awsec2.UserIdGroupPair {
	var ret []awsec2.UserIdGroupPair
	for r := range i.userIDGroupPair {
		if _, ok := other.userIDGroupPair[r]; !ok {
			ret = append(ret, r)
		}
	}
	return ret
}

func convertToMaps(rules []awsec2.IpPermission, interner stringInterner) map[ruleKey]*ipPermissionMap {
	ret := make(map[ruleKey]*ipPermissionMap)

	for _, rule := range rules {
		k := getKey(rule)
		normalized, ok := ret[k]
		if !ok {
			normalized = &ipPermissionMap{}
			ret[k] = normalized
		}

		normalized.Merge(rule, interner)
	}

	return ret
}

func hasRules(perm awsec2.IpPermission) bool {
	return perm.IpRanges != nil || perm.Ipv6Ranges != nil || perm.UserIdGroupPairs != nil || perm.PrefixListIds != nil
}

func diffPermissions(want, have []awsec2.IpPermission) (add, remove []awsec2.IpPermission) {
	// To be able to use AWS structs with *string everywhere as map
	// keys, we must use the same string object for consistently for
	// the same string. We achieve this by temporarily interning all
	// strings using the same map.
	interner := stringInterner(make(map[string]*string))

	// Convert the rule arrays to compact maps without duplicates.

	// We do this to avoid O(n^2) lookup if the rule sets are large,
	// and also because the user might represent two rules
	//
	//   [(proto,port,[iprange1,iprange2])]
	// as
	//   [(proto,port,[iprange1]), (proto,port,[iprange2])]
	//
	// By converting to maps and merging rules we can get the compact
	// first form and easily check if rules are present or not.
	wantMap := convertToMaps(want, interner)
	haveMap := convertToMaps(have, interner)

	for _, have := range haveMap {
		want, ok := wantMap[getKeyFromMap(*have)]
		if !ok {
			want = &ipPermissionMap{}
		}

		removeRules, addRules := have.Diff(*want)

		if hasRules(addRules) {
			add = append(add, addRules)
		}

		if hasRules(removeRules) {
			remove = append(remove, removeRules)
		}
	}

	for _, want := range wantMap {
		_, ok := haveMap[getKeyFromMap(*want)]
		if !ok {
			addRules, _ := want.Diff(ipPermissionMap{})
			add = append(add, addRules)
		}
	}

	return add, remove
}

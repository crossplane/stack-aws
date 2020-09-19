package ec2

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/crossplane/provider-aws/apis/ec2/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// NatGatewayIDNotFound is the code that is returned by ec2 when the given NATGatewayID is not valid
	// ref: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html#api-error-codes-table-client
	NatGatewayIDNotFound = "InvalidNatGatewayID.NotFound"
)

// NatGatewayClient is the external client used for NatGateway Custom Resource
type NatGatewayClient interface {
	CreateNatGatewayRequest(input *ec2.CreateNatGatewayInput) ec2.CreateNatGatewayRequest
	DeleteNatGatewayRequest(input *ec2.DeleteNatGatewayInput) ec2.DeleteNatGatewayRequest
	DescribeNatGatewaysRequest(input *ec2.DescribeNatGatewaysInput) ec2.DescribeNatGatewaysRequest
}

// NewNatGatewayClient returns a new client using AWS credentials as JSON encoded data.
func NewNatGatewayClient(cfg aws.Config) NatGatewayClient {
	return ec2.New(cfg)
}

// IsNatGatewayNotFoundErr returns true if the error is because the item doesn't exist
func IsNatGatewayNotFoundErr(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() == NatGatewayIDNotFound {
			return true
		}
	}

	return false
}

// GenerateNatObservation is used to produce v1beta1.NatGatewayObservation from
// ec2.NatGateway.
func GenerateNatObservation(nat ec2.NatGateway) v1beta1.NatGatewayObservation {
	addresses := make([]v1beta1.NatGatewayAddress, len(nat.NatGatewayAddresses))
	for k, a := range nat.NatGatewayAddresses {
		addresses[k] = v1beta1.NatGatewayAddress{
			AllocationID:       aws.StringValue(a.AllocationId),
			NetworkInterfaceID: aws.StringValue(a.NetworkInterfaceId),
			PrivateIP:          aws.StringValue(a.PrivateIp),
			PublicIP:           aws.StringValue(a.PublicIp),
		}
	}
	tags := v1beta1.BuildFromEC2Tags(nat.Tags)
	return v1beta1.NatGatewayObservation{
		CreateTime:          &metav1.Time{Time: *nat.CreateTime},
		NatGatewayAddresses: addresses,
		NatGatewayID:        aws.StringValue(nat.NatGatewayId),
		SubnetID:            aws.StringValue(nat.SubnetId),
		Tags:                tags,
		VpcID:               aws.StringValue(nat.VpcId),
	}
}

// // LateInitializeNat fills the empty fields in *v1beta1.NatGatewayParameters with
// // the values seen in ec2.NatGateway.
// func LateInitializeNat(in *v1beta1.NatGatewayParameters, nat *ec2.NatGateway) {
// 	if nat == nil {
// 		return
// 	}
// 	if len(in.Tags) == 0 && len(nat.Tags) != 0 {
// 		in.Tags = v1beta1.BuildFromEC2Tags(nat.Tags)
// 	}
// }

// IsNatUpToDate checks whether there is a change in any of the modifiable fields.
func IsNatUpToDate(p v1beta1.NatGatewayParameters, nat ec2.NatGateway) bool {
	return v1beta1.CompareTags(p.Tags, nat.Tags)
}

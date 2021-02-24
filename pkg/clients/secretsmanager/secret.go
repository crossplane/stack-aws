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

package secretsmanager

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/provider-aws/apis/secretsmanager/v1alpha1"
	awsclient "github.com/crossplane/provider-aws/pkg/clients"
)

const (
	errGetSecretFailed         = "failed to get Kubernetes secret"
	errSecretMarshalFailed     = "cannot marshal secret"
	errKeyNotFoundInSecretData = "cannot find key in given secret data"
)

// Client defines Secretsmanager Client operations
type Client interface {
	DescribeSecret(ctx context.Context, input *secretsmanager.DescribeSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	CreateSecret(ctx context.Context, input *secretsmanager.CreateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	DeleteSecret(ctx context.Context, input *secretsmanager.DeleteSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	UpdateSecret(ctx context.Context, input *secretsmanager.UpdateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
	TagResource(ctx context.Context, input *secretsmanager.TagResourceInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error)
	UntagResource(ctx context.Context, input *secretsmanager.UntagResourceInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.UntagResourceOutput, error)
}

// NewSecretsmanagerClient creates new Secretsmanager Client with provided AWS Configurations/Credentials.
func NewSecretsmanagerClient(cfg aws.Config) Client {
	return secretsmanager.NewFromConfig(cfg)
}

// IsErrorNotFound helper function to test for ErrCodeResourceNotFoundException error.
func IsErrorNotFound(err error) bool {
	var rnfe *secretsmanagertypes.ResourceNotFoundException
	return errors.As(err, &rnfe)
}

// GetSecretValue fetches the referenced secret for a Secret CRD
func GetSecretValue(ctx context.Context, kube client.Client, s *v1alpha1.Secret) (secret string, err error) {
	nn := types.NamespacedName{
		Name:      s.Spec.ForProvider.SecretRef.SecretReference.Name,
		Namespace: s.Spec.ForProvider.SecretRef.SecretReference.Namespace,
	}
	sc := &corev1.Secret{}
	if err := kube.Get(ctx, nn, sc); err != nil {
		return "", errors.Wrap(err, errGetSecretFailed)
	}
	if len(sc.Data) == 0 {
		return "", nil
	}

	if s.Spec.ForProvider.SecretRef.Key == "" {

		if len(sc.Data) == 1 {
			return string(firstEntryInMap(sc.Data)), nil
		}

		// if no key is provided and there is more than one secret in the secret data,
		// base64-decode all secret values, marshal all keys and values and return a map
		decodedSecretMap := make(map[string]string)
		for k, v := range sc.Data {
			decodedSecretMap[k] = string(v)
		}
		secretMapJSON, err := json.Marshal(decodedSecretMap)
		if err != nil {
			return "", errors.Wrap(err, errSecretMarshalFailed)
		}
		return string(secretMapJSON), nil
	}

	if secretValue, ok := sc.Data[s.Spec.ForProvider.SecretRef.Key]; ok {
		return string(secretValue), nil
	}

	return "", errors.New(errKeyNotFoundInSecretData)
}

func firstEntryInMap(secretData map[string][]byte) (firstEntry []byte) {
	for _, v := range secretData {
		return v
	}
	return nil
}

// GenerateCreateSecretsmanagerInput from ClusterParameters.
func GenerateCreateSecretsmanagerInput(name string, p *v1alpha1.SecretParameters, secret string) *secretsmanager.CreateSecretInput {
	c := &secretsmanager.CreateSecretInput{
		Name:         awsclient.String(name),
		SecretString: &secret,
	}

	if p.Description != nil {
		c.Description = p.Description
	}

	if p.KmsKeyID != nil {
		c.KmsKeyId = p.KmsKeyID
	}

	if len(p.Tags) != 0 {
		c.Tags = make([]secretsmanagertypes.Tag, len(p.Tags))
		for i, val := range p.Tags {
			c.Tags[i] = secretsmanagertypes.Tag{
				Key:   aws.String(val.Key),
				Value: aws.String(val.Value),
			}
		}
	}

	return c
}

// GenerateUpdateSecretInput from SecretParameters
func GenerateUpdateSecretInput(name string, p v1alpha1.SecretParameters, secret string) *secretsmanager.UpdateSecretInput {
	u := &secretsmanager.UpdateSecretInput{
		SecretString: &secret,
		SecretId:     awsclient.String(name),
	}

	if p.Description != nil {
		u.Description = p.Description
	}

	if p.KmsKeyID != nil {
		u.KmsKeyId = p.KmsKeyID
	}

	return u
}

// GenerateDeleteSecretInput from SecretParameters
func GenerateDeleteSecretInput(name string, p v1alpha1.SecretParameters) *secretsmanager.DeleteSecretInput {
	return &secretsmanager.DeleteSecretInput{
		SecretId:                   awsclient.String(name),
		ForceDeleteWithoutRecovery: aws.ToBool(p.ForceDeleteWithoutRecovery),
		RecoveryWindowInDays:       aws.ToInt64(p.RecoveryWindowInDays),
	}
}

// UpdateObservation updates status.AtProvider
func UpdateObservation(o *v1alpha1.SecretObservation, svr *secretsmanager.GetSecretValueOutput, do *secretsmanager.DescribeSecretOutput) {
	if svr != nil {
		svo := svr
		if svo != nil && svo.CreatedDate != nil {
			o.CreatedDate = &metav1.Time{Time: *svo.CreatedDate}
		}
	}

	if do != nil && do.DeletedDate != nil {
		o.DeletedDate = &metav1.Time{Time: *do.DeletedDate}
	}
}

// LateInitialize fills the empty fields in *v1alpha1.SecretParameters with the
// values seen in secretsmanager.DescribeSecretOutput.
func LateInitialize(in *v1alpha1.SecretParameters, so *secretsmanager.DescribeSecretOutput) { // nolint:gocyclo
	if so == nil {
		return
	}
	in.Description = awsclient.LateInitializeStringPtr(in.Description, so.Description)
	in.KmsKeyID = awsclient.LateInitializeStringPtr(in.KmsKeyID, so.KmsKeyId)

	if len(in.Tags) == 0 && len(so.Tags) > 0 {
		in.Tags = make([]v1alpha1.Tag, len(so.Tags))
		for i, t := range so.Tags {
			in.Tags[i] = v1alpha1.Tag{
				Key:   awsclient.StringValue(t.Key),
				Value: awsclient.StringValue(t.Value),
			}
		}
	}
}

// IsUpToDate checks whether there is a change in any of the modifiable fields.
func IsUpToDate(cr *v1alpha1.Secret, req *secretsmanager.DescribeSecretOutput, secret string, svo *secretsmanager.GetSecretValueOutput) bool {
	if awsclient.StringValue(cr.Spec.ForProvider.Description) != awsclient.StringValue(req.Description) {
		return false
	}
	if awsclient.StringValue(cr.Spec.ForProvider.KmsKeyID) != awsclient.StringValue(req.KmsKeyId) {
		return false
	}
	if !CompareTags(cr.Spec.ForProvider.Tags, req.Tags) {
		return false
	}

	if svo != nil {
		if !reflect.DeepEqual(secret, *svo.SecretString) {
			return false
		}
	}

	return true
}

// CompareTags compares arrays of v1alpha1.Tag and secretsmanagertypes.Tag
func CompareTags(tags []v1alpha1.Tag, secretsmanagerTags []secretsmanagertypes.Tag) bool {
	if len(tags) != len(secretsmanagerTags) {
		return false
	}

	SortTags(tags, secretsmanagerTags)

	for i, t := range tags {
		if t.Key != *secretsmanagerTags[i].Key || t.Value != *secretsmanagerTags[i].Value {
			return false
		}
	}

	return true
}

// SortTags sorts array of v1alpha1.Tag and secretsmanagertypes.Tag on 'Key'
func SortTags(tags []v1alpha1.Tag, secretsmanagerTags []secretsmanagertypes.Tag) {
	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Key < tags[j].Key
	})

	sort.Slice(secretsmanagerTags, func(i, j int) bool {
		return *secretsmanagerTags[i].Key < *secretsmanagerTags[j].Key
	})
}

// TimeToPtr converts time.Time to *time.Time
func TimeToPtr(t time.Time) *time.Time {
	return &t
}

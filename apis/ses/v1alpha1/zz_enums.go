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

// Code generated by ack-generate. DO NOT EDIT.

package v1alpha1

type BehaviorOnMXFailure string

const (
	BehaviorOnMXFailure_UseDefaultValue BehaviorOnMXFailure = "UseDefaultValue"
	BehaviorOnMXFailure_RejectMessage   BehaviorOnMXFailure = "RejectMessage"
)

type BounceType string

const (
	BounceType_DoesNotExist     BounceType = "DoesNotExist"
	BounceType_MessageTooLarge  BounceType = "MessageTooLarge"
	BounceType_ExceededQuota    BounceType = "ExceededQuota"
	BounceType_ContentRejected  BounceType = "ContentRejected"
	BounceType_Undefined        BounceType = "Undefined"
	BounceType_TemporaryFailure BounceType = "TemporaryFailure"
)

type BulkEmailStatus string

const (
	BulkEmailStatus_Success                       BulkEmailStatus = "Success"
	BulkEmailStatus_MessageRejected               BulkEmailStatus = "MessageRejected"
	BulkEmailStatus_MailFromDomainNotVerified     BulkEmailStatus = "MailFromDomainNotVerified"
	BulkEmailStatus_ConfigurationSetDoesNotExist  BulkEmailStatus = "ConfigurationSetDoesNotExist"
	BulkEmailStatus_TemplateDoesNotExist          BulkEmailStatus = "TemplateDoesNotExist"
	BulkEmailStatus_AccountSuspended              BulkEmailStatus = "AccountSuspended"
	BulkEmailStatus_AccountThrottled              BulkEmailStatus = "AccountThrottled"
	BulkEmailStatus_AccountDailyQuotaExceeded     BulkEmailStatus = "AccountDailyQuotaExceeded"
	BulkEmailStatus_InvalidSendingPoolName        BulkEmailStatus = "InvalidSendingPoolName"
	BulkEmailStatus_AccountSendingPaused          BulkEmailStatus = "AccountSendingPaused"
	BulkEmailStatus_ConfigurationSetSendingPaused BulkEmailStatus = "ConfigurationSetSendingPaused"
	BulkEmailStatus_InvalidParameterValue         BulkEmailStatus = "InvalidParameterValue"
	BulkEmailStatus_TransientFailure              BulkEmailStatus = "TransientFailure"
	BulkEmailStatus_Failed                        BulkEmailStatus = "Failed"
)

type ConfigurationSetAttribute string

const (
	ConfigurationSetAttribute_eventDestinations ConfigurationSetAttribute = "eventDestinations"
	ConfigurationSetAttribute_trackingOptions   ConfigurationSetAttribute = "trackingOptions"
	ConfigurationSetAttribute_deliveryOptions   ConfigurationSetAttribute = "deliveryOptions"
	ConfigurationSetAttribute_reputationOptions ConfigurationSetAttribute = "reputationOptions"
)

type CustomMailFromStatus string

const (
	CustomMailFromStatus_Pending          CustomMailFromStatus = "Pending"
	CustomMailFromStatus_Success          CustomMailFromStatus = "Success"
	CustomMailFromStatus_Failed           CustomMailFromStatus = "Failed"
	CustomMailFromStatus_TemporaryFailure CustomMailFromStatus = "TemporaryFailure"
)

type DimensionValueSource string

const (
	DimensionValueSource_messageTag  DimensionValueSource = "messageTag"
	DimensionValueSource_emailHeader DimensionValueSource = "emailHeader"
	DimensionValueSource_linkTag     DimensionValueSource = "linkTag"
)

type DsnAction string

const (
	DsnAction_failed    DsnAction = "failed"
	DsnAction_delayed   DsnAction = "delayed"
	DsnAction_delivered DsnAction = "delivered"
	DsnAction_relayed   DsnAction = "relayed"
	DsnAction_expanded  DsnAction = "expanded"
)

type EventType string

const (
	EventType_send             EventType = "send"
	EventType_reject           EventType = "reject"
	EventType_bounce           EventType = "bounce"
	EventType_complaint        EventType = "complaint"
	EventType_delivery         EventType = "delivery"
	EventType_open             EventType = "open"
	EventType_click            EventType = "click"
	EventType_renderingFailure EventType = "renderingFailure"
)

type IDentityType string

const (
	IDentityType_EmailAddress IDentityType = "EmailAddress"
	IDentityType_Domain       IDentityType = "Domain"
)

type InvocationType string

const (
	InvocationType_Event           InvocationType = "Event"
	InvocationType_RequestResponse InvocationType = "RequestResponse"
)

type NotificationType string

const (
	NotificationType_Bounce    NotificationType = "Bounce"
	NotificationType_Complaint NotificationType = "Complaint"
	NotificationType_Delivery  NotificationType = "Delivery"
)

type ReceiptFilterPolicy string

const (
	ReceiptFilterPolicy_Block ReceiptFilterPolicy = "Block"
	ReceiptFilterPolicy_Allow ReceiptFilterPolicy = "Allow"
)

type SNSActionEncoding string

const (
	SNSActionEncoding_UTF_8  SNSActionEncoding = "UTF-8"
	SNSActionEncoding_Base64 SNSActionEncoding = "Base64"
)

type StopScope string

const (
	StopScope_RuleSet StopScope = "RuleSet"
)

type TLSPolicy string

const (
	TLSPolicy_Require  TLSPolicy = "Require"
	TLSPolicy_Optional TLSPolicy = "Optional"
)

type VerificationStatus string

const (
	VerificationStatus_Pending          VerificationStatus = "Pending"
	VerificationStatus_Success          VerificationStatus = "Success"
	VerificationStatus_Failed           VerificationStatus = "Failed"
	VerificationStatus_TemporaryFailure VerificationStatus = "TemporaryFailure"
	VerificationStatus_NotStarted       VerificationStatus = "NotStarted"
)
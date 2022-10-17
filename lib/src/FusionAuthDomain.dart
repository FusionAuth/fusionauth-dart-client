/*
* Copyright (c) 2019-2022, FusionAuth, All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
* either express or implied. See the License for the specific
* language governing permissions and limitations under the License.
*/

import 'package:json_annotation/json_annotation.dart';

import 'Converters.dart';

part 'FusionAuthDomain.g.dart';

/// @author Daniel DeGroff
@JsonSerializable()
class AccessToken {
  String access_token;
  num expires_in;
  String id_token;
  String refresh_token;
  String refresh_token_id;
  String scope;
  TokenType token_type;
  String userId;

  AccessToken(
      {this.access_token,
      this.expires_in,
      this.id_token,
      this.refresh_token,
      this.refresh_token_id,
      this.scope,
      this.token_type,
      this.userId});

  factory AccessToken.fromJson(Map<String, dynamic> json) =>
      _$AccessTokenFromJson(json);
  Map<String, dynamic> toJson() => _$AccessTokenToJson(this);
}

@JsonSerializable()
class ActionData {
  String actioneeUserId;
  String actionerUserId;
  List<String> applicationIds;
  String comment;
  bool emailUser;
  num expiry;
  bool notifyUser;
  String option;
  String reasonId;
  String userActionId;

  ActionData(
      {this.actioneeUserId,
      this.actionerUserId,
      this.applicationIds,
      this.comment,
      this.emailUser,
      this.expiry,
      this.notifyUser,
      this.option,
      this.reasonId,
      this.userActionId});

  factory ActionData.fromJson(Map<String, dynamic> json) =>
      _$ActionDataFromJson(json);
  Map<String, dynamic> toJson() => _$ActionDataToJson(this);
}

/// The user action request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ActionRequest extends BaseEventRequest {
  ActionData action;
  bool broadcast;

  ActionRequest({this.action, this.broadcast});

  factory ActionRequest.fromJson(Map<String, dynamic> json) =>
      _$ActionRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ActionRequestToJson(this);
}

/// The user action response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ActionResponse {
  UserActionLog action;
  List<UserActionLog> actions;

  ActionResponse({this.action, this.actions});

  factory ActionResponse.fromJson(Map<String, dynamic> json) =>
      _$ActionResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ActionResponseToJson(this);
}

/// Available JSON Web Algorithms (JWA) as described in RFC 7518 available for this JWT implementation.
///
/// @author Daniel DeGroff
enum Algorithm {
  @JsonValue('ES256')
  ES256,
  @JsonValue('ES384')
  ES384,
  @JsonValue('ES512')
  ES512,
  @JsonValue('HS256')
  HS256,
  @JsonValue('HS384')
  HS384,
  @JsonValue('HS512')
  HS512,
  @JsonValue('PS256')
  PS256,
  @JsonValue('PS384')
  PS384,
  @JsonValue('PS512')
  PS512,
  @JsonValue('RS256')
  RS256,
  @JsonValue('RS384')
  RS384,
  @JsonValue('RS512')
  RS512,
  @JsonValue('none')
  none
}

/// domain POJO to represent AuthenticationKey
///
/// @author sanjay
@JsonSerializable()
class APIKey {
  String id;
  num insertInstant;
  String ipAccessControlListId;
  String key;
  bool keyManager;
  num lastUpdateInstant;
  APIKeyMetaData metaData;
  APIKeyPermissions permissions;
  String tenantId;

  APIKey(
      {this.id,
      this.insertInstant,
      this.ipAccessControlListId,
      this.key,
      this.keyManager,
      this.lastUpdateInstant,
      this.metaData,
      this.permissions,
      this.tenantId});

  factory APIKey.fromJson(Map<String, dynamic> json) => _$APIKeyFromJson(json);
  Map<String, dynamic> toJson() => _$APIKeyToJson(this);
}

@JsonSerializable()
class APIKeyMetaData {
  Map<String, String> attributes;

  APIKeyMetaData({this.attributes});

  factory APIKeyMetaData.fromJson(Map<String, dynamic> json) =>
      _$APIKeyMetaDataFromJson(json);
  Map<String, dynamic> toJson() => _$APIKeyMetaDataToJson(this);
}

@JsonSerializable()
class APIKeyPermissions {
  Map<String, Set<String>> endpoints;

  APIKeyPermissions({this.endpoints});

  factory APIKeyPermissions.fromJson(Map<String, dynamic> json) =>
      _$APIKeyPermissionsFromJson(json);
  Map<String, dynamic> toJson() => _$APIKeyPermissionsToJson(this);
}

/// Authentication key request object.
///
/// @author Sanjay
@JsonSerializable()
class APIKeyRequest {
  APIKey apiKey;
  String sourceKeyId;

  APIKeyRequest({this.apiKey, this.sourceKeyId});

  factory APIKeyRequest.fromJson(Map<String, dynamic> json) =>
      _$APIKeyRequestFromJson(json);
  Map<String, dynamic> toJson() => _$APIKeyRequestToJson(this);
}

/// Authentication key response object.
///
/// @author Sanjay
@JsonSerializable()
class APIKeyResponse {
  APIKey apiKey;

  APIKeyResponse({this.apiKey});

  factory APIKeyResponse.fromJson(Map<String, dynamic> json) =>
      _$APIKeyResponseFromJson(json);
  Map<String, dynamic> toJson() => _$APIKeyResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AppleApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String keyId;
  String scope;
  String servicesId;
  String teamId;

  AppleApplicationConfiguration(
      {this.buttonText, this.keyId, this.scope, this.servicesId, this.teamId});

  factory AppleApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$AppleApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AppleApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AppleIdentityProvider
    extends BaseIdentityProvider<AppleApplicationConfiguration> {
  String buttonText;
  String keyId;
  String scope;
  String servicesId;
  String teamId;

  AppleIdentityProvider(
      {this.buttonText, this.keyId, this.scope, this.servicesId, this.teamId});

  factory AppleIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$AppleIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$AppleIdentityProviderToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class Application {
  ApplicationAccessControlConfiguration accessControlConfiguration;
  bool active;
  AuthenticationTokenConfiguration authenticationTokenConfiguration;
  CleanSpeakConfiguration cleanSpeakConfiguration;
  Map<String, dynamic> data;
  ApplicationEmailConfiguration emailConfiguration;
  ApplicationExternalIdentifierConfiguration externalIdentifierConfiguration;
  ApplicationFormConfiguration formConfiguration;
  String id;
  num insertInstant;
  JWTConfiguration jwtConfiguration;
  dynamic lambdaConfiguration;
  num lastUpdateInstant;
  LoginConfiguration loginConfiguration;
  ApplicationMultiFactorConfiguration multiFactorConfiguration;
  String name;
  OAuth2Configuration oauthConfiguration;
  PasswordlessConfiguration passwordlessConfiguration;
  RegistrationConfiguration registrationConfiguration;
  ApplicationRegistrationDeletePolicy registrationDeletePolicy;
  List<ApplicationRole> roles;
  SAMLv2Configuration samlv2Configuration;
  ObjectState state;
  String tenantId;
  String themeId;
  RegistrationUnverifiedOptions unverified;
  String verificationEmailTemplateId;
  VerificationStrategy verificationStrategy;
  bool verifyRegistration;

  Application(
      {this.accessControlConfiguration,
      this.active,
      this.authenticationTokenConfiguration,
      this.cleanSpeakConfiguration,
      this.data,
      this.emailConfiguration,
      this.externalIdentifierConfiguration,
      this.formConfiguration,
      this.id,
      this.insertInstant,
      this.jwtConfiguration,
      this.lambdaConfiguration,
      this.lastUpdateInstant,
      this.loginConfiguration,
      this.multiFactorConfiguration,
      this.name,
      this.oauthConfiguration,
      this.passwordlessConfiguration,
      this.registrationConfiguration,
      this.registrationDeletePolicy,
      this.roles,
      this.samlv2Configuration,
      this.state,
      this.tenantId,
      this.themeId,
      this.unverified,
      this.verificationEmailTemplateId,
      this.verificationStrategy,
      this.verifyRegistration});

  factory Application.fromJson(Map<String, dynamic> json) =>
      _$ApplicationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationAccessControlConfiguration {
  String uiIPAccessControlListId;

  ApplicationAccessControlConfiguration({this.uiIPAccessControlListId});

  factory ApplicationAccessControlConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$ApplicationAccessControlConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ApplicationAccessControlConfigurationToJson(this);
}

@JsonSerializable()
class ApplicationEmailConfiguration {
  String emailUpdateEmailTemplateId;
  String emailVerificationEmailTemplateId;
  String emailVerifiedEmailTemplateId;
  String forgotPasswordEmailTemplateId;
  String loginIdInUseOnCreateEmailTemplateId;
  String loginIdInUseOnUpdateEmailTemplateId;
  String loginNewDeviceEmailTemplateId;
  String loginSuspiciousEmailTemplateId;
  String passwordlessEmailTemplateId;
  String passwordResetSuccessEmailTemplateId;
  String passwordUpdateEmailTemplateId;
  String setPasswordEmailTemplateId;
  String twoFactorMethodAddEmailTemplateId;
  String twoFactorMethodRemoveEmailTemplateId;

  ApplicationEmailConfiguration(
      {this.emailUpdateEmailTemplateId,
      this.emailVerificationEmailTemplateId,
      this.emailVerifiedEmailTemplateId,
      this.forgotPasswordEmailTemplateId,
      this.loginIdInUseOnCreateEmailTemplateId,
      this.loginIdInUseOnUpdateEmailTemplateId,
      this.loginNewDeviceEmailTemplateId,
      this.loginSuspiciousEmailTemplateId,
      this.passwordlessEmailTemplateId,
      this.passwordResetSuccessEmailTemplateId,
      this.passwordUpdateEmailTemplateId,
      this.setPasswordEmailTemplateId,
      this.twoFactorMethodAddEmailTemplateId,
      this.twoFactorMethodRemoveEmailTemplateId});

  factory ApplicationEmailConfiguration.fromJson(Map<String, dynamic> json) =>
      _$ApplicationEmailConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationEmailConfigurationToJson(this);
}

/// Events that are bound to applications.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ApplicationEvent {
  ApplicationEvent();

  factory ApplicationEvent.fromJson(Map<String, dynamic> json) =>
      _$ApplicationEventFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationExternalIdentifierConfiguration {
  num twoFactorTrustIdTimeToLiveInSeconds;

  ApplicationExternalIdentifierConfiguration(
      {this.twoFactorTrustIdTimeToLiveInSeconds});

  factory ApplicationExternalIdentifierConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$ApplicationExternalIdentifierConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ApplicationExternalIdentifierConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationFormConfiguration {
  String adminRegistrationFormId;
  String selfServiceFormId;

  ApplicationFormConfiguration(
      {this.adminRegistrationFormId, this.selfServiceFormId});

  factory ApplicationFormConfiguration.fromJson(Map<String, dynamic> json) =>
      _$ApplicationFormConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationFormConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationMultiFactorConfiguration {
  MultiFactorEmailTemplate email;
  MultiFactorLoginPolicy loginPolicy;
  MultiFactorSMSTemplate sms;
  ApplicationMultiFactorTrustPolicy trustPolicy;

  ApplicationMultiFactorConfiguration(
      {this.email, this.loginPolicy, this.sms, this.trustPolicy});

  factory ApplicationMultiFactorConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$ApplicationMultiFactorConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ApplicationMultiFactorConfigurationToJson(this);
}

/// @author Daniel DeGroff
enum ApplicationMultiFactorTrustPolicy {
  @JsonValue('Any')
  Any,
  @JsonValue('This')
  This,
  @JsonValue('None')
  None
}

/// A Application-level policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class ApplicationRegistrationDeletePolicy {
  TimeBasedDeletePolicy unverified;

  ApplicationRegistrationDeletePolicy({this.unverified});

  factory ApplicationRegistrationDeletePolicy.fromJson(
          Map<String, dynamic> json) =>
      _$ApplicationRegistrationDeletePolicyFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ApplicationRegistrationDeletePolicyToJson(this);
}

/// The Application API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ApplicationRequest extends BaseEventRequest {
  Application application;
  ApplicationRole role;

  ApplicationRequest({this.application, this.role});

  factory ApplicationRequest.fromJson(Map<String, dynamic> json) =>
      _$ApplicationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationRequestToJson(this);
}

/// The Application API response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ApplicationResponse {
  Application application;
  List<Application> applications;
  ApplicationRole role;

  ApplicationResponse({this.application, this.applications, this.role});

  factory ApplicationResponse.fromJson(Map<String, dynamic> json) =>
      _$ApplicationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationResponseToJson(this);
}

/// A role given to a user for a specific application.
///
/// @author Seth Musselman
@JsonSerializable()
class ApplicationRole {
  String description;
  String id;
  num insertInstant;
  bool isDefault;
  bool isSuperRole;
  num lastUpdateInstant;
  String name;

  ApplicationRole(
      {this.description,
      this.id,
      this.insertInstant,
      this.isDefault,
      this.isSuperRole,
      this.lastUpdateInstant,
      this.name});

  factory ApplicationRole.fromJson(Map<String, dynamic> json) =>
      _$ApplicationRoleFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationRoleToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationUnverifiedConfiguration {
  UnverifiedBehavior registration;
  VerificationStrategy verificationStrategy;
  RegistrationUnverifiedOptions whenGated;

  ApplicationUnverifiedConfiguration(
      {this.registration, this.verificationStrategy, this.whenGated});

  factory ApplicationUnverifiedConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$ApplicationUnverifiedConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ApplicationUnverifiedConfigurationToJson(this);
}

/// This class is a simple attachment with a byte array, name and MIME type.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Attachment {
  List<num> attachment;
  String mime;
  String name;

  Attachment({this.attachment, this.mime, this.name});

  factory Attachment.fromJson(Map<String, dynamic> json) =>
      _$AttachmentFromJson(json);
  Map<String, dynamic> toJson() => _$AttachmentToJson(this);
}

/// Used to communicate whether and how authenticator attestation should be delivered to the Relying Party
///
/// @author Spencer Witt
enum AttestationConveyancePreference {
  @JsonValue('none')
  none,
  @JsonValue('indirect')
  indirect,
  @JsonValue('direct')
  direct,
  @JsonValue('enterprise')
  enterprise
}

/// Used to indicate what type of attestation was included in the authenticator response for a given WebAuthn credential at the time it was created
///
/// @author Spencer Witt
enum AttestationType {
  @JsonValue('basic')
  basic,
  @JsonValue('self')
  self,
  @JsonValue('attestationCa')
  attestationCa,
  @JsonValue('anonymizationCa')
  anonymizationCa,
  @JsonValue('none')
  none
}

/// An audit log.
///
/// @author Brian Pontarelli
@JsonSerializable()
class AuditLog {
  Map<String, dynamic> data;
  num id;
  num insertInstant;
  String insertUser;
  String message;
  dynamic newValue;
  dynamic oldValue;
  String reason;

  AuditLog(
      {this.data,
      this.id,
      this.insertInstant,
      this.insertUser,
      this.message,
      this.newValue,
      this.oldValue,
      this.reason});

  factory AuditLog.fromJson(Map<String, dynamic> json) =>
      _$AuditLogFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogToJson(this);
}

@JsonSerializable()
class AuditLogConfiguration {
  DeleteConfiguration delete;

  AuditLogConfiguration({this.delete});

  factory AuditLogConfiguration.fromJson(Map<String, dynamic> json) =>
      _$AuditLogConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogConfigurationToJson(this);
}

/// Event event to an audit log was created.
///
/// @author Daniel DeGroff
@JsonSerializable()
class AuditLogCreateEvent extends BaseEvent {
  AuditLog auditLog;

  AuditLogCreateEvent({this.auditLog});

  factory AuditLogCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$AuditLogCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogCreateEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AuditLogExportRequest extends BaseExportRequest {
  AuditLogSearchCriteria criteria;

  AuditLogExportRequest({this.criteria});

  factory AuditLogExportRequest.fromJson(Map<String, dynamic> json) =>
      _$AuditLogExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogExportRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogRequest extends BaseEventRequest {
  AuditLog auditLog;

  AuditLogRequest({this.auditLog});

  factory AuditLogRequest.fromJson(Map<String, dynamic> json) =>
      _$AuditLogRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogRequestToJson(this);
}

/// Audit log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogResponse {
  AuditLog auditLog;

  AuditLogResponse({this.auditLog});

  factory AuditLogResponse.fromJson(Map<String, dynamic> json) =>
      _$AuditLogResponseFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchCriteria extends BaseSearchCriteria {
  num end;
  String message;
  String newValue;
  String oldValue;
  String reason;
  num start;
  String user;

  AuditLogSearchCriteria(
      {this.end,
      this.message,
      this.newValue,
      this.oldValue,
      this.reason,
      this.start,
      this.user});

  factory AuditLogSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$AuditLogSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchCriteriaToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchRequest {
  AuditLogSearchCriteria search;

  AuditLogSearchRequest({this.search});

  factory AuditLogSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$AuditLogSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchRequestToJson(this);
}

/// Audit log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchResponse {
  List<AuditLog> auditLogs;
  num total;

  AuditLogSearchResponse({this.auditLogs, this.total});

  factory AuditLogSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$AuditLogSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchResponseToJson(this);
}

/// @author Brett Pontarelli
enum AuthenticationThreats {
  @JsonValue('ImpossibleTravel')
  ImpossibleTravel
}

@JsonSerializable()
class AuthenticationTokenConfiguration extends Enableable {
  AuthenticationTokenConfiguration();

  factory AuthenticationTokenConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$AuthenticationTokenConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$AuthenticationTokenConfigurationToJson(this);
}

/// Describes the <a href="https://www.w3.org/TR/webauthn-2/#authenticator-attachment-modality">authenticator attachment modality</a>.
///
/// @author Spencer Witt
enum AuthenticatorAttachment {
  @JsonValue('platform')
  platform,
  @JsonValue('crossPlatform')
  crossPlatform
}

/// Describes the authenticator attachment modality preference for a WebAuthn workflow. See {@link AuthenticatorAttachment}
///
/// @author Spencer Witt
enum AuthenticatorAttachmentPreference {
  @JsonValue('platform')
  platform,
  @JsonValue('crossPlatform')
  crossPlatform,
  @JsonValue('either')
  either
}

/// The <i>authenticator's</i> response for the authentication ceremony in its encoded format
///
/// @author Spencer Witt
@JsonSerializable()
class AuthenticatorAuthenticationResponse {
  String authenticatorData;
  String clientDataJSON;
  String signature;
  String userHandle;

  AuthenticatorAuthenticationResponse(
      {this.authenticatorData,
      this.clientDataJSON,
      this.signature,
      this.userHandle});

  factory AuthenticatorAuthenticationResponse.fromJson(
          Map<String, dynamic> json) =>
      _$AuthenticatorAuthenticationResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$AuthenticatorAuthenticationResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AuthenticatorConfiguration {
  TOTPAlgorithm algorithm;
  num codeLength;
  num timeStep;

  AuthenticatorConfiguration({this.algorithm, this.codeLength, this.timeStep});

  factory AuthenticatorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$AuthenticatorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AuthenticatorConfigurationToJson(this);
}

/// The <i>authenticator's</i> response for the registration ceremony in its encoded format
///
/// @author Spencer Witt
@JsonSerializable()
class AuthenticatorRegistrationResponse {
  String attestationObject;
  String clientDataJSON;

  AuthenticatorRegistrationResponse(
      {this.attestationObject, this.clientDataJSON});

  factory AuthenticatorRegistrationResponse.fromJson(
          Map<String, dynamic> json) =>
      _$AuthenticatorRegistrationResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$AuthenticatorRegistrationResponseToJson(this);
}

/// Used by the Relying Party to specify their requirements for authenticator attributes. Fields use the deprecated "resident key" terminology to refer
/// to client-side discoverable credentials to maintain backwards compatibility with WebAuthn Level 1.
///
/// @author Spencer Witt
@JsonSerializable()
class AuthenticatorSelectionCriteria {
  AuthenticatorAttachment authenticatorAttachment;
  bool requireResidentKey;
  ResidentKeyRequirement residentKey;
  UserVerificationRequirement userVerification;

  AuthenticatorSelectionCriteria(
      {this.authenticatorAttachment,
      this.requireResidentKey,
      this.residentKey,
      this.userVerification});

  factory AuthenticatorSelectionCriteria.fromJson(Map<String, dynamic> json) =>
      _$AuthenticatorSelectionCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$AuthenticatorSelectionCriteriaToJson(this);
}

/// Describes how the authenticator communicates with a client. This can be used by the client as a hint to locate the
/// appropriate authenticator.
///
/// @author Spencer Witt
enum AuthenticatorTransport {
  @JsonValue('usb')
  usb,
  @JsonValue('nfc')
  nfc,
  @JsonValue('ble')
  ble,
  @JsonValue('platform')
  platform,
  @JsonValue('cable')
  cable
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
@JsonSerializable()
class BaseConnectorConfiguration {
  Map<String, dynamic> data;
  bool debug;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  ConnectorType type;

  BaseConnectorConfiguration(
      {this.data,
      this.debug,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.type});

  factory BaseConnectorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$BaseConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$BaseConnectorConfigurationToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class BaseElasticSearchCriteria extends BaseSearchCriteria {
  bool accurateTotal;
  List<String> ids;
  String query;
  String queryString;
  List<SortField> sortFields;

  BaseElasticSearchCriteria(
      {this.accurateTotal,
      this.ids,
      this.query,
      this.queryString,
      this.sortFields});

  factory BaseElasticSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$BaseElasticSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$BaseElasticSearchCriteriaToJson(this);
}

/// Base-class for all FusionAuth events.
///
/// @author Brian Pontarelli
@JsonSerializable()
class BaseEvent {
  num createInstant;
  String id;
  EventInfo info;
  String tenantId;
  EventType type;

  BaseEvent({this.createInstant, this.id, this.info, this.tenantId, this.type});

  factory BaseEvent.fromJson(Map<String, dynamic> json) =>
      _$BaseEventFromJson(json);
  Map<String, dynamic> toJson() => _$BaseEventToJson(this);
}

/// Base class for requests that can contain event information. This event information is used when sending Webhooks or emails
/// during the transaction. The caller is responsible for ensuring that the event information is correct.
///
/// @author Brian Pontarelli
@JsonSerializable()
class BaseEventRequest {
  EventInfo eventInfo;

  BaseEventRequest({this.eventInfo});

  factory BaseEventRequest.fromJson(Map<String, dynamic> json) =>
      _$BaseEventRequestFromJson(json);
  Map<String, dynamic> toJson() => _$BaseEventRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseExportRequest {
  String dateTimeSecondsFormat;
  String zoneId;

  BaseExportRequest({this.dateTimeSecondsFormat, this.zoneId});

  factory BaseExportRequest.fromJson(Map<String, dynamic> json) =>
      _$BaseExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$BaseExportRequestToJson(this);
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
@JsonSerializable(createFactory: false)
class BaseIdentityProvider<
    D extends BaseIdentityProviderApplicationConfiguration> extends Enableable {
  @IdentityProviderApplicationConfigurationConverter()
  Map<String, D> applicationConfiguration;
  Map<String, dynamic> data;
  bool debug;
  String id;
  num insertInstant;
  dynamic lambdaConfiguration;
  num lastUpdateInstant;
  IdentityProviderLinkingStrategy linkingStrategy;
  String name;
  Map<String, IdentityProviderTenantConfiguration> tenantConfiguration;
  IdentityProviderType type;

  BaseIdentityProvider(
      {this.applicationConfiguration,
      this.data,
      this.debug,
      this.id,
      this.insertInstant,
      this.lambdaConfiguration,
      this.lastUpdateInstant,
      this.linkingStrategy,
      this.name,
      this.tenantConfiguration,
      this.type});

  factory BaseIdentityProvider.fromJson(Map<String, dynamic> json) =>
      BaseIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$BaseIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseIdentityProviderApplicationConfiguration extends Enableable {
  bool createRegistration;
  Map<String, dynamic> data;

  BaseIdentityProviderApplicationConfiguration(
      {this.createRegistration, this.data});

  factory BaseIdentityProviderApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$BaseIdentityProviderApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$BaseIdentityProviderApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseLoginRequest extends BaseEventRequest {
  String applicationId;
  String ipAddress;
  MetaData metaData;
  bool newDevice;
  bool noJWT;

  BaseLoginRequest(
      {this.applicationId,
      this.ipAddress,
      this.metaData,
      this.newDevice,
      this.noJWT});

  factory BaseLoginRequest.fromJson(Map<String, dynamic> json) =>
      _$BaseLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$BaseLoginRequestToJson(this);
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
@JsonSerializable()
class BaseMessengerConfiguration {
  Map<String, dynamic> data;
  bool debug;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  String transport;
  MessengerType type;

  BaseMessengerConfiguration(
      {this.data,
      this.debug,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.transport,
      this.type});

  factory BaseMessengerConfiguration.fromJson(Map<String, dynamic> json) =>
      _$BaseMessengerConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$BaseMessengerConfigurationToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class BaseSearchCriteria {
  num numberOfResults;
  String orderBy;
  num startRow;

  BaseSearchCriteria({this.numberOfResults, this.orderBy, this.startRow});

  factory BaseSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$BaseSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$BaseSearchCriteriaToJson(this);
}

enum BreachAction {
  @JsonValue('Off')
  Off,
  @JsonValue('RecordOnly')
  RecordOnly,
  @JsonValue('NotifyUser')
  NotifyUser,
  @JsonValue('RequireChange')
  RequireChange
}

/// @author Daniel DeGroff
enum BreachedPasswordStatus {
  @JsonValue('None')
  None,
  @JsonValue('ExactMatch')
  ExactMatch,
  @JsonValue('SubAddressMatch')
  SubAddressMatch,
  @JsonValue('PasswordOnly')
  PasswordOnly,
  @JsonValue('CommonPassword')
  CommonPassword
}

/// @author Daniel DeGroff
@JsonSerializable()
class BreachedPasswordTenantMetric {
  num actionRequired;
  num matchedCommonPasswordCount;
  num matchedExactCount;
  num matchedPasswordCount;
  num matchedSubAddressCount;
  num passwordsCheckedCount;

  BreachedPasswordTenantMetric(
      {this.actionRequired,
      this.matchedCommonPasswordCount,
      this.matchedExactCount,
      this.matchedPasswordCount,
      this.matchedSubAddressCount,
      this.passwordsCheckedCount});

  factory BreachedPasswordTenantMetric.fromJson(Map<String, dynamic> json) =>
      _$BreachedPasswordTenantMetricFromJson(json);
  Map<String, dynamic> toJson() => _$BreachedPasswordTenantMetricToJson(this);
}

enum BreachMatchMode {
  @JsonValue('Low')
  Low,
  @JsonValue('Medium')
  Medium,
  @JsonValue('High')
  High
}

/// XML canonicalization method enumeration. This is used for the IdP and SP side of FusionAuth SAML.
///
/// @author Brian Pontarelli
enum CanonicalizationMethod {
  @JsonValue('exclusive')
  exclusive,
  @JsonValue('exclusive_with_comments')
  exclusive_with_comments,
  @JsonValue('inclusive')
  inclusive,
  @JsonValue('inclusive_with_comments')
  inclusive_with_comments
}

/// @author Brett Pontarelli
enum CaptchaMethod {
  @JsonValue('GoogleRecaptchaV2')
  GoogleRecaptchaV2,
  @JsonValue('GoogleRecaptchaV3')
  GoogleRecaptchaV3,
  @JsonValue('HCaptcha')
  HCaptcha,
  @JsonValue('HCaptchaEnterprise')
  HCaptchaEnterprise
}

@JsonSerializable()
class CertificateInformation {
  String issuer;
  String md5Fingerprint;
  String serialNumber;
  String sha1Fingerprint;
  String sha1Thumbprint;
  String sha256Fingerprint;
  String sha256Thumbprint;
  String subject;
  num validFrom;
  num validTo;

  CertificateInformation(
      {this.issuer,
      this.md5Fingerprint,
      this.serialNumber,
      this.sha1Fingerprint,
      this.sha1Thumbprint,
      this.sha256Fingerprint,
      this.sha256Thumbprint,
      this.subject,
      this.validFrom,
      this.validTo});

  factory CertificateInformation.fromJson(Map<String, dynamic> json) =>
      _$CertificateInformationFromJson(json);
  Map<String, dynamic> toJson() => _$CertificateInformationToJson(this);
}

/// @author Trevor Smith
enum ChangePasswordReason {
  @JsonValue('Administrative')
  Administrative,
  @JsonValue('Breached')
  Breached,
  @JsonValue('Expired')
  Expired,
  @JsonValue('Validation')
  Validation
}

/// Change password request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ChangePasswordRequest extends BaseEventRequest {
  String applicationId;
  String changePasswordId;
  String currentPassword;
  String loginId;
  String password;
  String refreshToken;
  String trustChallenge;
  String trustToken;

  ChangePasswordRequest(
      {this.applicationId,
      this.changePasswordId,
      this.currentPassword,
      this.loginId,
      this.password,
      this.refreshToken,
      this.trustChallenge,
      this.trustToken});

  factory ChangePasswordRequest.fromJson(Map<String, dynamic> json) =>
      _$ChangePasswordRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ChangePasswordRequestToJson(this);
}

/// Change password response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ChangePasswordResponse {
  String oneTimePassword;
  Map<String, dynamic> state;

  ChangePasswordResponse({this.oneTimePassword, this.state});

  factory ChangePasswordResponse.fromJson(Map<String, dynamic> json) =>
      _$ChangePasswordResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ChangePasswordResponseToJson(this);
}

/// CleanSpeak configuration at the system and application level.
///
/// @author Brian Pontarelli
@JsonSerializable()
class CleanSpeakConfiguration extends Enableable {
  String apiKey;
  List<String> applicationIds;
  String url;
  UsernameModeration usernameModeration;

  CleanSpeakConfiguration(
      {this.apiKey, this.applicationIds, this.url, this.usernameModeration});

  factory CleanSpeakConfiguration.fromJson(Map<String, dynamic> json) =>
      _$CleanSpeakConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$CleanSpeakConfigurationToJson(this);
}

enum ClientAuthenticationMethod {
  @JsonValue('none')
  none,
  @JsonValue('client_secret_basic')
  client_secret_basic,
  @JsonValue('client_secret_post')
  client_secret_post
}

/// @author Brett Guy
enum ClientAuthenticationPolicy {
  @JsonValue('Required')
  Required,
  @JsonValue('NotRequired')
  NotRequired,
  @JsonValue('NotRequiredWhenUsingPKCE')
  NotRequiredWhenUsingPKCE
}

/// @author Trevor Smith
@JsonSerializable()
class ConnectorPolicy {
  String connectorId;
  Map<String, dynamic> data;
  Set<String> domains;
  bool migrate;

  ConnectorPolicy({this.connectorId, this.data, this.domains, this.migrate});

  factory ConnectorPolicy.fromJson(Map<String, dynamic> json) =>
      _$ConnectorPolicyFromJson(json);
  Map<String, dynamic> toJson() => _$ConnectorPolicyToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class ConnectorRequest {
  BaseConnectorConfiguration connector;

  ConnectorRequest({this.connector});

  factory ConnectorRequest.fromJson(Map<String, dynamic> json) =>
      _$ConnectorRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ConnectorRequestToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class ConnectorResponse {
  BaseConnectorConfiguration connector;
  List<BaseConnectorConfiguration> connectors;

  ConnectorResponse({this.connector, this.connectors});

  factory ConnectorResponse.fromJson(Map<String, dynamic> json) =>
      _$ConnectorResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ConnectorResponseToJson(this);
}

/// The types of connectors. This enum is stored as an ordinal on the <code>identities</code> table, order must be maintained.
///
/// @author Trevor Smith
enum ConnectorType {
  @JsonValue('FusionAuth')
  FusionAuth,
  @JsonValue('Generic')
  Generic,
  @JsonValue('LDAP')
  LDAP
}

/// Models a consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class Consent {
  String consentEmailTemplateId;
  Map<String, num> countryMinimumAgeForSelfConsent;
  Map<String, dynamic> data;
  num defaultMinimumAgeForSelfConsent;
  EmailPlus emailPlus;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  bool multipleValuesAllowed;
  String name;
  List<String> values;

  Consent(
      {this.consentEmailTemplateId,
      this.countryMinimumAgeForSelfConsent,
      this.data,
      this.defaultMinimumAgeForSelfConsent,
      this.emailPlus,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.multipleValuesAllowed,
      this.name,
      this.values});

  factory Consent.fromJson(Map<String, dynamic> json) =>
      _$ConsentFromJson(json);
  Map<String, dynamic> toJson() => _$ConsentToJson(this);
}

/// API request for User consent types.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ConsentRequest {
  Consent consent;

  ConsentRequest({this.consent});

  factory ConsentRequest.fromJson(Map<String, dynamic> json) =>
      _$ConsentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ConsentRequestToJson(this);
}

/// API response for consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ConsentResponse {
  Consent consent;
  List<Consent> consents;

  ConsentResponse({this.consent, this.consents});

  factory ConsentResponse.fromJson(Map<String, dynamic> json) =>
      _$ConsentResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ConsentResponseToJson(this);
}

/// Models a consent.
///
/// @author Daniel DeGroff
enum ConsentStatus {
  @JsonValue('Active')
  Active,
  @JsonValue('Revoked')
  Revoked
}

/// Status for content like usernames, profile attributes, etc.
///
/// @author Brian Pontarelli
enum ContentStatus {
  @JsonValue('ACTIVE')
  ACTIVE,
  @JsonValue('PENDING')
  PENDING,
  @JsonValue('REJECTED')
  REJECTED
}

/// @author Trevor Smith
@JsonSerializable()
class CORSConfiguration extends Enableable {
  bool allowCredentials;
  List<String> allowedHeaders;
  List<HTTPMethod> allowedMethods;
  List<String> allowedOrigins;
  bool debug;
  List<String> exposedHeaders;
  num preflightMaxAgeInSeconds;

  CORSConfiguration(
      {this.allowCredentials,
      this.allowedHeaders,
      this.allowedMethods,
      this.allowedOrigins,
      this.debug,
      this.exposedHeaders,
      this.preflightMaxAgeInSeconds});

  factory CORSConfiguration.fromJson(Map<String, dynamic> json) =>
      _$CORSConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$CORSConfigurationToJson(this);
}

/// A number identifying a cryptographic algorithm. Values should be registered with the <a
/// href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>
///
/// @author Spencer Witt
enum CoseAlgorithmIdentifier {
  @JsonValue('ES256')
  ES256,
  @JsonValue('ES384')
  ES384,
  @JsonValue('ES512')
  ES512,
  @JsonValue('RS256')
  RS256,
  @JsonValue('RS384')
  RS384,
  @JsonValue('RS512')
  RS512,
  @JsonValue('PS256')
  PS256,
  @JsonValue('PS384')
  PS384,
  @JsonValue('PS512')
  PS512
}

/// COSE Elliptic Curve identifier to determine which elliptic curve to use with a given key
///
/// @author Spencer Witt
enum CoseEllipticCurve {
  @JsonValue('Reserved')
  Reserved,
  @JsonValue('P256')
  P256,
  @JsonValue('P384')
  P384,
  @JsonValue('P521')
  P521,
  @JsonValue('X25519')
  X25519,
  @JsonValue('X448')
  X448,
  @JsonValue('Ed25519')
  Ed25519,
  @JsonValue('Ed448')
  Ed448,
  @JsonValue('Secp256k1')
  Secp256k1
}

/// COSE key type
///
/// @author Spencer Witt
enum CoseKeyType {
  @JsonValue('Reserved')
  Reserved,
  @JsonValue('OKP')
  OKP,
  @JsonValue('EC2')
  EC2,
  @JsonValue('RSA')
  RSA,
  @JsonValue('Symmetric')
  Symmetric
}

/// @author Brian Pontarelli
@JsonSerializable()
class Count {
  num count;
  num interval;

  Count({this.count, this.interval});

  factory Count.fromJson(Map<String, dynamic> json) => _$CountFromJson(json);
  Map<String, dynamic> toJson() => _$CountToJson(this);
}

/// Contains the output for the {@code credProps} extension
///
/// @author Spencer Witt
@JsonSerializable()
class CredentialPropertiesOutput {
  bool rk;

  CredentialPropertiesOutput({this.rk});

  factory CredentialPropertiesOutput.fromJson(Map<String, dynamic> json) =>
      _$CredentialPropertiesOutputFromJson(json);
  Map<String, dynamic> toJson() => _$CredentialPropertiesOutputToJson(this);
}

/// Response for the daily active user report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class DailyActiveUserReportResponse {
  List<Count> dailyActiveUsers;
  num total;

  DailyActiveUserReportResponse({this.dailyActiveUsers, this.total});

  factory DailyActiveUserReportResponse.fromJson(Map<String, dynamic> json) =>
      _$DailyActiveUserReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$DailyActiveUserReportResponseToJson(this);
}

@JsonSerializable()
class DeleteConfiguration extends Enableable {
  num numberOfDaysToRetain;

  DeleteConfiguration({this.numberOfDaysToRetain});

  factory DeleteConfiguration.fromJson(Map<String, dynamic> json) =>
      _$DeleteConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$DeleteConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class DeviceInfo {
  String description;
  String lastAccessedAddress;
  num lastAccessedInstant;
  String name;
  DeviceType type;

  DeviceInfo(
      {this.description,
      this.lastAccessedAddress,
      this.lastAccessedInstant,
      this.name,
      this.type});

  factory DeviceInfo.fromJson(Map<String, dynamic> json) =>
      _$DeviceInfoFromJson(json);
  Map<String, dynamic> toJson() => _$DeviceInfoToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class DeviceResponse {
  String device_code;
  num expires_in;
  num interval;
  String user_code;
  String verification_uri;
  String verification_uri_complete;

  DeviceResponse(
      {this.device_code,
      this.expires_in,
      this.interval,
      this.user_code,
      this.verification_uri,
      this.verification_uri_complete});

  factory DeviceResponse.fromJson(Map<String, dynamic> json) =>
      _$DeviceResponseFromJson(json);
  Map<String, dynamic> toJson() => _$DeviceResponseToJson(this);
}

enum DeviceType {
  @JsonValue('BROWSER')
  BROWSER,
  @JsonValue('DESKTOP')
  DESKTOP,
  @JsonValue('LAPTOP')
  LAPTOP,
  @JsonValue('MOBILE')
  MOBILE,
  @JsonValue('OTHER')
  OTHER,
  @JsonValue('SERVER')
  SERVER,
  @JsonValue('TABLET')
  TABLET,
  @JsonValue('TV')
  TV,
  @JsonValue('UNKNOWN')
  UNKNOWN
}

/// A displayable raw login that includes application name and user loginId.
///
/// @author Brian Pontarelli
@JsonSerializable()
class DisplayableRawLogin extends RawLogin {
  String applicationName;
  Location location;
  String loginId;

  DisplayableRawLogin({this.applicationName, this.location, this.loginId});

  factory DisplayableRawLogin.fromJson(Map<String, dynamic> json) =>
      _$DisplayableRawLoginFromJson(json);
  Map<String, dynamic> toJson() => _$DisplayableRawLoginToJson(this);
}

/// Interface for all identity providers that can be domain based.
@JsonSerializable()
class DomainBasedIdentityProvider {
  DomainBasedIdentityProvider();

  factory DomainBasedIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$DomainBasedIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$DomainBasedIdentityProviderToJson(this);
}

/// This class is an abstraction of a simple email message.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Email {
  List<Attachment> attachments;
  List<EmailAddress> bcc;
  List<EmailAddress> cc;
  EmailAddress from;
  String html;
  EmailAddress replyTo;
  String subject;
  String text;
  List<EmailAddress> to;

  Email(
      {this.attachments,
      this.bcc,
      this.cc,
      this.from,
      this.html,
      this.replyTo,
      this.subject,
      this.text,
      this.to});

  factory Email.fromJson(Map<String, dynamic> json) => _$EmailFromJson(json);
  Map<String, dynamic> toJson() => _$EmailToJson(this);
}

/// An email address.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailAddress {
  String address;
  String display;

  EmailAddress({this.address, this.display});

  factory EmailAddress.fromJson(Map<String, dynamic> json) =>
      _$EmailAddressFromJson(json);
  Map<String, dynamic> toJson() => _$EmailAddressToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EmailConfiguration {
  List<EmailHeader> additionalHeaders;
  bool debug;
  String defaultFromEmail;
  String defaultFromName;
  String emailUpdateEmailTemplateId;
  String emailVerifiedEmailTemplateId;
  String forgotPasswordEmailTemplateId;
  String host;
  bool implicitEmailVerificationAllowed;
  String loginIdInUseOnCreateEmailTemplateId;
  String loginIdInUseOnUpdateEmailTemplateId;
  String loginNewDeviceEmailTemplateId;
  String loginSuspiciousEmailTemplateId;
  String password;
  String passwordlessEmailTemplateId;
  String passwordResetSuccessEmailTemplateId;
  String passwordUpdateEmailTemplateId;
  num port;
  String properties;
  EmailSecurityType security;
  String setPasswordEmailTemplateId;
  String twoFactorMethodAddEmailTemplateId;
  String twoFactorMethodRemoveEmailTemplateId;
  EmailUnverifiedOptions unverified;
  String username;
  String verificationEmailTemplateId;
  VerificationStrategy verificationStrategy;
  bool verifyEmail;
  bool verifyEmailWhenChanged;

  EmailConfiguration(
      {this.additionalHeaders,
      this.debug,
      this.defaultFromEmail,
      this.defaultFromName,
      this.emailUpdateEmailTemplateId,
      this.emailVerifiedEmailTemplateId,
      this.forgotPasswordEmailTemplateId,
      this.host,
      this.implicitEmailVerificationAllowed,
      this.loginIdInUseOnCreateEmailTemplateId,
      this.loginIdInUseOnUpdateEmailTemplateId,
      this.loginNewDeviceEmailTemplateId,
      this.loginSuspiciousEmailTemplateId,
      this.password,
      this.passwordlessEmailTemplateId,
      this.passwordResetSuccessEmailTemplateId,
      this.passwordUpdateEmailTemplateId,
      this.port,
      this.properties,
      this.security,
      this.setPasswordEmailTemplateId,
      this.twoFactorMethodAddEmailTemplateId,
      this.twoFactorMethodRemoveEmailTemplateId,
      this.unverified,
      this.username,
      this.verificationEmailTemplateId,
      this.verificationStrategy,
      this.verifyEmail,
      this.verifyEmailWhenChanged});

  factory EmailConfiguration.fromJson(Map<String, dynamic> json) =>
      _$EmailConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EmailConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class EmailHeader {
  String name;
  String value;

  EmailHeader({this.name, this.value});

  factory EmailHeader.fromJson(Map<String, dynamic> json) =>
      _$EmailHeaderFromJson(json);
  Map<String, dynamic> toJson() => _$EmailHeaderToJson(this);
}

@JsonSerializable()
class EmailPlus extends Enableable {
  String emailTemplateId;
  num maximumTimeToSendEmailInHours;
  num minimumTimeToSendEmailInHours;

  EmailPlus(
      {this.emailTemplateId,
      this.maximumTimeToSendEmailInHours,
      this.minimumTimeToSendEmailInHours});

  factory EmailPlus.fromJson(Map<String, dynamic> json) =>
      _$EmailPlusFromJson(json);
  Map<String, dynamic> toJson() => _$EmailPlusToJson(this);
}

enum EmailSecurityType {
  @JsonValue('NONE')
  NONE,
  @JsonValue('SSL')
  SSL,
  @JsonValue('TLS')
  TLS
}

/// Stores an email template used to send emails to users.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailTemplate {
  String defaultFromName;
  String defaultHtmlTemplate;
  String defaultSubject;
  String defaultTextTemplate;
  String fromEmail;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  Map<String, String> localizedFromNames;
  Map<String, String> localizedHtmlTemplates;
  Map<String, String> localizedSubjects;
  Map<String, String> localizedTextTemplates;
  String name;

  EmailTemplate(
      {this.defaultFromName,
      this.defaultHtmlTemplate,
      this.defaultSubject,
      this.defaultTextTemplate,
      this.fromEmail,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedFromNames,
      this.localizedHtmlTemplates,
      this.localizedSubjects,
      this.localizedTextTemplates,
      this.name});

  factory EmailTemplate.fromJson(Map<String, dynamic> json) =>
      _$EmailTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateToJson(this);
}

@JsonSerializable()
class EmailTemplateErrors {
  Map<String, String> parseErrors;
  Map<String, String> renderErrors;

  EmailTemplateErrors({this.parseErrors, this.renderErrors});

  factory EmailTemplateErrors.fromJson(Map<String, dynamic> json) =>
      _$EmailTemplateErrorsFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateErrorsToJson(this);
}

/// Email template request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailTemplateRequest {
  EmailTemplate emailTemplate;

  EmailTemplateRequest({this.emailTemplate});

  factory EmailTemplateRequest.fromJson(Map<String, dynamic> json) =>
      _$EmailTemplateRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateRequestToJson(this);
}

/// Email template response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailTemplateResponse {
  EmailTemplate emailTemplate;
  List<EmailTemplate> emailTemplates;

  EmailTemplateResponse({this.emailTemplate, this.emailTemplates});

  factory EmailTemplateResponse.fromJson(Map<String, dynamic> json) =>
      _$EmailTemplateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class EmailUnverifiedOptions {
  bool allowEmailChangeWhenGated;
  UnverifiedBehavior behavior;

  EmailUnverifiedOptions({this.allowEmailChangeWhenGated, this.behavior});

  factory EmailUnverifiedOptions.fromJson(Map<String, dynamic> json) =>
      _$EmailUnverifiedOptionsFromJson(json);
  Map<String, dynamic> toJson() => _$EmailUnverifiedOptionsToJson(this);
}

/// Something that can be enabled and thus also disabled.
///
/// @author Daniel DeGroff
@JsonSerializable()
class Enableable {
  bool enabled;

  Enableable({this.enabled});

  factory Enableable.fromJson(Map<String, dynamic> json) =>
      _$EnableableFromJson(json);
  Map<String, dynamic> toJson() => _$EnableableToJson(this);
}

/// Models an entity that a user can be granted permissions to. Or an entity that can be granted permissions to another entity.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Entity {
  String clientId;
  String clientSecret;
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  String parentId;
  String tenantId;
  EntityType type;

  Entity(
      {this.clientId,
      this.clientSecret,
      this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.parentId,
      this.tenantId,
      this.type});

  factory Entity.fromJson(Map<String, dynamic> json) => _$EntityFromJson(json);
  Map<String, dynamic> toJson() => _$EntityToJson(this);
}

/// A grant for an entity to a user or another entity.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrant {
  Map<String, dynamic> data;
  Entity entity;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  Set<String> permissions;
  String recipientEntityId;
  String userId;

  EntityGrant(
      {this.data,
      this.entity,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.permissions,
      this.recipientEntityId,
      this.userId});

  factory EntityGrant.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantToJson(this);
}

/// Entity grant API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrantRequest {
  EntityGrant grant;

  EntityGrantRequest({this.grant});

  factory EntityGrantRequest.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantRequestToJson(this);
}

/// Entity grant API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrantResponse {
  EntityGrant grant;
  List<EntityGrant> grants;

  EntityGrantResponse({this.grant, this.grants});

  factory EntityGrantResponse.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantResponseToJson(this);
}

/// Search criteria for entity grants.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrantSearchCriteria extends BaseSearchCriteria {
  String entityId;
  String name;
  String userId;

  EntityGrantSearchCriteria({this.entityId, this.name, this.userId});

  factory EntityGrantSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantSearchCriteriaToJson(this);
}

/// Search request for entity grants.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrantSearchRequest {
  EntityGrantSearchCriteria search;

  EntityGrantSearchRequest({this.search});

  factory EntityGrantSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantSearchRequestToJson(this);
}

/// Search request for entity grants.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityGrantSearchResponse {
  List<EntityGrant> grants;
  num total;

  EntityGrantSearchResponse({this.grants, this.total});

  factory EntityGrantSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$EntityGrantSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntityGrantSearchResponseToJson(this);
}

/// JWT Configuration for entities.
@JsonSerializable()
class EntityJWTConfiguration extends Enableable {
  String accessTokenKeyId;
  num timeToLiveInSeconds;

  EntityJWTConfiguration({this.accessTokenKeyId, this.timeToLiveInSeconds});

  factory EntityJWTConfiguration.fromJson(Map<String, dynamic> json) =>
      _$EntityJWTConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EntityJWTConfigurationToJson(this);
}

/// Entity API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityRequest {
  Entity entity;

  EntityRequest({this.entity});

  factory EntityRequest.fromJson(Map<String, dynamic> json) =>
      _$EntityRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntityRequestToJson(this);
}

/// Entity API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityResponse {
  Entity entity;

  EntityResponse({this.entity});

  factory EntityResponse.fromJson(Map<String, dynamic> json) =>
      _$EntityResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntityResponseToJson(this);
}

/// This class is the entity query. It provides a build pattern as well as public fields for use on forms and in actions.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntitySearchCriteria extends BaseElasticSearchCriteria {
  EntitySearchCriteria();

  factory EntitySearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$EntitySearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$EntitySearchCriteriaToJson(this);
}

/// Search request for entities
///
/// @author Brett Guy
@JsonSerializable()
class EntitySearchRequest {
  EntitySearchCriteria search;

  EntitySearchRequest({this.search});

  factory EntitySearchRequest.fromJson(Map<String, dynamic> json) =>
      _$EntitySearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntitySearchRequestToJson(this);
}

/// Search request for entities
///
/// @author Brett Guy
@JsonSerializable()
class EntitySearchResponse {
  List<Entity> entities;
  num total;

  EntitySearchResponse({this.entities, this.total});

  factory EntitySearchResponse.fromJson(Map<String, dynamic> json) =>
      _$EntitySearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntitySearchResponseToJson(this);
}

/// Models an entity type that has a specific set of permissions. These are global objects and can be used across tenants.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityType {
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  EntityJWTConfiguration jwtConfiguration;
  num lastUpdateInstant;
  String name;
  List<EntityTypePermission> permissions;

  EntityType(
      {this.data,
      this.id,
      this.insertInstant,
      this.jwtConfiguration,
      this.lastUpdateInstant,
      this.name,
      this.permissions});

  factory EntityType.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeToJson(this);
}

/// Models a specific entity type permission. This permission can be granted to users or other entities.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypePermission {
  Map<String, dynamic> data;
  String description;
  String id;
  num insertInstant;
  bool isDefault;
  num lastUpdateInstant;
  String name;

  EntityTypePermission(
      {this.data,
      this.description,
      this.id,
      this.insertInstant,
      this.isDefault,
      this.lastUpdateInstant,
      this.name});

  factory EntityTypePermission.fromJson(Map<String, dynamic> json) =>
      _$EntityTypePermissionFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypePermissionToJson(this);
}

/// Entity Type API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypeRequest {
  EntityType entityType;
  EntityTypePermission permission;

  EntityTypeRequest({this.entityType, this.permission});

  factory EntityTypeRequest.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeRequestToJson(this);
}

/// Entity Type API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypeResponse {
  EntityType entityType;
  List<EntityType> entityTypes;
  EntityTypePermission permission;

  EntityTypeResponse({this.entityType, this.entityTypes, this.permission});

  factory EntityTypeResponse.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeResponseToJson(this);
}

/// Search criteria for entity types.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypeSearchCriteria extends BaseSearchCriteria {
  String name;

  EntityTypeSearchCriteria({this.name});

  factory EntityTypeSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeSearchCriteriaToJson(this);
}

/// Search request for entity types.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypeSearchRequest {
  EntityTypeSearchCriteria search;

  EntityTypeSearchRequest({this.search});

  factory EntityTypeSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeSearchRequestToJson(this);
}

/// Search response for entity types.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EntityTypeSearchResponse {
  List<EntityType> entityTypes;
  num total;

  EntityTypeSearchResponse({this.entityTypes, this.total});

  factory EntityTypeSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$EntityTypeSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EntityTypeSearchResponseToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class EpicGamesApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  EpicGamesApplicationConfiguration(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory EpicGamesApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$EpicGamesApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$EpicGamesApplicationConfigurationToJson(this);
}

/// Epic gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class EpicGamesIdentityProvider
    extends BaseIdentityProvider<EpicGamesApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  EpicGamesIdentityProvider(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory EpicGamesIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$EpicGamesIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$EpicGamesIdentityProviderToJson(this);
}

/// Defines an error.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Error {
  String code;
  Map<String, dynamic> data;
  String message;

  Error({this.code, this.data, this.message});

  factory Error.fromJson(Map<String, dynamic> json) => _$ErrorFromJson(json);
  Map<String, dynamic> toJson() => _$ErrorToJson(this);
}

/// Standard error domain object that can also be used as the response from an API call.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Errors {
  Map<String, List<Error>> fieldErrors;
  List<Error> generalErrors;

  Errors({this.fieldErrors, this.generalErrors});

  factory Errors.fromJson(Map<String, dynamic> json) => _$ErrorsFromJson(json);
  Map<String, dynamic> toJson() => _$ErrorsToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EventConfiguration {
  Map<EventType, EventConfigurationData> events;

  EventConfiguration({this.events});

  factory EventConfiguration.fromJson(Map<String, dynamic> json) =>
      _$EventConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EventConfigurationToJson(this);
}

@JsonSerializable()
class EventConfigurationData extends Enableable {
  TransactionType transactionType;

  EventConfigurationData({this.transactionType});

  factory EventConfigurationData.fromJson(Map<String, dynamic> json) =>
      _$EventConfigurationDataFromJson(json);
  Map<String, dynamic> toJson() => _$EventConfigurationDataToJson(this);
}

/// Information about a user event (login, register, etc) that helps identify the source of the event (location, device type, OS, etc).
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventInfo {
  Map<String, dynamic> data;
  String deviceDescription;
  String deviceName;
  String deviceType;
  String ipAddress;
  Location location;
  String os;
  String userAgent;

  EventInfo(
      {this.data,
      this.deviceDescription,
      this.deviceName,
      this.deviceType,
      this.ipAddress,
      this.location,
      this.os,
      this.userAgent});

  factory EventInfo.fromJson(Map<String, dynamic> json) =>
      _$EventInfoFromJson(json);
  Map<String, dynamic> toJson() => _$EventInfoToJson(this);
}

/// Event log used internally by FusionAuth to help developers debug hooks, Webhooks, email templates, etc.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventLog {
  num id;
  num insertInstant;
  String message;
  EventLogType type;

  EventLog({this.id, this.insertInstant, this.message, this.type});

  factory EventLog.fromJson(Map<String, dynamic> json) =>
      _$EventLogFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogToJson(this);
}

@JsonSerializable()
class EventLogConfiguration {
  num numberToRetain;

  EventLogConfiguration({this.numberToRetain});

  factory EventLogConfiguration.fromJson(Map<String, dynamic> json) =>
      _$EventLogConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogConfigurationToJson(this);
}

/// Event event to an event log was created.
///
/// @author Daniel DeGroff
@JsonSerializable()
class EventLogCreateEvent extends BaseEvent {
  EventLog eventLog;

  EventLogCreateEvent({this.eventLog});

  factory EventLogCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$EventLogCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogCreateEventToJson(this);
}

/// Event log response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class EventLogResponse {
  EventLog eventLog;

  EventLogResponse({this.eventLog});

  factory EventLogResponse.fromJson(Map<String, dynamic> json) =>
      _$EventLogResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogResponseToJson(this);
}

/// Search criteria for the event log.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventLogSearchCriteria extends BaseSearchCriteria {
  num end;
  String message;
  num start;
  EventLogType type;

  EventLogSearchCriteria({this.end, this.message, this.start, this.type});

  factory EventLogSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$EventLogSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogSearchCriteriaToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EventLogSearchRequest {
  EventLogSearchCriteria search;

  EventLogSearchRequest({this.search});

  factory EventLogSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$EventLogSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogSearchRequestToJson(this);
}

/// Event log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventLogSearchResponse {
  List<EventLog> eventLogs;
  num total;

  EventLogSearchResponse({this.eventLogs, this.total});

  factory EventLogSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$EventLogSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogSearchResponseToJson(this);
}

/// Event Log Type
///
/// @author Daniel DeGroff
enum EventLogType {
  @JsonValue('Information')
  Information,
  @JsonValue('Debug')
  Debug,
  @JsonValue('Error')
  Error
}

/// Container for the event information. This is the JSON that is sent from FusionAuth to webhooks.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventRequest {
  BaseEvent event;

  EventRequest({this.event});

  factory EventRequest.fromJson(Map<String, dynamic> json) =>
      _$EventRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EventRequestToJson(this);
}

/// Models the event types that FusionAuth produces.
///
/// @author Brian Pontarelli
enum EventType {
  @JsonValue('JWTPublicKeyUpdate')
  JWTPublicKeyUpdate,
  @JsonValue('JWTRefreshTokenRevoke')
  JWTRefreshTokenRevoke,
  @JsonValue('JWTRefresh')
  JWTRefresh,
  @JsonValue('AuditLogCreate')
  AuditLogCreate,
  @JsonValue('EventLogCreate')
  EventLogCreate,
  @JsonValue('KickstartSuccess')
  KickstartSuccess,
  @JsonValue('GroupCreate')
  GroupCreate,
  @JsonValue('GroupCreateComplete')
  GroupCreateComplete,
  @JsonValue('GroupDelete')
  GroupDelete,
  @JsonValue('GroupDeleteComplete')
  GroupDeleteComplete,
  @JsonValue('GroupMemberAdd')
  GroupMemberAdd,
  @JsonValue('GroupMemberAddComplete')
  GroupMemberAddComplete,
  @JsonValue('GroupMemberRemove')
  GroupMemberRemove,
  @JsonValue('GroupMemberRemoveComplete')
  GroupMemberRemoveComplete,
  @JsonValue('GroupMemberUpdate')
  GroupMemberUpdate,
  @JsonValue('GroupMemberUpdateComplete')
  GroupMemberUpdateComplete,
  @JsonValue('GroupUpdate')
  GroupUpdate,
  @JsonValue('GroupUpdateComplete')
  GroupUpdateComplete,
  @JsonValue('UserAction')
  UserAction,
  @JsonValue('UserBulkCreate')
  UserBulkCreate,
  @JsonValue('UserCreate')
  UserCreate,
  @JsonValue('UserCreateComplete')
  UserCreateComplete,
  @JsonValue('UserDeactivate')
  UserDeactivate,
  @JsonValue('UserDelete')
  UserDelete,
  @JsonValue('UserDeleteComplete')
  UserDeleteComplete,
  @JsonValue('UserEmailUpdate')
  UserEmailUpdate,
  @JsonValue('UserEmailVerified')
  UserEmailVerified,
  @JsonValue('UserIdentityProviderLink')
  UserIdentityProviderLink,
  @JsonValue('UserIdentityProviderUnlink')
  UserIdentityProviderUnlink,
  @JsonValue('UserLoginIdDuplicateOnCreate')
  UserLoginIdDuplicateOnCreate,
  @JsonValue('UserLoginIdDuplicateOnUpdate')
  UserLoginIdDuplicateOnUpdate,
  @JsonValue('UserLoginFailed')
  UserLoginFailed,
  @JsonValue('UserLoginNewDevice')
  UserLoginNewDevice,
  @JsonValue('UserLoginSuccess')
  UserLoginSuccess,
  @JsonValue('UserLoginSuspicious')
  UserLoginSuspicious,
  @JsonValue('UserPasswordBreach')
  UserPasswordBreach,
  @JsonValue('UserPasswordResetSend')
  UserPasswordResetSend,
  @JsonValue('UserPasswordResetStart')
  UserPasswordResetStart,
  @JsonValue('UserPasswordResetSuccess')
  UserPasswordResetSuccess,
  @JsonValue('UserPasswordUpdate')
  UserPasswordUpdate,
  @JsonValue('UserReactivate')
  UserReactivate,
  @JsonValue('UserRegistrationCreate')
  UserRegistrationCreate,
  @JsonValue('UserRegistrationCreateComplete')
  UserRegistrationCreateComplete,
  @JsonValue('UserRegistrationDelete')
  UserRegistrationDelete,
  @JsonValue('UserRegistrationDeleteComplete')
  UserRegistrationDeleteComplete,
  @JsonValue('UserRegistrationUpdate')
  UserRegistrationUpdate,
  @JsonValue('UserRegistrationUpdateComplete')
  UserRegistrationUpdateComplete,
  @JsonValue('UserRegistrationVerified')
  UserRegistrationVerified,
  @JsonValue('UserTwoFactorMethodAdd')
  UserTwoFactorMethodAdd,
  @JsonValue('UserTwoFactorMethodRemove')
  UserTwoFactorMethodRemove,
  @JsonValue('UserUpdate')
  UserUpdate,
  @JsonValue('UserUpdateComplete')
  UserUpdateComplete,
  @JsonValue('Test')
  Test
}

/// @author Brian Pontarelli
enum ExpiryUnit {
  @JsonValue('MINUTES')
  MINUTES,
  @JsonValue('HOURS')
  HOURS,
  @JsonValue('DAYS')
  DAYS,
  @JsonValue('WEEKS')
  WEEKS,
  @JsonValue('MONTHS')
  MONTHS,
  @JsonValue('YEARS')
  YEARS
}

/// @author Daniel DeGroff
@JsonSerializable()
class ExternalIdentifierConfiguration {
  num authorizationGrantIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration changePasswordIdGenerator;
  num changePasswordIdTimeToLiveInSeconds;
  num deviceCodeTimeToLiveInSeconds;
  SecureGeneratorConfiguration deviceUserCodeIdGenerator;
  SecureGeneratorConfiguration emailVerificationIdGenerator;
  num emailVerificationIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration emailVerificationOneTimeCodeGenerator;
  num externalAuthenticationIdTimeToLiveInSeconds;
  num oneTimePasswordTimeToLiveInSeconds;
  SecureGeneratorConfiguration passwordlessLoginGenerator;
  num passwordlessLoginTimeToLiveInSeconds;
  num pendingAccountLinkTimeToLiveInSeconds;
  SecureGeneratorConfiguration registrationVerificationIdGenerator;
  num registrationVerificationIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration registrationVerificationOneTimeCodeGenerator;
  num samlv2AuthNRequestIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration setupPasswordIdGenerator;
  num setupPasswordIdTimeToLiveInSeconds;
  num trustTokenTimeToLiveInSeconds;
  num twoFactorIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration twoFactorOneTimeCodeIdGenerator;
  num twoFactorOneTimeCodeIdTimeToLiveInSeconds;
  num twoFactorTrustIdTimeToLiveInSeconds;
  num webAuthnAuthenticationChallenge;
  num webAuthnRegistrationChallenge;

  ExternalIdentifierConfiguration(
      {this.authorizationGrantIdTimeToLiveInSeconds,
      this.changePasswordIdGenerator,
      this.changePasswordIdTimeToLiveInSeconds,
      this.deviceCodeTimeToLiveInSeconds,
      this.deviceUserCodeIdGenerator,
      this.emailVerificationIdGenerator,
      this.emailVerificationIdTimeToLiveInSeconds,
      this.emailVerificationOneTimeCodeGenerator,
      this.externalAuthenticationIdTimeToLiveInSeconds,
      this.oneTimePasswordTimeToLiveInSeconds,
      this.passwordlessLoginGenerator,
      this.passwordlessLoginTimeToLiveInSeconds,
      this.pendingAccountLinkTimeToLiveInSeconds,
      this.registrationVerificationIdGenerator,
      this.registrationVerificationIdTimeToLiveInSeconds,
      this.registrationVerificationOneTimeCodeGenerator,
      this.samlv2AuthNRequestIdTimeToLiveInSeconds,
      this.setupPasswordIdGenerator,
      this.setupPasswordIdTimeToLiveInSeconds,
      this.trustTokenTimeToLiveInSeconds,
      this.twoFactorIdTimeToLiveInSeconds,
      this.twoFactorOneTimeCodeIdGenerator,
      this.twoFactorOneTimeCodeIdTimeToLiveInSeconds,
      this.twoFactorTrustIdTimeToLiveInSeconds,
      this.webAuthnAuthenticationChallenge,
      this.webAuthnRegistrationChallenge});

  factory ExternalIdentifierConfiguration.fromJson(Map<String, dynamic> json) =>
      _$ExternalIdentifierConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ExternalIdentifierConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ExternalJWTApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  ExternalJWTApplicationConfiguration();

  factory ExternalJWTApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$ExternalJWTApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$ExternalJWTApplicationConfigurationToJson(this);
}

/// External JWT-only identity provider.
///
/// @author Daniel DeGroff and Brian Pontarelli
@JsonSerializable()
class ExternalJWTIdentityProvider
    extends BaseIdentityProvider<ExternalJWTApplicationConfiguration> {
  Map<String, String> claimMap;
  String defaultKeyId;
  Set<String> domains;
  String headerKeyParameter;
  IdentityProviderOauth2Configuration oauth2;
  String uniqueIdentityClaim;

  ExternalJWTIdentityProvider(
      {this.claimMap,
      this.defaultKeyId,
      this.domains,
      this.headerKeyParameter,
      this.oauth2,
      this.uniqueIdentityClaim});

  factory ExternalJWTIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$ExternalJWTIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$ExternalJWTIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FacebookApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String appId;
  String buttonText;
  String client_secret;
  String fields;
  IdentityProviderLoginMethod loginMethod;
  String permissions;

  FacebookApplicationConfiguration(
      {this.appId,
      this.buttonText,
      this.client_secret,
      this.fields,
      this.loginMethod,
      this.permissions});

  factory FacebookApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$FacebookApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$FacebookApplicationConfigurationToJson(this);
}

/// Facebook social login provider.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FacebookIdentityProvider
    extends BaseIdentityProvider<FacebookApplicationConfiguration> {
  String appId;
  String buttonText;
  String client_secret;
  String fields;
  IdentityProviderLoginMethod loginMethod;
  String permissions;

  FacebookIdentityProvider(
      {this.appId,
      this.buttonText,
      this.client_secret,
      this.fields,
      this.loginMethod,
      this.permissions});

  factory FacebookIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$FacebookIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$FacebookIdentityProviderToJson(this);
}

/// Configuration for the behavior of failed login attempts. This helps us protect against brute force password attacks.
///
/// @author Daniel DeGroff
@JsonSerializable()
class FailedAuthenticationConfiguration {
  num actionDuration;
  ExpiryUnit actionDurationUnit;
  num resetCountInSeconds;
  num tooManyAttempts;
  String userActionId;

  FailedAuthenticationConfiguration(
      {this.actionDuration,
      this.actionDurationUnit,
      this.resetCountInSeconds,
      this.tooManyAttempts,
      this.userActionId});

  factory FailedAuthenticationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$FailedAuthenticationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$FailedAuthenticationConfigurationToJson(this);
}

/// Models a family grouping of users.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Family {
  String id;
  num insertInstant;
  num lastUpdateInstant;
  List<FamilyMember> members;

  Family({this.id, this.insertInstant, this.lastUpdateInstant, this.members});

  factory Family.fromJson(Map<String, dynamic> json) => _$FamilyFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class FamilyConfiguration extends Enableable {
  bool allowChildRegistrations;
  String confirmChildEmailTemplateId;
  bool deleteOrphanedAccounts;
  num deleteOrphanedAccountsDays;
  String familyRequestEmailTemplateId;
  num maximumChildAge;
  num minimumOwnerAge;
  bool parentEmailRequired;
  String parentRegistrationEmailTemplateId;

  FamilyConfiguration(
      {this.allowChildRegistrations,
      this.confirmChildEmailTemplateId,
      this.deleteOrphanedAccounts,
      this.deleteOrphanedAccountsDays,
      this.familyRequestEmailTemplateId,
      this.maximumChildAge,
      this.minimumOwnerAge,
      this.parentEmailRequired,
      this.parentRegistrationEmailTemplateId});

  factory FamilyConfiguration.fromJson(Map<String, dynamic> json) =>
      _$FamilyConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyConfigurationToJson(this);
}

/// API request for sending out family requests to parent's.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyEmailRequest {
  String parentEmail;

  FamilyEmailRequest({this.parentEmail});

  factory FamilyEmailRequest.fromJson(Map<String, dynamic> json) =>
      _$FamilyEmailRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyEmailRequestToJson(this);
}

/// Models a single family member.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyMember {
  Map<String, dynamic> data;
  num insertInstant;
  num lastUpdateInstant;
  bool owner;
  FamilyRole role;
  String userId;

  FamilyMember(
      {this.data,
      this.insertInstant,
      this.lastUpdateInstant,
      this.owner,
      this.role,
      this.userId});

  factory FamilyMember.fromJson(Map<String, dynamic> json) =>
      _$FamilyMemberFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyMemberToJson(this);
}

/// API request for managing families and members.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyRequest {
  FamilyMember familyMember;

  FamilyRequest({this.familyMember});

  factory FamilyRequest.fromJson(Map<String, dynamic> json) =>
      _$FamilyRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyRequestToJson(this);
}

/// API response for managing families and members.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyResponse {
  List<Family> families;
  Family family;

  FamilyResponse({this.families, this.family});

  factory FamilyResponse.fromJson(Map<String, dynamic> json) =>
      _$FamilyResponseFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyResponseToJson(this);
}

enum FamilyRole {
  @JsonValue('Child')
  Child,
  @JsonValue('Teen')
  Teen,
  @JsonValue('Adult')
  Adult
}

/// Forgot password request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ForgotPasswordRequest extends BaseEventRequest {
  String applicationId;
  String changePasswordId;
  String email;
  String loginId;
  bool sendForgotPasswordEmail;
  Map<String, dynamic> state;
  String username;

  ForgotPasswordRequest(
      {this.applicationId,
      this.changePasswordId,
      this.email,
      this.loginId,
      this.sendForgotPasswordEmail,
      this.state,
      this.username});

  factory ForgotPasswordRequest.fromJson(Map<String, dynamic> json) =>
      _$ForgotPasswordRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ForgotPasswordRequestToJson(this);
}

/// Forgot password response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ForgotPasswordResponse {
  String changePasswordId;

  ForgotPasswordResponse({this.changePasswordId});

  factory ForgotPasswordResponse.fromJson(Map<String, dynamic> json) =>
      _$ForgotPasswordResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ForgotPasswordResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class Form {
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  List<FormStep> steps;
  FormType type;

  Form(
      {this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.steps,
      this.type});

  factory Form.fromJson(Map<String, dynamic> json) => _$FormFromJson(json);
  Map<String, dynamic> toJson() => _$FormToJson(this);
}

/// @author Daniel DeGroff
enum FormControl {
  @JsonValue('checkbox')
  checkbox,
  @JsonValue('number')
  number,
  @JsonValue('password')
  password,
  @JsonValue('radio')
  radio,
  @JsonValue('select')
  select,
  @JsonValue('textarea')
  textarea,
  @JsonValue('text')
  text
}

/// @author Daniel DeGroff
enum FormDataType {
  @JsonValue('bool')
  bool,
  @JsonValue('consent')
  consent,
  @JsonValue('date')
  date,
  @JsonValue('email')
  email,
  @JsonValue('number')
  number,
  @JsonValue('string')
  string
}

/// @author Daniel DeGroff
@JsonSerializable()
class FormField {
  bool confirm;
  String consentId;
  FormControl control;
  Map<String, dynamic> data;
  String description;
  String id;
  num insertInstant;
  String key;
  num lastUpdateInstant;
  String name;
  List<String> options;
  bool required;
  FormDataType type;
  FormFieldValidator validator;

  FormField(
      {this.confirm,
      this.consentId,
      this.control,
      this.data,
      this.description,
      this.id,
      this.insertInstant,
      this.key,
      this.lastUpdateInstant,
      this.name,
      this.options,
      this.required,
      this.type,
      this.validator});

  factory FormField.fromJson(Map<String, dynamic> json) =>
      _$FormFieldFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldToJson(this);
}

/// @author Daniel DeGroff
enum FormFieldAdminPolicy {
  @JsonValue('Edit')
  Edit,
  @JsonValue('View')
  View
}

/// The FormField API request object.
///
/// @author Brett Guy
@JsonSerializable()
class FormFieldRequest {
  FormField field;
  List<FormField> fields;

  FormFieldRequest({this.field, this.fields});

  factory FormFieldRequest.fromJson(Map<String, dynamic> json) =>
      _$FormFieldRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldRequestToJson(this);
}

/// Form field response.
///
/// @author Brett Guy
@JsonSerializable()
class FormFieldResponse {
  FormField field;
  List<FormField> fields;

  FormFieldResponse({this.field, this.fields});

  factory FormFieldResponse.fromJson(Map<String, dynamic> json) =>
      _$FormFieldResponseFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FormFieldValidator extends Enableable {
  String expression;

  FormFieldValidator({this.expression});

  factory FormFieldValidator.fromJson(Map<String, dynamic> json) =>
      _$FormFieldValidatorFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldValidatorToJson(this);
}

/// Form response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class FormRequest {
  Form form;

  FormRequest({this.form});

  factory FormRequest.fromJson(Map<String, dynamic> json) =>
      _$FormRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FormRequestToJson(this);
}

/// Form response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class FormResponse {
  Form form;
  List<Form> forms;

  FormResponse({this.form, this.forms});

  factory FormResponse.fromJson(Map<String, dynamic> json) =>
      _$FormResponseFromJson(json);
  Map<String, dynamic> toJson() => _$FormResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FormStep {
  List<String> fields;

  FormStep({this.fields});

  factory FormStep.fromJson(Map<String, dynamic> json) =>
      _$FormStepFromJson(json);
  Map<String, dynamic> toJson() => _$FormStepToJson(this);
}

/// @author Daniel DeGroff
enum FormType {
  @JsonValue('registration')
  registration,
  @JsonValue('adminRegistration')
  adminRegistration,
  @JsonValue('adminUser')
  adminUser,
  @JsonValue('selfServiceUser')
  selfServiceUser
}

/// Models the FusionAuth connector.
///
/// @author Trevor Smith
@JsonSerializable()
class FusionAuthConnectorConfiguration extends BaseConnectorConfiguration {
  FusionAuthConnectorConfiguration();

  factory FusionAuthConnectorConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$FusionAuthConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$FusionAuthConnectorConfigurationToJson(this);
}

/// Models a generic connector.
///
/// @author Trevor Smith
@JsonSerializable()
class GenericConnectorConfiguration extends BaseConnectorConfiguration {
  String authenticationURL;
  num connectTimeout;
  Map<String, String> headers;
  String httpAuthenticationPassword;
  String httpAuthenticationUsername;
  num readTimeout;
  String sslCertificateKeyId;

  GenericConnectorConfiguration(
      {this.authenticationURL,
      this.connectTimeout,
      this.headers,
      this.httpAuthenticationPassword,
      this.httpAuthenticationUsername,
      this.readTimeout,
      this.sslCertificateKeyId});

  factory GenericConnectorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$GenericConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$GenericConnectorConfigurationToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class GenericMessengerConfiguration extends BaseMessengerConfiguration {
  num connectTimeout;
  Map<String, String> headers;
  String httpAuthenticationPassword;
  String httpAuthenticationUsername;
  num readTimeout;
  String sslCertificate;
  String url;

  GenericMessengerConfiguration(
      {this.connectTimeout,
      this.headers,
      this.httpAuthenticationPassword,
      this.httpAuthenticationUsername,
      this.readTimeout,
      this.sslCertificate,
      this.url});

  factory GenericMessengerConfiguration.fromJson(Map<String, dynamic> json) =>
      _$GenericMessengerConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$GenericMessengerConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class GoogleApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  IdentityProviderLoginMethod loginMethod;
  String scope;

  GoogleApplicationConfiguration(
      {this.buttonText,
      this.client_id,
      this.client_secret,
      this.loginMethod,
      this.scope});

  factory GoogleApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$GoogleApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$GoogleApplicationConfigurationToJson(this);
}

/// Google social login provider.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GoogleIdentityProvider
    extends BaseIdentityProvider<GoogleApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  IdentityProviderLoginMethod loginMethod;
  String scope;

  GoogleIdentityProvider(
      {this.buttonText,
      this.client_id,
      this.client_secret,
      this.loginMethod,
      this.scope});

  factory GoogleIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$GoogleIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$GoogleIdentityProviderToJson(this);
}

/// Authorization Grant types as defined by the <a href="https://tools.ietf.org/html/rfc6749">The OAuth 2.0 Authorization
/// Framework - RFC 6749</a>.
/// <p>
/// Specific names as defined by <a href="https://tools.ietf.org/html/rfc7591#section-4.1">
/// OAuth 2.0 Dynamic Client Registration Protocol - RFC 7591 Section 4.1</a>
///
/// @author Daniel DeGroff
enum GrantType {
  @JsonValue('authorization_code')
  authorization_code,
  @JsonValue('implicit')
  implicit,
  @JsonValue('password')
  password,
  @JsonValue('client_credentials')
  client_credentials,
  @JsonValue('refresh_token')
  refresh_token,
  @JsonValue('unknown')
  unknown,
  @JsonValue('device_code')
  device_code
}

/// @author Tyler Scott
@JsonSerializable()
class Group {
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  Map<String, List<ApplicationRole>> roles;
  String tenantId;

  Group(
      {this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.roles,
      this.tenantId});

  factory Group.fromJson(Map<String, dynamic> json) => _$GroupFromJson(json);
  Map<String, dynamic> toJson() => _$GroupToJson(this);
}

/// Models the Group Created Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupCreateCompleteEvent extends BaseEvent {
  Group group;

  GroupCreateCompleteEvent({this.group});

  factory GroupCreateCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupCreateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupCreateCompleteEventToJson(this);
}

/// Models the Group Create Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupCreateEvent extends BaseEvent {
  Group group;

  GroupCreateEvent({this.group});

  factory GroupCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupCreateEventToJson(this);
}

/// Models the Group Create Complete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupDeleteCompleteEvent extends BaseEvent {
  Group group;

  GroupDeleteCompleteEvent({this.group});

  factory GroupDeleteCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupDeleteCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupDeleteCompleteEventToJson(this);
}

/// Models the Group Delete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupDeleteEvent extends BaseEvent {
  Group group;

  GroupDeleteEvent({this.group});

  factory GroupDeleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupDeleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupDeleteEventToJson(this);
}

/// A User's membership into a Group
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMember {
  Map<String, dynamic> data;
  String groupId;
  String id;
  num insertInstant;
  User user;
  String userId;

  GroupMember(
      {this.data,
      this.groupId,
      this.id,
      this.insertInstant,
      this.user,
      this.userId});

  factory GroupMember.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberToJson(this);
}

/// Models the Group Member Add Complete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberAddCompleteEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberAddCompleteEvent({this.group, this.members});

  factory GroupMemberAddCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberAddCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberAddCompleteEventToJson(this);
}

/// Models the Group Member Add Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberAddEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberAddEvent({this.group, this.members});

  factory GroupMemberAddEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberAddEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberAddEventToJson(this);
}

/// Models the Group Member Remove Complete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberRemoveCompleteEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberRemoveCompleteEvent({this.group, this.members});

  factory GroupMemberRemoveCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberRemoveCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberRemoveCompleteEventToJson(this);
}

/// Models the Group Member Remove Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberRemoveEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberRemoveEvent({this.group, this.members});

  factory GroupMemberRemoveEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberRemoveEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberRemoveEventToJson(this);
}

/// Search criteria for Group Members
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberSearchCriteria extends BaseSearchCriteria {
  String groupId;
  String tenantId;
  String userId;

  GroupMemberSearchCriteria({this.groupId, this.tenantId, this.userId});

  factory GroupMemberSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberSearchCriteriaToJson(this);
}

/// Search request for Group Members.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberSearchRequest {
  GroupMemberSearchCriteria search;

  GroupMemberSearchRequest({this.search});

  factory GroupMemberSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberSearchRequestToJson(this);
}

/// Search response for Group Members
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberSearchResponse {
  List<GroupMember> members;
  num total;

  GroupMemberSearchResponse({this.members, this.total});

  factory GroupMemberSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberSearchResponseToJson(this);
}

/// Models the Group Member Update Complete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberUpdateCompleteEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberUpdateCompleteEvent({this.group, this.members});

  factory GroupMemberUpdateCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberUpdateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberUpdateCompleteEventToJson(this);
}

/// Models the Group Member Update Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupMemberUpdateEvent extends BaseEvent {
  Group group;
  List<GroupMember> members;

  GroupMemberUpdateEvent({this.group, this.members});

  factory GroupMemberUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupMemberUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberUpdateEventToJson(this);
}

/// Group API request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupRequest {
  Group group;
  List<String> roleIds;

  GroupRequest({this.group, this.roleIds});

  factory GroupRequest.fromJson(Map<String, dynamic> json) =>
      _$GroupRequestFromJson(json);
  Map<String, dynamic> toJson() => _$GroupRequestToJson(this);
}

/// Group API response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupResponse {
  Group group;
  List<Group> groups;

  GroupResponse({this.group, this.groups});

  factory GroupResponse.fromJson(Map<String, dynamic> json) =>
      _$GroupResponseFromJson(json);
  Map<String, dynamic> toJson() => _$GroupResponseToJson(this);
}

/// Search criteria for Groups
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupSearchCriteria extends BaseSearchCriteria {
  String name;
  String tenantId;

  GroupSearchCriteria({this.name, this.tenantId});

  factory GroupSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$GroupSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$GroupSearchCriteriaToJson(this);
}

/// Search request for Groups.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupSearchRequest {
  GroupSearchCriteria search;

  GroupSearchRequest({this.search});

  factory GroupSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$GroupSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$GroupSearchRequestToJson(this);
}

/// Search response for Groups
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupSearchResponse {
  List<Group> groups;
  num total;

  GroupSearchResponse({this.groups, this.total});

  factory GroupSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$GroupSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$GroupSearchResponseToJson(this);
}

/// Models the Group Update Complete Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupUpdateCompleteEvent extends BaseEvent {
  Group group;
  Group original;

  GroupUpdateCompleteEvent({this.group, this.original});

  factory GroupUpdateCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupUpdateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupUpdateCompleteEventToJson(this);
}

/// Models the Group Update Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupUpdateEvent extends BaseEvent {
  Group group;
  Group original;

  GroupUpdateEvent({this.group, this.original});

  factory GroupUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$GroupUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$GroupUpdateEventToJson(this);
}

@JsonSerializable()
class HistoryItem {
  String actionerUserId;
  String comment;
  num createInstant;
  num expiry;

  HistoryItem(
      {this.actionerUserId, this.comment, this.createInstant, this.expiry});

  factory HistoryItem.fromJson(Map<String, dynamic> json) =>
      _$HistoryItemFromJson(json);
  Map<String, dynamic> toJson() => _$HistoryItemToJson(this);
}

/// @author Daniel DeGroff
enum HTTPMethod {
  @JsonValue('GET')
  GET,
  @JsonValue('POST')
  POST,
  @JsonValue('PUT')
  PUT,
  @JsonValue('DELETE')
  DELETE,
  @JsonValue('HEAD')
  HEAD,
  @JsonValue('OPTIONS')
  OPTIONS,
  @JsonValue('PATCH')
  PATCH
}

/// @author Daniel DeGroff
@JsonSerializable()
class HYPRApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String relyingPartyApplicationId;
  String relyingPartyURL;

  HYPRApplicationConfiguration(
      {this.relyingPartyApplicationId, this.relyingPartyURL});

  factory HYPRApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$HYPRApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$HYPRApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class HYPRIdentityProvider
    extends BaseIdentityProvider<HYPRApplicationConfiguration> {
  String relyingPartyApplicationId;
  String relyingPartyURL;

  HYPRIdentityProvider({this.relyingPartyApplicationId, this.relyingPartyURL});

  factory HYPRIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$HYPRIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$HYPRIdentityProviderToJson(this);
}

@JsonSerializable()
class IdentityProviderDetails {
  List<String> applicationIds;
  String id;
  String idpEndpoint;
  String name;
  IdentityProviderOauth2Configuration oauth2;
  IdentityProviderType type;

  IdentityProviderDetails(
      {this.applicationIds,
      this.id,
      this.idpEndpoint,
      this.name,
      this.oauth2,
      this.type});

  factory IdentityProviderDetails.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderDetailsFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderDetailsToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderLimitUserLinkingPolicy extends Enableable {
  num maximumLinks;

  IdentityProviderLimitUserLinkingPolicy({this.maximumLinks});

  factory IdentityProviderLimitUserLinkingPolicy.fromJson(
          Map<String, dynamic> json) =>
      _$IdentityProviderLimitUserLinkingPolicyFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IdentityProviderLimitUserLinkingPolicyToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderLink {
  Map<String, dynamic> data;
  String displayName;
  String identityProviderId;
  String identityProviderUserId;
  num insertInstant;
  num lastLoginInstant;
  String tenantId;
  String token;
  String userId;

  IdentityProviderLink(
      {this.data,
      this.displayName,
      this.identityProviderId,
      this.identityProviderUserId,
      this.insertInstant,
      this.lastLoginInstant,
      this.tenantId,
      this.token,
      this.userId});

  factory IdentityProviderLink.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderLinkFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderLinkToJson(this);
}

/// The IdP behavior when no user link has been made yet.
///
/// @author Daniel DeGroff
enum IdentityProviderLinkingStrategy {
  @JsonValue('CreatePendingLink')
  CreatePendingLink,
  @JsonValue('Disabled')
  Disabled,
  @JsonValue('LinkAnonymously')
  LinkAnonymously,
  @JsonValue('LinkByEmail')
  LinkByEmail,
  @JsonValue('LinkByEmailForExistingUser')
  LinkByEmailForExistingUser,
  @JsonValue('LinkByUsername')
  LinkByUsername,
  @JsonValue('LinkByUsernameForExistingUser')
  LinkByUsernameForExistingUser,
  @JsonValue('Unsupported')
  Unsupported
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderLinkRequest extends BaseEventRequest {
  String displayName;
  String identityProviderId;
  String identityProviderUserId;
  String pendingIdPLinkId;
  String userId;

  IdentityProviderLinkRequest(
      {this.displayName,
      this.identityProviderId,
      this.identityProviderUserId,
      this.pendingIdPLinkId,
      this.userId});

  factory IdentityProviderLinkRequest.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderLinkRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderLinkRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderLinkResponse {
  IdentityProviderLink identityProviderLink;
  List<IdentityProviderLink> identityProviderLinks;

  IdentityProviderLinkResponse(
      {this.identityProviderLink, this.identityProviderLinks});

  factory IdentityProviderLinkResponse.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderLinkResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderLinkResponseToJson(this);
}

/// @author Brett Pontarelli
enum IdentityProviderLoginMethod {
  @JsonValue('UsePopup')
  UsePopup,
  @JsonValue('UseRedirect')
  UseRedirect
}

/// Login API request object used for login to third-party systems (i.e. Login with Facebook).
///
/// @author Brian Pontarelli
@JsonSerializable()
class IdentityProviderLoginRequest extends BaseLoginRequest {
  Map<String, String> data;
  String encodedJWT;
  String identityProviderId;
  bool noLink;

  IdentityProviderLoginRequest(
      {this.data, this.encodedJWT, this.identityProviderId, this.noLink});

  factory IdentityProviderLoginRequest.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderOauth2Configuration {
  String authorization_endpoint;
  String client_id;
  String client_secret;
  ClientAuthenticationMethod clientAuthenticationMethod;
  String emailClaim;
  String issuer;
  String scope;
  String token_endpoint;
  String uniqueIdClaim;
  String userinfo_endpoint;
  String usernameClaim;

  IdentityProviderOauth2Configuration(
      {this.authorization_endpoint,
      this.client_id,
      this.client_secret,
      this.clientAuthenticationMethod,
      this.emailClaim,
      this.issuer,
      this.scope,
      this.token_endpoint,
      this.uniqueIdClaim,
      this.userinfo_endpoint,
      this.usernameClaim});

  factory IdentityProviderOauth2Configuration.fromJson(
          Map<String, dynamic> json) =>
      _$IdentityProviderOauth2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IdentityProviderOauth2ConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderRequest {
  @IdentityProviderConverter()
  BaseIdentityProvider<dynamic> identityProvider;

  IdentityProviderRequest({this.identityProvider});

  factory IdentityProviderRequest.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderResponse {
  @IdentityProviderConverter()
  BaseIdentityProvider<dynamic> identityProvider;
  List<BaseIdentityProvider<dynamic>> identityProviders;

  IdentityProviderResponse({this.identityProvider, this.identityProviders});

  factory IdentityProviderResponse.fromJson(Map<String, dynamic> json) =>
      _$IdentityProviderResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderStartLoginRequest extends BaseLoginRequest {
  Map<String, String> data;
  String identityProviderId;
  String loginId;
  Map<String, dynamic> state;

  IdentityProviderStartLoginRequest(
      {this.data, this.identityProviderId, this.loginId, this.state});

  factory IdentityProviderStartLoginRequest.fromJson(
          Map<String, dynamic> json) =>
      _$IdentityProviderStartLoginRequestFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IdentityProviderStartLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderStartLoginResponse {
  String code;

  IdentityProviderStartLoginResponse({this.code});

  factory IdentityProviderStartLoginResponse.fromJson(
          Map<String, dynamic> json) =>
      _$IdentityProviderStartLoginResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IdentityProviderStartLoginResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderTenantConfiguration {
  Map<String, dynamic> data;
  IdentityProviderLimitUserLinkingPolicy limitUserLinkCount;

  IdentityProviderTenantConfiguration({this.data, this.limitUserLinkCount});

  factory IdentityProviderTenantConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$IdentityProviderTenantConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IdentityProviderTenantConfigurationToJson(this);
}

/// @author Daniel DeGroff
enum IdentityProviderType {
  @JsonValue('Apple')
  Apple,
  @JsonValue('EpicGames')
  EpicGames,
  @JsonValue('ExternalJWT')
  ExternalJWT,
  @JsonValue('Facebook')
  Facebook,
  @JsonValue('Google')
  Google,
  @JsonValue('HYPR')
  HYPR,
  @JsonValue('LinkedIn')
  LinkedIn,
  @JsonValue('Nintendo')
  Nintendo,
  @JsonValue('OpenIDConnect')
  OpenIDConnect,
  @JsonValue('SAMLv2')
  SAMLv2,
  @JsonValue('SAMLv2IdPInitiated')
  SAMLv2IdPInitiated,
  @JsonValue('SonyPSN')
  SonyPSN,
  @JsonValue('Steam')
  Steam,
  @JsonValue('Twitch')
  Twitch,
  @JsonValue('Twitter')
  Twitter,
  @JsonValue('Xbox')
  Xbox
}

/// Import request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ImportRequest extends BaseEventRequest {
  String encryptionScheme;
  num factor;
  List<User> users;
  bool validateDbConstraints;

  ImportRequest(
      {this.encryptionScheme,
      this.factor,
      this.users,
      this.validateDbConstraints});

  factory ImportRequest.fromJson(Map<String, dynamic> json) =>
      _$ImportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ImportRequestToJson(this);
}

/// A marker interface indicating this event is not scoped to a tenant and will be sent to all webhooks.
///
/// @author Daniel DeGroff
@JsonSerializable()
class InstanceEvent extends NonTransactionalEvent {
  InstanceEvent();

  factory InstanceEvent.fromJson(Map<String, dynamic> json) =>
      _$InstanceEventFromJson(json);
  Map<String, dynamic> toJson() => _$InstanceEventToJson(this);
}

/// The Integration Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class IntegrationRequest {
  Integrations integrations;

  IntegrationRequest({this.integrations});

  factory IntegrationRequest.fromJson(Map<String, dynamic> json) =>
      _$IntegrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationRequestToJson(this);
}

/// The Integration Response
///
/// @author Daniel DeGroff
@JsonSerializable()
class IntegrationResponse {
  Integrations integrations;

  IntegrationResponse({this.integrations});

  factory IntegrationResponse.fromJson(Map<String, dynamic> json) =>
      _$IntegrationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationResponseToJson(this);
}

/// Available Integrations
///
/// @author Daniel DeGroff
@JsonSerializable()
class Integrations {
  CleanSpeakConfiguration cleanspeak;
  KafkaConfiguration kafka;

  Integrations({this.cleanspeak, this.kafka});

  factory Integrations.fromJson(Map<String, dynamic> json) =>
      _$IntegrationsFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationsToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlEntry {
  IPAccessControlEntryAction action;
  String endIPAddress;
  String startIPAddress;

  IPAccessControlEntry({this.action, this.endIPAddress, this.startIPAddress});

  factory IPAccessControlEntry.fromJson(Map<String, dynamic> json) =>
      _$IPAccessControlEntryFromJson(json);
  Map<String, dynamic> toJson() => _$IPAccessControlEntryToJson(this);
}

/// @author Brett Guy
enum IPAccessControlEntryAction {
  @JsonValue('Allow')
  Allow,
  @JsonValue('Block')
  Block
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlList {
  Map<String, dynamic> data;
  List<IPAccessControlEntry> entries;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;

  IPAccessControlList(
      {this.data,
      this.entries,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name});

  factory IPAccessControlList.fromJson(Map<String, dynamic> json) =>
      _$IPAccessControlListFromJson(json);
  Map<String, dynamic> toJson() => _$IPAccessControlListToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlListRequest {
  IPAccessControlList ipAccessControlList;

  IPAccessControlListRequest({this.ipAccessControlList});

  factory IPAccessControlListRequest.fromJson(Map<String, dynamic> json) =>
      _$IPAccessControlListRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IPAccessControlListRequestToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlListResponse {
  IPAccessControlList ipAccessControlList;
  List<IPAccessControlList> ipAccessControlLists;

  IPAccessControlListResponse(
      {this.ipAccessControlList, this.ipAccessControlLists});

  factory IPAccessControlListResponse.fromJson(Map<String, dynamic> json) =>
      _$IPAccessControlListResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IPAccessControlListResponseToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlListSearchCriteria extends BaseSearchCriteria {
  String name;

  IPAccessControlListSearchCriteria({this.name});

  factory IPAccessControlListSearchCriteria.fromJson(
          Map<String, dynamic> json) =>
      _$IPAccessControlListSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IPAccessControlListSearchCriteriaToJson(this);
}

/// Search request for IP ACLs .
///
/// @author Brett Guy
@JsonSerializable()
class IPAccessControlListSearchRequest {
  IPAccessControlListSearchCriteria search;

  IPAccessControlListSearchRequest({this.search});

  factory IPAccessControlListSearchRequest.fromJson(
          Map<String, dynamic> json) =>
      _$IPAccessControlListSearchRequestFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IPAccessControlListSearchRequestToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class IPAccessControlListSearchResponse {
  List<IPAccessControlList> ipAccessControlLists;
  num total;

  IPAccessControlListSearchResponse({this.ipAccessControlLists, this.total});

  factory IPAccessControlListSearchResponse.fromJson(
          Map<String, dynamic> json) =>
      _$IPAccessControlListSearchResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$IPAccessControlListSearchResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IssueResponse {
  String refreshToken;
  String token;

  IssueResponse({this.refreshToken, this.token});

  factory IssueResponse.fromJson(Map<String, dynamic> json) =>
      _$IssueResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IssueResponseToJson(this);
}

/// A JSON Web Key as defined by <a href="https://tools.ietf.org/html/rfc7517#section-4">RFC 7517 JSON Web Key (JWK)
/// Section 4</a> and <a href="https://tools.ietf.org/html/rfc7518">RFC 7518 JSON Web Algorithms (JWA)</a>.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JSONWebKey {
  Algorithm alg;
  String crv;
  String d;
  String dp;
  String dq;
  String e;
  String kid;
  KeyType kty;
  String n;
  final Map<String, dynamic> _other = Map<String, dynamic>();
  dynamic operator [](String index) => _other[index]; // Get any other fields
  void operator []=(String index, dynamic value) =>
      _other[index] = value; // Set any other fields
  String p;
  String q;
  String qi;
  String use;
  String x;
  List<String> x5c;
  String x5t;
  @JsonKey(name: 'x5t#S256')
  String x5t_S256;
  String y;

  JSONWebKey(
      {this.alg,
      this.crv,
      this.d,
      this.dp,
      this.dq,
      this.e,
      this.kid,
      this.kty,
      this.n,
      this.p,
      this.q,
      this.qi,
      this.use,
      this.x,
      this.x5c,
      this.x5t,
      this.x5t_S256,
      this.y});

  factory JSONWebKey.fromJson(Map<String, dynamic> json) =>
      _$JSONWebKeyFromJson(json);
  Map<String, dynamic> toJson() => _$JSONWebKeyToJson(this);
}

/// Interface for any object that can provide JSON Web key Information.
@JsonSerializable()
class JSONWebKeyInfoProvider {
  JSONWebKeyInfoProvider();

  factory JSONWebKeyInfoProvider.fromJson(Map<String, dynamic> json) =>
      _$JSONWebKeyInfoProviderFromJson(json);
  Map<String, dynamic> toJson() => _$JSONWebKeyInfoProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class JWKSResponse {
  List<JSONWebKey> keys;

  JWKSResponse({this.keys});

  factory JWKSResponse.fromJson(Map<String, dynamic> json) =>
      _$JWKSResponseFromJson(json);
  Map<String, dynamic> toJson() => _$JWKSResponseToJson(this);
}

/// JSON Web Token (JWT) as defined by RFC 7519.
/// <pre>
/// From RFC 7519 Section 1. Introduction:
///    The suggested pronunciation of JWT is the same as the English word "jot".
/// </pre>
/// The JWT is not Thread-Safe and should not be re-used.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JWT {
  dynamic aud;
  num exp;
  num iat;
  String iss;
  String jti;
  num nbf;
  final Map<String, dynamic> _otherClaims = Map<String, dynamic>();
  dynamic operator [](String index) =>
      _otherClaims[index]; // Get any other fields
  void operator []=(String index, dynamic value) =>
      _otherClaims[index] = value; // Set any other fields
  String sub;

  JWT({this.aud, this.exp, this.iat, this.iss, this.jti, this.nbf, this.sub});

  factory JWT.fromJson(Map<String, dynamic> json) => _$JWTFromJson(json);
  Map<String, dynamic> toJson() => _$JWTToJson(this);
}

/// JWT Configuration. A JWT Configuration for an Application may not be active if it is using the global configuration, the configuration
/// may be <code>enabled = false</code>.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JWTConfiguration extends Enableable {
  String accessTokenKeyId;
  String idTokenKeyId;
  RefreshTokenExpirationPolicy refreshTokenExpirationPolicy;
  RefreshTokenRevocationPolicy refreshTokenRevocationPolicy;
  num refreshTokenTimeToLiveInMinutes;
  RefreshTokenUsagePolicy refreshTokenUsagePolicy;
  num timeToLiveInSeconds;

  JWTConfiguration(
      {this.accessTokenKeyId,
      this.idTokenKeyId,
      this.refreshTokenExpirationPolicy,
      this.refreshTokenRevocationPolicy,
      this.refreshTokenTimeToLiveInMinutes,
      this.refreshTokenUsagePolicy,
      this.timeToLiveInSeconds});

  factory JWTConfiguration.fromJson(Map<String, dynamic> json) =>
      _$JWTConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$JWTConfigurationToJson(this);
}

/// Models the JWT public key Refresh Token Revoke Event. This event might be for a single
/// token, a user or an entire application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class JWTPublicKeyUpdateEvent extends BaseEvent {
  Set<String> applicationIds;

  JWTPublicKeyUpdateEvent({this.applicationIds});

  factory JWTPublicKeyUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$JWTPublicKeyUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$JWTPublicKeyUpdateEventToJson(this);
}

/// Models the JWT Refresh Event. This event will be fired when a JWT is "refreshed" (generated) using a Refresh Token.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JWTRefreshEvent extends BaseEvent {
  String applicationId;
  String original;
  String refreshToken;
  String token;
  String userId;

  JWTRefreshEvent(
      {this.applicationId,
      this.original,
      this.refreshToken,
      this.token,
      this.userId});

  factory JWTRefreshEvent.fromJson(Map<String, dynamic> json) =>
      _$JWTRefreshEventFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshEventToJson(this);
}

/// API response for refreshing a JWT with a Refresh Token.
/// <p>
/// Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a
/// string.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JWTRefreshResponse {
  String refreshToken;
  String refreshTokenId;
  String token;

  JWTRefreshResponse({this.refreshToken, this.refreshTokenId, this.token});

  factory JWTRefreshResponse.fromJson(Map<String, dynamic> json) =>
      _$JWTRefreshResponseFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshResponseToJson(this);
}

/// Models the Refresh Token Revoke Event. This event might be for a single token, a user
/// or an entire application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class JWTRefreshTokenRevokeEvent extends BaseEvent {
  String applicationId;
  Map<String, num> applicationTimeToLiveInSeconds;
  RefreshToken refreshToken;
  User user;
  String userId;

  JWTRefreshTokenRevokeEvent(
      {this.applicationId,
      this.applicationTimeToLiveInSeconds,
      this.refreshToken,
      this.user,
      this.userId});

  factory JWTRefreshTokenRevokeEvent.fromJson(Map<String, dynamic> json) =>
      _$JWTRefreshTokenRevokeEventFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshTokenRevokeEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class JWTVendRequest {
  Map<String, dynamic> claims;
  String keyId;
  num timeToLiveInSeconds;

  JWTVendRequest({this.claims, this.keyId, this.timeToLiveInSeconds});

  factory JWTVendRequest.fromJson(Map<String, dynamic> json) =>
      _$JWTVendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$JWTVendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class JWTVendResponse {
  String token;

  JWTVendResponse({this.token});

  factory JWTVendResponse.fromJson(Map<String, dynamic> json) =>
      _$JWTVendResponseFromJson(json);
  Map<String, dynamic> toJson() => _$JWTVendResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class KafkaConfiguration extends Enableable {
  String defaultTopic;
  Map<String, String> producer;

  KafkaConfiguration({this.defaultTopic, this.producer});

  factory KafkaConfiguration.fromJson(Map<String, dynamic> json) =>
      _$KafkaConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$KafkaConfigurationToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class KafkaMessengerConfiguration extends BaseMessengerConfiguration {
  String defaultTopic;
  Map<String, String> producer;

  KafkaMessengerConfiguration({this.defaultTopic, this.producer});

  factory KafkaMessengerConfiguration.fromJson(Map<String, dynamic> json) =>
      _$KafkaMessengerConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$KafkaMessengerConfigurationToJson(this);
}

/// Domain for a public key, key pair or an HMAC secret. This is used by KeyMaster to manage keys for JWTs, SAML, etc.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Key {
  KeyAlgorithm algorithm;
  String certificate;
  CertificateInformation certificateInformation;
  num expirationInstant;
  bool hasPrivateKey;
  String id;
  num insertInstant;
  String issuer;
  String kid;
  num lastUpdateInstant;
  num length;
  String name;
  String privateKey;
  String publicKey;
  String secret;
  KeyType type;

  Key(
      {this.algorithm,
      this.certificate,
      this.certificateInformation,
      this.expirationInstant,
      this.hasPrivateKey,
      this.id,
      this.insertInstant,
      this.issuer,
      this.kid,
      this.lastUpdateInstant,
      this.length,
      this.name,
      this.privateKey,
      this.publicKey,
      this.secret,
      this.type});

  factory Key.fromJson(Map<String, dynamic> json) => _$KeyFromJson(json);
  Map<String, dynamic> toJson() => _$KeyToJson(this);
}

enum KeyAlgorithm {
  @JsonValue('ES256')
  ES256,
  @JsonValue('ES384')
  ES384,
  @JsonValue('ES512')
  ES512,
  @JsonValue('HS256')
  HS256,
  @JsonValue('HS384')
  HS384,
  @JsonValue('HS512')
  HS512,
  @JsonValue('RS256')
  RS256,
  @JsonValue('RS384')
  RS384,
  @JsonValue('RS512')
  RS512
}

/// Key API request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class KeyRequest {
  Key key;

  KeyRequest({this.key});

  factory KeyRequest.fromJson(Map<String, dynamic> json) =>
      _$KeyRequestFromJson(json);
  Map<String, dynamic> toJson() => _$KeyRequestToJson(this);
}

/// Key API response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class KeyResponse {
  Key key;
  List<Key> keys;

  KeyResponse({this.key, this.keys});

  factory KeyResponse.fromJson(Map<String, dynamic> json) =>
      _$KeyResponseFromJson(json);
  Map<String, dynamic> toJson() => _$KeyResponseToJson(this);
}

enum KeyType {
  @JsonValue('EC')
  EC,
  @JsonValue('RSA')
  RSA,
  @JsonValue('HMAC')
  HMAC
}

/// The use type of a key.
///
/// @author Daniel DeGroff
enum KeyUse {
  @JsonValue('SignOnly')
  SignOnly,
  @JsonValue('SignAndVerify')
  SignAndVerify,
  @JsonValue('VerifyOnly')
  VerifyOnly
}

/// Event event to indicate kickstart has been successfully completed.
///
/// @author Daniel DeGroff
@JsonSerializable()
class KickstartSuccessEvent extends BaseEvent {
  String instanceId;

  KickstartSuccessEvent({this.instanceId});

  factory KickstartSuccessEvent.fromJson(Map<String, dynamic> json) =>
      _$KickstartSuccessEventFromJson(json);
  Map<String, dynamic> toJson() => _$KickstartSuccessEventToJson(this);
}

/// A JavaScript lambda function that is executed during certain events inside FusionAuth.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Lambda {
  String body;
  bool debug;
  LambdaEngineType engineType;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  LambdaType type;

  Lambda(
      {this.body,
      this.debug,
      this.engineType,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.type});

  factory Lambda.fromJson(Map<String, dynamic> json) => _$LambdaFromJson(json);
  Map<String, dynamic> toJson() => _$LambdaToJson(this);
}

/// @author Daniel DeGroff
enum LambdaEngineType {
  @JsonValue('GraalJS')
  GraalJS,
  @JsonValue('Nashorn')
  Nashorn
}

/// Lambda API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LambdaRequest {
  Lambda lambda;

  LambdaRequest({this.lambda});

  factory LambdaRequest.fromJson(Map<String, dynamic> json) =>
      _$LambdaRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LambdaRequestToJson(this);
}

/// Lambda API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LambdaResponse {
  Lambda lambda;
  List<Lambda> lambdas;

  LambdaResponse({this.lambda, this.lambdas});

  factory LambdaResponse.fromJson(Map<String, dynamic> json) =>
      _$LambdaResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LambdaResponseToJson(this);
}

/// The types of lambdas that indicate how they are invoked by FusionAuth.
///
/// @author Brian Pontarelli
enum LambdaType {
  @JsonValue('JWTPopulate')
  JWTPopulate,
  @JsonValue('OpenIDReconcile')
  OpenIDReconcile,
  @JsonValue('SAMLv2Reconcile')
  SAMLv2Reconcile,
  @JsonValue('SAMLv2Populate')
  SAMLv2Populate,
  @JsonValue('AppleReconcile')
  AppleReconcile,
  @JsonValue('ExternalJWTReconcile')
  ExternalJWTReconcile,
  @JsonValue('FacebookReconcile')
  FacebookReconcile,
  @JsonValue('GoogleReconcile')
  GoogleReconcile,
  @JsonValue('HYPRReconcile')
  HYPRReconcile,
  @JsonValue('TwitterReconcile')
  TwitterReconcile,
  @JsonValue('LDAPConnectorReconcile')
  LDAPConnectorReconcile,
  @JsonValue('LinkedInReconcile')
  LinkedInReconcile,
  @JsonValue('EpicGamesReconcile')
  EpicGamesReconcile,
  @JsonValue('NintendoReconcile')
  NintendoReconcile,
  @JsonValue('SonyPSNReconcile')
  SonyPSNReconcile,
  @JsonValue('SteamReconcile')
  SteamReconcile,
  @JsonValue('TwitchReconcile')
  TwitchReconcile,
  @JsonValue('XboxReconcile')
  XboxReconcile,
  @JsonValue('ClientCredentialsJWTPopulate')
  ClientCredentialsJWTPopulate,
  @JsonValue('SCIMServerGroupRequestConverter')
  SCIMServerGroupRequestConverter,
  @JsonValue('SCIMServerGroupResponseConverter')
  SCIMServerGroupResponseConverter,
  @JsonValue('SCIMServerUserRequestConverter')
  SCIMServerUserRequestConverter,
  @JsonValue('SCIMServerUserResponseConverter')
  SCIMServerUserResponseConverter
}

/// Models an LDAP connector.
///
/// @author Trevor Smith
@JsonSerializable()
class LDAPConnectorConfiguration extends BaseConnectorConfiguration {
  String authenticationURL;
  String baseStructure;
  num connectTimeout;
  String identifyingAttribute;
  dynamic lambdaConfiguration;
  String loginIdAttribute;
  num readTimeout;
  List<String> requestedAttributes;
  LDAPSecurityMethod securityMethod;
  String systemAccountDN;
  String systemAccountPassword;

  LDAPConnectorConfiguration(
      {this.authenticationURL,
      this.baseStructure,
      this.connectTimeout,
      this.identifyingAttribute,
      this.lambdaConfiguration,
      this.loginIdAttribute,
      this.readTimeout,
      this.requestedAttributes,
      this.securityMethod,
      this.systemAccountDN,
      this.systemAccountPassword});

  factory LDAPConnectorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$LDAPConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LDAPConnectorConfigurationToJson(this);
}

enum LDAPSecurityMethod {
  @JsonValue('None')
  None,
  @JsonValue('LDAPS')
  LDAPS,
  @JsonValue('StartTLS')
  StartTLS
}

/// @author Daniel DeGroff
@JsonSerializable()
class LinkedInApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  LinkedInApplicationConfiguration(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory LinkedInApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$LinkedInApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$LinkedInApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LinkedInIdentityProvider
    extends BaseIdentityProvider<LinkedInApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  LinkedInIdentityProvider(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory LinkedInIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$LinkedInIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$LinkedInIdentityProviderToJson(this);
}

/// Location information. Useful for IP addresses and other displayable data objects.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Location {
  String city;
  String country;
  String displayString;
  num latitude;
  num longitude;
  String region;
  String zipcode;

  Location(
      {this.city,
      this.country,
      this.displayString,
      this.latitude,
      this.longitude,
      this.region,
      this.zipcode});

  factory Location.fromJson(Map<String, dynamic> json) =>
      _$LocationFromJson(json);
  Map<String, dynamic> toJson() => _$LocationToJson(this);
}

/// A historical state of a user log event. Since events can be modified, this stores the historical state.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LogHistory {
  List<HistoryItem> historyItems;

  LogHistory({this.historyItems});

  factory LogHistory.fromJson(Map<String, dynamic> json) =>
      _$LogHistoryFromJson(json);
  Map<String, dynamic> toJson() => _$LogHistoryToJson(this);
}

@JsonSerializable()
class LoginConfiguration {
  bool allowTokenRefresh;
  bool generateRefreshTokens;
  bool requireAuthentication;

  LoginConfiguration(
      {this.allowTokenRefresh,
      this.generateRefreshTokens,
      this.requireAuthentication});

  factory LoginConfiguration.fromJson(Map<String, dynamic> json) =>
      _$LoginConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LoginConfigurationToJson(this);
}

enum LoginIdType {
  @JsonValue('email')
  email,
  @JsonValue('username')
  username
}

/// Login Ping API request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class LoginPingRequest extends BaseLoginRequest {
  String userId;

  LoginPingRequest({this.userId});

  factory LoginPingRequest.fromJson(Map<String, dynamic> json) =>
      _$LoginPingRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginPingRequestToJson(this);
}

/// The summary of the action that is preventing login to be returned on the login response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class LoginPreventedResponse {
  String actionerUserId;
  String actionId;
  num expiry;
  String localizedName;
  String localizedOption;
  String localizedReason;
  String name;
  String option;
  String reason;
  String reasonCode;

  LoginPreventedResponse(
      {this.actionerUserId,
      this.actionId,
      this.expiry,
      this.localizedName,
      this.localizedOption,
      this.localizedReason,
      this.name,
      this.option,
      this.reason,
      this.reasonCode});

  factory LoginPreventedResponse.fromJson(Map<String, dynamic> json) =>
      _$LoginPreventedResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginPreventedResponseToJson(this);
}

@JsonSerializable()
class LoginRecordConfiguration {
  DeleteConfiguration delete;

  LoginRecordConfiguration({this.delete});

  factory LoginRecordConfiguration.fromJson(Map<String, dynamic> json) =>
      _$LoginRecordConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordExportRequest extends BaseExportRequest {
  LoginRecordSearchCriteria criteria;

  LoginRecordExportRequest({this.criteria});

  factory LoginRecordExportRequest.fromJson(Map<String, dynamic> json) =>
      _$LoginRecordExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordExportRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchCriteria extends BaseSearchCriteria {
  String applicationId;
  num end;
  num start;
  String userId;

  LoginRecordSearchCriteria(
      {this.applicationId, this.end, this.start, this.userId});

  factory LoginRecordSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$LoginRecordSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchCriteriaToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchRequest {
  bool retrieveTotal;
  LoginRecordSearchCriteria search;

  LoginRecordSearchRequest({this.retrieveTotal, this.search});

  factory LoginRecordSearchRequest.fromJson(Map<String, dynamic> json) =>
      _$LoginRecordSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchRequestToJson(this);
}

/// A raw login record response
///
/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchResponse {
  List<DisplayableRawLogin> logins;
  num total;

  LoginRecordSearchResponse({this.logins, this.total});

  factory LoginRecordSearchResponse.fromJson(Map<String, dynamic> json) =>
      _$LoginRecordSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchResponseToJson(this);
}

/// Response for the login report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LoginReportResponse {
  List<Count> hourlyCounts;
  num total;

  LoginReportResponse({this.hourlyCounts, this.total});

  factory LoginReportResponse.fromJson(Map<String, dynamic> json) =>
      _$LoginReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginReportResponseToJson(this);
}

/// Login API request object.
///
/// @author Seth Musselman
@JsonSerializable()
class LoginRequest extends BaseLoginRequest {
  String loginId;
  String oneTimePassword;
  String password;
  String twoFactorTrustId;

  LoginRequest(
      {this.loginId,
      this.oneTimePassword,
      this.password,
      this.twoFactorTrustId});

  factory LoginRequest.fromJson(Map<String, dynamic> json) =>
      _$LoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class LoginResponse {
  List<LoginPreventedResponse> actions;
  String changePasswordId;
  ChangePasswordReason changePasswordReason;
  String emailVerificationId;
  List<TwoFactorMethod> methods;
  String pendingIdPLinkId;
  String refreshToken;
  String refreshTokenId;
  String registrationVerificationId;
  Map<String, dynamic> state;
  Set<AuthenticationThreats> threatsDetected;
  String token;
  num tokenExpirationInstant;
  String trustToken;
  String twoFactorId;
  String twoFactorTrustId;
  User user;

  LoginResponse(
      {this.actions,
      this.changePasswordId,
      this.changePasswordReason,
      this.emailVerificationId,
      this.methods,
      this.pendingIdPLinkId,
      this.refreshToken,
      this.refreshTokenId,
      this.registrationVerificationId,
      this.state,
      this.threatsDetected,
      this.token,
      this.tokenExpirationInstant,
      this.trustToken,
      this.twoFactorId,
      this.twoFactorTrustId,
      this.user});

  factory LoginResponse.fromJson(Map<String, dynamic> json) =>
      _$LoginResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginResponseToJson(this);
}

/// @author Matthew Altman
enum LogoutBehavior {
  @JsonValue('RedirectOnly')
  RedirectOnly,
  @JsonValue('AllApplications')
  AllApplications
}

/// Request for the Logout API that can be used as an alternative to URL parameters.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LogoutRequest extends BaseEventRequest {
  bool global;
  String refreshToken;

  LogoutRequest({this.global, this.refreshToken});

  factory LogoutRequest.fromJson(Map<String, dynamic> json) =>
      _$LogoutRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LogoutRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LookupResponse {
  IdentityProviderDetails identityProvider;

  LookupResponse({this.identityProvider});

  factory LookupResponse.fromJson(Map<String, dynamic> json) =>
      _$LookupResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LookupResponseToJson(this);
}

/// This class contains the managed fields that are also put into the database during FusionAuth setup.
/// <p>
/// Internal Note: These fields are also declared in SQL in order to bootstrap the system. These need to stay in sync.
/// Any changes to these fields needs to also be reflected in mysql.sql and postgresql.sql
///
/// @author Brian Pontarelli
@JsonSerializable()
class ManagedFields {
  ManagedFields();

  factory ManagedFields.fromJson(Map<String, dynamic> json) =>
      _$ManagedFieldsFromJson(json);
  Map<String, dynamic> toJson() => _$ManagedFieldsToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class MaximumPasswordAge extends Enableable {
  num days;

  MaximumPasswordAge({this.days});

  factory MaximumPasswordAge.fromJson(Map<String, dynamic> json) =>
      _$MaximumPasswordAgeFromJson(json);
  Map<String, dynamic> toJson() => _$MaximumPasswordAgeToJson(this);
}

/// Group Member Delete Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberDeleteRequest {
  List<String> memberIds;
  Map<String, List<String>> members;

  MemberDeleteRequest({this.memberIds, this.members});

  factory MemberDeleteRequest.fromJson(Map<String, dynamic> json) =>
      _$MemberDeleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MemberDeleteRequestToJson(this);
}

/// Group Member Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberRequest {
  Map<String, List<GroupMember>> members;

  MemberRequest({this.members});

  factory MemberRequest.fromJson(Map<String, dynamic> json) =>
      _$MemberRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MemberRequestToJson(this);
}

/// Group Member Response
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberResponse {
  Map<String, List<GroupMember>> members;

  MemberResponse({this.members});

  factory MemberResponse.fromJson(Map<String, dynamic> json) =>
      _$MemberResponseFromJson(json);
  Map<String, dynamic> toJson() => _$MemberResponseToJson(this);
}

/// @author Mikey Sleevi
@JsonSerializable()
class Message {
  Message();

  factory Message.fromJson(Map<String, dynamic> json) =>
      _$MessageFromJson(json);
  Map<String, dynamic> toJson() => _$MessageToJson(this);
}

/// Stores an message template used to distribute messages;
///
/// @author Michael Sleevi
@JsonSerializable()
class MessageTemplate {
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  MessageType type;

  MessageTemplate(
      {this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.type});

  factory MessageTemplate.fromJson(Map<String, dynamic> json) =>
      _$MessageTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$MessageTemplateToJson(this);
}

/// A Message Template Request to the API
///
/// @author Michael Sleevi
@JsonSerializable()
class MessageTemplateRequest {
  MessageTemplate messageTemplate;

  MessageTemplateRequest({this.messageTemplate});

  factory MessageTemplateRequest.fromJson(Map<String, dynamic> json) =>
      _$MessageTemplateRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MessageTemplateRequestToJson(this);
}

/// @author Michael Sleevi
@JsonSerializable()
class MessageTemplateResponse {
  MessageTemplate messageTemplate;
  List<MessageTemplate> messageTemplates;

  MessageTemplateResponse({this.messageTemplate, this.messageTemplates});

  factory MessageTemplateResponse.fromJson(Map<String, dynamic> json) =>
      _$MessageTemplateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$MessageTemplateResponseToJson(this);
}

/// @author Mikey Sleevi
enum MessageType {
  @JsonValue('SMS')
  SMS
}

/// @author Brett Guy
@JsonSerializable()
class MessengerRequest {
  BaseMessengerConfiguration messenger;

  MessengerRequest({this.messenger});

  factory MessengerRequest.fromJson(Map<String, dynamic> json) =>
      _$MessengerRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MessengerRequestToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class MessengerResponse {
  BaseMessengerConfiguration messenger;
  List<BaseMessengerConfiguration> messengers;

  MessengerResponse({this.messenger, this.messengers});

  factory MessengerResponse.fromJson(Map<String, dynamic> json) =>
      _$MessengerResponseFromJson(json);
  Map<String, dynamic> toJson() => _$MessengerResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class MessengerTransport {
  MessengerTransport();

  factory MessengerTransport.fromJson(Map<String, dynamic> json) =>
      _$MessengerTransportFromJson(json);
  Map<String, dynamic> toJson() => _$MessengerTransportToJson(this);
}

/// @author Brett Guy
enum MessengerType {
  @JsonValue('Generic')
  Generic,
  @JsonValue('Kafka')
  Kafka,
  @JsonValue('Twilio')
  Twilio
}

@JsonSerializable()
class MetaData {
  DeviceInfo device;
  Set<String> scopes;

  MetaData({this.device, this.scopes});

  factory MetaData.fromJson(Map<String, dynamic> json) =>
      _$MetaDataFromJson(json);
  Map<String, dynamic> toJson() => _$MetaDataToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class MinimumPasswordAge extends Enableable {
  num seconds;

  MinimumPasswordAge({this.seconds});

  factory MinimumPasswordAge.fromJson(Map<String, dynamic> json) =>
      _$MinimumPasswordAgeFromJson(json);
  Map<String, dynamic> toJson() => _$MinimumPasswordAgeToJson(this);
}

/// Response for the daily active user report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class MonthlyActiveUserReportResponse {
  List<Count> monthlyActiveUsers;
  num total;

  MonthlyActiveUserReportResponse({this.monthlyActiveUsers, this.total});

  factory MonthlyActiveUserReportResponse.fromJson(Map<String, dynamic> json) =>
      _$MonthlyActiveUserReportResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$MonthlyActiveUserReportResponseToJson(this);
}

@JsonSerializable()
class MultiFactorAuthenticatorMethod extends Enableable {
  TOTPAlgorithm algorithm;
  num codeLength;
  num timeStep;

  MultiFactorAuthenticatorMethod(
      {this.algorithm, this.codeLength, this.timeStep});

  factory MultiFactorAuthenticatorMethod.fromJson(Map<String, dynamic> json) =>
      _$MultiFactorAuthenticatorMethodFromJson(json);
  Map<String, dynamic> toJson() => _$MultiFactorAuthenticatorMethodToJson(this);
}

@JsonSerializable()
class MultiFactorEmailMethod extends Enableable {
  String templateId;

  MultiFactorEmailMethod({this.templateId});

  factory MultiFactorEmailMethod.fromJson(Map<String, dynamic> json) =>
      _$MultiFactorEmailMethodFromJson(json);
  Map<String, dynamic> toJson() => _$MultiFactorEmailMethodToJson(this);
}

@JsonSerializable()
class MultiFactorEmailTemplate {
  String templateId;

  MultiFactorEmailTemplate({this.templateId});

  factory MultiFactorEmailTemplate.fromJson(Map<String, dynamic> json) =>
      _$MultiFactorEmailTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$MultiFactorEmailTemplateToJson(this);
}

/// @author Daniel DeGroff
enum MultiFactorLoginPolicy {
  @JsonValue('Disabled')
  Disabled,
  @JsonValue('Enabled')
  Enabled
}

@JsonSerializable()
class MultiFactorSMSMethod extends Enableable {
  String messengerId;
  String templateId;

  MultiFactorSMSMethod({this.messengerId, this.templateId});

  factory MultiFactorSMSMethod.fromJson(Map<String, dynamic> json) =>
      _$MultiFactorSMSMethodFromJson(json);
  Map<String, dynamic> toJson() => _$MultiFactorSMSMethodToJson(this);
}

@JsonSerializable()
class MultiFactorSMSTemplate {
  String templateId;

  MultiFactorSMSTemplate({this.templateId});

  factory MultiFactorSMSTemplate.fromJson(Map<String, dynamic> json) =>
      _$MultiFactorSMSTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$MultiFactorSMSTemplateToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class NintendoApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String emailClaim;
  String scope;
  String uniqueIdClaim;
  String usernameClaim;

  NintendoApplicationConfiguration(
      {this.buttonText,
      this.client_id,
      this.client_secret,
      this.emailClaim,
      this.scope,
      this.uniqueIdClaim,
      this.usernameClaim});

  factory NintendoApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$NintendoApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$NintendoApplicationConfigurationToJson(this);
}

/// Nintendo gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class NintendoIdentityProvider
    extends BaseIdentityProvider<NintendoApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String emailClaim;
  String scope;
  String uniqueIdClaim;
  String usernameClaim;

  NintendoIdentityProvider(
      {this.buttonText,
      this.client_id,
      this.client_secret,
      this.emailClaim,
      this.scope,
      this.uniqueIdClaim,
      this.usernameClaim});

  factory NintendoIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$NintendoIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$NintendoIdentityProviderToJson(this);
}

/// A marker interface indicating this event cannot be made transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class NonTransactionalEvent {
  NonTransactionalEvent();

  factory NonTransactionalEvent.fromJson(Map<String, dynamic> json) =>
      _$NonTransactionalEventFromJson(json);
  Map<String, dynamic> toJson() => _$NonTransactionalEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuth2Configuration {
  List<String> authorizedOriginURLs;
  List<String> authorizedRedirectURLs;
  ClientAuthenticationPolicy clientAuthenticationPolicy;
  String clientId;
  String clientSecret;
  bool debug;
  String deviceVerificationURL;
  Set<GrantType> enabledGrants;
  bool generateRefreshTokens;
  LogoutBehavior logoutBehavior;
  String logoutURL;
  ProofKeyForCodeExchangePolicy proofKeyForCodeExchangePolicy;
  bool requireClientAuthentication;
  bool requireRegistration;

  OAuth2Configuration(
      {this.authorizedOriginURLs,
      this.authorizedRedirectURLs,
      this.clientAuthenticationPolicy,
      this.clientId,
      this.clientSecret,
      this.debug,
      this.deviceVerificationURL,
      this.enabledGrants,
      this.generateRefreshTokens,
      this.logoutBehavior,
      this.logoutURL,
      this.proofKeyForCodeExchangePolicy,
      this.requireClientAuthentication,
      this.requireRegistration});

  factory OAuth2Configuration.fromJson(Map<String, dynamic> json) =>
      _$OAuth2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$OAuth2ConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuthConfigurationResponse {
  num httpSessionMaxInactiveInterval;
  String logoutURL;
  OAuth2Configuration oauthConfiguration;

  OAuthConfigurationResponse(
      {this.httpSessionMaxInactiveInterval,
      this.logoutURL,
      this.oauthConfiguration});

  factory OAuthConfigurationResponse.fromJson(Map<String, dynamic> json) =>
      _$OAuthConfigurationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$OAuthConfigurationResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuthError {
  String change_password_id;
  OAuthErrorType error;
  String error_description;
  OAuthErrorReason error_reason;
  String error_uri;
  String two_factor_id;
  List<TwoFactorMethod> two_factor_methods;

  OAuthError(
      {this.change_password_id,
      this.error,
      this.error_description,
      this.error_reason,
      this.error_uri,
      this.two_factor_id,
      this.two_factor_methods});

  factory OAuthError.fromJson(Map<String, dynamic> json) =>
      _$OAuthErrorFromJson(json);
  Map<String, dynamic> toJson() => _$OAuthErrorToJson(this);
}

enum OAuthErrorReason {
  @JsonValue('auth_code_not_found')
  auth_code_not_found,
  @JsonValue('access_token_malformed')
  access_token_malformed,
  @JsonValue('access_token_expired')
  access_token_expired,
  @JsonValue('access_token_unavailable_for_processing')
  access_token_unavailable_for_processing,
  @JsonValue('access_token_failed_processing')
  access_token_failed_processing,
  @JsonValue('refresh_token_not_found')
  refresh_token_not_found,
  @JsonValue('refresh_token_type_not_supported')
  refresh_token_type_not_supported,
  @JsonValue('invalid_client_id')
  invalid_client_id,
  @JsonValue('invalid_user_credentials')
  invalid_user_credentials,
  @JsonValue('invalid_grant_type')
  invalid_grant_type,
  @JsonValue('invalid_origin')
  invalid_origin,
  @JsonValue('invalid_origin_opaque')
  invalid_origin_opaque,
  @JsonValue('invalid_pkce_code_verifier')
  invalid_pkce_code_verifier,
  @JsonValue('invalid_pkce_code_challenge')
  invalid_pkce_code_challenge,
  @JsonValue('invalid_pkce_code_challenge_method')
  invalid_pkce_code_challenge_method,
  @JsonValue('invalid_redirect_uri')
  invalid_redirect_uri,
  @JsonValue('invalid_response_mode')
  invalid_response_mode,
  @JsonValue('invalid_response_type')
  invalid_response_type,
  @JsonValue('invalid_id_token_hint')
  invalid_id_token_hint,
  @JsonValue('invalid_post_logout_redirect_uri')
  invalid_post_logout_redirect_uri,
  @JsonValue('invalid_device_code')
  invalid_device_code,
  @JsonValue('invalid_user_code')
  invalid_user_code,
  @JsonValue('invalid_additional_client_id')
  invalid_additional_client_id,
  @JsonValue('invalid_target_entity_scope')
  invalid_target_entity_scope,
  @JsonValue('invalid_entity_permission_scope')
  invalid_entity_permission_scope,
  @JsonValue('grant_type_disabled')
  grant_type_disabled,
  @JsonValue('missing_client_id')
  missing_client_id,
  @JsonValue('missing_client_secret')
  missing_client_secret,
  @JsonValue('missing_code')
  missing_code,
  @JsonValue('missing_code_challenge')
  missing_code_challenge,
  @JsonValue('missing_code_verifier')
  missing_code_verifier,
  @JsonValue('missing_device_code')
  missing_device_code,
  @JsonValue('missing_grant_type')
  missing_grant_type,
  @JsonValue('missing_redirect_uri')
  missing_redirect_uri,
  @JsonValue('missing_refresh_token')
  missing_refresh_token,
  @JsonValue('missing_response_type')
  missing_response_type,
  @JsonValue('missing_token')
  missing_token,
  @JsonValue('missing_user_code')
  missing_user_code,
  @JsonValue('missing_verification_uri')
  missing_verification_uri,
  @JsonValue('login_prevented')
  login_prevented,
  @JsonValue('not_licensed')
  not_licensed,
  @JsonValue('user_code_expired')
  user_code_expired,
  @JsonValue('user_expired')
  user_expired,
  @JsonValue('user_locked')
  user_locked,
  @JsonValue('user_not_found')
  user_not_found,
  @JsonValue('client_authentication_missing')
  client_authentication_missing,
  @JsonValue('invalid_client_authentication_scheme')
  invalid_client_authentication_scheme,
  @JsonValue('invalid_client_authentication')
  invalid_client_authentication,
  @JsonValue('client_id_mismatch')
  client_id_mismatch,
  @JsonValue('change_password_administrative')
  change_password_administrative,
  @JsonValue('change_password_breached')
  change_password_breached,
  @JsonValue('change_password_expired')
  change_password_expired,
  @JsonValue('change_password_validation')
  change_password_validation,
  @JsonValue('unknown')
  unknown
}

enum OAuthErrorType {
  @JsonValue('invalid_request')
  invalid_request,
  @JsonValue('invalid_client')
  invalid_client,
  @JsonValue('invalid_grant')
  invalid_grant,
  @JsonValue('invalid_token')
  invalid_token,
  @JsonValue('unauthorized_client')
  unauthorized_client,
  @JsonValue('invalid_scope')
  invalid_scope,
  @JsonValue('server_error')
  server_error,
  @JsonValue('unsupported_grant_type')
  unsupported_grant_type,
  @JsonValue('unsupported_response_type')
  unsupported_response_type,
  @JsonValue('change_password_required')
  change_password_required,
  @JsonValue('not_licensed')
  not_licensed,
  @JsonValue('two_factor_required')
  two_factor_required,
  @JsonValue('authorization_pending')
  authorization_pending,
  @JsonValue('expired_token')
  expired_token,
  @JsonValue('unsupported_token_type')
  unsupported_token_type
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuthResponse {
  OAuthResponse();

  factory OAuthResponse.fromJson(Map<String, dynamic> json) =>
      _$OAuthResponseFromJson(json);
  Map<String, dynamic> toJson() => _$OAuthResponseToJson(this);
}

/// @author Daniel DeGroff
enum ObjectState {
  @JsonValue('Active')
  Active,
  @JsonValue('Inactive')
  Inactive,
  @JsonValue('PendingDelete')
  PendingDelete
}

/// OpenID Connect Configuration as described by the <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID
/// Provider Metadata</a>.
///
/// @author Daniel DeGroff
@JsonSerializable()
class OpenIdConfiguration {
  String authorization_endpoint;
  bool backchannel_logout_supported;
  List<String> claims_supported;
  String device_authorization_endpoint;
  String end_session_endpoint;
  bool frontchannel_logout_supported;
  List<String> grant_types_supported;
  List<String> id_token_signing_alg_values_supported;
  String issuer;
  String jwks_uri;
  List<String> response_modes_supported;
  List<String> response_types_supported;
  List<String> scopes_supported;
  List<String> subject_types_supported;
  String token_endpoint;
  List<String> token_endpoint_auth_methods_supported;
  String userinfo_endpoint;
  List<String> userinfo_signing_alg_values_supported;

  OpenIdConfiguration(
      {this.authorization_endpoint,
      this.backchannel_logout_supported,
      this.claims_supported,
      this.device_authorization_endpoint,
      this.end_session_endpoint,
      this.frontchannel_logout_supported,
      this.grant_types_supported,
      this.id_token_signing_alg_values_supported,
      this.issuer,
      this.jwks_uri,
      this.response_modes_supported,
      this.response_types_supported,
      this.scopes_supported,
      this.subject_types_supported,
      this.token_endpoint,
      this.token_endpoint_auth_methods_supported,
      this.userinfo_endpoint,
      this.userinfo_signing_alg_values_supported});

  factory OpenIdConfiguration.fromJson(Map<String, dynamic> json) =>
      _$OpenIdConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$OpenIdConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OpenIdConnectApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonImageURL;
  String buttonText;
  IdentityProviderOauth2Configuration oauth2;

  OpenIdConnectApplicationConfiguration(
      {this.buttonImageURL, this.buttonText, this.oauth2});

  factory OpenIdConnectApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$OpenIdConnectApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$OpenIdConnectApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OpenIdConnectIdentityProvider
    extends BaseIdentityProvider<OpenIdConnectApplicationConfiguration> {
  String buttonImageURL;
  String buttonText;
  Set<String> domains;
  IdentityProviderOauth2Configuration oauth2;
  bool postRequest;

  OpenIdConnectIdentityProvider(
      {this.buttonImageURL,
      this.buttonText,
      this.domains,
      this.oauth2,
      this.postRequest});

  factory OpenIdConnectIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$OpenIdConnectIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$OpenIdConnectIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordBreachDetection extends Enableable {
  BreachMatchMode matchMode;
  String notifyUserEmailTemplateId;
  BreachAction onLogin;

  PasswordBreachDetection(
      {this.matchMode, this.notifyUserEmailTemplateId, this.onLogin});

  factory PasswordBreachDetection.fromJson(Map<String, dynamic> json) =>
      _$PasswordBreachDetectionFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordBreachDetectionToJson(this);
}

/// Password Encryption Scheme Configuration
///
/// @author Daniel DeGroff
@JsonSerializable()
class PasswordEncryptionConfiguration {
  String encryptionScheme;
  num encryptionSchemeFactor;
  bool modifyEncryptionSchemeOnLogin;

  PasswordEncryptionConfiguration(
      {this.encryptionScheme,
      this.encryptionSchemeFactor,
      this.modifyEncryptionSchemeOnLogin});

  factory PasswordEncryptionConfiguration.fromJson(Map<String, dynamic> json) =>
      _$PasswordEncryptionConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$PasswordEncryptionConfigurationToJson(this);
}

@JsonSerializable()
class PasswordlessConfiguration extends Enableable {
  PasswordlessConfiguration();

  factory PasswordlessConfiguration.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessConfigurationToJson(this);
}

/// Interface for all identity providers that are passwordless and do not accept a password.
@JsonSerializable()
class PasswordlessIdentityProvider {
  PasswordlessIdentityProvider();

  factory PasswordlessIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessLoginRequest extends BaseLoginRequest {
  String code;
  String twoFactorTrustId;

  PasswordlessLoginRequest({this.code, this.twoFactorTrustId});

  factory PasswordlessLoginRequest.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessSendRequest {
  String applicationId;
  String code;
  String loginId;
  Map<String, dynamic> state;

  PasswordlessSendRequest(
      {this.applicationId, this.code, this.loginId, this.state});

  factory PasswordlessSendRequest.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessSendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessSendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessStartRequest {
  String applicationId;
  String loginId;
  Map<String, dynamic> state;

  PasswordlessStartRequest({this.applicationId, this.loginId, this.state});

  factory PasswordlessStartRequest.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessStartRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessStartRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessStartResponse {
  String code;

  PasswordlessStartResponse({this.code});

  factory PasswordlessStartResponse.fromJson(Map<String, dynamic> json) =>
      _$PasswordlessStartResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessStartResponseToJson(this);
}

/// @author Derek Klatt
@JsonSerializable()
class PasswordValidationRules {
  PasswordBreachDetection breachDetection;
  num maxLength;
  num minLength;
  RememberPreviousPasswords rememberPreviousPasswords;
  bool requireMixedCase;
  bool requireNonAlpha;
  bool requireNumber;
  bool validateOnLogin;

  PasswordValidationRules(
      {this.breachDetection,
      this.maxLength,
      this.minLength,
      this.rememberPreviousPasswords,
      this.requireMixedCase,
      this.requireNonAlpha,
      this.requireNumber,
      this.validateOnLogin});

  factory PasswordValidationRules.fromJson(Map<String, dynamic> json) =>
      _$PasswordValidationRulesFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordValidationRulesToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordValidationRulesResponse {
  PasswordValidationRules passwordValidationRules;

  PasswordValidationRulesResponse({this.passwordValidationRules});

  factory PasswordValidationRulesResponse.fromJson(Map<String, dynamic> json) =>
      _$PasswordValidationRulesResponseFromJson(json);
  Map<String, dynamic> toJson() =>
      _$PasswordValidationRulesResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PendingIdPLink {
  String displayName;
  String email;
  String identityProviderId;
  List<IdentityProviderLink> identityProviderLinks;
  String identityProviderName;
  IdentityProviderTenantConfiguration identityProviderTenantConfiguration;
  IdentityProviderType identityProviderType;
  String identityProviderUserId;
  User user;
  String username;

  PendingIdPLink(
      {this.displayName,
      this.email,
      this.identityProviderId,
      this.identityProviderLinks,
      this.identityProviderName,
      this.identityProviderTenantConfiguration,
      this.identityProviderType,
      this.identityProviderUserId,
      this.user,
      this.username});

  factory PendingIdPLink.fromJson(Map<String, dynamic> json) =>
      _$PendingIdPLinkFromJson(json);
  Map<String, dynamic> toJson() => _$PendingIdPLinkToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class PendingResponse {
  List<User> users;

  PendingResponse({this.users});

  factory PendingResponse.fromJson(Map<String, dynamic> json) =>
      _$PendingResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PendingResponseToJson(this);
}

/// @author Michael Sleevi
@JsonSerializable()
class PreviewMessageTemplateRequest {
  String locale;
  MessageTemplate messageTemplate;

  PreviewMessageTemplateRequest({this.locale, this.messageTemplate});

  factory PreviewMessageTemplateRequest.fromJson(Map<String, dynamic> json) =>
      _$PreviewMessageTemplateRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewMessageTemplateRequestToJson(this);
}

/// @author Michael Sleevi
@JsonSerializable()
class PreviewMessageTemplateResponse {
  Errors errors;
  SMSMessage message;

  PreviewMessageTemplateResponse({this.errors, this.message});

  factory PreviewMessageTemplateResponse.fromJson(Map<String, dynamic> json) =>
      _$PreviewMessageTemplateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewMessageTemplateResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class PreviewRequest {
  EmailTemplate emailTemplate;
  String locale;

  PreviewRequest({this.emailTemplate, this.locale});

  factory PreviewRequest.fromJson(Map<String, dynamic> json) =>
      _$PreviewRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewRequestToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class PreviewResponse {
  Email email;
  Errors errors;

  PreviewResponse({this.email, this.errors});

  factory PreviewResponse.fromJson(Map<String, dynamic> json) =>
      _$PreviewResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewResponseToJson(this);
}

/// @author Brett Guy
enum ProofKeyForCodeExchangePolicy {
  @JsonValue('Required')
  Required,
  @JsonValue('NotRequired')
  NotRequired,
  @JsonValue('NotRequiredWhenUsingClientAuthentication')
  NotRequiredWhenUsingClientAuthentication
}

/// Request to authenticate with WebAuthn
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyAuthenticationRequest {
  WebAuthnExtensionsClientOutputs clientExtensionResults;
  String id;
  AuthenticatorAuthenticationResponse response;
  String rpId;
  String type;

  PublicKeyAuthenticationRequest(
      {this.clientExtensionResults,
      this.id,
      this.response,
      this.rpId,
      this.type});

  factory PublicKeyAuthenticationRequest.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyAuthenticationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyAuthenticationRequestToJson(this);
}

/// Allows the Relying Party to specify desired attributes of a new credential.
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialCreationOptions {
  AttestationConveyancePreference attestation;
  AuthenticatorSelectionCriteria authenticatorSelection;
  String challenge;
  List<PublicKeyCredentialDescriptor> excludeCredentials;
  WebAuthnRegistrationExtensionOptions extensions;
  List<PublicKeyCredentialParameters> pubKeyCredParams;
  PublicKeyCredentialRelyingPartyEntity rp;
  num timeout;
  PublicKeyCredentialUserEntity user;

  PublicKeyCredentialCreationOptions(
      {this.attestation,
      this.authenticatorSelection,
      this.challenge,
      this.excludeCredentials,
      this.extensions,
      this.pubKeyCredParams,
      this.rp,
      this.timeout,
      this.user});

  factory PublicKeyCredentialCreationOptions.fromJson(
          Map<String, dynamic> json) =>
      _$PublicKeyCredentialCreationOptionsFromJson(json);
  Map<String, dynamic> toJson() =>
      _$PublicKeyCredentialCreationOptionsToJson(this);
}

/// Contains attributes for the Relying Party to refer to an existing public key credential as an input parameter.
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialDescriptor {
  String id;
  List<AuthenticatorTransport> transports;
  PublicKeyCredentialType type;

  PublicKeyCredentialDescriptor({this.id, this.transports, this.type});

  factory PublicKeyCredentialDescriptor.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyCredentialDescriptorFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyCredentialDescriptorToJson(this);
}

/// Describes a user account or WebAuthn Relying Party associated with a public key credential
@JsonSerializable()
class PublicKeyCredentialEntity {
  String name;

  PublicKeyCredentialEntity({this.name});

  factory PublicKeyCredentialEntity.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyCredentialEntityFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyCredentialEntityToJson(this);
}

/// Supply information on credential type and algorithm to the <i>authenticator</i>.
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialParameters {
  CoseAlgorithmIdentifier alg;
  PublicKeyCredentialType type;

  PublicKeyCredentialParameters({this.alg, this.type});

  factory PublicKeyCredentialParameters.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyCredentialParametersFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyCredentialParametersToJson(this);
}

/// Supply additional information about the Relying Party when creating a new credential
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialRelyingPartyEntity extends PublicKeyCredentialEntity {
  String id;

  PublicKeyCredentialRelyingPartyEntity({this.id});

  factory PublicKeyCredentialRelyingPartyEntity.fromJson(
          Map<String, dynamic> json) =>
      _$PublicKeyCredentialRelyingPartyEntityFromJson(json);
  Map<String, dynamic> toJson() =>
      _$PublicKeyCredentialRelyingPartyEntityToJson(this);
}

/// Provides the <i>authenticator</i> with the data it needs to generate an assertion.
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialRequestOptions {
  List<PublicKeyCredentialDescriptor> allowCredentials;
  String challenge;
  String relyingPartyId;
  num timeout;
  UserVerificationRequirement userVerification;

  PublicKeyCredentialRequestOptions(
      {this.allowCredentials,
      this.challenge,
      this.relyingPartyId,
      this.timeout,
      this.userVerification});

  factory PublicKeyCredentialRequestOptions.fromJson(
          Map<String, dynamic> json) =>
      _$PublicKeyCredentialRequestOptionsFromJson(json);
  Map<String, dynamic> toJson() =>
      _$PublicKeyCredentialRequestOptionsToJson(this);
}

/// Defines valid credential types. This is an extension point in the WebAuthn spec. The only defined value at this time is "public-key"
///
/// @author Spencer Witt
enum PublicKeyCredentialType {
  @JsonValue('publicKey')
  publicKey
}

/// Supply additional information about the user account when creating a new credential
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  String displayName;
  String id;

  PublicKeyCredentialUserEntity({this.displayName, this.id});

  factory PublicKeyCredentialUserEntity.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyCredentialUserEntityFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyCredentialUserEntityToJson(this);
}

/// Request to register a new public key with WebAuthn
///
/// @author Spencer Witt
@JsonSerializable()
class PublicKeyRegistrationRequest {
  WebAuthnExtensionsClientOutputs clientExtensionResults;
  String id;
  AuthenticatorRegistrationResponse response;
  String rpId;
  List<AuthenticatorTransport> transports;
  String type;

  PublicKeyRegistrationRequest(
      {this.clientExtensionResults,
      this.id,
      this.response,
      this.rpId,
      this.transports,
      this.type});

  factory PublicKeyRegistrationRequest.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyRegistrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyRegistrationRequestToJson(this);
}

/// JWT Public Key Response Object
///
/// @author Daniel DeGroff
@JsonSerializable()
class PublicKeyResponse {
  String publicKey;
  Map<String, String> publicKeys;

  PublicKeyResponse({this.publicKey, this.publicKeys});

  factory PublicKeyResponse.fromJson(Map<String, dynamic> json) =>
      _$PublicKeyResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RateLimitedRequestConfiguration extends Enableable {
  num limit;
  num timePeriodInSeconds;

  RateLimitedRequestConfiguration({this.limit, this.timePeriodInSeconds});

  factory RateLimitedRequestConfiguration.fromJson(Map<String, dynamic> json) =>
      _$RateLimitedRequestConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$RateLimitedRequestConfigurationToJson(this);
}

/// @author Daniel DeGroff
enum RateLimitedRequestType {
  @JsonValue('FailedLogin')
  FailedLogin,
  @JsonValue('ForgotPassword')
  ForgotPassword,
  @JsonValue('SendEmailVerification')
  SendEmailVerification,
  @JsonValue('SendPasswordless')
  SendPasswordless,
  @JsonValue('SendRegistrationVerification')
  SendRegistrationVerification,
  @JsonValue('SendTwoFactor')
  SendTwoFactor
}

/// Raw login information for each time a user logs into an application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RawLogin {
  String applicationId;
  num instant;
  String ipAddress;
  String userId;

  RawLogin({this.applicationId, this.instant, this.ipAddress, this.userId});

  factory RawLogin.fromJson(Map<String, dynamic> json) =>
      _$RawLoginFromJson(json);
  Map<String, dynamic> toJson() => _$RawLoginToJson(this);
}

/// @author Brian Pontarelli
enum ReactorFeatureStatus {
  @JsonValue('ACTIVE')
  ACTIVE,
  @JsonValue('DISCONNECTED')
  DISCONNECTED,
  @JsonValue('PENDING')
  PENDING,
  @JsonValue('DISABLED')
  DISABLED,
  @JsonValue('UNKNOWN')
  UNKNOWN
}

/// @author Daniel DeGroff
@JsonSerializable()
class ReactorMetrics {
  Map<String, BreachedPasswordTenantMetric> breachedPasswordMetrics;

  ReactorMetrics({this.breachedPasswordMetrics});

  factory ReactorMetrics.fromJson(Map<String, dynamic> json) =>
      _$ReactorMetricsFromJson(json);
  Map<String, dynamic> toJson() => _$ReactorMetricsToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ReactorMetricsResponse {
  ReactorMetrics metrics;

  ReactorMetricsResponse({this.metrics});

  factory ReactorMetricsResponse.fromJson(Map<String, dynamic> json) =>
      _$ReactorMetricsResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ReactorMetricsResponseToJson(this);
}

/// Request for managing FusionAuth Reactor and licenses.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ReactorRequest {
  String license;
  String licenseId;

  ReactorRequest({this.license, this.licenseId});

  factory ReactorRequest.fromJson(Map<String, dynamic> json) =>
      _$ReactorRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ReactorRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ReactorResponse {
  ReactorStatus status;

  ReactorResponse({this.status});

  factory ReactorResponse.fromJson(Map<String, dynamic> json) =>
      _$ReactorResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ReactorResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ReactorStatus {
  ReactorFeatureStatus advancedIdentityProviders;
  ReactorFeatureStatus advancedLambdas;
  ReactorFeatureStatus advancedMultiFactorAuthentication;
  ReactorFeatureStatus advancedRegistration;
  ReactorFeatureStatus applicationMultiFactorAuthentication;
  ReactorFeatureStatus applicationThemes;
  ReactorFeatureStatus breachedPasswordDetection;
  ReactorFeatureStatus connectors;
  ReactorFeatureStatus entityManagement;
  String expiration;
  Map<String, String> licenseAttributes;
  bool licensed;
  ReactorFeatureStatus scimServer;
  ReactorFeatureStatus threatDetection;
  ReactorFeatureStatus webAuthn;
  ReactorFeatureStatus webAuthnPlatformAuthenticators;
  ReactorFeatureStatus webAuthnRoamingAuthenticators;

  ReactorStatus(
      {this.advancedIdentityProviders,
      this.advancedLambdas,
      this.advancedMultiFactorAuthentication,
      this.advancedRegistration,
      this.applicationMultiFactorAuthentication,
      this.applicationThemes,
      this.breachedPasswordDetection,
      this.connectors,
      this.entityManagement,
      this.expiration,
      this.licenseAttributes,
      this.licensed,
      this.scimServer,
      this.threatDetection,
      this.webAuthn,
      this.webAuthnPlatformAuthenticators,
      this.webAuthnRoamingAuthenticators});

  factory ReactorStatus.fromJson(Map<String, dynamic> json) =>
      _$ReactorStatusFromJson(json);
  Map<String, dynamic> toJson() => _$ReactorStatusToJson(this);
}

/// Response for the user login report.
///
/// @author Seth Musselman
@JsonSerializable()
class RecentLoginResponse {
  List<DisplayableRawLogin> logins;

  RecentLoginResponse({this.logins});

  factory RecentLoginResponse.fromJson(Map<String, dynamic> json) =>
      _$RecentLoginResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RecentLoginResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshRequest extends BaseEventRequest {
  String refreshToken;
  String token;

  RefreshRequest({this.refreshToken, this.token});

  factory RefreshRequest.fromJson(Map<String, dynamic> json) =>
      _$RefreshRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshResponse {
  RefreshResponse();

  factory RefreshResponse.fromJson(Map<String, dynamic> json) =>
      _$RefreshResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshResponseToJson(this);
}

/// Models a JWT Refresh Token.
///
/// @author Daniel DeGroff
@JsonSerializable()
class RefreshToken {
  String applicationId;
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  MetaData metaData;
  num startInstant;
  String tenantId;
  String token;
  String userId;

  RefreshToken(
      {this.applicationId,
      this.data,
      this.id,
      this.insertInstant,
      this.metaData,
      this.startInstant,
      this.tenantId,
      this.token,
      this.userId});

  factory RefreshToken.fromJson(Map<String, dynamic> json) =>
      _$RefreshTokenFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenToJson(this);
}

/// @author Daniel DeGroff
enum RefreshTokenExpirationPolicy {
  @JsonValue('Fixed')
  Fixed,
  @JsonValue('SlidingWindow')
  SlidingWindow
}

/// Refresh Token Import request.
///
/// @author Brett Guy
@JsonSerializable()
class RefreshTokenImportRequest {
  List<RefreshToken> refreshTokens;
  bool validateDbConstraints;

  RefreshTokenImportRequest({this.refreshTokens, this.validateDbConstraints});

  factory RefreshTokenImportRequest.fromJson(Map<String, dynamic> json) =>
      _$RefreshTokenImportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenImportRequestToJson(this);
}

/// API response for retrieving Refresh Tokens
///
/// @author Daniel DeGroff
@JsonSerializable()
class RefreshTokenResponse {
  RefreshToken refreshToken;
  List<RefreshToken> refreshTokens;

  RefreshTokenResponse({this.refreshToken, this.refreshTokens});

  factory RefreshTokenResponse.fromJson(Map<String, dynamic> json) =>
      _$RefreshTokenResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshTokenRevocationPolicy {
  bool onLoginPrevented;
  bool onPasswordChanged;

  RefreshTokenRevocationPolicy({this.onLoginPrevented, this.onPasswordChanged});

  factory RefreshTokenRevocationPolicy.fromJson(Map<String, dynamic> json) =>
      _$RefreshTokenRevocationPolicyFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenRevocationPolicyToJson(this);
}

/// Request for the Refresh Token API to revoke a refresh token rather than using the URL parameters.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RefreshTokenRevokeRequest extends BaseEventRequest {
  String applicationId;
  String token;
  String userId;

  RefreshTokenRevokeRequest({this.applicationId, this.token, this.userId});

  factory RefreshTokenRevokeRequest.fromJson(Map<String, dynamic> json) =>
      _$RefreshTokenRevokeRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenRevokeRequestToJson(this);
}

/// @author Daniel DeGroff
enum RefreshTokenUsagePolicy {
  @JsonValue('Reusable')
  Reusable,
  @JsonValue('OneTimeUse')
  OneTimeUse
}

@JsonSerializable()
class RegistrationConfiguration extends Enableable {
  Requirable birthDate;
  bool confirmPassword;
  Requirable firstName;
  String formId;
  Requirable fullName;
  Requirable lastName;
  LoginIdType loginIdType;
  Requirable middleName;
  Requirable mobilePhone;
  RegistrationType type;

  RegistrationConfiguration(
      {this.birthDate,
      this.confirmPassword,
      this.firstName,
      this.formId,
      this.fullName,
      this.lastName,
      this.loginIdType,
      this.middleName,
      this.mobilePhone,
      this.type});

  factory RegistrationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$RegistrationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationConfigurationToJson(this);
}

/// Registration delete API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationDeleteRequest extends BaseEventRequest {
  RegistrationDeleteRequest();

  factory RegistrationDeleteRequest.fromJson(Map<String, dynamic> json) =>
      _$RegistrationDeleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationDeleteRequestToJson(this);
}

/// Response for the registration report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationReportResponse {
  List<Count> hourlyCounts;
  num total;

  RegistrationReportResponse({this.hourlyCounts, this.total});

  factory RegistrationReportResponse.fromJson(Map<String, dynamic> json) =>
      _$RegistrationReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationReportResponseToJson(this);
}

/// Registration API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationRequest extends BaseEventRequest {
  bool disableDomainBlock;
  bool generateAuthenticationToken;
  UserRegistration registration;
  bool sendSetPasswordEmail;
  bool skipRegistrationVerification;
  bool skipVerification;
  User user;

  RegistrationRequest(
      {this.disableDomainBlock,
      this.generateAuthenticationToken,
      this.registration,
      this.sendSetPasswordEmail,
      this.skipRegistrationVerification,
      this.skipVerification,
      this.user});

  factory RegistrationRequest.fromJson(Map<String, dynamic> json) =>
      _$RegistrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationRequestToJson(this);
}

/// Registration API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationResponse {
  String refreshToken;
  UserRegistration registration;
  String registrationVerificationId;
  String token;
  num tokenExpirationInstant;
  User user;

  RegistrationResponse(
      {this.refreshToken,
      this.registration,
      this.registrationVerificationId,
      this.token,
      this.tokenExpirationInstant,
      this.user});

  factory RegistrationResponse.fromJson(Map<String, dynamic> json) =>
      _$RegistrationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationResponseToJson(this);
}

enum RegistrationType {
  @JsonValue('basic')
  basic,
  @JsonValue('advanced')
  advanced
}

/// @author Daniel DeGroff
@JsonSerializable()
class RegistrationUnverifiedOptions {
  UnverifiedBehavior behavior;

  RegistrationUnverifiedOptions({this.behavior});

  factory RegistrationUnverifiedOptions.fromJson(Map<String, dynamic> json) =>
      _$RegistrationUnverifiedOptionsFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationUnverifiedOptionsToJson(this);
}

/// Reindex API request
///
/// @author Daniel DeGroff
@JsonSerializable()
class ReindexRequest {
  String index;

  ReindexRequest({this.index});

  factory ReindexRequest.fromJson(Map<String, dynamic> json) =>
      _$ReindexRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ReindexRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ReloadRequest {
  List<String> names;

  ReloadRequest({this.names});

  factory ReloadRequest.fromJson(Map<String, dynamic> json) =>
      _$ReloadRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ReloadRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RememberPreviousPasswords extends Enableable {
  num count;

  RememberPreviousPasswords({this.count});

  factory RememberPreviousPasswords.fromJson(Map<String, dynamic> json) =>
      _$RememberPreviousPasswordsFromJson(json);
  Map<String, dynamic> toJson() => _$RememberPreviousPasswordsToJson(this);
}

/// Something that can be required and thus also optional. This currently extends Enableable because anything that is
/// require/optional is almost always enableable as well.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Requirable extends Enableable {
  bool required;

  Requirable({this.required});

  factory Requirable.fromJson(Map<String, dynamic> json) =>
      _$RequirableFromJson(json);
  Map<String, dynamic> toJson() => _$RequirableToJson(this);
}

/// Interface describing the need for CORS configuration.
///
/// @author Daniel DeGroff
@JsonSerializable()
class RequiresCORSConfiguration {
  RequiresCORSConfiguration();

  factory RequiresCORSConfiguration.fromJson(Map<String, dynamic> json) =>
      _$RequiresCORSConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$RequiresCORSConfigurationToJson(this);
}

/// Describes the Relying Party's requirements for <a href="https://www.w3.org/TR/webauthn-2/#client-side-discoverable-credential">client-side
/// discoverable credentials</a> (formerly known as "resident keys")
///
/// @author Spencer Witt
enum ResidentKeyRequirement {
  @JsonValue('discouraged')
  discouraged,
  @JsonValue('preferred')
  preferred,
  @JsonValue('required')
  required
}

enum SAMLLogoutBehavior {
  @JsonValue('AllParticipants')
  AllParticipants,
  @JsonValue('OnlyOriginator')
  OnlyOriginator
}

/// @author Brian Pontarelli
@JsonSerializable()
class SAMLv2ApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonImageURL;
  String buttonText;

  SAMLv2ApplicationConfiguration({this.buttonImageURL, this.buttonText});

  factory SAMLv2ApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$SAMLv2ApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2ApplicationConfigurationToJson(this);
}

@JsonSerializable()
class SAMLv2Configuration extends Enableable {
  String audience;
  List<String> authorizedRedirectURLs;
  String callbackURL;
  bool debug;
  String defaultVerificationKeyId;
  String issuer;
  String keyId;
  SAMLv2Logout logout;
  String logoutURL;
  bool requireSignedRequests;
  CanonicalizationMethod xmlSignatureC14nMethod;
  XMLSignatureLocation xmlSignatureLocation;

  SAMLv2Configuration(
      {this.audience,
      this.authorizedRedirectURLs,
      this.callbackURL,
      this.debug,
      this.defaultVerificationKeyId,
      this.issuer,
      this.keyId,
      this.logout,
      this.logoutURL,
      this.requireSignedRequests,
      this.xmlSignatureC14nMethod,
      this.xmlSignatureLocation});

  factory SAMLv2Configuration.fromJson(Map<String, dynamic> json) =>
      _$SAMLv2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2ConfigurationToJson(this);
}

/// SAML v2 identity provider configuration.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SAMLv2IdentityProvider
    extends BaseIdentityProvider<SAMLv2ApplicationConfiguration> {
  String buttonImageURL;
  String buttonText;
  Set<String> domains;
  String emailClaim;
  String idpEndpoint;
  String issuer;
  String keyId;
  String nameIdFormat;
  bool postRequest;
  String requestSigningKeyId;
  bool signRequest;
  String uniqueIdClaim;
  bool useNameIdForEmail;
  String usernameClaim;
  CanonicalizationMethod xmlSignatureC14nMethod;

  SAMLv2IdentityProvider(
      {this.buttonImageURL,
      this.buttonText,
      this.domains,
      this.emailClaim,
      this.idpEndpoint,
      this.issuer,
      this.keyId,
      this.nameIdFormat,
      this.postRequest,
      this.requestSigningKeyId,
      this.signRequest,
      this.uniqueIdClaim,
      this.useNameIdForEmail,
      this.usernameClaim,
      this.xmlSignatureC14nMethod});

  factory SAMLv2IdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$SAMLv2IdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2IdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SAMLv2IdPInitiatedApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  SAMLv2IdPInitiatedApplicationConfiguration();

  factory SAMLv2IdPInitiatedApplicationConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$SAMLv2IdPInitiatedApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$SAMLv2IdPInitiatedApplicationConfigurationToJson(this);
}

/// SAML v2 IdP Initiated identity provider configuration.
///
/// @author Daniel DeGroff
@JsonSerializable()
class SAMLv2IdPInitiatedIdentityProvider
    extends BaseIdentityProvider<SAMLv2IdPInitiatedApplicationConfiguration> {
  String emailClaim;
  String issuer;
  String keyId;
  String uniqueIdClaim;
  bool useNameIdForEmail;
  String usernameClaim;

  SAMLv2IdPInitiatedIdentityProvider(
      {this.emailClaim,
      this.issuer,
      this.keyId,
      this.uniqueIdClaim,
      this.useNameIdForEmail,
      this.usernameClaim});

  factory SAMLv2IdPInitiatedIdentityProvider.fromJson(
          Map<String, dynamic> json) =>
      _$SAMLv2IdPInitiatedIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() =>
      _$SAMLv2IdPInitiatedIdentityProviderToJson(this);
}

@JsonSerializable()
class SAMLv2Logout {
  SAMLLogoutBehavior behavior;
  String defaultVerificationKeyId;
  String keyId;
  bool requireSignedRequests;
  SAMLv2SingleLogout singleLogout;
  CanonicalizationMethod xmlSignatureC14nMethod;

  SAMLv2Logout(
      {this.behavior,
      this.defaultVerificationKeyId,
      this.keyId,
      this.requireSignedRequests,
      this.singleLogout,
      this.xmlSignatureC14nMethod});

  factory SAMLv2Logout.fromJson(Map<String, dynamic> json) =>
      _$SAMLv2LogoutFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2LogoutToJson(this);
}

@JsonSerializable()
class SAMLv2SingleLogout extends Enableable {
  String keyId;
  String url;
  CanonicalizationMethod xmlSignatureC14nMethod;

  SAMLv2SingleLogout({this.keyId, this.url, this.xmlSignatureC14nMethod});

  factory SAMLv2SingleLogout.fromJson(Map<String, dynamic> json) =>
      _$SAMLv2SingleLogoutFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2SingleLogoutToJson(this);
}

/// Search API request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SearchRequest {
  UserSearchCriteria search;

  SearchRequest({this.search});

  factory SearchRequest.fromJson(Map<String, dynamic> json) =>
      _$SearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SearchRequestToJson(this);
}

/// Search API response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SearchResponse {
  num total;
  List<User> users;

  SearchResponse({this.total, this.users});

  factory SearchResponse.fromJson(Map<String, dynamic> json) =>
      _$SearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SearchResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SecretResponse {
  String secret;
  String secretBase32Encoded;

  SecretResponse({this.secret, this.secretBase32Encoded});

  factory SecretResponse.fromJson(Map<String, dynamic> json) =>
      _$SecretResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SecretResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SecureGeneratorConfiguration {
  num length;
  SecureGeneratorType type;

  SecureGeneratorConfiguration({this.length, this.type});

  factory SecureGeneratorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$SecureGeneratorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SecureGeneratorConfigurationToJson(this);
}

/// @author Daniel DeGroff
enum SecureGeneratorType {
  @JsonValue('randomDigits')
  randomDigits,
  @JsonValue('randomBytes')
  randomBytes,
  @JsonValue('randomAlpha')
  randomAlpha,
  @JsonValue('randomAlphaNumeric')
  randomAlphaNumeric
}

/// @author Daniel DeGroff
@JsonSerializable()
class SecureIdentity {
  num breachedPasswordLastCheckedInstant;
  BreachedPasswordStatus breachedPasswordStatus;
  String connectorId;
  String encryptionScheme;
  num factor;
  String id;
  num lastLoginInstant;
  String password;
  ChangePasswordReason passwordChangeReason;
  bool passwordChangeRequired;
  num passwordLastUpdateInstant;
  String salt;
  String uniqueUsername;
  String username;
  ContentStatus usernameStatus;
  bool verified;

  SecureIdentity(
      {this.breachedPasswordLastCheckedInstant,
      this.breachedPasswordStatus,
      this.connectorId,
      this.encryptionScheme,
      this.factor,
      this.id,
      this.lastLoginInstant,
      this.password,
      this.passwordChangeReason,
      this.passwordChangeRequired,
      this.passwordLastUpdateInstant,
      this.salt,
      this.uniqueUsername,
      this.username,
      this.usernameStatus,
      this.verified});

  factory SecureIdentity.fromJson(Map<String, dynamic> json) =>
      _$SecureIdentityFromJson(json);
  Map<String, dynamic> toJson() => _$SecureIdentityToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SendRequest {
  String applicationId;
  List<String> bccAddresses;
  List<String> ccAddresses;
  List<String> preferredLanguages;
  Map<String, dynamic> requestData;
  List<EmailAddress> toAddresses;
  List<String> userIds;

  SendRequest(
      {this.applicationId,
      this.bccAddresses,
      this.ccAddresses,
      this.preferredLanguages,
      this.requestData,
      this.toAddresses,
      this.userIds});

  factory SendRequest.fromJson(Map<String, dynamic> json) =>
      _$SendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SendResponse {
  Map<String, EmailTemplateErrors> anonymousResults;
  Map<String, EmailTemplateErrors> results;

  SendResponse({this.anonymousResults, this.results});

  factory SendResponse.fromJson(Map<String, dynamic> json) =>
      _$SendResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SendResponseToJson(this);
}

/// @author Michael Sleevi
@JsonSerializable()
class SMSMessage {
  String phoneNumber;
  String textMessage;

  SMSMessage({this.phoneNumber, this.textMessage});

  factory SMSMessage.fromJson(Map<String, dynamic> json) =>
      _$SMSMessageFromJson(json);
  Map<String, dynamic> toJson() => _$SMSMessageToJson(this);
}

/// @author Michael Sleevi
@JsonSerializable()
class SMSMessageTemplate extends MessageTemplate {
  String defaultTemplate;
  Map<String, String> localizedTemplates;

  SMSMessageTemplate({this.defaultTemplate, this.localizedTemplates});

  factory SMSMessageTemplate.fromJson(Map<String, dynamic> json) =>
      _$SMSMessageTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$SMSMessageTemplateToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class SonyPSNApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  SonyPSNApplicationConfiguration(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory SonyPSNApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$SonyPSNApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$SonyPSNApplicationConfigurationToJson(this);
}

/// SonyPSN gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class SonyPSNIdentityProvider
    extends BaseIdentityProvider<SonyPSNApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  SonyPSNIdentityProvider(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory SonyPSNIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$SonyPSNIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$SonyPSNIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
enum Sort {
  @JsonValue('asc')
  asc,
  @JsonValue('desc')
  desc
}

/// @author Daniel DeGroff
@JsonSerializable()
class SortField {
  String missing;
  String name;
  Sort order;

  SortField({this.missing, this.name, this.order});

  factory SortField.fromJson(Map<String, dynamic> json) =>
      _$SortFieldFromJson(json);
  Map<String, dynamic> toJson() => _$SortFieldToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class SteamApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String scope;
  String webAPIKey;

  SteamApplicationConfiguration(
      {this.buttonText, this.client_id, this.scope, this.webAPIKey});

  factory SteamApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$SteamApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SteamApplicationConfigurationToJson(this);
}

/// Steam gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class SteamIdentityProvider
    extends BaseIdentityProvider<SteamApplicationConfiguration> {
  String buttonText;
  String client_id;
  String scope;
  String webAPIKey;

  SteamIdentityProvider(
      {this.buttonText, this.client_id, this.scope, this.webAPIKey});

  factory SteamIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$SteamIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$SteamIdentityProviderToJson(this);
}

/// Helper interface that indicates an identity provider can be federated to using the HTTP POST method.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SupportsPostBindings {
  SupportsPostBindings();

  factory SupportsPostBindings.fromJson(Map<String, dynamic> json) =>
      _$SupportsPostBindingsFromJson(json);
  Map<String, dynamic> toJson() => _$SupportsPostBindingsToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class SystemConfiguration {
  AuditLogConfiguration auditLogConfiguration;
  CORSConfiguration corsConfiguration;
  Map<String, dynamic> data;
  EventLogConfiguration eventLogConfiguration;
  num insertInstant;
  num lastUpdateInstant;
  LoginRecordConfiguration loginRecordConfiguration;
  String reportTimezone;
  UIConfiguration uiConfiguration;

  SystemConfiguration(
      {this.auditLogConfiguration,
      this.corsConfiguration,
      this.data,
      this.eventLogConfiguration,
      this.insertInstant,
      this.lastUpdateInstant,
      this.loginRecordConfiguration,
      this.reportTimezone,
      this.uiConfiguration});

  factory SystemConfiguration.fromJson(Map<String, dynamic> json) =>
      _$SystemConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationToJson(this);
}

/// Request for the system configuration API.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SystemConfigurationRequest {
  SystemConfiguration systemConfiguration;

  SystemConfigurationRequest({this.systemConfiguration});

  factory SystemConfigurationRequest.fromJson(Map<String, dynamic> json) =>
      _$SystemConfigurationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationRequestToJson(this);
}

/// Response for the system configuration API.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SystemConfigurationResponse {
  SystemConfiguration systemConfiguration;

  SystemConfigurationResponse({this.systemConfiguration});

  factory SystemConfigurationResponse.fromJson(Map<String, dynamic> json) =>
      _$SystemConfigurationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SystemLogsExportRequest extends BaseExportRequest {
  num lastNBytes;

  SystemLogsExportRequest({this.lastNBytes});

  factory SystemLogsExportRequest.fromJson(Map<String, dynamic> json) =>
      _$SystemLogsExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SystemLogsExportRequestToJson(this);
}

@JsonSerializable()
class Templates {
  String accountEdit;
  String accountIndex;
  String accountTwoFactorDisable;
  String accountTwoFactorEnable;
  String accountTwoFactorIndex;
  String accountWebAuthnAdd;
  String accountWebAuthnDelete;
  String accountWebAuthnIndex;
  String emailComplete;
  String emailSend;
  String emailSent;
  String emailVerificationRequired;
  String emailVerify;
  String helpers;
  String index;
  String oauth2Authorize;
  String oauth2AuthorizedNotRegistered;
  String oauth2ChildRegistrationNotAllowed;
  String oauth2ChildRegistrationNotAllowedComplete;
  String oauth2CompleteRegistration;
  String oauth2Device;
  String oauth2DeviceComplete;
  String oauth2Error;
  String oauth2Logout;
  String oauth2Passwordless;
  String oauth2Register;
  String oauth2StartIdPLink;
  String oauth2TwoFactor;
  String oauth2TwoFactorMethods;
  String oauth2Wait;
  String oauth2WebAuthn;
  String oauth2WebAuthnReauth;
  String oauth2WebAuthnReauthEnable;
  String passwordChange;
  String passwordComplete;
  String passwordForgot;
  String passwordSent;
  String registrationComplete;
  String registrationSend;
  String registrationSent;
  String registrationVerificationRequired;
  String registrationVerify;
  String samlv2Logout;
  String unauthorized;

  Templates(
      {this.accountEdit,
      this.accountIndex,
      this.accountTwoFactorDisable,
      this.accountTwoFactorEnable,
      this.accountTwoFactorIndex,
      this.accountWebAuthnAdd,
      this.accountWebAuthnDelete,
      this.accountWebAuthnIndex,
      this.emailComplete,
      this.emailSend,
      this.emailSent,
      this.emailVerificationRequired,
      this.emailVerify,
      this.helpers,
      this.index,
      this.oauth2Authorize,
      this.oauth2AuthorizedNotRegistered,
      this.oauth2ChildRegistrationNotAllowed,
      this.oauth2ChildRegistrationNotAllowedComplete,
      this.oauth2CompleteRegistration,
      this.oauth2Device,
      this.oauth2DeviceComplete,
      this.oauth2Error,
      this.oauth2Logout,
      this.oauth2Passwordless,
      this.oauth2Register,
      this.oauth2StartIdPLink,
      this.oauth2TwoFactor,
      this.oauth2TwoFactorMethods,
      this.oauth2Wait,
      this.oauth2WebAuthn,
      this.oauth2WebAuthnReauth,
      this.oauth2WebAuthnReauthEnable,
      this.passwordChange,
      this.passwordComplete,
      this.passwordForgot,
      this.passwordSent,
      this.registrationComplete,
      this.registrationSend,
      this.registrationSent,
      this.registrationVerificationRequired,
      this.registrationVerify,
      this.samlv2Logout,
      this.unauthorized});

  factory Templates.fromJson(Map<String, dynamic> json) =>
      _$TemplatesFromJson(json);
  Map<String, dynamic> toJson() => _$TemplatesToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class Tenant {
  TenantAccessControlConfiguration accessControlConfiguration;
  TenantCaptchaConfiguration captchaConfiguration;
  bool configured;
  List<ConnectorPolicy> connectorPolicies;
  Map<String, dynamic> data;
  EmailConfiguration emailConfiguration;
  EventConfiguration eventConfiguration;
  ExternalIdentifierConfiguration externalIdentifierConfiguration;
  FailedAuthenticationConfiguration failedAuthenticationConfiguration;
  FamilyConfiguration familyConfiguration;
  TenantFormConfiguration formConfiguration;
  num httpSessionMaxInactiveInterval;
  String id;
  num insertInstant;
  String issuer;
  JWTConfiguration jwtConfiguration;
  TenantLambdaConfiguration lambdaConfiguration;
  num lastUpdateInstant;
  TenantLoginConfiguration loginConfiguration;
  String logoutURL;
  MaximumPasswordAge maximumPasswordAge;
  MinimumPasswordAge minimumPasswordAge;
  TenantMultiFactorConfiguration multiFactorConfiguration;
  String name;
  TenantOAuth2Configuration oauthConfiguration;
  PasswordEncryptionConfiguration passwordEncryptionConfiguration;
  PasswordValidationRules passwordValidationRules;
  TenantRateLimitConfiguration rateLimitConfiguration;
  TenantRegistrationConfiguration registrationConfiguration;
  TenantSCIMServerConfiguration scimServerConfiguration;
  TenantSSOConfiguration ssoConfiguration;
  ObjectState state;
  String themeId;
  TenantUserDeletePolicy userDeletePolicy;
  TenantUsernameConfiguration usernameConfiguration;
  TenantWebAuthnConfiguration webAuthnConfiguration;

  Tenant(
      {this.accessControlConfiguration,
      this.captchaConfiguration,
      this.configured,
      this.connectorPolicies,
      this.data,
      this.emailConfiguration,
      this.eventConfiguration,
      this.externalIdentifierConfiguration,
      this.failedAuthenticationConfiguration,
      this.familyConfiguration,
      this.formConfiguration,
      this.httpSessionMaxInactiveInterval,
      this.id,
      this.insertInstant,
      this.issuer,
      this.jwtConfiguration,
      this.lambdaConfiguration,
      this.lastUpdateInstant,
      this.loginConfiguration,
      this.logoutURL,
      this.maximumPasswordAge,
      this.minimumPasswordAge,
      this.multiFactorConfiguration,
      this.name,
      this.oauthConfiguration,
      this.passwordEncryptionConfiguration,
      this.passwordValidationRules,
      this.rateLimitConfiguration,
      this.registrationConfiguration,
      this.scimServerConfiguration,
      this.ssoConfiguration,
      this.state,
      this.themeId,
      this.userDeletePolicy,
      this.usernameConfiguration,
      this.webAuthnConfiguration});

  factory Tenant.fromJson(Map<String, dynamic> json) => _$TenantFromJson(json);
  Map<String, dynamic> toJson() => _$TenantToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class Tenantable {
  Tenantable();

  factory Tenantable.fromJson(Map<String, dynamic> json) =>
      _$TenantableFromJson(json);
  Map<String, dynamic> toJson() => _$TenantableToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class TenantAccessControlConfiguration {
  String uiIPAccessControlListId;

  TenantAccessControlConfiguration({this.uiIPAccessControlListId});

  factory TenantAccessControlConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$TenantAccessControlConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$TenantAccessControlConfigurationToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class TenantCaptchaConfiguration extends Enableable {
  CaptchaMethod captchaMethod;
  String secretKey;
  String siteKey;
  num threshold;

  TenantCaptchaConfiguration(
      {this.captchaMethod, this.secretKey, this.siteKey, this.threshold});

  factory TenantCaptchaConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantCaptchaConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantCaptchaConfigurationToJson(this);
}

/// Request for the Tenant API to delete a tenant rather than using the URL parameters.
///
/// @author Brian Pontarelli
@JsonSerializable()
class TenantDeleteRequest extends BaseEventRequest {
  bool async;

  TenantDeleteRequest({this.async});

  factory TenantDeleteRequest.fromJson(Map<String, dynamic> json) =>
      _$TenantDeleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TenantDeleteRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantFormConfiguration {
  String adminUserFormId;

  TenantFormConfiguration({this.adminUserFormId});

  factory TenantFormConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantFormConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantFormConfigurationToJson(this);
}

/// @author Rob Davis
@JsonSerializable()
class TenantLambdaConfiguration {
  String scimEnterpriseUserRequestConverterId;
  String scimEnterpriseUserResponseConverterId;
  String scimGroupRequestConverterId;
  String scimGroupResponseConverterId;
  String scimUserRequestConverterId;
  String scimUserResponseConverterId;

  TenantLambdaConfiguration(
      {this.scimEnterpriseUserRequestConverterId,
      this.scimEnterpriseUserResponseConverterId,
      this.scimGroupRequestConverterId,
      this.scimGroupResponseConverterId,
      this.scimUserRequestConverterId,
      this.scimUserResponseConverterId});

  factory TenantLambdaConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantLambdaConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantLambdaConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantLoginConfiguration {
  bool requireAuthentication;

  TenantLoginConfiguration({this.requireAuthentication});

  factory TenantLoginConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantLoginConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantLoginConfigurationToJson(this);
}

/// @author Mikey Sleevi
@JsonSerializable()
class TenantMultiFactorConfiguration {
  MultiFactorAuthenticatorMethod authenticator;
  MultiFactorEmailMethod email;
  MultiFactorLoginPolicy loginPolicy;
  MultiFactorSMSMethod sms;

  TenantMultiFactorConfiguration(
      {this.authenticator, this.email, this.loginPolicy, this.sms});

  factory TenantMultiFactorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantMultiFactorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantMultiFactorConfigurationToJson(this);
}

@JsonSerializable()
class TenantOAuth2Configuration {
  String clientCredentialsAccessTokenPopulateLambdaId;

  TenantOAuth2Configuration(
      {this.clientCredentialsAccessTokenPopulateLambdaId});

  factory TenantOAuth2Configuration.fromJson(Map<String, dynamic> json) =>
      _$TenantOAuth2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantOAuth2ConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantRateLimitConfiguration {
  RateLimitedRequestConfiguration failedLogin;
  RateLimitedRequestConfiguration forgotPassword;
  RateLimitedRequestConfiguration sendEmailVerification;
  RateLimitedRequestConfiguration sendPasswordless;
  RateLimitedRequestConfiguration sendRegistrationVerification;
  RateLimitedRequestConfiguration sendTwoFactor;

  TenantRateLimitConfiguration(
      {this.failedLogin,
      this.forgotPassword,
      this.sendEmailVerification,
      this.sendPasswordless,
      this.sendRegistrationVerification,
      this.sendTwoFactor});

  factory TenantRateLimitConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantRateLimitConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantRateLimitConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantRegistrationConfiguration {
  Set<String> blockedDomains;

  TenantRegistrationConfiguration({this.blockedDomains});

  factory TenantRegistrationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantRegistrationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$TenantRegistrationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantRequest extends BaseEventRequest {
  String sourceTenantId;
  Tenant tenant;
  List<String> webhookIds;

  TenantRequest({this.sourceTenantId, this.tenant, this.webhookIds});

  factory TenantRequest.fromJson(Map<String, dynamic> json) =>
      _$TenantRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TenantRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantResponse {
  Tenant tenant;
  List<Tenant> tenants;

  TenantResponse({this.tenant, this.tenants});

  factory TenantResponse.fromJson(Map<String, dynamic> json) =>
      _$TenantResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TenantResponseToJson(this);
}

/// @author Rob Davis
@JsonSerializable()
class TenantSCIMServerConfiguration extends Enableable {
  String clientEntityTypeId;
  Map<String, dynamic> schemas;
  String serverEntityTypeId;

  TenantSCIMServerConfiguration(
      {this.clientEntityTypeId, this.schemas, this.serverEntityTypeId});

  factory TenantSCIMServerConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantSCIMServerConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantSCIMServerConfigurationToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class TenantSSOConfiguration {
  num deviceTrustTimeToLiveInSeconds;

  TenantSSOConfiguration({this.deviceTrustTimeToLiveInSeconds});

  factory TenantSSOConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantSSOConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantSSOConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantUnverifiedConfiguration {
  UnverifiedBehavior email;
  RegistrationUnverifiedOptions whenGated;

  TenantUnverifiedConfiguration({this.email, this.whenGated});

  factory TenantUnverifiedConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantUnverifiedConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantUnverifiedConfigurationToJson(this);
}

/// A Tenant-level policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class TenantUserDeletePolicy {
  TimeBasedDeletePolicy unverified;

  TenantUserDeletePolicy({this.unverified});

  factory TenantUserDeletePolicy.fromJson(Map<String, dynamic> json) =>
      _$TenantUserDeletePolicyFromJson(json);
  Map<String, dynamic> toJson() => _$TenantUserDeletePolicyToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantUsernameConfiguration {
  UniqueUsernameConfiguration unique;

  TenantUsernameConfiguration({this.unique});

  factory TenantUsernameConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantUsernameConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantUsernameConfigurationToJson(this);
}

// TODO : WebAuthn : Daniel Review : Do we need this Enableable
@JsonSerializable()
class TenantWebAuthnConfiguration extends Enableable {
  TenantWebAuthnWorkflowConfiguration bootstrapWorkflow;
  TenantWebAuthnWorkflowConfiguration reauthenticationWorkflow;
  String relyingPartyId;
  String relyingPartyName;

  TenantWebAuthnConfiguration(
      {this.bootstrapWorkflow,
      this.reauthenticationWorkflow,
      this.relyingPartyId,
      this.relyingPartyName});

  factory TenantWebAuthnConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TenantWebAuthnConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantWebAuthnConfigurationToJson(this);
}

// TODO : WebAuthn : Daniel Review : If this also ends up living in the Application, we should rename to WebAuthnWorkflowConfiguration
@JsonSerializable()
class TenantWebAuthnWorkflowConfiguration extends Enableable {
  AuthenticatorAttachmentPreference authenticatorAttachmentPreference;
  UserVerificationRequirement userVerificationRequirement;

  TenantWebAuthnWorkflowConfiguration(
      {this.authenticatorAttachmentPreference,
      this.userVerificationRequirement});

  factory TenantWebAuthnWorkflowConfiguration.fromJson(
          Map<String, dynamic> json) =>
      _$TenantWebAuthnWorkflowConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$TenantWebAuthnWorkflowConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TestEvent extends BaseEvent {
  String message;

  TestEvent({this.message});

  factory TestEvent.fromJson(Map<String, dynamic> json) =>
      _$TestEventFromJson(json);
  Map<String, dynamic> toJson() => _$TestEventToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class Theme {
  Map<String, dynamic> data;
  String defaultMessages;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  Map<String, String> localizedMessages;
  String name;
  String stylesheet;
  Templates templates;

  Theme(
      {this.data,
      this.defaultMessages,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedMessages,
      this.name,
      this.stylesheet,
      this.templates});

  factory Theme.fromJson(Map<String, dynamic> json) => _$ThemeFromJson(json);
  Map<String, dynamic> toJson() => _$ThemeToJson(this);
}

/// Theme API request object.
///
/// @author Trevor Smith
@JsonSerializable()
class ThemeRequest {
  String sourceThemeId;
  Theme theme;

  ThemeRequest({this.sourceThemeId, this.theme});

  factory ThemeRequest.fromJson(Map<String, dynamic> json) =>
      _$ThemeRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ThemeRequestToJson(this);
}

/// Theme API response object.
///
/// @author Trevor Smith
@JsonSerializable()
class ThemeResponse {
  Theme theme;
  List<Theme> themes;

  ThemeResponse({this.theme, this.themes});

  factory ThemeResponse.fromJson(Map<String, dynamic> json) =>
      _$ThemeResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ThemeResponseToJson(this);
}

/// A policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class TimeBasedDeletePolicy extends Enableable {
  num numberOfDaysToRetain;

  TimeBasedDeletePolicy({this.numberOfDaysToRetain});

  factory TimeBasedDeletePolicy.fromJson(Map<String, dynamic> json) =>
      _$TimeBasedDeletePolicyFromJson(json);
  Map<String, dynamic> toJson() => _$TimeBasedDeletePolicyToJson(this);
}

/// <ul>
/// <li>Bearer Token type as defined by <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>.</li>
/// <li>MAC Token type as referenced by <a href="https://tools.ietf.org/html/rfc6749">RFC 6749</a> and
/// <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-05">
/// Draft RFC on OAuth 2.0 Message Authentication Code (MAC) Tokens</a>
/// </li>
/// </ul>
///
/// @author Daniel DeGroff
enum TokenType {
  @JsonValue('Bearer')
  Bearer,
  @JsonValue('MAC')
  MAC
}

@JsonSerializable()
class Totals {
  num logins;
  num registrations;
  num totalRegistrations;

  Totals({this.logins, this.registrations, this.totalRegistrations});

  factory Totals.fromJson(Map<String, dynamic> json) => _$TotalsFromJson(json);
  Map<String, dynamic> toJson() => _$TotalsToJson(this);
}

/// The response from the total report. This report stores the total numbers for each application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class TotalsReportResponse {
  Map<String, Totals> applicationTotals;
  num globalRegistrations;
  num totalGlobalRegistrations;

  TotalsReportResponse(
      {this.applicationTotals,
      this.globalRegistrations,
      this.totalGlobalRegistrations});

  factory TotalsReportResponse.fromJson(Map<String, dynamic> json) =>
      _$TotalsReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TotalsReportResponseToJson(this);
}

enum TOTPAlgorithm {
  @JsonValue('HmacSHA1')
  HmacSHA1,
  @JsonValue('HmacSHA256')
  HmacSHA256,
  @JsonValue('HmacSHA512')
  HmacSHA512
}

/// The transaction types for Webhooks and other event systems within FusionAuth.
///
/// @author Brian Pontarelli
enum TransactionType {
  @JsonValue('None')
  None,
  @JsonValue('Any')
  Any,
  @JsonValue('SimpleMajority')
  SimpleMajority,
  @JsonValue('SuperMajority')
  SuperMajority,
  @JsonValue('AbsoluteMajority')
  AbsoluteMajority
}

/// @author Brett Guy
@JsonSerializable()
class TwilioMessengerConfiguration extends BaseMessengerConfiguration {
  String accountSID;
  String authToken;
  String fromPhoneNumber;
  String messagingServiceSid;
  String url;

  TwilioMessengerConfiguration(
      {this.accountSID,
      this.authToken,
      this.fromPhoneNumber,
      this.messagingServiceSid,
      this.url});

  factory TwilioMessengerConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TwilioMessengerConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TwilioMessengerConfigurationToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class TwitchApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  TwitchApplicationConfiguration(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory TwitchApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TwitchApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TwitchApplicationConfigurationToJson(this);
}

/// Twitch gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class TwitchIdentityProvider
    extends BaseIdentityProvider<TwitchApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  TwitchIdentityProvider(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory TwitchIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$TwitchIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$TwitchIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwitterApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String consumerKey;
  String consumerSecret;

  TwitterApplicationConfiguration(
      {this.buttonText, this.consumerKey, this.consumerSecret});

  factory TwitterApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$TwitterApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() =>
      _$TwitterApplicationConfigurationToJson(this);
}

/// Twitter social login provider.
///
/// @author Daniel DeGroff
@JsonSerializable()
class TwitterIdentityProvider
    extends BaseIdentityProvider<TwitterApplicationConfiguration> {
  String buttonText;
  String consumerKey;
  String consumerSecret;

  TwitterIdentityProvider(
      {this.buttonText, this.consumerKey, this.consumerSecret});

  factory TwitterIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$TwitterIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$TwitterIdentityProviderToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class TwoFactorDisableRequest extends BaseEventRequest {
  String applicationId;
  String code;
  String methodId;

  TwoFactorDisableRequest({this.applicationId, this.code, this.methodId});

  factory TwoFactorDisableRequest.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorDisableRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorDisableRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorEnableDisableSendRequest {
  String email;
  String method;
  String methodId;
  String mobilePhone;

  TwoFactorEnableDisableSendRequest(
      {this.email, this.method, this.methodId, this.mobilePhone});

  factory TwoFactorEnableDisableSendRequest.fromJson(
          Map<String, dynamic> json) =>
      _$TwoFactorEnableDisableSendRequestFromJson(json);
  Map<String, dynamic> toJson() =>
      _$TwoFactorEnableDisableSendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorLoginRequest extends BaseLoginRequest {
  String code;
  bool trustComputer;
  String twoFactorId;
  String userId;

  TwoFactorLoginRequest(
      {this.code, this.trustComputer, this.twoFactorId, this.userId});

  factory TwoFactorLoginRequest.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorMethod {
  AuthenticatorConfiguration authenticator;
  String email;
  String id;
  bool lastUsed;
  String method;
  String mobilePhone;
  String secret;

  TwoFactorMethod(
      {this.authenticator,
      this.email,
      this.id,
      this.lastUsed,
      this.method,
      this.mobilePhone,
      this.secret});

  factory TwoFactorMethod.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorMethodFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorMethodToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorRecoveryCodeResponse {
  List<String> recoveryCodes;

  TwoFactorRecoveryCodeResponse({this.recoveryCodes});

  factory TwoFactorRecoveryCodeResponse.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorRecoveryCodeResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorRecoveryCodeResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class TwoFactorRequest extends BaseEventRequest {
  String applicationId;
  String authenticatorId;
  String code;
  String email;
  String method;
  String mobilePhone;
  String secret;
  String secretBase32Encoded;

  TwoFactorRequest(
      {this.applicationId,
      this.authenticatorId,
      this.code,
      this.email,
      this.method,
      this.mobilePhone,
      this.secret,
      this.secretBase32Encoded});

  factory TwoFactorRequest.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorResponse {
  List<String> recoveryCodes;

  TwoFactorResponse({this.recoveryCodes});

  factory TwoFactorResponse.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorSendRequest {
  String email;
  String method;
  String methodId;
  String mobilePhone;
  String userId;

  TwoFactorSendRequest(
      {this.email, this.method, this.methodId, this.mobilePhone, this.userId});

  factory TwoFactorSendRequest.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorSendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorSendRequestToJson(this);
}

/// @author Brett Guy
@JsonSerializable()
class TwoFactorStartRequest {
  String applicationId;
  String code;
  String loginId;
  Map<String, dynamic> state;
  String trustChallenge;
  String userId;

  TwoFactorStartRequest(
      {this.applicationId,
      this.code,
      this.loginId,
      this.state,
      this.trustChallenge,
      this.userId});

  factory TwoFactorStartRequest.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorStartRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorStartRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorStartResponse {
  String code;
  List<TwoFactorMethod> methods;
  String twoFactorId;

  TwoFactorStartResponse({this.code, this.methods, this.twoFactorId});

  factory TwoFactorStartResponse.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorStartResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorStartResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorStatusResponse {
  List<TwoFactorTrust> trusts;
  String twoFactorTrustId;

  TwoFactorStatusResponse({this.trusts, this.twoFactorTrustId});

  factory TwoFactorStatusResponse.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorStatusResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorStatusResponseToJson(this);
}

@JsonSerializable()
class TwoFactorTrust {
  String applicationId;
  num expiration;
  num startInstant;

  TwoFactorTrust({this.applicationId, this.expiration, this.startInstant});

  factory TwoFactorTrust.fromJson(Map<String, dynamic> json) =>
      _$TwoFactorTrustFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorTrustToJson(this);
}

@JsonSerializable()
class UIConfiguration {
  String headerColor;
  String logoURL;
  String menuFontColor;

  UIConfiguration({this.headerColor, this.logoURL, this.menuFontColor});

  factory UIConfiguration.fromJson(Map<String, dynamic> json) =>
      _$UIConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$UIConfigurationToJson(this);
}

@JsonSerializable()
class UniqueUsernameConfiguration extends Enableable {
  num numberOfDigits;
  char separator;
  UniqueUsernameStrategy strategy;

  UniqueUsernameConfiguration(
      {this.numberOfDigits, this.separator, this.strategy});

  factory UniqueUsernameConfiguration.fromJson(Map<String, dynamic> json) =>
      _$UniqueUsernameConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$UniqueUsernameConfigurationToJson(this);
}

enum UniqueUsernameStrategy {
  @JsonValue('Always')
  Always,
  @JsonValue('OnCollision')
  OnCollision
}

/// @author Daniel DeGroff
enum UnverifiedBehavior {
  @JsonValue('Allow')
  Allow,
  @JsonValue('Gated')
  Gated
}

/// The global view of a User. This object contains all global information about the user including birth date, registration information
/// preferred languages, global attributes, etc.
///
/// @author Seth Musselman
@JsonSerializable()
class User extends SecureIdentity {
  bool active;
  String birthDate;
  String cleanSpeakId;
  Map<String, dynamic> data;
  String email;
  num expiry;
  String firstName;
  String fullName;
  String imageUrl;
  num insertInstant;
  String lastName;
  num lastUpdateInstant;
  List<GroupMember> memberships;
  String middleName;
  String mobilePhone;
  String parentEmail;
  List<String> preferredLanguages;
  List<UserRegistration> registrations;
  String tenantId;
  String timezone;
  UserTwoFactorConfiguration twoFactor;

  User(
      {this.active,
      this.birthDate,
      this.cleanSpeakId,
      this.data,
      this.email,
      this.expiry,
      this.firstName,
      this.fullName,
      this.imageUrl,
      this.insertInstant,
      this.lastName,
      this.lastUpdateInstant,
      this.memberships,
      this.middleName,
      this.mobilePhone,
      this.parentEmail,
      this.preferredLanguages,
      this.registrations,
      this.tenantId,
      this.timezone,
      this.twoFactor});

  factory User.fromJson(Map<String, dynamic> json) => _$UserFromJson(json);
  Map<String, dynamic> toJson() => _$UserToJson(this);
}

/// An action that can be executed on a user (discipline or reward potentially).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserAction {
  bool active;
  String cancelEmailTemplateId;
  String endEmailTemplateId;
  String id;
  bool includeEmailInEventJSON;
  num insertInstant;
  num lastUpdateInstant;
  Map<String, String> localizedNames;
  String modifyEmailTemplateId;
  String name;
  List<UserActionOption> options;
  bool preventLogin;
  bool sendEndEvent;
  String startEmailTemplateId;
  bool temporal;
  TransactionType transactionType;
  bool userEmailingEnabled;
  bool userNotificationsEnabled;

  UserAction(
      {this.active,
      this.cancelEmailTemplateId,
      this.endEmailTemplateId,
      this.id,
      this.includeEmailInEventJSON,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedNames,
      this.modifyEmailTemplateId,
      this.name,
      this.options,
      this.preventLogin,
      this.sendEndEvent,
      this.startEmailTemplateId,
      this.temporal,
      this.transactionType,
      this.userEmailingEnabled,
      this.userNotificationsEnabled});

  factory UserAction.fromJson(Map<String, dynamic> json) =>
      _$UserActionFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionToJson(this);
}

/// Models the user action Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionEvent extends BaseEvent {
  String action;
  String actioneeUserId;
  String actionerUserId;
  String actionId;
  List<String> applicationIds;
  String comment;
  Email email;
  bool emailedUser;
  num expiry;
  String localizedAction;
  String localizedDuration;
  String localizedOption;
  String localizedReason;
  bool notifyUser;
  String option;
  UserActionPhase phase;
  String reason;
  String reasonCode;

  UserActionEvent(
      {this.action,
      this.actioneeUserId,
      this.actionerUserId,
      this.actionId,
      this.applicationIds,
      this.comment,
      this.email,
      this.emailedUser,
      this.expiry,
      this.localizedAction,
      this.localizedDuration,
      this.localizedOption,
      this.localizedReason,
      this.notifyUser,
      this.option,
      this.phase,
      this.reason,
      this.reasonCode});

  factory UserActionEvent.fromJson(Map<String, dynamic> json) =>
      _$UserActionEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionEventToJson(this);
}

/// A log for an action that was taken on a User.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionLog {
  String actioneeUserId;
  String actionerUserId;
  List<String> applicationIds;
  String comment;
  bool emailUserOnEnd;
  bool endEventSent;
  num expiry;
  LogHistory history;
  String id;
  num insertInstant;
  String localizedName;
  String localizedOption;
  String localizedReason;
  String name;
  bool notifyUserOnEnd;
  String option;
  String reason;
  String reasonCode;
  String userActionId;

  UserActionLog(
      {this.actioneeUserId,
      this.actionerUserId,
      this.applicationIds,
      this.comment,
      this.emailUserOnEnd,
      this.endEventSent,
      this.expiry,
      this.history,
      this.id,
      this.insertInstant,
      this.localizedName,
      this.localizedOption,
      this.localizedReason,
      this.name,
      this.notifyUserOnEnd,
      this.option,
      this.reason,
      this.reasonCode,
      this.userActionId});

  factory UserActionLog.fromJson(Map<String, dynamic> json) =>
      _$UserActionLogFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionLogToJson(this);
}

/// Models content user action options.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionOption {
  Map<String, String> localizedNames;
  String name;

  UserActionOption({this.localizedNames, this.name});

  factory UserActionOption.fromJson(Map<String, dynamic> json) =>
      _$UserActionOptionFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionOptionToJson(this);
}

/// The phases of a time-based user action.
///
/// @author Brian Pontarelli
enum UserActionPhase {
  @JsonValue('start')
  start,
  @JsonValue('modify')
  modify,
  @JsonValue('cancel')
  cancel,
  @JsonValue('end')
  end
}

/// Models action reasons.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionReason {
  String code;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  Map<String, String> localizedTexts;
  String text;

  UserActionReason(
      {this.code,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedTexts,
      this.text});

  factory UserActionReason.fromJson(Map<String, dynamic> json) =>
      _$UserActionReasonFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonToJson(this);
}

/// User Action Reason API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionReasonRequest {
  UserActionReason userActionReason;

  UserActionReasonRequest({this.userActionReason});

  factory UserActionReasonRequest.fromJson(Map<String, dynamic> json) =>
      _$UserActionReasonRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonRequestToJson(this);
}

/// User Action Reason API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionReasonResponse {
  UserActionReason userActionReason;
  List<UserActionReason> userActionReasons;

  UserActionReasonResponse({this.userActionReason, this.userActionReasons});

  factory UserActionReasonResponse.fromJson(Map<String, dynamic> json) =>
      _$UserActionReasonResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonResponseToJson(this);
}

/// User Action API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionRequest {
  UserAction userAction;

  UserActionRequest({this.userAction});

  factory UserActionRequest.fromJson(Map<String, dynamic> json) =>
      _$UserActionRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionRequestToJson(this);
}

/// User Action API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionResponse {
  UserAction userAction;
  List<UserAction> userActions;

  UserActionResponse({this.userAction, this.userActions});

  factory UserActionResponse.fromJson(Map<String, dynamic> json) =>
      _$UserActionResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionResponseToJson(this);
}

/// Models the User Bulk Create Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserBulkCreateEvent extends BaseEvent {
  List<User> users;

  UserBulkCreateEvent({this.users});

  factory UserBulkCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserBulkCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserBulkCreateEventToJson(this);
}

/// A log for an event that happened to a User.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserComment {
  String comment;
  String commenterId;
  String id;
  num insertInstant;
  String userId;

  UserComment(
      {this.comment,
      this.commenterId,
      this.id,
      this.insertInstant,
      this.userId});

  factory UserComment.fromJson(Map<String, dynamic> json) =>
      _$UserCommentFromJson(json);
  Map<String, dynamic> toJson() => _$UserCommentToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class UserCommentRequest {
  UserComment userComment;

  UserCommentRequest({this.userComment});

  factory UserCommentRequest.fromJson(Map<String, dynamic> json) =>
      _$UserCommentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserCommentRequestToJson(this);
}

/// User Comment Response
///
/// @author Seth Musselman
@JsonSerializable()
class UserCommentResponse {
  UserComment userComment;
  List<UserComment> userComments;

  UserCommentResponse({this.userComment, this.userComments});

  factory UserCommentResponse.fromJson(Map<String, dynamic> json) =>
      _$UserCommentResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserCommentResponseToJson(this);
}

/// Models a User consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserConsent {
  Consent consent;
  String consentId;
  Map<String, dynamic> data;
  String giverUserId;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  ConsentStatus status;
  String userId;
  List<String> values;

  UserConsent(
      {this.consent,
      this.consentId,
      this.data,
      this.giverUserId,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.status,
      this.userId,
      this.values});

  factory UserConsent.fromJson(Map<String, dynamic> json) =>
      _$UserConsentFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentToJson(this);
}

/// API response for User consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserConsentRequest {
  UserConsent userConsent;

  UserConsentRequest({this.userConsent});

  factory UserConsentRequest.fromJson(Map<String, dynamic> json) =>
      _$UserConsentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentRequestToJson(this);
}

/// API response for User consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserConsentResponse {
  UserConsent userConsent;
  List<UserConsent> userConsents;

  UserConsentResponse({this.userConsent, this.userConsents});

  factory UserConsentResponse.fromJson(Map<String, dynamic> json) =>
      _$UserConsentResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentResponseToJson(this);
}

/// Models the User Created Event.
/// <p>
/// This is different than the user.create event in that it will be sent after the user has been created. This event cannot be made transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserCreateCompleteEvent extends BaseEvent {
  User user;

  UserCreateCompleteEvent({this.user});

  factory UserCreateCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$UserCreateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserCreateCompleteEventToJson(this);
}

/// Models the User Create Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserCreateEvent extends BaseEvent {
  User user;

  UserCreateEvent({this.user});

  factory UserCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserCreateEventToJson(this);
}

/// Models the User Deactivate Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserDeactivateEvent extends BaseEvent {
  User user;

  UserDeactivateEvent({this.user});

  factory UserDeactivateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserDeactivateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeactivateEventToJson(this);
}

/// Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
/// delete).
/// <p>
/// This is different than user.delete because it is sent after the tx is committed, this cannot be transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserDeleteCompleteEvent extends BaseEvent {
  User user;

  UserDeleteCompleteEvent({this.user});

  factory UserDeleteCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$UserDeleteCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteCompleteEventToJson(this);
}

/// Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
/// delete).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserDeleteEvent extends BaseEvent {
  User user;

  UserDeleteEvent({this.user});

  factory UserDeleteEvent.fromJson(Map<String, dynamic> json) =>
      _$UserDeleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteEventToJson(this);
}

/// User API delete request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserDeleteRequest extends BaseEventRequest {
  bool dryRun;
  bool hardDelete;
  String query;
  String queryString;
  List<String> userIds;

  UserDeleteRequest(
      {this.dryRun,
      this.hardDelete,
      this.query,
      this.queryString,
      this.userIds});

  factory UserDeleteRequest.fromJson(Map<String, dynamic> json) =>
      _$UserDeleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteRequestToJson(this);
}

/// User API bulk response object.
///
/// @author Trevor Smith
@JsonSerializable()
class UserDeleteResponse {
  bool dryRun;
  bool hardDelete;
  num total;
  List<String> userIds;

  UserDeleteResponse({this.dryRun, this.hardDelete, this.total, this.userIds});

  factory UserDeleteResponse.fromJson(Map<String, dynamic> json) =>
      _$UserDeleteResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteResponseToJson(this);
}

/// User API delete request object for a single user.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserDeleteSingleRequest extends BaseEventRequest {
  bool hardDelete;

  UserDeleteSingleRequest({this.hardDelete});

  factory UserDeleteSingleRequest.fromJson(Map<String, dynamic> json) =>
      _$UserDeleteSingleRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteSingleRequestToJson(this);
}

/// Models an event where a user's email is updated outside of a forgot / change password workflow.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserEmailUpdateEvent extends BaseEvent {
  String previousEmail;
  User user;

  UserEmailUpdateEvent({this.previousEmail, this.user});

  factory UserEmailUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserEmailUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserEmailUpdateEventToJson(this);
}

/// Models the User Email Verify Event.
///
/// @author Trevor Smith
@JsonSerializable()
class UserEmailVerifiedEvent extends BaseEvent {
  User user;

  UserEmailVerifiedEvent({this.user});

  factory UserEmailVerifiedEvent.fromJson(Map<String, dynamic> json) =>
      _$UserEmailVerifiedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserEmailVerifiedEventToJson(this);
}

/// Models the User Identity Provider Link Event.
///
/// @author Rob Davis
@JsonSerializable()
class UserIdentityProviderLinkEvent extends BaseEvent {
  IdentityProviderLink identityProviderLink;
  User user;

  UserIdentityProviderLinkEvent({this.identityProviderLink, this.user});

  factory UserIdentityProviderLinkEvent.fromJson(Map<String, dynamic> json) =>
      _$UserIdentityProviderLinkEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserIdentityProviderLinkEventToJson(this);
}

/// Models the User Identity Provider Unlink Event.
///
/// @author Rob Davis
@JsonSerializable()
class UserIdentityProviderUnlinkEvent extends BaseEvent {
  IdentityProviderLink identityProviderLink;
  User user;

  UserIdentityProviderUnlinkEvent({this.identityProviderLink, this.user});

  factory UserIdentityProviderUnlinkEvent.fromJson(Map<String, dynamic> json) =>
      _$UserIdentityProviderUnlinkEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserIdentityProviderUnlinkEventToJson(this);
}

/// Models the User Login Failed Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginFailedEvent extends BaseEvent {
  String applicationId;
  String authenticationType;
  String ipAddress;
  User user;

  UserLoginFailedEvent(
      {this.applicationId, this.authenticationType, this.ipAddress, this.user});

  factory UserLoginFailedEvent.fromJson(Map<String, dynamic> json) =>
      _$UserLoginFailedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginFailedEventToJson(this);
}

/// Models an event where a user is being created with an "in-use" login Id (email or username).
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginIdDuplicateOnCreateEvent extends BaseEvent {
  String duplicateEmail;
  String duplicateUsername;
  User existing;
  User user;

  UserLoginIdDuplicateOnCreateEvent(
      {this.duplicateEmail, this.duplicateUsername, this.existing, this.user});

  factory UserLoginIdDuplicateOnCreateEvent.fromJson(
          Map<String, dynamic> json) =>
      _$UserLoginIdDuplicateOnCreateEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserLoginIdDuplicateOnCreateEventToJson(this);
}

/// Models an event where a user is being updated and tries to use an "in-use" login Id (email or username).
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginIdDuplicateOnUpdateEvent
    extends UserLoginIdDuplicateOnCreateEvent {
  UserLoginIdDuplicateOnUpdateEvent();

  factory UserLoginIdDuplicateOnUpdateEvent.fromJson(
          Map<String, dynamic> json) =>
      _$UserLoginIdDuplicateOnUpdateEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserLoginIdDuplicateOnUpdateEventToJson(this);
}

/// Models the User Login event for a new device (un-recognized)
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginNewDeviceEvent extends UserLoginSuccessEvent {
  UserLoginNewDeviceEvent();

  factory UserLoginNewDeviceEvent.fromJson(Map<String, dynamic> json) =>
      _$UserLoginNewDeviceEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginNewDeviceEventToJson(this);
}

/// Models the User Login Success Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginSuccessEvent extends BaseEvent {
  String applicationId;
  String authenticationType;
  String connectorId;
  String identityProviderId;
  String identityProviderName;
  String ipAddress;
  User user;

  UserLoginSuccessEvent(
      {this.applicationId,
      this.authenticationType,
      this.connectorId,
      this.identityProviderId,
      this.identityProviderName,
      this.ipAddress,
      this.user});

  factory UserLoginSuccessEvent.fromJson(Map<String, dynamic> json) =>
      _$UserLoginSuccessEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginSuccessEventToJson(this);
}

/// Models the User Login event that is suspicious.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginSuspiciousEvent extends UserLoginSuccessEvent {
  Set<AuthenticationThreats> threatsDetected;

  UserLoginSuspiciousEvent({this.threatsDetected});

  factory UserLoginSuspiciousEvent.fromJson(Map<String, dynamic> json) =>
      _$UserLoginSuspiciousEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginSuspiciousEventToJson(this);
}

@JsonSerializable()
class UsernameModeration extends Enableable {
  String applicationId;

  UsernameModeration({this.applicationId});

  factory UsernameModeration.fromJson(Map<String, dynamic> json) =>
      _$UsernameModerationFromJson(json);
  Map<String, dynamic> toJson() => _$UsernameModerationToJson(this);
}

/// Models the User Password Breach Event.
///
/// @author Matthew Altman
@JsonSerializable()
class UserPasswordBreachEvent extends BaseEvent {
  User user;

  UserPasswordBreachEvent({this.user});

  factory UserPasswordBreachEvent.fromJson(Map<String, dynamic> json) =>
      _$UserPasswordBreachEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordBreachEventToJson(this);
}

/// Models the User Password Reset Send Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserPasswordResetSendEvent extends BaseEvent {
  User user;

  UserPasswordResetSendEvent({this.user});

  factory UserPasswordResetSendEvent.fromJson(Map<String, dynamic> json) =>
      _$UserPasswordResetSendEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordResetSendEventToJson(this);
}

/// Models the User Password Reset Start Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserPasswordResetStartEvent extends BaseEvent {
  User user;

  UserPasswordResetStartEvent({this.user});

  factory UserPasswordResetStartEvent.fromJson(Map<String, dynamic> json) =>
      _$UserPasswordResetStartEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordResetStartEventToJson(this);
}

/// Models the User Password Reset Success Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserPasswordResetSuccessEvent extends BaseEvent {
  User user;

  UserPasswordResetSuccessEvent({this.user});

  factory UserPasswordResetSuccessEvent.fromJson(Map<String, dynamic> json) =>
      _$UserPasswordResetSuccessEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordResetSuccessEventToJson(this);
}

/// Models the User Password Update Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserPasswordUpdateEvent extends BaseEvent {
  User user;

  UserPasswordUpdateEvent({this.user});

  factory UserPasswordUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserPasswordUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordUpdateEventToJson(this);
}

/// Models the User Reactivate Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserReactivateEvent extends BaseEvent {
  User user;

  UserReactivateEvent({this.user});

  factory UserReactivateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserReactivateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserReactivateEventToJson(this);
}

/// User registration information for a single application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserRegistration {
  String applicationId;
  String authenticationToken;
  String cleanSpeakId;
  Map<String, dynamic> data;
  String id;
  num insertInstant;
  num lastLoginInstant;
  num lastUpdateInstant;
  List<String> preferredLanguages;
  Set<String> roles;
  String timezone;
  Map<String, String> tokens;
  String username;
  ContentStatus usernameStatus;
  bool verified;

  UserRegistration(
      {this.applicationId,
      this.authenticationToken,
      this.cleanSpeakId,
      this.data,
      this.id,
      this.insertInstant,
      this.lastLoginInstant,
      this.lastUpdateInstant,
      this.preferredLanguages,
      this.roles,
      this.timezone,
      this.tokens,
      this.username,
      this.usernameStatus,
      this.verified});

  factory UserRegistration.fromJson(Map<String, dynamic> json) =>
      _$UserRegistrationFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationToJson(this);
}

/// Models the User Created Registration Event.
/// <p>
/// This is different than the user.registration.create event in that it will be sent after the user has been created. This event cannot be made
/// transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationCreateCompleteEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationCreateCompleteEvent(
      {this.applicationId, this.registration, this.user});

  factory UserRegistrationCreateCompleteEvent.fromJson(
          Map<String, dynamic> json) =>
      _$UserRegistrationCreateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserRegistrationCreateCompleteEventToJson(this);
}

/// Models the User Create Registration Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationCreateEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationCreateEvent(
      {this.applicationId, this.registration, this.user});

  factory UserRegistrationCreateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserRegistrationCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationCreateEventToJson(this);
}

/// Models the User Deleted Registration Event.
/// <p>
/// This is different than user.registration.delete in that it is sent after the TX has been committed. This event cannot be transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationDeleteCompleteEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationDeleteCompleteEvent(
      {this.applicationId, this.registration, this.user});

  factory UserRegistrationDeleteCompleteEvent.fromJson(
          Map<String, dynamic> json) =>
      _$UserRegistrationDeleteCompleteEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserRegistrationDeleteCompleteEventToJson(this);
}

/// Models the User Delete Registration Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationDeleteEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationDeleteEvent(
      {this.applicationId, this.registration, this.user});

  factory UserRegistrationDeleteEvent.fromJson(Map<String, dynamic> json) =>
      _$UserRegistrationDeleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationDeleteEventToJson(this);
}

/// Models the User Update Registration Event.
/// <p>
/// This is different than user.registration.update in that it is sent after this event completes, this cannot be transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationUpdateCompleteEvent extends BaseEvent {
  String applicationId;
  UserRegistration original;
  UserRegistration registration;
  User user;

  UserRegistrationUpdateCompleteEvent(
      {this.applicationId, this.original, this.registration, this.user});

  factory UserRegistrationUpdateCompleteEvent.fromJson(
          Map<String, dynamic> json) =>
      _$UserRegistrationUpdateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() =>
      _$UserRegistrationUpdateCompleteEventToJson(this);
}

/// Models the User Update Registration Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationUpdateEvent extends BaseEvent {
  String applicationId;
  UserRegistration original;
  UserRegistration registration;
  User user;

  UserRegistrationUpdateEvent(
      {this.applicationId, this.original, this.registration, this.user});

  factory UserRegistrationUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserRegistrationUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationUpdateEventToJson(this);
}

/// Models the User Registration Verified Event.
///
/// @author Trevor Smith
@JsonSerializable()
class UserRegistrationVerifiedEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationVerifiedEvent(
      {this.applicationId, this.registration, this.user});

  factory UserRegistrationVerifiedEvent.fromJson(Map<String, dynamic> json) =>
      _$UserRegistrationVerifiedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationVerifiedEventToJson(this);
}

/// User API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserRequest extends BaseEventRequest {
  String applicationId;
  bool disableDomainBlock;
  bool sendSetPasswordEmail;
  bool skipVerification;
  User user;

  UserRequest(
      {this.applicationId,
      this.disableDomainBlock,
      this.sendSetPasswordEmail,
      this.skipVerification,
      this.user});

  factory UserRequest.fromJson(Map<String, dynamic> json) =>
      _$UserRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserRequestToJson(this);
}

/// User API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserResponse {
  String emailVerificationId;
  Map<String, String> registrationVerificationIds;
  String token;
  num tokenExpirationInstant;
  User user;

  UserResponse(
      {this.emailVerificationId,
      this.registrationVerificationIds,
      this.token,
      this.tokenExpirationInstant,
      this.user});

  factory UserResponse.fromJson(Map<String, dynamic> json) =>
      _$UserResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserResponseToJson(this);
}

/// This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserSearchCriteria extends BaseElasticSearchCriteria {
  UserSearchCriteria();

  factory UserSearchCriteria.fromJson(Map<String, dynamic> json) =>
      _$UserSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$UserSearchCriteriaToJson(this);
}

/// @author Daniel DeGroff
enum UserState {
  @JsonValue('Authenticated')
  Authenticated,
  @JsonValue('AuthenticatedNotRegistered')
  AuthenticatedNotRegistered,
  @JsonValue('AuthenticatedNotVerified')
  AuthenticatedNotVerified,
  @JsonValue('AuthenticatedRegistrationNotVerified')
  AuthenticatedRegistrationNotVerified
}

/// @author Daniel DeGroff
@JsonSerializable()
class UserTwoFactorConfiguration {
  List<TwoFactorMethod> methods;
  List<String> recoveryCodes;

  UserTwoFactorConfiguration({this.methods, this.recoveryCodes});

  factory UserTwoFactorConfiguration.fromJson(Map<String, dynamic> json) =>
      _$UserTwoFactorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$UserTwoFactorConfigurationToJson(this);
}

/// Model a user event when a two-factor method has been removed.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserTwoFactorMethodAddEvent extends BaseEvent {
  TwoFactorMethod method;
  User user;

  UserTwoFactorMethodAddEvent({this.method, this.user});

  factory UserTwoFactorMethodAddEvent.fromJson(Map<String, dynamic> json) =>
      _$UserTwoFactorMethodAddEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserTwoFactorMethodAddEventToJson(this);
}

/// Model a user event when a two-factor method has been added.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserTwoFactorMethodRemoveEvent extends BaseEvent {
  TwoFactorMethod method;
  User user;

  UserTwoFactorMethodRemoveEvent({this.method, this.user});

  factory UserTwoFactorMethodRemoveEvent.fromJson(Map<String, dynamic> json) =>
      _$UserTwoFactorMethodRemoveEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserTwoFactorMethodRemoveEventToJson(this);
}

/// Models the User Update Event once it is completed. This cannot be transactional.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserUpdateCompleteEvent extends BaseEvent {
  User original;
  User user;

  UserUpdateCompleteEvent({this.original, this.user});

  factory UserUpdateCompleteEvent.fromJson(Map<String, dynamic> json) =>
      _$UserUpdateCompleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserUpdateCompleteEventToJson(this);
}

/// Models the User Update Event.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserUpdateEvent extends BaseEvent {
  User original;
  User user;

  UserUpdateEvent({this.original, this.user});

  factory UserUpdateEvent.fromJson(Map<String, dynamic> json) =>
      _$UserUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserUpdateEventToJson(this);
}

/// Used to express whether the Relying Party requires <a href="https://www.w3.org/TR/webauthn-2/#user-verification">user verification</a> for the
/// current operation.
///
/// @author Spencer Witt
enum UserVerificationRequirement {
  @JsonValue('required')
  required,
  @JsonValue('preferred')
  preferred,
  @JsonValue('discouraged')
  discouraged
}

/// @author Daniel DeGroff
@JsonSerializable()
class ValidateResponse {
  JWT jwt;

  ValidateResponse({this.jwt});

  factory ValidateResponse.fromJson(Map<String, dynamic> json) =>
      _$ValidateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ValidateResponseToJson(this);
}

/// @author Daniel DeGroff
enum VerificationStrategy {
  @JsonValue('ClickableLink')
  ClickableLink,
  @JsonValue('FormField')
  FormField
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyEmailRequest extends BaseEventRequest {
  String oneTimeCode;
  String userId;
  String verificationId;

  VerifyEmailRequest({this.oneTimeCode, this.userId, this.verificationId});

  factory VerifyEmailRequest.fromJson(Map<String, dynamic> json) =>
      _$VerifyEmailRequestFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyEmailRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyEmailResponse {
  String oneTimeCode;
  String verificationId;

  VerifyEmailResponse({this.oneTimeCode, this.verificationId});

  factory VerifyEmailResponse.fromJson(Map<String, dynamic> json) =>
      _$VerifyEmailResponseFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyEmailResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyRegistrationRequest extends BaseEventRequest {
  String oneTimeCode;
  String verificationId;

  VerifyRegistrationRequest({this.oneTimeCode, this.verificationId});

  factory VerifyRegistrationRequest.fromJson(Map<String, dynamic> json) =>
      _$VerifyRegistrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyRegistrationRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyRegistrationResponse {
  String oneTimeCode;
  String verificationId;

  VerifyRegistrationResponse({this.oneTimeCode, this.verificationId});

  factory VerifyRegistrationResponse.fromJson(Map<String, dynamic> json) =>
      _$VerifyRegistrationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyRegistrationResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VersionResponse {
  String version;

  VersionResponse({this.version});

  factory VersionResponse.fromJson(Map<String, dynamic> json) =>
      _$VersionResponseFromJson(json);
  Map<String, dynamic> toJson() => _$VersionResponseToJson(this);
}

/// Request to complete the WebAuthn registration ceremony for a new credential
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnCompleteRequest {
  PublicKeyRegistrationRequest credential;
  String origin;
  String rpId;
  String userId;

  WebAuthnCompleteRequest(
      {this.credential, this.origin, this.rpId, this.userId});

  factory WebAuthnCompleteRequest.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnCompleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnCompleteRequestToJson(this);
}

/// API response for completing WebAuthn credential registration or assertion
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnCompleteResponse {
  String credentialId;

  WebAuthnCompleteResponse({this.credentialId});

  factory WebAuthnCompleteResponse.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnCompleteResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnCompleteResponseToJson(this);
}

/// A User's WebAuthnCredential. Contains all data required to complete WebAuthn authentication ceremonies.
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnCredential {
  CoseAlgorithmIdentifier algorithm;
  AttestationType attestationType;
  bool authenticatorSupportsUserVerification;
  String credentialId;
  String displayName;
  String id;
  num insertInstant;
  bool isDiscoverableCredential;
  num lastUseInstant;
  String name;
  String publicKey;
  String relyingPartyId;
  num signCount;
  String tenantId;
  List<AuthenticatorTransport> transports;
  String userAgent;
  String userId;

  WebAuthnCredential(
      {this.algorithm,
      this.attestationType,
      this.authenticatorSupportsUserVerification,
      this.credentialId,
      this.displayName,
      this.id,
      this.insertInstant,
      this.isDiscoverableCredential,
      this.lastUseInstant,
      this.name,
      this.publicKey,
      this.relyingPartyId,
      this.signCount,
      this.tenantId,
      this.transports,
      this.userAgent,
      this.userId});

  factory WebAuthnCredential.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnCredentialFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnCredentialToJson(this);
}

/// WebAuthn Credential API response
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnCredentialResponse {
  WebAuthnCredential webauthnCredential;
  List<WebAuthnCredential> webauthnCredentials;

  WebAuthnCredentialResponse(
      {this.webauthnCredential, this.webauthnCredentials});

  factory WebAuthnCredentialResponse.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnCredentialResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnCredentialResponseToJson(this);
}

/// Contains extension output for requested extensions during a WebAuthn ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnExtensionsClientOutputs {
  CredentialPropertiesOutput credProps;

  WebAuthnExtensionsClientOutputs({this.credProps});

  factory WebAuthnExtensionsClientOutputs.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnExtensionsClientOutputsFromJson(json);
  Map<String, dynamic> toJson() =>
      _$WebAuthnExtensionsClientOutputsToJson(this);
}

/// API request to import an existing WebAuthn credential
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnImportRequest {
  WebAuthnCredential credential;

  WebAuthnImportRequest({this.credential});

  factory WebAuthnImportRequest.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnImportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnImportRequestToJson(this);
}

/// Request to complete the WebAuthn registration ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnLoginRequest extends BaseLoginRequest {
  PublicKeyAuthenticationRequest credential;
  String origin;
  String rpId;

  WebAuthnLoginRequest({this.credential, this.origin, this.rpId});

  factory WebAuthnLoginRequest.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnLoginRequestToJson(this);
}

/// API request to start a WebAuthn registration ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnRegisterRequest {
  String displayName;
  String name;
  String userAgent;
  String userId;
  WebAuthnWorkflow workflow;

  WebAuthnRegisterRequest(
      {this.displayName,
      this.name,
      this.userAgent,
      this.userId,
      this.workflow});

  factory WebAuthnRegisterRequest.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnRegisterRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnRegisterRequestToJson(this);
}

/// API response for starting a WebAuthn registration ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnRegisterResponse {
  PublicKeyCredentialCreationOptions options;

  WebAuthnRegisterResponse({this.options});

  factory WebAuthnRegisterResponse.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnRegisterResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnRegisterResponseToJson(this);
}

/// Options to request extensions during credential registration
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnRegistrationExtensionOptions {
  bool credProps;

  WebAuthnRegistrationExtensionOptions({this.credProps});

  factory WebAuthnRegistrationExtensionOptions.fromJson(
          Map<String, dynamic> json) =>
      _$WebAuthnRegistrationExtensionOptionsFromJson(json);
  Map<String, dynamic> toJson() =>
      _$WebAuthnRegistrationExtensionOptionsToJson(this);
}

/// API request to start a WebAuthn authentication ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnStartRequest {
  String applicationId;
  String credentialId;
  String loginId;
  Map<String, dynamic> state;
  String userId;
  WebAuthnWorkflow workflow;

  WebAuthnStartRequest(
      {this.applicationId,
      this.credentialId,
      this.loginId,
      this.state,
      this.userId,
      this.workflow});

  factory WebAuthnStartRequest.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnStartRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnStartRequestToJson(this);
}

/// API response for starting a WebAuthn authentication ceremony
///
/// @author Spencer Witt
@JsonSerializable()
class WebAuthnStartResponse {
  PublicKeyCredentialRequestOptions options;

  WebAuthnStartResponse({this.options});

  factory WebAuthnStartResponse.fromJson(Map<String, dynamic> json) =>
      _$WebAuthnStartResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebAuthnStartResponseToJson(this);
}

/// Identifies the WebAuthn workflow. This will affect the parameters used for credential creation
/// and request based on the Tenant configuration.
///
/// @author Spencer Witt
enum WebAuthnWorkflow {
  @JsonValue('reAuthentication')
  reAuthentication,
  @JsonValue('bootstrap')
  bootstrap,
  @JsonValue('twoFactor')
  twoFactor,
  @JsonValue('general')
  general
}

/// A server where events are sent. This includes user action events and any other events sent by FusionAuth.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Webhook {
  num connectTimeout;
  Map<String, dynamic> data;
  String description;
  Map<EventType, bool> eventsEnabled;
  bool global;
  Map<String, String> headers;
  String httpAuthenticationPassword;
  String httpAuthenticationUsername;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  num readTimeout;
  String sslCertificate;
  List<String> tenantIds;
  String url;

  Webhook(
      {this.connectTimeout,
      this.data,
      this.description,
      this.eventsEnabled,
      this.global,
      this.headers,
      this.httpAuthenticationPassword,
      this.httpAuthenticationUsername,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.readTimeout,
      this.sslCertificate,
      this.tenantIds,
      this.url});

  factory Webhook.fromJson(Map<String, dynamic> json) =>
      _$WebhookFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookToJson(this);
}

/// Webhook API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class WebhookRequest {
  Webhook webhook;

  WebhookRequest({this.webhook});

  factory WebhookRequest.fromJson(Map<String, dynamic> json) =>
      _$WebhookRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookRequestToJson(this);
}

/// Webhook API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class WebhookResponse {
  Webhook webhook;
  List<Webhook> webhooks;

  WebhookResponse({this.webhook, this.webhooks});

  factory WebhookResponse.fromJson(Map<String, dynamic> json) =>
      _$WebhookResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookResponseToJson(this);
}

/// @author Brett Pontarelli
@JsonSerializable()
class XboxApplicationConfiguration
    extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  XboxApplicationConfiguration(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory XboxApplicationConfiguration.fromJson(Map<String, dynamic> json) =>
      _$XboxApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$XboxApplicationConfigurationToJson(this);
}

/// Xbox gaming login provider.
///
/// @author Brett Pontarelli
@JsonSerializable()
class XboxIdentityProvider
    extends BaseIdentityProvider<XboxApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  XboxIdentityProvider(
      {this.buttonText, this.client_id, this.client_secret, this.scope});

  factory XboxIdentityProvider.fromJson(Map<String, dynamic> json) =>
      _$XboxIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$XboxIdentityProviderToJson(this);
}

enum XMLSignatureLocation {
  @JsonValue('Assertion')
  Assertion,
  @JsonValue('Response')
  Response
}

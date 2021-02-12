/*
* Copyright (c) 2019, FusionAuth, All Rights Reserved
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
  String scope;
  TokenType token_type;
  String userId;

  AccessToken({
      this.access_token,
      this.expires_in,
      this.id_token,
      this.refresh_token,
      this.scope,
      this.token_type,
      this.userId
  });

  factory AccessToken.fromJson(Map<String, dynamic> json) => _$AccessTokenFromJson(json);
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

  ActionData({
      this.actioneeUserId,
      this.actionerUserId,
      this.applicationIds,
      this.comment,
      this.emailUser,
      this.expiry,
      this.notifyUser,
      this.option,
      this.reasonId,
      this.userActionId
  });

  factory ActionData.fromJson(Map<String, dynamic> json) => _$ActionDataFromJson(json);
  Map<String, dynamic> toJson() => _$ActionDataToJson(this);
}

/// The user action request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ActionRequest {
  ActionData action;
  bool broadcast;

  ActionRequest({
      this.action,
      this.broadcast
  });

  factory ActionRequest.fromJson(Map<String, dynamic> json) => _$ActionRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ActionRequestToJson(this);
}

/// The user action response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ActionResponse {
  UserActionLog action;
  List<UserActionLog> actions;

  ActionResponse({
      this.action,
      this.actions
  });

  factory ActionResponse.fromJson(Map<String, dynamic> json) => _$ActionResponseFromJson(json);
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
  @JsonValue('RS256')
  RS256,
  @JsonValue('RS384')
  RS384,
  @JsonValue('RS512')
  RS512,
  @JsonValue('none')
  none
}

/// @author Daniel DeGroff
@JsonSerializable()
class AppleApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String keyId;
  String scope;
  String servicesId;
  String teamId;

  AppleApplicationConfiguration({
      this.buttonText,
      this.keyId,
      this.scope,
      this.servicesId,
      this.teamId
  });

  factory AppleApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$AppleApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AppleApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AppleIdentityProvider extends BaseIdentityProvider<AppleApplicationConfiguration> {
  String buttonText;
  String keyId;
  String scope;
  String servicesId;
  String teamId;

  AppleIdentityProvider({
      this.buttonText,
      this.keyId,
      this.scope,
      this.servicesId,
      this.teamId
  });

  factory AppleIdentityProvider.fromJson(Map<String, dynamic> json) => _$AppleIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$AppleIdentityProviderToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class Application {
  bool active;
  AuthenticationTokenConfiguration authenticationTokenConfiguration;
  CleanSpeakConfiguration cleanSpeakConfiguration;
  Map<String, dynamic> data;
  ApplicationEmailConfiguration emailConfiguration;
  ApplicationFormConfiguration formConfiguration;
  String id;
  num insertInstant;
  JWTConfiguration jwtConfiguration;
  dynamic lambdaConfiguration;
  num lastUpdateInstant;
  LoginConfiguration loginConfiguration;
  String name;
  OAuth2Configuration oauthConfiguration;
  PasswordlessConfiguration passwordlessConfiguration;
  RegistrationConfiguration registrationConfiguration;
  ApplicationRegistrationDeletePolicy registrationDeletePolicy;
  List<ApplicationRole> roles;
  SAMLv2Configuration samlv2Configuration;
  ObjectState state;
  String tenantId;
  String verificationEmailTemplateId;
  bool verifyRegistration;

  Application({
      this.active,
      this.authenticationTokenConfiguration,
      this.cleanSpeakConfiguration,
      this.data,
      this.emailConfiguration,
      this.formConfiguration,
      this.id,
      this.insertInstant,
      this.jwtConfiguration,
      this.lambdaConfiguration,
      this.lastUpdateInstant,
      this.loginConfiguration,
      this.name,
      this.oauthConfiguration,
      this.passwordlessConfiguration,
      this.registrationConfiguration,
      this.registrationDeletePolicy,
      this.roles,
      this.samlv2Configuration,
      this.state,
      this.tenantId,
      this.verificationEmailTemplateId,
      this.verifyRegistration
  });

  factory Application.fromJson(Map<String, dynamic> json) => _$ApplicationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationToJson(this);
}

@JsonSerializable()
class ApplicationEmailConfiguration {
  String emailVerificationEmailTemplateId;
  String forgotPasswordEmailTemplateId;
  String passwordlessEmailTemplateId;
  String setPasswordEmailTemplateId;

  ApplicationEmailConfiguration({
      this.emailVerificationEmailTemplateId,
      this.forgotPasswordEmailTemplateId,
      this.passwordlessEmailTemplateId,
      this.setPasswordEmailTemplateId
  });

  factory ApplicationEmailConfiguration.fromJson(Map<String, dynamic> json) => _$ApplicationEmailConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationEmailConfigurationToJson(this);
}

/// Events that are bound to applications.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ApplicationEvent {

  ApplicationEvent();

  factory ApplicationEvent.fromJson(Map<String, dynamic> json) => _$ApplicationEventFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ApplicationFormConfiguration {
  String adminRegistrationFormId;

  ApplicationFormConfiguration({
      this.adminRegistrationFormId
  });

  factory ApplicationFormConfiguration.fromJson(Map<String, dynamic> json) => _$ApplicationFormConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationFormConfigurationToJson(this);
}

/// A Application-level policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class ApplicationRegistrationDeletePolicy {
  TimeBasedDeletePolicy unverified;

  ApplicationRegistrationDeletePolicy({
      this.unverified
  });

  factory ApplicationRegistrationDeletePolicy.fromJson(Map<String, dynamic> json) => _$ApplicationRegistrationDeletePolicyFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationRegistrationDeletePolicyToJson(this);
}

/// The Application API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ApplicationRequest {
  Application application;
  ApplicationRole role;
  List<String> webhookIds;

  ApplicationRequest({
      this.application,
      this.role,
      this.webhookIds
  });

  factory ApplicationRequest.fromJson(Map<String, dynamic> json) => _$ApplicationRequestFromJson(json);
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

  ApplicationResponse({
      this.application,
      this.applications,
      this.role
  });

  factory ApplicationResponse.fromJson(Map<String, dynamic> json) => _$ApplicationResponseFromJson(json);
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

  ApplicationRole({
      this.description,
      this.id,
      this.insertInstant,
      this.isDefault,
      this.isSuperRole,
      this.lastUpdateInstant,
      this.name
  });

  factory ApplicationRole.fromJson(Map<String, dynamic> json) => _$ApplicationRoleFromJson(json);
  Map<String, dynamic> toJson() => _$ApplicationRoleToJson(this);
}

/// This class is a simple attachment with a byte array, name and MIME type.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Attachment {
  List<num> attachment;
  String mime;
  String name;

  Attachment({
      this.attachment,
      this.mime,
      this.name
  });

  factory Attachment.fromJson(Map<String, dynamic> json) => _$AttachmentFromJson(json);
  Map<String, dynamic> toJson() => _$AttachmentToJson(this);
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

  AuditLog({
      this.data,
      this.id,
      this.insertInstant,
      this.insertUser,
      this.message,
      this.newValue,
      this.oldValue,
      this.reason
  });

  factory AuditLog.fromJson(Map<String, dynamic> json) => _$AuditLogFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogToJson(this);
}

@JsonSerializable()
class AuditLogConfiguration {
  DeleteConfiguration delete;

  AuditLogConfiguration({
      this.delete
  });

  factory AuditLogConfiguration.fromJson(Map<String, dynamic> json) => _$AuditLogConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class AuditLogExportRequest extends BaseExportRequest {
  AuditLogSearchCriteria criteria;

  AuditLogExportRequest({
      this.criteria
  });

  factory AuditLogExportRequest.fromJson(Map<String, dynamic> json) => _$AuditLogExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogExportRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogRequest {
  AuditLog auditLog;

  AuditLogRequest({
      this.auditLog
  });

  factory AuditLogRequest.fromJson(Map<String, dynamic> json) => _$AuditLogRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogRequestToJson(this);
}

/// Audit log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogResponse {
  AuditLog auditLog;

  AuditLogResponse({
      this.auditLog
  });

  factory AuditLogResponse.fromJson(Map<String, dynamic> json) => _$AuditLogResponseFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchCriteria extends BaseSearchCriteria {
  num end;
  String message;
  num start;
  String user;

  AuditLogSearchCriteria({
      this.end,
      this.message,
      this.start,
      this.user
  });

  factory AuditLogSearchCriteria.fromJson(Map<String, dynamic> json) => _$AuditLogSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchCriteriaToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchRequest {
  AuditLogSearchCriteria search;

  AuditLogSearchRequest({
      this.search
  });

  factory AuditLogSearchRequest.fromJson(Map<String, dynamic> json) => _$AuditLogSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchRequestToJson(this);
}

/// Audit log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class AuditLogSearchResponse {
  List<AuditLog> auditLogs;
  num total;

  AuditLogSearchResponse({
      this.auditLogs,
      this.total
  });

  factory AuditLogSearchResponse.fromJson(Map<String, dynamic> json) => _$AuditLogSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$AuditLogSearchResponseToJson(this);
}

@JsonSerializable()
class AuthenticationTokenConfiguration extends Enableable {

  AuthenticationTokenConfiguration();

  factory AuthenticationTokenConfiguration.fromJson(Map<String, dynamic> json) => _$AuthenticationTokenConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$AuthenticationTokenConfigurationToJson(this);
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

  BaseConnectorConfiguration({
      this.data,
      this.debug,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.type
  });

  factory BaseConnectorConfiguration.fromJson(Map<String, dynamic> json) => _$BaseConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$BaseConnectorConfigurationToJson(this);
}

/// Base-class for all FusionAuth events.
///
/// @author Brian Pontarelli
@JsonSerializable()
class BaseEvent {
  num createInstant;
  String id;
  String tenantId;

  BaseEvent({
      this.createInstant,
      this.id,
      this.tenantId
  });

  factory BaseEvent.fromJson(Map<String, dynamic> json) => _$BaseEventFromJson(json);
  Map<String, dynamic> toJson() => _$BaseEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseExportRequest {
  String dateTimeSecondsFormat;
  String zoneId;

  BaseExportRequest({
      this.dateTimeSecondsFormat,
      this.zoneId
  });

  factory BaseExportRequest.fromJson(Map<String, dynamic> json) => _$BaseExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$BaseExportRequestToJson(this);
}

// Do not require a setter for 'type', it is defined by the concrete class and is not mutable
@JsonSerializable(createFactory: false)
class BaseIdentityProvider<D extends BaseIdentityProviderApplicationConfiguration> extends Enableable {
  @IdentityProviderApplicationConfigurationConverter()
  Map<String, D> applicationConfiguration;
  Map<String, dynamic> data;
  bool debug;
  String id;
  num insertInstant;
  dynamic lambdaConfiguration;
  num lastUpdateInstant;
  String name;
  IdentityProviderType type;

  BaseIdentityProvider({
      this.applicationConfiguration,
      this.data,
      this.debug,
      this.id,
      this.insertInstant,
      this.lambdaConfiguration,
      this.lastUpdateInstant,
      this.name,
      this.type
  });

  factory BaseIdentityProvider.fromJson(Map<String, dynamic> json) => BaseIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$BaseIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseIdentityProviderApplicationConfiguration extends Enableable {
  bool createRegistration;
  Map<String, dynamic> data;

  BaseIdentityProviderApplicationConfiguration({
      this.createRegistration,
      this.data
  });

  factory BaseIdentityProviderApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$BaseIdentityProviderApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$BaseIdentityProviderApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class BaseLoginRequest {
  String applicationId;
  String ipAddress;
  MetaData metaData;
  bool noJWT;

  BaseLoginRequest({
      this.applicationId,
      this.ipAddress,
      this.metaData,
      this.noJWT
  });

  factory BaseLoginRequest.fromJson(Map<String, dynamic> json) => _$BaseLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$BaseLoginRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class BaseSearchCriteria {
  num numberOfResults;
  String orderBy;
  num startRow;

  BaseSearchCriteria({
      this.numberOfResults,
      this.orderBy,
      this.startRow
  });

  factory BaseSearchCriteria.fromJson(Map<String, dynamic> json) => _$BaseSearchCriteriaFromJson(json);
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

  CertificateInformation({
      this.issuer,
      this.md5Fingerprint,
      this.serialNumber,
      this.sha1Fingerprint,
      this.sha1Thumbprint,
      this.sha256Fingerprint,
      this.sha256Thumbprint,
      this.subject,
      this.validFrom,
      this.validTo
  });

  factory CertificateInformation.fromJson(Map<String, dynamic> json) => _$CertificateInformationFromJson(json);
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
class ChangePasswordRequest {
  String currentPassword;
  String loginId;
  String password;
  String refreshToken;

  ChangePasswordRequest({
      this.currentPassword,
      this.loginId,
      this.password,
      this.refreshToken
  });

  factory ChangePasswordRequest.fromJson(Map<String, dynamic> json) => _$ChangePasswordRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ChangePasswordRequestToJson(this);
}

/// Change password response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ChangePasswordResponse {
  String oneTimePassword;
  Map<String, dynamic> state;

  ChangePasswordResponse({
      this.oneTimePassword,
      this.state
  });

  factory ChangePasswordResponse.fromJson(Map<String, dynamic> json) => _$ChangePasswordResponseFromJson(json);
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

  CleanSpeakConfiguration({
      this.apiKey,
      this.applicationIds,
      this.url,
      this.usernameModeration
  });

  factory CleanSpeakConfiguration.fromJson(Map<String, dynamic> json) => _$CleanSpeakConfigurationFromJson(json);
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

/// @author Trevor Smith
@JsonSerializable()
class ConnectorPolicy {
  String connectorId;
  Map<String, dynamic> data;
  Set<String> domains;
  bool migrate;

  ConnectorPolicy({
      this.connectorId,
      this.data,
      this.domains,
      this.migrate
  });

  factory ConnectorPolicy.fromJson(Map<String, dynamic> json) => _$ConnectorPolicyFromJson(json);
  Map<String, dynamic> toJson() => _$ConnectorPolicyToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class ConnectorRequest {
  BaseConnectorConfiguration connector;

  ConnectorRequest({
      this.connector
  });

  factory ConnectorRequest.fromJson(Map<String, dynamic> json) => _$ConnectorRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ConnectorRequestToJson(this);
}

/// @author Trevor Smith
@JsonSerializable()
class ConnectorResponse {
  BaseConnectorConfiguration connector;
  List<BaseConnectorConfiguration> connectors;

  ConnectorResponse({
      this.connector,
      this.connectors
  });

  factory ConnectorResponse.fromJson(Map<String, dynamic> json) => _$ConnectorResponseFromJson(json);
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

  Consent({
      this.consentEmailTemplateId,
      this.countryMinimumAgeForSelfConsent,
      this.data,
      this.defaultMinimumAgeForSelfConsent,
      this.emailPlus,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.multipleValuesAllowed,
      this.name,
      this.values
  });

  factory Consent.fromJson(Map<String, dynamic> json) => _$ConsentFromJson(json);
  Map<String, dynamic> toJson() => _$ConsentToJson(this);
}

/// API request for User consent types.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ConsentRequest {
  Consent consent;

  ConsentRequest({
      this.consent
  });

  factory ConsentRequest.fromJson(Map<String, dynamic> json) => _$ConsentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ConsentRequestToJson(this);
}

/// API response for consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ConsentResponse {
  Consent consent;
  List<Consent> consents;

  ConsentResponse({
      this.consent,
      this.consents
  });

  factory ConsentResponse.fromJson(Map<String, dynamic> json) => _$ConsentResponseFromJson(json);
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
  List<String> exposedHeaders;
  num preflightMaxAgeInSeconds;

  CORSConfiguration({
      this.allowCredentials,
      this.allowedHeaders,
      this.allowedMethods,
      this.allowedOrigins,
      this.exposedHeaders,
      this.preflightMaxAgeInSeconds
  });

  factory CORSConfiguration.fromJson(Map<String, dynamic> json) => _$CORSConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$CORSConfigurationToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class Count {
  num count;
  num interval;

  Count({
      this.count,
      this.interval
  });

  factory Count.fromJson(Map<String, dynamic> json) => _$CountFromJson(json);
  Map<String, dynamic> toJson() => _$CountToJson(this);
}

/// Response for the daily active user report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class DailyActiveUserReportResponse {
  List<Count> dailyActiveUsers;
  num total;

  DailyActiveUserReportResponse({
      this.dailyActiveUsers,
      this.total
  });

  factory DailyActiveUserReportResponse.fromJson(Map<String, dynamic> json) => _$DailyActiveUserReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$DailyActiveUserReportResponseToJson(this);
}

@JsonSerializable()
class DeleteConfiguration extends Enableable {
  num numberOfDaysToRetain;

  DeleteConfiguration({
      this.numberOfDaysToRetain
  });

  factory DeleteConfiguration.fromJson(Map<String, dynamic> json) => _$DeleteConfigurationFromJson(json);
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

  DeviceInfo({
      this.description,
      this.lastAccessedAddress,
      this.lastAccessedInstant,
      this.name,
      this.type
  });

  factory DeviceInfo.fromJson(Map<String, dynamic> json) => _$DeviceInfoFromJson(json);
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

  DeviceResponse({
      this.device_code,
      this.expires_in,
      this.interval,
      this.user_code,
      this.verification_uri,
      this.verification_uri_complete
  });

  factory DeviceResponse.fromJson(Map<String, dynamic> json) => _$DeviceResponseFromJson(json);
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
  String loginId;

  DisplayableRawLogin({
      this.applicationName,
      this.loginId
  });

  factory DisplayableRawLogin.fromJson(Map<String, dynamic> json) => _$DisplayableRawLoginFromJson(json);
  Map<String, dynamic> toJson() => _$DisplayableRawLoginToJson(this);
}

/// Interface for all identity providers that can be domain based.
@JsonSerializable()
class DomainBasedIdentityProvider {

  DomainBasedIdentityProvider();

  factory DomainBasedIdentityProvider.fromJson(Map<String, dynamic> json) => _$DomainBasedIdentityProviderFromJson(json);
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

  Email({
      this.attachments,
      this.bcc,
      this.cc,
      this.from,
      this.html,
      this.replyTo,
      this.subject,
      this.text,
      this.to
  });

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

  EmailAddress({
      this.address,
      this.display
  });

  factory EmailAddress.fromJson(Map<String, dynamic> json) => _$EmailAddressFromJson(json);
  Map<String, dynamic> toJson() => _$EmailAddressToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EmailConfiguration {
  String defaultFromEmail;
  String defaultFromName;
  String forgotPasswordEmailTemplateId;
  String host;
  String password;
  String passwordlessEmailTemplateId;
  num port;
  String properties;
  EmailSecurityType security;
  String setPasswordEmailTemplateId;
  String username;
  String verificationEmailTemplateId;
  bool verifyEmail;
  bool verifyEmailWhenChanged;

  EmailConfiguration({
      this.defaultFromEmail,
      this.defaultFromName,
      this.forgotPasswordEmailTemplateId,
      this.host,
      this.password,
      this.passwordlessEmailTemplateId,
      this.port,
      this.properties,
      this.security,
      this.setPasswordEmailTemplateId,
      this.username,
      this.verificationEmailTemplateId,
      this.verifyEmail,
      this.verifyEmailWhenChanged
  });

  factory EmailConfiguration.fromJson(Map<String, dynamic> json) => _$EmailConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EmailConfigurationToJson(this);
}

@JsonSerializable()
class EmailPlus extends Enableable {
  String emailTemplateId;
  num maximumTimeToSendEmailInHours;
  num minimumTimeToSendEmailInHours;

  EmailPlus({
      this.emailTemplateId,
      this.maximumTimeToSendEmailInHours,
      this.minimumTimeToSendEmailInHours
  });

  factory EmailPlus.fromJson(Map<String, dynamic> json) => _$EmailPlusFromJson(json);
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

  EmailTemplate({
      this.defaultFromName,
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
      this.name
  });

  factory EmailTemplate.fromJson(Map<String, dynamic> json) => _$EmailTemplateFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateToJson(this);
}

@JsonSerializable()
class EmailTemplateErrors {
  Map<String, String> parseErrors;
  Map<String, String> renderErrors;

  EmailTemplateErrors({
      this.parseErrors,
      this.renderErrors
  });

  factory EmailTemplateErrors.fromJson(Map<String, dynamic> json) => _$EmailTemplateErrorsFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateErrorsToJson(this);
}

/// Email template request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailTemplateRequest {
  EmailTemplate emailTemplate;

  EmailTemplateRequest({
      this.emailTemplate
  });

  factory EmailTemplateRequest.fromJson(Map<String, dynamic> json) => _$EmailTemplateRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateRequestToJson(this);
}

/// Email template response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EmailTemplateResponse {
  EmailTemplate emailTemplate;
  List<EmailTemplate> emailTemplates;

  EmailTemplateResponse({
      this.emailTemplate,
      this.emailTemplates
  });

  factory EmailTemplateResponse.fromJson(Map<String, dynamic> json) => _$EmailTemplateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$EmailTemplateResponseToJson(this);
}

/// Something that can be enabled and thus also disabled.
///
/// @author Daniel DeGroff
@JsonSerializable()
class Enableable {
  bool enabled;

  Enableable({
      this.enabled
  });

  factory Enableable.fromJson(Map<String, dynamic> json) => _$EnableableFromJson(json);
  Map<String, dynamic> toJson() => _$EnableableToJson(this);
}

/// Defines an error.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Error {
  String code;
  String message;

  Error({
      this.code,
      this.message
  });

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

  Errors({
      this.fieldErrors,
      this.generalErrors
  });

  factory Errors.fromJson(Map<String, dynamic> json) => _$ErrorsFromJson(json);
  Map<String, dynamic> toJson() => _$ErrorsToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EventConfiguration {
  Map<EventType, EventConfigurationData> events;

  EventConfiguration({
      this.events
  });

  factory EventConfiguration.fromJson(Map<String, dynamic> json) => _$EventConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EventConfigurationToJson(this);
}

@JsonSerializable()
class EventConfigurationData extends Enableable {
  TransactionType transactionType;

  EventConfigurationData({
      this.transactionType
  });

  factory EventConfigurationData.fromJson(Map<String, dynamic> json) => _$EventConfigurationDataFromJson(json);
  Map<String, dynamic> toJson() => _$EventConfigurationDataToJson(this);
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

  EventLog({
      this.id,
      this.insertInstant,
      this.message,
      this.type
  });

  factory EventLog.fromJson(Map<String, dynamic> json) => _$EventLogFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogToJson(this);
}

@JsonSerializable()
class EventLogConfiguration {
  num numberToRetain;

  EventLogConfiguration({
      this.numberToRetain
  });

  factory EventLogConfiguration.fromJson(Map<String, dynamic> json) => _$EventLogConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogConfigurationToJson(this);
}

/// Event log response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class EventLogResponse {
  EventLog eventLog;

  EventLogResponse({
      this.eventLog
  });

  factory EventLogResponse.fromJson(Map<String, dynamic> json) => _$EventLogResponseFromJson(json);
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

  EventLogSearchCriteria({
      this.end,
      this.message,
      this.start,
      this.type
  });

  factory EventLogSearchCriteria.fromJson(Map<String, dynamic> json) => _$EventLogSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogSearchCriteriaToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class EventLogSearchRequest {
  EventLogSearchCriteria search;

  EventLogSearchRequest({
      this.search
  });

  factory EventLogSearchRequest.fromJson(Map<String, dynamic> json) => _$EventLogSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EventLogSearchRequestToJson(this);
}

/// Event log response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class EventLogSearchResponse {
  List<EventLog> eventLogs;
  num total;

  EventLogSearchResponse({
      this.eventLogs,
      this.total
  });

  factory EventLogSearchResponse.fromJson(Map<String, dynamic> json) => _$EventLogSearchResponseFromJson(json);
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

  EventRequest({
      this.event
  });

  factory EventRequest.fromJson(Map<String, dynamic> json) => _$EventRequestFromJson(json);
  Map<String, dynamic> toJson() => _$EventRequestToJson(this);
}

/// Models the event types that FusionAuth produces.
///
/// @author Brian Pontarelli
enum EventType {
  @JsonValue('UserDelete')
  UserDelete,
  @JsonValue('UserCreate')
  UserCreate,
  @JsonValue('UserUpdate')
  UserUpdate,
  @JsonValue('UserDeactivate')
  UserDeactivate,
  @JsonValue('UserBulkCreate')
  UserBulkCreate,
  @JsonValue('UserReactivate')
  UserReactivate,
  @JsonValue('UserAction')
  UserAction,
  @JsonValue('JWTRefreshTokenRevoke')
  JWTRefreshTokenRevoke,
  @JsonValue('JWTRefresh')
  JWTRefresh,
  @JsonValue('JWTPublicKeyUpdate')
  JWTPublicKeyUpdate,
  @JsonValue('UserLoginSuccess')
  UserLoginSuccess,
  @JsonValue('UserLoginFailed')
  UserLoginFailed,
  @JsonValue('UserRegistrationCreate')
  UserRegistrationCreate,
  @JsonValue('UserRegistrationUpdate')
  UserRegistrationUpdate,
  @JsonValue('UserRegistrationDelete')
  UserRegistrationDelete,
  @JsonValue('UserRegistrationVerified')
  UserRegistrationVerified,
  @JsonValue('UserEmailVerified')
  UserEmailVerified,
  @JsonValue('UserPasswordBreach')
  UserPasswordBreach,
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
  num externalAuthenticationIdTimeToLiveInSeconds;
  num oneTimePasswordTimeToLiveInSeconds;
  SecureGeneratorConfiguration passwordlessLoginGenerator;
  num passwordlessLoginTimeToLiveInSeconds;
  SecureGeneratorConfiguration registrationVerificationIdGenerator;
  num registrationVerificationIdTimeToLiveInSeconds;
  num samlv2AuthNRequestIdTimeToLiveInSeconds;
  SecureGeneratorConfiguration setupPasswordIdGenerator;
  num setupPasswordIdTimeToLiveInSeconds;
  num twoFactorIdTimeToLiveInSeconds;
  num twoFactorTrustIdTimeToLiveInSeconds;

  ExternalIdentifierConfiguration({
      this.authorizationGrantIdTimeToLiveInSeconds,
      this.changePasswordIdGenerator,
      this.changePasswordIdTimeToLiveInSeconds,
      this.deviceCodeTimeToLiveInSeconds,
      this.deviceUserCodeIdGenerator,
      this.emailVerificationIdGenerator,
      this.emailVerificationIdTimeToLiveInSeconds,
      this.externalAuthenticationIdTimeToLiveInSeconds,
      this.oneTimePasswordTimeToLiveInSeconds,
      this.passwordlessLoginGenerator,
      this.passwordlessLoginTimeToLiveInSeconds,
      this.registrationVerificationIdGenerator,
      this.registrationVerificationIdTimeToLiveInSeconds,
      this.samlv2AuthNRequestIdTimeToLiveInSeconds,
      this.setupPasswordIdGenerator,
      this.setupPasswordIdTimeToLiveInSeconds,
      this.twoFactorIdTimeToLiveInSeconds,
      this.twoFactorTrustIdTimeToLiveInSeconds
  });

  factory ExternalIdentifierConfiguration.fromJson(Map<String, dynamic> json) => _$ExternalIdentifierConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ExternalIdentifierConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ExternalJWTApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {

  ExternalJWTApplicationConfiguration();

  factory ExternalJWTApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$ExternalJWTApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$ExternalJWTApplicationConfigurationToJson(this);
}

/// External JWT-only identity provider.
///
/// @author Daniel DeGroff and Brian Pontarelli
@JsonSerializable()
class ExternalJWTIdentityProvider extends BaseIdentityProvider<ExternalJWTApplicationConfiguration> {
  Map<String, String> claimMap;
  String defaultKeyId;
  Set<String> domains;
  String headerKeyParameter;
  IdentityProviderOauth2Configuration oauth2;
  String uniqueIdentityClaim;

  ExternalJWTIdentityProvider({
      this.claimMap,
      this.defaultKeyId,
      this.domains,
      this.headerKeyParameter,
      this.oauth2,
      this.uniqueIdentityClaim
  });

  factory ExternalJWTIdentityProvider.fromJson(Map<String, dynamic> json) => _$ExternalJWTIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$ExternalJWTIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FacebookApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String appId;
  String buttonText;
  String client_secret;
  String fields;
  String permissions;

  FacebookApplicationConfiguration({
      this.appId,
      this.buttonText,
      this.client_secret,
      this.fields,
      this.permissions
  });

  factory FacebookApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$FacebookApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$FacebookApplicationConfigurationToJson(this);
}

/// Facebook social login provider.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FacebookIdentityProvider extends BaseIdentityProvider<FacebookApplicationConfiguration> {
  String appId;
  String buttonText;
  String client_secret;
  String fields;
  String permissions;

  FacebookIdentityProvider({
      this.appId,
      this.buttonText,
      this.client_secret,
      this.fields,
      this.permissions
  });

  factory FacebookIdentityProvider.fromJson(Map<String, dynamic> json) => _$FacebookIdentityProviderFromJson(json);
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

  FailedAuthenticationConfiguration({
      this.actionDuration,
      this.actionDurationUnit,
      this.resetCountInSeconds,
      this.tooManyAttempts,
      this.userActionId
  });

  factory FailedAuthenticationConfiguration.fromJson(Map<String, dynamic> json) => _$FailedAuthenticationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$FailedAuthenticationConfigurationToJson(this);
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

  Family({
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.members
  });

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

  FamilyConfiguration({
      this.allowChildRegistrations,
      this.confirmChildEmailTemplateId,
      this.deleteOrphanedAccounts,
      this.deleteOrphanedAccountsDays,
      this.familyRequestEmailTemplateId,
      this.maximumChildAge,
      this.minimumOwnerAge,
      this.parentEmailRequired,
      this.parentRegistrationEmailTemplateId
  });

  factory FamilyConfiguration.fromJson(Map<String, dynamic> json) => _$FamilyConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyConfigurationToJson(this);
}

/// API request for sending out family requests to parent's.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyEmailRequest {
  String parentEmail;

  FamilyEmailRequest({
      this.parentEmail
  });

  factory FamilyEmailRequest.fromJson(Map<String, dynamic> json) => _$FamilyEmailRequestFromJson(json);
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

  FamilyMember({
      this.data,
      this.insertInstant,
      this.lastUpdateInstant,
      this.owner,
      this.role,
      this.userId
  });

  factory FamilyMember.fromJson(Map<String, dynamic> json) => _$FamilyMemberFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyMemberToJson(this);
}

/// API request for managing families and members.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyRequest {
  FamilyMember familyMember;

  FamilyRequest({
      this.familyMember
  });

  factory FamilyRequest.fromJson(Map<String, dynamic> json) => _$FamilyRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FamilyRequestToJson(this);
}

/// API response for managing families and members.
///
/// @author Brian Pontarelli
@JsonSerializable()
class FamilyResponse {
  List<Family> families;
  Family family;

  FamilyResponse({
      this.families,
      this.family
  });

  factory FamilyResponse.fromJson(Map<String, dynamic> json) => _$FamilyResponseFromJson(json);
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
class ForgotPasswordRequest {
  String applicationId;
  String changePasswordId;
  String email;
  String loginId;
  bool sendForgotPasswordEmail;
  Map<String, dynamic> state;
  String username;

  ForgotPasswordRequest({
      this.applicationId,
      this.changePasswordId,
      this.email,
      this.loginId,
      this.sendForgotPasswordEmail,
      this.state,
      this.username
  });

  factory ForgotPasswordRequest.fromJson(Map<String, dynamic> json) => _$ForgotPasswordRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ForgotPasswordRequestToJson(this);
}

/// Forgot password response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class ForgotPasswordResponse {
  String changePasswordId;

  ForgotPasswordResponse({
      this.changePasswordId
  });

  factory ForgotPasswordResponse.fromJson(Map<String, dynamic> json) => _$ForgotPasswordResponseFromJson(json);
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

  Form({
      this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.steps,
      this.type
  });

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

  FormField({
      this.confirm,
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
      this.validator
  });

  factory FormField.fromJson(Map<String, dynamic> json) => _$FormFieldFromJson(json);
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

  FormFieldRequest({
      this.field,
      this.fields
  });

  factory FormFieldRequest.fromJson(Map<String, dynamic> json) => _$FormFieldRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldRequestToJson(this);
}

/// Form field response.
///
/// @author Brett Guy
@JsonSerializable()
class FormFieldResponse {
  FormField field;
  List<FormField> fields;

  FormFieldResponse({
      this.field,
      this.fields
  });

  factory FormFieldResponse.fromJson(Map<String, dynamic> json) => _$FormFieldResponseFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FormFieldValidator extends Enableable {
  String expression;

  FormFieldValidator({
      this.expression
  });

  factory FormFieldValidator.fromJson(Map<String, dynamic> json) => _$FormFieldValidatorFromJson(json);
  Map<String, dynamic> toJson() => _$FormFieldValidatorToJson(this);
}

/// Form response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class FormRequest {
  Form form;

  FormRequest({
      this.form
  });

  factory FormRequest.fromJson(Map<String, dynamic> json) => _$FormRequestFromJson(json);
  Map<String, dynamic> toJson() => _$FormRequestToJson(this);
}

/// Form response.
///
/// @author Daniel DeGroff
@JsonSerializable()
class FormResponse {
  Form form;
  List<Form> forms;

  FormResponse({
      this.form,
      this.forms
  });

  factory FormResponse.fromJson(Map<String, dynamic> json) => _$FormResponseFromJson(json);
  Map<String, dynamic> toJson() => _$FormResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class FormStep {
  List<String> fields;

  FormStep({
      this.fields
  });

  factory FormStep.fromJson(Map<String, dynamic> json) => _$FormStepFromJson(json);
  Map<String, dynamic> toJson() => _$FormStepToJson(this);
}

/// @author Daniel DeGroff
enum FormType {
  @JsonValue('registration')
  registration,
  @JsonValue('adminRegistration')
  adminRegistration,
  @JsonValue('adminUser')
  adminUser
}

/// Models the FusionAuth connector.
///
/// @author Trevor Smith
@JsonSerializable()
class FusionAuthConnectorConfiguration extends BaseConnectorConfiguration {

  FusionAuthConnectorConfiguration();

  factory FusionAuthConnectorConfiguration.fromJson(Map<String, dynamic> json) => _$FusionAuthConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$FusionAuthConnectorConfigurationToJson(this);
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

  GenericConnectorConfiguration({
      this.authenticationURL,
      this.connectTimeout,
      this.headers,
      this.httpAuthenticationPassword,
      this.httpAuthenticationUsername,
      this.readTimeout,
      this.sslCertificateKeyId
  });

  factory GenericConnectorConfiguration.fromJson(Map<String, dynamic> json) => _$GenericConnectorConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$GenericConnectorConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class GoogleApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  GoogleApplicationConfiguration({
      this.buttonText,
      this.client_id,
      this.client_secret,
      this.scope
  });

  factory GoogleApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$GoogleApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$GoogleApplicationConfigurationToJson(this);
}

/// Google social login provider.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GoogleIdentityProvider extends BaseIdentityProvider<GoogleApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  GoogleIdentityProvider({
      this.buttonText,
      this.client_id,
      this.client_secret,
      this.scope
  });

  factory GoogleIdentityProvider.fromJson(Map<String, dynamic> json) => _$GoogleIdentityProviderFromJson(json);
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

  Group({
      this.data,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.roles,
      this.tenantId
  });

  factory Group.fromJson(Map<String, dynamic> json) => _$GroupFromJson(json);
  Map<String, dynamic> toJson() => _$GroupToJson(this);
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
  String userId;

  GroupMember({
      this.data,
      this.groupId,
      this.id,
      this.insertInstant,
      this.userId
  });

  factory GroupMember.fromJson(Map<String, dynamic> json) => _$GroupMemberFromJson(json);
  Map<String, dynamic> toJson() => _$GroupMemberToJson(this);
}

/// Group API request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupRequest {
  Group group;
  List<String> roleIds;

  GroupRequest({
      this.group,
      this.roleIds
  });

  factory GroupRequest.fromJson(Map<String, dynamic> json) => _$GroupRequestFromJson(json);
  Map<String, dynamic> toJson() => _$GroupRequestToJson(this);
}

/// Group API response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class GroupResponse {
  Group group;
  List<Group> groups;

  GroupResponse({
      this.group,
      this.groups
  });

  factory GroupResponse.fromJson(Map<String, dynamic> json) => _$GroupResponseFromJson(json);
  Map<String, dynamic> toJson() => _$GroupResponseToJson(this);
}

@JsonSerializable()
class HistoryItem {
  String actionerUserId;
  String comment;
  num createInstant;
  num expiry;

  HistoryItem({
      this.actionerUserId,
      this.comment,
      this.createInstant,
      this.expiry
  });

  factory HistoryItem.fromJson(Map<String, dynamic> json) => _$HistoryItemFromJson(json);
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
class HYPRApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String relyingPartyApplicationId;
  String relyingPartyURL;

  HYPRApplicationConfiguration({
      this.relyingPartyApplicationId,
      this.relyingPartyURL
  });

  factory HYPRApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$HYPRApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$HYPRApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class HYPRIdentityProvider extends BaseIdentityProvider<HYPRApplicationConfiguration> {
  String relyingPartyApplicationId;
  String relyingPartyURL;

  HYPRIdentityProvider({
      this.relyingPartyApplicationId,
      this.relyingPartyURL
  });

  factory HYPRIdentityProvider.fromJson(Map<String, dynamic> json) => _$HYPRIdentityProviderFromJson(json);
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

  IdentityProviderDetails({
      this.applicationIds,
      this.id,
      this.idpEndpoint,
      this.name,
      this.oauth2,
      this.type
  });

  factory IdentityProviderDetails.fromJson(Map<String, dynamic> json) => _$IdentityProviderDetailsFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderDetailsToJson(this);
}

/// Login API request object used for login to third-party systems (i.e. Login with Facebook).
///
/// @author Brian Pontarelli
@JsonSerializable()
class IdentityProviderLoginRequest extends BaseLoginRequest {
  Map<String, String> data;
  String encodedJWT;
  String identityProviderId;

  IdentityProviderLoginRequest({
      this.data,
      this.encodedJWT,
      this.identityProviderId
  });

  factory IdentityProviderLoginRequest.fromJson(Map<String, dynamic> json) => _$IdentityProviderLoginRequestFromJson(json);
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
  String userinfo_endpoint;

  IdentityProviderOauth2Configuration({
      this.authorization_endpoint,
      this.client_id,
      this.client_secret,
      this.clientAuthenticationMethod,
      this.emailClaim,
      this.issuer,
      this.scope,
      this.token_endpoint,
      this.userinfo_endpoint
  });

  factory IdentityProviderOauth2Configuration.fromJson(Map<String, dynamic> json) => _$IdentityProviderOauth2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderOauth2ConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderRequest {
  @IdentityProviderConverter()
  BaseIdentityProvider<dynamic> identityProvider;

  IdentityProviderRequest({
      this.identityProvider
  });

  factory IdentityProviderRequest.fromJson(Map<String, dynamic> json) => _$IdentityProviderRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderResponse {
  @IdentityProviderConverter()
  BaseIdentityProvider<dynamic> identityProvider;
  List<BaseIdentityProvider<dynamic>> identityProviders;

  IdentityProviderResponse({
      this.identityProvider,
      this.identityProviders
  });

  factory IdentityProviderResponse.fromJson(Map<String, dynamic> json) => _$IdentityProviderResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderStartLoginRequest extends BaseLoginRequest {
  Map<String, String> data;
  String identityProviderId;
  String loginId;
  Map<String, dynamic> state;

  IdentityProviderStartLoginRequest({
      this.data,
      this.identityProviderId,
      this.loginId,
      this.state
  });

  factory IdentityProviderStartLoginRequest.fromJson(Map<String, dynamic> json) => _$IdentityProviderStartLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderStartLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IdentityProviderStartLoginResponse {
  String code;

  IdentityProviderStartLoginResponse({
      this.code
  });

  factory IdentityProviderStartLoginResponse.fromJson(Map<String, dynamic> json) => _$IdentityProviderStartLoginResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IdentityProviderStartLoginResponseToJson(this);
}

enum IdentityProviderType {
  @JsonValue('ExternalJWT')
  ExternalJWT,
  @JsonValue('OpenIDConnect')
  OpenIDConnect,
  @JsonValue('Facebook')
  Facebook,
  @JsonValue('Google')
  Google,
  @JsonValue('Twitter')
  Twitter,
  @JsonValue('SAMLv2')
  SAMLv2,
  @JsonValue('HYPR')
  HYPR,
  @JsonValue('Apple')
  Apple,
  @JsonValue('LinkedIn')
  LinkedIn
}

/// Import request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class ImportRequest {
  String encryptionScheme;
  num factor;
  List<User> users;
  bool validateDbConstraints;

  ImportRequest({
      this.encryptionScheme,
      this.factor,
      this.users,
      this.validateDbConstraints
  });

  factory ImportRequest.fromJson(Map<String, dynamic> json) => _$ImportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ImportRequestToJson(this);
}

/// The Integration Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class IntegrationRequest {
  Integrations integrations;

  IntegrationRequest({
      this.integrations
  });

  factory IntegrationRequest.fromJson(Map<String, dynamic> json) => _$IntegrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationRequestToJson(this);
}

/// The Integration Response
///
/// @author Daniel DeGroff
@JsonSerializable()
class IntegrationResponse {
  Integrations integrations;

  IntegrationResponse({
      this.integrations
  });

  factory IntegrationResponse.fromJson(Map<String, dynamic> json) => _$IntegrationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationResponseToJson(this);
}

/// Available Integrations
///
/// @author Daniel DeGroff
@JsonSerializable()
class Integrations {
  CleanSpeakConfiguration cleanspeak;
  KafkaConfiguration kafka;
  TwilioConfiguration twilio;

  Integrations({
      this.cleanspeak,
      this.kafka,
      this.twilio
  });

  factory Integrations.fromJson(Map<String, dynamic> json) => _$IntegrationsFromJson(json);
  Map<String, dynamic> toJson() => _$IntegrationsToJson(this);
}

/// Counts for a period.
///
/// @author Brian Pontarelli
@JsonSerializable()
class IntervalCount {
  String applicationId;
  num count;
  num decrementedCount;
  num period;

  IntervalCount({
      this.applicationId,
      this.count,
      this.decrementedCount,
      this.period
  });

  factory IntervalCount.fromJson(Map<String, dynamic> json) => _$IntervalCountFromJson(json);
  Map<String, dynamic> toJson() => _$IntervalCountToJson(this);
}

/// A user over an period (for daily and monthly active user calculations).
///
/// @author Brian Pontarelli
@JsonSerializable()
class IntervalUser {
  String applicationId;
  num period;
  String userId;

  IntervalUser({
      this.applicationId,
      this.period,
      this.userId
  });

  factory IntervalUser.fromJson(Map<String, dynamic> json) => _$IntervalUserFromJson(json);
  Map<String, dynamic> toJson() => _$IntervalUserToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class IssueResponse {
  String refreshToken;
  String token;

  IssueResponse({
      this.refreshToken,
      this.token
  });

  factory IssueResponse.fromJson(Map<String, dynamic> json) => _$IssueResponseFromJson(json);
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
  dynamic operator[](String index) => _other[index]; // Get any other fields
  void operator[]=(String index, dynamic value) => _other[index] = value; // Set any other fields
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

  JSONWebKey({
      this.alg,
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
      this.y
  });

  factory JSONWebKey.fromJson(Map<String, dynamic> json) => _$JSONWebKeyFromJson(json);
  Map<String, dynamic> toJson() => _$JSONWebKeyToJson(this);
}

/// Interface for any object that can provide JSON Web key Information.
@JsonSerializable()
class JSONWebKeyInfoProvider {

  JSONWebKeyInfoProvider();

  factory JSONWebKeyInfoProvider.fromJson(Map<String, dynamic> json) => _$JSONWebKeyInfoProviderFromJson(json);
  Map<String, dynamic> toJson() => _$JSONWebKeyInfoProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class JWKSResponse {
  List<JSONWebKey> keys;

  JWKSResponse({
      this.keys
  });

  factory JWKSResponse.fromJson(Map<String, dynamic> json) => _$JWKSResponseFromJson(json);
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
  dynamic operator[](String index) => _otherClaims[index]; // Get any other fields
  void operator[]=(String index, dynamic value) => _otherClaims[index] = value; // Set any other fields
  String sub;

  JWT({
      this.aud,
      this.exp,
      this.iat,
      this.iss,
      this.jti,
      this.nbf,
      this.sub
  });

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

  JWTConfiguration({
      this.accessTokenKeyId,
      this.idTokenKeyId,
      this.refreshTokenExpirationPolicy,
      this.refreshTokenRevocationPolicy,
      this.refreshTokenTimeToLiveInMinutes,
      this.refreshTokenUsagePolicy,
      this.timeToLiveInSeconds
  });

  factory JWTConfiguration.fromJson(Map<String, dynamic> json) => _$JWTConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$JWTConfigurationToJson(this);
}

/// Models the JWT public key Refresh Token Revoke Event (and can be converted to JSON). This event might be for a single
/// token, a user or an entire application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class JWTPublicKeyUpdateEvent extends BaseEvent {
  Set<String> applicationIds;

  JWTPublicKeyUpdateEvent({
      this.applicationIds
  });

  factory JWTPublicKeyUpdateEvent.fromJson(Map<String, dynamic> json) => _$JWTPublicKeyUpdateEventFromJson(json);
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

  JWTRefreshEvent({
      this.applicationId,
      this.original,
      this.refreshToken,
      this.token,
      this.userId
  });

  factory JWTRefreshEvent.fromJson(Map<String, dynamic> json) => _$JWTRefreshEventFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshEventToJson(this);
}

/// API response for refreshing a JWT with a Refresh Token.
/// <p>
/// Using a different response object from RefreshTokenResponse because the retrieve response will return an object for refreshToken, and this is a string.
///
/// @author Daniel DeGroff
@JsonSerializable()
class JWTRefreshResponse {
  String refreshToken;
  String token;

  JWTRefreshResponse({
      this.refreshToken,
      this.token
  });

  factory JWTRefreshResponse.fromJson(Map<String, dynamic> json) => _$JWTRefreshResponseFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshResponseToJson(this);
}

/// Models the Refresh Token Revoke Event (and can be converted to JSON). This event might be for a single token, a user
/// or an entire application.
///
/// @author Brian Pontarelli
@JsonSerializable()
class JWTRefreshTokenRevokeEvent extends BaseEvent {
  String applicationId;
  Map<String, num> applicationTimeToLiveInSeconds;
  User user;
  String userId;

  JWTRefreshTokenRevokeEvent({
      this.applicationId,
      this.applicationTimeToLiveInSeconds,
      this.user,
      this.userId
  });

  factory JWTRefreshTokenRevokeEvent.fromJson(Map<String, dynamic> json) => _$JWTRefreshTokenRevokeEventFromJson(json);
  Map<String, dynamic> toJson() => _$JWTRefreshTokenRevokeEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class KafkaConfiguration extends Enableable {
  String defaultTopic;
  Map<String, String> producer;

  KafkaConfiguration({
      this.defaultTopic,
      this.producer
  });

  factory KafkaConfiguration.fromJson(Map<String, dynamic> json) => _$KafkaConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$KafkaConfigurationToJson(this);
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

  Key({
      this.algorithm,
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
      this.type
  });

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

  KeyRequest({
      this.key
  });

  factory KeyRequest.fromJson(Map<String, dynamic> json) => _$KeyRequestFromJson(json);
  Map<String, dynamic> toJson() => _$KeyRequestToJson(this);
}

/// Key API response object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class KeyResponse {
  Key key;
  List<Key> keys;

  KeyResponse({
      this.key,
      this.keys
  });

  factory KeyResponse.fromJson(Map<String, dynamic> json) => _$KeyResponseFromJson(json);
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

/// A JavaScript lambda function that is executed during certain events inside FusionAuth.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Lambda extends Enableable {
  String body;
  bool debug;
  String id;
  num insertInstant;
  num lastUpdateInstant;
  String name;
  LambdaType type;

  Lambda({
      this.body,
      this.debug,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.name,
      this.type
  });

  factory Lambda.fromJson(Map<String, dynamic> json) => _$LambdaFromJson(json);
  Map<String, dynamic> toJson() => _$LambdaToJson(this);
}

/// Lambda API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LambdaRequest {
  Lambda lambda;

  LambdaRequest({
      this.lambda
  });

  factory LambdaRequest.fromJson(Map<String, dynamic> json) => _$LambdaRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LambdaRequestToJson(this);
}

/// Lambda API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LambdaResponse {
  Lambda lambda;
  List<Lambda> lambdas;

  LambdaResponse({
      this.lambda,
      this.lambdas
  });

  factory LambdaResponse.fromJson(Map<String, dynamic> json) => _$LambdaResponseFromJson(json);
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
  LinkedInReconcile
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

  LDAPConnectorConfiguration({
      this.authenticationURL,
      this.baseStructure,
      this.connectTimeout,
      this.identifyingAttribute,
      this.lambdaConfiguration,
      this.loginIdAttribute,
      this.readTimeout,
      this.requestedAttributes,
      this.securityMethod,
      this.systemAccountDN,
      this.systemAccountPassword
  });

  factory LDAPConnectorConfiguration.fromJson(Map<String, dynamic> json) => _$LDAPConnectorConfigurationFromJson(json);
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
class LinkedInApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  LinkedInApplicationConfiguration({
      this.buttonText,
      this.client_id,
      this.client_secret,
      this.scope
  });

  factory LinkedInApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$LinkedInApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LinkedInApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LinkedInIdentityProvider extends BaseIdentityProvider<LinkedInApplicationConfiguration> {
  String buttonText;
  String client_id;
  String client_secret;
  String scope;

  LinkedInIdentityProvider({
      this.buttonText,
      this.client_id,
      this.client_secret,
      this.scope
  });

  factory LinkedInIdentityProvider.fromJson(Map<String, dynamic> json) => _$LinkedInIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$LinkedInIdentityProviderToJson(this);
}

/// A historical state of a user log event. Since events can be modified, this stores the historical state.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LogHistory {
  List<HistoryItem> historyItems;

  LogHistory({
      this.historyItems
  });

  factory LogHistory.fromJson(Map<String, dynamic> json) => _$LogHistoryFromJson(json);
  Map<String, dynamic> toJson() => _$LogHistoryToJson(this);
}

@JsonSerializable()
class LoginConfiguration {
  bool allowTokenRefresh;
  bool generateRefreshTokens;
  bool requireAuthentication;

  LoginConfiguration({
      this.allowTokenRefresh,
      this.generateRefreshTokens,
      this.requireAuthentication
  });

  factory LoginConfiguration.fromJson(Map<String, dynamic> json) => _$LoginConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LoginConfigurationToJson(this);
}

enum LoginIdType {
  @JsonValue('email')
  email,
  @JsonValue('username')
  username
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

  LoginPreventedResponse({
      this.actionerUserId,
      this.actionId,
      this.expiry,
      this.localizedName,
      this.localizedOption,
      this.localizedReason,
      this.name,
      this.option,
      this.reason,
      this.reasonCode
  });

  factory LoginPreventedResponse.fromJson(Map<String, dynamic> json) => _$LoginPreventedResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginPreventedResponseToJson(this);
}

@JsonSerializable()
class LoginRecordConfiguration {
  DeleteConfiguration delete;

  LoginRecordConfiguration({
      this.delete
  });

  factory LoginRecordConfiguration.fromJson(Map<String, dynamic> json) => _$LoginRecordConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordExportRequest extends BaseExportRequest {
  LoginRecordSearchCriteria criteria;

  LoginRecordExportRequest({
      this.criteria
  });

  factory LoginRecordExportRequest.fromJson(Map<String, dynamic> json) => _$LoginRecordExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordExportRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchCriteria extends BaseSearchCriteria {
  String applicationId;
  num end;
  num start;
  String userId;

  LoginRecordSearchCriteria({
      this.applicationId,
      this.end,
      this.start,
      this.userId
  });

  factory LoginRecordSearchCriteria.fromJson(Map<String, dynamic> json) => _$LoginRecordSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchCriteriaToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchRequest {
  bool retrieveTotal;
  LoginRecordSearchCriteria search;

  LoginRecordSearchRequest({
      this.retrieveTotal,
      this.search
  });

  factory LoginRecordSearchRequest.fromJson(Map<String, dynamic> json) => _$LoginRecordSearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchRequestToJson(this);
}

/// A raw login record response
///
/// @author Daniel DeGroff
@JsonSerializable()
class LoginRecordSearchResponse {
  List<DisplayableRawLogin> logins;
  num total;

  LoginRecordSearchResponse({
      this.logins,
      this.total
  });

  factory LoginRecordSearchResponse.fromJson(Map<String, dynamic> json) => _$LoginRecordSearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRecordSearchResponseToJson(this);
}

/// Response for the login report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class LoginReportResponse {
  List<Count> hourlyCounts;
  num total;

  LoginReportResponse({
      this.hourlyCounts,
      this.total
  });

  factory LoginReportResponse.fromJson(Map<String, dynamic> json) => _$LoginReportResponseFromJson(json);
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

  LoginRequest({
      this.loginId,
      this.oneTimePassword,
      this.password,
      this.twoFactorTrustId
  });

  factory LoginRequest.fromJson(Map<String, dynamic> json) => _$LoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$LoginRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class LoginResponse {
  List<LoginPreventedResponse> actions;
  String changePasswordId;
  ChangePasswordReason changePasswordReason;
  String refreshToken;
  Map<String, dynamic> state;
  String token;
  String twoFactorId;
  String twoFactorTrustId;
  User user;

  LoginResponse({
      this.actions,
      this.changePasswordId,
      this.changePasswordReason,
      this.refreshToken,
      this.state,
      this.token,
      this.twoFactorId,
      this.twoFactorTrustId,
      this.user
  });

  factory LoginResponse.fromJson(Map<String, dynamic> json) => _$LoginResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LoginResponseToJson(this);
}

/// @author Matthew Altman
enum LogoutBehavior {
  @JsonValue('RedirectOnly')
  RedirectOnly,
  @JsonValue('AllApplications')
  AllApplications
}

/// @author Daniel DeGroff
@JsonSerializable()
class LookupResponse {
  IdentityProviderDetails identityProvider;

  LookupResponse({
      this.identityProvider
  });

  factory LookupResponse.fromJson(Map<String, dynamic> json) => _$LookupResponseFromJson(json);
  Map<String, dynamic> toJson() => _$LookupResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class MaximumPasswordAge extends Enableable {
  num days;

  MaximumPasswordAge({
      this.days
  });

  factory MaximumPasswordAge.fromJson(Map<String, dynamic> json) => _$MaximumPasswordAgeFromJson(json);
  Map<String, dynamic> toJson() => _$MaximumPasswordAgeToJson(this);
}

/// Group Member Delete Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberDeleteRequest {
  List<String> memberIds;
  Map<String, List<String>> members;

  MemberDeleteRequest({
      this.memberIds,
      this.members
  });

  factory MemberDeleteRequest.fromJson(Map<String, dynamic> json) => _$MemberDeleteRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MemberDeleteRequestToJson(this);
}

/// Group Member Request
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberRequest {
  Map<String, List<GroupMember>> members;

  MemberRequest({
      this.members
  });

  factory MemberRequest.fromJson(Map<String, dynamic> json) => _$MemberRequestFromJson(json);
  Map<String, dynamic> toJson() => _$MemberRequestToJson(this);
}

/// Group Member Response
///
/// @author Daniel DeGroff
@JsonSerializable()
class MemberResponse {
  Map<String, List<GroupMember>> members;

  MemberResponse({
      this.members
  });

  factory MemberResponse.fromJson(Map<String, dynamic> json) => _$MemberResponseFromJson(json);
  Map<String, dynamic> toJson() => _$MemberResponseToJson(this);
}

@JsonSerializable()
class MetaData {
  DeviceInfo device;
  Set<String> scopes;

  MetaData({
      this.device,
      this.scopes
  });

  factory MetaData.fromJson(Map<String, dynamic> json) => _$MetaDataFromJson(json);
  Map<String, dynamic> toJson() => _$MetaDataToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class MinimumPasswordAge extends Enableable {
  num seconds;

  MinimumPasswordAge({
      this.seconds
  });

  factory MinimumPasswordAge.fromJson(Map<String, dynamic> json) => _$MinimumPasswordAgeFromJson(json);
  Map<String, dynamic> toJson() => _$MinimumPasswordAgeToJson(this);
}

/// Response for the daily active user report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class MonthlyActiveUserReportResponse {
  List<Count> monthlyActiveUsers;
  num total;

  MonthlyActiveUserReportResponse({
      this.monthlyActiveUsers,
      this.total
  });

  factory MonthlyActiveUserReportResponse.fromJson(Map<String, dynamic> json) => _$MonthlyActiveUserReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$MonthlyActiveUserReportResponseToJson(this);
}

/// Helper methods for normalizing values.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Normalizer {

  Normalizer();

  factory Normalizer.fromJson(Map<String, dynamic> json) => _$NormalizerFromJson(json);
  Map<String, dynamic> toJson() => _$NormalizerToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuth2Configuration {
  List<String> authorizedOriginURLs;
  List<String> authorizedRedirectURLs;
  String clientId;
  String clientSecret;
  String deviceVerificationURL;
  Set<GrantType> enabledGrants;
  bool generateRefreshTokens;
  LogoutBehavior logoutBehavior;
  String logoutURL;
  bool requireClientAuthentication;

  OAuth2Configuration({
      this.authorizedOriginURLs,
      this.authorizedRedirectURLs,
      this.clientId,
      this.clientSecret,
      this.deviceVerificationURL,
      this.enabledGrants,
      this.generateRefreshTokens,
      this.logoutBehavior,
      this.logoutURL,
      this.requireClientAuthentication
  });

  factory OAuth2Configuration.fromJson(Map<String, dynamic> json) => _$OAuth2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$OAuth2ConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OAuthConfigurationResponse {
  num httpSessionMaxInactiveInterval;
  String logoutURL;
  OAuth2Configuration oauthConfiguration;

  OAuthConfigurationResponse({
      this.httpSessionMaxInactiveInterval,
      this.logoutURL,
      this.oauthConfiguration
  });

  factory OAuthConfigurationResponse.fromJson(Map<String, dynamic> json) => _$OAuthConfigurationResponseFromJson(json);
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

  OAuthError({
      this.change_password_id,
      this.error,
      this.error_description,
      this.error_reason,
      this.error_uri,
      this.two_factor_id
  });

  factory OAuthError.fromJson(Map<String, dynamic> json) => _$OAuthErrorFromJson(json);
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
  @JsonValue('grant_type_disabled')
  grant_type_disabled,
  @JsonValue('missing_client_id')
  missing_client_id,
  @JsonValue('missing_code')
  missing_code,
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

  factory OAuthResponse.fromJson(Map<String, dynamic> json) => _$OAuthResponseFromJson(json);
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

  OpenIdConfiguration({
      this.authorization_endpoint,
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
      this.userinfo_signing_alg_values_supported
  });

  factory OpenIdConfiguration.fromJson(Map<String, dynamic> json) => _$OpenIdConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$OpenIdConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OpenIdConnectApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonImageURL;
  String buttonText;
  IdentityProviderOauth2Configuration oauth2;

  OpenIdConnectApplicationConfiguration({
      this.buttonImageURL,
      this.buttonText,
      this.oauth2
  });

  factory OpenIdConnectApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$OpenIdConnectApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$OpenIdConnectApplicationConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class OpenIdConnectIdentityProvider extends BaseIdentityProvider<OpenIdConnectApplicationConfiguration> {
  String buttonImageURL;
  String buttonText;
  Set<String> domains;
  IdentityProviderOauth2Configuration oauth2;
  bool postRequest;

  OpenIdConnectIdentityProvider({
      this.buttonImageURL,
      this.buttonText,
      this.domains,
      this.oauth2,
      this.postRequest
  });

  factory OpenIdConnectIdentityProvider.fromJson(Map<String, dynamic> json) => _$OpenIdConnectIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$OpenIdConnectIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordBreachDetection extends Enableable {
  BreachMatchMode matchMode;
  String notifyUserEmailTemplateId;
  BreachAction onLogin;

  PasswordBreachDetection({
      this.matchMode,
      this.notifyUserEmailTemplateId,
      this.onLogin
  });

  factory PasswordBreachDetection.fromJson(Map<String, dynamic> json) => _$PasswordBreachDetectionFromJson(json);
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

  PasswordEncryptionConfiguration({
      this.encryptionScheme,
      this.encryptionSchemeFactor,
      this.modifyEncryptionSchemeOnLogin
  });

  factory PasswordEncryptionConfiguration.fromJson(Map<String, dynamic> json) => _$PasswordEncryptionConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordEncryptionConfigurationToJson(this);
}

@JsonSerializable()
class PasswordlessConfiguration extends Enableable {

  PasswordlessConfiguration();

  factory PasswordlessConfiguration.fromJson(Map<String, dynamic> json) => _$PasswordlessConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessConfigurationToJson(this);
}

/// Interface for all identity providers that are passwordless and do not accept a password.
@JsonSerializable()
class PasswordlessIdentityProvider {

  PasswordlessIdentityProvider();

  factory PasswordlessIdentityProvider.fromJson(Map<String, dynamic> json) => _$PasswordlessIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessLoginRequest extends BaseLoginRequest {
  String code;
  String twoFactorTrustId;

  PasswordlessLoginRequest({
      this.code,
      this.twoFactorTrustId
  });

  factory PasswordlessLoginRequest.fromJson(Map<String, dynamic> json) => _$PasswordlessLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessLoginRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessSendRequest {
  String applicationId;
  String code;
  String loginId;
  Map<String, dynamic> state;

  PasswordlessSendRequest({
      this.applicationId,
      this.code,
      this.loginId,
      this.state
  });

  factory PasswordlessSendRequest.fromJson(Map<String, dynamic> json) => _$PasswordlessSendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessSendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessStartRequest {
  String applicationId;
  String loginId;
  Map<String, dynamic> state;

  PasswordlessStartRequest({
      this.applicationId,
      this.loginId,
      this.state
  });

  factory PasswordlessStartRequest.fromJson(Map<String, dynamic> json) => _$PasswordlessStartRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordlessStartRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordlessStartResponse {
  String code;

  PasswordlessStartResponse({
      this.code
  });

  factory PasswordlessStartResponse.fromJson(Map<String, dynamic> json) => _$PasswordlessStartResponseFromJson(json);
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

  PasswordValidationRules({
      this.breachDetection,
      this.maxLength,
      this.minLength,
      this.rememberPreviousPasswords,
      this.requireMixedCase,
      this.requireNonAlpha,
      this.requireNumber,
      this.validateOnLogin
  });

  factory PasswordValidationRules.fromJson(Map<String, dynamic> json) => _$PasswordValidationRulesFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordValidationRulesToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class PasswordValidationRulesResponse {
  PasswordValidationRules passwordValidationRules;

  PasswordValidationRulesResponse({
      this.passwordValidationRules
  });

  factory PasswordValidationRulesResponse.fromJson(Map<String, dynamic> json) => _$PasswordValidationRulesResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PasswordValidationRulesResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class PendingResponse {
  List<User> users;

  PendingResponse({
      this.users
  });

  factory PendingResponse.fromJson(Map<String, dynamic> json) => _$PendingResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PendingResponseToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class PreviewRequest {
  EmailTemplate emailTemplate;
  String locale;

  PreviewRequest({
      this.emailTemplate,
      this.locale
  });

  factory PreviewRequest.fromJson(Map<String, dynamic> json) => _$PreviewRequestFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewRequestToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class PreviewResponse {
  Email email;
  Errors errors;

  PreviewResponse({
      this.email,
      this.errors
  });

  factory PreviewResponse.fromJson(Map<String, dynamic> json) => _$PreviewResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PreviewResponseToJson(this);
}

/// JWT Public Key Response Object
///
/// @author Daniel DeGroff
@JsonSerializable()
class PublicKeyResponse {
  String publicKey;
  Map<String, String> publicKeys;

  PublicKeyResponse({
      this.publicKey,
      this.publicKeys
  });

  factory PublicKeyResponse.fromJson(Map<String, dynamic> json) => _$PublicKeyResponseFromJson(json);
  Map<String, dynamic> toJson() => _$PublicKeyResponseToJson(this);
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

  RawLogin({
      this.applicationId,
      this.instant,
      this.ipAddress,
      this.userId
  });

  factory RawLogin.fromJson(Map<String, dynamic> json) => _$RawLoginFromJson(json);
  Map<String, dynamic> toJson() => _$RawLoginToJson(this);
}

/// Response for the user login report.
///
/// @author Seth Musselman
@JsonSerializable()
class RecentLoginResponse {
  List<DisplayableRawLogin> logins;

  RecentLoginResponse({
      this.logins
  });

  factory RecentLoginResponse.fromJson(Map<String, dynamic> json) => _$RecentLoginResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RecentLoginResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshRequest {
  String refreshToken;
  String token;

  RefreshRequest({
      this.refreshToken,
      this.token
  });

  factory RefreshRequest.fromJson(Map<String, dynamic> json) => _$RefreshRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshResponse {

  RefreshResponse();

  factory RefreshResponse.fromJson(Map<String, dynamic> json) => _$RefreshResponseFromJson(json);
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
  String token;
  String userId;

  RefreshToken({
      this.applicationId,
      this.data,
      this.id,
      this.insertInstant,
      this.metaData,
      this.startInstant,
      this.token,
      this.userId
  });

  factory RefreshToken.fromJson(Map<String, dynamic> json) => _$RefreshTokenFromJson(json);
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

  RefreshTokenImportRequest({
      this.refreshTokens,
      this.validateDbConstraints
  });

  factory RefreshTokenImportRequest.fromJson(Map<String, dynamic> json) => _$RefreshTokenImportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenImportRequestToJson(this);
}

/// API response for retrieving Refresh Tokens
///
/// @author Daniel DeGroff
@JsonSerializable()
class RefreshTokenResponse {
  RefreshToken refreshToken;
  List<RefreshToken> refreshTokens;

  RefreshTokenResponse({
      this.refreshToken,
      this.refreshTokens
  });

  factory RefreshTokenResponse.fromJson(Map<String, dynamic> json) => _$RefreshTokenResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RefreshTokenRevocationPolicy {
  bool onLoginPrevented;
  bool onPasswordChanged;

  RefreshTokenRevocationPolicy({
      this.onLoginPrevented,
      this.onPasswordChanged
  });

  factory RefreshTokenRevocationPolicy.fromJson(Map<String, dynamic> json) => _$RefreshTokenRevocationPolicyFromJson(json);
  Map<String, dynamic> toJson() => _$RefreshTokenRevocationPolicyToJson(this);
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

  RegistrationConfiguration({
      this.birthDate,
      this.confirmPassword,
      this.firstName,
      this.formId,
      this.fullName,
      this.lastName,
      this.loginIdType,
      this.middleName,
      this.mobilePhone,
      this.type
  });

  factory RegistrationConfiguration.fromJson(Map<String, dynamic> json) => _$RegistrationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationConfigurationToJson(this);
}

/// Response for the registration report.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationReportResponse {
  List<Count> hourlyCounts;
  num total;

  RegistrationReportResponse({
      this.hourlyCounts,
      this.total
  });

  factory RegistrationReportResponse.fromJson(Map<String, dynamic> json) => _$RegistrationReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationReportResponseToJson(this);
}

/// Registration API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationRequest {
  bool generateAuthenticationToken;
  UserRegistration registration;
  bool sendSetPasswordEmail;
  bool skipRegistrationVerification;
  bool skipVerification;
  User user;

  RegistrationRequest({
      this.generateAuthenticationToken,
      this.registration,
      this.sendSetPasswordEmail,
      this.skipRegistrationVerification,
      this.skipVerification,
      this.user
  });

  factory RegistrationRequest.fromJson(Map<String, dynamic> json) => _$RegistrationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$RegistrationRequestToJson(this);
}

/// Registration API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class RegistrationResponse {
  String refreshToken;
  UserRegistration registration;
  String token;
  User user;

  RegistrationResponse({
      this.refreshToken,
      this.registration,
      this.token,
      this.user
  });

  factory RegistrationResponse.fromJson(Map<String, dynamic> json) => _$RegistrationResponseFromJson(json);
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
class ReloadRequest {
  List<String> names;

  ReloadRequest({
      this.names
  });

  factory ReloadRequest.fromJson(Map<String, dynamic> json) => _$ReloadRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ReloadRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class RememberPreviousPasswords extends Enableable {
  num count;

  RememberPreviousPasswords({
      this.count
  });

  factory RememberPreviousPasswords.fromJson(Map<String, dynamic> json) => _$RememberPreviousPasswordsFromJson(json);
  Map<String, dynamic> toJson() => _$RememberPreviousPasswordsToJson(this);
}

/// Something that can be required and thus also optional. This currently extends Enableable because anything that is
/// require/optional is almost always enableable as well.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Requirable extends Enableable {
  bool required;

  Requirable({
      this.required
  });

  factory Requirable.fromJson(Map<String, dynamic> json) => _$RequirableFromJson(json);
  Map<String, dynamic> toJson() => _$RequirableToJson(this);
}

/// Interface describing the need for CORS configuration.
///
/// @author Daniel DeGroff
@JsonSerializable()
class RequiresCORSConfiguration {

  RequiresCORSConfiguration();

  factory RequiresCORSConfiguration.fromJson(Map<String, dynamic> json) => _$RequiresCORSConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$RequiresCORSConfigurationToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class SAMLv2ApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonImageURL;
  String buttonText;

  SAMLv2ApplicationConfiguration({
      this.buttonImageURL,
      this.buttonText
  });

  factory SAMLv2ApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$SAMLv2ApplicationConfigurationFromJson(json);
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
  String logoutURL;
  bool requireSignedRequests;
  CanonicalizationMethod xmlSignatureC14nMethod;
  XMLSignatureLocation xmlSignatureLocation;

  SAMLv2Configuration({
      this.audience,
      this.authorizedRedirectURLs,
      this.callbackURL,
      this.debug,
      this.defaultVerificationKeyId,
      this.issuer,
      this.keyId,
      this.logoutURL,
      this.requireSignedRequests,
      this.xmlSignatureC14nMethod,
      this.xmlSignatureLocation
  });

  factory SAMLv2Configuration.fromJson(Map<String, dynamic> json) => _$SAMLv2ConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2ConfigurationToJson(this);
}

/// SAML v2 identity provider configuration.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SAMLv2IdentityProvider extends BaseIdentityProvider<SAMLv2ApplicationConfiguration> {
  String buttonImageURL;
  String buttonText;
  Set<String> domains;
  String emailClaim;
  String idpEndpoint;
  String issuer;
  String keyId;
  bool postRequest;
  String requestSigningKeyId;
  bool signRequest;
  bool useNameIdForEmail;
  CanonicalizationMethod xmlSignatureC14nMethod;

  SAMLv2IdentityProvider({
      this.buttonImageURL,
      this.buttonText,
      this.domains,
      this.emailClaim,
      this.idpEndpoint,
      this.issuer,
      this.keyId,
      this.postRequest,
      this.requestSigningKeyId,
      this.signRequest,
      this.useNameIdForEmail,
      this.xmlSignatureC14nMethod
  });

  factory SAMLv2IdentityProvider.fromJson(Map<String, dynamic> json) => _$SAMLv2IdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$SAMLv2IdentityProviderToJson(this);
}

/// Search API request.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SearchRequest {
  UserSearchCriteria search;

  SearchRequest({
      this.search
  });

  factory SearchRequest.fromJson(Map<String, dynamic> json) => _$SearchRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SearchRequestToJson(this);
}

/// Search API response.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SearchResponse {
  num total;
  List<User> users;

  SearchResponse({
      this.total,
      this.users
  });

  factory SearchResponse.fromJson(Map<String, dynamic> json) => _$SearchResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SearchResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SecretResponse {
  String secret;
  String secretBase32Encoded;

  SecretResponse({
      this.secret,
      this.secretBase32Encoded
  });

  factory SecretResponse.fromJson(Map<String, dynamic> json) => _$SecretResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SecretResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SecureGeneratorConfiguration {
  num length;
  SecureGeneratorType type;

  SecureGeneratorConfiguration({
      this.length,
      this.type
  });

  factory SecureGeneratorConfiguration.fromJson(Map<String, dynamic> json) => _$SecureGeneratorConfigurationFromJson(json);
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
  TwoFactorDelivery twoFactorDelivery;
  bool twoFactorEnabled;
  String twoFactorSecret;
  String username;
  ContentStatus usernameStatus;
  bool verified;

  SecureIdentity({
      this.breachedPasswordLastCheckedInstant,
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
      this.twoFactorDelivery,
      this.twoFactorEnabled,
      this.twoFactorSecret,
      this.username,
      this.usernameStatus,
      this.verified
  });

  factory SecureIdentity.fromJson(Map<String, dynamic> json) => _$SecureIdentityFromJson(json);
  Map<String, dynamic> toJson() => _$SecureIdentityToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SendRequest {
  List<String> bccAddresses;
  List<String> ccAddresses;
  Map<String, dynamic> requestData;
  List<String> userIds;

  SendRequest({
      this.bccAddresses,
      this.ccAddresses,
      this.requestData,
      this.userIds
  });

  factory SendRequest.fromJson(Map<String, dynamic> json) => _$SendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SendRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SendResponse {
  Map<String, EmailTemplateErrors> results;

  SendResponse({
      this.results
  });

  factory SendResponse.fromJson(Map<String, dynamic> json) => _$SendResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SendResponseToJson(this);
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

  SortField({
      this.missing,
      this.name,
      this.order
  });

  factory SortField.fromJson(Map<String, dynamic> json) => _$SortFieldFromJson(json);
  Map<String, dynamic> toJson() => _$SortFieldToJson(this);
}

/// Helper interface that indicates an identity provider can be federated to using the HTTP POST method.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SupportsPostBindings {

  SupportsPostBindings();

  factory SupportsPostBindings.fromJson(Map<String, dynamic> json) => _$SupportsPostBindingsFromJson(json);
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

  SystemConfiguration({
      this.auditLogConfiguration,
      this.corsConfiguration,
      this.data,
      this.eventLogConfiguration,
      this.insertInstant,
      this.lastUpdateInstant,
      this.loginRecordConfiguration,
      this.reportTimezone,
      this.uiConfiguration
  });

  factory SystemConfiguration.fromJson(Map<String, dynamic> json) => _$SystemConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationToJson(this);
}

/// Request for the system configuration API.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SystemConfigurationRequest {
  SystemConfiguration systemConfiguration;

  SystemConfigurationRequest({
      this.systemConfiguration
  });

  factory SystemConfigurationRequest.fromJson(Map<String, dynamic> json) => _$SystemConfigurationRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationRequestToJson(this);
}

/// Response for the system configuration API.
///
/// @author Brian Pontarelli
@JsonSerializable()
class SystemConfigurationResponse {
  SystemConfiguration systemConfiguration;

  SystemConfigurationResponse({
      this.systemConfiguration
  });

  factory SystemConfigurationResponse.fromJson(Map<String, dynamic> json) => _$SystemConfigurationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$SystemConfigurationResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class SystemLogsExportRequest extends BaseExportRequest {
  num lastNBytes;

  SystemLogsExportRequest({
      this.lastNBytes
  });

  factory SystemLogsExportRequest.fromJson(Map<String, dynamic> json) => _$SystemLogsExportRequestFromJson(json);
  Map<String, dynamic> toJson() => _$SystemLogsExportRequestToJson(this);
}

@JsonSerializable()
class Templates {
  String emailComplete;
  String emailSend;
  String emailVerify;
  String helpers;
  String oauth2Authorize;
  String oauth2ChildRegistrationNotAllowed;
  String oauth2ChildRegistrationNotAllowedComplete;
  String oauth2CompleteRegistration;
  String oauth2Device;
  String oauth2DeviceComplete;
  String oauth2Error;
  String oauth2Logout;
  String oauth2Passwordless;
  String oauth2Register;
  String oauth2TwoFactor;
  String oauth2Wait;
  String passwordChange;
  String passwordComplete;
  String passwordForgot;
  String passwordSent;
  String registrationComplete;
  String registrationSend;
  String registrationVerify;

  Templates({
      this.emailComplete,
      this.emailSend,
      this.emailVerify,
      this.helpers,
      this.oauth2Authorize,
      this.oauth2ChildRegistrationNotAllowed,
      this.oauth2ChildRegistrationNotAllowedComplete,
      this.oauth2CompleteRegistration,
      this.oauth2Device,
      this.oauth2DeviceComplete,
      this.oauth2Error,
      this.oauth2Logout,
      this.oauth2Passwordless,
      this.oauth2Register,
      this.oauth2TwoFactor,
      this.oauth2Wait,
      this.passwordChange,
      this.passwordComplete,
      this.passwordForgot,
      this.passwordSent,
      this.registrationComplete,
      this.registrationSend,
      this.registrationVerify
  });

  factory Templates.fromJson(Map<String, dynamic> json) => _$TemplatesFromJson(json);
  Map<String, dynamic> toJson() => _$TemplatesToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class Tenant {
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
  num lastUpdateInstant;
  String logoutURL;
  MaximumPasswordAge maximumPasswordAge;
  MinimumPasswordAge minimumPasswordAge;
  String name;
  PasswordEncryptionConfiguration passwordEncryptionConfiguration;
  PasswordValidationRules passwordValidationRules;
  ObjectState state;
  String themeId;
  TenantUserDeletePolicy userDeletePolicy;

  Tenant({
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
      this.lastUpdateInstant,
      this.logoutURL,
      this.maximumPasswordAge,
      this.minimumPasswordAge,
      this.name,
      this.passwordEncryptionConfiguration,
      this.passwordValidationRules,
      this.state,
      this.themeId,
      this.userDeletePolicy
  });

  factory Tenant.fromJson(Map<String, dynamic> json) => _$TenantFromJson(json);
  Map<String, dynamic> toJson() => _$TenantToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class Tenantable {

  Tenantable();

  factory Tenantable.fromJson(Map<String, dynamic> json) => _$TenantableFromJson(json);
  Map<String, dynamic> toJson() => _$TenantableToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantFormConfiguration {
  String adminUserFormId;

  TenantFormConfiguration({
      this.adminUserFormId
  });

  factory TenantFormConfiguration.fromJson(Map<String, dynamic> json) => _$TenantFormConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TenantFormConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantRequest {
  String sourceTenantId;
  Tenant tenant;

  TenantRequest({
      this.sourceTenantId,
      this.tenant
  });

  factory TenantRequest.fromJson(Map<String, dynamic> json) => _$TenantRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TenantRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TenantResponse {
  Tenant tenant;
  List<Tenant> tenants;

  TenantResponse({
      this.tenant,
      this.tenants
  });

  factory TenantResponse.fromJson(Map<String, dynamic> json) => _$TenantResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TenantResponseToJson(this);
}

/// A Tenant-level policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class TenantUserDeletePolicy {
  TimeBasedDeletePolicy unverified;

  TenantUserDeletePolicy({
      this.unverified
  });

  factory TenantUserDeletePolicy.fromJson(Map<String, dynamic> json) => _$TenantUserDeletePolicyFromJson(json);
  Map<String, dynamic> toJson() => _$TenantUserDeletePolicyToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TestEvent extends BaseEvent {
  String message;

  TestEvent({
      this.message
  });

  factory TestEvent.fromJson(Map<String, dynamic> json) => _$TestEventFromJson(json);
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

  Theme({
      this.data,
      this.defaultMessages,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedMessages,
      this.name,
      this.stylesheet,
      this.templates
  });

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

  ThemeRequest({
      this.sourceThemeId,
      this.theme
  });

  factory ThemeRequest.fromJson(Map<String, dynamic> json) => _$ThemeRequestFromJson(json);
  Map<String, dynamic> toJson() => _$ThemeRequestToJson(this);
}

/// Theme API response object.
///
/// @author Trevor Smith
@JsonSerializable()
class ThemeResponse {
  Theme theme;
  List<Theme> themes;

  ThemeResponse({
      this.theme,
      this.themes
  });

  factory ThemeResponse.fromJson(Map<String, dynamic> json) => _$ThemeResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ThemeResponseToJson(this);
}

/// A policy for deleting Users.
///
/// @author Trevor Smith
@JsonSerializable()
class TimeBasedDeletePolicy extends Enableable {
  num numberOfDaysToRetain;

  TimeBasedDeletePolicy({
      this.numberOfDaysToRetain
  });

  factory TimeBasedDeletePolicy.fromJson(Map<String, dynamic> json) => _$TimeBasedDeletePolicyFromJson(json);
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

  Totals({
      this.logins,
      this.registrations,
      this.totalRegistrations
  });

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

  TotalsReportResponse({
      this.applicationTotals,
      this.globalRegistrations,
      this.totalGlobalRegistrations
  });

  factory TotalsReportResponse.fromJson(Map<String, dynamic> json) => _$TotalsReportResponseFromJson(json);
  Map<String, dynamic> toJson() => _$TotalsReportResponseToJson(this);
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

/// Twilio Service Configuration.
///
/// @author Daniel DeGroff
@JsonSerializable()
class TwilioConfiguration extends Enableable {
  String accountSID;
  String authToken;
  String fromPhoneNumber;
  String messagingServiceSid;
  String url;

  TwilioConfiguration({
      this.accountSID,
      this.authToken,
      this.fromPhoneNumber,
      this.messagingServiceSid,
      this.url
  });

  factory TwilioConfiguration.fromJson(Map<String, dynamic> json) => _$TwilioConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TwilioConfigurationToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwitterApplicationConfiguration extends BaseIdentityProviderApplicationConfiguration {
  String buttonText;
  String consumerKey;
  String consumerSecret;

  TwitterApplicationConfiguration({
      this.buttonText,
      this.consumerKey,
      this.consumerSecret
  });

  factory TwitterApplicationConfiguration.fromJson(Map<String, dynamic> json) => _$TwitterApplicationConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$TwitterApplicationConfigurationToJson(this);
}

/// Twitter social login provider.
///
/// @author Daniel DeGroff
@JsonSerializable()
class TwitterIdentityProvider extends BaseIdentityProvider<TwitterApplicationConfiguration> {
  String buttonText;
  String consumerKey;
  String consumerSecret;

  TwitterIdentityProvider({
      this.buttonText,
      this.consumerKey,
      this.consumerSecret
  });

  factory TwitterIdentityProvider.fromJson(Map<String, dynamic> json) => _$TwitterIdentityProviderFromJson(json);
  Map<String, dynamic> toJson() => _$TwitterIdentityProviderToJson(this);
}

/// @author Daniel DeGroff
enum TwoFactorDelivery {
  @JsonValue('None')
  None,
  @JsonValue('TextMessage')
  TextMessage
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorLoginRequest extends BaseLoginRequest {
  String code;
  bool trustComputer;
  String twoFactorId;

  TwoFactorLoginRequest({
      this.code,
      this.trustComputer,
      this.twoFactorId
  });

  factory TwoFactorLoginRequest.fromJson(Map<String, dynamic> json) => _$TwoFactorLoginRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorLoginRequestToJson(this);
}

/// @author Brian Pontarelli
@JsonSerializable()
class TwoFactorRequest {
  String code;
  TwoFactorDelivery delivery;
  String secret;
  String secretBase32Encoded;

  TwoFactorRequest({
      this.code,
      this.delivery,
      this.secret,
      this.secretBase32Encoded
  });

  factory TwoFactorRequest.fromJson(Map<String, dynamic> json) => _$TwoFactorRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorRequestToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class TwoFactorSendRequest {
  String mobilePhone;
  String secret;
  String userId;

  TwoFactorSendRequest({
      this.mobilePhone,
      this.secret,
      this.userId
  });

  factory TwoFactorSendRequest.fromJson(Map<String, dynamic> json) => _$TwoFactorSendRequestFromJson(json);
  Map<String, dynamic> toJson() => _$TwoFactorSendRequestToJson(this);
}

@JsonSerializable()
class UIConfiguration {
  String headerColor;
  String logoURL;
  String menuFontColor;

  UIConfiguration({
      this.headerColor,
      this.logoURL,
      this.menuFontColor
  });

  factory UIConfiguration.fromJson(Map<String, dynamic> json) => _$UIConfigurationFromJson(json);
  Map<String, dynamic> toJson() => _$UIConfigurationToJson(this);
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

  User({
      this.active,
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
      this.timezone
  });

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

  UserAction({
      this.active,
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
      this.userNotificationsEnabled
  });

  factory UserAction.fromJson(Map<String, dynamic> json) => _$UserActionFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionToJson(this);
}

/// Models the user action event (and can be converted to JSON).
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

  UserActionEvent({
      this.action,
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
      this.reasonCode
  });

  factory UserActionEvent.fromJson(Map<String, dynamic> json) => _$UserActionEventFromJson(json);
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

  UserActionLog({
      this.actioneeUserId,
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
      this.userActionId
  });

  factory UserActionLog.fromJson(Map<String, dynamic> json) => _$UserActionLogFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionLogToJson(this);
}

/// Models content user action options.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionOption {
  Map<String, String> localizedNames;
  String name;

  UserActionOption({
      this.localizedNames,
      this.name
  });

  factory UserActionOption.fromJson(Map<String, dynamic> json) => _$UserActionOptionFromJson(json);
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

  UserActionReason({
      this.code,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.localizedTexts,
      this.text
  });

  factory UserActionReason.fromJson(Map<String, dynamic> json) => _$UserActionReasonFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonToJson(this);
}

/// User Action Reason API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionReasonRequest {
  UserActionReason userActionReason;

  UserActionReasonRequest({
      this.userActionReason
  });

  factory UserActionReasonRequest.fromJson(Map<String, dynamic> json) => _$UserActionReasonRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonRequestToJson(this);
}

/// User Action Reason API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionReasonResponse {
  UserActionReason userActionReason;
  List<UserActionReason> userActionReasons;

  UserActionReasonResponse({
      this.userActionReason,
      this.userActionReasons
  });

  factory UserActionReasonResponse.fromJson(Map<String, dynamic> json) => _$UserActionReasonResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionReasonResponseToJson(this);
}

/// User Action API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionRequest {
  UserAction userAction;

  UserActionRequest({
      this.userAction
  });

  factory UserActionRequest.fromJson(Map<String, dynamic> json) => _$UserActionRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionRequestToJson(this);
}

/// User Action API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserActionResponse {
  UserAction userAction;
  List<UserAction> userActions;

  UserActionResponse({
      this.userAction,
      this.userActions
  });

  factory UserActionResponse.fromJson(Map<String, dynamic> json) => _$UserActionResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserActionResponseToJson(this);
}

/// Models the User Bulk Create Event (and can be converted to JSON).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserBulkCreateEvent extends BaseEvent {
  List<User> users;

  UserBulkCreateEvent({
      this.users
  });

  factory UserBulkCreateEvent.fromJson(Map<String, dynamic> json) => _$UserBulkCreateEventFromJson(json);
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

  UserComment({
      this.comment,
      this.commenterId,
      this.id,
      this.insertInstant,
      this.userId
  });

  factory UserComment.fromJson(Map<String, dynamic> json) => _$UserCommentFromJson(json);
  Map<String, dynamic> toJson() => _$UserCommentToJson(this);
}

/// @author Seth Musselman
@JsonSerializable()
class UserCommentRequest {
  UserComment userComment;

  UserCommentRequest({
      this.userComment
  });

  factory UserCommentRequest.fromJson(Map<String, dynamic> json) => _$UserCommentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserCommentRequestToJson(this);
}

/// User Comment Response
///
/// @author Seth Musselman
@JsonSerializable()
class UserCommentResponse {
  UserComment userComment;
  List<UserComment> userComments;

  UserCommentResponse({
      this.userComment,
      this.userComments
  });

  factory UserCommentResponse.fromJson(Map<String, dynamic> json) => _$UserCommentResponseFromJson(json);
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

  UserConsent({
      this.consent,
      this.consentId,
      this.data,
      this.giverUserId,
      this.id,
      this.insertInstant,
      this.lastUpdateInstant,
      this.status,
      this.userId,
      this.values
  });

  factory UserConsent.fromJson(Map<String, dynamic> json) => _$UserConsentFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentToJson(this);
}

/// API response for User consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserConsentRequest {
  UserConsent userConsent;

  UserConsentRequest({
      this.userConsent
  });

  factory UserConsentRequest.fromJson(Map<String, dynamic> json) => _$UserConsentRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentRequestToJson(this);
}

/// API response for User consent.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserConsentResponse {
  UserConsent userConsent;
  List<UserConsent> userConsents;

  UserConsentResponse({
      this.userConsent,
      this.userConsents
  });

  factory UserConsentResponse.fromJson(Map<String, dynamic> json) => _$UserConsentResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserConsentResponseToJson(this);
}

/// Models the User Create Event (and can be converted to JSON).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserCreateEvent extends BaseEvent {
  User user;

  UserCreateEvent({
      this.user
  });

  factory UserCreateEvent.fromJson(Map<String, dynamic> json) => _$UserCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserCreateEventToJson(this);
}

/// Models the User Deactivate Event (and can be converted to JSON).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserDeactivateEvent extends BaseEvent {
  User user;

  UserDeactivateEvent({
      this.user
  });

  factory UserDeactivateEvent.fromJson(Map<String, dynamic> json) => _$UserDeactivateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeactivateEventToJson(this);
}

/// Models the User Event (and can be converted to JSON) that is used for all user modifications (create, update,
/// delete).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserDeleteEvent extends BaseEvent {
  User user;

  UserDeleteEvent({
      this.user
  });

  factory UserDeleteEvent.fromJson(Map<String, dynamic> json) => _$UserDeleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteEventToJson(this);
}

/// User API delete request object.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserDeleteRequest {
  bool dryRun;
  bool hardDelete;
  String query;
  String queryString;
  List<String> userIds;

  UserDeleteRequest({
      this.dryRun,
      this.hardDelete,
      this.query,
      this.queryString,
      this.userIds
  });

  factory UserDeleteRequest.fromJson(Map<String, dynamic> json) => _$UserDeleteRequestFromJson(json);
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

  UserDeleteResponse({
      this.dryRun,
      this.hardDelete,
      this.total,
      this.userIds
  });

  factory UserDeleteResponse.fromJson(Map<String, dynamic> json) => _$UserDeleteResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserDeleteResponseToJson(this);
}

/// Models the User Email Verify Event (and can be converted to JSON).
///
/// @author Trevor Smith
@JsonSerializable()
class UserEmailVerifiedEvent extends BaseEvent {
  User user;

  UserEmailVerifiedEvent({
      this.user
  });

  factory UserEmailVerifiedEvent.fromJson(Map<String, dynamic> json) => _$UserEmailVerifiedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserEmailVerifiedEventToJson(this);
}

/// Models the User Login Failed Event.
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserLoginFailedEvent extends BaseEvent {
  String applicationId;
  String authenticationType;
  User user;

  UserLoginFailedEvent({
      this.applicationId,
      this.authenticationType,
      this.user
  });

  factory UserLoginFailedEvent.fromJson(Map<String, dynamic> json) => _$UserLoginFailedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginFailedEventToJson(this);
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
  User user;

  UserLoginSuccessEvent({
      this.applicationId,
      this.authenticationType,
      this.connectorId,
      this.identityProviderId,
      this.identityProviderName,
      this.user
  });

  factory UserLoginSuccessEvent.fromJson(Map<String, dynamic> json) => _$UserLoginSuccessEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserLoginSuccessEventToJson(this);
}

@JsonSerializable()
class UsernameModeration extends Enableable {
  String applicationId;

  UsernameModeration({
      this.applicationId
  });

  factory UsernameModeration.fromJson(Map<String, dynamic> json) => _$UsernameModerationFromJson(json);
  Map<String, dynamic> toJson() => _$UsernameModerationToJson(this);
}

/// Models the User Password Breach Event.
///
/// @author Matthew Altman
@JsonSerializable()
class UserPasswordBreachEvent extends BaseEvent {
  User user;

  UserPasswordBreachEvent({
      this.user
  });

  factory UserPasswordBreachEvent.fromJson(Map<String, dynamic> json) => _$UserPasswordBreachEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserPasswordBreachEventToJson(this);
}

/// Models the User Reactivate Event (and can be converted to JSON).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserReactivateEvent extends BaseEvent {
  User user;

  UserReactivateEvent({
      this.user
  });

  factory UserReactivateEvent.fromJson(Map<String, dynamic> json) => _$UserReactivateEventFromJson(json);
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

  UserRegistration({
      this.applicationId,
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
      this.verified
  });

  factory UserRegistration.fromJson(Map<String, dynamic> json) => _$UserRegistrationFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationToJson(this);
}

/// Models the User Create Registration Event (and can be converted to JSON).
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationCreateEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationCreateEvent({
      this.applicationId,
      this.registration,
      this.user
  });

  factory UserRegistrationCreateEvent.fromJson(Map<String, dynamic> json) => _$UserRegistrationCreateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationCreateEventToJson(this);
}

/// Models the User Delete Registration Event (and can be converted to JSON).
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationDeleteEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationDeleteEvent({
      this.applicationId,
      this.registration,
      this.user
  });

  factory UserRegistrationDeleteEvent.fromJson(Map<String, dynamic> json) => _$UserRegistrationDeleteEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationDeleteEventToJson(this);
}

/// Models the User Update Registration Event (and can be converted to JSON).
///
/// @author Daniel DeGroff
@JsonSerializable()
class UserRegistrationUpdateEvent extends BaseEvent {
  String applicationId;
  UserRegistration original;
  UserRegistration registration;
  User user;

  UserRegistrationUpdateEvent({
      this.applicationId,
      this.original,
      this.registration,
      this.user
  });

  factory UserRegistrationUpdateEvent.fromJson(Map<String, dynamic> json) => _$UserRegistrationUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationUpdateEventToJson(this);
}

/// Models the User Registration Verified Event (and can be converted to JSON).
///
/// @author Trevor Smith
@JsonSerializable()
class UserRegistrationVerifiedEvent extends BaseEvent {
  String applicationId;
  UserRegistration registration;
  User user;

  UserRegistrationVerifiedEvent({
      this.applicationId,
      this.registration,
      this.user
  });

  factory UserRegistrationVerifiedEvent.fromJson(Map<String, dynamic> json) => _$UserRegistrationVerifiedEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserRegistrationVerifiedEventToJson(this);
}

/// User API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserRequest {
  bool sendSetPasswordEmail;
  bool skipVerification;
  User user;

  UserRequest({
      this.sendSetPasswordEmail,
      this.skipVerification,
      this.user
  });

  factory UserRequest.fromJson(Map<String, dynamic> json) => _$UserRequestFromJson(json);
  Map<String, dynamic> toJson() => _$UserRequestToJson(this);
}

/// User API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserResponse {
  String token;
  User user;

  UserResponse({
      this.token,
      this.user
  });

  factory UserResponse.fromJson(Map<String, dynamic> json) => _$UserResponseFromJson(json);
  Map<String, dynamic> toJson() => _$UserResponseToJson(this);
}

/// This class is the user query. It provides a build pattern as well as public fields for use on forms and in actions.
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserSearchCriteria extends BaseSearchCriteria {
  bool accurateTotal;
  List<String> ids;
  String query;
  String queryString;
  List<SortField> sortFields;

  UserSearchCriteria({
      this.accurateTotal,
      this.ids,
      this.query,
      this.queryString,
      this.sortFields
  });

  factory UserSearchCriteria.fromJson(Map<String, dynamic> json) => _$UserSearchCriteriaFromJson(json);
  Map<String, dynamic> toJson() => _$UserSearchCriteriaToJson(this);
}

/// @author Daniel DeGroff
enum UserState {
  @JsonValue('Authenticated')
  Authenticated,
  @JsonValue('AuthenticatedNotRegistered')
  AuthenticatedNotRegistered
}

/// Models the User Update Event (and can be converted to JSON).
///
/// @author Brian Pontarelli
@JsonSerializable()
class UserUpdateEvent extends BaseEvent {
  User original;
  User user;

  UserUpdateEvent({
      this.original,
      this.user
  });

  factory UserUpdateEvent.fromJson(Map<String, dynamic> json) => _$UserUpdateEventFromJson(json);
  Map<String, dynamic> toJson() => _$UserUpdateEventToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class ValidateResponse {
  JWT jwt;

  ValidateResponse({
      this.jwt
  });

  factory ValidateResponse.fromJson(Map<String, dynamic> json) => _$ValidateResponseFromJson(json);
  Map<String, dynamic> toJson() => _$ValidateResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyEmailResponse {
  String verificationId;

  VerifyEmailResponse({
      this.verificationId
  });

  factory VerifyEmailResponse.fromJson(Map<String, dynamic> json) => _$VerifyEmailResponseFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyEmailResponseToJson(this);
}

/// @author Daniel DeGroff
@JsonSerializable()
class VerifyRegistrationResponse {
  String verificationId;

  VerifyRegistrationResponse({
      this.verificationId
  });

  factory VerifyRegistrationResponse.fromJson(Map<String, dynamic> json) => _$VerifyRegistrationResponseFromJson(json);
  Map<String, dynamic> toJson() => _$VerifyRegistrationResponseToJson(this);
}

/// A server where events are sent. This includes user action events and any other events sent by FusionAuth.
///
/// @author Brian Pontarelli
@JsonSerializable()
class Webhook {
  List<String> applicationIds;
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
  String url;

  Webhook({
      this.applicationIds,
      this.connectTimeout,
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
      this.url
  });

  factory Webhook.fromJson(Map<String, dynamic> json) => _$WebhookFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookToJson(this);
}

/// Webhook API request object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class WebhookRequest {
  Webhook webhook;

  WebhookRequest({
      this.webhook
  });

  factory WebhookRequest.fromJson(Map<String, dynamic> json) => _$WebhookRequestFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookRequestToJson(this);
}

/// Webhook API response object.
///
/// @author Brian Pontarelli
@JsonSerializable()
class WebhookResponse {
  Webhook webhook;
  List<Webhook> webhooks;

  WebhookResponse({
      this.webhook,
      this.webhooks
  });

  factory WebhookResponse.fromJson(Map<String, dynamic> json) => _$WebhookResponseFromJson(json);
  Map<String, dynamic> toJson() => _$WebhookResponseToJson(this);
}

enum XMLSignatureLocation {
  @JsonValue('Assertion')
  Assertion,
  @JsonValue('Response')
  Response
}


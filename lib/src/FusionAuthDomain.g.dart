// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'FusionAuthDomain.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AccessToken _$AccessTokenFromJson(Map<String, dynamic> json) => AccessToken(
      access_token: json['access_token'] as String,
      expires_in: json['expires_in'] as num,
      id_token: json['id_token'] as String,
      refresh_token: json['refresh_token'] as String,
      scope: json['scope'] as String,
      token_type: _$enumDecode(_$TokenTypeEnumMap, json['token_type']),
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$AccessTokenToJson(AccessToken instance) =>
    <String, dynamic>{
      'access_token': instance.access_token,
      'expires_in': instance.expires_in,
      'id_token': instance.id_token,
      'refresh_token': instance.refresh_token,
      'scope': instance.scope,
      'token_type': _$TokenTypeEnumMap[instance.token_type],
      'userId': instance.userId,
    };

K _$enumDecode<K, V>(
  Map<K, V> enumValues,
  Object? source, {
  K? unknownValue,
}) {
  if (source == null) {
    throw ArgumentError(
      'A value must be provided. Supported values: '
      '${enumValues.values.join(', ')}',
    );
  }

  return enumValues.entries.singleWhere(
    (e) => e.value == source,
    orElse: () {
      if (unknownValue == null) {
        throw ArgumentError(
          '`$source` is not one of the supported values: '
          '${enumValues.values.join(', ')}',
        );
      }
      return MapEntry(unknownValue, enumValues.values.first);
    },
  ).key;
}

const _$TokenTypeEnumMap = {
  TokenType.Bearer: 'Bearer',
  TokenType.MAC: 'MAC',
};

ActionData _$ActionDataFromJson(Map<String, dynamic> json) => ActionData(
      actioneeUserId: json['actioneeUserId'] as String,
      actionerUserId: json['actionerUserId'] as String,
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      comment: json['comment'] as String,
      emailUser: json['emailUser'] as bool,
      expiry: json['expiry'] as num,
      notifyUser: json['notifyUser'] as bool,
      option: json['option'] as String,
      reasonId: json['reasonId'] as String,
      userActionId: json['userActionId'] as String,
    );

Map<String, dynamic> _$ActionDataToJson(ActionData instance) =>
    <String, dynamic>{
      'actioneeUserId': instance.actioneeUserId,
      'actionerUserId': instance.actionerUserId,
      'applicationIds': instance.applicationIds,
      'comment': instance.comment,
      'emailUser': instance.emailUser,
      'expiry': instance.expiry,
      'notifyUser': instance.notifyUser,
      'option': instance.option,
      'reasonId': instance.reasonId,
      'userActionId': instance.userActionId,
    };

ActionRequest _$ActionRequestFromJson(Map<String, dynamic> json) =>
    ActionRequest(
      action: ActionData.fromJson(json['action'] as Map<String, dynamic>),
      broadcast: json['broadcast'] as bool,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$ActionRequestToJson(ActionRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'action': instance.action,
      'broadcast': instance.broadcast,
    };

ActionResponse _$ActionResponseFromJson(Map<String, dynamic> json) =>
    ActionResponse(
      action: UserActionLog.fromJson(json['action'] as Map<String, dynamic>),
      actions: (json['actions'] as List<dynamic>)
          .map((e) => UserActionLog.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$ActionResponseToJson(ActionResponse instance) =>
    <String, dynamic>{
      'action': instance.action,
      'actions': instance.actions,
    };

APIKey _$APIKeyFromJson(Map<String, dynamic> json) => APIKey(
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      ipAccessControlListId: json['ipAccessControlListId'] as String,
      key: json['key'] as String,
      keyManager: json['keyManager'] as bool,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      metaData:
          APIKeyMetaData.fromJson(json['metaData'] as Map<String, dynamic>),
      permissions: APIKeyPermissions.fromJson(
          json['permissions'] as Map<String, dynamic>),
      tenantId: json['tenantId'] as String,
    );

Map<String, dynamic> _$APIKeyToJson(APIKey instance) => <String, dynamic>{
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'ipAccessControlListId': instance.ipAccessControlListId,
      'key': instance.key,
      'keyManager': instance.keyManager,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'metaData': instance.metaData,
      'permissions': instance.permissions,
      'tenantId': instance.tenantId,
    };

APIKeyMetaData _$APIKeyMetaDataFromJson(Map<String, dynamic> json) =>
    APIKeyMetaData(
      attributes: Map<String, String>.from(json['attributes'] as Map),
    );

Map<String, dynamic> _$APIKeyMetaDataToJson(APIKeyMetaData instance) =>
    <String, dynamic>{
      'attributes': instance.attributes,
    };

APIKeyPermissions _$APIKeyPermissionsFromJson(Map<String, dynamic> json) =>
    APIKeyPermissions(
      endpoints: (json['endpoints'] as Map<String, dynamic>).map(
        (k, e) =>
            MapEntry(k, (e as List<dynamic>).map((e) => e as String).toSet()),
      ),
    );

Map<String, dynamic> _$APIKeyPermissionsToJson(APIKeyPermissions instance) =>
    <String, dynamic>{
      'endpoints': instance.endpoints.map((k, e) => MapEntry(k, e.toList())),
    };

APIKeyRequest _$APIKeyRequestFromJson(Map<String, dynamic> json) =>
    APIKeyRequest(
      apiKey: APIKey.fromJson(json['apiKey'] as Map<String, dynamic>),
      sourceKeyId: json['sourceKeyId'] as String,
    );

Map<String, dynamic> _$APIKeyRequestToJson(APIKeyRequest instance) =>
    <String, dynamic>{
      'apiKey': instance.apiKey,
      'sourceKeyId': instance.sourceKeyId,
    };

APIKeyResponse _$APIKeyResponseFromJson(Map<String, dynamic> json) =>
    APIKeyResponse(
      apiKey: APIKey.fromJson(json['apiKey'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$APIKeyResponseToJson(APIKeyResponse instance) =>
    <String, dynamic>{
      'apiKey': instance.apiKey,
    };

AppleApplicationConfiguration _$AppleApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    AppleApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      keyId: json['keyId'] as String,
      scope: json['scope'] as String,
      servicesId: json['servicesId'] as String,
      teamId: json['teamId'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$AppleApplicationConfigurationToJson(
        AppleApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'keyId': instance.keyId,
      'scope': instance.scope,
      'servicesId': instance.servicesId,
      'teamId': instance.teamId,
    };

AppleIdentityProvider _$AppleIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    AppleIdentityProvider(
      buttonText: json['buttonText'] as String,
      keyId: json['keyId'] as String,
      scope: json['scope'] as String,
      servicesId: json['servicesId'] as String,
      teamId: json['teamId'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            AppleApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$AppleIdentityProviderToJson(
    AppleIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['keyId'] = instance.keyId;
  val['scope'] = instance.scope;
  val['servicesId'] = instance.servicesId;
  val['teamId'] = instance.teamId;
  return val;
}

const _$IdentityProviderLinkingStrategyEnumMap = {
  IdentityProviderLinkingStrategy.CreatePendingLink: 'CreatePendingLink',
  IdentityProviderLinkingStrategy.LinkAnonymously: 'LinkAnonymously',
  IdentityProviderLinkingStrategy.LinkByEmail: 'LinkByEmail',
  IdentityProviderLinkingStrategy.LinkByEmailForExistingUser:
      'LinkByEmailForExistingUser',
  IdentityProviderLinkingStrategy.LinkByUsername: 'LinkByUsername',
  IdentityProviderLinkingStrategy.LinkByUsernameForExistingUser:
      'LinkByUsernameForExistingUser',
  IdentityProviderLinkingStrategy.Unsupported: 'Unsupported',
};

const _$IdentityProviderTypeEnumMap = {
  IdentityProviderType.Apple: 'Apple',
  IdentityProviderType.EpicGames: 'EpicGames',
  IdentityProviderType.ExternalJWT: 'ExternalJWT',
  IdentityProviderType.Facebook: 'Facebook',
  IdentityProviderType.Google: 'Google',
  IdentityProviderType.HYPR: 'HYPR',
  IdentityProviderType.LinkedIn: 'LinkedIn',
  IdentityProviderType.Nintendo: 'Nintendo',
  IdentityProviderType.OpenIDConnect: 'OpenIDConnect',
  IdentityProviderType.SAMLv2: 'SAMLv2',
  IdentityProviderType.SAMLv2IdPInitiated: 'SAMLv2IdPInitiated',
  IdentityProviderType.SonyPSN: 'SonyPSN',
  IdentityProviderType.Steam: 'Steam',
  IdentityProviderType.Twitch: 'Twitch',
  IdentityProviderType.Twitter: 'Twitter',
  IdentityProviderType.Xbox: 'Xbox',
};

Application _$ApplicationFromJson(Map<String, dynamic> json) => Application(
      accessControlConfiguration:
          ApplicationAccessControlConfiguration.fromJson(
              json['accessControlConfiguration'] as Map<String, dynamic>),
      active: json['active'] as bool,
      authenticationTokenConfiguration:
          AuthenticationTokenConfiguration.fromJson(
              json['authenticationTokenConfiguration'] as Map<String, dynamic>),
      cleanSpeakConfiguration: CleanSpeakConfiguration.fromJson(
          json['cleanSpeakConfiguration'] as Map<String, dynamic>),
      data: json['data'] as Map<String, dynamic>,
      emailConfiguration: ApplicationEmailConfiguration.fromJson(
          json['emailConfiguration'] as Map<String, dynamic>),
      formConfiguration: ApplicationFormConfiguration.fromJson(
          json['formConfiguration'] as Map<String, dynamic>),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      jwtConfiguration: JWTConfiguration.fromJson(
          json['jwtConfiguration'] as Map<String, dynamic>),
      lambdaConfiguration: json['lambdaConfiguration'],
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      loginConfiguration: LoginConfiguration.fromJson(
          json['loginConfiguration'] as Map<String, dynamic>),
      multiFactorConfiguration: ApplicationMultiFactorConfiguration.fromJson(
          json['multiFactorConfiguration'] as Map<String, dynamic>),
      name: json['name'] as String,
      oauthConfiguration: OAuth2Configuration.fromJson(
          json['oauthConfiguration'] as Map<String, dynamic>),
      passwordlessConfiguration: PasswordlessConfiguration.fromJson(
          json['passwordlessConfiguration'] as Map<String, dynamic>),
      registrationConfiguration: RegistrationConfiguration.fromJson(
          json['registrationConfiguration'] as Map<String, dynamic>),
      registrationDeletePolicy: ApplicationRegistrationDeletePolicy.fromJson(
          json['registrationDeletePolicy'] as Map<String, dynamic>),
      roles: (json['roles'] as List<dynamic>)
          .map((e) => ApplicationRole.fromJson(e as Map<String, dynamic>))
          .toList(),
      samlv2Configuration: SAMLv2Configuration.fromJson(
          json['samlv2Configuration'] as Map<String, dynamic>),
      state: _$enumDecode(_$ObjectStateEnumMap, json['state']),
      tenantId: json['tenantId'] as String,
      themeId: json['themeId'] as String,
      unverified: RegistrationUnverifiedOptions.fromJson(
          json['unverified'] as Map<String, dynamic>),
      verificationEmailTemplateId:
          json['verificationEmailTemplateId'] as String,
      verificationStrategy: _$enumDecode(
          _$VerificationStrategyEnumMap, json['verificationStrategy']),
      verifyRegistration: json['verifyRegistration'] as bool,
    );

Map<String, dynamic> _$ApplicationToJson(Application instance) {
  final val = <String, dynamic>{
    'accessControlConfiguration': instance.accessControlConfiguration,
    'active': instance.active,
    'authenticationTokenConfiguration':
        instance.authenticationTokenConfiguration,
    'cleanSpeakConfiguration': instance.cleanSpeakConfiguration,
    'data': instance.data,
    'emailConfiguration': instance.emailConfiguration,
    'formConfiguration': instance.formConfiguration,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
    'jwtConfiguration': instance.jwtConfiguration,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['loginConfiguration'] = instance.loginConfiguration;
  val['multiFactorConfiguration'] = instance.multiFactorConfiguration;
  val['name'] = instance.name;
  val['oauthConfiguration'] = instance.oauthConfiguration;
  val['passwordlessConfiguration'] = instance.passwordlessConfiguration;
  val['registrationConfiguration'] = instance.registrationConfiguration;
  val['registrationDeletePolicy'] = instance.registrationDeletePolicy;
  val['roles'] = instance.roles;
  val['samlv2Configuration'] = instance.samlv2Configuration;
  val['state'] = _$ObjectStateEnumMap[instance.state];
  val['tenantId'] = instance.tenantId;
  val['themeId'] = instance.themeId;
  val['unverified'] = instance.unverified;
  val['verificationEmailTemplateId'] = instance.verificationEmailTemplateId;
  val['verificationStrategy'] =
      _$VerificationStrategyEnumMap[instance.verificationStrategy];
  val['verifyRegistration'] = instance.verifyRegistration;
  return val;
}

const _$ObjectStateEnumMap = {
  ObjectState.Active: 'Active',
  ObjectState.Inactive: 'Inactive',
  ObjectState.PendingDelete: 'PendingDelete',
};

const _$VerificationStrategyEnumMap = {
  VerificationStrategy.ClickableLink: 'ClickableLink',
  VerificationStrategy.FormField: 'FormField',
};

ApplicationAccessControlConfiguration
    _$ApplicationAccessControlConfigurationFromJson(
            Map<String, dynamic> json) =>
        ApplicationAccessControlConfiguration(
          uiIPAccessControlListId: json['uiIPAccessControlListId'] as String,
        );

Map<String, dynamic> _$ApplicationAccessControlConfigurationToJson(
        ApplicationAccessControlConfiguration instance) =>
    <String, dynamic>{
      'uiIPAccessControlListId': instance.uiIPAccessControlListId,
    };

ApplicationEmailConfiguration _$ApplicationEmailConfigurationFromJson(
        Map<String, dynamic> json) =>
    ApplicationEmailConfiguration(
      emailUpdateEmailTemplateId: json['emailUpdateEmailTemplateId'] as String,
      emailVerificationEmailTemplateId:
          json['emailVerificationEmailTemplateId'] as String,
      emailVerifiedEmailTemplateId:
          json['emailVerifiedEmailTemplateId'] as String,
      forgotPasswordEmailTemplateId:
          json['forgotPasswordEmailTemplateId'] as String,
      loginIdInUseOnCreateEmailTemplateId:
          json['loginIdInUseOnCreateEmailTemplateId'] as String,
      loginIdInUseOnUpdateEmailTemplateId:
          json['loginIdInUseOnUpdateEmailTemplateId'] as String,
      loginNewDeviceEmailTemplateId:
          json['loginNewDeviceEmailTemplateId'] as String,
      loginSuspiciousEmailTemplateId:
          json['loginSuspiciousEmailTemplateId'] as String,
      passwordlessEmailTemplateId:
          json['passwordlessEmailTemplateId'] as String,
      passwordResetSuccessEmailTemplateId:
          json['passwordResetSuccessEmailTemplateId'] as String,
      passwordUpdateEmailTemplateId:
          json['passwordUpdateEmailTemplateId'] as String,
      setPasswordEmailTemplateId: json['setPasswordEmailTemplateId'] as String,
      twoFactorMethodAddEmailTemplateId:
          json['twoFactorMethodAddEmailTemplateId'] as String,
      twoFactorMethodRemoveEmailTemplateId:
          json['twoFactorMethodRemoveEmailTemplateId'] as String,
    );

Map<String, dynamic> _$ApplicationEmailConfigurationToJson(
        ApplicationEmailConfiguration instance) =>
    <String, dynamic>{
      'emailUpdateEmailTemplateId': instance.emailUpdateEmailTemplateId,
      'emailVerificationEmailTemplateId':
          instance.emailVerificationEmailTemplateId,
      'emailVerifiedEmailTemplateId': instance.emailVerifiedEmailTemplateId,
      'forgotPasswordEmailTemplateId': instance.forgotPasswordEmailTemplateId,
      'loginIdInUseOnCreateEmailTemplateId':
          instance.loginIdInUseOnCreateEmailTemplateId,
      'loginIdInUseOnUpdateEmailTemplateId':
          instance.loginIdInUseOnUpdateEmailTemplateId,
      'loginNewDeviceEmailTemplateId': instance.loginNewDeviceEmailTemplateId,
      'loginSuspiciousEmailTemplateId': instance.loginSuspiciousEmailTemplateId,
      'passwordlessEmailTemplateId': instance.passwordlessEmailTemplateId,
      'passwordResetSuccessEmailTemplateId':
          instance.passwordResetSuccessEmailTemplateId,
      'passwordUpdateEmailTemplateId': instance.passwordUpdateEmailTemplateId,
      'setPasswordEmailTemplateId': instance.setPasswordEmailTemplateId,
      'twoFactorMethodAddEmailTemplateId':
          instance.twoFactorMethodAddEmailTemplateId,
      'twoFactorMethodRemoveEmailTemplateId':
          instance.twoFactorMethodRemoveEmailTemplateId,
    };

ApplicationEvent _$ApplicationEventFromJson(Map<String, dynamic> json) =>
    ApplicationEvent();

Map<String, dynamic> _$ApplicationEventToJson(ApplicationEvent instance) =>
    <String, dynamic>{};

ApplicationFormConfiguration _$ApplicationFormConfigurationFromJson(
        Map<String, dynamic> json) =>
    ApplicationFormConfiguration(
      adminRegistrationFormId: json['adminRegistrationFormId'] as String,
      selfServiceFormId: json['selfServiceFormId'] as String,
    );

Map<String, dynamic> _$ApplicationFormConfigurationToJson(
        ApplicationFormConfiguration instance) =>
    <String, dynamic>{
      'adminRegistrationFormId': instance.adminRegistrationFormId,
      'selfServiceFormId': instance.selfServiceFormId,
    };

ApplicationMultiFactorConfiguration
    _$ApplicationMultiFactorConfigurationFromJson(Map<String, dynamic> json) =>
        ApplicationMultiFactorConfiguration(
          email: MultiFactorEmailTemplate.fromJson(
              json['email'] as Map<String, dynamic>),
          sms: MultiFactorSMSTemplate.fromJson(
              json['sms'] as Map<String, dynamic>),
        );

Map<String, dynamic> _$ApplicationMultiFactorConfigurationToJson(
        ApplicationMultiFactorConfiguration instance) =>
    <String, dynamic>{
      'email': instance.email,
      'sms': instance.sms,
    };

ApplicationRegistrationDeletePolicy
    _$ApplicationRegistrationDeletePolicyFromJson(Map<String, dynamic> json) =>
        ApplicationRegistrationDeletePolicy(
          unverified: TimeBasedDeletePolicy.fromJson(
              json['unverified'] as Map<String, dynamic>),
        );

Map<String, dynamic> _$ApplicationRegistrationDeletePolicyToJson(
        ApplicationRegistrationDeletePolicy instance) =>
    <String, dynamic>{
      'unverified': instance.unverified,
    };

ApplicationRequest _$ApplicationRequestFromJson(Map<String, dynamic> json) =>
    ApplicationRequest(
      application:
          Application.fromJson(json['application'] as Map<String, dynamic>),
      role: ApplicationRole.fromJson(json['role'] as Map<String, dynamic>),
      webhookIds: (json['webhookIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$ApplicationRequestToJson(ApplicationRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'application': instance.application,
      'role': instance.role,
      'webhookIds': instance.webhookIds,
    };

ApplicationResponse _$ApplicationResponseFromJson(Map<String, dynamic> json) =>
    ApplicationResponse(
      application:
          Application.fromJson(json['application'] as Map<String, dynamic>),
      applications: (json['applications'] as List<dynamic>)
          .map((e) => Application.fromJson(e as Map<String, dynamic>))
          .toList(),
      role: ApplicationRole.fromJson(json['role'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ApplicationResponseToJson(
        ApplicationResponse instance) =>
    <String, dynamic>{
      'application': instance.application,
      'applications': instance.applications,
      'role': instance.role,
    };

ApplicationRole _$ApplicationRoleFromJson(Map<String, dynamic> json) =>
    ApplicationRole(
      description: json['description'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      isDefault: json['isDefault'] as bool,
      isSuperRole: json['isSuperRole'] as bool,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
    );

Map<String, dynamic> _$ApplicationRoleToJson(ApplicationRole instance) =>
    <String, dynamic>{
      'description': instance.description,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'isDefault': instance.isDefault,
      'isSuperRole': instance.isSuperRole,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
    };

ApplicationUnverifiedConfiguration _$ApplicationUnverifiedConfigurationFromJson(
        Map<String, dynamic> json) =>
    ApplicationUnverifiedConfiguration(
      registration:
          _$enumDecode(_$UnverifiedBehaviorEnumMap, json['registration']),
      verificationStrategy: _$enumDecode(
          _$VerificationStrategyEnumMap, json['verificationStrategy']),
      whenGated: RegistrationUnverifiedOptions.fromJson(
          json['whenGated'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ApplicationUnverifiedConfigurationToJson(
        ApplicationUnverifiedConfiguration instance) =>
    <String, dynamic>{
      'registration': _$UnverifiedBehaviorEnumMap[instance.registration],
      'verificationStrategy':
          _$VerificationStrategyEnumMap[instance.verificationStrategy],
      'whenGated': instance.whenGated,
    };

const _$UnverifiedBehaviorEnumMap = {
  UnverifiedBehavior.Allow: 'Allow',
  UnverifiedBehavior.Gated: 'Gated',
};

Attachment _$AttachmentFromJson(Map<String, dynamic> json) => Attachment(
      attachment:
          (json['attachment'] as List<dynamic>).map((e) => e as num).toList(),
      mime: json['mime'] as String,
      name: json['name'] as String,
    );

Map<String, dynamic> _$AttachmentToJson(Attachment instance) =>
    <String, dynamic>{
      'attachment': instance.attachment,
      'mime': instance.mime,
      'name': instance.name,
    };

AuditLog _$AuditLogFromJson(Map<String, dynamic> json) => AuditLog(
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as num,
      insertInstant: json['insertInstant'] as num,
      insertUser: json['insertUser'] as String,
      message: json['message'] as String,
      newValue: json['newValue'],
      oldValue: json['oldValue'],
      reason: json['reason'] as String,
    );

Map<String, dynamic> _$AuditLogToJson(AuditLog instance) {
  final val = <String, dynamic>{
    'data': instance.data,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
    'insertUser': instance.insertUser,
    'message': instance.message,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('newValue', instance.newValue);
  writeNotNull('oldValue', instance.oldValue);
  val['reason'] = instance.reason;
  return val;
}

AuditLogConfiguration _$AuditLogConfigurationFromJson(
        Map<String, dynamic> json) =>
    AuditLogConfiguration(
      delete:
          DeleteConfiguration.fromJson(json['delete'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$AuditLogConfigurationToJson(
        AuditLogConfiguration instance) =>
    <String, dynamic>{
      'delete': instance.delete,
    };

AuditLogCreateEvent _$AuditLogCreateEventFromJson(Map<String, dynamic> json) =>
    AuditLogCreateEvent(
      auditLog: AuditLog.fromJson(json['auditLog'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$AuditLogCreateEventToJson(
        AuditLogCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'auditLog': instance.auditLog,
    };

const _$EventTypeEnumMap = {
  EventType.JWTPublicKeyUpdate: 'JWTPublicKeyUpdate',
  EventType.JWTRefreshTokenRevoke: 'JWTRefreshTokenRevoke',
  EventType.JWTRefresh: 'JWTRefresh',
  EventType.AuditLogCreate: 'AuditLogCreate',
  EventType.EventLogCreate: 'EventLogCreate',
  EventType.KickstartSuccess: 'KickstartSuccess',
  EventType.UserAction: 'UserAction',
  EventType.UserBulkCreate: 'UserBulkCreate',
  EventType.UserCreate: 'UserCreate',
  EventType.UserCreateComplete: 'UserCreateComplete',
  EventType.UserDeactivate: 'UserDeactivate',
  EventType.UserDelete: 'UserDelete',
  EventType.UserDeleteComplete: 'UserDeleteComplete',
  EventType.UserEmailUpdate: 'UserEmailUpdate',
  EventType.UserEmailVerified: 'UserEmailVerified',
  EventType.UserIdentityProviderLink: 'UserIdentityProviderLink',
  EventType.UserIdentityProviderUnlink: 'UserIdentityProviderUnlink',
  EventType.UserLoginIdDuplicateOnCreate: 'UserLoginIdDuplicateOnCreate',
  EventType.UserLoginIdDuplicateOnUpdate: 'UserLoginIdDuplicateOnUpdate',
  EventType.UserLoginFailed: 'UserLoginFailed',
  EventType.UserLoginNewDevice: 'UserLoginNewDevice',
  EventType.UserLoginSuccess: 'UserLoginSuccess',
  EventType.UserLoginSuspicious: 'UserLoginSuspicious',
  EventType.UserPasswordBreach: 'UserPasswordBreach',
  EventType.UserPasswordResetSend: 'UserPasswordResetSend',
  EventType.UserPasswordResetStart: 'UserPasswordResetStart',
  EventType.UserPasswordResetSuccess: 'UserPasswordResetSuccess',
  EventType.UserPasswordUpdate: 'UserPasswordUpdate',
  EventType.UserReactivate: 'UserReactivate',
  EventType.UserRegistrationCreate: 'UserRegistrationCreate',
  EventType.UserRegistrationCreateComplete: 'UserRegistrationCreateComplete',
  EventType.UserRegistrationDelete: 'UserRegistrationDelete',
  EventType.UserRegistrationDeleteComplete: 'UserRegistrationDeleteComplete',
  EventType.UserRegistrationUpdate: 'UserRegistrationUpdate',
  EventType.UserRegistrationUpdateComplete: 'UserRegistrationUpdateComplete',
  EventType.UserRegistrationVerified: 'UserRegistrationVerified',
  EventType.UserTwoFactorMethodAdd: 'UserTwoFactorMethodAdd',
  EventType.UserTwoFactorMethodRemove: 'UserTwoFactorMethodRemove',
  EventType.UserUpdate: 'UserUpdate',
  EventType.UserUpdateComplete: 'UserUpdateComplete',
  EventType.Test: 'Test',
};

AuditLogExportRequest _$AuditLogExportRequestFromJson(
        Map<String, dynamic> json) =>
    AuditLogExportRequest(
      criteria: AuditLogSearchCriteria.fromJson(
          json['criteria'] as Map<String, dynamic>),
    )
      ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
      ..zoneId = json['zoneId'] as String;

Map<String, dynamic> _$AuditLogExportRequestToJson(
        AuditLogExportRequest instance) =>
    <String, dynamic>{
      'dateTimeSecondsFormat': instance.dateTimeSecondsFormat,
      'zoneId': instance.zoneId,
      'criteria': instance.criteria,
    };

AuditLogRequest _$AuditLogRequestFromJson(Map<String, dynamic> json) =>
    AuditLogRequest(
      auditLog: AuditLog.fromJson(json['auditLog'] as Map<String, dynamic>),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$AuditLogRequestToJson(AuditLogRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'auditLog': instance.auditLog,
    };

AuditLogResponse _$AuditLogResponseFromJson(Map<String, dynamic> json) =>
    AuditLogResponse(
      auditLog: AuditLog.fromJson(json['auditLog'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$AuditLogResponseToJson(AuditLogResponse instance) =>
    <String, dynamic>{
      'auditLog': instance.auditLog,
    };

AuditLogSearchCriteria _$AuditLogSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    AuditLogSearchCriteria(
      end: json['end'] as num,
      message: json['message'] as String,
      newValue: json['newValue'] as String,
      oldValue: json['oldValue'] as String,
      reason: json['reason'] as String,
      start: json['start'] as num,
      user: json['user'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$AuditLogSearchCriteriaToJson(
        AuditLogSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'end': instance.end,
      'message': instance.message,
      'newValue': instance.newValue,
      'oldValue': instance.oldValue,
      'reason': instance.reason,
      'start': instance.start,
      'user': instance.user,
    };

AuditLogSearchRequest _$AuditLogSearchRequestFromJson(
        Map<String, dynamic> json) =>
    AuditLogSearchRequest(
      search: AuditLogSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$AuditLogSearchRequestToJson(
        AuditLogSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

AuditLogSearchResponse _$AuditLogSearchResponseFromJson(
        Map<String, dynamic> json) =>
    AuditLogSearchResponse(
      auditLogs: (json['auditLogs'] as List<dynamic>)
          .map((e) => AuditLog.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$AuditLogSearchResponseToJson(
        AuditLogSearchResponse instance) =>
    <String, dynamic>{
      'auditLogs': instance.auditLogs,
      'total': instance.total,
    };

AuthenticationTokenConfiguration _$AuthenticationTokenConfigurationFromJson(
        Map<String, dynamic> json) =>
    AuthenticationTokenConfiguration()..enabled = json['enabled'] as bool;

Map<String, dynamic> _$AuthenticationTokenConfigurationToJson(
        AuthenticationTokenConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
    };

AuthenticatorConfiguration _$AuthenticatorConfigurationFromJson(
        Map<String, dynamic> json) =>
    AuthenticatorConfiguration(
      algorithm: _$enumDecode(_$TOTPAlgorithmEnumMap, json['algorithm']),
      codeLength: json['codeLength'] as num,
      timeStep: json['timeStep'] as num,
    );

Map<String, dynamic> _$AuthenticatorConfigurationToJson(
        AuthenticatorConfiguration instance) =>
    <String, dynamic>{
      'algorithm': _$TOTPAlgorithmEnumMap[instance.algorithm],
      'codeLength': instance.codeLength,
      'timeStep': instance.timeStep,
    };

const _$TOTPAlgorithmEnumMap = {
  TOTPAlgorithm.HmacSHA1: 'HmacSHA1',
  TOTPAlgorithm.HmacSHA256: 'HmacSHA256',
  TOTPAlgorithm.HmacSHA512: 'HmacSHA512',
};

BaseConnectorConfiguration _$BaseConnectorConfigurationFromJson(
        Map<String, dynamic> json) =>
    BaseConnectorConfiguration(
      data: json['data'] as Map<String, dynamic>,
      debug: json['debug'] as bool,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      type: _$enumDecode(_$ConnectorTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$BaseConnectorConfigurationToJson(
        BaseConnectorConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$ConnectorTypeEnumMap[instance.type],
    };

const _$ConnectorTypeEnumMap = {
  ConnectorType.FusionAuth: 'FusionAuth',
  ConnectorType.Generic: 'Generic',
  ConnectorType.LDAP: 'LDAP',
};

BaseElasticSearchCriteria _$BaseElasticSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    BaseElasticSearchCriteria(
      accurateTotal: json['accurateTotal'] as bool,
      ids: (json['ids'] as List<dynamic>).map((e) => e as String).toList(),
      query: json['query'] as String,
      queryString: json['queryString'] as String,
      sortFields: (json['sortFields'] as List<dynamic>)
          .map((e) => SortField.fromJson(e as Map<String, dynamic>))
          .toList(),
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$BaseElasticSearchCriteriaToJson(
        BaseElasticSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'accurateTotal': instance.accurateTotal,
      'ids': instance.ids,
      'query': instance.query,
      'queryString': instance.queryString,
      'sortFields': instance.sortFields,
    };

BaseEvent _$BaseEventFromJson(Map<String, dynamic> json) => BaseEvent(
      createInstant: json['createInstant'] as num,
      id: json['id'] as String,
      info: EventInfo.fromJson(json['info'] as Map<String, dynamic>),
      tenantId: json['tenantId'] as String,
      type: _$enumDecode(_$EventTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$BaseEventToJson(BaseEvent instance) => <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
    };

BaseEventRequest _$BaseEventRequestFromJson(Map<String, dynamic> json) =>
    BaseEventRequest(
      eventInfo: EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$BaseEventRequestToJson(BaseEventRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
    };

BaseExportRequest _$BaseExportRequestFromJson(Map<String, dynamic> json) =>
    BaseExportRequest(
      dateTimeSecondsFormat: json['dateTimeSecondsFormat'] as String,
      zoneId: json['zoneId'] as String,
    );

Map<String, dynamic> _$BaseExportRequestToJson(BaseExportRequest instance) =>
    <String, dynamic>{
      'dateTimeSecondsFormat': instance.dateTimeSecondsFormat,
      'zoneId': instance.zoneId,
    };

Map<String, dynamic> _$BaseIdentityProviderToJson<
        D extends BaseIdentityProviderApplicationConfiguration>(
    BaseIdentityProvider<D> instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration.map((k, e) =>
        MapEntry(k,
            IdentityProviderApplicationConfigurationConverter<D>().toJson(e))),
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  return val;
}

BaseIdentityProviderApplicationConfiguration
    _$BaseIdentityProviderApplicationConfigurationFromJson(
            Map<String, dynamic> json) =>
        BaseIdentityProviderApplicationConfiguration(
          createRegistration: json['createRegistration'] as bool,
          data: json['data'] as Map<String, dynamic>,
        )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$BaseIdentityProviderApplicationConfigurationToJson(
        BaseIdentityProviderApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
    };

BaseLoginRequest _$BaseLoginRequestFromJson(Map<String, dynamic> json) =>
    BaseLoginRequest(
      applicationId: json['applicationId'] as String,
      ipAddress: json['ipAddress'] as String,
      metaData: MetaData.fromJson(json['metaData'] as Map<String, dynamic>),
      newDevice: json['newDevice'] as bool,
      noJWT: json['noJWT'] as bool,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$BaseLoginRequestToJson(BaseLoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
    };

BaseMessengerConfiguration _$BaseMessengerConfigurationFromJson(
        Map<String, dynamic> json) =>
    BaseMessengerConfiguration(
      data: json['data'] as Map<String, dynamic>,
      debug: json['debug'] as bool,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      transport: json['transport'] as String,
      type: _$enumDecode(_$MessengerTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$BaseMessengerConfigurationToJson(
        BaseMessengerConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'transport': instance.transport,
      'type': _$MessengerTypeEnumMap[instance.type],
    };

const _$MessengerTypeEnumMap = {
  MessengerType.Generic: 'Generic',
  MessengerType.Kafka: 'Kafka',
  MessengerType.Twilio: 'Twilio',
};

BaseSearchCriteria _$BaseSearchCriteriaFromJson(Map<String, dynamic> json) =>
    BaseSearchCriteria(
      numberOfResults: json['numberOfResults'] as num,
      orderBy: json['orderBy'] as String,
      startRow: json['startRow'] as num,
    );

Map<String, dynamic> _$BaseSearchCriteriaToJson(BaseSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
    };

BreachedPasswordTenantMetric _$BreachedPasswordTenantMetricFromJson(
        Map<String, dynamic> json) =>
    BreachedPasswordTenantMetric(
      actionRequired: json['actionRequired'] as num,
      matchedCommonPasswordCount: json['matchedCommonPasswordCount'] as num,
      matchedExactCount: json['matchedExactCount'] as num,
      matchedPasswordCount: json['matchedPasswordCount'] as num,
      matchedSubAddressCount: json['matchedSubAddressCount'] as num,
      passwordsCheckedCount: json['passwordsCheckedCount'] as num,
    );

Map<String, dynamic> _$BreachedPasswordTenantMetricToJson(
        BreachedPasswordTenantMetric instance) =>
    <String, dynamic>{
      'actionRequired': instance.actionRequired,
      'matchedCommonPasswordCount': instance.matchedCommonPasswordCount,
      'matchedExactCount': instance.matchedExactCount,
      'matchedPasswordCount': instance.matchedPasswordCount,
      'matchedSubAddressCount': instance.matchedSubAddressCount,
      'passwordsCheckedCount': instance.passwordsCheckedCount,
    };

CertificateInformation _$CertificateInformationFromJson(
        Map<String, dynamic> json) =>
    CertificateInformation(
      issuer: json['issuer'] as String,
      md5Fingerprint: json['md5Fingerprint'] as String,
      serialNumber: json['serialNumber'] as String,
      sha1Fingerprint: json['sha1Fingerprint'] as String,
      sha1Thumbprint: json['sha1Thumbprint'] as String,
      sha256Fingerprint: json['sha256Fingerprint'] as String,
      sha256Thumbprint: json['sha256Thumbprint'] as String,
      subject: json['subject'] as String,
      validFrom: json['validFrom'] as num,
      validTo: json['validTo'] as num,
    );

Map<String, dynamic> _$CertificateInformationToJson(
        CertificateInformation instance) =>
    <String, dynamic>{
      'issuer': instance.issuer,
      'md5Fingerprint': instance.md5Fingerprint,
      'serialNumber': instance.serialNumber,
      'sha1Fingerprint': instance.sha1Fingerprint,
      'sha1Thumbprint': instance.sha1Thumbprint,
      'sha256Fingerprint': instance.sha256Fingerprint,
      'sha256Thumbprint': instance.sha256Thumbprint,
      'subject': instance.subject,
      'validFrom': instance.validFrom,
      'validTo': instance.validTo,
    };

ChangePasswordRequest _$ChangePasswordRequestFromJson(
        Map<String, dynamic> json) =>
    ChangePasswordRequest(
      applicationId: json['applicationId'] as String,
      changePasswordId: json['changePasswordId'] as String,
      currentPassword: json['currentPassword'] as String,
      loginId: json['loginId'] as String,
      password: json['password'] as String,
      refreshToken: json['refreshToken'] as String,
      trustChallenge: json['trustChallenge'] as String,
      trustToken: json['trustToken'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$ChangePasswordRequestToJson(
        ChangePasswordRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'changePasswordId': instance.changePasswordId,
      'currentPassword': instance.currentPassword,
      'loginId': instance.loginId,
      'password': instance.password,
      'refreshToken': instance.refreshToken,
      'trustChallenge': instance.trustChallenge,
      'trustToken': instance.trustToken,
    };

ChangePasswordResponse _$ChangePasswordResponseFromJson(
        Map<String, dynamic> json) =>
    ChangePasswordResponse(
      oneTimePassword: json['oneTimePassword'] as String,
      state: json['state'] as Map<String, dynamic>,
    );

Map<String, dynamic> _$ChangePasswordResponseToJson(
        ChangePasswordResponse instance) =>
    <String, dynamic>{
      'oneTimePassword': instance.oneTimePassword,
      'state': instance.state,
    };

CleanSpeakConfiguration _$CleanSpeakConfigurationFromJson(
        Map<String, dynamic> json) =>
    CleanSpeakConfiguration(
      apiKey: json['apiKey'] as String,
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      url: json['url'] as String,
      usernameModeration: UsernameModeration.fromJson(
          json['usernameModeration'] as Map<String, dynamic>),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$CleanSpeakConfigurationToJson(
        CleanSpeakConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'apiKey': instance.apiKey,
      'applicationIds': instance.applicationIds,
      'url': instance.url,
      'usernameModeration': instance.usernameModeration,
    };

ConnectorPolicy _$ConnectorPolicyFromJson(Map<String, dynamic> json) =>
    ConnectorPolicy(
      connectorId: json['connectorId'] as String,
      data: json['data'] as Map<String, dynamic>,
      domains:
          (json['domains'] as List<dynamic>).map((e) => e as String).toSet(),
      migrate: json['migrate'] as bool,
    );

Map<String, dynamic> _$ConnectorPolicyToJson(ConnectorPolicy instance) =>
    <String, dynamic>{
      'connectorId': instance.connectorId,
      'data': instance.data,
      'domains': instance.domains.toList(),
      'migrate': instance.migrate,
    };

ConnectorRequest _$ConnectorRequestFromJson(Map<String, dynamic> json) =>
    ConnectorRequest(
      connector: BaseConnectorConfiguration.fromJson(
          json['connector'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ConnectorRequestToJson(ConnectorRequest instance) =>
    <String, dynamic>{
      'connector': instance.connector,
    };

ConnectorResponse _$ConnectorResponseFromJson(Map<String, dynamic> json) =>
    ConnectorResponse(
      connector: BaseConnectorConfiguration.fromJson(
          json['connector'] as Map<String, dynamic>),
      connectors: (json['connectors'] as List<dynamic>)
          .map((e) =>
              BaseConnectorConfiguration.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$ConnectorResponseToJson(ConnectorResponse instance) =>
    <String, dynamic>{
      'connector': instance.connector,
      'connectors': instance.connectors,
    };

Consent _$ConsentFromJson(Map<String, dynamic> json) => Consent(
      consentEmailTemplateId: json['consentEmailTemplateId'] as String,
      countryMinimumAgeForSelfConsent:
          Map<String, num>.from(json['countryMinimumAgeForSelfConsent'] as Map),
      data: json['data'] as Map<String, dynamic>,
      defaultMinimumAgeForSelfConsent:
          json['defaultMinimumAgeForSelfConsent'] as num,
      emailPlus: EmailPlus.fromJson(json['emailPlus'] as Map<String, dynamic>),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      multipleValuesAllowed: json['multipleValuesAllowed'] as bool,
      name: json['name'] as String,
      values:
          (json['values'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$ConsentToJson(Consent instance) => <String, dynamic>{
      'consentEmailTemplateId': instance.consentEmailTemplateId,
      'countryMinimumAgeForSelfConsent':
          instance.countryMinimumAgeForSelfConsent,
      'data': instance.data,
      'defaultMinimumAgeForSelfConsent':
          instance.defaultMinimumAgeForSelfConsent,
      'emailPlus': instance.emailPlus,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'multipleValuesAllowed': instance.multipleValuesAllowed,
      'name': instance.name,
      'values': instance.values,
    };

ConsentRequest _$ConsentRequestFromJson(Map<String, dynamic> json) =>
    ConsentRequest(
      consent: Consent.fromJson(json['consent'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ConsentRequestToJson(ConsentRequest instance) =>
    <String, dynamic>{
      'consent': instance.consent,
    };

ConsentResponse _$ConsentResponseFromJson(Map<String, dynamic> json) =>
    ConsentResponse(
      consent: Consent.fromJson(json['consent'] as Map<String, dynamic>),
      consents: (json['consents'] as List<dynamic>)
          .map((e) => Consent.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$ConsentResponseToJson(ConsentResponse instance) =>
    <String, dynamic>{
      'consent': instance.consent,
      'consents': instance.consents,
    };

CORSConfiguration _$CORSConfigurationFromJson(Map<String, dynamic> json) =>
    CORSConfiguration(
      allowCredentials: json['allowCredentials'] as bool,
      allowedHeaders: (json['allowedHeaders'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      allowedMethods: (json['allowedMethods'] as List<dynamic>)
          .map((e) => _$enumDecode(_$HTTPMethodEnumMap, e))
          .toList(),
      allowedOrigins: (json['allowedOrigins'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      debug: json['debug'] as bool,
      exposedHeaders: (json['exposedHeaders'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      preflightMaxAgeInSeconds: json['preflightMaxAgeInSeconds'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$CORSConfigurationToJson(CORSConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'allowCredentials': instance.allowCredentials,
      'allowedHeaders': instance.allowedHeaders,
      'allowedMethods':
          instance.allowedMethods.map((e) => _$HTTPMethodEnumMap[e]).toList(),
      'allowedOrigins': instance.allowedOrigins,
      'debug': instance.debug,
      'exposedHeaders': instance.exposedHeaders,
      'preflightMaxAgeInSeconds': instance.preflightMaxAgeInSeconds,
    };

const _$HTTPMethodEnumMap = {
  HTTPMethod.GET: 'GET',
  HTTPMethod.POST: 'POST',
  HTTPMethod.PUT: 'PUT',
  HTTPMethod.DELETE: 'DELETE',
  HTTPMethod.HEAD: 'HEAD',
  HTTPMethod.OPTIONS: 'OPTIONS',
  HTTPMethod.PATCH: 'PATCH',
};

Count _$CountFromJson(Map<String, dynamic> json) => Count(
      count: json['count'] as num,
      interval: json['interval'] as num,
    );

Map<String, dynamic> _$CountToJson(Count instance) => <String, dynamic>{
      'count': instance.count,
      'interval': instance.interval,
    };

DailyActiveUserReportResponse _$DailyActiveUserReportResponseFromJson(
        Map<String, dynamic> json) =>
    DailyActiveUserReportResponse(
      dailyActiveUsers: (json['dailyActiveUsers'] as List<dynamic>)
          .map((e) => Count.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$DailyActiveUserReportResponseToJson(
        DailyActiveUserReportResponse instance) =>
    <String, dynamic>{
      'dailyActiveUsers': instance.dailyActiveUsers,
      'total': instance.total,
    };

DeleteConfiguration _$DeleteConfigurationFromJson(Map<String, dynamic> json) =>
    DeleteConfiguration(
      numberOfDaysToRetain: json['numberOfDaysToRetain'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$DeleteConfigurationToJson(
        DeleteConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'numberOfDaysToRetain': instance.numberOfDaysToRetain,
    };

DeviceInfo _$DeviceInfoFromJson(Map<String, dynamic> json) => DeviceInfo(
      description: json['description'] as String,
      lastAccessedAddress: json['lastAccessedAddress'] as String,
      lastAccessedInstant: json['lastAccessedInstant'] as num,
      name: json['name'] as String,
      type: _$enumDecode(_$DeviceTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$DeviceInfoToJson(DeviceInfo instance) =>
    <String, dynamic>{
      'description': instance.description,
      'lastAccessedAddress': instance.lastAccessedAddress,
      'lastAccessedInstant': instance.lastAccessedInstant,
      'name': instance.name,
      'type': _$DeviceTypeEnumMap[instance.type],
    };

const _$DeviceTypeEnumMap = {
  DeviceType.BROWSER: 'BROWSER',
  DeviceType.DESKTOP: 'DESKTOP',
  DeviceType.LAPTOP: 'LAPTOP',
  DeviceType.MOBILE: 'MOBILE',
  DeviceType.OTHER: 'OTHER',
  DeviceType.SERVER: 'SERVER',
  DeviceType.TABLET: 'TABLET',
  DeviceType.TV: 'TV',
  DeviceType.UNKNOWN: 'UNKNOWN',
};

DeviceResponse _$DeviceResponseFromJson(Map<String, dynamic> json) =>
    DeviceResponse(
      device_code: json['device_code'] as String,
      expires_in: json['expires_in'] as num,
      interval: json['interval'] as num,
      user_code: json['user_code'] as String,
      verification_uri: json['verification_uri'] as String,
      verification_uri_complete: json['verification_uri_complete'] as String,
    );

Map<String, dynamic> _$DeviceResponseToJson(DeviceResponse instance) =>
    <String, dynamic>{
      'device_code': instance.device_code,
      'expires_in': instance.expires_in,
      'interval': instance.interval,
      'user_code': instance.user_code,
      'verification_uri': instance.verification_uri,
      'verification_uri_complete': instance.verification_uri_complete,
    };

DisplayableRawLogin _$DisplayableRawLoginFromJson(Map<String, dynamic> json) =>
    DisplayableRawLogin(
      applicationName: json['applicationName'] as String,
      location: Location.fromJson(json['location'] as Map<String, dynamic>),
      loginId: json['loginId'] as String,
    )
      ..applicationId = json['applicationId'] as String
      ..instant = json['instant'] as num
      ..ipAddress = json['ipAddress'] as String
      ..userId = json['userId'] as String;

Map<String, dynamic> _$DisplayableRawLoginToJson(
        DisplayableRawLogin instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'instant': instance.instant,
      'ipAddress': instance.ipAddress,
      'userId': instance.userId,
      'applicationName': instance.applicationName,
      'location': instance.location,
      'loginId': instance.loginId,
    };

DomainBasedIdentityProvider _$DomainBasedIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    DomainBasedIdentityProvider();

Map<String, dynamic> _$DomainBasedIdentityProviderToJson(
        DomainBasedIdentityProvider instance) =>
    <String, dynamic>{};

Email _$EmailFromJson(Map<String, dynamic> json) => Email(
      attachments: (json['attachments'] as List<dynamic>)
          .map((e) => Attachment.fromJson(e as Map<String, dynamic>))
          .toList(),
      bcc: (json['bcc'] as List<dynamic>)
          .map((e) => EmailAddress.fromJson(e as Map<String, dynamic>))
          .toList(),
      cc: (json['cc'] as List<dynamic>)
          .map((e) => EmailAddress.fromJson(e as Map<String, dynamic>))
          .toList(),
      from: EmailAddress.fromJson(json['from'] as Map<String, dynamic>),
      html: json['html'] as String,
      replyTo: EmailAddress.fromJson(json['replyTo'] as Map<String, dynamic>),
      subject: json['subject'] as String,
      text: json['text'] as String,
      to: (json['to'] as List<dynamic>)
          .map((e) => EmailAddress.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$EmailToJson(Email instance) => <String, dynamic>{
      'attachments': instance.attachments,
      'bcc': instance.bcc,
      'cc': instance.cc,
      'from': instance.from,
      'html': instance.html,
      'replyTo': instance.replyTo,
      'subject': instance.subject,
      'text': instance.text,
      'to': instance.to,
    };

EmailAddress _$EmailAddressFromJson(Map<String, dynamic> json) => EmailAddress(
      address: json['address'] as String,
      display: json['display'] as String,
    );

Map<String, dynamic> _$EmailAddressToJson(EmailAddress instance) =>
    <String, dynamic>{
      'address': instance.address,
      'display': instance.display,
    };

EmailConfiguration _$EmailConfigurationFromJson(Map<String, dynamic> json) =>
    EmailConfiguration(
      additionalHeaders: (json['additionalHeaders'] as List<dynamic>)
          .map((e) => EmailHeader.fromJson(e as Map<String, dynamic>))
          .toList(),
      debug: json['debug'] as bool,
      defaultFromEmail: json['defaultFromEmail'] as String,
      defaultFromName: json['defaultFromName'] as String,
      emailUpdateEmailTemplateId: json['emailUpdateEmailTemplateId'] as String,
      emailVerifiedEmailTemplateId:
          json['emailVerifiedEmailTemplateId'] as String,
      forgotPasswordEmailTemplateId:
          json['forgotPasswordEmailTemplateId'] as String,
      host: json['host'] as String,
      implicitEmailVerificationAllowed:
          json['implicitEmailVerificationAllowed'] as bool,
      loginIdInUseOnCreateEmailTemplateId:
          json['loginIdInUseOnCreateEmailTemplateId'] as String,
      loginIdInUseOnUpdateEmailTemplateId:
          json['loginIdInUseOnUpdateEmailTemplateId'] as String,
      loginNewDeviceEmailTemplateId:
          json['loginNewDeviceEmailTemplateId'] as String,
      loginSuspiciousEmailTemplateId:
          json['loginSuspiciousEmailTemplateId'] as String,
      password: json['password'] as String,
      passwordlessEmailTemplateId:
          json['passwordlessEmailTemplateId'] as String,
      passwordResetSuccessEmailTemplateId:
          json['passwordResetSuccessEmailTemplateId'] as String,
      passwordUpdateEmailTemplateId:
          json['passwordUpdateEmailTemplateId'] as String,
      port: json['port'] as num,
      properties: json['properties'] as String,
      security: _$enumDecode(_$EmailSecurityTypeEnumMap, json['security']),
      setPasswordEmailTemplateId: json['setPasswordEmailTemplateId'] as String,
      twoFactorMethodAddEmailTemplateId:
          json['twoFactorMethodAddEmailTemplateId'] as String,
      twoFactorMethodRemoveEmailTemplateId:
          json['twoFactorMethodRemoveEmailTemplateId'] as String,
      unverified: EmailUnverifiedOptions.fromJson(
          json['unverified'] as Map<String, dynamic>),
      username: json['username'] as String,
      verificationEmailTemplateId:
          json['verificationEmailTemplateId'] as String,
      verificationStrategy: _$enumDecode(
          _$VerificationStrategyEnumMap, json['verificationStrategy']),
      verifyEmail: json['verifyEmail'] as bool,
      verifyEmailWhenChanged: json['verifyEmailWhenChanged'] as bool,
    );

Map<String, dynamic> _$EmailConfigurationToJson(EmailConfiguration instance) =>
    <String, dynamic>{
      'additionalHeaders': instance.additionalHeaders,
      'debug': instance.debug,
      'defaultFromEmail': instance.defaultFromEmail,
      'defaultFromName': instance.defaultFromName,
      'emailUpdateEmailTemplateId': instance.emailUpdateEmailTemplateId,
      'emailVerifiedEmailTemplateId': instance.emailVerifiedEmailTemplateId,
      'forgotPasswordEmailTemplateId': instance.forgotPasswordEmailTemplateId,
      'host': instance.host,
      'implicitEmailVerificationAllowed':
          instance.implicitEmailVerificationAllowed,
      'loginIdInUseOnCreateEmailTemplateId':
          instance.loginIdInUseOnCreateEmailTemplateId,
      'loginIdInUseOnUpdateEmailTemplateId':
          instance.loginIdInUseOnUpdateEmailTemplateId,
      'loginNewDeviceEmailTemplateId': instance.loginNewDeviceEmailTemplateId,
      'loginSuspiciousEmailTemplateId': instance.loginSuspiciousEmailTemplateId,
      'password': instance.password,
      'passwordlessEmailTemplateId': instance.passwordlessEmailTemplateId,
      'passwordResetSuccessEmailTemplateId':
          instance.passwordResetSuccessEmailTemplateId,
      'passwordUpdateEmailTemplateId': instance.passwordUpdateEmailTemplateId,
      'port': instance.port,
      'properties': instance.properties,
      'security': _$EmailSecurityTypeEnumMap[instance.security],
      'setPasswordEmailTemplateId': instance.setPasswordEmailTemplateId,
      'twoFactorMethodAddEmailTemplateId':
          instance.twoFactorMethodAddEmailTemplateId,
      'twoFactorMethodRemoveEmailTemplateId':
          instance.twoFactorMethodRemoveEmailTemplateId,
      'unverified': instance.unverified,
      'username': instance.username,
      'verificationEmailTemplateId': instance.verificationEmailTemplateId,
      'verificationStrategy':
          _$VerificationStrategyEnumMap[instance.verificationStrategy],
      'verifyEmail': instance.verifyEmail,
      'verifyEmailWhenChanged': instance.verifyEmailWhenChanged,
    };

const _$EmailSecurityTypeEnumMap = {
  EmailSecurityType.NONE: 'NONE',
  EmailSecurityType.SSL: 'SSL',
  EmailSecurityType.TLS: 'TLS',
};

EmailHeader _$EmailHeaderFromJson(Map<String, dynamic> json) => EmailHeader(
      name: json['name'] as String,
      value: json['value'] as String,
    );

Map<String, dynamic> _$EmailHeaderToJson(EmailHeader instance) =>
    <String, dynamic>{
      'name': instance.name,
      'value': instance.value,
    };

EmailPlus _$EmailPlusFromJson(Map<String, dynamic> json) => EmailPlus(
      emailTemplateId: json['emailTemplateId'] as String,
      maximumTimeToSendEmailInHours:
          json['maximumTimeToSendEmailInHours'] as num,
      minimumTimeToSendEmailInHours:
          json['minimumTimeToSendEmailInHours'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$EmailPlusToJson(EmailPlus instance) => <String, dynamic>{
      'enabled': instance.enabled,
      'emailTemplateId': instance.emailTemplateId,
      'maximumTimeToSendEmailInHours': instance.maximumTimeToSendEmailInHours,
      'minimumTimeToSendEmailInHours': instance.minimumTimeToSendEmailInHours,
    };

EmailTemplate _$EmailTemplateFromJson(Map<String, dynamic> json) =>
    EmailTemplate(
      defaultFromName: json['defaultFromName'] as String,
      defaultHtmlTemplate: json['defaultHtmlTemplate'] as String,
      defaultSubject: json['defaultSubject'] as String,
      defaultTextTemplate: json['defaultTextTemplate'] as String,
      fromEmail: json['fromEmail'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      localizedFromNames:
          Map<String, String>.from(json['localizedFromNames'] as Map),
      localizedHtmlTemplates:
          Map<String, String>.from(json['localizedHtmlTemplates'] as Map),
      localizedSubjects:
          Map<String, String>.from(json['localizedSubjects'] as Map),
      localizedTextTemplates:
          Map<String, String>.from(json['localizedTextTemplates'] as Map),
      name: json['name'] as String,
    );

Map<String, dynamic> _$EmailTemplateToJson(EmailTemplate instance) =>
    <String, dynamic>{
      'defaultFromName': instance.defaultFromName,
      'defaultHtmlTemplate': instance.defaultHtmlTemplate,
      'defaultSubject': instance.defaultSubject,
      'defaultTextTemplate': instance.defaultTextTemplate,
      'fromEmail': instance.fromEmail,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'localizedFromNames': instance.localizedFromNames,
      'localizedHtmlTemplates': instance.localizedHtmlTemplates,
      'localizedSubjects': instance.localizedSubjects,
      'localizedTextTemplates': instance.localizedTextTemplates,
      'name': instance.name,
    };

EmailTemplateErrors _$EmailTemplateErrorsFromJson(Map<String, dynamic> json) =>
    EmailTemplateErrors(
      parseErrors: Map<String, String>.from(json['parseErrors'] as Map),
      renderErrors: Map<String, String>.from(json['renderErrors'] as Map),
    );

Map<String, dynamic> _$EmailTemplateErrorsToJson(
        EmailTemplateErrors instance) =>
    <String, dynamic>{
      'parseErrors': instance.parseErrors,
      'renderErrors': instance.renderErrors,
    };

EmailTemplateRequest _$EmailTemplateRequestFromJson(
        Map<String, dynamic> json) =>
    EmailTemplateRequest(
      emailTemplate:
          EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EmailTemplateRequestToJson(
        EmailTemplateRequest instance) =>
    <String, dynamic>{
      'emailTemplate': instance.emailTemplate,
    };

EmailTemplateResponse _$EmailTemplateResponseFromJson(
        Map<String, dynamic> json) =>
    EmailTemplateResponse(
      emailTemplate:
          EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
      emailTemplates: (json['emailTemplates'] as List<dynamic>)
          .map((e) => EmailTemplate.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$EmailTemplateResponseToJson(
        EmailTemplateResponse instance) =>
    <String, dynamic>{
      'emailTemplate': instance.emailTemplate,
      'emailTemplates': instance.emailTemplates,
    };

EmailUnverifiedOptions _$EmailUnverifiedOptionsFromJson(
        Map<String, dynamic> json) =>
    EmailUnverifiedOptions(
      allowEmailChangeWhenGated: json['allowEmailChangeWhenGated'] as bool,
      behavior: _$enumDecode(_$UnverifiedBehaviorEnumMap, json['behavior']),
    );

Map<String, dynamic> _$EmailUnverifiedOptionsToJson(
        EmailUnverifiedOptions instance) =>
    <String, dynamic>{
      'allowEmailChangeWhenGated': instance.allowEmailChangeWhenGated,
      'behavior': _$UnverifiedBehaviorEnumMap[instance.behavior],
    };

Enableable _$EnableableFromJson(Map<String, dynamic> json) => Enableable(
      enabled: json['enabled'] as bool,
    );

Map<String, dynamic> _$EnableableToJson(Enableable instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
    };

Entity _$EntityFromJson(Map<String, dynamic> json) => Entity(
      clientId: json['clientId'] as String,
      clientSecret: json['clientSecret'] as String,
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      parentId: json['parentId'] as String,
      tenantId: json['tenantId'] as String,
      type: EntityType.fromJson(json['type'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityToJson(Entity instance) => <String, dynamic>{
      'clientId': instance.clientId,
      'clientSecret': instance.clientSecret,
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'parentId': instance.parentId,
      'tenantId': instance.tenantId,
      'type': instance.type,
    };

EntityGrant _$EntityGrantFromJson(Map<String, dynamic> json) => EntityGrant(
      data: json['data'] as Map<String, dynamic>,
      entity: Entity.fromJson(json['entity'] as Map<String, dynamic>),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      permissions: (json['permissions'] as List<dynamic>)
          .map((e) => e as String)
          .toSet(),
      recipientEntityId: json['recipientEntityId'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$EntityGrantToJson(EntityGrant instance) =>
    <String, dynamic>{
      'data': instance.data,
      'entity': instance.entity,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'permissions': instance.permissions.toList(),
      'recipientEntityId': instance.recipientEntityId,
      'userId': instance.userId,
    };

EntityGrantRequest _$EntityGrantRequestFromJson(Map<String, dynamic> json) =>
    EntityGrantRequest(
      grant: EntityGrant.fromJson(json['grant'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityGrantRequestToJson(EntityGrantRequest instance) =>
    <String, dynamic>{
      'grant': instance.grant,
    };

EntityGrantResponse _$EntityGrantResponseFromJson(Map<String, dynamic> json) =>
    EntityGrantResponse(
      grant: EntityGrant.fromJson(json['grant'] as Map<String, dynamic>),
      grants: (json['grants'] as List<dynamic>)
          .map((e) => EntityGrant.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$EntityGrantResponseToJson(
        EntityGrantResponse instance) =>
    <String, dynamic>{
      'grant': instance.grant,
      'grants': instance.grants,
    };

EntityGrantSearchCriteria _$EntityGrantSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    EntityGrantSearchCriteria(
      entityId: json['entityId'] as String,
      name: json['name'] as String,
      userId: json['userId'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$EntityGrantSearchCriteriaToJson(
        EntityGrantSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'entityId': instance.entityId,
      'name': instance.name,
      'userId': instance.userId,
    };

EntityGrantSearchRequest _$EntityGrantSearchRequestFromJson(
        Map<String, dynamic> json) =>
    EntityGrantSearchRequest(
      search: EntityGrantSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityGrantSearchRequestToJson(
        EntityGrantSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

EntityGrantSearchResponse _$EntityGrantSearchResponseFromJson(
        Map<String, dynamic> json) =>
    EntityGrantSearchResponse(
      grants: (json['grants'] as List<dynamic>)
          .map((e) => EntityGrant.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$EntityGrantSearchResponseToJson(
        EntityGrantSearchResponse instance) =>
    <String, dynamic>{
      'grants': instance.grants,
      'total': instance.total,
    };

EntityJWTConfiguration _$EntityJWTConfigurationFromJson(
        Map<String, dynamic> json) =>
    EntityJWTConfiguration(
      accessTokenKeyId: json['accessTokenKeyId'] as String,
      timeToLiveInSeconds: json['timeToLiveInSeconds'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$EntityJWTConfigurationToJson(
        EntityJWTConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'accessTokenKeyId': instance.accessTokenKeyId,
      'timeToLiveInSeconds': instance.timeToLiveInSeconds,
    };

EntityRequest _$EntityRequestFromJson(Map<String, dynamic> json) =>
    EntityRequest(
      entity: Entity.fromJson(json['entity'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityRequestToJson(EntityRequest instance) =>
    <String, dynamic>{
      'entity': instance.entity,
    };

EntityResponse _$EntityResponseFromJson(Map<String, dynamic> json) =>
    EntityResponse(
      entity: Entity.fromJson(json['entity'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityResponseToJson(EntityResponse instance) =>
    <String, dynamic>{
      'entity': instance.entity,
    };

EntitySearchCriteria _$EntitySearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    EntitySearchCriteria()
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num
      ..accurateTotal = json['accurateTotal'] as bool
      ..ids = (json['ids'] as List<dynamic>).map((e) => e as String).toList()
      ..query = json['query'] as String
      ..queryString = json['queryString'] as String
      ..sortFields = (json['sortFields'] as List<dynamic>)
          .map((e) => SortField.fromJson(e as Map<String, dynamic>))
          .toList();

Map<String, dynamic> _$EntitySearchCriteriaToJson(
        EntitySearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'accurateTotal': instance.accurateTotal,
      'ids': instance.ids,
      'query': instance.query,
      'queryString': instance.queryString,
      'sortFields': instance.sortFields,
    };

EntitySearchRequest _$EntitySearchRequestFromJson(Map<String, dynamic> json) =>
    EntitySearchRequest(
      search:
          EntitySearchCriteria.fromJson(json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntitySearchRequestToJson(
        EntitySearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

EntitySearchResponse _$EntitySearchResponseFromJson(
        Map<String, dynamic> json) =>
    EntitySearchResponse(
      entities: (json['entities'] as List<dynamic>)
          .map((e) => Entity.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$EntitySearchResponseToJson(
        EntitySearchResponse instance) =>
    <String, dynamic>{
      'entities': instance.entities,
      'total': instance.total,
    };

EntityType _$EntityTypeFromJson(Map<String, dynamic> json) => EntityType(
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      jwtConfiguration: EntityJWTConfiguration.fromJson(
          json['jwtConfiguration'] as Map<String, dynamic>),
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      permissions: (json['permissions'] as List<dynamic>)
          .map((e) => EntityTypePermission.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$EntityTypeToJson(EntityType instance) =>
    <String, dynamic>{
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'jwtConfiguration': instance.jwtConfiguration,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'permissions': instance.permissions,
    };

EntityTypePermission _$EntityTypePermissionFromJson(
        Map<String, dynamic> json) =>
    EntityTypePermission(
      data: json['data'] as Map<String, dynamic>,
      description: json['description'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      isDefault: json['isDefault'] as bool,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
    );

Map<String, dynamic> _$EntityTypePermissionToJson(
        EntityTypePermission instance) =>
    <String, dynamic>{
      'data': instance.data,
      'description': instance.description,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'isDefault': instance.isDefault,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
    };

EntityTypeRequest _$EntityTypeRequestFromJson(Map<String, dynamic> json) =>
    EntityTypeRequest(
      entityType:
          EntityType.fromJson(json['entityType'] as Map<String, dynamic>),
      permission: EntityTypePermission.fromJson(
          json['permission'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityTypeRequestToJson(EntityTypeRequest instance) =>
    <String, dynamic>{
      'entityType': instance.entityType,
      'permission': instance.permission,
    };

EntityTypeResponse _$EntityTypeResponseFromJson(Map<String, dynamic> json) =>
    EntityTypeResponse(
      entityType:
          EntityType.fromJson(json['entityType'] as Map<String, dynamic>),
      entityTypes: (json['entityTypes'] as List<dynamic>)
          .map((e) => EntityType.fromJson(e as Map<String, dynamic>))
          .toList(),
      permission: EntityTypePermission.fromJson(
          json['permission'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityTypeResponseToJson(EntityTypeResponse instance) =>
    <String, dynamic>{
      'entityType': instance.entityType,
      'entityTypes': instance.entityTypes,
      'permission': instance.permission,
    };

EntityTypeSearchCriteria _$EntityTypeSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    EntityTypeSearchCriteria(
      name: json['name'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$EntityTypeSearchCriteriaToJson(
        EntityTypeSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'name': instance.name,
    };

EntityTypeSearchRequest _$EntityTypeSearchRequestFromJson(
        Map<String, dynamic> json) =>
    EntityTypeSearchRequest(
      search: EntityTypeSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EntityTypeSearchRequestToJson(
        EntityTypeSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

EntityTypeSearchResponse _$EntityTypeSearchResponseFromJson(
        Map<String, dynamic> json) =>
    EntityTypeSearchResponse(
      entityTypes: (json['entityTypes'] as List<dynamic>)
          .map((e) => EntityType.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$EntityTypeSearchResponseToJson(
        EntityTypeSearchResponse instance) =>
    <String, dynamic>{
      'entityTypes': instance.entityTypes,
      'total': instance.total,
    };

EpicGamesApplicationConfiguration _$EpicGamesApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    EpicGamesApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$EpicGamesApplicationConfigurationToJson(
        EpicGamesApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'scope': instance.scope,
    };

EpicGamesIdentityProvider _$EpicGamesIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    EpicGamesIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            EpicGamesApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$EpicGamesIdentityProviderToJson(
    EpicGamesIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['scope'] = instance.scope;
  return val;
}

Error _$ErrorFromJson(Map<String, dynamic> json) => Error(
      code: json['code'] as String,
      data: json['data'] as Map<String, dynamic>,
      message: json['message'] as String,
    );

Map<String, dynamic> _$ErrorToJson(Error instance) => <String, dynamic>{
      'code': instance.code,
      'data': instance.data,
      'message': instance.message,
    };

Errors _$ErrorsFromJson(Map<String, dynamic> json) => Errors(
      fieldErrors: (json['fieldErrors'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List<dynamic>)
                .map((e) => Error.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
      generalErrors: (json['generalErrors'] as List<dynamic>)
          .map((e) => Error.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$ErrorsToJson(Errors instance) => <String, dynamic>{
      'fieldErrors': instance.fieldErrors,
      'generalErrors': instance.generalErrors,
    };

EventConfiguration _$EventConfigurationFromJson(Map<String, dynamic> json) =>
    EventConfiguration(
      events: (json['events'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(_$enumDecode(_$EventTypeEnumMap, k),
            EventConfigurationData.fromJson(e as Map<String, dynamic>)),
      ),
    );

Map<String, dynamic> _$EventConfigurationToJson(EventConfiguration instance) =>
    <String, dynamic>{
      'events':
          instance.events.map((k, e) => MapEntry(_$EventTypeEnumMap[k], e)),
    };

EventConfigurationData _$EventConfigurationDataFromJson(
        Map<String, dynamic> json) =>
    EventConfigurationData(
      transactionType:
          _$enumDecode(_$TransactionTypeEnumMap, json['transactionType']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$EventConfigurationDataToJson(
        EventConfigurationData instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'transactionType': _$TransactionTypeEnumMap[instance.transactionType],
    };

const _$TransactionTypeEnumMap = {
  TransactionType.None: 'None',
  TransactionType.Any: 'Any',
  TransactionType.SimpleMajority: 'SimpleMajority',
  TransactionType.SuperMajority: 'SuperMajority',
  TransactionType.AbsoluteMajority: 'AbsoluteMajority',
};

EventInfo _$EventInfoFromJson(Map<String, dynamic> json) => EventInfo(
      data: json['data'] as Map<String, dynamic>,
      deviceDescription: json['deviceDescription'] as String,
      deviceName: json['deviceName'] as String,
      deviceType: json['deviceType'] as String,
      ipAddress: json['ipAddress'] as String,
      location: Location.fromJson(json['location'] as Map<String, dynamic>),
      os: json['os'] as String,
      userAgent: json['userAgent'] as String,
    );

Map<String, dynamic> _$EventInfoToJson(EventInfo instance) => <String, dynamic>{
      'data': instance.data,
      'deviceDescription': instance.deviceDescription,
      'deviceName': instance.deviceName,
      'deviceType': instance.deviceType,
      'ipAddress': instance.ipAddress,
      'location': instance.location,
      'os': instance.os,
      'userAgent': instance.userAgent,
    };

EventLog _$EventLogFromJson(Map<String, dynamic> json) => EventLog(
      id: json['id'] as num,
      insertInstant: json['insertInstant'] as num,
      message: json['message'] as String,
      type: _$enumDecode(_$EventLogTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$EventLogToJson(EventLog instance) => <String, dynamic>{
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'message': instance.message,
      'type': _$EventLogTypeEnumMap[instance.type],
    };

const _$EventLogTypeEnumMap = {
  EventLogType.Information: 'Information',
  EventLogType.Debug: 'Debug',
  EventLogType.Error: 'Error',
};

EventLogConfiguration _$EventLogConfigurationFromJson(
        Map<String, dynamic> json) =>
    EventLogConfiguration(
      numberToRetain: json['numberToRetain'] as num,
    );

Map<String, dynamic> _$EventLogConfigurationToJson(
        EventLogConfiguration instance) =>
    <String, dynamic>{
      'numberToRetain': instance.numberToRetain,
    };

EventLogCreateEvent _$EventLogCreateEventFromJson(Map<String, dynamic> json) =>
    EventLogCreateEvent(
      eventLog: EventLog.fromJson(json['eventLog'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$EventLogCreateEventToJson(
        EventLogCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'eventLog': instance.eventLog,
    };

EventLogResponse _$EventLogResponseFromJson(Map<String, dynamic> json) =>
    EventLogResponse(
      eventLog: EventLog.fromJson(json['eventLog'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EventLogResponseToJson(EventLogResponse instance) =>
    <String, dynamic>{
      'eventLog': instance.eventLog,
    };

EventLogSearchCriteria _$EventLogSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    EventLogSearchCriteria(
      end: json['end'] as num,
      message: json['message'] as String,
      start: json['start'] as num,
      type: _$enumDecode(_$EventLogTypeEnumMap, json['type']),
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$EventLogSearchCriteriaToJson(
        EventLogSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'end': instance.end,
      'message': instance.message,
      'start': instance.start,
      'type': _$EventLogTypeEnumMap[instance.type],
    };

EventLogSearchRequest _$EventLogSearchRequestFromJson(
        Map<String, dynamic> json) =>
    EventLogSearchRequest(
      search: EventLogSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EventLogSearchRequestToJson(
        EventLogSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

EventLogSearchResponse _$EventLogSearchResponseFromJson(
        Map<String, dynamic> json) =>
    EventLogSearchResponse(
      eventLogs: (json['eventLogs'] as List<dynamic>)
          .map((e) => EventLog.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$EventLogSearchResponseToJson(
        EventLogSearchResponse instance) =>
    <String, dynamic>{
      'eventLogs': instance.eventLogs,
      'total': instance.total,
    };

EventRequest _$EventRequestFromJson(Map<String, dynamic> json) => EventRequest(
      event: BaseEvent.fromJson(json['event'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$EventRequestToJson(EventRequest instance) =>
    <String, dynamic>{
      'event': instance.event,
    };

ExternalIdentifierConfiguration _$ExternalIdentifierConfigurationFromJson(
        Map<String, dynamic> json) =>
    ExternalIdentifierConfiguration(
      authorizationGrantIdTimeToLiveInSeconds:
          json['authorizationGrantIdTimeToLiveInSeconds'] as num,
      changePasswordIdGenerator: SecureGeneratorConfiguration.fromJson(
          json['changePasswordIdGenerator'] as Map<String, dynamic>),
      changePasswordIdTimeToLiveInSeconds:
          json['changePasswordIdTimeToLiveInSeconds'] as num,
      deviceCodeTimeToLiveInSeconds:
          json['deviceCodeTimeToLiveInSeconds'] as num,
      deviceUserCodeIdGenerator: SecureGeneratorConfiguration.fromJson(
          json['deviceUserCodeIdGenerator'] as Map<String, dynamic>),
      emailVerificationIdGenerator: SecureGeneratorConfiguration.fromJson(
          json['emailVerificationIdGenerator'] as Map<String, dynamic>),
      emailVerificationIdTimeToLiveInSeconds:
          json['emailVerificationIdTimeToLiveInSeconds'] as num,
      emailVerificationOneTimeCodeGenerator:
          SecureGeneratorConfiguration.fromJson(
              json['emailVerificationOneTimeCodeGenerator']
                  as Map<String, dynamic>),
      externalAuthenticationIdTimeToLiveInSeconds:
          json['externalAuthenticationIdTimeToLiveInSeconds'] as num,
      oneTimePasswordTimeToLiveInSeconds:
          json['oneTimePasswordTimeToLiveInSeconds'] as num,
      passwordlessLoginGenerator: SecureGeneratorConfiguration.fromJson(
          json['passwordlessLoginGenerator'] as Map<String, dynamic>),
      passwordlessLoginTimeToLiveInSeconds:
          json['passwordlessLoginTimeToLiveInSeconds'] as num,
      pendingAccountLinkTimeToLiveInSeconds:
          json['pendingAccountLinkTimeToLiveInSeconds'] as num,
      registrationVerificationIdGenerator:
          SecureGeneratorConfiguration.fromJson(
              json['registrationVerificationIdGenerator']
                  as Map<String, dynamic>),
      registrationVerificationIdTimeToLiveInSeconds:
          json['registrationVerificationIdTimeToLiveInSeconds'] as num,
      registrationVerificationOneTimeCodeGenerator:
          SecureGeneratorConfiguration.fromJson(
              json['registrationVerificationOneTimeCodeGenerator']
                  as Map<String, dynamic>),
      samlv2AuthNRequestIdTimeToLiveInSeconds:
          json['samlv2AuthNRequestIdTimeToLiveInSeconds'] as num,
      setupPasswordIdGenerator: SecureGeneratorConfiguration.fromJson(
          json['setupPasswordIdGenerator'] as Map<String, dynamic>),
      setupPasswordIdTimeToLiveInSeconds:
          json['setupPasswordIdTimeToLiveInSeconds'] as num,
      trustTokenTimeToLiveInSeconds:
          json['trustTokenTimeToLiveInSeconds'] as num,
      twoFactorIdTimeToLiveInSeconds:
          json['twoFactorIdTimeToLiveInSeconds'] as num,
      twoFactorOneTimeCodeIdGenerator: SecureGeneratorConfiguration.fromJson(
          json['twoFactorOneTimeCodeIdGenerator'] as Map<String, dynamic>),
      twoFactorOneTimeCodeIdTimeToLiveInSeconds:
          json['twoFactorOneTimeCodeIdTimeToLiveInSeconds'] as num,
      twoFactorTrustIdTimeToLiveInSeconds:
          json['twoFactorTrustIdTimeToLiveInSeconds'] as num,
    );

Map<String, dynamic> _$ExternalIdentifierConfigurationToJson(
        ExternalIdentifierConfiguration instance) =>
    <String, dynamic>{
      'authorizationGrantIdTimeToLiveInSeconds':
          instance.authorizationGrantIdTimeToLiveInSeconds,
      'changePasswordIdGenerator': instance.changePasswordIdGenerator,
      'changePasswordIdTimeToLiveInSeconds':
          instance.changePasswordIdTimeToLiveInSeconds,
      'deviceCodeTimeToLiveInSeconds': instance.deviceCodeTimeToLiveInSeconds,
      'deviceUserCodeIdGenerator': instance.deviceUserCodeIdGenerator,
      'emailVerificationIdGenerator': instance.emailVerificationIdGenerator,
      'emailVerificationIdTimeToLiveInSeconds':
          instance.emailVerificationIdTimeToLiveInSeconds,
      'emailVerificationOneTimeCodeGenerator':
          instance.emailVerificationOneTimeCodeGenerator,
      'externalAuthenticationIdTimeToLiveInSeconds':
          instance.externalAuthenticationIdTimeToLiveInSeconds,
      'oneTimePasswordTimeToLiveInSeconds':
          instance.oneTimePasswordTimeToLiveInSeconds,
      'passwordlessLoginGenerator': instance.passwordlessLoginGenerator,
      'passwordlessLoginTimeToLiveInSeconds':
          instance.passwordlessLoginTimeToLiveInSeconds,
      'pendingAccountLinkTimeToLiveInSeconds':
          instance.pendingAccountLinkTimeToLiveInSeconds,
      'registrationVerificationIdGenerator':
          instance.registrationVerificationIdGenerator,
      'registrationVerificationIdTimeToLiveInSeconds':
          instance.registrationVerificationIdTimeToLiveInSeconds,
      'registrationVerificationOneTimeCodeGenerator':
          instance.registrationVerificationOneTimeCodeGenerator,
      'samlv2AuthNRequestIdTimeToLiveInSeconds':
          instance.samlv2AuthNRequestIdTimeToLiveInSeconds,
      'setupPasswordIdGenerator': instance.setupPasswordIdGenerator,
      'setupPasswordIdTimeToLiveInSeconds':
          instance.setupPasswordIdTimeToLiveInSeconds,
      'trustTokenTimeToLiveInSeconds': instance.trustTokenTimeToLiveInSeconds,
      'twoFactorIdTimeToLiveInSeconds': instance.twoFactorIdTimeToLiveInSeconds,
      'twoFactorOneTimeCodeIdGenerator':
          instance.twoFactorOneTimeCodeIdGenerator,
      'twoFactorOneTimeCodeIdTimeToLiveInSeconds':
          instance.twoFactorOneTimeCodeIdTimeToLiveInSeconds,
      'twoFactorTrustIdTimeToLiveInSeconds':
          instance.twoFactorTrustIdTimeToLiveInSeconds,
    };

ExternalJWTApplicationConfiguration
    _$ExternalJWTApplicationConfigurationFromJson(Map<String, dynamic> json) =>
        ExternalJWTApplicationConfiguration()
          ..enabled = json['enabled'] as bool
          ..createRegistration = json['createRegistration'] as bool
          ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$ExternalJWTApplicationConfigurationToJson(
        ExternalJWTApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
    };

ExternalJWTIdentityProvider _$ExternalJWTIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    ExternalJWTIdentityProvider(
      claimMap: Map<String, String>.from(json['claimMap'] as Map),
      defaultKeyId: json['defaultKeyId'] as String,
      domains:
          (json['domains'] as List<dynamic>).map((e) => e as String).toSet(),
      headerKeyParameter: json['headerKeyParameter'] as String,
      oauth2: IdentityProviderOauth2Configuration.fromJson(
          json['oauth2'] as Map<String, dynamic>),
      uniqueIdentityClaim: json['uniqueIdentityClaim'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            ExternalJWTApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$ExternalJWTIdentityProviderToJson(
    ExternalJWTIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['claimMap'] = instance.claimMap;
  val['defaultKeyId'] = instance.defaultKeyId;
  val['domains'] = instance.domains.toList();
  val['headerKeyParameter'] = instance.headerKeyParameter;
  val['oauth2'] = instance.oauth2;
  val['uniqueIdentityClaim'] = instance.uniqueIdentityClaim;
  return val;
}

FacebookApplicationConfiguration _$FacebookApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    FacebookApplicationConfiguration(
      appId: json['appId'] as String,
      buttonText: json['buttonText'] as String,
      client_secret: json['client_secret'] as String,
      fields: json['fields'] as String,
      loginMethod: _$enumDecode(
          _$IdentityProviderLoginMethodEnumMap, json['loginMethod']),
      permissions: json['permissions'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$FacebookApplicationConfigurationToJson(
        FacebookApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'appId': instance.appId,
      'buttonText': instance.buttonText,
      'client_secret': instance.client_secret,
      'fields': instance.fields,
      'loginMethod': _$IdentityProviderLoginMethodEnumMap[instance.loginMethod],
      'permissions': instance.permissions,
    };

const _$IdentityProviderLoginMethodEnumMap = {
  IdentityProviderLoginMethod.UsePopup: 'UsePopup',
  IdentityProviderLoginMethod.UseRedirect: 'UseRedirect',
};

FacebookIdentityProvider _$FacebookIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    FacebookIdentityProvider(
      appId: json['appId'] as String,
      buttonText: json['buttonText'] as String,
      client_secret: json['client_secret'] as String,
      fields: json['fields'] as String,
      loginMethod: _$enumDecode(
          _$IdentityProviderLoginMethodEnumMap, json['loginMethod']),
      permissions: json['permissions'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            FacebookApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$FacebookIdentityProviderToJson(
    FacebookIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['appId'] = instance.appId;
  val['buttonText'] = instance.buttonText;
  val['client_secret'] = instance.client_secret;
  val['fields'] = instance.fields;
  val['loginMethod'] =
      _$IdentityProviderLoginMethodEnumMap[instance.loginMethod];
  val['permissions'] = instance.permissions;
  return val;
}

FailedAuthenticationConfiguration _$FailedAuthenticationConfigurationFromJson(
        Map<String, dynamic> json) =>
    FailedAuthenticationConfiguration(
      actionDuration: json['actionDuration'] as num,
      actionDurationUnit:
          _$enumDecode(_$ExpiryUnitEnumMap, json['actionDurationUnit']),
      resetCountInSeconds: json['resetCountInSeconds'] as num,
      tooManyAttempts: json['tooManyAttempts'] as num,
      userActionId: json['userActionId'] as String,
    );

Map<String, dynamic> _$FailedAuthenticationConfigurationToJson(
        FailedAuthenticationConfiguration instance) =>
    <String, dynamic>{
      'actionDuration': instance.actionDuration,
      'actionDurationUnit': _$ExpiryUnitEnumMap[instance.actionDurationUnit],
      'resetCountInSeconds': instance.resetCountInSeconds,
      'tooManyAttempts': instance.tooManyAttempts,
      'userActionId': instance.userActionId,
    };

const _$ExpiryUnitEnumMap = {
  ExpiryUnit.MINUTES: 'MINUTES',
  ExpiryUnit.HOURS: 'HOURS',
  ExpiryUnit.DAYS: 'DAYS',
  ExpiryUnit.WEEKS: 'WEEKS',
  ExpiryUnit.MONTHS: 'MONTHS',
  ExpiryUnit.YEARS: 'YEARS',
};

Family _$FamilyFromJson(Map<String, dynamic> json) => Family(
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      members: (json['members'] as List<dynamic>)
          .map((e) => FamilyMember.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$FamilyToJson(Family instance) => <String, dynamic>{
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'members': instance.members,
    };

FamilyConfiguration _$FamilyConfigurationFromJson(Map<String, dynamic> json) =>
    FamilyConfiguration(
      allowChildRegistrations: json['allowChildRegistrations'] as bool,
      confirmChildEmailTemplateId:
          json['confirmChildEmailTemplateId'] as String,
      deleteOrphanedAccounts: json['deleteOrphanedAccounts'] as bool,
      deleteOrphanedAccountsDays: json['deleteOrphanedAccountsDays'] as num,
      familyRequestEmailTemplateId:
          json['familyRequestEmailTemplateId'] as String,
      maximumChildAge: json['maximumChildAge'] as num,
      minimumOwnerAge: json['minimumOwnerAge'] as num,
      parentEmailRequired: json['parentEmailRequired'] as bool,
      parentRegistrationEmailTemplateId:
          json['parentRegistrationEmailTemplateId'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$FamilyConfigurationToJson(
        FamilyConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'allowChildRegistrations': instance.allowChildRegistrations,
      'confirmChildEmailTemplateId': instance.confirmChildEmailTemplateId,
      'deleteOrphanedAccounts': instance.deleteOrphanedAccounts,
      'deleteOrphanedAccountsDays': instance.deleteOrphanedAccountsDays,
      'familyRequestEmailTemplateId': instance.familyRequestEmailTemplateId,
      'maximumChildAge': instance.maximumChildAge,
      'minimumOwnerAge': instance.minimumOwnerAge,
      'parentEmailRequired': instance.parentEmailRequired,
      'parentRegistrationEmailTemplateId':
          instance.parentRegistrationEmailTemplateId,
    };

FamilyEmailRequest _$FamilyEmailRequestFromJson(Map<String, dynamic> json) =>
    FamilyEmailRequest(
      parentEmail: json['parentEmail'] as String,
    );

Map<String, dynamic> _$FamilyEmailRequestToJson(FamilyEmailRequest instance) =>
    <String, dynamic>{
      'parentEmail': instance.parentEmail,
    };

FamilyMember _$FamilyMemberFromJson(Map<String, dynamic> json) => FamilyMember(
      data: json['data'] as Map<String, dynamic>,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      owner: json['owner'] as bool,
      role: _$enumDecode(_$FamilyRoleEnumMap, json['role']),
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$FamilyMemberToJson(FamilyMember instance) =>
    <String, dynamic>{
      'data': instance.data,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'owner': instance.owner,
      'role': _$FamilyRoleEnumMap[instance.role],
      'userId': instance.userId,
    };

const _$FamilyRoleEnumMap = {
  FamilyRole.Child: 'Child',
  FamilyRole.Teen: 'Teen',
  FamilyRole.Adult: 'Adult',
};

FamilyRequest _$FamilyRequestFromJson(Map<String, dynamic> json) =>
    FamilyRequest(
      familyMember:
          FamilyMember.fromJson(json['familyMember'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$FamilyRequestToJson(FamilyRequest instance) =>
    <String, dynamic>{
      'familyMember': instance.familyMember,
    };

FamilyResponse _$FamilyResponseFromJson(Map<String, dynamic> json) =>
    FamilyResponse(
      families: (json['families'] as List<dynamic>)
          .map((e) => Family.fromJson(e as Map<String, dynamic>))
          .toList(),
      family: Family.fromJson(json['family'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$FamilyResponseToJson(FamilyResponse instance) =>
    <String, dynamic>{
      'families': instance.families,
      'family': instance.family,
    };

ForgotPasswordRequest _$ForgotPasswordRequestFromJson(
        Map<String, dynamic> json) =>
    ForgotPasswordRequest(
      applicationId: json['applicationId'] as String,
      changePasswordId: json['changePasswordId'] as String,
      email: json['email'] as String,
      loginId: json['loginId'] as String,
      sendForgotPasswordEmail: json['sendForgotPasswordEmail'] as bool,
      state: json['state'] as Map<String, dynamic>,
      username: json['username'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$ForgotPasswordRequestToJson(
        ForgotPasswordRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'changePasswordId': instance.changePasswordId,
      'email': instance.email,
      'loginId': instance.loginId,
      'sendForgotPasswordEmail': instance.sendForgotPasswordEmail,
      'state': instance.state,
      'username': instance.username,
    };

ForgotPasswordResponse _$ForgotPasswordResponseFromJson(
        Map<String, dynamic> json) =>
    ForgotPasswordResponse(
      changePasswordId: json['changePasswordId'] as String,
    );

Map<String, dynamic> _$ForgotPasswordResponseToJson(
        ForgotPasswordResponse instance) =>
    <String, dynamic>{
      'changePasswordId': instance.changePasswordId,
    };

Form _$FormFromJson(Map<String, dynamic> json) => Form(
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      steps: (json['steps'] as List<dynamic>)
          .map((e) => FormStep.fromJson(e as Map<String, dynamic>))
          .toList(),
      type: _$enumDecode(_$FormTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$FormToJson(Form instance) => <String, dynamic>{
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'steps': instance.steps,
      'type': _$FormTypeEnumMap[instance.type],
    };

const _$FormTypeEnumMap = {
  FormType.registration: 'registration',
  FormType.adminRegistration: 'adminRegistration',
  FormType.adminUser: 'adminUser',
  FormType.selfServiceUser: 'selfServiceUser',
};

FormField _$FormFieldFromJson(Map<String, dynamic> json) => FormField(
      confirm: json['confirm'] as bool,
      consentId: json['consentId'] as String,
      control: _$enumDecode(_$FormControlEnumMap, json['control']),
      data: json['data'] as Map<String, dynamic>,
      description: json['description'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      key: json['key'] as String,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      options:
          (json['options'] as List<dynamic>).map((e) => e as String).toList(),
      required: json['required'] as bool,
      type: _$enumDecode(_$FormDataTypeEnumMap, json['type']),
      validator: FormFieldValidator.fromJson(
          json['validator'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$FormFieldToJson(FormField instance) => <String, dynamic>{
      'confirm': instance.confirm,
      'consentId': instance.consentId,
      'control': _$FormControlEnumMap[instance.control],
      'data': instance.data,
      'description': instance.description,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'key': instance.key,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'options': instance.options,
      'required': instance.required,
      'type': _$FormDataTypeEnumMap[instance.type],
      'validator': instance.validator,
    };

const _$FormControlEnumMap = {
  FormControl.checkbox: 'checkbox',
  FormControl.number: 'number',
  FormControl.password: 'password',
  FormControl.radio: 'radio',
  FormControl.select: 'select',
  FormControl.textarea: 'textarea',
  FormControl.text: 'text',
};

const _$FormDataTypeEnumMap = {
  FormDataType.bool: 'bool',
  FormDataType.consent: 'consent',
  FormDataType.date: 'date',
  FormDataType.email: 'email',
  FormDataType.number: 'number',
  FormDataType.string: 'string',
};

FormFieldRequest _$FormFieldRequestFromJson(Map<String, dynamic> json) =>
    FormFieldRequest(
      field: FormField.fromJson(json['field'] as Map<String, dynamic>),
      fields: (json['fields'] as List<dynamic>)
          .map((e) => FormField.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$FormFieldRequestToJson(FormFieldRequest instance) =>
    <String, dynamic>{
      'field': instance.field,
      'fields': instance.fields,
    };

FormFieldResponse _$FormFieldResponseFromJson(Map<String, dynamic> json) =>
    FormFieldResponse(
      field: FormField.fromJson(json['field'] as Map<String, dynamic>),
      fields: (json['fields'] as List<dynamic>)
          .map((e) => FormField.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$FormFieldResponseToJson(FormFieldResponse instance) =>
    <String, dynamic>{
      'field': instance.field,
      'fields': instance.fields,
    };

FormFieldValidator _$FormFieldValidatorFromJson(Map<String, dynamic> json) =>
    FormFieldValidator(
      expression: json['expression'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$FormFieldValidatorToJson(FormFieldValidator instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'expression': instance.expression,
    };

FormRequest _$FormRequestFromJson(Map<String, dynamic> json) => FormRequest(
      form: Form.fromJson(json['form'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$FormRequestToJson(FormRequest instance) =>
    <String, dynamic>{
      'form': instance.form,
    };

FormResponse _$FormResponseFromJson(Map<String, dynamic> json) => FormResponse(
      form: Form.fromJson(json['form'] as Map<String, dynamic>),
      forms: (json['forms'] as List<dynamic>)
          .map((e) => Form.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$FormResponseToJson(FormResponse instance) =>
    <String, dynamic>{
      'form': instance.form,
      'forms': instance.forms,
    };

FormStep _$FormStepFromJson(Map<String, dynamic> json) => FormStep(
      fields:
          (json['fields'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$FormStepToJson(FormStep instance) => <String, dynamic>{
      'fields': instance.fields,
    };

FusionAuthConnectorConfiguration _$FusionAuthConnectorConfigurationFromJson(
        Map<String, dynamic> json) =>
    FusionAuthConnectorConfiguration()
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..type = _$enumDecode(_$ConnectorTypeEnumMap, json['type']);

Map<String, dynamic> _$FusionAuthConnectorConfigurationToJson(
        FusionAuthConnectorConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$ConnectorTypeEnumMap[instance.type],
    };

GenericConnectorConfiguration _$GenericConnectorConfigurationFromJson(
        Map<String, dynamic> json) =>
    GenericConnectorConfiguration(
      authenticationURL: json['authenticationURL'] as String,
      connectTimeout: json['connectTimeout'] as num,
      headers: Map<String, String>.from(json['headers'] as Map),
      httpAuthenticationPassword: json['httpAuthenticationPassword'] as String,
      httpAuthenticationUsername: json['httpAuthenticationUsername'] as String,
      readTimeout: json['readTimeout'] as num,
      sslCertificateKeyId: json['sslCertificateKeyId'] as String,
    )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..type = _$enumDecode(_$ConnectorTypeEnumMap, json['type']);

Map<String, dynamic> _$GenericConnectorConfigurationToJson(
        GenericConnectorConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$ConnectorTypeEnumMap[instance.type],
      'authenticationURL': instance.authenticationURL,
      'connectTimeout': instance.connectTimeout,
      'headers': instance.headers,
      'httpAuthenticationPassword': instance.httpAuthenticationPassword,
      'httpAuthenticationUsername': instance.httpAuthenticationUsername,
      'readTimeout': instance.readTimeout,
      'sslCertificateKeyId': instance.sslCertificateKeyId,
    };

GenericMessengerConfiguration _$GenericMessengerConfigurationFromJson(
        Map<String, dynamic> json) =>
    GenericMessengerConfiguration(
      connectTimeout: json['connectTimeout'] as num,
      headers: Map<String, String>.from(json['headers'] as Map),
      httpAuthenticationPassword: json['httpAuthenticationPassword'] as String,
      httpAuthenticationUsername: json['httpAuthenticationUsername'] as String,
      readTimeout: json['readTimeout'] as num,
      sslCertificate: json['sslCertificate'] as String,
      url: json['url'] as String,
    )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..transport = json['transport'] as String
      ..type = _$enumDecode(_$MessengerTypeEnumMap, json['type']);

Map<String, dynamic> _$GenericMessengerConfigurationToJson(
        GenericMessengerConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'transport': instance.transport,
      'type': _$MessengerTypeEnumMap[instance.type],
      'connectTimeout': instance.connectTimeout,
      'headers': instance.headers,
      'httpAuthenticationPassword': instance.httpAuthenticationPassword,
      'httpAuthenticationUsername': instance.httpAuthenticationUsername,
      'readTimeout': instance.readTimeout,
      'sslCertificate': instance.sslCertificate,
      'url': instance.url,
    };

GoogleApplicationConfiguration _$GoogleApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    GoogleApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      loginMethod: _$enumDecode(
          _$IdentityProviderLoginMethodEnumMap, json['loginMethod']),
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$GoogleApplicationConfigurationToJson(
        GoogleApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'loginMethod': _$IdentityProviderLoginMethodEnumMap[instance.loginMethod],
      'scope': instance.scope,
    };

GoogleIdentityProvider _$GoogleIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    GoogleIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      loginMethod: _$enumDecode(
          _$IdentityProviderLoginMethodEnumMap, json['loginMethod']),
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            GoogleApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$GoogleIdentityProviderToJson(
    GoogleIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['loginMethod'] =
      _$IdentityProviderLoginMethodEnumMap[instance.loginMethod];
  val['scope'] = instance.scope;
  return val;
}

Group _$GroupFromJson(Map<String, dynamic> json) => Group(
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      roles: (json['roles'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List<dynamic>)
                .map((e) => ApplicationRole.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
      tenantId: json['tenantId'] as String,
    );

Map<String, dynamic> _$GroupToJson(Group instance) => <String, dynamic>{
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'roles': instance.roles,
      'tenantId': instance.tenantId,
    };

GroupMember _$GroupMemberFromJson(Map<String, dynamic> json) => GroupMember(
      data: json['data'] as Map<String, dynamic>,
      groupId: json['groupId'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$GroupMemberToJson(GroupMember instance) =>
    <String, dynamic>{
      'data': instance.data,
      'groupId': instance.groupId,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'user': instance.user,
      'userId': instance.userId,
    };

GroupMemberSearchCriteria _$GroupMemberSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    GroupMemberSearchCriteria(
      groupId: json['groupId'] as String,
      userId: json['userId'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$GroupMemberSearchCriteriaToJson(
        GroupMemberSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'groupId': instance.groupId,
      'userId': instance.userId,
    };

GroupMemberSearchRequest _$GroupMemberSearchRequestFromJson(
        Map<String, dynamic> json) =>
    GroupMemberSearchRequest(
      search: GroupMemberSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$GroupMemberSearchRequestToJson(
        GroupMemberSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

GroupMemberSearchResponse _$GroupMemberSearchResponseFromJson(
        Map<String, dynamic> json) =>
    GroupMemberSearchResponse(
      members: (json['members'] as List<dynamic>)
          .map((e) => GroupMember.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$GroupMemberSearchResponseToJson(
        GroupMemberSearchResponse instance) =>
    <String, dynamic>{
      'members': instance.members,
      'total': instance.total,
    };

GroupRequest _$GroupRequestFromJson(Map<String, dynamic> json) => GroupRequest(
      group: Group.fromJson(json['group'] as Map<String, dynamic>),
      roleIds:
          (json['roleIds'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$GroupRequestToJson(GroupRequest instance) =>
    <String, dynamic>{
      'group': instance.group,
      'roleIds': instance.roleIds,
    };

GroupResponse _$GroupResponseFromJson(Map<String, dynamic> json) =>
    GroupResponse(
      group: Group.fromJson(json['group'] as Map<String, dynamic>),
      groups: (json['groups'] as List<dynamic>)
          .map((e) => Group.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$GroupResponseToJson(GroupResponse instance) =>
    <String, dynamic>{
      'group': instance.group,
      'groups': instance.groups,
    };

HistoryItem _$HistoryItemFromJson(Map<String, dynamic> json) => HistoryItem(
      actionerUserId: json['actionerUserId'] as String,
      comment: json['comment'] as String,
      createInstant: json['createInstant'] as num,
      expiry: json['expiry'] as num,
    );

Map<String, dynamic> _$HistoryItemToJson(HistoryItem instance) =>
    <String, dynamic>{
      'actionerUserId': instance.actionerUserId,
      'comment': instance.comment,
      'createInstant': instance.createInstant,
      'expiry': instance.expiry,
    };

HYPRApplicationConfiguration _$HYPRApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    HYPRApplicationConfiguration(
      relyingPartyApplicationId: json['relyingPartyApplicationId'] as String,
      relyingPartyURL: json['relyingPartyURL'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$HYPRApplicationConfigurationToJson(
        HYPRApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'relyingPartyApplicationId': instance.relyingPartyApplicationId,
      'relyingPartyURL': instance.relyingPartyURL,
    };

HYPRIdentityProvider _$HYPRIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    HYPRIdentityProvider(
      relyingPartyApplicationId: json['relyingPartyApplicationId'] as String,
      relyingPartyURL: json['relyingPartyURL'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            HYPRApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$HYPRIdentityProviderToJson(
    HYPRIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['relyingPartyApplicationId'] = instance.relyingPartyApplicationId;
  val['relyingPartyURL'] = instance.relyingPartyURL;
  return val;
}

IdentityProviderDetails _$IdentityProviderDetailsFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderDetails(
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      id: json['id'] as String,
      idpEndpoint: json['idpEndpoint'] as String,
      name: json['name'] as String,
      oauth2: IdentityProviderOauth2Configuration.fromJson(
          json['oauth2'] as Map<String, dynamic>),
      type: _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$IdentityProviderDetailsToJson(
        IdentityProviderDetails instance) =>
    <String, dynamic>{
      'applicationIds': instance.applicationIds,
      'id': instance.id,
      'idpEndpoint': instance.idpEndpoint,
      'name': instance.name,
      'oauth2': instance.oauth2,
      'type': _$IdentityProviderTypeEnumMap[instance.type],
    };

IdentityProviderLimitUserLinkingPolicy
    _$IdentityProviderLimitUserLinkingPolicyFromJson(
            Map<String, dynamic> json) =>
        IdentityProviderLimitUserLinkingPolicy(
          maximumLinks: json['maximumLinks'] as num,
        )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$IdentityProviderLimitUserLinkingPolicyToJson(
        IdentityProviderLimitUserLinkingPolicy instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'maximumLinks': instance.maximumLinks,
    };

IdentityProviderLink _$IdentityProviderLinkFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderLink(
      data: json['data'] as Map<String, dynamic>,
      displayName: json['displayName'] as String,
      identityProviderId: json['identityProviderId'] as String,
      identityProviderUserId: json['identityProviderUserId'] as String,
      insertInstant: json['insertInstant'] as num,
      lastLoginInstant: json['lastLoginInstant'] as num,
      tenantId: json['tenantId'] as String,
      token: json['token'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$IdentityProviderLinkToJson(
        IdentityProviderLink instance) =>
    <String, dynamic>{
      'data': instance.data,
      'displayName': instance.displayName,
      'identityProviderId': instance.identityProviderId,
      'identityProviderUserId': instance.identityProviderUserId,
      'insertInstant': instance.insertInstant,
      'lastLoginInstant': instance.lastLoginInstant,
      'tenantId': instance.tenantId,
      'token': instance.token,
      'userId': instance.userId,
    };

IdentityProviderLinkRequest _$IdentityProviderLinkRequestFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderLinkRequest(
      displayName: json['displayName'] as String,
      identityProviderId: json['identityProviderId'] as String,
      identityProviderUserId: json['identityProviderUserId'] as String,
      pendingIdPLinkId: json['pendingIdPLinkId'] as String,
      userId: json['userId'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$IdentityProviderLinkRequestToJson(
        IdentityProviderLinkRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'displayName': instance.displayName,
      'identityProviderId': instance.identityProviderId,
      'identityProviderUserId': instance.identityProviderUserId,
      'pendingIdPLinkId': instance.pendingIdPLinkId,
      'userId': instance.userId,
    };

IdentityProviderLinkResponse _$IdentityProviderLinkResponseFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderLinkResponse(
      identityProviderLink: IdentityProviderLink.fromJson(
          json['identityProviderLink'] as Map<String, dynamic>),
      identityProviderLinks: (json['identityProviderLinks'] as List<dynamic>)
          .map((e) => IdentityProviderLink.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$IdentityProviderLinkResponseToJson(
        IdentityProviderLinkResponse instance) =>
    <String, dynamic>{
      'identityProviderLink': instance.identityProviderLink,
      'identityProviderLinks': instance.identityProviderLinks,
    };

IdentityProviderLoginRequest _$IdentityProviderLoginRequestFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderLoginRequest(
      data: Map<String, String>.from(json['data'] as Map),
      encodedJWT: json['encodedJWT'] as String,
      identityProviderId: json['identityProviderId'] as String,
      noLink: json['noLink'] as bool,
    )
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>)
      ..applicationId = json['applicationId'] as String
      ..ipAddress = json['ipAddress'] as String
      ..metaData = MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
      ..newDevice = json['newDevice'] as bool
      ..noJWT = json['noJWT'] as bool;

Map<String, dynamic> _$IdentityProviderLoginRequestToJson(
        IdentityProviderLoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
      'data': instance.data,
      'encodedJWT': instance.encodedJWT,
      'identityProviderId': instance.identityProviderId,
      'noLink': instance.noLink,
    };

IdentityProviderOauth2Configuration
    _$IdentityProviderOauth2ConfigurationFromJson(Map<String, dynamic> json) =>
        IdentityProviderOauth2Configuration(
          authorization_endpoint: json['authorization_endpoint'] as String,
          client_id: json['client_id'] as String,
          client_secret: json['client_secret'] as String,
          clientAuthenticationMethod: _$enumDecode(
              _$ClientAuthenticationMethodEnumMap,
              json['clientAuthenticationMethod']),
          emailClaim: json['emailClaim'] as String,
          issuer: json['issuer'] as String,
          scope: json['scope'] as String,
          token_endpoint: json['token_endpoint'] as String,
          uniqueIdClaim: json['uniqueIdClaim'] as String,
          userinfo_endpoint: json['userinfo_endpoint'] as String,
          usernameClaim: json['usernameClaim'] as String,
        );

Map<String, dynamic> _$IdentityProviderOauth2ConfigurationToJson(
        IdentityProviderOauth2Configuration instance) =>
    <String, dynamic>{
      'authorization_endpoint': instance.authorization_endpoint,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'clientAuthenticationMethod': _$ClientAuthenticationMethodEnumMap[
          instance.clientAuthenticationMethod],
      'emailClaim': instance.emailClaim,
      'issuer': instance.issuer,
      'scope': instance.scope,
      'token_endpoint': instance.token_endpoint,
      'uniqueIdClaim': instance.uniqueIdClaim,
      'userinfo_endpoint': instance.userinfo_endpoint,
      'usernameClaim': instance.usernameClaim,
    };

const _$ClientAuthenticationMethodEnumMap = {
  ClientAuthenticationMethod.none: 'none',
  ClientAuthenticationMethod.client_secret_basic: 'client_secret_basic',
  ClientAuthenticationMethod.client_secret_post: 'client_secret_post',
};

IdentityProviderRequest _$IdentityProviderRequestFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderRequest(
      identityProvider: BaseIdentityProvider<dynamic>.fromJson(
          json['identityProvider'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IdentityProviderRequestToJson(
        IdentityProviderRequest instance) =>
    <String, dynamic>{
      'identityProvider': instance.identityProvider,
    };

IdentityProviderResponse _$IdentityProviderResponseFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderResponse(
      identityProvider: BaseIdentityProvider<dynamic>.fromJson(
          json['identityProvider'] as Map<String, dynamic>),
      identityProviders: (json['identityProviders'] as List<dynamic>)
          .map((e) =>
              BaseIdentityProvider<dynamic>.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$IdentityProviderResponseToJson(
        IdentityProviderResponse instance) =>
    <String, dynamic>{
      'identityProvider': instance.identityProvider,
      'identityProviders': instance.identityProviders,
    };

IdentityProviderStartLoginRequest _$IdentityProviderStartLoginRequestFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderStartLoginRequest(
      data: Map<String, String>.from(json['data'] as Map),
      identityProviderId: json['identityProviderId'] as String,
      loginId: json['loginId'] as String,
      state: json['state'] as Map<String, dynamic>,
    )
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>)
      ..applicationId = json['applicationId'] as String
      ..ipAddress = json['ipAddress'] as String
      ..metaData = MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
      ..newDevice = json['newDevice'] as bool
      ..noJWT = json['noJWT'] as bool;

Map<String, dynamic> _$IdentityProviderStartLoginRequestToJson(
        IdentityProviderStartLoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
      'data': instance.data,
      'identityProviderId': instance.identityProviderId,
      'loginId': instance.loginId,
      'state': instance.state,
    };

IdentityProviderStartLoginResponse _$IdentityProviderStartLoginResponseFromJson(
        Map<String, dynamic> json) =>
    IdentityProviderStartLoginResponse(
      code: json['code'] as String,
    );

Map<String, dynamic> _$IdentityProviderStartLoginResponseToJson(
        IdentityProviderStartLoginResponse instance) =>
    <String, dynamic>{
      'code': instance.code,
    };

IdentityProviderTenantConfiguration
    _$IdentityProviderTenantConfigurationFromJson(Map<String, dynamic> json) =>
        IdentityProviderTenantConfiguration(
          data: json['data'] as Map<String, dynamic>,
          limitUserLinkCount: IdentityProviderLimitUserLinkingPolicy.fromJson(
              json['limitUserLinkCount'] as Map<String, dynamic>),
        );

Map<String, dynamic> _$IdentityProviderTenantConfigurationToJson(
        IdentityProviderTenantConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'limitUserLinkCount': instance.limitUserLinkCount,
    };

ImportRequest _$ImportRequestFromJson(Map<String, dynamic> json) =>
    ImportRequest(
      encryptionScheme: json['encryptionScheme'] as String,
      factor: json['factor'] as num,
      users: (json['users'] as List<dynamic>)
          .map((e) => User.fromJson(e as Map<String, dynamic>))
          .toList(),
      validateDbConstraints: json['validateDbConstraints'] as bool,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$ImportRequestToJson(ImportRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'encryptionScheme': instance.encryptionScheme,
      'factor': instance.factor,
      'users': instance.users,
      'validateDbConstraints': instance.validateDbConstraints,
    };

InstanceEvent _$InstanceEventFromJson(Map<String, dynamic> json) =>
    InstanceEvent();

Map<String, dynamic> _$InstanceEventToJson(InstanceEvent instance) =>
    <String, dynamic>{};

IntegrationRequest _$IntegrationRequestFromJson(Map<String, dynamic> json) =>
    IntegrationRequest(
      integrations:
          Integrations.fromJson(json['integrations'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IntegrationRequestToJson(IntegrationRequest instance) =>
    <String, dynamic>{
      'integrations': instance.integrations,
    };

IntegrationResponse _$IntegrationResponseFromJson(Map<String, dynamic> json) =>
    IntegrationResponse(
      integrations:
          Integrations.fromJson(json['integrations'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IntegrationResponseToJson(
        IntegrationResponse instance) =>
    <String, dynamic>{
      'integrations': instance.integrations,
    };

Integrations _$IntegrationsFromJson(Map<String, dynamic> json) => Integrations(
      cleanspeak: CleanSpeakConfiguration.fromJson(
          json['cleanspeak'] as Map<String, dynamic>),
      kafka: KafkaConfiguration.fromJson(json['kafka'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IntegrationsToJson(Integrations instance) =>
    <String, dynamic>{
      'cleanspeak': instance.cleanspeak,
      'kafka': instance.kafka,
    };

IPAccessControlEntry _$IPAccessControlEntryFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlEntry(
      action: _$enumDecode(_$IPAccessControlEntryActionEnumMap, json['action']),
      endIPAddress: json['endIPAddress'] as String,
      startIPAddress: json['startIPAddress'] as String,
    );

Map<String, dynamic> _$IPAccessControlEntryToJson(
        IPAccessControlEntry instance) =>
    <String, dynamic>{
      'action': _$IPAccessControlEntryActionEnumMap[instance.action],
      'endIPAddress': instance.endIPAddress,
      'startIPAddress': instance.startIPAddress,
    };

const _$IPAccessControlEntryActionEnumMap = {
  IPAccessControlEntryAction.Allow: 'Allow',
  IPAccessControlEntryAction.Block: 'Block',
};

IPAccessControlList _$IPAccessControlListFromJson(Map<String, dynamic> json) =>
    IPAccessControlList(
      data: json['data'] as Map<String, dynamic>,
      entries: (json['entries'] as List<dynamic>)
          .map((e) => IPAccessControlEntry.fromJson(e as Map<String, dynamic>))
          .toList(),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
    );

Map<String, dynamic> _$IPAccessControlListToJson(
        IPAccessControlList instance) =>
    <String, dynamic>{
      'data': instance.data,
      'entries': instance.entries,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
    };

IPAccessControlListRequest _$IPAccessControlListRequestFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlListRequest(
      ipAccessControlList: IPAccessControlList.fromJson(
          json['ipAccessControlList'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IPAccessControlListRequestToJson(
        IPAccessControlListRequest instance) =>
    <String, dynamic>{
      'ipAccessControlList': instance.ipAccessControlList,
    };

IPAccessControlListResponse _$IPAccessControlListResponseFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlListResponse(
      ipAccessControlList: IPAccessControlList.fromJson(
          json['ipAccessControlList'] as Map<String, dynamic>),
      ipAccessControlLists: (json['ipAccessControlLists'] as List<dynamic>)
          .map((e) => IPAccessControlList.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$IPAccessControlListResponseToJson(
        IPAccessControlListResponse instance) =>
    <String, dynamic>{
      'ipAccessControlList': instance.ipAccessControlList,
      'ipAccessControlLists': instance.ipAccessControlLists,
    };

IPAccessControlListSearchCriteria _$IPAccessControlListSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlListSearchCriteria(
      name: json['name'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$IPAccessControlListSearchCriteriaToJson(
        IPAccessControlListSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'name': instance.name,
    };

IPAccessControlListSearchRequest _$IPAccessControlListSearchRequestFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlListSearchRequest(
      search: IPAccessControlListSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$IPAccessControlListSearchRequestToJson(
        IPAccessControlListSearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

IPAccessControlListSearchResponse _$IPAccessControlListSearchResponseFromJson(
        Map<String, dynamic> json) =>
    IPAccessControlListSearchResponse(
      ipAccessControlLists: (json['ipAccessControlLists'] as List<dynamic>)
          .map((e) => IPAccessControlList.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$IPAccessControlListSearchResponseToJson(
        IPAccessControlListSearchResponse instance) =>
    <String, dynamic>{
      'ipAccessControlLists': instance.ipAccessControlLists,
      'total': instance.total,
    };

IssueResponse _$IssueResponseFromJson(Map<String, dynamic> json) =>
    IssueResponse(
      refreshToken: json['refreshToken'] as String,
      token: json['token'] as String,
    );

Map<String, dynamic> _$IssueResponseToJson(IssueResponse instance) =>
    <String, dynamic>{
      'refreshToken': instance.refreshToken,
      'token': instance.token,
    };

JSONWebKey _$JSONWebKeyFromJson(Map<String, dynamic> json) => JSONWebKey(
      alg: _$enumDecode(_$AlgorithmEnumMap, json['alg']),
      crv: json['crv'] as String,
      d: json['d'] as String,
      dp: json['dp'] as String,
      dq: json['dq'] as String,
      e: json['e'] as String,
      kid: json['kid'] as String,
      kty: _$enumDecode(_$KeyTypeEnumMap, json['kty']),
      n: json['n'] as String,
      p: json['p'] as String,
      q: json['q'] as String,
      qi: json['qi'] as String,
      use: json['use'] as String,
      x: json['x'] as String,
      x5c: (json['x5c'] as List<dynamic>).map((e) => e as String).toList(),
      x5t: json['x5t'] as String,
      x5t_S256: json['x5t#S256'] as String,
      y: json['y'] as String,
    );

Map<String, dynamic> _$JSONWebKeyToJson(JSONWebKey instance) =>
    <String, dynamic>{
      'alg': _$AlgorithmEnumMap[instance.alg],
      'crv': instance.crv,
      'd': instance.d,
      'dp': instance.dp,
      'dq': instance.dq,
      'e': instance.e,
      'kid': instance.kid,
      'kty': _$KeyTypeEnumMap[instance.kty],
      'n': instance.n,
      'p': instance.p,
      'q': instance.q,
      'qi': instance.qi,
      'use': instance.use,
      'x': instance.x,
      'x5c': instance.x5c,
      'x5t': instance.x5t,
      'x5t#S256': instance.x5t_S256,
      'y': instance.y,
    };

const _$AlgorithmEnumMap = {
  Algorithm.ES256: 'ES256',
  Algorithm.ES384: 'ES384',
  Algorithm.ES512: 'ES512',
  Algorithm.HS256: 'HS256',
  Algorithm.HS384: 'HS384',
  Algorithm.HS512: 'HS512',
  Algorithm.RS256: 'RS256',
  Algorithm.RS384: 'RS384',
  Algorithm.RS512: 'RS512',
  Algorithm.none: 'none',
};

const _$KeyTypeEnumMap = {
  KeyType.EC: 'EC',
  KeyType.RSA: 'RSA',
  KeyType.HMAC: 'HMAC',
};

JSONWebKeyInfoProvider _$JSONWebKeyInfoProviderFromJson(
        Map<String, dynamic> json) =>
    JSONWebKeyInfoProvider();

Map<String, dynamic> _$JSONWebKeyInfoProviderToJson(
        JSONWebKeyInfoProvider instance) =>
    <String, dynamic>{};

JWKSResponse _$JWKSResponseFromJson(Map<String, dynamic> json) => JWKSResponse(
      keys: (json['keys'] as List<dynamic>)
          .map((e) => JSONWebKey.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$JWKSResponseToJson(JWKSResponse instance) =>
    <String, dynamic>{
      'keys': instance.keys,
    };

JWT _$JWTFromJson(Map<String, dynamic> json) => JWT(
      aud: json['aud'],
      exp: json['exp'] as num,
      iat: json['iat'] as num,
      iss: json['iss'] as String,
      jti: json['jti'] as String,
      nbf: json['nbf'] as num,
      sub: json['sub'] as String,
    );

Map<String, dynamic> _$JWTToJson(JWT instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('aud', instance.aud);
  val['exp'] = instance.exp;
  val['iat'] = instance.iat;
  val['iss'] = instance.iss;
  val['jti'] = instance.jti;
  val['nbf'] = instance.nbf;
  val['sub'] = instance.sub;
  return val;
}

JWTConfiguration _$JWTConfigurationFromJson(Map<String, dynamic> json) =>
    JWTConfiguration(
      accessTokenKeyId: json['accessTokenKeyId'] as String,
      idTokenKeyId: json['idTokenKeyId'] as String,
      refreshTokenExpirationPolicy: _$enumDecode(
          _$RefreshTokenExpirationPolicyEnumMap,
          json['refreshTokenExpirationPolicy']),
      refreshTokenRevocationPolicy: RefreshTokenRevocationPolicy.fromJson(
          json['refreshTokenRevocationPolicy'] as Map<String, dynamic>),
      refreshTokenTimeToLiveInMinutes:
          json['refreshTokenTimeToLiveInMinutes'] as num,
      refreshTokenUsagePolicy: _$enumDecode(
          _$RefreshTokenUsagePolicyEnumMap, json['refreshTokenUsagePolicy']),
      timeToLiveInSeconds: json['timeToLiveInSeconds'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$JWTConfigurationToJson(JWTConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'accessTokenKeyId': instance.accessTokenKeyId,
      'idTokenKeyId': instance.idTokenKeyId,
      'refreshTokenExpirationPolicy': _$RefreshTokenExpirationPolicyEnumMap[
          instance.refreshTokenExpirationPolicy],
      'refreshTokenRevocationPolicy': instance.refreshTokenRevocationPolicy,
      'refreshTokenTimeToLiveInMinutes':
          instance.refreshTokenTimeToLiveInMinutes,
      'refreshTokenUsagePolicy':
          _$RefreshTokenUsagePolicyEnumMap[instance.refreshTokenUsagePolicy],
      'timeToLiveInSeconds': instance.timeToLiveInSeconds,
    };

const _$RefreshTokenExpirationPolicyEnumMap = {
  RefreshTokenExpirationPolicy.Fixed: 'Fixed',
  RefreshTokenExpirationPolicy.SlidingWindow: 'SlidingWindow',
};

const _$RefreshTokenUsagePolicyEnumMap = {
  RefreshTokenUsagePolicy.Reusable: 'Reusable',
  RefreshTokenUsagePolicy.OneTimeUse: 'OneTimeUse',
};

JWTPublicKeyUpdateEvent _$JWTPublicKeyUpdateEventFromJson(
        Map<String, dynamic> json) =>
    JWTPublicKeyUpdateEvent(
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toSet(),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$JWTPublicKeyUpdateEventToJson(
        JWTPublicKeyUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationIds': instance.applicationIds.toList(),
    };

JWTRefreshEvent _$JWTRefreshEventFromJson(Map<String, dynamic> json) =>
    JWTRefreshEvent(
      applicationId: json['applicationId'] as String,
      original: json['original'] as String,
      refreshToken: json['refreshToken'] as String,
      token: json['token'] as String,
      userId: json['userId'] as String,
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$JWTRefreshEventToJson(JWTRefreshEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'original': instance.original,
      'refreshToken': instance.refreshToken,
      'token': instance.token,
      'userId': instance.userId,
    };

JWTRefreshResponse _$JWTRefreshResponseFromJson(Map<String, dynamic> json) =>
    JWTRefreshResponse(
      refreshToken: json['refreshToken'] as String,
      token: json['token'] as String,
    );

Map<String, dynamic> _$JWTRefreshResponseToJson(JWTRefreshResponse instance) =>
    <String, dynamic>{
      'refreshToken': instance.refreshToken,
      'token': instance.token,
    };

JWTRefreshTokenRevokeEvent _$JWTRefreshTokenRevokeEventFromJson(
        Map<String, dynamic> json) =>
    JWTRefreshTokenRevokeEvent(
      applicationId: json['applicationId'] as String,
      applicationTimeToLiveInSeconds:
          Map<String, num>.from(json['applicationTimeToLiveInSeconds'] as Map),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
      userId: json['userId'] as String,
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$JWTRefreshTokenRevokeEventToJson(
        JWTRefreshTokenRevokeEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'applicationTimeToLiveInSeconds': instance.applicationTimeToLiveInSeconds,
      'user': instance.user,
      'userId': instance.userId,
    };

JWTVendRequest _$JWTVendRequestFromJson(Map<String, dynamic> json) =>
    JWTVendRequest(
      claims: json['claims'] as Map<String, dynamic>,
      keyId: json['keyId'] as String,
      timeToLiveInSeconds: json['timeToLiveInSeconds'] as num,
    );

Map<String, dynamic> _$JWTVendRequestToJson(JWTVendRequest instance) =>
    <String, dynamic>{
      'claims': instance.claims,
      'keyId': instance.keyId,
      'timeToLiveInSeconds': instance.timeToLiveInSeconds,
    };

JWTVendResponse _$JWTVendResponseFromJson(Map<String, dynamic> json) =>
    JWTVendResponse(
      token: json['token'] as String,
    );

Map<String, dynamic> _$JWTVendResponseToJson(JWTVendResponse instance) =>
    <String, dynamic>{
      'token': instance.token,
    };

KafkaConfiguration _$KafkaConfigurationFromJson(Map<String, dynamic> json) =>
    KafkaConfiguration(
      defaultTopic: json['defaultTopic'] as String,
      producer: Map<String, String>.from(json['producer'] as Map),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$KafkaConfigurationToJson(KafkaConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'defaultTopic': instance.defaultTopic,
      'producer': instance.producer,
    };

KafkaMessengerConfiguration _$KafkaMessengerConfigurationFromJson(
        Map<String, dynamic> json) =>
    KafkaMessengerConfiguration(
      defaultTopic: json['defaultTopic'] as String,
      producer: Map<String, String>.from(json['producer'] as Map),
    )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..transport = json['transport'] as String
      ..type = _$enumDecode(_$MessengerTypeEnumMap, json['type']);

Map<String, dynamic> _$KafkaMessengerConfigurationToJson(
        KafkaMessengerConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'transport': instance.transport,
      'type': _$MessengerTypeEnumMap[instance.type],
      'defaultTopic': instance.defaultTopic,
      'producer': instance.producer,
    };

Key _$KeyFromJson(Map<String, dynamic> json) => Key(
      algorithm: _$enumDecode(_$KeyAlgorithmEnumMap, json['algorithm']),
      certificate: json['certificate'] as String,
      certificateInformation: CertificateInformation.fromJson(
          json['certificateInformation'] as Map<String, dynamic>),
      expirationInstant: json['expirationInstant'] as num,
      hasPrivateKey: json['hasPrivateKey'] as bool,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      issuer: json['issuer'] as String,
      kid: json['kid'] as String,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      length: json['length'] as num,
      name: json['name'] as String,
      privateKey: json['privateKey'] as String,
      publicKey: json['publicKey'] as String,
      secret: json['secret'] as String,
      type: _$enumDecode(_$KeyTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$KeyToJson(Key instance) => <String, dynamic>{
      'algorithm': _$KeyAlgorithmEnumMap[instance.algorithm],
      'certificate': instance.certificate,
      'certificateInformation': instance.certificateInformation,
      'expirationInstant': instance.expirationInstant,
      'hasPrivateKey': instance.hasPrivateKey,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'issuer': instance.issuer,
      'kid': instance.kid,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'length': instance.length,
      'name': instance.name,
      'privateKey': instance.privateKey,
      'publicKey': instance.publicKey,
      'secret': instance.secret,
      'type': _$KeyTypeEnumMap[instance.type],
    };

const _$KeyAlgorithmEnumMap = {
  KeyAlgorithm.ES256: 'ES256',
  KeyAlgorithm.ES384: 'ES384',
  KeyAlgorithm.ES512: 'ES512',
  KeyAlgorithm.HS256: 'HS256',
  KeyAlgorithm.HS384: 'HS384',
  KeyAlgorithm.HS512: 'HS512',
  KeyAlgorithm.RS256: 'RS256',
  KeyAlgorithm.RS384: 'RS384',
  KeyAlgorithm.RS512: 'RS512',
};

KeyRequest _$KeyRequestFromJson(Map<String, dynamic> json) => KeyRequest(
      key: Key.fromJson(json['key'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$KeyRequestToJson(KeyRequest instance) =>
    <String, dynamic>{
      'key': instance.key,
    };

KeyResponse _$KeyResponseFromJson(Map<String, dynamic> json) => KeyResponse(
      key: Key.fromJson(json['key'] as Map<String, dynamic>),
      keys: (json['keys'] as List<dynamic>)
          .map((e) => Key.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$KeyResponseToJson(KeyResponse instance) =>
    <String, dynamic>{
      'key': instance.key,
      'keys': instance.keys,
    };

KickstartSuccessEvent _$KickstartSuccessEventFromJson(
        Map<String, dynamic> json) =>
    KickstartSuccessEvent(
      instanceId: json['instanceId'] as String,
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$KickstartSuccessEventToJson(
        KickstartSuccessEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'instanceId': instance.instanceId,
    };

Lambda _$LambdaFromJson(Map<String, dynamic> json) => Lambda(
      body: json['body'] as String,
      debug: json['debug'] as bool,
      engineType: _$enumDecode(_$LambdaEngineTypeEnumMap, json['engineType']),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      type: _$enumDecode(_$LambdaTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$LambdaToJson(Lambda instance) => <String, dynamic>{
      'body': instance.body,
      'debug': instance.debug,
      'engineType': _$LambdaEngineTypeEnumMap[instance.engineType],
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$LambdaTypeEnumMap[instance.type],
    };

const _$LambdaEngineTypeEnumMap = {
  LambdaEngineType.GraalJS: 'GraalJS',
  LambdaEngineType.Nashorn: 'Nashorn',
};

const _$LambdaTypeEnumMap = {
  LambdaType.JWTPopulate: 'JWTPopulate',
  LambdaType.OpenIDReconcile: 'OpenIDReconcile',
  LambdaType.SAMLv2Reconcile: 'SAMLv2Reconcile',
  LambdaType.SAMLv2Populate: 'SAMLv2Populate',
  LambdaType.AppleReconcile: 'AppleReconcile',
  LambdaType.ExternalJWTReconcile: 'ExternalJWTReconcile',
  LambdaType.FacebookReconcile: 'FacebookReconcile',
  LambdaType.GoogleReconcile: 'GoogleReconcile',
  LambdaType.HYPRReconcile: 'HYPRReconcile',
  LambdaType.TwitterReconcile: 'TwitterReconcile',
  LambdaType.LDAPConnectorReconcile: 'LDAPConnectorReconcile',
  LambdaType.LinkedInReconcile: 'LinkedInReconcile',
  LambdaType.EpicGamesReconcile: 'EpicGamesReconcile',
  LambdaType.NintendoReconcile: 'NintendoReconcile',
  LambdaType.SonyPSNReconcile: 'SonyPSNReconcile',
  LambdaType.SteamReconcile: 'SteamReconcile',
  LambdaType.TwitchReconcile: 'TwitchReconcile',
  LambdaType.XboxReconcile: 'XboxReconcile',
  LambdaType.ClientCredentialsJWTPopulate: 'ClientCredentialsJWTPopulate',
  LambdaType.SCIMServerGroupRequestConverter: 'SCIMServerGroupRequestConverter',
  LambdaType.SCIMServerGroupResponseConverter:
      'SCIMServerGroupResponseConverter',
  LambdaType.SCIMServerUserRequestConverter: 'SCIMServerUserRequestConverter',
  LambdaType.SCIMServerUserResponseConverter: 'SCIMServerUserResponseConverter',
};

LambdaRequest _$LambdaRequestFromJson(Map<String, dynamic> json) =>
    LambdaRequest(
      lambda: Lambda.fromJson(json['lambda'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$LambdaRequestToJson(LambdaRequest instance) =>
    <String, dynamic>{
      'lambda': instance.lambda,
    };

LambdaResponse _$LambdaResponseFromJson(Map<String, dynamic> json) =>
    LambdaResponse(
      lambda: Lambda.fromJson(json['lambda'] as Map<String, dynamic>),
      lambdas: (json['lambdas'] as List<dynamic>)
          .map((e) => Lambda.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$LambdaResponseToJson(LambdaResponse instance) =>
    <String, dynamic>{
      'lambda': instance.lambda,
      'lambdas': instance.lambdas,
    };

LDAPConnectorConfiguration _$LDAPConnectorConfigurationFromJson(
        Map<String, dynamic> json) =>
    LDAPConnectorConfiguration(
      authenticationURL: json['authenticationURL'] as String,
      baseStructure: json['baseStructure'] as String,
      connectTimeout: json['connectTimeout'] as num,
      identifyingAttribute: json['identifyingAttribute'] as String,
      lambdaConfiguration: json['lambdaConfiguration'],
      loginIdAttribute: json['loginIdAttribute'] as String,
      readTimeout: json['readTimeout'] as num,
      requestedAttributes: (json['requestedAttributes'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      securityMethod:
          _$enumDecode(_$LDAPSecurityMethodEnumMap, json['securityMethod']),
      systemAccountDN: json['systemAccountDN'] as String,
      systemAccountPassword: json['systemAccountPassword'] as String,
    )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..type = _$enumDecode(_$ConnectorTypeEnumMap, json['type']);

Map<String, dynamic> _$LDAPConnectorConfigurationToJson(
    LDAPConnectorConfiguration instance) {
  final val = <String, dynamic>{
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
    'lastUpdateInstant': instance.lastUpdateInstant,
    'name': instance.name,
    'type': _$ConnectorTypeEnumMap[instance.type],
    'authenticationURL': instance.authenticationURL,
    'baseStructure': instance.baseStructure,
    'connectTimeout': instance.connectTimeout,
    'identifyingAttribute': instance.identifyingAttribute,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['loginIdAttribute'] = instance.loginIdAttribute;
  val['readTimeout'] = instance.readTimeout;
  val['requestedAttributes'] = instance.requestedAttributes;
  val['securityMethod'] = _$LDAPSecurityMethodEnumMap[instance.securityMethod];
  val['systemAccountDN'] = instance.systemAccountDN;
  val['systemAccountPassword'] = instance.systemAccountPassword;
  return val;
}

const _$LDAPSecurityMethodEnumMap = {
  LDAPSecurityMethod.None: 'None',
  LDAPSecurityMethod.LDAPS: 'LDAPS',
  LDAPSecurityMethod.StartTLS: 'StartTLS',
};

LinkedInApplicationConfiguration _$LinkedInApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    LinkedInApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$LinkedInApplicationConfigurationToJson(
        LinkedInApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'scope': instance.scope,
    };

LinkedInIdentityProvider _$LinkedInIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    LinkedInIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            LinkedInApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$LinkedInIdentityProviderToJson(
    LinkedInIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['scope'] = instance.scope;
  return val;
}

Location _$LocationFromJson(Map<String, dynamic> json) => Location(
      city: json['city'] as String,
      country: json['country'] as String,
      displayString: json['displayString'] as String,
      latitude: json['latitude'] as num,
      longitude: json['longitude'] as num,
      region: json['region'] as String,
      zipcode: json['zipcode'] as String,
    );

Map<String, dynamic> _$LocationToJson(Location instance) => <String, dynamic>{
      'city': instance.city,
      'country': instance.country,
      'displayString': instance.displayString,
      'latitude': instance.latitude,
      'longitude': instance.longitude,
      'region': instance.region,
      'zipcode': instance.zipcode,
    };

LogHistory _$LogHistoryFromJson(Map<String, dynamic> json) => LogHistory(
      historyItems: (json['historyItems'] as List<dynamic>)
          .map((e) => HistoryItem.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$LogHistoryToJson(LogHistory instance) =>
    <String, dynamic>{
      'historyItems': instance.historyItems,
    };

LoginConfiguration _$LoginConfigurationFromJson(Map<String, dynamic> json) =>
    LoginConfiguration(
      allowTokenRefresh: json['allowTokenRefresh'] as bool,
      generateRefreshTokens: json['generateRefreshTokens'] as bool,
      requireAuthentication: json['requireAuthentication'] as bool,
    );

Map<String, dynamic> _$LoginConfigurationToJson(LoginConfiguration instance) =>
    <String, dynamic>{
      'allowTokenRefresh': instance.allowTokenRefresh,
      'generateRefreshTokens': instance.generateRefreshTokens,
      'requireAuthentication': instance.requireAuthentication,
    };

LoginPreventedResponse _$LoginPreventedResponseFromJson(
        Map<String, dynamic> json) =>
    LoginPreventedResponse(
      actionerUserId: json['actionerUserId'] as String,
      actionId: json['actionId'] as String,
      expiry: json['expiry'] as num,
      localizedName: json['localizedName'] as String,
      localizedOption: json['localizedOption'] as String,
      localizedReason: json['localizedReason'] as String,
      name: json['name'] as String,
      option: json['option'] as String,
      reason: json['reason'] as String,
      reasonCode: json['reasonCode'] as String,
    );

Map<String, dynamic> _$LoginPreventedResponseToJson(
        LoginPreventedResponse instance) =>
    <String, dynamic>{
      'actionerUserId': instance.actionerUserId,
      'actionId': instance.actionId,
      'expiry': instance.expiry,
      'localizedName': instance.localizedName,
      'localizedOption': instance.localizedOption,
      'localizedReason': instance.localizedReason,
      'name': instance.name,
      'option': instance.option,
      'reason': instance.reason,
      'reasonCode': instance.reasonCode,
    };

LoginRecordConfiguration _$LoginRecordConfigurationFromJson(
        Map<String, dynamic> json) =>
    LoginRecordConfiguration(
      delete:
          DeleteConfiguration.fromJson(json['delete'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$LoginRecordConfigurationToJson(
        LoginRecordConfiguration instance) =>
    <String, dynamic>{
      'delete': instance.delete,
    };

LoginRecordExportRequest _$LoginRecordExportRequestFromJson(
        Map<String, dynamic> json) =>
    LoginRecordExportRequest(
      criteria: LoginRecordSearchCriteria.fromJson(
          json['criteria'] as Map<String, dynamic>),
    )
      ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
      ..zoneId = json['zoneId'] as String;

Map<String, dynamic> _$LoginRecordExportRequestToJson(
        LoginRecordExportRequest instance) =>
    <String, dynamic>{
      'dateTimeSecondsFormat': instance.dateTimeSecondsFormat,
      'zoneId': instance.zoneId,
      'criteria': instance.criteria,
    };

LoginRecordSearchCriteria _$LoginRecordSearchCriteriaFromJson(
        Map<String, dynamic> json) =>
    LoginRecordSearchCriteria(
      applicationId: json['applicationId'] as String,
      end: json['end'] as num,
      start: json['start'] as num,
      userId: json['userId'] as String,
    )
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num;

Map<String, dynamic> _$LoginRecordSearchCriteriaToJson(
        LoginRecordSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'applicationId': instance.applicationId,
      'end': instance.end,
      'start': instance.start,
      'userId': instance.userId,
    };

LoginRecordSearchRequest _$LoginRecordSearchRequestFromJson(
        Map<String, dynamic> json) =>
    LoginRecordSearchRequest(
      retrieveTotal: json['retrieveTotal'] as bool,
      search: LoginRecordSearchCriteria.fromJson(
          json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$LoginRecordSearchRequestToJson(
        LoginRecordSearchRequest instance) =>
    <String, dynamic>{
      'retrieveTotal': instance.retrieveTotal,
      'search': instance.search,
    };

LoginRecordSearchResponse _$LoginRecordSearchResponseFromJson(
        Map<String, dynamic> json) =>
    LoginRecordSearchResponse(
      logins: (json['logins'] as List<dynamic>)
          .map((e) => DisplayableRawLogin.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$LoginRecordSearchResponseToJson(
        LoginRecordSearchResponse instance) =>
    <String, dynamic>{
      'logins': instance.logins,
      'total': instance.total,
    };

LoginReportResponse _$LoginReportResponseFromJson(Map<String, dynamic> json) =>
    LoginReportResponse(
      hourlyCounts: (json['hourlyCounts'] as List<dynamic>)
          .map((e) => Count.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$LoginReportResponseToJson(
        LoginReportResponse instance) =>
    <String, dynamic>{
      'hourlyCounts': instance.hourlyCounts,
      'total': instance.total,
    };

LoginRequest _$LoginRequestFromJson(Map<String, dynamic> json) => LoginRequest(
      loginId: json['loginId'] as String,
      oneTimePassword: json['oneTimePassword'] as String,
      password: json['password'] as String,
      twoFactorTrustId: json['twoFactorTrustId'] as String,
    )
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>)
      ..applicationId = json['applicationId'] as String
      ..ipAddress = json['ipAddress'] as String
      ..metaData = MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
      ..newDevice = json['newDevice'] as bool
      ..noJWT = json['noJWT'] as bool;

Map<String, dynamic> _$LoginRequestToJson(LoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
      'loginId': instance.loginId,
      'oneTimePassword': instance.oneTimePassword,
      'password': instance.password,
      'twoFactorTrustId': instance.twoFactorTrustId,
    };

LoginResponse _$LoginResponseFromJson(Map<String, dynamic> json) =>
    LoginResponse(
      actions: (json['actions'] as List<dynamic>)
          .map(
              (e) => LoginPreventedResponse.fromJson(e as Map<String, dynamic>))
          .toList(),
      changePasswordId: json['changePasswordId'] as String,
      changePasswordReason: _$enumDecode(
          _$ChangePasswordReasonEnumMap, json['changePasswordReason']),
      emailVerificationId: json['emailVerificationId'] as String,
      methods: (json['methods'] as List<dynamic>)
          .map((e) => TwoFactorMethod.fromJson(e as Map<String, dynamic>))
          .toList(),
      pendingIdPLinkId: json['pendingIdPLinkId'] as String,
      refreshToken: json['refreshToken'] as String,
      registrationVerificationId: json['registrationVerificationId'] as String,
      state: json['state'] as Map<String, dynamic>,
      threatsDetected: (json['threatsDetected'] as List<dynamic>)
          .map((e) => _$enumDecode(_$AuthenticationThreatsEnumMap, e))
          .toSet(),
      token: json['token'] as String,
      tokenExpirationInstant: json['tokenExpirationInstant'] as num,
      trustToken: json['trustToken'] as String,
      twoFactorId: json['twoFactorId'] as String,
      twoFactorTrustId: json['twoFactorTrustId'] as String,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$LoginResponseToJson(LoginResponse instance) =>
    <String, dynamic>{
      'actions': instance.actions,
      'changePasswordId': instance.changePasswordId,
      'changePasswordReason':
          _$ChangePasswordReasonEnumMap[instance.changePasswordReason],
      'emailVerificationId': instance.emailVerificationId,
      'methods': instance.methods,
      'pendingIdPLinkId': instance.pendingIdPLinkId,
      'refreshToken': instance.refreshToken,
      'registrationVerificationId': instance.registrationVerificationId,
      'state': instance.state,
      'threatsDetected': instance.threatsDetected
          .map((e) => _$AuthenticationThreatsEnumMap[e])
          .toList(),
      'token': instance.token,
      'tokenExpirationInstant': instance.tokenExpirationInstant,
      'trustToken': instance.trustToken,
      'twoFactorId': instance.twoFactorId,
      'twoFactorTrustId': instance.twoFactorTrustId,
      'user': instance.user,
    };

const _$ChangePasswordReasonEnumMap = {
  ChangePasswordReason.Administrative: 'Administrative',
  ChangePasswordReason.Breached: 'Breached',
  ChangePasswordReason.Expired: 'Expired',
  ChangePasswordReason.Validation: 'Validation',
};

const _$AuthenticationThreatsEnumMap = {
  AuthenticationThreats.ImpossibleTravel: 'ImpossibleTravel',
};

LogoutRequest _$LogoutRequestFromJson(Map<String, dynamic> json) =>
    LogoutRequest(
      global: json['global'] as bool,
      refreshToken: json['refreshToken'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$LogoutRequestToJson(LogoutRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'global': instance.global,
      'refreshToken': instance.refreshToken,
    };

LookupResponse _$LookupResponseFromJson(Map<String, dynamic> json) =>
    LookupResponse(
      identityProvider: IdentityProviderDetails.fromJson(
          json['identityProvider'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$LookupResponseToJson(LookupResponse instance) =>
    <String, dynamic>{
      'identityProvider': instance.identityProvider,
    };

ManagedFields _$ManagedFieldsFromJson(Map<String, dynamic> json) =>
    ManagedFields();

Map<String, dynamic> _$ManagedFieldsToJson(ManagedFields instance) =>
    <String, dynamic>{};

MaximumPasswordAge _$MaximumPasswordAgeFromJson(Map<String, dynamic> json) =>
    MaximumPasswordAge(
      days: json['days'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$MaximumPasswordAgeToJson(MaximumPasswordAge instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'days': instance.days,
    };

MemberDeleteRequest _$MemberDeleteRequestFromJson(Map<String, dynamic> json) =>
    MemberDeleteRequest(
      memberIds:
          (json['memberIds'] as List<dynamic>).map((e) => e as String).toList(),
      members: (json['members'] as Map<String, dynamic>).map(
        (k, e) =>
            MapEntry(k, (e as List<dynamic>).map((e) => e as String).toList()),
      ),
    );

Map<String, dynamic> _$MemberDeleteRequestToJson(
        MemberDeleteRequest instance) =>
    <String, dynamic>{
      'memberIds': instance.memberIds,
      'members': instance.members,
    };

MemberRequest _$MemberRequestFromJson(Map<String, dynamic> json) =>
    MemberRequest(
      members: (json['members'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List<dynamic>)
                .map((e) => GroupMember.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
    );

Map<String, dynamic> _$MemberRequestToJson(MemberRequest instance) =>
    <String, dynamic>{
      'members': instance.members,
    };

MemberResponse _$MemberResponseFromJson(Map<String, dynamic> json) =>
    MemberResponse(
      members: (json['members'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            (e as List<dynamic>)
                .map((e) => GroupMember.fromJson(e as Map<String, dynamic>))
                .toList()),
      ),
    );

Map<String, dynamic> _$MemberResponseToJson(MemberResponse instance) =>
    <String, dynamic>{
      'members': instance.members,
    };

Message _$MessageFromJson(Map<String, dynamic> json) => Message();

Map<String, dynamic> _$MessageToJson(Message instance) => <String, dynamic>{};

MessageTemplate _$MessageTemplateFromJson(Map<String, dynamic> json) =>
    MessageTemplate(
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      name: json['name'] as String,
      type: _$enumDecode(_$MessageTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$MessageTemplateToJson(MessageTemplate instance) =>
    <String, dynamic>{
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$MessageTypeEnumMap[instance.type],
    };

const _$MessageTypeEnumMap = {
  MessageType.SMS: 'SMS',
};

MessageTemplateRequest _$MessageTemplateRequestFromJson(
        Map<String, dynamic> json) =>
    MessageTemplateRequest(
      messageTemplate: MessageTemplate.fromJson(
          json['messageTemplate'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$MessageTemplateRequestToJson(
        MessageTemplateRequest instance) =>
    <String, dynamic>{
      'messageTemplate': instance.messageTemplate,
    };

MessageTemplateResponse _$MessageTemplateResponseFromJson(
        Map<String, dynamic> json) =>
    MessageTemplateResponse(
      messageTemplate: MessageTemplate.fromJson(
          json['messageTemplate'] as Map<String, dynamic>),
      messageTemplates: (json['messageTemplates'] as List<dynamic>)
          .map((e) => MessageTemplate.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$MessageTemplateResponseToJson(
        MessageTemplateResponse instance) =>
    <String, dynamic>{
      'messageTemplate': instance.messageTemplate,
      'messageTemplates': instance.messageTemplates,
    };

MessengerRequest _$MessengerRequestFromJson(Map<String, dynamic> json) =>
    MessengerRequest(
      messenger: BaseMessengerConfiguration.fromJson(
          json['messenger'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$MessengerRequestToJson(MessengerRequest instance) =>
    <String, dynamic>{
      'messenger': instance.messenger,
    };

MessengerResponse _$MessengerResponseFromJson(Map<String, dynamic> json) =>
    MessengerResponse(
      messenger: BaseMessengerConfiguration.fromJson(
          json['messenger'] as Map<String, dynamic>),
      messengers: (json['messengers'] as List<dynamic>)
          .map((e) =>
              BaseMessengerConfiguration.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$MessengerResponseToJson(MessengerResponse instance) =>
    <String, dynamic>{
      'messenger': instance.messenger,
      'messengers': instance.messengers,
    };

MessengerTransport _$MessengerTransportFromJson(Map<String, dynamic> json) =>
    MessengerTransport();

Map<String, dynamic> _$MessengerTransportToJson(MessengerTransport instance) =>
    <String, dynamic>{};

MetaData _$MetaDataFromJson(Map<String, dynamic> json) => MetaData(
      device: DeviceInfo.fromJson(json['device'] as Map<String, dynamic>),
      scopes: (json['scopes'] as List<dynamic>).map((e) => e as String).toSet(),
    );

Map<String, dynamic> _$MetaDataToJson(MetaData instance) => <String, dynamic>{
      'device': instance.device,
      'scopes': instance.scopes.toList(),
    };

MinimumPasswordAge _$MinimumPasswordAgeFromJson(Map<String, dynamic> json) =>
    MinimumPasswordAge(
      seconds: json['seconds'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$MinimumPasswordAgeToJson(MinimumPasswordAge instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'seconds': instance.seconds,
    };

MonthlyActiveUserReportResponse _$MonthlyActiveUserReportResponseFromJson(
        Map<String, dynamic> json) =>
    MonthlyActiveUserReportResponse(
      monthlyActiveUsers: (json['monthlyActiveUsers'] as List<dynamic>)
          .map((e) => Count.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$MonthlyActiveUserReportResponseToJson(
        MonthlyActiveUserReportResponse instance) =>
    <String, dynamic>{
      'monthlyActiveUsers': instance.monthlyActiveUsers,
      'total': instance.total,
    };

MultiFactorAuthenticatorMethod _$MultiFactorAuthenticatorMethodFromJson(
        Map<String, dynamic> json) =>
    MultiFactorAuthenticatorMethod(
      algorithm: _$enumDecode(_$TOTPAlgorithmEnumMap, json['algorithm']),
      codeLength: json['codeLength'] as num,
      timeStep: json['timeStep'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$MultiFactorAuthenticatorMethodToJson(
        MultiFactorAuthenticatorMethod instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'algorithm': _$TOTPAlgorithmEnumMap[instance.algorithm],
      'codeLength': instance.codeLength,
      'timeStep': instance.timeStep,
    };

MultiFactorEmailMethod _$MultiFactorEmailMethodFromJson(
        Map<String, dynamic> json) =>
    MultiFactorEmailMethod(
      templateId: json['templateId'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$MultiFactorEmailMethodToJson(
        MultiFactorEmailMethod instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'templateId': instance.templateId,
    };

MultiFactorEmailTemplate _$MultiFactorEmailTemplateFromJson(
        Map<String, dynamic> json) =>
    MultiFactorEmailTemplate(
      templateId: json['templateId'] as String,
    );

Map<String, dynamic> _$MultiFactorEmailTemplateToJson(
        MultiFactorEmailTemplate instance) =>
    <String, dynamic>{
      'templateId': instance.templateId,
    };

MultiFactorSMSMethod _$MultiFactorSMSMethodFromJson(
        Map<String, dynamic> json) =>
    MultiFactorSMSMethod(
      messengerId: json['messengerId'] as String,
      templateId: json['templateId'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$MultiFactorSMSMethodToJson(
        MultiFactorSMSMethod instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'messengerId': instance.messengerId,
      'templateId': instance.templateId,
    };

MultiFactorSMSTemplate _$MultiFactorSMSTemplateFromJson(
        Map<String, dynamic> json) =>
    MultiFactorSMSTemplate(
      templateId: json['templateId'] as String,
    );

Map<String, dynamic> _$MultiFactorSMSTemplateToJson(
        MultiFactorSMSTemplate instance) =>
    <String, dynamic>{
      'templateId': instance.templateId,
    };

NintendoApplicationConfiguration _$NintendoApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    NintendoApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      emailClaim: json['emailClaim'] as String,
      scope: json['scope'] as String,
      uniqueIdClaim: json['uniqueIdClaim'] as String,
      usernameClaim: json['usernameClaim'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$NintendoApplicationConfigurationToJson(
        NintendoApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'emailClaim': instance.emailClaim,
      'scope': instance.scope,
      'uniqueIdClaim': instance.uniqueIdClaim,
      'usernameClaim': instance.usernameClaim,
    };

NintendoIdentityProvider _$NintendoIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    NintendoIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      emailClaim: json['emailClaim'] as String,
      scope: json['scope'] as String,
      uniqueIdClaim: json['uniqueIdClaim'] as String,
      usernameClaim: json['usernameClaim'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            NintendoApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$NintendoIdentityProviderToJson(
    NintendoIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['emailClaim'] = instance.emailClaim;
  val['scope'] = instance.scope;
  val['uniqueIdClaim'] = instance.uniqueIdClaim;
  val['usernameClaim'] = instance.usernameClaim;
  return val;
}

NonTransactionalEvent _$NonTransactionalEventFromJson(
        Map<String, dynamic> json) =>
    NonTransactionalEvent();

Map<String, dynamic> _$NonTransactionalEventToJson(
        NonTransactionalEvent instance) =>
    <String, dynamic>{};

OAuth2Configuration _$OAuth2ConfigurationFromJson(Map<String, dynamic> json) =>
    OAuth2Configuration(
      authorizedOriginURLs: (json['authorizedOriginURLs'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      authorizedRedirectURLs: (json['authorizedRedirectURLs'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      clientAuthenticationPolicy: _$enumDecode(
          _$ClientAuthenticationPolicyEnumMap,
          json['clientAuthenticationPolicy']),
      clientId: json['clientId'] as String,
      clientSecret: json['clientSecret'] as String,
      debug: json['debug'] as bool,
      deviceVerificationURL: json['deviceVerificationURL'] as String,
      enabledGrants: (json['enabledGrants'] as List<dynamic>)
          .map((e) => _$enumDecode(_$GrantTypeEnumMap, e))
          .toSet(),
      generateRefreshTokens: json['generateRefreshTokens'] as bool,
      logoutBehavior:
          _$enumDecode(_$LogoutBehaviorEnumMap, json['logoutBehavior']),
      logoutURL: json['logoutURL'] as String,
      proofKeyForCodeExchangePolicy: _$enumDecode(
          _$ProofKeyForCodeExchangePolicyEnumMap,
          json['proofKeyForCodeExchangePolicy']),
      requireClientAuthentication: json['requireClientAuthentication'] as bool,
      requireRegistration: json['requireRegistration'] as bool,
    );

Map<String, dynamic> _$OAuth2ConfigurationToJson(
        OAuth2Configuration instance) =>
    <String, dynamic>{
      'authorizedOriginURLs': instance.authorizedOriginURLs,
      'authorizedRedirectURLs': instance.authorizedRedirectURLs,
      'clientAuthenticationPolicy': _$ClientAuthenticationPolicyEnumMap[
          instance.clientAuthenticationPolicy],
      'clientId': instance.clientId,
      'clientSecret': instance.clientSecret,
      'debug': instance.debug,
      'deviceVerificationURL': instance.deviceVerificationURL,
      'enabledGrants':
          instance.enabledGrants.map((e) => _$GrantTypeEnumMap[e]).toList(),
      'generateRefreshTokens': instance.generateRefreshTokens,
      'logoutBehavior': _$LogoutBehaviorEnumMap[instance.logoutBehavior],
      'logoutURL': instance.logoutURL,
      'proofKeyForCodeExchangePolicy': _$ProofKeyForCodeExchangePolicyEnumMap[
          instance.proofKeyForCodeExchangePolicy],
      'requireClientAuthentication': instance.requireClientAuthentication,
      'requireRegistration': instance.requireRegistration,
    };

const _$ClientAuthenticationPolicyEnumMap = {
  ClientAuthenticationPolicy.Required: 'Required',
  ClientAuthenticationPolicy.NotRequired: 'NotRequired',
  ClientAuthenticationPolicy.NotRequiredWhenUsingPKCE:
      'NotRequiredWhenUsingPKCE',
};

const _$GrantTypeEnumMap = {
  GrantType.authorization_code: 'authorization_code',
  GrantType.implicit: 'implicit',
  GrantType.password: 'password',
  GrantType.client_credentials: 'client_credentials',
  GrantType.refresh_token: 'refresh_token',
  GrantType.unknown: 'unknown',
  GrantType.device_code: 'device_code',
};

const _$LogoutBehaviorEnumMap = {
  LogoutBehavior.RedirectOnly: 'RedirectOnly',
  LogoutBehavior.AllApplications: 'AllApplications',
};

const _$ProofKeyForCodeExchangePolicyEnumMap = {
  ProofKeyForCodeExchangePolicy.Required: 'Required',
  ProofKeyForCodeExchangePolicy.NotRequired: 'NotRequired',
  ProofKeyForCodeExchangePolicy.NotRequiredWhenUsingClientAuthentication:
      'NotRequiredWhenUsingClientAuthentication',
};

OAuthConfigurationResponse _$OAuthConfigurationResponseFromJson(
        Map<String, dynamic> json) =>
    OAuthConfigurationResponse(
      httpSessionMaxInactiveInterval:
          json['httpSessionMaxInactiveInterval'] as num,
      logoutURL: json['logoutURL'] as String,
      oauthConfiguration: OAuth2Configuration.fromJson(
          json['oauthConfiguration'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$OAuthConfigurationResponseToJson(
        OAuthConfigurationResponse instance) =>
    <String, dynamic>{
      'httpSessionMaxInactiveInterval': instance.httpSessionMaxInactiveInterval,
      'logoutURL': instance.logoutURL,
      'oauthConfiguration': instance.oauthConfiguration,
    };

OAuthError _$OAuthErrorFromJson(Map<String, dynamic> json) => OAuthError(
      change_password_id: json['change_password_id'] as String,
      error: _$enumDecode(_$OAuthErrorTypeEnumMap, json['error']),
      error_description: json['error_description'] as String,
      error_reason:
          _$enumDecode(_$OAuthErrorReasonEnumMap, json['error_reason']),
      error_uri: json['error_uri'] as String,
      two_factor_id: json['two_factor_id'] as String,
      two_factor_methods: (json['two_factor_methods'] as List<dynamic>)
          .map((e) => TwoFactorMethod.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$OAuthErrorToJson(OAuthError instance) =>
    <String, dynamic>{
      'change_password_id': instance.change_password_id,
      'error': _$OAuthErrorTypeEnumMap[instance.error],
      'error_description': instance.error_description,
      'error_reason': _$OAuthErrorReasonEnumMap[instance.error_reason],
      'error_uri': instance.error_uri,
      'two_factor_id': instance.two_factor_id,
      'two_factor_methods': instance.two_factor_methods,
    };

const _$OAuthErrorTypeEnumMap = {
  OAuthErrorType.invalid_request: 'invalid_request',
  OAuthErrorType.invalid_client: 'invalid_client',
  OAuthErrorType.invalid_grant: 'invalid_grant',
  OAuthErrorType.invalid_token: 'invalid_token',
  OAuthErrorType.unauthorized_client: 'unauthorized_client',
  OAuthErrorType.invalid_scope: 'invalid_scope',
  OAuthErrorType.server_error: 'server_error',
  OAuthErrorType.unsupported_grant_type: 'unsupported_grant_type',
  OAuthErrorType.unsupported_response_type: 'unsupported_response_type',
  OAuthErrorType.change_password_required: 'change_password_required',
  OAuthErrorType.not_licensed: 'not_licensed',
  OAuthErrorType.two_factor_required: 'two_factor_required',
  OAuthErrorType.authorization_pending: 'authorization_pending',
  OAuthErrorType.expired_token: 'expired_token',
  OAuthErrorType.unsupported_token_type: 'unsupported_token_type',
};

const _$OAuthErrorReasonEnumMap = {
  OAuthErrorReason.auth_code_not_found: 'auth_code_not_found',
  OAuthErrorReason.access_token_malformed: 'access_token_malformed',
  OAuthErrorReason.access_token_expired: 'access_token_expired',
  OAuthErrorReason.access_token_unavailable_for_processing:
      'access_token_unavailable_for_processing',
  OAuthErrorReason.access_token_failed_processing:
      'access_token_failed_processing',
  OAuthErrorReason.refresh_token_not_found: 'refresh_token_not_found',
  OAuthErrorReason.refresh_token_type_not_supported:
      'refresh_token_type_not_supported',
  OAuthErrorReason.invalid_client_id: 'invalid_client_id',
  OAuthErrorReason.invalid_user_credentials: 'invalid_user_credentials',
  OAuthErrorReason.invalid_grant_type: 'invalid_grant_type',
  OAuthErrorReason.invalid_origin: 'invalid_origin',
  OAuthErrorReason.invalid_origin_opaque: 'invalid_origin_opaque',
  OAuthErrorReason.invalid_pkce_code_verifier: 'invalid_pkce_code_verifier',
  OAuthErrorReason.invalid_pkce_code_challenge: 'invalid_pkce_code_challenge',
  OAuthErrorReason.invalid_pkce_code_challenge_method:
      'invalid_pkce_code_challenge_method',
  OAuthErrorReason.invalid_redirect_uri: 'invalid_redirect_uri',
  OAuthErrorReason.invalid_response_mode: 'invalid_response_mode',
  OAuthErrorReason.invalid_response_type: 'invalid_response_type',
  OAuthErrorReason.invalid_id_token_hint: 'invalid_id_token_hint',
  OAuthErrorReason.invalid_post_logout_redirect_uri:
      'invalid_post_logout_redirect_uri',
  OAuthErrorReason.invalid_device_code: 'invalid_device_code',
  OAuthErrorReason.invalid_user_code: 'invalid_user_code',
  OAuthErrorReason.invalid_additional_client_id: 'invalid_additional_client_id',
  OAuthErrorReason.invalid_target_entity_scope: 'invalid_target_entity_scope',
  OAuthErrorReason.invalid_entity_permission_scope:
      'invalid_entity_permission_scope',
  OAuthErrorReason.grant_type_disabled: 'grant_type_disabled',
  OAuthErrorReason.missing_client_id: 'missing_client_id',
  OAuthErrorReason.missing_client_secret: 'missing_client_secret',
  OAuthErrorReason.missing_code: 'missing_code',
  OAuthErrorReason.missing_code_challenge: 'missing_code_challenge',
  OAuthErrorReason.missing_code_verifier: 'missing_code_verifier',
  OAuthErrorReason.missing_device_code: 'missing_device_code',
  OAuthErrorReason.missing_grant_type: 'missing_grant_type',
  OAuthErrorReason.missing_redirect_uri: 'missing_redirect_uri',
  OAuthErrorReason.missing_refresh_token: 'missing_refresh_token',
  OAuthErrorReason.missing_response_type: 'missing_response_type',
  OAuthErrorReason.missing_token: 'missing_token',
  OAuthErrorReason.missing_user_code: 'missing_user_code',
  OAuthErrorReason.missing_verification_uri: 'missing_verification_uri',
  OAuthErrorReason.login_prevented: 'login_prevented',
  OAuthErrorReason.not_licensed: 'not_licensed',
  OAuthErrorReason.user_code_expired: 'user_code_expired',
  OAuthErrorReason.user_expired: 'user_expired',
  OAuthErrorReason.user_locked: 'user_locked',
  OAuthErrorReason.user_not_found: 'user_not_found',
  OAuthErrorReason.client_authentication_missing:
      'client_authentication_missing',
  OAuthErrorReason.invalid_client_authentication_scheme:
      'invalid_client_authentication_scheme',
  OAuthErrorReason.invalid_client_authentication:
      'invalid_client_authentication',
  OAuthErrorReason.client_id_mismatch: 'client_id_mismatch',
  OAuthErrorReason.change_password_administrative:
      'change_password_administrative',
  OAuthErrorReason.change_password_breached: 'change_password_breached',
  OAuthErrorReason.change_password_expired: 'change_password_expired',
  OAuthErrorReason.change_password_validation: 'change_password_validation',
  OAuthErrorReason.unknown: 'unknown',
};

OAuthResponse _$OAuthResponseFromJson(Map<String, dynamic> json) =>
    OAuthResponse();

Map<String, dynamic> _$OAuthResponseToJson(OAuthResponse instance) =>
    <String, dynamic>{};

OpenIdConfiguration _$OpenIdConfigurationFromJson(Map<String, dynamic> json) =>
    OpenIdConfiguration(
      authorization_endpoint: json['authorization_endpoint'] as String,
      backchannel_logout_supported:
          json['backchannel_logout_supported'] as bool,
      claims_supported: (json['claims_supported'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      device_authorization_endpoint:
          json['device_authorization_endpoint'] as String,
      end_session_endpoint: json['end_session_endpoint'] as String,
      frontchannel_logout_supported:
          json['frontchannel_logout_supported'] as bool,
      grant_types_supported: (json['grant_types_supported'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      id_token_signing_alg_values_supported:
          (json['id_token_signing_alg_values_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
      issuer: json['issuer'] as String,
      jwks_uri: json['jwks_uri'] as String,
      response_modes_supported:
          (json['response_modes_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
      response_types_supported:
          (json['response_types_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
      scopes_supported: (json['scopes_supported'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      subject_types_supported:
          (json['subject_types_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
      token_endpoint: json['token_endpoint'] as String,
      token_endpoint_auth_methods_supported:
          (json['token_endpoint_auth_methods_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
      userinfo_endpoint: json['userinfo_endpoint'] as String,
      userinfo_signing_alg_values_supported:
          (json['userinfo_signing_alg_values_supported'] as List<dynamic>)
              .map((e) => e as String)
              .toList(),
    );

Map<String, dynamic> _$OpenIdConfigurationToJson(
        OpenIdConfiguration instance) =>
    <String, dynamic>{
      'authorization_endpoint': instance.authorization_endpoint,
      'backchannel_logout_supported': instance.backchannel_logout_supported,
      'claims_supported': instance.claims_supported,
      'device_authorization_endpoint': instance.device_authorization_endpoint,
      'end_session_endpoint': instance.end_session_endpoint,
      'frontchannel_logout_supported': instance.frontchannel_logout_supported,
      'grant_types_supported': instance.grant_types_supported,
      'id_token_signing_alg_values_supported':
          instance.id_token_signing_alg_values_supported,
      'issuer': instance.issuer,
      'jwks_uri': instance.jwks_uri,
      'response_modes_supported': instance.response_modes_supported,
      'response_types_supported': instance.response_types_supported,
      'scopes_supported': instance.scopes_supported,
      'subject_types_supported': instance.subject_types_supported,
      'token_endpoint': instance.token_endpoint,
      'token_endpoint_auth_methods_supported':
          instance.token_endpoint_auth_methods_supported,
      'userinfo_endpoint': instance.userinfo_endpoint,
      'userinfo_signing_alg_values_supported':
          instance.userinfo_signing_alg_values_supported,
    };

OpenIdConnectApplicationConfiguration
    _$OpenIdConnectApplicationConfigurationFromJson(
            Map<String, dynamic> json) =>
        OpenIdConnectApplicationConfiguration(
          buttonImageURL: json['buttonImageURL'] as String,
          buttonText: json['buttonText'] as String,
          oauth2: IdentityProviderOauth2Configuration.fromJson(
              json['oauth2'] as Map<String, dynamic>),
        )
          ..enabled = json['enabled'] as bool
          ..createRegistration = json['createRegistration'] as bool
          ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$OpenIdConnectApplicationConfigurationToJson(
        OpenIdConnectApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonImageURL': instance.buttonImageURL,
      'buttonText': instance.buttonText,
      'oauth2': instance.oauth2,
    };

OpenIdConnectIdentityProvider _$OpenIdConnectIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    OpenIdConnectIdentityProvider(
      buttonImageURL: json['buttonImageURL'] as String,
      buttonText: json['buttonText'] as String,
      domains:
          (json['domains'] as List<dynamic>).map((e) => e as String).toSet(),
      oauth2: IdentityProviderOauth2Configuration.fromJson(
          json['oauth2'] as Map<String, dynamic>),
      postRequest: json['postRequest'] as bool,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            OpenIdConnectApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$OpenIdConnectIdentityProviderToJson(
    OpenIdConnectIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonImageURL'] = instance.buttonImageURL;
  val['buttonText'] = instance.buttonText;
  val['domains'] = instance.domains.toList();
  val['oauth2'] = instance.oauth2;
  val['postRequest'] = instance.postRequest;
  return val;
}

PasswordBreachDetection _$PasswordBreachDetectionFromJson(
        Map<String, dynamic> json) =>
    PasswordBreachDetection(
      matchMode: _$enumDecode(_$BreachMatchModeEnumMap, json['matchMode']),
      notifyUserEmailTemplateId: json['notifyUserEmailTemplateId'] as String,
      onLogin: _$enumDecode(_$BreachActionEnumMap, json['onLogin']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$PasswordBreachDetectionToJson(
        PasswordBreachDetection instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'matchMode': _$BreachMatchModeEnumMap[instance.matchMode],
      'notifyUserEmailTemplateId': instance.notifyUserEmailTemplateId,
      'onLogin': _$BreachActionEnumMap[instance.onLogin],
    };

const _$BreachMatchModeEnumMap = {
  BreachMatchMode.Low: 'Low',
  BreachMatchMode.Medium: 'Medium',
  BreachMatchMode.High: 'High',
};

const _$BreachActionEnumMap = {
  BreachAction.Off: 'Off',
  BreachAction.RecordOnly: 'RecordOnly',
  BreachAction.NotifyUser: 'NotifyUser',
  BreachAction.RequireChange: 'RequireChange',
};

PasswordEncryptionConfiguration _$PasswordEncryptionConfigurationFromJson(
        Map<String, dynamic> json) =>
    PasswordEncryptionConfiguration(
      encryptionScheme: json['encryptionScheme'] as String,
      encryptionSchemeFactor: json['encryptionSchemeFactor'] as num,
      modifyEncryptionSchemeOnLogin:
          json['modifyEncryptionSchemeOnLogin'] as bool,
    );

Map<String, dynamic> _$PasswordEncryptionConfigurationToJson(
        PasswordEncryptionConfiguration instance) =>
    <String, dynamic>{
      'encryptionScheme': instance.encryptionScheme,
      'encryptionSchemeFactor': instance.encryptionSchemeFactor,
      'modifyEncryptionSchemeOnLogin': instance.modifyEncryptionSchemeOnLogin,
    };

PasswordlessConfiguration _$PasswordlessConfigurationFromJson(
        Map<String, dynamic> json) =>
    PasswordlessConfiguration()..enabled = json['enabled'] as bool;

Map<String, dynamic> _$PasswordlessConfigurationToJson(
        PasswordlessConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
    };

PasswordlessIdentityProvider _$PasswordlessIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    PasswordlessIdentityProvider();

Map<String, dynamic> _$PasswordlessIdentityProviderToJson(
        PasswordlessIdentityProvider instance) =>
    <String, dynamic>{};

PasswordlessLoginRequest _$PasswordlessLoginRequestFromJson(
        Map<String, dynamic> json) =>
    PasswordlessLoginRequest(
      code: json['code'] as String,
      twoFactorTrustId: json['twoFactorTrustId'] as String,
    )
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>)
      ..applicationId = json['applicationId'] as String
      ..ipAddress = json['ipAddress'] as String
      ..metaData = MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
      ..newDevice = json['newDevice'] as bool
      ..noJWT = json['noJWT'] as bool;

Map<String, dynamic> _$PasswordlessLoginRequestToJson(
        PasswordlessLoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
      'code': instance.code,
      'twoFactorTrustId': instance.twoFactorTrustId,
    };

PasswordlessSendRequest _$PasswordlessSendRequestFromJson(
        Map<String, dynamic> json) =>
    PasswordlessSendRequest(
      applicationId: json['applicationId'] as String,
      code: json['code'] as String,
      loginId: json['loginId'] as String,
      state: json['state'] as Map<String, dynamic>,
    );

Map<String, dynamic> _$PasswordlessSendRequestToJson(
        PasswordlessSendRequest instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'code': instance.code,
      'loginId': instance.loginId,
      'state': instance.state,
    };

PasswordlessStartRequest _$PasswordlessStartRequestFromJson(
        Map<String, dynamic> json) =>
    PasswordlessStartRequest(
      applicationId: json['applicationId'] as String,
      loginId: json['loginId'] as String,
      state: json['state'] as Map<String, dynamic>,
    );

Map<String, dynamic> _$PasswordlessStartRequestToJson(
        PasswordlessStartRequest instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'loginId': instance.loginId,
      'state': instance.state,
    };

PasswordlessStartResponse _$PasswordlessStartResponseFromJson(
        Map<String, dynamic> json) =>
    PasswordlessStartResponse(
      code: json['code'] as String,
    );

Map<String, dynamic> _$PasswordlessStartResponseToJson(
        PasswordlessStartResponse instance) =>
    <String, dynamic>{
      'code': instance.code,
    };

PasswordValidationRules _$PasswordValidationRulesFromJson(
        Map<String, dynamic> json) =>
    PasswordValidationRules(
      breachDetection: PasswordBreachDetection.fromJson(
          json['breachDetection'] as Map<String, dynamic>),
      maxLength: json['maxLength'] as num,
      minLength: json['minLength'] as num,
      rememberPreviousPasswords: RememberPreviousPasswords.fromJson(
          json['rememberPreviousPasswords'] as Map<String, dynamic>),
      requireMixedCase: json['requireMixedCase'] as bool,
      requireNonAlpha: json['requireNonAlpha'] as bool,
      requireNumber: json['requireNumber'] as bool,
      validateOnLogin: json['validateOnLogin'] as bool,
    );

Map<String, dynamic> _$PasswordValidationRulesToJson(
        PasswordValidationRules instance) =>
    <String, dynamic>{
      'breachDetection': instance.breachDetection,
      'maxLength': instance.maxLength,
      'minLength': instance.minLength,
      'rememberPreviousPasswords': instance.rememberPreviousPasswords,
      'requireMixedCase': instance.requireMixedCase,
      'requireNonAlpha': instance.requireNonAlpha,
      'requireNumber': instance.requireNumber,
      'validateOnLogin': instance.validateOnLogin,
    };

PasswordValidationRulesResponse _$PasswordValidationRulesResponseFromJson(
        Map<String, dynamic> json) =>
    PasswordValidationRulesResponse(
      passwordValidationRules: PasswordValidationRules.fromJson(
          json['passwordValidationRules'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$PasswordValidationRulesResponseToJson(
        PasswordValidationRulesResponse instance) =>
    <String, dynamic>{
      'passwordValidationRules': instance.passwordValidationRules,
    };

PendingIdPLink _$PendingIdPLinkFromJson(Map<String, dynamic> json) =>
    PendingIdPLink(
      displayName: json['displayName'] as String,
      email: json['email'] as String,
      identityProviderId: json['identityProviderId'] as String,
      identityProviderLinks: (json['identityProviderLinks'] as List<dynamic>)
          .map((e) => IdentityProviderLink.fromJson(e as Map<String, dynamic>))
          .toList(),
      identityProviderName: json['identityProviderName'] as String,
      identityProviderTenantConfiguration:
          IdentityProviderTenantConfiguration.fromJson(
              json['identityProviderTenantConfiguration']
                  as Map<String, dynamic>),
      identityProviderType: _$enumDecode(
          _$IdentityProviderTypeEnumMap, json['identityProviderType']),
      identityProviderUserId: json['identityProviderUserId'] as String,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
      username: json['username'] as String,
    );

Map<String, dynamic> _$PendingIdPLinkToJson(PendingIdPLink instance) =>
    <String, dynamic>{
      'displayName': instance.displayName,
      'email': instance.email,
      'identityProviderId': instance.identityProviderId,
      'identityProviderLinks': instance.identityProviderLinks,
      'identityProviderName': instance.identityProviderName,
      'identityProviderTenantConfiguration':
          instance.identityProviderTenantConfiguration,
      'identityProviderType':
          _$IdentityProviderTypeEnumMap[instance.identityProviderType],
      'identityProviderUserId': instance.identityProviderUserId,
      'user': instance.user,
      'username': instance.username,
    };

PendingResponse _$PendingResponseFromJson(Map<String, dynamic> json) =>
    PendingResponse(
      users: (json['users'] as List<dynamic>)
          .map((e) => User.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$PendingResponseToJson(PendingResponse instance) =>
    <String, dynamic>{
      'users': instance.users,
    };

PreviewMessageTemplateRequest _$PreviewMessageTemplateRequestFromJson(
        Map<String, dynamic> json) =>
    PreviewMessageTemplateRequest(
      locale: json['locale'] as String,
      messageTemplate: MessageTemplate.fromJson(
          json['messageTemplate'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$PreviewMessageTemplateRequestToJson(
        PreviewMessageTemplateRequest instance) =>
    <String, dynamic>{
      'locale': instance.locale,
      'messageTemplate': instance.messageTemplate,
    };

PreviewMessageTemplateResponse _$PreviewMessageTemplateResponseFromJson(
        Map<String, dynamic> json) =>
    PreviewMessageTemplateResponse(
      errors: Errors.fromJson(json['errors'] as Map<String, dynamic>),
      message: SMSMessage.fromJson(json['message'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$PreviewMessageTemplateResponseToJson(
        PreviewMessageTemplateResponse instance) =>
    <String, dynamic>{
      'errors': instance.errors,
      'message': instance.message,
    };

PreviewRequest _$PreviewRequestFromJson(Map<String, dynamic> json) =>
    PreviewRequest(
      emailTemplate:
          EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
      locale: json['locale'] as String,
    );

Map<String, dynamic> _$PreviewRequestToJson(PreviewRequest instance) =>
    <String, dynamic>{
      'emailTemplate': instance.emailTemplate,
      'locale': instance.locale,
    };

PreviewResponse _$PreviewResponseFromJson(Map<String, dynamic> json) =>
    PreviewResponse(
      email: Email.fromJson(json['email'] as Map<String, dynamic>),
      errors: Errors.fromJson(json['errors'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$PreviewResponseToJson(PreviewResponse instance) =>
    <String, dynamic>{
      'email': instance.email,
      'errors': instance.errors,
    };

PublicKeyResponse _$PublicKeyResponseFromJson(Map<String, dynamic> json) =>
    PublicKeyResponse(
      publicKey: json['publicKey'] as String,
      publicKeys: Map<String, String>.from(json['publicKeys'] as Map),
    );

Map<String, dynamic> _$PublicKeyResponseToJson(PublicKeyResponse instance) =>
    <String, dynamic>{
      'publicKey': instance.publicKey,
      'publicKeys': instance.publicKeys,
    };

RateLimitedRequestConfiguration _$RateLimitedRequestConfigurationFromJson(
        Map<String, dynamic> json) =>
    RateLimitedRequestConfiguration(
      limit: json['limit'] as num,
      timePeriodInSeconds: json['timePeriodInSeconds'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$RateLimitedRequestConfigurationToJson(
        RateLimitedRequestConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'limit': instance.limit,
      'timePeriodInSeconds': instance.timePeriodInSeconds,
    };

RawLogin _$RawLoginFromJson(Map<String, dynamic> json) => RawLogin(
      applicationId: json['applicationId'] as String,
      instant: json['instant'] as num,
      ipAddress: json['ipAddress'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$RawLoginToJson(RawLogin instance) => <String, dynamic>{
      'applicationId': instance.applicationId,
      'instant': instance.instant,
      'ipAddress': instance.ipAddress,
      'userId': instance.userId,
    };

ReactorMetrics _$ReactorMetricsFromJson(Map<String, dynamic> json) =>
    ReactorMetrics(
      breachedPasswordMetrics:
          (json['breachedPasswordMetrics'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            BreachedPasswordTenantMetric.fromJson(e as Map<String, dynamic>)),
      ),
    );

Map<String, dynamic> _$ReactorMetricsToJson(ReactorMetrics instance) =>
    <String, dynamic>{
      'breachedPasswordMetrics': instance.breachedPasswordMetrics,
    };

ReactorMetricsResponse _$ReactorMetricsResponseFromJson(
        Map<String, dynamic> json) =>
    ReactorMetricsResponse(
      metrics: ReactorMetrics.fromJson(json['metrics'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ReactorMetricsResponseToJson(
        ReactorMetricsResponse instance) =>
    <String, dynamic>{
      'metrics': instance.metrics,
    };

ReactorRequest _$ReactorRequestFromJson(Map<String, dynamic> json) =>
    ReactorRequest(
      license: json['license'] as String,
      licenseId: json['licenseId'] as String,
    );

Map<String, dynamic> _$ReactorRequestToJson(ReactorRequest instance) =>
    <String, dynamic>{
      'license': instance.license,
      'licenseId': instance.licenseId,
    };

ReactorResponse _$ReactorResponseFromJson(Map<String, dynamic> json) =>
    ReactorResponse(
      status: ReactorStatus.fromJson(json['status'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ReactorResponseToJson(ReactorResponse instance) =>
    <String, dynamic>{
      'status': instance.status,
    };

ReactorStatus _$ReactorStatusFromJson(Map<String, dynamic> json) =>
    ReactorStatus(
      advancedIdentityProviders: _$enumDecode(
          _$ReactorFeatureStatusEnumMap, json['advancedIdentityProviders']),
      advancedLambdas:
          _$enumDecode(_$ReactorFeatureStatusEnumMap, json['advancedLambdas']),
      advancedMultiFactorAuthentication: _$enumDecode(
          _$ReactorFeatureStatusEnumMap,
          json['advancedMultiFactorAuthentication']),
      advancedRegistration: _$enumDecode(
          _$ReactorFeatureStatusEnumMap, json['advancedRegistration']),
      applicationThemes: _$enumDecode(
          _$ReactorFeatureStatusEnumMap, json['applicationThemes']),
      breachedPasswordDetection: _$enumDecode(
          _$ReactorFeatureStatusEnumMap, json['breachedPasswordDetection']),
      connectors:
          _$enumDecode(_$ReactorFeatureStatusEnumMap, json['connectors']),
      entityManagement:
          _$enumDecode(_$ReactorFeatureStatusEnumMap, json['entityManagement']),
      expiration: json['expiration'] as String,
      licensed: json['licensed'] as bool,
      scimServer:
          _$enumDecode(_$ReactorFeatureStatusEnumMap, json['scimServer']),
      threatDetection:
          _$enumDecode(_$ReactorFeatureStatusEnumMap, json['threatDetection']),
    );

Map<String, dynamic> _$ReactorStatusToJson(ReactorStatus instance) =>
    <String, dynamic>{
      'advancedIdentityProviders':
          _$ReactorFeatureStatusEnumMap[instance.advancedIdentityProviders],
      'advancedLambdas':
          _$ReactorFeatureStatusEnumMap[instance.advancedLambdas],
      'advancedMultiFactorAuthentication': _$ReactorFeatureStatusEnumMap[
          instance.advancedMultiFactorAuthentication],
      'advancedRegistration':
          _$ReactorFeatureStatusEnumMap[instance.advancedRegistration],
      'applicationThemes':
          _$ReactorFeatureStatusEnumMap[instance.applicationThemes],
      'breachedPasswordDetection':
          _$ReactorFeatureStatusEnumMap[instance.breachedPasswordDetection],
      'connectors': _$ReactorFeatureStatusEnumMap[instance.connectors],
      'entityManagement':
          _$ReactorFeatureStatusEnumMap[instance.entityManagement],
      'expiration': instance.expiration,
      'licensed': instance.licensed,
      'scimServer': _$ReactorFeatureStatusEnumMap[instance.scimServer],
      'threatDetection':
          _$ReactorFeatureStatusEnumMap[instance.threatDetection],
    };

const _$ReactorFeatureStatusEnumMap = {
  ReactorFeatureStatus.ACTIVE: 'ACTIVE',
  ReactorFeatureStatus.DISCONNECTED: 'DISCONNECTED',
  ReactorFeatureStatus.PENDING: 'PENDING',
  ReactorFeatureStatus.DISABLED: 'DISABLED',
  ReactorFeatureStatus.UNKNOWN: 'UNKNOWN',
};

RecentLoginResponse _$RecentLoginResponseFromJson(Map<String, dynamic> json) =>
    RecentLoginResponse(
      logins: (json['logins'] as List<dynamic>)
          .map((e) => DisplayableRawLogin.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$RecentLoginResponseToJson(
        RecentLoginResponse instance) =>
    <String, dynamic>{
      'logins': instance.logins,
    };

RefreshRequest _$RefreshRequestFromJson(Map<String, dynamic> json) =>
    RefreshRequest(
      refreshToken: json['refreshToken'] as String,
      token: json['token'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$RefreshRequestToJson(RefreshRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'refreshToken': instance.refreshToken,
      'token': instance.token,
    };

RefreshResponse _$RefreshResponseFromJson(Map<String, dynamic> json) =>
    RefreshResponse();

Map<String, dynamic> _$RefreshResponseToJson(RefreshResponse instance) =>
    <String, dynamic>{};

RefreshToken _$RefreshTokenFromJson(Map<String, dynamic> json) => RefreshToken(
      applicationId: json['applicationId'] as String,
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      metaData: MetaData.fromJson(json['metaData'] as Map<String, dynamic>),
      startInstant: json['startInstant'] as num,
      tenantId: json['tenantId'] as String,
      token: json['token'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$RefreshTokenToJson(RefreshToken instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'metaData': instance.metaData,
      'startInstant': instance.startInstant,
      'tenantId': instance.tenantId,
      'token': instance.token,
      'userId': instance.userId,
    };

RefreshTokenImportRequest _$RefreshTokenImportRequestFromJson(
        Map<String, dynamic> json) =>
    RefreshTokenImportRequest(
      refreshTokens: (json['refreshTokens'] as List<dynamic>)
          .map((e) => RefreshToken.fromJson(e as Map<String, dynamic>))
          .toList(),
      validateDbConstraints: json['validateDbConstraints'] as bool,
    );

Map<String, dynamic> _$RefreshTokenImportRequestToJson(
        RefreshTokenImportRequest instance) =>
    <String, dynamic>{
      'refreshTokens': instance.refreshTokens,
      'validateDbConstraints': instance.validateDbConstraints,
    };

RefreshTokenResponse _$RefreshTokenResponseFromJson(
        Map<String, dynamic> json) =>
    RefreshTokenResponse(
      refreshToken:
          RefreshToken.fromJson(json['refreshToken'] as Map<String, dynamic>),
      refreshTokens: (json['refreshTokens'] as List<dynamic>)
          .map((e) => RefreshToken.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$RefreshTokenResponseToJson(
        RefreshTokenResponse instance) =>
    <String, dynamic>{
      'refreshToken': instance.refreshToken,
      'refreshTokens': instance.refreshTokens,
    };

RefreshTokenRevocationPolicy _$RefreshTokenRevocationPolicyFromJson(
        Map<String, dynamic> json) =>
    RefreshTokenRevocationPolicy(
      onLoginPrevented: json['onLoginPrevented'] as bool,
      onPasswordChanged: json['onPasswordChanged'] as bool,
    );

Map<String, dynamic> _$RefreshTokenRevocationPolicyToJson(
        RefreshTokenRevocationPolicy instance) =>
    <String, dynamic>{
      'onLoginPrevented': instance.onLoginPrevented,
      'onPasswordChanged': instance.onPasswordChanged,
    };

RefreshTokenRevokeRequest _$RefreshTokenRevokeRequestFromJson(
        Map<String, dynamic> json) =>
    RefreshTokenRevokeRequest(
      applicationId: json['applicationId'] as String,
      token: json['token'] as String,
      userId: json['userId'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$RefreshTokenRevokeRequestToJson(
        RefreshTokenRevokeRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'token': instance.token,
      'userId': instance.userId,
    };

RegistrationConfiguration _$RegistrationConfigurationFromJson(
        Map<String, dynamic> json) =>
    RegistrationConfiguration(
      birthDate: Requirable.fromJson(json['birthDate'] as Map<String, dynamic>),
      confirmPassword: json['confirmPassword'] as bool,
      firstName: Requirable.fromJson(json['firstName'] as Map<String, dynamic>),
      formId: json['formId'] as String,
      fullName: Requirable.fromJson(json['fullName'] as Map<String, dynamic>),
      lastName: Requirable.fromJson(json['lastName'] as Map<String, dynamic>),
      loginIdType: _$enumDecode(_$LoginIdTypeEnumMap, json['loginIdType']),
      middleName:
          Requirable.fromJson(json['middleName'] as Map<String, dynamic>),
      mobilePhone:
          Requirable.fromJson(json['mobilePhone'] as Map<String, dynamic>),
      type: _$enumDecode(_$RegistrationTypeEnumMap, json['type']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$RegistrationConfigurationToJson(
        RegistrationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'birthDate': instance.birthDate,
      'confirmPassword': instance.confirmPassword,
      'firstName': instance.firstName,
      'formId': instance.formId,
      'fullName': instance.fullName,
      'lastName': instance.lastName,
      'loginIdType': _$LoginIdTypeEnumMap[instance.loginIdType],
      'middleName': instance.middleName,
      'mobilePhone': instance.mobilePhone,
      'type': _$RegistrationTypeEnumMap[instance.type],
    };

const _$LoginIdTypeEnumMap = {
  LoginIdType.email: 'email',
  LoginIdType.username: 'username',
};

const _$RegistrationTypeEnumMap = {
  RegistrationType.basic: 'basic',
  RegistrationType.advanced: 'advanced',
};

RegistrationDeleteRequest _$RegistrationDeleteRequestFromJson(
        Map<String, dynamic> json) =>
    RegistrationDeleteRequest()
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$RegistrationDeleteRequestToJson(
        RegistrationDeleteRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
    };

RegistrationReportResponse _$RegistrationReportResponseFromJson(
        Map<String, dynamic> json) =>
    RegistrationReportResponse(
      hourlyCounts: (json['hourlyCounts'] as List<dynamic>)
          .map((e) => Count.fromJson(e as Map<String, dynamic>))
          .toList(),
      total: json['total'] as num,
    );

Map<String, dynamic> _$RegistrationReportResponseToJson(
        RegistrationReportResponse instance) =>
    <String, dynamic>{
      'hourlyCounts': instance.hourlyCounts,
      'total': instance.total,
    };

RegistrationRequest _$RegistrationRequestFromJson(Map<String, dynamic> json) =>
    RegistrationRequest(
      disableDomainBlock: json['disableDomainBlock'] as bool,
      generateAuthenticationToken: json['generateAuthenticationToken'] as bool,
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      sendSetPasswordEmail: json['sendSetPasswordEmail'] as bool,
      skipRegistrationVerification:
          json['skipRegistrationVerification'] as bool,
      skipVerification: json['skipVerification'] as bool,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$RegistrationRequestToJson(
        RegistrationRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'disableDomainBlock': instance.disableDomainBlock,
      'generateAuthenticationToken': instance.generateAuthenticationToken,
      'registration': instance.registration,
      'sendSetPasswordEmail': instance.sendSetPasswordEmail,
      'skipRegistrationVerification': instance.skipRegistrationVerification,
      'skipVerification': instance.skipVerification,
      'user': instance.user,
    };

RegistrationResponse _$RegistrationResponseFromJson(
        Map<String, dynamic> json) =>
    RegistrationResponse(
      refreshToken: json['refreshToken'] as String,
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      registrationVerificationId: json['registrationVerificationId'] as String,
      token: json['token'] as String,
      tokenExpirationInstant: json['tokenExpirationInstant'] as num,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$RegistrationResponseToJson(
        RegistrationResponse instance) =>
    <String, dynamic>{
      'refreshToken': instance.refreshToken,
      'registration': instance.registration,
      'registrationVerificationId': instance.registrationVerificationId,
      'token': instance.token,
      'tokenExpirationInstant': instance.tokenExpirationInstant,
      'user': instance.user,
    };

RegistrationUnverifiedOptions _$RegistrationUnverifiedOptionsFromJson(
        Map<String, dynamic> json) =>
    RegistrationUnverifiedOptions(
      behavior: _$enumDecode(_$UnverifiedBehaviorEnumMap, json['behavior']),
    );

Map<String, dynamic> _$RegistrationUnverifiedOptionsToJson(
        RegistrationUnverifiedOptions instance) =>
    <String, dynamic>{
      'behavior': _$UnverifiedBehaviorEnumMap[instance.behavior],
    };

ReindexRequest _$ReindexRequestFromJson(Map<String, dynamic> json) =>
    ReindexRequest(
      index: json['index'] as String,
    );

Map<String, dynamic> _$ReindexRequestToJson(ReindexRequest instance) =>
    <String, dynamic>{
      'index': instance.index,
    };

ReloadRequest _$ReloadRequestFromJson(Map<String, dynamic> json) =>
    ReloadRequest(
      names: (json['names'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$ReloadRequestToJson(ReloadRequest instance) =>
    <String, dynamic>{
      'names': instance.names,
    };

RememberPreviousPasswords _$RememberPreviousPasswordsFromJson(
        Map<String, dynamic> json) =>
    RememberPreviousPasswords(
      count: json['count'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$RememberPreviousPasswordsToJson(
        RememberPreviousPasswords instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'count': instance.count,
    };

Requirable _$RequirableFromJson(Map<String, dynamic> json) => Requirable(
      required: json['required'] as bool,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$RequirableToJson(Requirable instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'required': instance.required,
    };

RequiresCORSConfiguration _$RequiresCORSConfigurationFromJson(
        Map<String, dynamic> json) =>
    RequiresCORSConfiguration();

Map<String, dynamic> _$RequiresCORSConfigurationToJson(
        RequiresCORSConfiguration instance) =>
    <String, dynamic>{};

SAMLv2ApplicationConfiguration _$SAMLv2ApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    SAMLv2ApplicationConfiguration(
      buttonImageURL: json['buttonImageURL'] as String,
      buttonText: json['buttonText'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$SAMLv2ApplicationConfigurationToJson(
        SAMLv2ApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonImageURL': instance.buttonImageURL,
      'buttonText': instance.buttonText,
    };

SAMLv2Configuration _$SAMLv2ConfigurationFromJson(Map<String, dynamic> json) =>
    SAMLv2Configuration(
      audience: json['audience'] as String,
      authorizedRedirectURLs: (json['authorizedRedirectURLs'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      callbackURL: json['callbackURL'] as String,
      debug: json['debug'] as bool,
      defaultVerificationKeyId: json['defaultVerificationKeyId'] as String,
      issuer: json['issuer'] as String,
      keyId: json['keyId'] as String,
      logout: SAMLv2Logout.fromJson(json['logout'] as Map<String, dynamic>),
      logoutURL: json['logoutURL'] as String,
      requireSignedRequests: json['requireSignedRequests'] as bool,
      xmlSignatureC14nMethod: _$enumDecode(
          _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
      xmlSignatureLocation: _$enumDecode(
          _$XMLSignatureLocationEnumMap, json['xmlSignatureLocation']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$SAMLv2ConfigurationToJson(
        SAMLv2Configuration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'audience': instance.audience,
      'authorizedRedirectURLs': instance.authorizedRedirectURLs,
      'callbackURL': instance.callbackURL,
      'debug': instance.debug,
      'defaultVerificationKeyId': instance.defaultVerificationKeyId,
      'issuer': instance.issuer,
      'keyId': instance.keyId,
      'logout': instance.logout,
      'logoutURL': instance.logoutURL,
      'requireSignedRequests': instance.requireSignedRequests,
      'xmlSignatureC14nMethod':
          _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod],
      'xmlSignatureLocation':
          _$XMLSignatureLocationEnumMap[instance.xmlSignatureLocation],
    };

const _$CanonicalizationMethodEnumMap = {
  CanonicalizationMethod.exclusive: 'exclusive',
  CanonicalizationMethod.exclusive_with_comments: 'exclusive_with_comments',
  CanonicalizationMethod.inclusive: 'inclusive',
  CanonicalizationMethod.inclusive_with_comments: 'inclusive_with_comments',
};

const _$XMLSignatureLocationEnumMap = {
  XMLSignatureLocation.Assertion: 'Assertion',
  XMLSignatureLocation.Response: 'Response',
};

SAMLv2IdentityProvider _$SAMLv2IdentityProviderFromJson(
        Map<String, dynamic> json) =>
    SAMLv2IdentityProvider(
      buttonImageURL: json['buttonImageURL'] as String,
      buttonText: json['buttonText'] as String,
      domains:
          (json['domains'] as List<dynamic>).map((e) => e as String).toSet(),
      emailClaim: json['emailClaim'] as String,
      idpEndpoint: json['idpEndpoint'] as String,
      issuer: json['issuer'] as String,
      keyId: json['keyId'] as String,
      nameIdFormat: json['nameIdFormat'] as String,
      postRequest: json['postRequest'] as bool,
      requestSigningKeyId: json['requestSigningKeyId'] as String,
      signRequest: json['signRequest'] as bool,
      uniqueIdClaim: json['uniqueIdClaim'] as String,
      useNameIdForEmail: json['useNameIdForEmail'] as bool,
      usernameClaim: json['usernameClaim'] as String,
      xmlSignatureC14nMethod: _$enumDecode(
          _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            SAMLv2ApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$SAMLv2IdentityProviderToJson(
    SAMLv2IdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonImageURL'] = instance.buttonImageURL;
  val['buttonText'] = instance.buttonText;
  val['domains'] = instance.domains.toList();
  val['emailClaim'] = instance.emailClaim;
  val['idpEndpoint'] = instance.idpEndpoint;
  val['issuer'] = instance.issuer;
  val['keyId'] = instance.keyId;
  val['nameIdFormat'] = instance.nameIdFormat;
  val['postRequest'] = instance.postRequest;
  val['requestSigningKeyId'] = instance.requestSigningKeyId;
  val['signRequest'] = instance.signRequest;
  val['uniqueIdClaim'] = instance.uniqueIdClaim;
  val['useNameIdForEmail'] = instance.useNameIdForEmail;
  val['usernameClaim'] = instance.usernameClaim;
  val['xmlSignatureC14nMethod'] =
      _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod];
  return val;
}

SAMLv2IdPInitiatedApplicationConfiguration
    _$SAMLv2IdPInitiatedApplicationConfigurationFromJson(
            Map<String, dynamic> json) =>
        SAMLv2IdPInitiatedApplicationConfiguration()
          ..enabled = json['enabled'] as bool
          ..createRegistration = json['createRegistration'] as bool
          ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$SAMLv2IdPInitiatedApplicationConfigurationToJson(
        SAMLv2IdPInitiatedApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
    };

SAMLv2IdPInitiatedIdentityProvider _$SAMLv2IdPInitiatedIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    SAMLv2IdPInitiatedIdentityProvider(
      emailClaim: json['emailClaim'] as String,
      issuer: json['issuer'] as String,
      keyId: json['keyId'] as String,
      uniqueIdClaim: json['uniqueIdClaim'] as String,
      useNameIdForEmail: json['useNameIdForEmail'] as bool,
      usernameClaim: json['usernameClaim'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            SAMLv2IdPInitiatedApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$SAMLv2IdPInitiatedIdentityProviderToJson(
    SAMLv2IdPInitiatedIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['emailClaim'] = instance.emailClaim;
  val['issuer'] = instance.issuer;
  val['keyId'] = instance.keyId;
  val['uniqueIdClaim'] = instance.uniqueIdClaim;
  val['useNameIdForEmail'] = instance.useNameIdForEmail;
  val['usernameClaim'] = instance.usernameClaim;
  return val;
}

SAMLv2Logout _$SAMLv2LogoutFromJson(Map<String, dynamic> json) => SAMLv2Logout(
      behavior: _$enumDecode(_$SAMLLogoutBehaviorEnumMap, json['behavior']),
      defaultVerificationKeyId: json['defaultVerificationKeyId'] as String,
      keyId: json['keyId'] as String,
      requireSignedRequests: json['requireSignedRequests'] as bool,
      singleLogout: SAMLv2SingleLogout.fromJson(
          json['singleLogout'] as Map<String, dynamic>),
      xmlSignatureC14nMethod: _$enumDecode(
          _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
    );

Map<String, dynamic> _$SAMLv2LogoutToJson(SAMLv2Logout instance) =>
    <String, dynamic>{
      'behavior': _$SAMLLogoutBehaviorEnumMap[instance.behavior],
      'defaultVerificationKeyId': instance.defaultVerificationKeyId,
      'keyId': instance.keyId,
      'requireSignedRequests': instance.requireSignedRequests,
      'singleLogout': instance.singleLogout,
      'xmlSignatureC14nMethod':
          _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod],
    };

const _$SAMLLogoutBehaviorEnumMap = {
  SAMLLogoutBehavior.AllParticipants: 'AllParticipants',
  SAMLLogoutBehavior.OnlyOriginator: 'OnlyOriginator',
};

SAMLv2SingleLogout _$SAMLv2SingleLogoutFromJson(Map<String, dynamic> json) =>
    SAMLv2SingleLogout(
      keyId: json['keyId'] as String,
      url: json['url'] as String,
      xmlSignatureC14nMethod: _$enumDecode(
          _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$SAMLv2SingleLogoutToJson(SAMLv2SingleLogout instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'keyId': instance.keyId,
      'url': instance.url,
      'xmlSignatureC14nMethod':
          _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod],
    };

SearchRequest _$SearchRequestFromJson(Map<String, dynamic> json) =>
    SearchRequest(
      search:
          UserSearchCriteria.fromJson(json['search'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$SearchRequestToJson(SearchRequest instance) =>
    <String, dynamic>{
      'search': instance.search,
    };

SearchResponse _$SearchResponseFromJson(Map<String, dynamic> json) =>
    SearchResponse(
      total: json['total'] as num,
      users: (json['users'] as List<dynamic>)
          .map((e) => User.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$SearchResponseToJson(SearchResponse instance) =>
    <String, dynamic>{
      'total': instance.total,
      'users': instance.users,
    };

SecretResponse _$SecretResponseFromJson(Map<String, dynamic> json) =>
    SecretResponse(
      secret: json['secret'] as String,
      secretBase32Encoded: json['secretBase32Encoded'] as String,
    );

Map<String, dynamic> _$SecretResponseToJson(SecretResponse instance) =>
    <String, dynamic>{
      'secret': instance.secret,
      'secretBase32Encoded': instance.secretBase32Encoded,
    };

SecureGeneratorConfiguration _$SecureGeneratorConfigurationFromJson(
        Map<String, dynamic> json) =>
    SecureGeneratorConfiguration(
      length: json['length'] as num,
      type: _$enumDecode(_$SecureGeneratorTypeEnumMap, json['type']),
    );

Map<String, dynamic> _$SecureGeneratorConfigurationToJson(
        SecureGeneratorConfiguration instance) =>
    <String, dynamic>{
      'length': instance.length,
      'type': _$SecureGeneratorTypeEnumMap[instance.type],
    };

const _$SecureGeneratorTypeEnumMap = {
  SecureGeneratorType.randomDigits: 'randomDigits',
  SecureGeneratorType.randomBytes: 'randomBytes',
  SecureGeneratorType.randomAlpha: 'randomAlpha',
  SecureGeneratorType.randomAlphaNumeric: 'randomAlphaNumeric',
};

SecureIdentity _$SecureIdentityFromJson(Map<String, dynamic> json) =>
    SecureIdentity(
      breachedPasswordLastCheckedInstant:
          json['breachedPasswordLastCheckedInstant'] as num,
      breachedPasswordStatus: _$enumDecode(
          _$BreachedPasswordStatusEnumMap, json['breachedPasswordStatus']),
      connectorId: json['connectorId'] as String,
      encryptionScheme: json['encryptionScheme'] as String,
      factor: json['factor'] as num,
      id: json['id'] as String,
      lastLoginInstant: json['lastLoginInstant'] as num,
      password: json['password'] as String,
      passwordChangeReason: _$enumDecode(
          _$ChangePasswordReasonEnumMap, json['passwordChangeReason']),
      passwordChangeRequired: json['passwordChangeRequired'] as bool,
      passwordLastUpdateInstant: json['passwordLastUpdateInstant'] as num,
      salt: json['salt'] as String,
      uniqueUsername: json['uniqueUsername'] as String,
      username: json['username'] as String,
      usernameStatus:
          _$enumDecode(_$ContentStatusEnumMap, json['usernameStatus']),
      verified: json['verified'] as bool,
    );

Map<String, dynamic> _$SecureIdentityToJson(SecureIdentity instance) =>
    <String, dynamic>{
      'breachedPasswordLastCheckedInstant':
          instance.breachedPasswordLastCheckedInstant,
      'breachedPasswordStatus':
          _$BreachedPasswordStatusEnumMap[instance.breachedPasswordStatus],
      'connectorId': instance.connectorId,
      'encryptionScheme': instance.encryptionScheme,
      'factor': instance.factor,
      'id': instance.id,
      'lastLoginInstant': instance.lastLoginInstant,
      'password': instance.password,
      'passwordChangeReason':
          _$ChangePasswordReasonEnumMap[instance.passwordChangeReason],
      'passwordChangeRequired': instance.passwordChangeRequired,
      'passwordLastUpdateInstant': instance.passwordLastUpdateInstant,
      'salt': instance.salt,
      'uniqueUsername': instance.uniqueUsername,
      'username': instance.username,
      'usernameStatus': _$ContentStatusEnumMap[instance.usernameStatus],
      'verified': instance.verified,
    };

const _$BreachedPasswordStatusEnumMap = {
  BreachedPasswordStatus.None: 'None',
  BreachedPasswordStatus.ExactMatch: 'ExactMatch',
  BreachedPasswordStatus.SubAddressMatch: 'SubAddressMatch',
  BreachedPasswordStatus.PasswordOnly: 'PasswordOnly',
  BreachedPasswordStatus.CommonPassword: 'CommonPassword',
};

const _$ContentStatusEnumMap = {
  ContentStatus.ACTIVE: 'ACTIVE',
  ContentStatus.PENDING: 'PENDING',
  ContentStatus.REJECTED: 'REJECTED',
};

SendRequest _$SendRequestFromJson(Map<String, dynamic> json) => SendRequest(
      applicationId: json['applicationId'] as String,
      bccAddresses: (json['bccAddresses'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      ccAddresses: (json['ccAddresses'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      preferredLanguages: (json['preferredLanguages'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      requestData: json['requestData'] as Map<String, dynamic>,
      toAddresses: (json['toAddresses'] as List<dynamic>)
          .map((e) => EmailAddress.fromJson(e as Map<String, dynamic>))
          .toList(),
      userIds:
          (json['userIds'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$SendRequestToJson(SendRequest instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'bccAddresses': instance.bccAddresses,
      'ccAddresses': instance.ccAddresses,
      'preferredLanguages': instance.preferredLanguages,
      'requestData': instance.requestData,
      'toAddresses': instance.toAddresses,
      'userIds': instance.userIds,
    };

SendResponse _$SendResponseFromJson(Map<String, dynamic> json) => SendResponse(
      anonymousResults: (json['anonymousResults'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k, EmailTemplateErrors.fromJson(e as Map<String, dynamic>)),
      ),
      results: (json['results'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k, EmailTemplateErrors.fromJson(e as Map<String, dynamic>)),
      ),
    );

Map<String, dynamic> _$SendResponseToJson(SendResponse instance) =>
    <String, dynamic>{
      'anonymousResults': instance.anonymousResults,
      'results': instance.results,
    };

SMSMessage _$SMSMessageFromJson(Map<String, dynamic> json) => SMSMessage(
      phoneNumber: json['phoneNumber'] as String,
      textMessage: json['textMessage'] as String,
    );

Map<String, dynamic> _$SMSMessageToJson(SMSMessage instance) =>
    <String, dynamic>{
      'phoneNumber': instance.phoneNumber,
      'textMessage': instance.textMessage,
    };

SMSMessageTemplate _$SMSMessageTemplateFromJson(Map<String, dynamic> json) =>
    SMSMessageTemplate(
      defaultTemplate: json['defaultTemplate'] as String,
      localizedTemplates:
          Map<String, String>.from(json['localizedTemplates'] as Map),
    )
      ..data = json['data'] as Map<String, dynamic>
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..type = _$enumDecode(_$MessageTypeEnumMap, json['type']);

Map<String, dynamic> _$SMSMessageTemplateToJson(SMSMessageTemplate instance) =>
    <String, dynamic>{
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'type': _$MessageTypeEnumMap[instance.type],
      'defaultTemplate': instance.defaultTemplate,
      'localizedTemplates': instance.localizedTemplates,
    };

SonyPSNApplicationConfiguration _$SonyPSNApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    SonyPSNApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$SonyPSNApplicationConfigurationToJson(
        SonyPSNApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'scope': instance.scope,
    };

SonyPSNIdentityProvider _$SonyPSNIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    SonyPSNIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            SonyPSNApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$SonyPSNIdentityProviderToJson(
    SonyPSNIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['scope'] = instance.scope;
  return val;
}

SortField _$SortFieldFromJson(Map<String, dynamic> json) => SortField(
      missing: json['missing'] as String,
      name: json['name'] as String,
      order: _$enumDecode(_$SortEnumMap, json['order']),
    );

Map<String, dynamic> _$SortFieldToJson(SortField instance) => <String, dynamic>{
      'missing': instance.missing,
      'name': instance.name,
      'order': _$SortEnumMap[instance.order],
    };

const _$SortEnumMap = {
  Sort.asc: 'asc',
  Sort.desc: 'desc',
};

SteamApplicationConfiguration _$SteamApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    SteamApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      scope: json['scope'] as String,
      webAPIKey: json['webAPIKey'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$SteamApplicationConfigurationToJson(
        SteamApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'scope': instance.scope,
      'webAPIKey': instance.webAPIKey,
    };

SteamIdentityProvider _$SteamIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    SteamIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      scope: json['scope'] as String,
      webAPIKey: json['webAPIKey'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            SteamApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$SteamIdentityProviderToJson(
    SteamIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['scope'] = instance.scope;
  val['webAPIKey'] = instance.webAPIKey;
  return val;
}

SupportsPostBindings _$SupportsPostBindingsFromJson(
        Map<String, dynamic> json) =>
    SupportsPostBindings();

Map<String, dynamic> _$SupportsPostBindingsToJson(
        SupportsPostBindings instance) =>
    <String, dynamic>{};

SystemConfiguration _$SystemConfigurationFromJson(Map<String, dynamic> json) =>
    SystemConfiguration(
      auditLogConfiguration: AuditLogConfiguration.fromJson(
          json['auditLogConfiguration'] as Map<String, dynamic>),
      corsConfiguration: CORSConfiguration.fromJson(
          json['corsConfiguration'] as Map<String, dynamic>),
      data: json['data'] as Map<String, dynamic>,
      eventLogConfiguration: EventLogConfiguration.fromJson(
          json['eventLogConfiguration'] as Map<String, dynamic>),
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      loginRecordConfiguration: LoginRecordConfiguration.fromJson(
          json['loginRecordConfiguration'] as Map<String, dynamic>),
      reportTimezone: json['reportTimezone'] as String,
      uiConfiguration: UIConfiguration.fromJson(
          json['uiConfiguration'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$SystemConfigurationToJson(
        SystemConfiguration instance) =>
    <String, dynamic>{
      'auditLogConfiguration': instance.auditLogConfiguration,
      'corsConfiguration': instance.corsConfiguration,
      'data': instance.data,
      'eventLogConfiguration': instance.eventLogConfiguration,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'loginRecordConfiguration': instance.loginRecordConfiguration,
      'reportTimezone': instance.reportTimezone,
      'uiConfiguration': instance.uiConfiguration,
    };

SystemConfigurationRequest _$SystemConfigurationRequestFromJson(
        Map<String, dynamic> json) =>
    SystemConfigurationRequest(
      systemConfiguration: SystemConfiguration.fromJson(
          json['systemConfiguration'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$SystemConfigurationRequestToJson(
        SystemConfigurationRequest instance) =>
    <String, dynamic>{
      'systemConfiguration': instance.systemConfiguration,
    };

SystemConfigurationResponse _$SystemConfigurationResponseFromJson(
        Map<String, dynamic> json) =>
    SystemConfigurationResponse(
      systemConfiguration: SystemConfiguration.fromJson(
          json['systemConfiguration'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$SystemConfigurationResponseToJson(
        SystemConfigurationResponse instance) =>
    <String, dynamic>{
      'systemConfiguration': instance.systemConfiguration,
    };

SystemLogsExportRequest _$SystemLogsExportRequestFromJson(
        Map<String, dynamic> json) =>
    SystemLogsExportRequest(
      lastNBytes: json['lastNBytes'] as num,
    )
      ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
      ..zoneId = json['zoneId'] as String;

Map<String, dynamic> _$SystemLogsExportRequestToJson(
        SystemLogsExportRequest instance) =>
    <String, dynamic>{
      'dateTimeSecondsFormat': instance.dateTimeSecondsFormat,
      'zoneId': instance.zoneId,
      'lastNBytes': instance.lastNBytes,
    };

Templates _$TemplatesFromJson(Map<String, dynamic> json) => Templates(
      accountEdit: json['accountEdit'] as String,
      accountIndex: json['accountIndex'] as String,
      accountTwoFactorDisable: json['accountTwoFactorDisable'] as String,
      accountTwoFactorEnable: json['accountTwoFactorEnable'] as String,
      accountTwoFactorIndex: json['accountTwoFactorIndex'] as String,
      emailComplete: json['emailComplete'] as String,
      emailSend: json['emailSend'] as String,
      emailSent: json['emailSent'] as String,
      emailVerificationRequired: json['emailVerificationRequired'] as String,
      emailVerify: json['emailVerify'] as String,
      helpers: json['helpers'] as String,
      index: json['index'] as String,
      oauth2Authorize: json['oauth2Authorize'] as String,
      oauth2AuthorizedNotRegistered:
          json['oauth2AuthorizedNotRegistered'] as String,
      oauth2ChildRegistrationNotAllowed:
          json['oauth2ChildRegistrationNotAllowed'] as String,
      oauth2ChildRegistrationNotAllowedComplete:
          json['oauth2ChildRegistrationNotAllowedComplete'] as String,
      oauth2CompleteRegistration: json['oauth2CompleteRegistration'] as String,
      oauth2Device: json['oauth2Device'] as String,
      oauth2DeviceComplete: json['oauth2DeviceComplete'] as String,
      oauth2Error: json['oauth2Error'] as String,
      oauth2Logout: json['oauth2Logout'] as String,
      oauth2Passwordless: json['oauth2Passwordless'] as String,
      oauth2Register: json['oauth2Register'] as String,
      oauth2StartIdPLink: json['oauth2StartIdPLink'] as String,
      oauth2TwoFactor: json['oauth2TwoFactor'] as String,
      oauth2TwoFactorMethods: json['oauth2TwoFactorMethods'] as String,
      oauth2Wait: json['oauth2Wait'] as String,
      passwordChange: json['passwordChange'] as String,
      passwordComplete: json['passwordComplete'] as String,
      passwordForgot: json['passwordForgot'] as String,
      passwordSent: json['passwordSent'] as String,
      registrationComplete: json['registrationComplete'] as String,
      registrationSend: json['registrationSend'] as String,
      registrationSent: json['registrationSent'] as String,
      registrationVerificationRequired:
          json['registrationVerificationRequired'] as String,
      registrationVerify: json['registrationVerify'] as String,
      samlv2Logout: json['samlv2Logout'] as String,
      unauthorized: json['unauthorized'] as String,
    );

Map<String, dynamic> _$TemplatesToJson(Templates instance) => <String, dynamic>{
      'accountEdit': instance.accountEdit,
      'accountIndex': instance.accountIndex,
      'accountTwoFactorDisable': instance.accountTwoFactorDisable,
      'accountTwoFactorEnable': instance.accountTwoFactorEnable,
      'accountTwoFactorIndex': instance.accountTwoFactorIndex,
      'emailComplete': instance.emailComplete,
      'emailSend': instance.emailSend,
      'emailSent': instance.emailSent,
      'emailVerificationRequired': instance.emailVerificationRequired,
      'emailVerify': instance.emailVerify,
      'helpers': instance.helpers,
      'index': instance.index,
      'oauth2Authorize': instance.oauth2Authorize,
      'oauth2AuthorizedNotRegistered': instance.oauth2AuthorizedNotRegistered,
      'oauth2ChildRegistrationNotAllowed':
          instance.oauth2ChildRegistrationNotAllowed,
      'oauth2ChildRegistrationNotAllowedComplete':
          instance.oauth2ChildRegistrationNotAllowedComplete,
      'oauth2CompleteRegistration': instance.oauth2CompleteRegistration,
      'oauth2Device': instance.oauth2Device,
      'oauth2DeviceComplete': instance.oauth2DeviceComplete,
      'oauth2Error': instance.oauth2Error,
      'oauth2Logout': instance.oauth2Logout,
      'oauth2Passwordless': instance.oauth2Passwordless,
      'oauth2Register': instance.oauth2Register,
      'oauth2StartIdPLink': instance.oauth2StartIdPLink,
      'oauth2TwoFactor': instance.oauth2TwoFactor,
      'oauth2TwoFactorMethods': instance.oauth2TwoFactorMethods,
      'oauth2Wait': instance.oauth2Wait,
      'passwordChange': instance.passwordChange,
      'passwordComplete': instance.passwordComplete,
      'passwordForgot': instance.passwordForgot,
      'passwordSent': instance.passwordSent,
      'registrationComplete': instance.registrationComplete,
      'registrationSend': instance.registrationSend,
      'registrationSent': instance.registrationSent,
      'registrationVerificationRequired':
          instance.registrationVerificationRequired,
      'registrationVerify': instance.registrationVerify,
      'samlv2Logout': instance.samlv2Logout,
      'unauthorized': instance.unauthorized,
    };

Tenant _$TenantFromJson(Map<String, dynamic> json) => Tenant(
      accessControlConfiguration: TenantAccessControlConfiguration.fromJson(
          json['accessControlConfiguration'] as Map<String, dynamic>),
      captchaConfiguration: TenantCaptchaConfiguration.fromJson(
          json['captchaConfiguration'] as Map<String, dynamic>),
      configured: json['configured'] as bool,
      connectorPolicies: (json['connectorPolicies'] as List<dynamic>)
          .map((e) => ConnectorPolicy.fromJson(e as Map<String, dynamic>))
          .toList(),
      data: json['data'] as Map<String, dynamic>,
      emailConfiguration: EmailConfiguration.fromJson(
          json['emailConfiguration'] as Map<String, dynamic>),
      eventConfiguration: EventConfiguration.fromJson(
          json['eventConfiguration'] as Map<String, dynamic>),
      externalIdentifierConfiguration: ExternalIdentifierConfiguration.fromJson(
          json['externalIdentifierConfiguration'] as Map<String, dynamic>),
      failedAuthenticationConfiguration:
          FailedAuthenticationConfiguration.fromJson(
              json['failedAuthenticationConfiguration']
                  as Map<String, dynamic>),
      familyConfiguration: FamilyConfiguration.fromJson(
          json['familyConfiguration'] as Map<String, dynamic>),
      formConfiguration: TenantFormConfiguration.fromJson(
          json['formConfiguration'] as Map<String, dynamic>),
      httpSessionMaxInactiveInterval:
          json['httpSessionMaxInactiveInterval'] as num,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      issuer: json['issuer'] as String,
      jwtConfiguration: JWTConfiguration.fromJson(
          json['jwtConfiguration'] as Map<String, dynamic>),
      lambdaConfiguration: TenantLambdaConfiguration.fromJson(
          json['lambdaConfiguration'] as Map<String, dynamic>),
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      loginConfiguration: TenantLoginConfiguration.fromJson(
          json['loginConfiguration'] as Map<String, dynamic>),
      logoutURL: json['logoutURL'] as String,
      maximumPasswordAge: MaximumPasswordAge.fromJson(
          json['maximumPasswordAge'] as Map<String, dynamic>),
      minimumPasswordAge: MinimumPasswordAge.fromJson(
          json['minimumPasswordAge'] as Map<String, dynamic>),
      multiFactorConfiguration: TenantMultiFactorConfiguration.fromJson(
          json['multiFactorConfiguration'] as Map<String, dynamic>),
      name: json['name'] as String,
      oauthConfiguration: TenantOAuth2Configuration.fromJson(
          json['oauthConfiguration'] as Map<String, dynamic>),
      passwordEncryptionConfiguration: PasswordEncryptionConfiguration.fromJson(
          json['passwordEncryptionConfiguration'] as Map<String, dynamic>),
      passwordValidationRules: PasswordValidationRules.fromJson(
          json['passwordValidationRules'] as Map<String, dynamic>),
      rateLimitConfiguration: TenantRateLimitConfiguration.fromJson(
          json['rateLimitConfiguration'] as Map<String, dynamic>),
      registrationConfiguration: TenantRegistrationConfiguration.fromJson(
          json['registrationConfiguration'] as Map<String, dynamic>),
      scimServerConfiguration: TenantSCIMServerConfiguration.fromJson(
          json['scimServerConfiguration'] as Map<String, dynamic>),
      ssoConfiguration: TenantSSOConfiguration.fromJson(
          json['ssoConfiguration'] as Map<String, dynamic>),
      state: _$enumDecode(_$ObjectStateEnumMap, json['state']),
      themeId: json['themeId'] as String,
      userDeletePolicy: TenantUserDeletePolicy.fromJson(
          json['userDeletePolicy'] as Map<String, dynamic>),
      usernameConfiguration: TenantUsernameConfiguration.fromJson(
          json['usernameConfiguration'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantToJson(Tenant instance) => <String, dynamic>{
      'accessControlConfiguration': instance.accessControlConfiguration,
      'captchaConfiguration': instance.captchaConfiguration,
      'configured': instance.configured,
      'connectorPolicies': instance.connectorPolicies,
      'data': instance.data,
      'emailConfiguration': instance.emailConfiguration,
      'eventConfiguration': instance.eventConfiguration,
      'externalIdentifierConfiguration':
          instance.externalIdentifierConfiguration,
      'failedAuthenticationConfiguration':
          instance.failedAuthenticationConfiguration,
      'familyConfiguration': instance.familyConfiguration,
      'formConfiguration': instance.formConfiguration,
      'httpSessionMaxInactiveInterval': instance.httpSessionMaxInactiveInterval,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'issuer': instance.issuer,
      'jwtConfiguration': instance.jwtConfiguration,
      'lambdaConfiguration': instance.lambdaConfiguration,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'loginConfiguration': instance.loginConfiguration,
      'logoutURL': instance.logoutURL,
      'maximumPasswordAge': instance.maximumPasswordAge,
      'minimumPasswordAge': instance.minimumPasswordAge,
      'multiFactorConfiguration': instance.multiFactorConfiguration,
      'name': instance.name,
      'oauthConfiguration': instance.oauthConfiguration,
      'passwordEncryptionConfiguration':
          instance.passwordEncryptionConfiguration,
      'passwordValidationRules': instance.passwordValidationRules,
      'rateLimitConfiguration': instance.rateLimitConfiguration,
      'registrationConfiguration': instance.registrationConfiguration,
      'scimServerConfiguration': instance.scimServerConfiguration,
      'ssoConfiguration': instance.ssoConfiguration,
      'state': _$ObjectStateEnumMap[instance.state],
      'themeId': instance.themeId,
      'userDeletePolicy': instance.userDeletePolicy,
      'usernameConfiguration': instance.usernameConfiguration,
    };

Tenantable _$TenantableFromJson(Map<String, dynamic> json) => Tenantable();

Map<String, dynamic> _$TenantableToJson(Tenantable instance) =>
    <String, dynamic>{};

TenantAccessControlConfiguration _$TenantAccessControlConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantAccessControlConfiguration(
      uiIPAccessControlListId: json['uiIPAccessControlListId'] as String,
    );

Map<String, dynamic> _$TenantAccessControlConfigurationToJson(
        TenantAccessControlConfiguration instance) =>
    <String, dynamic>{
      'uiIPAccessControlListId': instance.uiIPAccessControlListId,
    };

TenantCaptchaConfiguration _$TenantCaptchaConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantCaptchaConfiguration(
      captchaMethod:
          _$enumDecode(_$CaptchaMethodEnumMap, json['captchaMethod']),
      secretKey: json['secretKey'] as String,
      siteKey: json['siteKey'] as String,
      threshold: json['threshold'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$TenantCaptchaConfigurationToJson(
        TenantCaptchaConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'captchaMethod': _$CaptchaMethodEnumMap[instance.captchaMethod],
      'secretKey': instance.secretKey,
      'siteKey': instance.siteKey,
      'threshold': instance.threshold,
    };

const _$CaptchaMethodEnumMap = {
  CaptchaMethod.GoogleRecaptchaV2: 'GoogleRecaptchaV2',
  CaptchaMethod.GoogleRecaptchaV3: 'GoogleRecaptchaV3',
  CaptchaMethod.HCaptcha: 'HCaptcha',
  CaptchaMethod.HCaptchaEnterprise: 'HCaptchaEnterprise',
};

TenantDeleteRequest _$TenantDeleteRequestFromJson(Map<String, dynamic> json) =>
    TenantDeleteRequest(
      async: json['async'] as bool,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$TenantDeleteRequestToJson(
        TenantDeleteRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'async': instance.async,
    };

TenantFormConfiguration _$TenantFormConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantFormConfiguration(
      adminUserFormId: json['adminUserFormId'] as String,
    );

Map<String, dynamic> _$TenantFormConfigurationToJson(
        TenantFormConfiguration instance) =>
    <String, dynamic>{
      'adminUserFormId': instance.adminUserFormId,
    };

TenantLambdaConfiguration _$TenantLambdaConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantLambdaConfiguration(
      scimEnterpriseUserRequestConverterId:
          json['scimEnterpriseUserRequestConverterId'] as String,
      scimEnterpriseUserResponseConverterId:
          json['scimEnterpriseUserResponseConverterId'] as String,
      scimGroupRequestConverterId:
          json['scimGroupRequestConverterId'] as String,
      scimGroupResponseConverterId:
          json['scimGroupResponseConverterId'] as String,
      scimUserRequestConverterId: json['scimUserRequestConverterId'] as String,
      scimUserResponseConverterId:
          json['scimUserResponseConverterId'] as String,
    );

Map<String, dynamic> _$TenantLambdaConfigurationToJson(
        TenantLambdaConfiguration instance) =>
    <String, dynamic>{
      'scimEnterpriseUserRequestConverterId':
          instance.scimEnterpriseUserRequestConverterId,
      'scimEnterpriseUserResponseConverterId':
          instance.scimEnterpriseUserResponseConverterId,
      'scimGroupRequestConverterId': instance.scimGroupRequestConverterId,
      'scimGroupResponseConverterId': instance.scimGroupResponseConverterId,
      'scimUserRequestConverterId': instance.scimUserRequestConverterId,
      'scimUserResponseConverterId': instance.scimUserResponseConverterId,
    };

TenantLoginConfiguration _$TenantLoginConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantLoginConfiguration(
      requireAuthentication: json['requireAuthentication'] as bool,
    );

Map<String, dynamic> _$TenantLoginConfigurationToJson(
        TenantLoginConfiguration instance) =>
    <String, dynamic>{
      'requireAuthentication': instance.requireAuthentication,
    };

TenantMultiFactorConfiguration _$TenantMultiFactorConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantMultiFactorConfiguration(
      authenticator: MultiFactorAuthenticatorMethod.fromJson(
          json['authenticator'] as Map<String, dynamic>),
      email: MultiFactorEmailMethod.fromJson(
          json['email'] as Map<String, dynamic>),
      sms: MultiFactorSMSMethod.fromJson(json['sms'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantMultiFactorConfigurationToJson(
        TenantMultiFactorConfiguration instance) =>
    <String, dynamic>{
      'authenticator': instance.authenticator,
      'email': instance.email,
      'sms': instance.sms,
    };

TenantOAuth2Configuration _$TenantOAuth2ConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantOAuth2Configuration(
      clientCredentialsAccessTokenPopulateLambdaId:
          json['clientCredentialsAccessTokenPopulateLambdaId'] as String,
    );

Map<String, dynamic> _$TenantOAuth2ConfigurationToJson(
        TenantOAuth2Configuration instance) =>
    <String, dynamic>{
      'clientCredentialsAccessTokenPopulateLambdaId':
          instance.clientCredentialsAccessTokenPopulateLambdaId,
    };

TenantRateLimitConfiguration _$TenantRateLimitConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantRateLimitConfiguration(
      failedLogin: RateLimitedRequestConfiguration.fromJson(
          json['failedLogin'] as Map<String, dynamic>),
      forgotPassword: RateLimitedRequestConfiguration.fromJson(
          json['forgotPassword'] as Map<String, dynamic>),
      sendEmailVerification: RateLimitedRequestConfiguration.fromJson(
          json['sendEmailVerification'] as Map<String, dynamic>),
      sendPasswordless: RateLimitedRequestConfiguration.fromJson(
          json['sendPasswordless'] as Map<String, dynamic>),
      sendRegistrationVerification: RateLimitedRequestConfiguration.fromJson(
          json['sendRegistrationVerification'] as Map<String, dynamic>),
      sendTwoFactor: RateLimitedRequestConfiguration.fromJson(
          json['sendTwoFactor'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantRateLimitConfigurationToJson(
        TenantRateLimitConfiguration instance) =>
    <String, dynamic>{
      'failedLogin': instance.failedLogin,
      'forgotPassword': instance.forgotPassword,
      'sendEmailVerification': instance.sendEmailVerification,
      'sendPasswordless': instance.sendPasswordless,
      'sendRegistrationVerification': instance.sendRegistrationVerification,
      'sendTwoFactor': instance.sendTwoFactor,
    };

TenantRegistrationConfiguration _$TenantRegistrationConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantRegistrationConfiguration(
      blockedDomains: (json['blockedDomains'] as List<dynamic>)
          .map((e) => e as String)
          .toSet(),
    );

Map<String, dynamic> _$TenantRegistrationConfigurationToJson(
        TenantRegistrationConfiguration instance) =>
    <String, dynamic>{
      'blockedDomains': instance.blockedDomains.toList(),
    };

TenantRequest _$TenantRequestFromJson(Map<String, dynamic> json) =>
    TenantRequest(
      sourceTenantId: json['sourceTenantId'] as String,
      tenant: Tenant.fromJson(json['tenant'] as Map<String, dynamic>),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$TenantRequestToJson(TenantRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'sourceTenantId': instance.sourceTenantId,
      'tenant': instance.tenant,
    };

TenantResponse _$TenantResponseFromJson(Map<String, dynamic> json) =>
    TenantResponse(
      tenant: Tenant.fromJson(json['tenant'] as Map<String, dynamic>),
      tenants: (json['tenants'] as List<dynamic>)
          .map((e) => Tenant.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$TenantResponseToJson(TenantResponse instance) =>
    <String, dynamic>{
      'tenant': instance.tenant,
      'tenants': instance.tenants,
    };

TenantSCIMServerConfiguration _$TenantSCIMServerConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantSCIMServerConfiguration(
      clientEntityTypeId: json['clientEntityTypeId'] as String,
      schemas: json['schemas'] as Map<String, dynamic>,
      serverEntityTypeId: json['serverEntityTypeId'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$TenantSCIMServerConfigurationToJson(
        TenantSCIMServerConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'clientEntityTypeId': instance.clientEntityTypeId,
      'schemas': instance.schemas,
      'serverEntityTypeId': instance.serverEntityTypeId,
    };

TenantSSOConfiguration _$TenantSSOConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantSSOConfiguration(
      deviceTrustTimeToLiveInSeconds:
          json['deviceTrustTimeToLiveInSeconds'] as num,
    );

Map<String, dynamic> _$TenantSSOConfigurationToJson(
        TenantSSOConfiguration instance) =>
    <String, dynamic>{
      'deviceTrustTimeToLiveInSeconds': instance.deviceTrustTimeToLiveInSeconds,
    };

TenantUnverifiedConfiguration _$TenantUnverifiedConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantUnverifiedConfiguration(
      email: _$enumDecode(_$UnverifiedBehaviorEnumMap, json['email']),
      whenGated: RegistrationUnverifiedOptions.fromJson(
          json['whenGated'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantUnverifiedConfigurationToJson(
        TenantUnverifiedConfiguration instance) =>
    <String, dynamic>{
      'email': _$UnverifiedBehaviorEnumMap[instance.email],
      'whenGated': instance.whenGated,
    };

TenantUserDeletePolicy _$TenantUserDeletePolicyFromJson(
        Map<String, dynamic> json) =>
    TenantUserDeletePolicy(
      unverified: TimeBasedDeletePolicy.fromJson(
          json['unverified'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantUserDeletePolicyToJson(
        TenantUserDeletePolicy instance) =>
    <String, dynamic>{
      'unverified': instance.unverified,
    };

TenantUsernameConfiguration _$TenantUsernameConfigurationFromJson(
        Map<String, dynamic> json) =>
    TenantUsernameConfiguration(
      unique: UniqueUsernameConfiguration.fromJson(
          json['unique'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$TenantUsernameConfigurationToJson(
        TenantUsernameConfiguration instance) =>
    <String, dynamic>{
      'unique': instance.unique,
    };

TestEvent _$TestEventFromJson(Map<String, dynamic> json) => TestEvent(
      message: json['message'] as String,
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$TestEventToJson(TestEvent instance) => <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'message': instance.message,
    };

Theme _$ThemeFromJson(Map<String, dynamic> json) => Theme(
      data: json['data'] as Map<String, dynamic>,
      defaultMessages: json['defaultMessages'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      localizedMessages:
          Map<String, String>.from(json['localizedMessages'] as Map),
      name: json['name'] as String,
      stylesheet: json['stylesheet'] as String,
      templates: Templates.fromJson(json['templates'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ThemeToJson(Theme instance) => <String, dynamic>{
      'data': instance.data,
      'defaultMessages': instance.defaultMessages,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'localizedMessages': instance.localizedMessages,
      'name': instance.name,
      'stylesheet': instance.stylesheet,
      'templates': instance.templates,
    };

ThemeRequest _$ThemeRequestFromJson(Map<String, dynamic> json) => ThemeRequest(
      sourceThemeId: json['sourceThemeId'] as String,
      theme: Theme.fromJson(json['theme'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ThemeRequestToJson(ThemeRequest instance) =>
    <String, dynamic>{
      'sourceThemeId': instance.sourceThemeId,
      'theme': instance.theme,
    };

ThemeResponse _$ThemeResponseFromJson(Map<String, dynamic> json) =>
    ThemeResponse(
      theme: Theme.fromJson(json['theme'] as Map<String, dynamic>),
      themes: (json['themes'] as List<dynamic>)
          .map((e) => Theme.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$ThemeResponseToJson(ThemeResponse instance) =>
    <String, dynamic>{
      'theme': instance.theme,
      'themes': instance.themes,
    };

TimeBasedDeletePolicy _$TimeBasedDeletePolicyFromJson(
        Map<String, dynamic> json) =>
    TimeBasedDeletePolicy(
      numberOfDaysToRetain: json['numberOfDaysToRetain'] as num,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$TimeBasedDeletePolicyToJson(
        TimeBasedDeletePolicy instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'numberOfDaysToRetain': instance.numberOfDaysToRetain,
    };

Totals _$TotalsFromJson(Map<String, dynamic> json) => Totals(
      logins: json['logins'] as num,
      registrations: json['registrations'] as num,
      totalRegistrations: json['totalRegistrations'] as num,
    );

Map<String, dynamic> _$TotalsToJson(Totals instance) => <String, dynamic>{
      'logins': instance.logins,
      'registrations': instance.registrations,
      'totalRegistrations': instance.totalRegistrations,
    };

TotalsReportResponse _$TotalsReportResponseFromJson(
        Map<String, dynamic> json) =>
    TotalsReportResponse(
      applicationTotals:
          (json['applicationTotals'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k, Totals.fromJson(e as Map<String, dynamic>)),
      ),
      globalRegistrations: json['globalRegistrations'] as num,
      totalGlobalRegistrations: json['totalGlobalRegistrations'] as num,
    );

Map<String, dynamic> _$TotalsReportResponseToJson(
        TotalsReportResponse instance) =>
    <String, dynamic>{
      'applicationTotals': instance.applicationTotals,
      'globalRegistrations': instance.globalRegistrations,
      'totalGlobalRegistrations': instance.totalGlobalRegistrations,
    };

TwilioMessengerConfiguration _$TwilioMessengerConfigurationFromJson(
        Map<String, dynamic> json) =>
    TwilioMessengerConfiguration(
      accountSID: json['accountSID'] as String,
      authToken: json['authToken'] as String,
      fromPhoneNumber: json['fromPhoneNumber'] as String,
      messagingServiceSid: json['messagingServiceSid'] as String,
      url: json['url'] as String,
    )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..name = json['name'] as String
      ..transport = json['transport'] as String
      ..type = _$enumDecode(_$MessengerTypeEnumMap, json['type']);

Map<String, dynamic> _$TwilioMessengerConfigurationToJson(
        TwilioMessengerConfiguration instance) =>
    <String, dynamic>{
      'data': instance.data,
      'debug': instance.debug,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'name': instance.name,
      'transport': instance.transport,
      'type': _$MessengerTypeEnumMap[instance.type],
      'accountSID': instance.accountSID,
      'authToken': instance.authToken,
      'fromPhoneNumber': instance.fromPhoneNumber,
      'messagingServiceSid': instance.messagingServiceSid,
      'url': instance.url,
    };

TwitchApplicationConfiguration _$TwitchApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    TwitchApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$TwitchApplicationConfigurationToJson(
        TwitchApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'scope': instance.scope,
    };

TwitchIdentityProvider _$TwitchIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    TwitchIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            TwitchApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$TwitchIdentityProviderToJson(
    TwitchIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['scope'] = instance.scope;
  return val;
}

TwitterApplicationConfiguration _$TwitterApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    TwitterApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      consumerKey: json['consumerKey'] as String,
      consumerSecret: json['consumerSecret'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$TwitterApplicationConfigurationToJson(
        TwitterApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'consumerKey': instance.consumerKey,
      'consumerSecret': instance.consumerSecret,
    };

TwitterIdentityProvider _$TwitterIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    TwitterIdentityProvider(
      buttonText: json['buttonText'] as String,
      consumerKey: json['consumerKey'] as String,
      consumerSecret: json['consumerSecret'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            TwitterApplicationConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$TwitterIdentityProviderToJson(
    TwitterIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['consumerKey'] = instance.consumerKey;
  val['consumerSecret'] = instance.consumerSecret;
  return val;
}

TwoFactorDisableRequest _$TwoFactorDisableRequestFromJson(
        Map<String, dynamic> json) =>
    TwoFactorDisableRequest(
      applicationId: json['applicationId'] as String,
      code: json['code'] as String,
      methodId: json['methodId'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$TwoFactorDisableRequestToJson(
        TwoFactorDisableRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'code': instance.code,
      'methodId': instance.methodId,
    };

TwoFactorEnableDisableSendRequest _$TwoFactorEnableDisableSendRequestFromJson(
        Map<String, dynamic> json) =>
    TwoFactorEnableDisableSendRequest(
      email: json['email'] as String,
      method: json['method'] as String,
      methodId: json['methodId'] as String,
      mobilePhone: json['mobilePhone'] as String,
    );

Map<String, dynamic> _$TwoFactorEnableDisableSendRequestToJson(
        TwoFactorEnableDisableSendRequest instance) =>
    <String, dynamic>{
      'email': instance.email,
      'method': instance.method,
      'methodId': instance.methodId,
      'mobilePhone': instance.mobilePhone,
    };

TwoFactorLoginRequest _$TwoFactorLoginRequestFromJson(
        Map<String, dynamic> json) =>
    TwoFactorLoginRequest(
      code: json['code'] as String,
      trustComputer: json['trustComputer'] as bool,
      twoFactorId: json['twoFactorId'] as String,
      userId: json['userId'] as String,
    )
      ..eventInfo =
          EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>)
      ..applicationId = json['applicationId'] as String
      ..ipAddress = json['ipAddress'] as String
      ..metaData = MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
      ..newDevice = json['newDevice'] as bool
      ..noJWT = json['noJWT'] as bool;

Map<String, dynamic> _$TwoFactorLoginRequestToJson(
        TwoFactorLoginRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'ipAddress': instance.ipAddress,
      'metaData': instance.metaData,
      'newDevice': instance.newDevice,
      'noJWT': instance.noJWT,
      'code': instance.code,
      'trustComputer': instance.trustComputer,
      'twoFactorId': instance.twoFactorId,
      'userId': instance.userId,
    };

TwoFactorMethod _$TwoFactorMethodFromJson(Map<String, dynamic> json) =>
    TwoFactorMethod(
      authenticator: AuthenticatorConfiguration.fromJson(
          json['authenticator'] as Map<String, dynamic>),
      email: json['email'] as String,
      id: json['id'] as String,
      lastUsed: json['lastUsed'] as bool,
      method: json['method'] as String,
      mobilePhone: json['mobilePhone'] as String,
      secret: json['secret'] as String,
    );

Map<String, dynamic> _$TwoFactorMethodToJson(TwoFactorMethod instance) =>
    <String, dynamic>{
      'authenticator': instance.authenticator,
      'email': instance.email,
      'id': instance.id,
      'lastUsed': instance.lastUsed,
      'method': instance.method,
      'mobilePhone': instance.mobilePhone,
      'secret': instance.secret,
    };

TwoFactorRecoveryCodeResponse _$TwoFactorRecoveryCodeResponseFromJson(
        Map<String, dynamic> json) =>
    TwoFactorRecoveryCodeResponse(
      recoveryCodes: (json['recoveryCodes'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
    );

Map<String, dynamic> _$TwoFactorRecoveryCodeResponseToJson(
        TwoFactorRecoveryCodeResponse instance) =>
    <String, dynamic>{
      'recoveryCodes': instance.recoveryCodes,
    };

TwoFactorRequest _$TwoFactorRequestFromJson(Map<String, dynamic> json) =>
    TwoFactorRequest(
      applicationId: json['applicationId'] as String,
      authenticatorId: json['authenticatorId'] as String,
      code: json['code'] as String,
      email: json['email'] as String,
      method: json['method'] as String,
      mobilePhone: json['mobilePhone'] as String,
      secret: json['secret'] as String,
      secretBase32Encoded: json['secretBase32Encoded'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$TwoFactorRequestToJson(TwoFactorRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'authenticatorId': instance.authenticatorId,
      'code': instance.code,
      'email': instance.email,
      'method': instance.method,
      'mobilePhone': instance.mobilePhone,
      'secret': instance.secret,
      'secretBase32Encoded': instance.secretBase32Encoded,
    };

TwoFactorResponse _$TwoFactorResponseFromJson(Map<String, dynamic> json) =>
    TwoFactorResponse(
      recoveryCodes: (json['recoveryCodes'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
    );

Map<String, dynamic> _$TwoFactorResponseToJson(TwoFactorResponse instance) =>
    <String, dynamic>{
      'recoveryCodes': instance.recoveryCodes,
    };

TwoFactorSendRequest _$TwoFactorSendRequestFromJson(
        Map<String, dynamic> json) =>
    TwoFactorSendRequest(
      email: json['email'] as String,
      method: json['method'] as String,
      methodId: json['methodId'] as String,
      mobilePhone: json['mobilePhone'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$TwoFactorSendRequestToJson(
        TwoFactorSendRequest instance) =>
    <String, dynamic>{
      'email': instance.email,
      'method': instance.method,
      'methodId': instance.methodId,
      'mobilePhone': instance.mobilePhone,
      'userId': instance.userId,
    };

TwoFactorStartRequest _$TwoFactorStartRequestFromJson(
        Map<String, dynamic> json) =>
    TwoFactorStartRequest(
      applicationId: json['applicationId'] as String,
      code: json['code'] as String,
      loginId: json['loginId'] as String,
      state: json['state'] as Map<String, dynamic>,
      trustChallenge: json['trustChallenge'] as String,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$TwoFactorStartRequestToJson(
        TwoFactorStartRequest instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'code': instance.code,
      'loginId': instance.loginId,
      'state': instance.state,
      'trustChallenge': instance.trustChallenge,
      'userId': instance.userId,
    };

TwoFactorStartResponse _$TwoFactorStartResponseFromJson(
        Map<String, dynamic> json) =>
    TwoFactorStartResponse(
      code: json['code'] as String,
      methods: (json['methods'] as List<dynamic>)
          .map((e) => TwoFactorMethod.fromJson(e as Map<String, dynamic>))
          .toList(),
      twoFactorId: json['twoFactorId'] as String,
    );

Map<String, dynamic> _$TwoFactorStartResponseToJson(
        TwoFactorStartResponse instance) =>
    <String, dynamic>{
      'code': instance.code,
      'methods': instance.methods,
      'twoFactorId': instance.twoFactorId,
    };

UIConfiguration _$UIConfigurationFromJson(Map<String, dynamic> json) =>
    UIConfiguration(
      headerColor: json['headerColor'] as String,
      logoURL: json['logoURL'] as String,
      menuFontColor: json['menuFontColor'] as String,
    );

Map<String, dynamic> _$UIConfigurationToJson(UIConfiguration instance) =>
    <String, dynamic>{
      'headerColor': instance.headerColor,
      'logoURL': instance.logoURL,
      'menuFontColor': instance.menuFontColor,
    };

UniqueUsernameConfiguration _$UniqueUsernameConfigurationFromJson(
        Map<String, dynamic> json) =>
    UniqueUsernameConfiguration(
      numberOfDigits: json['numberOfDigits'] as num,
      separator: json['separator'],
      strategy: _$enumDecode(_$UniqueUsernameStrategyEnumMap, json['strategy']),
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$UniqueUsernameConfigurationToJson(
    UniqueUsernameConfiguration instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'numberOfDigits': instance.numberOfDigits,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('separator', instance.separator);
  val['strategy'] = _$UniqueUsernameStrategyEnumMap[instance.strategy];
  return val;
}

const _$UniqueUsernameStrategyEnumMap = {
  UniqueUsernameStrategy.Always: 'Always',
  UniqueUsernameStrategy.OnCollision: 'OnCollision',
};

User _$UserFromJson(Map<String, dynamic> json) => User(
      active: json['active'] as bool,
      birthDate: json['birthDate'] as String,
      cleanSpeakId: json['cleanSpeakId'] as String,
      data: json['data'] as Map<String, dynamic>,
      email: json['email'] as String,
      expiry: json['expiry'] as num,
      firstName: json['firstName'] as String,
      fullName: json['fullName'] as String,
      imageUrl: json['imageUrl'] as String,
      insertInstant: json['insertInstant'] as num,
      lastName: json['lastName'] as String,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      memberships: (json['memberships'] as List<dynamic>)
          .map((e) => GroupMember.fromJson(e as Map<String, dynamic>))
          .toList(),
      middleName: json['middleName'] as String,
      mobilePhone: json['mobilePhone'] as String,
      parentEmail: json['parentEmail'] as String,
      preferredLanguages: (json['preferredLanguages'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      registrations: (json['registrations'] as List<dynamic>)
          .map((e) => UserRegistration.fromJson(e as Map<String, dynamic>))
          .toList(),
      tenantId: json['tenantId'] as String,
      timezone: json['timezone'] as String,
      twoFactor: UserTwoFactorConfiguration.fromJson(
          json['twoFactor'] as Map<String, dynamic>),
    )
      ..breachedPasswordLastCheckedInstant =
          json['breachedPasswordLastCheckedInstant'] as num
      ..breachedPasswordStatus = _$enumDecode(
          _$BreachedPasswordStatusEnumMap, json['breachedPasswordStatus'])
      ..connectorId = json['connectorId'] as String
      ..encryptionScheme = json['encryptionScheme'] as String
      ..factor = json['factor'] as num
      ..id = json['id'] as String
      ..lastLoginInstant = json['lastLoginInstant'] as num
      ..password = json['password'] as String
      ..passwordChangeReason = _$enumDecode(
          _$ChangePasswordReasonEnumMap, json['passwordChangeReason'])
      ..passwordChangeRequired = json['passwordChangeRequired'] as bool
      ..passwordLastUpdateInstant = json['passwordLastUpdateInstant'] as num
      ..salt = json['salt'] as String
      ..uniqueUsername = json['uniqueUsername'] as String
      ..username = json['username'] as String
      ..usernameStatus =
          _$enumDecode(_$ContentStatusEnumMap, json['usernameStatus'])
      ..verified = json['verified'] as bool;

Map<String, dynamic> _$UserToJson(User instance) => <String, dynamic>{
      'breachedPasswordLastCheckedInstant':
          instance.breachedPasswordLastCheckedInstant,
      'breachedPasswordStatus':
          _$BreachedPasswordStatusEnumMap[instance.breachedPasswordStatus],
      'connectorId': instance.connectorId,
      'encryptionScheme': instance.encryptionScheme,
      'factor': instance.factor,
      'id': instance.id,
      'lastLoginInstant': instance.lastLoginInstant,
      'password': instance.password,
      'passwordChangeReason':
          _$ChangePasswordReasonEnumMap[instance.passwordChangeReason],
      'passwordChangeRequired': instance.passwordChangeRequired,
      'passwordLastUpdateInstant': instance.passwordLastUpdateInstant,
      'salt': instance.salt,
      'uniqueUsername': instance.uniqueUsername,
      'username': instance.username,
      'usernameStatus': _$ContentStatusEnumMap[instance.usernameStatus],
      'verified': instance.verified,
      'active': instance.active,
      'birthDate': instance.birthDate,
      'cleanSpeakId': instance.cleanSpeakId,
      'data': instance.data,
      'email': instance.email,
      'expiry': instance.expiry,
      'firstName': instance.firstName,
      'fullName': instance.fullName,
      'imageUrl': instance.imageUrl,
      'insertInstant': instance.insertInstant,
      'lastName': instance.lastName,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'memberships': instance.memberships,
      'middleName': instance.middleName,
      'mobilePhone': instance.mobilePhone,
      'parentEmail': instance.parentEmail,
      'preferredLanguages': instance.preferredLanguages,
      'registrations': instance.registrations,
      'tenantId': instance.tenantId,
      'timezone': instance.timezone,
      'twoFactor': instance.twoFactor,
    };

UserAction _$UserActionFromJson(Map<String, dynamic> json) => UserAction(
      active: json['active'] as bool,
      cancelEmailTemplateId: json['cancelEmailTemplateId'] as String,
      endEmailTemplateId: json['endEmailTemplateId'] as String,
      id: json['id'] as String,
      includeEmailInEventJSON: json['includeEmailInEventJSON'] as bool,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      localizedNames: Map<String, String>.from(json['localizedNames'] as Map),
      modifyEmailTemplateId: json['modifyEmailTemplateId'] as String,
      name: json['name'] as String,
      options: (json['options'] as List<dynamic>)
          .map((e) => UserActionOption.fromJson(e as Map<String, dynamic>))
          .toList(),
      preventLogin: json['preventLogin'] as bool,
      sendEndEvent: json['sendEndEvent'] as bool,
      startEmailTemplateId: json['startEmailTemplateId'] as String,
      temporal: json['temporal'] as bool,
      transactionType:
          _$enumDecode(_$TransactionTypeEnumMap, json['transactionType']),
      userEmailingEnabled: json['userEmailingEnabled'] as bool,
      userNotificationsEnabled: json['userNotificationsEnabled'] as bool,
    );

Map<String, dynamic> _$UserActionToJson(UserAction instance) =>
    <String, dynamic>{
      'active': instance.active,
      'cancelEmailTemplateId': instance.cancelEmailTemplateId,
      'endEmailTemplateId': instance.endEmailTemplateId,
      'id': instance.id,
      'includeEmailInEventJSON': instance.includeEmailInEventJSON,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'localizedNames': instance.localizedNames,
      'modifyEmailTemplateId': instance.modifyEmailTemplateId,
      'name': instance.name,
      'options': instance.options,
      'preventLogin': instance.preventLogin,
      'sendEndEvent': instance.sendEndEvent,
      'startEmailTemplateId': instance.startEmailTemplateId,
      'temporal': instance.temporal,
      'transactionType': _$TransactionTypeEnumMap[instance.transactionType],
      'userEmailingEnabled': instance.userEmailingEnabled,
      'userNotificationsEnabled': instance.userNotificationsEnabled,
    };

UserActionEvent _$UserActionEventFromJson(Map<String, dynamic> json) =>
    UserActionEvent(
      action: json['action'] as String,
      actioneeUserId: json['actioneeUserId'] as String,
      actionerUserId: json['actionerUserId'] as String,
      actionId: json['actionId'] as String,
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      comment: json['comment'] as String,
      email: Email.fromJson(json['email'] as Map<String, dynamic>),
      emailedUser: json['emailedUser'] as bool,
      expiry: json['expiry'] as num,
      localizedAction: json['localizedAction'] as String,
      localizedDuration: json['localizedDuration'] as String,
      localizedOption: json['localizedOption'] as String,
      localizedReason: json['localizedReason'] as String,
      notifyUser: json['notifyUser'] as bool,
      option: json['option'] as String,
      phase: _$enumDecode(_$UserActionPhaseEnumMap, json['phase']),
      reason: json['reason'] as String,
      reasonCode: json['reasonCode'] as String,
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserActionEventToJson(UserActionEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'action': instance.action,
      'actioneeUserId': instance.actioneeUserId,
      'actionerUserId': instance.actionerUserId,
      'actionId': instance.actionId,
      'applicationIds': instance.applicationIds,
      'comment': instance.comment,
      'email': instance.email,
      'emailedUser': instance.emailedUser,
      'expiry': instance.expiry,
      'localizedAction': instance.localizedAction,
      'localizedDuration': instance.localizedDuration,
      'localizedOption': instance.localizedOption,
      'localizedReason': instance.localizedReason,
      'notifyUser': instance.notifyUser,
      'option': instance.option,
      'phase': _$UserActionPhaseEnumMap[instance.phase],
      'reason': instance.reason,
      'reasonCode': instance.reasonCode,
    };

const _$UserActionPhaseEnumMap = {
  UserActionPhase.start: 'start',
  UserActionPhase.modify: 'modify',
  UserActionPhase.cancel: 'cancel',
  UserActionPhase.end: 'end',
};

UserActionLog _$UserActionLogFromJson(Map<String, dynamic> json) =>
    UserActionLog(
      actioneeUserId: json['actioneeUserId'] as String,
      actionerUserId: json['actionerUserId'] as String,
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      comment: json['comment'] as String,
      emailUserOnEnd: json['emailUserOnEnd'] as bool,
      endEventSent: json['endEventSent'] as bool,
      expiry: json['expiry'] as num,
      history: LogHistory.fromJson(json['history'] as Map<String, dynamic>),
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      localizedName: json['localizedName'] as String,
      localizedOption: json['localizedOption'] as String,
      localizedReason: json['localizedReason'] as String,
      name: json['name'] as String,
      notifyUserOnEnd: json['notifyUserOnEnd'] as bool,
      option: json['option'] as String,
      reason: json['reason'] as String,
      reasonCode: json['reasonCode'] as String,
      userActionId: json['userActionId'] as String,
    );

Map<String, dynamic> _$UserActionLogToJson(UserActionLog instance) =>
    <String, dynamic>{
      'actioneeUserId': instance.actioneeUserId,
      'actionerUserId': instance.actionerUserId,
      'applicationIds': instance.applicationIds,
      'comment': instance.comment,
      'emailUserOnEnd': instance.emailUserOnEnd,
      'endEventSent': instance.endEventSent,
      'expiry': instance.expiry,
      'history': instance.history,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'localizedName': instance.localizedName,
      'localizedOption': instance.localizedOption,
      'localizedReason': instance.localizedReason,
      'name': instance.name,
      'notifyUserOnEnd': instance.notifyUserOnEnd,
      'option': instance.option,
      'reason': instance.reason,
      'reasonCode': instance.reasonCode,
      'userActionId': instance.userActionId,
    };

UserActionOption _$UserActionOptionFromJson(Map<String, dynamic> json) =>
    UserActionOption(
      localizedNames: Map<String, String>.from(json['localizedNames'] as Map),
      name: json['name'] as String,
    );

Map<String, dynamic> _$UserActionOptionToJson(UserActionOption instance) =>
    <String, dynamic>{
      'localizedNames': instance.localizedNames,
      'name': instance.name,
    };

UserActionReason _$UserActionReasonFromJson(Map<String, dynamic> json) =>
    UserActionReason(
      code: json['code'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      localizedTexts: Map<String, String>.from(json['localizedTexts'] as Map),
      text: json['text'] as String,
    );

Map<String, dynamic> _$UserActionReasonToJson(UserActionReason instance) =>
    <String, dynamic>{
      'code': instance.code,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'localizedTexts': instance.localizedTexts,
      'text': instance.text,
    };

UserActionReasonRequest _$UserActionReasonRequestFromJson(
        Map<String, dynamic> json) =>
    UserActionReasonRequest(
      userActionReason: UserActionReason.fromJson(
          json['userActionReason'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$UserActionReasonRequestToJson(
        UserActionReasonRequest instance) =>
    <String, dynamic>{
      'userActionReason': instance.userActionReason,
    };

UserActionReasonResponse _$UserActionReasonResponseFromJson(
        Map<String, dynamic> json) =>
    UserActionReasonResponse(
      userActionReason: UserActionReason.fromJson(
          json['userActionReason'] as Map<String, dynamic>),
      userActionReasons: (json['userActionReasons'] as List<dynamic>)
          .map((e) => UserActionReason.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$UserActionReasonResponseToJson(
        UserActionReasonResponse instance) =>
    <String, dynamic>{
      'userActionReason': instance.userActionReason,
      'userActionReasons': instance.userActionReasons,
    };

UserActionRequest _$UserActionRequestFromJson(Map<String, dynamic> json) =>
    UserActionRequest(
      userAction:
          UserAction.fromJson(json['userAction'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$UserActionRequestToJson(UserActionRequest instance) =>
    <String, dynamic>{
      'userAction': instance.userAction,
    };

UserActionResponse _$UserActionResponseFromJson(Map<String, dynamic> json) =>
    UserActionResponse(
      userAction:
          UserAction.fromJson(json['userAction'] as Map<String, dynamic>),
      userActions: (json['userActions'] as List<dynamic>)
          .map((e) => UserAction.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$UserActionResponseToJson(UserActionResponse instance) =>
    <String, dynamic>{
      'userAction': instance.userAction,
      'userActions': instance.userActions,
    };

UserBulkCreateEvent _$UserBulkCreateEventFromJson(Map<String, dynamic> json) =>
    UserBulkCreateEvent(
      users: (json['users'] as List<dynamic>)
          .map((e) => User.fromJson(e as Map<String, dynamic>))
          .toList(),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserBulkCreateEventToJson(
        UserBulkCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'users': instance.users,
    };

UserComment _$UserCommentFromJson(Map<String, dynamic> json) => UserComment(
      comment: json['comment'] as String,
      commenterId: json['commenterId'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      userId: json['userId'] as String,
    );

Map<String, dynamic> _$UserCommentToJson(UserComment instance) =>
    <String, dynamic>{
      'comment': instance.comment,
      'commenterId': instance.commenterId,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'userId': instance.userId,
    };

UserCommentRequest _$UserCommentRequestFromJson(Map<String, dynamic> json) =>
    UserCommentRequest(
      userComment:
          UserComment.fromJson(json['userComment'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$UserCommentRequestToJson(UserCommentRequest instance) =>
    <String, dynamic>{
      'userComment': instance.userComment,
    };

UserCommentResponse _$UserCommentResponseFromJson(Map<String, dynamic> json) =>
    UserCommentResponse(
      userComment:
          UserComment.fromJson(json['userComment'] as Map<String, dynamic>),
      userComments: (json['userComments'] as List<dynamic>)
          .map((e) => UserComment.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$UserCommentResponseToJson(
        UserCommentResponse instance) =>
    <String, dynamic>{
      'userComment': instance.userComment,
      'userComments': instance.userComments,
    };

UserConsent _$UserConsentFromJson(Map<String, dynamic> json) => UserConsent(
      consent: Consent.fromJson(json['consent'] as Map<String, dynamic>),
      consentId: json['consentId'] as String,
      data: json['data'] as Map<String, dynamic>,
      giverUserId: json['giverUserId'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      status: _$enumDecode(_$ConsentStatusEnumMap, json['status']),
      userId: json['userId'] as String,
      values:
          (json['values'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$UserConsentToJson(UserConsent instance) =>
    <String, dynamic>{
      'consent': instance.consent,
      'consentId': instance.consentId,
      'data': instance.data,
      'giverUserId': instance.giverUserId,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'status': _$ConsentStatusEnumMap[instance.status],
      'userId': instance.userId,
      'values': instance.values,
    };

const _$ConsentStatusEnumMap = {
  ConsentStatus.Active: 'Active',
  ConsentStatus.Revoked: 'Revoked',
};

UserConsentRequest _$UserConsentRequestFromJson(Map<String, dynamic> json) =>
    UserConsentRequest(
      userConsent:
          UserConsent.fromJson(json['userConsent'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$UserConsentRequestToJson(UserConsentRequest instance) =>
    <String, dynamic>{
      'userConsent': instance.userConsent,
    };

UserConsentResponse _$UserConsentResponseFromJson(Map<String, dynamic> json) =>
    UserConsentResponse(
      userConsent:
          UserConsent.fromJson(json['userConsent'] as Map<String, dynamic>),
      userConsents: (json['userConsents'] as List<dynamic>)
          .map((e) => UserConsent.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$UserConsentResponseToJson(
        UserConsentResponse instance) =>
    <String, dynamic>{
      'userConsent': instance.userConsent,
      'userConsents': instance.userConsents,
    };

UserCreateCompleteEvent _$UserCreateCompleteEventFromJson(
        Map<String, dynamic> json) =>
    UserCreateCompleteEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserCreateCompleteEventToJson(
        UserCreateCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserCreateEvent _$UserCreateEventFromJson(Map<String, dynamic> json) =>
    UserCreateEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserCreateEventToJson(UserCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserDeactivateEvent _$UserDeactivateEventFromJson(Map<String, dynamic> json) =>
    UserDeactivateEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserDeactivateEventToJson(
        UserDeactivateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserDeleteCompleteEvent _$UserDeleteCompleteEventFromJson(
        Map<String, dynamic> json) =>
    UserDeleteCompleteEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserDeleteCompleteEventToJson(
        UserDeleteCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserDeleteEvent _$UserDeleteEventFromJson(Map<String, dynamic> json) =>
    UserDeleteEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserDeleteEventToJson(UserDeleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserDeleteRequest _$UserDeleteRequestFromJson(Map<String, dynamic> json) =>
    UserDeleteRequest(
      dryRun: json['dryRun'] as bool,
      hardDelete: json['hardDelete'] as bool,
      query: json['query'] as String,
      queryString: json['queryString'] as String,
      userIds:
          (json['userIds'] as List<dynamic>).map((e) => e as String).toList(),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$UserDeleteRequestToJson(UserDeleteRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'dryRun': instance.dryRun,
      'hardDelete': instance.hardDelete,
      'query': instance.query,
      'queryString': instance.queryString,
      'userIds': instance.userIds,
    };

UserDeleteResponse _$UserDeleteResponseFromJson(Map<String, dynamic> json) =>
    UserDeleteResponse(
      dryRun: json['dryRun'] as bool,
      hardDelete: json['hardDelete'] as bool,
      total: json['total'] as num,
      userIds:
          (json['userIds'] as List<dynamic>).map((e) => e as String).toList(),
    );

Map<String, dynamic> _$UserDeleteResponseToJson(UserDeleteResponse instance) =>
    <String, dynamic>{
      'dryRun': instance.dryRun,
      'hardDelete': instance.hardDelete,
      'total': instance.total,
      'userIds': instance.userIds,
    };

UserDeleteSingleRequest _$UserDeleteSingleRequestFromJson(
        Map<String, dynamic> json) =>
    UserDeleteSingleRequest(
      hardDelete: json['hardDelete'] as bool,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$UserDeleteSingleRequestToJson(
        UserDeleteSingleRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'hardDelete': instance.hardDelete,
    };

UserEmailUpdateEvent _$UserEmailUpdateEventFromJson(
        Map<String, dynamic> json) =>
    UserEmailUpdateEvent(
      previousEmail: json['previousEmail'] as String,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserEmailUpdateEventToJson(
        UserEmailUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'previousEmail': instance.previousEmail,
      'user': instance.user,
    };

UserEmailVerifiedEvent _$UserEmailVerifiedEventFromJson(
        Map<String, dynamic> json) =>
    UserEmailVerifiedEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserEmailVerifiedEventToJson(
        UserEmailVerifiedEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserIdentityProviderLinkEvent _$UserIdentityProviderLinkEventFromJson(
        Map<String, dynamic> json) =>
    UserIdentityProviderLinkEvent(
      identityProviderLink: IdentityProviderLink.fromJson(
          json['identityProviderLink'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserIdentityProviderLinkEventToJson(
        UserIdentityProviderLinkEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'identityProviderLink': instance.identityProviderLink,
      'user': instance.user,
    };

UserIdentityProviderUnlinkEvent _$UserIdentityProviderUnlinkEventFromJson(
        Map<String, dynamic> json) =>
    UserIdentityProviderUnlinkEvent(
      identityProviderLink: IdentityProviderLink.fromJson(
          json['identityProviderLink'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserIdentityProviderUnlinkEventToJson(
        UserIdentityProviderUnlinkEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'identityProviderLink': instance.identityProviderLink,
      'user': instance.user,
    };

UserLoginFailedEvent _$UserLoginFailedEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginFailedEvent(
      applicationId: json['applicationId'] as String,
      authenticationType: json['authenticationType'] as String,
      ipAddress: json['ipAddress'] as String,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserLoginFailedEventToJson(
        UserLoginFailedEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'authenticationType': instance.authenticationType,
      'ipAddress': instance.ipAddress,
      'user': instance.user,
    };

UserLoginIdDuplicateOnCreateEvent _$UserLoginIdDuplicateOnCreateEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginIdDuplicateOnCreateEvent(
      duplicateEmail: json['duplicateEmail'] as String,
      duplicateUsername: json['duplicateUsername'] as String,
      existing: User.fromJson(json['existing'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserLoginIdDuplicateOnCreateEventToJson(
        UserLoginIdDuplicateOnCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'duplicateEmail': instance.duplicateEmail,
      'duplicateUsername': instance.duplicateUsername,
      'existing': instance.existing,
      'user': instance.user,
    };

UserLoginIdDuplicateOnUpdateEvent _$UserLoginIdDuplicateOnUpdateEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginIdDuplicateOnUpdateEvent()
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type'])
      ..duplicateEmail = json['duplicateEmail'] as String
      ..duplicateUsername = json['duplicateUsername'] as String
      ..existing = User.fromJson(json['existing'] as Map<String, dynamic>)
      ..user = User.fromJson(json['user'] as Map<String, dynamic>);

Map<String, dynamic> _$UserLoginIdDuplicateOnUpdateEventToJson(
        UserLoginIdDuplicateOnUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'duplicateEmail': instance.duplicateEmail,
      'duplicateUsername': instance.duplicateUsername,
      'existing': instance.existing,
      'user': instance.user,
    };

UserLoginNewDeviceEvent _$UserLoginNewDeviceEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginNewDeviceEvent()
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type'])
      ..applicationId = json['applicationId'] as String
      ..authenticationType = json['authenticationType'] as String
      ..connectorId = json['connectorId'] as String
      ..identityProviderId = json['identityProviderId'] as String
      ..identityProviderName = json['identityProviderName'] as String
      ..ipAddress = json['ipAddress'] as String
      ..user = User.fromJson(json['user'] as Map<String, dynamic>);

Map<String, dynamic> _$UserLoginNewDeviceEventToJson(
        UserLoginNewDeviceEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'authenticationType': instance.authenticationType,
      'connectorId': instance.connectorId,
      'identityProviderId': instance.identityProviderId,
      'identityProviderName': instance.identityProviderName,
      'ipAddress': instance.ipAddress,
      'user': instance.user,
    };

UserLoginSuccessEvent _$UserLoginSuccessEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginSuccessEvent(
      applicationId: json['applicationId'] as String,
      authenticationType: json['authenticationType'] as String,
      connectorId: json['connectorId'] as String,
      identityProviderId: json['identityProviderId'] as String,
      identityProviderName: json['identityProviderName'] as String,
      ipAddress: json['ipAddress'] as String,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserLoginSuccessEventToJson(
        UserLoginSuccessEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'authenticationType': instance.authenticationType,
      'connectorId': instance.connectorId,
      'identityProviderId': instance.identityProviderId,
      'identityProviderName': instance.identityProviderName,
      'ipAddress': instance.ipAddress,
      'user': instance.user,
    };

UserLoginSuspiciousEvent _$UserLoginSuspiciousEventFromJson(
        Map<String, dynamic> json) =>
    UserLoginSuspiciousEvent(
      threatsDetected: (json['threatsDetected'] as List<dynamic>)
          .map((e) => _$enumDecode(_$AuthenticationThreatsEnumMap, e))
          .toSet(),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type'])
      ..applicationId = json['applicationId'] as String
      ..authenticationType = json['authenticationType'] as String
      ..connectorId = json['connectorId'] as String
      ..identityProviderId = json['identityProviderId'] as String
      ..identityProviderName = json['identityProviderName'] as String
      ..ipAddress = json['ipAddress'] as String
      ..user = User.fromJson(json['user'] as Map<String, dynamic>);

Map<String, dynamic> _$UserLoginSuspiciousEventToJson(
        UserLoginSuspiciousEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'authenticationType': instance.authenticationType,
      'connectorId': instance.connectorId,
      'identityProviderId': instance.identityProviderId,
      'identityProviderName': instance.identityProviderName,
      'ipAddress': instance.ipAddress,
      'user': instance.user,
      'threatsDetected': instance.threatsDetected
          .map((e) => _$AuthenticationThreatsEnumMap[e])
          .toList(),
    };

UsernameModeration _$UsernameModerationFromJson(Map<String, dynamic> json) =>
    UsernameModeration(
      applicationId: json['applicationId'] as String,
    )..enabled = json['enabled'] as bool;

Map<String, dynamic> _$UsernameModerationToJson(UsernameModeration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'applicationId': instance.applicationId,
    };

UserPasswordBreachEvent _$UserPasswordBreachEventFromJson(
        Map<String, dynamic> json) =>
    UserPasswordBreachEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserPasswordBreachEventToJson(
        UserPasswordBreachEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserPasswordResetSendEvent _$UserPasswordResetSendEventFromJson(
        Map<String, dynamic> json) =>
    UserPasswordResetSendEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserPasswordResetSendEventToJson(
        UserPasswordResetSendEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserPasswordResetStartEvent _$UserPasswordResetStartEventFromJson(
        Map<String, dynamic> json) =>
    UserPasswordResetStartEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserPasswordResetStartEventToJson(
        UserPasswordResetStartEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserPasswordResetSuccessEvent _$UserPasswordResetSuccessEventFromJson(
        Map<String, dynamic> json) =>
    UserPasswordResetSuccessEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserPasswordResetSuccessEventToJson(
        UserPasswordResetSuccessEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserPasswordUpdateEvent _$UserPasswordUpdateEventFromJson(
        Map<String, dynamic> json) =>
    UserPasswordUpdateEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserPasswordUpdateEventToJson(
        UserPasswordUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserReactivateEvent _$UserReactivateEventFromJson(Map<String, dynamic> json) =>
    UserReactivateEvent(
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserReactivateEventToJson(
        UserReactivateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'user': instance.user,
    };

UserRegistration _$UserRegistrationFromJson(Map<String, dynamic> json) =>
    UserRegistration(
      applicationId: json['applicationId'] as String,
      authenticationToken: json['authenticationToken'] as String,
      cleanSpeakId: json['cleanSpeakId'] as String,
      data: json['data'] as Map<String, dynamic>,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastLoginInstant: json['lastLoginInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      preferredLanguages: (json['preferredLanguages'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      roles: (json['roles'] as List<dynamic>).map((e) => e as String).toSet(),
      timezone: json['timezone'] as String,
      tokens: Map<String, String>.from(json['tokens'] as Map),
      username: json['username'] as String,
      usernameStatus:
          _$enumDecode(_$ContentStatusEnumMap, json['usernameStatus']),
      verified: json['verified'] as bool,
    );

Map<String, dynamic> _$UserRegistrationToJson(UserRegistration instance) =>
    <String, dynamic>{
      'applicationId': instance.applicationId,
      'authenticationToken': instance.authenticationToken,
      'cleanSpeakId': instance.cleanSpeakId,
      'data': instance.data,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastLoginInstant': instance.lastLoginInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'preferredLanguages': instance.preferredLanguages,
      'roles': instance.roles.toList(),
      'timezone': instance.timezone,
      'tokens': instance.tokens,
      'username': instance.username,
      'usernameStatus': _$ContentStatusEnumMap[instance.usernameStatus],
      'verified': instance.verified,
    };

UserRegistrationCreateCompleteEvent
    _$UserRegistrationCreateCompleteEventFromJson(Map<String, dynamic> json) =>
        UserRegistrationCreateCompleteEvent(
          applicationId: json['applicationId'] as String,
          registration: UserRegistration.fromJson(
              json['registration'] as Map<String, dynamic>),
          user: User.fromJson(json['user'] as Map<String, dynamic>),
        )
          ..createInstant = json['createInstant'] as num
          ..id = json['id'] as String
          ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
          ..tenantId = json['tenantId'] as String
          ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationCreateCompleteEventToJson(
        UserRegistrationCreateCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationCreateEvent _$UserRegistrationCreateEventFromJson(
        Map<String, dynamic> json) =>
    UserRegistrationCreateEvent(
      applicationId: json['applicationId'] as String,
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationCreateEventToJson(
        UserRegistrationCreateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationDeleteCompleteEvent
    _$UserRegistrationDeleteCompleteEventFromJson(Map<String, dynamic> json) =>
        UserRegistrationDeleteCompleteEvent(
          applicationId: json['applicationId'] as String,
          registration: UserRegistration.fromJson(
              json['registration'] as Map<String, dynamic>),
          user: User.fromJson(json['user'] as Map<String, dynamic>),
        )
          ..createInstant = json['createInstant'] as num
          ..id = json['id'] as String
          ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
          ..tenantId = json['tenantId'] as String
          ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationDeleteCompleteEventToJson(
        UserRegistrationDeleteCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationDeleteEvent _$UserRegistrationDeleteEventFromJson(
        Map<String, dynamic> json) =>
    UserRegistrationDeleteEvent(
      applicationId: json['applicationId'] as String,
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationDeleteEventToJson(
        UserRegistrationDeleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationUpdateCompleteEvent
    _$UserRegistrationUpdateCompleteEventFromJson(Map<String, dynamic> json) =>
        UserRegistrationUpdateCompleteEvent(
          applicationId: json['applicationId'] as String,
          original: UserRegistration.fromJson(
              json['original'] as Map<String, dynamic>),
          registration: UserRegistration.fromJson(
              json['registration'] as Map<String, dynamic>),
          user: User.fromJson(json['user'] as Map<String, dynamic>),
        )
          ..createInstant = json['createInstant'] as num
          ..id = json['id'] as String
          ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
          ..tenantId = json['tenantId'] as String
          ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationUpdateCompleteEventToJson(
        UserRegistrationUpdateCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'original': instance.original,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationUpdateEvent _$UserRegistrationUpdateEventFromJson(
        Map<String, dynamic> json) =>
    UserRegistrationUpdateEvent(
      applicationId: json['applicationId'] as String,
      original:
          UserRegistration.fromJson(json['original'] as Map<String, dynamic>),
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationUpdateEventToJson(
        UserRegistrationUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'original': instance.original,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRegistrationVerifiedEvent _$UserRegistrationVerifiedEventFromJson(
        Map<String, dynamic> json) =>
    UserRegistrationVerifiedEvent(
      applicationId: json['applicationId'] as String,
      registration: UserRegistration.fromJson(
          json['registration'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserRegistrationVerifiedEventToJson(
        UserRegistrationVerifiedEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'applicationId': instance.applicationId,
      'registration': instance.registration,
      'user': instance.user,
    };

UserRequest _$UserRequestFromJson(Map<String, dynamic> json) => UserRequest(
      applicationId: json['applicationId'] as String,
      disableDomainBlock: json['disableDomainBlock'] as bool,
      sendSetPasswordEmail: json['sendSetPasswordEmail'] as bool,
      skipVerification: json['skipVerification'] as bool,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$UserRequestToJson(UserRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'applicationId': instance.applicationId,
      'disableDomainBlock': instance.disableDomainBlock,
      'sendSetPasswordEmail': instance.sendSetPasswordEmail,
      'skipVerification': instance.skipVerification,
      'user': instance.user,
    };

UserResponse _$UserResponseFromJson(Map<String, dynamic> json) => UserResponse(
      emailVerificationId: json['emailVerificationId'] as String,
      registrationVerificationIds:
          Map<String, String>.from(json['registrationVerificationIds'] as Map),
      token: json['token'] as String,
      tokenExpirationInstant: json['tokenExpirationInstant'] as num,
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$UserResponseToJson(UserResponse instance) =>
    <String, dynamic>{
      'emailVerificationId': instance.emailVerificationId,
      'registrationVerificationIds': instance.registrationVerificationIds,
      'token': instance.token,
      'tokenExpirationInstant': instance.tokenExpirationInstant,
      'user': instance.user,
    };

UserSearchCriteria _$UserSearchCriteriaFromJson(Map<String, dynamic> json) =>
    UserSearchCriteria()
      ..numberOfResults = json['numberOfResults'] as num
      ..orderBy = json['orderBy'] as String
      ..startRow = json['startRow'] as num
      ..accurateTotal = json['accurateTotal'] as bool
      ..ids = (json['ids'] as List<dynamic>).map((e) => e as String).toList()
      ..query = json['query'] as String
      ..queryString = json['queryString'] as String
      ..sortFields = (json['sortFields'] as List<dynamic>)
          .map((e) => SortField.fromJson(e as Map<String, dynamic>))
          .toList();

Map<String, dynamic> _$UserSearchCriteriaToJson(UserSearchCriteria instance) =>
    <String, dynamic>{
      'numberOfResults': instance.numberOfResults,
      'orderBy': instance.orderBy,
      'startRow': instance.startRow,
      'accurateTotal': instance.accurateTotal,
      'ids': instance.ids,
      'query': instance.query,
      'queryString': instance.queryString,
      'sortFields': instance.sortFields,
    };

UserTwoFactorConfiguration _$UserTwoFactorConfigurationFromJson(
        Map<String, dynamic> json) =>
    UserTwoFactorConfiguration(
      methods: (json['methods'] as List<dynamic>)
          .map((e) => TwoFactorMethod.fromJson(e as Map<String, dynamic>))
          .toList(),
      recoveryCodes: (json['recoveryCodes'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
    );

Map<String, dynamic> _$UserTwoFactorConfigurationToJson(
        UserTwoFactorConfiguration instance) =>
    <String, dynamic>{
      'methods': instance.methods,
      'recoveryCodes': instance.recoveryCodes,
    };

UserTwoFactorMethodAddEvent _$UserTwoFactorMethodAddEventFromJson(
        Map<String, dynamic> json) =>
    UserTwoFactorMethodAddEvent(
      method: TwoFactorMethod.fromJson(json['method'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserTwoFactorMethodAddEventToJson(
        UserTwoFactorMethodAddEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'method': instance.method,
      'user': instance.user,
    };

UserTwoFactorMethodRemoveEvent _$UserTwoFactorMethodRemoveEventFromJson(
        Map<String, dynamic> json) =>
    UserTwoFactorMethodRemoveEvent(
      method: TwoFactorMethod.fromJson(json['method'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserTwoFactorMethodRemoveEventToJson(
        UserTwoFactorMethodRemoveEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'method': instance.method,
      'user': instance.user,
    };

UserUpdateCompleteEvent _$UserUpdateCompleteEventFromJson(
        Map<String, dynamic> json) =>
    UserUpdateCompleteEvent(
      original: User.fromJson(json['original'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserUpdateCompleteEventToJson(
        UserUpdateCompleteEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'original': instance.original,
      'user': instance.user,
    };

UserUpdateEvent _$UserUpdateEventFromJson(Map<String, dynamic> json) =>
    UserUpdateEvent(
      original: User.fromJson(json['original'] as Map<String, dynamic>),
      user: User.fromJson(json['user'] as Map<String, dynamic>),
    )
      ..createInstant = json['createInstant'] as num
      ..id = json['id'] as String
      ..info = EventInfo.fromJson(json['info'] as Map<String, dynamic>)
      ..tenantId = json['tenantId'] as String
      ..type = _$enumDecode(_$EventTypeEnumMap, json['type']);

Map<String, dynamic> _$UserUpdateEventToJson(UserUpdateEvent instance) =>
    <String, dynamic>{
      'createInstant': instance.createInstant,
      'id': instance.id,
      'info': instance.info,
      'tenantId': instance.tenantId,
      'type': _$EventTypeEnumMap[instance.type],
      'original': instance.original,
      'user': instance.user,
    };

ValidateResponse _$ValidateResponseFromJson(Map<String, dynamic> json) =>
    ValidateResponse(
      jwt: JWT.fromJson(json['jwt'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$ValidateResponseToJson(ValidateResponse instance) =>
    <String, dynamic>{
      'jwt': instance.jwt,
    };

VerifyEmailRequest _$VerifyEmailRequestFromJson(Map<String, dynamic> json) =>
    VerifyEmailRequest(
      oneTimeCode: json['oneTimeCode'] as String,
      userId: json['userId'] as String,
      verificationId: json['verificationId'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$VerifyEmailRequestToJson(VerifyEmailRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'oneTimeCode': instance.oneTimeCode,
      'userId': instance.userId,
      'verificationId': instance.verificationId,
    };

VerifyEmailResponse _$VerifyEmailResponseFromJson(Map<String, dynamic> json) =>
    VerifyEmailResponse(
      oneTimeCode: json['oneTimeCode'] as String,
      verificationId: json['verificationId'] as String,
    );

Map<String, dynamic> _$VerifyEmailResponseToJson(
        VerifyEmailResponse instance) =>
    <String, dynamic>{
      'oneTimeCode': instance.oneTimeCode,
      'verificationId': instance.verificationId,
    };

VerifyRegistrationRequest _$VerifyRegistrationRequestFromJson(
        Map<String, dynamic> json) =>
    VerifyRegistrationRequest(
      oneTimeCode: json['oneTimeCode'] as String,
      verificationId: json['verificationId'] as String,
    )..eventInfo =
        EventInfo.fromJson(json['eventInfo'] as Map<String, dynamic>);

Map<String, dynamic> _$VerifyRegistrationRequestToJson(
        VerifyRegistrationRequest instance) =>
    <String, dynamic>{
      'eventInfo': instance.eventInfo,
      'oneTimeCode': instance.oneTimeCode,
      'verificationId': instance.verificationId,
    };

VerifyRegistrationResponse _$VerifyRegistrationResponseFromJson(
        Map<String, dynamic> json) =>
    VerifyRegistrationResponse(
      oneTimeCode: json['oneTimeCode'] as String,
      verificationId: json['verificationId'] as String,
    );

Map<String, dynamic> _$VerifyRegistrationResponseToJson(
        VerifyRegistrationResponse instance) =>
    <String, dynamic>{
      'oneTimeCode': instance.oneTimeCode,
      'verificationId': instance.verificationId,
    };

VersionResponse _$VersionResponseFromJson(Map<String, dynamic> json) =>
    VersionResponse(
      version: json['version'] as String,
    );

Map<String, dynamic> _$VersionResponseToJson(VersionResponse instance) =>
    <String, dynamic>{
      'version': instance.version,
    };

Webhook _$WebhookFromJson(Map<String, dynamic> json) => Webhook(
      applicationIds: (json['applicationIds'] as List<dynamic>)
          .map((e) => e as String)
          .toList(),
      connectTimeout: json['connectTimeout'] as num,
      data: json['data'] as Map<String, dynamic>,
      description: json['description'] as String,
      eventsEnabled: (json['eventsEnabled'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(_$enumDecode(_$EventTypeEnumMap, k), e as bool),
      ),
      global: json['global'] as bool,
      headers: Map<String, String>.from(json['headers'] as Map),
      httpAuthenticationPassword: json['httpAuthenticationPassword'] as String,
      httpAuthenticationUsername: json['httpAuthenticationUsername'] as String,
      id: json['id'] as String,
      insertInstant: json['insertInstant'] as num,
      lastUpdateInstant: json['lastUpdateInstant'] as num,
      readTimeout: json['readTimeout'] as num,
      sslCertificate: json['sslCertificate'] as String,
      url: json['url'] as String,
    );

Map<String, dynamic> _$WebhookToJson(Webhook instance) => <String, dynamic>{
      'applicationIds': instance.applicationIds,
      'connectTimeout': instance.connectTimeout,
      'data': instance.data,
      'description': instance.description,
      'eventsEnabled': instance.eventsEnabled
          .map((k, e) => MapEntry(_$EventTypeEnumMap[k], e)),
      'global': instance.global,
      'headers': instance.headers,
      'httpAuthenticationPassword': instance.httpAuthenticationPassword,
      'httpAuthenticationUsername': instance.httpAuthenticationUsername,
      'id': instance.id,
      'insertInstant': instance.insertInstant,
      'lastUpdateInstant': instance.lastUpdateInstant,
      'readTimeout': instance.readTimeout,
      'sslCertificate': instance.sslCertificate,
      'url': instance.url,
    };

WebhookRequest _$WebhookRequestFromJson(Map<String, dynamic> json) =>
    WebhookRequest(
      webhook: Webhook.fromJson(json['webhook'] as Map<String, dynamic>),
    );

Map<String, dynamic> _$WebhookRequestToJson(WebhookRequest instance) =>
    <String, dynamic>{
      'webhook': instance.webhook,
    };

WebhookResponse _$WebhookResponseFromJson(Map<String, dynamic> json) =>
    WebhookResponse(
      webhook: Webhook.fromJson(json['webhook'] as Map<String, dynamic>),
      webhooks: (json['webhooks'] as List<dynamic>)
          .map((e) => Webhook.fromJson(e as Map<String, dynamic>))
          .toList(),
    );

Map<String, dynamic> _$WebhookResponseToJson(WebhookResponse instance) =>
    <String, dynamic>{
      'webhook': instance.webhook,
      'webhooks': instance.webhooks,
    };

XboxApplicationConfiguration _$XboxApplicationConfigurationFromJson(
        Map<String, dynamic> json) =>
    XboxApplicationConfiguration(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..createRegistration = json['createRegistration'] as bool
      ..data = json['data'] as Map<String, dynamic>;

Map<String, dynamic> _$XboxApplicationConfigurationToJson(
        XboxApplicationConfiguration instance) =>
    <String, dynamic>{
      'enabled': instance.enabled,
      'createRegistration': instance.createRegistration,
      'data': instance.data,
      'buttonText': instance.buttonText,
      'client_id': instance.client_id,
      'client_secret': instance.client_secret,
      'scope': instance.scope,
    };

XboxIdentityProvider _$XboxIdentityProviderFromJson(
        Map<String, dynamic> json) =>
    XboxIdentityProvider(
      buttonText: json['buttonText'] as String,
      client_id: json['client_id'] as String,
      client_secret: json['client_secret'] as String,
      scope: json['scope'] as String,
    )
      ..enabled = json['enabled'] as bool
      ..applicationConfiguration =
          (json['applicationConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(k,
            XboxApplicationConfiguration.fromJson(e as Map<String, dynamic>)),
      )
      ..data = json['data'] as Map<String, dynamic>
      ..debug = json['debug'] as bool
      ..id = json['id'] as String
      ..insertInstant = json['insertInstant'] as num
      ..lambdaConfiguration = json['lambdaConfiguration']
      ..lastUpdateInstant = json['lastUpdateInstant'] as num
      ..linkingStrategy = _$enumDecode(
          _$IdentityProviderLinkingStrategyEnumMap, json['linkingStrategy'])
      ..name = json['name'] as String
      ..tenantConfiguration =
          (json['tenantConfiguration'] as Map<String, dynamic>).map(
        (k, e) => MapEntry(
            k,
            IdentityProviderTenantConfiguration.fromJson(
                e as Map<String, dynamic>)),
      )
      ..type = _$enumDecode(_$IdentityProviderTypeEnumMap, json['type']);

Map<String, dynamic> _$XboxIdentityProviderToJson(
    XboxIdentityProvider instance) {
  final val = <String, dynamic>{
    'enabled': instance.enabled,
    'applicationConfiguration': instance.applicationConfiguration,
    'data': instance.data,
    'debug': instance.debug,
    'id': instance.id,
    'insertInstant': instance.insertInstant,
  };

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  val['lastUpdateInstant'] = instance.lastUpdateInstant;
  val['linkingStrategy'] =
      _$IdentityProviderLinkingStrategyEnumMap[instance.linkingStrategy];
  val['name'] = instance.name;
  val['tenantConfiguration'] = instance.tenantConfiguration;
  val['type'] = _$IdentityProviderTypeEnumMap[instance.type];
  val['buttonText'] = instance.buttonText;
  val['client_id'] = instance.client_id;
  val['client_secret'] = instance.client_secret;
  val['scope'] = instance.scope;
  return val;
}

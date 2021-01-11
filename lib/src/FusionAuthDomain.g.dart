// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'FusionAuthDomain.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AccessToken _$AccessTokenFromJson(Map<String, dynamic> json) {
  return AccessToken(
    access_token: json['access_token'] as String,
    expires_in: json['expires_in'] as num,
    id_token: json['id_token'] as String,
    refresh_token: json['refresh_token'] as String,
    scope: json['scope'] as String,
    token_type: _$enumDecodeNullable(_$TokenTypeEnumMap, json['token_type']),
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$AccessTokenToJson(AccessToken instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('access_token', instance.access_token);
  writeNotNull('expires_in', instance.expires_in);
  writeNotNull('id_token', instance.id_token);
  writeNotNull('refresh_token', instance.refresh_token);
  writeNotNull('scope', instance.scope);
  writeNotNull('token_type', _$TokenTypeEnumMap[instance.token_type]);
  writeNotNull('userId', instance.userId);
  return val;
}

T _$enumDecode<T>(
  Map<T, dynamic> enumValues,
  dynamic source, {
  T unknownValue,
}) {
  if (source == null) {
    throw ArgumentError('A value must be provided. Supported values: '
        '${enumValues.values.join(', ')}');
  }

  final value = enumValues.entries
      .singleWhere((e) => e.value == source, orElse: () => null)
      ?.key;

  if (value == null && unknownValue == null) {
    throw ArgumentError('`$source` is not one of the supported values: '
        '${enumValues.values.join(', ')}');
  }
  return value ?? unknownValue;
}

T _$enumDecodeNullable<T>(
  Map<T, dynamic> enumValues,
  dynamic source, {
  T unknownValue,
}) {
  if (source == null) {
    return null;
  }
  return _$enumDecode<T>(enumValues, source, unknownValue: unknownValue);
}

const _$TokenTypeEnumMap = {
  TokenType.Bearer: 'Bearer',
  TokenType.MAC: 'MAC',
};

ActionData _$ActionDataFromJson(Map<String, dynamic> json) {
  return ActionData(
    actioneeUserId: json['actioneeUserId'] as String,
    actionerUserId: json['actionerUserId'] as String,
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    comment: json['comment'] as String,
    emailUser: json['emailUser'] as bool,
    expiry: json['expiry'] as num,
    notifyUser: json['notifyUser'] as bool,
    option: json['option'] as String,
    reasonId: json['reasonId'] as String,
    userActionId: json['userActionId'] as String,
  );
}

Map<String, dynamic> _$ActionDataToJson(ActionData instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actioneeUserId', instance.actioneeUserId);
  writeNotNull('actionerUserId', instance.actionerUserId);
  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('comment', instance.comment);
  writeNotNull('emailUser', instance.emailUser);
  writeNotNull('expiry', instance.expiry);
  writeNotNull('notifyUser', instance.notifyUser);
  writeNotNull('option', instance.option);
  writeNotNull('reasonId', instance.reasonId);
  writeNotNull('userActionId', instance.userActionId);
  return val;
}

ActionRequest _$ActionRequestFromJson(Map<String, dynamic> json) {
  return ActionRequest(
    action: json['action'] == null
        ? null
        : ActionData.fromJson(json['action'] as Map<String, dynamic>),
    broadcast: json['broadcast'] as bool,
  );
}

Map<String, dynamic> _$ActionRequestToJson(ActionRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('action', instance.action);
  writeNotNull('broadcast', instance.broadcast);
  return val;
}

ActionResponse _$ActionResponseFromJson(Map<String, dynamic> json) {
  return ActionResponse(
    action: json['action'] == null
        ? null
        : UserActionLog.fromJson(json['action'] as Map<String, dynamic>),
    actions: (json['actions'] as List)
        ?.map((e) => e == null
            ? null
            : UserActionLog.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$ActionResponseToJson(ActionResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('action', instance.action);
  writeNotNull('actions', instance.actions);
  return val;
}

AppleApplicationConfiguration _$AppleApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return AppleApplicationConfiguration(
    buttonText: json['buttonText'] as String,
    keyId: json['keyId'] as String,
    scope: json['scope'] as String,
    servicesId: json['servicesId'] as String,
    teamId: json['teamId'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$AppleApplicationConfigurationToJson(
    AppleApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('keyId', instance.keyId);
  writeNotNull('scope', instance.scope);
  writeNotNull('servicesId', instance.servicesId);
  writeNotNull('teamId', instance.teamId);
  return val;
}

AppleIdentityProvider _$AppleIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return AppleIdentityProvider(
    buttonText: json['buttonText'] as String,
    keyId: json['keyId'] as String,
    scope: json['scope'] as String,
    servicesId: json['servicesId'] as String,
    teamId: json['teamId'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : AppleApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$AppleIdentityProviderToJson(
    AppleIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('keyId', instance.keyId);
  writeNotNull('scope', instance.scope);
  writeNotNull('servicesId', instance.servicesId);
  writeNotNull('teamId', instance.teamId);
  return val;
}

const _$IdentityProviderTypeEnumMap = {
  IdentityProviderType.ExternalJWT: 'ExternalJWT',
  IdentityProviderType.OpenIDConnect: 'OpenIDConnect',
  IdentityProviderType.Facebook: 'Facebook',
  IdentityProviderType.Google: 'Google',
  IdentityProviderType.Twitter: 'Twitter',
  IdentityProviderType.SAMLv2: 'SAMLv2',
  IdentityProviderType.HYPR: 'HYPR',
  IdentityProviderType.Apple: 'Apple',
  IdentityProviderType.LinkedIn: 'LinkedIn',
};

Application _$ApplicationFromJson(Map<String, dynamic> json) {
  return Application(
    active: json['active'] as bool,
    authenticationTokenConfiguration:
        json['authenticationTokenConfiguration'] == null
            ? null
            : AuthenticationTokenConfiguration.fromJson(
                json['authenticationTokenConfiguration']
                    as Map<String, dynamic>),
    cleanSpeakConfiguration: json['cleanSpeakConfiguration'] == null
        ? null
        : CleanSpeakConfiguration.fromJson(
            json['cleanSpeakConfiguration'] as Map<String, dynamic>),
    data: json['data'] as Map<String, dynamic>,
    emailConfiguration: json['emailConfiguration'] == null
        ? null
        : ApplicationEmailConfiguration.fromJson(
            json['emailConfiguration'] as Map<String, dynamic>),
    formConfiguration: json['formConfiguration'] == null
        ? null
        : ApplicationFormConfiguration.fromJson(
            json['formConfiguration'] as Map<String, dynamic>),
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    jwtConfiguration: json['jwtConfiguration'] == null
        ? null
        : JWTConfiguration.fromJson(
            json['jwtConfiguration'] as Map<String, dynamic>),
    lambdaConfiguration: json['lambdaConfiguration'],
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    loginConfiguration: json['loginConfiguration'] == null
        ? null
        : LoginConfiguration.fromJson(
            json['loginConfiguration'] as Map<String, dynamic>),
    name: json['name'] as String,
    oauthConfiguration: json['oauthConfiguration'] == null
        ? null
        : OAuth2Configuration.fromJson(
            json['oauthConfiguration'] as Map<String, dynamic>),
    passwordlessConfiguration: json['passwordlessConfiguration'] == null
        ? null
        : PasswordlessConfiguration.fromJson(
            json['passwordlessConfiguration'] as Map<String, dynamic>),
    registrationConfiguration: json['registrationConfiguration'] == null
        ? null
        : RegistrationConfiguration.fromJson(
            json['registrationConfiguration'] as Map<String, dynamic>),
    registrationDeletePolicy: json['registrationDeletePolicy'] == null
        ? null
        : ApplicationRegistrationDeletePolicy.fromJson(
            json['registrationDeletePolicy'] as Map<String, dynamic>),
    roles: (json['roles'] as List)
        ?.map((e) => e == null
            ? null
            : ApplicationRole.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    samlv2Configuration: json['samlv2Configuration'] == null
        ? null
        : SAMLv2Configuration.fromJson(
            json['samlv2Configuration'] as Map<String, dynamic>),
    state: _$enumDecodeNullable(_$ObjectStateEnumMap, json['state']),
    tenantId: json['tenantId'] as String,
    verificationEmailTemplateId: json['verificationEmailTemplateId'] as String,
    verifyRegistration: json['verifyRegistration'] as bool,
  );
}

Map<String, dynamic> _$ApplicationToJson(Application instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('active', instance.active);
  writeNotNull('authenticationTokenConfiguration',
      instance.authenticationTokenConfiguration);
  writeNotNull('cleanSpeakConfiguration', instance.cleanSpeakConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('emailConfiguration', instance.emailConfiguration);
  writeNotNull('formConfiguration', instance.formConfiguration);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('jwtConfiguration', instance.jwtConfiguration);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('loginConfiguration', instance.loginConfiguration);
  writeNotNull('name', instance.name);
  writeNotNull('oauthConfiguration', instance.oauthConfiguration);
  writeNotNull('passwordlessConfiguration', instance.passwordlessConfiguration);
  writeNotNull('registrationConfiguration', instance.registrationConfiguration);
  writeNotNull('registrationDeletePolicy', instance.registrationDeletePolicy);
  writeNotNull('roles', instance.roles);
  writeNotNull('samlv2Configuration', instance.samlv2Configuration);
  writeNotNull('state', _$ObjectStateEnumMap[instance.state]);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull(
      'verificationEmailTemplateId', instance.verificationEmailTemplateId);
  writeNotNull('verifyRegistration', instance.verifyRegistration);
  return val;
}

const _$ObjectStateEnumMap = {
  ObjectState.Active: 'Active',
  ObjectState.Inactive: 'Inactive',
  ObjectState.PendingDelete: 'PendingDelete',
};

ApplicationEmailConfiguration _$ApplicationEmailConfigurationFromJson(
    Map<String, dynamic> json) {
  return ApplicationEmailConfiguration(
    emailVerificationEmailTemplateId:
        json['emailVerificationEmailTemplateId'] as String,
    forgotPasswordEmailTemplateId:
        json['forgotPasswordEmailTemplateId'] as String,
    passwordlessEmailTemplateId: json['passwordlessEmailTemplateId'] as String,
    setPasswordEmailTemplateId: json['setPasswordEmailTemplateId'] as String,
  );
}

Map<String, dynamic> _$ApplicationEmailConfigurationToJson(
    ApplicationEmailConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('emailVerificationEmailTemplateId',
      instance.emailVerificationEmailTemplateId);
  writeNotNull(
      'forgotPasswordEmailTemplateId', instance.forgotPasswordEmailTemplateId);
  writeNotNull(
      'passwordlessEmailTemplateId', instance.passwordlessEmailTemplateId);
  writeNotNull(
      'setPasswordEmailTemplateId', instance.setPasswordEmailTemplateId);
  return val;
}

ApplicationEvent _$ApplicationEventFromJson(Map<String, dynamic> json) {
  return ApplicationEvent();
}

Map<String, dynamic> _$ApplicationEventToJson(ApplicationEvent instance) =>
    <String, dynamic>{};

ApplicationFormConfiguration _$ApplicationFormConfigurationFromJson(
    Map<String, dynamic> json) {
  return ApplicationFormConfiguration(
    adminRegistrationFormId: json['adminRegistrationFormId'] as String,
  );
}

Map<String, dynamic> _$ApplicationFormConfigurationToJson(
    ApplicationFormConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('adminRegistrationFormId', instance.adminRegistrationFormId);
  return val;
}

ApplicationRegistrationDeletePolicy
    _$ApplicationRegistrationDeletePolicyFromJson(Map<String, dynamic> json) {
  return ApplicationRegistrationDeletePolicy(
    unverified: json['unverified'] == null
        ? null
        : TimeBasedDeletePolicy.fromJson(
            json['unverified'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ApplicationRegistrationDeletePolicyToJson(
    ApplicationRegistrationDeletePolicy instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('unverified', instance.unverified);
  return val;
}

ApplicationRequest _$ApplicationRequestFromJson(Map<String, dynamic> json) {
  return ApplicationRequest(
    application: json['application'] == null
        ? null
        : Application.fromJson(json['application'] as Map<String, dynamic>),
    role: json['role'] == null
        ? null
        : ApplicationRole.fromJson(json['role'] as Map<String, dynamic>),
    webhookIds: (json['webhookIds'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$ApplicationRequestToJson(ApplicationRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('application', instance.application);
  writeNotNull('role', instance.role);
  writeNotNull('webhookIds', instance.webhookIds);
  return val;
}

ApplicationResponse _$ApplicationResponseFromJson(Map<String, dynamic> json) {
  return ApplicationResponse(
    application: json['application'] == null
        ? null
        : Application.fromJson(json['application'] as Map<String, dynamic>),
    applications: (json['applications'] as List)
        ?.map((e) =>
            e == null ? null : Application.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    role: json['role'] == null
        ? null
        : ApplicationRole.fromJson(json['role'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ApplicationResponseToJson(ApplicationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('application', instance.application);
  writeNotNull('applications', instance.applications);
  writeNotNull('role', instance.role);
  return val;
}

ApplicationRole _$ApplicationRoleFromJson(Map<String, dynamic> json) {
  return ApplicationRole(
    description: json['description'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    isDefault: json['isDefault'] as bool,
    isSuperRole: json['isSuperRole'] as bool,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
  );
}

Map<String, dynamic> _$ApplicationRoleToJson(ApplicationRole instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('description', instance.description);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('isDefault', instance.isDefault);
  writeNotNull('isSuperRole', instance.isSuperRole);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  return val;
}

Attachment _$AttachmentFromJson(Map<String, dynamic> json) {
  return Attachment(
    attachment: (json['attachment'] as List)?.map((e) => e as num)?.toList(),
    mime: json['mime'] as String,
    name: json['name'] as String,
  );
}

Map<String, dynamic> _$AttachmentToJson(Attachment instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('attachment', instance.attachment);
  writeNotNull('mime', instance.mime);
  writeNotNull('name', instance.name);
  return val;
}

AuditLog _$AuditLogFromJson(Map<String, dynamic> json) {
  return AuditLog(
    data: json['data'] as Map<String, dynamic>,
    id: json['id'] as num,
    insertInstant: json['insertInstant'] as num,
    insertUser: json['insertUser'] as String,
    message: json['message'] as String,
    newValue: json['newValue'],
    oldValue: json['oldValue'],
    reason: json['reason'] as String,
  );
}

Map<String, dynamic> _$AuditLogToJson(AuditLog instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('insertUser', instance.insertUser);
  writeNotNull('message', instance.message);
  writeNotNull('newValue', instance.newValue);
  writeNotNull('oldValue', instance.oldValue);
  writeNotNull('reason', instance.reason);
  return val;
}

AuditLogConfiguration _$AuditLogConfigurationFromJson(
    Map<String, dynamic> json) {
  return AuditLogConfiguration(
    delete: json['delete'] == null
        ? null
        : DeleteConfiguration.fromJson(json['delete'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$AuditLogConfigurationToJson(
    AuditLogConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('delete', instance.delete);
  return val;
}

AuditLogExportRequest _$AuditLogExportRequestFromJson(
    Map<String, dynamic> json) {
  return AuditLogExportRequest(
    criteria: json['criteria'] == null
        ? null
        : AuditLogSearchCriteria.fromJson(
            json['criteria'] as Map<String, dynamic>),
  )
    ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
    ..zoneId = json['zoneId'] as String;
}

Map<String, dynamic> _$AuditLogExportRequestToJson(
    AuditLogExportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dateTimeSecondsFormat', instance.dateTimeSecondsFormat);
  writeNotNull('zoneId', instance.zoneId);
  writeNotNull('criteria', instance.criteria);
  return val;
}

AuditLogRequest _$AuditLogRequestFromJson(Map<String, dynamic> json) {
  return AuditLogRequest(
    auditLog: json['auditLog'] == null
        ? null
        : AuditLog.fromJson(json['auditLog'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$AuditLogRequestToJson(AuditLogRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('auditLog', instance.auditLog);
  return val;
}

AuditLogResponse _$AuditLogResponseFromJson(Map<String, dynamic> json) {
  return AuditLogResponse(
    auditLog: json['auditLog'] == null
        ? null
        : AuditLog.fromJson(json['auditLog'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$AuditLogResponseToJson(AuditLogResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('auditLog', instance.auditLog);
  return val;
}

AuditLogSearchCriteria _$AuditLogSearchCriteriaFromJson(
    Map<String, dynamic> json) {
  return AuditLogSearchCriteria(
    end: json['end'] as num,
    message: json['message'] as String,
    start: json['start'] as num,
    user: json['user'] as String,
  )
    ..numberOfResults = json['numberOfResults'] as num
    ..orderBy = json['orderBy'] as String
    ..startRow = json['startRow'] as num;
}

Map<String, dynamic> _$AuditLogSearchCriteriaToJson(
    AuditLogSearchCriteria instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberOfResults', instance.numberOfResults);
  writeNotNull('orderBy', instance.orderBy);
  writeNotNull('startRow', instance.startRow);
  writeNotNull('end', instance.end);
  writeNotNull('message', instance.message);
  writeNotNull('start', instance.start);
  writeNotNull('user', instance.user);
  return val;
}

AuditLogSearchRequest _$AuditLogSearchRequestFromJson(
    Map<String, dynamic> json) {
  return AuditLogSearchRequest(
    search: json['search'] == null
        ? null
        : AuditLogSearchCriteria.fromJson(
            json['search'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$AuditLogSearchRequestToJson(
    AuditLogSearchRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('search', instance.search);
  return val;
}

AuditLogSearchResponse _$AuditLogSearchResponseFromJson(
    Map<String, dynamic> json) {
  return AuditLogSearchResponse(
    auditLogs: (json['auditLogs'] as List)
        ?.map((e) =>
            e == null ? null : AuditLog.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$AuditLogSearchResponseToJson(
    AuditLogSearchResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('auditLogs', instance.auditLogs);
  writeNotNull('total', instance.total);
  return val;
}

AuthenticationTokenConfiguration _$AuthenticationTokenConfigurationFromJson(
    Map<String, dynamic> json) {
  return AuthenticationTokenConfiguration()..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$AuthenticationTokenConfigurationToJson(
    AuthenticationTokenConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  return val;
}

BaseConnectorConfiguration _$BaseConnectorConfigurationFromJson(
    Map<String, dynamic> json) {
  return BaseConnectorConfiguration(
    data: json['data'] as Map<String, dynamic>,
    debug: json['debug'] as bool,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
    type: _$enumDecodeNullable(_$ConnectorTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$BaseConnectorConfigurationToJson(
    BaseConnectorConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$ConnectorTypeEnumMap[instance.type]);
  return val;
}

const _$ConnectorTypeEnumMap = {
  ConnectorType.FusionAuth: 'FusionAuth',
  ConnectorType.Generic: 'Generic',
  ConnectorType.LDAP: 'LDAP',
};

BaseEvent _$BaseEventFromJson(Map<String, dynamic> json) {
  return BaseEvent(
    createInstant: json['createInstant'] as num,
    id: json['id'] as String,
    tenantId: json['tenantId'] as String,
  );
}

Map<String, dynamic> _$BaseEventToJson(BaseEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  return val;
}

BaseExportRequest _$BaseExportRequestFromJson(Map<String, dynamic> json) {
  return BaseExportRequest(
    dateTimeSecondsFormat: json['dateTimeSecondsFormat'] as String,
    zoneId: json['zoneId'] as String,
  );
}

Map<String, dynamic> _$BaseExportRequestToJson(BaseExportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dateTimeSecondsFormat', instance.dateTimeSecondsFormat);
  writeNotNull('zoneId', instance.zoneId);
  return val;
}

Map<String, dynamic> _$BaseIdentityProviderToJson<
        D extends BaseIdentityProviderApplicationConfiguration>(
    BaseIdentityProvider<D> instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull(
      'applicationConfiguration',
      instance.applicationConfiguration?.map((k, e) => MapEntry(k,
          IdentityProviderApplicationConfigurationConverter<D>().toJson(e))));
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  return val;
}

BaseIdentityProviderApplicationConfiguration
    _$BaseIdentityProviderApplicationConfigurationFromJson(
        Map<String, dynamic> json) {
  return BaseIdentityProviderApplicationConfiguration(
    createRegistration: json['createRegistration'] as bool,
    data: json['data'] as Map<String, dynamic>,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$BaseIdentityProviderApplicationConfigurationToJson(
    BaseIdentityProviderApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  return val;
}

BaseLoginRequest _$BaseLoginRequestFromJson(Map<String, dynamic> json) {
  return BaseLoginRequest(
    applicationId: json['applicationId'] as String,
    ipAddress: json['ipAddress'] as String,
    metaData: json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>),
    noJWT: json['noJWT'] as bool,
  );
}

Map<String, dynamic> _$BaseLoginRequestToJson(BaseLoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  return val;
}

BaseSearchCriteria _$BaseSearchCriteriaFromJson(Map<String, dynamic> json) {
  return BaseSearchCriteria(
    numberOfResults: json['numberOfResults'] as num,
    orderBy: json['orderBy'] as String,
    startRow: json['startRow'] as num,
  );
}

Map<String, dynamic> _$BaseSearchCriteriaToJson(BaseSearchCriteria instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberOfResults', instance.numberOfResults);
  writeNotNull('orderBy', instance.orderBy);
  writeNotNull('startRow', instance.startRow);
  return val;
}

CertificateInformation _$CertificateInformationFromJson(
    Map<String, dynamic> json) {
  return CertificateInformation(
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
}

Map<String, dynamic> _$CertificateInformationToJson(
    CertificateInformation instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('issuer', instance.issuer);
  writeNotNull('md5Fingerprint', instance.md5Fingerprint);
  writeNotNull('serialNumber', instance.serialNumber);
  writeNotNull('sha1Fingerprint', instance.sha1Fingerprint);
  writeNotNull('sha1Thumbprint', instance.sha1Thumbprint);
  writeNotNull('sha256Fingerprint', instance.sha256Fingerprint);
  writeNotNull('sha256Thumbprint', instance.sha256Thumbprint);
  writeNotNull('subject', instance.subject);
  writeNotNull('validFrom', instance.validFrom);
  writeNotNull('validTo', instance.validTo);
  return val;
}

ChangePasswordRequest _$ChangePasswordRequestFromJson(
    Map<String, dynamic> json) {
  return ChangePasswordRequest(
    currentPassword: json['currentPassword'] as String,
    loginId: json['loginId'] as String,
    password: json['password'] as String,
    refreshToken: json['refreshToken'] as String,
  );
}

Map<String, dynamic> _$ChangePasswordRequestToJson(
    ChangePasswordRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('currentPassword', instance.currentPassword);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('password', instance.password);
  writeNotNull('refreshToken', instance.refreshToken);
  return val;
}

ChangePasswordResponse _$ChangePasswordResponseFromJson(
    Map<String, dynamic> json) {
  return ChangePasswordResponse(
    oneTimePassword: json['oneTimePassword'] as String,
    state: json['state'] as Map<String, dynamic>,
  );
}

Map<String, dynamic> _$ChangePasswordResponseToJson(
    ChangePasswordResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('oneTimePassword', instance.oneTimePassword);
  writeNotNull('state', instance.state);
  return val;
}

CleanSpeakConfiguration _$CleanSpeakConfigurationFromJson(
    Map<String, dynamic> json) {
  return CleanSpeakConfiguration(
    apiKey: json['apiKey'] as String,
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    url: json['url'] as String,
    usernameModeration: json['usernameModeration'] == null
        ? null
        : UsernameModeration.fromJson(
            json['usernameModeration'] as Map<String, dynamic>),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$CleanSpeakConfigurationToJson(
    CleanSpeakConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('apiKey', instance.apiKey);
  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('url', instance.url);
  writeNotNull('usernameModeration', instance.usernameModeration);
  return val;
}

ConnectorPolicy _$ConnectorPolicyFromJson(Map<String, dynamic> json) {
  return ConnectorPolicy(
    connectorId: json['connectorId'] as String,
    data: json['data'] as Map<String, dynamic>,
    domains: (json['domains'] as List)?.map((e) => e as String)?.toSet(),
    migrate: json['migrate'] as bool,
  );
}

Map<String, dynamic> _$ConnectorPolicyToJson(ConnectorPolicy instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('connectorId', instance.connectorId);
  writeNotNull('data', instance.data);
  writeNotNull('domains', instance.domains?.toList());
  writeNotNull('migrate', instance.migrate);
  return val;
}

ConnectorRequest _$ConnectorRequestFromJson(Map<String, dynamic> json) {
  return ConnectorRequest(
    connector: json['connector'] == null
        ? null
        : BaseConnectorConfiguration.fromJson(
            json['connector'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ConnectorRequestToJson(ConnectorRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('connector', instance.connector);
  return val;
}

ConnectorResponse _$ConnectorResponseFromJson(Map<String, dynamic> json) {
  return ConnectorResponse(
    connector: json['connector'] == null
        ? null
        : BaseConnectorConfiguration.fromJson(
            json['connector'] as Map<String, dynamic>),
    connectors: (json['connectors'] as List)
        ?.map((e) => e == null
            ? null
            : BaseConnectorConfiguration.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$ConnectorResponseToJson(ConnectorResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('connector', instance.connector);
  writeNotNull('connectors', instance.connectors);
  return val;
}

Consent _$ConsentFromJson(Map<String, dynamic> json) {
  return Consent(
    consentEmailTemplateId: json['consentEmailTemplateId'] as String,
    countryMinimumAgeForSelfConsent:
        (json['countryMinimumAgeForSelfConsent'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as num),
    ),
    data: json['data'] as Map<String, dynamic>,
    defaultMinimumAgeForSelfConsent:
        json['defaultMinimumAgeForSelfConsent'] as num,
    emailPlus: json['emailPlus'] == null
        ? null
        : EmailPlus.fromJson(json['emailPlus'] as Map<String, dynamic>),
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    multipleValuesAllowed: json['multipleValuesAllowed'] as bool,
    name: json['name'] as String,
    values: (json['values'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$ConsentToJson(Consent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('consentEmailTemplateId', instance.consentEmailTemplateId);
  writeNotNull('countryMinimumAgeForSelfConsent',
      instance.countryMinimumAgeForSelfConsent);
  writeNotNull('data', instance.data);
  writeNotNull('defaultMinimumAgeForSelfConsent',
      instance.defaultMinimumAgeForSelfConsent);
  writeNotNull('emailPlus', instance.emailPlus);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('multipleValuesAllowed', instance.multipleValuesAllowed);
  writeNotNull('name', instance.name);
  writeNotNull('values', instance.values);
  return val;
}

ConsentRequest _$ConsentRequestFromJson(Map<String, dynamic> json) {
  return ConsentRequest(
    consent: json['consent'] == null
        ? null
        : Consent.fromJson(json['consent'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ConsentRequestToJson(ConsentRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('consent', instance.consent);
  return val;
}

ConsentResponse _$ConsentResponseFromJson(Map<String, dynamic> json) {
  return ConsentResponse(
    consent: json['consent'] == null
        ? null
        : Consent.fromJson(json['consent'] as Map<String, dynamic>),
    consents: (json['consents'] as List)
        ?.map((e) =>
            e == null ? null : Consent.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$ConsentResponseToJson(ConsentResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('consent', instance.consent);
  writeNotNull('consents', instance.consents);
  return val;
}

CORSConfiguration _$CORSConfigurationFromJson(Map<String, dynamic> json) {
  return CORSConfiguration(
    allowCredentials: json['allowCredentials'] as bool,
    allowedHeaders:
        (json['allowedHeaders'] as List)?.map((e) => e as String)?.toList(),
    allowedMethods: (json['allowedMethods'] as List)
        ?.map((e) => _$enumDecodeNullable(_$HTTPMethodEnumMap, e))
        ?.toList(),
    allowedOrigins:
        (json['allowedOrigins'] as List)?.map((e) => e as String)?.toList(),
    exposedHeaders:
        (json['exposedHeaders'] as List)?.map((e) => e as String)?.toList(),
    preflightMaxAgeInSeconds: json['preflightMaxAgeInSeconds'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$CORSConfigurationToJson(CORSConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('allowCredentials', instance.allowCredentials);
  writeNotNull('allowedHeaders', instance.allowedHeaders);
  writeNotNull('allowedMethods',
      instance.allowedMethods?.map((e) => _$HTTPMethodEnumMap[e])?.toList());
  writeNotNull('allowedOrigins', instance.allowedOrigins);
  writeNotNull('exposedHeaders', instance.exposedHeaders);
  writeNotNull('preflightMaxAgeInSeconds', instance.preflightMaxAgeInSeconds);
  return val;
}

const _$HTTPMethodEnumMap = {
  HTTPMethod.GET: 'GET',
  HTTPMethod.POST: 'POST',
  HTTPMethod.PUT: 'PUT',
  HTTPMethod.DELETE: 'DELETE',
  HTTPMethod.HEAD: 'HEAD',
  HTTPMethod.OPTIONS: 'OPTIONS',
  HTTPMethod.PATCH: 'PATCH',
};

Count _$CountFromJson(Map<String, dynamic> json) {
  return Count(
    count: json['count'] as num,
    interval: json['interval'] as num,
  );
}

Map<String, dynamic> _$CountToJson(Count instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('count', instance.count);
  writeNotNull('interval', instance.interval);
  return val;
}

DailyActiveUserReportResponse _$DailyActiveUserReportResponseFromJson(
    Map<String, dynamic> json) {
  return DailyActiveUserReportResponse(
    dailyActiveUsers: (json['dailyActiveUsers'] as List)
        ?.map(
            (e) => e == null ? null : Count.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$DailyActiveUserReportResponseToJson(
    DailyActiveUserReportResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dailyActiveUsers', instance.dailyActiveUsers);
  writeNotNull('total', instance.total);
  return val;
}

DeleteConfiguration _$DeleteConfigurationFromJson(Map<String, dynamic> json) {
  return DeleteConfiguration(
    numberOfDaysToRetain: json['numberOfDaysToRetain'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$DeleteConfigurationToJson(DeleteConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('numberOfDaysToRetain', instance.numberOfDaysToRetain);
  return val;
}

DeviceInfo _$DeviceInfoFromJson(Map<String, dynamic> json) {
  return DeviceInfo(
    description: json['description'] as String,
    lastAccessedAddress: json['lastAccessedAddress'] as String,
    lastAccessedInstant: json['lastAccessedInstant'] as num,
    name: json['name'] as String,
    type: _$enumDecodeNullable(_$DeviceTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$DeviceInfoToJson(DeviceInfo instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('description', instance.description);
  writeNotNull('lastAccessedAddress', instance.lastAccessedAddress);
  writeNotNull('lastAccessedInstant', instance.lastAccessedInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$DeviceTypeEnumMap[instance.type]);
  return val;
}

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

DeviceResponse _$DeviceResponseFromJson(Map<String, dynamic> json) {
  return DeviceResponse(
    device_code: json['device_code'] as String,
    expires_in: json['expires_in'] as num,
    interval: json['interval'] as num,
    user_code: json['user_code'] as String,
    verification_uri: json['verification_uri'] as String,
    verification_uri_complete: json['verification_uri_complete'] as String,
  );
}

Map<String, dynamic> _$DeviceResponseToJson(DeviceResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('device_code', instance.device_code);
  writeNotNull('expires_in', instance.expires_in);
  writeNotNull('interval', instance.interval);
  writeNotNull('user_code', instance.user_code);
  writeNotNull('verification_uri', instance.verification_uri);
  writeNotNull('verification_uri_complete', instance.verification_uri_complete);
  return val;
}

DisplayableRawLogin _$DisplayableRawLoginFromJson(Map<String, dynamic> json) {
  return DisplayableRawLogin(
    applicationName: json['applicationName'] as String,
    loginId: json['loginId'] as String,
  )
    ..applicationId = json['applicationId'] as String
    ..instant = json['instant'] as num
    ..ipAddress = json['ipAddress'] as String
    ..userId = json['userId'] as String;
}

Map<String, dynamic> _$DisplayableRawLoginToJson(DisplayableRawLogin instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('instant', instance.instant);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('userId', instance.userId);
  writeNotNull('applicationName', instance.applicationName);
  writeNotNull('loginId', instance.loginId);
  return val;
}

DomainBasedIdentityProvider _$DomainBasedIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return DomainBasedIdentityProvider();
}

Map<String, dynamic> _$DomainBasedIdentityProviderToJson(
        DomainBasedIdentityProvider instance) =>
    <String, dynamic>{};

Email _$EmailFromJson(Map<String, dynamic> json) {
  return Email(
    attachments: (json['attachments'] as List)
        ?.map((e) =>
            e == null ? null : Attachment.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    bcc: (json['bcc'] as List)
        ?.map((e) =>
            e == null ? null : EmailAddress.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    cc: (json['cc'] as List)
        ?.map((e) =>
            e == null ? null : EmailAddress.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    from: json['from'] == null
        ? null
        : EmailAddress.fromJson(json['from'] as Map<String, dynamic>),
    html: json['html'] as String,
    replyTo: json['replyTo'] == null
        ? null
        : EmailAddress.fromJson(json['replyTo'] as Map<String, dynamic>),
    subject: json['subject'] as String,
    text: json['text'] as String,
    to: (json['to'] as List)
        ?.map((e) =>
            e == null ? null : EmailAddress.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$EmailToJson(Email instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('attachments', instance.attachments);
  writeNotNull('bcc', instance.bcc);
  writeNotNull('cc', instance.cc);
  writeNotNull('from', instance.from);
  writeNotNull('html', instance.html);
  writeNotNull('replyTo', instance.replyTo);
  writeNotNull('subject', instance.subject);
  writeNotNull('text', instance.text);
  writeNotNull('to', instance.to);
  return val;
}

EmailAddress _$EmailAddressFromJson(Map<String, dynamic> json) {
  return EmailAddress(
    address: json['address'] as String,
    display: json['display'] as String,
  );
}

Map<String, dynamic> _$EmailAddressToJson(EmailAddress instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('address', instance.address);
  writeNotNull('display', instance.display);
  return val;
}

EmailConfiguration _$EmailConfigurationFromJson(Map<String, dynamic> json) {
  return EmailConfiguration(
    defaultFromEmail: json['defaultFromEmail'] as String,
    defaultFromName: json['defaultFromName'] as String,
    forgotPasswordEmailTemplateId:
        json['forgotPasswordEmailTemplateId'] as String,
    host: json['host'] as String,
    password: json['password'] as String,
    passwordlessEmailTemplateId: json['passwordlessEmailTemplateId'] as String,
    port: json['port'] as num,
    properties: json['properties'] as String,
    security:
        _$enumDecodeNullable(_$EmailSecurityTypeEnumMap, json['security']),
    setPasswordEmailTemplateId: json['setPasswordEmailTemplateId'] as String,
    username: json['username'] as String,
    verificationEmailTemplateId: json['verificationEmailTemplateId'] as String,
    verifyEmail: json['verifyEmail'] as bool,
    verifyEmailWhenChanged: json['verifyEmailWhenChanged'] as bool,
  );
}

Map<String, dynamic> _$EmailConfigurationToJson(EmailConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('defaultFromEmail', instance.defaultFromEmail);
  writeNotNull('defaultFromName', instance.defaultFromName);
  writeNotNull(
      'forgotPasswordEmailTemplateId', instance.forgotPasswordEmailTemplateId);
  writeNotNull('host', instance.host);
  writeNotNull('password', instance.password);
  writeNotNull(
      'passwordlessEmailTemplateId', instance.passwordlessEmailTemplateId);
  writeNotNull('port', instance.port);
  writeNotNull('properties', instance.properties);
  writeNotNull('security', _$EmailSecurityTypeEnumMap[instance.security]);
  writeNotNull(
      'setPasswordEmailTemplateId', instance.setPasswordEmailTemplateId);
  writeNotNull('username', instance.username);
  writeNotNull(
      'verificationEmailTemplateId', instance.verificationEmailTemplateId);
  writeNotNull('verifyEmail', instance.verifyEmail);
  writeNotNull('verifyEmailWhenChanged', instance.verifyEmailWhenChanged);
  return val;
}

const _$EmailSecurityTypeEnumMap = {
  EmailSecurityType.NONE: 'NONE',
  EmailSecurityType.SSL: 'SSL',
  EmailSecurityType.TLS: 'TLS',
};

EmailPlus _$EmailPlusFromJson(Map<String, dynamic> json) {
  return EmailPlus(
    emailTemplateId: json['emailTemplateId'] as String,
    maximumTimeToSendEmailInHours: json['maximumTimeToSendEmailInHours'] as num,
    minimumTimeToSendEmailInHours: json['minimumTimeToSendEmailInHours'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$EmailPlusToJson(EmailPlus instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('emailTemplateId', instance.emailTemplateId);
  writeNotNull(
      'maximumTimeToSendEmailInHours', instance.maximumTimeToSendEmailInHours);
  writeNotNull(
      'minimumTimeToSendEmailInHours', instance.minimumTimeToSendEmailInHours);
  return val;
}

EmailTemplate _$EmailTemplateFromJson(Map<String, dynamic> json) {
  return EmailTemplate(
    defaultFromName: json['defaultFromName'] as String,
    defaultHtmlTemplate: json['defaultHtmlTemplate'] as String,
    defaultSubject: json['defaultSubject'] as String,
    defaultTextTemplate: json['defaultTextTemplate'] as String,
    fromEmail: json['fromEmail'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    localizedFromNames:
        (json['localizedFromNames'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    localizedHtmlTemplates:
        (json['localizedHtmlTemplates'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    localizedSubjects: (json['localizedSubjects'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    localizedTextTemplates:
        (json['localizedTextTemplates'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    name: json['name'] as String,
  );
}

Map<String, dynamic> _$EmailTemplateToJson(EmailTemplate instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('defaultFromName', instance.defaultFromName);
  writeNotNull('defaultHtmlTemplate', instance.defaultHtmlTemplate);
  writeNotNull('defaultSubject', instance.defaultSubject);
  writeNotNull('defaultTextTemplate', instance.defaultTextTemplate);
  writeNotNull('fromEmail', instance.fromEmail);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('localizedFromNames', instance.localizedFromNames);
  writeNotNull('localizedHtmlTemplates', instance.localizedHtmlTemplates);
  writeNotNull('localizedSubjects', instance.localizedSubjects);
  writeNotNull('localizedTextTemplates', instance.localizedTextTemplates);
  writeNotNull('name', instance.name);
  return val;
}

EmailTemplateErrors _$EmailTemplateErrorsFromJson(Map<String, dynamic> json) {
  return EmailTemplateErrors(
    parseErrors: (json['parseErrors'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    renderErrors: (json['renderErrors'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
  );
}

Map<String, dynamic> _$EmailTemplateErrorsToJson(EmailTemplateErrors instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('parseErrors', instance.parseErrors);
  writeNotNull('renderErrors', instance.renderErrors);
  return val;
}

EmailTemplateRequest _$EmailTemplateRequestFromJson(Map<String, dynamic> json) {
  return EmailTemplateRequest(
    emailTemplate: json['emailTemplate'] == null
        ? null
        : EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$EmailTemplateRequestToJson(
    EmailTemplateRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('emailTemplate', instance.emailTemplate);
  return val;
}

EmailTemplateResponse _$EmailTemplateResponseFromJson(
    Map<String, dynamic> json) {
  return EmailTemplateResponse(
    emailTemplate: json['emailTemplate'] == null
        ? null
        : EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
    emailTemplates: (json['emailTemplates'] as List)
        ?.map((e) => e == null
            ? null
            : EmailTemplate.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$EmailTemplateResponseToJson(
    EmailTemplateResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('emailTemplate', instance.emailTemplate);
  writeNotNull('emailTemplates', instance.emailTemplates);
  return val;
}

Enableable _$EnableableFromJson(Map<String, dynamic> json) {
  return Enableable(
    enabled: json['enabled'] as bool,
  );
}

Map<String, dynamic> _$EnableableToJson(Enableable instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  return val;
}

Error _$ErrorFromJson(Map<String, dynamic> json) {
  return Error(
    code: json['code'] as String,
    message: json['message'] as String,
  );
}

Map<String, dynamic> _$ErrorToJson(Error instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('code', instance.code);
  writeNotNull('message', instance.message);
  return val;
}

Errors _$ErrorsFromJson(Map<String, dynamic> json) {
  return Errors(
    fieldErrors: (json['fieldErrors'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          (e as List)
              ?.map((e) =>
                  e == null ? null : Error.fromJson(e as Map<String, dynamic>))
              ?.toList()),
    ),
    generalErrors: (json['generalErrors'] as List)
        ?.map(
            (e) => e == null ? null : Error.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$ErrorsToJson(Errors instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('fieldErrors', instance.fieldErrors);
  writeNotNull('generalErrors', instance.generalErrors);
  return val;
}

EventConfiguration _$EventConfigurationFromJson(Map<String, dynamic> json) {
  return EventConfiguration(
    events: (json['events'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          _$enumDecodeNullable(_$EventTypeEnumMap, k),
          e == null
              ? null
              : EventConfigurationData.fromJson(e as Map<String, dynamic>)),
    ),
  );
}

Map<String, dynamic> _$EventConfigurationToJson(EventConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('events',
      instance.events?.map((k, e) => MapEntry(_$EventTypeEnumMap[k], e)));
  return val;
}

const _$EventTypeEnumMap = {
  EventType.UserDelete: 'UserDelete',
  EventType.UserCreate: 'UserCreate',
  EventType.UserUpdate: 'UserUpdate',
  EventType.UserDeactivate: 'UserDeactivate',
  EventType.UserBulkCreate: 'UserBulkCreate',
  EventType.UserReactivate: 'UserReactivate',
  EventType.UserAction: 'UserAction',
  EventType.JWTRefreshTokenRevoke: 'JWTRefreshTokenRevoke',
  EventType.JWTRefresh: 'JWTRefresh',
  EventType.JWTPublicKeyUpdate: 'JWTPublicKeyUpdate',
  EventType.UserLoginSuccess: 'UserLoginSuccess',
  EventType.UserLoginFailed: 'UserLoginFailed',
  EventType.UserRegistrationCreate: 'UserRegistrationCreate',
  EventType.UserRegistrationUpdate: 'UserRegistrationUpdate',
  EventType.UserRegistrationDelete: 'UserRegistrationDelete',
  EventType.UserRegistrationVerified: 'UserRegistrationVerified',
  EventType.UserEmailVerified: 'UserEmailVerified',
  EventType.UserPasswordBreach: 'UserPasswordBreach',
  EventType.Test: 'Test',
};

EventConfigurationData _$EventConfigurationDataFromJson(
    Map<String, dynamic> json) {
  return EventConfigurationData(
    transactionType:
        _$enumDecodeNullable(_$TransactionTypeEnumMap, json['transactionType']),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$EventConfigurationDataToJson(
    EventConfigurationData instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull(
      'transactionType', _$TransactionTypeEnumMap[instance.transactionType]);
  return val;
}

const _$TransactionTypeEnumMap = {
  TransactionType.None: 'None',
  TransactionType.Any: 'Any',
  TransactionType.SimpleMajority: 'SimpleMajority',
  TransactionType.SuperMajority: 'SuperMajority',
  TransactionType.AbsoluteMajority: 'AbsoluteMajority',
};

EventLog _$EventLogFromJson(Map<String, dynamic> json) {
  return EventLog(
    id: json['id'] as num,
    insertInstant: json['insertInstant'] as num,
    message: json['message'] as String,
    type: _$enumDecodeNullable(_$EventLogTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$EventLogToJson(EventLog instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('message', instance.message);
  writeNotNull('type', _$EventLogTypeEnumMap[instance.type]);
  return val;
}

const _$EventLogTypeEnumMap = {
  EventLogType.Information: 'Information',
  EventLogType.Debug: 'Debug',
  EventLogType.Error: 'Error',
};

EventLogConfiguration _$EventLogConfigurationFromJson(
    Map<String, dynamic> json) {
  return EventLogConfiguration(
    numberToRetain: json['numberToRetain'] as num,
  );
}

Map<String, dynamic> _$EventLogConfigurationToJson(
    EventLogConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberToRetain', instance.numberToRetain);
  return val;
}

EventLogResponse _$EventLogResponseFromJson(Map<String, dynamic> json) {
  return EventLogResponse(
    eventLog: json['eventLog'] == null
        ? null
        : EventLog.fromJson(json['eventLog'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$EventLogResponseToJson(EventLogResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('eventLog', instance.eventLog);
  return val;
}

EventLogSearchCriteria _$EventLogSearchCriteriaFromJson(
    Map<String, dynamic> json) {
  return EventLogSearchCriteria(
    end: json['end'] as num,
    message: json['message'] as String,
    start: json['start'] as num,
    type: _$enumDecodeNullable(_$EventLogTypeEnumMap, json['type']),
  )
    ..numberOfResults = json['numberOfResults'] as num
    ..orderBy = json['orderBy'] as String
    ..startRow = json['startRow'] as num;
}

Map<String, dynamic> _$EventLogSearchCriteriaToJson(
    EventLogSearchCriteria instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberOfResults', instance.numberOfResults);
  writeNotNull('orderBy', instance.orderBy);
  writeNotNull('startRow', instance.startRow);
  writeNotNull('end', instance.end);
  writeNotNull('message', instance.message);
  writeNotNull('start', instance.start);
  writeNotNull('type', _$EventLogTypeEnumMap[instance.type]);
  return val;
}

EventLogSearchRequest _$EventLogSearchRequestFromJson(
    Map<String, dynamic> json) {
  return EventLogSearchRequest(
    search: json['search'] == null
        ? null
        : EventLogSearchCriteria.fromJson(
            json['search'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$EventLogSearchRequestToJson(
    EventLogSearchRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('search', instance.search);
  return val;
}

EventLogSearchResponse _$EventLogSearchResponseFromJson(
    Map<String, dynamic> json) {
  return EventLogSearchResponse(
    eventLogs: (json['eventLogs'] as List)
        ?.map((e) =>
            e == null ? null : EventLog.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$EventLogSearchResponseToJson(
    EventLogSearchResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('eventLogs', instance.eventLogs);
  writeNotNull('total', instance.total);
  return val;
}

EventRequest _$EventRequestFromJson(Map<String, dynamic> json) {
  return EventRequest(
    event: json['event'] == null
        ? null
        : BaseEvent.fromJson(json['event'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$EventRequestToJson(EventRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('event', instance.event);
  return val;
}

ExternalIdentifierConfiguration _$ExternalIdentifierConfigurationFromJson(
    Map<String, dynamic> json) {
  return ExternalIdentifierConfiguration(
    authorizationGrantIdTimeToLiveInSeconds:
        json['authorizationGrantIdTimeToLiveInSeconds'] as num,
    changePasswordIdGenerator: json['changePasswordIdGenerator'] == null
        ? null
        : SecureGeneratorConfiguration.fromJson(
            json['changePasswordIdGenerator'] as Map<String, dynamic>),
    changePasswordIdTimeToLiveInSeconds:
        json['changePasswordIdTimeToLiveInSeconds'] as num,
    deviceCodeTimeToLiveInSeconds: json['deviceCodeTimeToLiveInSeconds'] as num,
    deviceUserCodeIdGenerator: json['deviceUserCodeIdGenerator'] == null
        ? null
        : SecureGeneratorConfiguration.fromJson(
            json['deviceUserCodeIdGenerator'] as Map<String, dynamic>),
    emailVerificationIdGenerator: json['emailVerificationIdGenerator'] == null
        ? null
        : SecureGeneratorConfiguration.fromJson(
            json['emailVerificationIdGenerator'] as Map<String, dynamic>),
    emailVerificationIdTimeToLiveInSeconds:
        json['emailVerificationIdTimeToLiveInSeconds'] as num,
    externalAuthenticationIdTimeToLiveInSeconds:
        json['externalAuthenticationIdTimeToLiveInSeconds'] as num,
    oneTimePasswordTimeToLiveInSeconds:
        json['oneTimePasswordTimeToLiveInSeconds'] as num,
    passwordlessLoginGenerator: json['passwordlessLoginGenerator'] == null
        ? null
        : SecureGeneratorConfiguration.fromJson(
            json['passwordlessLoginGenerator'] as Map<String, dynamic>),
    passwordlessLoginTimeToLiveInSeconds:
        json['passwordlessLoginTimeToLiveInSeconds'] as num,
    registrationVerificationIdGenerator:
        json['registrationVerificationIdGenerator'] == null
            ? null
            : SecureGeneratorConfiguration.fromJson(
                json['registrationVerificationIdGenerator']
                    as Map<String, dynamic>),
    registrationVerificationIdTimeToLiveInSeconds:
        json['registrationVerificationIdTimeToLiveInSeconds'] as num,
    samlv2AuthNRequestIdTimeToLiveInSeconds:
        json['samlv2AuthNRequestIdTimeToLiveInSeconds'] as num,
    setupPasswordIdGenerator: json['setupPasswordIdGenerator'] == null
        ? null
        : SecureGeneratorConfiguration.fromJson(
            json['setupPasswordIdGenerator'] as Map<String, dynamic>),
    setupPasswordIdTimeToLiveInSeconds:
        json['setupPasswordIdTimeToLiveInSeconds'] as num,
    twoFactorIdTimeToLiveInSeconds:
        json['twoFactorIdTimeToLiveInSeconds'] as num,
    twoFactorTrustIdTimeToLiveInSeconds:
        json['twoFactorTrustIdTimeToLiveInSeconds'] as num,
  );
}

Map<String, dynamic> _$ExternalIdentifierConfigurationToJson(
    ExternalIdentifierConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('authorizationGrantIdTimeToLiveInSeconds',
      instance.authorizationGrantIdTimeToLiveInSeconds);
  writeNotNull('changePasswordIdGenerator', instance.changePasswordIdGenerator);
  writeNotNull('changePasswordIdTimeToLiveInSeconds',
      instance.changePasswordIdTimeToLiveInSeconds);
  writeNotNull(
      'deviceCodeTimeToLiveInSeconds', instance.deviceCodeTimeToLiveInSeconds);
  writeNotNull('deviceUserCodeIdGenerator', instance.deviceUserCodeIdGenerator);
  writeNotNull(
      'emailVerificationIdGenerator', instance.emailVerificationIdGenerator);
  writeNotNull('emailVerificationIdTimeToLiveInSeconds',
      instance.emailVerificationIdTimeToLiveInSeconds);
  writeNotNull('externalAuthenticationIdTimeToLiveInSeconds',
      instance.externalAuthenticationIdTimeToLiveInSeconds);
  writeNotNull('oneTimePasswordTimeToLiveInSeconds',
      instance.oneTimePasswordTimeToLiveInSeconds);
  writeNotNull(
      'passwordlessLoginGenerator', instance.passwordlessLoginGenerator);
  writeNotNull('passwordlessLoginTimeToLiveInSeconds',
      instance.passwordlessLoginTimeToLiveInSeconds);
  writeNotNull('registrationVerificationIdGenerator',
      instance.registrationVerificationIdGenerator);
  writeNotNull('registrationVerificationIdTimeToLiveInSeconds',
      instance.registrationVerificationIdTimeToLiveInSeconds);
  writeNotNull('samlv2AuthNRequestIdTimeToLiveInSeconds',
      instance.samlv2AuthNRequestIdTimeToLiveInSeconds);
  writeNotNull('setupPasswordIdGenerator', instance.setupPasswordIdGenerator);
  writeNotNull('setupPasswordIdTimeToLiveInSeconds',
      instance.setupPasswordIdTimeToLiveInSeconds);
  writeNotNull('twoFactorIdTimeToLiveInSeconds',
      instance.twoFactorIdTimeToLiveInSeconds);
  writeNotNull('twoFactorTrustIdTimeToLiveInSeconds',
      instance.twoFactorTrustIdTimeToLiveInSeconds);
  return val;
}

ExternalJWTApplicationConfiguration
    _$ExternalJWTApplicationConfigurationFromJson(Map<String, dynamic> json) {
  return ExternalJWTApplicationConfiguration()
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$ExternalJWTApplicationConfigurationToJson(
    ExternalJWTApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  return val;
}

ExternalJWTIdentityProvider _$ExternalJWTIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return ExternalJWTIdentityProvider(
    claimMap: (json['claimMap'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    defaultKeyId: json['defaultKeyId'] as String,
    domains: (json['domains'] as List)?.map((e) => e as String)?.toSet(),
    headerKeyParameter: json['headerKeyParameter'] as String,
    oauth2: json['oauth2'] == null
        ? null
        : IdentityProviderOauth2Configuration.fromJson(
            json['oauth2'] as Map<String, dynamic>),
    uniqueIdentityClaim: json['uniqueIdentityClaim'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : ExternalJWTApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$ExternalJWTIdentityProviderToJson(
    ExternalJWTIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('claimMap', instance.claimMap);
  writeNotNull('defaultKeyId', instance.defaultKeyId);
  writeNotNull('domains', instance.domains?.toList());
  writeNotNull('headerKeyParameter', instance.headerKeyParameter);
  writeNotNull('oauth2', instance.oauth2);
  writeNotNull('uniqueIdentityClaim', instance.uniqueIdentityClaim);
  return val;
}

FacebookApplicationConfiguration _$FacebookApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return FacebookApplicationConfiguration(
    appId: json['appId'] as String,
    buttonText: json['buttonText'] as String,
    client_secret: json['client_secret'] as String,
    fields: json['fields'] as String,
    permissions: json['permissions'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$FacebookApplicationConfigurationToJson(
    FacebookApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('appId', instance.appId);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('fields', instance.fields);
  writeNotNull('permissions', instance.permissions);
  return val;
}

FacebookIdentityProvider _$FacebookIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return FacebookIdentityProvider(
    appId: json['appId'] as String,
    buttonText: json['buttonText'] as String,
    client_secret: json['client_secret'] as String,
    fields: json['fields'] as String,
    permissions: json['permissions'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : FacebookApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$FacebookIdentityProviderToJson(
    FacebookIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('appId', instance.appId);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('fields', instance.fields);
  writeNotNull('permissions', instance.permissions);
  return val;
}

FailedAuthenticationConfiguration _$FailedAuthenticationConfigurationFromJson(
    Map<String, dynamic> json) {
  return FailedAuthenticationConfiguration(
    actionDuration: json['actionDuration'] as num,
    actionDurationUnit:
        _$enumDecodeNullable(_$ExpiryUnitEnumMap, json['actionDurationUnit']),
    resetCountInSeconds: json['resetCountInSeconds'] as num,
    tooManyAttempts: json['tooManyAttempts'] as num,
    userActionId: json['userActionId'] as String,
  );
}

Map<String, dynamic> _$FailedAuthenticationConfigurationToJson(
    FailedAuthenticationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actionDuration', instance.actionDuration);
  writeNotNull(
      'actionDurationUnit', _$ExpiryUnitEnumMap[instance.actionDurationUnit]);
  writeNotNull('resetCountInSeconds', instance.resetCountInSeconds);
  writeNotNull('tooManyAttempts', instance.tooManyAttempts);
  writeNotNull('userActionId', instance.userActionId);
  return val;
}

const _$ExpiryUnitEnumMap = {
  ExpiryUnit.MINUTES: 'MINUTES',
  ExpiryUnit.HOURS: 'HOURS',
  ExpiryUnit.DAYS: 'DAYS',
  ExpiryUnit.WEEKS: 'WEEKS',
  ExpiryUnit.MONTHS: 'MONTHS',
  ExpiryUnit.YEARS: 'YEARS',
};

Family _$FamilyFromJson(Map<String, dynamic> json) {
  return Family(
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    members: (json['members'] as List)
        ?.map((e) =>
            e == null ? null : FamilyMember.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$FamilyToJson(Family instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('members', instance.members);
  return val;
}

FamilyConfiguration _$FamilyConfigurationFromJson(Map<String, dynamic> json) {
  return FamilyConfiguration(
    allowChildRegistrations: json['allowChildRegistrations'] as bool,
    confirmChildEmailTemplateId: json['confirmChildEmailTemplateId'] as String,
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
}

Map<String, dynamic> _$FamilyConfigurationToJson(FamilyConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('allowChildRegistrations', instance.allowChildRegistrations);
  writeNotNull(
      'confirmChildEmailTemplateId', instance.confirmChildEmailTemplateId);
  writeNotNull('deleteOrphanedAccounts', instance.deleteOrphanedAccounts);
  writeNotNull(
      'deleteOrphanedAccountsDays', instance.deleteOrphanedAccountsDays);
  writeNotNull(
      'familyRequestEmailTemplateId', instance.familyRequestEmailTemplateId);
  writeNotNull('maximumChildAge', instance.maximumChildAge);
  writeNotNull('minimumOwnerAge', instance.minimumOwnerAge);
  writeNotNull('parentEmailRequired', instance.parentEmailRequired);
  writeNotNull('parentRegistrationEmailTemplateId',
      instance.parentRegistrationEmailTemplateId);
  return val;
}

FamilyEmailRequest _$FamilyEmailRequestFromJson(Map<String, dynamic> json) {
  return FamilyEmailRequest(
    parentEmail: json['parentEmail'] as String,
  );
}

Map<String, dynamic> _$FamilyEmailRequestToJson(FamilyEmailRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('parentEmail', instance.parentEmail);
  return val;
}

FamilyMember _$FamilyMemberFromJson(Map<String, dynamic> json) {
  return FamilyMember(
    data: json['data'] as Map<String, dynamic>,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    owner: json['owner'] as bool,
    role: _$enumDecodeNullable(_$FamilyRoleEnumMap, json['role']),
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$FamilyMemberToJson(FamilyMember instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('owner', instance.owner);
  writeNotNull('role', _$FamilyRoleEnumMap[instance.role]);
  writeNotNull('userId', instance.userId);
  return val;
}

const _$FamilyRoleEnumMap = {
  FamilyRole.Child: 'Child',
  FamilyRole.Teen: 'Teen',
  FamilyRole.Adult: 'Adult',
};

FamilyRequest _$FamilyRequestFromJson(Map<String, dynamic> json) {
  return FamilyRequest(
    familyMember: json['familyMember'] == null
        ? null
        : FamilyMember.fromJson(json['familyMember'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$FamilyRequestToJson(FamilyRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('familyMember', instance.familyMember);
  return val;
}

FamilyResponse _$FamilyResponseFromJson(Map<String, dynamic> json) {
  return FamilyResponse(
    families: (json['families'] as List)
        ?.map((e) =>
            e == null ? null : Family.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    family: json['family'] == null
        ? null
        : Family.fromJson(json['family'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$FamilyResponseToJson(FamilyResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('families', instance.families);
  writeNotNull('family', instance.family);
  return val;
}

ForgotPasswordRequest _$ForgotPasswordRequestFromJson(
    Map<String, dynamic> json) {
  return ForgotPasswordRequest(
    applicationId: json['applicationId'] as String,
    changePasswordId: json['changePasswordId'] as String,
    email: json['email'] as String,
    loginId: json['loginId'] as String,
    sendForgotPasswordEmail: json['sendForgotPasswordEmail'] as bool,
    state: json['state'] as Map<String, dynamic>,
    username: json['username'] as String,
  );
}

Map<String, dynamic> _$ForgotPasswordRequestToJson(
    ForgotPasswordRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('changePasswordId', instance.changePasswordId);
  writeNotNull('email', instance.email);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('sendForgotPasswordEmail', instance.sendForgotPasswordEmail);
  writeNotNull('state', instance.state);
  writeNotNull('username', instance.username);
  return val;
}

ForgotPasswordResponse _$ForgotPasswordResponseFromJson(
    Map<String, dynamic> json) {
  return ForgotPasswordResponse(
    changePasswordId: json['changePasswordId'] as String,
  );
}

Map<String, dynamic> _$ForgotPasswordResponseToJson(
    ForgotPasswordResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('changePasswordId', instance.changePasswordId);
  return val;
}

Form _$FormFromJson(Map<String, dynamic> json) {
  return Form(
    data: json['data'] as Map<String, dynamic>,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
    steps: (json['steps'] as List)
        ?.map((e) =>
            e == null ? null : FormStep.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    type: _$enumDecodeNullable(_$FormTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$FormToJson(Form instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('steps', instance.steps);
  writeNotNull('type', _$FormTypeEnumMap[instance.type]);
  return val;
}

const _$FormTypeEnumMap = {
  FormType.registration: 'registration',
  FormType.adminRegistration: 'adminRegistration',
  FormType.adminUser: 'adminUser',
};

FormField _$FormFieldFromJson(Map<String, dynamic> json) {
  return FormField(
    confirm: json['confirm'] as bool,
    consentId: json['consentId'] as String,
    control: _$enumDecodeNullable(_$FormControlEnumMap, json['control']),
    data: json['data'] as Map<String, dynamic>,
    description: json['description'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    key: json['key'] as String,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
    options: (json['options'] as List)?.map((e) => e as String)?.toList(),
    required: json['required'] as bool,
    type: _$enumDecodeNullable(_$FormDataTypeEnumMap, json['type']),
    validator: json['validator'] == null
        ? null
        : FormFieldValidator.fromJson(
            json['validator'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$FormFieldToJson(FormField instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('confirm', instance.confirm);
  writeNotNull('consentId', instance.consentId);
  writeNotNull('control', _$FormControlEnumMap[instance.control]);
  writeNotNull('data', instance.data);
  writeNotNull('description', instance.description);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('key', instance.key);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('options', instance.options);
  writeNotNull('required', instance.required);
  writeNotNull('type', _$FormDataTypeEnumMap[instance.type]);
  writeNotNull('validator', instance.validator);
  return val;
}

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

FormFieldRequest _$FormFieldRequestFromJson(Map<String, dynamic> json) {
  return FormFieldRequest(
    field: json['field'] == null
        ? null
        : FormField.fromJson(json['field'] as Map<String, dynamic>),
    fields: (json['fields'] as List)
        ?.map((e) =>
            e == null ? null : FormField.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$FormFieldRequestToJson(FormFieldRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('field', instance.field);
  writeNotNull('fields', instance.fields);
  return val;
}

FormFieldResponse _$FormFieldResponseFromJson(Map<String, dynamic> json) {
  return FormFieldResponse(
    field: json['field'] == null
        ? null
        : FormField.fromJson(json['field'] as Map<String, dynamic>),
    fields: (json['fields'] as List)
        ?.map((e) =>
            e == null ? null : FormField.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$FormFieldResponseToJson(FormFieldResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('field', instance.field);
  writeNotNull('fields', instance.fields);
  return val;
}

FormFieldValidator _$FormFieldValidatorFromJson(Map<String, dynamic> json) {
  return FormFieldValidator(
    expression: json['expression'] as String,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$FormFieldValidatorToJson(FormFieldValidator instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('expression', instance.expression);
  return val;
}

FormRequest _$FormRequestFromJson(Map<String, dynamic> json) {
  return FormRequest(
    form: json['form'] == null
        ? null
        : Form.fromJson(json['form'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$FormRequestToJson(FormRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('form', instance.form);
  return val;
}

FormResponse _$FormResponseFromJson(Map<String, dynamic> json) {
  return FormResponse(
    form: json['form'] == null
        ? null
        : Form.fromJson(json['form'] as Map<String, dynamic>),
    forms: (json['forms'] as List)
        ?.map(
            (e) => e == null ? null : Form.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$FormResponseToJson(FormResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('form', instance.form);
  writeNotNull('forms', instance.forms);
  return val;
}

FormStep _$FormStepFromJson(Map<String, dynamic> json) {
  return FormStep(
    fields: (json['fields'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$FormStepToJson(FormStep instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('fields', instance.fields);
  return val;
}

FusionAuthConnectorConfiguration _$FusionAuthConnectorConfigurationFromJson(
    Map<String, dynamic> json) {
  return FusionAuthConnectorConfiguration()
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$ConnectorTypeEnumMap, json['type']);
}

Map<String, dynamic> _$FusionAuthConnectorConfigurationToJson(
    FusionAuthConnectorConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$ConnectorTypeEnumMap[instance.type]);
  return val;
}

GenericConnectorConfiguration _$GenericConnectorConfigurationFromJson(
    Map<String, dynamic> json) {
  return GenericConnectorConfiguration(
    authenticationURL: json['authenticationURL'] as String,
    connectTimeout: json['connectTimeout'] as num,
    headers: (json['headers'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
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
    ..type = _$enumDecodeNullable(_$ConnectorTypeEnumMap, json['type']);
}

Map<String, dynamic> _$GenericConnectorConfigurationToJson(
    GenericConnectorConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$ConnectorTypeEnumMap[instance.type]);
  writeNotNull('authenticationURL', instance.authenticationURL);
  writeNotNull('connectTimeout', instance.connectTimeout);
  writeNotNull('headers', instance.headers);
  writeNotNull(
      'httpAuthenticationPassword', instance.httpAuthenticationPassword);
  writeNotNull(
      'httpAuthenticationUsername', instance.httpAuthenticationUsername);
  writeNotNull('readTimeout', instance.readTimeout);
  writeNotNull('sslCertificateKeyId', instance.sslCertificateKeyId);
  return val;
}

GoogleApplicationConfiguration _$GoogleApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return GoogleApplicationConfiguration(
    buttonText: json['buttonText'] as String,
    client_id: json['client_id'] as String,
    client_secret: json['client_secret'] as String,
    scope: json['scope'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$GoogleApplicationConfigurationToJson(
    GoogleApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_id', instance.client_id);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('scope', instance.scope);
  return val;
}

GoogleIdentityProvider _$GoogleIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return GoogleIdentityProvider(
    buttonText: json['buttonText'] as String,
    client_id: json['client_id'] as String,
    client_secret: json['client_secret'] as String,
    scope: json['scope'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : GoogleApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$GoogleIdentityProviderToJson(
    GoogleIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_id', instance.client_id);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('scope', instance.scope);
  return val;
}

Group _$GroupFromJson(Map<String, dynamic> json) {
  return Group(
    data: json['data'] as Map<String, dynamic>,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
    roles: (json['roles'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          (e as List)
              ?.map((e) => e == null
                  ? null
                  : ApplicationRole.fromJson(e as Map<String, dynamic>))
              ?.toList()),
    ),
    tenantId: json['tenantId'] as String,
  );
}

Map<String, dynamic> _$GroupToJson(Group instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('roles', instance.roles);
  writeNotNull('tenantId', instance.tenantId);
  return val;
}

GroupMember _$GroupMemberFromJson(Map<String, dynamic> json) {
  return GroupMember(
    data: json['data'] as Map<String, dynamic>,
    groupId: json['groupId'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$GroupMemberToJson(GroupMember instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('groupId', instance.groupId);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('userId', instance.userId);
  return val;
}

GroupRequest _$GroupRequestFromJson(Map<String, dynamic> json) {
  return GroupRequest(
    group: json['group'] == null
        ? null
        : Group.fromJson(json['group'] as Map<String, dynamic>),
    roleIds: (json['roleIds'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$GroupRequestToJson(GroupRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('group', instance.group);
  writeNotNull('roleIds', instance.roleIds);
  return val;
}

GroupResponse _$GroupResponseFromJson(Map<String, dynamic> json) {
  return GroupResponse(
    group: json['group'] == null
        ? null
        : Group.fromJson(json['group'] as Map<String, dynamic>),
    groups: (json['groups'] as List)
        ?.map(
            (e) => e == null ? null : Group.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$GroupResponseToJson(GroupResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('group', instance.group);
  writeNotNull('groups', instance.groups);
  return val;
}

HistoryItem _$HistoryItemFromJson(Map<String, dynamic> json) {
  return HistoryItem(
    actionerUserId: json['actionerUserId'] as String,
    comment: json['comment'] as String,
    createInstant: json['createInstant'] as num,
    expiry: json['expiry'] as num,
  );
}

Map<String, dynamic> _$HistoryItemToJson(HistoryItem instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actionerUserId', instance.actionerUserId);
  writeNotNull('comment', instance.comment);
  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('expiry', instance.expiry);
  return val;
}

HYPRApplicationConfiguration _$HYPRApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return HYPRApplicationConfiguration(
    relyingPartyApplicationId: json['relyingPartyApplicationId'] as String,
    relyingPartyURL: json['relyingPartyURL'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$HYPRApplicationConfigurationToJson(
    HYPRApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('relyingPartyApplicationId', instance.relyingPartyApplicationId);
  writeNotNull('relyingPartyURL', instance.relyingPartyURL);
  return val;
}

HYPRIdentityProvider _$HYPRIdentityProviderFromJson(Map<String, dynamic> json) {
  return HYPRIdentityProvider(
    relyingPartyApplicationId: json['relyingPartyApplicationId'] as String,
    relyingPartyURL: json['relyingPartyURL'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : HYPRApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$HYPRIdentityProviderToJson(
    HYPRIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('relyingPartyApplicationId', instance.relyingPartyApplicationId);
  writeNotNull('relyingPartyURL', instance.relyingPartyURL);
  return val;
}

IdentityProviderDetails _$IdentityProviderDetailsFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderDetails(
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    id: json['id'] as String,
    idpEndpoint: json['idpEndpoint'] as String,
    name: json['name'] as String,
    oauth2: json['oauth2'] == null
        ? null
        : IdentityProviderOauth2Configuration.fromJson(
            json['oauth2'] as Map<String, dynamic>),
    type: _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$IdentityProviderDetailsToJson(
    IdentityProviderDetails instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('id', instance.id);
  writeNotNull('idpEndpoint', instance.idpEndpoint);
  writeNotNull('name', instance.name);
  writeNotNull('oauth2', instance.oauth2);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  return val;
}

IdentityProviderLoginRequest _$IdentityProviderLoginRequestFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderLoginRequest(
    data: (json['data'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    encodedJWT: json['encodedJWT'] as String,
    identityProviderId: json['identityProviderId'] as String,
  )
    ..applicationId = json['applicationId'] as String
    ..ipAddress = json['ipAddress'] as String
    ..metaData = json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
    ..noJWT = json['noJWT'] as bool;
}

Map<String, dynamic> _$IdentityProviderLoginRequestToJson(
    IdentityProviderLoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  writeNotNull('data', instance.data);
  writeNotNull('encodedJWT', instance.encodedJWT);
  writeNotNull('identityProviderId', instance.identityProviderId);
  return val;
}

IdentityProviderOauth2Configuration
    _$IdentityProviderOauth2ConfigurationFromJson(Map<String, dynamic> json) {
  return IdentityProviderOauth2Configuration(
    authorization_endpoint: json['authorization_endpoint'] as String,
    client_id: json['client_id'] as String,
    client_secret: json['client_secret'] as String,
    clientAuthenticationMethod: _$enumDecodeNullable(
        _$ClientAuthenticationMethodEnumMap,
        json['clientAuthenticationMethod']),
    emailClaim: json['emailClaim'] as String,
    issuer: json['issuer'] as String,
    scope: json['scope'] as String,
    token_endpoint: json['token_endpoint'] as String,
    userinfo_endpoint: json['userinfo_endpoint'] as String,
  );
}

Map<String, dynamic> _$IdentityProviderOauth2ConfigurationToJson(
    IdentityProviderOauth2Configuration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('authorization_endpoint', instance.authorization_endpoint);
  writeNotNull('client_id', instance.client_id);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('clientAuthenticationMethod',
      _$ClientAuthenticationMethodEnumMap[instance.clientAuthenticationMethod]);
  writeNotNull('emailClaim', instance.emailClaim);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('scope', instance.scope);
  writeNotNull('token_endpoint', instance.token_endpoint);
  writeNotNull('userinfo_endpoint', instance.userinfo_endpoint);
  return val;
}

const _$ClientAuthenticationMethodEnumMap = {
  ClientAuthenticationMethod.none: 'none',
  ClientAuthenticationMethod.client_secret_basic: 'client_secret_basic',
  ClientAuthenticationMethod.client_secret_post: 'client_secret_post',
};

IdentityProviderRequest _$IdentityProviderRequestFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderRequest(
    identityProvider: json['identityProvider'] == null
        ? null
        : BaseIdentityProvider.fromJson(
            json['identityProvider'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$IdentityProviderRequestToJson(
    IdentityProviderRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('identityProvider', instance.identityProvider);
  return val;
}

IdentityProviderResponse _$IdentityProviderResponseFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderResponse(
    identityProvider: json['identityProvider'] == null
        ? null
        : BaseIdentityProvider.fromJson(
            json['identityProvider'] as Map<String, dynamic>),
    identityProviders: (json['identityProviders'] as List)
        ?.map((e) => e == null
            ? null
            : BaseIdentityProvider.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$IdentityProviderResponseToJson(
    IdentityProviderResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('identityProvider', instance.identityProvider);
  writeNotNull('identityProviders', instance.identityProviders);
  return val;
}

IdentityProviderStartLoginRequest _$IdentityProviderStartLoginRequestFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderStartLoginRequest(
    data: (json['data'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    identityProviderId: json['identityProviderId'] as String,
    loginId: json['loginId'] as String,
    state: json['state'] as Map<String, dynamic>,
  )
    ..applicationId = json['applicationId'] as String
    ..ipAddress = json['ipAddress'] as String
    ..metaData = json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
    ..noJWT = json['noJWT'] as bool;
}

Map<String, dynamic> _$IdentityProviderStartLoginRequestToJson(
    IdentityProviderStartLoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  writeNotNull('data', instance.data);
  writeNotNull('identityProviderId', instance.identityProviderId);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('state', instance.state);
  return val;
}

IdentityProviderStartLoginResponse _$IdentityProviderStartLoginResponseFromJson(
    Map<String, dynamic> json) {
  return IdentityProviderStartLoginResponse(
    code: json['code'] as String,
  );
}

Map<String, dynamic> _$IdentityProviderStartLoginResponseToJson(
    IdentityProviderStartLoginResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('code', instance.code);
  return val;
}

ImportRequest _$ImportRequestFromJson(Map<String, dynamic> json) {
  return ImportRequest(
    encryptionScheme: json['encryptionScheme'] as String,
    factor: json['factor'] as num,
    users: (json['users'] as List)
        ?.map(
            (e) => e == null ? null : User.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    validateDbConstraints: json['validateDbConstraints'] as bool,
  );
}

Map<String, dynamic> _$ImportRequestToJson(ImportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('encryptionScheme', instance.encryptionScheme);
  writeNotNull('factor', instance.factor);
  writeNotNull('users', instance.users);
  writeNotNull('validateDbConstraints', instance.validateDbConstraints);
  return val;
}

IntegrationRequest _$IntegrationRequestFromJson(Map<String, dynamic> json) {
  return IntegrationRequest(
    integrations: json['integrations'] == null
        ? null
        : Integrations.fromJson(json['integrations'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$IntegrationRequestToJson(IntegrationRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('integrations', instance.integrations);
  return val;
}

IntegrationResponse _$IntegrationResponseFromJson(Map<String, dynamic> json) {
  return IntegrationResponse(
    integrations: json['integrations'] == null
        ? null
        : Integrations.fromJson(json['integrations'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$IntegrationResponseToJson(IntegrationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('integrations', instance.integrations);
  return val;
}

Integrations _$IntegrationsFromJson(Map<String, dynamic> json) {
  return Integrations(
    cleanspeak: json['cleanspeak'] == null
        ? null
        : CleanSpeakConfiguration.fromJson(
            json['cleanspeak'] as Map<String, dynamic>),
    kafka: json['kafka'] == null
        ? null
        : KafkaConfiguration.fromJson(json['kafka'] as Map<String, dynamic>),
    twilio: json['twilio'] == null
        ? null
        : TwilioConfiguration.fromJson(json['twilio'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$IntegrationsToJson(Integrations instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('cleanspeak', instance.cleanspeak);
  writeNotNull('kafka', instance.kafka);
  writeNotNull('twilio', instance.twilio);
  return val;
}

IntervalCount _$IntervalCountFromJson(Map<String, dynamic> json) {
  return IntervalCount(
    applicationId: json['applicationId'] as String,
    count: json['count'] as num,
    decrementedCount: json['decrementedCount'] as num,
    period: json['period'] as num,
  );
}

Map<String, dynamic> _$IntervalCountToJson(IntervalCount instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('count', instance.count);
  writeNotNull('decrementedCount', instance.decrementedCount);
  writeNotNull('period', instance.period);
  return val;
}

IntervalUser _$IntervalUserFromJson(Map<String, dynamic> json) {
  return IntervalUser(
    applicationId: json['applicationId'] as String,
    period: json['period'] as num,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$IntervalUserToJson(IntervalUser instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('period', instance.period);
  writeNotNull('userId', instance.userId);
  return val;
}

IssueResponse _$IssueResponseFromJson(Map<String, dynamic> json) {
  return IssueResponse(
    refreshToken: json['refreshToken'] as String,
    token: json['token'] as String,
  );
}

Map<String, dynamic> _$IssueResponseToJson(IssueResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('token', instance.token);
  return val;
}

JSONWebKey _$JSONWebKeyFromJson(Map<String, dynamic> json) {
  return JSONWebKey(
    alg: _$enumDecodeNullable(_$AlgorithmEnumMap, json['alg']),
    crv: json['crv'] as String,
    d: json['d'] as String,
    dp: json['dp'] as String,
    dq: json['dq'] as String,
    e: json['e'] as String,
    kid: json['kid'] as String,
    kty: _$enumDecodeNullable(_$KeyTypeEnumMap, json['kty']),
    n: json['n'] as String,
    p: json['p'] as String,
    q: json['q'] as String,
    qi: json['qi'] as String,
    use: json['use'] as String,
    x: json['x'] as String,
    x5c: (json['x5c'] as List)?.map((e) => e as String)?.toList(),
    x5t: json['x5t'] as String,
    x5t_S256: json['x5t#S256'] as String,
    y: json['y'] as String,
  );
}

Map<String, dynamic> _$JSONWebKeyToJson(JSONWebKey instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('alg', _$AlgorithmEnumMap[instance.alg]);
  writeNotNull('crv', instance.crv);
  writeNotNull('d', instance.d);
  writeNotNull('dp', instance.dp);
  writeNotNull('dq', instance.dq);
  writeNotNull('e', instance.e);
  writeNotNull('kid', instance.kid);
  writeNotNull('kty', _$KeyTypeEnumMap[instance.kty]);
  writeNotNull('n', instance.n);
  writeNotNull('p', instance.p);
  writeNotNull('q', instance.q);
  writeNotNull('qi', instance.qi);
  writeNotNull('use', instance.use);
  writeNotNull('x', instance.x);
  writeNotNull('x5c', instance.x5c);
  writeNotNull('x5t', instance.x5t);
  writeNotNull('x5t#S256', instance.x5t_S256);
  writeNotNull('y', instance.y);
  return val;
}

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
    Map<String, dynamic> json) {
  return JSONWebKeyInfoProvider();
}

Map<String, dynamic> _$JSONWebKeyInfoProviderToJson(
        JSONWebKeyInfoProvider instance) =>
    <String, dynamic>{};

JWKSResponse _$JWKSResponseFromJson(Map<String, dynamic> json) {
  return JWKSResponse(
    keys: (json['keys'] as List)
        ?.map((e) =>
            e == null ? null : JSONWebKey.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$JWKSResponseToJson(JWKSResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('keys', instance.keys);
  return val;
}

JWT _$JWTFromJson(Map<String, dynamic> json) {
  return JWT(
    aud: json['aud'],
    exp: json['exp'] as num,
    iat: json['iat'] as num,
    iss: json['iss'] as String,
    jti: json['jti'] as String,
    nbf: json['nbf'] as num,
    sub: json['sub'] as String,
  );
}

Map<String, dynamic> _$JWTToJson(JWT instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('aud', instance.aud);
  writeNotNull('exp', instance.exp);
  writeNotNull('iat', instance.iat);
  writeNotNull('iss', instance.iss);
  writeNotNull('jti', instance.jti);
  writeNotNull('nbf', instance.nbf);
  writeNotNull('sub', instance.sub);
  return val;
}

JWTConfiguration _$JWTConfigurationFromJson(Map<String, dynamic> json) {
  return JWTConfiguration(
    accessTokenKeyId: json['accessTokenKeyId'] as String,
    idTokenKeyId: json['idTokenKeyId'] as String,
    refreshTokenExpirationPolicy: _$enumDecodeNullable(
        _$RefreshTokenExpirationPolicyEnumMap,
        json['refreshTokenExpirationPolicy']),
    refreshTokenRevocationPolicy: json['refreshTokenRevocationPolicy'] == null
        ? null
        : RefreshTokenRevocationPolicy.fromJson(
            json['refreshTokenRevocationPolicy'] as Map<String, dynamic>),
    refreshTokenTimeToLiveInMinutes:
        json['refreshTokenTimeToLiveInMinutes'] as num,
    refreshTokenUsagePolicy: _$enumDecodeNullable(
        _$RefreshTokenUsagePolicyEnumMap, json['refreshTokenUsagePolicy']),
    timeToLiveInSeconds: json['timeToLiveInSeconds'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$JWTConfigurationToJson(JWTConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('accessTokenKeyId', instance.accessTokenKeyId);
  writeNotNull('idTokenKeyId', instance.idTokenKeyId);
  writeNotNull(
      'refreshTokenExpirationPolicy',
      _$RefreshTokenExpirationPolicyEnumMap[
          instance.refreshTokenExpirationPolicy]);
  writeNotNull(
      'refreshTokenRevocationPolicy', instance.refreshTokenRevocationPolicy);
  writeNotNull('refreshTokenTimeToLiveInMinutes',
      instance.refreshTokenTimeToLiveInMinutes);
  writeNotNull('refreshTokenUsagePolicy',
      _$RefreshTokenUsagePolicyEnumMap[instance.refreshTokenUsagePolicy]);
  writeNotNull('timeToLiveInSeconds', instance.timeToLiveInSeconds);
  return val;
}

const _$RefreshTokenExpirationPolicyEnumMap = {
  RefreshTokenExpirationPolicy.Fixed: 'Fixed',
  RefreshTokenExpirationPolicy.SlidingWindow: 'SlidingWindow',
};

const _$RefreshTokenUsagePolicyEnumMap = {
  RefreshTokenUsagePolicy.Reusable: 'Reusable',
  RefreshTokenUsagePolicy.OneTimeUse: 'OneTimeUse',
};

JWTPublicKeyUpdateEvent _$JWTPublicKeyUpdateEventFromJson(
    Map<String, dynamic> json) {
  return JWTPublicKeyUpdateEvent(
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toSet(),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$JWTPublicKeyUpdateEventToJson(
    JWTPublicKeyUpdateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationIds', instance.applicationIds?.toList());
  return val;
}

JWTRefreshEvent _$JWTRefreshEventFromJson(Map<String, dynamic> json) {
  return JWTRefreshEvent(
    applicationId: json['applicationId'] as String,
    original: json['original'] as String,
    refreshToken: json['refreshToken'] as String,
    token: json['token'] as String,
    userId: json['userId'] as String,
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$JWTRefreshEventToJson(JWTRefreshEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('original', instance.original);
  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('token', instance.token);
  writeNotNull('userId', instance.userId);
  return val;
}

JWTRefreshTokenRevokeEvent _$JWTRefreshTokenRevokeEventFromJson(
    Map<String, dynamic> json) {
  return JWTRefreshTokenRevokeEvent(
    applicationId: json['applicationId'] as String,
    applicationTimeToLiveInSeconds:
        (json['applicationTimeToLiveInSeconds'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as num),
    ),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
    userId: json['userId'] as String,
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$JWTRefreshTokenRevokeEventToJson(
    JWTRefreshTokenRevokeEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('applicationTimeToLiveInSeconds',
      instance.applicationTimeToLiveInSeconds);
  writeNotNull('user', instance.user);
  writeNotNull('userId', instance.userId);
  return val;
}

KafkaConfiguration _$KafkaConfigurationFromJson(Map<String, dynamic> json) {
  return KafkaConfiguration(
    defaultTopic: json['defaultTopic'] as String,
    producer: (json['producer'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$KafkaConfigurationToJson(KafkaConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('defaultTopic', instance.defaultTopic);
  writeNotNull('producer', instance.producer);
  return val;
}

Key _$KeyFromJson(Map<String, dynamic> json) {
  return Key(
    algorithm: _$enumDecodeNullable(_$KeyAlgorithmEnumMap, json['algorithm']),
    certificate: json['certificate'] as String,
    certificateInformation: json['certificateInformation'] == null
        ? null
        : CertificateInformation.fromJson(
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
    type: _$enumDecodeNullable(_$KeyTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$KeyToJson(Key instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('algorithm', _$KeyAlgorithmEnumMap[instance.algorithm]);
  writeNotNull('certificate', instance.certificate);
  writeNotNull('certificateInformation', instance.certificateInformation);
  writeNotNull('expirationInstant', instance.expirationInstant);
  writeNotNull('hasPrivateKey', instance.hasPrivateKey);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('kid', instance.kid);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('length', instance.length);
  writeNotNull('name', instance.name);
  writeNotNull('privateKey', instance.privateKey);
  writeNotNull('publicKey', instance.publicKey);
  writeNotNull('secret', instance.secret);
  writeNotNull('type', _$KeyTypeEnumMap[instance.type]);
  return val;
}

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

KeyRequest _$KeyRequestFromJson(Map<String, dynamic> json) {
  return KeyRequest(
    key: json['key'] == null
        ? null
        : Key.fromJson(json['key'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$KeyRequestToJson(KeyRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('key', instance.key);
  return val;
}

KeyResponse _$KeyResponseFromJson(Map<String, dynamic> json) {
  return KeyResponse(
    key: json['key'] == null
        ? null
        : Key.fromJson(json['key'] as Map<String, dynamic>),
    keys: (json['keys'] as List)
        ?.map((e) => e == null ? null : Key.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$KeyResponseToJson(KeyResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('key', instance.key);
  writeNotNull('keys', instance.keys);
  return val;
}

Lambda _$LambdaFromJson(Map<String, dynamic> json) {
  return Lambda(
    body: json['body'] as String,
    debug: json['debug'] as bool,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    name: json['name'] as String,
    type: _$enumDecodeNullable(_$LambdaTypeEnumMap, json['type']),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$LambdaToJson(Lambda instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('body', instance.body);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$LambdaTypeEnumMap[instance.type]);
  return val;
}

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
};

LambdaRequest _$LambdaRequestFromJson(Map<String, dynamic> json) {
  return LambdaRequest(
    lambda: json['lambda'] == null
        ? null
        : Lambda.fromJson(json['lambda'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$LambdaRequestToJson(LambdaRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambda', instance.lambda);
  return val;
}

LambdaResponse _$LambdaResponseFromJson(Map<String, dynamic> json) {
  return LambdaResponse(
    lambda: json['lambda'] == null
        ? null
        : Lambda.fromJson(json['lambda'] as Map<String, dynamic>),
    lambdas: (json['lambdas'] as List)
        ?.map((e) =>
            e == null ? null : Lambda.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$LambdaResponseToJson(LambdaResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('lambda', instance.lambda);
  writeNotNull('lambdas', instance.lambdas);
  return val;
}

LDAPConnectorConfiguration _$LDAPConnectorConfigurationFromJson(
    Map<String, dynamic> json) {
  return LDAPConnectorConfiguration(
    authenticationURL: json['authenticationURL'] as String,
    baseStructure: json['baseStructure'] as String,
    connectTimeout: json['connectTimeout'] as num,
    identifyingAttribute: json['identifyingAttribute'] as String,
    lambdaConfiguration: json['lambdaConfiguration'],
    loginIdAttribute: json['loginIdAttribute'] as String,
    readTimeout: json['readTimeout'] as num,
    requestedAttributes: (json['requestedAttributes'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    securityMethod: _$enumDecodeNullable(
        _$LDAPSecurityMethodEnumMap, json['securityMethod']),
    systemAccountDN: json['systemAccountDN'] as String,
    systemAccountPassword: json['systemAccountPassword'] as String,
  )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$ConnectorTypeEnumMap, json['type']);
}

Map<String, dynamic> _$LDAPConnectorConfigurationToJson(
    LDAPConnectorConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$ConnectorTypeEnumMap[instance.type]);
  writeNotNull('authenticationURL', instance.authenticationURL);
  writeNotNull('baseStructure', instance.baseStructure);
  writeNotNull('connectTimeout', instance.connectTimeout);
  writeNotNull('identifyingAttribute', instance.identifyingAttribute);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('loginIdAttribute', instance.loginIdAttribute);
  writeNotNull('readTimeout', instance.readTimeout);
  writeNotNull('requestedAttributes', instance.requestedAttributes);
  writeNotNull(
      'securityMethod', _$LDAPSecurityMethodEnumMap[instance.securityMethod]);
  writeNotNull('systemAccountDN', instance.systemAccountDN);
  writeNotNull('systemAccountPassword', instance.systemAccountPassword);
  return val;
}

const _$LDAPSecurityMethodEnumMap = {
  LDAPSecurityMethod.None: 'None',
  LDAPSecurityMethod.LDAPS: 'LDAPS',
  LDAPSecurityMethod.StartTLS: 'StartTLS',
};

LinkedInApplicationConfiguration _$LinkedInApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return LinkedInApplicationConfiguration(
    buttonText: json['buttonText'] as String,
    client_id: json['client_id'] as String,
    client_secret: json['client_secret'] as String,
    scope: json['scope'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$LinkedInApplicationConfigurationToJson(
    LinkedInApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_id', instance.client_id);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('scope', instance.scope);
  return val;
}

LinkedInIdentityProvider _$LinkedInIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return LinkedInIdentityProvider(
    buttonText: json['buttonText'] as String,
    client_id: json['client_id'] as String,
    client_secret: json['client_secret'] as String,
    scope: json['scope'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : LinkedInApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$LinkedInIdentityProviderToJson(
    LinkedInIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('client_id', instance.client_id);
  writeNotNull('client_secret', instance.client_secret);
  writeNotNull('scope', instance.scope);
  return val;
}

LogHistory _$LogHistoryFromJson(Map<String, dynamic> json) {
  return LogHistory(
    historyItems: (json['historyItems'] as List)
        ?.map((e) =>
            e == null ? null : HistoryItem.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$LogHistoryToJson(LogHistory instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('historyItems', instance.historyItems);
  return val;
}

LoginConfiguration _$LoginConfigurationFromJson(Map<String, dynamic> json) {
  return LoginConfiguration(
    allowTokenRefresh: json['allowTokenRefresh'] as bool,
    generateRefreshTokens: json['generateRefreshTokens'] as bool,
    requireAuthentication: json['requireAuthentication'] as bool,
  );
}

Map<String, dynamic> _$LoginConfigurationToJson(LoginConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('allowTokenRefresh', instance.allowTokenRefresh);
  writeNotNull('generateRefreshTokens', instance.generateRefreshTokens);
  writeNotNull('requireAuthentication', instance.requireAuthentication);
  return val;
}

LoginPreventedResponse _$LoginPreventedResponseFromJson(
    Map<String, dynamic> json) {
  return LoginPreventedResponse(
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
}

Map<String, dynamic> _$LoginPreventedResponseToJson(
    LoginPreventedResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actionerUserId', instance.actionerUserId);
  writeNotNull('actionId', instance.actionId);
  writeNotNull('expiry', instance.expiry);
  writeNotNull('localizedName', instance.localizedName);
  writeNotNull('localizedOption', instance.localizedOption);
  writeNotNull('localizedReason', instance.localizedReason);
  writeNotNull('name', instance.name);
  writeNotNull('option', instance.option);
  writeNotNull('reason', instance.reason);
  writeNotNull('reasonCode', instance.reasonCode);
  return val;
}

LoginRecordConfiguration _$LoginRecordConfigurationFromJson(
    Map<String, dynamic> json) {
  return LoginRecordConfiguration(
    delete: json['delete'] == null
        ? null
        : DeleteConfiguration.fromJson(json['delete'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$LoginRecordConfigurationToJson(
    LoginRecordConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('delete', instance.delete);
  return val;
}

LoginRecordExportRequest _$LoginRecordExportRequestFromJson(
    Map<String, dynamic> json) {
  return LoginRecordExportRequest(
    criteria: json['criteria'] == null
        ? null
        : LoginRecordSearchCriteria.fromJson(
            json['criteria'] as Map<String, dynamic>),
  )
    ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
    ..zoneId = json['zoneId'] as String;
}

Map<String, dynamic> _$LoginRecordExportRequestToJson(
    LoginRecordExportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dateTimeSecondsFormat', instance.dateTimeSecondsFormat);
  writeNotNull('zoneId', instance.zoneId);
  writeNotNull('criteria', instance.criteria);
  return val;
}

LoginRecordSearchCriteria _$LoginRecordSearchCriteriaFromJson(
    Map<String, dynamic> json) {
  return LoginRecordSearchCriteria(
    applicationId: json['applicationId'] as String,
    end: json['end'] as num,
    start: json['start'] as num,
    userId: json['userId'] as String,
  )
    ..numberOfResults = json['numberOfResults'] as num
    ..orderBy = json['orderBy'] as String
    ..startRow = json['startRow'] as num;
}

Map<String, dynamic> _$LoginRecordSearchCriteriaToJson(
    LoginRecordSearchCriteria instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberOfResults', instance.numberOfResults);
  writeNotNull('orderBy', instance.orderBy);
  writeNotNull('startRow', instance.startRow);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('end', instance.end);
  writeNotNull('start', instance.start);
  writeNotNull('userId', instance.userId);
  return val;
}

LoginRecordSearchRequest _$LoginRecordSearchRequestFromJson(
    Map<String, dynamic> json) {
  return LoginRecordSearchRequest(
    retrieveTotal: json['retrieveTotal'] as bool,
    search: json['search'] == null
        ? null
        : LoginRecordSearchCriteria.fromJson(
            json['search'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$LoginRecordSearchRequestToJson(
    LoginRecordSearchRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('retrieveTotal', instance.retrieveTotal);
  writeNotNull('search', instance.search);
  return val;
}

LoginRecordSearchResponse _$LoginRecordSearchResponseFromJson(
    Map<String, dynamic> json) {
  return LoginRecordSearchResponse(
    logins: (json['logins'] as List)
        ?.map((e) => e == null
            ? null
            : DisplayableRawLogin.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$LoginRecordSearchResponseToJson(
    LoginRecordSearchResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('logins', instance.logins);
  writeNotNull('total', instance.total);
  return val;
}

LoginReportResponse _$LoginReportResponseFromJson(Map<String, dynamic> json) {
  return LoginReportResponse(
    hourlyCounts: (json['hourlyCounts'] as List)
        ?.map(
            (e) => e == null ? null : Count.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$LoginReportResponseToJson(LoginReportResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('hourlyCounts', instance.hourlyCounts);
  writeNotNull('total', instance.total);
  return val;
}

LoginRequest _$LoginRequestFromJson(Map<String, dynamic> json) {
  return LoginRequest(
    loginId: json['loginId'] as String,
    oneTimePassword: json['oneTimePassword'] as String,
    password: json['password'] as String,
    twoFactorTrustId: json['twoFactorTrustId'] as String,
  )
    ..applicationId = json['applicationId'] as String
    ..ipAddress = json['ipAddress'] as String
    ..metaData = json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
    ..noJWT = json['noJWT'] as bool;
}

Map<String, dynamic> _$LoginRequestToJson(LoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('oneTimePassword', instance.oneTimePassword);
  writeNotNull('password', instance.password);
  writeNotNull('twoFactorTrustId', instance.twoFactorTrustId);
  return val;
}

LoginResponse _$LoginResponseFromJson(Map<String, dynamic> json) {
  return LoginResponse(
    actions: (json['actions'] as List)
        ?.map((e) => e == null
            ? null
            : LoginPreventedResponse.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    changePasswordId: json['changePasswordId'] as String,
    changePasswordReason: _$enumDecodeNullable(
        _$ChangePasswordReasonEnumMap, json['changePasswordReason']),
    refreshToken: json['refreshToken'] as String,
    state: json['state'] as Map<String, dynamic>,
    token: json['token'] as String,
    twoFactorId: json['twoFactorId'] as String,
    twoFactorTrustId: json['twoFactorTrustId'] as String,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$LoginResponseToJson(LoginResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actions', instance.actions);
  writeNotNull('changePasswordId', instance.changePasswordId);
  writeNotNull('changePasswordReason',
      _$ChangePasswordReasonEnumMap[instance.changePasswordReason]);
  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('state', instance.state);
  writeNotNull('token', instance.token);
  writeNotNull('twoFactorId', instance.twoFactorId);
  writeNotNull('twoFactorTrustId', instance.twoFactorTrustId);
  writeNotNull('user', instance.user);
  return val;
}

const _$ChangePasswordReasonEnumMap = {
  ChangePasswordReason.Administrative: 'Administrative',
  ChangePasswordReason.Breached: 'Breached',
  ChangePasswordReason.Expired: 'Expired',
  ChangePasswordReason.Validation: 'Validation',
};

LookupResponse _$LookupResponseFromJson(Map<String, dynamic> json) {
  return LookupResponse(
    identityProvider: json['identityProvider'] == null
        ? null
        : IdentityProviderDetails.fromJson(
            json['identityProvider'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$LookupResponseToJson(LookupResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('identityProvider', instance.identityProvider);
  return val;
}

MaximumPasswordAge _$MaximumPasswordAgeFromJson(Map<String, dynamic> json) {
  return MaximumPasswordAge(
    days: json['days'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$MaximumPasswordAgeToJson(MaximumPasswordAge instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('days', instance.days);
  return val;
}

MemberDeleteRequest _$MemberDeleteRequestFromJson(Map<String, dynamic> json) {
  return MemberDeleteRequest(
    memberIds: (json['memberIds'] as List)?.map((e) => e as String)?.toList(),
    members: (json['members'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, (e as List)?.map((e) => e as String)?.toList()),
    ),
  );
}

Map<String, dynamic> _$MemberDeleteRequestToJson(MemberDeleteRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('memberIds', instance.memberIds);
  writeNotNull('members', instance.members);
  return val;
}

MemberRequest _$MemberRequestFromJson(Map<String, dynamic> json) {
  return MemberRequest(
    members: (json['members'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          (e as List)
              ?.map((e) => e == null
                  ? null
                  : GroupMember.fromJson(e as Map<String, dynamic>))
              ?.toList()),
    ),
  );
}

Map<String, dynamic> _$MemberRequestToJson(MemberRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('members', instance.members);
  return val;
}

MemberResponse _$MemberResponseFromJson(Map<String, dynamic> json) {
  return MemberResponse(
    members: (json['members'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          (e as List)
              ?.map((e) => e == null
                  ? null
                  : GroupMember.fromJson(e as Map<String, dynamic>))
              ?.toList()),
    ),
  );
}

Map<String, dynamic> _$MemberResponseToJson(MemberResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('members', instance.members);
  return val;
}

MetaData _$MetaDataFromJson(Map<String, dynamic> json) {
  return MetaData(
    device: json['device'] == null
        ? null
        : DeviceInfo.fromJson(json['device'] as Map<String, dynamic>),
    scopes: (json['scopes'] as List)?.map((e) => e as String)?.toSet(),
  );
}

Map<String, dynamic> _$MetaDataToJson(MetaData instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('device', instance.device);
  writeNotNull('scopes', instance.scopes?.toList());
  return val;
}

MinimumPasswordAge _$MinimumPasswordAgeFromJson(Map<String, dynamic> json) {
  return MinimumPasswordAge(
    seconds: json['seconds'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$MinimumPasswordAgeToJson(MinimumPasswordAge instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('seconds', instance.seconds);
  return val;
}

MonthlyActiveUserReportResponse _$MonthlyActiveUserReportResponseFromJson(
    Map<String, dynamic> json) {
  return MonthlyActiveUserReportResponse(
    monthlyActiveUsers: (json['monthlyActiveUsers'] as List)
        ?.map(
            (e) => e == null ? null : Count.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$MonthlyActiveUserReportResponseToJson(
    MonthlyActiveUserReportResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('monthlyActiveUsers', instance.monthlyActiveUsers);
  writeNotNull('total', instance.total);
  return val;
}

Normalizer _$NormalizerFromJson(Map<String, dynamic> json) {
  return Normalizer();
}

Map<String, dynamic> _$NormalizerToJson(Normalizer instance) =>
    <String, dynamic>{};

OAuth2Configuration _$OAuth2ConfigurationFromJson(Map<String, dynamic> json) {
  return OAuth2Configuration(
    authorizedOriginURLs: (json['authorizedOriginURLs'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    authorizedRedirectURLs: (json['authorizedRedirectURLs'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    clientId: json['clientId'] as String,
    clientSecret: json['clientSecret'] as String,
    deviceVerificationURL: json['deviceVerificationURL'] as String,
    enabledGrants: (json['enabledGrants'] as List)
        ?.map((e) => _$enumDecodeNullable(_$GrantTypeEnumMap, e))
        ?.toSet(),
    generateRefreshTokens: json['generateRefreshTokens'] as bool,
    logoutBehavior:
        _$enumDecodeNullable(_$LogoutBehaviorEnumMap, json['logoutBehavior']),
    logoutURL: json['logoutURL'] as String,
    requireClientAuthentication: json['requireClientAuthentication'] as bool,
  );
}

Map<String, dynamic> _$OAuth2ConfigurationToJson(OAuth2Configuration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('authorizedOriginURLs', instance.authorizedOriginURLs);
  writeNotNull('authorizedRedirectURLs', instance.authorizedRedirectURLs);
  writeNotNull('clientId', instance.clientId);
  writeNotNull('clientSecret', instance.clientSecret);
  writeNotNull('deviceVerificationURL', instance.deviceVerificationURL);
  writeNotNull('enabledGrants',
      instance.enabledGrants?.map((e) => _$GrantTypeEnumMap[e])?.toList());
  writeNotNull('generateRefreshTokens', instance.generateRefreshTokens);
  writeNotNull(
      'logoutBehavior', _$LogoutBehaviorEnumMap[instance.logoutBehavior]);
  writeNotNull('logoutURL', instance.logoutURL);
  writeNotNull(
      'requireClientAuthentication', instance.requireClientAuthentication);
  return val;
}

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

OAuthConfigurationResponse _$OAuthConfigurationResponseFromJson(
    Map<String, dynamic> json) {
  return OAuthConfigurationResponse(
    httpSessionMaxInactiveInterval:
        json['httpSessionMaxInactiveInterval'] as num,
    logoutURL: json['logoutURL'] as String,
    oauthConfiguration: json['oauthConfiguration'] == null
        ? null
        : OAuth2Configuration.fromJson(
            json['oauthConfiguration'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$OAuthConfigurationResponseToJson(
    OAuthConfigurationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('httpSessionMaxInactiveInterval',
      instance.httpSessionMaxInactiveInterval);
  writeNotNull('logoutURL', instance.logoutURL);
  writeNotNull('oauthConfiguration', instance.oauthConfiguration);
  return val;
}

OAuthError _$OAuthErrorFromJson(Map<String, dynamic> json) {
  return OAuthError(
    change_password_id: json['change_password_id'] as String,
    error: _$enumDecodeNullable(_$OAuthErrorTypeEnumMap, json['error']),
    error_description: json['error_description'] as String,
    error_reason:
        _$enumDecodeNullable(_$OAuthErrorReasonEnumMap, json['error_reason']),
    error_uri: json['error_uri'] as String,
    two_factor_id: json['two_factor_id'] as String,
  );
}

Map<String, dynamic> _$OAuthErrorToJson(OAuthError instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('change_password_id', instance.change_password_id);
  writeNotNull('error', _$OAuthErrorTypeEnumMap[instance.error]);
  writeNotNull('error_description', instance.error_description);
  writeNotNull(
      'error_reason', _$OAuthErrorReasonEnumMap[instance.error_reason]);
  writeNotNull('error_uri', instance.error_uri);
  writeNotNull('two_factor_id', instance.two_factor_id);
  return val;
}

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
  OAuthErrorType.two_factor_required: 'two_factor_required',
  OAuthErrorType.authorization_pending: 'authorization_pending',
  OAuthErrorType.expired_token: 'expired_token',
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
  OAuthErrorReason.grant_type_disabled: 'grant_type_disabled',
  OAuthErrorReason.missing_client_id: 'missing_client_id',
  OAuthErrorReason.missing_code: 'missing_code',
  OAuthErrorReason.missing_device_code: 'missing_device_code',
  OAuthErrorReason.missing_grant_type: 'missing_grant_type',
  OAuthErrorReason.missing_redirect_uri: 'missing_redirect_uri',
  OAuthErrorReason.missing_refresh_token: 'missing_refresh_token',
  OAuthErrorReason.missing_response_type: 'missing_response_type',
  OAuthErrorReason.missing_token: 'missing_token',
  OAuthErrorReason.missing_user_code: 'missing_user_code',
  OAuthErrorReason.missing_verification_uri: 'missing_verification_uri',
  OAuthErrorReason.login_prevented: 'login_prevented',
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

OAuthResponse _$OAuthResponseFromJson(Map<String, dynamic> json) {
  return OAuthResponse();
}

Map<String, dynamic> _$OAuthResponseToJson(OAuthResponse instance) =>
    <String, dynamic>{};

OpenIdConfiguration _$OpenIdConfigurationFromJson(Map<String, dynamic> json) {
  return OpenIdConfiguration(
    authorization_endpoint: json['authorization_endpoint'] as String,
    backchannel_logout_supported: json['backchannel_logout_supported'] as bool,
    claims_supported:
        (json['claims_supported'] as List)?.map((e) => e as String)?.toList(),
    device_authorization_endpoint:
        json['device_authorization_endpoint'] as String,
    end_session_endpoint: json['end_session_endpoint'] as String,
    frontchannel_logout_supported:
        json['frontchannel_logout_supported'] as bool,
    grant_types_supported: (json['grant_types_supported'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    id_token_signing_alg_values_supported:
        (json['id_token_signing_alg_values_supported'] as List)
            ?.map((e) => e as String)
            ?.toList(),
    issuer: json['issuer'] as String,
    jwks_uri: json['jwks_uri'] as String,
    response_modes_supported: (json['response_modes_supported'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    response_types_supported: (json['response_types_supported'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    scopes_supported:
        (json['scopes_supported'] as List)?.map((e) => e as String)?.toList(),
    subject_types_supported: (json['subject_types_supported'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    token_endpoint: json['token_endpoint'] as String,
    token_endpoint_auth_methods_supported:
        (json['token_endpoint_auth_methods_supported'] as List)
            ?.map((e) => e as String)
            ?.toList(),
    userinfo_endpoint: json['userinfo_endpoint'] as String,
    userinfo_signing_alg_values_supported:
        (json['userinfo_signing_alg_values_supported'] as List)
            ?.map((e) => e as String)
            ?.toList(),
  );
}

Map<String, dynamic> _$OpenIdConfigurationToJson(OpenIdConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('authorization_endpoint', instance.authorization_endpoint);
  writeNotNull(
      'backchannel_logout_supported', instance.backchannel_logout_supported);
  writeNotNull('claims_supported', instance.claims_supported);
  writeNotNull(
      'device_authorization_endpoint', instance.device_authorization_endpoint);
  writeNotNull('end_session_endpoint', instance.end_session_endpoint);
  writeNotNull(
      'frontchannel_logout_supported', instance.frontchannel_logout_supported);
  writeNotNull('grant_types_supported', instance.grant_types_supported);
  writeNotNull('id_token_signing_alg_values_supported',
      instance.id_token_signing_alg_values_supported);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('jwks_uri', instance.jwks_uri);
  writeNotNull('response_modes_supported', instance.response_modes_supported);
  writeNotNull('response_types_supported', instance.response_types_supported);
  writeNotNull('scopes_supported', instance.scopes_supported);
  writeNotNull('subject_types_supported', instance.subject_types_supported);
  writeNotNull('token_endpoint', instance.token_endpoint);
  writeNotNull('token_endpoint_auth_methods_supported',
      instance.token_endpoint_auth_methods_supported);
  writeNotNull('userinfo_endpoint', instance.userinfo_endpoint);
  writeNotNull('userinfo_signing_alg_values_supported',
      instance.userinfo_signing_alg_values_supported);
  return val;
}

OpenIdConnectApplicationConfiguration
    _$OpenIdConnectApplicationConfigurationFromJson(Map<String, dynamic> json) {
  return OpenIdConnectApplicationConfiguration(
    buttonImageURL: json['buttonImageURL'] as String,
    buttonText: json['buttonText'] as String,
    oauth2: json['oauth2'] == null
        ? null
        : IdentityProviderOauth2Configuration.fromJson(
            json['oauth2'] as Map<String, dynamic>),
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$OpenIdConnectApplicationConfigurationToJson(
    OpenIdConnectApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonImageURL', instance.buttonImageURL);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('oauth2', instance.oauth2);
  return val;
}

OpenIdConnectIdentityProvider _$OpenIdConnectIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return OpenIdConnectIdentityProvider(
    buttonImageURL: json['buttonImageURL'] as String,
    buttonText: json['buttonText'] as String,
    domains: (json['domains'] as List)?.map((e) => e as String)?.toSet(),
    oauth2: json['oauth2'] == null
        ? null
        : IdentityProviderOauth2Configuration.fromJson(
            json['oauth2'] as Map<String, dynamic>),
    postRequest: json['postRequest'] as bool,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : OpenIdConnectApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$OpenIdConnectIdentityProviderToJson(
    OpenIdConnectIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonImageURL', instance.buttonImageURL);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('domains', instance.domains?.toList());
  writeNotNull('oauth2', instance.oauth2);
  writeNotNull('postRequest', instance.postRequest);
  return val;
}

PasswordBreachDetection _$PasswordBreachDetectionFromJson(
    Map<String, dynamic> json) {
  return PasswordBreachDetection(
    matchMode:
        _$enumDecodeNullable(_$BreachMatchModeEnumMap, json['matchMode']),
    notifyUserEmailTemplateId: json['notifyUserEmailTemplateId'] as String,
    onLogin: _$enumDecodeNullable(_$BreachActionEnumMap, json['onLogin']),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$PasswordBreachDetectionToJson(
    PasswordBreachDetection instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('matchMode', _$BreachMatchModeEnumMap[instance.matchMode]);
  writeNotNull('notifyUserEmailTemplateId', instance.notifyUserEmailTemplateId);
  writeNotNull('onLogin', _$BreachActionEnumMap[instance.onLogin]);
  return val;
}

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
    Map<String, dynamic> json) {
  return PasswordEncryptionConfiguration(
    encryptionScheme: json['encryptionScheme'] as String,
    encryptionSchemeFactor: json['encryptionSchemeFactor'] as num,
    modifyEncryptionSchemeOnLogin:
        json['modifyEncryptionSchemeOnLogin'] as bool,
  );
}

Map<String, dynamic> _$PasswordEncryptionConfigurationToJson(
    PasswordEncryptionConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('encryptionScheme', instance.encryptionScheme);
  writeNotNull('encryptionSchemeFactor', instance.encryptionSchemeFactor);
  writeNotNull(
      'modifyEncryptionSchemeOnLogin', instance.modifyEncryptionSchemeOnLogin);
  return val;
}

PasswordlessConfiguration _$PasswordlessConfigurationFromJson(
    Map<String, dynamic> json) {
  return PasswordlessConfiguration()..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$PasswordlessConfigurationToJson(
    PasswordlessConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  return val;
}

PasswordlessIdentityProvider _$PasswordlessIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return PasswordlessIdentityProvider();
}

Map<String, dynamic> _$PasswordlessIdentityProviderToJson(
        PasswordlessIdentityProvider instance) =>
    <String, dynamic>{};

PasswordlessLoginRequest _$PasswordlessLoginRequestFromJson(
    Map<String, dynamic> json) {
  return PasswordlessLoginRequest(
    code: json['code'] as String,
    twoFactorTrustId: json['twoFactorTrustId'] as String,
  )
    ..applicationId = json['applicationId'] as String
    ..ipAddress = json['ipAddress'] as String
    ..metaData = json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
    ..noJWT = json['noJWT'] as bool;
}

Map<String, dynamic> _$PasswordlessLoginRequestToJson(
    PasswordlessLoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  writeNotNull('code', instance.code);
  writeNotNull('twoFactorTrustId', instance.twoFactorTrustId);
  return val;
}

PasswordlessSendRequest _$PasswordlessSendRequestFromJson(
    Map<String, dynamic> json) {
  return PasswordlessSendRequest(
    applicationId: json['applicationId'] as String,
    code: json['code'] as String,
    loginId: json['loginId'] as String,
    state: json['state'] as Map<String, dynamic>,
  );
}

Map<String, dynamic> _$PasswordlessSendRequestToJson(
    PasswordlessSendRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('code', instance.code);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('state', instance.state);
  return val;
}

PasswordlessStartRequest _$PasswordlessStartRequestFromJson(
    Map<String, dynamic> json) {
  return PasswordlessStartRequest(
    applicationId: json['applicationId'] as String,
    loginId: json['loginId'] as String,
    state: json['state'] as Map<String, dynamic>,
  );
}

Map<String, dynamic> _$PasswordlessStartRequestToJson(
    PasswordlessStartRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('loginId', instance.loginId);
  writeNotNull('state', instance.state);
  return val;
}

PasswordlessStartResponse _$PasswordlessStartResponseFromJson(
    Map<String, dynamic> json) {
  return PasswordlessStartResponse(
    code: json['code'] as String,
  );
}

Map<String, dynamic> _$PasswordlessStartResponseToJson(
    PasswordlessStartResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('code', instance.code);
  return val;
}

PasswordValidationRules _$PasswordValidationRulesFromJson(
    Map<String, dynamic> json) {
  return PasswordValidationRules(
    breachDetection: json['breachDetection'] == null
        ? null
        : PasswordBreachDetection.fromJson(
            json['breachDetection'] as Map<String, dynamic>),
    maxLength: json['maxLength'] as num,
    minLength: json['minLength'] as num,
    rememberPreviousPasswords: json['rememberPreviousPasswords'] == null
        ? null
        : RememberPreviousPasswords.fromJson(
            json['rememberPreviousPasswords'] as Map<String, dynamic>),
    requireMixedCase: json['requireMixedCase'] as bool,
    requireNonAlpha: json['requireNonAlpha'] as bool,
    requireNumber: json['requireNumber'] as bool,
    validateOnLogin: json['validateOnLogin'] as bool,
  );
}

Map<String, dynamic> _$PasswordValidationRulesToJson(
    PasswordValidationRules instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('breachDetection', instance.breachDetection);
  writeNotNull('maxLength', instance.maxLength);
  writeNotNull('minLength', instance.minLength);
  writeNotNull('rememberPreviousPasswords', instance.rememberPreviousPasswords);
  writeNotNull('requireMixedCase', instance.requireMixedCase);
  writeNotNull('requireNonAlpha', instance.requireNonAlpha);
  writeNotNull('requireNumber', instance.requireNumber);
  writeNotNull('validateOnLogin', instance.validateOnLogin);
  return val;
}

PasswordValidationRulesResponse _$PasswordValidationRulesResponseFromJson(
    Map<String, dynamic> json) {
  return PasswordValidationRulesResponse(
    passwordValidationRules: json['passwordValidationRules'] == null
        ? null
        : PasswordValidationRules.fromJson(
            json['passwordValidationRules'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$PasswordValidationRulesResponseToJson(
    PasswordValidationRulesResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('passwordValidationRules', instance.passwordValidationRules);
  return val;
}

PendingResponse _$PendingResponseFromJson(Map<String, dynamic> json) {
  return PendingResponse(
    users: (json['users'] as List)
        ?.map(
            (e) => e == null ? null : User.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$PendingResponseToJson(PendingResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('users', instance.users);
  return val;
}

PreviewRequest _$PreviewRequestFromJson(Map<String, dynamic> json) {
  return PreviewRequest(
    emailTemplate: json['emailTemplate'] == null
        ? null
        : EmailTemplate.fromJson(json['emailTemplate'] as Map<String, dynamic>),
    locale: json['locale'] as String,
  );
}

Map<String, dynamic> _$PreviewRequestToJson(PreviewRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('emailTemplate', instance.emailTemplate);
  writeNotNull('locale', instance.locale);
  return val;
}

PreviewResponse _$PreviewResponseFromJson(Map<String, dynamic> json) {
  return PreviewResponse(
    email: json['email'] == null
        ? null
        : Email.fromJson(json['email'] as Map<String, dynamic>),
    errors: json['errors'] == null
        ? null
        : Errors.fromJson(json['errors'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$PreviewResponseToJson(PreviewResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('email', instance.email);
  writeNotNull('errors', instance.errors);
  return val;
}

PublicKeyResponse _$PublicKeyResponseFromJson(Map<String, dynamic> json) {
  return PublicKeyResponse(
    publicKey: json['publicKey'] as String,
    publicKeys: (json['publicKeys'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
  );
}

Map<String, dynamic> _$PublicKeyResponseToJson(PublicKeyResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('publicKey', instance.publicKey);
  writeNotNull('publicKeys', instance.publicKeys);
  return val;
}

RawLogin _$RawLoginFromJson(Map<String, dynamic> json) {
  return RawLogin(
    applicationId: json['applicationId'] as String,
    instant: json['instant'] as num,
    ipAddress: json['ipAddress'] as String,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$RawLoginToJson(RawLogin instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('instant', instance.instant);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('userId', instance.userId);
  return val;
}

RecentLoginResponse _$RecentLoginResponseFromJson(Map<String, dynamic> json) {
  return RecentLoginResponse(
    logins: (json['logins'] as List)
        ?.map((e) => e == null
            ? null
            : DisplayableRawLogin.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$RecentLoginResponseToJson(RecentLoginResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('logins', instance.logins);
  return val;
}

RefreshRequest _$RefreshRequestFromJson(Map<String, dynamic> json) {
  return RefreshRequest(
    refreshToken: json['refreshToken'] as String,
    token: json['token'] as String,
  );
}

Map<String, dynamic> _$RefreshRequestToJson(RefreshRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('token', instance.token);
  return val;
}

RefreshResponse _$RefreshResponseFromJson(Map<String, dynamic> json) {
  return RefreshResponse(
    refreshToken: json['refreshToken'] as String,
    refreshTokens: (json['refreshTokens'] as List)
        ?.map((e) =>
            e == null ? null : RefreshToken.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    token: json['token'] as String,
  );
}

Map<String, dynamic> _$RefreshResponseToJson(RefreshResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('refreshTokens', instance.refreshTokens);
  writeNotNull('token', instance.token);
  return val;
}

RefreshToken _$RefreshTokenFromJson(Map<String, dynamic> json) {
  return RefreshToken(
    applicationId: json['applicationId'] as String,
    data: json['data'] as Map<String, dynamic>,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    metaData: json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>),
    startInstant: json['startInstant'] as num,
    token: json['token'] as String,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$RefreshTokenToJson(RefreshToken instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('data', instance.data);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('startInstant', instance.startInstant);
  writeNotNull('token', instance.token);
  writeNotNull('userId', instance.userId);
  return val;
}

RefreshTokenImportRequest _$RefreshTokenImportRequestFromJson(
    Map<String, dynamic> json) {
  return RefreshTokenImportRequest(
    refreshTokens: (json['refreshTokens'] as List)
        ?.map((e) =>
            e == null ? null : RefreshToken.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    validateDbConstraints: json['validateDbConstraints'] as bool,
  );
}

Map<String, dynamic> _$RefreshTokenImportRequestToJson(
    RefreshTokenImportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('refreshTokens', instance.refreshTokens);
  writeNotNull('validateDbConstraints', instance.validateDbConstraints);
  return val;
}

RefreshTokenRevocationPolicy _$RefreshTokenRevocationPolicyFromJson(
    Map<String, dynamic> json) {
  return RefreshTokenRevocationPolicy(
    onLoginPrevented: json['onLoginPrevented'] as bool,
    onPasswordChanged: json['onPasswordChanged'] as bool,
  );
}

Map<String, dynamic> _$RefreshTokenRevocationPolicyToJson(
    RefreshTokenRevocationPolicy instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('onLoginPrevented', instance.onLoginPrevented);
  writeNotNull('onPasswordChanged', instance.onPasswordChanged);
  return val;
}

RegistrationConfiguration _$RegistrationConfigurationFromJson(
    Map<String, dynamic> json) {
  return RegistrationConfiguration(
    birthDate: json['birthDate'] == null
        ? null
        : Requirable.fromJson(json['birthDate'] as Map<String, dynamic>),
    confirmPassword: json['confirmPassword'] as bool,
    firstName: json['firstName'] == null
        ? null
        : Requirable.fromJson(json['firstName'] as Map<String, dynamic>),
    formId: json['formId'] as String,
    fullName: json['fullName'] == null
        ? null
        : Requirable.fromJson(json['fullName'] as Map<String, dynamic>),
    lastName: json['lastName'] == null
        ? null
        : Requirable.fromJson(json['lastName'] as Map<String, dynamic>),
    loginIdType:
        _$enumDecodeNullable(_$LoginIdTypeEnumMap, json['loginIdType']),
    middleName: json['middleName'] == null
        ? null
        : Requirable.fromJson(json['middleName'] as Map<String, dynamic>),
    mobilePhone: json['mobilePhone'] == null
        ? null
        : Requirable.fromJson(json['mobilePhone'] as Map<String, dynamic>),
    type: _$enumDecodeNullable(_$RegistrationTypeEnumMap, json['type']),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$RegistrationConfigurationToJson(
    RegistrationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('birthDate', instance.birthDate);
  writeNotNull('confirmPassword', instance.confirmPassword);
  writeNotNull('firstName', instance.firstName);
  writeNotNull('formId', instance.formId);
  writeNotNull('fullName', instance.fullName);
  writeNotNull('lastName', instance.lastName);
  writeNotNull('loginIdType', _$LoginIdTypeEnumMap[instance.loginIdType]);
  writeNotNull('middleName', instance.middleName);
  writeNotNull('mobilePhone', instance.mobilePhone);
  writeNotNull('type', _$RegistrationTypeEnumMap[instance.type]);
  return val;
}

const _$LoginIdTypeEnumMap = {
  LoginIdType.email: 'email',
  LoginIdType.username: 'username',
};

const _$RegistrationTypeEnumMap = {
  RegistrationType.basic: 'basic',
  RegistrationType.advanced: 'advanced',
};

RegistrationReportResponse _$RegistrationReportResponseFromJson(
    Map<String, dynamic> json) {
  return RegistrationReportResponse(
    hourlyCounts: (json['hourlyCounts'] as List)
        ?.map(
            (e) => e == null ? null : Count.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    total: json['total'] as num,
  );
}

Map<String, dynamic> _$RegistrationReportResponseToJson(
    RegistrationReportResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('hourlyCounts', instance.hourlyCounts);
  writeNotNull('total', instance.total);
  return val;
}

RegistrationRequest _$RegistrationRequestFromJson(Map<String, dynamic> json) {
  return RegistrationRequest(
    generateAuthenticationToken: json['generateAuthenticationToken'] as bool,
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    sendSetPasswordEmail: json['sendSetPasswordEmail'] as bool,
    skipRegistrationVerification: json['skipRegistrationVerification'] as bool,
    skipVerification: json['skipVerification'] as bool,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$RegistrationRequestToJson(RegistrationRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull(
      'generateAuthenticationToken', instance.generateAuthenticationToken);
  writeNotNull('registration', instance.registration);
  writeNotNull('sendSetPasswordEmail', instance.sendSetPasswordEmail);
  writeNotNull(
      'skipRegistrationVerification', instance.skipRegistrationVerification);
  writeNotNull('skipVerification', instance.skipVerification);
  writeNotNull('user', instance.user);
  return val;
}

RegistrationResponse _$RegistrationResponseFromJson(Map<String, dynamic> json) {
  return RegistrationResponse(
    refreshToken: json['refreshToken'] as String,
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    token: json['token'] as String,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$RegistrationResponseToJson(
    RegistrationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('refreshToken', instance.refreshToken);
  writeNotNull('registration', instance.registration);
  writeNotNull('token', instance.token);
  writeNotNull('user', instance.user);
  return val;
}

ReloadRequest _$ReloadRequestFromJson(Map<String, dynamic> json) {
  return ReloadRequest(
    names: (json['names'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$ReloadRequestToJson(ReloadRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('names', instance.names);
  return val;
}

RememberPreviousPasswords _$RememberPreviousPasswordsFromJson(
    Map<String, dynamic> json) {
  return RememberPreviousPasswords(
    count: json['count'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$RememberPreviousPasswordsToJson(
    RememberPreviousPasswords instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('count', instance.count);
  return val;
}

Requirable _$RequirableFromJson(Map<String, dynamic> json) {
  return Requirable(
    required: json['required'] as bool,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$RequirableToJson(Requirable instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('required', instance.required);
  return val;
}

RequiresCORSConfiguration _$RequiresCORSConfigurationFromJson(
    Map<String, dynamic> json) {
  return RequiresCORSConfiguration();
}

Map<String, dynamic> _$RequiresCORSConfigurationToJson(
        RequiresCORSConfiguration instance) =>
    <String, dynamic>{};

SAMLv2ApplicationConfiguration _$SAMLv2ApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return SAMLv2ApplicationConfiguration(
    buttonImageURL: json['buttonImageURL'] as String,
    buttonText: json['buttonText'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$SAMLv2ApplicationConfigurationToJson(
    SAMLv2ApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonImageURL', instance.buttonImageURL);
  writeNotNull('buttonText', instance.buttonText);
  return val;
}

SAMLv2Configuration _$SAMLv2ConfigurationFromJson(Map<String, dynamic> json) {
  return SAMLv2Configuration(
    audience: json['audience'] as String,
    authorizedRedirectURLs: (json['authorizedRedirectURLs'] as List)
        ?.map((e) => e as String)
        ?.toList(),
    callbackURL: json['callbackURL'] as String,
    debug: json['debug'] as bool,
    defaultVerificationKeyId: json['defaultVerificationKeyId'] as String,
    issuer: json['issuer'] as String,
    keyId: json['keyId'] as String,
    logoutURL: json['logoutURL'] as String,
    requireSignedRequests: json['requireSignedRequests'] as bool,
    xmlSignatureC14nMethod: _$enumDecodeNullable(
        _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
    xmlSignatureLocation: _$enumDecodeNullable(
        _$XMLSignatureLocationEnumMap, json['xmlSignatureLocation']),
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$SAMLv2ConfigurationToJson(SAMLv2Configuration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('audience', instance.audience);
  writeNotNull('authorizedRedirectURLs', instance.authorizedRedirectURLs);
  writeNotNull('callbackURL', instance.callbackURL);
  writeNotNull('debug', instance.debug);
  writeNotNull('defaultVerificationKeyId', instance.defaultVerificationKeyId);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('keyId', instance.keyId);
  writeNotNull('logoutURL', instance.logoutURL);
  writeNotNull('requireSignedRequests', instance.requireSignedRequests);
  writeNotNull('xmlSignatureC14nMethod',
      _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod]);
  writeNotNull('xmlSignatureLocation',
      _$XMLSignatureLocationEnumMap[instance.xmlSignatureLocation]);
  return val;
}

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
    Map<String, dynamic> json) {
  return SAMLv2IdentityProvider(
    buttonImageURL: json['buttonImageURL'] as String,
    buttonText: json['buttonText'] as String,
    domains: (json['domains'] as List)?.map((e) => e as String)?.toSet(),
    emailClaim: json['emailClaim'] as String,
    idpEndpoint: json['idpEndpoint'] as String,
    issuer: json['issuer'] as String,
    keyId: json['keyId'] as String,
    postRequest: json['postRequest'] as bool,
    requestSigningKeyId: json['requestSigningKeyId'] as String,
    signRequest: json['signRequest'] as bool,
    useNameIdForEmail: json['useNameIdForEmail'] as bool,
    xmlSignatureC14nMethod: _$enumDecodeNullable(
        _$CanonicalizationMethodEnumMap, json['xmlSignatureC14nMethod']),
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : SAMLv2ApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$SAMLv2IdentityProviderToJson(
    SAMLv2IdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonImageURL', instance.buttonImageURL);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('domains', instance.domains?.toList());
  writeNotNull('emailClaim', instance.emailClaim);
  writeNotNull('idpEndpoint', instance.idpEndpoint);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('keyId', instance.keyId);
  writeNotNull('postRequest', instance.postRequest);
  writeNotNull('requestSigningKeyId', instance.requestSigningKeyId);
  writeNotNull('signRequest', instance.signRequest);
  writeNotNull('useNameIdForEmail', instance.useNameIdForEmail);
  writeNotNull('xmlSignatureC14nMethod',
      _$CanonicalizationMethodEnumMap[instance.xmlSignatureC14nMethod]);
  return val;
}

SearchRequest _$SearchRequestFromJson(Map<String, dynamic> json) {
  return SearchRequest(
    search: json['search'] == null
        ? null
        : UserSearchCriteria.fromJson(json['search'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$SearchRequestToJson(SearchRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('search', instance.search);
  return val;
}

SearchResponse _$SearchResponseFromJson(Map<String, dynamic> json) {
  return SearchResponse(
    total: json['total'] as num,
    users: (json['users'] as List)
        ?.map(
            (e) => e == null ? null : User.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$SearchResponseToJson(SearchResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('total', instance.total);
  writeNotNull('users', instance.users);
  return val;
}

SecretResponse _$SecretResponseFromJson(Map<String, dynamic> json) {
  return SecretResponse(
    secret: json['secret'] as String,
    secretBase32Encoded: json['secretBase32Encoded'] as String,
  );
}

Map<String, dynamic> _$SecretResponseToJson(SecretResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('secret', instance.secret);
  writeNotNull('secretBase32Encoded', instance.secretBase32Encoded);
  return val;
}

SecureGeneratorConfiguration _$SecureGeneratorConfigurationFromJson(
    Map<String, dynamic> json) {
  return SecureGeneratorConfiguration(
    length: json['length'] as num,
    type: _$enumDecodeNullable(_$SecureGeneratorTypeEnumMap, json['type']),
  );
}

Map<String, dynamic> _$SecureGeneratorConfigurationToJson(
    SecureGeneratorConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('length', instance.length);
  writeNotNull('type', _$SecureGeneratorTypeEnumMap[instance.type]);
  return val;
}

const _$SecureGeneratorTypeEnumMap = {
  SecureGeneratorType.randomDigits: 'randomDigits',
  SecureGeneratorType.randomBytes: 'randomBytes',
  SecureGeneratorType.randomAlpha: 'randomAlpha',
  SecureGeneratorType.randomAlphaNumeric: 'randomAlphaNumeric',
};

SecureIdentity _$SecureIdentityFromJson(Map<String, dynamic> json) {
  return SecureIdentity(
    breachedPasswordLastCheckedInstant:
        json['breachedPasswordLastCheckedInstant'] as num,
    breachedPasswordStatus: _$enumDecodeNullable(
        _$BreachedPasswordStatusEnumMap, json['breachedPasswordStatus']),
    connectorId: json['connectorId'] as String,
    encryptionScheme: json['encryptionScheme'] as String,
    factor: json['factor'] as num,
    id: json['id'] as String,
    lastLoginInstant: json['lastLoginInstant'] as num,
    password: json['password'] as String,
    passwordChangeReason: _$enumDecodeNullable(
        _$ChangePasswordReasonEnumMap, json['passwordChangeReason']),
    passwordChangeRequired: json['passwordChangeRequired'] as bool,
    passwordLastUpdateInstant: json['passwordLastUpdateInstant'] as num,
    salt: json['salt'] as String,
    twoFactorDelivery: _$enumDecodeNullable(
        _$TwoFactorDeliveryEnumMap, json['twoFactorDelivery']),
    twoFactorEnabled: json['twoFactorEnabled'] as bool,
    twoFactorSecret: json['twoFactorSecret'] as String,
    username: json['username'] as String,
    usernameStatus:
        _$enumDecodeNullable(_$ContentStatusEnumMap, json['usernameStatus']),
    verified: json['verified'] as bool,
  );
}

Map<String, dynamic> _$SecureIdentityToJson(SecureIdentity instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('breachedPasswordLastCheckedInstant',
      instance.breachedPasswordLastCheckedInstant);
  writeNotNull('breachedPasswordStatus',
      _$BreachedPasswordStatusEnumMap[instance.breachedPasswordStatus]);
  writeNotNull('connectorId', instance.connectorId);
  writeNotNull('encryptionScheme', instance.encryptionScheme);
  writeNotNull('factor', instance.factor);
  writeNotNull('id', instance.id);
  writeNotNull('lastLoginInstant', instance.lastLoginInstant);
  writeNotNull('password', instance.password);
  writeNotNull('passwordChangeReason',
      _$ChangePasswordReasonEnumMap[instance.passwordChangeReason]);
  writeNotNull('passwordChangeRequired', instance.passwordChangeRequired);
  writeNotNull('passwordLastUpdateInstant', instance.passwordLastUpdateInstant);
  writeNotNull('salt', instance.salt);
  writeNotNull('twoFactorDelivery',
      _$TwoFactorDeliveryEnumMap[instance.twoFactorDelivery]);
  writeNotNull('twoFactorEnabled', instance.twoFactorEnabled);
  writeNotNull('twoFactorSecret', instance.twoFactorSecret);
  writeNotNull('username', instance.username);
  writeNotNull(
      'usernameStatus', _$ContentStatusEnumMap[instance.usernameStatus]);
  writeNotNull('verified', instance.verified);
  return val;
}

const _$BreachedPasswordStatusEnumMap = {
  BreachedPasswordStatus.None: 'None',
  BreachedPasswordStatus.ExactMatch: 'ExactMatch',
  BreachedPasswordStatus.SubAddressMatch: 'SubAddressMatch',
  BreachedPasswordStatus.PasswordOnly: 'PasswordOnly',
  BreachedPasswordStatus.CommonPassword: 'CommonPassword',
};

const _$TwoFactorDeliveryEnumMap = {
  TwoFactorDelivery.None: 'None',
  TwoFactorDelivery.TextMessage: 'TextMessage',
};

const _$ContentStatusEnumMap = {
  ContentStatus.ACTIVE: 'ACTIVE',
  ContentStatus.PENDING: 'PENDING',
  ContentStatus.REJECTED: 'REJECTED',
};

SendRequest _$SendRequestFromJson(Map<String, dynamic> json) {
  return SendRequest(
    bccAddresses:
        (json['bccAddresses'] as List)?.map((e) => e as String)?.toList(),
    ccAddresses:
        (json['ccAddresses'] as List)?.map((e) => e as String)?.toList(),
    requestData: json['requestData'] as Map<String, dynamic>,
    userIds: (json['userIds'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$SendRequestToJson(SendRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('bccAddresses', instance.bccAddresses);
  writeNotNull('ccAddresses', instance.ccAddresses);
  writeNotNull('requestData', instance.requestData);
  writeNotNull('userIds', instance.userIds);
  return val;
}

SendResponse _$SendResponseFromJson(Map<String, dynamic> json) {
  return SendResponse(
    results: (json['results'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : EmailTemplateErrors.fromJson(e as Map<String, dynamic>)),
    ),
  );
}

Map<String, dynamic> _$SendResponseToJson(SendResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('results', instance.results);
  return val;
}

SortField _$SortFieldFromJson(Map<String, dynamic> json) {
  return SortField(
    missing: json['missing'] as String,
    name: json['name'] as String,
    order: _$enumDecodeNullable(_$SortEnumMap, json['order']),
  );
}

Map<String, dynamic> _$SortFieldToJson(SortField instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('missing', instance.missing);
  writeNotNull('name', instance.name);
  writeNotNull('order', _$SortEnumMap[instance.order]);
  return val;
}

const _$SortEnumMap = {
  Sort.asc: 'asc',
  Sort.desc: 'desc',
};

SupportsPostBindings _$SupportsPostBindingsFromJson(Map<String, dynamic> json) {
  return SupportsPostBindings();
}

Map<String, dynamic> _$SupportsPostBindingsToJson(
        SupportsPostBindings instance) =>
    <String, dynamic>{};

SystemConfiguration _$SystemConfigurationFromJson(Map<String, dynamic> json) {
  return SystemConfiguration(
    auditLogConfiguration: json['auditLogConfiguration'] == null
        ? null
        : AuditLogConfiguration.fromJson(
            json['auditLogConfiguration'] as Map<String, dynamic>),
    corsConfiguration: json['corsConfiguration'] == null
        ? null
        : CORSConfiguration.fromJson(
            json['corsConfiguration'] as Map<String, dynamic>),
    data: json['data'] as Map<String, dynamic>,
    eventLogConfiguration: json['eventLogConfiguration'] == null
        ? null
        : EventLogConfiguration.fromJson(
            json['eventLogConfiguration'] as Map<String, dynamic>),
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    loginRecordConfiguration: json['loginRecordConfiguration'] == null
        ? null
        : LoginRecordConfiguration.fromJson(
            json['loginRecordConfiguration'] as Map<String, dynamic>),
    reportTimezone: json['reportTimezone'] as String,
    uiConfiguration: json['uiConfiguration'] == null
        ? null
        : UIConfiguration.fromJson(
            json['uiConfiguration'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$SystemConfigurationToJson(SystemConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('auditLogConfiguration', instance.auditLogConfiguration);
  writeNotNull('corsConfiguration', instance.corsConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('eventLogConfiguration', instance.eventLogConfiguration);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('loginRecordConfiguration', instance.loginRecordConfiguration);
  writeNotNull('reportTimezone', instance.reportTimezone);
  writeNotNull('uiConfiguration', instance.uiConfiguration);
  return val;
}

SystemConfigurationRequest _$SystemConfigurationRequestFromJson(
    Map<String, dynamic> json) {
  return SystemConfigurationRequest(
    systemConfiguration: json['systemConfiguration'] == null
        ? null
        : SystemConfiguration.fromJson(
            json['systemConfiguration'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$SystemConfigurationRequestToJson(
    SystemConfigurationRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('systemConfiguration', instance.systemConfiguration);
  return val;
}

SystemConfigurationResponse _$SystemConfigurationResponseFromJson(
    Map<String, dynamic> json) {
  return SystemConfigurationResponse(
    systemConfiguration: json['systemConfiguration'] == null
        ? null
        : SystemConfiguration.fromJson(
            json['systemConfiguration'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$SystemConfigurationResponseToJson(
    SystemConfigurationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('systemConfiguration', instance.systemConfiguration);
  return val;
}

SystemLogsExportRequest _$SystemLogsExportRequestFromJson(
    Map<String, dynamic> json) {
  return SystemLogsExportRequest(
    lastNBytes: json['lastNBytes'] as num,
  )
    ..dateTimeSecondsFormat = json['dateTimeSecondsFormat'] as String
    ..zoneId = json['zoneId'] as String;
}

Map<String, dynamic> _$SystemLogsExportRequestToJson(
    SystemLogsExportRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dateTimeSecondsFormat', instance.dateTimeSecondsFormat);
  writeNotNull('zoneId', instance.zoneId);
  writeNotNull('lastNBytes', instance.lastNBytes);
  return val;
}

Templates _$TemplatesFromJson(Map<String, dynamic> json) {
  return Templates(
    emailComplete: json['emailComplete'] as String,
    emailSend: json['emailSend'] as String,
    emailVerify: json['emailVerify'] as String,
    helpers: json['helpers'] as String,
    oauth2Authorize: json['oauth2Authorize'] as String,
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
    oauth2TwoFactor: json['oauth2TwoFactor'] as String,
    oauth2Wait: json['oauth2Wait'] as String,
    passwordChange: json['passwordChange'] as String,
    passwordComplete: json['passwordComplete'] as String,
    passwordForgot: json['passwordForgot'] as String,
    passwordSent: json['passwordSent'] as String,
    registrationComplete: json['registrationComplete'] as String,
    registrationSend: json['registrationSend'] as String,
    registrationVerify: json['registrationVerify'] as String,
  );
}

Map<String, dynamic> _$TemplatesToJson(Templates instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('emailComplete', instance.emailComplete);
  writeNotNull('emailSend', instance.emailSend);
  writeNotNull('emailVerify', instance.emailVerify);
  writeNotNull('helpers', instance.helpers);
  writeNotNull('oauth2Authorize', instance.oauth2Authorize);
  writeNotNull('oauth2ChildRegistrationNotAllowed',
      instance.oauth2ChildRegistrationNotAllowed);
  writeNotNull('oauth2ChildRegistrationNotAllowedComplete',
      instance.oauth2ChildRegistrationNotAllowedComplete);
  writeNotNull(
      'oauth2CompleteRegistration', instance.oauth2CompleteRegistration);
  writeNotNull('oauth2Device', instance.oauth2Device);
  writeNotNull('oauth2DeviceComplete', instance.oauth2DeviceComplete);
  writeNotNull('oauth2Error', instance.oauth2Error);
  writeNotNull('oauth2Logout', instance.oauth2Logout);
  writeNotNull('oauth2Passwordless', instance.oauth2Passwordless);
  writeNotNull('oauth2Register', instance.oauth2Register);
  writeNotNull('oauth2TwoFactor', instance.oauth2TwoFactor);
  writeNotNull('oauth2Wait', instance.oauth2Wait);
  writeNotNull('passwordChange', instance.passwordChange);
  writeNotNull('passwordComplete', instance.passwordComplete);
  writeNotNull('passwordForgot', instance.passwordForgot);
  writeNotNull('passwordSent', instance.passwordSent);
  writeNotNull('registrationComplete', instance.registrationComplete);
  writeNotNull('registrationSend', instance.registrationSend);
  writeNotNull('registrationVerify', instance.registrationVerify);
  return val;
}

Tenant _$TenantFromJson(Map<String, dynamic> json) {
  return Tenant(
    configured: json['configured'] as bool,
    connectorPolicies: (json['connectorPolicies'] as List)
        ?.map((e) => e == null
            ? null
            : ConnectorPolicy.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    data: json['data'] as Map<String, dynamic>,
    emailConfiguration: json['emailConfiguration'] == null
        ? null
        : EmailConfiguration.fromJson(
            json['emailConfiguration'] as Map<String, dynamic>),
    eventConfiguration: json['eventConfiguration'] == null
        ? null
        : EventConfiguration.fromJson(
            json['eventConfiguration'] as Map<String, dynamic>),
    externalIdentifierConfiguration: json['externalIdentifierConfiguration'] ==
            null
        ? null
        : ExternalIdentifierConfiguration.fromJson(
            json['externalIdentifierConfiguration'] as Map<String, dynamic>),
    failedAuthenticationConfiguration:
        json['failedAuthenticationConfiguration'] == null
            ? null
            : FailedAuthenticationConfiguration.fromJson(
                json['failedAuthenticationConfiguration']
                    as Map<String, dynamic>),
    familyConfiguration: json['familyConfiguration'] == null
        ? null
        : FamilyConfiguration.fromJson(
            json['familyConfiguration'] as Map<String, dynamic>),
    formConfiguration: json['formConfiguration'] == null
        ? null
        : TenantFormConfiguration.fromJson(
            json['formConfiguration'] as Map<String, dynamic>),
    httpSessionMaxInactiveInterval:
        json['httpSessionMaxInactiveInterval'] as num,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    issuer: json['issuer'] as String,
    jwtConfiguration: json['jwtConfiguration'] == null
        ? null
        : JWTConfiguration.fromJson(
            json['jwtConfiguration'] as Map<String, dynamic>),
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    logoutURL: json['logoutURL'] as String,
    maximumPasswordAge: json['maximumPasswordAge'] == null
        ? null
        : MaximumPasswordAge.fromJson(
            json['maximumPasswordAge'] as Map<String, dynamic>),
    minimumPasswordAge: json['minimumPasswordAge'] == null
        ? null
        : MinimumPasswordAge.fromJson(
            json['minimumPasswordAge'] as Map<String, dynamic>),
    name: json['name'] as String,
    passwordEncryptionConfiguration: json['passwordEncryptionConfiguration'] ==
            null
        ? null
        : PasswordEncryptionConfiguration.fromJson(
            json['passwordEncryptionConfiguration'] as Map<String, dynamic>),
    passwordValidationRules: json['passwordValidationRules'] == null
        ? null
        : PasswordValidationRules.fromJson(
            json['passwordValidationRules'] as Map<String, dynamic>),
    state: _$enumDecodeNullable(_$ObjectStateEnumMap, json['state']),
    themeId: json['themeId'] as String,
    userDeletePolicy: json['userDeletePolicy'] == null
        ? null
        : TenantUserDeletePolicy.fromJson(
            json['userDeletePolicy'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$TenantToJson(Tenant instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('configured', instance.configured);
  writeNotNull('connectorPolicies', instance.connectorPolicies);
  writeNotNull('data', instance.data);
  writeNotNull('emailConfiguration', instance.emailConfiguration);
  writeNotNull('eventConfiguration', instance.eventConfiguration);
  writeNotNull('externalIdentifierConfiguration',
      instance.externalIdentifierConfiguration);
  writeNotNull('failedAuthenticationConfiguration',
      instance.failedAuthenticationConfiguration);
  writeNotNull('familyConfiguration', instance.familyConfiguration);
  writeNotNull('formConfiguration', instance.formConfiguration);
  writeNotNull('httpSessionMaxInactiveInterval',
      instance.httpSessionMaxInactiveInterval);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('issuer', instance.issuer);
  writeNotNull('jwtConfiguration', instance.jwtConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('logoutURL', instance.logoutURL);
  writeNotNull('maximumPasswordAge', instance.maximumPasswordAge);
  writeNotNull('minimumPasswordAge', instance.minimumPasswordAge);
  writeNotNull('name', instance.name);
  writeNotNull('passwordEncryptionConfiguration',
      instance.passwordEncryptionConfiguration);
  writeNotNull('passwordValidationRules', instance.passwordValidationRules);
  writeNotNull('state', _$ObjectStateEnumMap[instance.state]);
  writeNotNull('themeId', instance.themeId);
  writeNotNull('userDeletePolicy', instance.userDeletePolicy);
  return val;
}

Tenantable _$TenantableFromJson(Map<String, dynamic> json) {
  return Tenantable();
}

Map<String, dynamic> _$TenantableToJson(Tenantable instance) =>
    <String, dynamic>{};

TenantFormConfiguration _$TenantFormConfigurationFromJson(
    Map<String, dynamic> json) {
  return TenantFormConfiguration(
    adminUserFormId: json['adminUserFormId'] as String,
  );
}

Map<String, dynamic> _$TenantFormConfigurationToJson(
    TenantFormConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('adminUserFormId', instance.adminUserFormId);
  return val;
}

TenantRequest _$TenantRequestFromJson(Map<String, dynamic> json) {
  return TenantRequest(
    sourceTenantId: json['sourceTenantId'] as String,
    tenant: json['tenant'] == null
        ? null
        : Tenant.fromJson(json['tenant'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$TenantRequestToJson(TenantRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('sourceTenantId', instance.sourceTenantId);
  writeNotNull('tenant', instance.tenant);
  return val;
}

TenantResponse _$TenantResponseFromJson(Map<String, dynamic> json) {
  return TenantResponse(
    tenant: json['tenant'] == null
        ? null
        : Tenant.fromJson(json['tenant'] as Map<String, dynamic>),
    tenants: (json['tenants'] as List)
        ?.map((e) =>
            e == null ? null : Tenant.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$TenantResponseToJson(TenantResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('tenant', instance.tenant);
  writeNotNull('tenants', instance.tenants);
  return val;
}

TenantUserDeletePolicy _$TenantUserDeletePolicyFromJson(
    Map<String, dynamic> json) {
  return TenantUserDeletePolicy(
    unverified: json['unverified'] == null
        ? null
        : TimeBasedDeletePolicy.fromJson(
            json['unverified'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$TenantUserDeletePolicyToJson(
    TenantUserDeletePolicy instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('unverified', instance.unverified);
  return val;
}

TestEvent _$TestEventFromJson(Map<String, dynamic> json) {
  return TestEvent(
    message: json['message'] as String,
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$TestEventToJson(TestEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('message', instance.message);
  return val;
}

Theme _$ThemeFromJson(Map<String, dynamic> json) {
  return Theme(
    data: json['data'] as Map<String, dynamic>,
    defaultMessages: json['defaultMessages'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    localizedMessages: (json['localizedMessages'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    name: json['name'] as String,
    stylesheet: json['stylesheet'] as String,
    templates: json['templates'] == null
        ? null
        : Templates.fromJson(json['templates'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ThemeToJson(Theme instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('data', instance.data);
  writeNotNull('defaultMessages', instance.defaultMessages);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('localizedMessages', instance.localizedMessages);
  writeNotNull('name', instance.name);
  writeNotNull('stylesheet', instance.stylesheet);
  writeNotNull('templates', instance.templates);
  return val;
}

ThemeRequest _$ThemeRequestFromJson(Map<String, dynamic> json) {
  return ThemeRequest(
    sourceThemeId: json['sourceThemeId'] as String,
    theme: json['theme'] == null
        ? null
        : Theme.fromJson(json['theme'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ThemeRequestToJson(ThemeRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('sourceThemeId', instance.sourceThemeId);
  writeNotNull('theme', instance.theme);
  return val;
}

ThemeResponse _$ThemeResponseFromJson(Map<String, dynamic> json) {
  return ThemeResponse(
    theme: json['theme'] == null
        ? null
        : Theme.fromJson(json['theme'] as Map<String, dynamic>),
    themes: (json['themes'] as List)
        ?.map(
            (e) => e == null ? null : Theme.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$ThemeResponseToJson(ThemeResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('theme', instance.theme);
  writeNotNull('themes', instance.themes);
  return val;
}

TimeBasedDeletePolicy _$TimeBasedDeletePolicyFromJson(
    Map<String, dynamic> json) {
  return TimeBasedDeletePolicy(
    numberOfDaysToRetain: json['numberOfDaysToRetain'] as num,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$TimeBasedDeletePolicyToJson(
    TimeBasedDeletePolicy instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('numberOfDaysToRetain', instance.numberOfDaysToRetain);
  return val;
}

Totals _$TotalsFromJson(Map<String, dynamic> json) {
  return Totals(
    logins: json['logins'] as num,
    registrations: json['registrations'] as num,
    totalRegistrations: json['totalRegistrations'] as num,
  );
}

Map<String, dynamic> _$TotalsToJson(Totals instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('logins', instance.logins);
  writeNotNull('registrations', instance.registrations);
  writeNotNull('totalRegistrations', instance.totalRegistrations);
  return val;
}

TotalsReportResponse _$TotalsReportResponseFromJson(Map<String, dynamic> json) {
  return TotalsReportResponse(
    applicationTotals: (json['applicationTotals'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k, e == null ? null : Totals.fromJson(e as Map<String, dynamic>)),
    ),
    globalRegistrations: json['globalRegistrations'] as num,
    totalGlobalRegistrations: json['totalGlobalRegistrations'] as num,
  );
}

Map<String, dynamic> _$TotalsReportResponseToJson(
    TotalsReportResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationTotals', instance.applicationTotals);
  writeNotNull('globalRegistrations', instance.globalRegistrations);
  writeNotNull('totalGlobalRegistrations', instance.totalGlobalRegistrations);
  return val;
}

TwilioConfiguration _$TwilioConfigurationFromJson(Map<String, dynamic> json) {
  return TwilioConfiguration(
    accountSID: json['accountSID'] as String,
    authToken: json['authToken'] as String,
    fromPhoneNumber: json['fromPhoneNumber'] as String,
    messagingServiceSid: json['messagingServiceSid'] as String,
    url: json['url'] as String,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$TwilioConfigurationToJson(TwilioConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('accountSID', instance.accountSID);
  writeNotNull('authToken', instance.authToken);
  writeNotNull('fromPhoneNumber', instance.fromPhoneNumber);
  writeNotNull('messagingServiceSid', instance.messagingServiceSid);
  writeNotNull('url', instance.url);
  return val;
}

TwitterApplicationConfiguration _$TwitterApplicationConfigurationFromJson(
    Map<String, dynamic> json) {
  return TwitterApplicationConfiguration(
    buttonText: json['buttonText'] as String,
    consumerKey: json['consumerKey'] as String,
    consumerSecret: json['consumerSecret'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..createRegistration = json['createRegistration'] as bool
    ..data = json['data'] as Map<String, dynamic>;
}

Map<String, dynamic> _$TwitterApplicationConfigurationToJson(
    TwitterApplicationConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('createRegistration', instance.createRegistration);
  writeNotNull('data', instance.data);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('consumerKey', instance.consumerKey);
  writeNotNull('consumerSecret', instance.consumerSecret);
  return val;
}

TwitterIdentityProvider _$TwitterIdentityProviderFromJson(
    Map<String, dynamic> json) {
  return TwitterIdentityProvider(
    buttonText: json['buttonText'] as String,
    consumerKey: json['consumerKey'] as String,
    consumerSecret: json['consumerSecret'] as String,
  )
    ..enabled = json['enabled'] as bool
    ..applicationConfiguration =
        (json['applicationConfiguration'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(
          k,
          e == null
              ? null
              : TwitterApplicationConfiguration.fromJson(
                  e as Map<String, dynamic>)),
    )
    ..data = json['data'] as Map<String, dynamic>
    ..debug = json['debug'] as bool
    ..id = json['id'] as String
    ..insertInstant = json['insertInstant'] as num
    ..lambdaConfiguration = json['lambdaConfiguration']
    ..lastUpdateInstant = json['lastUpdateInstant'] as num
    ..name = json['name'] as String
    ..type = _$enumDecodeNullable(_$IdentityProviderTypeEnumMap, json['type']);
}

Map<String, dynamic> _$TwitterIdentityProviderToJson(
    TwitterIdentityProvider instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationConfiguration', instance.applicationConfiguration);
  writeNotNull('data', instance.data);
  writeNotNull('debug', instance.debug);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lambdaConfiguration', instance.lambdaConfiguration);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('name', instance.name);
  writeNotNull('type', _$IdentityProviderTypeEnumMap[instance.type]);
  writeNotNull('buttonText', instance.buttonText);
  writeNotNull('consumerKey', instance.consumerKey);
  writeNotNull('consumerSecret', instance.consumerSecret);
  return val;
}

TwoFactorLoginRequest _$TwoFactorLoginRequestFromJson(
    Map<String, dynamic> json) {
  return TwoFactorLoginRequest(
    code: json['code'] as String,
    trustComputer: json['trustComputer'] as bool,
    twoFactorId: json['twoFactorId'] as String,
  )
    ..applicationId = json['applicationId'] as String
    ..ipAddress = json['ipAddress'] as String
    ..metaData = json['metaData'] == null
        ? null
        : MetaData.fromJson(json['metaData'] as Map<String, dynamic>)
    ..noJWT = json['noJWT'] as bool;
}

Map<String, dynamic> _$TwoFactorLoginRequestToJson(
    TwoFactorLoginRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('ipAddress', instance.ipAddress);
  writeNotNull('metaData', instance.metaData);
  writeNotNull('noJWT', instance.noJWT);
  writeNotNull('code', instance.code);
  writeNotNull('trustComputer', instance.trustComputer);
  writeNotNull('twoFactorId', instance.twoFactorId);
  return val;
}

TwoFactorRequest _$TwoFactorRequestFromJson(Map<String, dynamic> json) {
  return TwoFactorRequest(
    code: json['code'] as String,
    delivery:
        _$enumDecodeNullable(_$TwoFactorDeliveryEnumMap, json['delivery']),
    secret: json['secret'] as String,
    secretBase32Encoded: json['secretBase32Encoded'] as String,
  );
}

Map<String, dynamic> _$TwoFactorRequestToJson(TwoFactorRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('code', instance.code);
  writeNotNull('delivery', _$TwoFactorDeliveryEnumMap[instance.delivery]);
  writeNotNull('secret', instance.secret);
  writeNotNull('secretBase32Encoded', instance.secretBase32Encoded);
  return val;
}

TwoFactorSendRequest _$TwoFactorSendRequestFromJson(Map<String, dynamic> json) {
  return TwoFactorSendRequest(
    mobilePhone: json['mobilePhone'] as String,
    secret: json['secret'] as String,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$TwoFactorSendRequestToJson(
    TwoFactorSendRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('mobilePhone', instance.mobilePhone);
  writeNotNull('secret', instance.secret);
  writeNotNull('userId', instance.userId);
  return val;
}

UIConfiguration _$UIConfigurationFromJson(Map<String, dynamic> json) {
  return UIConfiguration(
    headerColor: json['headerColor'] as String,
    logoURL: json['logoURL'] as String,
    menuFontColor: json['menuFontColor'] as String,
  );
}

Map<String, dynamic> _$UIConfigurationToJson(UIConfiguration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('headerColor', instance.headerColor);
  writeNotNull('logoURL', instance.logoURL);
  writeNotNull('menuFontColor', instance.menuFontColor);
  return val;
}

User _$UserFromJson(Map<String, dynamic> json) {
  return User(
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
    memberships: (json['memberships'] as List)
        ?.map((e) =>
            e == null ? null : GroupMember.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    middleName: json['middleName'] as String,
    mobilePhone: json['mobilePhone'] as String,
    parentEmail: json['parentEmail'] as String,
    preferredLanguages:
        (json['preferredLanguages'] as List)?.map((e) => e as String)?.toList(),
    registrations: (json['registrations'] as List)
        ?.map((e) => e == null
            ? null
            : UserRegistration.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    tenantId: json['tenantId'] as String,
    timezone: json['timezone'] as String,
  )
    ..breachedPasswordLastCheckedInstant =
        json['breachedPasswordLastCheckedInstant'] as num
    ..breachedPasswordStatus = _$enumDecodeNullable(
        _$BreachedPasswordStatusEnumMap, json['breachedPasswordStatus'])
    ..connectorId = json['connectorId'] as String
    ..encryptionScheme = json['encryptionScheme'] as String
    ..factor = json['factor'] as num
    ..id = json['id'] as String
    ..lastLoginInstant = json['lastLoginInstant'] as num
    ..password = json['password'] as String
    ..passwordChangeReason = _$enumDecodeNullable(
        _$ChangePasswordReasonEnumMap, json['passwordChangeReason'])
    ..passwordChangeRequired = json['passwordChangeRequired'] as bool
    ..passwordLastUpdateInstant = json['passwordLastUpdateInstant'] as num
    ..salt = json['salt'] as String
    ..twoFactorDelivery = _$enumDecodeNullable(
        _$TwoFactorDeliveryEnumMap, json['twoFactorDelivery'])
    ..twoFactorEnabled = json['twoFactorEnabled'] as bool
    ..twoFactorSecret = json['twoFactorSecret'] as String
    ..username = json['username'] as String
    ..usernameStatus =
        _$enumDecodeNullable(_$ContentStatusEnumMap, json['usernameStatus'])
    ..verified = json['verified'] as bool;
}

Map<String, dynamic> _$UserToJson(User instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('breachedPasswordLastCheckedInstant',
      instance.breachedPasswordLastCheckedInstant);
  writeNotNull('breachedPasswordStatus',
      _$BreachedPasswordStatusEnumMap[instance.breachedPasswordStatus]);
  writeNotNull('connectorId', instance.connectorId);
  writeNotNull('encryptionScheme', instance.encryptionScheme);
  writeNotNull('factor', instance.factor);
  writeNotNull('id', instance.id);
  writeNotNull('lastLoginInstant', instance.lastLoginInstant);
  writeNotNull('password', instance.password);
  writeNotNull('passwordChangeReason',
      _$ChangePasswordReasonEnumMap[instance.passwordChangeReason]);
  writeNotNull('passwordChangeRequired', instance.passwordChangeRequired);
  writeNotNull('passwordLastUpdateInstant', instance.passwordLastUpdateInstant);
  writeNotNull('salt', instance.salt);
  writeNotNull('twoFactorDelivery',
      _$TwoFactorDeliveryEnumMap[instance.twoFactorDelivery]);
  writeNotNull('twoFactorEnabled', instance.twoFactorEnabled);
  writeNotNull('twoFactorSecret', instance.twoFactorSecret);
  writeNotNull('username', instance.username);
  writeNotNull(
      'usernameStatus', _$ContentStatusEnumMap[instance.usernameStatus]);
  writeNotNull('verified', instance.verified);
  writeNotNull('active', instance.active);
  writeNotNull('birthDate', instance.birthDate);
  writeNotNull('cleanSpeakId', instance.cleanSpeakId);
  writeNotNull('data', instance.data);
  writeNotNull('email', instance.email);
  writeNotNull('expiry', instance.expiry);
  writeNotNull('firstName', instance.firstName);
  writeNotNull('fullName', instance.fullName);
  writeNotNull('imageUrl', instance.imageUrl);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastName', instance.lastName);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('memberships', instance.memberships);
  writeNotNull('middleName', instance.middleName);
  writeNotNull('mobilePhone', instance.mobilePhone);
  writeNotNull('parentEmail', instance.parentEmail);
  writeNotNull('preferredLanguages', instance.preferredLanguages);
  writeNotNull('registrations', instance.registrations);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('timezone', instance.timezone);
  return val;
}

UserAction _$UserActionFromJson(Map<String, dynamic> json) {
  return UserAction(
    active: json['active'] as bool,
    cancelEmailTemplateId: json['cancelEmailTemplateId'] as String,
    endEmailTemplateId: json['endEmailTemplateId'] as String,
    id: json['id'] as String,
    includeEmailInEventJSON: json['includeEmailInEventJSON'] as bool,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    localizedNames: (json['localizedNames'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    modifyEmailTemplateId: json['modifyEmailTemplateId'] as String,
    name: json['name'] as String,
    options: (json['options'] as List)
        ?.map((e) => e == null
            ? null
            : UserActionOption.fromJson(e as Map<String, dynamic>))
        ?.toList(),
    preventLogin: json['preventLogin'] as bool,
    sendEndEvent: json['sendEndEvent'] as bool,
    startEmailTemplateId: json['startEmailTemplateId'] as String,
    temporal: json['temporal'] as bool,
    transactionType:
        _$enumDecodeNullable(_$TransactionTypeEnumMap, json['transactionType']),
    userEmailingEnabled: json['userEmailingEnabled'] as bool,
    userNotificationsEnabled: json['userNotificationsEnabled'] as bool,
  );
}

Map<String, dynamic> _$UserActionToJson(UserAction instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('active', instance.active);
  writeNotNull('cancelEmailTemplateId', instance.cancelEmailTemplateId);
  writeNotNull('endEmailTemplateId', instance.endEmailTemplateId);
  writeNotNull('id', instance.id);
  writeNotNull('includeEmailInEventJSON', instance.includeEmailInEventJSON);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('localizedNames', instance.localizedNames);
  writeNotNull('modifyEmailTemplateId', instance.modifyEmailTemplateId);
  writeNotNull('name', instance.name);
  writeNotNull('options', instance.options);
  writeNotNull('preventLogin', instance.preventLogin);
  writeNotNull('sendEndEvent', instance.sendEndEvent);
  writeNotNull('startEmailTemplateId', instance.startEmailTemplateId);
  writeNotNull('temporal', instance.temporal);
  writeNotNull(
      'transactionType', _$TransactionTypeEnumMap[instance.transactionType]);
  writeNotNull('userEmailingEnabled', instance.userEmailingEnabled);
  writeNotNull('userNotificationsEnabled', instance.userNotificationsEnabled);
  return val;
}

UserActionEvent _$UserActionEventFromJson(Map<String, dynamic> json) {
  return UserActionEvent(
    action: json['action'] as String,
    actioneeUserId: json['actioneeUserId'] as String,
    actionerUserId: json['actionerUserId'] as String,
    actionId: json['actionId'] as String,
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    comment: json['comment'] as String,
    email: json['email'] == null
        ? null
        : Email.fromJson(json['email'] as Map<String, dynamic>),
    emailedUser: json['emailedUser'] as bool,
    expiry: json['expiry'] as num,
    localizedAction: json['localizedAction'] as String,
    localizedDuration: json['localizedDuration'] as String,
    localizedOption: json['localizedOption'] as String,
    localizedReason: json['localizedReason'] as String,
    notifyUser: json['notifyUser'] as bool,
    option: json['option'] as String,
    phase: _$enumDecodeNullable(_$UserActionPhaseEnumMap, json['phase']),
    reason: json['reason'] as String,
    reasonCode: json['reasonCode'] as String,
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserActionEventToJson(UserActionEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('action', instance.action);
  writeNotNull('actioneeUserId', instance.actioneeUserId);
  writeNotNull('actionerUserId', instance.actionerUserId);
  writeNotNull('actionId', instance.actionId);
  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('comment', instance.comment);
  writeNotNull('email', instance.email);
  writeNotNull('emailedUser', instance.emailedUser);
  writeNotNull('expiry', instance.expiry);
  writeNotNull('localizedAction', instance.localizedAction);
  writeNotNull('localizedDuration', instance.localizedDuration);
  writeNotNull('localizedOption', instance.localizedOption);
  writeNotNull('localizedReason', instance.localizedReason);
  writeNotNull('notifyUser', instance.notifyUser);
  writeNotNull('option', instance.option);
  writeNotNull('phase', _$UserActionPhaseEnumMap[instance.phase]);
  writeNotNull('reason', instance.reason);
  writeNotNull('reasonCode', instance.reasonCode);
  return val;
}

const _$UserActionPhaseEnumMap = {
  UserActionPhase.start: 'start',
  UserActionPhase.modify: 'modify',
  UserActionPhase.cancel: 'cancel',
  UserActionPhase.end: 'end',
};

UserActionLog _$UserActionLogFromJson(Map<String, dynamic> json) {
  return UserActionLog(
    actioneeUserId: json['actioneeUserId'] as String,
    actionerUserId: json['actionerUserId'] as String,
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    comment: json['comment'] as String,
    emailUserOnEnd: json['emailUserOnEnd'] as bool,
    endEventSent: json['endEventSent'] as bool,
    expiry: json['expiry'] as num,
    history: json['history'] == null
        ? null
        : LogHistory.fromJson(json['history'] as Map<String, dynamic>),
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
}

Map<String, dynamic> _$UserActionLogToJson(UserActionLog instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('actioneeUserId', instance.actioneeUserId);
  writeNotNull('actionerUserId', instance.actionerUserId);
  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('comment', instance.comment);
  writeNotNull('emailUserOnEnd', instance.emailUserOnEnd);
  writeNotNull('endEventSent', instance.endEventSent);
  writeNotNull('expiry', instance.expiry);
  writeNotNull('history', instance.history);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('localizedName', instance.localizedName);
  writeNotNull('localizedOption', instance.localizedOption);
  writeNotNull('localizedReason', instance.localizedReason);
  writeNotNull('name', instance.name);
  writeNotNull('notifyUserOnEnd', instance.notifyUserOnEnd);
  writeNotNull('option', instance.option);
  writeNotNull('reason', instance.reason);
  writeNotNull('reasonCode', instance.reasonCode);
  writeNotNull('userActionId', instance.userActionId);
  return val;
}

UserActionOption _$UserActionOptionFromJson(Map<String, dynamic> json) {
  return UserActionOption(
    localizedNames: (json['localizedNames'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    name: json['name'] as String,
  );
}

Map<String, dynamic> _$UserActionOptionToJson(UserActionOption instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('localizedNames', instance.localizedNames);
  writeNotNull('name', instance.name);
  return val;
}

UserActionReason _$UserActionReasonFromJson(Map<String, dynamic> json) {
  return UserActionReason(
    code: json['code'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    localizedTexts: (json['localizedTexts'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    text: json['text'] as String,
  );
}

Map<String, dynamic> _$UserActionReasonToJson(UserActionReason instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('code', instance.code);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('localizedTexts', instance.localizedTexts);
  writeNotNull('text', instance.text);
  return val;
}

UserActionReasonRequest _$UserActionReasonRequestFromJson(
    Map<String, dynamic> json) {
  return UserActionReasonRequest(
    userActionReason: json['userActionReason'] == null
        ? null
        : UserActionReason.fromJson(
            json['userActionReason'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserActionReasonRequestToJson(
    UserActionReasonRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userActionReason', instance.userActionReason);
  return val;
}

UserActionReasonResponse _$UserActionReasonResponseFromJson(
    Map<String, dynamic> json) {
  return UserActionReasonResponse(
    userActionReason: json['userActionReason'] == null
        ? null
        : UserActionReason.fromJson(
            json['userActionReason'] as Map<String, dynamic>),
    userActionReasons: (json['userActionReasons'] as List)
        ?.map((e) => e == null
            ? null
            : UserActionReason.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$UserActionReasonResponseToJson(
    UserActionReasonResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userActionReason', instance.userActionReason);
  writeNotNull('userActionReasons', instance.userActionReasons);
  return val;
}

UserActionRequest _$UserActionRequestFromJson(Map<String, dynamic> json) {
  return UserActionRequest(
    userAction: json['userAction'] == null
        ? null
        : UserAction.fromJson(json['userAction'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserActionRequestToJson(UserActionRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userAction', instance.userAction);
  return val;
}

UserActionResponse _$UserActionResponseFromJson(Map<String, dynamic> json) {
  return UserActionResponse(
    userAction: json['userAction'] == null
        ? null
        : UserAction.fromJson(json['userAction'] as Map<String, dynamic>),
    userActions: (json['userActions'] as List)
        ?.map((e) =>
            e == null ? null : UserAction.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$UserActionResponseToJson(UserActionResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userAction', instance.userAction);
  writeNotNull('userActions', instance.userActions);
  return val;
}

UserBulkCreateEvent _$UserBulkCreateEventFromJson(Map<String, dynamic> json) {
  return UserBulkCreateEvent(
    users: (json['users'] as List)
        ?.map(
            (e) => e == null ? null : User.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserBulkCreateEventToJson(UserBulkCreateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('users', instance.users);
  return val;
}

UserComment _$UserCommentFromJson(Map<String, dynamic> json) {
  return UserComment(
    comment: json['comment'] as String,
    commenterId: json['commenterId'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    userId: json['userId'] as String,
  );
}

Map<String, dynamic> _$UserCommentToJson(UserComment instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('comment', instance.comment);
  writeNotNull('commenterId', instance.commenterId);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('userId', instance.userId);
  return val;
}

UserCommentRequest _$UserCommentRequestFromJson(Map<String, dynamic> json) {
  return UserCommentRequest(
    userComment: json['userComment'] == null
        ? null
        : UserComment.fromJson(json['userComment'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserCommentRequestToJson(UserCommentRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userComment', instance.userComment);
  return val;
}

UserCommentResponse _$UserCommentResponseFromJson(Map<String, dynamic> json) {
  return UserCommentResponse(
    userComment: json['userComment'] == null
        ? null
        : UserComment.fromJson(json['userComment'] as Map<String, dynamic>),
    userComments: (json['userComments'] as List)
        ?.map((e) =>
            e == null ? null : UserComment.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$UserCommentResponseToJson(UserCommentResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userComment', instance.userComment);
  writeNotNull('userComments', instance.userComments);
  return val;
}

UserConsent _$UserConsentFromJson(Map<String, dynamic> json) {
  return UserConsent(
    consent: json['consent'] == null
        ? null
        : Consent.fromJson(json['consent'] as Map<String, dynamic>),
    consentId: json['consentId'] as String,
    data: json['data'] as Map<String, dynamic>,
    giverUserId: json['giverUserId'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    status: _$enumDecodeNullable(_$ConsentStatusEnumMap, json['status']),
    userId: json['userId'] as String,
    values: (json['values'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$UserConsentToJson(UserConsent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('consent', instance.consent);
  writeNotNull('consentId', instance.consentId);
  writeNotNull('data', instance.data);
  writeNotNull('giverUserId', instance.giverUserId);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('status', _$ConsentStatusEnumMap[instance.status]);
  writeNotNull('userId', instance.userId);
  writeNotNull('values', instance.values);
  return val;
}

const _$ConsentStatusEnumMap = {
  ConsentStatus.Active: 'Active',
  ConsentStatus.Revoked: 'Revoked',
};

UserConsentRequest _$UserConsentRequestFromJson(Map<String, dynamic> json) {
  return UserConsentRequest(
    userConsent: json['userConsent'] == null
        ? null
        : UserConsent.fromJson(json['userConsent'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserConsentRequestToJson(UserConsentRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userConsent', instance.userConsent);
  return val;
}

UserConsentResponse _$UserConsentResponseFromJson(Map<String, dynamic> json) {
  return UserConsentResponse(
    userConsent: json['userConsent'] == null
        ? null
        : UserConsent.fromJson(json['userConsent'] as Map<String, dynamic>),
    userConsents: (json['userConsents'] as List)
        ?.map((e) =>
            e == null ? null : UserConsent.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$UserConsentResponseToJson(UserConsentResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('userConsent', instance.userConsent);
  writeNotNull('userConsents', instance.userConsents);
  return val;
}

UserCreateEvent _$UserCreateEventFromJson(Map<String, dynamic> json) {
  return UserCreateEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserCreateEventToJson(UserCreateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserDeactivateEvent _$UserDeactivateEventFromJson(Map<String, dynamic> json) {
  return UserDeactivateEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserDeactivateEventToJson(UserDeactivateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserDeleteEvent _$UserDeleteEventFromJson(Map<String, dynamic> json) {
  return UserDeleteEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserDeleteEventToJson(UserDeleteEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserDeleteRequest _$UserDeleteRequestFromJson(Map<String, dynamic> json) {
  return UserDeleteRequest(
    dryRun: json['dryRun'] as bool,
    hardDelete: json['hardDelete'] as bool,
    query: json['query'] as String,
    queryString: json['queryString'] as String,
    userIds: (json['userIds'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$UserDeleteRequestToJson(UserDeleteRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dryRun', instance.dryRun);
  writeNotNull('hardDelete', instance.hardDelete);
  writeNotNull('query', instance.query);
  writeNotNull('queryString', instance.queryString);
  writeNotNull('userIds', instance.userIds);
  return val;
}

UserDeleteResponse _$UserDeleteResponseFromJson(Map<String, dynamic> json) {
  return UserDeleteResponse(
    dryRun: json['dryRun'] as bool,
    hardDelete: json['hardDelete'] as bool,
    total: json['total'] as num,
    userIds: (json['userIds'] as List)?.map((e) => e as String)?.toList(),
  );
}

Map<String, dynamic> _$UserDeleteResponseToJson(UserDeleteResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('dryRun', instance.dryRun);
  writeNotNull('hardDelete', instance.hardDelete);
  writeNotNull('total', instance.total);
  writeNotNull('userIds', instance.userIds);
  return val;
}

UserEmailVerifiedEvent _$UserEmailVerifiedEventFromJson(
    Map<String, dynamic> json) {
  return UserEmailVerifiedEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserEmailVerifiedEventToJson(
    UserEmailVerifiedEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserLoginFailedEvent _$UserLoginFailedEventFromJson(Map<String, dynamic> json) {
  return UserLoginFailedEvent(
    applicationId: json['applicationId'] as String,
    authenticationType: json['authenticationType'] as String,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserLoginFailedEventToJson(
    UserLoginFailedEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('authenticationType', instance.authenticationType);
  writeNotNull('user', instance.user);
  return val;
}

UserLoginSuccessEvent _$UserLoginSuccessEventFromJson(
    Map<String, dynamic> json) {
  return UserLoginSuccessEvent(
    applicationId: json['applicationId'] as String,
    authenticationType: json['authenticationType'] as String,
    connectorId: json['connectorId'] as String,
    identityProviderId: json['identityProviderId'] as String,
    identityProviderName: json['identityProviderName'] as String,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserLoginSuccessEventToJson(
    UserLoginSuccessEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('authenticationType', instance.authenticationType);
  writeNotNull('connectorId', instance.connectorId);
  writeNotNull('identityProviderId', instance.identityProviderId);
  writeNotNull('identityProviderName', instance.identityProviderName);
  writeNotNull('user', instance.user);
  return val;
}

UsernameModeration _$UsernameModerationFromJson(Map<String, dynamic> json) {
  return UsernameModeration(
    applicationId: json['applicationId'] as String,
  )..enabled = json['enabled'] as bool;
}

Map<String, dynamic> _$UsernameModerationToJson(UsernameModeration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('enabled', instance.enabled);
  writeNotNull('applicationId', instance.applicationId);
  return val;
}

UserPasswordBreachEvent _$UserPasswordBreachEventFromJson(
    Map<String, dynamic> json) {
  return UserPasswordBreachEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserPasswordBreachEventToJson(
    UserPasswordBreachEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserReactivateEvent _$UserReactivateEventFromJson(Map<String, dynamic> json) {
  return UserReactivateEvent(
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserReactivateEventToJson(UserReactivateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('user', instance.user);
  return val;
}

UserRegistration _$UserRegistrationFromJson(Map<String, dynamic> json) {
  return UserRegistration(
    applicationId: json['applicationId'] as String,
    authenticationToken: json['authenticationToken'] as String,
    cleanSpeakId: json['cleanSpeakId'] as String,
    data: json['data'] as Map<String, dynamic>,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastLoginInstant: json['lastLoginInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    preferredLanguages:
        (json['preferredLanguages'] as List)?.map((e) => e as String)?.toList(),
    roles: (json['roles'] as List)?.map((e) => e as String)?.toSet(),
    timezone: json['timezone'] as String,
    tokens: (json['tokens'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    username: json['username'] as String,
    usernameStatus:
        _$enumDecodeNullable(_$ContentStatusEnumMap, json['usernameStatus']),
    verified: json['verified'] as bool,
  );
}

Map<String, dynamic> _$UserRegistrationToJson(UserRegistration instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('authenticationToken', instance.authenticationToken);
  writeNotNull('cleanSpeakId', instance.cleanSpeakId);
  writeNotNull('data', instance.data);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastLoginInstant', instance.lastLoginInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('preferredLanguages', instance.preferredLanguages);
  writeNotNull('roles', instance.roles?.toList());
  writeNotNull('timezone', instance.timezone);
  writeNotNull('tokens', instance.tokens);
  writeNotNull('username', instance.username);
  writeNotNull(
      'usernameStatus', _$ContentStatusEnumMap[instance.usernameStatus]);
  writeNotNull('verified', instance.verified);
  return val;
}

UserRegistrationCreateEvent _$UserRegistrationCreateEventFromJson(
    Map<String, dynamic> json) {
  return UserRegistrationCreateEvent(
    applicationId: json['applicationId'] as String,
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserRegistrationCreateEventToJson(
    UserRegistrationCreateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('registration', instance.registration);
  writeNotNull('user', instance.user);
  return val;
}

UserRegistrationDeleteEvent _$UserRegistrationDeleteEventFromJson(
    Map<String, dynamic> json) {
  return UserRegistrationDeleteEvent(
    applicationId: json['applicationId'] as String,
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserRegistrationDeleteEventToJson(
    UserRegistrationDeleteEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('registration', instance.registration);
  writeNotNull('user', instance.user);
  return val;
}

UserRegistrationUpdateEvent _$UserRegistrationUpdateEventFromJson(
    Map<String, dynamic> json) {
  return UserRegistrationUpdateEvent(
    applicationId: json['applicationId'] as String,
    original: json['original'] == null
        ? null
        : UserRegistration.fromJson(json['original'] as Map<String, dynamic>),
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserRegistrationUpdateEventToJson(
    UserRegistrationUpdateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('original', instance.original);
  writeNotNull('registration', instance.registration);
  writeNotNull('user', instance.user);
  return val;
}

UserRegistrationVerifiedEvent _$UserRegistrationVerifiedEventFromJson(
    Map<String, dynamic> json) {
  return UserRegistrationVerifiedEvent(
    applicationId: json['applicationId'] as String,
    registration: json['registration'] == null
        ? null
        : UserRegistration.fromJson(
            json['registration'] as Map<String, dynamic>),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserRegistrationVerifiedEventToJson(
    UserRegistrationVerifiedEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('applicationId', instance.applicationId);
  writeNotNull('registration', instance.registration);
  writeNotNull('user', instance.user);
  return val;
}

UserRequest _$UserRequestFromJson(Map<String, dynamic> json) {
  return UserRequest(
    sendSetPasswordEmail: json['sendSetPasswordEmail'] as bool,
    skipVerification: json['skipVerification'] as bool,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserRequestToJson(UserRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('sendSetPasswordEmail', instance.sendSetPasswordEmail);
  writeNotNull('skipVerification', instance.skipVerification);
  writeNotNull('user', instance.user);
  return val;
}

UserResponse _$UserResponseFromJson(Map<String, dynamic> json) {
  return UserResponse(
    token: json['token'] as String,
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$UserResponseToJson(UserResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('token', instance.token);
  writeNotNull('user', instance.user);
  return val;
}

UserSearchCriteria _$UserSearchCriteriaFromJson(Map<String, dynamic> json) {
  return UserSearchCriteria(
    ids: (json['ids'] as List)?.map((e) => e as String)?.toList(),
    query: json['query'] as String,
    queryString: json['queryString'] as String,
    sortFields: (json['sortFields'] as List)
        ?.map((e) =>
            e == null ? null : SortField.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  )
    ..numberOfResults = json['numberOfResults'] as num
    ..orderBy = json['orderBy'] as String
    ..startRow = json['startRow'] as num;
}

Map<String, dynamic> _$UserSearchCriteriaToJson(UserSearchCriteria instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('numberOfResults', instance.numberOfResults);
  writeNotNull('orderBy', instance.orderBy);
  writeNotNull('startRow', instance.startRow);
  writeNotNull('ids', instance.ids);
  writeNotNull('query', instance.query);
  writeNotNull('queryString', instance.queryString);
  writeNotNull('sortFields', instance.sortFields);
  return val;
}

UserUpdateEvent _$UserUpdateEventFromJson(Map<String, dynamic> json) {
  return UserUpdateEvent(
    original: json['original'] == null
        ? null
        : User.fromJson(json['original'] as Map<String, dynamic>),
    user: json['user'] == null
        ? null
        : User.fromJson(json['user'] as Map<String, dynamic>),
  )
    ..createInstant = json['createInstant'] as num
    ..id = json['id'] as String
    ..tenantId = json['tenantId'] as String;
}

Map<String, dynamic> _$UserUpdateEventToJson(UserUpdateEvent instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('createInstant', instance.createInstant);
  writeNotNull('id', instance.id);
  writeNotNull('tenantId', instance.tenantId);
  writeNotNull('original', instance.original);
  writeNotNull('user', instance.user);
  return val;
}

ValidateResponse _$ValidateResponseFromJson(Map<String, dynamic> json) {
  return ValidateResponse(
    jwt: json['jwt'] == null
        ? null
        : JWT.fromJson(json['jwt'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$ValidateResponseToJson(ValidateResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('jwt', instance.jwt);
  return val;
}

VerifyEmailResponse _$VerifyEmailResponseFromJson(Map<String, dynamic> json) {
  return VerifyEmailResponse(
    verificationId: json['verificationId'] as String,
  );
}

Map<String, dynamic> _$VerifyEmailResponseToJson(VerifyEmailResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('verificationId', instance.verificationId);
  return val;
}

VerifyRegistrationResponse _$VerifyRegistrationResponseFromJson(
    Map<String, dynamic> json) {
  return VerifyRegistrationResponse(
    verificationId: json['verificationId'] as String,
  );
}

Map<String, dynamic> _$VerifyRegistrationResponseToJson(
    VerifyRegistrationResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('verificationId', instance.verificationId);
  return val;
}

Webhook _$WebhookFromJson(Map<String, dynamic> json) {
  return Webhook(
    applicationIds:
        (json['applicationIds'] as List)?.map((e) => e as String)?.toList(),
    connectTimeout: json['connectTimeout'] as num,
    data: json['data'] as Map<String, dynamic>,
    description: json['description'] as String,
    eventsEnabled: (json['eventsEnabled'] as Map<String, dynamic>)?.map(
      (k, e) =>
          MapEntry(_$enumDecodeNullable(_$EventTypeEnumMap, k), e as bool),
    ),
    global: json['global'] as bool,
    headers: (json['headers'] as Map<String, dynamic>)?.map(
      (k, e) => MapEntry(k, e as String),
    ),
    httpAuthenticationPassword: json['httpAuthenticationPassword'] as String,
    httpAuthenticationUsername: json['httpAuthenticationUsername'] as String,
    id: json['id'] as String,
    insertInstant: json['insertInstant'] as num,
    lastUpdateInstant: json['lastUpdateInstant'] as num,
    readTimeout: json['readTimeout'] as num,
    sslCertificate: json['sslCertificate'] as String,
    url: json['url'] as String,
  );
}

Map<String, dynamic> _$WebhookToJson(Webhook instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('applicationIds', instance.applicationIds);
  writeNotNull('connectTimeout', instance.connectTimeout);
  writeNotNull('data', instance.data);
  writeNotNull('description', instance.description);
  writeNotNull(
      'eventsEnabled',
      instance.eventsEnabled
          ?.map((k, e) => MapEntry(_$EventTypeEnumMap[k], e)));
  writeNotNull('global', instance.global);
  writeNotNull('headers', instance.headers);
  writeNotNull(
      'httpAuthenticationPassword', instance.httpAuthenticationPassword);
  writeNotNull(
      'httpAuthenticationUsername', instance.httpAuthenticationUsername);
  writeNotNull('id', instance.id);
  writeNotNull('insertInstant', instance.insertInstant);
  writeNotNull('lastUpdateInstant', instance.lastUpdateInstant);
  writeNotNull('readTimeout', instance.readTimeout);
  writeNotNull('sslCertificate', instance.sslCertificate);
  writeNotNull('url', instance.url);
  return val;
}

WebhookRequest _$WebhookRequestFromJson(Map<String, dynamic> json) {
  return WebhookRequest(
    webhook: json['webhook'] == null
        ? null
        : Webhook.fromJson(json['webhook'] as Map<String, dynamic>),
  );
}

Map<String, dynamic> _$WebhookRequestToJson(WebhookRequest instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('webhook', instance.webhook);
  return val;
}

WebhookResponse _$WebhookResponseFromJson(Map<String, dynamic> json) {
  return WebhookResponse(
    webhook: json['webhook'] == null
        ? null
        : Webhook.fromJson(json['webhook'] as Map<String, dynamic>),
    webhooks: (json['webhooks'] as List)
        ?.map((e) =>
            e == null ? null : Webhook.fromJson(e as Map<String, dynamic>))
        ?.toList(),
  );
}

Map<String, dynamic> _$WebhookResponseToJson(WebhookResponse instance) {
  final val = <String, dynamic>{};

  void writeNotNull(String key, dynamic value) {
    if (value != null) {
      val[key] = value;
    }
  }

  writeNotNull('webhook', instance.webhook);
  writeNotNull('webhooks', instance.webhooks);
  return val;
}

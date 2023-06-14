/*
* Copyright (c) 2020-2023, FusionAuth, All Rights Reserved
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

import 'dart:io';
import 'FusionAuthRESTClient.dart';
import 'FusionAuthDomain.dart';

typedef RESTClientFactory = FusionAuthRESTClient
    Function<ReturnType, ErrorReturnType>(String host, HttpClient httpClient);

FusionAuthRESTClient<ReturnType, ErrorReturnType>
    DefaultFusionAuthRESTClientFactory<ReturnType, ErrorReturnType>(
        host, httpClient) {
  return FusionAuthRESTClient<ReturnType, ErrorReturnType>(host, httpClient);
}

class FusionAuthClient {
  HttpClientCredentials credentials;
  String apiKey;
  String host;
  String tenantId;
  RESTClientFactory fusionAuthRESTClientFactory =
      DefaultFusionAuthRESTClientFactory;

  FusionAuthClient(this.apiKey, this.host, this.tenantId);

  /// Sets the tenant id, that will be included in the X-FusionAuth-TenantId header.
  ///
  /// @param {string | null} tenantId The value of the X-FusionAuth-TenantId header.
  /// @returns {FusionAuthClient}
  FusionAuthClient setTenantId(String tenantId) {
    this.tenantId = tenantId;
    return this;
  }

  /// Sets whether and how cookies will be sent with each request.
  ///
  /// @param value The value that indicates whether and how cookies will be sent.
  /// @returns {FusionAuthClient}
  FusionAuthClient setRequestCredentials(HttpClientCredentials value) {
    credentials = value;
    return this;
  }

  /// Sets the builder for the rest client so that it can be overridden/subclassed/or altered before client use.
  FusionAuthClient setRESTClientFactory(RESTClientFactory restClientFactory) {
    fusionAuthRESTClientFactory = restClientFactory;
    return this;
  }

  /// Takes an action on a user. The user being actioned is called the "actionee" and the user taking the action is called the
  /// "actioner". Both user ids are required in the request object.
  ///
  /// @param {ActionRequest} request The action request that includes all the information about the action being taken including
  ///    the id of the action, any options and the duration (if applicable).
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> actionUser(
      ActionRequest request) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Activates the FusionAuth Reactor using a license id and optionally a license text (for air-gapped deployments)
  ///
  /// @param {ReactorRequest} request An optional request that contains the license text to activate Reactor (useful for air-gap deployments of FusionAuth).
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> activateReactor(ReactorRequest request) {
    return _start<void, Errors>()
        .withUri('/api/reactor')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Adds a user to an existing family. The family id must be specified.
  ///
  /// @param {String} familyId The id of the family.
  /// @param {FamilyRequest} request The request object that contains all the information used to determine which user to add to the family.
  /// @returns {Promise<ClientResponse<FamilyResponse>>}
  Future<ClientResponse<FamilyResponse, Errors>> addUserToFamily(
      String familyId, FamilyRequest request) {
    return _start<FamilyResponse, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FamilyResponse.fromJson(d)))
        .go();
  }

  /// Approve a device grant.
  ///
  /// @param {String} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
  /// @param {String} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
  /// @param {String} token The access token used to identify the user.
  /// @param {String} user_code The end-user verification code.
  /// @returns {Promise<ClientResponse<DeviceApprovalResponse>>}
  Future<ClientResponse<DeviceApprovalResponse, Errors>> approveDevice(
      String client_id, String client_secret, String token, String user_code) {
    var body = Map<String, dynamic>();
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['token'] = token;
    body['user_code'] = user_code;
    return _start<DeviceApprovalResponse, Errors>()
        .withUri('/oauth2/device/approve')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => DeviceApprovalResponse.fromJson(d)))
        .go();
  }

  /// Cancels the user action.
  ///
  /// @param {String} actionId The action id of the action to cancel.
  /// @param {ActionRequest} request The action request that contains the information about the cancellation.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> cancelAction(
      String actionId, ActionRequest request) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withJSONBody(request)
        .withMethod('DELETE')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Changes a user's password using the change password Id. This usually occurs after an email has been sent to the user
  /// and they clicked on a link to reset their password.
  ///
  /// As of version 1.32.2, prefer sending the changePasswordId in the request body. To do this, omit the first parameter, and set
  /// the value in the request body.
  ///
  /// @param {String} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
  /// @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
  /// @returns {Promise<ClientResponse<ChangePasswordResponse>>}
  Future<ClientResponse<ChangePasswordResponse, Errors>> changePassword(
      String changePasswordId, ChangePasswordRequest request) {
    return _startAnonymous<ChangePasswordResponse, Errors>()
        .withUri('/api/user/change-password')
        .withUriSegment(changePasswordId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ChangePasswordResponse.fromJson(d)))
        .go();
  }

  /// Changes a user's password using their identity (login id and password). Using a loginId instead of the changePasswordId
  /// bypasses the email verification and allows a password to be changed directly without first calling the #forgotPassword
  /// method.
  ///
  /// @param {ChangePasswordRequest} request The change password request that contains all the information used to change the password.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> changePasswordByIdentity(
      ChangePasswordRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/change-password')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
  /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
  /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
  ///
  /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
  ///
  /// @param {String} changePasswordId The change password Id used to find the user. This value is generated by FusionAuth once the change password workflow has been initiated.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> checkChangePasswordUsingId(
      String changePasswordId) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/user/change-password')
        .withUriSegment(changePasswordId)
        .withMethod('GET')
        .go();
  }

  /// Check to see if the user must obtain a Trust Token Id in order to complete a change password request.
  /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
  /// your password, you must obtain a Trust Token by completing a Two-Factor Step-Up authentication.
  ///
  /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
  ///
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> checkChangePasswordUsingJWT(
      String encodedJWT) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/user/change-password')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod('GET')
        .go();
  }

  /// Check to see if the user must obtain a Trust Request Id in order to complete a change password request.
  /// When a user has enabled Two-Factor authentication, before you are allowed to use the Change Password API to change
  /// your password, you must obtain a Trust Request Id by completing a Two-Factor Step-Up authentication.
  ///
  /// An HTTP status code of 400 with a general error code of [TrustTokenRequired] indicates that a Trust Token is required to make a POST request to this API.
  ///
  /// @param {String} loginId The loginId of the User that you intend to change the password for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> checkChangePasswordUsingLoginId(
      String loginId) {
    return _start<void, Errors>()
        .withUri('/api/user/change-password')
        .withParameter('username', loginId)
        .withMethod('GET')
        .go();
  }

  /// Make a Client Credentials grant request to obtain an access token.
  ///
  /// @param {String} client_id (Optional) The client identifier. The client Id is the Id of the FusionAuth Entity in which you are attempting to authenticate.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} client_secret (Optional) The client secret used to authenticate this request.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} scope (Optional) This parameter is used to indicate which target entity you are requesting access. To request access to an entity, use the format target-entity:&lt;target-entity-id&gt;:&lt;roles&gt;. Roles are an optional comma separated list.
  /// @returns {Promise<ClientResponse<AccessToken>>}
  Future<ClientResponse<AccessToken, OAuthError>> clientCredentialsGrant(
      String client_id, String client_secret, String scope) {
    var body = Map<String, dynamic>();
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['grant_type'] = 'client_credentials';
    body['scope'] = scope;
    return _startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AccessToken.fromJson(d)))
        .go();
  }

  /// Adds a comment to the user's account.
  ///
  /// @param {UserCommentRequest} request The request object that contains all the information used to create the user comment.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> commentOnUser(
      UserCommentRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/comment')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge without logging the user in
  ///
  /// @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
  /// @returns {Promise<ClientResponse<WebAuthnAssertResponse>>}
  Future<ClientResponse<WebAuthnAssertResponse, Errors>>
      completeWebAuthnAssertion(WebAuthnLoginRequest request) {
    return _startAnonymous<WebAuthnAssertResponse, Errors>()
        .withUri('/api/webauthn/assert')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnAssertResponse.fromJson(d)))
        .go();
  }

  /// Complete a WebAuthn authentication ceremony by validating the signature against the previously generated challenge and then login the user in
  ///
  /// @param {WebAuthnLoginRequest} request An object containing data necessary for completing the authentication ceremony
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> completeWebAuthnLogin(
      WebAuthnLoginRequest request) {
    return _startAnonymous<LoginResponse, Errors>()
        .withUri('/api/webauthn/login')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Complete a WebAuthn registration ceremony by validating the client request and saving the new credential
  ///
  /// @param {WebAuthnRegisterCompleteRequest} request An object containing data necessary for completing the registration ceremony
  /// @returns {Promise<ClientResponse<WebAuthnRegisterCompleteResponse>>}
  Future<ClientResponse<WebAuthnRegisterCompleteResponse, Errors>>
      completeWebAuthnRegistration(WebAuthnRegisterCompleteRequest request) {
    return _start<WebAuthnRegisterCompleteResponse, Errors>()
        .withUri('/api/webauthn/register/complete')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnRegisterCompleteResponse.fromJson(d)))
        .go();
  }

  /// Creates an API key. You can optionally specify a unique Id for the key, if not provided one will be generated.
  /// an API key can only be created with equal or lesser authority. An API key cannot create another API key unless it is granted
  /// to that API key.
  ///
  /// If an API key is locked to a tenant, it can only create API Keys for that same tenant.
  ///
  /// @param {String} keyId (Optional) The unique Id of the API key. If not provided a secure random Id will be generated.
  /// @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
  /// @returns {Promise<ClientResponse<APIKeyResponse>>}
  Future<ClientResponse<APIKeyResponse, Errors>> createAPIKey(
      String keyId, APIKeyRequest request) {
    return _start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => APIKeyResponse.fromJson(d)))
        .go();
  }

  /// Creates an application. You can optionally specify an Id for the application, if not provided one will be generated.
  ///
  /// @param {String} applicationId (Optional) The Id to use for the application. If not provided a secure random UUID will be generated.
  /// @param {ApplicationRequest} request The request object that contains all the information used to create the application.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> createApplication(
      String applicationId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Creates a new role for an application. You must specify the id of the application you are creating the role for.
  /// You can optionally specify an Id for the role inside the ApplicationRole object itself, if not provided one will be generated.
  ///
  /// @param {String} applicationId The Id of the application to create the role on.
  /// @param {String} roleId (Optional) The Id of the role. If not provided a secure random UUID will be generated.
  /// @param {ApplicationRequest} request The request object that contains all the information used to create the application role.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> createApplicationRole(
      String applicationId, String roleId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Creates an audit log with the message and user name (usually an email). Audit logs should be written anytime you
  /// make changes to the FusionAuth database. When using the FusionAuth App web interface, any changes are automatically
  /// written to the audit log. However, if you are accessing the API, you must write the audit logs yourself.
  ///
  /// @param {AuditLogRequest} request The request object that contains all the information used to create the audit log entry.
  /// @returns {Promise<ClientResponse<AuditLogResponse>>}
  Future<ClientResponse<AuditLogResponse, Errors>> createAuditLog(
      AuditLogRequest request) {
    return _start<AuditLogResponse, Errors>()
        .withUri('/api/system/audit-log')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AuditLogResponse.fromJson(d)))
        .go();
  }

  /// Creates a connector.  You can optionally specify an Id for the connector, if not provided one will be generated.
  ///
  /// @param {String} connectorId (Optional) The Id for the connector. If not provided a secure random UUID will be generated.
  /// @param {ConnectorRequest} request The request object that contains all the information used to create the connector.
  /// @returns {Promise<ClientResponse<ConnectorResponse>>}
  Future<ClientResponse<ConnectorResponse, Errors>> createConnector(
      String connectorId, ConnectorRequest request) {
    return _start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConnectorResponse.fromJson(d)))
        .go();
  }

  /// Creates a user consent type. You can optionally specify an Id for the consent type, if not provided one will be generated.
  ///
  /// @param {String} consentId (Optional) The Id for the consent. If not provided a secure random UUID will be generated.
  /// @param {ConsentRequest} request The request object that contains all the information used to create the consent.
  /// @returns {Promise<ClientResponse<ConsentResponse>>}
  Future<ClientResponse<ConsentResponse, Errors>> createConsent(
      String consentId, ConsentRequest request) {
    return _start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConsentResponse.fromJson(d)))
        .go();
  }

  /// Creates an email template. You can optionally specify an Id for the template, if not provided one will be generated.
  ///
  /// @param {String} emailTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
  /// @param {EmailTemplateRequest} request The request object that contains all the information used to create the email template.
  /// @returns {Promise<ClientResponse<EmailTemplateResponse>>}
  Future<ClientResponse<EmailTemplateResponse, Errors>> createEmailTemplate(
      String emailTemplateId, EmailTemplateRequest request) {
    return _start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateResponse.fromJson(d)))
        .go();
  }

  /// Creates an Entity. You can optionally specify an Id for the Entity. If not provided one will be generated.
  ///
  /// @param {String} entityId (Optional) The Id for the Entity. If not provided a secure random UUID will be generated.
  /// @param {EntityRequest} request The request object that contains all the information used to create the Entity.
  /// @returns {Promise<ClientResponse<EntityResponse>>}
  Future<ClientResponse<EntityResponse, Errors>> createEntity(
      String entityId, EntityRequest request) {
    return _start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => EntityResponse.fromJson(d)))
        .go();
  }

  /// Creates a Entity Type. You can optionally specify an Id for the Entity Type, if not provided one will be generated.
  ///
  /// @param {String} entityTypeId (Optional) The Id for the Entity Type. If not provided a secure random UUID will be generated.
  /// @param {EntityTypeRequest} request The request object that contains all the information used to create the Entity Type.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> createEntityType(
      String entityTypeId, EntityTypeRequest request) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Creates a new permission for an entity type. You must specify the id of the entity type you are creating the permission for.
  /// You can optionally specify an Id for the permission inside the EntityTypePermission object itself, if not provided one will be generated.
  ///
  /// @param {String} entityTypeId The Id of the entity type to create the permission on.
  /// @param {String} permissionId (Optional) The Id of the permission. If not provided a secure random UUID will be generated.
  /// @param {EntityTypeRequest} request The request object that contains all the information used to create the permission.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> createEntityTypePermission(
      String entityTypeId, String permissionId, EntityTypeRequest request) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Creates a family with the user id in the request as the owner and sole member of the family. You can optionally specify an id for the
  /// family, if not provided one will be generated.
  ///
  /// @param {String} familyId (Optional) The id for the family. If not provided a secure random UUID will be generated.
  /// @param {FamilyRequest} request The request object that contains all the information used to create the family.
  /// @returns {Promise<ClientResponse<FamilyResponse>>}
  Future<ClientResponse<FamilyResponse, Errors>> createFamily(
      String familyId, FamilyRequest request) {
    return _start<FamilyResponse, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FamilyResponse.fromJson(d)))
        .go();
  }

  /// Creates a form.  You can optionally specify an Id for the form, if not provided one will be generated.
  ///
  /// @param {String} formId (Optional) The Id for the form. If not provided a secure random UUID will be generated.
  /// @param {FormRequest} request The request object that contains all the information used to create the form.
  /// @returns {Promise<ClientResponse<FormResponse>>}
  Future<ClientResponse<FormResponse, Errors>> createForm(
      String formId, FormRequest request) {
    return _start<FormResponse, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormResponse.fromJson(d)))
        .go();
  }

  /// Creates a form field.  You can optionally specify an Id for the form, if not provided one will be generated.
  ///
  /// @param {String} fieldId (Optional) The Id for the form field. If not provided a secure random UUID will be generated.
  /// @param {FormFieldRequest} request The request object that contains all the information used to create the form field.
  /// @returns {Promise<ClientResponse<FormFieldResponse>>}
  Future<ClientResponse<FormFieldResponse, Errors>> createFormField(
      String fieldId, FormFieldRequest request) {
    return _start<FormFieldResponse, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormFieldResponse.fromJson(d)))
        .go();
  }

  /// Creates a group. You can optionally specify an Id for the group, if not provided one will be generated.
  ///
  /// @param {String} groupId (Optional) The Id for the group. If not provided a secure random UUID will be generated.
  /// @param {GroupRequest} request The request object that contains all the information used to create the group.
  /// @returns {Promise<ClientResponse<GroupResponse>>}
  Future<ClientResponse<GroupResponse, Errors>> createGroup(
      String groupId, GroupRequest request) {
    return _start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => GroupResponse.fromJson(d)))
        .go();
  }

  /// Creates a member in a group.
  ///
  /// @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
  /// @returns {Promise<ClientResponse<MemberResponse>>}
  Future<ClientResponse<MemberResponse, Errors>> createGroupMembers(
      MemberRequest request) {
    return _start<MemberResponse, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MemberResponse.fromJson(d)))
        .go();
  }

  /// Creates an IP Access Control List. You can optionally specify an Id on this create request, if one is not provided one will be generated.
  ///
  /// @param {String} accessControlListId (Optional) The Id for the IP Access Control List. If not provided a secure random UUID will be generated.
  /// @param {IPAccessControlListRequest} request The request object that contains all the information used to create the IP Access Control List.
  /// @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
  Future<ClientResponse<IPAccessControlListResponse, Errors>>
      createIPAccessControlList(
          String accessControlListId, IPAccessControlListRequest request) {
    return _start<IPAccessControlListResponse, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(accessControlListId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IPAccessControlListResponse.fromJson(d)))
        .go();
  }

  /// Creates an identity provider. You can optionally specify an Id for the identity provider, if not provided one will be generated.
  ///
  /// @param {String} identityProviderId (Optional) The Id of the identity provider. If not provided a secure random UUID will be generated.
  /// @param {IdentityProviderRequest} request The request object that contains all the information used to create the identity provider.
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, Errors>>
      createIdentityProvider(
          String identityProviderId, IdentityProviderRequest request) {
    return _start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Creates a Lambda. You can optionally specify an Id for the lambda, if not provided one will be generated.
  ///
  /// @param {String} lambdaId (Optional) The Id for the lambda. If not provided a secure random UUID will be generated.
  /// @param {LambdaRequest} request The request object that contains all the information used to create the lambda.
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, Errors>> createLambda(
      String lambdaId, LambdaRequest request) {
    return _start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Creates an message template. You can optionally specify an Id for the template, if not provided one will be generated.
  ///
  /// @param {String} messageTemplateId (Optional) The Id for the template. If not provided a secure random UUID will be generated.
  /// @param {MessageTemplateRequest} request The request object that contains all the information used to create the message template.
  /// @returns {Promise<ClientResponse<MessageTemplateResponse>>}
  Future<ClientResponse<MessageTemplateResponse, Errors>> createMessageTemplate(
      String messageTemplateId, MessageTemplateRequest request) {
    return _start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Creates a messenger.  You can optionally specify an Id for the messenger, if not provided one will be generated.
  ///
  /// @param {String} messengerId (Optional) The Id for the messenger. If not provided a secure random UUID will be generated.
  /// @param {MessengerRequest} request The request object that contains all the information used to create the messenger.
  /// @returns {Promise<ClientResponse<MessengerResponse>>}
  Future<ClientResponse<MessengerResponse, Errors>> createMessenger(
      String messengerId, MessengerRequest request) {
    return _start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MessengerResponse.fromJson(d)))
        .go();
  }

  /// Creates a tenant. You can optionally specify an Id for the tenant, if not provided one will be generated.
  ///
  /// @param {String} tenantId (Optional) The Id for the tenant. If not provided a secure random UUID will be generated.
  /// @param {TenantRequest} request The request object that contains all the information used to create the tenant.
  /// @returns {Promise<ClientResponse<TenantResponse>>}
  Future<ClientResponse<TenantResponse, Errors>> createTenant(
      String tenantId, TenantRequest request) {
    return _start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TenantResponse.fromJson(d)))
        .go();
  }

  /// Creates a Theme. You can optionally specify an Id for the theme, if not provided one will be generated.
  ///
  /// @param {String} themeId (Optional) The Id for the theme. If not provided a secure random UUID will be generated.
  /// @param {ThemeRequest} request The request object that contains all the information used to create the theme.
  /// @returns {Promise<ClientResponse<ThemeResponse>>}
  Future<ClientResponse<ThemeResponse, Errors>> createTheme(
      String themeId, ThemeRequest request) {
    return _start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ThemeResponse.fromJson(d)))
        .go();
  }

  /// Creates a user. You can optionally specify an Id for the user, if not provided one will be generated.
  ///
  /// @param {String} userId (Optional) The Id for the user. If not provided a secure random UUID will be generated.
  /// @param {UserRequest} request The request object that contains all the information used to create the user.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> createUser(
      String userId, UserRequest request) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Creates a user action. This action cannot be taken on a user until this call successfully returns. Anytime after
  /// that the user action can be applied to any user.
  ///
  /// @param {String} userActionId (Optional) The Id for the user action. If not provided a secure random UUID will be generated.
  /// @param {UserActionRequest} request The request object that contains all the information used to create the user action.
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, Errors>> createUserAction(
      String userActionId, UserActionRequest request) {
    return _start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Creates a user reason. This user action reason cannot be used when actioning a user until this call completes
  /// successfully. Anytime after that the user action reason can be used.
  ///
  /// @param {String} userActionReasonId (Optional) The Id for the user action reason. If not provided a secure random UUID will be generated.
  /// @param {UserActionReasonRequest} request The request object that contains all the information used to create the user action reason.
  /// @returns {Promise<ClientResponse<UserActionReasonResponse>>}
  Future<ClientResponse<UserActionReasonResponse, Errors>>
      createUserActionReason(
          String userActionReasonId, UserActionReasonRequest request) {
    return _start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionReasonResponse.fromJson(d)))
        .go();
  }

  /// Creates a single User consent.
  ///
  /// @param {String} userConsentId (Optional) The Id for the User consent. If not provided a secure random UUID will be generated.
  /// @param {UserConsentRequest} request The request that contains the user consent information.
  /// @returns {Promise<ClientResponse<UserConsentResponse>>}
  Future<ClientResponse<UserConsentResponse, Errors>> createUserConsent(
      String userConsentId, UserConsentRequest request) {
    return _start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserConsentResponse.fromJson(d)))
        .go();
  }

  /// Link an external user from a 3rd party identity provider to a FusionAuth user.
  ///
  /// @param {IdentityProviderLinkRequest} request The request object that contains all the information used to link the FusionAuth user.
  /// @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
  Future<ClientResponse<IdentityProviderLinkResponse, Errors>> createUserLink(
      IdentityProviderLinkRequest request) {
    return _start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderLinkResponse.fromJson(d)))
        .go();
  }

  /// Creates a webhook. You can optionally specify an Id for the webhook, if not provided one will be generated.
  ///
  /// @param {String} webhookId (Optional) The Id for the webhook. If not provided a secure random UUID will be generated.
  /// @param {WebhookRequest} request The request object that contains all the information used to create the webhook.
  /// @returns {Promise<ClientResponse<WebhookResponse>>}
  Future<ClientResponse<WebhookResponse, Errors>> createWebhook(
      String webhookId, WebhookRequest request) {
    return _start<WebhookResponse, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => WebhookResponse.fromJson(d)))
        .go();
  }

  /// Deactivates the application with the given Id.
  ///
  /// @param {String} applicationId The Id of the application to deactivate.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deactivateApplication(
      String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withMethod('DELETE')
        .go();
  }

  /// Deactivates the FusionAuth Reactor.
  ///
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> deactivateReactor() {
    return _start<void, void>()
        .withUri('/api/reactor')
        .withMethod('DELETE')
        .go();
  }

  /// Deactivates the user with the given Id.
  ///
  /// @param {String} userId The Id of the user to deactivate.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deactivateUser(String userId) {
    return _start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withMethod('DELETE')
        .go();
  }

  /// Deactivates the user action with the given Id.
  ///
  /// @param {String} userActionId The Id of the user action to deactivate.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deactivateUserAction(
      String userActionId) {
    return _start<void, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withMethod('DELETE')
        .go();
  }

  /// Deactivates the users with the given ids.
  ///
  /// @param {List<String>} userIds The ids of the users to deactivate.
  /// @returns {Promise<ClientResponse<UserDeleteResponse>>}
  ///
  /// @deprecated This method has been renamed to deactivateUsersByIds, use that method instead.
  Future<ClientResponse<UserDeleteResponse, Errors>> deactivateUsers(
      List<String> userIds) {
    return _start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withParameter('userId', userIds)
        .withParameter('dryRun', false)
        .withParameter('hardDelete', false)
        .withMethod('DELETE')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserDeleteResponse.fromJson(d)))
        .go();
  }

  /// Deactivates the users with the given ids.
  ///
  /// @param {List<String>} userIds The ids of the users to deactivate.
  /// @returns {Promise<ClientResponse<UserDeleteResponse>>}
  Future<ClientResponse<UserDeleteResponse, Errors>> deactivateUsersByIds(
      List<String> userIds) {
    return _start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withParameter('userId', userIds)
        .withParameter('dryRun', false)
        .withParameter('hardDelete', false)
        .withMethod('DELETE')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserDeleteResponse.fromJson(d)))
        .go();
  }

  /// Deletes the API key for the given Id.
  ///
  /// @param {String} keyId The Id of the authentication API key to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteAPIKey(String keyId) {
    return _start<void, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withMethod('DELETE')
        .go();
  }

  /// Hard deletes an application. This is a dangerous operation and should not be used in most circumstances. This will
  /// delete the application, any registrations for that application, metrics and reports for the application, all the
  /// roles for the application, and any other data associated with the application. This operation could take a very
  /// long time, depending on the amount of data in your database.
  ///
  /// @param {String} applicationId The Id of the application to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteApplication(String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withParameter('hardDelete', true)
        .withMethod('DELETE')
        .go();
  }

  /// Hard deletes an application role. This is a dangerous operation and should not be used in most circumstances. This
  /// permanently removes the given role from all users that had it.
  ///
  /// @param {String} applicationId The Id of the application to deactivate.
  /// @param {String} roleId The Id of the role to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteApplicationRole(
      String applicationId, String roleId) {
    return _start<void, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the connector for the given Id.
  ///
  /// @param {String} connectorId The Id of the connector to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteConnector(String connectorId) {
    return _start<void, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the consent for the given Id.
  ///
  /// @param {String} consentId The Id of the consent to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteConsent(String consentId) {
    return _start<void, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the email template for the given Id.
  ///
  /// @param {String} emailTemplateId The Id of the email template to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteEmailTemplate(
      String emailTemplateId) {
    return _start<void, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the Entity for the given Id.
  ///
  /// @param {String} entityId The Id of the Entity to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteEntity(String entityId) {
    return _start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes an Entity Grant for the given User or Entity.
  ///
  /// @param {String} entityId The Id of the Entity that the Entity Grant is being deleted for.
  /// @param {String} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
  /// @param {String} userId (Optional) The Id of the User that the Entity Grant is for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteEntityGrant(
      String entityId, String recipientEntityId, String userId) {
    return _start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withParameter('recipientEntityId', recipientEntityId)
        .withParameter('userId', userId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the Entity Type for the given Id.
  ///
  /// @param {String} entityTypeId The Id of the Entity Type to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteEntityType(String entityTypeId) {
    return _start<void, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withMethod('DELETE')
        .go();
  }

  /// Hard deletes a permission. This is a dangerous operation and should not be used in most circumstances. This
  /// permanently removes the given permission from all grants that had it.
  ///
  /// @param {String} entityTypeId The Id of the entityType the the permission belongs to.
  /// @param {String} permissionId The Id of the permission to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteEntityTypePermission(
      String entityTypeId, String permissionId) {
    return _start<void, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the form for the given Id.
  ///
  /// @param {String} formId The Id of the form to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteForm(String formId) {
    return _start<void, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the form field for the given Id.
  ///
  /// @param {String} fieldId The Id of the form field to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteFormField(String fieldId) {
    return _start<void, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the group for the given Id.
  ///
  /// @param {String} groupId The Id of the group to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteGroup(String groupId) {
    return _start<void, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withMethod('DELETE')
        .go();
  }

  /// Removes users as members of a group.
  ///
  /// @param {MemberDeleteRequest} request The member request that contains all the information used to remove members to the group.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteGroupMembers(
      MemberDeleteRequest request) {
    return _start<void, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the IP Access Control List for the given Id.
  ///
  /// @param {String} ipAccessControlListId The Id of the IP Access Control List to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteIPAccessControlList(
      String ipAccessControlListId) {
    return _start<void, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(ipAccessControlListId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the identity provider for the given Id.
  ///
  /// @param {String} identityProviderId The Id of the identity provider to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteIdentityProvider(
      String identityProviderId) {
    return _start<void, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the key for the given Id.
  ///
  /// @param {String} keyId The Id of the key to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteKey(String keyId) {
    return _start<void, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the lambda for the given Id.
  ///
  /// @param {String} lambdaId The Id of the lambda to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteLambda(String lambdaId) {
    return _start<void, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the message template for the given Id.
  ///
  /// @param {String} messageTemplateId The Id of the message template to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteMessageTemplate(
      String messageTemplateId) {
    return _start<void, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the messenger for the given Id.
  ///
  /// @param {String} messengerId The Id of the messenger to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteMessenger(String messengerId) {
    return _start<void, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the user registration for the given user and application.
  ///
  /// @param {String} userId The Id of the user whose registration is being deleted.
  /// @param {String} applicationId The Id of the application to remove the registration for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteRegistration(
      String userId, String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the user registration for the given user and application along with the given JSON body that contains the event information.
  ///
  /// @param {String} userId The Id of the user whose registration is being deleted.
  /// @param {String} applicationId The Id of the application to remove the registration for.
  /// @param {RegistrationDeleteRequest} request The request body that contains the event information.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteRegistrationWithRequest(
      String userId, String applicationId, RegistrationDeleteRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the tenant based on the given Id on the URL. This permanently deletes all information, metrics, reports and data associated
  /// with the tenant and everything under the tenant (applications, users, etc).
  ///
  /// @param {String} tenantId The Id of the tenant to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteTenant(String tenantId) {
    return _start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the tenant for the given Id asynchronously.
  /// This method is helpful if you do not want to wait for the delete operation to complete.
  ///
  /// @param {String} tenantId The Id of the tenant to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteTenantAsync(String tenantId) {
    return _start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withParameter('async', true)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the tenant based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
  /// with the tenant and everything under the tenant (applications, users, etc).
  ///
  /// @param {String} tenantId The Id of the tenant to delete.
  /// @param {TenantDeleteRequest} request The request object that contains all the information used to delete the user.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteTenantWithRequest(
      String tenantId, TenantDeleteRequest request) {
    return _start<void, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the theme for the given Id.
  ///
  /// @param {String} themeId The Id of the theme to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteTheme(String themeId) {
    return _start<void, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the user for the given Id. This permanently deletes all information, metrics, reports and data associated
  /// with the user.
  ///
  /// @param {String} userId The Id of the user to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteUser(String userId) {
    return _start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withParameter('hardDelete', true)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the user action for the given Id. This permanently deletes the user action and also any history and logs of
  /// the action being applied to any users.
  ///
  /// @param {String} userActionId The Id of the user action to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteUserAction(String userActionId) {
    return _start<void, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withParameter('hardDelete', true)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the user action reason for the given Id.
  ///
  /// @param {String} userActionReasonId The Id of the user action reason to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteUserActionReason(
      String userActionReasonId) {
    return _start<void, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withMethod('DELETE')
        .go();
  }

  /// Remove an existing link that has been made from a 3rd party identity provider to a FusionAuth user.
  ///
  /// @param {String} identityProviderId The unique Id of the identity provider.
  /// @param {String} identityProviderUserId The unique Id of the user in the 3rd party identity provider to unlink.
  /// @param {String} userId The unique Id of the FusionAuth user to unlink.
  /// @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
  Future<ClientResponse<IdentityProviderLinkResponse, Errors>> deleteUserLink(
      String identityProviderId, String identityProviderUserId, String userId) {
    return _start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('identityProviderUserId', identityProviderUserId)
        .withParameter('userId', userId)
        .withMethod('DELETE')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderLinkResponse.fromJson(d)))
        .go();
  }

  /// Deletes the user based on the given request (sent to the API as JSON). This permanently deletes all information, metrics, reports and data associated
  /// with the user.
  ///
  /// @param {String} userId The Id of the user to delete (required).
  /// @param {UserDeleteSingleRequest} request The request object that contains all the information used to delete the user.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteUserWithRequest(
      String userId, UserDeleteSingleRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
  /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
  ///
  /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
  /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
  ///
  /// @param {UserDeleteRequest} request The UserDeleteRequest.
  /// @returns {Promise<ClientResponse<UserDeleteResponse>>}
  ///
  /// @deprecated This method has been renamed to deleteUsersByQuery, use that method instead.
  Future<ClientResponse<UserDeleteResponse, Errors>> deleteUsers(
      UserDeleteRequest request) {
    return _start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withJSONBody(request)
        .withMethod('DELETE')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserDeleteResponse.fromJson(d)))
        .go();
  }

  /// Deletes the users with the given ids, or users matching the provided JSON query or queryString.
  /// The order of preference is ids, query and then queryString, it is recommended to only provide one of the three for the request.
  ///
  /// This method can be used to deactivate or permanently delete (hard-delete) users based upon the hardDelete boolean in the request body.
  /// Using the dryRun parameter you may also request the result of the action without actually deleting or deactivating any users.
  ///
  /// @param {UserDeleteRequest} request The UserDeleteRequest.
  /// @returns {Promise<ClientResponse<UserDeleteResponse>>}
  Future<ClientResponse<UserDeleteResponse, Errors>> deleteUsersByQuery(
      UserDeleteRequest request) {
    return _start<UserDeleteResponse, Errors>()
        .withUri('/api/user/bulk')
        .withJSONBody(request)
        .withMethod('DELETE')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserDeleteResponse.fromJson(d)))
        .go();
  }

  /// Deletes the WebAuthn credential for the given Id.
  ///
  /// @param {String} id The Id of the WebAuthn credential to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteWebAuthnCredential(String id) {
    return _start<void, Errors>()
        .withUri('/api/webauthn')
        .withUriSegment(id)
        .withMethod('DELETE')
        .go();
  }

  /// Deletes the webhook for the given Id.
  ///
  /// @param {String} webhookId The Id of the webhook to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> deleteWebhook(String webhookId) {
    return _start<void, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withMethod('DELETE')
        .go();
  }

  /// Disable two-factor authentication for a user.
  ///
  /// @param {String} userId The Id of the User for which you're disabling two-factor authentication.
  /// @param {String} methodId The two-factor method identifier you wish to disable
  /// @param {String} code The two-factor code used verify the the caller knows the two-factor secret.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> disableTwoFactor(
      String userId, String methodId, String code) {
    return _start<void, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withParameter('methodId', methodId)
        .withParameter('code', code)
        .withMethod('DELETE')
        .go();
  }

  /// Disable two-factor authentication for a user using a JSON body rather than URL parameters.
  ///
  /// @param {String} userId The Id of the User for which you're disabling two-factor authentication.
  /// @param {TwoFactorDisableRequest} request The request information that contains the code and methodId along with any event information.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> disableTwoFactorWithRequest(
      String userId, TwoFactorDisableRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Enable two-factor authentication for a user.
  ///
  /// @param {String} userId The Id of the user to enable two-factor authentication.
  /// @param {TwoFactorRequest} request The two-factor enable request information.
  /// @returns {Promise<ClientResponse<TwoFactorResponse>>}
  Future<ClientResponse<TwoFactorResponse, Errors>> enableTwoFactor(
      String userId, TwoFactorRequest request) {
    return _start<TwoFactorResponse, Errors>()
        .withUri('/api/user/two-factor')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TwoFactorResponse.fromJson(d)))
        .go();
  }

  /// Exchanges an OAuth authorization code for an access token.
  /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint for an access token.
  ///
  /// @param {String} code The authorization code returned on the /oauth2/authorize response.
  /// @param {String} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} client_secret (Optional) The client secret. This value will be required if client authentication is enabled.
  /// @param {String} redirect_uri The URI to redirect to upon a successful request.
  /// @returns {Promise<ClientResponse<AccessToken>>}
  Future<ClientResponse<AccessToken, OAuthError>>
      exchangeOAuthCodeForAccessToken(String code, String client_id,
          String client_secret, String redirect_uri) {
    var body = Map<String, dynamic>();
    body['code'] = code;
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['grant_type'] = 'authorization_code';
    body['redirect_uri'] = redirect_uri;
    return _startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AccessToken.fromJson(d)))
        .go();
  }

  /// Exchanges an OAuth authorization code and code_verifier for an access token.
  /// Makes a request to the Token endpoint to exchange the authorization code returned from the Authorize endpoint and a code_verifier for an access token.
  ///
  /// @param {String} code The authorization code returned on the /oauth2/authorize response.
  /// @param {String} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
  /// @param {String} redirect_uri The URI to redirect to upon a successful request.
  /// @param {String} code_verifier The random string generated previously. Will be compared with the code_challenge sent previously, which allows the OAuth provider to authenticate your app.
  /// @returns {Promise<ClientResponse<AccessToken>>}
  Future<ClientResponse<AccessToken, OAuthError>>
      exchangeOAuthCodeForAccessTokenUsingPKCE(String code, String client_id,
          String client_secret, String redirect_uri, String code_verifier) {
    var body = Map<String, dynamic>();
    body['code'] = code;
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['grant_type'] = 'authorization_code';
    body['redirect_uri'] = redirect_uri;
    body['code_verifier'] = code_verifier;
    return _startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AccessToken.fromJson(d)))
        .go();
  }

  /// Exchange a Refresh Token for an Access Token.
  /// If you will be using the Refresh Token Grant, you will make a request to the Token endpoint to exchange the user’s refresh token for an access token.
  ///
  /// @param {String} refresh_token The refresh token that you would like to use to exchange for an access token.
  /// @param {String} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
  /// @param {String} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
  /// @param {String} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
  /// @returns {Promise<ClientResponse<AccessToken>>}
  Future<ClientResponse<AccessToken, OAuthError>>
      exchangeRefreshTokenForAccessToken(String refresh_token, String client_id,
          String client_secret, String scope, String user_code) {
    var body = Map<String, dynamic>();
    body['refresh_token'] = refresh_token;
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['grant_type'] = 'refresh_token';
    body['scope'] = scope;
    body['user_code'] = user_code;
    return _startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AccessToken.fromJson(d)))
        .go();
  }

  /// Exchange a refresh token for a new JWT.
  ///
  /// @param {RefreshRequest} request The refresh request.
  /// @returns {Promise<ClientResponse<JWTRefreshResponse>>}
  Future<ClientResponse<JWTRefreshResponse, Errors>> exchangeRefreshTokenForJWT(
      RefreshRequest request) {
    return _startAnonymous<JWTRefreshResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => JWTRefreshResponse.fromJson(d)))
        .go();
  }

  /// Exchange User Credentials for a Token.
  /// If you will be using the Resource Owner Password Credential Grant, you will make a request to the Token endpoint to exchange the user’s email and password for an access token.
  ///
  /// @param {String} username The login identifier of the user. The login identifier can be either the email or the username.
  /// @param {String} password The user’s password.
  /// @param {String} client_id (Optional) The unique client identifier. The client Id is the Id of the FusionAuth Application in which you are attempting to authenticate. This parameter is optional when the Authorization header is provided.
  ///    This parameter is optional when Basic Authorization is used to authenticate this request.
  /// @param {String} client_secret (Optional) The client secret. This value may optionally be provided in the request body instead of the Authorization header.
  /// @param {String} scope (Optional) This parameter is optional and if omitted, the same scope requested during the authorization request will be used. If provided the scopes must match those requested during the initial authorization request.
  /// @param {String} user_code (Optional) The end-user verification code. This code is required if using this endpoint to approve the Device Authorization.
  /// @returns {Promise<ClientResponse<AccessToken>>}
  Future<ClientResponse<AccessToken, OAuthError>>
      exchangeUserCredentialsForAccessToken(
          String username,
          String password,
          String client_id,
          String client_secret,
          String scope,
          String user_code) {
    var body = Map<String, dynamic>();
    body['username'] = username;
    body['password'] = password;
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['grant_type'] = 'password';
    body['scope'] = scope;
    body['user_code'] = user_code;
    return _startAnonymous<AccessToken, OAuthError>()
        .withUri('/oauth2/token')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AccessToken.fromJson(d)))
        .go();
  }

  /// Begins the forgot password sequence, which kicks off an email to the user so that they can reset their password.
  ///
  /// @param {ForgotPasswordRequest} request The request that contains the information about the user so that they can be emailed.
  /// @returns {Promise<ClientResponse<ForgotPasswordResponse>>}
  Future<ClientResponse<ForgotPasswordResponse, Errors>> forgotPassword(
      ForgotPasswordRequest request) {
    return _start<ForgotPasswordResponse, Errors>()
        .withUri('/api/user/forgot-password')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ForgotPasswordResponse.fromJson(d)))
        .go();
  }

  /// Generate a new Email Verification Id to be used with the Verify Email API. This API will not attempt to send an
  /// email to the User. This API may be used to collect the verificationId for use with a third party system.
  ///
  /// @param {String} email The email address of the user that needs a new verification email.
  /// @returns {Promise<ClientResponse<VerifyEmailResponse>>}
  Future<ClientResponse<VerifyEmailResponse, void>> generateEmailVerificationId(
      String email) {
    return _start<VerifyEmailResponse, void>()
        .withUri('/api/user/verify-email')
        .withParameter('email', email)
        .withParameter('sendVerifyEmail', false)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => VerifyEmailResponse.fromJson(d)))
        .go();
  }

  /// Generate a new RSA or EC key pair or an HMAC secret.
  ///
  /// @param {String} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
  /// @param {KeyRequest} request The request object that contains all the information used to create the key.
  /// @returns {Promise<ClientResponse<KeyResponse>>}
  Future<ClientResponse<KeyResponse, Errors>> generateKey(
      String keyId, KeyRequest request) {
    return _start<KeyResponse, Errors>()
        .withUri('/api/key/generate')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeyResponse.fromJson(d)))
        .go();
  }

  /// Generate a new Application Registration Verification Id to be used with the Verify Registration API. This API will not attempt to send an
  /// email to the User. This API may be used to collect the verificationId for use with a third party system.
  ///
  /// @param {String} email The email address of the user that needs a new verification email.
  /// @param {String} applicationId The Id of the application to be verified.
  /// @returns {Promise<ClientResponse<VerifyRegistrationResponse>>}
  Future<ClientResponse<VerifyRegistrationResponse, void>>
      generateRegistrationVerificationId(String email, String applicationId) {
    return _start<VerifyRegistrationResponse, void>()
        .withUri('/api/user/verify-registration')
        .withParameter('email', email)
        .withParameter('sendVerifyPasswordEmail', false)
        .withParameter('applicationId', applicationId)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => VerifyRegistrationResponse.fromJson(d)))
        .go();
  }

  /// Generate two-factor recovery codes for a user. Generating two-factor recovery codes will invalidate any existing recovery codes.
  ///
  /// @param {String} userId The Id of the user to generate new Two Factor recovery codes.
  /// @returns {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>}
  Future<ClientResponse<TwoFactorRecoveryCodeResponse, Errors>>
      generateTwoFactorRecoveryCodes(String userId) {
    return _start<TwoFactorRecoveryCodeResponse, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/two-factor/recovery-code')
        .withUriSegment(userId)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TwoFactorRecoveryCodeResponse.fromJson(d)))
        .go();
  }

  /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
  /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
  /// application such as Google Authenticator.
  ///
  /// @returns {Promise<ClientResponse<SecretResponse>>}
  Future<ClientResponse<SecretResponse, void>> generateTwoFactorSecret() {
    return _start<SecretResponse, void>()
        .withUri('/api/two-factor/secret')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SecretResponse.fromJson(d)))
        .go();
  }

  /// Generate a Two Factor secret that can be used to enable Two Factor authentication for a User. The response will contain
  /// both the secret and a Base32 encoded form of the secret which can be shown to a User when using a 2 Step Authentication
  /// application such as Google Authenticator.
  ///
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @returns {Promise<ClientResponse<SecretResponse>>}
  Future<ClientResponse<SecretResponse, void>> generateTwoFactorSecretUsingJWT(
      String encodedJWT) {
    return _startAnonymous<SecretResponse, void>()
        .withUri('/api/two-factor/secret')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SecretResponse.fromJson(d)))
        .go();
  }

  /// Handles login via third-parties including Social login, external OAuth and OpenID Connect, and other
  /// login systems.
  ///
  /// @param {IdentityProviderLoginRequest} request The third-party login request that contains information from the third-party login
  ///    providers that FusionAuth uses to reconcile the user's account.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> identityProviderLogin(
      IdentityProviderLoginRequest request) {
    return _startAnonymous<LoginResponse, Errors>()
        .withUri('/api/identity-provider/login')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Import an existing RSA or EC key pair or an HMAC secret.
  ///
  /// @param {String} keyId (Optional) The Id for the key. If not provided a secure random UUID will be generated.
  /// @param {KeyRequest} request The request object that contains all the information used to create the key.
  /// @returns {Promise<ClientResponse<KeyResponse>>}
  Future<ClientResponse<KeyResponse, Errors>> importKey(
      String keyId, KeyRequest request) {
    return _start<KeyResponse, Errors>()
        .withUri('/api/key/import')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeyResponse.fromJson(d)))
        .go();
  }

  /// Bulk imports refresh tokens. This request performs minimal validation and runs batch inserts of refresh tokens with the
  /// expectation that each token represents a user that already exists and is registered for the corresponding FusionAuth
  /// Application. This is done to increases the insert performance.
  ///
  /// Therefore, if you encounter an error due to a database key violation, the response will likely offer a generic
  /// explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
  /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of
  /// the failure. See the validateDbConstraints request parameter.
  ///
  /// @param {RefreshTokenImportRequest} request The request that contains all the information about all the refresh tokens to import.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> importRefreshTokens(
      RefreshTokenImportRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/refresh-token/import')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Bulk imports users. This request performs minimal validation and runs batch inserts of users with the expectation
  /// that each user does not yet exist and each registration corresponds to an existing FusionAuth Application. This is done to
  /// increases the insert performance.
  ///
  /// Therefore, if you encounter an error due to a database key violation, the response will likely offer
  /// a generic explanation. If you encounter an error, you may optionally enable additional validation to receive a JSON response
  /// body with specific validation errors. This will slow the request down but will allow you to identify the cause of the failure. See
  /// the validateDbConstraints request parameter.
  ///
  /// @param {ImportRequest} request The request that contains all the information about all the users to import.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> importUsers(ImportRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/import')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Import a WebAuthn credential
  ///
  /// @param {WebAuthnCredentialImportRequest} request An object containing data necessary for importing the credential
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> importWebAuthnCredential(
      WebAuthnCredentialImportRequest request) {
    return _start<void, Errors>()
        .withUri('/api/webauthn/import')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Inspect an access token issued as the result of the User based grant such as the Authorization Code Grant, Implicit Grant, the User Credentials Grant or the Refresh Grant.
  ///
  /// @param {String} client_id The unique client identifier. The client Id is the Id of the FusionAuth Application for which this token was generated.
  /// @param {String} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
  /// @returns {Promise<ClientResponse<Map<String, dynamic>>>}
  Future<ClientResponse<Map<String, dynamic>, OAuthError>>
      introspectAccessToken(String client_id, String token) {
    var body = Map<String, dynamic>();
    body['client_id'] = client_id;
    body['token'] = token;
    return _startAnonymous<Map<String, dynamic>, OAuthError>()
        .withUri('/oauth2/introspect')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => Map<String, dynamic>.fromJson(d)))
        .go();
  }

  /// Inspect an access token issued as the result of the Client Credentials Grant.
  ///
  /// @param {String} token The access token returned by this OAuth provider as the result of a successful client credentials grant.
  /// @returns {Promise<ClientResponse<Map<String, dynamic>>>}
  Future<ClientResponse<Map<String, dynamic>, OAuthError>>
      introspectClientCredentialsAccessToken(String token) {
    var body = Map<String, dynamic>();
    body['token'] = token;
    return _startAnonymous<Map<String, dynamic>, OAuthError>()
        .withUri('/oauth2/introspect')
        .withFormData(body)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => Map<String, dynamic>.fromJson(d)))
        .go();
  }

  /// Issue a new access token (JWT) for the requested Application after ensuring the provided JWT is valid. A valid
  /// access token is properly signed and not expired.
  /// <p>
  /// This API may be used in an SSO configuration to issue new tokens for another application after the user has
  /// obtained a valid token from authentication.
  ///
  /// @param {String} applicationId The Application Id for which you are requesting a new access token be issued.
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @param {String} refreshToken (Optional) An existing refresh token used to request a refresh token in addition to a JWT in the response.
  ///    <p>The target application represented by the applicationId request parameter must have refresh
  ///    tokens enabled in order to receive a refresh token in the response.</p>
  /// @returns {Promise<ClientResponse<IssueResponse>>}
  Future<ClientResponse<IssueResponse, Errors>> issueJWT(
      String applicationId, String encodedJWT, String refreshToken) {
    return _startAnonymous<IssueResponse, Errors>()
        .withUri('/api/jwt/issue')
        .withAuthorization('Bearer ' + encodedJWT)
        .withParameter('applicationId', applicationId)
        .withParameter('refreshToken', refreshToken)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => IssueResponse.fromJson(d)))
        .go();
  }

  /// Authenticates a user to FusionAuth.
  ///
  /// This API optionally requires an API key. See <code>Application.loginConfiguration.requireAuthentication</code>.
  ///
  /// @param {LoginRequest} request The login request that contains the user credentials used to log them in.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> login(LoginRequest request) {
    return _start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
  /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
  /// application where they no longer have a session. This helps correctly track login counts, times and helps with
  /// reporting.
  ///
  /// @param {String} userId The Id of the user that was logged in.
  /// @param {String} applicationId The Id of the application that they logged into.
  /// @param {String} callerIPAddress (Optional) The IP address of the end-user that is logging in. If a null value is provided
  ///    the IP address will be that of the client or last proxy that sent the request.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> loginPing(
      String userId, String applicationId, String callerIPAddress) {
    return _start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withParameter('ipAddress', callerIPAddress)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Sends a ping to FusionAuth indicating that the user was automatically logged into an application. When using
  /// FusionAuth's SSO or your own, you should call this if the user is already logged in centrally, but accesses an
  /// application where they no longer have a session. This helps correctly track login counts, times and helps with
  /// reporting.
  ///
  /// @param {LoginPingRequest} request The login request that contains the user credentials used to log them in.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> loginPingWithRequest(
      LoginPingRequest request) {
    return _start<LoginResponse, Errors>()
        .withUri('/api/login')
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
  /// client and revoke the refresh token stored. This API does nothing if the request does not contain an access
  /// token or refresh token cookies.
  ///
  /// @param {bool} global When this value is set to true all the refresh tokens issued to the owner of the
  ///    provided token will be revoked.
  /// @param {String} refreshToken (Optional) The refresh_token as a request parameter instead of coming in via a cookie.
  ///    If provided this takes precedence over the cookie.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> logout(bool global, String refreshToken) {
    return _startAnonymous<void, void>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/logout')
        .withParameter('global', global)
        .withParameter('refreshToken', refreshToken)
        .withMethod('POST')
        .go();
  }

  /// The Logout API is intended to be used to remove the refresh token and access token cookies if they exist on the
  /// client and revoke the refresh token stored. This API takes the refresh token in the JSON body.
  ///
  /// @param {LogoutRequest} request The request object that contains all the information used to logout the user.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> logoutWithRequest(LogoutRequest request) {
    return _startAnonymous<void, void>()
        .withUri('/api/logout')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Retrieves the identity provider for the given domain. A 200 response code indicates the domain is managed
  /// by a registered identity provider. A 404 indicates the domain is not managed.
  ///
  /// @param {String} domain The domain or email address to lookup.
  /// @returns {Promise<ClientResponse<LookupResponse>>}
  Future<ClientResponse<LookupResponse, void>> lookupIdentityProvider(
      String domain) {
    return _start<LookupResponse, void>()
        .withUri('/api/identity-provider/lookup')
        .withParameter('domain', domain)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LookupResponse.fromJson(d)))
        .go();
  }

  /// Modifies a temporal user action by changing the expiration of the action and optionally adding a comment to the
  /// action.
  ///
  /// @param {String} actionId The Id of the action to modify. This is technically the user action log id.
  /// @param {ActionRequest} request The request that contains all the information about the modification.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> modifyAction(
      String actionId, ActionRequest request) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Complete a login request using a passwordless code
  ///
  /// @param {PasswordlessLoginRequest} request The passwordless login request that contains all the information used to complete login.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> passwordlessLogin(
      PasswordlessLoginRequest request) {
    return _startAnonymous<LoginResponse, Errors>()
        .withUri('/api/passwordless/login')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Updates an authentication API key by given id
  ///
  /// @param {String} keyId The Id of the authentication key. If not provided a secure random api key will be generated.
  /// @param {APIKeyRequest} request The request object that contains all the information needed to create the APIKey.
  /// @returns {Promise<ClientResponse<APIKeyResponse>>}
  Future<ClientResponse<APIKeyResponse, Errors>> patchAPIKey(
      String keyId, APIKeyRequest request) {
    return _start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => APIKeyResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the application with the given Id.
  ///
  /// @param {String} applicationId The Id of the application to update.
  /// @param {ApplicationRequest} request The request that contains just the new application information.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> patchApplication(
      String applicationId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the application role with the given id for the application.
  ///
  /// @param {String} applicationId The Id of the application that the role belongs to.
  /// @param {String} roleId The Id of the role to update.
  /// @param {ApplicationRequest} request The request that contains just the new role information.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> patchApplicationRole(
      String applicationId, String roleId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the connector with the given Id.
  ///
  /// @param {String} connectorId The Id of the connector to update.
  /// @param {ConnectorRequest} request The request that contains just the new connector information.
  /// @returns {Promise<ClientResponse<ConnectorResponse>>}
  Future<ClientResponse<ConnectorResponse, Errors>> patchConnector(
      String connectorId, ConnectorRequest request) {
    return _start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConnectorResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the consent with the given Id.
  ///
  /// @param {String} consentId The Id of the consent to update.
  /// @param {ConsentRequest} request The request that contains just the new consent information.
  /// @returns {Promise<ClientResponse<ConsentResponse>>}
  Future<ClientResponse<ConsentResponse, Errors>> patchConsent(
      String consentId, ConsentRequest request) {
    return _start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConsentResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the email template with the given Id.
  ///
  /// @param {String} emailTemplateId The Id of the email template to update.
  /// @param {EmailTemplateRequest} request The request that contains just the new email template information.
  /// @returns {Promise<ClientResponse<EmailTemplateResponse>>}
  Future<ClientResponse<EmailTemplateResponse, Errors>> patchEmailTemplate(
      String emailTemplateId, EmailTemplateRequest request) {
    return _start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the Entity Type with the given Id.
  ///
  /// @param {String} entityTypeId The Id of the Entity Type to update.
  /// @param {EntityTypeRequest} request The request that contains just the new Entity Type information.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> patchEntityType(
      String entityTypeId, EntityTypeRequest request) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the group with the given Id.
  ///
  /// @param {String} groupId The Id of the group to update.
  /// @param {GroupRequest} request The request that contains just the new group information.
  /// @returns {Promise<ClientResponse<GroupResponse>>}
  Future<ClientResponse<GroupResponse, Errors>> patchGroup(
      String groupId, GroupRequest request) {
    return _start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => GroupResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the identity provider with the given Id.
  ///
  /// @param {String} identityProviderId The Id of the identity provider to update.
  /// @param {IdentityProviderRequest} request The request object that contains just the updated identity provider information.
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, Errors>>
      patchIdentityProvider(
          String identityProviderId, IdentityProviderRequest request) {
    return _start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the available integrations.
  ///
  /// @param {IntegrationRequest} request The request that contains just the new integration information.
  /// @returns {Promise<ClientResponse<IntegrationResponse>>}
  Future<ClientResponse<IntegrationResponse, Errors>> patchIntegrations(
      IntegrationRequest request) {
    return _start<IntegrationResponse, Errors>()
        .withUri('/api/integration')
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IntegrationResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the lambda with the given Id.
  ///
  /// @param {String} lambdaId The Id of the lambda to update.
  /// @param {LambdaRequest} request The request that contains just the new lambda information.
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, Errors>> patchLambda(
      String lambdaId, LambdaRequest request) {
    return _start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the message template with the given Id.
  ///
  /// @param {String} messageTemplateId The Id of the message template to update.
  /// @param {MessageTemplateRequest} request The request that contains just the new message template information.
  /// @returns {Promise<ClientResponse<MessageTemplateResponse>>}
  Future<ClientResponse<MessageTemplateResponse, Errors>> patchMessageTemplate(
      String messageTemplateId, MessageTemplateRequest request) {
    return _start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the messenger with the given Id.
  ///
  /// @param {String} messengerId The Id of the messenger to update.
  /// @param {MessengerRequest} request The request that contains just the new messenger information.
  /// @returns {Promise<ClientResponse<MessengerResponse>>}
  Future<ClientResponse<MessengerResponse, Errors>> patchMessenger(
      String messengerId, MessengerRequest request) {
    return _start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MessengerResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the registration for the user with the given id and the application defined in the request.
  ///
  /// @param {String} userId The Id of the user whose registration is going to be updated.
  /// @param {RegistrationRequest} request The request that contains just the new registration information.
  /// @returns {Promise<ClientResponse<RegistrationResponse>>}
  Future<ClientResponse<RegistrationResponse, Errors>> patchRegistration(
      String userId, RegistrationRequest request) {
    return _start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RegistrationResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the system configuration.
  ///
  /// @param {SystemConfigurationRequest} request The request that contains just the new system configuration information.
  /// @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
  Future<ClientResponse<SystemConfigurationResponse, Errors>>
      patchSystemConfiguration(SystemConfigurationRequest request) {
    return _start<SystemConfigurationResponse, Errors>()
        .withUri('/api/system-configuration')
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => SystemConfigurationResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the tenant with the given Id.
  ///
  /// @param {String} tenantId The Id of the tenant to update.
  /// @param {TenantRequest} request The request that contains just the new tenant information.
  /// @returns {Promise<ClientResponse<TenantResponse>>}
  Future<ClientResponse<TenantResponse, Errors>> patchTenant(
      String tenantId, TenantRequest request) {
    return _start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TenantResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the theme with the given Id.
  ///
  /// @param {String} themeId The Id of the theme to update.
  /// @param {ThemeRequest} request The request that contains just the new theme information.
  /// @returns {Promise<ClientResponse<ThemeResponse>>}
  Future<ClientResponse<ThemeResponse, Errors>> patchTheme(
      String themeId, ThemeRequest request) {
    return _start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ThemeResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the user with the given Id.
  ///
  /// @param {String} userId The Id of the user to update.
  /// @param {UserRequest} request The request that contains just the new user information.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> patchUser(
      String userId, UserRequest request) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the user action with the given Id.
  ///
  /// @param {String} userActionId The Id of the user action to update.
  /// @param {UserActionRequest} request The request that contains just the new user action information.
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, Errors>> patchUserAction(
      String userActionId, UserActionRequest request) {
    return _start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, the user action reason with the given Id.
  ///
  /// @param {String} userActionReasonId The Id of the user action reason to update.
  /// @param {UserActionReasonRequest} request The request that contains just the new user action reason information.
  /// @returns {Promise<ClientResponse<UserActionReasonResponse>>}
  Future<ClientResponse<UserActionReasonResponse, Errors>>
      patchUserActionReason(
          String userActionReasonId, UserActionReasonRequest request) {
    return _start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionReasonResponse.fromJson(d)))
        .go();
  }

  /// Updates, via PATCH, a single User consent by Id.
  ///
  /// @param {String} userConsentId The User Consent Id
  /// @param {UserConsentRequest} request The request that contains just the new user consent information.
  /// @returns {Promise<ClientResponse<UserConsentResponse>>}
  Future<ClientResponse<UserConsentResponse, Errors>> patchUserConsent(
      String userConsentId, UserConsentRequest request) {
    return _start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod('PATCH')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserConsentResponse.fromJson(d)))
        .go();
  }

  /// Reactivates the application with the given Id.
  ///
  /// @param {String} applicationId The Id of the application to reactivate.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> reactivateApplication(
      String applicationId) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withParameter('reactivate', true)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Reactivates the user with the given Id.
  ///
  /// @param {String} userId The Id of the user to reactivate.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> reactivateUser(String userId) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withParameter('reactivate', true)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Reactivates the user action with the given Id.
  ///
  /// @param {String} userActionId The Id of the user action to reactivate.
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, Errors>> reactivateUserAction(
      String userActionId) {
    return _start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withParameter('reactivate', true)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Reconcile a User to FusionAuth using JWT issued from another Identity Provider.
  ///
  /// @param {IdentityProviderLoginRequest} request The reconcile request that contains the data to reconcile the User.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> reconcileJWT(
      IdentityProviderLoginRequest request) {
    return _startAnonymous<LoginResponse, Errors>()
        .withUri('/api/jwt/reconcile')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Request a refresh of the Entity search index. This API is not generally necessary and the search index will become consistent in a
  /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
  /// if you are using the Search API or Delete Tenant API immediately following a Entity Create etc, you may wish to request a refresh to
  ///  ensure the index immediately current before making a query request to the search index.
  ///
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> refreshEntitySearchIndex() {
    return _start<void, void>()
        .withUri('/api/entity/search')
        .withMethod('PUT')
        .go();
  }

  /// Request a refresh of the User search index. This API is not generally necessary and the search index will become consistent in a
  /// reasonable amount of time. There may be scenarios where you may wish to manually request an index refresh. One example may be
  /// if you are using the Search API or Delete Tenant API immediately following a User Create etc, you may wish to request a refresh to
  ///  ensure the index immediately current before making a query request to the search index.
  ///
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> refreshUserSearchIndex() {
    return _start<void, void>()
        .withUri('/api/user/search')
        .withMethod('PUT')
        .go();
  }

  /// Regenerates any keys that are used by the FusionAuth Reactor.
  ///
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> regenerateReactorKeys() {
    return _start<void, void>().withUri('/api/reactor').withMethod('PUT').go();
  }

  /// Registers a user for an application. If you provide the User and the UserRegistration object on this request, it
  /// will create the user as well as register them for the application. This is called a Full Registration. However, if
  /// you only provide the UserRegistration object, then the user must already exist and they will be registered for the
  /// application. The user id can also be provided and it will either be used to look up an existing user or it will be
  /// used for the newly created User.
  ///
  /// @param {String} userId (Optional) The Id of the user being registered for the application and optionally created.
  /// @param {RegistrationRequest} request The request that optionally contains the User and must contain the UserRegistration.
  /// @returns {Promise<ClientResponse<RegistrationResponse>>}
  Future<ClientResponse<RegistrationResponse, Errors>> register(
      String userId, RegistrationRequest request) {
    return _start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RegistrationResponse.fromJson(d)))
        .go();
  }

  /// Requests Elasticsearch to delete and rebuild the index for FusionAuth users or entities. Be very careful when running this request as it will
  /// increase the CPU and I/O load on your database until the operation completes. Generally speaking you do not ever need to run this operation unless
  /// instructed by FusionAuth support, or if you are migrating a database another system and you are not brining along the Elasticsearch index.
  ///
  /// You have been warned.
  ///
  /// @param {ReindexRequest} request The request that contains the index name.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> reindex(ReindexRequest request) {
    return _start<void, Errors>()
        .withUri('/api/system/reindex')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Removes a user from the family with the given id.
  ///
  /// @param {String} familyId The id of the family to remove the user from.
  /// @param {String} userId The id of the user to remove from the family.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> removeUserFromFamily(
      String familyId, String userId) {
    return _start<void, Errors>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withUriSegment(userId)
        .withMethod('DELETE')
        .go();
  }

  /// Re-sends the verification email to the user.
  ///
  /// @param {String} email The email address of the user that needs a new verification email.
  /// @returns {Promise<ClientResponse<VerifyEmailResponse>>}
  Future<ClientResponse<VerifyEmailResponse, Errors>> resendEmailVerification(
      String email) {
    return _start<VerifyEmailResponse, Errors>()
        .withUri('/api/user/verify-email')
        .withParameter('email', email)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => VerifyEmailResponse.fromJson(d)))
        .go();
  }

  /// Re-sends the verification email to the user. If the Application has configured a specific email template this will be used
  /// instead of the tenant configuration.
  ///
  /// @param {String} applicationId The unique Application Id to used to resolve an application specific email template.
  /// @param {String} email The email address of the user that needs a new verification email.
  /// @returns {Promise<ClientResponse<VerifyEmailResponse>>}
  Future<ClientResponse<VerifyEmailResponse, Errors>>
      resendEmailVerificationWithApplicationTemplate(
          String applicationId, String email) {
    return _start<VerifyEmailResponse, Errors>()
        .withUri('/api/user/verify-email')
        .withParameter('applicationId', applicationId)
        .withParameter('email', email)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => VerifyEmailResponse.fromJson(d)))
        .go();
  }

  /// Re-sends the application registration verification email to the user.
  ///
  /// @param {String} email The email address of the user that needs a new verification email.
  /// @param {String} applicationId The Id of the application to be verified.
  /// @returns {Promise<ClientResponse<VerifyRegistrationResponse>>}
  Future<ClientResponse<VerifyRegistrationResponse, Errors>>
      resendRegistrationVerification(String email, String applicationId) {
    return _start<VerifyRegistrationResponse, Errors>()
        .withUri('/api/user/verify-registration')
        .withParameter('email', email)
        .withParameter('applicationId', applicationId)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => VerifyRegistrationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves an authentication API key for the given id
  ///
  /// @param {String} keyId The Id of the API key to retrieve.
  /// @returns {Promise<ClientResponse<APIKeyResponse>>}
  Future<ClientResponse<APIKeyResponse, Errors>> retrieveAPIKey(String keyId) {
    return _start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(keyId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => APIKeyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves a single action log (the log of a user action that was taken on a user previously) for the given Id.
  ///
  /// @param {String} actionId The Id of the action to retrieve.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> retrieveAction(
      String actionId) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withUriSegment(actionId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the actions for the user with the given Id. This will return all time based actions that are active,
  /// and inactive as well as non-time based actions.
  ///
  /// @param {String} userId The Id of the user to fetch the actions for.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> retrieveActions(
      String userId) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the actions for the user with the given Id that are currently preventing the User from logging in.
  ///
  /// @param {String} userId The Id of the user to fetch the actions for.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> retrieveActionsPreventingLogin(
      String userId) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('preventingLogin', true)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the actions for the user with the given Id that are currently active.
  /// An active action means one that is time based and has not been canceled, and has not ended.
  ///
  /// @param {String} userId The Id of the user to fetch the actions for.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> retrieveActiveActions(
      String userId) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('active', true)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the application for the given id or all the applications if the id is null.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, void>> retrieveApplication(
      String applicationId) {
    return _start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the applications.
  ///
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, void>> retrieveApplications() {
    return _start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves a single audit log for the given Id.
  ///
  /// @param {num} auditLogId The Id of the audit log to retrieve.
  /// @returns {Promise<ClientResponse<AuditLogResponse>>}
  Future<ClientResponse<AuditLogResponse, Errors>> retrieveAuditLog(
      num auditLogId) {
    return _start<AuditLogResponse, Errors>()
        .withUri('/api/system/audit-log')
        .withUriSegment(auditLogId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => AuditLogResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the connector with the given Id.
  ///
  /// @param {String} connectorId The Id of the connector.
  /// @returns {Promise<ClientResponse<ConnectorResponse>>}
  Future<ClientResponse<ConnectorResponse, void>> retrieveConnector(
      String connectorId) {
    return _start<ConnectorResponse, void>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConnectorResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the connectors.
  ///
  /// @returns {Promise<ClientResponse<ConnectorResponse>>}
  Future<ClientResponse<ConnectorResponse, void>> retrieveConnectors() {
    return _start<ConnectorResponse, void>()
        .withUri('/api/connector')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConnectorResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Consent for the given Id.
  ///
  /// @param {String} consentId The Id of the consent.
  /// @returns {Promise<ClientResponse<ConsentResponse>>}
  Future<ClientResponse<ConsentResponse, void>> retrieveConsent(
      String consentId) {
    return _start<ConsentResponse, void>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConsentResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the consent.
  ///
  /// @returns {Promise<ClientResponse<ConsentResponse>>}
  Future<ClientResponse<ConsentResponse, void>> retrieveConsents() {
    return _start<ConsentResponse, void>()
        .withUri('/api/consent')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConsentResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the daily active user report between the two instants. If you specify an application id, it will only
  /// return the daily active counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<DailyActiveUserReportResponse>>}
  Future<ClientResponse<DailyActiveUserReportResponse, Errors>>
      retrieveDailyActiveReport(String applicationId, num start, num end) {
    return _start<DailyActiveUserReportResponse, Errors>()
        .withUri('/api/report/daily-active-user')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => DailyActiveUserReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the email template for the given Id. If you don't specify the id, this will return all the email templates.
  ///
  /// @param {String} emailTemplateId (Optional) The Id of the email template.
  /// @returns {Promise<ClientResponse<EmailTemplateResponse>>}
  Future<ClientResponse<EmailTemplateResponse, void>> retrieveEmailTemplate(
      String emailTemplateId) {
    return _start<EmailTemplateResponse, void>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateResponse.fromJson(d)))
        .go();
  }

  /// Creates a preview of the email template provided in the request. This allows you to preview an email template that
  /// hasn't been saved to the database yet. The entire email template does not need to be provided on the request. This
  /// will create the preview based on whatever is given.
  ///
  /// @param {PreviewRequest} request The request that contains the email template and optionally a locale to render it in.
  /// @returns {Promise<ClientResponse<PreviewResponse>>}
  Future<ClientResponse<PreviewResponse, Errors>> retrieveEmailTemplatePreview(
      PreviewRequest request) {
    return _start<PreviewResponse, Errors>()
        .withUri('/api/email/template/preview')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => PreviewResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the email templates.
  ///
  /// @returns {Promise<ClientResponse<EmailTemplateResponse>>}
  Future<ClientResponse<EmailTemplateResponse, void>> retrieveEmailTemplates() {
    return _start<EmailTemplateResponse, void>()
        .withUri('/api/email/template')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Entity for the given Id.
  ///
  /// @param {String} entityId The Id of the Entity.
  /// @returns {Promise<ClientResponse<EntityResponse>>}
  Future<ClientResponse<EntityResponse, Errors>> retrieveEntity(
      String entityId) {
    return _start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => EntityResponse.fromJson(d)))
        .go();
  }

  /// Retrieves an Entity Grant for the given Entity and User/Entity.
  ///
  /// @param {String} entityId The Id of the Entity.
  /// @param {String} recipientEntityId (Optional) The Id of the Entity that the Entity Grant is for.
  /// @param {String} userId (Optional) The Id of the User that the Entity Grant is for.
  /// @returns {Promise<ClientResponse<EntityGrantResponse>>}
  Future<ClientResponse<EntityGrantResponse, Errors>> retrieveEntityGrant(
      String entityId, String recipientEntityId, String userId) {
    return _start<EntityGrantResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withParameter('recipientEntityId', recipientEntityId)
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityGrantResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Entity Type for the given Id.
  ///
  /// @param {String} entityTypeId The Id of the Entity Type.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> retrieveEntityType(
      String entityTypeId) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the Entity Types.
  ///
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> retrieveEntityTypes() {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Retrieves a single event log for the given Id.
  ///
  /// @param {num} eventLogId The Id of the event log to retrieve.
  /// @returns {Promise<ClientResponse<EventLogResponse>>}
  Future<ClientResponse<EventLogResponse, Errors>> retrieveEventLog(
      num eventLogId) {
    return _start<EventLogResponse, Errors>()
        .withUri('/api/system/event-log')
        .withUriSegment(eventLogId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => EventLogResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the families that a user belongs to.
  ///
  /// @param {String} userId The User's id
  /// @returns {Promise<ClientResponse<FamilyResponse>>}
  Future<ClientResponse<FamilyResponse, void>> retrieveFamilies(String userId) {
    return _start<FamilyResponse, void>()
        .withUri('/api/user/family')
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FamilyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the members of a family by the unique Family Id.
  ///
  /// @param {String} familyId The unique Id of the Family.
  /// @returns {Promise<ClientResponse<FamilyResponse>>}
  Future<ClientResponse<FamilyResponse, void>> retrieveFamilyMembersByFamilyId(
      String familyId) {
    return _start<FamilyResponse, void>()
        .withUri('/api/user/family')
        .withUriSegment(familyId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FamilyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the form with the given Id.
  ///
  /// @param {String} formId The Id of the form.
  /// @returns {Promise<ClientResponse<FormResponse>>}
  Future<ClientResponse<FormResponse, void>> retrieveForm(String formId) {
    return _start<FormResponse, void>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the form field with the given Id.
  ///
  /// @param {String} fieldId The Id of the form field.
  /// @returns {Promise<ClientResponse<FormFieldResponse>>}
  Future<ClientResponse<FormFieldResponse, void>> retrieveFormField(
      String fieldId) {
    return _start<FormFieldResponse, void>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormFieldResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the forms fields
  ///
  /// @returns {Promise<ClientResponse<FormFieldResponse>>}
  Future<ClientResponse<FormFieldResponse, void>> retrieveFormFields() {
    return _start<FormFieldResponse, void>()
        .withUri('/api/form/field')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormFieldResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the forms.
  ///
  /// @returns {Promise<ClientResponse<FormResponse>>}
  Future<ClientResponse<FormResponse, void>> retrieveForms() {
    return _start<FormResponse, void>()
        .withUri('/api/form')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the group for the given Id.
  ///
  /// @param {String} groupId The Id of the group.
  /// @returns {Promise<ClientResponse<GroupResponse>>}
  Future<ClientResponse<GroupResponse, Errors>> retrieveGroup(String groupId) {
    return _start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => GroupResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the groups.
  ///
  /// @returns {Promise<ClientResponse<GroupResponse>>}
  Future<ClientResponse<GroupResponse, void>> retrieveGroups() {
    return _start<GroupResponse, void>()
        .withUri('/api/group')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => GroupResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the IP Access Control List with the given Id.
  ///
  /// @param {String} ipAccessControlListId The Id of the IP Access Control List.
  /// @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
  Future<ClientResponse<IPAccessControlListResponse, void>>
      retrieveIPAccessControlList(String ipAccessControlListId) {
    return _start<IPAccessControlListResponse, void>()
        .withUri('/api/ip-acl')
        .withUriSegment(ipAccessControlListId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IPAccessControlListResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the identity provider for the given id or all the identity providers if the id is null.
  ///
  /// @param {String} identityProviderId The identity provider Id.
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, Errors>>
      retrieveIdentityProvider(String identityProviderId) {
    return _start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Retrieves one or more identity provider for the given type. For types such as Google, Facebook, Twitter and LinkedIn, only a single
  /// identity provider can exist. For types such as OpenID Connect and SAMLv2 more than one identity provider can be configured so this request
  /// may return multiple identity providers.
  ///
  /// @param {IdentityProviderType} type The type of the identity provider.
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, Errors>>
      retrieveIdentityProviderByType(IdentityProviderType type) {
    return _start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withParameter('type', type)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the identity providers.
  ///
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, void>>
      retrieveIdentityProviders() {
    return _start<IdentityProviderResponse, void>()
        .withUri('/api/identity-provider')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the actions for the user with the given Id that are currently inactive.
  /// An inactive action means one that is time based and has been canceled or has expired, or is not time based.
  ///
  /// @param {String} userId The Id of the user to fetch the actions for.
  /// @returns {Promise<ClientResponse<ActionResponse>>}
  Future<ClientResponse<ActionResponse, Errors>> retrieveInactiveActions(
      String userId) {
    return _start<ActionResponse, Errors>()
        .withUri('/api/user/action')
        .withParameter('userId', userId)
        .withParameter('active', false)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the applications that are currently inactive.
  ///
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, void>>
      retrieveInactiveApplications() {
    return _start<ApplicationResponse, void>()
        .withUri('/api/application')
        .withParameter('inactive', true)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the user actions that are currently inactive.
  ///
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, void>>
      retrieveInactiveUserActions() {
    return _start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withParameter('inactive', true)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the available integrations.
  ///
  /// @returns {Promise<ClientResponse<IntegrationResponse>>}
  Future<ClientResponse<IntegrationResponse, void>> retrieveIntegration() {
    return _start<IntegrationResponse, void>()
        .withUri('/api/integration')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IntegrationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Public Key configured for verifying JSON Web Tokens (JWT) by the key Id (kid).
  ///
  /// @param {String} keyId The Id of the public key (kid).
  /// @returns {Promise<ClientResponse<PublicKeyResponse>>}
  Future<ClientResponse<PublicKeyResponse, void>> retrieveJWTPublicKey(
      String keyId) {
    return _startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withParameter('kid', keyId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => PublicKeyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Public Key configured for verifying the JSON Web Tokens (JWT) issued by the Login API by the Application Id.
  ///
  /// @param {String} applicationId The Id of the Application for which this key is used.
  /// @returns {Promise<ClientResponse<PublicKeyResponse>>}
  Future<ClientResponse<PublicKeyResponse, void>>
      retrieveJWTPublicKeyByApplicationId(String applicationId) {
    return _startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withParameter('applicationId', applicationId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => PublicKeyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all Public Keys configured for verifying JSON Web Tokens (JWT).
  ///
  /// @returns {Promise<ClientResponse<PublicKeyResponse>>}
  Future<ClientResponse<PublicKeyResponse, void>> retrieveJWTPublicKeys() {
    return _startAnonymous<PublicKeyResponse, void>()
        .withUri('/api/jwt/public-key')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => PublicKeyResponse.fromJson(d)))
        .go();
  }

  /// Returns public keys used by FusionAuth to cryptographically verify JWTs using the JSON Web Key format.
  ///
  /// @returns {Promise<ClientResponse<JWKSResponse>>}
  Future<ClientResponse<JWKSResponse, void>> retrieveJsonWebKeySet() {
    return _startAnonymous<JWKSResponse, void>()
        .withUri('/.well-known/jwks.json')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => JWKSResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the key for the given Id.
  ///
  /// @param {String} keyId The Id of the key.
  /// @returns {Promise<ClientResponse<KeyResponse>>}
  Future<ClientResponse<KeyResponse, Errors>> retrieveKey(String keyId) {
    return _start<KeyResponse, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the keys.
  ///
  /// @returns {Promise<ClientResponse<KeyResponse>>}
  Future<ClientResponse<KeyResponse, void>> retrieveKeys() {
    return _start<KeyResponse, void>()
        .withUri('/api/key')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeyResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the lambda for the given Id.
  ///
  /// @param {String} lambdaId The Id of the lambda.
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, Errors>> retrieveLambda(
      String lambdaId) {
    return _start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the lambdas.
  ///
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, void>> retrieveLambdas() {
    return _start<LambdaResponse, void>()
        .withUri('/api/lambda')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the lambdas for the provided type.
  ///
  /// @param {LambdaType} type The type of the lambda to return.
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, void>> retrieveLambdasByType(
      LambdaType type) {
    return _start<LambdaResponse, void>()
        .withUri('/api/lambda')
        .withParameter('type', type)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the login report between the two instants. If you specify an application id, it will only return the
  /// login counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<LoginReportResponse>>}
  Future<ClientResponse<LoginReportResponse, Errors>> retrieveLoginReport(
      String applicationId, num start, num end) {
    return _start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => LoginReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the message template for the given Id. If you don't specify the id, this will return all the message templates.
  ///
  /// @param {String} messageTemplateId (Optional) The Id of the message template.
  /// @returns {Promise<ClientResponse<MessageTemplateResponse>>}
  Future<ClientResponse<MessageTemplateResponse, void>> retrieveMessageTemplate(
      String messageTemplateId) {
    return _start<MessageTemplateResponse, void>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Creates a preview of the message template provided in the request, normalized to a given locale.
  ///
  /// @param {PreviewMessageTemplateRequest} request The request that contains the email template and optionally a locale to render it in.
  /// @returns {Promise<ClientResponse<PreviewMessageTemplateResponse>>}
  Future<ClientResponse<PreviewMessageTemplateResponse, Errors>>
      retrieveMessageTemplatePreview(PreviewMessageTemplateRequest request) {
    return _start<PreviewMessageTemplateResponse, Errors>()
        .withUri('/api/message/template/preview')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => PreviewMessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the message templates.
  ///
  /// @returns {Promise<ClientResponse<MessageTemplateResponse>>}
  Future<ClientResponse<MessageTemplateResponse, void>>
      retrieveMessageTemplates() {
    return _start<MessageTemplateResponse, void>()
        .withUri('/api/message/template')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the messenger with the given Id.
  ///
  /// @param {String} messengerId The Id of the messenger.
  /// @returns {Promise<ClientResponse<MessengerResponse>>}
  Future<ClientResponse<MessengerResponse, void>> retrieveMessenger(
      String messengerId) {
    return _start<MessengerResponse, void>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MessengerResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the messengers.
  ///
  /// @returns {Promise<ClientResponse<MessengerResponse>>}
  Future<ClientResponse<MessengerResponse, void>> retrieveMessengers() {
    return _start<MessengerResponse, void>()
        .withUri('/api/messenger')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MessengerResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the monthly active user report between the two instants. If you specify an application id, it will only
  /// return the monthly active counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<MonthlyActiveUserReportResponse>>}
  Future<ClientResponse<MonthlyActiveUserReportResponse, Errors>>
      retrieveMonthlyActiveReport(String applicationId, num start, num end) {
    return _start<MonthlyActiveUserReportResponse, Errors>()
        .withUri('/api/report/monthly-active-user')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MonthlyActiveUserReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the Oauth2 configuration for the application for the given Application Id.
  ///
  /// @param {String} applicationId The Id of the Application to retrieve OAuth configuration.
  /// @returns {Promise<ClientResponse<OAuthConfigurationResponse>>}
  Future<ClientResponse<OAuthConfigurationResponse, Errors>>
      retrieveOauthConfiguration(String applicationId) {
    return _start<OAuthConfigurationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("oauth-configuration")
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => OAuthConfigurationResponse.fromJson(d)))
        .go();
  }

  /// Returns the well known OpenID Configuration JSON document
  ///
  /// @returns {Promise<ClientResponse<OpenIdConfiguration>>}
  Future<ClientResponse<OpenIdConfiguration, void>>
      retrieveOpenIdConfiguration() {
    return _startAnonymous<OpenIdConfiguration, void>()
        .withUri('/.well-known/openid-configuration')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => OpenIdConfiguration.fromJson(d)))
        .go();
  }

  /// Retrieves the password validation rules for a specific tenant. This method requires a tenantId to be provided
  /// through the use of a Tenant scoped API key or an HTTP header X-FusionAuth-TenantId to specify the Tenant Id.
  ///
  /// This API does not require an API key.
  ///
  /// @returns {Promise<ClientResponse<PasswordValidationRulesResponse>>}
  Future<ClientResponse<PasswordValidationRulesResponse, void>>
      retrievePasswordValidationRules() {
    return _startAnonymous<PasswordValidationRulesResponse, void>()
        .withUri('/api/tenant/password-validation-rules')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => PasswordValidationRulesResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the password validation rules for a specific tenant.
  ///
  /// This API does not require an API key.
  ///
  /// @param {String} tenantId The Id of the tenant.
  /// @returns {Promise<ClientResponse<PasswordValidationRulesResponse>>}
  Future<ClientResponse<PasswordValidationRulesResponse, void>>
      retrievePasswordValidationRulesWithTenantId(String tenantId) {
    return _startAnonymous<PasswordValidationRulesResponse, void>()
        .withUri('/api/tenant/password-validation-rules')
        .withUriSegment(tenantId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => PasswordValidationRulesResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the children for the given parent email address.
  ///
  /// @param {String} parentEmail The email of the parent.
  /// @returns {Promise<ClientResponse<PendingResponse>>}
  Future<ClientResponse<PendingResponse, Errors>> retrievePendingChildren(
      String parentEmail) {
    return _start<PendingResponse, Errors>()
        .withUri('/api/user/family/pending')
        .withParameter('parentEmail', parentEmail)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => PendingResponse.fromJson(d)))
        .go();
  }

  /// Retrieve a pending identity provider link. This is useful to validate a pending link and retrieve meta-data about the identity provider link.
  ///
  /// @param {String} pendingLinkId The pending link Id.
  /// @param {String} userId The optional userId. When provided additional meta-data will be provided to identify how many links if any the user already has.
  /// @returns {Promise<ClientResponse<IdentityProviderPendingLinkResponse>>}
  Future<ClientResponse<IdentityProviderPendingLinkResponse, Errors>>
      retrievePendingLink(String pendingLinkId, String userId) {
    return _start<IdentityProviderPendingLinkResponse, Errors>()
        .withUri('/api/identity-provider/link/pending')
        .withUriSegment(pendingLinkId)
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderPendingLinkResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the FusionAuth Reactor metrics.
  ///
  /// @returns {Promise<ClientResponse<ReactorMetricsResponse>>}
  Future<ClientResponse<ReactorMetricsResponse, void>>
      retrieveReactorMetrics() {
    return _start<ReactorMetricsResponse, void>()
        .withUri('/api/reactor/metrics')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ReactorMetricsResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the FusionAuth Reactor status.
  ///
  /// @returns {Promise<ClientResponse<ReactorResponse>>}
  Future<ClientResponse<ReactorResponse, void>> retrieveReactorStatus() {
    return _start<ReactorResponse, void>()
        .withUri('/api/reactor')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ReactorResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the last number of login records.
  ///
  /// @param {num} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
  /// @param {num} limit (Optional, defaults to 10) The number of records to retrieve.
  /// @returns {Promise<ClientResponse<RecentLoginResponse>>}
  Future<ClientResponse<RecentLoginResponse, Errors>> retrieveRecentLogins(
      num offset, num limit) {
    return _start<RecentLoginResponse, Errors>()
        .withUri('/api/user/recent-login')
        .withParameter('offset', offset)
        .withParameter('limit', limit)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RecentLoginResponse.fromJson(d)))
        .go();
  }

  /// Retrieves a single refresh token by unique Id. This is not the same thing as the string value of the refresh token. If you have that, you already have what you need.
  ///
  /// @param {String} tokenId The Id of the token.
  /// @returns {Promise<ClientResponse<RefreshTokenResponse>>}
  Future<ClientResponse<RefreshTokenResponse, Errors>> retrieveRefreshTokenById(
      String tokenId) {
    return _start<RefreshTokenResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withUriSegment(tokenId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RefreshTokenResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the refresh tokens that belong to the user with the given Id.
  ///
  /// @param {String} userId The Id of the user.
  /// @returns {Promise<ClientResponse<RefreshTokenResponse>>}
  Future<ClientResponse<RefreshTokenResponse, Errors>> retrieveRefreshTokens(
      String userId) {
    return _start<RefreshTokenResponse, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RefreshTokenResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user registration for the user with the given id and the given application id.
  ///
  /// @param {String} userId The Id of the user.
  /// @param {String} applicationId The Id of the application.
  /// @returns {Promise<ClientResponse<RegistrationResponse>>}
  Future<ClientResponse<RegistrationResponse, Errors>> retrieveRegistration(
      String userId, String applicationId) {
    return _start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withUriSegment(applicationId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RegistrationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the registration report between the two instants. If you specify an application id, it will only return
  /// the registration counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<RegistrationReportResponse>>}
  Future<ClientResponse<RegistrationReportResponse, Errors>>
      retrieveRegistrationReport(String applicationId, num start, num end) {
    return _start<RegistrationReportResponse, Errors>()
        .withUri('/api/report/registration')
        .withParameter('applicationId', applicationId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RegistrationReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieve the status of a re-index process. A status code of 200 indicates the re-index is in progress, a status code of
  /// 404 indicates no re-index is in progress.
  ///
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> retrieveReindexStatus() {
    return _start<void, Errors>()
        .withUri('/api/system/reindex')
        .withMethod('GET')
        .go();
  }

  /// Retrieves the system configuration.
  ///
  /// @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
  Future<ClientResponse<SystemConfigurationResponse, void>>
      retrieveSystemConfiguration() {
    return _start<SystemConfigurationResponse, void>()
        .withUri('/api/system-configuration')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => SystemConfigurationResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the tenant for the given Id.
  ///
  /// @param {String} tenantId The Id of the tenant.
  /// @returns {Promise<ClientResponse<TenantResponse>>}
  Future<ClientResponse<TenantResponse, Errors>> retrieveTenant(
      String tenantId) {
    return _start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TenantResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the tenants.
  ///
  /// @returns {Promise<ClientResponse<TenantResponse>>}
  Future<ClientResponse<TenantResponse, void>> retrieveTenants() {
    return _start<TenantResponse, void>()
        .withUri('/api/tenant')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TenantResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the theme for the given Id.
  ///
  /// @param {String} themeId The Id of the theme.
  /// @returns {Promise<ClientResponse<ThemeResponse>>}
  Future<ClientResponse<ThemeResponse, Errors>> retrieveTheme(String themeId) {
    return _start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ThemeResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the themes.
  ///
  /// @returns {Promise<ClientResponse<ThemeResponse>>}
  Future<ClientResponse<ThemeResponse, void>> retrieveThemes() {
    return _start<ThemeResponse, void>()
        .withUri('/api/theme')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ThemeResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the totals report. This contains all the total counts for each application and the global registration
  /// count.
  ///
  /// @returns {Promise<ClientResponse<TotalsReportResponse>>}
  Future<ClientResponse<TotalsReportResponse, void>> retrieveTotalReport() {
    return _start<TotalsReportResponse, void>()
        .withUri('/api/report/totals')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TotalsReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieve two-factor recovery codes for a user.
  ///
  /// @param {String} userId The Id of the user to retrieve Two Factor recovery codes.
  /// @returns {Promise<ClientResponse<TwoFactorRecoveryCodeResponse>>}
  Future<ClientResponse<TwoFactorRecoveryCodeResponse, Errors>>
      retrieveTwoFactorRecoveryCodes(String userId) {
    return _start<TwoFactorRecoveryCodeResponse, Errors>()
        .withUri('/api/user/two-factor/recovery-code')
        .withUriSegment(userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TwoFactorRecoveryCodeResponse.fromJson(d)))
        .go();
  }

  /// Retrieve a user's two-factor status.
  ///
  /// This can be used to see if a user will need to complete a two-factor challenge to complete a login,
  /// and optionally identify the state of the two-factor trust across various applications.
  ///
  /// @param {String} userId The user Id to retrieve the Two-Factor status.
  /// @param {String} applicationId The optional applicationId to verify.
  /// @param {String} twoFactorTrustId The optional two-factor trust Id to verify.
  /// @returns {Promise<ClientResponse<TwoFactorStatusResponse>>}
  Future<ClientResponse<TwoFactorStatusResponse, Errors>>
      retrieveTwoFactorStatus(
          String userId, String applicationId, String twoFactorTrustId) {
    return _start<TwoFactorStatusResponse, Errors>()
        .withUri('/api/two-factor/status')
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withUriSegment(twoFactorTrustId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TwoFactorStatusResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user for the given Id.
  ///
  /// @param {String} userId The Id of the user.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUser(String userId) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user action for the given Id. If you pass in null for the id, this will return all the user
  /// actions.
  ///
  /// @param {String} userActionId (Optional) The Id of the user action.
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, void>> retrieveUserAction(
      String userActionId) {
    return _start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user action reason for the given Id. If you pass in null for the id, this will return all the user
  /// action reasons.
  ///
  /// @param {String} userActionReasonId (Optional) The Id of the user action reason.
  /// @returns {Promise<ClientResponse<UserActionReasonResponse>>}
  Future<ClientResponse<UserActionReasonResponse, void>>
      retrieveUserActionReason(String userActionReasonId) {
    return _start<UserActionReasonResponse, void>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionReasonResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the user action reasons.
  ///
  /// @returns {Promise<ClientResponse<UserActionReasonResponse>>}
  Future<ClientResponse<UserActionReasonResponse, void>>
      retrieveUserActionReasons() {
    return _start<UserActionReasonResponse, void>()
        .withUri('/api/user-action-reason')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionReasonResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the user actions.
  ///
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, void>> retrieveUserActions() {
    return _start<UserActionResponse, void>()
        .withUri('/api/user-action')
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user by a change password Id. The intended use of this API is to retrieve a user after the forgot
  /// password workflow has been initiated and you may not know the user's email or username.
  ///
  /// @param {String} changePasswordId The unique change password Id that was sent via email or returned by the Forgot Password API.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserByChangePasswordId(
      String changePasswordId) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('changePasswordId', changePasswordId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user for the given email.
  ///
  /// @param {String} email The email of the user.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserByEmail(
      String email) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('email', email)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user for the loginId. The loginId can be either the username or the email.
  ///
  /// @param {String} loginId The email or username of the user.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserByLoginId(
      String loginId) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('loginId', loginId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user for the given username.
  ///
  /// @param {String} username The username of the user.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserByUsername(
      String username) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('username', username)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user by a verificationId. The intended use of this API is to retrieve a user after the forgot
  /// password workflow has been initiated and you may not know the user's email or username.
  ///
  /// @param {String} verificationId The unique verification Id that has been set on the user object.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserByVerificationId(
      String verificationId) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withParameter('verificationId', verificationId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
  ///
  /// This API is useful if you want to build your own login workflow to complete a device grant.
  ///
  /// @param {String} client_id The client id.
  /// @param {String} client_secret The client id.
  /// @param {String} user_code The end-user verification code.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> retrieveUserCode(
      String client_id, String client_secret, String user_code) {
    var body = Map<String, dynamic>();
    body['client_id'] = client_id;
    body['client_secret'] = client_secret;
    body['user_code'] = user_code;
    return _startAnonymous<void, void>()
        .withUri('/oauth2/device/user-code')
        .withFormData(body)
        .withMethod('GET')
        .go();
  }

  /// Retrieve a user_code that is part of an in-progress Device Authorization Grant.
  ///
  /// This API is useful if you want to build your own login workflow to complete a device grant.
  ///
  /// This request will require an API key.
  ///
  /// @param {String} user_code The end-user verification code.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> retrieveUserCode(String user_code) {
    var body = Map<String, dynamic>();
    body['user_code'] = user_code;
    return _startAnonymous<void, void>()
        .withUri('/oauth2/device/user-code')
        .withFormData(body)
        .withMethod('GET')
        .go();
  }

  /// Retrieves all the comments for the user with the given Id.
  ///
  /// @param {String} userId The Id of the user.
  /// @returns {Promise<ClientResponse<UserCommentResponse>>}
  Future<ClientResponse<UserCommentResponse, Errors>> retrieveUserComments(
      String userId) {
    return _start<UserCommentResponse, Errors>()
        .withUri('/api/user/comment')
        .withUriSegment(userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserCommentResponse.fromJson(d)))
        .go();
  }

  /// Retrieve a single User consent by Id.
  ///
  /// @param {String} userConsentId The User consent Id
  /// @returns {Promise<ClientResponse<UserConsentResponse>>}
  Future<ClientResponse<UserConsentResponse, void>> retrieveUserConsent(
      String userConsentId) {
    return _start<UserConsentResponse, void>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserConsentResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the consents for a User.
  ///
  /// @param {String} userId The User's Id
  /// @returns {Promise<ClientResponse<UserConsentResponse>>}
  Future<ClientResponse<UserConsentResponse, void>> retrieveUserConsents(
      String userId) {
    return _start<UserConsentResponse, void>()
        .withUri('/api/user/consent')
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserConsentResponse.fromJson(d)))
        .go();
  }

  /// Call the UserInfo endpoint to retrieve User Claims from the access token issued by FusionAuth.
  ///
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @returns {Promise<ClientResponse<Map<String, dynamic>>>}
  Future<ClientResponse<Map<String, dynamic>, OAuthError>>
      retrieveUserInfoFromAccessToken(String encodedJWT) {
    return _startAnonymous<Map<String, dynamic>, OAuthError>()
        .withUri('/oauth2/userinfo')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => Map<String, dynamic>.fromJson(d)))
        .go();
  }

  /// Retrieve a single Identity Provider user (link).
  ///
  /// @param {String} identityProviderId The unique Id of the identity provider.
  /// @param {String} identityProviderUserId The unique Id of the user in the 3rd party identity provider.
  /// @param {String} userId The unique Id of the FusionAuth user.
  /// @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
  Future<ClientResponse<IdentityProviderLinkResponse, Errors>> retrieveUserLink(
      String identityProviderId, String identityProviderUserId, String userId) {
    return _start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('identityProviderUserId', identityProviderUserId)
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderLinkResponse.fromJson(d)))
        .go();
  }

  /// Retrieve all Identity Provider users (links) for the user. Specify the optional identityProviderId to retrieve links for a particular IdP.
  ///
  /// @param {String} identityProviderId (Optional) The unique Id of the identity provider. Specify this value to reduce the links returned to those for a particular IdP.
  /// @param {String} userId The unique Id of the user.
  /// @returns {Promise<ClientResponse<IdentityProviderLinkResponse>>}
  Future<ClientResponse<IdentityProviderLinkResponse, Errors>>
      retrieveUserLinksByUserId(String identityProviderId, String userId) {
    return _start<IdentityProviderLinkResponse, Errors>()
        .withUri('/api/identity-provider/link')
        .withParameter('identityProviderId', identityProviderId)
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderLinkResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the login report between the two instants for a particular user by Id. If you specify an application id, it will only return the
  /// login counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {String} userId The userId id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<LoginReportResponse>>}
  Future<ClientResponse<LoginReportResponse, Errors>> retrieveUserLoginReport(
      String applicationId, String userId, num start, num end) {
    return _start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('userId', userId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => LoginReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the login report between the two instants for a particular user by login Id. If you specify an application id, it will only return the
  /// login counts for that application.
  ///
  /// @param {String} applicationId (Optional) The application id.
  /// @param {String} loginId The userId id.
  /// @param {num} start The start instant as UTC milliseconds since Epoch.
  /// @param {num} end The end instant as UTC milliseconds since Epoch.
  /// @returns {Promise<ClientResponse<LoginReportResponse>>}
  Future<ClientResponse<LoginReportResponse, Errors>>
      retrieveUserLoginReportByLoginId(
          String applicationId, String loginId, num start, num end) {
    return _start<LoginReportResponse, Errors>()
        .withUri('/api/report/login')
        .withParameter('applicationId', applicationId)
        .withParameter('loginId', loginId)
        .withParameter('start', start)
        .withParameter('end', end)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => LoginReportResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the last number of login records for a user.
  ///
  /// @param {String} userId The Id of the user.
  /// @param {num} offset The initial record. e.g. 0 is the last login, 100 will be the 100th most recent login.
  /// @param {num} limit (Optional, defaults to 10) The number of records to retrieve.
  /// @returns {Promise<ClientResponse<RecentLoginResponse>>}
  Future<ClientResponse<RecentLoginResponse, Errors>> retrieveUserRecentLogins(
      String userId, num offset, num limit) {
    return _start<RecentLoginResponse, Errors>()
        .withUri('/api/user/recent-login')
        .withParameter('userId', userId)
        .withParameter('offset', offset)
        .withParameter('limit', limit)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RecentLoginResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the user for the given Id. This method does not use an API key, instead it uses a JSON Web Token (JWT) for authentication.
  ///
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> retrieveUserUsingJWT(
      String encodedJWT) {
    return _startAnonymous<UserResponse, Errors>()
        .withUri('/api/user')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the FusionAuth version string.
  ///
  /// @returns {Promise<ClientResponse<VersionResponse>>}
  Future<ClientResponse<VersionResponse, Errors>> retrieveVersion() {
    return _start<VersionResponse, Errors>()
        .withUri('/api/system/version')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => VersionResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the WebAuthn credential for the given Id.
  ///
  /// @param {String} id The Id of the WebAuthn credential.
  /// @returns {Promise<ClientResponse<WebAuthnCredentialResponse>>}
  Future<ClientResponse<WebAuthnCredentialResponse, Errors>>
      retrieveWebAuthnCredential(String id) {
    return _start<WebAuthnCredentialResponse, Errors>()
        .withUri('/api/webauthn')
        .withUriSegment(id)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnCredentialResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all WebAuthn credentials for the given user.
  ///
  /// @param {String} userId The user's ID.
  /// @returns {Promise<ClientResponse<WebAuthnCredentialResponse>>}
  Future<ClientResponse<WebAuthnCredentialResponse, Errors>>
      retrieveWebAuthnCredentialsForUser(String userId) {
    return _start<WebAuthnCredentialResponse, Errors>()
        .withUri('/api/webauthn')
        .withParameter('userId', userId)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnCredentialResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the webhook for the given Id. If you pass in null for the id, this will return all the webhooks.
  ///
  /// @param {String} webhookId (Optional) The Id of the webhook.
  /// @returns {Promise<ClientResponse<WebhookResponse>>}
  Future<ClientResponse<WebhookResponse, void>> retrieveWebhook(
      String webhookId) {
    return _start<WebhookResponse, void>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => WebhookResponse.fromJson(d)))
        .go();
  }

  /// Retrieves all the webhooks.
  ///
  /// @returns {Promise<ClientResponse<WebhookResponse>>}
  Future<ClientResponse<WebhookResponse, void>> retrieveWebhooks() {
    return _start<WebhookResponse, void>()
        .withUri('/api/webhook')
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => WebhookResponse.fromJson(d)))
        .go();
  }

  /// Revokes refresh tokens.
  ///
  /// Usage examples:
  ///   - Delete a single refresh token, pass in only the token.
  ///       revokeRefreshToken(token)
  ///
  ///   - Delete all refresh tokens for a user, pass in only the userId.
  ///       revokeRefreshToken(null, userId)
  ///
  ///   - Delete all refresh tokens for a user for a specific application, pass in both the userId and the applicationId.
  ///       revokeRefreshToken(null, userId, applicationId)
  ///
  ///   - Delete all refresh tokens for an application
  ///       revokeRefreshToken(null, null, applicationId)
  ///
  /// Note: <code>null</code> may be handled differently depending upon the programming language.
  ///
  /// See also: (method names may vary by language... but you'll figure it out)
  ///
  ///  - revokeRefreshTokenById
  ///  - revokeRefreshTokenByToken
  ///  - revokeRefreshTokensByUserId
  ///  - revokeRefreshTokensByApplicationId
  ///  - revokeRefreshTokensByUserIdForApplication
  ///
  /// @param {String} token (Optional) The refresh token to delete.
  /// @param {String} userId (Optional) The user id whose tokens to delete.
  /// @param {String} applicationId (Optional) The application id of the tokens to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshToken(
      String token, String userId, String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('token', token)
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withMethod('DELETE')
        .go();
  }

  /// Revokes a single refresh token by the unique Id. The unique Id is not sensitive as it cannot be used to obtain another JWT.
  ///
  /// @param {String} tokenId The unique Id of the token to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshTokenById(String tokenId) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withUriSegment(tokenId)
        .withMethod('DELETE')
        .go();
  }

  /// Revokes a single refresh token by using the actual refresh token value. This refresh token value is sensitive, so  be careful with this API request.
  ///
  /// @param {String} token The refresh token to delete.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshTokenByToken(String token) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('token', token)
        .withMethod('DELETE')
        .go();
  }

  /// Revoke all refresh tokens that belong to an application by applicationId.
  ///
  /// @param {String} applicationId The unique Id of the application that you want to delete all refresh tokens for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshTokensByApplicationId(
      String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('applicationId', applicationId)
        .withMethod('DELETE')
        .go();
  }

  /// Revoke all refresh tokens that belong to a user by user Id.
  ///
  /// @param {String} userId The unique Id of the user that you want to delete all refresh tokens for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshTokensByUserId(
      String userId) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withMethod('DELETE')
        .go();
  }

  /// Revoke all refresh tokens that belong to a user by user Id for a specific application by applicationId.
  ///
  /// @param {String} userId The unique Id of the user that you want to delete all refresh tokens for.
  /// @param {String} applicationId The unique Id of the application that you want to delete refresh tokens for.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>>
      revokeRefreshTokensByUserIdForApplication(
          String userId, String applicationId) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withParameter('userId', userId)
        .withParameter('applicationId', applicationId)
        .withMethod('DELETE')
        .go();
  }

  /// Revokes refresh tokens using the information in the JSON body. The handling for this method is the same as the revokeRefreshToken method
  /// and is based on the information you provide in the RefreshDeleteRequest object. See that method for additional information.
  ///
  /// @param {RefreshTokenRevokeRequest} request The request information used to revoke the refresh tokens.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> revokeRefreshTokensWithRequest(
      RefreshTokenRevokeRequest request) {
    return _start<void, Errors>()
        .withUri('/api/jwt/refresh')
        .withJSONBody(request)
        .withMethod('DELETE')
        .go();
  }

  /// Revokes a single User consent by Id.
  ///
  /// @param {String} userConsentId The User Consent Id
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> revokeUserConsent(String userConsentId) {
    return _start<void, void>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withMethod('DELETE')
        .go();
  }

  /// Searches applications with the specified criteria and pagination.
  ///
  /// @param {ApplicationSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<ApplicationSearchResponse>>}
  Future<ClientResponse<ApplicationSearchResponse, Errors>> searchApplications(
      ApplicationSearchRequest request) {
    return _start<ApplicationSearchResponse, Errors>()
        .withUri('/api/application/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches the audit logs with the specified criteria and pagination.
  ///
  /// @param {AuditLogSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<AuditLogSearchResponse>>}
  Future<ClientResponse<AuditLogSearchResponse, Errors>> searchAuditLogs(
      AuditLogSearchRequest request) {
    return _start<AuditLogSearchResponse, Errors>()
        .withUri('/api/system/audit-log/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => AuditLogSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches consents with the specified criteria and pagination.
  ///
  /// @param {ConsentSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<ConsentSearchResponse>>}
  Future<ClientResponse<ConsentSearchResponse, Errors>> searchConsents(
      ConsentSearchRequest request) {
    return _start<ConsentSearchResponse, Errors>()
        .withUri('/api/consent/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ConsentSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches email templates with the specified criteria and pagination.
  ///
  /// @param {EmailTemplateSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<EmailTemplateSearchResponse>>}
  Future<ClientResponse<EmailTemplateSearchResponse, Errors>>
      searchEmailTemplates(EmailTemplateSearchRequest request) {
    return _start<EmailTemplateSearchResponse, Errors>()
        .withUri('/api/email/template/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches entities with the specified criteria and pagination.
  ///
  /// @param {EntitySearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<EntitySearchResponse>>}
  Future<ClientResponse<EntitySearchResponse, Errors>> searchEntities(
      EntitySearchRequest request) {
    return _start<EntitySearchResponse, Errors>()
        .withUri('/api/entity/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntitySearchResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the entities for the given ids. If any id is invalid, it is ignored.
  ///
  /// @param {List<String>} ids The entity ids to search for.
  /// @returns {Promise<ClientResponse<EntitySearchResponse>>}
  Future<ClientResponse<EntitySearchResponse, Errors>> searchEntitiesByIds(
      List<String> ids) {
    return _start<EntitySearchResponse, Errors>()
        .withUri('/api/entity/search')
        .withParameter('ids', ids)
        .withMethod('GET')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntitySearchResponse.fromJson(d)))
        .go();
  }

  /// Searches Entity Grants with the specified criteria and pagination.
  ///
  /// @param {EntityGrantSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<EntityGrantSearchResponse>>}
  Future<ClientResponse<EntityGrantSearchResponse, Errors>> searchEntityGrants(
      EntityGrantSearchRequest request) {
    return _start<EntityGrantSearchResponse, Errors>()
        .withUri('/api/entity/grant/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityGrantSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches the entity types with the specified criteria and pagination.
  ///
  /// @param {EntityTypeSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<EntityTypeSearchResponse>>}
  Future<ClientResponse<EntityTypeSearchResponse, Errors>> searchEntityTypes(
      EntityTypeSearchRequest request) {
    return _start<EntityTypeSearchResponse, Errors>()
        .withUri('/api/entity/type/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches the event logs with the specified criteria and pagination.
  ///
  /// @param {EventLogSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<EventLogSearchResponse>>}
  Future<ClientResponse<EventLogSearchResponse, Errors>> searchEventLogs(
      EventLogSearchRequest request) {
    return _start<EventLogSearchResponse, Errors>()
        .withUri('/api/system/event-log/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EventLogSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches group members with the specified criteria and pagination.
  ///
  /// @param {GroupMemberSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<GroupMemberSearchResponse>>}
  Future<ClientResponse<GroupMemberSearchResponse, Errors>> searchGroupMembers(
      GroupMemberSearchRequest request) {
    return _start<GroupMemberSearchResponse, Errors>()
        .withUri('/api/group/member/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => GroupMemberSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches groups with the specified criteria and pagination.
  ///
  /// @param {GroupSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<GroupSearchResponse>>}
  Future<ClientResponse<GroupSearchResponse, Errors>> searchGroups(
      GroupSearchRequest request) {
    return _start<GroupSearchResponse, Errors>()
        .withUri('/api/group/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => GroupSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches the IP Access Control Lists with the specified criteria and pagination.
  ///
  /// @param {IPAccessControlListSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<IPAccessControlListSearchResponse>>}
  Future<ClientResponse<IPAccessControlListSearchResponse, Errors>>
      searchIPAccessControlLists(IPAccessControlListSearchRequest request) {
    return _start<IPAccessControlListSearchResponse, Errors>()
        .withUri('/api/ip-acl/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IPAccessControlListSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches identity providers with the specified criteria and pagination.
  ///
  /// @param {IdentityProviderSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<IdentityProviderSearchResponse>>}
  Future<ClientResponse<IdentityProviderSearchResponse, Errors>>
      searchIdentityProviders(IdentityProviderSearchRequest request) {
    return _start<IdentityProviderSearchResponse, Errors>()
        .withUri('/api/identity-provider/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches keys with the specified criteria and pagination.
  ///
  /// @param {KeySearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<KeySearchResponse>>}
  Future<ClientResponse<KeySearchResponse, Errors>> searchKeys(
      KeySearchRequest request) {
    return _start<KeySearchResponse, Errors>()
        .withUri('/api/key/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeySearchResponse.fromJson(d)))
        .go();
  }

  /// Searches lambdas with the specified criteria and pagination.
  ///
  /// @param {LambdaSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<LambdaSearchResponse>>}
  Future<ClientResponse<LambdaSearchResponse, Errors>> searchLambdas(
      LambdaSearchRequest request) {
    return _start<LambdaSearchResponse, Errors>()
        .withUri('/api/lambda/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => LambdaSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches the login records with the specified criteria and pagination.
  ///
  /// @param {LoginRecordSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<LoginRecordSearchResponse>>}
  Future<ClientResponse<LoginRecordSearchResponse, Errors>> searchLoginRecords(
      LoginRecordSearchRequest request) {
    return _start<LoginRecordSearchResponse, Errors>()
        .withUri('/api/system/login-record/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => LoginRecordSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches tenants with the specified criteria and pagination.
  ///
  /// @param {TenantSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<TenantSearchResponse>>}
  Future<ClientResponse<TenantSearchResponse, Errors>> searchTenants(
      TenantSearchRequest request) {
    return _start<TenantSearchResponse, Errors>()
        .withUri('/api/tenant/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TenantSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches themes with the specified criteria and pagination.
  ///
  /// @param {ThemeSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<ThemeSearchResponse>>}
  Future<ClientResponse<ThemeSearchResponse, Errors>> searchThemes(
      ThemeSearchRequest request) {
    return _start<ThemeSearchResponse, Errors>()
        .withUri('/api/theme/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ThemeSearchResponse.fromJson(d)))
        .go();
  }

  /// Searches user comments with the specified criteria and pagination.
  ///
  /// @param {UserCommentSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<UserCommentSearchResponse>>}
  Future<ClientResponse<UserCommentSearchResponse, Errors>> searchUserComments(
      UserCommentSearchRequest request) {
    return _start<UserCommentSearchResponse, Errors>()
        .withUri('/api/user/comment/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserCommentSearchResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
  ///
  /// @param {List<String>} ids The user ids to search for.
  /// @returns {Promise<ClientResponse<SearchResponse>>}
  ///
  /// @deprecated This method has been renamed to searchUsersByIds, use that method instead.
  Future<ClientResponse<SearchResponse, Errors>> searchUsers(List<String> ids) {
    return _start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withParameter('ids', ids)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SearchResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the users for the given ids. If any id is invalid, it is ignored.
  ///
  /// @param {List<String>} ids The user ids to search for.
  /// @returns {Promise<ClientResponse<SearchResponse>>}
  Future<ClientResponse<SearchResponse, Errors>> searchUsersByIds(
      List<String> ids) {
    return _start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withParameter('ids', ids)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SearchResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the users for the given search criteria and pagination.
  ///
  /// @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
  ///    and sortFields.
  /// @returns {Promise<ClientResponse<SearchResponse>>}
  Future<ClientResponse<SearchResponse, Errors>> searchUsersByQuery(
      SearchRequest request) {
    return _start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SearchResponse.fromJson(d)))
        .go();
  }

  /// Retrieves the users for the given search criteria and pagination.
  ///
  /// @param {SearchRequest} request The search criteria and pagination constraints. Fields used: ids, query, queryString, numberOfResults, orderBy, startRow,
  ///    and sortFields.
  /// @returns {Promise<ClientResponse<SearchResponse>>}
  ///
  /// @deprecated This method has been renamed to searchUsersByQuery, use that method instead.
  Future<ClientResponse<SearchResponse, Errors>> searchUsersByQueryString(
      SearchRequest request) {
    return _start<SearchResponse, Errors>()
        .withUri('/api/user/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SearchResponse.fromJson(d)))
        .go();
  }

  /// Searches webhooks with the specified criteria and pagination.
  ///
  /// @param {WebhookSearchRequest} request The search criteria and pagination information.
  /// @returns {Promise<ClientResponse<WebhookSearchResponse>>}
  Future<ClientResponse<WebhookSearchResponse, Errors>> searchWebhooks(
      WebhookSearchRequest request) {
    return _start<WebhookSearchResponse, Errors>()
        .withUri('/api/webhook/search')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebhookSearchResponse.fromJson(d)))
        .go();
  }

  /// Send an email using an email template id. You can optionally provide <code>requestData</code> to access key value
  /// pairs in the email template.
  ///
  /// @param {String} emailTemplateId The id for the template.
  /// @param {SendRequest} request The send email request that contains all the information used to send the email.
  /// @returns {Promise<ClientResponse<SendResponse>>}
  Future<ClientResponse<SendResponse, Errors>> sendEmail(
      String emailTemplateId, SendRequest request) {
    return _start<SendResponse, Errors>()
        .withUri('/api/email/send')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => SendResponse.fromJson(d)))
        .go();
  }

  /// Sends out an email to a parent that they need to register and create a family or need to log in and add a child to their existing family.
  ///
  /// @param {FamilyEmailRequest} request The request object that contains the parent email.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> sendFamilyRequestEmail(
      FamilyEmailRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/family/request')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Send a passwordless authentication code in an email to complete login.
  ///
  /// @param {PasswordlessSendRequest} request The passwordless send request that contains all the information used to send an email containing a code.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> sendPasswordlessCode(
      PasswordlessSendRequest request) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/passwordless/send')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
  ///
  /// @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
  /// @returns {Promise<ClientResponse<void>>}
  ///
  /// @deprecated This method has been renamed to sendTwoFactorCodeForEnableDisable, use that method instead.
  Future<ClientResponse<void, Errors>> sendTwoFactorCode(
      TwoFactorSendRequest request) {
    return _start<void, Errors>()
        .withUri('/api/two-factor/send')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Send a Two Factor authentication code to assist in setting up Two Factor authentication or disabling.
  ///
  /// @param {TwoFactorSendRequest} request The request object that contains all the information used to send the code.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> sendTwoFactorCodeForEnableDisable(
      TwoFactorSendRequest request) {
    return _start<void, Errors>()
        .withUri('/api/two-factor/send')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
  ///
  /// @param {String} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
  /// @returns {Promise<ClientResponse<void>>}
  ///
  /// @deprecated This method has been renamed to sendTwoFactorCodeForLoginUsingMethod, use that method instead.
  Future<ClientResponse<void, Errors>> sendTwoFactorCodeForLogin(
      String twoFactorId) {
    return _startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/two-factor/send')
        .withUriSegment(twoFactorId)
        .withMethod('POST')
        .go();
  }

  /// Send a Two Factor authentication code to allow the completion of Two Factor authentication.
  ///
  /// @param {String} twoFactorId The Id returned by the Login API necessary to complete Two Factor authentication.
  /// @param {TwoFactorSendRequest} request The Two Factor send request that contains all the information used to send the Two Factor code to the user.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> sendTwoFactorCodeForLoginUsingMethod(
      String twoFactorId, TwoFactorSendRequest request) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/two-factor/send')
        .withUriSegment(twoFactorId)
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Begins a login request for a 3rd party login that requires user interaction such as HYPR.
  ///
  /// @param {IdentityProviderStartLoginRequest} request The third-party login request that contains information from the third-party login
  ///    providers that FusionAuth uses to reconcile the user's account.
  /// @returns {Promise<ClientResponse<IdentityProviderStartLoginResponse>>}
  Future<ClientResponse<IdentityProviderStartLoginResponse, Errors>>
      startIdentityProviderLogin(IdentityProviderStartLoginRequest request) {
    return _start<IdentityProviderStartLoginResponse, Errors>()
        .withUri('/api/identity-provider/start')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderStartLoginResponse.fromJson(d)))
        .go();
  }

  /// Start a passwordless login request by generating a passwordless code. This code can be sent to the User using the Send
  /// Passwordless Code API or using a mechanism outside of FusionAuth. The passwordless login is completed by using the Passwordless Login API with this code.
  ///
  /// @param {PasswordlessStartRequest} request The passwordless start request that contains all the information used to begin the passwordless login request.
  /// @returns {Promise<ClientResponse<PasswordlessStartResponse>>}
  Future<ClientResponse<PasswordlessStartResponse, Errors>>
      startPasswordlessLogin(PasswordlessStartRequest request) {
    return _start<PasswordlessStartResponse, Errors>()
        .withUri('/api/passwordless/start')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => PasswordlessStartResponse.fromJson(d)))
        .go();
  }

  /// Start a Two-Factor login request by generating a two-factor identifier. This code can then be sent to the Two Factor Send
  /// API (/api/two-factor/send)in order to send a one-time use code to a user. You can also use one-time use code returned
  /// to send the code out-of-band. The Two-Factor login is completed by making a request to the Two-Factor Login
  /// API (/api/two-factor/login). with the two-factor identifier and the one-time use code.
  ///
  /// This API is intended to allow you to begin a Two-Factor login outside a normal login that originated from the Login API (/api/login).
  ///
  /// @param {TwoFactorStartRequest} request The Two-Factor start request that contains all the information used to begin the Two-Factor login request.
  /// @returns {Promise<ClientResponse<TwoFactorStartResponse>>}
  Future<ClientResponse<TwoFactorStartResponse, Errors>> startTwoFactorLogin(
      TwoFactorStartRequest request) {
    return _start<TwoFactorStartResponse, Errors>()
        .withUri('/api/two-factor/start')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => TwoFactorStartResponse.fromJson(d)))
        .go();
  }

  /// Start a WebAuthn authentication ceremony by generating a new challenge for the user
  ///
  /// @param {WebAuthnStartRequest} request An object containing data necessary for starting the authentication ceremony
  /// @returns {Promise<ClientResponse<WebAuthnStartResponse>>}
  Future<ClientResponse<WebAuthnStartResponse, Errors>> startWebAuthnLogin(
      WebAuthnStartRequest request) {
    return _start<WebAuthnStartResponse, Errors>()
        .withUri('/api/webauthn/start')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnStartResponse.fromJson(d)))
        .go();
  }

  /// Start a WebAuthn registration ceremony by generating a new challenge for the user
  ///
  /// @param {WebAuthnRegisterStartRequest} request An object containing data necessary for starting the registration ceremony
  /// @returns {Promise<ClientResponse<WebAuthnRegisterStartResponse>>}
  Future<ClientResponse<WebAuthnRegisterStartResponse, Errors>>
      startWebAuthnRegistration(WebAuthnRegisterStartRequest request) {
    return _start<WebAuthnRegisterStartResponse, Errors>()
        .withUri('/api/webauthn/register/start')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => WebAuthnRegisterStartResponse.fromJson(d)))
        .go();
  }

  /// Complete login using a 2FA challenge
  ///
  /// @param {TwoFactorLoginRequest} request The login request that contains the user credentials used to log them in.
  /// @returns {Promise<ClientResponse<LoginResponse>>}
  Future<ClientResponse<LoginResponse, Errors>> twoFactorLogin(
      TwoFactorLoginRequest request) {
    return _startAnonymous<LoginResponse, Errors>()
        .withUri('/api/two-factor/login')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LoginResponse.fromJson(d)))
        .go();
  }

  /// Updates an API key by given id
  ///
  /// @param {String} apiKeyId The Id of the API key to update.
  /// @param {APIKeyRequest} request The request object that contains all the information used to create the API Key.
  /// @returns {Promise<ClientResponse<APIKeyResponse>>}
  Future<ClientResponse<APIKeyResponse, Errors>> updateAPIKey(
      String apiKeyId, APIKeyRequest request) {
    return _start<APIKeyResponse, Errors>()
        .withUri('/api/api-key')
        .withUriSegment(apiKeyId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => APIKeyResponse.fromJson(d)))
        .go();
  }

  /// Updates the application with the given Id.
  ///
  /// @param {String} applicationId The Id of the application to update.
  /// @param {ApplicationRequest} request The request that contains all the new application information.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> updateApplication(
      String applicationId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Updates the application role with the given id for the application.
  ///
  /// @param {String} applicationId The Id of the application that the role belongs to.
  /// @param {String} roleId The Id of the role to update.
  /// @param {ApplicationRequest} request The request that contains all the new role information.
  /// @returns {Promise<ClientResponse<ApplicationResponse>>}
  Future<ClientResponse<ApplicationResponse, Errors>> updateApplicationRole(
      String applicationId, String roleId, ApplicationRequest request) {
    return _start<ApplicationResponse, Errors>()
        .withUri('/api/application')
        .withUriSegment(applicationId)
        .withUriSegment("role")
        .withUriSegment(roleId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => ApplicationResponse.fromJson(d)))
        .go();
  }

  /// Updates the connector with the given Id.
  ///
  /// @param {String} connectorId The Id of the connector to update.
  /// @param {ConnectorRequest} request The request object that contains all the new connector information.
  /// @returns {Promise<ClientResponse<ConnectorResponse>>}
  Future<ClientResponse<ConnectorResponse, Errors>> updateConnector(
      String connectorId, ConnectorRequest request) {
    return _start<ConnectorResponse, Errors>()
        .withUri('/api/connector')
        .withUriSegment(connectorId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConnectorResponse.fromJson(d)))
        .go();
  }

  /// Updates the consent with the given Id.
  ///
  /// @param {String} consentId The Id of the consent to update.
  /// @param {ConsentRequest} request The request that contains all the new consent information.
  /// @returns {Promise<ClientResponse<ConsentResponse>>}
  Future<ClientResponse<ConsentResponse, Errors>> updateConsent(
      String consentId, ConsentRequest request) {
    return _start<ConsentResponse, Errors>()
        .withUri('/api/consent')
        .withUriSegment(consentId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ConsentResponse.fromJson(d)))
        .go();
  }

  /// Updates the email template with the given Id.
  ///
  /// @param {String} emailTemplateId The Id of the email template to update.
  /// @param {EmailTemplateRequest} request The request that contains all the new email template information.
  /// @returns {Promise<ClientResponse<EmailTemplateResponse>>}
  Future<ClientResponse<EmailTemplateResponse, Errors>> updateEmailTemplate(
      String emailTemplateId, EmailTemplateRequest request) {
    return _start<EmailTemplateResponse, Errors>()
        .withUri('/api/email/template')
        .withUriSegment(emailTemplateId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EmailTemplateResponse.fromJson(d)))
        .go();
  }

  /// Updates the Entity with the given Id.
  ///
  /// @param {String} entityId The Id of the Entity to update.
  /// @param {EntityRequest} request The request that contains all the new Entity information.
  /// @returns {Promise<ClientResponse<EntityResponse>>}
  Future<ClientResponse<EntityResponse, Errors>> updateEntity(
      String entityId, EntityRequest request) {
    return _start<EntityResponse, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => EntityResponse.fromJson(d)))
        .go();
  }

  /// Updates the Entity Type with the given Id.
  ///
  /// @param {String} entityTypeId The Id of the Entity Type to update.
  /// @param {EntityTypeRequest} request The request that contains all the new Entity Type information.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> updateEntityType(
      String entityTypeId, EntityTypeRequest request) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Updates the permission with the given id for the entity type.
  ///
  /// @param {String} entityTypeId The Id of the entityType that the permission belongs to.
  /// @param {String} permissionId The Id of the permission to update.
  /// @param {EntityTypeRequest} request The request that contains all the new permission information.
  /// @returns {Promise<ClientResponse<EntityTypeResponse>>}
  Future<ClientResponse<EntityTypeResponse, Errors>> updateEntityTypePermission(
      String entityTypeId, String permissionId, EntityTypeRequest request) {
    return _start<EntityTypeResponse, Errors>()
        .withUri('/api/entity/type')
        .withUriSegment(entityTypeId)
        .withUriSegment("permission")
        .withUriSegment(permissionId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => EntityTypeResponse.fromJson(d)))
        .go();
  }

  /// Updates the form with the given Id.
  ///
  /// @param {String} formId The Id of the form to update.
  /// @param {FormRequest} request The request object that contains all the new form information.
  /// @returns {Promise<ClientResponse<FormResponse>>}
  Future<ClientResponse<FormResponse, Errors>> updateForm(
      String formId, FormRequest request) {
    return _start<FormResponse, Errors>()
        .withUri('/api/form')
        .withUriSegment(formId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormResponse.fromJson(d)))
        .go();
  }

  /// Updates the form field with the given Id.
  ///
  /// @param {String} fieldId The Id of the form field to update.
  /// @param {FormFieldRequest} request The request object that contains all the new form field information.
  /// @returns {Promise<ClientResponse<FormFieldResponse>>}
  Future<ClientResponse<FormFieldResponse, Errors>> updateFormField(
      String fieldId, FormFieldRequest request) {
    return _start<FormFieldResponse, Errors>()
        .withUri('/api/form/field')
        .withUriSegment(fieldId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => FormFieldResponse.fromJson(d)))
        .go();
  }

  /// Updates the group with the given Id.
  ///
  /// @param {String} groupId The Id of the group to update.
  /// @param {GroupRequest} request The request that contains all the new group information.
  /// @returns {Promise<ClientResponse<GroupResponse>>}
  Future<ClientResponse<GroupResponse, Errors>> updateGroup(
      String groupId, GroupRequest request) {
    return _start<GroupResponse, Errors>()
        .withUri('/api/group')
        .withUriSegment(groupId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => GroupResponse.fromJson(d)))
        .go();
  }

  /// Creates a member in a group.
  ///
  /// @param {MemberRequest} request The request object that contains all the information used to create the group member(s).
  /// @returns {Promise<ClientResponse<MemberResponse>>}
  Future<ClientResponse<MemberResponse, Errors>> updateGroupMembers(
      MemberRequest request) {
    return _start<MemberResponse, Errors>()
        .withUri('/api/group/member')
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MemberResponse.fromJson(d)))
        .go();
  }

  /// Updates the IP Access Control List with the given Id.
  ///
  /// @param {String} accessControlListId The Id of the IP Access Control List to update.
  /// @param {IPAccessControlListRequest} request The request that contains all the new IP Access Control List information.
  /// @returns {Promise<ClientResponse<IPAccessControlListResponse>>}
  Future<ClientResponse<IPAccessControlListResponse, Errors>>
      updateIPAccessControlList(
          String accessControlListId, IPAccessControlListRequest request) {
    return _start<IPAccessControlListResponse, Errors>()
        .withUri('/api/ip-acl')
        .withUriSegment(accessControlListId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IPAccessControlListResponse.fromJson(d)))
        .go();
  }

  /// Updates the identity provider with the given Id.
  ///
  /// @param {String} identityProviderId The Id of the identity provider to update.
  /// @param {IdentityProviderRequest} request The request object that contains the updated identity provider.
  /// @returns {Promise<ClientResponse<IdentityProviderResponse>>}
  Future<ClientResponse<IdentityProviderResponse, Errors>>
      updateIdentityProvider(
          String identityProviderId, IdentityProviderRequest request) {
    return _start<IdentityProviderResponse, Errors>()
        .withUri('/api/identity-provider')
        .withUriSegment(identityProviderId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IdentityProviderResponse.fromJson(d)))
        .go();
  }

  /// Updates the available integrations.
  ///
  /// @param {IntegrationRequest} request The request that contains all the new integration information.
  /// @returns {Promise<ClientResponse<IntegrationResponse>>}
  Future<ClientResponse<IntegrationResponse, Errors>> updateIntegrations(
      IntegrationRequest request) {
    return _start<IntegrationResponse, Errors>()
        .withUri('/api/integration')
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => IntegrationResponse.fromJson(d)))
        .go();
  }

  /// Updates the key with the given Id.
  ///
  /// @param {String} keyId The Id of the key to update.
  /// @param {KeyRequest} request The request that contains all the new key information.
  /// @returns {Promise<ClientResponse<KeyResponse>>}
  Future<ClientResponse<KeyResponse, Errors>> updateKey(
      String keyId, KeyRequest request) {
    return _start<KeyResponse, Errors>()
        .withUri('/api/key')
        .withUriSegment(keyId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => KeyResponse.fromJson(d)))
        .go();
  }

  /// Updates the lambda with the given Id.
  ///
  /// @param {String} lambdaId The Id of the lambda to update.
  /// @param {LambdaRequest} request The request that contains all the new lambda information.
  /// @returns {Promise<ClientResponse<LambdaResponse>>}
  Future<ClientResponse<LambdaResponse, Errors>> updateLambda(
      String lambdaId, LambdaRequest request) {
    return _start<LambdaResponse, Errors>()
        .withUri('/api/lambda')
        .withUriSegment(lambdaId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => LambdaResponse.fromJson(d)))
        .go();
  }

  /// Updates the message template with the given Id.
  ///
  /// @param {String} messageTemplateId The Id of the message template to update.
  /// @param {MessageTemplateRequest} request The request that contains all the new message template information.
  /// @returns {Promise<ClientResponse<MessageTemplateResponse>>}
  Future<ClientResponse<MessageTemplateResponse, Errors>> updateMessageTemplate(
      String messageTemplateId, MessageTemplateRequest request) {
    return _start<MessageTemplateResponse, Errors>()
        .withUri('/api/message/template')
        .withUriSegment(messageTemplateId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => MessageTemplateResponse.fromJson(d)))
        .go();
  }

  /// Updates the messenger with the given Id.
  ///
  /// @param {String} messengerId The Id of the messenger to update.
  /// @param {MessengerRequest} request The request object that contains all the new messenger information.
  /// @returns {Promise<ClientResponse<MessengerResponse>>}
  Future<ClientResponse<MessengerResponse, Errors>> updateMessenger(
      String messengerId, MessengerRequest request) {
    return _start<MessengerResponse, Errors>()
        .withUri('/api/messenger')
        .withUriSegment(messengerId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => MessengerResponse.fromJson(d)))
        .go();
  }

  /// Updates the registration for the user with the given id and the application defined in the request.
  ///
  /// @param {String} userId The Id of the user whose registration is going to be updated.
  /// @param {RegistrationRequest} request The request that contains all the new registration information.
  /// @returns {Promise<ClientResponse<RegistrationResponse>>}
  Future<ClientResponse<RegistrationResponse, Errors>> updateRegistration(
      String userId, RegistrationRequest request) {
    return _start<RegistrationResponse, Errors>()
        .withUri('/api/user/registration')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => RegistrationResponse.fromJson(d)))
        .go();
  }

  /// Updates the system configuration.
  ///
  /// @param {SystemConfigurationRequest} request The request that contains all the new system configuration information.
  /// @returns {Promise<ClientResponse<SystemConfigurationResponse>>}
  Future<ClientResponse<SystemConfigurationResponse, Errors>>
      updateSystemConfiguration(SystemConfigurationRequest request) {
    return _start<SystemConfigurationResponse, Errors>()
        .withUri('/api/system-configuration')
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => SystemConfigurationResponse.fromJson(d)))
        .go();
  }

  /// Updates the tenant with the given Id.
  ///
  /// @param {String} tenantId The Id of the tenant to update.
  /// @param {TenantRequest} request The request that contains all the new tenant information.
  /// @returns {Promise<ClientResponse<TenantResponse>>}
  Future<ClientResponse<TenantResponse, Errors>> updateTenant(
      String tenantId, TenantRequest request) {
    return _start<TenantResponse, Errors>()
        .withUri('/api/tenant')
        .withUriSegment(tenantId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => TenantResponse.fromJson(d)))
        .go();
  }

  /// Updates the theme with the given Id.
  ///
  /// @param {String} themeId The Id of the theme to update.
  /// @param {ThemeRequest} request The request that contains all the new theme information.
  /// @returns {Promise<ClientResponse<ThemeResponse>>}
  Future<ClientResponse<ThemeResponse, Errors>> updateTheme(
      String themeId, ThemeRequest request) {
    return _start<ThemeResponse, Errors>()
        .withUri('/api/theme')
        .withUriSegment(themeId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ThemeResponse.fromJson(d)))
        .go();
  }

  /// Updates the user with the given Id.
  ///
  /// @param {String} userId The Id of the user to update.
  /// @param {UserRequest} request The request that contains all the new user information.
  /// @returns {Promise<ClientResponse<UserResponse>>}
  Future<ClientResponse<UserResponse, Errors>> updateUser(
      String userId, UserRequest request) {
    return _start<UserResponse, Errors>()
        .withUri('/api/user')
        .withUriSegment(userId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => UserResponse.fromJson(d)))
        .go();
  }

  /// Updates the user action with the given Id.
  ///
  /// @param {String} userActionId The Id of the user action to update.
  /// @param {UserActionRequest} request The request that contains all the new user action information.
  /// @returns {Promise<ClientResponse<UserActionResponse>>}
  Future<ClientResponse<UserActionResponse, Errors>> updateUserAction(
      String userActionId, UserActionRequest request) {
    return _start<UserActionResponse, Errors>()
        .withUri('/api/user-action')
        .withUriSegment(userActionId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionResponse.fromJson(d)))
        .go();
  }

  /// Updates the user action reason with the given Id.
  ///
  /// @param {String} userActionReasonId The Id of the user action reason to update.
  /// @param {UserActionReasonRequest} request The request that contains all the new user action reason information.
  /// @returns {Promise<ClientResponse<UserActionReasonResponse>>}
  Future<ClientResponse<UserActionReasonResponse, Errors>>
      updateUserActionReason(
          String userActionReasonId, UserActionReasonRequest request) {
    return _start<UserActionReasonResponse, Errors>()
        .withUri('/api/user-action-reason')
        .withUriSegment(userActionReasonId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserActionReasonResponse.fromJson(d)))
        .go();
  }

  /// Updates a single User consent by Id.
  ///
  /// @param {String} userConsentId The User Consent Id
  /// @param {UserConsentRequest} request The request that contains the user consent information.
  /// @returns {Promise<ClientResponse<UserConsentResponse>>}
  Future<ClientResponse<UserConsentResponse, Errors>> updateUserConsent(
      String userConsentId, UserConsentRequest request) {
    return _start<UserConsentResponse, Errors>()
        .withUri('/api/user/consent')
        .withUriSegment(userConsentId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(defaultResponseHandlerBuilder(
            (d) => UserConsentResponse.fromJson(d)))
        .go();
  }

  /// Updates the webhook with the given Id.
  ///
  /// @param {String} webhookId The Id of the webhook to update.
  /// @param {WebhookRequest} request The request that contains all the new webhook information.
  /// @returns {Promise<ClientResponse<WebhookResponse>>}
  Future<ClientResponse<WebhookResponse, Errors>> updateWebhook(
      String webhookId, WebhookRequest request) {
    return _start<WebhookResponse, Errors>()
        .withUri('/api/webhook')
        .withUriSegment(webhookId)
        .withJSONBody(request)
        .withMethod('PUT')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => WebhookResponse.fromJson(d)))
        .go();
  }

  /// Creates or updates an Entity Grant. This is when a User/Entity is granted permissions to an Entity.
  ///
  /// @param {String} entityId The Id of the Entity that the User/Entity is being granted access to.
  /// @param {EntityGrantRequest} request The request object that contains all the information used to create the Entity Grant.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> upsertEntityGrant(
      String entityId, EntityGrantRequest request) {
    return _start<void, Errors>()
        .withUri('/api/entity')
        .withUriSegment(entityId)
        .withUriSegment("grant")
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Validates the end-user provided user_code from the user-interaction of the Device Authorization Grant.
  /// If you build your own activation form you should validate the user provided code prior to beginning the Authorization grant.
  ///
  /// @param {String} user_code The end-user verification code.
  /// @param {String} client_id The client id.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, void>> validateDevice(
      String user_code, String client_id) {
    return _startAnonymous<void, void>()
        .withUri('/oauth2/device/validate')
        .withParameter('user_code', user_code)
        .withParameter('client_id', client_id)
        .withMethod('GET')
        .go();
  }

  /// Validates the provided JWT (encoded JWT string) to ensure the token is valid. A valid access token is properly
  /// signed and not expired.
  /// <p>
  /// This API may be used to verify the JWT as well as decode the encoded JWT into human readable identity claims.
  ///
  /// @param {String} encodedJWT The encoded JWT (access token).
  /// @returns {Promise<ClientResponse<ValidateResponse>>}
  Future<ClientResponse<ValidateResponse, void>> validateJWT(
      String encodedJWT) {
    return _startAnonymous<ValidateResponse, void>()
        .withUri('/api/jwt/validate')
        .withAuthorization('Bearer ' + encodedJWT)
        .withMethod('GET')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => ValidateResponse.fromJson(d)))
        .go();
  }

  /// It's a JWT vending machine!
  ///
  /// Issue a new access token (JWT) with the provided claims in the request. This JWT is not scoped to a tenant or user, it is a free form
  /// token that will contain what claims you provide.
  /// <p>
  /// The iat, exp and jti claims will be added by FusionAuth, all other claims must be provided by the caller.
  ///
  /// If a TTL is not provided in the request, the TTL will be retrieved from the default Tenant or the Tenant specified on the request either
  /// by way of the X-FusionAuth-TenantId request header, or a tenant scoped API key.
  ///
  /// @param {JWTVendRequest} request The request that contains all the claims for this JWT.
  /// @returns {Promise<ClientResponse<JWTVendResponse>>}
  Future<ClientResponse<JWTVendResponse, Errors>> vendJWT(
      JWTVendRequest request) {
    return _start<JWTVendResponse, Errors>()
        .withUri('/api/jwt/vend')
        .withJSONBody(request)
        .withMethod('POST')
        .withResponseHandler(
            defaultResponseHandlerBuilder((d) => JWTVendResponse.fromJson(d)))
        .go();
  }

  /// Confirms a email verification. The Id given is usually from an email sent to the user.
  ///
  /// @param {String} verificationId The email verification id sent to the user.
  /// @returns {Promise<ClientResponse<void>>}
  ///
  /// @deprecated This method has been renamed to verifyEmailAddress and changed to take a JSON request body, use that method instead.
  Future<ClientResponse<void, Errors>> verifyEmail(String verificationId) {
    return _startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/verify-email')
        .withUriSegment(verificationId)
        .withMethod('POST')
        .go();
  }

  /// Confirms a user's email address.
  ///
  /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
  /// the tenant is configured to gate a user until their email address is verified, this procedures requires two values instead of one.
  /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
  /// two values together are able to confirm a user's email address and mark the user's email address as verified.
  ///
  /// @param {VerifyEmailRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> verifyEmailAddress(
      VerifyEmailRequest request) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/user/verify-email')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Administratively verify a user's email address. Use this method to bypass email verification for the user.
  ///
  /// The request body will contain the userId to be verified. An API key is required when sending the userId in the request body.
  ///
  /// @param {VerifyEmailRequest} request The request that contains the userId to verify.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> verifyEmailAddressByUserId(
      VerifyEmailRequest request) {
    return _start<void, Errors>()
        .withUri('/api/user/verify-email')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /// Confirms an application registration. The Id given is usually from an email sent to the user.
  ///
  /// @param {String} verificationId The registration verification Id sent to the user.
  /// @returns {Promise<ClientResponse<void>>}
  ///
  /// @deprecated This method has been renamed to verifyUserRegistration and changed to take a JSON request body, use that method instead.
  Future<ClientResponse<void, Errors>> verifyRegistration(
      String verificationId) {
    return _startAnonymous<void, Errors>()
        .withHeader('Content-Type', 'text/plain')
        .withUri('/api/user/verify-registration')
        .withUriSegment(verificationId)
        .withMethod('POST')
        .go();
  }

  /// Confirms a user's registration.
  ///
  /// The request body will contain the verificationId. You may also be required to send a one-time use code based upon your configuration. When
  /// the application is configured to gate a user until their registration is verified, this procedures requires two values instead of one.
  /// The verificationId is a high entropy value and the one-time use code is a low entropy value that is easily entered in a user interactive form. The
  /// two values together are able to confirm a user's registration and mark the user's registration as verified.
  ///
  /// @param {VerifyRegistrationRequest} request The request that contains the verificationId and optional one-time use code paired with the verificationId.
  /// @returns {Promise<ClientResponse<void>>}
  Future<ClientResponse<void, Errors>> verifyUserRegistration(
      VerifyRegistrationRequest request) {
    return _startAnonymous<void, Errors>()
        .withUri('/api/user/verify-registration')
        .withJSONBody(request)
        .withMethod('POST')
        .go();
  }

  /* ===================================================================================================================
   * Private methods
   * ===================================================================================================================*/

  final HttpClient _httpClient = HttpClient();

  FusionAuthRESTClient _start<RT, ERT>() {
    return _startAnonymous<RT, ERT>().withAuthorization(apiKey);
  }

  FusionAuthRESTClient _startAnonymous<RT, ERT>() {
    var client = fusionAuthRESTClientFactory<RT, ERT>(host, _httpClient);

    if (tenantId != null) {
      client.withHeader('X-FusionAuth-TenantId', tenantId);
    }

    if (credentials != null) {
      client.withCredentials(credentials);
    }

    return client;
  }
}

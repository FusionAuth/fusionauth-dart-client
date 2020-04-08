/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
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

import 'FusionAuthDomain.dart';

class IdentityProviderConverter<T> implements JsonConverter<T, dynamic> {
  const IdentityProviderConverter();

  @override
  T fromJson(dynamic json) {
    switch (json['type']) {
      case 'Facebook':
        return FacebookIdentityProvider.fromJson(json) as T;
      case 'Google':
        return GoogleIdentityProvider.fromJson(json) as T;
      case 'Twitter':
        return TwitterIdentityProvider.fromJson(json) as T;
      case 'ExternalJWT':
        return ExternalJWTIdentityProvider.fromJson(json) as T;
      case 'OpenIDConnect':
        return OpenIdConnectIdentityProvider.fromJson(json) as T;
      case 'SAML2':
        return SAMLv2IdentityProvider.fromJson(json) as T;
      default:
        throw UnimplementedError('Missing converter for $T');
    }
  }

  @override
  dynamic toJson(T object) {
    return object;
  }
}

BaseIdentityProvider BaseIdentityProviderFromJson(Map<String, dynamic> json) {
  switch (json['type']) {
    case 'Facebook':
      return FacebookIdentityProvider.fromJson(json);
    case 'Google':
      return GoogleIdentityProvider.fromJson(json);
    case 'Twitter':
      return TwitterIdentityProvider.fromJson(json);
    case 'ExternalJWT':
      return ExternalJWTIdentityProvider.fromJson(json);
    case 'OpenIDConnect':
      return OpenIdConnectIdentityProvider.fromJson(json);
    case 'SAML2':
      return SAMLv2IdentityProvider.fromJson(json);
    default:
      throw UnimplementedError('Missing converter for ${json['type']}');
  }
}

class IdentityProviderApplicationConfigurationConverter<T>
    implements JsonConverter<T, dynamic> {
  const IdentityProviderApplicationConfigurationConverter();

  @override
  T fromJson(dynamic json) {
    if (T is FacebookApplicationConfiguration) {
      return FacebookApplicationConfiguration.fromJson(json) as T;
    } else if (T is GoogleApplicationConfiguration) {
      return GoogleApplicationConfiguration.fromJson(json) as T;
    } else if (T is TwitterApplicationConfiguration) {
      return TwitterApplicationConfiguration.fromJson(json) as T;
    } else if (T is ExternalJWTApplicationConfiguration) {
      return ExternalJWTApplicationConfiguration.fromJson(json) as T;
    } else if (T is OpenIdConnectApplicationConfiguration) {
      return OpenIdConnectApplicationConfiguration.fromJson(json) as T;
    } else if (T is SAMLv2ApplicationConfiguration) {
      return SAMLv2ApplicationConfiguration.fromJson(json) as T;
    } else {
      throw UnimplementedError('Missing converter for $T');
    }
  }

  @override
  dynamic toJson(T object) {
    return object;
  }
}

/*
 * Copyright (c) 2020, FusionAuth, All Rights Reserved
 */

import 'dart:convert';
import 'dart:io';

import 'FusionAuthDomain.dart';

class ClientResponse<RT, ERT> {
  num statusCode;
  dynamic exception;

  RT successResponse;
  ERT errorResponse;
}

typedef ResponseHandler<RT, ERT> = Future<void> Function(
    HttpClientResponse, ClientResponse<RT, ERT>);

typedef FromJsonMethod<RT> = RT Function(dynamic);

ResponseHandler<RT, ERT> defaultResponseHandlerBuilder<RT, ERT>(
    FromJsonMethod fromJson) {
  return (httpClientResponse, clientResponse) async {
    var body = await httpClientResponse.transform(utf8.decoder).join();
    clientResponse.successResponse = fromJson(json.decode(body));
  };
}

ResponseHandler<RT, ERT> defaultErrorResponseHandlerBuilder<RT, ERT>(
    FromJsonMethod fromJson) {
  return (httpClientResponse, clientResponse) async {
    var body = await httpClientResponse.transform(utf8.decoder).join();
    clientResponse.errorResponse = fromJson(json.decode(body));
  };
}

class FusionAuthRESTClient<ReturnType, ErrorReturnType> {
  dynamic body;
  Map<String, String> headers = Map<String, String>();
  String method;
  Map<String, String> parameters = Map<String, String>();
  String uri;
  HttpClientCredentials credentials;
  String realm;
  String host;
  ResponseHandler<ReturnType, ErrorReturnType> responseHandler;
  ResponseHandler<ReturnType, ErrorReturnType> errorResponseHandler;

  final HttpClient httpClient;

  FusionAuthRESTClient(this.host, this.httpClient) {
    if (ErrorReturnType == Errors) {
      errorResponseHandler =
          defaultErrorResponseHandlerBuilder((d) => Errors.fromJson(d));
    }
  }

  /// Sets the authorization header using a key
  ///
  /// @param {string} key The value of the authorization header.
  /// @returns {DefaultRESTClient}
  FusionAuthRESTClient withAuthorization(String key) {
    withHeader('Authorization', key);
    return this;
  }

  /// Adds a segment to the request uri
  FusionAuthRESTClient withUriSegment(dynamic segment) {
    if (segment == null) {
      return this;
    }
    uri ??= '';
    if (uri[uri.length - 1] != '/') {
      uri += '/';
    }
    uri = uri + segment;
    return this;
  }

  /// Get the full url + parameter list
  String getFullUrl() {
    return host + uri + _getQueryString();
  }

  /// Sets the body of the client request.
  ///
  /// @param body The object to be written to the request body as form data.
  FusionAuthRESTClient withFormData(Map<String, dynamic> body) {
    this.body = body;
    withHeader('Content-Type', 'application/x-www-form-urlencoded');
    return this;
  }

  /// Adds a header to the request.
  ///
  /// @param key The name of the header.
  /// @param value The value of the header.
  FusionAuthRESTClient withHeader(String key, String value) {
    headers[key] = value;
    return this;
  }

  /// Sets the body of the client request.
  ///
  /// @param body The object to be written to the request body as JSON.
  FusionAuthRESTClient withJSONBody(dynamic body) {
    this.body = body;
    withHeader('Content-Type', 'application/json');
    // Omit the Content-Length, this is set auto-magically by the request library
    return this;
  }

  /// Sets the http method for the request
  FusionAuthRESTClient withMethod(String method) {
    this.method = method;
    return this;
  }

  /// Sets the uri of the request
  FusionAuthRESTClient withUri(String uri) {
    this.uri = uri;
    return this;
  }

  /// Adds parameters to the request.
  ///
  /// @param name The name of the parameter.
  /// @param value The value of the parameter, may be a string, object or number.
  FusionAuthRESTClient withParameter(String name, dynamic value) {
    parameters[name] = value.toString();
    return this;
  }

  /// Sets request's credentials.
  ///
  /// @param value A string indicating whether credentials will be sent with the request always, never, or only when sent to a same-origin URL.
  FusionAuthRESTClient withCredentials(HttpClientCredentials value) {
    credentials = value;
    return this;
  }

  FusionAuthRESTClient withRealm(String realm) {
    this.realm = realm;
    return this;
  }

  FusionAuthRESTClient withResponseHandler(ResponseHandler responseHandler) {
    this.responseHandler = responseHandler;
    return this;
  }

  FusionAuthRESTClient withErrorResponseHandler(
      ResponseHandler errorResponseHandler) {
    this.errorResponseHandler = errorResponseHandler;
    return this;
  }

  /// Run the request and return a promise. This promise will resolve if the request is successful
  /// and reject otherwise.
  Future<ClientResponse<ReturnType, ErrorReturnType>> go() async {
    var clientResponse = ClientResponse<ReturnType, ErrorReturnType>();
    try {
      var request = await _newRequest(Uri.parse(getFullUrl()));

      headers.forEach(request.headers.add);
      if (headers['Content-Type'] == 'application/json') {
        request.write(json.encode(body));
      } else if (headers['Content-Type'] ==
          'application/x-www-form-urlencoded') {
        var sep = '';
        (body as Map).forEach((key, value) {
          request.write(sep +
              Uri.encodeComponent(key) +
              '=' +
              Uri.encodeComponent(value));
          sep = '&';
        });
      } else if (body != null) {
        request.write(body.toString());
      }
      var response = await request.close();

      clientResponse.statusCode = response.statusCode;

      if (response.statusCode == 400 && errorResponseHandler != null) {
        await errorResponseHandler(response, clientResponse);
      }

      if (response.statusCode >= 200 &&
          response.statusCode < 300 &&
          responseHandler != null) {
        await responseHandler(response, clientResponse);
      }
    } catch (e) {
      clientResponse.exception = e;
    }

    return clientResponse;
  }

  Future<HttpClientRequest> _newRequest(Uri uri) {
    if (credentials != null) {
      httpClient.addCredentials(uri, realm, credentials);
    }

    switch (method) {
      case 'GET':
        return httpClient.getUrl(uri);
      case 'DELETE':
        return httpClient.deleteUrl(uri);
      case 'POST':
        return httpClient.postUrl(uri);
      case 'PUT':
        return httpClient.putUrl(uri);
      case 'PATCH':
        return httpClient.patchUrl(uri);
      default:
        throw UnimplementedError('Unimplemented http method');
    }
  }

  String _getQueryString() {
    var queryString = '';
    parameters.forEach((key, value) {
      if (queryString.isEmpty) {
        queryString += '?';
      } else {
        queryString += '&';
      }
      queryString += key + '=' + Uri.encodeComponent(value);
    });
    return queryString;
  }
}

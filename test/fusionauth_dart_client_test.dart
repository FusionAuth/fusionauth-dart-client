import 'package:fusionauth_dart_client/fusionauth_dart_client.dart';
import 'package:test/test.dart';
import 'dart:convert';

import 'dart:io' show Platform;

void main() {
  group('A group of tests', () {
    FusionAuthClient client;

    setUp(() async {
      client = FusionAuthClient(
          Platform.environment['FUSIONAUTH_API_KEY'] ??
              'bf69486b-4733-4470-a592-f1bfce7af580',
          Platform.environment['FUSIONAUTH_URL'] ??
              'https://local.fusionauth.io',
          null);

      print('Testing against [${client.host}] with key [${client.apiKey}]');

      var response = await client.searchUsersByQuery(SearchRequest(
          search: UserSearchCriteria(queryString: "email:test@example.com")));

      if (response.statusCode == 200 &&
          response.successResponse.users != null &&
          response.successResponse.users.isNotEmpty) {
        await client.deleteUser(response.successResponse.users[0].id);
      }
    });

    test('GET', () async {
      var result = await client.retrieveApplications();
      expect(result.statusCode, equals(200));
      expect(result.successResponse, isNotNull);
      expect(result.successResponse.applications.isNotEmpty, isTrue);
    });

    test('POST', () async {
      var request = UserRequest(
          sendSetPasswordEmail: false,
          skipVerification: true,
          user: User(email: 'test@example.com'));

      // This is a bit uggs. we could probably fix this somehow
      request.user.password = 'password';

      var result = await client.createUser(null, request);

      expect(result.statusCode, equals(200),
          reason: result.errorResponse != null
              ? 'Failed because of ${json.encode(result.errorResponse.toJson())}'
              : '');
      expect(result.successResponse, isNotNull);
      expect(result.successResponse.user.email, equals('test@example.com'));
    });

    // TODO POST, PUT, GET, DELETE, PATCH with json
    // TODO test the toJson of a subclass
    // TODO test an any setter return type
    // TODO test an any setter request type
  });
}

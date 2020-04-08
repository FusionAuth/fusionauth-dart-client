import 'dart:convert';

import 'package:fusionauth_dart_client/fusionauth_dart_client.dart';

void main() async {
  var client = FusionAuthClient('bf69486b-4733-4470-a592-f1bfce7af580',
      'https://local.fusionauth.io', null);

  var response = await client.searchUsersByQuery(SearchRequest(
      search: UserSearchCriteria(queryString: "email:test@example.com")));

  if (response.successResponse != null) {
    print(json.encode(response.successResponse.users));
  }
}

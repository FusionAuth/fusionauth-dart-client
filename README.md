# FusionAuth Dart Client

A library for FusionAuth Dart developers.

---

## Beta notice

This client is flagged as a beta client due to missing or incomplete features.

### Known limitations

* The use of some objects are limited due to missing support for dynamic fields (example: custom claims on a jwt). Currently any data placed in json will not render in dart unless the class is explicitly subclassed to contain those fields.
---

## Usage

A simple usage example:

```dart
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
```

pubspec.yaml:
```yaml
dependencies:
  fusionauth_dart_client: ^1.15.8-beta
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: https://github.com/FusionAuth/fusionauth-dart-client/issues

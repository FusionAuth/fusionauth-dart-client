# FusionAuth Dart Client ![semver 2.0.0 compliant](http://img.shields.io/badge/semver-2.0.0-brightgreen.svg?style=flat-square)
If you're integrating FusionAuth with a Dart or Flutter application, this library will speed up your development time.

For additional information and documentation on FusionAuth refer to [https://fusionauth.io](https://fusionauth.io).

A library for FusionAuth Dart developers.

---

### Known limitations

* The use of some objects are limited due to missing support for dynamic fields (example: custom claims on a jwt). Currently, any data placed in JSON will not render in dart unless the class is explicitly subclassed to contain those fields.
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
  fusionauth_dart_client: ^1.21.0
```

## Contributors

* [Dmitriy Scherbakov/sherbacov](https://github.com/sherbacov) added the auth example. 

## Questions and support

If you have a question or support issue regarding this client library, we'd love to hear from you.

If you have a paid edition with support included, please [open a ticket with via your account portal](https://account.fusionauth.io/account/support/). Learn more about [paid editions here](https://fusionauth.io/pricing/).

Otherwise, please [post your question in the community forum](https://fusionauth.io/community/forum/).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/FusionAuth/fusionauth-dart-client.

## License

This code is available as open source under the terms of the [Apache v2.0 License](https://opensource.org/licenses/Apache-2.0).


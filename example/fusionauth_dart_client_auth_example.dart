import 'package:fusionauth_dart_client/fusionauth_dart_client.dart'
    as fusionauth;

void main() async {
  var loginRequest = fusionauth.LoginRequest(
      loginId: 'user@domain.com', password: 'Password!');

  loginRequest.applicationId = '9e0f97c2-5563-4b81-83a8-1db6e6457906';
  loginRequest.noJWT = false;
  loginRequest.metaData = fusionauth.MetaData(
      device: fusionauth.DeviceInfo(
          name: 'IPhone XR', //DeviceName
          type: fusionauth.DeviceType.MOBILE));

  var client = fusionauth.FusionAuthClient(
      'bf69486b-4733-4470-a592-f1bfce7af580', //API Key
      'https://local.fusionauth.io',
      null);

  var result = await client.login(loginRequest);

  if (result.statusCode >= 200 && result.statusCode < 300) {
    print(result.successResponse.toJson());
    if (result.successResponse.user != null) {
      print(result.successResponse.user.toJson());
    }
  } else {
    // error
    print('statusCode: ' + result.statusCode.toString());
    if (result.statusCode == 404) {
      print('Result code 404 can mean the wrong user or password.');
    }

    if (result.errorResponse != null) {
      print(result.errorResponse.toJson());
    }
  }
}

// Copyright (c) 2012, the Dart project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:async';

import 'package:http/http.dart' as http;

import 'client.dart';
import 'handle_access_token_response.dart';
import 'utils.dart';

/// Obtains credentials using a [client credentials grant][].
///
/// This mode of authorization uses the client identifier and client secret
/// to obtain an authentication token, which can then be stored.
///
/// The client [identifier] and [secret] are issued by the server, and are
/// used to identify and authenticate your specific OAuth2 client. These are
/// usually global to the program using this library.
///
/// The specific permissions being requested from the authorization server may
/// be specified via [scopes]. The scope strings are specific to the
/// authorization server and may be found in its documentation. Note that you
/// may not be granted access to every scope you request; you may check the
/// [Credentials.scopes] field of [Client.credentials] to see which scopes you
/// were granted.
///
/// The scope strings will be separated by the provided [delimiter]. This
/// defaults to `" "`, the OAuth2 standard, but some APIs (such as Facebook's)
/// use non-standard delimiters.
Future<Client> clientCredentialsGrant(
    Uri tokenEndpoint,
    String identifier,
    String secret,
    {Iterable<String> scopes,
    bool basicAuth: true,
    bool implicitScopes: false,
    http.Client httpClient,
    String delimiter}) async {
  delimiter ??= ' ';
  var startTime = new DateTime.now();

  var body = {
    "grant_type": "client_credentials",
  };

  var headers = <String, String>{};

  if (basicAuth) {
    headers['Authorization'] = basicAuthHeader(identifier, secret);
  } else {
    body['client_id'] = identifier;
    if (secret != null) body['client_secret'] = secret;
  }

  if (scopes != null && !scopes.isEmpty) body['scope'] = scopes.join(delimiter);

  if (httpClient == null) httpClient = new http.Client();
  var response = await httpClient.post(tokenEndpoint,
      headers: headers, body: body);

  var credentials = await handleAccessTokenResponse(
      response, tokenEndpoint, startTime, scopes, delimiter, isClientCredentialsGrant: true);
  return new Client(credentials, identifier: identifier, secret: secret,
      httpClient: httpClient, implicitScopes: implicitScopes);
}

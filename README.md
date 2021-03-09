# kong

Kong does not support multiple types of authentication methods at the same time.

When the authentication method needs to be modified, such as switching from BasicAuth to HmacAuth, the service needs a transition period that supports multiple authentication methods.

# How does this plugin work

As specified in \[[RFC 7235](https://tools.ietf.org/html/rfc7235)\], each authentication type is determined by the auth-scheme in the HTTP Authentication Header.

| AuthType | AuthScheme |
| --- | --- |
| Basic Auth | Basic |
| JWT | Bearer |
| Hmac Auth | Hmac |
| AWS Signature Version 4 | AWS4-HMAC-SHA256 |

Therefore, according to the auth-scheme, the authentication type used by the request can be determined.

Then perform authentication according to the corresponding authentication type.

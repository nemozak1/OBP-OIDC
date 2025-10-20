# Client Credentials Flow Support

## Overview

OBP-OIDC now supports the OAuth 2.0 Client Credentials grant type, enabling service-to-service authentication without user interaction.

## What is Client Credentials Flow?

Client Credentials is an OAuth 2.0 grant type used for machine-to-machine authentication where:
- No user context is needed
- The client authenticates using its own credentials (client_id and client_secret)
- The resulting access token represents the client itself, not a user
- Useful for backend services, APIs, and automated processes

## How to Use

### Method 1: HTTP Basic Authentication (Recommended)

```bash
curl -X POST http://localhost:9000/obp-oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'YOUR_CLIENT_ID:YOUR_CLIENT_SECRET' | base64)" \
  -d "grant_type=client_credentials&scope=openid"
```

### Method 2: Form Parameters

```bash
curl -X POST http://localhost:9000/obp-oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=openid"
```

## Request Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `client_credentials` |
| `client_id` | Yes* | Your client identifier |
| `client_secret` | Yes* | Your client secret |
| `scope` | Optional | Requested scope (defaults to empty string) |

\* Can be provided via HTTP Basic Auth header or form parameters

## Response

### Success Response (200 OK)

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9pZGMta2V5LTEifQ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid"
}
```

**Note:** Client credentials flow does NOT return:
- `id_token` (no user to identify)
- `refresh_token` (client can request new tokens anytime)

### Error Response (400 Bad Request)

```json
{
  "error": "invalid_client",
  "error_description": "Invalid client credentials"
}
```

## Token Claims

Access tokens issued via client credentials include:

```json
{
  "iss": "http://localhost:9000/obp-oidc",
  "sub": "YOUR_CLIENT_ID",
  "aud": "http://localhost:9000/obp-oidc",
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "openid",
  "client_id": "YOUR_CLIENT_ID",
  "grant_type": "client_credentials"
}
```

Key differences from user tokens:
- `sub` (subject) is the client_id, not a user identifier
- `aud` (audience) is the issuer itself
- No user-specific claims (name, email, etc.)
- Includes `grant_type` claim set to "client_credentials"

## Configuration

### Client Setup

By default, all clients created by OBP-OIDC now support three grant types:
- `authorization_code`
- `refresh_token`
- `client_credentials`

This is configured in `ClientBootstrap.scala`:

```scala
private val DEFAULT_GRANT_TYPES =
  List("authorization_code", "refresh_token", "client_credentials")
```

### Discovery Document

The OIDC discovery document at `/.well-known/openid-configuration` advertises support:

```json
{
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "none"
  ]
}
```

## Use Cases

### Backend Service Authentication

```bash
# Service A authenticates to call Service B
ACCESS_TOKEN=$(curl -s -X POST http://localhost:9000/obp-oidc/token \
  -H "Authorization: Basic $(echo -n 'service-a:secret123' | base64)" \
  -d "grant_type=client_credentials&scope=api:read" | jq -r '.access_token')

# Use the token to call another service
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://api-service/protected-resource
```

### Automated Scripts

```python
import requests
import base64

client_id = "automation-client"
client_secret = "secret456"

# Encode credentials for Basic Auth
credentials = f"{client_id}:{client_secret}"
encoded = base64.b64encode(credentials.encode()).decode()

response = requests.post(
    "http://localhost:9000/obp-oidc/token",
    headers={
        "Authorization": f"Basic {encoded}",
        "Content-Type": "application/x-www-form-urlencoded"
    },
    data={
        "grant_type": "client_credentials",
        "scope": "api:write"
    }
)

token = response.json()["access_token"]
```

## Security Considerations

1. **Keep client secrets secure**: Treat them like passwords
2. **Use HTTPS in production**: Never send credentials over plain HTTP
3. **Rotate secrets regularly**: Update client secrets periodically
4. **Limit scope**: Request only the scopes your service needs
5. **Short-lived tokens**: Client credentials tokens should expire quickly (default: 1 hour)
6. **Monitor usage**: Track which clients are using this flow

## Implementation Details

### Files Modified

1. **AuthService.scala**: Added `authenticateClient` method
2. **DatabaseAuthService.scala**: Implemented client authentication
3. **JwtService.scala**: Added `generateClientCredentialsToken` method
4. **TokenEndpoint.scala**: Added `processClientCredentialsGrant` handler
5. **ClientBootstrap.scala**: Updated default grant types
6. **OidcModels.scala**: Added `grant_types_supported` to discovery document
7. **DiscoveryEndpoint.scala**: Advertise client credentials support

### Error Codes

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing required parameters |
| `invalid_client` | Client authentication failed |
| `unsupported_grant_type` | Grant type not supported (shouldn't happen) |

## Testing

Run the server and test with curl:

```bash
# Start the server
./run-server.sh

# Get client credentials from server output
# Look for lines like:
# Client ID: test-client-123
# Client Secret: secret-abc-456

# Test the endpoint
curl -v -X POST http://localhost:9000/obp-oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'test-client-123:secret-abc-456' | base64)" \
  -d "grant_type=client_credentials&scope=openid"
```

## Differences from Other Flows

| Feature | Authorization Code | Refresh Token | Client Credentials |
|---------|-------------------|---------------|-------------------|
| Requires user | Yes | No (uses refresh token) | No |
| Returns ID token | Yes | No | No |
| Returns refresh token | Yes | Yes | No |
| Subject (sub) | User ID | User ID | Client ID |
| Use case | User login | Token renewal | Service auth |

## Troubleshooting

### "Invalid client credentials"

- Verify client_id and client_secret are correct
- Check if client exists in database
- Ensure secret matches exactly (case-sensitive)

### "Missing client credentials"

- Include both client_id and client_secret
- Use either Basic Auth header OR form parameters (not both)
- Verify Content-Type header is set correctly

### Token validation fails

- Check token hasn't expired
- Verify issuer matches your OIDC server URL
- Ensure you're using the correct JWKS endpoint for validation

## References

- [RFC 6749 - OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749#section-4.4)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

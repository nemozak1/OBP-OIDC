# OBP-OIDC

A bare bones OpenID Connect (OIDC) provider built with http4s and functional programming in Scala. This implementation follows the same technology stack as OBP-API-II and integrates with PostgreSQL database for real user authentication.

## Features

- **Pure Functional Programming**: Built with Cats Effect IO and immutable data structures
- **Modern Scala**: Uses http4s, Circe for JSON, and functional error handling
- **PostgreSQL Database**: Authenticates real users from OBP authuser table via read-only view
- **Complete OIDC Support**: All essential endpoints for authorization code flow
- **JWT Tokens**: RS256 signed ID tokens and access tokens
- **BCrypt Password Verification**: Compatible with OBP-API password hashing
- **Integration Tests**: Comprehensive test suite demonstrating full OIDC flow

## Technology Stack

- **Language**: Scala 2.12 with functional programming principles
- **HTTP Framework**: http4s with Ember server
- **Effect System**: Cats Effect IO
- **Database**: PostgreSQL with Doobie for functional database access
- **JSON**: Circe for serialization/deserialization  
- **JWT**: Auth0 Java JWT library
- **Build Tool**: Maven
- **Testing**: ScalaTest

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- PostgreSQL database with OBP schema
- OBP authuser table with validated users

## Database Setup

### 1. PostgreSQL Database
Ensure you have a PostgreSQL database with the OBP authuser table populated with users.

### 2. Create OIDC Database User and View
Run the OIDC setup script to create a read-only database user and view:

```bash
psql -h localhost -p 5432 -d sandbox -U obp -f workspace_2024/OBP-API-C/OBP-API/obp-api/src/main/scripts/sql/create_oidc_user_and_views.sql
```

This script will:
- Create `oidc_user` with read-only access
- Create `v_authuser_oidc` view exposing validated users
- Set up proper permissions and security measures

### 3. Database Configuration
Set environment variables for database connection:

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=sandbox
export DB_USERNAME=oidc_user
export DB_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!
export DB_MAX_CONNECTIONS=10
```

⚠️ **Security Note**: Use a strong password and follow the security recommendations in the setup script.

## Quick Start

### Build and Run

1. **Compile the project:**
   ```bash
   mvn clean compile
   ```

2. **Run the server:**
   ```bash
   mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
   ```

3. **The server starts on http://localhost:8080**

### Server Configuration

Configure via environment variables:

```bash
export OIDC_HOST=localhost
export OIDC_PORT=8080
export OIDC_ISSUER=http://localhost:8080
export OIDC_KEY_ID=oidc-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600
```

## OIDC Endpoints

### Discovery Document
```
GET /.well-known/openid-configuration
```
Returns the OIDC discovery document with all endpoint URLs and supported features.

### Authorization Endpoint
```
GET /auth?response_type=code&client_id=YOUR_CLIENT&redirect_uri=YOUR_REDIRECT&scope=openid%20profile%20email&state=ABC123
```
Shows HTML login form for user authentication. Supports authorization code flow.

### Token Endpoint
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTH_CODE&redirect_uri=YOUR_REDIRECT&client_id=YOUR_CLIENT
```
Exchanges authorization code for ID token and access token.

### UserInfo Endpoint
```
GET /userinfo
Authorization: Bearer ACCESS_TOKEN
```
Returns user claims based on token scope.

### JWKS Endpoint
```
GET /jwks
```
Returns JSON Web Key Set for token verification.

## Authentication

### Database Users
This OIDC provider authenticates users from the PostgreSQL `v_authuser_oidc` view, which includes:
- All validated users from the authuser table
- BCrypt password verification
- User profile information (name, email)

### Supported User Fields
From the database view:
- `username`: Login identifier
- `firstname`, `lastname`: User's full name
- `email`: User's email address
- `uniqueid`: Used as OIDC subject identifier
- `validated`: Must be true for authentication
- `password_pw`: BCrypt password hash
- `password_slt`: Password salt for verification

## Example OIDC Flow

1. **Authorization Request:**
   ```
   http://localhost:8080/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid%20profile%20email&state=abc123
   ```

2. **User Login:** Enter valid database user credentials

3. **Authorization Code:** Redirected to your callback URL with code parameter

4. **Token Exchange:**
   ```bash
   curl -X POST http://localhost:8080/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=https://example.com/callback&client_id=test-client"
   ```

5. **UserInfo Request:**
   ```bash
   curl http://localhost:8080/userinfo \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

## Testing

### Database Connection Test
The server will test the database connection on startup and log the results.

### Integration Tests
Run the test suite:

```bash
mvn test
```

The tests demonstrate:
- Discovery document validation
- JWKS endpoint functionality
- Authorization flow with login forms
- Token generation and validation
- UserInfo endpoint with Bearer tokens
- Complete end-to-end OIDC flow

## Development

### Project Structure

```
src/main/scala/com/tesobe/oidc/
├── server/           # Main server setup
├── endpoints/        # OIDC endpoint implementations
├── auth/            # Database authentication service
├── tokens/          # JWT token handling
├── models/          # Data models with Circe JSON support
└── config/          # Configuration management
```

### Key Components

- **DatabaseAuthService**: PostgreSQL-based user authentication
- **JwtService**: JWT token generation and validation with RSA256
- **CodeService**: Authorization code management with expiration
- **Endpoints**: Individual OIDC endpoint implementations
- **OidcServer**: Main application with http4s routing

### Database Integration

- **Doobie**: Functional database access with connection pooling
- **HikariCP**: Connection pool management with proper timeouts
- **BCrypt**: Password verification compatible with OBP-API
- **Read-only Access**: Uses dedicated `oidc_user` with minimal permissions

### Functional Programming Principles

- Pure functions where possible
- Cats Effect IO for side effects
- Immutable data structures
- Monadic error handling with Either types
- Thread-safe database access with connection pooling

## Security Considerations

- Database user has read-only access to validated users only
- BCrypt password verification with proper salt handling
- Connection pooling with leak detection and timeouts
- SSL/TLS preference for database connections
- Comprehensive logging for security monitoring
- No password storage in memory beyond verification

## Troubleshooting

### Database Connection Issues
1. Verify PostgreSQL is running and accessible
2. Check database credentials and permissions
3. Ensure `v_authuser_oidc` view exists and is accessible
4. Review database logs for connection errors

### Authentication Failures
1. Verify user exists and is validated in authuser table
2. Check password hash format matches BCrypt expectations
3. Review application logs for authentication attempts
4. Ensure database view returns expected user data

## License

This project is licensed under the same terms as the Open Bank Project.
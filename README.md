# OBP-OIDC

A bare bones OpenID Connect (OIDC) provider built with http4s and functional programming in Scala. This implementation follows the same technology stack as OBP-API-II and integrates with PostgreSQL database for real user authentication.

It's meant to be used with OBP-API and apps such as the OBP Portal.

If you're having trouble understanding OIDC with OBP this tool might help.

Designed to create clients for the OBP Apps as it starts up. It will print client_id, secrets and other info so you can copy and paste into your Props or env files.

Designed to read / write to the OBP Users and Consumers tables via SQL views defined in https://github.com/OpenBankProject/OBP-API/blob/develop/obp-api/src/main/scripts/sql/create_oidc_user_and_views.sql


Very Work in Progress.

Please take the following with a very big pinch of salt!


## Features

- **Pure Functional Programming**: Built with Cats Effect IO and immutable data structures
- **Modern Scala**: Uses http4s, Circe for JSON, and functional error handling
- **PostgreSQL Database**: Authenticates real users from OBP authuser table via read-only view
- **Complete OIDC Support**: All essential endpoints for authorization code flow
- **Client Management**: CRUD operations for OIDC clients via admin database user
- **Automatic Client Creation**: Auto-creates OBP-API, Portal, Explorer II, and Opey II clients on startup
- **JWT Tokens**: RS256 signed ID tokens and access tokens
- **BCrypt Password Verification**: Compatible with OBP-API password hashing
- **Integration Tests**: Comprehensive test suite demonstrating full OIDC flow

## Technology Stack

- **Language**: Scala 2.13 with functional programming principles
- **HTTP Framework**: http4s with Ember server
- **Effect System**: Cats Effect IO
- **Database**: PostgreSQL with Doobie for functional database access
- **JSON**: Circe for serialization/deserialization
- **JWT**: Auth0 Java JWT library
- **Build Tool**: Maven
- **Testing**: ScalaTest

## Quick Start for Developers 🚀

**New to OBP-OIDC? Get up and running in 3 steps:**

### Step 1: Generate Configuration

```bash
# Interactive configuration generator
./generate-config.sh

# Or generate directly
mvn exec:java -Dexec.args="--generate-config"
```

### Step 2: Locate your OBP database.

see below

### Step 3: Start OBP-OIDC

```bash
# Export the generated environment variables
export OIDC_USER_PASSWORD=YourGeneratedPassword123!
export OIDC_ADMIN_PASSWORD=YourGeneratedAdminPass456#
# ... (other exports from generated config)

# Start the server
./run-server.sh
```

**That's it!** 🎉 Copy the printed OIDC client configurations to your OBP projects.

---

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

**Read-Only Database User** (for user authentication):

```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=sandbox
export OIDC_USER_USERNAME=oidc_user
export OIDC_USER_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!
export DB_MAX_CONNECTIONS=10
```

**Admin Database User** (for client management via v_oidc_admin_clients):

```bash
export OIDC_ADMIN_USERNAME=oidc_admin_user
export OIDC_ADMIN_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_ADMIN_PASSWORD_2024!
export DB_ADMIN_MAX_CONNECTIONS=5
```

**OBP Ecosystem Client Configuration** (optional - auto-generated if not set):

```bash
export OIDC_CLIENT_OBP_API_ID=obp-api-client
export OIDC_CLIENT_OBP_API_SECRET=YOUR_SECURE_SECRET_HERE
export OIDC_CLIENT_OBP_API_REDIRECTS=http://localhost:8080/auth/openid-connect/callback

export OIDC_CLIENT_PORTAL_ID=obp-portal-client
export OIDC_CLIENT_PORTAL_SECRET=YOUR_SECURE_SECRET_HERE
export OIDC_CLIENT_PORTAL_REDIRECTS=http://localhost:5174/login/obp/callback

export OIDC_CLIENT_EXPLORER_ID=obp-explorer-ii-client
export OIDC_CLIENT_EXPLORER_SECRET=YOUR_SECURE_SECRET_HERE
export OIDC_CLIENT_EXPLORER_REDIRECTS=http://localhost:3001/callback,http://localhost:3001/oauth/callback

export OIDC_CLIENT_OPEY_ID=obp-opey-ii-client
export OIDC_CLIENT_OPEY_SECRET=YOUR_SECURE_SECRET_HERE
export OIDC_CLIENT_OPEY_REDIRECTS=http://localhost:3002/callback,http://localhost:3002/oauth/callback
```

⚠️ **Security Note**: Use a strong password and follow the security recommendations in the setup script.

### 4. Test Admin Database Connection (Optional)

Before running the server, you can test your admin database configuration:

```bash
# Copy and customize the test script
cp test-admin-db.example.sh test-admin-db.sh
nano test-admin-db.sh  # Edit with your admin database credentials
chmod +x test-admin-db.sh

# Run the test
./test-admin-db.sh
```

This will verify:

- Basic admin database connection
- Access to `v_oidc_admin_clients` view
- INSERT, UPDATE, and DELETE permissions

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

3. **The server starts on http://localhost:9000** and automatically:
   - Creates OIDC clients for OBP-API, Portal, Explorer II, and Opey II
   - Prints complete client configurations for easy integration
   - Tests all database connections

### Using the Run Script (Recommended)

For easier configuration and running:

1. **Copy the example script:**

   ```bash
   cp run-server.sh run-server.sh
   ```

2. **Edit your database credentials:**

   ```bash
   nano run-server.sh
   # Edit the DB_* environment variables with your actual database settings
   ```

3. **Make it executable and run:**
   ```bash
   chmod +x run-server.sh
   ./run-server.sh
   ```

The script will:

- ✅ Set all necessary environment variables
- ✅ Build the project
- ✅ Start the server with helpful output
- ✅ Show available endpoint URLs
- ✅ Print ready-to-use OBP-API configuration

### Server Configuration

#### Port Configuration

The server runs on port **9000** by default. You can change this by setting the `OIDC_PORT` environment variable:

```bash
# Run on default port 9000
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"

# Run on custom port (e.g., 8080)
export OIDC_PORT=8080
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"

# Or set inline
OIDC_PORT=8080 mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

#### All Configuration Options

Configure via environment variables:

```bash
export OIDC_HOST=localhost
export OIDC_PORT=9000
export OIDC_ISSUER=http://localhost:9000
export OIDC_KEY_ID=oidc-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600
```

#### OBP-API Configuration Output

When the server starts, it automatically prints the complete OBP-API configuration:

```
📋 OBP-API CONFIGURATION - Copy and paste into your props file:
================================================================================

# OIDC Configuration for OBP-OIDC Provider
openid_connect.scope=openid email profile

# OBP-API OIDC Provider Settings
openid_connect_1.button_text=OBP-OIDC
openid_connect_1.client_id=obp-api-client
openid_connect_1.client_secret=generated-secret-here
openid_connect_1.callback_url=http://127.0.0.1:8080/auth/openid-connect/callback

# OIDC Endpoints
openid_connect_1.endpoint.discovery=http://localhost:9000/.well-known/openid-configuration
# ... plus SQL for client registration
```

Simply copy this output to your OBP-API props file!

#### Security Note

⚠️ **Important**: The `run-server.sh` file is in `.gitignore` to prevent accidentally committing database credentials. Always:

- Keep your database passwords secure
- Never commit `run-server.sh` with real credentials
- Use the `run-server.example.sh` template for sharing configurations

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

## Testing the Server

### Quick Health Check

Once the server is running, test it with these curl commands:

```bash
# Health check
curl -v http://localhost:9000/health
# Expected: "OIDC Provider is running"

# Root welcome page
curl -v http://localhost:9000/
# Expected: HTML page with endpoint documentation
```

### OIDC Discovery Document ⭐

This is the standard OIDC well-known URL that clients use to discover your service:

```bash
curl http://localhost:9000/.well-known/openid-configuration
```

**Expected JSON response:**

```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/auth",
  "token_endpoint": "http://localhost:9000/token",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "jwks_uri": "http://localhost:9000/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```

### JSON Web Key Set (JWKS)

```bash
curl http://localhost:9000/jwks
```

**Expected JSON response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "your-key-id",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Authorization Endpoint (Login Form)

```bash
curl "http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid%20profile%20email&state=test123"
```

**Expected:** HTML login form

### Browser Testing

Open these URLs in your browser:

- **Welcome Page**: `http://localhost:9000/`
- **Discovery**: `http://localhost:9000/.well-known/openid-configuration`
- **JWKS**: `http://localhost:9000/jwks`
- **Login Form**: `http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid&state=test123`

## Authentication

### Database Views

This OIDC provider uses three PostgreSQL database views:

#### User Authentication (`v_oidc_users`)

- Authenticates users from the validated authuser table
- BCrypt password verification
- User profile information (name, email)

#### Client Registration (`v_oidc_clients`)

- Validates registered OIDC clients
- Controls allowed redirect URIs
- Manages client permissions and scopes

#### Client Management (`v_oidc_admin_clients`)

- Provides write access for client administration
- Used by admin database user for CRUD operations
- Supports creating, updating, and deleting OIDC clients

### Supported Database Fields

#### User Fields (`v_oidc_users` view)

- `user_id`: Internal unique identifier
- `username`: Login identifier, used as OIDC subject (`sub`) claim for OBP-API compatibility
- `firstname`, `lastname`: User's full name
- `email`: User's email address
- `provider`: Authentication provider, used as OIDC issuer (`iss`) claim for OBP-API compatibility
- `validated`: Must be true for authentication

#### Client Fields (`v_oidc_clients` and `v_oidc_admin_clients` views)

- `client_id`: Unique client identifier
- `client_secret`: Client authentication secret
- `client_name`: Human-readable client name
- `redirect_uris`: Comma-separated list of allowed redirect URIs
- `grant_types`: Supported OAuth2 grant types
- `response_types`: Supported OAuth2 response types
- `scopes`: Available OAuth2 scopes
- `token_endpoint_auth_method`: Client authentication method
- `created_at`: Client registration timestamp
- `password_pw`: BCrypt password hash
- `password_slt`: Password salt for verification

#### Client Fields (`v_oidc_clients` view)

- `client_id`: Unique client identifier
- `client_secret`: Secret for confidential clients (optional)
- `client_name`: Human-readable application name
- `redirect_uris`: JSON array of allowed callback URLs
- `grant_types`: Supported OAuth2 grant types (default: authorization_code)
- `scopes`: Allowed access scopes (default: openid, profile, email)
- `token_endpoint_auth_method`: Client authentication method

## OBP-API Integration

### JWT Token Claims

For compatibility with OBP-API, JWT tokens are generated with specific claim mappings from the `v_oidc_users` database view:

- **`sub` (Subject)**: Contains the user's `username` field from `v_oidc_users`
  - Source: `v_oidc_users.username`
  - Purpose: OBP-API uses this to identify the user
- **`iss` (Issuer)**: Contains the user's `provider` field from `v_oidc_users`
  - Source: `v_oidc_users.provider`
  - Purpose: OBP-API uses this to identify the authentication provider
- **Standard claims**: Populated from user data in `v_oidc_users`
  - `name`: Combined from `v_oidc_users.firstname` and `v_oidc_users.lastname`
  - `email`: From `v_oidc_users.email`
  - `email_verified`: From `v_oidc_users.validated`

This ensures that OBP-API can correctly identify users using the `sub` field as username and `iss` field as provider, exactly as required for proper integration.

### Token Validation

The OIDC server accepts tokens with various provider-based issuers, providing flexibility for different authentication providers while maintaining security.

## Example OIDC Flow

1. **Authorization Request:**

   ```
   http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid%20profile%20email&state=abc123
   ```

2. **User Login:** Enter valid database user credentials

3. **Authorization Code:** Redirected to your callback URL with code parameter

4. **Token Exchange:**

   ```bash
   curl -X POST http://localhost:9000/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=https://example.com/callback&client_id=test-client"
   ```

5. **UserInfo Request:**
   ```bash
   curl http://localhost:9000/userinfo \
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

### Client Management

- **Automatic Bootstrap**: Creates standard OBP ecosystem clients on startup
- **Environment Configuration**: Fully customizable via environment variables
- **Secure Secret Generation**: Auto-generates cryptographically secure client secrets
- **Update Detection**: Intelligently updates clients when configuration changes
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

## Database Callback URL Fix

### Issue: Wrong Callback URL in Database

If you encounter redirect issues where the system redirects to `http://localhost:8080/oauth/callback` instead of `http://localhost:8080/auth/openid-connect/callback`, you need to update the database record.

**Root Cause:** The `consumer` table stores the client's `redirecturl` field, which may have been set incorrectly during initial client creation.

**Fix Steps:**

1. **Run the SQL fix script:**

   ```bash
   psql -d sandbox -f fix-callback-url.sql
   ```

2. **Or manually update via SQL:**

   ```sql
   UPDATE consumer
   SET redirecturl = 'http://localhost:8080/auth/openid-connect/callback'
   WHERE key_c = 'obp-api-client';
   ```

3. **Verify the fix:**
   ```sql
   SELECT key_c, name, redirecturl FROM consumer WHERE key_c = 'obp-api-client';
   ```

**Expected Output:**

```
 client_id    | client_name           | redirecturl
--------------+-----------------------+------------------------------------------------
 obp-api-client| OBP-API Core Service | http://localhost:8080/auth/openid-connect/callback
```

This ensures the OAuth authorization flow redirects to the correct OBP-API endpoint.

## Password Verification Fix

### Issue Resolution - OBP-API Password Hash Compatibility

**Problem:** OBP-OIDC was unable to verify passwords hashed by OBP-API due to incompatible BCrypt format handling.

**Root Cause:** OBP-API uses Lift framework's MegaProtoUser which stores BCrypt hashes in a custom format:

- Format: `password_pw = "b;" + BCrypt.hashpw(password, salt).substring(0, 44)`
- The "b;" prefix indicates BCrypt format
- Hash is truncated to 44 characters
- Salt is stored separately in `password_slt` field

**Solution Implemented:**

1. **Added jBCrypt dependency** (same library used by OBP-API):

   ```xml
   <dependency>
     <groupId>org.mindrot</groupId>
     <artifactId>jbcrypt</artifactId>
     <version>0.4</version>
   </dependency>
   ```

2. **Updated password verification logic** in `DatabaseAuthService.scala`:

   ```scala
   if (storedHash.startsWith("b;")) {
     val hashWithoutPrefix = storedHash.substring(2) // Remove "b;" prefix
     val generatedHash = JBCrypt.hashpw(plainPassword, salt).substring(0, 44)
     val isMatch = generatedHash == hashWithoutPrefix
   }
   ```

3. **Database view compatibility** - Uses existing `v_oidc_users` view fields:
   - `password_pw` - Contains "b;" + truncated hash
   - `password_slt` - Contains BCrypt salt

**Verification Process:**

1. Detect "b;" prefix format
2. Extract hash without prefix
3. Generate hash using `JBCrypt.hashpw(password, salt)`
4. Truncate to 44 characters
5. Compare with stored hash

**Testing:**

- Use `test-password-verification.scala` to validate implementation
- Comprehensive debug logging added for troubleshooting
- Character-by-character comparison for failed attempts

This fix ensures 100% compatibility with OBP-API password verification.

## Troubleshooting

### Server Startup Hanging

If the server hangs during startup (especially after showing "🚀 Initializing OBP ecosystem OIDC clients..."):

1. **Admin Database Issues**: The server may be waiting for admin database connection

   ```bash
   # Check if admin database user exists and has permissions
   ./test-admin-db.sh
   ```

2. **Quick Fix**: The server has built-in timeouts (15 seconds) and will continue startup
   - Wait up to 30 seconds for automatic recovery
   - Look for timeout warnings in logs
   - Server will provide manual SQL commands if admin DB unavailable

3. **Manual Client Creation**: If admin database unavailable, copy SQL from server logs:

   ```sql
   INSERT INTO v_oidc_admin_clients (client_id, client_secret, client_name, ...)
   VALUES ('obp-api-client', 'your-secret', 'OBP-API', ...);
   ```

4. **Disable Client Bootstrap**: Set environment variable to skip:
   ```bash
   export OIDC_SKIP_CLIENT_BOOTSTRAP=true
   ```

### Database Connection Issues

1. Verify PostgreSQL is running and accessible
2. Check database credentials and permissions:
   - `OIDC_USER_USERNAME` and `OIDC_USER_PASSWORD` for read-only access
   - `OIDC_ADMIN_USERNAME` and `OIDC_ADMIN_PASSWORD` for client management
3. Ensure database views exist:
   - `v_oidc_users` for user authentication
   - `v_oidc_clients` for client validation
   - `v_oidc_admin_clients` for client management (optional)
4. Review database logs for connection errors

### Authentication Failures

1. Verify user exists and is validated in authuser table
2. Check password hash format - should start with "b;" for OBP-API compatibility
3. Verify jBCrypt library is available (org.mindrot:jbcrypt:0.4)
4. Review application logs for detailed password verification debug output
5. Use test-password-verification.scala to validate hash generation
6. Ensure database view returns expected user data

### Callback URL Issues

If authentication succeeds but redirects to wrong URL:

1. Check the `consumer` table `redirecturl` field:

   ```sql
   SELECT key_c, redirecturl FROM consumer WHERE key_c = 'obp-api-client';
   ```

2. Should be: `http://localhost:8080/auth/openid-connect/callback` (not `/oauth/callback`)

3. Fix with: `psql -d sandbox -f fix-callback-url.sql`

4. Restart OBP-OIDC service after database changes

## License

This project is licensed under the same terms as the Open Bank Project.

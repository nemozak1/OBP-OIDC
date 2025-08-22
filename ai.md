# OBP-OIDC Project Goals and Requirements

## Project Overview
Create a bare bones OpenID Connect (OIDC) provider using modern Scala with functional programming principles, following the same technology stack as OBP-API-II. Now integrated with PostgreSQL database for real user authentication.

## Technology Stack
- **Language**: Scala 2.13+ with functional programming style
- **HTTP Framework**: http4s (same as OBP-API-II)
- **Effect System**: Cats Effect IO
- **JSON Handling**: Circe
- **Build Tool**: Maven (to match OBP-API-II structure)
- **Database**: PostgreSQL with Doobie for functional database access
- **Authentication**: Real database authentication via v_authuser_oidc view

## Core Requirements

### 1. OIDC Provider Endpoints
Implement the minimal OIDC endpoints required for basic functionality:
- `/.well-known/openid-configuration` - Discovery endpoint
- `/auth` - Authorization endpoint
- `/token` - Token endpoint
- `/userinfo` - UserInfo endpoint
- `/jwks` - JSON Web Key Set endpoint

### 2. Authentication Strategy
- **POSTGRESQL DATABASE**: Connect to OBP database via read-only view v_authuser_oidc
- Authenticate real users from authuser table with BCrypt password verification
- Compatible with existing OBP-API user authentication system

### 3. Token Management
- Generate JWT tokens for ID tokens and access tokens
- Implement basic token validation
- Use RS256 algorithm for signing
- Generate and manage JWK keys in memory

### 4. OIDC Flow Support
Initially support:
- Authorization Code Flow
- Basic scopes: `openid`, `profile`, `email`
- Standard OIDC claims in ID token

### 5. Functional Programming Principles
- Pure functions where possible
- Use Cats Effect IO for side effects
- Immutable data structures
- Monadic error handling
- No mutable state except where absolutely necessary

### 6. Project Structure
Follow OBP-API-II patterns:
```
src/main/scala/
├── com/tesobe/oidc/
│   ├── server/           # Main server setup
│   ├── endpoints/        # OIDC endpoint implementations
│   ├── auth/            # Authentication logic
│   ├── tokens/          # JWT token handling
│   ├── models/          # Data models
│   └── config/          # Configuration
```

## Non-Requirements (Out of Scope)
- User registration/management (use existing OBP users)
- Complex scopes and permissions
- Advanced OIDC features (PKCE, etc.)
- Production-ready security hardening beyond database security
- Persistent key storage
- Session management beyond basic flow

## Success Criteria
1. Server starts and serves OIDC discovery document
2. Can authenticate real users via PostgreSQL database
3. Completes authorization code flow successfully
4. Issues valid JWT ID tokens and access tokens
5. UserInfo endpoint returns user claims from database
6. Code follows functional programming principles
7. Integration test demonstrating full OIDC flow with database

## Development Phases
1. **Phase 1**: Project setup, basic http4s server, discovery endpoint ✅
2. **Phase 2**: Mocked authentication service, basic models ✅
3. **Phase 3**: JWT token generation and validation ✅
4. **Phase 4**: Authorization and token endpoints ✅
5. **Phase 5**: UserInfo endpoint and integration testing ✅
6. **Phase 6**: PostgreSQL database integration ✅

## Database Setup
Requires PostgreSQL database with OBP authuser table and OIDC view:
1. Run OBP database setup to create authuser table
2. Execute `create_oidc_user_and_views.sql` to create read-only view and oidc_user
3. Set environment variables: DB_HOST, DB_PORT, DB_NAME, OIDC_USER_USERNAME, OIDC_USER_PASSWORD
4. Any validated user in the authuser table can authenticate

Database View: `v_authuser_oidc` provides read-only access to validated users with BCrypt password verification.

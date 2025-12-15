# SQL Injection Protection

## Overview

This application is **protected against SQL injection attacks** through the use of parameterized queries via the Doobie library.

## Implementation

### Doobie Library

The application uses [Doobie](https://tpolecat.github.io/doobie/) (version 1.0.0-RC4), a pure functional JDBC layer for Scala that provides automatic SQL injection protection through parameterized queries (prepared statements).

### How It Works

All database queries use Doobie's SQL interpolator syntax:

```scala
val query = sql"""
  SELECT user_id, username, firstname, lastname, email,
         validated, provider, password_pw, password_slt,
         createdat, updatedat
  FROM v_oidc_users
  WHERE username = $username AND provider = $provider AND validated = true
""".query[DatabaseUser]
```

The `$username` and `$provider` variables are **NOT** string interpolation. Doobie automatically converts these into JDBC prepared statements:

```sql
WHERE username = ? AND provider = ?
```

And safely binds the parameter values, ensuring that:

- Special SQL characters (`'`, `"`, `;`, `--`, etc.) are treated as literal data, not SQL code
- No string concatenation occurs
- The PostgreSQL JDBC driver handles proper escaping

## Protected Inputs

All user-supplied inputs from the `/obp-oidc/auth` login form are protected:

| Input Field    | Protection Method                                                | Location                                                                                   |
| -------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `username`     | Input validation (8-100 chars) + Parameterized query             | `AuthEndpoint.validateAuthInput()` + `DatabaseAuthService.findUserByUsernameAndProvider()` |
| `password`     | Input validation (10-512 chars) + BCrypt comparison (not in SQL) | `AuthEndpoint.validateAuthInput()` + `DatabaseAuthService.authenticate()`                  |
| `provider`     | Input validation (5-512 chars) + Parameterized query             | `AuthEndpoint.validateAuthInput()` + `DatabaseAuthService.findUserByUsernameAndProvider()` |
| `client_id`    | Parameterized query                                              | `DatabaseAuthService.findClientById()`                                                     |
| `redirect_uri` | Whitelist validation (not directly in SQL)                       | `DatabaseAuthService.validateClient()`                                                     |

## Code Examples

### ✅ SAFE - Parameterized Query (Current Implementation)

```scala
// Doobie automatically creates prepared statement
val query = sql"""
  SELECT * FROM v_oidc_users
  WHERE username = $username AND provider = $provider
""".query[DatabaseUser]
```

This becomes:

```sql
SELECT * FROM v_oidc_users WHERE username = ? AND provider = ?
-- Parameters: [username_value, provider_value]
```

## Additional Security Measures

1. **Input Length Validation**: All authentication inputs are validated before processing:
   - Username: 8-100 characters
   - Password: 10-512 characters
   - Provider: 5-512 characters
   - This prevents DoS attacks via oversized inputs and ensures database compatibility

2. **Read-Only Database User**: The main `oidc_user` database account has read-only access to views, limiting potential damage from any hypothetical SQL injection.

3. **Database Views**: Application only accesses data through views (`v_oidc_users`, `v_oidc_clients`), not direct table access.

4. **Whitelist Validation**: Input validation occurs before database queries (e.g., redirect_uri whitelist checking).

5. **BCrypt Password Hashing**: Passwords are never stored or queried in plaintext; only BCrypt hashes are compared.

## Verification

To verify SQL injection protection is working:

1. Attempt login with malicious username: `admin' OR '1'='1`
2. The parameterized query treats this as a literal username string
3. Authentication fails because no user exists with that exact username
4. No SQL injection occurs

## Dependencies

From `pom.xml`:

```xml
<doobie.version>1.0.0-RC4</doobie.version>

<dependency>
  <groupId>org.tpolecat</groupId>
  <artifactId>doobie-core_${scala.version}</artifactId>
  <version>${doobie.version}</version>
</dependency>
<dependency>
  <groupId>org.tpolecat</groupId>
  <artifactId>doobie-postgres_${scala.version}</artifactId>
  <version>${doobie.version}</version>
</dependency>
```

## Conclusion

**SQL injection protection is complete** through Doobie's parameterized queries. **Input validation is implemented** to prevent denial-of-service attacks and ensure data fits within database constraints. Together, these provide defense-in-depth security without breaking legitimate use cases.

### Key Points:

- ✅ Parameterized queries prevent SQL injection (no sanitization needed)
- ✅ Length validation prevents DoS and ensures database compatibility
- ✅ Legitimate characters (including `'`, `"`, etc.) are allowed
- ✅ Business logic validation is separate from SQL injection protection

## References

- [Doobie Documentation](https://tpolecat.github.io/doobie/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Prepared Statements in JDBC](https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html)

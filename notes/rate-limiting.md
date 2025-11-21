# Rate Limiting

## Overview

The OBP-OIDC server implements rate limiting to prevent brute force authentication attacks. Rate limiting tracks failed login attempts by both IP address and username, providing defense-in-depth security.

## Implementation

### In-Memory Rate Limiting

The current implementation uses in-memory storage via `InMemoryRateLimitService`. This is suitable for:
- Single-instance deployments
- Development and testing environments
- Small to medium scale production deployments

**Advantages:**
- No external dependencies
- Fast (no network latency)
- Simple to configure and maintain

**Limitations:**
- Rate limit state is lost on server restart (acceptable for rate limiting)
- Does not work across multiple server instances
- Memory bounded by server resources

### How It Works

1. **Before Authentication**: Check if the IP or username is rate-limited
2. **Record Attempts**: Track each failed login attempt with timestamp
3. **Sliding Window**: Only count attempts within the configured time window
4. **Block When Exceeded**: Temporarily block IP or username after threshold reached
5. **Success Resets**: Successful login clears all failed attempts for that IP/username
6. **Automatic Cleanup**: Periodically removes old attempts and expired blocks

## Configuration

Rate limiting is configured via environment variables:

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `RATE_LIMIT_MAX_ATTEMPTS_PER_IP` | `10` | Maximum failed attempts per IP address within the time window |
| `RATE_LIMIT_MAX_ATTEMPTS_PER_USERNAME` | `5` | Maximum failed attempts per username within the time window |
| `RATE_LIMIT_WINDOW_SECONDS` | `300` | Time window for counting attempts (5 minutes) |
| `RATE_LIMIT_BLOCK_SECONDS` | `900` | How long to block after exceeding limit (15 minutes) |

### Example Configuration

```bash
# Strict rate limiting (for high-security environments)
export RATE_LIMIT_MAX_ATTEMPTS_PER_IP=5
export RATE_LIMIT_MAX_ATTEMPTS_PER_USERNAME=3
export RATE_LIMIT_WINDOW_SECONDS=300
export RATE_LIMIT_BLOCK_SECONDS=1800

# Lenient rate limiting (for development)
export RATE_LIMIT_MAX_ATTEMPTS_PER_IP=20
export RATE_LIMIT_MAX_ATTEMPTS_PER_USERNAME=10
export RATE_LIMIT_WINDOW_SECONDS=600
export RATE_LIMIT_BLOCK_SECONDS=300
```

## Attack Scenarios Prevented

### 1. Brute Force Attack from Single IP

**Scenario**: Attacker tries many passwords for different usernames from one IP.

**Protection**: After 10 failed attempts from that IP (default), the IP is blocked for 15 minutes.

**User Experience**: Legitimate users from that IP cannot authenticate until the block expires.

### 2. Credential Stuffing

**Scenario**: Attacker uses stolen credentials from multiple IPs to target specific accounts.

**Protection**: After 5 failed attempts for a username (default), that username is blocked for 15 minutes, regardless of IP.

**User Experience**: The targeted account cannot authenticate until the block expires, even from legitimate IPs.

### 3. Distributed Brute Force

**Scenario**: Attacker uses many IPs to try passwords for a specific username.

**Protection**: Username-based rate limiting blocks the account after the threshold, preventing further attempts from any IP.

**User Experience**: Account is temporarily locked after repeated failures.

## Rate Limit Flow

```
User Login Attempt
       ↓
Check IP Rate Limit
       ↓
   Blocked? ─YES→ Return Error (429-style)
       ↓ NO
Check Username Rate Limit
       ↓
   Blocked? ─YES→ Return Error (429-style)
       ↓ NO
Record Failed Attempt
       ↓
Attempt Authentication
       ↓
   Success? ─YES→ Clear Failed Attempts
       ↓           ↓
      NO          Return Success
       ↓
Count Recent Attempts
       ↓
Exceeded Limit? ─YES→ Block IP/Username
       ↓ NO              ↓
Return Auth Failed   Return Error (Blocked)
```

## Error Messages

When rate limited, users receive descriptive error messages:

### IP Rate Limited
```
Too many failed login attempts from this IP address. 
Please try again in 15 minutes.
```

### Username Rate Limited
```
Too many failed login attempts for this account. 
Please try again in 15 minutes.
```

### Just Exceeded Limit
```
Too many failed login attempts. Your IP address has been 
temporarily blocked for 15 minutes.
```

## Logging

Rate limiting events are logged for security monitoring:

```
WARN  - Rate limit: IP blocked: 192.168.1.100
WARN  - Rate limit: Username blocked: testuser
WARN  - Rate limit: Blocking IP 192.168.1.100 after 10 attempts
WARN  - Rate limit: Blocking username testuser after 5 attempts
DEBUG - Rate limit: Recorded failed attempt for IP 192.168.1.100, 
        username testuser (IP: 3/10, Username: 2/5)
DEBUG - Rate limit: Clearing failed attempts for IP 192.168.1.100, 
        username testuser
```

## Testing Rate Limiting

### Manual Testing

1. **Test IP rate limiting:**
   ```bash
   # Make 11 failed login attempts with different usernames
   for i in {1..11}; do
     curl -X POST http://localhost:9000/obp-oidc/auth \
       -d "username=user$i&password=wrong&provider=obp-test&client_id=test&redirect_uri=http://localhost/callback&scope=openid"
   done
   # 11th attempt should be blocked
   ```

2. **Test username rate limiting:**
   ```bash
   # Make 6 failed login attempts for the same username
   for i in {1..6}; do
     curl -X POST http://localhost:9000/obp-oidc/auth \
       -d "username=testuser&password=wrong$i&provider=obp-test&client_id=test&redirect_uri=http://localhost/callback&scope=openid"
   done
   # 6th attempt should be blocked
   ```

3. **Test successful login clears attempts:**
   ```bash
   # Fail 3 times
   for i in {1..3}; do
     curl -X POST http://localhost:9000/obp-oidc/auth \
       -d "username=alice123&password=wrong&provider=obp-test&client_id=test&redirect_uri=http://localhost/callback&scope=openid"
   done
   
   # Succeed once with correct password
   curl -X POST http://localhost:9000/obp-oidc/auth \
     -d "username=alice123&password=secret123456&provider=obp-test&client_id=test&redirect_uri=http://localhost/callback&scope=openid"
   
   # Failed attempts should be cleared, can try again
   ```

## Future Enhancements

### Redis-Based Rate Limiting

For multi-instance deployments behind a load balancer, implement Redis-based rate limiting:

**Benefits:**
- Shared state across multiple server instances
- Persistent rate limit state across restarts
- Scales horizontally

**Implementation:**
```scala
class RedisRateLimitService(
  config: RateLimitConfig,
  redisClient: RedisClient
) extends RateLimitService[IO] {
  // Use Redis sorted sets for time-based tracking
  // Use Redis key expiration for automatic cleanup
}
```

### Additional Features

1. **Progressive Delays**: Increase delay between attempts exponentially
2. **CAPTCHA Integration**: Show CAPTCHA after 2-3 failed attempts
3. **Email Notifications**: Alert users about suspicious login attempts
4. **IP Whitelisting**: Exclude trusted IPs from rate limiting
5. **Account Recovery**: Self-service unlock via email verification
6. **Admin Override**: Allow admins to manually unblock IPs/usernames
7. **Analytics Dashboard**: Visualize rate limiting events and patterns

## Security Considerations

1. **Rate Limit State**: In-memory state is lost on restart, which is acceptable as it only temporarily affects rate limiting
2. **IP Spoofing**: Rate limiting by IP can be bypassed with VPNs/proxies, but username rate limiting provides second layer
3. **Denial of Service**: Attackers could intentionally lock out legitimate users by failing logins for target usernames
4. **Privacy**: IP addresses in logs may be considered personal data under GDPR
5. **False Positives**: Shared IPs (corporate networks, VPNs) may affect multiple legitimate users

## Best Practices

1. **Monitor Logs**: Regularly review rate limit logs for attack patterns
2. **Tune Thresholds**: Adjust limits based on your security requirements and user behavior
3. **User Communication**: Clearly communicate rate limiting to users
4. **Account Recovery**: Provide mechanism for users to unlock their accounts
5. **Combined with Other Security**: Use alongside strong passwords, 2FA, account monitoring

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Credential Stuffing Prevention](https://owasp.org/www-community/attacks/Credential_stuffing)
- [Rate Limiting Design Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)

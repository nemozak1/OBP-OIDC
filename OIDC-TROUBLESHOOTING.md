# OBP-OIDC Troubleshooting Guide

This guide helps diagnose and fix common issues with OBP-OIDC, especially the error:
**"Authorization endpoint not found in OIDC configuration"** or **"Full OIDC config: undefined"**

## Quick Diagnostic Steps

### 1. Test OIDC Server Connectivity

First, run the connectivity test script:

```bash
./test-oidc-connectivity.sh
```

This will check:
- ✅ Server accessibility
- ✅ Well-known endpoint availability
- ✅ OIDC configuration validity
- ✅ Individual endpoint reachability

### 2. Check Server Status

Verify the OIDC server is running:

```bash
# Check for running processes
ps aux | grep java | grep oidc

# Check port availability
netstat -tulpn | grep :9000

# Check server logs
tail -f logs/application.log  # If logs directory exists
```

### 3. Test Well-Known Endpoint Manually

The OIDC discovery endpoint should be accessible at:

```bash
curl http://localhost:9000/obp-oidc/.well-known/openid-configuration
```

Expected response should contain:
```json
{
  "issuer": "http://localhost:9000/obp-oidc",
  "authorization_endpoint": "http://localhost:9000/obp-oidc/auth",
  "token_endpoint": "http://localhost:9000/obp-oidc/token",
  "userinfo_endpoint": "http://localhost:9000/obp-oidc/userinfo",
  "jwks_uri": "http://localhost:9000/obp-oidc/jwks",
  ...
}
```

## Common Issues & Solutions

### Issue 1: Server Not Running

**Symptoms:**
- Connection refused errors
- No response from well-known endpoint
- Process not found

**Solutions:**

1. **Start the server:**
   ```bash
   ./run-server.sh
   ```

2. **Check configuration:**
   ```bash
   # Verify run-server.sh exists and has correct database credentials
   ls -la run-server.sh

   # Create from example if missing
   cp run-server.example.sh run-server.sh
   # Edit run-server.sh with your database credentials
   ```

3. **Check for build issues:**
   ```bash
   ./build_and_run_server.sh
   ```

### Issue 2: Database Connection Problems

**Symptoms:**
- Server starts but crashes
- Database connection errors in logs
- "SQL NULL read at column 5" errors

**Solutions:**

1. **Test database connectivity:**
   ```bash
   ./test-admin-db.sh  # Copy from test-admin-db.example.sh first
   ```

2. **Verify database views exist:**
   ```sql
   -- Connect to your database and check:
   \d v_oidc_users
   \d v_oidc_clients
   \d v_oidc_admin_clients
   ```

3. **Fix NULL column mapping issues:**
   - The recent database mapping fix should resolve "SQL NULL read" errors
   - Ensure you're using the updated code with Optional types for nullable columns

### Issue 3: Wrong Host/Port Configuration

**Symptoms:**
- Server runs but OBP-API can't connect
- Well-known endpoint accessible locally but not from OBP-API

**Solutions:**

1. **Check environment variables in `run-server.sh`:**
   ```bash
   export OIDC_HOST=localhost     # Change to actual server IP if needed
   export OIDC_PORT=9000          # Default port
   export OIDC_EXTERNAL_URL=      # Set if behind proxy/load balancer
   ```

2. **For external access:**
   ```bash
   # If OIDC server is behind a proxy or needs external URL
   export OIDC_EXTERNAL_URL=https://your-domain.com/oidc
   ```

3. **Network connectivity test:**
   ```bash
   # From the machine running OBP-API, test:
   curl http://YOUR_OIDC_HOST:9000/obp-oidc/.well-known/openid-configuration
   ```

### Issue 4: Firewall/Network Issues

**Symptoms:**
- Connection timeouts
- Works locally but not from other machines

**Solutions:**

1. **Check firewall rules:**
   ```bash
   # Ubuntu/Debian
   sudo ufw status
   sudo ufw allow 9000

   # CentOS/RHEL
   sudo firewall-cmd --list-ports
   sudo firewall-cmd --permanent --add-port=9000/tcp
   sudo firewall-cmd --reload
   ```

2. **Test network connectivity:**
   ```bash
   # From OBP-API machine, test OIDC server port
   telnet YOUR_OIDC_HOST 9000
   ```

### Issue 5: Incorrect OBP-API Configuration

**Symptoms:**
- "OIDC Config not present on OAuth client"
- "Retry to get config from OIDC well-known endpoint"

**Solutions:**

1. **Verify OBP-API configuration:**
   ```properties
   # In OBP-API's application.properties or environment:
   oauth.client.id=your-client-id
   oauth.client.secret=your-client-secret
   oidc.discovery.url=http://YOUR_OIDC_HOST:9000/obp-oidc/.well-known/openid-configuration
   ```

2. **Generate client configuration:**
   ```bash
   # Use OIDC server's config generator
   ./generate-config.sh
   # Copy generated client config to OBP-API
   ```

## Configuration Checklist

### OIDC Server Configuration

- [ ] `run-server.sh` exists and is configured
- [ ] Database credentials are correct
- [ ] Database views (`v_oidc_users`, `v_oidc_clients`, `v_oidc_admin_clients`) exist
- [ ] Server host/port match network requirements
- [ ] External URL set if behind proxy

### OBP-API Configuration

- [ ] OIDC discovery URL points to correct endpoint
- [ ] Client ID and secret match registered client
- [ ] Network connectivity from OBP-API to OIDC server
- [ ] No firewall blocking connections

## Debugging Commands

### Server Diagnostics

```bash
# Full connectivity test
./test-oidc-connectivity.sh

# Database connection test
./test-admin-db.sh

# Configuration generation
./generate-config.sh

# Build and start server
./build_and_run_server.sh
```

### Manual Testing

```bash
# Test well-known endpoint
curl -v http://localhost:9000/obp-oidc/.well-known/openid-configuration

# Test authorization endpoint (should return 400 or redirect)
curl -v http://localhost:9000/obp-oidc/auth

# Test token endpoint (should return 405 Method Not Allowed)
curl -v http://localhost:9000/obp-oidc/token

# Test JWKS endpoint
curl -v http://localhost:9000/obp-oidc/jwks
```

### Database Queries

```sql
-- Check user view
SELECT COUNT(*) FROM v_oidc_users;
SELECT * FROM v_oidc_users LIMIT 5;

-- Check client view
SELECT COUNT(*) FROM v_oidc_clients;
SELECT client_id, client_name, redirect_uris FROM v_oidc_clients LIMIT 5;

-- Check admin client view
SELECT COUNT(*) FROM v_oidc_admin_clients;
SELECT consumerid, name, redirecturl FROM v_oidc_admin_clients LIMIT 5;
```

## Getting Help

1. **Run diagnostics first:**
   ```bash
   ./test-oidc-connectivity.sh > oidc-test-results.txt 2>&1
   ```

2. **Collect logs:**
   ```bash
   # Server logs
   journalctl -u your-oidc-service --since "1 hour ago"

   # Or application logs if they exist
   tail -n 100 logs/application.log
   ```

3. **Check configuration:**
   ```bash
   # Sanitized configuration (removes passwords)
   env | grep -E "(OIDC|DB)_" | sed 's/PASSWORD=.*/PASSWORD=***/'
   ```

## Security Notes

- Never share actual passwords or secrets in troubleshooting
- Use test credentials for debugging when possible
- Ensure HTTPS in production environments
- Regularly rotate client secrets and database passwords

## Common URLs Reference

| Component | URL Pattern | Example |
|-----------|-------------|---------|
| Well-known Config | `{base}/obp-oidc/.well-known/openid-configuration` | `http://localhost:9000/obp-oidc/.well-known/openid-configuration` |
| Authorization | `{base}/obp-oidc/auth` | `http://localhost:9000/obp-oidc/auth` |
| Token | `{base}/obp-oidc/token` | `http://localhost:9000/obp-oidc/token` |
| UserInfo | `{base}/obp-oidc/userinfo` | `http://localhost:9000/obp-oidc/userinfo` |
| JWKS | `{base}/obp-oidc/jwks` | `http://localhost:9000/obp-oidc/jwks` |

Where `{base}` is typically `http://localhost:9000` or your configured external URL.

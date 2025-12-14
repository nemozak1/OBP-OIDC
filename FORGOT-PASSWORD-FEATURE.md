# Forgot Password Feature

## Overview

The OBP-OIDC Provider login page includes a "Forgot password?" link that helps users reset their passwords. This link intelligently defaults to the calling application's password reset page, ensuring a seamless user experience.

## How It Works

### Automatic URL Detection

The forgot password link automatically points to the calling application by extracting the base URL from the OAuth2 `redirect_uri` parameter:

1. **Extract base URL**: Parse the `redirect_uri` to get scheme, host, and port
2. **Append path**: Add `/forgot-password` to the base URL
3. **Display link**: Show "Forgot password?" below the password field

### Examples

| Calling Application Redirect URI | Forgot Password Link |
|----------------------------------|----------------------|
| `http://localhost:5174/login/callback` | `http://localhost:5174/forgot-password` |
| `https://portal.example.com/oauth/callback` | `https://portal.example.com/forgot-password` |
| `https://api.bank.com:8080/auth/callback` | `https://api.bank.com:8080/forgot-password` |

## Configuration

### Environment Variable

You can override the default behavior by setting the `FORGOT_PASSWORD_URL` environment variable:

```bash
# Custom forgot password URL
export FORGOT_PASSWORD_URL="https://portal.example.com/user/reset-password"
```

### Configuration Priority

1. **Explicit configuration**: If `FORGOT_PASSWORD_URL` is set, use that value
2. **Auto-detected URL**: Otherwise, use `{calling_app_url}/forgot-password`
3. **Test mode default**: For `/obp-oidc/test-login`, defaults to `http://localhost:5174/forgot-password`

## Implementation Details

### Code Changes

**Config.scala**:
- Added `forgotPasswordUrl: Option[String]` to `OidcConfig` case class
- Reads from `FORGOT_PASSWORD_URL` environment variable
- Defaults to `None` (enables auto-detection)

**AuthEndpoint.scala**:
- Extracts base URL from `redirect_uri` (already done for logo link)
- Computes forgot password link: `config.forgotPasswordUrl.getOrElse(s"$logoLinkUrl/forgot-password")`
- Added link below password field in login form HTML
- Also added to standalone test login form

### UI Display

The forgot password link appears:
- Below the password input field
- Right-aligned
- Styled as a small blue hyperlink (0.9rem, #0066cc)
- Text: "Forgot password?"

```html
<div style="text-align: right; margin-top: 0.5rem;">
  <a href="$forgotPasswordLink" style="font-size: 0.9rem; color: #0066cc; text-decoration: none;">
    Forgot password?
  </a>
</div>
```

## Use Cases

### Scenario 1: OBP Portal Integration

**Setup**:
```bash
# Portal redirects from http://localhost:5174
export OIDC_CLIENT_PORTAL_REDIRECTS=http://localhost:5174/login/obp/callback
```

**Result**:
- Forgot password link: `http://localhost:5174/forgot-password`
- Portal should handle this route and provide password reset functionality

### Scenario 2: Custom Password Reset URL

**Setup**:
```bash
# Override with specific URL
export FORGOT_PASSWORD_URL="https://accounts.example.com/password/reset"
```

**Result**:
- All login pages will link to `https://accounts.example.com/password/reset`
- Useful for centralized authentication systems

### Scenario 3: Multiple Applications

**No configuration needed** - The link automatically adapts:

- **Portal**: `http://localhost:5174/login/callback` → `http://localhost:5174/forgot-password`
- **Explorer**: `http://localhost:8082/auth/callback` → `http://localhost:8082/forgot-password`
- **Custom App**: `https://myapp.com/oauth/redirect` → `https://myapp.com/forgot-password`

## Testing

### Test with Default Behavior

1. Start OIDC server:
   ```bash
   ./run-server.sh
   ```

2. Navigate to test login:
   ```
   http://localhost:9000/obp-oidc/test-login
   ```

3. Check that "Forgot password?" link appears below password field

4. Verify link points to `http://localhost:5174/forgot-password` (default test value)

### Test with Real Client

1. Start OIDC server with Portal client configured

2. Initiate OAuth2 flow from Portal:
   ```
   http://localhost:9000/obp-oidc/auth?client_id=obp-portal-client&redirect_uri=http://localhost:5174/login/obp/callback&scope=openid&response_type=code
   ```

3. Verify "Forgot password?" link points to `http://localhost:5174/forgot-password`

### Test with Custom URL

1. Set custom URL:
   ```bash
   export FORGOT_PASSWORD_URL="https://custom.example.com/reset"
   ./run-server.sh
   ```

2. Navigate to any login page

3. Verify link points to `https://custom.example.com/reset`

## Integration Requirements

### Portal/Application Side

Applications using OBP-OIDC should implement a `/forgot-password` route that:

1. **Displays password reset form**: Collect username/email
2. **Validates user exists**: Check against user database
3. **Sends reset email**: Email with secure reset token/link
4. **Handles reset flow**: Allow user to set new password

### Alternative Approach

If the application prefers a different path (e.g., `/user/reset-password`), set:

```bash
export FORGOT_PASSWORD_URL="http://localhost:5174/user/reset-password"
```

## Security Considerations

1. **No sensitive data in URL**: The forgot password link contains no user information
2. **Application responsibility**: Password reset security is handled by the calling application
3. **HTTPS in production**: Always use HTTPS for password reset flows in production
4. **Rate limiting**: Applications should implement rate limiting on password reset requests

## Future Enhancements

Potential improvements for consideration:

1. **Pre-fill username**: Pass username as query parameter (optional)
2. **Return URL**: Include return URL to resume OAuth flow after reset
3. **Per-client URLs**: Allow different reset URLs for different clients
4. **Localization**: Support translated text for different languages

## Related Documentation

- [README.md](README.md) - Main documentation with configuration examples
- [LOGO-CONFIGURATION.md](LOGO-CONFIGURATION.md) - Logo and branding customization
- [DESIGN-NOTES.md](DESIGN-NOTES.md) - UI design principles

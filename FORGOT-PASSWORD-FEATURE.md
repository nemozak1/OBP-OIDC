# Forgot Password Feature

## Overview

The OBP-OIDC Provider login page includes a "Forgot password?" link that sends users to the OBP Portal's `/forgot-password` page.

## How It Works

The forgot password link is constructed from the `OBP_PORTAL_BASE_URL` environment variable (defaulting to `http://localhost:5174`) with `/forgot-password` appended.

### Examples

| `OBP_PORTAL_BASE_URL` | Forgot Password Link |
|------------------------|----------------------|
| *(not set)* | `http://localhost:5174/forgot-password` |
| `https://portal.example.com` | `https://portal.example.com/forgot-password` |
| `https://api.bank.com:8080` | `https://api.bank.com:8080/forgot-password` |

## Configuration

### Environment Variable

Set `OBP_PORTAL_BASE_URL` to point to your Portal host:

```bash
# Default (if not set): http://localhost:5174
export OBP_PORTAL_BASE_URL="https://portal.example.com"
```

A trailing slash is automatically stripped if present.

## Implementation Details

### Code Changes

**Config.scala**:
- `obpPortalBaseUrl: String` in `OidcConfig` case class
- Reads from `OBP_PORTAL_BASE_URL` environment variable
- Defaults to `http://localhost:5174`

**AuthEndpoint.scala**:
- Constructs forgot password link: `s"${config.obpPortalBaseUrl}/forgot-password"`
- Used in both the main login form and the standalone test login form

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

4. Verify link points to `http://localhost:5174/forgot-password`

### Test with Custom Portal URL

1. Set Portal URL:
   ```bash
   export OBP_PORTAL_BASE_URL="https://portal.example.com"
   ./run-server.sh
   ```

2. Navigate to any login page

3. Verify link points to `https://portal.example.com/forgot-password`

## Integration Requirements

### Portal Side

The OBP Portal should implement a `/forgot-password` route that:

1. **Displays password reset form**: Collect username/email
2. **Validates user exists**: Check against user database
3. **Sends reset email**: Email with secure reset token/link
4. **Handles reset flow**: Allow user to set new password

## Security Considerations

1. **No sensitive data in URL**: The forgot password link contains no user information
2. **Application responsibility**: Password reset security is handled by the Portal
3. **HTTPS in production**: Always use HTTPS for password reset flows in production
4. **Rate limiting**: The Portal should implement rate limiting on password reset requests

## Related Documentation

- [README.md](README.md) - Main documentation with configuration examples
- [LOGO-CONFIGURATION.md](LOGO-CONFIGURATION.md) - Logo and branding customization
- [DESIGN-NOTES.md](DESIGN-NOTES.md) - UI design principles

# Logo Configuration

## Overview

The OBP OIDC Provider displays the **Open Bank Project logo by default** on the login page. You can customize this to use your own logo to brand the authentication experience with your organization's logo.

## Configuration

### Environment Variables

Two environment variables control the logo display:

| Variable        | Required | Default                                                                 | Description                        |
| --------------- | -------- | ----------------------------------------------------------------------- | ---------------------------------- |
| `LOGO_URL`      | No       | `https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png` | URL to your logo image             |
| `LOGO_ALT_TEXT` | No       | `"Open Bank Project"`                                                   | Alternative text for accessibility |

### Using the Default Logo

By default, the Open Bank Project logo is displayed. No configuration is required.

### Setting Up a Custom Logo

#### Option 1: Export Environment Variables

```bash
export LOGO_URL="https://example.com/logo.png"
export LOGO_ALT_TEXT="Company Logo"
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

#### Option 2: Inline with Command

```bash
LOGO_URL="https://example.com/logo.png" \
LOGO_ALT_TEXT="Company Logo" \
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

#### Option 3: Edit run-server.sh

Uncomment and modify the logo configuration section in `run-server.sh`:

```bash
# Logo Configuration (Optional - defaults shown)
# Uncomment and change to use a custom logo
#export LOGO_URL="https://example.com/logo.png"
#export LOGO_ALT_TEXT="Company Logo"
```

Then run:

```bash
./run-server.sh
```

## Logo Specifications

### Image Requirements

- **Format**: Any web-compatible format (PNG, SVG, JPG, GIF)
- **Recommended Format**: PNG or SVG for best quality
- **Maximum Display Width**: 200px (desktop), 150px (mobile)
- **Maximum Display Height**: 80px (desktop), 60px (mobile)
- **Aspect Ratio**: Maintained automatically
- **File Size**: Keep under 100KB for fast loading

### Optimal Dimensions

For best results, use a logo with these characteristics:

- **Horizontal Logo**: 200px × 60px (recommended)
- **Square Logo**: 80px × 80px
- **Vertical Logo**: 100px × 80px

The logo will automatically scale to fit within the maximum dimensions while maintaining its aspect ratio.

## Logo Display Behavior

### Where the Logo Appears

The logo is displayed:

- ✅ On the main login page (`/obp-oidc/auth`)
- ✅ Above the "Sign In" heading
- ✅ Centered in the login container
- ✅ In both development and production modes
- ✅ **By default** (OBP logo) unless customized or disabled

### Disabling the Logo

To remove the logo entirely, set `LOGO_URL` to an empty string:

```bash
export LOGO_URL=""
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

### When the Logo is NOT Displayed

The logo will not appear if:

- `LOGO_URL` is set to an empty string (intentionally disabled)
- The image URL is invalid or unreachable

**No error is shown** - the login page simply displays without a logo.

## Examples

### Example 1: Using Default Logo (No Configuration Needed)

```bash
# Simply start the server - OBP logo displays by default
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

Default values:

- URL: `https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png`
- Alt Text: "Open Bank Project"

### Example 2: Custom Company Logo

```bash
export LOGO_URL="https://mycompany.com/logo.png"
export LOGO_ALT_TEXT="My Company Inc."
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

### Example 3: Local Logo File

If serving from a static file server:

```bash
export LOGO_URL="http://localhost:8000/company-logo.png"
export LOGO_ALT_TEXT="My Company"
```

### Example 4: Base64 Encoded Logo

For small logos, you can use base64 encoding:

```bash
export LOGO_URL="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA..."
export LOGO_ALT_TEXT="Company Logo"
```

### Example 5: CDN-Hosted Logo

```bash
export LOGO_URL="https://cdn.mycompany.com/assets/logo.svg"
export LOGO_ALT_TEXT="MyCompany Inc."
```

### Example 6: Disable Logo Entirely

```bash
export LOGO_URL=""
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

## Accessibility

### Alt Text Best Practices

The `LOGO_ALT_TEXT` should:

1. **Be Descriptive**: Describe what the logo represents
   - ✅ Good: "Open Bank Project" (default)
   - ✅ Good: "Acme Corporation"
   - ❌ Bad: "Logo"
   - ❌ Bad: "Image"

2. **Be Concise**: Keep it short and meaningful
   - ✅ Good: "MyCompany Banking"
   - ❌ Bad: "The official logo of MyCompany Banking Corporation established in 1999"

3. **Match Context**: Reflect what users see
   - If logo includes text, use that text
   - If logo is symbolic, describe it briefly

### Screen Reader Support

The logo is properly marked up with:

```html
<img src="[LOGO_URL]" alt="[LOGO_ALT_TEXT]" />
```

Screen readers will announce the alt text, helping visually impaired users understand which organization they're logging into.

## Troubleshooting

### Logo Not Displaying

**Problem**: Logo doesn't appear on the login page.

**Solutions**:

1. **Check if LOGO_URL is set or disabled**:

   ```bash
   echo $LOGO_URL
   ```

   - If empty string (`""`), logo is intentionally disabled
   - If unset, default OBP logo should display
   - If set to custom URL, verify the URL is correct

2. **Verify URL is accessible**:

   ```bash
   curl -I $LOGO_URL
   ```

   Should return HTTP 200.

3. **Check browser console**: Open developer tools and look for image loading errors.

4. **Test URL directly**: Paste the URL in a browser to ensure the image loads.

### Logo Too Large or Too Small

**Problem**: Logo appears with incorrect size.

**Solutions**:

1. **For too large**: The CSS automatically limits the size. If it's still too large, your image might be very high resolution. Consider resizing the source image.

2. **For too small**: If your logo is very small and looks pixelated, use a higher resolution source image (at least 200px wide for horizontal logos).

3. **Aspect ratio issues**: The system maintains aspect ratio. If you want different proportions, edit the source image.

### HTTPS Mixed Content Warning

**Problem**: Browser shows mixed content warning (HTTPS page loading HTTP image).

**Solution**: If your OIDC server runs on HTTPS, ensure `LOGO_URL` also uses HTTPS:

```bash
# ❌ Wrong (HTTP logo on HTTPS site)
export LOGO_URL="http://example.com/logo.png"

# ✅ Correct (HTTPS logo on HTTPS site)
export LOGO_URL="https://example.com/logo.png"
```

### CORS Issues

**Problem**: Logo fails to load due to CORS policy.

**Solution**: Ensure the server hosting your logo allows cross-origin requests. Add these headers to your logo hosting server:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET
```

## CSS Styling

The logo is styled with the `.login-logo` class defined in `/static/css/forms.css`:

```css
.login-logo {
  text-align: center;
  margin-bottom: 30px;
}

.login-logo img {
  max-width: 200px;
  max-height: 80px;
  height: auto;
  width: auto;
}

/* Mobile responsive */
@media (max-width: 768px) {
  .login-logo img {
    max-width: 150px;
    max-height: 60px;
  }
}
```

### Customizing Logo Styles

If you need custom styling (not recommended, but possible):

1. Edit `src/main/resources/static/css/forms.css`
2. Modify the `.login-logo` or `.login-logo img` selectors
3. Rebuild the project

## Testing

### Test Logo Configuration

1. **Start the server with default logo** (no configuration needed):

   ```bash
   ./run-server.sh
   ```

   The OBP logo should display automatically.

2. **Start the server with custom logo**:

   ```bash
   export LOGO_URL="https://example.com/custom-logo.png"
   export LOGO_ALT_TEXT="Custom Company"
   ./run-server.sh
   ```

3. **Navigate to login page**: Visit the auth endpoint with test parameters:

   ```
   http://localhost:9000/obp-oidc/test-login
   ```

4. **Verify logo appears**:
   - Logo should be centered above "Sign In"
   - Image should be properly sized
   - Alt text should be present (right-click image → Inspect)

5. **Test disabling the logo**:
   ```bash
   export LOGO_URL=""
   ./run-server.sh
   ```
   Login page should display without any logo.

### Test Responsive Design

1. Open the login page in a browser
2. Open Developer Tools (F12)
3. Toggle device toolbar (Ctrl+Shift+M)
4. Test different screen sizes:
   - Desktop (1920×1080): Logo max 200×80px
   - Tablet (768×1024): Logo max 200×80px
   - Mobile (375×667): Logo max 150×60px

## Best Practices

### Performance

1. **Use CDN**: Host your logo on a CDN for faster loading
2. **Optimize Image**: Compress your logo to reduce file size
3. **Use SVG**: For logos that scale well, SVG provides the best quality and smallest size
4. **Cache Headers**: Ensure your logo server sends proper cache headers

### Security

1. **Use HTTPS**: Always serve logos over HTTPS in production
2. **Trusted Sources**: Only use logo URLs from domains you control
3. **Content Security Policy**: If using CSP, ensure logo domain is whitelisted

### Branding

1. **Consistent Logo**: Use the same logo across all authentication flows
2. **White Background**: Ensure your logo works well on a white background (the login container is white)
3. **Test Visibility**: Verify logo is visible and clear at the display size

## Related Files

- `src/main/scala/com/tesobe/oidc/config/Config.scala` - Configuration loading
- `src/main/scala/com/tesobe/oidc/endpoints/AuthEndpoint.scala` - Logo rendering
- `src/main/resources/static/css/forms.css` - Logo styling
- `run-server.sh` - Example configuration
- `README.md` - General documentation

## Support

For issues or questions about logo configuration:

1. Check this documentation first
2. Review the [Troubleshooting](#troubleshooting) section
3. Examine browser console for errors
4. Verify your image URL is accessible
5. Check that environment variables are set correctly

## Changelog

### Version 1.0.0

- ✅ Initial logo configuration support
- ✅ Default OBP logo displayed out-of-the-box
- ✅ Responsive design (desktop and mobile)
- ✅ Accessibility support with alt text
- ✅ Can be customized or disabled via environment variables
- ✅ Automatic image scaling

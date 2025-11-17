# CSS Refactoring Documentation

## Overview

The OBP OIDC Provider's UI has been refactored to use external CSS files instead of inline styles, eliminating code duplication and improving maintainability.

## Changes Made

### 1. Created Shared CSS Files

**Location:** `src/main/resources/static/css/`

#### `main.css`
- **Purpose:** Core styles shared across all pages
- **Contains:**
  - Reset and base styles
  - Typography (h1, h2, h3, paragraphs)
  - Container layouts
  - Links and navigation
  - Code elements
  - Badges and indicators
  - Info cards and alert boxes
  - Tables and lists
  - Buttons
  - Stats cards and grids
  - Responsive design breakpoints
  - Utility classes

#### `forms.css`
- **Purpose:** Styles specific to form pages (login, authentication)
- **Contains:**
  - Login container styles
  - Form elements (inputs, selects, labels)
  - Form buttons
  - Error and info boxes
  - Hint text
  - Form layout helpers (rows, grids)
  - Responsive form design

### 2. Created Static Files Endpoint

**File:** `src/main/scala/com/tesobe/oidc/endpoints/StaticFilesEndpoint.scala`

- Serves CSS files from `src/main/resources/static/css/`
- Route: `/static/css/{filename}.css`
- Handles file loading from classpath resources
- Returns appropriate content types
- Error handling for missing files

### 3. Integrated Static Files into Server

**File:** `src/main/scala/com/tesobe/oidc/server/OidcServer.scala`

- Initialized `StaticFilesEndpoint` in server startup
- Added route handler for static files (always available)
- Placed before other routes for optimal performance

### 4. Updated All HTML Pages

#### Pages Updated:
1. **Root page** (`/`)
   - Removed ~100 lines of inline CSS
   - Added external CSS link
   - Uses modern mode indicators

2. **Health check** (`/health`)
   - Removed ~80 lines of inline CSS
   - Simplified structure with utility classes

3. **Login form** (`/obp-oidc/auth`)
   - Removed ~130 lines of inline CSS
   - Links to both `main.css` and `forms.css`
   - Added `form-page` body class

4. **Test login** (`/obp-oidc/test-login`)
   - Removed ~120 lines of inline CSS
   - Links to both CSS files
   - Uses `login-container-large` class

5. **Clients page** (`/clients`)
   - Removed ~60 lines of inline CSS
   - Kept only page-specific styles (client-specific classes)
   - Uses alert components

6. **Stats page** (`/stats`)
   - Removed ~150 lines of inline CSS
   - Kept only gradient header styles
   - Simplified with shared components

7. **Info page** (`/info`)
   - Already had modern styling
   - No changes needed

8. **Error pages**
   - Updated to use external CSS
   - Uses alert components

## Benefits

### 1. **Eliminated Duplication**
- Reduced ~640+ lines of duplicate CSS code
- Single source of truth for styling
- Consistent design across all pages

### 2. **Improved Maintainability**
- Change styles in one place
- Easy to update color schemes, fonts, spacing
- Clear separation of concerns

### 3. **Better Performance**
- CSS files are cacheable by browsers
- Reduced HTML payload size
- Faster page loads after first visit

### 4. **Easier Theming**
- All colors and design tokens in one place
- Can easily create alternative themes
- Consistent spacing and sizing

### 5. **Responsive Design**
- Centralized media queries
- Consistent mobile experience
- Easy to adjust breakpoints

## CSS Architecture

### Color Palette
```css
Primary: #26a69a (teal)
Primary Dark: #1f8a7e
Success: #10b981
Error: #ef4444
Warning: #f59e0b
Info: #3b82f6
Text: #2c3e50
Subtle: #666
Background: #f8f9fa
```

### Component Classes

#### Containers
- `.container` - Standard page container (max-width: 1200px)
- `.container-small` - Narrow container (max-width: 600px)
- `.login-container` - Form container (max-width: 450px)
- `.login-container-large` - Large form container (max-width: 520px)

#### Alerts
- `.alert` - Base alert box
- `.alert-info` - Information alert (blue)
- `.alert-success` - Success alert (green)
- `.alert-warning` - Warning alert (orange)
- `.alert-error` - Error alert (red)

#### Badges
- `.badge` - Base badge
- `.badge-primary` - Primary badge (teal)
- `.badge-success` - Success badge (green)
- `.badge-warning` - Warning badge (orange)

#### Mode Indicators
- `.mode-indicator` - Base mode indicator
- `.mode-development` - Development mode (orange)
- `.mode-production` - Production mode (green)

#### Stats Cards
- `.stats-grid` - Grid layout for stats
- `.stat-card` - Individual stat card
- `.stat-card.success` - Success variant
- `.stat-card.error` - Error variant
- `.stat-card.info` - Info variant

#### Info Cards
- `.info-card` - Information card with left border
- `.info-grid` - Grid layout for info cards

#### Utility Classes
- `.text-center` - Center text
- `.mt-20` - Margin top 20px
- `.mb-20` - Margin bottom 20px
- `.p-20` - Padding 20px

## Usage Examples

### Basic Page Template
```html
<!DOCTYPE html>
<html>
<head>
  <title>Page Title</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>
  <div class="container">
    <h1>Page Heading</h1>
    <p class="subtitle">Page subtitle</p>
    <!-- Content here -->
  </div>
</body>
</html>
```

### Form Page Template
```html
<!DOCTYPE html>
<html>
<head>
  <title>Form Page</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/static/css/main.css">
  <link rel="stylesheet" href="/static/css/forms.css">
</head>
<body class="form-page">
  <div class="login-container">
    <h2>Form Title</h2>
    <p class="subtitle">Form subtitle</p>
    <form>
      <!-- Form fields here -->
    </form>
  </div>
</body>
</html>
```

### Alert Box
```html
<div class="alert alert-warning">
  <strong>Note:</strong> This is a warning message.
</div>
```

### Stats Grid
```html
<div class="stats-grid">
  <div class="stat-card success">
    <h2 class="stat-number">150</h2>
    <p class="stat-label">Successful Logins</p>
    <p class="stat-description">Users authenticated successfully</p>
  </div>
  <!-- More stat cards -->
</div>
```

## Migration Guide

### For New Pages

1. Always link to `/static/css/main.css`
2. For forms, also link to `/static/css/forms.css`
3. Use existing component classes instead of inline styles
4. Only add page-specific styles in `<style>` tags if truly unique

### For Existing Inline Styles

**Before:**
```html
<style>
  .my-box {
    background: #f8f9fa;
    padding: 20px;
    border-radius: 6px;
  }
</style>
```

**After:**
```html
<!-- Just use existing .info-card class -->
<div class="info-card">
  <!-- Content -->
</div>
```

## Future Improvements

### Potential Enhancements
1. **CSS Variables** - Use CSS custom properties for easier theming
2. **Dark Mode** - Add dark theme support
3. **Animation Library** - Shared animations for transitions
4. **Icon System** - Consistent icon styling
5. **Print Styles** - Optimize for printing
6. **Additional Themes** - Alternative color schemes

### Adding New Styles

When adding new styles:
1. Check if similar style exists in `main.css` or `forms.css`
2. Reuse existing components when possible
3. If creating new component, add it to appropriate CSS file
4. Document new classes in this file
5. Use consistent naming conventions (BEM or similar)

## Testing

To verify CSS is working:

1. **Start the server**
   ```bash
   mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
   ```

2. **Test static file serving**
   ```bash
   curl http://localhost:8080/static/css/main.css
   curl http://localhost:8080/static/css/forms.css
   ```

3. **Test pages render correctly**
   - Visit each page in a browser
   - Check browser console for CSS loading errors
   - Verify responsive design at different screen sizes

4. **Test caching**
   - Refresh pages multiple times
   - Check network tab for cached CSS files (304 responses)

## Browser Compatibility

The CSS uses modern but well-supported features:
- Flexbox
- CSS Grid
- CSS Custom Properties (if added)
- Modern color functions
- Viewport units

**Supported Browsers:**
- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Maintenance

### Regular Tasks
- Review and remove unused CSS classes
- Optimize file size if it grows too large
- Update documentation when adding new components
- Test responsive design on new components
- Keep color palette consistent

### File Size Monitoring
- `main.css`: Currently ~8KB uncompressed
- `forms.css`: Currently ~4KB uncompressed
- Total: ~12KB (minimal impact on performance)

## Related Files

- `src/main/resources/static/css/main.css` - Main stylesheet
- `src/main/resources/static/css/forms.css` - Form stylesheet
- `src/main/scala/com/tesobe/oidc/endpoints/StaticFilesEndpoint.scala` - Static file server
- `src/main/scala/com/tesobe/oidc/server/OidcServer.scala` - Server integration

## Conclusion

This refactoring significantly improves the maintainability and consistency of the OBP OIDC Provider's UI. By centralizing styles into shared CSS files, we've reduced duplication, improved performance, and made future updates much easier.

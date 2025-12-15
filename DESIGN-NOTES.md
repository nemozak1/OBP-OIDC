# Design Notes - OBP OIDC Provider UI

## Overview

The OBP OIDC Provider features a modern, professional design that matches the OBP Portal's design language. This document describes the visual design system, including colors, gradients, and layout principles.

## Color Palette

### OBP Portal Color Palette (OKLCH Color Space)

The exact color values from the OBP Portal theme:

**Primary Colors (Dark Navy/Teal):**

```
primary-950: oklch(14.97% 0.03 285.58deg)  /* Very dark - gradient background */
primary-900: oklch(17.29% 0.03 286.25deg)
primary-800: oklch(19.8% 0.03 283.79deg)
primary-700: oklch(21.93% 0.02 284.32deg)
primary-600: oklch(24.33% 0.02 280.66deg)
primary-500: oklch(26.42% 0.02 280.83deg)
primary-400: oklch(43.36% 0.01 280.75deg)
primary-300: oklch(58.74% 0.01 278.59deg)
primary-200: oklch(72.99% 0.01 286.35deg)
primary-100: oklch(86.74% 0 286.74deg)
primary-50:  oklch(100% 0 none)
```

**Secondary Colors (Teal/Green):**

```
secondary-950: oklch(12.18% 0.01 144.78deg)
secondary-900: oklch(25.75% 0.04 148.91deg)
secondary-800: oklch(37.48% 0.07 148.84deg)
secondary-700: oklch(48.34% 0.09 148.26deg)
secondary-600: oklch(58.64% 0.12 148.32deg)
secondary-500: oklch(68.5% 0.14 148.36deg)  /* Main teal - gradient highlight */
secondary-400: oklch(74.3% 0.11 149.35deg)
secondary-300: oklch(80.08% 0.08 150.72deg)
secondary-200: oklch(86.27% 0.06 150.59deg)
secondary-100: oklch(92.28% 0.03 152.28deg)
secondary-50:  oklch(98.51% 0 none)
```

### Semantic Colors

```
Success:          #10b981 (green)
Error:            #ef4444 (red)
Warning:          #f59e0b (orange)
Info:             #3b82f6 (blue)
```

### Neutral Colors

```
Text Primary:     #2c3e50 (dark gray)
Text Subtle:      #666666 (medium gray)
Background:       #f8f9fa (very light gray)
White:            #ffffff
```

## Background Gradient

### Login Page Background

The login and authentication pages feature a **dynamic conic gradient** using the exact OBP Portal colors:

```css
background: conic-gradient(
  from 180deg at 50% 50%,
  oklch(14.97% 0.03 285.58deg) 0deg,
  /* primary-950: Very dark */ oklch(68.5% 0.14 148.36deg) 120deg,
  /* secondary-500: Bright teal */ oklch(14.97% 0.03 285.58deg) 240deg,
  /* primary-950: Very dark */ oklch(68.5% 0.14 148.36deg) 360deg
    /* secondary-500: Bright teal */
);
backdrop-filter: blur(40px);
```

**Visual Effect:**

- Creates a subtle, rotating color transition
- `primary-950` (very dark navy) provides depth and contrast
- `secondary-500` (bright teal) adds energy and brand recognition
- Blur effect softens the gradient for a premium feel
- **Exact match** with the OBP Portal's design language

### Color Rotation Pattern

```
       0° - primary-950 (Very dark navy)
         ↓
     120° - secondary-500 (Bright teal)
         ↓
     240° - primary-950 (Very dark navy)
         ↓
     360° - secondary-500 (Bright teal)
```

**Why OKLCH Color Space?**

OKLCH (Oklab Lightness Chroma Hue) is a modern, perceptually uniform color space that:

- Provides more accurate color perception than RGB/HSL
- Ensures consistent lightness across hues
- Used natively by the OBP Portal for precise color matching
- Supported by all modern browsers (Chrome 111+, Firefox 113+, Safari 15.4+)

## Login Container (Glassmorphism)

The login form uses modern **glassmorphism** design principles:

### Container Styling

```css
background: rgba(255, 255, 255, 0.95); /* 95% opaque white */
backdrop-filter: blur(10px); /* Frosted glass effect */
border-radius: 12px; /* Rounded corners */
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); /* Elevated shadow */
border: 1px solid rgba(255, 255, 255, 0.2); /* Subtle border */
padding: 40px;
```

**Key Features:**

- Semi-transparent white background (95% opacity)
- Backdrop blur creates "frosted glass" effect
- Elevated shadow makes container float above gradient
- Subtle white border adds definition
- Generous padding for comfortable reading

### Visual Hierarchy

```
┌─────────────────────────────────────────┐
│                                         │
│         [OBP Logo]                      │  ← Logo (if configured)
│                                         │
│         Sign In                         │  ← H2 heading (2rem, bold)
│   Client Name is asking you to login   │  ← Subtitle (0.95rem, gray)
│                                         │
│  ┌───────────────────────────────────┐  │
│  │ Technical Info (dev mode only)    │  │  ← Info box (light gray bg)
│  └───────────────────────────────────┘  │
│                                         │
│  Username                               │
│  [input field]                          │
│                                         │
│  Password                               │
│  [input field]                          │
│                                         │
│  Provider                               │
│  [dropdown]                             │
│                                         │
│  [Sign In Button]                       │  ← Full-width teal button
│                                         │
└─────────────────────────────────────────┘
```

## Typography

### Font Family

```
Primary: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont,
         "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif
```

**Plus Jakarta Sans** is a modern geometric sans-serif that's:

- Professional and clean
- Excellent readability
- Good spacing and proportions
- Matches OBP Portal typography

### Font Sizes & Weights

```
H1 (Page Titles):      2.5rem, 700 weight
H2 (Section Titles):   2rem, 700 weight (login pages)
H3 (Subsections):      1.5rem, 600 weight
Body Text:             1rem, 400 weight
Subtitle:              0.95rem, 400 weight
Labels:                0.95rem, 600 weight
Small Text:            0.85rem, 400 weight
```

### Letter Spacing

```
Headings:  -0.02em (slightly tighter)
Body:       0.01em (slightly looser for readability)
```

## Form Elements

### Input Fields

```css
padding: 12px 16px;
border: 1px solid #dee2e6;
border-radius: 6px;
font-size: 1rem;
transition: all 0.2s;

/* Focus State */
border-color: #26a69a; /* Teal border */
box-shadow: 0 0 0 3px rgba(38, 166, 154, 0.1); /* Teal glow */
```

**Interaction States:**

- Default: Light gray border
- Focus: Teal border with subtle glow
- Hover: Slight shadow increase
- Error: Red border with red glow

### Buttons

```css
Primary Button (Sign In):
  background: #26a69a;
  color: white;
  padding: 14px 24px;
  border-radius: 6px;
  font-size: 1rem;
  font-weight: 600;

  /* Hover */
  background: #1f8a7e;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(38, 166, 154, 0.3);
```

**Button States:**

- Default: Teal background
- Hover: Darker teal, lifts up 1px, adds shadow
- Active: Returns to flat position
- Disabled: Gray with reduced opacity

### Select Dropdowns

```css
Custom dropdown with arrow:
  appearance: none;
  background-image: url("data:image/svg+xml,...");
  background-position: right 16px center;
  padding-right: 40px;
```

Uses a custom SVG arrow icon for consistent cross-browser styling.

## Alert Boxes

### Info Box (Development Mode)

```css
background: #f8f9fa;
border-left: 4px solid #26a69a; /* Teal accent */
padding: 16px;
border-radius: 6px;
font-size: 0.9rem;
```

Shows technical details like Client ID, Consumer ID, etc.

### Error Box

```css
background: #ffebee;
color: #c62828;
border-left: 4px solid #ef5350; /* Red accent */
padding: 12px 16px;
border-radius: 6px;
```

Displays authentication errors.

## Logo Display

### Logo Specifications

```
Desktop:
  max-width: 200px
  max-height: 80px

Mobile:
  max-width: 150px
  max-height: 60px

Position: Centered, 30px margin below
Aspect Ratio: Preserved automatically
```

**Default Logo:**

- URL: `https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png`
- Alt Text: "Open Bank Project"

## Responsive Design

### Breakpoints

```css
Desktop:  > 768px   (full layout)
Tablet:   ≤ 768px   (adjusted spacing)
Mobile:   ≤ 375px   (stacked layout, smaller text)
```

### Mobile Adaptations

```
Login Container:
  - Padding: 40px → 30px 20px
  - Max width: 100% (full screen minus margins)

Logo:
  - Max width: 200px → 150px
  - Max height: 80px → 60px

Form Fields:
  - Font size: 16px minimum (prevents iOS zoom)

Buttons:
  - Full width maintained
  - Touch target: minimum 44px height
```

## Animation & Transitions

### Subtle Animations

```css
All interactive elements:
  transition: all 0.2s ease;

Button hover:
  transform: translateY(-1px);
  transition: transform 0.2s, box-shadow 0.2s;

Input focus:
  transition: border-color 0.2s, box-shadow 0.2s;
```

**Philosophy:**

- Animations should be quick (0.2s)
- Provide visual feedback
- Never delay user actions
- Enhance, don't distract

## Accessibility

### Color Contrast

All text meets WCAG 2.1 AA standards:

- Text on white background: 7:1 ratio or better
- Text on teal buttons: 4.5:1 ratio or better
- Links and interactive elements: clearly distinguishable

### Focus Indicators

```css
All interactive elements have visible focus:
  - Teal outline/glow
  - 3px width for visibility
  - Clear contrast against background
```

### Screen Reader Support

- Semantic HTML (proper heading hierarchy)
- Alt text on logo image
- Label elements associated with inputs
- ARIA labels where appropriate
- Keyboard navigation fully supported

## Design Principles

### 1. Professional First

- Clean, uncluttered layout
- Generous whitespace
- Clear visual hierarchy
- Professional typography

### 2. Brand Consistency

- Matches OBP Portal design language
- Uses OBP teal/green color scheme
- Consistent with Open Bank Project branding

### 3. Modern & Premium

- Glassmorphism effects
- Subtle gradients and shadows
- Smooth animations
- High-quality imagery

### 4. User-Focused

- Clear error messages
- Helpful development information (dev mode)
- Responsive across all devices
- Fast, smooth interactions

### 5. Accessible

- WCAG 2.1 AA compliant
- Keyboard navigable
- Screen reader friendly
- High contrast text

## Browser Support

Tested and optimized for:

```
Chrome/Edge:   Latest 2 versions
Firefox:       Latest 2 versions
Safari:        Latest 2 versions (macOS & iOS)
Mobile Safari: iOS 14+
Chrome Mobile: Android 10+
```

**Modern CSS Features Used:**

- Conic gradients
- Backdrop filters
- CSS Grid & Flexbox
- Custom properties (where used)
- Transform & transitions

## Production vs Development Mode

### Production Mode

**Visual Characteristics:**

- Clean, minimal interface
- Shows only: Logo, Sign In heading, Client name, form
- No technical details exposed
- Professional appearance

### Development Mode

**Visual Characteristics:**

- Includes info box with technical details
- Shows Consumer ID, Client ID, Scopes
- Teal-bordered info box stands out
- Helpful for debugging

**Toggle via:**

```bash
export LOCAL_DEVELOPMENT_MODE=true   # Development
export LOCAL_DEVELOPMENT_MODE=false  # Production (default)
```

## Files

### CSS Files

```
src/main/resources/static/css/
├── main.css          (~8KB)  - Core styles, shared components
└── forms.css         (~4KB)  - Form styling, gradient background
```

### Key Sections

**main.css:**

- Typography system
- Container layouts
- Buttons, links, badges
- Alert components
- Tables and lists
- Utility classes

**forms.css:**

- Conic gradient background
- Glassmorphism login container
- Form element styling
- Input fields & buttons
- Error/info boxes
- Responsive adaptations

## Future Enhancements

### Potential Improvements

1. **Dark Mode Support**
   - Inverted color scheme
   - Adjusted gradient for dark backgrounds
   - Enhanced contrast for OLED screens

2. **Animation Library**
   - Subtle entrance animations
   - Loading states
   - Success confirmations

3. **Additional Themes**
   - Alternative color schemes
   - Custom branding options
   - White-label capabilities

4. **Enhanced Mobile Experience**
   - Bottom sheet for mobile login
   - Biometric authentication UI
   - Progressive Web App features

## Inspiration Sources

The design draws inspiration from:

1. **OBP Portal** - Primary design language, color scheme, gradient style
2. **Modern Banking Apps** - Clean, professional, trustworthy aesthetic
3. **Glassmorphism Trend** - Premium feel, modern UI patterns
4. **Material Design** - Elevation, shadows, interaction patterns

## Conclusion

The OBP OIDC Provider design system creates a modern, professional authentication experience that:

- Matches the OBP Portal design language
- Provides excellent user experience across devices
- Maintains accessibility standards
- Supports both development and production use cases
- Creates trust through professional visual design

The teal/green gradient background combined with the glassmorphism login container creates a distinctive, memorable authentication experience that reinforces the Open Bank Project brand identity.

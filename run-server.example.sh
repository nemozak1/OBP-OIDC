#!/bin/bash

# Copyright (c) 2025 TESOBE
#
# This file is part of OBP-OIDC.
#
# OBP-OIDC is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OBP-OIDC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.

# OBP-OIDC Server Runner Script
# This script sets up environment variables and starts the OIDC server
#
# TRACE Logging:
# To enable detailed TRACE level logs for debugging:
#   OIDC_ENABLE_TRACE_LOGGING=true ./run-server.sh

echo "🚀 Starting OBP-OIDC Server..."
echo "================================="

# Server Configuration
export OIDC_HOST=localhost
export OIDC_PORT=9000
export OIDC_KEY_ID=oidc-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600

# UI Customization (optional)
# Logo displayed on login page
# export LOGO_URL="https://example.com/logo.png"
# export LOGO_ALT_TEXT="Company Logo"

# Forgot Password Link (optional)
# Defaults to calling application's URL + /forgot-password
# export FORGOT_PASSWORD_URL="https://portal.example.com/reset-password"

# OBP-API Configuration
export OBP_API_HOST=localhost:8080
export OBP_API_URL=http://localhost:8080

# Client Bootstrap Configuration
# Set to 'true' to skip automatic client creation on startup
export OIDC_SKIP_CLIENT_BOOTSTRAP=false

# Database Configuration (Read-Only User)
# ⚠️  IMPORTANT: Edit these values for your database setup
# These are example values - CHANGE THEM!
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=sandbox
export OIDC_USER_USERNAME=oidc_user
export OIDC_USER_PASSWORD=lakij8777fagg
export DB_MAX_CONNECTIONS=10

# Admin Database Configuration (Write Access to v_oidc_admin_clients)
# ⚠️  IMPORTANT: Edit these values for your admin database user
# This user has write access to manage OIDC clients
export OIDC_ADMIN_USERNAME=oidc_admin
export OIDC_ADMIN_PASSWORD=fhka77uefassEE
export DB_ADMIN_MAX_CONNECTIONS=5

# OBP Ecosystem Client Configuration
# ⚠️  IMPORTANT: These are auto-generated if not set
# Customize these values for your environment
export OIDC_CLIENT_OBP_API_ID=obp-api-client
export OIDC_CLIENT_OBP_API_SECRET=CHANGE_THIS_TO_OBP_API_SECRET_2024
export OIDC_CLIENT_OBP_API_REDIRECTS=http://localhost:8080/auth/openid-connect/callback

export OIDC_CLIENT_PORTAL_ID=obp-portal-client
export OIDC_CLIENT_PORTAL_SECRET=CHANGE_THIS_TO_PORTAL_SECRET_2024
export OIDC_CLIENT_PORTAL_REDIRECTS=http://localhost:5174/login/obp/callback

export OIDC_CLIENT_EXPLORER_ID=obp-explorer-ii-client
export OIDC_CLIENT_EXPLORER_SECRET=CHANGE_THIS_TO_EXPLORER_SECRET_2024
export OIDC_CLIENT_EXPLORER_REDIRECTS=http://localhost:3001/callback,http://localhost:3001/oauth/callback

export OIDC_CLIENT_OPEY_ID=obp-opey-ii-client
export OIDC_CLIENT_OPEY_SECRET=CHANGE_THIS_TO_OPEY_SECRET_2024
export OIDC_CLIENT_OPEY_REDIRECTS=http://localhost:3002/callback,http://localhost:3002/oauth/callback

export OIDC_CLIENT_STRIPE_ID=obp-stripe
export OIDC_CLIENT_STRIPE_SECRET=CHANGE_THIS_TO_STRIPE_SECRET_2024
export OIDC_CLIENT_STRIPE_REDIRECTS=http://localhost:4242/callback

export OIDC_CLIENT_OTHER_APP_1_ID=other_app_1
export OIDC_CLIENT_OTHER_APP_1_SECRET=CHANGE_THIS_TO_OTHER_APP_1_SECRET_2024
export OIDC_CLIENT_OTHER_APP_1_REDIRECTS=http://localhost:5175/login/obp/callback

export OIDC_CLIENT_OTHER_APP_2_ID=other_app_2
export OIDC_CLIENT_OTHER_APP_2_SECRET=CHANGE_THIS_TO_OTHER_APP_2_SECRET_2024
export OIDC_CLIENT_OTHER_APP_2_REDIRECTS=http://localhost:5176/login/obp/callback

export OIDC_CLIENT_OTHER_APP_3_ID=other_app_3
export OIDC_CLIENT_OTHER_APP_3_SECRET=CHANGE_THIS_TO_OTHER_APP_3_SECRET_2024
export OIDC_CLIENT_OTHER_APP_3_REDIRECTS=http://localhost:5177/login/obp/callback

export OIDC_CLIENT_OTHER_APP_4_ID=other_app_4
export OIDC_CLIENT_OTHER_APP_4_SECRET=CHANGE_THIS_TO_OTHER_APP_4_SECRET_2024
export OIDC_CLIENT_OTHER_APP_4_REDIRECTS=http://localhost:5178/login/obp/callback

echo "📋 Configuration:"
echo "  Server: $OIDC_HOST:$OIDC_PORT"
echo "  Issuer: obp-oidc (hardcoded)"
echo "  Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  Read User: $OIDC_USER_USERNAME"
echo "  Admin User: $OIDC_ADMIN_USERNAME"
echo "🔧 OBP Ecosystem Clients:"
echo "  OBP-API: $OIDC_CLIENT_OBP_API_ID"
echo "  Portal: $OIDC_CLIENT_PORTAL_ID"
echo "  Explorer II: $OIDC_CLIENT_EXPLORER_ID"
echo "  Opey II: $OIDC_CLIENT_OPEY_ID"
echo "  Stripe: $OIDC_CLIENT_STRIPE_ID"
echo "  Other App 1: $OIDC_CLIENT_OTHER_APP_1_ID"
echo "  Other App 2: $OIDC_CLIENT_OTHER_APP_2_ID"
echo "  Other App 3: $OIDC_CLIENT_OTHER_APP_3_ID"
echo "  Other App 4: $OIDC_CLIENT_OTHER_APP_4_ID"
echo ""

# Logging Configuration
# Set to 'true' to enable TRACE level logging for detailed debugging
# Usage: OIDC_ENABLE_TRACE_LOGGING=true ./run-server.sh
export OIDC_ENABLE_TRACE_LOGGING=${OIDC_ENABLE_TRACE_LOGGING:-false}

if [ "$OIDC_ENABLE_TRACE_LOGGING" = "true" ]; then
    echo "🔍 TRACE logging: ENABLED (detailed debugging)"
else
    echo "📋 TRACE logging: DISABLED (use OIDC_ENABLE_TRACE_LOGGING=true to enable)"
fi

# Silence the threading warning
export CATS_EFFECT_WARN_ON_NON_MAIN_THREAD_DETECTED=false

echo "🔧 Building project..."
mvn clean compile

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
    echo ""
    echo "🌐 Starting OIDC server..."
    echo "   Health Check: http://$OIDC_HOST:$OIDC_PORT/health"
    echo "   Discovery: http://$OIDC_HOST:$OIDC_PORT/.well-known/openid-configuration"
    echo "   JWKS: http://$OIDC_HOST:$OIDC_PORT/jwks"
    echo ""
    echo "📋 Note: OIDC client configurations will be printed on startup"
    echo "   Copy the configurations from the server output to your service Props/env files"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "================================="

    # Run the server with optional TRACE logging
    if [ "$OIDC_ENABLE_TRACE_LOGGING" = "true" ]; then
        echo "🔍 TRACE logging enabled for detailed debugging"
        mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer" -Dlogback.logger.com.tesobe.oidc.level=TRACE
    else
        mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
    fi
else
    echo "❌ Build failed"
    exit 1
fi

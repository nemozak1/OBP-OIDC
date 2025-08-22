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

# OBP-OIDC Server Runner Script Template
#
# SETUP INSTRUCTIONS:
# 1. Copy this file to run-server.sh:
#    cp run-server.example.sh run-server.sh
# 2. Edit run-server.sh with your database credentials
# 3. Make it executable:
#    chmod +x run-server.sh
# 4. Run it:
#    ./run-server.sh

echo "🚀 Starting OBP-OIDC Server..."
echo "================================="

# Server Configuration
export OIDC_HOST=localhost
export OIDC_PORT=9000
export OIDC_ISSUER=http://localhost:9000
export OIDC_KEY_ID=oidc-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600

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
export OIDC_USER_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!
export DB_MAX_CONNECTIONS=10

# Admin Database Configuration (Write Access to v_oidc_admin_clients)
# ⚠️  IMPORTANT: Edit these values for your admin database user
# This user has write access to manage OIDC clients
export OIDC_ADMIN_USERNAME=oidc_admin
export OIDC_ADMIN_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_ADMIN_PASSWORD_2024!
export DB_ADMIN_MAX_CONNECTIONS=5

# OBP Ecosystem Client Configuration
# ⚠️  IMPORTANT: These are auto-generated if not set
# Customize these values for your environment
export OIDC_CLIENT_OBP_API_ID=obp-api-client
export OIDC_CLIENT_OBP_API_SECRET=CHANGE_THIS_TO_OBP_API_SECRET_2024
export OIDC_CLIENT_OBP_API_REDIRECTS=http://localhost:8080/oauth/callback

export OIDC_CLIENT_PORTAL_ID=obp-portal-client
export OIDC_CLIENT_PORTAL_SECRET=CHANGE_THIS_TO_PORTAL_SECRET_2024
export OIDC_CLIENT_PORTAL_REDIRECTS=http://localhost:3000/callback,http://localhost:3000/oauth/callback

export OIDC_CLIENT_EXPLORER_ID=obp-explorer-ii-client
export OIDC_CLIENT_EXPLORER_SECRET=CHANGE_THIS_TO_EXPLORER_SECRET_2024
export OIDC_CLIENT_EXPLORER_REDIRECTS=http://localhost:3001/callback,http://localhost:3001/oauth/callback

export OIDC_CLIENT_OPEY_ID=obp-opey-ii-client
export OIDC_CLIENT_OPEY_SECRET=CHANGE_THIS_TO_OPEY_SECRET_2024
export OIDC_CLIENT_OPEY_REDIRECTS=http://localhost:3002/callback,http://localhost:3002/oauth/callback

echo "📋 Configuration:"
echo "  Server: $OIDC_HOST:$OIDC_PORT"
echo "  Issuer: $OIDC_ISSUER"
echo "  Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  Read User: $OIDC_USER_USERNAME"
echo "  Admin User: $OIDC_ADMIN_USERNAME"
echo "🔧 OBP Ecosystem Clients:"
echo "  OBP-API: $OIDC_CLIENT_OBP_API_ID"
echo "  Portal: $OIDC_CLIENT_PORTAL_ID"
echo "  Explorer II: $OIDC_CLIENT_EXPLORER_ID"
echo "  Opey II: $OIDC_CLIENT_OPEY_ID"
echo ""

# Silence the threading warning
export CATS_EFFECT_WARN_ON_NON_MAIN_THREAD_DETECTED=false

echo "🔧 Building project..."
mvn clean compile

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
    echo ""
    echo "🌐 Starting OIDC server..."
    echo "   Health Check: $OIDC_ISSUER/health"
    echo "   Discovery: $OIDC_ISSUER/.well-known/openid-configuration"
    echo "   JWKS: $OIDC_ISSUER/jwks"
    echo ""
    echo "📋 Note: OIDC client configurations will be printed on startup"
    echo "   Copy the configurations from the server output to your service Props/env files"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "================================="

    # Run the server
    mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
else
    echo "❌ Build failed"
    exit 1
fi

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

echo "🚀 Starting OBP-OIDC Server..."
echo "================================="

# Server Configuration
export OIDC_HOST=localhost
export OIDC_PORT=9000
export OIDC_ISSUER=http://localhost:9000
export OIDC_KEY_ID=oidc-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600

# Database Configuration
# Edit these values for your database setup
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=sandbox
export DB_USERNAME=oidc_user
export DB_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!
export DB_MAX_CONNECTIONS=10

echo "📋 Configuration:"
echo "  Server: $OIDC_HOST:$OIDC_PORT"
echo "  Issuer: $OIDC_ISSUER"
echo "  Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  User: $DB_USERNAME"
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
    echo "Press Ctrl+C to stop the server"
    echo "================================="
    
    # Run the server
    mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
else
    echo "❌ Build failed"
    exit 1
fi
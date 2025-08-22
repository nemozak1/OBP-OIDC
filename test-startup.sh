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

# OBP-OIDC Startup Test Script
# Tests server startup behavior with various database configurations

echo "🧪 Testing OBP-OIDC Startup Scenarios"
echo "======================================"

# Server Configuration
export OIDC_HOST=localhost
export OIDC_PORT=9001
export OIDC_ISSUER=http://localhost:9001
export OIDC_KEY_ID=test-key-1
export OIDC_TOKEN_EXPIRATION=3600
export OIDC_CODE_EXPIRATION=600

# Basic Database Configuration (likely to work with mock/test setup)
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=test_db
export OIDC_USER_USERNAME=test_user
export OIDC_USER_PASSWORD=test_pass
export DB_MAX_CONNECTIONS=5

# Admin Database Configuration (likely to fail/hang)
export OIDC_ADMIN_USERNAME=nonexistent_admin
export OIDC_ADMIN_PASSWORD=wrong_password
export DB_ADMIN_MAX_CONNECTIONS=2

# OBP Client Configuration
export OIDC_CLIENT_OBP_API_ID=test-obp-api
export OIDC_CLIENT_OBP_API_SECRET=test-secret-123
export OIDC_CLIENT_OBP_API_REDIRECTS=http://localhost:8080/test/callback

export OIDC_CLIENT_PORTAL_ID=test-portal
export OIDC_CLIENT_PORTAL_SECRET=test-portal-secret-456
export OIDC_CLIENT_PORTAL_REDIRECTS=http://localhost:3000/test/callback

export OIDC_CLIENT_EXPLORER_ID=test-explorer
export OIDC_CLIENT_EXPLORER_SECRET=test-explorer-secret-789
export OIDC_CLIENT_EXPLORER_REDIRECTS=http://localhost:3001/test/callback

export OIDC_CLIENT_OPEY_ID=test-opey
export OIDC_CLIENT_OPEY_SECRET=test-opey-secret-abc
export OIDC_CLIENT_OPEY_REDIRECTS=http://localhost:3002/test/callback

# Silence threading warning
export CATS_EFFECT_WARN_ON_NON_MAIN_THREAD_DETECTED=false

echo "📋 Test Configuration:"
echo "  Server: $OIDC_HOST:$OIDC_PORT"
echo "  Issuer: $OIDC_ISSUER"
echo "  Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  User: $OIDC_USER_USERNAME (likely invalid)"
echo "  Admin: $OIDC_ADMIN_USERNAME (likely invalid)"
echo ""

echo "🔧 Compiling project..."
mvn clean compile -q

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed"
    exit 1
fi

echo "✅ Compilation successful"
echo ""

echo "🚀 Starting OIDC server with potentially problematic database config..."
echo "   This will test timeout and error handling behavior"
echo ""
echo "⏱️  Server should start within 30 seconds even with database issues"
echo "   Watch for timeout messages and graceful fallback behavior"
echo ""
echo "🛑 Press Ctrl+C to stop the test"
echo "======================================"

# Start server in background and monitor
timeout 45s mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer" &
SERVER_PID=$!

# Wait a bit then test if server responds
sleep 20

echo ""
echo "🔍 Testing server health after 20 seconds..."
if curl -s http://localhost:9001/health > /dev/null 2>&1; then
    echo "✅ Server is responding to health checks"
    curl -s http://localhost:9001/health
else
    echo "❌ Server is not responding (this may be expected with invalid database config)"
fi

echo ""
echo "⏱️  Waiting for server to complete startup or timeout..."

# Wait for the server process to finish or timeout
wait $SERVER_PID 2>/dev/null
EXIT_CODE=$?

echo ""
echo "📊 Test Results:"
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Server started and shut down normally"
elif [ $EXIT_CODE -eq 124 ]; then
    echo "⏱️  Server was terminated due to timeout (45s) - this tests timeout behavior"
else
    echo "⚠️  Server exited with code $EXIT_CODE"
fi

echo ""
echo "💡 Expected Behavior:"
echo "  - Server should not hang indefinitely"
echo "  - Should show timeout warnings for database operations"
echo "  - Should continue startup even if client creation fails"
echo "  - Should provide manual SQL commands if admin DB unavailable"
echo ""
echo "🧪 Test completed"
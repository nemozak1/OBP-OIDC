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

# OBP-OIDC Connectivity Test Script
#
# This script tests OIDC server connectivity and well-known endpoint accessibility
# Use this to diagnose "Authorization endpoint not found in OIDC configuration" errors
#
# SETUP INSTRUCTIONS:
# 1. Make it executable: chmod +x test-oidc-connectivity.sh
# 2. Run it: ./test-oidc-connectivity.sh
# 3. Optional: specify custom host/port: ./test-oidc-connectivity.sh localhost 9000

echo "🔍 OBP-OIDC Connectivity Test"
echo "============================="

# Configuration - can be overridden via command line arguments
OIDC_HOST=${1:-${OIDC_HOST:-localhost}}
OIDC_PORT=${2:-${OIDC_PORT:-9000}}
OIDC_EXTERNAL_URL=${OIDC_EXTERNAL_URL}

# Determine the base URL
if [ -n "$OIDC_EXTERNAL_URL" ]; then
    BASE_URL="${OIDC_EXTERNAL_URL%/}"  # Remove trailing slash
    echo "📋 Using external URL: $BASE_URL"
else
    BASE_URL="http://$OIDC_HOST:$OIDC_PORT"
    echo "📋 Using internal URL: $BASE_URL"
fi

ISSUER_URL="$BASE_URL/obp-oidc"
WELL_KNOWN_URL="$ISSUER_URL/.well-known/openid-configuration"

echo "📋 Testing OIDC configuration:"
echo "  Host: $OIDC_HOST"
echo "  Port: $OIDC_PORT"
echo "  Base URL: $BASE_URL"
echo "  Issuer: $ISSUER_URL"
echo "  Well-known endpoint: $WELL_KNOWN_URL"
echo ""

# Test 1: Basic connectivity to OIDC server
echo "🔌 Test 1: Basic server connectivity..."
if timeout 5 bash -c "</dev/tcp/$OIDC_HOST/$OIDC_PORT" 2>/dev/null; then
    echo "✅ Server is reachable at $OIDC_HOST:$OIDC_PORT"
else
    echo "❌ Server is NOT reachable at $OIDC_HOST:$OIDC_PORT"
    echo "   Possible causes:"
    echo "   - OIDC server is not running"
    echo "   - Wrong host/port configuration"
    echo "   - Firewall blocking the connection"
    echo ""
    echo "💡 Try these commands to check:"
    echo "   ps aux | grep java | grep oidc"
    echo "   netstat -tulpn | grep :$OIDC_PORT"
    echo "   ./run-server.sh  # Start the server if not running"
    echo ""
    exit 1
fi

# Test 2: HTTP response from server
echo ""
echo "🌐 Test 2: HTTP response from server..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$BASE_URL" 2>/dev/null || echo "000")

if [ "$HTTP_STATUS" = "000" ]; then
    echo "❌ No HTTP response from $BASE_URL"
    echo "   Server may not be responding to HTTP requests"
    exit 1
elif [ "$HTTP_STATUS" = "404" ]; then
    echo "✅ Server responds (HTTP $HTTP_STATUS) - this is expected for root path"
else
    echo "✅ Server responds (HTTP $HTTP_STATUS)"
fi

# Test 3: Well-known endpoint accessibility
echo ""
echo "🔍 Test 3: OIDC well-known endpoint..."
WELL_KNOWN_RESPONSE=$(curl -s --connect-timeout 5 --max-time 10 "$WELL_KNOWN_URL" 2>/dev/null)
WELL_KNOWN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$WELL_KNOWN_URL" 2>/dev/null || echo "000")

echo "   URL: $WELL_KNOWN_URL"
echo "   Status: HTTP $WELL_KNOWN_STATUS"

if [ "$WELL_KNOWN_STATUS" = "200" ]; then
    echo "✅ Well-known endpoint accessible"

    # Test 4: Parse and validate OIDC configuration
    echo ""
    echo "📊 Test 4: OIDC configuration validation..."

    # Check if response is valid JSON
    if echo "$WELL_KNOWN_RESPONSE" | jq . >/dev/null 2>&1; then
        echo "✅ Response is valid JSON"

        # Extract key endpoints
        ISSUER=$(echo "$WELL_KNOWN_RESPONSE" | jq -r '.issuer // empty')
        AUTH_ENDPOINT=$(echo "$WELL_KNOWN_RESPONSE" | jq -r '.authorization_endpoint // empty')
        TOKEN_ENDPOINT=$(echo "$WELL_KNOWN_RESPONSE" | jq -r '.token_endpoint // empty')
        USERINFO_ENDPOINT=$(echo "$WELL_KNOWN_RESPONSE" | jq -r '.userinfo_endpoint // empty')
        JWKS_URI=$(echo "$WELL_KNOWN_RESPONSE" | jq -r '.jwks_uri // empty')

        echo ""
        echo "📋 OIDC Configuration Details:"
        echo "   Issuer: $ISSUER"
        echo "   Authorization Endpoint: $AUTH_ENDPOINT"
        echo "   Token Endpoint: $TOKEN_ENDPOINT"
        echo "   UserInfo Endpoint: $USERINFO_ENDPOINT"
        echo "   JWKS URI: $JWKS_URI"

        # Validate required endpoints
        MISSING_ENDPOINTS=()
        [ -z "$ISSUER" ] && MISSING_ENDPOINTS+=("issuer")
        [ -z "$AUTH_ENDPOINT" ] && MISSING_ENDPOINTS+=("authorization_endpoint")
        [ -z "$TOKEN_ENDPOINT" ] && MISSING_ENDPOINTS+=("token_endpoint")
        [ -z "$USERINFO_ENDPOINT" ] && MISSING_ENDPOINTS+=("userinfo_endpoint")
        [ -z "$JWKS_URI" ] && MISSING_ENDPOINTS+=("jwks_uri")

        if [ ${#MISSING_ENDPOINTS[@]} -eq 0 ]; then
            echo "✅ All required endpoints present"

            # Test 5: Test individual endpoints
            echo ""
            echo "🔗 Test 5: Individual endpoint accessibility..."

            for endpoint_name in "Authorization" "Token" "UserInfo" "JWKS"; do
                case $endpoint_name in
                    "Authorization") url="$AUTH_ENDPOINT" ;;
                    "Token") url="$TOKEN_ENDPOINT" ;;
                    "UserInfo") url="$USERINFO_ENDPOINT" ;;
                    "JWKS") url="$JWKS_URI" ;;
                esac

                status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || echo "000")

                if [ "$status" = "000" ]; then
                    echo "❌ $endpoint_name endpoint not reachable: $url"
                elif [ "$status" = "405" ] || [ "$status" = "400" ] || [ "$status" = "401" ]; then
                    echo "✅ $endpoint_name endpoint accessible: $url (HTTP $status - expected for GET request)"
                elif [ "$status" = "200" ]; then
                    echo "✅ $endpoint_name endpoint accessible: $url (HTTP $status)"
                else
                    echo "⚠️  $endpoint_name endpoint responds: $url (HTTP $status)"
                fi
            done

        else
            echo "❌ Missing required endpoints: ${MISSING_ENDPOINTS[*]}"
        fi

    else
        echo "❌ Response is not valid JSON"
        echo "   Raw response (first 200 chars):"
        echo "   $(echo "$WELL_KNOWN_RESPONSE" | head -c 200)..."
    fi

elif [ "$WELL_KNOWN_STATUS" = "404" ]; then
    echo "❌ Well-known endpoint not found (HTTP 404)"
    echo "   This suggests the OIDC discovery endpoint is not properly configured"
    echo "   Expected path: /obp-oidc/.well-known/openid-configuration"

elif [ "$WELL_KNOWN_STATUS" = "000" ]; then
    echo "❌ No response from well-known endpoint"
    echo "   Connection failed or timeout"

else
    echo "❌ Unexpected response from well-known endpoint (HTTP $WELL_KNOWN_STATUS)"
    if [ -n "$WELL_KNOWN_RESPONSE" ]; then
        echo "   Response (first 200 chars):"
        echo "   $(echo "$WELL_KNOWN_RESPONSE" | head -c 200)..."
    fi
fi

# Test 6: Common troubleshooting
echo ""
echo "🔧 Troubleshooting Information:"
echo ""

# Check if server is running
SERVER_PROCESSES=$(ps aux | grep -i java | grep -i oidc | grep -v grep || echo "")
if [ -n "$SERVER_PROCESSES" ]; then
    echo "✅ OIDC server process found:"
    echo "$SERVER_PROCESSES" | sed 's/^/   /'
else
    echo "❌ No OIDC server process found"
    echo "   Start the server with: ./run-server.sh"
fi

echo ""
echo "📋 For OBP-API integration, ensure:"
echo "   1. OBP-API is configured with the correct OIDC URL"
echo "   2. The OIDC server is accessible from OBP-API's network"
echo "   3. No firewall is blocking the connection"
echo ""

# Show full configuration for copy-paste
if [ "$WELL_KNOWN_STATUS" = "200" ] && [ -n "$WELL_KNOWN_RESPONSE" ]; then
    echo "📋 Complete OIDC Configuration (for debugging):"
    echo "$WELL_KNOWN_RESPONSE" | jq . 2>/dev/null || echo "$WELL_KNOWN_RESPONSE"
    echo ""
fi

echo "🎯 Next Steps:"
if [ "$WELL_KNOWN_STATUS" = "200" ]; then
    echo "   ✅ OIDC server is working correctly"
    echo "   🔧 Check OBP-API configuration:"
    echo "      - Verify OIDC discovery URL: $WELL_KNOWN_URL"
    echo "      - Check network connectivity from OBP-API to OIDC server"
    echo "      - Review OBP-API logs for detailed error messages"
else
    echo "   ❌ Fix OIDC server issues first:"
    echo "      - Ensure server is running: ./run-server.sh"
    echo "      - Check server logs for errors"
    echo "      - Verify configuration in run-server.sh"
    echo "      - Test database connectivity: ./test-admin-db.sh"
fi

echo ""
echo "💡 Need more help?"
echo "   - Check server logs: tail -f logs/application.log"
echo "   - Verify database: ./test-admin-db.sh"
echo "   - Review configuration: ./generate-config.sh"

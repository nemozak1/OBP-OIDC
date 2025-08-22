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

# OBP-OIDC Admin Database Connection Test Script
# 
# SETUP INSTRUCTIONS:
# 1. Copy this file to test-admin-db.sh:
#    cp test-admin-db.example.sh test-admin-db.sh
# 2. Edit test-admin-db.sh with your admin database credentials
# 3. Make it executable:
#    chmod +x test-admin-db.sh
# 4. Run it:
#    ./test-admin-db.sh

echo "🔧 OBP-OIDC Admin Database Connection Test"
echo "==========================================="

# Admin Database Configuration
# ⚠️  IMPORTANT: Edit these values for your admin database setup
# These are example values - CHANGE THEM!
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sandbox
DB_ADMIN_USER=oidc_admin_user
DB_ADMIN_PASSWORD=CHANGE_THIS_TO_A_VERY_STRONG_ADMIN_PASSWORD_2024!

echo "📋 Testing admin database connection:"
echo "  Host: $DB_HOST:$DB_PORT"
echo "  Database: $DB_NAME"
echo "  Admin User: $DB_ADMIN_USER"
echo ""

# Test basic connection
echo "🔌 Testing basic database connection..."
if psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -c "SELECT version();" > /dev/null 2>&1; then
    echo "✅ Basic connection successful"
else
    echo "❌ Basic connection failed"
    echo "   Please check your database credentials and ensure PostgreSQL is running"
    exit 1
fi

# Test v_oidc_admin_clients view access
echo ""
echo "📊 Testing v_oidc_admin_clients view access..."
if psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -c "SELECT COUNT(*) FROM v_oidc_admin_clients;" > /dev/null 2>&1; then
    CLIENT_COUNT=$(psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "SELECT COUNT(*) FROM v_oidc_admin_clients;" | xargs)
    echo "✅ v_oidc_admin_clients view accessible"
    echo "   Found $CLIENT_COUNT client(s) in the view"
else
    echo "❌ v_oidc_admin_clients view not accessible"
    echo "   Please ensure the view exists and your user has the correct permissions"
    exit 1
fi

# Test write permissions (INSERT)
echo ""
echo "✏️  Testing write permissions (INSERT)..."
TEST_CLIENT_ID="test-client-$(date +%s)"
INSERT_RESULT=$(psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
INSERT INTO v_oidc_admin_clients (
    client_id, client_secret, client_name, redirect_uris, 
    grant_types, response_types, scopes, token_endpoint_auth_method
) VALUES (
    '$TEST_CLIENT_ID', 'test-secret', 'Test Client', 'http://localhost:3000/callback',
    'authorization_code', 'code', 'openid', 'client_secret_basic'
) RETURNING client_id;" 2>&1)

if echo "$INSERT_RESULT" | grep -q "$TEST_CLIENT_ID"; then
    echo "✅ INSERT permission working"
    
    # Test UPDATE permission
    echo "🔄 Testing UPDATE permission..."
    UPDATE_RESULT=$(psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
    UPDATE v_oidc_admin_clients 
    SET client_name = 'Updated Test Client' 
    WHERE client_id = '$TEST_CLIENT_ID' 
    RETURNING client_id;" 2>&1)
    
    if echo "$UPDATE_RESULT" | grep -q "$TEST_CLIENT_ID"; then
        echo "✅ UPDATE permission working"
    else
        echo "❌ UPDATE permission failed: $UPDATE_RESULT"
    fi
    
    # Test DELETE permission
    echo "🗑️  Testing DELETE permission..."
    DELETE_RESULT=$(psql "postgresql://$DB_ADMIN_USER:$DB_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
    DELETE FROM v_oidc_admin_clients 
    WHERE client_id = '$TEST_CLIENT_ID' 
    RETURNING client_id;" 2>&1)
    
    if echo "$DELETE_RESULT" | grep -q "$TEST_CLIENT_ID"; then
        echo "✅ DELETE permission working"
        echo "🧹 Test client cleaned up successfully"
    else
        echo "❌ DELETE permission failed: $DELETE_RESULT"
        echo "⚠️  You may need to manually clean up the test client: $TEST_CLIENT_ID"
    fi
    
else
    echo "❌ INSERT permission failed: $INSERT_RESULT"
    echo "   Please ensure your admin user has INSERT permissions on v_oidc_admin_clients"
fi

echo ""
echo "🎉 Admin database connection test completed!"
echo ""
echo "📝 Summary:"
echo "   - Basic connection: ✅"
echo "   - View access: ✅"
echo "   - Write permissions test completed"
echo ""
echo "💡 If all tests passed, your admin database configuration is ready!"
echo "   You can now use the OIDC provider's client management features."
echo ""
echo "🚀 Next steps:"
echo "   1. Update your run-server.sh with these admin database credentials"
echo "   2. Start the OIDC server with: ./run-server.sh"
echo "   3. The server will automatically test both database connections on startup"
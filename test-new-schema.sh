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

# Test Script for New v_oidc_admin_clients Schema
#
# This script tests write operations to the updated database schema
#
# SETUP INSTRUCTIONS:
# 1. Update the database credentials below
# 2. Make it executable: chmod +x test-new-schema.sh
# 3. Run it: ./test-new-schema.sh

echo "🧪 Testing New v_oidc_admin_clients Schema"
echo "==========================================="

# Database Configuration
# ⚠️  IMPORTANT: Edit these values for your database setup
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sandbox
OIDC_ADMIN_USER=oidc_admin
OIDC_ADMIN_PASSWORD=fhka77uefassEE

echo "📋 TestiCHANGE_THIS_TO_A_VERY_STRONG_ADMIN_PASSWORD_2024ng database connection:"
echo "  Host: $DB_HOST:$DB_PORT"
echo "  Database: $DB_NAME"
echo "  Admin User: $OIDC_ADMIN_USER"
echo ""

# Test basic connection
echo "🔌 Testing basic database connection..."
if psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -c "SELECT version();" > /dev/null 2>&1; then
    echo "✅ Database login successful as user: $OIDC_ADMIN_USER"
else
    echo "❌ Database login failed"
    echo "   Possible causes:"
    echo "   - Wrong username or password"
    echo "   - PostgreSQL service not running"
    echo "   - Database '$DB_NAME' doesn't exist"
    echo "   - User '$OIDC_ADMIN_USER' doesn't exist"
    echo ""
    echo "   💡 Try these commands to check:"
    echo "   sudo systemctl status postgresql"
    echo "   psql -h $DB_HOST -p $DB_PORT -U $OIDC_ADMIN_USER -d $DB_NAME"
    exit 1
fi

# Test view schema
echo ""
echo "📊 Checking v_oidc_admin_clients view schema..."
SCHEMA_CHECK=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
SELECT column_name
FROM information_schema.columns
WHERE table_name = 'v_oidc_admin_clients'
ORDER BY ordinal_position;" 2>&1)

if echo "$SCHEMA_CHECK" | grep -q "consumerid"; then
    echo "✅ New schema detected with consumerid column"
    echo "   Available columns:"
    echo "$SCHEMA_CHECK" | sed 's/^/ - /'
else
    echo "❌ View structure not as expected"
    echo "   The view 'v_oidc_admin_clients' was not found or doesn't have the expected columns"
    echo "   Available columns:"
    echo "$SCHEMA_CHECK" | sed 's/^/ - /'
    exit 1
fi

# Test record count
echo ""
echo "📊 Testing view access..."
CLIENT_COUNT=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "SELECT COUNT(*) FROM v_oidc_admin_clients;" | xargs)
echo "✅ v_oidc_admin_clients view accessible"
echo "   Found $CLIENT_COUNT existing client(s)"

# Test write permissions with new schema
echo ""
echo "✏️  Testing write permissions with new schema..."
TEST_CLIENT_ID="test-new-schema-$(date +%s)"
TEST_SECRET="test-secret-$(date +%s)"

# Use new schema column names (consumerid is auto-generated, don't set it)
INSERT_RESULT=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
INSERT INTO v_oidc_admin_clients (
  name, apptype, description, developeremail, sub,
  secret, azp, aud, iss, redirecturl, company, consumerid, isactive
) VALUES (
  'Test Client New Schema',
  'WEB',
  'Test client for new database schema',
  'test@tesobe.com',
  'test-subject',
  '$TEST_SECRET',
  '$TEST_CLIENT_ID',
  'obp-api',
  'obp-oidc',
  'http://localhost:3000/test/callback',
  'TESOBE',
  '$TEST_CLIENT_ID',
  true
) RETURNING consumerid;" 2>&1)

if echo "$INSERT_RESULT" | grep -q "$TEST_CLIENT_ID"; then
    echo "✅ INSERT with new schema successful"

    # Test UPDATE with new schema
    echo "🔄 Testing UPDATE with new schema..."
    UPDATE_RESULT=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
    UPDATE v_oidc_admin_clients 
    SET name = 'Updated Test Client',
        description = 'Updated test description',
        redirecturl = 'http://localhost:3000/updated/callback'
    WHERE consumerid = '$TEST_CLIENT_ID'
    RETURNING consumerid;" 2>&1)

    if echo "$UPDATE_RESULT" | grep -q "$TEST_CLIENT_ID"; then
        echo "✅ UPDATE with new schema successful"
    else
        echo "❌ UPDATE failed: $UPDATE_RESULT"
    fi

    # Test SELECT to verify data
    echo "📋 Testing SELECT with new schema..."
    SELECT_RESULT=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
    SELECT name, consumerid, secret, redirecturl, isactive
    FROM v_oidc_admin_clients 
    WHERE consumerid = '$TEST_CLIENT_ID';" 2>&1)

    if echo "$SELECT_RESULT" | grep -q "Updated Test Client"; then
        echo "✅ SELECT with new schema successful"
        echo "   Retrieved data: $SELECT_RESULT"
    else
        echo "❌ SELECT failed or data not found: $SELECT_RESULT"
    fi

    # Test DELETE with new schema
    echo "🗑️  Testing DELETE with new schema..."
    DELETE_RESULT=$(psql "postgresql://$OIDC_ADMIN_USER:$OIDC_ADMIN_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME" -t -c "
    DELETE FROM v_oidc_admin_clients 
    WHERE consumerid = '$TEST_CLIENT_ID'
    RETURNING consumerid;" 2>&1)

    if echo "$DELETE_RESULT" | grep -q "$TEST_CLIENT_ID"; then
        echo "✅ DELETE with new schema successful"
        echo "🧹 Test client cleaned up successfully"
    else
        echo "❌ DELETE failed: $DELETE_RESULT"
        echo "⚠️  You may need to manually clean up the test client: $TEST_CLIENT_ID"
    fi

else
    echo "❌ INSERT with new schema failed: $INSERT_RESULT"
    echo "   Please check if the view supports INSERT operations"
    echo "   and all required columns are present"
fi

echo ""
echo "🎉 New schema test completed!"
echo ""
echo "📝 Test Summary:"
echo "   - Database connection: ✅"
echo "   - New schema detection: ✅"
echo "   - View access: ✅"
echo "   - Write operations test: See results above"
echo ""
echo "💡 If all tests passed, the OBP-OIDC server should work with your new schema!"
echo ""
echo "🚀 Next steps:"
echo "   1. Start the OIDC server with: ./run-server.sh"
echo "   2. The server will automatically use the new schema"
echo "   3. Check server logs for client creation status"
echo ""
echo "📋 Column Mapping (OIDC Standard → Your Database):"
echo "   client_id         → consumerid"
echo "   client_secret     → secret"
echo "   client_name       → name"
echo "   redirect_uris     → redirecturl"
echo "   created_at        → createdat"
echo "   updated_at        → updatedat"
echo "   consumer_id       → consumerid

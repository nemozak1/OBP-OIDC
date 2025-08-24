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

# OBP-OIDC Developer Configuration Generator
# This script generates secure database passwords and OIDC client configurations

set -e

echo "🚀 OBP-OIDC Developer Configuration Generator"
echo "=============================================="
echo ""

# Check if mvn is available
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven is required but not installed."
    echo "   Please install Maven: https://maven.apache.org/install.html"
    exit 1
fi

# Check if Java is available
if ! command -v java &> /dev/null; then
    echo "❌ Java is required but not installed."
    echo "   Please install Java 11 or later"
    exit 1
fi

echo "📋 What would you like to generate?"
echo ""
echo "1. Database configuration only"
echo "2. Full configuration (database + OIDC clients)"
echo "3. Help / Show all commands"
echo ""
read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        echo ""
        echo "🔐 Generating database configuration..."
        echo ""
        mvn compile exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer" -Dexec.args="--db-config" -q
        ;;
    2)
        echo ""
        echo "🔐 Generating full developer configuration..."
        echo ""
        mvn compile exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer" -Dexec.args="--generate-config" -q
        ;;
    3)
        echo ""
        echo "🚀 OBP-OIDC Developer Helper Commands"
        echo "====================================="
        echo ""
        echo "Manual commands:"
        echo "  mvn exec:java -Dexec.args=\"--generate-config\"  # Generate all config"
        echo "  mvn exec:java -Dexec.args=\"--db-config\"       # Generate DB config only"
        echo "  mvn exec:java                                    # Start server"
        echo ""
        echo "Or use this script:"
        echo "  ./generate-config.sh                            # Interactive menu"
        echo ""
        echo "Generated files:"
        echo "  obp-oidc-database-config.txt                    # Database setup commands"
        echo "  obp-oidc-generated-config.txt                   # OIDC client configurations"
        echo ""
        ;;
    *)
        echo "❌ Invalid choice. Please run the script again and choose 1, 2, or 3."
        exit 1
        ;;
esac

echo ""
echo "✅ Configuration generation complete!"
echo ""
echo "📄 Generated files:"
if [ -f "obp-oidc-database-config.txt" ]; then
    echo "   📁 obp-oidc-database-config.txt    (Database setup)"
fi
if [ -f "obp-oidc-generated-config.txt" ]; then
    echo "   📁 obp-oidc-generated-config.txt   (OIDC client config)"
fi
echo ""
echo "🎯 Next steps:"
echo "   1. Set up your database using the commands in obp-oidc-database-config.txt"
echo "   2. Run ./run-server.sh to start OBP-OIDC"
echo "   3. Copy configurations from generated files to your OBP projects"
echo ""
echo "💡 Need help? Run: ./generate-config.sh and choose option 3"
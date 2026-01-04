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

# OBP-OIDC Build and Run Script
# This script builds the project from scratch and then delegates to run-server.sh
#
# Usage:
#   ./build_and_run_server.sh                    # Standard build and run
#   OIDC_ENABLE_TRACE_LOGGING=true ./build_and_run_server.sh  # With trace logging

set -e  # Exit on any error

echo "OBP-OIDC Build and Run"
echo "======================"
echo ""

# Check if we're in the right directory
if [ ! -f "pom.xml" ]; then
    echo "Error: pom.xml not found. Please run this script from the OBP-OIDC project root directory."
    exit 1
fi

# Check if .env exists, if not create it from example
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo ".env file not found. Creating it from .env.example..."
        cp .env.example .env
        echo ""
        echo "⚠️  IMPORTANT: Please edit .env with your configuration before running!"
        echo "   The example file has been copied, but you need to update:"
        echo "   - OIDC_USER_PASSWORD, OIDC_ADMIN_PASSWORD (database credentials)"
        echo "   - DB_HOST, DB_PORT, DB_NAME (if different from defaults)"
        echo ""
        echo "   Note: OIDC client credentials are auto-generated on first startup"
        echo ""
        echo "Press Enter to continue once you've updated the configuration, or Ctrl+C to exit..."
        read -r
    else
        echo "Error: .env.example not found."
        echo "Please ensure .env.example exists in the project."
        exit 1
    fi
fi

# Clean and build the project
echo "Step 1: Cleaning previous builds..."
mvn clean

echo ""
echo "Step 2: Building project and creating executable JAR..."
MAVEN_OPTS="-Xmx3G -Xss2m" mvn package -DskipTests

# Check if build was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "Build successful! JAR created: target/obp-oidc-1.0.0-SNAPSHOT.jar"
    echo ""
    echo "Step 3: Starting server..."
    echo "Delegating to run-server.sh..."
    echo "============================================"

    # Make sure run-server.sh is executable
    chmod +x run-server.sh

    # Delegate to run-server.sh, preserving all environment variables
    exec ./run-server.sh
else
    echo ""
    echo "Build failed. Please check the error messages above."
    exit 1
fi

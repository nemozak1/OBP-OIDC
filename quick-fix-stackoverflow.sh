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

# Quick Fix for StackOverflowError During Compilation
#
# This script applies immediate fixes for the StackOverflowError issue
# that can occur during Scala compilation on some machines.
#
# USAGE:
# chmod +x quick-fix-stackoverflow.sh
# ./quick-fix-stackoverflow.sh

echo "🚀 Quick Fix for StackOverflowError"
echo "===================================="

# Step 1: Set aggressive memory settings
echo "📋 Step 1: Setting maximum memory for Maven compilation"
export MAVEN_OPTS="-Xmx8g -Xms2g -XX:MaxPermSize=1g -XX:ReservedCodeCacheSize=1g -XX:+UseG1GC -XX:MaxGCPauseMillis=200"

echo "   MAVEN_OPTS set to: $MAVEN_OPTS"
echo "   ✅ Memory settings applied"

# Step 2: Clean all build artifacts thoroughly
echo ""
echo "📋 Step 2: Deep cleaning build artifacts"
echo "   Removing target directory..."
rm -rf target/

echo "   Removing IDE files..."
rm -rf .idea/ .vscode/ .metals/ .bloop/

echo "   Clearing local Maven repository for this project..."
rm -rf ~/.m2/repository/com/tesobe/

echo "   ✅ Deep clean completed"

# Step 3: Single-threaded compilation with minimal flags
echo ""
echo "📋 Step 3: Attempting single-threaded compilation"
echo "   Using command: mvn clean compile -T 1 -q"
echo "   This may take longer but should avoid stack overflow..."

mvn clean compile -T 1 -q

COMPILE_RESULT=$?

if [ $COMPILE_RESULT -eq 0 ]; then
    echo ""
    echo "🎉 SUCCESS! Compilation completed successfully"
    echo ""
    echo "📋 What was fixed:"
    echo "   - Increased JVM heap size to 8GB"
    echo "   - Used G1 garbage collector for better memory management"
    echo "   - Forced single-threaded compilation (-T 1)"
    echo "   - Cleared all cached artifacts that might cause conflicts"
    echo ""
    echo "🚀 You can now run the server:"
    echo "   ./run-server.sh"
    echo ""
    echo "💡 To avoid this issue in the future, consider:"
    echo "   - Adding 'export MAVEN_OPTS=\"-Xmx4g -XX:+UseG1GC\"' to your ~/.bashrc"
    echo "   - Closing other memory-intensive applications before building"
else
    echo ""
    echo "❌ Compilation still failed. Trying alternative approaches..."
    echo ""

    # Alternative approach 1: Force dependency resolution first
    echo "📋 Alternative 1: Force dependency resolution"
    mvn dependency:resolve -U -q

    if [ $? -eq 0 ]; then
        echo "   Dependencies resolved, retrying compilation..."
        mvn compile -T 1 -q -DforkCount=1 -DreuseForks=false

        if [ $? -eq 0 ]; then
            echo "🎉 SUCCESS! Alternative approach 1 worked"
            exit 0
        fi
    fi

    # Alternative approach 2: Compile with even more conservative settings
    echo ""
    echo "📋 Alternative 2: Ultra-conservative compilation"
    export MAVEN_OPTS="-Xmx6g -Xms3g -XX:NewRatio=1 -XX:SurvivorRatio=8 -XX:+UseSerialGC -Xss8m"

    mvn clean compile -T 1 -q -Dmaven.compile.fork=true -Dmaven.compiler.maxmem=4g

    if [ $? -eq 0 ]; then
        echo "🎉 SUCCESS! Ultra-conservative approach worked"
        exit 0
    fi

    # If everything fails, provide manual steps
    echo ""
    echo "❌ All automatic fixes failed. Manual intervention required."
    echo ""
    echo "🔧 MANUAL STEPS TO TRY:"
    echo ""
    echo "1. Restart your machine to free up all memory"
    echo ""
    echo "2. Close ALL other applications, especially:"
    echo "   - Web browsers with many tabs"
    echo "   - IDEs (IntelliJ IDEA, VS Code, etc.)"
    echo "   - Docker containers"
    echo "   - Other Java applications"
    echo ""
    echo "3. Try building on a machine with more RAM (8GB+ recommended)"
    echo ""
    echo "4. If you have limited RAM, try this ultra-minimal approach:"
    echo "   export MAVEN_OPTS=\"-Xmx2g -Xms512m -XX:+UseSerialGC\""
    echo "   mvn clean"
    echo "   mvn compile -T 1 -o  # Offline mode"
    echo ""
    echo "5. As a last resort, try compiling individual modules:"
    echo "   mvn compile -pl :obp-oidc"
    echo ""
    echo "6. Check system resources:"
    echo "   free -h        # Check available memory"
    echo "   df -h          # Check disk space"
    echo "   top            # Check running processes"
    echo ""
    echo "📧 If the issue persists, this indicates:"
    echo "   - Insufficient system memory for Scala compilation"
    echo "   - Possible circular dependency in recent code changes"
    echo "   - JVM or compiler bug on this specific system"
    echo ""
    echo "💡 Consider:"
    echo "   - Using a cloud build environment (GitHub Actions, etc.)"
    echo "   - Building on a different machine temporarily"
    echo "   - Reverting recent complex changes and building incrementally"

    exit 1
fi

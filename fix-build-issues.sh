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

# OBP-OIDC Build Issues Troubleshooting Script
#
# This script helps diagnose and fix common build issues including:
# - StackOverflowError during compilation
# - Deprecated API warnings
# - Memory issues
# - Scala compiler problems
#
# USAGE:
# chmod +x fix-build-issues.sh
# ./fix-build-issues.sh

echo "🔧 OBP-OIDC Build Issues Troubleshooting"
echo "========================================="

# Function to check system requirements
check_system_requirements() {
    echo ""
    echo "📋 Checking system requirements..."

    # Check Java version
    if command -v java &> /dev/null; then
        JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d '"' -f 2)
        echo "✅ Java version: $JAVA_VERSION"

        # Extract major version number
        JAVA_MAJOR=$(echo "$JAVA_VERSION" | cut -d '.' -f 1)
        if [ "$JAVA_MAJOR" -lt 11 ]; then
            echo "⚠️  WARNING: Java 11 or higher recommended (found: $JAVA_VERSION)"
        fi
    else
        echo "❌ Java not found. Please install Java 11 or higher."
        return 1
    fi

    # Check Maven version
    if command -v mvn &> /dev/null; then
        MVN_VERSION=$(mvn -version 2>&1 | head -n 1 | cut -d ' ' -f 3)
        echo "✅ Maven version: $MVN_VERSION"
    else
        echo "❌ Maven not found. Please install Apache Maven."
        return 1
    fi

    # Check available memory
    if command -v free &> /dev/null; then
        TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
        AVAIL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
        echo "📊 System memory: ${TOTAL_MEM}MB total, ${AVAIL_MEM}MB available"

        if [ "$AVAIL_MEM" -lt 2048 ]; then
            echo "⚠️  WARNING: Low available memory. Compilation may fail or be slow."
            echo "   Consider closing other applications or increasing memory."
        fi
    fi
}

# Function to clean build artifacts
clean_build() {
    echo ""
    echo "🧹 Cleaning build artifacts..."

    # Clean Maven artifacts
    if [ -d "target" ]; then
        echo "   Removing target/ directory..."
        rm -rf target/
    fi

    # Clean Maven cache for this project (optional)
    echo "   Cleaning Maven cache..."
    mvn dependency:purge-local-repository -q 2>/dev/null || echo "   (Maven cache clean skipped)"

    echo "✅ Build artifacts cleaned"
}

# Function to check for known problematic patterns
check_code_issues() {
    echo ""
    echo "🔍 Checking for known problematic code patterns..."

    # Check for deprecated mapValues usage
    MAPVALUES_COUNT=$(grep -r "\.mapValues(" src/ 2>/dev/null | wc -l || echo "0")
    if [ "$MAPVALUES_COUNT" -gt 0 ]; then
        echo "⚠️  Found $MAPVALUES_COUNT deprecated mapValues usage(s)"
        echo "   These have been fixed in the latest code but may cause warnings"
        grep -rn "\.mapValues(" src/ 2>/dev/null | head -5 | sed 's/^/   /'
    else
        echo "✅ No deprecated mapValues usage found"
    fi

    # Check for circular imports or dependencies
    echo "   Checking for potential circular dependencies..."
    # This is a simplified check - look for imports that might cause issues
    CIRCULAR_IMPORTS=$(find src/ -name "*.scala" -exec grep -l "import.*DatabaseAuthService" {} \; 2>/dev/null | wc -l || echo "0")
    if [ "$CIRCULAR_IMPORTS" -gt 5 ]; then
        echo "⚠️  Potential circular import issues detected"
        echo "   Multiple files importing DatabaseAuthService: $CIRCULAR_IMPORTS"
    else
        echo "✅ No obvious circular import issues"
    fi
}

# Function to increase JVM memory settings
configure_maven_memory() {
    echo ""
    echo "💾 Configuring Maven memory settings..."

    # Check current MAVEN_OPTS
    if [ -n "$MAVEN_OPTS" ]; then
        echo "   Current MAVEN_OPTS: $MAVEN_OPTS"
    else
        echo "   MAVEN_OPTS not set"
    fi

    # Recommend memory settings
    RECOMMENDED_OPTS="-Xms1g -Xmx4g -XX:PermSize=256m -XX:MaxPermSize=512m -XX:ReservedCodeCacheSize=256m"

    echo "   Recommended MAVEN_OPTS: $RECOMMENDED_OPTS"
    echo ""
    echo "   To apply these settings, run:"
    echo "   export MAVEN_OPTS=\"$RECOMMENDED_OPTS\""
    echo "   mvn clean compile"
    echo ""

    # Ask if user wants to apply settings for this session
    read -p "   Apply these settings for this build session? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        export MAVEN_OPTS="$RECOMMENDED_OPTS"
        echo "✅ Memory settings applied for this session"
        return 0
    else
        echo "⚠️  Memory settings not applied - you may need to set them manually"
        return 1
    fi
}

# Function to try different build strategies
try_build_strategies() {
    echo ""
    echo "🔨 Trying different build strategies..."

    # Strategy 1: Clean compile with increased memory
    echo ""
    echo "📋 Strategy 1: Clean compile with verbose output"
    echo "Command: mvn clean compile -X"
    read -p "Try this strategy? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mvn clean compile -X
        if [ $? -eq 0 ]; then
            echo "✅ Strategy 1 succeeded!"
            return 0
        else
            echo "❌ Strategy 1 failed"
        fi
    fi

    # Strategy 2: Compile in single-threaded mode
    echo ""
    echo "📋 Strategy 2: Single-threaded compilation"
    echo "Command: mvn clean compile -T 1"
    read -p "Try this strategy? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mvn clean compile -T 1
        if [ $? -eq 0 ]; then
            echo "✅ Strategy 2 succeeded!"
            return 0
        else
            echo "❌ Strategy 2 failed"
        fi
    fi

    # Strategy 3: Compile without tests
    echo ""
    echo "📋 Strategy 3: Compile without tests"
    echo "Command: mvn clean compile -DskipTests"
    read -p "Try this strategy? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mvn clean compile -DskipTests
        if [ $? -eq 0 ]; then
            echo "✅ Strategy 3 succeeded!"
            return 0
        else
            echo "❌ Strategy 3 failed"
        fi
    fi

    # Strategy 4: Force dependency update
    echo ""
    echo "📋 Strategy 4: Force dependency update"
    echo "Command: mvn clean compile -U"
    read -p "Try this strategy? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mvn clean compile -U
        if [ $? -eq 0 ]; then
            echo "✅ Strategy 4 succeeded!"
            return 0
        else
            echo "❌ Strategy 4 failed"
        fi
    fi

    return 1
}

# Function to provide specific fixes for known errors
provide_specific_fixes() {
    echo ""
    echo "🎯 Specific fixes for known errors:"
    echo ""

    echo "📋 For StackOverflowError during compilation:"
    echo "   1. Increase JVM heap size: export MAVEN_OPTS=\"-Xmx4g -Xms1g\""
    echo "   2. Reduce compiler parallelism: mvn compile -T 1"
    echo "   3. Clean workspace completely: rm -rf target/ ~/.m2/repository/com/tesobe/"
    echo "   4. Try older Scala version if necessary"
    echo ""

    echo "📋 For deprecated mapValues warnings:"
    echo "   - These are just warnings and should not cause build failure"
    echo "   - Fix: Replace .mapValues(f) with .view.mapValues(f).toMap"
    echo "   - Already fixed in recent code updates"
    echo ""

    echo "📋 For missing BCrypt dependency:"
    echo "   - Ensure jbcrypt dependency is in pom.xml"
    echo "   - Run: mvn dependency:resolve"
    echo "   - Check internet connection for dependency download"
    echo ""

    echo "📋 For out of memory errors:"
    echo "   - Close other applications"
    echo "   - Increase system swap space"
    echo "   - Use: export MAVEN_OPTS=\"-Xmx4g -XX:MaxPermSize=512m\""
    echo ""
}

# Function to check dependencies
check_dependencies() {
    echo ""
    echo "📦 Checking project dependencies..."

    echo "   Resolving dependencies..."
    mvn dependency:resolve -q
    if [ $? -eq 0 ]; then
        echo "✅ All dependencies resolved successfully"
    else
        echo "❌ Some dependencies could not be resolved"
        echo "   Try: mvn dependency:resolve -U (force update)"
        return 1
    fi

    # Check for dependency conflicts
    echo "   Checking for dependency conflicts..."
    mvn dependency:tree -q > /tmp/dep-tree.txt 2>&1
    if grep -q "conflicts" /tmp/dep-tree.txt; then
        echo "⚠️  Potential dependency conflicts found:"
        grep "conflicts" /tmp/dep-tree.txt | head -3 | sed 's/^/   /'
    else
        echo "✅ No obvious dependency conflicts"
    fi

    rm -f /tmp/dep-tree.txt
}

# Function to create emergency build script
create_emergency_build() {
    echo ""
    echo "🆘 Creating emergency build script..."

    cat > emergency-build.sh << 'EOF'
#!/bin/bash
# Emergency build script with maximum memory and minimal parallelism

export MAVEN_OPTS="-Xmx6g -Xms2g -XX:MaxPermSize=1g -XX:ReservedCodeCacheSize=512m -XX:+UseG1GC"

echo "🆘 Running emergency build with maximum memory settings..."
echo "MAVEN_OPTS: $MAVEN_OPTS"

# Clean everything
rm -rf target/
mvn clean

# Try to compile with single thread and verbose output
mvn compile -T 1 -X -DforkCount=1 -DreuseForks=false

echo "Build completed. Check output above for results."
EOF

    chmod +x emergency-build.sh
    echo "✅ Created emergency-build.sh"
    echo "   Run with: ./emergency-build.sh"
}

# Main execution
main() {
    echo "Starting build troubleshooting..."

    # Run checks
    check_system_requirements
    if [ $? -ne 0 ]; then
        echo "❌ System requirements not met. Please fix before continuing."
        exit 1
    fi

    check_dependencies
    check_code_issues

    # Clean build
    clean_build

    # Configure memory
    configure_maven_memory
    MEMORY_CONFIGURED=$?

    # Try build strategies
    echo ""
    echo "🚀 Ready to try building..."
    read -p "Proceed with build strategies? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        try_build_strategies
        BUILD_SUCCESS=$?

        if [ $BUILD_SUCCESS -ne 0 ]; then
            echo ""
            echo "❌ All build strategies failed"
            provide_specific_fixes
            create_emergency_build

            echo ""
            echo "🆘 NEXT STEPS:"
            echo "1. Try the emergency build: ./emergency-build.sh"
            echo "2. Check system resources (RAM, disk space)"
            echo "3. Try on a different machine with more memory"
            echo "4. Consider using a lighter IDE or closing other applications"
            echo "5. If persistent, consider downgrading Scala version temporarily"
        else
            echo ""
            echo "🎉 Build completed successfully!"
            echo "You can now run: ./run-server.sh"
        fi
    else
        provide_specific_fixes
        create_emergency_build
    fi

    echo ""
    echo "📋 Troubleshooting complete."
    echo "Check the output above for specific recommendations."
}

# Run main function
main "$@"

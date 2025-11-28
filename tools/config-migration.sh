#!/bin/bash

# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.

# Configuration Migration Tool
# Migrates old authentication/authorization backend configurations
# to the new plugin-based configuration format.

set -e

SCRIPT_PATH="${BASH_SOURCE[0]}"
if ! [ -x "$(command -v realpath)" ]; then
    if [ -L "$SCRIPT_PATH" ]; then
        [ -x "$(command -v readlink)" ] || { echo "Unable to resolve symlink. Please install realpath or readlink."; exit 1; }
        SCRIPT_PATH=$(readlink -f "$SCRIPT_PATH")
    fi
else
    SCRIPT_PATH=$(realpath "$SCRIPT_PATH")
fi

SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
BASE_DIR="$SCRIPT_DIR/.."

# Check if running from the correct directory
if [ ! -f "$BASE_DIR/build.gradle" ]; then
    echo "Error: This script must be run from the OpenSearch Security plugin directory"
    exit 1
fi

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] <old-config-path> <new-config-path>

Migrates old authentication/authorization backend configurations
to the new plugin-based configuration format.

Arguments:
  old-config-path    Path to the old config.yml file
  new-config-path    Path where the new configuration should be written

Options:
  -h, --help         Display this help message
  -v, --verbose      Enable verbose output
  -d, --dry-run      Show what would be migrated without writing output

Examples:
  # Migrate configuration
  $0 /etc/opensearch/config.yml /etc/opensearch/config-new.yml

  # Dry run to preview migration
  $0 --dry-run /etc/opensearch/config.yml /tmp/config-preview.yml

EOF
}

# Parse command line arguments
VERBOSE=false
DRY_RUN=false
OLD_CONFIG=""
NEW_CONFIG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            if [ -z "$OLD_CONFIG" ]; then
                OLD_CONFIG="$1"
            elif [ -z "$NEW_CONFIG" ]; then
                NEW_CONFIG="$1"
            else
                echo "Error: Too many arguments"
                usage
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate arguments
if [ -z "$OLD_CONFIG" ] || [ -z "$NEW_CONFIG" ]; then
    echo "Error: Both old-config-path and new-config-path are required"
    usage
    exit 1
fi

# Check if old config exists
if [ ! -f "$OLD_CONFIG" ]; then
    echo "Error: Old configuration file not found: $OLD_CONFIG"
    exit 1
fi

# Check if new config already exists
if [ -f "$NEW_CONFIG" ] && [ "$DRY_RUN" = false ]; then
    read -p "Warning: New configuration file already exists. Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Migration cancelled"
        exit 0
    fi
fi

# Find the JAR file
JAR_FILE=$(find "$BASE_DIR/build/libs" -name "opensearch-security-*.jar" 2>/dev/null | head -n 1)

if [ -z "$JAR_FILE" ]; then
    echo "Error: OpenSearch Security JAR file not found"
    echo "Please build the project first: ./gradlew build"
    exit 1
fi

# Build classpath
CLASSPATH="$JAR_FILE"
for jar in "$BASE_DIR"/build/libs/*.jar; do
    if [ -f "$jar" ]; then
        CLASSPATH="$CLASSPATH:$jar"
    fi
done

# Add dependencies
if [ -d "$BASE_DIR/build/dependencies" ]; then
    for jar in "$BASE_DIR"/build/dependencies/*.jar; do
        if [ -f "$jar" ]; then
            CLASSPATH="$CLASSPATH:$jar"
        fi
    done
fi

# Run the migration tool
if [ "$VERBOSE" = true ]; then
    echo "Running configuration migration..."
    echo "Old config: $OLD_CONFIG"
    echo "New config: $NEW_CONFIG"
    echo "Classpath: $CLASSPATH"
    echo
fi

if [ "$DRY_RUN" = true ]; then
    echo "DRY RUN MODE - No files will be modified"
    echo
fi

# Execute the migration
java -cp "$CLASSPATH" org.opensearch.security.tools.ConfigMigrationTool "$OLD_CONFIG" "$NEW_CONFIG"

if [ $? -eq 0 ]; then
    echo
    echo "Migration completed successfully!"
    echo
    echo "IMPORTANT: Please review the new configuration before using it in production."
    echo "The new configuration has been written to: $NEW_CONFIG"
    echo
    echo "Next steps:"
    echo "1. Review the migrated configuration"
    echo "2. Test the configuration in a non-production environment"
    echo "3. Update your OpenSearch Security configuration"
    echo "4. Restart OpenSearch"
else
    echo
    echo "Migration failed. Please check the error messages above."
    exit 1
fi

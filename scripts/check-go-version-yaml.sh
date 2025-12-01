#!/bin/bash

# Define the exit status flag. 0 means success, 1 means one or more files failed the check.
EXIT_STATUS=0

# Helper function to check for a specific pattern (key) and its value in a YAML file.
# Arguments:
# 1: yamlfile - The path to the YAML file.
# 2: key_pattern - The regex pattern for the YAML key (e.g., 'go:', 'GO_VERSION:').
# 3: required_go_version - The Go version required by the user.
# 4: error_tag - A short identifier for the error message (e.g., 'go:', 'GO_VERSION:').
check_yaml_version_pattern() {
    local yamlfile="$1"
    local key_pattern="$2"
    local required_go_version="$3"
    local error_tag="$4"
    
    # Regex to capture the version number (e.g., 1.21, 1.21.0). 
    # It accounts for optional quotes around the version and leading/trailing spaces.
    local version_regex='([0-9]+\.[0-9]+(\.[0-9]+)?)'
    
    # The full pattern ensures we only match lines with the key and extract the version.
    # The 'g' flag for grep is necessary to treat the file as text and not ignore errors
    # if the file doesn't exist (though find should prevent this).
    # We use awk to be more robust than sed at handling different quoting styles.
    # This AWK command searches for the key, then strips quotes and trims whitespace from the value.
    local extracted_go_version=$(awk -v key="$key_pattern" \
        'BEGIN {IGNORECASE=1}
         $0 ~ key {
             # Replace the key (case-insensitive) and any following colon/spaces
             sub("[ \t]*" key "[ \t]*:?[ \t]*", "", $0);
             # Remove quotes (single or double) from the start/end
             gsub(/^["\x27]|["\x27]$/, "", $0);
             # Trim leading/trailing whitespace again
             gsub(/^[ \t]|[ \t]$/, "", $0);
             print $0;
             exit
         }' "$yamlfile"
    )

    # Check if a version was extracted and if it matches the required version.
    if [[ -n "$extracted_go_version" ]]; then
        if [[ "$extracted_go_version" != "$required_go_version" ]]; then
            echo "Error finding pattern '$error_tag': $yamlfile specifies Go version '$extracted_go_version', but required version is '$required_go_version'."
            EXIT_STATUS=1
        else
            # Optional: provide successful output for visibility
            echo "Success: $yamlfile matches required version '$required_go_version' for $error_tag."
        fi
    fi
    # If no version is found, we assume the pattern is not used in that file and do nothing (no error).
}

# --- Main Execution ---

# Check if the target Go version argument is provided.
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_go_version>"
    exit 1
fi

target_go_version="$1"

echo "Checking all YAML files for required Go version: $target_go_version..."
echo "--------------------------------------------------------"

# Use 'find' piped into 'while read' loop for safe handling of filenames with spaces/special characters.
# The -print0 and -0 combination ensures null-separated output/input.
find . -type f \( -name "*.yaml" -o -name "*.yml" \) -print0 | while IFS= read -r -d $'\0' file; do
    # 1. Check for the standard 'go:' field (e.g., in gitlab-ci, CircleCI config)
    check_yaml_version_pattern "$file" "go" "$target_go_version" "go:"
    
    # 2. Check for the environment variable 'GO_VERSION:' field
    check_yaml_version_pattern "$file" "GO_VERSION" "$target_go_version" "GO_VERSION:"
done

echo "--------------------------------------------------------"

# Check the final exit status flag.
if [ "$EXIT_STATUS" -eq 0 ]; then
    echo "All YAML files pass the Go version check for Go version $target_go_version. ✅"
else
    echo "One or more YAML files failed the Go version check. Please review the errors above. ❌"
fi

exit "$EXIT_STATUS"

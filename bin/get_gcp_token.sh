#!/bin/bash
set -xeo pipefail

HOST_ID="$1"
ACCOUNT="$2"
BASE_URL="http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
OUTPUT_DIR="gcp"

# Check if account, hostId, and output file are provided
if [[ -z "$ACCOUNT" || -z "$HOST_ID" || -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 <account> <hostId> <outputFile>"
  exit 1
fi
[[ -d "$OUTPUT_DIR" ]] && rm -rf $OUTPUT_DIR 2>/dev/null
mkdir $OUTPUT_DIR

# Build audience parameter
AUDIENCE="conjur/$ACCOUNT/$HOST_ID"

# Make the request to the metadata server
TOKEN=$(curl -s -X GET "$BASE_URL?audience=$AUDIENCE&format=full" -H "Metadata-Flavor: Google")

# Check if the request was successful
if [[ $? -ne 0 || -z "$TOKEN" ]]; then
  echo "Failed to fetch the token."
  exit 1
fi

# Store the token in the output file
echo "$TOKEN" > "$OUTPUT_DIR/token"
echo "Token saved to $OUTPUT_DIR/token"

# GET PROJECT ID
GCP_PROJECT=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id")
echo "$GCP_PROJECT" > "$OUTPUT_DIR/project-id"
echo "Project ID saved to $OUTPUT_DIR/project-id"
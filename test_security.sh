#!/bin/bash

BASE_URL="http://127.0.0.1:3000"

echo "=== Testing CPR Security Flow ==="
echo ""
echo "Testing that CPR submission requires authentication..."
echo ""

# Get CSRF token
CSRF_TOKEN=$(curl -s "$BASE_URL/api/csrf-token" | jq -r '.csrf_token')

# Try to submit CPR without JWT token
RESULT=$(curl -s -w "\nHTTP:%{http_code}" -X POST "$BASE_URL/api/account/cpr" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{"account_id":"testaccount1234","cpr":"010190-1234"}')

HTTP_CODE=$(echo "$RESULT" | grep "HTTP:" | cut -d: -f2)
BODY=$(echo "$RESULT" | grep -v "HTTP:")

echo "Scenario: Submit CPR without JWT token"
echo "Expected: HTTP 401 Unauthorized"
echo "Got: HTTP $HTTP_CODE"
echo "Response: $BODY"
echo ""

if [ "$HTTP_CODE" = "401" ]; then
  echo "✓ SUCCESS: CPR endpoint correctly requires authentication"
else
  echo "✗ FAILED: CPR endpoint should require authentication"
fi


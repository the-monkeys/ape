#!/bin/bash

# A.P.E. Test Script
# This script demonstrates how to use the A.P.E. API

BASE_URL="http://localhost:8080/v1"

echo "🦍 A.P.E. API Test Script"
echo "=========================="

# Step 1: Health check
echo "1. Health check..."
curl -s "$BASE_URL/health" | jq .
echo ""

# Step 2: Create an AppRole (this needs to be done first by an admin)
echo "2. Creating AppRole..."
ROLE_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/approle/role/test-app" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Test application role",
    "policies": ["read-secrets", "write-secrets"]
  }')

echo "AppRole created: $ROLE_RESPONSE"
ROLE_ID=$(echo $ROLE_RESPONSE | jq -r '.data.role_id')
SECRET_ID=$(echo $ROLE_RESPONSE | jq -r '.data.secret_id')
echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"
echo ""

# Step 3: Authenticate with AppRole
echo "3. Authenticating with AppRole..."
AUTH_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/approle/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"role_id\": \"$ROLE_ID\",
    \"secret_id\": \"$SECRET_ID\"
  }")

echo "Auth response: $AUTH_RESPONSE"
TOKEN=$(echo $AUTH_RESPONSE | jq -r '.auth.client_token')
echo "Token: $TOKEN"
echo ""

# Step 4: Create a secret
echo "4. Creating a secret..."
curl -s -X POST "$BASE_URL/secret/data/myapp/database" \
  -H "Content-Type: application/json" \
  -H "X-Ape-Token: $TOKEN" \
  -d '{
    "data": {
      "username": "myapp_user",
      "password": "super-secret-password",
      "host": "db.example.com",
      "port": 5432
    }
  }' | jq .
echo ""

# Step 5: Retrieve the secret
echo "5. Retrieving the secret..."
curl -s -X GET "$BASE_URL/secret/data/myapp/database" \
  -H "X-Ape-Token: $TOKEN" | jq .
echo ""

# Step 6: List secrets
echo "6. Listing secrets..."
curl -s -X GET "$BASE_URL/secret/metadata?path=myapp" \
  -H "X-Ape-Token: $TOKEN" | jq .
echo ""

echo "✅ Test completed successfully!"

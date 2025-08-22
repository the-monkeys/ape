#!/bin/bash

# Script to test A.P.E. API Documentation
# This script demonstrates how to access the API documentation

echo "🐒 A.P.E. API Documentation Test Script"
echo "========================================"

# Check if server is running
SERVER_URL="http://localhost:8080"

echo ""
echo "📋 Available Documentation Endpoints:"
echo "  Main Documentation:     $SERVER_URL/docs"
echo "  Interactive Swagger UI: $SERVER_URL/docs/swagger"
echo "  OpenAPI JSON Spec:      $SERVER_URL/docs/openapi.json"
echo "  Health Check:           $SERVER_URL/health"
echo ""

# Function to check if server is responding
check_server() {
    if curl -s "$SERVER_URL/health" > /dev/null 2>&1; then
        echo "✅ Server is running at $SERVER_URL"
        return 0
    else
        echo "❌ Server is not responding at $SERVER_URL"
        echo "   Please start the server first with: go run main.go"
        return 1
    fi
}

# Function to open documentation in browser
open_docs() {
    echo ""
    echo "🌐 Opening API documentation in your browser..."
    
    # Detect OS and open browser accordingly
    case "$(uname -s)" in
        Darwin)  # macOS
            open "$SERVER_URL/docs"
            ;;
        Linux)   # Linux
            if command -v xdg-open > /dev/null; then
                xdg-open "$SERVER_URL/docs"
            else
                echo "Please open $SERVER_URL/docs in your browser"
            fi
            ;;
        CYGWIN*|MINGW32*|MSYS*|MINGW*)  # Windows
            start "$SERVER_URL/docs"
            ;;
        *)
            echo "Please open $SERVER_URL/docs in your browser"
            ;;
    esac
}

# Function to demonstrate API calls
demo_api_calls() {
    echo ""
    echo "🔧 API Examples:"
    echo ""
    
    echo "1. Health Check:"
    echo "   curl $SERVER_URL/health"
    echo ""
    
    echo "2. Get OpenAPI Specification:"
    echo "   curl $SERVER_URL/docs/openapi.json"
    echo ""
    
    echo "3. Create AppRole (requires admin token):"
    echo '   curl -X POST '$SERVER_URL'/auth/approle \'
    echo '     -H "Content-Type: application/json" \'
    echo '     -H "Authorization: Bearer <admin-token>" \'
    echo '     -d '"'"'{'
    echo '       "role_name": "my-app",'
    echo '       "policies": ["read-secrets"],'
    echo '       "token_ttl": 3600'
    echo '     }'"'"
    echo ""
    
    echo "4. Login with AppRole:"
    echo '   curl -X POST '$SERVER_URL'/auth/login \'
    echo '     -H "Content-Type: application/json" \'
    echo '     -d '"'"'{'
    echo '       "role_id": "your-role-id",'
    echo '       "secret_id": "your-secret-id"'
    echo '     }'"'"
    echo ""
}

# Main execution
if check_server; then
    echo ""
    echo "Select an option:"
    echo "  1) Open documentation in browser"
    echo "  2) Show API examples"
    echo "  3) Test health endpoint"
    echo "  4) Get OpenAPI spec"
    echo "  q) Quit"
    echo ""
    
    while true; do
        read -p "Enter your choice (1-4, q): " choice
        case $choice in
            1)
                open_docs
                break
                ;;
            2)
                demo_api_calls
                break
                ;;
            3)
                echo ""
                echo "🏥 Testing health endpoint..."
                curl -s "$SERVER_URL/health" | python3 -m json.tool 2>/dev/null || curl -s "$SERVER_URL/health"
                echo ""
                break
                ;;
            4)
                echo ""
                echo "📄 Fetching OpenAPI specification..."
                curl -s "$SERVER_URL/docs/openapi.json" | python3 -m json.tool 2>/dev/null || curl -s "$SERVER_URL/docs/openapi.json"
                echo ""
                break
                ;;
            q|Q)
                echo "Goodbye! 🐒"
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
else
    echo ""
    echo "💡 To start the server:"
    echo "   go run main.go"
    echo ""
    echo "💡 To access documentation once server is running:"
    echo "   Open http://localhost:8080/docs in your browser"
fi

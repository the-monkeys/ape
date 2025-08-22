# A.P.E. API Documentation Test Script for Windows PowerShell
# This script demonstrates how to access the API documentation

Write-Host "🐒 A.P.E. API Documentation Test Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Server configuration
$ServerUrl = "http://localhost:8080"

Write-Host ""
Write-Host "📋 Available Documentation Endpoints:" -ForegroundColor Yellow
Write-Host "  Main Documentation:     $ServerUrl/docs" -ForegroundColor White
Write-Host "  Interactive Swagger UI: $ServerUrl/docs/swagger" -ForegroundColor White
Write-Host "  OpenAPI JSON Spec:      $ServerUrl/docs/openapi.json" -ForegroundColor White
Write-Host "  Health Check:           $ServerUrl/health" -ForegroundColor White
Write-Host ""

# Function to check if server is responding
function Test-ServerHealth {
    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/health" -Method Get -TimeoutSec 5
        Write-Host "✅ Server is running at $ServerUrl" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "❌ Server is not responding at $ServerUrl" -ForegroundColor Red
        Write-Host "   Please start the server first with: go run main.go" -ForegroundColor Yellow
        return $false
    }
}

# Function to open documentation in browser
function Open-Documentation {
    Write-Host ""
    Write-Host "🌐 Opening API documentation in your browser..." -ForegroundColor Green
    Start-Process "$ServerUrl/docs"
}

# Function to demonstrate API calls
function Show-APIExamples {
    Write-Host ""
    Write-Host "🔧 API Examples:" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "1. Health Check:" -ForegroundColor Cyan
    Write-Host "   Invoke-RestMethod -Uri $ServerUrl/health -Method Get" -ForegroundColor White
    Write-Host ""
    
    Write-Host "2. Get OpenAPI Specification:" -ForegroundColor Cyan
    Write-Host "   Invoke-RestMethod -Uri $ServerUrl/docs/openapi.json -Method Get" -ForegroundColor White
    Write-Host ""
    
    Write-Host "3. Create AppRole (requires admin token):" -ForegroundColor Cyan
    Write-Host @"
   `$headers = @{
       'Content-Type' = 'application/json'
       'Authorization' = 'Bearer <admin-token>'
   }
   `$body = @{
       role_name = 'my-app'
       policies = @('read-secrets')
       token_ttl = 3600
   } | ConvertTo-Json
   Invoke-RestMethod -Uri $ServerUrl/auth/approle -Method Post -Headers `$headers -Body `$body
"@ -ForegroundColor White
    Write-Host ""
    
    Write-Host "4. Login with AppRole:" -ForegroundColor Cyan
    Write-Host @"
   `$body = @{
       role_id = 'your-role-id'
       secret_id = 'your-secret-id'
   } | ConvertTo-Json
   Invoke-RestMethod -Uri $ServerUrl/auth/login -Method Post -Headers @{'Content-Type'='application/json'} -Body `$body
"@ -ForegroundColor White
    Write-Host ""
}

# Function to test health endpoint
function Test-HealthEndpoint {
    Write-Host ""
    Write-Host "🏥 Testing health endpoint..." -ForegroundColor Green
    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/health" -Method Get
        $response | ConvertTo-Json -Depth 3
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# Function to get OpenAPI spec
function Get-OpenAPISpec {
    Write-Host ""
    Write-Host "📄 Fetching OpenAPI specification..." -ForegroundColor Green
    try {
        $response = Invoke-RestMethod -Uri "$ServerUrl/docs/openapi.json" -Method Get
        $response | ConvertTo-Json -Depth 10
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# Main execution
if (Test-ServerHealth) {
    Write-Host ""
    Write-Host "Select an option:" -ForegroundColor Yellow
    Write-Host "  1) Open documentation in browser" -ForegroundColor White
    Write-Host "  2) Show API examples" -ForegroundColor White
    Write-Host "  3) Test health endpoint" -ForegroundColor White
    Write-Host "  4) Get OpenAPI spec" -ForegroundColor White
    Write-Host "  q) Quit" -ForegroundColor White
    Write-Host ""
    
    do {
        $choice = Read-Host "Enter your choice (1-4, q)"
        switch ($choice.ToLower()) {
            "1" {
                Open-Documentation
                break
            }
            "2" {
                Show-APIExamples
                break
            }
            "3" {
                Test-HealthEndpoint
                break
            }
            "4" {
                Get-OpenAPISpec
                break
            }
            "q" {
                Write-Host "Goodbye! 🐒" -ForegroundColor Cyan
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
            }
        }
    } while ($choice.ToLower() -notin @("1", "2", "3", "4", "q"))
}
else {
    Write-Host ""
    Write-Host "💡 To start the server:" -ForegroundColor Yellow
    Write-Host "   go run main.go" -ForegroundColor White
    Write-Host ""
    Write-Host "💡 To access documentation once server is running:" -ForegroundColor Yellow
    Write-Host "   Open http://localhost:8080/docs in your browser" -ForegroundColor White
}

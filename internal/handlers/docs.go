package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// ServeOpenAPISpec serves the OpenAPI specification as JSON
func (h *Handler) ServeOpenAPISpec(c *gin.Context) {
	// Get the current working directory
	wd, err := os.Getwd()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get working directory"})
		return
	}

	// Construct the path to the OpenAPI spec file
	specPath := filepath.Join(wd, "api", "openapi.yaml")

	// Read the OpenAPI spec file
	data, err := os.ReadFile(specPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read OpenAPI specification"})
		return
	}

	// Parse YAML and convert to JSON
	var spec interface{}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to parse OpenAPI specification",
			"details": err.Error(),
		})
		return
	}

	// Update server URL dynamically
	if specMap, ok := spec.(map[string]interface{}); ok {
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		currentServerURL := scheme + "://" + c.Request.Host

		specMap["servers"] = []map[string]string{
			{
				"url":         currentServerURL,
				"description": "Current server",
			},
		}
	}

	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, spec)
}

// ServeSwaggerUI serves the Swagger UI interface
func (h *Handler) ServeSwaggerUI(c *gin.Context) {
	specURL := "http://" + c.Request.Host + "/docs/openapi.json"

	html := `<!DOCTYPE html>
<html>
<head>
    <title>A.P.E. API</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui.css" />
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '` + specURL + `',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.presets.standalone]
        });
    </script>
</body>
</html>`

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

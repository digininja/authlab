package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Index(c *gin.Context) {
	// The second parameter is template name from /templates directory
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "Authentication Lab",
	})
}

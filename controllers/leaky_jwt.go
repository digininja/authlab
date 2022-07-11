package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Leaky_JWT_Login(c *gin.Context) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZXZlbCI6ImFkbWluIiwicGFzc3dvcmQiOiIyYWM5Y2I3ZGMwMmIzYzAwODNlYjcwODk4ZTU0OWI2MyIsInVzZXJuYW1lIjoiam9lIn0.6j3NrK-0C7K8gmaWeB9CCyZuQKfvVEAl4KhitRN2p5k"

	username := c.PostForm("username")
	password := c.PostForm("password")
	success := false

	if username == "joe" && password == "Password1" {
		success = true
	}

	c.HTML(http.StatusOK, "leaky_jwt.html", gin.H{
		"title":       "Leaky JWT",
		"tokenString": tokenString,
		"username":    username,
		"success":     success,
		"post":        true,
	})
}

func Leaky_JWT(c *gin.Context) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZXZlbCI6ImFkbWluIiwicGFzc3dvcmQiOiIyYWM5Y2I3ZGMwMmIzYzAwODNlYjcwODk4ZTU0OWI2MyIsInVzZXJuYW1lIjoiam9lIn0.6j3NrK-0C7K8gmaWeB9CCyZuQKfvVEAl4KhitRN2p5k"

	//var username string = c.Params.Form["username"][0]
	username := ""
	c.HTML(http.StatusOK, "leaky_jwt.html", gin.H{
		"content":     "This is an about page...",
		"tokenString": tokenString,
		"title":       "Leaky JWT",
		"username":    username,
		"post":        false,
	})
}

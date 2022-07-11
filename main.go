package main

import (
	"github.com/digininja/authlabgin/controllers"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.Static("/public", "./public")
	router.LoadHTMLGlob("templates/*.html")

	router.GET("/", controllers.Index)

	router.GET("/Leaky_JWT", controllers.Leaky_JWT)
	router.POST("/Leaky_JWT", controllers.Leaky_JWT_Login)

	router.Run(":9000")
}

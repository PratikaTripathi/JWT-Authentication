package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/pratika/jwt-authentication/controllers"
	"github.com/pratika/jwt-authentication/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:user_Id", controllers.GetUser())
}
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/pratika/jwt-authentication/controllers"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("users/signup", controllers.SignUp())
	incomingRoutes.POST("user/login", controllers.Login())
}

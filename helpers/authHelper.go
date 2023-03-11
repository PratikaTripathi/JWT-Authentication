package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func MatchUserTypeToUid(ctx *gin.Context , userId string) (err error){
	userType := ctx.GetString("user_type")
	uid:= ctx.GetString("uid")
	err=nil
	if userType=="USER" && uid!=userId {
		err = errors.New("unauthorised to access this document")
		return err
	}
	err = CheckUserType(ctx,userType)
	return err
}

func CheckUserType(ctx *gin.Context , role string) (err error){
	userType := ctx.GetString("user_type")
	err=nil
	if userType!=role {
		err=errors.New("unauthorised to access this document")
	}
	return err
}
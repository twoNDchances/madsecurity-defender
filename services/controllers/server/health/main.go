package health

import (
	"madsecurity-defender/services/controllers/server/complete"

	"github.com/gin-gonic/gin"
)

func Health(context *gin.Context) {
	complete.OK(context, "connected", nil)
}

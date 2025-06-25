package sync

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/complete"

	"github.com/gin-gonic/gin"
)

func Sync(context *gin.Context) {
	complete.OK(
		context,
		"synced",
		gin.H{
			"groups": globals.Groups,
			"rules": globals.Rules,
			"targets": globals.Targets,
			"wordlists": globals.Wordlists,
			// "words": globals.Words,
			"counter": gin.H{
				"groups": len(globals.Groups),
				"rules": len(globals.Rules),
				"targets": len(globals.Targets),
				"wordlists": len(globals.Wordlists),
				"words": len(globals.Words),
			},
		},
	)
}

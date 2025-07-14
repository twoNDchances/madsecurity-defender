package info

import (
	"fmt"
	"madsecurity-defender/utils"

	"github.com/common-nighthawk/go-figure"
)

type Banner struct {
	ProjectName string
	AppName     string
	AppVersion  string
	GoVersion   string
	GinVersion  string
	Author      string
}

func (b *Banner) Print() {
	figure.NewColorFigure(b.AppName, "larry3d", "purple", true).Print()
	figure.NewColorFigure(b.ProjectName, "slant", "blue", true).Print()
	fmt.Printf(utils.NewColor(`
Version: %s
Go     : %s
Gin    : %s
Author : %s
`, utils.GREEN),
		b.AppVersion, b.GoVersion, b.GinVersion, b.Author,
	)
}

func NewBanner() *Banner {
	banner := Banner{
		ProjectName: projectName,
		AppName:     appName,
		AppVersion:  appVersion,
		GoVersion:   goVersion,
		GinVersion:  ginVersion,
		Author:      author,
	}
	return &banner
}

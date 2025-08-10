package globals

import (
	"fmt"
	"madsecurity-defender/utils"
	"net/url"
	"slices"
	"strings"
)

var schemeSupported = ListString{
	"http",
}

type Backend struct {
	Scheme string
	Host   string
	Port   int
	Path   string
}

func (b *Backend) Validate() ListError {
	if errors := Validate(
		b.validateScheme(),
		b.validateHost(),
		b.validatePort(),
		b.validatePath(),
		b.validateUrl(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (b *Backend) validateScheme() error {
	if !slices.Contains(schemeSupported, b.Scheme) {
		return utils.NewProxyError("Backend.Scheme", "Only support ['http']")
	}
	return nil
}

func (b *Backend) validateHost() error {
	if b.Host == "0.0.0.0" || len(b.Host) == 0 {
		return utils.NewProxyError("Backend.Host", "Must specific an valid host")
	}
	return nil
}

func (b *Backend) validatePort() error {
	if b.Port <= 0 || b.Port >= 100000 {
		return utils.NewProxyError("Backend.Port", "Must in range 1 -> 99999")
	}
	return nil
}

func (b *Backend) validatePath() error {
	if len(b.Path) > 0 && !strings.HasPrefix(b.Path, "/") {
		return utils.NewProxyError("Backend.Path", "Must start with /")
	}
	return nil
}

func (b *Backend) BuildUrl() string {
	return fmt.Sprintf("%s://%s:%d%s", b.Scheme, b.Host, b.Port, b.Path)
}

func (b *Backend) validateUrl() error {
	_, err := url.Parse(b.BuildUrl())
	if err != nil {
		return utils.NewProxyError("Backend", err.Error())
	}
	return nil
}

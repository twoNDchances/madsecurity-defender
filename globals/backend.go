package globals

// import (
// 	"madsecurity-defender/utils"
// 	"slices"
// )

// var schemeSupported = ListString{
// 	"http",
// }

// type Backend struct {
// 	Scheme string
// 	Host   string
// 	Port   uint32
// 	Path   string
// }

// func (b *Backend) Validate() ListError {
// 	errors := make(ListError, 0)
// 	if err := b.validateScheme(); err != nil {
// 		errors = append(errors, err)
// 	}
// 	if err := b.validatePort(); err != nil {
// 		errors = append(errors, err)
// 	}
// 	if len(errors) > 0 {
// 		return errors
// 	}
// 	return nil
// }

// func (b *Backend) validateScheme() error {
// 	if !slices.Contains(schemeSupported, b.Scheme) {
// 		return utils.NewProxyError("Backend.Scheme", "Only support ['http']")
// 	}
// 	return nil
// }

// func (b *Backend) validatePort() error {
// 	if b.Port <= 0 || b.Port >= ^uint32(0) {
// 		return utils.NewProxyError("Backend.Port", "Must in range 1 -> 4294967295")
// 	}
// 	return nil
// }

// func (b *Backend) validatePath() {
	
// }

package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
)

var supportedMethods = []string{
	"post",
	"put",
	"patch",
	"delete",
}

type httpRequest struct {
	method string
	url    string
	body   map[string]interface{}
}

func (h *httpRequest) validate() error {
	errs := make([]error, 0)
	if err := h.validateMethod(); err != nil {
		errs = append(errs, err)
	}
	if err := h.validateUrl(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (h *httpRequest) validateMethod() error {
	if !slices.Contains(supportedMethods, h.method) {
		msg := "must in 'post', 'put', 'patch', 'delete'"
		return errors.New(msg)
	}
	return nil
}

func (h *httpRequest) validateUrl() error {
	if _, err := url.Parse(h.url); err != nil {
		return err
	}
	return nil
}

func NewHttp(method, url string, body map[string]interface{}) (*httpRequest, error) {
	http := httpRequest{
		method: method,
		url:    url,
		body:   body,
	}
	if err := http.validate(); err != nil {
		return nil, err
	}
	return &http, nil
}

func (h *httpRequest) Send() (*http.Response, error) {
	jsonData, err := json.Marshal(h.body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(h.methodUpper(), h.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	return client.Do(req)
}

func (h *httpRequest) methodUpper() string {
	switch h.method {
	case "post":
		return http.MethodPost
	case "put":
		return http.MethodPut
	case "patch":
		return http.MethodPatch
	case "delete":
		return http.MethodDelete
	default:
		return h.method
	}
}

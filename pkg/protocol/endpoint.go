package protocol

import (
	"errors"
	"strings"
)

var ErrNilEndpoint = errors.New("nil endpoint")

type Endpoint struct {
	path string
	url  string
}

func NewEndpoint(path string) *Endpoint {
	return &Endpoint{path: path}
}

func NewEndpointWithURL(path, url string) *Endpoint {
	return &Endpoint{path: path, url: url}
}

func (e *Endpoint) Relative() string {
	if e == nil {
		return ""
	}
	return "/" + strings.TrimPrefix(e.path, "/")
}

func (e *Endpoint) Absolute(host string) string {
	if e == nil {
		return ""
	}
	if e.url != "" {
		return e.url
	}
	return strings.TrimSuffix(host, "/") + e.Relative()
}

func (e *Endpoint) Validate() error {
	if e == nil {
		return ErrNilEndpoint
	}
	return nil
}

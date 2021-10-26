// Package private provides primitives to interact the openapi HTTP API.
//
// Code generated by github.com/algorand/oapi-codegen DO NOT EDIT.
package private

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"github.com/algorand/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Aborts a catchpoint catchup.
	// (DELETE /v2/catchup/{catchpoint})
	AbortCatchup(ctx echo.Context, catchpoint string) error
	// Starts a catchpoint catchup.
	// (POST /v2/catchup/{catchpoint})
	StartCatchup(ctx echo.Context, catchpoint string) error

	// (POST /v2/register-participation-keys/{address})
	RegisterParticipationKeys(ctx echo.Context, address string, params RegisterParticipationKeysParams) error

	// (POST /v2/shutdown)
	ShutdownNode(ctx echo.Context, params ShutdownNodeParams) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// AbortCatchup converts echo context to params.
func (w *ServerInterfaceWrapper) AbortCatchup(ctx echo.Context) error {

	validQueryParams := map[string]bool{
		"pretty": true,
	}

	// Check for unknown query parameters.
	for name, _ := range ctx.QueryParams() {
		if _, ok := validQueryParams[name]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unknown parameter detected: %s", name))
		}
	}

	var err error
	// ------------- Path parameter "catchpoint" -------------
	var catchpoint string

	err = runtime.BindStyledParameter("simple", false, "catchpoint", ctx.Param("catchpoint"), &catchpoint)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter catchpoint: %s", err))
	}

	ctx.Set("api_key.Scopes", []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.AbortCatchup(ctx, catchpoint)
	return err
}

// StartCatchup converts echo context to params.
func (w *ServerInterfaceWrapper) StartCatchup(ctx echo.Context) error {

	validQueryParams := map[string]bool{
		"pretty": true,
	}

	// Check for unknown query parameters.
	for name, _ := range ctx.QueryParams() {
		if _, ok := validQueryParams[name]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unknown parameter detected: %s", name))
		}
	}

	var err error
	// ------------- Path parameter "catchpoint" -------------
	var catchpoint string

	err = runtime.BindStyledParameter("simple", false, "catchpoint", ctx.Param("catchpoint"), &catchpoint)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter catchpoint: %s", err))
	}

	ctx.Set("api_key.Scopes", []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.StartCatchup(ctx, catchpoint)
	return err
}

// RegisterParticipationKeys converts echo context to params.
func (w *ServerInterfaceWrapper) RegisterParticipationKeys(ctx echo.Context) error {

	validQueryParams := map[string]bool{
		"pretty":           true,
		"fee":              true,
		"key-dilution":     true,
		"round-last-valid": true,
		"no-wait":          true,
	}

	// Check for unknown query parameters.
	for name, _ := range ctx.QueryParams() {
		if _, ok := validQueryParams[name]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unknown parameter detected: %s", name))
		}
	}

	var err error
	// ------------- Path parameter "address" -------------
	var address string

	err = runtime.BindStyledParameter("simple", false, "address", ctx.Param("address"), &address)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter address: %s", err))
	}

	ctx.Set("api_key.Scopes", []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params RegisterParticipationKeysParams
	// ------------- Optional query parameter "fee" -------------
	if paramValue := ctx.QueryParam("fee"); paramValue != "" {

	}

	err = runtime.BindQueryParameter("form", true, false, "fee", ctx.QueryParams(), &params.Fee)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter fee: %s", err))
	}

	// ------------- Optional query parameter "key-dilution" -------------
	if paramValue := ctx.QueryParam("key-dilution"); paramValue != "" {

	}

	err = runtime.BindQueryParameter("form", true, false, "key-dilution", ctx.QueryParams(), &params.KeyDilution)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter key-dilution: %s", err))
	}

	// ------------- Optional query parameter "round-last-valid" -------------
	if paramValue := ctx.QueryParam("round-last-valid"); paramValue != "" {

	}

	err = runtime.BindQueryParameter("form", true, false, "round-last-valid", ctx.QueryParams(), &params.RoundLastValid)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter round-last-valid: %s", err))
	}

	// ------------- Optional query parameter "no-wait" -------------
	if paramValue := ctx.QueryParam("no-wait"); paramValue != "" {

	}

	err = runtime.BindQueryParameter("form", true, false, "no-wait", ctx.QueryParams(), &params.NoWait)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter no-wait: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RegisterParticipationKeys(ctx, address, params)
	return err
}

// ShutdownNode converts echo context to params.
func (w *ServerInterfaceWrapper) ShutdownNode(ctx echo.Context) error {

	validQueryParams := map[string]bool{
		"pretty":  true,
		"timeout": true,
	}

	// Check for unknown query parameters.
	for name, _ := range ctx.QueryParams() {
		if _, ok := validQueryParams[name]; !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unknown parameter detected: %s", name))
		}
	}

	var err error

	ctx.Set("api_key.Scopes", []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params ShutdownNodeParams
	// ------------- Optional query parameter "timeout" -------------
	if paramValue := ctx.QueryParam("timeout"); paramValue != "" {

	}

	err = runtime.BindQueryParameter("form", true, false, "timeout", ctx.QueryParams(), &params.Timeout)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter timeout: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ShutdownNode(ctx, params)
	return err
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}, si ServerInterface, m ...echo.MiddlewareFunc) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.DELETE("/v2/catchup/:catchpoint", wrapper.AbortCatchup, m...)
	router.POST("/v2/catchup/:catchpoint", wrapper.StartCatchup, m...)
	router.POST("/v2/register-participation-keys/:address", wrapper.RegisterParticipationKeys, m...)
	router.POST("/v2/shutdown", wrapper.ShutdownNode, m...)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"nwAAAP//cW8RT+KQAAA=",
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file.
func GetSwagger() (*openapi3.Swagger, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	swagger, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error loading Swagger: %s", err)
	}
	return swagger, nil
}

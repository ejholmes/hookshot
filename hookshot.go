// Copyright 2014 Eric Holmes.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hookshot is a router that de-multiplexes and authorizes github webhooks.
package hookshot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	// HeaderEvent is the name of the header that contains the type of event.
	HeaderEvent = "X-GitHub-Event"

	// HeaderSignature is the name of the header that contains the signature.
	HeaderSignature = "X-Hub-Signature"
)

// Router demultiplexes github hooks.
type Router struct {
	// NotFoundHandler is called when a handler is not found for a given GitHub event.
	NotFoundHandler http.Handler

	// UnauthorizedHandler is called when the calculated signature does not match the
	// provided signature in the X-Hub-Signature header.
	UnauthorizedHandler http.Handler

	// SetHeader controls what happens when the X-Hub-Signature header value does
	// not match the calculated signature. Setting this value to true will set
	// the X-Calculated-Signature header in the response.
	//
	// It's recommended that you only enable this for debugging purposes.
	SetHeader bool

	routes routes
	secret string
}

// NewRouter returns a new Router.
func NewRouter(secret string) *Router {
	return &Router{
		routes: make(routes),
		secret: secret,
	}
}

// Handle maps a github event to an http.Handler.
func (r *Router) Handle(event string, h http.Handler) *Route {
	route := &Route{Secret: r.secret, event: event, handler: h}
	r.routes[event] = route
	return route
}

// HandleFunc maps a github event to an http.HandlerFunc.
func (r *Router) HandleFunc(event string, fn func(http.ResponseWriter, *http.Request)) *Route {
	return r.Handle(event, http.HandlerFunc(fn))
}

// ServeHTTP implements the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	event := req.Header.Get(HeaderEvent)

	route := r.routes[event]
	if route == nil {
		r.notFound(w, req)
		return
	}

	sig, ok := authorized(req, route.Secret)

	if r.SetHeader {
		w.Header().Set("X-Calculated-Signature", sig)
	}

	if !ok {
		r.unauthorized(w, req)
		return
	}

	route.ServeHTTP(w, req)
}

func (r *Router) notFound(w http.ResponseWriter, req *http.Request) {
	if r.NotFoundHandler == nil {
		r.NotFoundHandler = http.HandlerFunc(http.NotFound)
	}
	r.NotFoundHandler.ServeHTTP(w, req)
}

func (r *Router) unauthorized(w http.ResponseWriter, req *http.Request) {
	if r.UnauthorizedHandler == nil {
		r.UnauthorizedHandler = http.HandlerFunc(unauthorized)
	}
	r.UnauthorizedHandler.ServeHTTP(w, req)
}

// Route represents the http.Handler for a github event.
type Route struct {
	Secret string

	handler http.Handler
	event   string
}

// ServeHTTP implements the http.Handler interface.
func (r *Route) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

// routes maps a github event to a Route.
type routes map[string]*Route

// Signature calculates the SHA1 HMAC signature of body, signed by the secret.
//
// When github-services makes a POST request, it includes a SHA1 HMAC signature
// of the request body, signed with the secret provided in the webhook configuration.
// See http://goo.gl/Oe4WwR.
func Signature(body []byte, secret string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// authorized checks that the calculated signature for the request matches the provided signature in
// the request headers.
func authorized(r *http.Request, secret string) (string, bool) {
	raw, er := ioutil.ReadAll(r.Body)
	if er != nil {
		return "", false
	}

	// Since we're reading the request from the network, r.Body will return EOF if any
	// downstream http.Handler attempts to read it. We set it to a new io.ReadCloser
	// that will read from the bytes in memory.
	r.Body = ioutil.NopCloser(bytes.NewReader(raw))

	if len(r.Header[HeaderSignature]) == 0 {
		return "", true
	}

	sig := "sha1=" + Signature(raw, secret)

	return sig, r.Header.Get(HeaderSignature) == sig
}

// unauthorized is the default UnauthorizedHandler.
func unauthorized(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "The provided signature in the "+HeaderSignature+" header does not match.", 403)
}

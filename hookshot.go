package hookshot

import (
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
	NotFoundHandler     http.Handler
	UnauthorizedHandler http.Handler

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
func (rr *Router) Handle(event string, h http.Handler) {
	route := &route{event: event, handler: h, secret: rr.secret}
	rr.routes[event] = route
}

// ServeHTTP implements the http.Handler interface.
func (rr *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	event := r.Header.Get(HeaderEvent)

	route := rr.routes[event]
	if route == nil {
		rr.notFound(w, r)
		return
	}

	if !authorized(r, route.secret) {
		rr.unauthorized(w, r)
	}
}

func (rr *Router) notFound(w http.ResponseWriter, r *http.Request) {
	if rr.NotFoundHandler == nil {
		rr.NotFoundHandler = http.HandlerFunc(http.NotFound)
	}
	rr.NotFoundHandler.ServeHTTP(w, r)
}

func (rr *Router) unauthorized(w http.ResponseWriter, r *http.Request) {
	if rr.UnauthorizedHandler == nil {
		rr.UnauthorizedHandler = http.HandlerFunc(unauthorized)
	}
	rr.UnauthorizedHandler.ServeHTTP(w, r)
}

// route represents the http.Handler for a github event.
type route struct {
	secret  string
	event   string
	handler http.Handler
}

// routes maps a github event to a route.
type routes map[string]*route

// Signature calculates the SHA1 HMAC signature of in using the secret.
func Signature(in []byte, secret string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(in)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// authorized checks that the calculated signature for the request matches the provided signature in
// the request headers.
func authorized(r *http.Request, secret string) bool {
	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false
	}
	return r.Header.Get(HeaderSignature) == "sha1="+Signature(raw, secret)
}

// unauthorized is the default UnauthorizedHandler.
func unauthorized(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "The provided signature in the "+HeaderSignature+" header does not match.", 403)
}

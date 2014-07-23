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
func (r *Router) Handle(event string, h http.Handler) *Route {
	route := &Route{Event: event, Handler: h, Secret: r.secret}
	r.routes[event] = route
	return route
}

// ServeHTTP implements the http.Handler interface.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	event := req.Header.Get(HeaderEvent)

	route := r.routes[event]
	if route == nil {
		r.notFound(w, req)
		return
	}

	if !authorized(req, route.Secret) {
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
	Secret  string
	Event   string
	Handler http.Handler
}

// ServeHTTP implements the http.Handler interface.
func (r *Route) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.Handler.ServeHTTP(w, req)
}

// routes maps a github event to a Route.
type routes map[string]*Route

// Signature calculates the SHA1 HMAC signature of in using the secret.
func Signature(in []byte, secret string) string {
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(in)
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// authorized checks that the calculated signature for the request matches the provided signature in
// the request headers.
func authorized(r *http.Request, secret string) bool {
	raw, er := ioutil.ReadAll(r.Body)
	if er != nil {
		return false
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(raw))

	if len(r.Header[HeaderSignature]) == 0 {
		return true
	}

	return r.Header.Get(HeaderSignature) == "sha1="+Signature(raw, secret)
}

// unauthorized is the default UnauthorizedHandler.
func unauthorized(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "The provided signature in the "+HeaderSignature+" header does not match.", 403)
}

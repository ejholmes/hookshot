# [Hookshot](https://github.com/ejholmes/hookshot) [![Build Status](https://travis-ci.org/ejholmes/hookshot.svg?branch=master)](https://travis-ci.org/ejholmes/hookshot)

[Godoc](http://godoc.org/github.com/ejholmes/hookshot)

Hookshot is a Go http router that de-multiplexes and authorizes GitHub Webhooks.


## Usage

```go
r := hookshot.NewRouter()

r.Handle("deployment", DeploymentHandler)
r.Handle("deployment_status", DeploymentStatusHandler)
```

To automatically verify that the request came from GitHub using a secret:

```go
r := hookshot.NewRouterWithSecret("secret")
```

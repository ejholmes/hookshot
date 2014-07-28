# [Hookshot](https://github.com/tugbt/hookshot) [![Build Status](https://travis-ci.org/tugbt/hookshot.svg?branch=master)](https://travis-ci.org/tugbt/hookshot)

[Godoc](http://godoc.org/github.com/tugbt/hookshot)

Hookshot is a Go http router that de-multiplexes and authorizes GitHub Webhooks.


## Usage

```go
r := hookshot.NewRouter("secret")

r.Handle("deployment", DeploymentHandler)
r.Handle("deployment_status", DeploymentStatusHandler)
```

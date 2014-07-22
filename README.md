# [Hookshot](https://github.com/ejholmes/hookshot)

[Godoc](http://godoc.org/github.com/ejholmes/hookshot)

Hookshot is a Go http router that de-multiplexes and authorizes GitHub Webhooks.


## Usage

```go
r := hookshot.NewRouter("secret")

r.Handle("deployment", DeploymentHandler)
r.Handle("deployment_status", DeploymentStatusHandler)
```

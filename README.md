# [Hookshot](/)

Hookshot is a Go http router that de-multiplexes and authorizes GitHub Webhooks.


## Usage

```go
r := hookshot.NewRouter()

r.Handle("deployment", DeploymentHandler)
r.Handle("deployment_status", DeploymentStatusHandler)
```

Tetragon Process Execution Logger
=================================

A Kubernetes sidecar for logging (and filtering) Tetragon process execution events.

## Configuration

```yaml
rules:
  # This rule will log all process exec events in the default namespace
  # for containers named "nginx", excluding events from the nginx binary.
  - namespaces:
      - default
    containers:
      - nginx
    labels:
      app: webserver
    excludeBinaries:
      - /usr/sbin/nginx
```

# Daemon configuration

Platforms can set the maximum raw SPDM message size when starting the daemon:

```sh
spdmd --max-spdm-message-size 2047
```

The value is in bytes, excluding transport headers and trailers. It applies to
all discovered MCTP responders, including initialization retries and devices
added at runtime. The default is 4608 bytes, and valid values are 42 through
4608 inclusive. Invalid values are rejected before discovery starts.

Platform service configuration can supply this option in the daemon's
`ExecStart` command. Combine it with `--state-dir` if the platform also needs to
override the state directory.

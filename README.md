# spdm

`spdmd` is the OpenBMC daemon for SPDM attestation. It discovers SPDM responders
over MCTP and TCP and serves the attestation policy on D-Bus.

The design is [Redfish SPDM Attestation Support][design].

## To Build

```sh
meson setup build
ninja -C build
```

The unit tests can be run in the OpenBMC CI container, as described in
[local-ci-build.md][ci].

## Hosted Services

`service/spdmd.service` runs `/usr/libexec/spdm/spdmd` as
`xyz.openbmc_project.spdmd`. MCTP endpoints come from mctpd and TCP responders
from entity-manager `SpdmTcpResponder` configurations. The policy interface,
`xyz.openbmc_project.Control.Security.SPDM.Policy`, is saved to `policy.json` in
`<localstatedir>/lib/spdm`, or in the directory given with `--state-dir`.

[design]:
  https://github.com/openbmc/docs/blob/master/designs/redfish-spdm-attestation.md
[ci]: https://github.com/openbmc/docs/blob/master/testing/local-ci-build.md

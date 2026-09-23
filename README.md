# spdm

`spdmd` is the OpenBMC daemon for SPDM attestation. It discovers SPDM responders
over MCTP and TCP and serves the attestation policy on D-Bus. It does not run
the SPDM protocol itself; libspdm is not a dependency.

The design is [Redfish SPDM Attestation Support][design].

## To Build

```sh
meson setup build
meson compile -C build
```

The compiler is chosen when the build directory is created. GCC 13.3, the
default on Ubuntu 24.04, stops with an internal compiler error in
`requester/utils/mapper.cpp`. GCC 14.2 works, so on that system create the
directory with:

```sh
CC=gcc-14 CXX=g++-14 meson setup build
```

The sdbusplus code generator needs the Python packages `inflection`, `mako` and
`pyyaml` for setup, and `jsonschema` for the compile. meson looks for `python3`
on `PATH`, so activate the virtualenv instead of only running meson from it:

```sh
python3 -m venv ~/venv-spdm
. ~/venv-spdm/bin/activate
pip install meson ninja inflection mako pyyaml jsonschema
```

## To Run Tests

```sh
meson test -C build
```

`test_policy_manager` requests a service name on the system bus, which a normal
Linux desktop does not allow. Outside a BMC, give the tests a private bus:

```sh
dbus-run-session -- sh -c \
  'DBUS_SYSTEM_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS meson test -C build'
```

## To Run

`service/spdmd.service` runs `/usr/libexec/spdm/spdmd`, which takes the bus name
`xyz.openbmc_project.spdmd` after its first discovery pass. MCTP endpoints come
from mctpd and TCP responders from entity-manager `SpdmTcpResponder`
configurations. The policy interface,
`xyz.openbmc_project.Control.Security.SPDM.Policy`, is saved to `policy.json` in
`<localstatedir>/lib/spdm`, or in the directory given with `--state-dir`.

[design]:
  https://github.com/openbmc/docs/blob/master/designs/redfish-spdm-attestation.md

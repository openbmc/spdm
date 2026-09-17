# spdm

`spdmd` is the OpenBMC daemon for SPDM attestation of attached devices. It
discovers the SPDM-capable responders on a system and serves the attestation
policy that applies to them on D-Bus.

This README describes what the repository contains today. The daemon does not
itself speak SPDM: `libspdm` is not among its dependencies and no handshake is
performed. Its responsibilities at present are discovery and policy.

The Redfish-facing design it is being built towards is described in [Redfish
SPDM Attestation Support][design].

## What the daemon does at start-up

1. Creates an `sdbusplus` async context and an object manager under the
   `xyz.openbmc_project.Attestation.ComponentIntegrity` namespace path.
2. Constructs a `PolicyManager`, which serves
   `xyz.openbmc_project.Control.Security.SPDM.Policy` on that path and restores
   its properties from a JSON cache written by a previous run.
3. Starts transport discovery for MCTP and for TCP.
4. Requests the well-known name `xyz.openbmc_project.spdmd` only after the
   initial discovery has completed, so that a client which sees the name also
   sees a populated object tree.

## Transport discovery

`TransportType` in `requester/spdm_discovery.hpp` names three transports. Two of
them have a discovery implementation.

| Transport | Discovery | Responders are found by                                |
| --------- | --------- | ------------------------------------------------------ |
| MCTP      | yes       | `xyz.openbmc_project.MCTP.Endpoint` objects from mctpd |
| TCP       | yes       | `xyz.openbmc_project.Configuration.SpdmTcpResponder`   |
| PCIe DOE  | no        | `TransportType::PCIE_DOE` has no discovery class       |

**MCTP.** `MCTPTransportDiscovery` queries the object mapper for
`xyz.openbmc_project.MCTP.Endpoint` instances and keeps an endpoint only if its
`SupportedMessageTypes` contains `0x05`, the MCTP message type assigned to SPDM.
The endpoint ID is taken from that interface and the UUID, where the device
publishes one, from `xyz.openbmc_project.Common.UUID`. Runtime changes are
followed through `InterfacesAdded` and `InterfacesRemoved` under
`/au/com/codeconstruct/mctp1`, which is the tree mctpd publishes under.

**TCP.** `TCPTransportDiscovery` looks for
`xyz.openbmc_project.Configuration.SpdmTcpResponder` objects, that is, an
entity-manager configuration naming a `hostname` and a `port`, and follows
runtime changes under the `xyz.openbmc_project.Inventory.Item` namespace path.

Both discoveries arm their matches before reading the mapper snapshot, and
`SPDMDiscovery::add()` de-duplicates on object path, so an endpoint that appears
while enumeration is in progress is registered exactly once.

## D-Bus

|                  |                                                    |
| ---------------- | -------------------------------------------------- |
| Service name     | `xyz.openbmc_project.spdmd`                        |
| Object manager   | the `ComponentIntegrity` namespace path            |
| Policy interface | `xyz.openbmc_project.Control.Security.SPDM.Policy` |

The policy interface carries `Enabled`, `SecureSessionEnabled`,
`VerifyCertificate`, `AllowExtendedAlgorithms`, `AllowedVersions`,
`AllowedAlgorithmsAEAD`, `AllowedAlgorithmsBaseHash` and
`AllowedAlgorithmsBaseAsym`; the definitions are in phosphor-dbus-interfaces.
Writes are persisted immediately to `policy.json` in the state directory, which
defaults to `<localstatedir>/lib/spdm` and can be overridden at run time:

```sh
/usr/libexec/spdm/spdmd --state-dir /run/spdm
```

`service/spdmd.service` installs the daemon as a `Type=dbus` unit with
`Restart=always`.

## Code organization

| Path                                   | Contents                                                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `requester/spdmd.cpp`                  | `main()`: context, object manager, policy manager, both discoveries                                              |
| `requester/spdm_discovery.{hpp,cpp}`   | `SPDMDiscovery`, the registry of discovered responders, and the `DiscoveryType` concept a transport must satisfy |
| `requester/mctp_transport_discovery.*` | MCTP discovery and its runtime monitors                                                                          |
| `requester/tcp_transport_discovery.*`  | TCP discovery and its runtime monitors                                                                           |
| `requester/policy_manager.*`           | the Policy server and its JSON cache                                                                             |
| `requester/utils/mapper.*`             | object-mapper lookup by interface                                                                                |
| `requester/utils/paths.*`              | the state directory and the policy cache path                                                                    |
| `service/spdmd.service`                | systemd unit                                                                                                     |
| `tests/`                               | GTest unit tests                                                                                                 |

A new transport needs a class with a `discovery(SPDMDiscovery&)` coroutine and a
static `type()`, which is what the `spdm::details::DiscoveryType` concept
requires, plus a call to `SPDMDiscovery::discover()` in `main()`.

## Building

Dependencies are phosphor-dbus-interfaces, phosphor-logging, sdbusplus, systemd,
CLI11 and, for the tests, GTest. meson wraps are provided for the OpenBMC ones,
so a network-enabled `meson setup` will fetch what it does not find.

sdbusplus generates code during the build, and its generator needs three Python
modules that `meson setup` does not report together:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install meson ninja inflection mako pyyaml jsonschema
meson setup build
meson compile -C build
```

The virtual environment has to be _activated_ rather than called by path. meson
resolves the generator with `find_program('python3')`, which searches `PATH`, so
running `./.venv/bin/meson` while `.venv/bin` is not on `PATH` finds the system
interpreter and the generator fails on a missing module.

`jsonschema` is needed at compile time rather than at setup time, so a
`meson setup` that succeeded does not mean the modules are all present.

## Testing

```sh
meson test -C build
```

`tests/` holds three suites: `test_spdm_discovery`,
`test_mctp_transport_discovery` and `test_policy_manager`. Tests are built by
default and can be turned off with `-Dtests=disabled`.

[design]:
  https://github.com/openbmc/docs/blob/master/designs/redfish-spdm-attestation.md

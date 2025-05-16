# SPDM
  
This repository contains a D-Bus server that exposes D-Bus APIs to get attestation data and certificates from connected devices.
The daemon uses the SPDM protocol to securely retrieve attestation data from SPDM-capable devices.

## Key Features

- D-Bus interface for device attestation
- Secure communication via SPDM protocol
- Certificate retrieval from connected devices
- Collection of attestation data

## Build Instructions

To build the project, run the following commands:

```sh
1. meson build
2. ninja -C build

```

## Dependencies

- [sdbusplus](https://github.com/openbmc/sdbusplus)
- [phosphor-logging](https://github.com/openbmc/phosphor-logging)
- [phosphor-dbus-interfaces](https://github.com/openbmc/phosphor-dbus-interfaces)
- [boost](https://github.com/boostorg/boost)

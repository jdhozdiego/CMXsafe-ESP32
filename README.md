# CMXsafe: Secure Reverse Socket Proxy for ESP32

This project provides a loosely coupled, source code–independent proxy designed to secure local communications for tasks running on an ESP32 device. It is built on CMXsafe architecture principles, leverages `libssh` for operation, and is potentially portable to other architectures. Security features are provided through a modular approach that aligns with [SESIP methodology](https://globalplatform.org/sesip), facilitating composite secure certification and reusability of the components.

![Screenshot](images/chain-of-trust.svg)

#### Key Features

- **Secure Reverse Socket Proxying**: Facilitates encrypted and isolated communication channels between the ESP32-S3 and remote services using `libssh`. Each proxy operates independently, ensuring modularity and scalability.
- **Modular Security Contexts**: Implements a security module that enforces isolation policies. Only explicitly defined ports in `fw_ports.h` are accessible, minimizing the attack surface and ensuring that unauthorized communications are blocked by default.
- **Over-The-Air (OTA) Updates**: This mechanism enables secure firmware updates through a reverse proxy. It can be understood as a practical example where an existing insecure application, such as the OTAWebUpdater example from ArduinoIDE, is implemented securely into the firmware, allowing remote updates via a secure channel, ensuring integrity and authenticity.
- **Remote Attestation of Firmware Integrity**: This component utilizes the ESP32-S3's hardware HMAC module to perform challenge-response authentication. By storing a 256-bit key in an eFuse block (e.g., BLOCK_KEY3) with the purpose HMAC_UP, the system can generate HMACs that attest to the firmware's integrity without exposing the key to software.
- **Portability and Flexibility**: CMXsafe's loosely coupled architecture allows it to be adapted to other platforms beyond the ESP32-S3. Its modular design allows for easy integration and customization based on specific project requirements.

This project provides support for ESP32 microcontrollers with four components: 
- CMXsafe Client Socket Proxy
- CMXsafe Security Module
- OTA Module
- Remote Attestation Module

A device incorporating at least the CMXsafe Client Socket Proxy and Security module can easily be integrated into a full-fledged CMXsafe implementation. However, this is unnecessary for testing or small deployments requiring no CMX-GWs. IoT servers can be easily isolated and secured to manage local port allocation and adequately protect access to any remote proxies.
In full-fledged CMXsafe implementations, the device connects to a CMX-GW, where the allocation of the proxied ports is protected and defined in specific virtual IPv6 addresses. This avoid port overlapping and facilitates addressing local requests.

---

## CMXsafe Client Socket Proxy
This component offers security modules that initialize the proxies.

#### Required Includes

```cpp
#include "settings.h"
#include "cmxsafe.h"
#include "fw_ports.h"
```

#### Enabling in the `.ino` Project

Within the `setup()` function, include:

```cpp
xTaskCreatePinnedToCore(ssh_port_forwarding_task, "SSH Port Forwarding Task", 10500, &streamPort, 5, NULL, 1);
```

Each proxy requires a specific xTaskCreatePinnedToCore call, as they work independently. Likewise, each proxy (such as **`streamPort`** ) refers to the corresponding Security Context and must be described described in `fw_ports.h` as follows:

```cpp
TaskParameters streamPort = {
    .local_port = 81,
    .forward_remote_port = 81,
    .high_bw = true,
};
```
-	`local_port`: stands for the port to be proxied.
-	`Forward_remote_port`: stands for the port where the service is being proxied in the remote machine
-	`high_bw`: refers to an experimental parameter to increase buffer sizes the buffers to increase bandwidth. Not used at the moment.

The security contexts are not enabled (enforced) unless the security module is also enabled. The security module provides isolation, which is not strictly required for the proxies to operate but is instrumental in guaranteeing isolation, particularly from external devices.

## CMXsafe Security Module (Isolation & Security Contexts)

This component allows enabling security contexts and isolation as described in  `fw_ports.h` . It is enabled in the main `.ino` project after initialization of CMXsafe by including the following.

#### Required Includes

```cpp
#include "sm.h"
```

#### Enabling in the `.ino` Project

Within the `setup()` function, include:

```cpp
setup_sm();
```

After calling `setup_sm()`, any communication apart from the main SSH connection is not allowed from/to the device, and internal communications to open ports are not allowed unless specified in `fw_ports.h` and enabled through a proxy.

## Over The Air Update (OTA)

This component allows remote firmware upgrading. It is based on the default example application available in ArduinoIDE for the ESP32 [file->examples->ArduinoOTA->OTAWebUpdater](https://forum.arduino.cc/t/otawebupdate-esp32/675499). This OTA example is enabled and secured in the main application by including the following:

#### Required Includes

```cpp
#include "ota.h"
```

#### Enabling in the `.ino` Project

Within the `setup()` function, include:

```cpp
xTaskCreatePinnedToCore(setup_ota, "setup ota", 16384, NULL, 0, NULL, 1);
xTaskCreatePinnedToCore(ssh_port_forwarding_task, "SSH Port Forwarding Task3", 10500, &otaPort, 5, NULL, 1);
```

Where otaPort is the reverse socket proxy defined in `fw_ports.h` as follows:

```cpp
TaskParameters otaPort = {
    .local_port = 8989,
    .forward_remote_port = 8989, //on the client computer
    .high_bw = false,
};
```
The above configuration sets the local port 8989 in the ESP32 for OTA and also sets the local port 8989 in the remote server for reverse socket proxying. Once the proxy is set, from the server, it is possible to remotely upgrade the firmware of the device as follows (according to example configurations), where firmware.bin is the new firmware to update:

```sh
curl -X POST -F "update=@firmware.bin" http://127.0.0.1:8989/update
```

## Remote attestation of firmware integrity and device identity

This application allows remote attestation of identity and firmware integrity. This process relies on hardware features of the microcontroller. Specifically, built-in SHA-256 hash function that uses an internal [secure HASH key](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/peripherals/hmac.html). The characteristics of this key are as follows
- It is a 32-byte (256-bit) secure key stored on an e-fused on-chip ROM block that is writable only once.
- It can be configured for [specific purposes](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/espefuse/burn-key-cmd.html), including protection from being read from any program directly and only being used by hardware-built-in cryptographic functions
In order to use this remote attestation functionality, it is required to configure a memory block with a HASH key (random secret) to make use of the hash function securely. To achieve this, it is necessary to set up the ESPRESSIF [esptool](https://docs.espressif.com/projects/esptool/en/latest/esp32/installation.html). Then, we create a HASH key and burn it on the microcontroller as follows:

```sh
openssl rand -out private_key.bin 32
espefuse.py --port /dev/ttyACM0 burn_key BLOCK_KEY3 private_key.bin HMAC_UP
```
- `/dev/ttyACM0` is the device descriptor of the (virtual) serial port used to connect your microcontroller to the computer.
- `BLOCK_KEY3` [corresponds to `EFUSE_BLK7`](https://docs.espressif.com/projects/esp-idf/en/v5.1.6/esp32s3/esp-idf-en-v5.1.6-esp32s3.pdf) and can be used to [store an HMAC key](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/efuse.html)
- `HMAC_UP` specifies that the key will be used for HASH purposes by built-in HASH methods invoked by an application. The application will not have access to the key, but will be able to access the HASH result.

After setting up the ESP32 with the key, it is possible to enable the remote attestation component in the main application by including the following:

#### Required Includes

```cpp
#include "remoteAttest.h"
```

#### Enabling in the `.ino` Project

Within the `setup()` function, include:

```cpp
int paramAttest = NULL;
remoteAttest::setup_remoteAttest(&paramAttest);
xTaskCreatePinnedToCore(ssh_port_forwarding_task, "SSH Port Forwarding Task4", 10500, &attestationPort, 5, NULL, 1);
```

Where attestationPort is the reverse socket proxy defined in `fw_ports.h` as follows:

```cpp
TaskParameters attestationPort = {
    .local_port = 8888,
    .forward_remote_port = 8888, //on the client computer
    .high_bw = false,
};
```
The above configuration sets the local port 8888 in the ESP32 and also sets the local port 8888 in the remote server for remote attestation. The remote attestation process is performed as follows:

```sh
curl -X GET http://127.0.0.1:8888/hash?challenge=string_to_use_as_challenge
```

Thanks to the HMAC key used, the attestation process validates the microcontroller's firmware integrity and identity. The default attestation for this chip is set for a standard usage of just 4MB of the external ROM available, but it can be modified easily for other sizes. The process verifies not only the firmware but also the available space in the ROM to validate the state in which the ROM should be found. Nevertheless, it is impossible to validate the entire ROM chip, as the reading of the ROM from the internal HASH function is different in particular memory addresses (non-volatile storage NVS). Thus, this test only evaluates the integrity of the area dedicated to application firmwares `(0x010000 to 0x400000)`, leaving the system information and bootloader `(0x000000 to 0x004000 aprox)`, the partition table `(0x008000 to 0x008C00 aprox)`, and the NVS `(0x00E000 to 0x0000FFFF)` segment out of the analysis. A dynamic verification functionality will be added in the future to allow arbitrary address ranges to be attested.

The resulting HASH from the microcontroller can be verified with the provided `remote_attestation.py`, provided that an image of the ROM is available (from 0x010000 to 0x400000). This can be easily obtained from a testing microcontroller after any upgrade, before delivering upgrades to remote systems. The process to obtain the firmware image and validate the HASH is as follows:

```sh
#This command saves the firmware contents of the microcontroller from 0x010000 to 0x400000 (0x3F0000 in size) into firmware.bin
esptool.py -b 921600 --port /dev/ttyACM0 read_flash 0x00010000 0x3F0000 firmware.bin

#Then, the following command evaluates the HASH of the ROM with the "string_to_use_as_a_challenge" provided that the HASH key burnt into the microcontroller is available in private_key.bin file
python3 remote_attestation.py string_to_use_as_challenge
```

## Licensing and Funding

This software is licensed under the BSD 3-Clause Clear License, which permits open access and reuse according to the principles of the Marie Skłodowska-Curie Actions under Horizon Europe.

> **Funding Acknowledgment**  
> This work was supported by the European Union’s Horizon Europe research and innovation programme under the Marie Skłodowska-Curie Actions grant agreement No. 101149974 ([Project CMXsafe](https://cordis.europa.eu/project/id/101149974)).


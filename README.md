![OpenASC Logo](git-assets/openasc-logo.svg)

# OpenASC-Catalogs

OpenASC is an open-source repository of structured threat, control, and asset catalogs. It provides a foundational resource for systematically identifying, assessing, and mitigating security threats in the automotive domain utilizing classification models like STRIDE and MITRE ATT&CK©. OpenASC is designed to actively support the Risk Assessment and TARA processes outlined in Clause 15 of **ISO/SAE 21434** and **UN Regulations No. 155 and No. 156** for cybersecurity management in road vehicles.

## Features
- **Threat Catalog**: A comprehensive, interconnected list of automotive-specific threats, classified via STRIDE/MITRE ATT&CK and mapped to UN R155 Annex 5 threat categories.
- **Control Catalog**: Standardized security controls (cryptographic, hardware, process) mathematically designed to reduce attack feasibility, mapped to UN R155 mitigations.
- **Asset Catalog**: A detailed physical and logical inventory of the Vehicle ecosystem, following different architectures.
- **Graph-Ready Capability Taxonomy**: Utilizes a strict, Mutually Exclusive and Collectively Exhaustive (MECE) dictionary (`Action:Class:Domain`) to map dynamic attack paths using `requires`, `grants` (Threats) and `denies`, `overriddenBy` (Controls) for logic gates.
- **AI Vector Integration**: Seamlessly maps natural language queries to the structured taxonomy using locally executed LLM embeddings.
- **JSON Schema Validation**: All catalogs are validated against strict JSON Schemas to ensure logical consistency and programmatic interoperability.

## Project Structure
```text
catalogs/         # The main catalogs for assets, threats, and controls
schemas/          # JSON Schemas for assets, threats, and controls
scripts/          # Validation scripts (Node.js)
LICENSE.md        # MIT License
package.json      # Project metadata and scripts
README.md         # Project documentation
CONTRIBUTING.md   # Project contribution guide

```

## Getting Started

### Prerequisites

* Node.js (v16 or later recommended)

### Install Dependencies

```sh
npm install

```

### Validate Catalogs

Validate threats, controls, assets, or all simultaneously using the provided scripts:

```sh
# Validate threats catalog
npm run validate:threats

# Validate controls catalog
npm run validate:controls

# Validate assets catalog
npm run validate:assets

# Validate all catalogs
npm run validate:all

```

## Catalog Formats

* **Assets**: Defined in `catalogs/assets.json`, validated by `schemas/asset.schema.json`.
* **Threats**: Defined in `catalogs/threats.json`, validated by `schemas/threat.schema.json`.
* **Controls**: Defined in `catalogs/controls.json`, validated by `schemas/control.schema.json`.

---

## The OpenASC Asset & Impact Methodology

To align with ISO/SAE 21434, OpenASC natively separates damage impacts into two distinct stakeholder perspectives: `oem` and `roadUser`, with the capability of adding `thirdPartySupplier`.

---

## Automotive Threat Modeling Taxonomy (Structure vs. Payload)

To support automated threat modeling and graph-based attack path analysis without combinatorial state explosion, OpenASC utilizes a highly deterministic **Structure vs. Payload** philosophy.
To support automated threat modeling and graph-based attack path analysis without combinatorial explosion, OpenASC utilizes a strict, highly condensed capability syntax formatted as: **`Action:Class:Domain`**.

This taxonomy abstracts away hyper-specific technologies into 8 core functional classes, allowing engineers to model legacy E/E architectures, modern Software-Defined Vehicles (SDVs), Advanced Hardware Fault Injection, and Post-Quantum Cryptography (PQC) threats using a single, unified mathematical logic.

This is known internally as the **$8 \times 8 \times 8 \times 80$ Matrix**.

* **The Structure ($8 \times 8 \times 8$):** A strictly controlled syntax formatted as **`Action:Class:Domain`**. This mathematically guarantees that graph routing algorithms resolve without infinite loops, allowing legacy ICE architectures and modern SDVs to be modeled with the exact same math.
* **The Payload ($80$ Tags):** An array of curated Engineering Metadata Tags (`tags: string[]`). This brings the graph back to engineering reality by specifying the exact protocol, hardware, or mechanism involved (e.g., separating a generic "Network Inject" into specific `[CAN-FD]` vs `[Automotive Ethernet]` vectors). The NLP Engine utilizes these tags to mathematically filter edge-cases.

### 1. ALLOWED ACTIONS (The Verbs)

The action list relies on exactly 8 mutually exclusive attacker operations. This forces threat models to describe the *mechanism* of the attack.

* **`Extract`**: Read data or code at rest (e.g., memory dumping, extracting a key, SCA/DFA).
* **`Intercept`**: Read data or code in transit (e.g., passively sniffing a bus, wiretapping).
* **`Modify`**: Alter data or code at rest (e.g., patching a binary, changing a config).
* **`Inject`**: Introduce malicious data or commands in transit (e.g., spoofing messages, API injection).
* **`Disrupt`**: Exhaust resources or deny service (e.g., flooding a network, cutting a physical wire).
* **`Execute`**: Run arbitrary code or commands (e.g., remote code execution).
* **`Elevate`**: Escalate privileges or logical state (e.g., bypassing a secure boot check, User to Root).
* **`Fault`**: Physically manipulate hardware state (e.g., voltage glitching, electromagnetic fault injection).

### 2. ALLOWED ASSET CLASSES (The Nouns)

Instead of a massive, overlapping list of protocols and hardware, the taxonomy targets 8 core functional classes.

* **`Compute`**: Physical processing units (e.g., MCU, SoC, HSM, GPU).
* **`Memory`**: Physical storage hardware (e.g., Flash, RAM, EEPROM, eFuse).
* **`Peripheral`**: Edge hardware components (e.g., Sensors, Actuators, Transceivers).
* **`Network`**: Inter-node internal communication channels (e.g., CAN, Ethernet, LIN).
* **`Interface`**: External physical or logical entry points (e.g., OBD2, USB, JTAG, Bluetooth).
* **`Executable`**: Compiled software, logic, or active instructions (e.g., Bootloader, OS, Firmware, App).
* **`Data`**: Passive information at rest (e.g., Configurations, Logs, PII, Calibration data).
* **`Crypto`**: Cryptographic security material (e.g., Keys, Certificates, Seeds, Entropy).

### 3. ALLOWED DOMAINS (The Trust Boundaries)

Domains are structured as base architectural zones. A component or signal operates within a specific boundary.

* **`Powertrain`**: Propulsion, energy, and battery management.
* **`Chassis`**: Steering, braking, and suspension.
* **`Body`**: Lighting, access, and comfort systems.
* **`Infotainment`**: User interfaces, displays, and cabin OS.
* **`ADAS`**: Autonomous driving, perception, and decision algorithms.
* **`Telematics`**: External connectivity and gateway routing.
* **`Backend`**: OEM or third-party cloud infrastructure and services.
* **`External`**: Off-board entities (e.g., Mobile Apps, EVSE, Diagnostic Tools, KeyFobs).

### 4. ALLOWED METADATA (The Engineering Payload)

When defining an Asset, Threat, or Control in the JSON catalogs, engineers must apply the relevant metadata from this $80$-item curated dictionary to ensure the AI and UI filters resolve accurately.

* **1. In-Vehicle Networking (IVN)**: `CAN / CAN-FD / CAN-XL`, `Automotive Ethernet`, `LIN`, `FlexRay`, `SerDes`, `PCIe`, `SPI / I2C / I3C`, `UART / USART`, `CXPI`, `SENT / PSI5`
* **2. Wireless & External RF**: `Cellular`, `Wi-Fi`, `Bluetooth / BLE`, `UWB`, `NFC / RFID`, `GNSS`, `LF / RF`, `V2X`, `Satellite`, `mmWave`
* **3. Data & App Protocols**: `UDS`, `DoIP`, `SOME/IP`, `DDS`, `MQTT / AMQP`, `XCP / CCP`, `J1939 / FMS`, `ISO 15118 / OCPP`, `gRPC / REST`, `LWM2M / OMA-DM`
* **4. Interfaces & Diagnostics**: `OBD-II`, `JTAG / cJTAG`, `SWD`, `USB`, `HDMI / DisplayPort`, `Audio Jacks / A2B`, `EVSE Plug`, `Trailer Socket`, `Media Slots`, `Diagnostic Pads`
* **5. Hardware & Silicon**: `MCU`, `MPU`, `SoC`, `HPC / Zonal Controller`, `GPU / NPU`, `Sensor / Actuator`, `Transceiver / PHY`, `Memory`, `NVRAM`, `eFuse / OTP`
* **6. Software Environments**: `RTOS`, `HLOS`, `Hypervisor`, `Container`, `Bootloader`, `Middleware`, `App / Service`, `Kernel / Driver`, `ML Model / Weights`, `Config / Calibration File`
* **7. Security Mechanisms**: `HSM / SHE`, `TEE`, `TPM / SE`, `SecOC`, `MACsec / IPsec`, `TLS / DTLS`, `Secure Boot`, `TRNG / PRNG`, `PUF`, `IDS / IPS`
* **8. Cryptographic Assets**: `PKI / Certificates`, `Symmetric Keys`, `Asymmetric Keys`, `Hashes`, `MAC / HMAC / CMAC`, `Digital Signatures`, `Nonces / IVs`, `Passwords / PINs`, `Tokens / API Keys`, `Seeds / RoT Data`

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://www.google.com/search?q=CONTRIBUTING.md) for detailed guidelines.

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

## Author

[Stefanos Flokos](https://www.stefanosflokos.dev)
![OpenASC Logo](git-assets/openasc-logo.svg)

# OpenASC-Catalogs

OpenASC is an open-source repository of structured threat, control, and asset catalogs. It provides a foundational resource for systematically identifying, assessing, and mitigating security threats in the automotive domain utilizing classification models like STRIDE and MITRE ATT&CK©. OpenASC is designed to actively support the Risk Assessment and TARA processes outlined in Clause 15 of **ISO/SAE 21434** and **UN Regulations No. 155 and No. 156** for cybersecurity management in road vehicles.

## Features
- **Threat Catalog**: A comprehensive, interconnected list of automotive-specific threats, classified via STRIDE/MITRE ATT&CK and mapped to UN R155 Annex 5 threat categories.
- **Control Catalog**: Standardized security controls (cryptographic, hardware, process) mathematically designed to reduce attack feasibility, mapped to UN R155 mitigations.
- **Asset Catalog**: A detailed physical and logical inventory of the vehicle ecosystem, following different E/E architectures.
- **Graph-Ready Capability Taxonomy**: Utilizes a strict, Mutually Exclusive and Collectively Exhaustive (MECE) capability syntax (`Action:Class:Domain`) to map dynamic attack paths using `requires`, `grants` (Threats) and `denies`, `overriddenBy` (Controls) for logic gates.
- **AI Vector Integration**: Schema is designed for seamless integration with locally-executed LLM embedding engines for NLP-powered threat relevance scoring.
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

To support automated threat modeling and graph-based attack path analysis without combinatorial explosion, OpenASC utilizes a strict, highly condensed capability syntax formatted as: **`Action:Class:Domain`**.

This taxonomy abstracts away hyper-specific technologies into 8 core functional classes, allowing engineers to model legacy E/E architectures, modern Software-Defined Vehicles (SDVs), Advanced Hardware Fault Injection, and Post-Quantum Cryptography (PQC) threats using a single, unified mathematical logic.

This is known internally as the **$8 \times 8 \times 8 \times 80$ Matrix**.

* **The Structure ($8 \times 8 \times 8$):** A strictly controlled syntax formatted as **`Action:Class:Domain`**. This mathematically guarantees that graph routing algorithms resolve without infinite loops, allowing legacy ICE architectures and modern SDVs to be modeled with the exact same math.
* **The Payload ($80$ Tags):** An array of curated Engineering Metadata Tags (`metadata: string[]`). This brings the graph back to engineering reality by specifying the exact protocol, hardware, or mechanism involved (e.g., separating a generic "Network Inject" into specific `[CAN-FD]` vs `[Automotive Ethernet]` vectors).

### 1. ALLOWED ACTIONS (The Verbs)

The action list relies on exactly 8 mutually exclusive attacker operations. This forces threat models to describe the *mechanism* of the attack.

* **`Extract`**: Read data or code at rest (e.g., memory dumping, extracting a key, SCA).
* **`Intercept`**: Read data or code in transit (e.g., passively sniffing a bus, wiretapping).
* **`Modify`**: Alter data or code at rest (e.g., patching a binary, changing a config).
* **`Inject`**: Introduce malicious data or commands in transit (e.g., spoofing messages, API injection).
* **`Disrupt`**: Exhaust resources or deny service (e.g., flooding a network, cutting a physical wire).
* **`Execute`**: Run arbitrary code or commands (e.g., remote code execution).
* **`Elevate`**: Escalate privileges or logical state (e.g., bypassing a secure boot check, User to Root).
* **`Fault`**: Physically manipulate hardware state (e.g., voltage glitching, electromagnetic fault injection, DFA).

### 2. ALLOWED ASSET CLASSES (The Nouns)

* **`Compute`**: Physical processing units (e.g., MCU, SoC, HSM, GPU, FPGA).
* **`Memory`**: Physical storage hardware (e.g., Flash, RAM, EEPROM, eFuse).
* **`Peripheral`**: Edge hardware components (e.g., Sensors, Actuators, Transceivers).
* **`Network`**: Logical communication channels and protocol stacks, regardless of whether they operate within the vehicle or across external trust boundaries (e.g., CAN, Automotive Ethernet, Cellular link, TLS session, REST API, V2X channel).
* **`Interface`**: Physical hardware access points - the connector, port, pad, or antenna feed where a channel is established or directly probed (e.g., OBD-II port, USB connector, JTAG pads, EVSE plug).
* **`Executable`**: Compiled software, logic, or active instructions (e.g., Bootloader, OS, Firmware, App).
* **`Data`**: Passive information at rest (e.g., Configurations, Logs, PII, Calibration data, ML model weights, FPGA bitstreams).
* **`Crypto`**: Cryptographic security material (e.g., Keys, Certificates, Seeds, Entropy).

### 3. ALLOWED DOMAINS (The Trust Boundaries)

* **`Powertrain`**: Propulsion, energy, and battery management.
* **`Chassis`**: Steering, braking, and suspension.
* **`Body`**: Lighting, access, and comfort systems.
* **`Infotainment`**: User interfaces, displays, and cabin OS.
* **`ADAS`**: Autonomous driving, perception, and decision algorithms.
* **`Telematics`**: External connectivity and gateway routing.
* **`Backend`**: OEM or third-party cloud infrastructure and services.
* **`External`**: Off-board entities (e.g., Mobile Apps, EVSE, Diagnostic Tools, Key Fobs).

### 4. ALLOWED METADATA (The Engineering Payload)

When defining an Asset, Threat, or Control in the JSON catalogs, engineers must apply the relevant metadata from this $80$-item curated dictionary to ensure AI and UI filters resolve accurately.

* **1. In-Vehicle Networking (IVN)**: `CAN / CAN-FD / CAN-XL`, `Automotive Ethernet`, `LIN`, `FlexRay`, `SerDes`, `PCIe`, `SPI / I2C / I3C`, `UART / USART`, `CXPI`, `SENT / PSI5`
* **2. Wireless & External RF**: `Cellular`, `Wi-Fi`, `Bluetooth / BLE`, `UWB`, `NFC / RFID`, `GNSS`, `LF / RF`, `V2X`, `Satellite`, `mmWave`
* **3. Data & App Protocols**: `UDS`, `DoIP`, `SOME/IP`, `DDS`, `MQTT / AMQP`, `XCP / CCP`, `J1939 / FMS`, `ISO 15118 / OCPP`, `gRPC / REST`, `LWM2M / OMA-DM`
* **4. Interfaces & Diagnostics**: `OBD-II`, `JTAG / cJTAG`, `SWD`, `USB`, `HDMI / DisplayPort`, `Audio Jacks / A2B`, `EVSE Plug`, `Trailer Socket`, `Media Slots`, `Diagnostic Pads`
* **5. Hardware & Silicon**: `MCU`, `MPU`, `SoC`, `HPC / Zonal Controller`, `GPU / NPU`, `Sensor / Actuator`, `Transceiver / PHY`, `Memory`, `FPGA`, `eFuse / OTP`
* **6. Software Environments**: `RTOS`, `HLOS`, `Hypervisor`, `Container`, `Bootloader`, `Middleware`, `App / Service`, `Kernel / Driver`, `ML Model / Weights`, `Config / Calibration File`
* **7. Security Mechanisms**: `HSM / SHE`, `TEE`, `TPM / SE`, `SecOC`, `MACsec / IPsec`, `TLS / DTLS`, `Secure Boot`, `TRNG / PRNG`, `PUF`, `IDS / IPS`
* **8. Cryptographic Assets**: `PKI / Certificates`, `Symmetric Keys`, `Asymmetric Keys`, `Hashes`, `MAC / HMAC / CMAC`, `Digital Signatures`, `Nonces / IVs`, `Passwords / PINs`, `Tokens / API Keys`, `Seeds / RoT Data`

---

## Graph-Ready Schema & Capability Model

The OpenASC catalog schema is designed to be consumed by the attack graph engines present in [openasc.org](https://openasc.org). The fields below define logical capability dependencies across catalog entries — understanding their semantics is essential for contributing accurate entries.

### Capability Fields

**On Threat entries:**

* **`requires`**: A logical condition (`AND` / `OR` tree of `Action:Class:Domain` nodes) expressing what attacker capability must already be present before this threat can be executed. `AND` means the attacker needs all listed capabilities; `OR` means any one is sufficient. Single-node conditions may be expressed directly without a wrapper.
* **`grants`**: The `Action:Class:Domain` capabilities the attacker gains upon successful execution. These are what graph engines use to chain threats into multi-step attack paths — a threat's `grants` resolves another threat's `requires`.

**On Control entries:**

* **`denies`**: The `Action:Class:Domain` capabilities this control prevents the attacker from gaining. A control that denies a capability blocks every attack path downstream of it.
* **`overriddenBy`**: A logical condition expressing what attacker capability would bypass this control entirely. Used to model conditional control effectiveness and defence weaknesses.

### Attack Potential Scoring

The `attackFeasibility.attackPotential` block on each threat entry follows **ISO/SAE 21434 Annex I Table I.1**. Each of the five components must be assigned one of the following rating keys.


Catalog entries should be rated for the **complete attack scenario** they describe, using the highest plausible value for each component dimension. The platform that consumes these catalogs aggregates component scores, maps them to the ISO 21434 Annex I feasibility level (High / Medium / Low / Very Low), and cross-references with worst-case asset impact through ISO 21434 Table H.8 to produce a final risk rating. The on-device platform processes all data locally — no catalog or asset information is transmitted externally.

---

## Disclosure

### AI-Assisted Development

Portions of the threat, control, and asset catalog entries were developed with the assistance of Large Language Models (LLMs). All catalog content has been subject to expert human review against ISO/SAE 21434 requirements, automotive E/E architecture conventions, and established cybersecurity engineering practice.

Despite this review, given the scope and technical depth of the catalogs, **errors, inaccuracies, or omissions may be present**. Catalog entries should be validated against your specific vehicle architecture, threat landscape, and applicable regulatory requirements before use in a formal TARA. OpenASC is a reference foundation, not a substitute for qualified cybersecurity engineering judgement.

Corrections, improvements, and new catalog entries submitted via pull request are strongly encouraged and actively reviewed.

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

## Author

[Stefanos Flokos](https://www.stefanosflokos.dev)
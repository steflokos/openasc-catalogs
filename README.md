![OpenASC Logo](git-assets/openasc-logo.svg)

# OpenASC-Catalogs

OpenASC is an open-source set of threat, control and asset catalogs for automotive cybersecurity. It assists on finding, assessing and reducing security threats, and it uses classifications such as STRIDE and MITRE ATT&CK®. It supports the risk assessment and TARA work in Clause 15 of **ISO/SAE 21434** and the threat and mitigation requirements of **UN Regulation No. 155**, while some controls also help with the software update practices in **UN Regulation No. 156**. 

## Features
- **Threat Catalog**: A list of interconnected automotive threats. They are classified with STRIDE and MITRE ATT&CK® and mapped to the UN R155 Annex 5 threat categories.
- **Control Catalog**: Standard security controls (cryptographic, hardware, process) that lower how feasible an attack is. They are mapped to the UN R155 mitigations.
- **Asset Catalog**: A list of the physical and logical parts of the vehicle, covering different E/E architectures.
- **Capability Taxonomy for Graphs**: One strict syntax (`Action:Class:Domain`) with no overlaps and no gaps (MECE). Tools use it to build attack paths. Threats use `requires` and `grants`. Controls use `denies` and `overriddenBy`, which act as gates.
- **AI Vector Integration**: The schema can feed embedding models that run on your own machine, for example to rank threats by relevance.
- **JSON Schema Validation**: Every catalog is checked against strict JSON Schemas, so the data stays consistent and easy for programs to read.

## Project Structure
```text
catalogs/         # The main catalogs for assets, threats, and controls, plus property-rubric.json
schemas/          # JSON Schemas for assets, threats, and controls
scripts/          # Validation scripts (Node.js)
tools/            # Maintainer tools: the semantic lint (npm run lint:semantics)
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

## Automotive Threat Modeling Taxonomy

To let tools build attack paths in a structured way, OpenASC writes every capability in one short, strict form: **`Action:Class:Domain`**.

The taxonomy groups very specific technologies into 8 classes. This lets you model older E/E architectures, modern software-defined vehicles (SDVs), hardware fault injection and post-quantum cryptography (PQC) threats with the same rules.

This is a **$8 \times 8 \times 8 \times 88$ Matrix**: 8 actions, 8 classes, 8 domains and a curated list of 88 tags (see §4).

* **The Structure ($8 \times 8 \times 8$):** The strict syntax **`Action:Class:Domain`**. The set of possible capabilities is small and fixed, so a path search always finishes and cannot loop forever. Older combustion-engine architectures and modern SDVs are modeled with the same rules. `Domain` also accepts a reserved wildcard (`*`) for platform-level capabilities that do not belong to one domain. See §3 below for how it matches.
* **The Tags (88):** A list of engineering tags (`metadata: string[]`). They name the exact protocol, hardware or mechanism involved. For example, they split a general "network inject" into `CAN / CAN-FD / CAN-XL` and `Automotive Ethernet`.

### 1. ALLOWED ACTIONS (The Verbs)

There are exactly 8 actions, and each one is different from the others. This makes a threat model say *how* the attack works.

* **`Extract`**: Read data or code at rest (e.g., memory dumping, extracting a key, SCA).
* **`Intercept`**: Read data or code in transit (e.g., passively sniffing a bus, wiretapping).
* **`Modify`**: Alter data or code at rest (e.g., patching a binary, changing a config).
* **`Inject`**: Put malicious data or commands into traffic (e.g., spoofing messages, API injection).
* **`Disrupt`**: Use up resources or deny service (e.g., flooding a network, cutting a physical wire).
* **`Execute`**: Run any code or commands (e.g., remote code execution).
* **`Elevate`**: Gain more privileges or change the logical state (e.g., bypassing a secure boot check, User to Root).
* **`Fault`**: Physically change the state of the hardware (e.g., voltage glitching, electromagnetic fault injection, DFA). As a capability the attacker holds (`Fault:Compute`) it means a fault injection has worked, along with whatever a successful injection can bring: corrupted or skipped computation, a bypassed authentication or secure-boot check, a key leaked through DFA, a crash or reset. A crash or reset is an effect here, not the action. An attack whose only goal is to deny service uses `Disrupt`.

### 2. ALLOWED ASSET CLASSES (The Nouns)

* **`Compute`**: Physical processing units (e.g., MCU, SoC, HSM, GPU, FPGA).
* **`Memory`**: Physical storage hardware (e.g., Flash, RAM, EEPROM, eFuse).
* **`Peripheral`**: Edge hardware components (e.g., Sensors, Actuators, Transceivers).
* **`Network`**: Communication channels and protocol stacks, inside the vehicle or across outside trust boundaries (e.g., CAN, Automotive Ethernet, Cellular link, TLS session, REST API, V2X channel).
* **`Interface`**: Physical access points: the connector, port, pad or antenna feed where a channel starts or is probed directly (e.g., OBD-II port, USB connector, JTAG pads, EVSE plug).
* **`Executable`**: Compiled software, logic or running instructions (e.g., Bootloader, OS, Firmware, App).
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
* **`*` (wildcard)**: Used for capabilities and assets that do not belong to one domain. These are platform-level parts such as a root of trust, a hypervisor or a shared secure element, which every domain relies on. The `domain` enum therefore has 9 values, but only 8 are vehicle domains. The wildcard is a placeholder for matching, not a 9th domain.

**How wildcards match:** when a tool checks whether a capability an attacker holds (from a threat's `grants`) meets a capability that is required (in another threat's `requires`, or in a control's `denies` or `overriddenBy`), it first replaces every `*` with the one domain being analysed (see "Scoped resolution" below). Only then does it compare the `domain` fields. A `*` on either side becomes that domain. So in an Infotainment analysis, a held `Modify:Memory:*` is `Modify:Memory:Infotainment` and meets exactly that. A named domain only ever matches itself. `action` and `assetClass` are never wildcards: they must match exactly. This keeps each comparison cheap and stops one capability from quietly meeting every action and class in a domain. If a threat or control really covers several actions or classes, write an explicit `OR` (in `requires` or `overriddenBy`) or list several entries (in `grants` or `denies`) instead of using a wildcard.

**Per-domain instances: `*` is a placeholder for one domain (catalog 2.0)** Many threats in the catalog are generic technique templates, such as runtime memory tampering or privilege escalation through a compromised executable. How they work does not depend on which vehicle domain hosts them, so their `requires` and `grants` use `*`. A tool treats such an entry as a **template** and makes **one instance per domain**, replacing every `*` in it (on the `requires` side and the `grants` side, and for controls in `denies` and `overriddenBy`) with that domain. `T.06.1` in Telematics needs `Execute:Executable:Telematics` and gives `Elevate:Executable:Telematics`; the same entry in Powertrain is a separate step with its own domain. An instance never mixes domains, so a capability granted in one domain never meets a requirement in an unrelated one. Entries that name their domains are used as written, and they are the **only** way from one domain to another. A control is instantiated the same way: getting past Secure Boot in Telematics does not get past it in Powertrain. (Catalog 1.x said to resolve `*` once per analysis, for the domain being studied. That is the special case of an analysis that never leaves one domain, and it gives the same answers there.)

**Do not use `domain: "*"` on both `requires` and `grants` for a threat that moves the attacker from one domain to another.** Scoped resolution turns every wildcard into the one domain being analysed. A threat with `*` on both sides can therefore only mean "same domain in, same domain out". It cannot describe a move between domains, whatever its `description` says. If the move is one specific case (for example, code execution in Telematics that lets the attacker inject messages in Powertrain through a gateway), use named domains on the sides that need them. If the threat is a generic template for a mechanism that can bridge several domains (for example, a Central Gateway that relays between the segments it connects), list every domain it could reach as separate named entries: an `OR` of named domains in `requires`, or several named entries in `grants`. Do not rely on `*`. A project catalog that uses such a template for one real vehicle should shorten the list to the domains its gateway really connects, instead of keeping the full list from the template.

**Links between domains.** A link, such as the connection between the vehicle and the cloud, has an end in each domain it joins and a path in between (`External`). A threat that attacks the link itself, by intercepting or altering what travels over it, lists the capability for every end it touches. For the vehicle-to-cloud link that means `Telematics` and `Backend`, next to `External` for the path. This is the same wide approach as for the gateway above: a project catalog can shorten the list. The same information also passes through the vehicle's own networks. The generic sniffing threats (written with `*`) cover that, one analysis domain at a time.

**Domains on controls.** Use `*` in a control's `denies` and `overriddenBy` unless the control itself is tied to one domain, or to the border between two. A control describes a mechanism (a scheduler, a file system check, an allowlist), and the mechanism works the same in every domain. Keep a named domain only when the control's own text ties it there. A project catalog can narrow a control to the domains it really has, in the same way as for a template threat. 

**Bypassing a control.** A control falls when what it rests on can be changed: rules and policy fall to `Modify:Data`, certificates and trust stores to `Modify:Crypto`, and the chain ends at hardware that cannot be changed (HSM, TPM, OTP, eFuses), which denies `Modify:Crypto` and falls only to `Fault:Compute`. A bypass must not need something the control itself denies.

### 4. ALLOWED METADATA (The Engineering Tags)

When you write an Asset, Threat or Control in the JSON catalogs, pick the tags that apply from this curated list of 88. This keeps AI and UI filters accurate.

* **1. In-Vehicle Networking (IVN)**: `CAN / CAN-FD / CAN-XL`, `Automotive Ethernet`, `LIN`, `FlexRay`, `SerDes`, `PCIe`, `SPI / I2C / I3C`, `UART / USART`, `CXPI`, `SENT / PSI5`, `TSN / AVB (Time-Sensitive Networking)`
* **2. Wireless & External RF**: `Cellular`, `Wi-Fi`, `Bluetooth / BLE`, `UWB`, `NFC / RFID`, `GNSS`, `LF / RF`, `V2X`, `Satellite`, `mmWave`, `RKE / PEPS (Keyless Entry)`
* **3. Data & App Protocols**: `UDS`, `DoIP`, `SOME/IP`, `DDS`, `MQTT / AMQP`, `XCP / CCP`, `J1939 / FMS`, `ISO 15118 / OCPP`, `gRPC / REST`, `LWM2M / OMA-DM`, `OTA / SOTA / FOTA`
* **4. Interfaces & Diagnostics**: `OBD-II`, `JTAG / cJTAG`, `SWD`, `USB`, `HDMI / DisplayPort`, `Audio Jacks / A2B`, `EVSE Plug / Wireless Charging`, `Trailer Socket`, `Media Slots`, `Diagnostic Pads`
* **5. Hardware & Silicon**: `MCU`, `MPU`, `SoC`, `HPC / Zonal Controller`, `GPU / NPU`, `Sensor / Actuator`, `Transceiver / PHY`, `Flash / RAM / EEPROM`, `FPGA`, `eFuse / OTP`, `LiDAR / Radar / Camera`
* **6. Software Environments**: `RTOS`, `HLOS`, `Hypervisor`, `Container`, `Bootloader`, `Middleware`, `App / Service`, `Kernel / Driver`, `ML Model / Weights`, `Config / Calibration File`, `SBOM / Software Composition`, `LLM / Conversational AI`
* **7. Security Mechanisms**: `HSM / SHE`, `TEE`, `TPM / SE`, `SecOC`, `MACsec / IPsec`, `TLS / DTLS`, `Secure Boot`, `TRNG / PRNG`, `PUF`, `IDS / IPS`, `OAuth / OIDC / SAML`
* **8. Cryptographic Assets**: `PKI / Certificates`, `Symmetric Keys`, `Asymmetric Keys`, `Hashes`, `MAC / HMAC / CMAC`, `Digital Signatures`, `Nonces / IVs`, `Passwords / PINs`, `Tokens / API Keys`, `Seeds / RoT Data`, `Session Keys / Ephemeral Secrets`

---

## Graph-Ready Schema & Capability Model

Tools such as the [openasc.org](https://openasc.org) Playground read the catalog schema to build attack paths. The fields below say how catalog entries depend on each other. You need to understand them to contribute correct entries.

### Capability Fields

**On Threat entries:**

* **`requires`**: A condition (an `AND` / `OR` tree of `Action:Class:Domain` nodes) that says what the attacker must already be able to do before this threat can run. `AND` means all listed capabilities are needed. `OR` means any one is enough. A single capability can be written directly, without a wrapper.
* **`grants`**: The `Action:Class:Domain` capabilities the attacker gains when the threat succeeds. Tools use these to chain threats into multi-step attack paths: what one threat `grants` can satisfy another threat's `requires`. 

**On Control entries:**

* **`denies`**: The `Action:Class:Domain` capabilities this control stops the attacker from gaining. A control that denies a capability blocks every attack path that comes after it.
* **`overriddenBy`**: A condition that says what the attacker would need to get around this control completely. It models controls that work only under certain conditions, and their weak points. A control that declares no `overriddenBy` is a deliberate hard block: nothing in the catalog can defeat it, and tools show it that way (every control in the current catalog declares one). A declared bypass must not need a capability that the control itself denies, because such a bypass can never be met.

**On any entry (structure fields):**

* **`refines`** (threats and controls): the id of the parent entry. It is always the entry's own id without its last `.n` part (`C.05.2` refines `C.05`). An entry that others refine is an *umbrella*: a category or tactic heading (`T.16` Lateral Movement, `C.05` Digital Signature), not a concrete mechanism. Chain the concrete entries below it. The openasc.org tool never suggests an umbrella as a step in an attack path, and the semantic lint (`npm run lint:semantics`) does the same.
* **`partOf`** (assets): the id of the asset that contains this one (`A.022` is part of `A.040`). It is only a cross-reference for organisation and plays no part in capability matching.

### The CIANA Properties - `compromises` / `protects` / `cybersecurityProperties`

Threats, controls and assets each carry a list of properties from the same 5 values: `Confidentiality`, `Integrity`, `Availability`, `Authenticity` and `Non Repudiation`. The field name is different for each type, because each one relates to the property in a different way:

* **Threat `compromises`**: the properties this threat breaks when it succeeds. It should agree with what its `grants` mean (for example, a threat that grants `Extract:Crypto` should list `Confidentiality`).
* **Control `protects`**: the properties this control defends. It should agree with its `denies` and `overriddenBy`. A purely detective control such as an IDS protects different properties than a purely preventive one.
* **Asset `cybersecurityProperties`**: the properties the asset needs to stay trustworthy, whatever the threat or control. This is the asset's own baseline security need.

The values are shared because the idea (confidentiality, integrity and so on) is the same. 

### Layers of an attack path (catalog 2.0)

A realistic path has layers, and the catalog is written so that the capabilities follow them:

1. **Access** - the starting points, the only threats with no `requires`. Each one declares an **`attackVector`** (ISO/SAE 21434 Annex G): `Network` (remote, over a public or cellular network), `Adjacent` (in radio or sensor range: Bluetooth, Wi-Fi, V2X, RF, the road environment), `Local` (a local interface or media in the cabin) or `Physical` (hands on the vehicle or the hardware). Starting points give **access** in a named domain (`Inject`/`Intercept:Interface`, `Intercept:Compute` for hands on a board, `Extract:Crypto:External` for phished credentials) or, for a remotely reachable service, user-level code execution in the domain that exposes it (Telematics, Infotainment). They never give root, keys or code changes in a domain behind the gateway.
2. **Exploit** - needs access in a domain and gives `Execute:Executable` there.
3. **Escalate** - `Execute` to `Elevate` in the same domain.
4. **Move** - named-domain entries only. Domains behind the central gateway are reached through Telematics (gateway routing): root on the gateway/TCU gives `Inject:Network` in the vehicle domains, root on an ECU of another domain reaches the gateway's network. OTA delivery from the Backend needs the signing key **and** control of the delivery path.
5. **Impact** - `Modify:Executable/Data/Crypto`, `Execute:Peripheral`, `Inject:Peripheral`, `Disrupt:*` in the target domain.

Physical attacks on a board (debug ports, flash extraction, glitching) need `Intercept:Compute` in that domain first, which only physical vehicle access gives, and only for in-vehicle domains. Fault injection (`Fault:Compute`) is a step of its own (T.02.5), not something access hands out. `npm run report:paths` prints, per attack vector and domain, the round in which key capabilities are first held; lint rule F2 warns when a remote path to code changes in Powertrain, Chassis, Body or ADAS takes fewer than 3 steps.

**Control types.** Controls declare `controlType`: `Preventive` (stops the capabilities it denies), `Detective` (notices an attack: IDS, logging, monitoring) or `Organizational` (processes, key management, VSOC). Detective and organizational controls keep their `denies` for compatibility, but tools may treat them as weaker than a preventive barrier; their main effect is the raised attack potential.

### Capabilities and Compromised Properties

A tool can let an engineer set a goal such as "lose Integrity on Executable in Powertrain". To do that it must know which capabilities count as that loss. The capability alone decides this, using the table in [`catalogs/property-rubric.json`](catalogs/property-rubric.json). A granted `Action:Class` counts as losing the properties listed in its row. `compromises` is not used for this. `compromises` stays the threat's damage list for the TARA. It should include what the threat's own grants directly break, and it may add what later steps lead to. For example, a code-execution threat may list Confidentiality, because the attacker can then read what the host holds.

| Granted capability | Counts as compromising |
|---|---|
| `Extract`, `Intercept` (any class) | Confidentiality |
| `Modify` (any class) | Integrity |
| `Modify:Executable`, `Modify:Crypto` | Integrity, Authenticity (tampered code or keys are no longer authentic) |
| `Modify:Data` | Integrity, Non Repudiation (`Data` includes records and logs) |
| `Inject` (any class) | Integrity, Authenticity (spoofed origin) |
| `Disrupt` (any class) | Availability |
| `Disrupt:Data` | Availability, Non Repudiation |
| `Execute`, `Elevate` (any class except Crypto) | Integrity of the asset it acts on (code or privilege controlled by the attacker is already a loss of integrity) |
| `Elevate:Crypto` | Authenticity, Non Repudiation (acting under another's authority) |
| `Fault` | Integrity, Availability, Authenticity, Confidentiality (a successful fault injection and what it can bring: corrupted or skipped computation, a bypassed check, a crash or reset, key leakage through DFA) |

The table is a default, not a fixed rule. A project whose TARA counts attacker code execution as a loss of every property can ship its own `property-rubric.json`. The openasc.org Playground also lets a user change single rows for one analysis. Only the changed rows are stored, and the goal is marked as using custom rules.


### Attack Potential Scoring

The `attackFeasibility.attackPotential` block on each threat (and the matching `attackFeasibilityReduction.attackPotentialReduction` block on each control) follows **ISO/SAE 21434 Annex I Table I.1**. Each of the five parts gets one rating key. The letters name the part and the number names the level within it: `ET0`-`ET4` (Elapsed Time, 5 levels), `SE0`-`SE3` (Specialist Expertise, 4 levels), `KoIC0`-`KoIC3` (Knowledge of the Item or Component, 4 levels), `WoO0`-`WoO3` (Window of Opportunity, 4 levels), `Eq0`-`Eq3` (Equipment, 4 levels). On a threat, a lower number means the attack is easier. On a control, a lower number means a smaller reduction.

### Impact Scoring

To align with ISO/SAE 21434, OpenASC rates damage in **Assets** from two points of view: `oem` and `roadUser`. A `supplier` view can be added.

### Scalability

Every threat has a required `scalability` field with one of three values: `Single Vehicle`, `Limited Batch` or `Fleet-Wide`. It says how many vehicles the threat's *mechanism* can realistically reach, whatever the size of any one company's fleet. It is not the same as `attackFeasibility`, which rates the attacker's effort *for one attack*. `scalability` rates how many vehicles one successful exploit reaches without the attacker repeating the work.

* **`Single Vehicle`**: needs physical possession of, or closeness to, each target, and the work must be repeated for every extra victim (hardware fault injection, JTAG probing, chip decapsulation). The attacker's effort grows in step with the number of victims.
* **`Limited Batch`**: limited by something smaller than the whole fleet but bigger than one vehicle: one production run, hardware revision, region, backend tenant or campaign, or an RF-range attack (jamming, relay, V2X spoofing) that only reaches vehicles in range at that moment. Most MITRE-style follow-on techniques (persistence, discovery, defense evasion, lateral movement) are rated here by default. They work inside a vehicle that is already compromised, and they get their real reach from the initial-access threat that gave the foothold. They are not initial-access vectors themselves.
* **`Fleet-Wide`**: can be repeated remotely or across the whole system, with no need to be near a vehicle or hold it: a backend or cloud API flaw, a flaw in shared firmware that is identical on every unit, a compromise of the OTA or update channel, or a cryptographic weakness in a protocol used across the fleet.


### Threat Actors

Every threat also has a required `threatActors` list with one or more values. It says *who* would realistically carry out the threat and *why*. This is a third question, apart from `attackFeasibility` (how hard) and `scalability` (how far it reaches). The list leaves out skill labels such as "script kiddie". `attackFeasibility` already covers skill through its `specialistExpertise` and `equipment` parts, so this field is about motive and how the actor gets access, not ability.

* **`Nation-State / State-Sponsored`**: well-funded actors directed by a government, motivated by espionage, strategic disruption or sabotage. Use it only for threats that need a lot of skill or aim at high-value targets (root-of-trust material, supply-chain implants, backend infrastructure at scale), and not for every serious-sounding threat.
* **`Organized Cybercrime`**: motivated by money: vehicle theft rings, selling data, fraud, extortion. This is the most widely used value, because most threats have some way to make money.
* **`Hacktivist`**: motivated by beliefs or politics. Prefers disruptive or visible results to quiet financial gain.
* **`Insider (Employee / Dealer / Supplier)`**: someone who misuses access they got through a job, a dealership or a supplier *relationship*. It does not mean "an attacker who already has code execution from an earlier step", because that applies to outside attackers too and says nothing about a relationship.
* **`Vehicle Owner / Authorized User`**: the vehicle's own legitimate holder acting against the interest of the OEM (or of a regulator or insurer): unlocking paid features or getting around DRM, odometer or emissions tampering, insurance or warranty fraud, switching off telemetry, or rolling back firmware to get a removed feature back.

These values come from the ENISA Threat Landscape and from industry threat-intelligence lists (Nation-State, Organized Cybercrime, Hacktivist, Insider). We added Vehicle Owner / Authorized User, which is the automotive version of the "customer" threat source in NIST SP 800-30. Neither ISO/SAE 21434 nor SAE J3061 defines threat actors. ISO/SAE 21434 avoids the question by rating attack feasibility instead, and this catalog does that too. `threatActors` is our own addition on top of the standard, not a value taken from it.

---

## Disclosure

### AI-Assisted Development

Large Language Models (LLMs) helped write parts of the threat, control and asset entries. An expert has reviewed all catalog content against ISO/SAE 21434, common E/E architecture practice and established cybersecurity engineering practice.

Even so, the catalogs are large and technical, so **there may be errors, inaccuracies or missing items**. Check the entries against your own vehicle architecture, threat landscape and regulatory requirements before you use them in a formal TARA. OpenASC is a reference to start from. It does not replace the judgement of a qualified cybersecurity engineer.

We welcome and review corrections, improvements and new entries sent as pull requests.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the guidelines.

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

## Author

[Stefanos Flokos](https://www.stefanosflokos.dev)

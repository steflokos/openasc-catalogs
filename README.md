![OpenASC Logo](assets/openasc-logo.svg)

# OpenASC-Catalogs

OpenASC is an open-source repository of structured threat and control catalogs. It provides a foundational resource for systematically identifying and mitigating security threats in the automotive domain utilizing classification models like STRIDE and MITRE ATT&CK©. OpenASC is designed to support processes outlined in Clause 15 of ISO/SAE 21434 and the United Nations regulation no.155 for cybersecurity management in road vehicles.

## Features
- **Threat Catalog**: Comprehensive list of automotive-specific threats, classified (e.g., STRIDE, MITRE ATT&CK) and mapped to regulations (e.g., UN Regulation No. 155).
- **Control Catalog**: Standardized security controls with detailed descriptions and mappings to regulations (e.g., UN Regulation No. 155).
- **Threat/Control Relationships**: Explicit mappings indicate which controls mitigate specific threats and which threats possibly affect some controls.
- **JSON Schema Validation**: All catalogs are validated against strict JSON Schemas for consistency and interoperability.
- **Validation Scripts**: Node.js scripts for validating catalog files.

## Project Structure
```
controls/         # Security control catalog (JSON)
schemas/          # JSON Schemas for threats and controls
scripts/          # Validation scripts (Node.js)
threats/          # Threat catalog (JSON)
LICENSE.md        # MIT License
package.json      # Project metadata and scripts
README.md         # Project documentation
CONTRIBUTING.md   # Project contribution guide
```

## Getting Started
### Prerequisites
- Node.js (v16 or later recommended)

### Install Dependencies
```sh
npm install
```

### Validate Catalogs
Validate threats, controls, or both using the provided scripts:
```sh
# Validate threats catalog
npm run validate:threats

# Validate controls catalog
npm run validate:controls

# Validate all catalogs
npm run validate:all
```

## Catalog Format
- **Threats**: Defined in `threats/threats.json`, validated by `schemas/threat-array.schema.json`.
- **Controls**: Defined in `controls/controls.json`, validated by `schemas/control-array.schema.json`.
- See the `schemas/` directory for detailed schema definitions.

## Contributing
Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License
This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

## Author
Stefanos Flokos

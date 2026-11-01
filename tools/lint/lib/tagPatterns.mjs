// tools/lint/lib/tagPatterns.mjs
//
// High-signal text patterns for rule S10 (tag vs text). A heuristic: it finds entries whose name or description
// names a technology that has a dictionary tag but lacks the tag, and entries that carry the tag without naming it.
// It cannot judge intent (an asset may deliberately carry a tag for what it is protected by). The tag strings must
// match the schema's metadata enum exactly; lint.mjs checks that.

export const TAG_PATTERNS = [
    ['CAN / CAN-FD / CAN-XL', /\bCAN(?:-FD|-XL)?\b/],
    ['Automotive Ethernet', /\bEthernet\b/i],
    ['LIN', /\bLIN\b/],
    ['FlexRay', /FlexRay/i],
    ['UART / USART', /\bU?S?ART\b/],
    ['Cellular', /cellular|\bLTE\b|\b[345]G\b|base station|\bSIM\b|\beSIM\b/i],
    ['Wi-Fi', /wi-?fi|\bWLAN\b|802\.11/i],
    ['Bluetooth / BLE', /bluetooth|\bBLE\b/i],
    ['NFC / RFID', /\bNFC\b|\bRFID\b/],
    ['GNSS', /\bGNSS\b|\bGPS\b/],
    ['V2X', /\bV2[XVIG]\b|vehicle-to-/i],
    ['RKE / PEPS (Keyless Entry)', /key ?fob|keyless (?:entry|access|start|go)|\bRKE\b|\bPEPS\b|\bPaaK\b|rolling code/i],
    ['UDS', /\bUDS\b|unified diagnostic|security access/i],
    ['DoIP', /\bDoIP\b/],
    ['SOME/IP', /SOME\/IP/],
    ['MQTT / AMQP', /\bMQTT\b|\bAMQP\b/],
    ['gRPC / REST', /gRPC|\bREST\b|\bHTTPS?\b|\bAPIs?\b|web service/],
    ['OAuth / OIDC / SAML', /OAuth|\bOIDC\b|\bSAML\b|\bJWT\b/],
    ['OTA / SOTA / FOTA', /\bOTA\b|over-the-air|\bSOTA\b|\bFOTA\b/i],
    ['OBD-II', /\bOBD(?:-II)?\b/],
    ['JTAG / cJTAG', /\bc?JTAG\b/],
    ['SWD', /\bSWD\b|serial wire/i],
    ['USB', /\bUSB\b/],
    ['HSM / SHE', /\bHSM\b|\bSHE\b|hardware security module/i],
    ['TEE', /\bTEE\b|trustzone|trusted execution/i],
    ['SecOC', /\bSecOC\b/],
    ['TLS / DTLS', /\bD?TLS\b|\bSSL\b/],
    ['Secure Boot', /secure boot|chain of trust|boot chain/i],
    ['TRNG / PRNG', /\bT?PRNG\b|\bTRNG\b|random number/i],
    ['IDS / IPS', /\bIDS\b|\bIPS\b|intrusion detection|intrusion prevention/i],
    ['PKI / Certificates', /certificate|\bPKI\b/i],
    ['Hypervisor', /hypervisor/i],
    ['Container', /\bcontainers?\b/i],
    ['Bootloader', /bootloader/i],
    ['SBOM / Software Composition', /\bSBOM\b|software composition|bill of materials/i],
    ['ML Model / Weights', /machine learning|\bML\b|neural network|model weights/i],
    ['LLM / Conversational AI', /\bLLM\b|large language model|conversational/i],
];

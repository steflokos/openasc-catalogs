# Catalog audit and 2.0.0 restructure

This records what the audit of the capability model found, what 2.0.0 changes, and what is left. The numbers come
from `npm run report:paths` (per-domain instances, see README "Domains"), run on 1.0.1 and on 2.0.0.

## Findings on 1.0.1

- **Every threat ran in every domain, and the picture was the same everywhere.** From the starting points, all 837
  threat instances fired, and code execution and root (`Execute`/`Elevate:Executable`) were held in round 1 in all 8
  domains, Backend and External included. The cause was starting points that granted deep capabilities with `*`:
  JTAG (T.06.4), physical data tampering (T.02.7/.8), extraction (T.04.6/.7), physical modification (T.09.7) and
  physical access (T.06.6, T.19.7) needed nothing and gave root, keys or memory writes in *any* domain, so "JTAG on the
  backend" was a valid one-step path. The radio exploit T.09.3 gave `Elevate:Executable:*`.
- **Every control could be bypassed in every domain** (538/538 instances). `Fault:Compute` is the bypass of 40
  controls, and two starting points handed it out for free (T.06.6, T.09.7).
- **Domains were not boundaries.** T.13.2 and T.16.2 took root in any domain to every vehicle network in one step;
  command-and-control and exfiltration threats (T.15.2, T.17.x, T.18.x, T.19.x) granted the vehicle's *external radio
  interface* from code execution anywhere, which other threats then used as an entry (EV charging spoofing T.01.12
  gave `Modify:Executable:Powertrain` from it).
- **Backend keys were a starting point.** T.04.8 extracted the OEM signing key with no access at all, and T.01.3
  (malicious firmware update) needed only that key: two steps from nothing to new firmware in every domain.
- **Seven controls could only be bypassed with what they deny** (C.02, C.02.1, C.02.2, C.03.1, C.03.13, C.15, C.17).
- No starting point said how it is reached (no attack vector), and no control said whether it prevents or detects.
- Assets bound to the wrong domain: A.032 Plug & Charge credentials and A.033 V2X pseudonym certificates (External,
  but stored in the vehicle), A.045 DTC data and A.064 diagnostic access (External, but on every ECU).

## Changes in 2.0.0

| Entry | Before | After |
| --- | --- | --- |
| T.06.6 Physical ECU / Vehicle Access | needs nothing; Fault/Intercept/Modify/Elevate:Compute in any domain | Physical starting point: `Intercept:Compute`, `Inject`/`Intercept:Interface` in the six in-vehicle domains only |
| T.02.7, T.02.8 physical tampering | starting points; Modify:Memory + Execute:Executable `*` | need board access (`Intercept:Compute`); Modify:Memory |
| T.04.6, T.04.7 physical extraction; T.06.4 JTAG; T.19.7 physical access | starting points | need board access in that domain |
| T.09.7 Physical Modification | starting point; Fault:Compute, Execute:Compute, Modify:Memory | needs board access; Execute:Compute, Modify:Memory |
| T.02.5 Fault injection (glitching) | needs Fault:Compute | needs board access; gives Fault/Modify/Elevate:Compute (fault injection is its own step) |
| T.09.3 Exploit via radio interface | Execute:Executable:Telematics + Elevate:Executable:`*` | Execute:Executable:Telematics (Adjacent) |
| T.02.9 RCE via Telematics/IVI | Execute:Executable:Telematics | + Execute:Executable:Infotainment (Network) |
| T.09.4 Removable media | Execute + Elevate:Executable:Infotainment | Execute only (Local) |
| T.09.2 Browser compromise; T.10.1 Command interpreter | gave Elevate:Executable directly | no root without an escalation step |
| T.16.2 Bridge Vehicle Networks | root in any domain → Inject:Network in all | root on the gateway (Telematics) → Inject:Network in Powertrain, Chassis, Body, ADAS, Infotainment |
| T.13.2 Bypass Network Filtering | root in any domain → Intercept/Inject:Network in all | root on an ECU behind the gateway → the gateway's network (Telematics) |
| T.06.7 Cross-Domain Lateral Movement | TCU code execution → Inject:Network + root in Powertrain | TCU root → Inject:Network:Powertrain |
| T.04.8 Backend key extraction | starting point | needs root on the backend |
| T.01.3 Malicious firmware update | signing key (or signing authority) | signing key AND the delivery path (backend root, or the domain's network) |
| T.15.2, T.17.4, T.17.8, T.18.2–T.18.5, T.19.1–T.19.4, T.19.6 C2 / exfiltration | granted the vehicle's external radio interface | grant `Extract:Data:External` (data leaves the vehicle); T.17.8 discovers in its own domain |
| T.17.1 Capture SMS | code execution in any domain | code execution in Telematics (the TCU handles SMS) |
| T.11.2 Disable software update | root, or the external radio interface | root |
| T.08.5 Manipulate communication | gave Modify:Executable:Backend | no longer |
| T.01.12 EV Charging Session Spoofing | needed the external radio interface; gave Modify:Executable:Powertrain | Physical starting point (rogue charger): Inject:Interface, Modify:Data, Extract:Crypto in Powertrain |
| All 19 starting points | - | `attackVector` (Network 2, Adjacent 14, Local 1, Physical 2) |
| C.02, C.02.1, C.02.2 | denied Extract:Crypto, bypassed by Extract:Crypto | no longer deny key extraction (encryption does not stop it) |
| C.03.1 TLS, C.03.13 downgrade prevention | denied Extract:Crypto, Modify:Data/Executable | deny Intercept:Network |
| C.15 Logging, C.17 Randomness | bypassed by what they deny | that bypass removed |
| All 88 controls | - | `controlType` (Preventive 76, Detective 5, Organizational 7) |
| A.032, A.033, A.045, A.064 | External | Powertrain, Telematics, `*`, `*` |
| Schemas | - | `attackVector` (threats), `controlType` (controls) |
| Lint | S1c info | S1c error; new F1 (starting points declare an attack vector), F2 (remote paths to code changes in Powertrain, Chassis, Body, ADAS take ≥ 3 steps, physical ≥ 2) |

## Result (report:paths)

Before (1.0.1, all starting points): every domain held Execute and Elevate:Executable in round 1 and
Modify:Executable in round 2; 538/538 control instances could be bypassed. Attack vectors did not exist.

After (2.0.0):

```
166 threats (818 instances), 93 controls (564 instances)
Round in which a capability is first held (1 = a starting point gives it; - = never)
## Starting points: Any  - 791 threat instances fire, 553/564 control instances can be bypassed
Domain       Execute:Executable Elevate:Executable Modify:Executable  Modify:Data        Execute:Peripheral Inject:Network     
Powertrain   2                  2                  3                  1                  1                  2                  
Chassis      2                  2                  3                  3                  3                  3                  
Body         2                  2                  3                  3                  1                  3                  
Infotainment 1                  2                  2                  2                  3                  3                  
ADAS         2                  2                  3                  3                  3                  3                  
Telematics   1                  2                  3                  2                  3                  2                  
Backend      2                  3                  4                  3                  4                  3                  
External     2                  3                  3                  3                  3                  2                  

## Starting points: Network  - 686 threat instances fire, 517/564 control instances can be bypassed
Domain       Execute:Executable Elevate:Executable Modify:Executable  Modify:Data        Execute:Peripheral Inject:Network     
Powertrain   4                  5                  4                  4                  5                  3                  
Chassis      4                  5                  4                  4                  5                  3                  
Body         4                  5                  4                  4                  3                  3                  
Infotainment 1                  2                  2                  2                  4                  3                  
ADAS         4                  5                  4                  4                  5                  3                  
Telematics   1                  2                  3                  2                  3                  2                  
Backend      2                  3                  4                  3                  5                  5                  
External     2                  3                  4                  3                  5                  5                  
```

A remote attacker now needs four steps to change code in Powertrain, Chassis, Body or ADAS, e.g. phishing →
backend access → backend root → malicious OTA update, or TCU exploit → TCU root → gateway → ECU exploit. Physical
board attacks no longer apply to the Backend or External.

## Second pass: controls, starting points, assets

Auto-ISAC ATM entries (T.07–T.20) follow the official matrix: their names, descriptions and structure (including the
same technique listed under several tactics) are kept. Only our own fields change on them: `requires`, `grants`,
`attackVector`, `metadata` and the UN R155 mapping. New entries go into our own STRIDE families.

| Entry | Change |
| --- | --- |
| C.03.15 Central Gateway Firewall and Domain Separation (new) | denies `Inject:Network` per domain; bypassed by being wired to the segment (`Inject:Interface`) or by root on the gateway AND rewriting its rules |
| C.08.8 HSM-Backed Code Signing (new) | denies stealing the backend signing key; bypassed by root on the signing service AND changing its approval policy |
| C.09.7 Phishing-Resistant MFA (new) | denies the use of phished credentials (`Extract:Crypto:External`); bypassed by an attacker-in-the-middle proxy or malware on the user's device |
| C.12.2 Firmware Image Encryption (new) | denies reading firmware (`Extract:Executable`); bypassed by the image key or a fault during decryption |
| C.23 Fault-Injection and Side-Channel Countermeasures (new) | denies `Fault:Compute`; software countermeasures fall once the firmware can be replaced |
| T.01.16 Rogue V2X / Short-Range Radio Transmitter (new) | Adjacent starting point: the radio channel to the vehicle and the V2X / telematics parsers |
| T.06.9 Compromised Aftermarket OBD-II Dongle (new) | Adjacent starting point: the diagnostic connector over the dongle's radio |
| A.076–A.081 (new) | OTA distribution backend, code-signing keys, HSM core, EV charging inlet, body control module, fleet telemetry and customer data store |
| T.08.6 Relay Communications | unlock and start (`Execute:Peripheral` Body, Powertrain) instead of privileged compute in Powertrain and the external radio link |
| T.09.1, T.18.1 Aftermarket / dealer equipment | the equipment has to be connected to the vehicle (`Inject:Interface` in that domain), not just compromised |
| T.01.10 Diagnostic credential spoofing | the credentials AND a diagnostic connection |
| T.13.3 Bypass UDS Security Access | an unlocked diagnostic session (`Elevate:Crypto`), not root |
| T.06.5 Misconfiguration EoP | needs code running, not just a key |
| T.11.5, T.12.8, T.13.5, T.16.6 Compromise Cryptographic Security | need code running as well as the data or firmware; give keys, not root (the four copies now agree) |
| T.09.8 Supply Chain Compromise | needs changed release artefacts on the backend, not just backend data |
| T.11.3 Modify OS kernel / boot partition | needs root (no longer interface access alone) |
| Lint S4b | info, not warn: since 2.0 physical and named-domain threats are meant not to run in every domain |

Defence in depth now holds (site test `proposals.test.ts`): with secure boot (C.10), the gateway firewall (C.03.15),
SecOC (C.06.3), HSM-backed signing (C.08.8), authenticated diagnostics (C.13), phishing-resistant MFA (C.09.7) and
fault-injection countermeasures (C.23), a Network attacker has **no** path to code changes in Powertrain; without
them the best path is phishing → backend access → backend root → stolen signing credentials → malicious OTA update.
With every control active, 16 Powertrain control instances can still be bypassed (51 before).

## Left for a later release

- UWB distance bounding against relay attacks: the capability model has no capability that only a relayed key
  gives, so a control denying it would also block unrelated attacks. Needs a taxonomy decision.
- An attacker-owned companion-app account as a Network starting point: nothing in the catalog consumes access to the
  OEM's public API yet (no API-abuse / IDOR threat in our families).
- UN R155 mappings for T.01.14 and T.07.1, to be taken from the regulation text rather than guessed.
- Asset overlaps (A.028/A.038/A.051, A.031/A.053, A.034/A.048).

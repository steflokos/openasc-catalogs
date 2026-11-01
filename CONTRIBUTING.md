# Contributing to OpenASC-Catalogs

Thank you for your interest in contributing to the OpenASC project! 

OpenASC is an open-source repository of structured threat and control catalogs. It provides a foundational resource for systematically identifying and mitigating security threats in the automotive domain utilizing classification models like STRIDE and MITRE ATT&CK©. OpenASC is designed to support processes outlined in Clause 15 of ISO/SAE 21434 and the United Nations regulation no.155 for cybersecurity management in road vehicles.

Your contributions help improve the quality and coverage of our catalogs.

## Quick Links
- [OpenASC GitHub Repository](https://github.com/OpenASC/OpenASC)
- [GitHub: Contributing to Projects](https://docs.github.com/en/get-started/quickstart/contributing-to-projects)
- [GitHub: About Pull Requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests)
- [GitHub: Creating a pull request from a fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork)

## How to Contribute
1. **Fork the Repository**: Use the Fork button on our GitHub repository to create your own copy.
2. **Clone Your Fork**:
   ```sh
   git clone https://github.com/<your-username>/OpenASC.git
   cd OpenASC
   ```
3. **Create a Feature Branch**: Name your branch descriptively (e.g., `feature/add-new-threat-xyz`).
   ```sh
   git checkout -b feature/add-new-threat-xyz
   ```
4. **Add or Update Entries**: Make your changes directly to catalogs `catalogs/threats.json`, `catalogs/controls.json`, `assets.json` depending on where you are contributing. Please ensure you are following [best practices](#best-practices) as explained below.
5. **Validate Your Changes**: Before submitting, validate your JSON files to ensure they conform to the schemas. You can use built-in scripts, online tools such as [JSON Schema Validator](https://www.jsonschemavalidator.net/iurl), or take advantage of automatic schema validation features available in editors like VS Code.
   - Using built-in scripts:
     ```sh
     npm install
     npm run validate:threats
     npm run validate:controls
     npm run validate:assets
     npm run validate:all
     ```
   - The semantic lint checks what the schemas cannot (control bypass logic, threat reachability, `compromises` against `grants`, metadata against text). It reports findings and exits 0 unless you pass `--strict`:
     ```sh
     npm run lint:semantics
     node tools/lint/lint.mjs threats --limit all   # one catalog, every finding
     ```
6. **Commit and Push**:
   ```sh
   git add catalogs/threats.json catalogs/controls.json catalogs/assets.json
   git commit -m "Add new threat or control or asset: XYZ description"
   git push origin feature/add-new-xyz
   ```
7. **Create a Pull Request**: Go to your fork on GitHub and click "Compare & pull request". Provide a meaningful title and description, and link to any related issues if applicable.
8. **Review Process**: The maintainers will review your PR. Please respond to any feedback or requested changes.
9. **Merge**: Once approved, your changes will be merged into the main repository.

## Branching Strategy

- **main**: Always points to the latest stable release. Users and production deployments should use this branch.
- **dev**: All development and new features should be based on this branch. Submit your pull requests here.

**Summary:**
- Base your work and pull requests on `dev`.
- `main` is for the latest stable release.

## Best Practices
- **Atomic Commits**: Each pull request should address a single change (e.g., add or update one threat or control).
- **Descriptive Commit Messages**: Write clear, concise commit messages describing your change.
- **Document Complex Entries**: If your entry is complex, add documentation or comments.
- **Writing Controls**: Use `*` as the domain in `denies` and `overriddenBy` unless the control's own text ties it to one domain, such as a cloud service for Backend; the lint (rule S2) lists the exceptions, and the reason for each goes in `tools/lint/lint-allow.json`. A control is bypassed by changing what it rests on: `Modify:Data` for rules and policy, `Modify:Crypto` for certificates and trust stores, `Elevate:Executable` for the code that enforces it. Hardware that cannot be changed (HSM, TPM, OTP, eFuses) denies `Modify:Crypto` and falls only to `Fault:Compute`. A bypass must never need something the control itself denies.
- **Writing Threats and Assets**: A threat whose name states a domain should not use `*` (S20), and an asset's name should match its domain; if a name lists two domains, make one asset for each (S19).
- **Check for Existing Issues/PRs**: Before submitting new ones, check if your idea or fix already exists.
- **Reference Issues**: In your PR description, reference issues your change addresses or closes (e.g., `Closes #123`).
- **Respectful Communication**: Keep discussions respectful and constructive.
- **Open Issues for Discussion**: If unsure, open a GitHub issue first to discuss your idea.

## Need Help?
If you have questions or need guidance, open an issue on GitHub or contact us via email at [mail@openasc.org](mailto:mail@openasc.org).

---
Thank you for helping us build a comprehensive and open TARA catalogs!

### Auto-ISAC ATM entries (T.07–T.20)

These follow the official Auto-ISAC Automotive Threat Matrix. Do not rename them, rewrite their descriptions, merge
the copies of a technique that ATM lists under several tactics, or add new entries to these families. Only the
fields the catalog adds on top may change: `requires`, `grants`, `attackVector`, `metadata` and
`unitedNationsRegulation155`. Copies of the same technique should carry the same `requires` and `grants` unless the
tactic really changes what the step needs or gives. New threats go into the STRIDE families (T.01–T.06).

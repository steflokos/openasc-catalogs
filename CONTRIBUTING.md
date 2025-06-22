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
4. **Add or Update Entries**: Make your changes directly to either `threats/threats.json` or `controls/controls.json`, depending on whether you are contributing a threat or a control. Please ensure you are following [best practices](#best-practices) as explained below.
5. **Validate Your Changes**: Before submitting, validate your JSON files to ensure they conform to the schemas. You can use built-in scripts, online tools such as [JSON Schema Validator](https://www.jsonschemavalidator.net/iurl), or take advantage of automatic schema validation features available in editors like VS Code.
   - Using built-in scripts:
     ```sh
     npm install
     npm run validate:threats
     npm run validate:controls
     npm run validate:all
     ```
6. **Commit and Push**:
   ```sh
   git add threats/threats.json controls/controls.json
   git commit -m "Add new threat or control: XYZ description"
   git push origin feature/add-new-threat-xyz
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
- **Check for Existing Issues/PRs**: Before submitting new ones, check if your idea or fix already exists.
- **Reference Issues**: In your PR description, reference issues your change addresses or closes (e.g., `Closes #123`).
- **Respectful Communication**: Keep discussions respectful and constructive.
- **Open Issues for Discussion**: If unsure, open a GitHub issue first to discuss your idea.

## Need Help?
If you have questions or need guidance, open an issue on GitHub or contact us via email at [mail@openasc.org](mailto:mail@openasc.org).

---
Thank you for helping us build a comprehensive and open TARA threat/control catalog!

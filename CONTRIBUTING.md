# Contributing to Sigilum

Thanks for helping build Sigilum.

Sigilum is focused on auditable identity and delegation for AI agents. Contributions include core protocol and product code, SDK/API integrations, testing infrastructure, documentation, and governance/compliance artifacts.

Agent-authored contributions are welcome. Every change must still have a clearly accountable human reviewer before merge.

## How You Can Contribute

- Implement protocol, identity, delegation, and verification logic.
- Build service/API/SDK/CLI components and integrations.
- Add tests, fixtures, and CI improvements.
- Improve or clarify documentation in `/docs`.
- Propose protocol ideas in `/docs/protocol`.
- Add architecture and trust-boundary docs in `/docs/architecture`.
- Add governance and compliance material in `/docs/governance` and `/docs/compliance`.
- Improve roadmap planning in `/docs/roadmap`.
- Open issues for bugs, ambiguities, or missing documentation.

## Ground Rules

- Keep changes focused and small.
- Prefer one logical change per pull request.
- Include rationale, especially for protocol or governance decisions.
- Do not include secrets, credentials, private keys, or internal customer data.
- A human contributor is accountable for every merged change, including agent-authored output.

## Workflow

1. Fork the repository and create a branch.
2. Make your changes with clear commit messages (see commit format below).
3. Run relevant validation for your change (tests/lint/type checks, plus docs/link checks where applicable).
4. Open a pull request using `.github/pull_request_template.md` and complete all required disclosure fields.

## Agent Contributions

Because Sigilum is accountability-focused infrastructure, autonomously agent-authored changes require explicit provenance and human review.

### Required Disclosure in PRs

If a PR is marked `Agent-authored`, include:

- The Sigilum namespace DID: `did:sigilum:<namespace>`
- The agent public key used for signing (`ed25519:<base64>` or fingerprint)
- Claim proof URL (BaseScan/Blockscan tx link) showing the key is in `approved` state
- Namespace accountability proof URL (GitHub URL) binding the DID to the accountable human/operator
- What the human validator verified (logic, tests, security, docs)
- Any residual uncertainty or an explicit `none`

### Sigilum Identity Requirement (Mandatory)

Agent-authored contributions are accepted only from agents with valid Sigilum identity and active authorization.

This requirement does not apply to `Human-only` PRs where a human is the author.

- The agent must have a Sigilum namespace DID (`did:sigilum:<namespace>`).
- The agent must use a service-specific Ed25519 keypair for contribution actions.
- The `(namespace, public_key, service)` claim must be in `approved` state at submission and merge time.
- Contributions from agents without valid Sigilum identity/authorization are not eligible for merge.

### Automated Enforcement

The CI workflow `.github/workflows/enforce-agent-contribution-policy.yml` validates PR disclosure fields.

- PRs that fail disclosure/format checks are blocked.
- Agent-authored PRs must provide Sigilum DID, agent key reference, approved-claim proof URL, and namespace accountability proof URL.
- Bot-authored PRs cannot be marked as `Human-only`.

### Human Accountability Rules

- A human sponsor must open the pull request and remain accountable for the result.
- Autonomous agents must not directly merge to protected branches.
- If a contributor cannot explain a generated change, that change should not be merged.

### Verification and Safety

- Run relevant checks before PR (tests, lint, typecheck, link checks where applicable).
- Validate generated output for correctness, security, privacy, and license compatibility.
- Remove hallucinated APIs, fabricated references, placeholder TODOs, and dead code.
- For protocol, security, governance, or compliance changes, include a short impact/risk note in the PR description.

### Optional Footers

Use Conventional Commits as usual. Optional commit or PR footers can be used when teams want extra traceability:

- `Reviewed-By: <human handle>`

## Commit Message Format

This project uses Conventional Commits (adapted from the referenced cheatsheet):

`<type>[optional scope]: <description>`

Examples:

- `feat(protocol): add delegation token claims draft`
- `fix(docs): correct revocation latency definition`
- `docs(architecture): add trust boundary diagram notes`
- `feat(api)!: change verification endpoint response`

### Allowed Types

- `build`: Build system or external dependency changes
- `ci`: CI/CD config and workflow changes
- `chore`: Maintenance changes not affecting behavior
- `docs`: Documentation-only changes
- `feat`: New functionality
- `fix`: Bug fixes
- `perf`: Performance improvements
- `refactor`: Internal changes without behavior change
- `revert`: Revert previous changes
- `style`: Formatting/whitespace/style-only changes
- `test`: Add or update tests

### Breaking Changes

Use either:

- `type(scope)!: description`
- or a footer:

`BREAKING CHANGE: <what changed and migration notes>`

If your change is breaking, include migration guidance in the PR description.

## Pull Request Checklist

- The PR title is clear and specific.
- Commits follow Conventional Commits.
- Documentation is updated for behavior/protocol changes.
- New terms are defined where first introduced.
- Related issues are linked (if applicable).
- Breaking changes are explicitly called out.
- If marked `Agent-authored`, provenance and disclosure details are included.
- Agent-authored changes include Sigilum DID, key reference, approved-claim proof URL, and namespace accountability proof URL.
- A human validator has validated generated content for correctness and safety.

## Documentation Conventions

- Put docs in the correct section under `/docs`.
- Keep headings descriptive and stable.
- Prefer short sections with explicit assumptions.
- Include examples for protocol semantics and edge cases.
- Cross-link relevant docs (architecture, protocol, governance, compliance).

## Review Expectations

Maintainers may request updates for:

- Technical correctness
- Security and trust model clarity
- Regulatory and auditability implications
- Naming, consistency, and information structure

## Community

Be respectful and constructive in issues and pull requests. Assume good intent, discuss tradeoffs directly, and keep feedback actionable.

## References

- Conventional Commits spec: https://www.conventionalcommits.org/en/v1.0.0/
- Cheatsheet reference: https://gist.github.com/Zekfad/f51cb06ac76e2457f11c80ed705c95a3

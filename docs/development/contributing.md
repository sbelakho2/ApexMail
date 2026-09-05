# Contributing to ApexMail

Thank you for your interest in contributing to ApexMail! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful** - Treat everyone with respect and kindness
- **Be inclusive** - Welcome people of all backgrounds
- **Be constructive** - Provide helpful feedback
- **Be collaborative** - Work together toward solutions

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. Use the **bug report template**
3. Include:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Node version, etc.)
   - Screenshots/logs if applicable

### Suggesting Features

1. **Search existing issues** for similar suggestions
2. Use the **feature request template**
3. Describe:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative solutions you considered
   - Any implementation ideas

### Contributing Code

#### 1. Fork and Clone

```bash
# Fork the repository on GitHub

# Clone your fork
git clone https://github.com/YOUR_USERNAME/ApexMail.git
cd ApexMail

# Add upstream remote
# The public repository opens with the first stable release; until then
# contributions are handled via support@apexmail.ee.
```

#### 2. Create a Branch

```bash
# Update main
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

#### 3. Make Changes

- Follow the [coding standards](../user-guide/getting-started.md)
- Write tests for new functionality
- Update documentation as needed

#### 4. Commit Changes

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git add .
git commit -m "feat(api): add email scheduling endpoint"
```

#### 5. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create Pull Request on GitHub
```

### Pull Request Guidelines

#### Title

Use conventional commit format:
- `feat(scope): description` - New feature
- `fix(scope): description` - Bug fix
- `docs(scope): description` - Documentation
- `refactor(scope): description` - Code refactoring

#### Description

Include:
- Summary of changes
- Related issue (e.g., "Closes #123")
- Breaking changes (if any)
- Screenshots (for UI changes)

#### Checklist

- [ ] Code follows project style guidelines
- [ ] Rust tests pass locally (`cargo test --manifest-path services/mail-server/Cargo.toml`)
- [ ] Formatting/lint checks pass for touched Rust code
- [ ] Documentation updated
- [ ] Commit messages follow conventions

> **Style guide:** The project uses an [`.editorconfig`](../../.editorconfig) for machine-readable style rules (indentation, charset, line endings). For visual and UI style, see the [Style System](style-system.md); the former binary `style_guide.docx` was removed from the docs tree (2026-09-05) — its content lives on in git history.

### Code Review Process

1. **Automated checks** run on PR creation
2. **Maintainer review** within 3 business days
3. **Address feedback** and update PR
4. **Approval** from at least one maintainer
5. **Merge** using squash and merge

---

## Development Setup

See the [root Contributing guide](../../CONTRIBUTING.md) and [README](../../README.md) for full setup instructions.

Quick start:
```bash
# Clone access is granted to contributors directly (support@apexmail.ee).
cd ApexMail

docker compose up -d postgres redis
cargo test --manifest-path services/mail-server/Cargo.toml
```

---

## Testing

### Running Tests

```bash
# Full workspace tests
cargo test --manifest-path services/mail-server/Cargo.toml

# Specific crate
cargo test --manifest-path services/mail-server/Cargo.toml -p api-server
```

### Writing Tests

- Write tests for all new functionality
- Maintain >80% code coverage
- Use descriptive test names
- Follow the Arrange-Act-Assert pattern

```rust
#[tokio::test]
async fn creates_user_with_valid_email() {
    let input = CreateUserInput {
        email: "test@example.com".into(),
        name: "Test".into(),
    };

    let result = service.create_user(input).await;

    assert!(result.success);
    assert_eq!(result.data.email, "test@example.com");
}
```

---

## Documentation

### Types of Documentation

| Type | Location | Purpose |
|------|----------|---------|
| API Reference | `docs/api/` | Endpoint documentation |
| Architecture | `docs/architecture/` | System design |
| User Guide | `docs/user-guide/` | End-user documentation |
| Development | `docs/development/` | Developer docs |
| Style System | `docs/development/style-system.md` | Premium UI and Apex icon standards |
| ADRs | `docs/adr/` | Decision records |

### Writing Documentation

- Use clear, concise language
- Include code examples
- Keep docs up-to-date with code changes
- Use proper Markdown formatting

### Architecture Decision Records

For significant decisions, create an ADR:

```markdown
# ADR-XXXX: Title

## Status
Proposed | Accepted | Deprecated | Superseded

## Context
What is the issue we're addressing?

## Decision
What did we decide to do?

## Consequences
What are the results of this decision?
```

---

## Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `feature` | New feature request |
| `docs` | Documentation improvements |
| `good first issue` | Good for newcomers |
| `help wanted` | Extra attention needed |
| `priority:critical` | Must be addressed immediately |
| `priority:high` | Important, should be addressed soon |
| `priority:low` | Nice to have |

---

## Release Process

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Workflow

1. Update `CHANGELOG.md`
2. Bump versions in the affected crate and SDK metadata
3. Create release PR
4. After merge, tag release
5. Publish the affected SDKs and Docker images

---

## Getting Help

- **Documentation**: Read the docs first — almost every contributor question is already answered there
- **Discussions**: support@apexmail.ee — single shared channel until the public repository opens
- **Issues**: For bugs and features

> Contributor support is async-first. We do not run a per-contributor or per-enterprise Discord.

### Response Times

| Priority | First Response | Resolution Target |
|----------|---------------|-------------------|
| Critical | 4 hours | 24 hours |
| High | 1 day | 1 week |
| Medium | 3 days | 2 weeks |
| Low | 1 week | Next release |

---

## Recognition

Contributors are recognized in:

- `CONTRIBUTORS.md` file
- Release notes
- Project README

Thank you for contributing to ApexMail! 🎉

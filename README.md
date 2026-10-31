# Terraform Infrastructure

This repository contains Terraform code for managing infrastructure on AWS and GCP.

## Project Structure

The repository is organized by cloud provider, with each provider having its own directory:

- **aws/**: Contains Terraform code for AWS resources.
- **gcp/**: Contains Terraform code for GCP resources.

Within each provider directory, the code is further divided into:

- **modules/**: Reusable Terraform modules for creating specific resources (e.g., an S3 bucket, a GCS bucket).
- **services/**: Configurations that use the modules to deploy services.

## Testing

This project uses the built-in Terraform testing framework. Tests are located in the `tests/` directory, and the structure of the `tests/` directory mirrors the structure of the main provider directories.

To run the tests, navigate to the specific test directory (e.g., `tests/aws/s3`) and run the following command:

```
terraform test
```

## Security Scan

To ensure infrastructure security and compliance with organizational policies, run the provided security check tool:

```bash
./scripts/security_check.sh
```

This tool uses **Trivy** to scan for misconfigurations and applies custom **OPA (Rego)** policies defined in the `policy/` directory. It covers:
- Encryption & Data Protection
- Least Privilege (IAM)
- Network Perimeter Defense
- Governance & Tagging
- Resilience & Anti-Ransomware measures

## CI/CD Security & Workflow Lockfiles

This repository adopts **GitHub Actions Workflow Dependency Lockfiles** (`.github/workflows/actions.lock`) to prevent CI/CD supply chain attacks while maintaining human-readable action tags.

- **Lockfile Verification**: Tested in CI via `.github/workflows/verify-lockfile.yml`
- **Documentation**: See [docs/articles/github_actions_workflow_lockfiles_ga.md](docs/articles/github_actions_workflow_lockfiles_ga.md)

## Security Architecture & Technical Articles

Detailed architectural proposals, defense-in-depth implementations, and security evaluations:
- [GitHub Actionsの「Workflow Lockfiles」がGAされたので実際に動かして検証してみた](docs/articles/github_actions_workflow_lockfiles_ga.md)
- [Jev-Inspired Dynamic AI Guardrail & Multi-Layer Defense](docs/articles/ai_security_guardrail_jev.md)
- [OSI-Based Zero-Trust Multi-Layer Security Architecture](docs/articles/zero_trust_defense_in_depth.md)

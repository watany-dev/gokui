# Release Evidence Template

Use this template to record release-readiness evidence for a candidate commit.

## Metadata

- Release date (UTC):
- Mode (`offline` or `online`):
- Candidate commit SHA:
- Reviewer:
- Environment:

## Quality Gates

- `make release-check`:
  - result:
  - notes:

- `make release-check-offline` (if used):
  - result:
  - reason online check unavailable:
  - notes:

- `make vuln` (required before final publication):
  - result:
  - timestamp:
  - notes:

## Contract Spot-Checks

- JSON error contracts:
  - result:
  - notes:

- Exit code contracts:
  - result:
  - notes:

- Docs sync tests:
  - result:
  - notes:

## Build Artifact

- `gokui` build result:
- post-check cleanup (`rm -f gokui`) completed:

## Approval

- Ready for release: `yes/no`
- Approver:
- Final remarks:

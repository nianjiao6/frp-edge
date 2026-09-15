# AGENTS.md

## Development Commands

### Build
- `make build` - Build both frps and frpc binaries
- `make frps` - Build server binary only
- `make frpc` - Build client binary only
- `make all` - Build everything with formatting

### Testing
- `make test` - Run unit tests
- `make e2e` - Run end-to-end tests
- `make e2e-trace` - Run e2e tests with trace logging
- `make alltest` - Run all tests including vet, unit tests, and e2e

### Code Quality
- `make fmt` - Run go fmt
- `make fmt-more` - Run gofumpt for more strict formatting
- `make gci` - Run gci import organizer
- `make vet` - Run go vet
- `golangci-lint run` - Run comprehensive linting (configured in .golangci.yml)

### Assets
- `make web` - Build web dashboards (frps and frpc)

### Cleanup
- `make clean` - Remove built binaries and temporary files

## Testing

- E2E tests using Ginkgo/Gomega framework
- Mock servers in `/test/e2e/mock/`
- Run: `make e2e` or `make alltest`

## Docs

- `docs/INTERFACE.md` - the `[tokenGate]` integration contract (for third-party frps operators)
- System-level design/architecture/contract docs live in the mtunnel-ctrl repo (`docs/`); this repo is the public open-source fork and carries no internal specs

## Git Conventions

- `<type>: <subject>` - conventional types (feat / fix / docs / test / chore); English subjects
- One commit = one theme; no Co-Authored-By trailer
- History here is PUBLIC (an open-source fork): never commit internal
  specs, credentials or business-private documents; squashing requires
  a force push - only with the user's explicit word, and never over
  commits someone else may have fetched

## Agent Runbooks

Operational procedures for agents are in `doc/agents/`:
- `doc/agents/release.md` - Release process

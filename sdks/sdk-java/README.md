# Sigilum Java SDK (Not Yet Supported)

This directory is currently a placeholder for the future Java SDK implementation.

## Current Status

- `sdk-java` is **not supported** for production use.
- No Java source implementation is currently shipped (`src/main/java` is absent).
- Maven metadata (`pom.xml`) exists only to reserve project structure and coordinates.

## What To Use Today

Use one of the supported SDKs instead:

- TypeScript: `sdks/sdk-ts`
- Go: `sdks/sdk-go`
- Python: `sdks/sdk-python`

## Support Gate

Java support should only be marked as available after all of the following are true:

- Java SDK source implementation is restored in-repo.
- Shared RFC 9421 conformance vectors pass in Java alongside TS/Go/Python.
- Java SDK README and examples reflect executable, tested APIs.

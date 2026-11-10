# Contributing

Thank you for helping. Issues and pull requests are welcome on GitHub.

- **Before a large change**, open an issue to agree on the approach. Guard is security code: a smaller change that is
  easy to review is more likely to land.
- **Build and test** as the README says: `dotnet build`, `dotnet test` (the integration tests need PostgreSQL), and
  `dotnet pack`. A pull request runs the same in CI, on GitHub Actions.
- **Keep what hosts rely on.** Error codes, routes, claims, policies, the names in `GuardNames` and the DTOs' shapes
  are a contract: changing one is a breaking change and goes in the CHANGELOG under the version that makes it.
- **Migrations.** Never edit a released migration. Add a new one, in the same EF Core context.
- **No product's name:** AbpGuard names no product but its own, in code, texts, samples or docs. CI's
  `scripts/check-names.sh` fails the build otherwise.
- **Tests** come with the change: a unit test for logic, and a test through the sample host for anything a host sees.
- **CHANGELOG.md:** write what changes for someone using the packages under `## [Unreleased]`.

By contributing you agree that your contribution is licensed under the Apache License, Version 2.0.

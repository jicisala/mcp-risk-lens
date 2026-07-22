# Contributing

Small, reviewable pull requests are welcome.

1. Add a synthetic test that demonstrates the risk or false positive.
2. Implement the narrowest deterministic rule that addresses it.
3. Ensure evidence never includes a raw credential.
4. Run `ruff check src tests` and `pytest -q`.
5. Explain rule limitations and likely false positives in the pull request.

Do not submit customer configurations, real credentials, non-public incident data, or exploit code
for systems you are not authorized to test.


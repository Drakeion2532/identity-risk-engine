# Security policy

This is a portfolio and research project, not a hosted service. If you find a security issue in the
code (for example an input that crashes the API or bypasses a decision), please email
**shubhanpunde@gmail.com** with steps to reproduce rather than opening a public issue. I aim to reply
within a few days.

Every push runs `bandit` (static analysis) and `pip-audit` (known-vulnerable dependencies) in CI.

# Stan Mic Bridge

- Canonical repository: https://github.com/stantheman0128/stan-mic-bridge
- Publish and push using the `stantheman0128` GitHub account. Verify `gh api user --jq .login` with the process-scoped credential before any write. Do not switch the machine-wide active account, which other tasks may use.
- Preserve existing local signing identity and update verification boundaries.
- Mac source changes require the `Mac build and update checks` workflow to pass on the release commit. Publish its tested universal artifact with a matching SHA-256 manifest and source archive.
- Do not restart or modify the live Windows receiver merely to validate Mac UI or release changes.

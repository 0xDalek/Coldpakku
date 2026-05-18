# Contributing to GBA Signer

Thanks for your interest. This project is an experimental Ethereum
hardware wallet running on a Game Boy Advance, and it benefits a lot
from external eyes — code review, bug reports, fuzzing, documentation
fixes, dApp compatibility reports, hardware testing, and so on.

Please read this short document before opening a PR. It will save us
both time.

## Code of conduct

Be respectful and assume good faith. Disagree about ideas, not about
people. That is the whole policy.

## Before you start

- Read the [README](README.md) for an overview of the architecture,
  the security model, and how to build / install the three components
  (ROM, Pico bridge, browser extension).
- Skim the **Roadmap** section in [`RELEASE_NOTES.md`](RELEASE_NOTES.md)
  for areas where work is already planned. If you want to take on one
  of those items, opening an issue first to coordinate is helpful but
  not required for small things.
- For anything non-trivial (new opcodes, new protocol fields, large
  refactors, new dependencies), please open an issue describing the
  approach before writing the code. We would rather discuss the design
  upfront than ask you to redo a finished PR.

## Reporting bugs

- **Security vulnerabilities** → do not open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- **Functional bugs** → open a GitHub issue with: what you did, what
  you expected, what happened, and (if possible) the firmware version,
  the extension version, the chain you were on, and the dApp.

## Building

The build instructions live in the [README's "Build from source"
section](README.md#build-from-source-developers-only). They cover the
ROM (`devkitARM`), the browser extension (`npm`), and the Pico bridge
firmware.

If your change does not touch the firmware, you do not need
`devkitARM` installed — `npm` (for the extension) or Python 3.10+ (for
host tools) is enough.

## Style by language

### C (firmware, `src/`)

- Must compile cleanly with the flags used by [`build.sh`](build.sh)
  (`-Wall -Wextra -Wno-unused-parameter`). No new warnings.
- Stick to portable C; do not introduce GCC-only extensions unless
  there is no reasonable alternative, and document the reason in a
  comment if you do.
- No dynamic allocation. The firmware has no heap; use static buffers
  and stack with bounded sizes.
- Prefer `static` for anything that is not part of a module's public
  API. Public APIs go in the matching `.h`.
- All buffers exposed to host input (UART, RLP, ABI, TLV) must have
  explicit bounds checks. This is the highest-risk area of the code.
- Zeroize secret material (`memset` to 0) before any early return.
- Match existing naming: `snake_case` for functions and locals,
  `UPPER_SNAKE` for macros and constants.

### TypeScript (extension, `extension/`)

- Must pass `npm run typecheck` and `npm run build` with no new
  warnings.
- Follow the style of the file you are editing. Do not reformat the
  whole file as part of a feature PR.
- Strict TypeScript: avoid `any`; if you need to escape the type
  system, isolate it in a small helper and document why.
- Keep the per-method handlers under `extension/src/background/methods/`
  small and auditable. Cross-method helpers go in `_shared.ts`.

### Python (host tools, `pc/` and `pico/`)

- PEP 8-ish. No formatter is enforced — just keep it readable.
- Python 3.10+ is the supported floor.
- For `pico/` (MicroPython) keep dependencies to the standard library
  only; the Pico does not run pip.

## Tests

There is no full CI yet; please run the relevant tests locally before
opening a PR.

- **Firmware changes** → run `tests/algorithm_verify.py` (the
  `tests/` directory is gitignored because it contains a literal test
  mnemonic; the README explains how to regenerate it on your machine).
  For protocol or signing changes, also run `pc/test_signing_v4.py`
  against an mGBA instance with `-l 0.0.0.0:12345`.
- **Extension changes** → `npm run typecheck` in `extension/`. For UI
  or flow changes, do a manual end-to-end test against a real or fake
  GBA.
- **Host-tool changes** → `python3 -m compileall pc/` at minimum.
  `pc/test_e2e.py` is the canonical end-to-end smoke test.

## Pull request checklist

Before opening a PR, please confirm:

- [ ] The code compiles cleanly with no new warnings.
- [ ] Relevant tests pass locally (see above).
- [ ] Firmware PRs: the ROM still builds reproducibly. If the SHA-256
      changes intentionally, mention it in the PR description.
- [ ] Commit messages describe the *why*, not just the *what*.
- [ ] The PR description explains the motivation and any trade-offs.
- [ ] Documentation (README, RELEASE_NOTES, inline comments) is
      updated if behaviour changed.

## Security

If you believe you have found a vulnerability, **do not open a public
issue or PR**. Follow the process in [`SECURITY.md`](SECURITY.md). DMs
to [`@coldpakku`](https://x.com/coldpakku) on X are the preferred
first contact.

## Licensing of contributions

This project is licensed under [Apache License 2.0](LICENSE). By
submitting a contribution, you agree that it will be licensed under
the same terms (Apache 2.0, Section 5: "Submission of Contributions").
No separate CLA is required.

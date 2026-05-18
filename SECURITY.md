# Security Policy

GBA Signer (Coldpakku) is an experimental hardware wallet running on a
Game Boy Advance. Until we reach `v1.0.0` the project should be treated
as **pre-release software**: do not store funds you cannot afford to
lose, and please help us harden it by reporting issues responsibly.

## Supported versions

Only the latest `v0.1.x` line receives security fixes. Older snapshots
and forks are out of scope.

| Version | Supported |
|---------|-----------|
| `0.1.x` | Yes       |
| `< 0.1` | No        |

## Reporting a vulnerability

**Please do not open a public GitHub issue, pull request, or discussion
for security reports.** Public disclosure before a fix is shipped puts
every user at risk.

Preferred contact:

- **DM on X to [`@coldpakku`](https://x.com/coldpakku)**.

Your first message can be short — for example, "I think I found a
vulnerability in GBA Signer, can we move to a private channel?". If the
report contains sensitive details (exploit code, key material, PoCs)
you can request an encrypted channel (PGP email, Signal, etc.) in that
first DM and we will set one up before you share the details.

Please include, when you can:

- Affected component (firmware / extension / Pico bridge / protocol).
- Version or commit hash you tested against.
- A description of the issue and, if possible, a reproducer.
- The impact you believe the issue has (e.g. seed exfiltration, signing
  the wrong hash, denial of service).

We will acknowledge the report within **72 hours** and aim to provide a
substantive response (triage, severity, planned fix) within **7 days**.

## Disclosure timeline

The default coordinated disclosure window is **90 days** from the
initial report. If a fix is complex or requires upstream coordination
(e.g. a third-party library), we may agree to extend it. If we are
unresponsive past the agreed window, you are free to disclose publicly.

We will credit reporters in the relevant `RELEASE_NOTES.md` entry and
in the commit message of the fix, unless you explicitly request to
remain anonymous.

## Scope

In scope (please report):

- Firmware running on the GBA — everything under `src/`.
- Browser extension — everything under `extension/src/`.
- Pico bridge firmware — `pico/main.py`.
- Host-side tools that touch the protocol — `pc/*.py`.
- The GBA UART protocol itself and any framing / parser code.

Out of scope (please report upstream instead, or not at all):

- Vulnerabilities in vendored third-party libraries
  (`third_party/micro-ecc`, `third_party/crypto-algorithms`,
  `third_party/libgba`). Please report those to their upstream
  maintainers; if you also want to flag them to us so we can update the
  pinned version, that is welcome.
- Attacks that require **physical access** to the cartridge, the GBA,
  or the user's PC. Physical-attack resistance is explicitly outside
  the threat model — see `RELEASE_NOTES.md` and the README's "Security
  model" section.
- Attacks that require the user to install a **maliciously modified
  toolchain** (compromised devkitPro, compromised `npm` registry,
  compromised Python wheels). Reproducible builds are the mitigation
  here, not the report channel.
- Social-engineering attacks that do not have a software component on
  our side (e.g. "the user typed their seed into a phishing page" is
  out of scope; "the extension's connect screen can be spoofed by a
  malicious page" is in scope).

## Bug bounty

There is **no monetary bug bounty** at this time. The project is run by
volunteers without external funding. We will, however, credit you
publicly (see "Disclosure timeline" above) and we appreciate every
report.

## Hall of fame

This section will list researchers who have responsibly disclosed
issues. Currently empty — be the first.

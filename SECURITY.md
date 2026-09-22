# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, report them privately through GitHub's private vulnerability reporting:

1. Go to the [**Security** tab](https://github.com/WebOfTrust/keripy/security) of this repository.
2. Click **Report a vulnerability** to open a private advisory draft.
3. Fill in as much detail as you can (see "What to include" below).

This routes the report directly and privately to the maintainer, who is notified by GitHub. Your report is not visible to the public.

### What to include

A good report helps us confirm and fix the issue quickly. Where possible,
please include:

- The type of issue (e.g. injection, data exposure, auth bypass, dependency vuln).
- The affected component, file path, and/or version or commit.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if you have it.
- The impact: what an attacker could do with this.

## Our Commitment

We follow a responsible (coordinated) disclosure model:

- **Acknowledgement:** We will acknowledge your report within **5 business days**.
- **Assessment:** We will investigate and let you know whether we agree it is a vulnerability, and our planned course of action.
- **Fix timeline:** For issues we confirm, we aim to release a fix within **30 days** of acknowledgement. Complex issues may take longer; if so, we will keep you informed of progress.
- **Coordination:** We will coordinate the timing of public disclosure with you and credit you in the published advisory unless you prefer to remain anonymous.

We ask that you give us a reasonable opportunity to address the issue before
any public disclosure.

## No Bug Bounty

Keripy is an open-source project run by a coalition of the willing. **We do not offer a paid bug bounty or any other monetary reward** for vulnerability reports. We genuinely appreciate responsible disclosure and are happy to publicly credit reporters in the advisory, but please report only because you want to help — not in expectation of payment.

## Supported Versions

We are primarily focused on keripy 2.x right now; that's the version on main and on 2.1*. The latest version of 1.x keripy receives our active attention; currently, this is the 1.3 branch. Vulns in other branches are not likely to be prioritized.

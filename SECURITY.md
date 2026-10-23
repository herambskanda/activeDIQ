# Security policy

activeDIQ manages Active Directory with delegated rights over users, groups and passwords, and
parts of it are designed to run on domain controllers. A vulnerability in it can be a vulnerability
in your domain. We want to hear about every one, and we will treat your report that way.

## Report a vulnerability privately

**Use GitHub private vulnerability reporting:**
<https://github.com/herambskanda/activeDIQ/security/advisories/new>
(or the **Security** tab of this repository → **Report a vulnerability**).

Only you and the maintainers can see the report. Please include:

- the component (server, API, console, self-service portal, connector, DC-side component,
  installer or update channel) and the commit or version;
- the steps to reproduce, and what an attacker gains;
- whether you believe it is already known or exploited.

**Do not open a public issue, pull request or discussion about a vulnerability.**
If the private form is unavailable to you, open a public issue titled exactly
`Security contact request` with **no technical details**. We will reply in that issue with a private
channel and then close it.

## What we commit to

These are targets we hold ourselves to and publish so you can measure us against them:

| Step | Target |
| --- | --- |
| Acknowledge your report | within 3 business days |
| Triage: confirm or decline, give you a severity | within 7 days of the report |
| Fix released, **critical** severity | within 14 days of triage |
| Fix released, **high** severity | within 30 days of triage |
| Fix released, medium and low severity | in a scheduled release; we tell you which one |
| Security advisory published | **the same day the fix ships** |

- Severity is scored with CVSS. We publish the score once, and the advisory and the CVE record carry
  the same score.
- Until activeDIQ is its own CVE Numbering Authority, CVE IDs are requested through GitHub's
  CNA from the private advisory. We are working towards our own CNA.
- If we are going to miss a target, we tell you before it passes, with the reason and a new date.
- We credit you in the advisory by the name you choose, or not at all if you prefer.
- Please give us until the fix ships, or 90 days from your report, whichever comes first, before
  you disclose publicly. If that does not work for you, tell us and we will agree on a date.

## Safe harbour

We consider security research done in good faith and within this policy to be authorised. For such
research we will not pursue or support legal action against you, and if a third party takes action
against you for it, we will make it known that your work was authorised by this policy.

Good faith means that you:

- test only against an installation of activeDIQ that you own or are allowed to test, and a
  directory you own or are allowed to test — never another organisation's domain, tenant or
  installation;
- do not access, change, keep or share data that is not yours beyond what is needed to show the
  issue, and delete anything you obtained once the report is closed;
- do not degrade service for others (no denial-of-service, no mass account lockouts), and do
  not use social engineering, phishing or physical attacks against us or anyone else;
- report to us privately and give us the time described above before you disclose.

If you are unsure whether something is in scope, ask in your private report first.

## Scope

In scope: everything in this repository, including the server, API and PowerShell module, web
console, self-service portal, directory connectors, DC-side components, installers, update and
release signing, and the factory tooling that builds them.

Out of scope: vulnerabilities in Active Directory, Windows or Entra ID themselves (report those to
[Microsoft MSRC](https://msrc.microsoft.com/report)), and in third-party dependencies unless
activeDIQ uses them in a vulnerable way (report those upstream; tell us too, so we can ship the fix).

## Supported versions

activeDIQ has no customer release yet. Security fixes land on the `main` branch. This section will
list the supported release lines from the first release on.

## Machine-readable contact

[`.well-known/security.txt`](.well-known/security.txt) ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116))
carries the same contact. It has an expiry date and CI fails 30 days before it, so a stale file
cannot ship.

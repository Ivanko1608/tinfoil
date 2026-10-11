# leak-check

**Ask Claude "is this safe to post?" and get a real answer.**

A free, open-source [Claude skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) that checks anything you're about to make public: a repo, a screenshot, a PDF, a blog post. It looks for credentials, personal data, and the stuff you didn't realize you were giving away.

You deleted that `.env` file. Git didn't.

```text
$ leakscan.py my-side-project --history
leakscan: 2 files, 2 commits | 1 critical, 2 high, 3 medium, 0 low, 1 info

== CRITICAL ==
  secret/aws_access_key  .env:1 [history:9c02b57af9]
      AKIA••••••••••VB (20 chars)   fp:34dde4add3d4
      note: not in current files but still in git history

== HIGH ==
  file/risky_file  .env [history]
      note: environment file - deleted from HEAD but still in history
  metadata/exif_gps  docs/screenshot.jpg
      40.4••••••••••61 (17 chars)   fp:6a34d1276e1b
      note: image embeds GPS location

== MEDIUM ==
  identity/commit_identity  .git [history]
      Jane••••••••••m> (32 chars)
      note: author/committer identity is published with every commit
  identity/home_path  README.md:2
      note: home path reveals local username
  infra/internal_hostname  README.md:3
```

That's real output from a two-commit demo repo. The skill then has Claude read the code, docs, commit messages, and images the way a bored stranger with a search engine would. You get back a verdict (**Safe to publish**, **Fix first**, or **Do not publish (yet)**) plus exact fixes.

## Why this exists

Secret scanners are good at finding API keys. But most of what gets people doxxed, fired, or phished isn't an API key:

- the photo in your README with GPS coordinates of your flat
- your personal Gmail on every commit of the "anonymous" project
- `/Users/firstname.lastname/` in a stack trace
- the client's name in a test fixture, or a Jira ticket key in a commit message
- the "deleted" text in a Word doc's tracked changes
- a screenshot whose browser tabs say exactly where you work
- "away all of August" in a blog post, next to your city

Regex can't catch most of that. An LLM reading carefully can. This skill combines both.

## How it works

Three layers, each catching what the others miss:

1. **Mechanical scan** with [`leakscan.py`](skills/leak-check/scripts/leakscan.py): pure Python stdlib, no dependencies, read-only.
   - **Credentials:** AWS, GitHub, GitLab, Slack, Stripe, Google, Anthropic, OpenAI, Hugging Face, Telegram, SendGrid, npm, WireGuard, JWTs, private keys, passwords in URLs and `.env` files
   - **Personal data:** emails, phone numbers, dates of birth, street addresses
   - **Financial and government IDs, checksum-validated:** cards (Luhn), IBANs (mod-97), Spanish DNI/NIE, Russian SNILS/INN, passports, US SSNs
   - **Infrastructure:** internal hostnames, IPs, Slack/Atlassian/SharePoint workspace URLs, Google Docs links, "CONFIDENTIAL" markers
   - **Identity:** home-directory paths, `user@hostname` shell prompts, GPS coordinates
   - **Metadata:** EXIF GPS, owner and serial in JPEG/PNG/WebP/TIFF; author, comments and tracked changes in Office files; author and earlier revisions in PDFs
   - **Git:** every commit on every branch, files deleted but still in history, author emails, commit timezones
   - **Risky files:** `.env`, SSH keys, `.har`, `tfstate`, shell history, database dumps, and more
2. **Contextual read by Claude.** It works through a [checklist](skills/leak-check/references/contextual-leaks.md) of what pattern matching can't see: employer and client exposure, other people's data, location and routine, identity linkage between personas, and details that are harmless alone but identifying together.
3. **Remediation.** The [playbook](skills/leak-check/references/remediation.md) says rotate first, because deleting a pushed secret is cosmetic. It also covers rewriting history properly, stripping metadata without leaving it recoverable, and prevention setup (noreply email, pre-commit hook, push protection).

A few design decisions:

- **Findings are masked.** The report shows `AKIA••••••••••VB`, never the full value. Your chat transcript doesn't become a second leak.
- **It never runs your project** and never sends your material anywhere. The scanner only reads files.
- **It asks who you're publishing as.** Your email on your portfolio is fine. Your email in a project meant to be unlinkable to you is the worst finding in the repo. Severity depends on intent.
- **It covers Claude's own writing.** When Claude drafts a public README or post, it checks that it didn't "helpfully" include your employer's name from earlier in the chat.
- **It's honest about coverage.** Every report says what *wasn't* checked (no `.git` folder, video, HEIC, scanned PDFs). A clean scan isn't presented as a certificate.

## Install

### Claude Code (recommended)

```text
/plugin marketplace add Ivanko1608/claude-privacy
/plugin install leak-check@claude-privacy
```

### Claude.ai / Claude Desktop

1. Download [`dist/leak-check.zip`](dist/leak-check.zip).
2. Go to **Settings → Capabilities → Skills** and upload it. Code execution needs to be enabled.

### Manual

```bash
git clone https://github.com/Ivanko1608/claude-privacy
cp -r claude-privacy/skills/leak-check ~/.claude/skills/
```

## Use it

Just talk normally. It triggers on its own:

> "I'm about to make this repo public, anything I should worry about?"

> "Is this screenshot safe to post on Twitter?"

> "Check this blog post draft before I publish it."

> "Scan the full git history, I think I committed a key at some point."

### Use the scanner without Claude

`leakscan.py` is a single file with no dependencies, so it works on its own:

```bash
S=skills/leak-check/scripts/leakscan.py
python3 $S path/to/repo --history        # working tree + every commit, every branch
python3 $S path/to/repo --staged         # just what you're about to commit
python3 $S photo.jpg report.pdf deck.pptx
python3 $S --stdin < blog-post.md
python3 $S . --json --fail-on medium     # for CI
```

It exits `1` when something reaches `--fail-on` (default `high`), so it drops straight into a pre-commit hook or CI step. This repo scans itself too; see [`.leakscanignore`](.leakscanignore) for the handful of intentional matches.

### Personal denylist

The scanner can't know that "Acme" is your employer or that your kid's name is Sam. You can tell it:

```text
# ~/.config/leakscan/denylist.txt   (never commit this file)
Jane Q. Example
AcmeCorp
re:acme[- ]?(internal|corp)
PROJ-
```

### False positives

Add `fp:<fingerprint>`, `detector:<id>`, or a path glob to a `.leakscanignore` file in the repo root. Fingerprints are truncated hashes, so the file is safe to commit.

## What it isn't

- **Not a replacement for [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog).** They cover hundreds more credential formats and can verify whether a key is live. Run one of them in CI too. This tool focuses on what they skip: personal, location, identity and business exposure.
- **Not a guarantee.** It doesn't cover video, audio, HEIC, text inside images (Claude still *looks* at images during the contextual pass), or compressed PDF streams.
- **Not legal advice**, including when it flags that something looks like your employer's code.

## Contributing

Issues and PRs are welcome, especially new credential formats, national ID checksums for more countries, and false-positive reports. Run the tests with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/build.py   # rebuild dist/leak-check.zip after changing the skill
```

Test fixtures are assembled at runtime from string fragments, so this repo never contains anything secret-shaped. Please keep it that way.

## License

[MIT](LICENSE). Free to use, fork, and ship.

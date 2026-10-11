# tinfoil

**Your paranoid friend reads it before the internet does.**

Ask Claude "is this safe to post?" and get a real answer. You don't have to wear the hat; it wears it for you.

A free, open-source [Claude skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) that reviews anything you're about to make public (a repo, a screenshot, a PDF, a blog post) the way someone trying to find you would. Then it tells you whether to ship it.

Here's what that looks like on a small demo repo. The company and customer names are fictional; the report is real skill output.

> **You:** I'm about to make order-sync public on my GitHub. Anything I should worry about?
>
> **Claude:** Quick question first: is this going out under your real name, or should it be unlinkable to you?
>
> **You:** Real name, it's for my portfolio.
>
> **Claude:**
>
> ### Verdict: Do not publish (yet)
>
> The leaked key is fixable in ten minutes. The bigger problem is that this repo looks like your employer's code, and it makes you easy to identify.
>
> **Must fix**
>
> 1. **AWS key in git history.** `.env` was deleted in `8883ac8`, but `AKIA••••••••••VB` is still in `38f4844`. Anyone who clones the repo gets it, and bots scrape new public repos within minutes. **Rotate the key first**, then strip it with `git filter-repo`. Deleting the file did nothing.
> 2. **This may not be yours to publish.** The first commit message is *"initial import from contoso-logistics/order-sync"*, and the README says you wrote it while working on Contoso's logistics team. Even with every secret stripped, code written for an employer usually belongs to the employer. Check your contract before publishing anything. (Not legal advice, but definitely a question to settle first.)
> 3. **Customer data in `tests/fixtures/orders.csv`.** Northwind Traders and Fabrikam, with cities and order totals. If those are real Contoso customers, you'd be publishing a third party's business data. Replace them with obviously synthetic rows.
> 4. **The README identifies you, and your routine.** *"Only backend dev on Contoso's logistics team"* + *"I'm in Toronto"* + *"push most changes before 9am"* narrows it to one person. Commit timestamps (−04:00, 07:41 and 08:12) confirm the schedule. On top of that, `docs/dashboard.jpg` has GPS coordinates embedded, 43.65, −79.38, which is downtown Toronto. None of these is a problem alone; together they give your employer, city and daily routine to anyone who reads it.
>
> **Should fix**
>
> - `orders-replica.contoso.internal`, *"fell over at ~4M rows"* and *"hotfix for CL-2291 prod outage"* map a real company's internal infrastructure and incidents. Generalize them or cut them.
> - Both commits carry a personal Gmail address. Switch to your GitHub noreply address and rewrite the author with `--mailmap`.
> - `/Users/jsmith/` in the README shows your local username. Use `cd order-sync` instead.
>
> **Coverage:** 3 files and 2 commits on all branches; image checked for metadata only (the demo image has no visual content to review). No issues, PRs or packages exist yet. Step-by-step fixes are in `references/remediation.md`; I can walk you through them.

Only the first item and half of the fourth come from pattern matching. A secret scanner would have flagged the key, the GPS tag and the hostname, and missed the rest: whose code it is, whose data it is, and how three harmless sentences identify one person.

## What the skill does that a scanner can't

Secret scanners are good at API keys. But most of what gets people doxxed, fired or phished isn't an API key. The skill makes Claude do the parts that take judgment:

- **Asks who you're publishing as.** Your email on your portfolio is fine; the same email in a project meant to be unlinkable to you is the worst finding in the repo. The severity of everything depends on that answer.
- **Reads like an adversary.** It goes through READMEs, comments, commit messages, branch names, fixtures, notebooks, CI files and docs, asking one question: could a stranger get from this to a name, address, employer, client, family member, or a way into a system?
- **Looks at your images.** Browser tabs, taskbars, notification previews, terminal prompts, reflections, street signs through the window.
- **Connects the dots.** City + job title + company size + timezone + one anecdote is often enough to name someone. It reports that as a single finding, not five nitpicks.
- **Flags work that isn't yours to share.** Employer code, client data, internal ticket keys and codenames, even with every secret stripped out.
- **Gives a verdict, not a dump.** *Safe to publish*, *Fix first*, or *Do not publish (yet)*. Then must-fix / should-fix / your-call, with false positives triaged away instead of buried under 40 maybes.
- **Knows the fix.** Rotate before you rewrite history, because deleting a pushed secret is cosmetic. Strip PDF metadata in a way that doesn't leave it recoverable. Watch out for screenshot crops that keep the uncropped data.
- **Checks its own writing.** When Claude drafts your README, blog post or video description, it makes sure it didn't "helpfully" include your employer's name from earlier in the conversation.
- **Never repeats your secrets.** Findings are masked (`AKIA••••••••••VB`), so the chat transcript doesn't become a second leak. It never runs your project or sends your material anywhere.
- **Is honest about coverage.** Every report says what *wasn't* checked. A clean report isn't a certificate.

The full checklist Claude works through is in [`references/contextual-leaks.md`](skills/tinfoil/references/contextual-leaks.md). It's worth a read even if you never install anything.

## Under the hood

To get the mechanical part right, the skill ships with [`leakscan.py`](skills/tinfoil/scripts/leakscan.py), a dependency-free, read-only Python scanner that Claude runs first. It's built for high recall on known patterns; triage and judgment happen afterwards.

<details>
<summary>What the scanner covers</summary>

- **Credentials:** AWS, GitHub, GitLab, Slack, Stripe, Google, Anthropic, OpenAI, Hugging Face, Telegram, SendGrid, npm, WireGuard, JWTs, private keys, passwords in URLs and `.env` files
- **Personal data:** emails, phone numbers, dates of birth, street addresses
- **Financial and government IDs, checksum-validated:** cards (Luhn), IBANs (mod-97), Spanish DNI/NIE, Russian SNILS/INN, passports, US SSNs
- **Infrastructure:** internal hostnames, IPs, Slack/Atlassian/SharePoint workspace URLs, Google Docs links, "CONFIDENTIAL" markers
- **Identity:** home-directory paths, `user@hostname` shell prompts, GPS coordinates
- **Metadata:** EXIF GPS, owner and serial in JPEG/PNG/WebP/TIFF; author, comments and tracked changes in Office files; author and earlier revisions in PDFs
- **Git:** every commit on every branch, files deleted but still in history, author emails, commit timezones
- **Risky files:** `.env`, SSH keys, `.har`, `tfstate`, shell history, database dumps, and more

</details>

## Install

### Claude Code (recommended)

```text
/plugin marketplace add Ivanko1608/tinfoil
/plugin install tinfoil@tinfoil
```

### Claude.ai / Claude Desktop

1. Download [`dist/tinfoil.zip`](dist/tinfoil.zip).
2. Go to **Settings → Capabilities → Skills** and upload it. Code execution needs to be enabled.

### Manual

```bash
git clone https://github.com/Ivanko1608/tinfoil
cp -r tinfoil/skills/tinfoil ~/.claude/skills/
```

## Use it

Just talk normally. It triggers on its own:

> "I'm about to make this repo public, anything I should worry about?"

> "Is this screenshot safe to post on Twitter?"

> "Check this blog post draft before I publish it."

> "Scan the full git history, I think I committed a key at some point."

> "Write a LinkedIn post about this project." (The skill checks Claude's own draft before handing it over.)

### Bonus: the scanner on its own

`leakscan.py` is a single file with no dependencies, so you can also use it without Claude, in a pre-commit hook or in CI:

```bash
S=skills/tinfoil/scripts/leakscan.py
python3 $S path/to/repo --history        # working tree + every commit, every branch
python3 $S path/to/repo --staged         # just what you're about to commit
python3 $S photo.jpg report.pdf deck.pptx
python3 $S --stdin < blog-post.md
python3 $S . --json --fail-on medium     # for CI
```

It exits `1` when something reaches `--fail-on` (default `high`), so it drops straight into a pre-commit hook or CI step. This repo scans itself too; see [`.leakscanignore`](.leakscanignore) for the handful of intentional matches.

### Personal denylist

Neither Claude nor the scanner can know that "Acme" is your employer or that your kid's name is Sam. Tell them once, and the skill offers to draft this list for you:

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
python3 scripts/build.py   # rebuild dist/tinfoil.zip after changing the skill
```

Test fixtures are assembled at runtime from string fragments, so this repo never contains anything secret-shaped. Please keep it that way.

## License

[MIT](LICENSE). Free to use, fork, and ship.

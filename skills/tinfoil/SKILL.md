---
name: tinfoil
description: Checks anything about to go public for secrets, personal data, and work information that shouldn't be online - git repos including full history, images (EXIF/GPS), PDFs, Office files, screenshots, and plain text. Use when the user is about to make a repo public, push code, publish a package or Docker image, or post a README, blog post, video description, portfolio piece, or proposal; when they ask whether something is safe to post, or want it scanned, redacted, or sanitized; and before Claude hands over anything it wrote for a public audience, even unasked.
---

# Tinfoil

Goal: nothing reaches the public internet that the user would not knowingly publish. That covers credentials, personal identifiers, and the softer stuff that has no fixed shape - employer and client details, internal infrastructure, people in the user's life, location and routine, and combinations of harmless details that together identify someone.

Three layers, each catching what the others miss:

1. **Mechanical scan** - `scripts/leakscan.py` (stdlib Python, read-only). Known shapes: API keys, private keys, emails, phones, cards (Luhn), IBANs (mod-97), Spanish DNI/NIE and Russian SNILS/INN (checksums), passports with context, internal hostnames, IPs, SaaS workspace URLs, home paths, shell prompts, GPS coordinates, confidentiality markers, risky files (.env, keys, shell history, HAR, tfstate, DB dumps), image EXIF (GPS, owner, serial), PDF metadata and revisions, Office authors/comments/tracked changes, git commit identities and timezones, and everything ever committed on any branch. High recall on patterns, zero understanding.
2. **Contextual read** - you. Things regex cannot see. Read `references/contextual-leaks.md` before this step.
3. **Remediation** - `references/remediation.md`. For a pushed secret the fix is rotation; deleting it is cosmetic.

## Ground rules

- **Never echo secrets or identifiers in full.** Reports use the scanner's masked form plus `path:line` and fingerprint. Use `--reveal` only if the user explicitly asks, and say that the chat transcript will then contain the raw values.
- **Do not move the material somewhere else to check it.** No pasting repo contents, drafts, or findings into web search or other tools. Whether to check if an email or handle is already public is the user's decision; ask first.
- **Do not execute the project.** No installing its deps, running its scripts, tests, or hooks. The scanner only reads.
- **History is part of the repo.** Anything that was ever committed and pushed is presumed compromised even if deleted since. Force-pushed commits stay reachable on GitHub by SHA, in forks, and in PR refs.
- **Calibrate.** Look at the surrounding code before calling a regex hit real. Two genuine problems buried under forty low-confidence ones is a failed report. State confidence where it is not obvious.
- **Severity depends on intent.** The user's public email on their portfolio is fine; the same email in a project meant to be unlinkable to them is the worst finding in the repo. Establish the posture first (step 0).

## Step 0 - Identity posture and ownership

If it isn't clear from context, ask one question: is this published under their real name, under a public brand or handle that is openly theirs, or meant to be unlinkable to them? This decides what matters:

- **Real name / open brand** - focus on employer and client data, other people's data, credentials, home location, finances.
- **Unlinkable** - everything above plus every linkage vector: commit email and name, GPG and SSH key reuse, timezone and working hours, home paths, writing tics, cross-links, shared analytics IDs, avatars. See the identity-linkage section of the reference.

If they don't say, assume "public under their own brand, not anonymous" and state that assumption in the report.

Also check ownership: code, docs, or data produced for an employer or client may not be the user's to publish at all, even with every name stripped. Flag that as a finding (not legal advice) when the material looks like it came from work.

## Step 1 - Personal denylist

The scanner can't know what is private for this particular user. A denylist fixes that: real full name (when publishing under a handle), family members' names, home street and building, employer, clients, internal project codenames, internal domains, Jira project keys, colleagues' names, private phone and email, licence plates.

Format, one entry per line, `#` for comments, `re:` prefix for a regex:

```
# people
Jane Q. Example
re:\bjqe@
# work
AcmeCorp
re:acme[- ]?(internal|corp)
PROJ-
```

Lookup order: `--denylist PATH`, `$LEAKSCAN_DENYLIST`, `~/.config/leakscan/denylist.txt`. If none exists, offer to draft one from what the user tells you (and, with their OK, from context you already have). The denylist is itself sensitive: write it outside the repo, never commit it. On claude.ai the container resets between sessions, so the user keeps it locally and uploads it when needed.

## Step 2 - Mechanical scan

The script lives next to this file; call it by full path.

```bash
S=<skill-dir>/scripts/leakscan.py
python3 $S <repo> --history                 # working tree + every commit on every branch
python3 $S <repo> --staged                  # only what's staged (pre-commit use)
python3 $S report.pdf photo.jpg deck.pptx   # individual files, metadata included
python3 $S --stdin < draft.md               # a piece of text
# common flags: --denylist PATH  --json  --fail-on {critical,high,medium,low,none}
#               --max-commits N  --include-deps  --reveal
```

Exit code 1 when anything reaches `--fail-on` (default `high`). Files ignored by git are reported as `info`/`gitignored`, since git won't publish them - but they matter if the folder ships another way (zip, Docker build context, screen share). Large multi-author repos collapse commit identities into one summary line.

On claude.ai: uploads are in `/mnt/user-data/uploads`. A repo arriving as a zip often has no `.git`, which means history can't be checked - say so in the report rather than implying it was. Public GitHub repos can be cloned (`git clone --depth 500` is usually enough; say if history was truncated).

Not covered by the scanner: video and audio, HEIC images, scanned PDFs, compressed PDF streams, text inside images, and anything without a fixed pattern. That's what step 4 is for.

## Step 3 - Triage

For every finding above `low`, open the file at that line and classify it: real, false positive, or intentional. Notes:

- **Secrets**: anything that could be live and was ever pushed needs rotation. Keys under test/fixture paths are downgraded automatically but still confirm they're throwaway.
- **History-only findings** deserve emphasis - the user believes those are already gone.
- **Other publication channels** leak independently of git: `COPY . .` in a Dockerfile without a `.dockerignore` ships `.env` in the image; `cargo package --list`, `npm pack --dry-run`, and Python sdists show what a package publish actually includes. Check whichever applies.
- **Confirmed false positives**: add `fp:<fingerprint>` (or `detector:<id>`, or a path glob) to `.leakscanignore` in the repo root so re-runs stay clean. That file is safe to commit - fingerprints are truncated hashes.

## Step 4 - Contextual review

Read `references/contextual-leaks.md`, then go through the material the way a motivated stranger with a search engine and an afternoon would. Prioritise human-written content over library code:

- README, docs, changelogs, code comments, TODOs
- commit messages, branch and tag names: `git log --all --format='%h %an %s%n%b'`, `git branch -a`, `git tag`
- test fixtures, seed data, sample configs, notebooks with saved outputs
- CI files (`.github/workflows`), Dockerfiles, deployment manifests
- every image: view it. Taskbars, browser tabs and bookmarks, notifications, terminal prompts, window titles, chat sidebars, calendars, maps, reflections, what's visible through windows
- any document's visible text, comments, speaker notes, hidden sheets

The question to keep asking: could someone go from this material to a name, address, employer, client, family member, or a way into a system?

## Step 5 - Report

Lead with a one-line verdict: **Safe to publish**, **Fix first**, or **Do not publish (yet)**. Then:

- **Must fix** - each item: location, what it is (masked), what an adversary actually gets from it, the fix. Point to `references/remediation.md` for rotation, history rewrites, and metadata stripping.
- **Should fix** - helps targeting or is unnecessary personal detail.
- **Your call** - deliberate-looking disclosures only the user can judge ("your city is in the README - fine if intended").
- **Coverage** - what was checked and, explicitly, what wasn't (no `.git`, truncated history, video not reviewed, compressed PDF streams). A clean report must not read as a certificate.

Group repetitive findings ("18 private IPs, all in test fixtures - fine"). Don't pad. After a repo audit, offer the prevention setup once (pre-commit hook, noreply email, push protection - in the remediation reference).

## Self-check for material Claude writes

Before handing over anything Claude wrote that is headed for a public audience (README, docs, blog post, video description or script, social post, portfolio entry, proposal, example code, sample data):

1. **Trace every specific.** Each concrete detail - company, client, city, colleague, project name, dataset, figure, URL, email, anecdote - should come from the user's request for this piece. Claude often carries context from memory, earlier conversation, or uploaded files and it is easy to "enrich" a public draft with the employer's name or a real client. Anything that isn't traceable gets replaced with a generic version, or asked about.
2. **Use reserved placeholders in examples**: `example.com` / `.org` / `.net`, IPs from `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, test cards like `4242 4242 4242 4242`, names like Jane Doe / ACME, `YOUR_API_KEY`. Never a real-looking key, even a fake one - scanners and humans can't tell the difference.
3. **For longer pieces, run the scanner** on the draft: `python3 $S --stdin --denylist ... < draft`.
4. If something was swapped out or is a judgment call, say so in one line. Otherwise stay quiet - the check is hygiene, not a performance.

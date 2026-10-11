# Remediation and prevention

## Contents
1. Leaked secret: order of operations
2. Removing things from git history
3. Stripping metadata
4. Prevention setup

## 1. Leaked secret: order of operations

1. **Revoke or rotate first.** Public pushes are scraped by bots within minutes. Rewriting history does not un-leak anything.
2. **Check for use.** Provider audit logs (cloud trail logs, billing spikes, DB connection logs, bot message history).
3. **Then clean history** (section 2), so the dead credential stops triggering alerts and the repo is tidy.
4. **Hunt for copies**: the same secret is often also in CI variables, other repos, `.env` backups, shell history, chat messages.

Per type, in general terms (check the provider's current docs for exact steps):
- Cloud/API keys: deactivate the key in the provider console, create a new one, update consumers.
- GitHub / GitLab tokens: revoke in account developer settings.
- Bot tokens (e.g. Telegram): revoke and reissue through the platform's bot management.
- SSH keys: remove the public key from every server's `authorized_keys` and from every git host, generate a new pair.
- Database passwords in connection strings: change the password, check whether the host is reachable from the internet at all.
- Webhooks (Slack, Discord): delete and recreate; anyone holding the URL can post.

## 2. Removing things from git history

Prefer `git filter-repo` (`pip install git-filter-repo`). Work on a fresh clone.

```bash
git clone --mirror <url> repo.git && cd repo.git   # or a normal fresh clone

# delete a file from every commit
git filter-repo --invert-paths --path path/to/secret.env

# replace strings everywhere (literal or regex)
cat > /tmp/replacements.txt <<'EOF'
the-actual-secret-value==>REDACTED
regex:AKIA[0-9A-Z]{16}==>REDACTED
EOF
git filter-repo --replace-text /tmp/replacements.txt
shred -u /tmp/replacements.txt       # it contains the secrets

# rewrite author identities
cat > /tmp/mailmap <<'EOF'
Handle <12345+handle@users.noreply.github.com> <real.name@personal-mail.com>
EOF
git filter-repo --mailmap /tmp/mailmap

# filter-repo removes 'origin' as a safety measure
git remote add origin <url>
git push --force --all && git push --force --tags
```

Then:
- Every collaborator must re-clone; an old clone pushed back reintroduces everything.
- On GitHub, old commits can stay reachable by SHA, through PR refs, and in forks. Contact the host's support to purge cached views and PR refs; forks are separate repositories.
- Assume mirrors and archives already have it - another reason step 1 is rotation.
- If the repo was private and is about to become public: rewriting before the flip is fully effective. That's the cheap moment.

## 3. Stripping metadata

**Images**: `exiftool -all= -overwrite_original photo.jpg`, or `mat2 photo.jpg`. Removes GPS, owner, serial, and the embedded thumbnail. Simplest reliable alternative: take a fresh screenshot of the image and publish that. Turn off location tagging in the phone camera.

**PDF**: exiftool's PDF edits are reversible (it appends an incremental update and the old metadata stays in the file). Either rewrite after editing - `exiftool -all:all= in.pdf && qpdf --linearize in.pdf out.pdf` - or use `mat2`, or better, re-export from the source with metadata disabled. For redaction use a real redaction tool or rasterise the page; then verify with `pdftotext out.pdf -` that the text is gone.

**Office files**: accept or reject all tracked changes, delete comments, check for hidden sheets/rows/columns and speaker notes, then use the app's built-in "inspect document / remove personal information" feature. Exporting to PDF afterwards still needs the PDF step.

**Video**: platform editors (e.g. YouTube Studio) can blur regions after upload; otherwise re-edit and re-upload. Check titles, descriptions, pinned comments, end screens, and chapter names too.

## 4. Prevention setup

**Keep personal email out of commits**
- On GitHub: Settings -> Emails -> keep email private, and enable blocking of command-line pushes that expose it.
- `git config --global user.email "<id>+<handle>@users.noreply.github.com"`

**Separate identities per persona** (in `~/.gitconfig`):
```ini
[includeIf "gitdir:~/code/handle/"]
    path = ~/.gitconfig-handle
```
with its own `user.name`, `user.email`, and `core.sshCommand = ssh -i ~/.ssh/id_handle -o IdentitiesOnly=yes`. Separate SSH keys per account, never shared.

**Pre-commit hook** (`.git/hooks/pre-commit`, `chmod +x`):
```sh
#!/bin/sh
python3 "$HOME/.local/share/leakscan/leakscan.py" "$(git rev-parse --show-toplevel)" \
  --staged --fail-on high || {
  echo "leakscan blocked this commit. Review above; 'git commit --no-verify' to override."
  exit 1
}
```
Copy `leakscan.py` to that path first (or adjust it). Put the denylist at `~/.config/leakscan/denylist.txt` so the hook picks it up.

**Host-side**: enable secret scanning and push protection on the git host (free for public repos on GitHub). Add a broader scanner such as gitleaks or trufflehog to CI - they cover hundreds more credential formats and can verify whether a key is live; this skill's scanner is deliberately small and focused on personal/business exposure.

**Packaging**: keep a `.dockerignore` (at minimum `.env*`, `.git`, `*.pem`, `*.key`); check `cargo package --list` / `npm pack --dry-run` before publishing; prefer an explicit `include`/`files` allowlist over an exclude list.

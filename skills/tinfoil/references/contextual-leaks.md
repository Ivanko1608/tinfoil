# Contextual leaks - what pattern matching can't see

Read this before the contextual review. Each section: what to look for, and what an adversary gets from it. The last section (aggregation) is the one people underestimate most.

## Contents
1. Identity linkage
2. Employer and client exposure
3. Infrastructure and security posture
4. Location and routine
5. Other people
6. Money, legal, status
7. Screenshots, images, video
8. Document artefacts
9. Git-specific channels
10. Jurisdictional risk
11. Aggregation
12. Severity rubric

## 1. Identity linkage

Matters most when a project, handle, or channel is supposed to be unlinkable to the person behind it, or to their other personas.

- Commit author name and email, including in old commits and on other branches. GPG key UIDs carry name and email too.
- SSH key reuse: GitHub publishes every account's public keys at `github.com/<user>.keys`. The same key on two accounts links them.
- Same avatar, banner, or uncommon handle across platforms (reverse image search finds avatars).
- Cross-links: personal site, LinkedIn, freelancer profiles, sponsor or donation links, "built by" footers.
- Shared tracking IDs across sites: analytics, ad publisher, tag manager IDs are a classic way to tie two sites to one owner.
- Package registry maintainer emails, domain WHOIS, TLS certificate transparency logs listing related domains.
- Timezone and working hours from commit timestamps; the scanner reports timezones.
- Writing fingerprints: recurring phrases, unusual spellings, language-specific punctuation habits, the same joke in two places.
- Home paths (`/home/<username>/`) and shell prompts (`user@hostname`) where the username or hostname is distinctive.

Adversary gains: proof that persona A is person B, which unlocks everything else known about B.

## 2. Employer and client exposure

- Client and partner names, logos, screenshots of their dashboards or data.
- Real records in fixtures, seed data, logs, or notebook outputs - even "anonymised" rows often aren't (rare combinations of age, postcode, and job identify people).
- Internal endpoints, service names, schemas, table names, queue/topic names that mirror a real employer's system.
- Business figures: row counts, traffic, revenue, headcount, rates and pricing, contract terms, deadlines, upcoming launches.
- Incident write-ups and war stories naming or implying the company ("at my current job the orders table hit 4M rows and fell over").
- Code lifted from work repos. Unique internal naming conventions identify the source even with names stripped - and it may not be the user's to publish (employment contract / NDA / client IP). Flag it; don't rule on it.
- Codenames, internal ticket keys (`OPS-123`), internal tool names, Slack channel names.

Adversary gains: material for phishing the employer, competitive intel, and a breach-of-contract problem for the user.

## 3. Infrastructure and security posture

- Hostnames, IP ranges, VPN endpoints, bastion names, internal DNS zones.
- Cloud account IDs (AWS account IDs are 12 digits), bucket names, project IDs, Kubernetes namespaces and cluster names.
- Exact stack and versions of a specific organisation's production systems.
- Where secrets live, how deploys work, backup schedules, on-call rotations, who has admin.
- Self-hosting setups at home: router models, open ports, dynamic DNS names, home server hostnames.

Adversary gains: a target map. Generic architecture discussion is fine; the identifying specifics of a real system are not.

## 4. Location and routine

- Home address, street names, building details, neighbourhood names in casual text.
- Photos: views from windows, street signs, shop fronts, skylines, distinctive landmarks, sun angle and shadows (geolocation from a single photo is a routine OSINT exercise).
- Routine: gym, cafe, commute, kids' school runs, "every Tuesday I...".
- Travel and moving plans with dates ("away all of August", "moving to X next month") - the home is empty, or the new address is predictable.
- Wi-Fi network names in screenshots, licence plates, parcel labels, local weather or holiday references pinning a region.

Adversary gains: physical location and timing.

## 5. Other people

- Family, partner, children (names, ages, schools, photos), colleagues and opinions about them.
- Third-party data in fixtures, logs, screenshots, email previews, chat sidebars. Those people didn't consent.
- Other people's emails in LICENSE files and examples are normal in open source when they're the authors; real customers' or users' data is not.

Adversary gains: targets who never chose to be public, and leverage over the user.

## 6. Money, legal, status

- Income, rates, invoices, savings, debts, bank names, tax IDs, payment details.
- Residency, visa or registration status, legal disputes, health information.

Adversary gains: fraud material, social engineering hooks, discrimination risk.

## 7. Screenshots, images, video

Look at the whole frame, not just the subject:

- taskbar and system tray, browser tabs, bookmark bar, extension icons, profile avatars
- notifications and popups, email or chat previews, chat sidebars (channel and contact names)
- terminal prompts, window titles and editor title bars (which show full folder paths), git branch names in prompts
- calendars, maps, autocomplete dropdowns, recent-files lists
- reflections in glasses, monitors, windows; documents on the desk; whiteboards behind
- video: every frame counts, plus audio (names said aloud, background conversations, notification sounds that identify apps)

Redaction pitfalls:
- blur and pixelation of text can sometimes be reversed or guessed; use solid boxes
- black boxes drawn over text in a PDF often leave the text underneath, selectable
- some older cropping tools kept the uncropped data in the file (the "aCropalypse" bug in certain phone and desktop screenshot tools); re-export rather than trusting a crop
- JPEG EXIF can carry an embedded thumbnail of the pre-edit image

## 8. Document artefacts

- Author, last-modified-by, company metadata; PDF producer strings revealing internal tools.
- Tracked changes and comments (deleted text is still in the file).
- Hidden sheets, rows, columns; speaker notes; off-slide objects; PDF layers.
- PDF incremental saves: earlier revisions remain in the file.
- File names themselves: `Proposal_RealClient_v3_FINAL.pdf`.

## 9. Git-specific channels

- Commit messages and bodies ("hotfix for RealClient prod outage"), branch names, tag annotations.
- `.gitmodules` URLs pointing at private hosts; CI workflows naming self-hosted runners or internal registries.
- Issue/PR templates and history once a repo flips from private to public: old issues and PR discussions become public too.
- What can't be undone after a push: forks, PR refs (`refs/pull/*`), commits reachable by SHA, mirrors and archives.

## 10. Jurisdictional risk

Some content carries legal or personal risk depending on where the author or their relatives live: political commentary, coverage of wars and conflicts, tools for circumventing censorship or surveillance, criticism of governments. Publishing such content is the user's right and choice - but tying it to a real identity, or to identifiable relatives, is a decision they should make knowingly. When the material is in this territory, treat identity-linkage findings and mentions of relatives as blocking unless the user has clearly chosen to publish under their own name, and say why in one sentence without lecturing.

## 11. Aggregation

Individually harmless details combine. "Backend lead" + city + company size + language stack + timezone + one anecdote can be enough to name an employer, and the employer plus a first name finds the person. The test: list every concrete detail in the material and ask what someone could conclude from all of them together. Report aggregation risks as one finding that names the combination, not as a pile of separate nitpicks.

## 12. Severity rubric for contextual findings

- **Must fix**: enables account or system access, financial fraud, physical location of a person, an identity link the user wants to avoid, exposure of third parties' private data, employer or client confidential material or IP.
- **Should fix**: helps targeting (specific internal infra, a real organisation's stack), unnecessary personal detail, other people named without need.
- **Your call**: deliberate self-disclosure consistent with the stated posture.

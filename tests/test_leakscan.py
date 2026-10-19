"""End-to-end tests for leakscan.py.

Fixtures are assembled at runtime from fragments so this repository never
contains a string that looks like a real secret (and so GitHub push
protection, or leakscan itself, stays quiet when scanning this repo).

Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER = os.path.join(HERE, "..", "skills", "tinfoil", "scripts",
                       "leakscan.py")

# fragments joined at runtime
AWS = "AK" + "IA" + "QX7RZ2M4LP9WT3VB"
GH = "gh" + "p_" + "aZ3kLm9QwErTyUiOpAsDfGhJkLzXcVbNm12345"
ANT = "sk-" + "ant-" + "api03-Hq7xLm2Pz9Rt4Kw8Nv3Bc6Yd1Fg5Js0Ae"
PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
CARD = "4" + "539 1488 0343 6467"          # Luhn-valid, not a test card
IBAN = "GB82 " + "WEST 1234 5698 7654 32"  # the classic mod-97 valid sample


def scanner_env(extra=None):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("PRE_COMMIT_")}
    env.update(extra or {})
    return env


def run(*args, stdin=None, env=None):
    # run from an empty dir so this repo's own .leakscanignore can't leak in
    with tempfile.TemporaryDirectory() as cwd:
        r = subprocess.run([sys.executable, SCANNER, "--json", "--fail-on",
                            "none", *args], capture_output=True, text=True,
                           input=stdin, cwd=cwd, env=scanner_env(env))
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


def detectors(report):
    return {f["detector"] for f in report["findings"]}


PRIVATE_EMAIL = "jane.personal@gmail.com"
NOREPLY_EMAIL = "12345+janedoe@users.noreply.github.com"
NULL_SHA = "0" * 40


def git(cwd, *args, email=PRIVATE_EMAIL):
    r = subprocess.run(["git", "-C", cwd, "-c", "user.name=Jane Doe",
                        "-c", f"user.email={email}",
                        "-c", "commit.gpgsign=false", *args],
                       check=True, capture_output=True, text=True)
    return r.stdout.strip()


def jpeg_with_gps(lat=(40, 25, 1), lon=(3, 42, 13)):
    """Minimal JPEG whose EXIF carries a GPS IFD (big-endian TIFF)."""
    e = ">"
    # IFD0: one entry -> GPS IFD pointer at offset 26
    ifd0 = struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x8825, 4, 1, 26) \
        + struct.pack(e + "I", 0)
    gps_off = 26
    data_off = gps_off + 2 + 4 * 12 + 4
    lat_r = b"".join(struct.pack(e + "II", v, 1) for v in lat)
    lon_r = b"".join(struct.pack(e + "II", v, 1) for v in lon)
    gps = struct.pack(e + "H", 4)
    gps += struct.pack(e + "HHI", 1, 2, 2) + b"N\0\0\0"
    gps += struct.pack(e + "HHII", 2, 5, 3, data_off)
    gps += struct.pack(e + "HHI", 3, 2, 2) + b"W\0\0\0"
    gps += struct.pack(e + "HHII", 4, 5, 3, data_off + 24)
    gps += struct.pack(e + "I", 0)
    tiff = b"MM\0*" + struct.pack(e + "I", 8) + ifd0 + gps + lat_r + lon_r
    app1 = b"Exif\0\0" + tiff
    return (b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + b"\xff\xda\0\x02" + b"\xff\xd9")


class TextDetectors(unittest.TestCase):
    def test_secrets_in_text(self):
        text = f"aws={AWS}\ntoken: {GH}\nkey {ANT}\n{PEM}\n"
        self.assertTrue({"aws_access_key", "github_token", "anthropic_key",
                         "private_key"} <= detectors(run("--stdin", stdin=text)))

    def test_financial_checksums(self):
        rep = run("--stdin", stdin=f"card {CARD}\niban {IBAN}\n")
        self.assertTrue({"payment_card", "iban"} <= detectors(rep))

    def test_invalid_checksums_ignored(self):
        bad_card = CARD[:-1] + "8"
        rep = run("--stdin", stdin=f"card {bad_card}\n")
        self.assertNotIn("payment_card", detectors(rep))

    def test_placeholders_are_quiet(self):
        text = ("API_KEY=your_api_key_here\nmail me at jane@example.com\n"
                "card 4242 4242 4242 4242\nserver 192.0.2.10\n")
        rep = run("--stdin", stdin=text)
        sev = {f["detector"]: f["severity"] for f in rep["findings"]}
        self.assertNotIn("env_secret_assignment", sev)
        self.assertNotIn("email", sev)
        self.assertNotIn("public_ip", sev)
        self.assertEqual(sev.get("payment_card"), "low")

    def test_output_is_masked(self):
        rep = run("--stdin", stdin=f"{AWS}\n")
        self.assertNotIn(AWS, json.dumps(rep))

    def test_identity_leaks(self):
        text = ("see /Users/jsmith/projects/app\n"
                "jdoe@prod-db-01:~$ ls\nhost db1.acme.internal\n")
        self.assertTrue({"home_path", "shell_prompt", "internal_hostname"}
                        <= detectors(run("--stdin", stdin=text)))

    def test_home_path_matches_at_path_start(self):
        starts = ["/home/alice/app", "x /Users/alice/app", "cd '/home/alice'",
                  'p="/Users/alice"', "path=/home/alice", "at:/home/alice",
                  "open(/home/alice)", "file:///home/alice/x"]
        for text in starts:
            with self.subTest(text=text):
                self.assertIn("home_path", detectors(run("--stdin", stdin=text)))

    def test_home_path_ignores_url_and_nested_paths(self):
        paths = ["/api/budgets/home/settings", "https://example.com/home/page",
                 "http://example.com/Users/list"]
        for text in paths:
            with self.subTest(text=text):
                self.assertNotIn("home_path",
                                 detectors(run("--stdin", stdin=text)))

    def test_home_path_matches_windows_users_dir(self):
        text = "C:\\Users\\alice\\Documents"
        self.assertIn("home_path", detectors(run("--stdin", stdin=text)))

    def test_denylist(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# work\nAcmeCorp\nre:proj-\\d+\n")
        try:
            rep = run("--stdin", "--denylist", fh.name,
                      stdin="fixed PROJ-142 for acmecorp\n")
            self.assertEqual(sum(f["detector"] == "denylist"
                                 for f in rep["findings"]), 2)
        finally:
            os.unlink(fh.name)


class FileAndRepo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, data):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(data, bytes) else "w") as fh:
            fh.write(data)
        return p

    def test_exif_gps(self):
        p = self.write("photo.jpg", jpeg_with_gps())
        rep = run(p)
        gps = [f for f in rep["findings"] if f["detector"] == "exif_gps"]
        self.assertEqual(len(gps), 1)
        self.assertEqual(gps[0]["severity"], "high")

    def test_office_metadata(self):
        p = os.path.join(self.d, "proposal.docx")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("docProps/core.xml",
                       "<cp:coreProperties><dc:creator>Jane Doe</dc:creator>"
                       "</cp:coreProperties>")
            z.writestr("word/document.xml",
                       '<w:document><w:ins w:author="Boss Person">x</w:ins>'
                       "</w:document>")
            z.writestr("word/comments.xml", "<w:comments/>")
        self.assertTrue({"office_creator", "office_tracked_changes",
                         "office_comments"} <= detectors(run(p)))

    def test_history_remembers_deleted_secrets(self):
        git(self.d, "init", "-q")
        self.write(".env", f"AWS_ACCESS_KEY_ID={AWS}\n")
        self.write("README.md", "# demo\n")
        git(self.d, "add", ".")
        git(self.d, "commit", "-qm", "init")
        git(self.d, "rm", "-q", ".env")
        git(self.d, "commit", "-qm", "oops, remove env")

        self.assertNotIn("aws_access_key", detectors(run(self.d)))

        rep = run(self.d, "--history")
        hist = {f["detector"]: f for f in rep["findings"]
                if f["where"].startswith("history")}
        self.assertIn("aws_access_key", hist)
        self.assertIn("still in git history", hist["aws_access_key"]["note"])
        self.assertIn("risky_file", hist)
        ids = [f for f in rep["findings"] if f["detector"] == "commit_identity"]
        self.assertTrue(ids)

    def test_staged_mode(self):
        git(self.d, "init", "-q")
        self.write("config.py", f'TOKEN = "{GH}"\n')
        git(self.d, "add", "config.py")
        self.assertIn("github_token", detectors(run(self.d, "--staged")))

    def test_leakscanignore(self):
        p = self.write("notes.txt", f"{AWS}\n")
        fp = next(f["fingerprint"] for f in run(p)["findings"]
                  if f["detector"] == "aws_access_key")
        self.write(".leakscanignore", f"fp:{fp}\n")
        self.assertNotIn("aws_access_key", detectors(run(self.d)))

    def test_exit_code(self):
        p = self.write("k.txt", PEM + "\n")
        r = subprocess.run([sys.executable, SCANNER, p], capture_output=True)
        self.assertEqual(r.returncode, 1)
        r = subprocess.run([sys.executable, SCANNER, p, "--fail-on", "none"],
                           capture_output=True)
        self.assertEqual(r.returncode, 0)


class PushMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        git(self.d, "init", "-q", "-b", "main")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, name, text, email=PRIVATE_EMAIL):
        with open(os.path.join(self.d, name), "w") as fh:
            fh.write(text)
        git(self.d, "add", name)
        git(self.d, "commit", "-qm", f"add {name}", email=email)
        return git(self.d, "rev-parse", "HEAD")

    def mark_pushed(self, sha):
        git(self.d, "update-ref", "refs/remotes/origin/main", sha)

    def push_line(self, sha):
        return f"refs/heads/main {sha} refs/heads/main {NULL_SHA}\n"

    def identities(self, report):
        return [f for f in report["findings"]
                if f["detector"] == "commit_identity"]

    def test_private_email_in_pushed_range_is_high(self):
        base = self.commit("a.txt", "a\n", email=NOREPLY_EMAIL)
        self.mark_pushed(base)
        sha = self.commit("b.txt", "b\n")

        rep = run(self.d, "--push", stdin=self.push_line(sha))

        found = self.identities(rep)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(found[0]["where"], "push")
        self.assertEqual(rep["commits_scanned"], 1)

    def test_private_email_fails_push_at_default_level(self):
        sha = self.commit("a.txt", "a\n")

        r = subprocess.run([sys.executable, SCANNER, self.d, "--push"],
                           input=self.push_line(sha), capture_output=True,
                           text=True, env=scanner_env())

        self.assertEqual(r.returncode, 1)

    def test_commit_already_on_remote_is_skipped(self):
        sha = self.commit("a.txt", "a\n")
        self.mark_pushed(sha)

        rep = run(self.d, "--push", stdin=self.push_line(sha))

        self.assertEqual(self.identities(rep), [])
        self.assertEqual(rep["commits_scanned"], 0)

    def test_noreply_email_passes(self):
        sha = self.commit("a.txt", "a\n", email=NOREPLY_EMAIL)

        rep = run(self.d, "--push", stdin=self.push_line(sha))

        self.assertEqual(self.identities(rep), [])
        self.assertEqual(rep["commits_scanned"], 1)

    def test_branch_deletion_passes(self):
        self.commit("a.txt", "a\n")
        deletion = f"(delete) {NULL_SHA} refs/heads/old {NULL_SHA}\n"

        rep = run(self.d, "--push", stdin=deletion)

        self.assertEqual(rep["findings"], [])
        self.assertEqual(rep["commits_scanned"], 0)

    def test_secret_in_pushed_commit(self):
        sha = self.commit("config.py", f'TOKEN = "{GH}"\n', email=NOREPLY_EMAIL)

        rep = run(self.d, "--push", stdin=self.push_line(sha))

        self.assertIn("github_token", detectors(rep))

    def test_pre_commit_env_vars(self):
        base = self.commit("a.txt", "a\n", email=NOREPLY_EMAIL)
        self.mark_pushed(base)
        sha = self.commit("b.txt", "b\n")
        env = {"PRE_COMMIT_REMOTE_NAME": "origin", "PRE_COMMIT_FROM_REF": base,
               "PRE_COMMIT_TO_REF": sha}

        rep = run(self.d, "--push", env=env)

        self.assertEqual(len(self.identities(rep)), 1)

    def test_pre_commit_env_vars_for_root_commit(self):
        self.commit("a.txt", "a\n")
        env = {"PRE_COMMIT_REMOTE_NAME": "origin",
               "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/main"}

        rep = run(self.d, "--push", env=env)

        self.assertEqual(len(self.identities(rep)), 1)


if __name__ == "__main__":
    unittest.main()

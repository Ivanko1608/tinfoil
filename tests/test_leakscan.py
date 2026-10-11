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
SCANNER = os.path.join(HERE, "..", "skills", "leak-check", "scripts",
                       "leakscan.py")

# fragments joined at runtime
AWS = "AK" + "IA" + "QX7RZ2M4LP9WT3VB"
GH = "gh" + "p_" + "aZ3kLm9QwErTyUiOpAsDfGhJkLzXcVbNm12345"
ANT = "sk-" + "ant-" + "api03-Hq7xLm2Pz9Rt4Kw8Nv3Bc6Yd1Fg5Js0Ae"
PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
CARD = "4" + "539 1488 0343 6467"          # Luhn-valid, not a test card
IBAN = "GB82 " + "WEST 1234 5698 7654 32"  # the classic mod-97 valid sample


def run(*args, stdin=None):
    # run from an empty dir so this repo's own .leakscanignore can't leak in
    with tempfile.TemporaryDirectory() as cwd:
        r = subprocess.run([sys.executable, SCANNER, "--json", "--fail-on",
                            "none", *args], capture_output=True, text=True,
                           input=stdin, cwd=cwd)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout)


def detectors(report):
    return {f["detector"] for f in report["findings"]}


def git(cwd, *args):
    subprocess.run(["git", "-C", cwd, "-c", "user.name=Jane Doe",
                    "-c", "user.email=jane.personal@gmail.com",
                    "-c", "commit.gpgsign=false", *args],
                   check=True, capture_output=True)


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


if __name__ == "__main__":
    unittest.main()

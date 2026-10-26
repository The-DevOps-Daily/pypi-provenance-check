"""python3 -I -S -m unittest discover -s tests -v   (run from the repo root)"""
import contextlib
import hashlib
import io
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import fixtures  # noqa: E402
import ioc_check  # noqa: E402


def run(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = ioc_check.main(list(argv))
    return code, out.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ioc-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


class TestConstants(unittest.TestCase):
    def test_fixture_cook_pth_is_the_published_file(self):
        digest = hashlib.sha256(fixtures.PAYLOAD["cook.pth"]).hexdigest()
        self.assertEqual(ioc_check.PAYLOAD_SHA256.get(digest), "cook.pth")

    def test_fake_payload_is_not_the_real_one(self):
        for fn in ("cook.py", "sitecustomize.py"):
            self.assertNotIn(hashlib.sha256(fixtures.PAYLOAD[fn]).hexdigest(), ioc_check.PAYLOAD_SHA256)


class TestEnv(Base):
    def test_infected_venv(self):
        sp = fixtures.install_like_pip(self.p("venv/lib/python3.12/site-packages"))
        code, out = run("env", self.p("venv"))
        self.assertEqual(code, 1)
        for needle in ("litellm 1.107.0 is installed", "cook.pth", "cook.py",
                       "sitecustomize.py installed by litellm-1.107.0"):
            self.assertIn(needle, out)
        self.assertTrue(os.path.isfile(os.path.join(sp, "cook.pth")))

    def test_clean_venv(self):
        fixtures.install_like_pip(self.p("venv/lib/python3.12/site-packages"), version="1.106.2", payload=False)
        code, out = run("env", self.p("venv"))
        self.assertEqual(code, 0, out)
        self.assertIn("litellm 1.106.2 installed", out)

    def test_leftover_pyc_after_cleanup(self):
        sp = self.p("venv/lib/python3.12/site-packages")
        os.makedirs(os.path.join(sp, "__pycache__"))
        open(os.path.join(sp, "__pycache__", "cook.cpython-312.pyc"), "wb").close()
        code, out = run("env", sp)
        self.assertEqual(code, 1)
        self.assertIn("compiled cook module", out)

    def test_unowned_sitecustomize_is_suspicious(self):
        sp = self.p("site-packages")
        os.makedirs(sp)
        with open(os.path.join(sp, "sitecustomize.py"), "w") as f:
            f.write("import os\n")
        code, out = run("env", sp)
        self.assertEqual(code, 3)
        self.assertIn("no installed distribution lists", out)

    def test_owned_sitecustomize_is_info(self):
        sp = self.p("site-packages")
        fixtures.install_like_pip(sp, name="tracer", version="1.0", payload=False)
        with open(os.path.join(sp, "sitecustomize.py"), "w") as f:
            f.write("import os\n")
        with open(os.path.join(sp, "tracer-1.0.dist-info", "RECORD"), "a") as f:
            f.write("sitecustomize.py,,\n")
        code, out = run("env", sp)
        self.assertEqual(code, 0, out)
        self.assertIn("owned by tracer-1.0", out)

    def test_unowned_pth_import_is_suspicious(self):
        sp = self.p("site-packages")
        os.makedirs(sp)
        with open(os.path.join(sp, "zz.pth"), "w") as f:
            f.write("import base64\n")
        code, out = run("env", sp)
        self.assertEqual(code, 3)

    def test_virtualenv_pth_is_fine(self):
        sp = self.p("site-packages")
        os.makedirs(sp)
        with open(os.path.join(sp, "_virtualenv.pth"), "w") as f:
            f.write("import _virtualenv\n")
        open(os.path.join(sp, "_virtualenv.py"), "w").close()
        code, out = run("env", sp)
        self.assertEqual(code, 0, out)

    def test_named_path_missing_is_incomplete(self):
        code, out = run("env", self.p("nope"))
        self.assertEqual(code, 4)


class TestLock(Base):
    def write(self, name, text):
        path = self.p(name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_requirements_pin(self):
        code, _ = run("lock", self.write("requirements.txt", "openai==2.1.0\nlitellm==1.107.0 ; python_version>='3.10'\n"))
        self.assertEqual(code, 1)

    def test_requirements_extras_and_triple_equals(self):
        code, _ = run("lock", self.write("requirements.txt", "litellm[proxy]===1.107.0\n"))
        self.assertEqual(code, 1)

    def test_requirements_rc_is_not_the_release(self):
        code, out = run("lock", self.write("requirements.txt", "litellm==1.107.0rc2\n"))
        self.assertEqual(code, 0, out)

    def test_requirements_hash_only(self):
        h = "462d0c9f67ca522d9e0e4acd245e90b36ce0d5353604a66bb7c43a1ec4a6fcf7"
        code, out = run("lock", self.write("requirements.txt", f"some-name==1.0 \\\n    --hash=sha256:{h}\n"))
        self.assertEqual(code, 1)
        self.assertIn("manylinux_2_28_x86_64", out)

    def test_uv_lock(self):
        text = ('version = 1\n[[package]]\nname = "litellm"\nversion = "1.107.0"\n'
                'source = { registry = "https://pypi.org/simple" }\n')
        code, _ = run("lock", self.write("uv.lock", text))
        self.assertEqual(code, 1)

    def test_pylock(self):
        text = 'lock-version = "1.0"\n[[packages]]\nname = "litellm"\nversion = "1.107.0"\n'
        code, _ = run("lock", self.write("pylock.toml", text))
        self.assertEqual(code, 1)

    def test_poetry_lock(self):
        text = '[[package]]\nname = "litellm"\nversion = "1.107.0"\ndescription = ""\n'
        code, _ = run("lock", self.write("poetry.lock", text))
        self.assertEqual(code, 1)

    def test_pipfile_lock(self):
        text = '{"default": {"litellm": {"version": "==1.107.0", "hashes": []}}, "develop": {}}'
        code, _ = run("lock", self.write("Pipfile.lock", text))
        self.assertEqual(code, 1)

    def test_zero_padded_and_case(self):
        for line in ("LiteLLM==1.107\n", "litellm == 1.107.0.0\n", "litellm==v1.107.0\n"):
            code, out = run("lock", self.write("requirements.txt", line))
            self.assertEqual(code, 1, line)

    def test_other_spellings_are_not_the_release(self):
        for line in ("litellm==1.107.0-rc1\n", "litellm==1.107.0.post1\n", "litellm===1.107\n",
                     "litellm==1.107.0+local\n", "litellm==1.1070\n"):
            code, out = run("lock", self.write("requirements.txt", line))
            self.assertNotEqual(code, 1, line)

    def test_zero_epoch(self):
        code, _ = run("lock", self.write("requirements.txt", "litellm==0!1.107.0\n"))
        self.assertEqual(code, 1)

    def test_pipfile_keeps_the_operator(self):
        text = '{"default": {"litellm": {"version": "===1.107"}}, "develop": {}}'
        code, _ = run("lock", self.write("Pipfile.lock", text))
        self.assertEqual(code, 0)

    def test_safe_exact_pin_is_not_called_unpinned(self):
        code, out = run("lock", self.write("requirements.txt", "litellm==1.106.2\n"))
        self.assertEqual(code, 0)
        self.assertNotIn("without an exact pin", out)

    def test_prefix_match_is_unpinned(self):
        code, out = run("lock", self.write("requirements.txt", "litellm==1.107.*\n"))
        self.assertEqual(code, 0)
        self.assertIn("without an exact pin", out)

    def test_clean_lock(self):
        text = 'version = 1\n[[package]]\nname = "litellm"\nversion = "1.106.2"\n'
        code, out = run("lock", self.write("uv.lock", text))
        self.assertEqual(code, 0, out)

    def test_unpinned_is_info(self):
        code, out = run("lock", self.write("requirements.in", "litellm>=1.100\n"))
        self.assertEqual(code, 0)
        self.assertIn("without an exact pin", out)


class TestScan(Base):
    def test_wheel(self):
        path = fixtures.build_wheel(self.tmp)
        code, out = run("scan", path)
        self.assertEqual(code, 1)
        self.assertIn(".data/purelib/cook.pth", out)

    def test_artifact_hash(self):
        path = fixtures.build_wheel(self.tmp)
        digest = ioc_check.sha256_of(path)
        ioc_check.ARTIFACT_SHA256[digest] = "fixture wheel"
        try:
            code, out = run("scan", path)
        finally:
            del ioc_check.ARTIFACT_SHA256[digest]
        self.assertIn("sha256 is fixture wheel", out)

    def test_sdist_hash(self):
        path = self.p("litellm-1.107.0.tar.gz")
        with open(path, "wb") as f:
            f.write(fixtures._tar_bytes({"litellm-1.107.0/pyproject.toml": b"[tool.maturin]\n"}, gz=True))
        digest = ioc_check.sha256_of(path)
        ioc_check.ARTIFACT_SHA256[digest] = "fixture sdist"
        try:
            code, out = run("scan", path)
        finally:
            del ioc_check.ARTIFACT_SHA256[digest]
        self.assertEqual(code, 1, out)
        self.assertIn("sha256 is fixture sdist", out)

    @unittest.skipIf(os.geteuid() == 0, "root can read everything")
    def test_unreadable_directory_is_incomplete(self):
        d = self.p("cache", "locked")
        os.makedirs(d)
        os.chmod(d, 0)
        try:
            code, out = run("scan", self.p("cache"))
        finally:
            os.chmod(d, 0o755)
        self.assertEqual(code, 4, out)

    def test_truncated_wheel_is_incomplete(self):
        path = fixtures.build_wheel(self.tmp)
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[: len(data) // 3])
        code, out = run("scan", path)
        self.assertIn(code, (1, 4), out)  # the member-name bytes may survive; never a clean 0
        self.assertIn("could not be read", out)

    def test_truncated_tar_is_incomplete(self):
        path = self.p("img.tar")
        fixtures.build_docker_save(path, infected=False)
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(data[:1500])
        code, out = run("scan", path)
        self.assertEqual(code, 4, out)

    @unittest.skipIf(os.geteuid() == 0, "root can read everything")
    def test_unreadable_pth_is_incomplete(self):
        sp = self.p("site-packages")
        os.makedirs(sp)
        pth = os.path.join(sp, "zz.pth")
        with open(pth, "w") as f:
            f.write("import base64\n")
        os.chmod(pth, 0)
        try:
            code, out = run("env", sp)
        finally:
            os.chmod(pth, 0o644)
        self.assertEqual(code, 4, out)

    def test_pip_http_v2_body(self):
        wheel = fixtures.build_wheel(self.tmp)
        body = self.p("cache/http-v2/a/b/c/d/e/0123.body")
        os.makedirs(os.path.dirname(body))
        shutil.copy(wheel, body)
        os.remove(wheel)
        code, out = run("scan", self.p("cache"))
        self.assertEqual(code, 1)

    def test_pip_http_v1_wrapped_body(self):
        wheel = fixtures.build_wheel(self.tmp)
        entry = self.p("cache/http/0/9/a/c/9/09ac93d1")
        os.makedirs(os.path.dirname(entry))
        with open(wheel, "rb") as src, open(entry, "wb") as dst:
            dst.write(b"cc=4\x00" + b"\x92\xa4fake msgpack header" + src.read())
        os.remove(wheel)
        code, out = run("scan", self.p("cache"))
        self.assertEqual(code, 1)
        self.assertIn("contains the member name", out)

    def test_uv_archive_and_index(self):
        fixtures.install_like_pip(self.p("uv/archive-v0/x1"))  # installed layout
        os.makedirs(self.p("uv/archive-v0/x2", fixtures.DATA))  # unpacked wheel layout
        os.makedirs(self.p("uv/wheels-v7/pypi/litellm"))
        open(self.p("uv/wheels-v7/pypi/litellm/1.107.0-cp310-abi3-manylinux_2_28_x86_64.http"), "w").close()
        code, out = run("scan", self.p("uv"))
        self.assertEqual(code, 1)
        self.assertIn("uv cache entry for litellm 1.107.0", out)
        self.assertIn("unpacked litellm 1.107.0 wheel", out)

    def test_docker_save(self):
        code, out = run("scan", fixtures.build_docker_save(self.p("img.tar")))
        self.assertEqual(code, 1)
        self.assertIn("layer.tar", out)
        self.assertIn("site-packages/cook.pth", out)

    def test_oci_archive_gzip_layers(self):
        code, out = run("scan", fixtures.build_oci_archive(self.p("img.tar")))
        self.assertEqual(code, 1)
        self.assertIn("site-packages/cook.py", out)

    def test_docker_export_flat_tar(self):
        path = self.p("fs.tar")
        with open(path, "wb") as f:
            f.write(fixtures._tar_bytes(fixtures.layer_files()))
        code, out = run("scan", path)
        self.assertEqual(code, 1)
        self.assertIn("site-packages/cook.pth", out)

    def test_clean_image(self):
        code, out = run("scan", fixtures.build_oci_archive(self.p("img.tar"), infected=False))
        self.assertEqual(code, 0, out)

    def test_known_image_digest_in_index(self):
        path = self.p("img.tar")
        fixtures.build_oci_archive(path, infected=False)
        import tarfile, json
        bad = "bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5"
        with tarfile.open(path, "a") as tf:
            data = json.dumps({"manifests": [{"digest": f"sha256:{bad}"}]}).encode()
            info = tarfile.TarInfo("index.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        code, out = run("scan", path)
        self.assertEqual(code, 1)
        self.assertIn("linux/amd64", out)


class TestHost(Base):
    def test_markers(self):
        tmp = self.p("tmp")
        os.makedirs(os.path.join(tmp, ".pc_sq_abc"))
        open(os.path.join(tmp, ".pc_once_72129118c59f5636c0bb"), "w").close()
        code, out = run("--tmp-dir", tmp, "--proc-dir", self.p("noproc"), "host")
        self.assertEqual(code, 1)
        self.assertIn("successful exfiltration", out)

    def test_process_env(self):
        proc = self.p("proc")
        os.makedirs(os.path.join(proc, "4242", "fd"))
        with open(os.path.join(proc, "4242", "environ"), "wb") as f:
            f.write(b"HOME=/root\0PRIVCOLLECT_ACTIVE=1\0")
        code, out = run("--tmp-dir", self.p("tmp"), "--proc-dir", proc, "host")
        self.assertEqual(code, 1)
        self.assertIn("PRIVCOLLECT_ACTIVE=1", out)

    def test_clean_host(self):
        os.makedirs(self.p("tmp"))
        code, out = run("--tmp-dir", self.p("tmp"), "--proc-dir", self.p("noproc"), "host")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()

"""Updater integration against temporary Git repositories; no network, pip install or product calls."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("update_bridge", ROOT / "scripts/update_bridge.py")
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout.strip()


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bridger update ")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.remote, self.seed, self.root = base / "remote.git", base / "seed", base / "installed project"
        git(base, "init", "--bare", "--initial-branch=master", str(self.remote))
        git(base, "clone", str(self.remote), str(self.seed))
        git(self.seed, "config", "user.name", "Synthetic Test")
        git(self.seed, "config", "user.email", "test@example.invalid")
        (self.seed / ".gitignore").write_text(".venv/\nreports/\n.kiro/settings/\n", encoding="utf-8")
        (self.seed / "tracked.txt").write_text("original\n", encoding="utf-8")
        git(self.seed, "add", ".")
        git(self.seed, "commit", "-m", "synthetic baseline")
        git(self.seed, "push", "origin", "master")
        git(base, "clone", str(self.remote), str(self.root))
        git(self.root, "config", "user.name", "Synthetic Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        self.before = git(self.root, "rev-parse", "HEAD")
        self.origin = patch.object(updater, "ORIGIN", re.compile(re.escape(str(self.remote))))
        self.origin.start()
        self.addCleanup(self.origin.stop)
        self.steps = []
        self.silent = contextlib.redirect_stdout(io.StringIO())
        self.silent.__enter__()
        self.addCleanup(self.silent.__exit__, None, None, None)

    def publish(self, name="new.txt", text="updated\n", force=False):
        path = self.seed / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        git(self.seed, "add", *( ["-f"] if force else []), name)
        git(self.seed, "commit", "-m", "synthetic update")
        git(self.seed, "push", "origin", "master")
        return git(self.seed, "rev-parse", "HEAD")

    def run_update(self, fail=None):
        def step(root, python, label, *args):
            self.assertEqual(root, self.root)
            self.assertEqual(python, "synthetic-venv-python")
            self.steps.append(args)
            if fail == len(self.steps):
                raise updater.UpdateError("synthetic failure", 7)
        with patch.object(updater, "_python_step", side_effect=step):
            updater.update(self.root, "synthetic-venv-python")

    def test_fast_forward_preserves_personal_files_and_local_settings(self):
        personal = self.root / "personal.xlsx"
        personal.write_bytes(b"synthetic personal file")
        settings = self.root / ".kiro/settings/mcp.json"
        settings.parent.mkdir(parents=True)
        settings.write_text('{"synthetic":"keep"}', encoding="utf-8")
        report = self.root / "reports/cases/synthetic.json"
        report.parent.mkdir(parents=True)
        report.write_text("keep", encoding="utf-8")
        target = self.publish()
        self.run_update()
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), target)
        self.assertEqual(personal.read_bytes(), b"synthetic personal file")
        self.assertEqual(settings.read_text(encoding="utf-8"), '{"synthetic":"keep"}')
        self.assertEqual(report.read_text(encoding="utf-8"), "keep")
        self.assertEqual(self.steps, [("-m", "pip", "install", "--no-input", "-e", "."),
                                     ("-m", "unittest", "discover", "-s", "tests", "-q"),
                                     ("scripts/build_upstream_registry.py", "--check"),
                                     ("scripts/build_coverage_matrix.py", "--check")])
        self.assertFalse((self.root / ".git/bridger-update.lock").exists())

    def test_dirty_tracked_work_stops_before_fetch_and_install(self):
        self.publish()
        for staged in (False, True):
            with self.subTest(staged=staged):
                (self.root / "tracked.txt").write_text("local work", encoding="utf-8")
                if staged:
                    git(self.root, "add", "tracked.txt")
                with self.assertRaisesRegex(updater.UpdateError, "alteracoes locais"):
                    self.run_update()
                self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.before)
                self.assertEqual(git(self.root, "rev-parse", "origin/master"), self.before)
                self.assertEqual((self.root / "tracked.txt").read_text(), "local work")
        self.assertEqual(self.steps, [])

    def test_unmerged_branch_is_preserved(self):
        git(self.root, "checkout", "-b", "my-work")
        (self.root / "local.txt").write_text("unmerged", encoding="utf-8")
        git(self.root, "add", "local.txt")
        git(self.root, "commit", "-m", "local work")
        local = git(self.root, "rev-parse", "HEAD")
        self.publish()
        with self.assertRaisesRegex(updater.UpdateError, "commits fora"):
            self.run_update()
        self.assertEqual(git(self.root, "branch", "--show-current"), "my-work")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), local)
        self.assertEqual(self.steps, [])

    def test_merged_branch_can_switch_to_master(self):
        git(self.root, "checkout", "-b", "already-merged")
        target = self.publish()
        self.run_update()
        self.assertEqual(git(self.root, "branch", "--show-current"), "master")
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), target)

    def test_divergent_master_blocks_switch_even_from_an_ancestor_branch(self):
        (self.root / "local.txt").write_text("local commit", encoding="utf-8")
        git(self.root, "add", "local.txt")
        git(self.root, "commit", "-m", "local master commit")
        git(self.root, "checkout", "-b", "old-branch", self.before)
        self.publish()
        with self.assertRaisesRegex(updater.UpdateError, "master local"):
            self.run_update()
        self.assertEqual(git(self.root, "branch", "--show-current"), "old-branch")
        self.assertEqual(self.steps, [])

    def test_colliding_untracked_or_ignored_file_is_not_overwritten(self):
        for name, force in (("new.txt", False), (".kiro/settings/mcp.json", True)):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("personal", encoding="utf-8")
                self.publish(name, "remote", force=force)
                with self.assertRaises(updater.UpdateError):
                    self.run_update()
                self.assertEqual(path.read_text(encoding="utf-8"), "personal")
                self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.before)
                path.unlink()  # the next case must exercise its own collision, not this one again
        self.assertEqual(self.steps, [])

    def test_install_or_test_failure_stops_later_steps_without_rollback(self):
        target = self.publish()
        for fail in (1, 2, 3):
            with self.subTest(step=fail), contextlib.redirect_stderr(io.StringIO()) as err:
                self.steps.clear()
                with self.assertRaises(updater.UpdateError) as caught:
                    self.run_update(fail=fail)
                self.assertEqual(caught.exception.code, 7)
                self.assertEqual(len(self.steps), fail)
                self.assertEqual(git(self.root, "rev-parse", "HEAD"), target)
                self.assertIn("nao terminou", err.getvalue())
                self.assertFalse((self.root / ".git/bridger-update.lock").exists())

    def test_fetch_failure_does_not_continue(self):
        original = updater._command
        def command(root, args, **kwargs):
            if args[:2] == ["git", "fetch"]:
                return subprocess.CompletedProcess(args, 1, "", "synthetic credential must not be echoed")
            return original(root, args, **kwargs)
        with patch.object(updater, "_command", side_effect=command):
            with self.assertRaises(updater.UpdateError) as caught:
                self.run_update()
        self.assertNotIn("synthetic credential", str(caught.exception))
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.before)
        self.assertEqual(self.steps, [])

    def test_lock_and_in_progress_git_operation_are_respected(self):
        lock = self.root / ".git/bridger-update.lock"
        lock.write_text("synthetic other process", encoding="utf-8")
        with self.assertRaisesRegex(updater.UpdateError, "Outra atualizacao"):
            self.run_update()
        self.assertEqual(lock.read_text(), "synthetic other process")
        lock.unlink()
        (self.root / ".git/MERGE_HEAD").write_text(self.before, encoding="ascii")
        with self.assertRaisesRegex(updater.UpdateError, "em andamento"):
            self.run_update()
        self.assertFalse(lock.exists())
        self.assertEqual(self.steps, [])

    def test_detached_head_is_not_moved(self):
        git(self.root, "checkout", "--detach")
        with self.assertRaisesRegex(updater.UpdateError, "destacado"):
            self.run_update()
        self.assertEqual(git(self.root, "rev-parse", "HEAD"), self.before)


class EntryTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows CMD wrapper")
    def test_windows_wrapper_from_another_directory_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="bridger wrapper ") as folder:
            root = Path(folder) / "project with spaces"
            (root / "scripts").mkdir(parents=True)
            (root / "bridger.cmd").write_bytes((ROOT / "bridger.cmd").read_bytes())
            (root / "scripts/update_bridge.py").write_bytes((ROOT / "scripts/update_bridge.py").read_bytes())
            missing = subprocess.run([str(root / "bridger.cmd"), "--update"], cwd=folder,
                                     capture_output=True, text=True)
            self.assertEqual(missing.returncode, 1)
            self.assertIn(".venv not found", missing.stderr)
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root / ".venv")], check=True)
            help_result = subprocess.run([str(root / "bridger.cmd"), "--help"], cwd=folder,
                                         capture_output=True, text=True)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("--update", help_result.stdout)

    def test_system_python_cannot_update(self):
        with patch.object(updater.sys, "prefix", "/synthetic-wrong-venv"), \
                patch.object(updater, "update") as update, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(updater.main(["--update"]), 1)
        update.assert_not_called()

    def test_command_requires_explicit_update(self):
        with patch.object(updater, "update") as update, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(updater.main([]), 2)
        update.assert_not_called()

    def test_failed_step_exit_code_is_propagated(self):
        with patch.object(updater.sys, "prefix", str(updater.PROJECT / ".venv")), \
                patch.object(updater, "update", side_effect=updater.UpdateError("synthetic", 7)), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(updater.main(["--update"]), 7)

    def test_official_origin_urls(self):
        for url in ("https://github.com/HianSoares/KiroBridgerMCP.git", "git@github.com:HianSoares/KiroBridgerMCP.git",
                    "ssh://git@github.com/HianSoares/KiroBridgerMCP"):
            self.assertTrue(updater.ORIGIN.fullmatch(url))
        for url in ("https://token@github.com/HianSoares/KiroBridgerMCP.git", "https://example.invalid/repo.git"):
            self.assertIsNone(updater.ORIGIN.fullmatch(url))


if __name__ == "__main__":
    unittest.main()

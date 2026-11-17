"""The diagnostic substitution preserves every original namespace switch."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest

from native_rootfs_vm_proof import NAMESPACES, constructor_tail, native_constructor


class NativeRootfsLaunch(unittest.TestCase):
    def fixture(self):
        launch = ("from ci.gauntlet.benchmark.product_vm_rootfs import construct;"
                  "construct(expected_artifact_manifest_digest=sys.argv[8])")
        return ["/usr/bin/systemd-run", "--pipe", *NAMESPACES,
                "/usr/bin/python3", "-I", "-B", "-c", launch,
                "/opt/artifacts/code", "/var/lib/cell/stage", "a" * 64,
                "net:[42]", "b" * 64, "ubuntu2404-controller-v1", "c" * 64, "d" * 64]

    def test_only_one_complete_fixed_constructor_can_be_substituted(self):
        argv = self.fixture()
        index, tail = constructor_tail(argv)
        self.assertEqual(index, 2)
        self.assertEqual(tail[6], "/var/lib/cell/stage")
        for switch in NAMESPACES[1:]:
            changed = copy.deepcopy(argv)
            changed.remove(switch)
            self.assertIsNone(constructor_tail(changed), switch)
        self.assertIsNone(constructor_tail([*argv, "extra"]))
        self.assertIsNone(constructor_tail([*argv, "/usr/bin/unshare"]))

    def test_foreign_root_programs_and_nonisolated_python_are_unchanged(self):
        self.assertIsNone(constructor_tail(["/usr/bin/python3", "-c", "print('inert')"]))
        changed = self.fixture()
        changed[changed.index("-I")] = "-E"
        self.assertIsNone(constructor_tail(changed))

    def test_libraries_retain_the_generic_process_class_and_ordinary_launches(self):
        original = subprocess.Popen
        with native_constructor(None, Path("/unused"), "a" * 64, []):
            self.assertTrue(issubclass(subprocess.Popen, original))
            self.assertIsNotNone(subprocess.Popen[bytes])
            result = subprocess.run([sys.executable, "-I", "-c", "print('ordinary child')"],
                                    capture_output=True, check=True)
            self.assertEqual(result.stdout, b"ordinary child\n")
        self.assertIs(subprocess.Popen, original)
        changed = self.fixture()
        changed[changed.index("-c") + 1] = "print('different Root program')"
        self.assertIsNone(constructor_tail(changed))


if __name__ == "__main__":
    unittest.main()

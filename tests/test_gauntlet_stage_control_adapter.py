"""The staging adapter accepts only fixed identities before any VM execution."""

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from ci.gauntlet.benchmark.stage_control_adapter import ROLES, main, parse_args


BUILD = 'a' * 16
RUN = 'b' * 16
SOURCE = 'c' * 40
CONFIG = 'd' * 64
MANIFEST = 'e' * 64


class StagingControlAdapterTests(unittest.TestCase):
    def test_exact_role_set_and_candidate_identity(self):
        self.assertEqual(ROLES, {
            'success', 'input-binding', 'injection', 'boundary', 'timeout', 'cancel'
        })
        for role in ROLES:
            self.assertEqual(
                parse_args([BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, role])[-1], role
            )

    def test_arbitrary_paths_selectors_and_malformed_pins_refuse(self):
        valid = [BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, 'success']
        bad = [
            valid[:-1], valid + ['/tmp/override'],
            ['../' + BUILD, *valid[1:]],
            [BUILD.upper(), *valid[1:]],
            [BUILD, RUN + '/other', *valid[2:]],
            [*valid[:2], SOURCE[:-1], *valid[3:]],
            [*valid[:3], '3.49.0;sh', *valid[4:]],
            [*valid[:4], CONFIG.upper(), *valid[5:]],
            [*valid[:5], MANIFEST[:-1], valid[6]],
            [*valid[:6], 'all'],
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                parse_args(candidate)

    def test_non_linux_refuses_before_key_or_state_access(self):
        valid = [BUILD, RUN, SOURCE, '3.49.0', CONFIG, MANIFEST, 'success']
        stderr = io.StringIO()
        with patch('ci.gauntlet.benchmark.stage_control_adapter.sys.platform', 'darwin'), redirect_stderr(stderr):
            self.assertEqual(main(valid), 2)
        self.assertIn('isolated, assertion-enabled Linux Root controller required', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()

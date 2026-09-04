import unittest

from tests.native_validation import windows_native_validation_enabled


class WindowsNativeValidationGateTests(unittest.TestCase):
    def test_windows_requires_exact_closed_opt_in(self):
        for value in (None, "", "0", "true", "TRUE", "yes", "random text"):
            with self.subTest(value=value):
                environment = {} if value is None else {
                    "CYBERWATCHTOWER_VALIDATE_NATIVE_WINDOWS": value
                }
                self.assertFalse(windows_native_validation_enabled(
                    system_name="Windows", environment=environment
                ))

        self.assertTrue(windows_native_validation_enabled(
            system_name="Windows",
            environment={"CYBERWATCHTOWER_VALIDATE_NATIVE_WINDOWS": "1"},
        ))

    def test_non_windows_remains_disabled_with_opt_in(self):
        for system_name in ("Linux", "Darwin", "Plan9"):
            with self.subTest(system_name=system_name):
                self.assertFalse(windows_native_validation_enabled(
                    system_name=system_name,
                    environment={"CYBERWATCHTOWER_VALIDATE_NATIVE_WINDOWS": "1"},
                ))


if __name__ == "__main__":
    unittest.main()

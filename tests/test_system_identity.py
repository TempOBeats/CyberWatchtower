import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cyberwatchtower.system_identity import derive_system_id, get_local_system_id


class SystemIdentityTests(unittest.TestCase):
    def test_derivation_is_stable_opaque_and_namespaced(self):
        raw_identifier = "raw-machine-id-secret"

        first = derive_system_id(raw_identifier)
        second = derive_system_id(raw_identifier)

        self.assertEqual(first, second)
        self.assertTrue(first.startswith("cwt-"))
        self.assertNotIn(raw_identifier, first)
        self.assertEqual(len(first), 68)

    def test_local_identifier_is_read_and_only_hash_is_returned(self):
        with TemporaryDirectory() as directory:
            machine_id_path = Path(directory) / "machine-id"
            machine_id_path.write_text("private-machine-id\n", encoding="utf-8")

            system_id = get_local_system_id((machine_id_path,))

        self.assertEqual(system_id, derive_system_id("private-machine-id"))
        self.assertNotIn("private-machine-id", system_id)


if __name__ == "__main__":
    unittest.main()

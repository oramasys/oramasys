"""The inert sender consumes only existing durable dispatch authority."""
import unittest

from orama.graph.inert_effect_driver import InertEffectDriver
from orama.graph.dispatch_attempts import SqliteAttemptStore, AttemptStateError
from tempfile import TemporaryDirectory
from pathlib import Path


class InertDriverTests(unittest.TestCase):
    """Refuse unwired dispatch without creating authority or a new attempt."""

    def test_unknown_attempt_never_creates_authority(self):
        """A dry run is not a bypass around the durable authorization transaction."""
        with TemporaryDirectory() as directory:
            store = SqliteAttemptStore(Path(directory) / "attempts.sqlite", governed=True)
            try:
                with self.assertRaises(AttemptStateError):
                    InertEffectDriver(store).send("unknown")
                self.assertIsNone(store.outbox_row("unknown"))
            finally:
                store.close()

"""tests.test_api_gateway.test_rest.test_cli module."""

import unittest
from unittest.mock import (
    PropertyMock,
    patch,
)

from typer.testing import (
    CliRunner,
)

from minos.auth import (
    AuthConfig,
)
from minos.auth.cli import (
    app,
)
from minos.auth.launchers import (
    EntrypointLauncher,
)
from tests.utils import (
    BASE_PATH,
    FakeEntrypoint,
)

runner = CliRunner()


class Foo:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class TestCli(unittest.TestCase):
    CONFIG_FILE_PATH = BASE_PATH / "config.yml"

    def setUp(self):
        self.config = AuthConfig(self.CONFIG_FILE_PATH)
        self.services = ["a", "b", Foo]
        self.launcher = EntrypointLauncher(config=self.config, services=self.services)

    def test_app_ko(self):
        path = f"{BASE_PATH}/non_existing_config.yml"
        result = runner.invoke(app, ["start", path])
        self.assertEqual(result.exit_code, 1)
        self.assertTrue("Error loading config" in result.stdout)

    def test_launch(self):
        entrypoint = FakeEntrypoint()
        with patch("minos.auth.launchers.EntrypointLauncher.entrypoint", new_callable=PropertyMock) as mock:
            mock.return_value = entrypoint
            self.launcher.launch()
        self.assertEqual(1, entrypoint.call_count)


if __name__ == "__main__":
    unittest.main()

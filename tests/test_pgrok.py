import os
import sys
import platform
import time
import uuid
from http import HTTPStatus
from unittest import mock
from urllib.parse import urlparse
from urllib.request import urlopen
import unittest
import yaml
import shutil
import psutil

from pgrok import pgrok, tools
from pgrok.exception import PyngrokNgrokHTTPError, PyngrokNgrokURLError, PyngrokSecurityError, PyngrokError, \
    PyngrokNgrokError


class PgrokTestCase(unittest.TestCase):
    def setUp(self):
        self.config_dir = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".pgrok"))
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        config_path = os.path.join(self.config_dir, "config.yml")

        pgrok.DEFAULT_PGROK_CONFIG_PATH = config_path
        self.pyngrok_config = pgrok.PgrokConfig(
            pgrok_path=pgrok.DEFAULT_PGROK_PATH,
            config_path=pgrok.DEFAULT_PGROK_CONFIG_PATH,
            reconnect_session_retries=10
        )
        pgrok.set_default_config(self.pyngrok_config)

        # ngrok's CDN can be flaky, so make sure its flakiness isn't reflect in our CI/CD test runs
        tools.DEFAULT_RETRY_COUNT = 3

    def given_ngrok_installed(pyngrok_config):
        pgrok.install_pgrok(pyngrok_config)

    def tearDown(self):
        for p in list(pgrok._current_processes.values()):
            try:
                pgrok.kill_process(p.pyngrok_config.ngrok_path)
                p.proc.wait()
            except OSError:
                pass

        pgrok._current_tunnels.clear()

        if os.path.exists(self.config_dir):
            shutil.rmtree(self.config_dir)

    @staticmethod
    def given_ngrok_not_installed(ngrok_path):
        if os.path.exists(ngrok_path):
            os.remove(ngrok_path)

    @staticmethod
    def create_unique_subdomain():
        return "pyngrok-{}-{}-{}-{}{}-tcp".format(uuid.uuid4(), platform.system(),
                                                  platform.python_implementation(), sys.version_info[0],
                                                  sys.version_info[1]).lower()

    @staticmethod
    def copy_with_updates(to_copy, **kwargs):
        copied = copy(to_copy)

        for key, value in kwargs.items():
            copied.__setattr__(key, value)

        return copied

    def assertNoZombies(self):
        try:
            self.assertEqual(0, len(
                list(filter(lambda p: p.name() == "ngrok" and p.status() == "zombie", psutil.process_iter()))))
        except (AccessDenied, NoSuchProcess):
            # Some OSes are flaky on this assertion, but that isn't an indication anything is wrong, so pass
            pass


class TestPgrok(PgrokTestCase):
    @mock.patch("subprocess.call")
    def test_run(self, mock_call):
        # WHEN
        pgrok.run()

        # THEN
        self.assertTrue(mock_call.called)

    @mock.patch("subprocess.call")
    def test_main(self, mock_call):
        # WHEN
        pgrok.main()

        # THEN
        self.assertTrue(mock_call.called)

    def test_connect(self):
        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        self.assertEqual(len(pgrok._current_tunnels.keys()), 0)

        # WHEN
        pgrok_tunnel = pgrok.connect(5000, pyngrok_config=self.pyngrok_config)
        current_process = pgrok.get_pgrok_process()

        # THEN
        self.assertEqual(len(pgrok._current_tunnels.keys()), 1)
        self.assertIsNotNone(current_process)
        self.assertIsNone(current_process.proc.poll())
        self.assertTrue(current_process._monitor_thread.is_alive())
        self.assertTrue(pgrok_tunnel.name.startswith("http-5000-"))
        self.assertEqual("http", pgrok_tunnel.proto)
        self.assertEqual("http://localhost:5000", pgrok_tunnel.config["addr"])
        self.assertIsNotNone(pgrok_tunnel.public_url)
        self.assertIsNotNone(process.get_process(self.pyngrok_config))
        self.assertIn('http://', pgrok_tunnel.public_url)
        self.assertEqual(len(pgrok._current_processes.keys()), 1)

    def test_connect_name(self):
        # WHEN
        pgrok_tunnel = pgrok.connect(name="my-tunnel", pyngrok_config=self.pyngrok_config)

        # THEN
        self.assertEqual(pgrok_tunnel.name, "my-tunnel (http)")
        self.assertEqual("http", pgrok_tunnel.proto)
        self.assertEqual("http://localhost:80", pgrok_tunnel.config["addr"])

    def test_multiple_connections_no_token_fails(self):
        # WHEN
        with self.assertRaises(PyngrokNgrokHTTPError) as cm:
            pgrok.connect(5000, pyngrok_config=self.pyngrok_config)
            time.sleep(1)
            pgrok.connect(5001, pyngrok_config=self.pyngrok_config)
            time.sleep(1)

        # THEN
        self.assertEqual(502, cm.exception.status_code)
        self.assertIn("account may not run more than 2 tunnels", str(cm.exception))

    def test_get_tunnels(self):
        # GIVEN
        url = pgrok.connect(pyngrok_config=self.pyngrok_config).public_url
        time.sleep(1)
        self.assertEqual(len(pgrok._current_tunnels.keys()), 1)

        # WHEN
        tunnels = pgrok.get_tunnels()
        self.assertEqual(len(pgrok._current_tunnels.keys()), 2)

        # THEN
        self.assertEqual(len(pgrok._current_tunnels.keys()), 2)
        self.assertEqual(len(tunnels), 2)
        for tunnel in tunnels:
            if tunnel.proto == "http":
                self.assertEqual(tunnel.public_url, url)
            else:
                self.assertEqual(tunnel.proto, "https")
                self.assertEqual(tunnel.public_url, url.replace("http", "https"))
            self.assertEqual(tunnel.config["addr"], "http://localhost:80")

    def test_bind_tls_both(self):
        # WHEN
        url = pgrok.connect(bind_tls="both", pyngrok_config=self.pyngrok_config).public_url
        num_tunnels = len(pgrok.get_tunnels())

        # THEN
        self.assertTrue(url.startswith("http"))
        self.assertEqual(num_tunnels, 2)

    def test_bind_tls_https_only(self):
        # WHEN
        url = pgrok.connect(bind_tls=True, pyngrok_config=self.pyngrok_config).public_url
        num_tunnels = len(pgrok.get_tunnels())

        # THEN
        self.assertTrue(url.startswith("https"))
        self.assertEqual(num_tunnels, 1)

    def test_bind_tls_http_only(self):
        # WHEN
        url = pgrok.connect(bind_tls=False, pyngrok_config=self.pyngrok_config).public_url
        num_tunnels = len(pgrok.get_tunnels())

        # THEN
        self.assertTrue(url.startswith("http"))
        self.assertEqual(num_tunnels, 1)

    def test_disconnect(self):
        # GIVEN
        url = pgrok.connect(pyngrok_config=self.pyngrok_config).public_url
        time.sleep(1)
        tunnels = pgrok.get_tunnels()
        # Two tunnels, as one each was created for "http" and "https"
        self.assertEqual(len(pgrok._current_tunnels.keys()), 2)
        self.assertEqual(len(tunnels), 2)

        # WHEN
        pgrok.disconnect(url)
        self.assertEqual(len(pgrok._current_tunnels.keys()), 1)
        time.sleep(1)
        tunnels = pgrok.get_tunnels()

        # THEN
        # There is still one tunnel left, as we only disconnected the http tunnel
        self.assertEqual(len(pgrok._current_tunnels.keys()), 1)
        self.assertEqual(len(tunnels), 1)

    def test_kill(self):
        # GIVEN
        pgrok.connect(5000, pyngrok_config=self.pyngrok_config)
        time.sleep(1)
        pgrok_process = pgrok.get_process(self.pyngrok_config.pgrok_path)
        monitor_thread = pgrok_process._monitor_thread
        self.assertEqual(len(pgrok._current_tunnels.keys()), 1)

        # WHEN
        pgrok.kill()
        time.sleep(1)

        # THEN
        self.assertEqual(len(pgrok._current_tunnels.keys()), 0)
        self.assertIsNotNone(pgrok_process.proc.poll())
        self.assertFalse(monitor_thread.is_alive())
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        self.assertNoZombies()

    def test_process_request_success(self):
        # GIVEN
        current_process = pgrok.get_pgrok_process(pyngrok_config=self.pyngrok_config)
        pgrok_tunnel = pgrok.connect()
        time.sleep(1)

        # THEN
        self.assertEqual(pgrok_tunnel.name, pgrok_tunnel["name"])
        self.assertTrue(pgrok_tunnel.public_url.startswith("http"))

    def test_process_request_fails(self):
        # GIVEN
        current_process = pgrok.get_pgrok_process(pyngrok_config=self.pyngrok_config)
        bad_data = {
            "name": str(uuid.uuid4()),
            "addr": "8080",
            "proto": "invalid-proto"
        }

        # WHEN
        with self.assertRaises(PyngrokNgrokHTTPError) as cm:
            # TODO: Get current process from global _process variable
            pass

        # THEN
        self.assertEqual(HTTPStatus.BAD_REQUEST, cm.exception.status_code)
        self.assertIn("invalid tunnel configuration", str(cm.exception))
        self.assertIn("protocol name", str(cm.exception))

    def test_process_request_timeout(self):
        # GIVEN
        current_process = pgrok.get_pgrok_process(pyngrok_config=self.pyngrok_config)
        ngrok_tunnel = pgrok.connect()
        time.sleep(1)

        # WHEN
        with self.assertRaises(PyngrokNgrokURLError) as cm:
            # TODO: Get current process from global _process variable
            pass

        # THEN
        self.assertIn("timed out", cm.exception.reason)

    def test_regional_tcp(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        subdomain = self.create_unique_subdomain()
        pyngrok_config = self.copy_with_updates(self.pyngrok_config,
                                                auth_token=os.environ["NGROK_AUTHTOKEN"],
                                                region="au")

        # WHEN
        pgrok_tunnel = pgrok.connect(5000, "tcp", subdomain=subdomain, pyngrok_config=pyngrok_config)
        current_process = pgrok.get_pgrok_process()

        # THEN
        self.assertIsNotNone(current_process)
        self.assertIsNone(current_process.proc.poll())
        self.assertIsNotNone(pgrok_tunnel.public_url)
        self.assertIsNotNone(pgrok.get_process(pyngrok_config))
        self.assertEqual("localhost:5000", pgrok_tunnel.config["addr"])
        self.assertIn("tcp://", pgrok_tunnel.public_url)
        self.assertIn(".au.", pgrok_tunnel.public_url)
        self.assertEqual(len(pgrok._current_processes.keys()), 1)

    def test_regional_subdomain(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        subdomain = self.create_unique_subdomain()
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, auth_token=os.environ["NGROK_AUTHTOKEN"],
                                                region="au")

        # WHEN
        url = pgrok.connect(5000, subdomain=subdomain, pyngrok_config=pyngrok_config).public_url
        current_process = pgrok.get_pgrok_process()

        # THEN
        self.assertIsNotNone(current_process)
        self.assertIsNone(current_process.proc.poll())
        self.assertIsNotNone(url)
        self.assertIsNotNone(pgrok.get_process(pyngrok_config))
        self.assertIn("http://", url)
        self.assertIn(".au.", url)
        self.assertIn(subdomain, url)
        self.assertEqual(len(pgrok._current_processes.keys()), 1)

    def test_connect_fileserver(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, auth_token=os.environ["NGROK_AUTHTOKEN"])

        # WHEN
        pgrok_tunnel = pgrok.connect("file:///", pyngrok_config=pyngrok_config)
        current_process = pgrok.get_pgrok_process()
        time.sleep(1)
        tunnels = pgrok.get_tunnels()

        # THEN
        self.assertEqual(len(tunnels), 2)
        self.assertIsNotNone(current_process)
        self.assertIsNone(current_process.proc.poll())
        self.assertTrue(current_process._monitor_thread.is_alive())
        self.assertTrue(pgrok_tunnel.name.startswith("http-file-"))
        self.assertEqual("file:///", pgrok_tunnel.config["addr"])
        self.assertIsNotNone(pgrok_tunnel.public_url)
        self.assertIsNotNone(pgrok.get_process(self.pyngrok_config))
        self.assertIn('http://', pgrok_tunnel.public_url)
        self.assertEqual(len(pgrok._current_processes.keys()), 1)

    def test_disconnect_fileserver(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, auth_token=os.environ["NGROK_AUTHTOKEN"])
        url = pgrok.connect("file:///", pyngrok_config=pyngrok_config).public_url
        time.sleep(1)

        # WHEN
        pgrok.disconnect(url)
        time.sleep(1)
        tunnels = pgrok.get_tunnels()

        # THEN
        # There is still one tunnel left, as we only disconnected the http tunnel
        self.assertEqual(len(tunnels), 1)

    def test_get_tunnel_fileserver(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        # GIVEN
        self.assertEqual(len(pgrok._current_processes.keys()), 0)
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, auth_token=os.environ["NGROK_AUTHTOKEN"])
        pgrok_tunnel = pgrok.connect("file:///", pyngrok_config=pyngrok_config)
        time.sleep(1)
        public_url = pgrok.get_pgrok_process(pyngrok_config).public_url

        # WHEN
        response = pgrok._current_tunnels[public_url]

        # THEN
        self.assertEqual(pgrok_tunnel.name, response["name"])
        self.assertTrue(pgrok_tunnel.name.startswith("http-file-"))

    def test_ngrok_tunnel_refresh_metrics(self):
        # GIVEN
        current_process = pgrok.get_pgrok_process(pyngrok_config=self.pyngrok_config)
        pgrok_tunnel = pgrok.connect(urlparse(current_process.api_url).port, bind_tls=True)
        time.sleep(1)
        self.assertEqual(0, pgrok_tunnel.metrics.get("http").get("count"))
        self.assertEqual(pgrok_tunnel.data["metrics"].get("http").get("count"), 0)

        urlopen("{}/status".format(pgrok_tunnel.public_url)).read()
        time.sleep(3)

        # WHEN
        pgrok_tunnel.refresh_metrics()

        # THEN
        self.assertGreater(pgrok_tunnel.metrics.get("http").get("count"), 0)
        self.assertGreater(pgrok_tunnel.data["metrics"].get("http").get("count"), 0)

    def test_tunnel_definitions(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        subdomain = self.create_unique_subdomain()

        # GIVEN
        config = {
            "tunnels": {
                "http-tunnel": {
                    "proto": "http",
                    "addr": "8000",
                    "subdomain": subdomain
                },
                "tcp-tunnel": {
                    "proto": "tcp",
                    "addr": "22"
                }
            }
        }
        config_path = os.path.join(self.config_dir, "config2.yml")
        pgrok.install_default_config(config_path, config)
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, config_path=config_path,
                                                auth_token=os.environ["NGROK_AUTHTOKEN"])

        # WHEN
        http_tunnel = pgrok.connect(name="http-tunnel", pyngrok_config=pyngrok_config)
        ssh_tunnel = pgrok.connect(name="tcp-tunnel", pyngrok_config=pyngrok_config)

        # THEN
        self.assertEqual(http_tunnel.name, "http-tunnel (http)")
        self.assertEqual(http_tunnel.config["addr"],
                         "http://localhost:{}".format(config["tunnels"]["http-tunnel"]["addr"]))
        self.assertEqual(http_tunnel.proto, config["tunnels"]["http-tunnel"]["proto"])
        self.assertEqual(http_tunnel.public_url,
                         "http://{}.ngrok.io".format(config["tunnels"]["http-tunnel"]["subdomain"]))
        self.assertEqual(ssh_tunnel.name, "tcp-tunnel")
        self.assertEqual(ssh_tunnel.config["addr"],
                         "localhost:{}".format(config["tunnels"]["tcp-tunnel"]["addr"]))
        self.assertEqual(ssh_tunnel.proto, config["tunnels"]["tcp-tunnel"]["proto"])
        self.assertTrue(ssh_tunnel.public_url.startswith("tcp://"))

    def test_tunnel_definitions_pyngrok_default_with_overrides(self):
        if "NGROK_AUTHTOKEN" not in os.environ:
            self.skipTest("NGROK_AUTHTOKEN environment variable not set")

        subdomain = self.create_unique_subdomain()

        # GIVEN
        config = {
            "tunnels": {
                "pyngrok-default": {
                    "proto": "http",
                    "addr": "8080",
                    "subdomain": subdomain
                }
            }
        }
        config_path = os.path.join(self.config_dir, "config2.yml")
        pgrok.install_default_config(config_path, config)
        subdomain = self.create_unique_subdomain()
        pyngrok_config = self.copy_with_updates(self.pyngrok_config, config_path=config_path,
                                                auth_token=os.environ["NGROK_AUTHTOKEN"])

        # WHEN
        pgrok_tunnel1 = pgrok.connect(pyngrok_config=pyngrok_config)
        pgrok_tunnel2 = pgrok.connect(5000, subdomain=subdomain, pyngrok_config=pyngrok_config)

        # THEN
        self.assertEqual(pgrok_tunnel1.name, "pyngrok-default (http)")
        self.assertEqual(pgrok_tunnel1.config["addr"],
                         "http://localhost:{}".format(config["tunnels"]["pyngrok-default"]["addr"]))
        self.assertEqual(pgrok_tunnel1.proto, config["tunnels"]["pyngrok-default"]["proto"])
        self.assertEqual(pgrok_tunnel1.public_url,
                         "http://{}.ngrok.io".format(config["tunnels"]["pyngrok-default"]["subdomain"]))
        self.assertEqual(pgrok_tunnel2.name, "pyngrok-default (http)")
        self.assertEqual(pgrok_tunnel2.config["addr"], "http://localhost:5000")
        self.assertEqual(pgrok_tunnel2.proto, config["tunnels"]["pyngrok-default"]["proto"])
        self.assertIn(subdomain, pgrok_tunnel2.public_url)

    ################################################################################
    # Tests below this point don't need to start a long-lived ngrok process, they
    # are asserting on pyngrok-specific code or edge cases.
    ################################################################################

    def test_web_addr_false_not_allowed(self):
        # GIVEN
        with open(self.pyngrok_config.config_path, "w") as config_file:
            yaml.dump({"web_addr": False}, config_file)

        # WHEN
        with self.assertRaises(PyngrokError):
            pgrok.connect(pyngrok_config=self.pyngrok_config)

    def test_log_format_json_not_allowed(self):
        # GIVEN
        with open(self.pyngrok_config.config_path, "w") as config_file:
            yaml.dump({"log_format": "json"}, config_file)

        # WHEN
        with self.assertRaises(PyngrokError):
            pgrok.connect(pyngrok_config=self.pyngrok_config)

    def test_log_level_warn_not_allowed(self):
        # GIVEN
        with open(self.pyngrok_config.config_path, "w") as config_file:
            yaml.dump({"log_level": "warn"}, config_file)

        # WHEN
        with self.assertRaises(PyngrokError):
            pgrok.connect(pyngrok_config=self.pyngrok_config)

    def test_api_request_security_error(self):
        # WHEN
        with self.assertRaises(PyngrokSecurityError):
            pgrok.api_request("file:{}".format(__file__))

    @mock.patch("pyngrok.process.capture_run_process")
    def test_update(self, mock_capture_run_process):
        pgrok.update(pyngrok_config=self.pyngrok_config)

        self.assertEqual(mock_capture_run_process.call_count, 1)
        self.assertEqual("update", mock_capture_run_process.call_args[0][1][0])

    def test_version(self):
        # WHEN
        pgrok_version, pypgrok_version = pgrok.get_version(pyngrok_config=self.pyngrok_config)

        # THEN
        self.assertIsNotNone(pgrok_version)
        self.assertEqual(pgrok.__version__, pypgrok_version)

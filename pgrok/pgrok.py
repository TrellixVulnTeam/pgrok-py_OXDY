import logging
import os
import re
import sys
import uuid
import yaml
import time
from pgrok import tools
from copy import deepcopy
import subprocess
import atexit
import threading
import tempfile
from pgrok.exception import PgrokError, PgrokSecurityError

__version__ = "5.0.6"
logger = logging.getLogger(__name__)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

_current_tunnels = {}
_config_cache = None
_current_processes = {}
_default_config = {
    "server_addr": "ejemplo.me:4443",
    "tunnels": {
        "pgrok_default": {
            "proto": {"http": 8080},
            "subdomain": "pypgrok"
        }
    }
}

_default_pypgrok_config = None
BIN_DIR = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "bin"))
DEFAULT_PGROK_PATH = os.path.join(BIN_DIR, tools.get_pgrok_bin())
DEFAULT_PGROK_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".pgrok", "pgrok4.yml")
SAVE_DEFAULT_CONFIG = False


def _validate_path(pgrok_path):
    """
    Validate the given path exists, is a ``pgrok`` binary, and is ready to be started, otherwise raise a
    relevant exception.

    :param pgrok_path: The path to the ``pgrok`` binary.
    :type pgrok_path: str
    """
    if not os.path.exists(pgrok_path):
        raise PgrokError(
            "pgrok binary was not found. Be sure to call \"pgrok.install_pgrok()\" first for "
            "\"pgrok_path\": {}".format(pgrok_path))

    if pgrok_path in _current_processes:
        raise PgrokError("pgrok is already running for the \"pgrok_path\": {}".format(pgrok_path))


def _validate_config(config_path):
    with open(config_path, "r") as config_file:
        config = yaml.safe_load(config_file)

    if config is not None:
        validate_config(config)


def _terminate_process(process):
    if process is None:
        return
    try:
        process.terminate()
    except OSError:  # pragma: no cover
        logger.debug("pgrok process already terminated: {}".format(process.pid))


class PgrokProcess:
    """
    An object containing information about the ``pgrok`` process.

    :var proc: The child process that is running ``pgrok``.
    :vartype proc: subprocess.Popen
    :var pyngrok_config: The ``pyngrok`` configuration to use with ``pgrok``.
    :vartype pyngrok_config: PyngrokConfig
    :var api_url: The API URL for the ``pgrok`` web interface.
    :vartype api_url: str
    :var logs: A list of the most recent logs from ``pgrok``, limited in size to ``max_logs``.
    :vartype logs: list[PgrokLog]
    :var startup_error: If ``pgrok`` startup fails, this will be the log of the failure.
    :vartype startup_error: str
    """

    def __init__(self, proc, pgrok_config):
        self.proc = proc
        self.pgrok_config = pgrok_config
        self.public_url = None
        self.api_url = None
        self.client_id = None
        self.logs = []
        self.startup_error = None

        self._tunnel_started = False
        self._client_connected = False
        self._monitor_thread = None

    def __repr__(self):
        return "<PgrokProcess: \"{}\">".format(self.api_url)

    def __str__(self):  # pragma: no cover
        return "PgrokProcess: \"{}\"".format(self.api_url)

    @staticmethod
    def _line_has_error(log):
        return log.lvl in ["ERROR", "CRITICAL"]

    def _log_startup_line(self, line):
        """
        Parse the given startup log line and use it to manage the startup state
        of the ``pgrok`` process.

        :param line: The line to be parsed and logged.
        :type line: str
        :return: The parsed log.
        :rtype: PgrokLog
        """
        log = self._log_line(line)

        if log is None:
            return
        elif self._line_has_error(log):
            self.startup_error = log.msg
        else:
            if log.msg is None:
                return
            log_msg = log.msg.lower()
            # Log pgrok startup states as they come in
            if "serving web interface" in log_msg and log.addr is not None:
                self.api_url = "http://{}".format(log.addr)
            elif "tunnel established at" in log_msg:
                self._tunnel_started = True
                self.public_url = log.public_url
            elif "authenticated with server, client id" in log_msg:
                self._client_connected = True

        return log

    def _log_line(self, line):
        """
        Parse, log, and emit (if ``log_event_callback`` in :class:`~pyngrok.conf.PyngrokConfig` is registered) the
        given log line.

        :param line: The line to be processed.
        :type line: str
        :return: The parsed log.
        :rtype: PgrokLog
        """
        log = PgrokLog(line)

        if log.line == "":
            return None

        logger.log(getattr(logging, log.lvl), log.line)
        # print(f"{log.lvl} --> {log.msg}")
        self.logs.append(log)
        if len(self.logs) > self.pgrok_config.max_logs:
            self.logs.pop(0)

        if self.pgrok_config.log_event_callback is not None:
            self.pgrok_config.log_event_callback(log)

        return log

    def healthy(self):
        """
        Check whether the ``ngrok`` process has finished starting up and is in a running, healthy state.

        :return: ``True`` if the ``ngrok`` process is started, running, and healthy.
        :rtype: bool
        """
        if not self.api_url or \
                not self._tunnel_started or \
                not self._client_connected:
            return False

        if not self.api_url.lower().startswith("http"):
            raise PgrokSecurityError("URL must start with \"http\": {}".format(self.api_url))

        return self.proc.poll() is None and self.startup_error is None

    def _monitor_process(self):
        thread = threading.current_thread()

        thread.alive = True
        while thread.alive and self.proc.poll() is None:
            self._log_line(self.proc.stdout.readline())

        self._monitor_thread = None

    def start_monitor_thread(self):
        """
        Start a thread that will monitor the ``ngrok`` process and its logs until it completes.

        If a monitor thread is already running, nothing will be done.
        """
        if self._monitor_thread is None:
            logger.debug("Monitor thread will be started")

            self._monitor_thread = threading.Thread(target=self._monitor_process)
            self._monitor_thread.daemon = True
            self._monitor_thread.start()

    def stop_monitor_thread(self):
        """
        Set the monitor thread to stop monitoring the ``ngrok`` process after the next log event. This will not
        necessarily terminate the thread immediately, as the thread may currently be idle, rather it sets a flag
        on the thread telling it to terminate the next time it wakes up.

        This has no impact on the ``ngrok`` process itself, only ``pyngrok``'s monitor of the process and
        its logs.
        """
        if self._monitor_thread is not None:
            logger.debug("Monitor thread will be stopped")

            self._monitor_thread.alive = False


class PgrokLog:
    """An object containing a parsed log from the ``pgrok`` process."""

    def __init__(self, line):
        self.line = line.strip()
        self.lvl = "NOTSET"
        self.msg = None
        self.addr = None
        self.tag = None
        self.public_url = None

        found = re.search(r'\bINFO|DEBG|EROR|WARN\b', line)
        if found:
            value = found.group().upper()
            if value == "CRIT":
                value = "CRITICAL"
            elif value in ["ERR", "EROR"]:
                value = "ERROR"
            elif value == "WARN":
                value = "WARNING"
            elif value in ["DEBG", "DEBUG"]:
                value = "DEBUG"

            if not hasattr(logging, value):
                value = self.lvl
            setattr(self, 'lvl', value)
        # Split each caption and set attributes
        log_msg = [li.strip() for li in re.split(r'\[|\]', line) if li.strip()]
        if len(log_msg) >= 2:
            self.msg = log_msg[-1]
            self.tag = log_msg[-2]
            # Match ip address in the payload
            re_ipaddress = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4})')
            ip_addr = re_ipaddress.search(self.msg)
            if ip_addr and self.tag == "web":
                self.addr = ip_addr.group()

            # Match public url
            re_hostname = re.compile(
                r"(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
            public_url = re_hostname.search(self.msg)
            if public_url:
                self.public_url = public_url.group()

    def __repr__(self):
        return "<PgrokLog: t={} lvl={} msg=\"{}\">".format(self.t, self.lvl, self.msg)

    def __str__(self):  # pragma: no cover
        attrs = [attr for attr in dir(self) if not attr.startswith("_") and getattr(self, attr) is not None]
        attrs.remove("line")

        return " ".join("{}=\"{}\"".format(attr, getattr(self, attr)) for attr in attrs)


class PgrokConfig:
    """
    An object containing ``pypgrok``'s configuration for interacting with the ``pgrok`` binary. All values are
    optional when it is instantiated, and default values will be used for parameters not passed.

    Use :func:`~pypgrok.conf.get_default` and :func:`~pypgrok.conf.set_default` to interact with the default
    ``pgrok_config``, or pass another instance of this object as the ``pgrok_config`` keyword arg to most
    methods in the :mod:`~pypgrok.pgrok` module to override the default.

    .. code-block:: python

        from pypgrok import conf, pgrok

        # Here we update the entire default config
        pgrok_config = conf.PypgrokConfig(pgrok_path="/usr/local/bin/pgrok")
        conf.set_default(pgrok_config)

        # Here we update just one variable in the default config
        conf.get_default().pgrok_path = "/usr/local/bin/pgrok"

        # Here we leave the default config as-is and pass an override
        pgrok_config = PgrokConfig(pgrok_path="/usr/local/bin/pgrok")
        pgrok.connect(pgrok_config=pgrok_config)
    :var pgrok_path: The path to the ``pgrok`` binary, defaults to the value in
        `conf.DEFAULT_PGROK_PATH <index.html#config-file>`_
    :vartype pgrok_path: str
    :var config_path: The path to the ``pgrok`` config, defaults to ``None`` and ``pgrok`` manages it.
    :vartype config_path: str
    :var auth_token: An authtoken to pass to commands (overrides what is in the config).
    :vartype auth_token: str
    :var region: The region in which ``pgrok`` should start.
    :vartype region: str
    :var monitor_thread: Whether ``pgrok`` should continue to be monitored (for logs, etc.) after startup
        is complete.
    :vartype monitor_thread: bool
    :var log_event_callback: A callback that will be invoked each time ``pgrok`` emits a log. ``monitor_thread``
        must be set to ``True`` or the function will stop being called after ``pgrok`` finishes starting.
    :vartype log_event_callback: types.FunctionType
    :var startup_timeout: The max number of seconds to wait for ``pgrok`` to start before timing out.
    :vartype startup_timeout: int
    :var max_logs: The max number of logs to store in :class:`~pypgrok.process.pgrokProcess`'s ``logs`` variable.
    :vartype max_logs: int
    :var request_timeout: The max timeout when making requests to ``pgrok``'s API.
    :vartype request_timeout: float
    :var start_new_session: Passed to :py:class:`subprocess.Popen` when launching ``pgrok``. (Python 3 and POSIX only)
    :vartype start_new_session: bool
    """

    def __init__(self,
                 pgrok_path=None,
                 config_path=None,
                 auth_token=None,
                 monitor_thread=True,
                 log_event_callback=None,
                 startup_timeout=15,
                 max_logs=100,
                 request_timeout=4,
                 start_new_session=False,
                 reconnect_session_retries=0):

        self.pgrok_path = DEFAULT_PGROK_PATH if pgrok_path is None else pgrok_path
        self.config_path = DEFAULT_PGROK_CONFIG_PATH if config_path is None else config_path
        self.auth_token = auth_token
        self.monitor_thread = monitor_thread
        self.log_event_callback = log_event_callback
        self.startup_timeout = startup_timeout
        self.max_logs = max_logs
        self.request_timeout = request_timeout
        self.start_new_session = start_new_session
        self.reconnect_session_retries = reconnect_session_retries


class PgrokTunnel:
    """
    An object containing information about a ``pgrok`` tunnel.

    :var data: The original tunnel data.
    :vartype data: dict
    :var name: The name of the tunnel.
    :vartype name: str
    :var proto: The protocol of the tunnel.
    :vartype proto: str
    :var uri: The tunnel URI, a relative path that can be used to make requests to the ``pgrok`` web interface.
    :vartype uri: str
    :var public_url: The public ``pgrok`` URL.
    :vartype public_url: str
    :var config: The config for the tunnel.
    :vartype config: dict
    :var pypgrok_config: The ``pypgrok`` configuration to use when interacting with the ``pgrok``.
    :vartype pypgrok_config: PypgrokConfig
    :var api_url: The API URL for the ``pgrok`` web interface.
    :vartype api_url: str
    """

    def __init__(self, data, pypgrok_config):
        self.name = data.get("name")
        self.proto = data.get("proto")
        self.addr = data.get("addr")
        self.public_url = data.get("public_url")
        self.uri = data.get("uri", 'localhost')
        self.api_url = data.get('api_url')
        self.pypgrok_config = pypgrok_config

    def __repr__(self):
        return "<PgrokTunnel: \"{}\" -> \"{}\">".format(self.public_url, self.addr) \
            if getattr(self, "addr", None) else "<pending Tunnel>"

    def __str__(self):  # pragma: no cover
        return "PgrokTunnel: \"{}\" -> \"{}\"".format(self.public_url, self.config["addr"]) \
            if getattr(self, "addr", None) else "<pending Tunnel>"

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"Key with {key} doesn't exist")


def get_pgrok_config(config_path, use_cache=True):
    """
    Get the ``pgrok`` config from the given path.

    :param config_path: The ``pgrok`` config path to read.
    :type config_path: str
    :param use_cache: Use the cached version of the config (if populated).
    :type use_cache: bool
    :return: The ``pgrok`` config.
    :rtype: dict
    """
    global _config_cache

    if not _config_cache or not use_cache:
        with open(config_path, "r") as config_file:
            config = yaml.safe_load(config_file)
            if config is None:
                config = {}
        _config_cache = config

    return _config_cache


def install_default_config(config_path, data=None):
    """
    Install the given data to the ``pgrok`` config. If a config is not already present for the given path, create one.
    Before saving new data to the default config, validate that they are compatible with ``pgrok``.

    :param config_path: The path to where the ``pgrok`` config should be installed.
    :type config_path: str
    :param data: A dictionary of things to add to the default config.
    :type data: dict, optional
    """
    if data is None:
        data = {}

    config_dir = os.path.dirname(config_path)
    os.makedirs(config_dir, exist_ok=True)
    if not os.path.exists(config_path):
        open(config_path, "w").close()

    config = get_pgrok_config(config_path, use_cache=False)
    config.update(data)
    validate_config(config)

    with open(config_path, "w") as config_file:
        logger.debug("Installing default pgrok config to {} ...".format(config_path))
        yaml.dump(config, config_file)


def validate_config(data):
    """
    Validate that the given dict of config items are valid for ``pgrok`` and ``pypgrok``.

    :param data: A dictionary of things to be validated as config items.
    :type data: dict
    """
    # TODO: Write a proper validation for verifying the config data
    # - Check if tunnels key exists
    if data.get("web_addr", None) is False:
        raise PgrokError("\"web_addr\" cannot be False, as the pgrok API is a dependency for pypgrok")
    elif data.get("log_format") == "json":
        raise PgrokError("\"log_format\" must be \"term\" to be compatible with pypgrok")
    elif data.get("log_level", "info") not in ["info", "debug"]:
        raise PgrokError("\"log_level\" must be \"info\" to be compatible with pypgrok")
    return True


def get_default_config():
    """
    Get the default config to be used with methods in the :mod:`~pypgrok.pgrok` module. To override the
    default individually, the ``pgrok_config`` keyword arg can also be passed to most of these methods,
    or set a new default config with :func:`~pgrok.set_default_config`.

    :return: The default ``pgrok_config``.
    :rtype: PypgrokConfig
    """
    if _default_pypgrok_config is None:
        set_default_config(PgrokConfig())

    return _default_pypgrok_config


def set_default_config(pgrok_config):
    """
    Set a new default config to be used with methods in the :mod:`~pypgrok.pgrok` module. To override the
    default individually, the ``pgrok_config`` keyword arg can also be passed to most of these methods.

    :param pgrok_config: The new ``pgrok_config`` to be used by default.
    :type pgrok_config: PgrokConfig
    """
    global _default_pypgrok_config
    _default_pypgrok_config = pgrok_config


def _is_process_running(pgrok_path):
    """
    Check if the ``pgrok`` process is currently running.

    :param pgrok_path: The path to the ``pgrok`` binary.
    :type pgrok_path: str
    :return: ``True`` if ``pgrok`` is running from the given path.
    """
    if pgrok_path in _current_processes:
        # Ensure the process is still running and hasn't been killed externally, otherwise cleanup
        if _current_processes[pgrok_path].proc.poll() is None:
            return True
        else:
            logger.debug("Removing stale process for \"pgrok_path\" {}".format(pgrok_path))
            _current_processes.pop(pgrok_path, None)

    return False


def _start_process(pgrok_config, retries=0, service_name='pgrok_default'):
    """
    Start a ``pgrok`` process with no tunnels. This will start the ``pgrok`` web interface, against
    which HTTP requests can be made to create, interact with, and destroy tunnels.

    :param pgrok_config: The ``pgrok`` configuration to use when interacting with the ``pgrok`` binary.
    :type pgrok_config: PgrokConfig
    :param retries: The retry attempt index, if ``pgrok`` fails to establish the tunnel.
    :type retries: int, optional
    :return: The ``pgrok`` process.
    :rtype: PgrokProcess
    """
    # TODO: Extend this to support many pgrok process and save each one in _current_process map
    _validate_path(pgrok_config.pgrok_path)
    _validate_config(pgrok_config.config_path)

    start = [pgrok_config.pgrok_path, "-log=stdout"]
    logger.info("Starting pgrok with config file: {}".format(pgrok_config.config_path))
    start.append("-config={}".format(pgrok_config.config_path))
    if pgrok_config.auth_token:
        logger.info("Overriding default auth token")
        start.append("-authtoken={}".format(pgrok_config.auth_token))
    start += ["start", service_name]
    popen_kwargs = {"stdout": subprocess.PIPE, "universal_newlines": True}
    if os.name == "posix":
        popen_kwargs.update(start_new_session=pgrok_config.start_new_session)
    elif pgrok_config.start_new_session:
        logger.warning("Ignoring start_new_session=True, which requires POSIX")
    proc = subprocess.Popen(start, **popen_kwargs)
    atexit.register(_terminate_process, proc)

    logger.debug("pgrok process starting with PID: {}".format(proc.pid))

    pgrok_process = PgrokProcess(proc, pgrok_config)
    _current_processes[pgrok_config.pgrok_path] = pgrok_process

    timeout = time.time() + pgrok_config.startup_timeout
    while time.time() < timeout:
        line = proc.stdout.readline()
        pgrok_process._log_startup_line(line)

        if pgrok_process.healthy():
            logger.debug("pgrok process has started with API URL: {}".format(pgrok_process.api_url))
            if pgrok_config.monitor_thread:
                pgrok_process.start_monitor_thread()
            break
        elif pgrok_process.startup_error is not None or \
                pgrok_process.proc.poll() is not None:
            break

    if not pgrok_process.healthy():
        # If the process did not come up in a healthy state, clean up the state
        kill_process(pgrok_config.pgrok_path)

        if pgrok_process.startup_error is not None:
            if retries < pgrok_config.reconnect_session_retries:
                logger.warning("pgrok reset our connection, retrying in 0.5 seconds ...")
                time.sleep(0.5)

                return _start_process(pgrok_config, retries + 1, service_name=service_name)
            else:
                raise PgrokError("The pgrok process errored on start: {}.".format(pgrok_process.startup_error),
                                 pgrok_process.logs,
                                 pgrok_process.startup_error)
        else:
            raise PgrokError("The pgrok process was unable to start.", pgrok_process.logs)

    return pgrok_process


def get_process(pgrok_path, args):
    """
    Start a blocking ``pgrok`` process with the binary at the given path and the passed args. When the process
    returns, so will this method, and the captured output from the process along with it.

    This method is meant for invoking ``pgrok`` directly (for instance, from the command line) and is not
    necessarily compatible with non-blocking API methods. 

    :param pgrok_path: The path to the ``pgrok`` binary.
    :type pgrok_path: str
    :param args: The args to pass to ``pgrok``.
    :type args: list[str]
    :return: The output from the process.
    :rtype: str
    """
    _validate_path(pgrok_path)

    start = [pgrok_path] + args
    output = subprocess.check_output(start)
    return output.decode("utf-8").strip()


def kill_process(pgrok_path):
    """
    Terminate the ``pgrok`` processes, if running, for the given path. This method will not block, it will just
    issue a kill request.

    :param pgrok_path: The path to the ``pgrok`` binary.
    :type pgrok_path: str
    """
    if _is_process_running(pgrok_path):
        pgrok_process = _current_processes[pgrok_path]

        logger.info("Killing pgrok process: {}".format(pgrok_process.proc.pid))

        try:
            pgrok_process.proc.kill()
            pgrok_process.proc.wait()
        except OSError as e:  # pragma: no cover
            # If the process was already killed, nothing to do but cleanup state
            if e.errno != 3:
                raise e

        _current_processes.pop(pgrok_path, None)
    else:
        logger.debug("\"pgrok_path\" {} is not running a process".format(pgrok_path))


def run(args=None, pypgrok_config=None):
    """
    Ensure ``pgrok`` is installed at the default path, then call :func:`~pypgrok.process.run_process`.

    This method is meant for interacting with ``pgrok`` from the command line and is not necessarily
    compatible with non-blocking API methods. For that, use :mod:`~pypgrok.pgrok`'s interface methods (like
    :func:`~pypgrok.pgrok.connect`), or use :func:`~pypgrok.process.get_process`.

    :param args: Arguments to be passed to the ``pgrok`` process.
    :type args: list[str], optional
    :param pypgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.conf.get_default()`.
    :type pypgrok_config: PypgrokConfig, optional
    """
    if args is None:
        args = []
    if pypgrok_config is None:
        pypgrok_config = get_default_config()

    install_pgrok(pypgrok_config)
    _validate_path(pypgrok_config.pgrok_path)

    start = [pypgrok_config.pgrok_path] + args
    subprocess.call(start)


def install_pgrok(pypgrok_config=None):
    """
    Download, install, and initialize ``pgrok`` for the given config. If ``pgrok`` and its default
    config is already installed, calling this method will do nothing.

    :param pypgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.conf.get_default()`.
    :type pypgrok_config: PypgrokConfig, optional
    """
    if pypgrok_config is None:
        pypgrok_config = get_default_config()

    if not os.path.exists(pypgrok_config.pgrok_path):
        tools.install_pgrok(pypgrok_config.pgrok_path)

    # If no config_path is set, pgrok will use its default path
    if pypgrok_config.config_path is not None:
        config_path = pypgrok_config.config_path
    else:
        config_path = DEFAULT_PGROK_CONFIG_PATH

    # Install the config to the requested path
    if not os.path.exists(config_path):
        install_default_config(config_path, data=_default_config)

    # Install the default config, even if we don't need it this time, if it doesn't already exist
    if SAVE_DEFAULT_CONFIG and DEFAULT_PGROK_CONFIG_PATH != config_path and \
            not os.path.exists(DEFAULT_PGROK_CONFIG_PATH):
        install_default_config(DEFAULT_PGROK_CONFIG_PATH, data=_default_config)


def get_pgrok_process(pgrok_config=None, service_name='pgrok_default'):
    """
    Get the current ``pgrok`` process for the given config's ``pgrok_path``.

    If ``pgrok`` is not installed at :class:`~pgrok.PypgrokConfig`'s ``pgrok_path``, calling this method
    will first download and install ``pgrok``.

    If ``pgrok`` is not running, calling this method will first start a process with
    :class:`~pypgrok.conf.PypgrokConfig`.

    Use :func:`~pgrok.is_process_running` to check if a process is running without also implicitly
    installing and starting it.

    :param pgrok_config: A ``pgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pgrok.get_default()`.
    :type pgrok_config: PgrokConfig, optional
    :return: The ``pgrok`` process.
    :rtype: pgrokProcess
    """
    if pgrok_config is None:
        pgrok_config = get_default_config()

    install_pgrok(pgrok_config)
    if _is_process_running(pgrok_config.pgrok_path):
        return _current_processes[pgrok_config.pgrok_path]

    return _start_process(pgrok_config, service_name=service_name)


def connect(addr=None, proto=None, name=None, pgrok_config=None, **options):
    """
    Establish a new ``pgrok`` tunnel for the given protocol to the given port, returning an object representing
    the connected tunnel.

    If a `tunnel definition in pgrok's config file  matches the given ``name``, it will be loaded and used to 
    start the tunnel. When ``name`` is ``None`` and a "pgrok_default" tunnel definition exists in ``pgrok``'s 
    config, it will be loaded and use. Any ``kwargs`` passed as ``options`` will
    override properties from the loaded tunnel definition.

    If ``pgrok`` is not installed at :class:`~pgrok.PgrokConfig`'s ``pgrok_path``, calling this method
    will first download and install ``pgrok``.

    If ``pgrok`` is not running, calling this method will first start a process with
    :class:`~pgrok.PgrokConfig`.

    .. note::

        ``pgrok``'s default behavior for ``http`` when no additional properties are passed is to open *two* tunnels,
        one ``http`` and one ``https``. This method will return a reference to the ``http`` tunnel in this case. If
        only a single tunnel is needed, pass ``bind_tls=True`` and a reference to the ``https`` tunnel will be returned.

    """
    if pgrok_config is None:
        pgrok_config = get_default_config()

    config = get_pgrok_config(pgrok_config.config_path) if os.path.exists(pgrok_config.config_path) else {}

    # If a "pgrok-default" tunnel definition exists in the pgrok config, use that
    tunnel_definitions = config.get("tunnels", {})
    if not name and "pgrok_default" in tunnel_definitions:
        name = "pgrok_default"

    # Use a tunnel definition for the given name, if it exists
    if name and name in tunnel_definitions:
        tunnel_definition = tunnel_definitions[name]
        proto_map = tunnel_definition.get("proto", {})
        protocol = [k for k in proto_map.keys() if k in ['http', 'https', 'tcp']]
        assert len(protocol) > 0, \
            ValueError("Invalid proto in config should be http|https|tcp")

        addr = proto_map[protocol[0]] if not addr else addr
        proto = proto if proto else protocol[0]
        # Use the tunnel definition as the base, but override with any passed in options
        tunnel_definition.update(options)
        options = tunnel_definition

    addr = str(addr) if addr else "80"
    if not proto:
        proto = "http"

    if not name:
        if not addr.startswith("file://"):
            name = "{}-{}-{}".format(proto, addr, uuid.uuid4())
        else:
            name = "{}-file-{}".format(proto, uuid.uuid4())

    logger.info("Opening tunnel named: {}".format(name))

    if not os.path.exists(pgrok_config.config_path) or \
            not validate_config(get_pgrok_config(pgrok_config.config_path, use_cache=False)):
        # Create a temporary config with namedtempfile
        with tempfile.NamedTemporaryFile(suffix='.yml') as tmp:
            _default_config['tunnels'].pop('pgrok_default', None)
            tunnel_name = {}
            tunnel_name['proto'] = {proto: addr}
            tunnel_name['proto'].update(options)
            _default_config['tunnels'][name] = tunnel_name
            pgrok_config.config_path = tmp.name

    process = get_pgrok_process(pgrok_config, service_name=name)
    # Set tunnel parameter
    _tunnelcfg = {
        "name": name,
        "addr": addr,
        "proto": proto
    }
    options.update(_tunnelcfg)
    options['api_url'] = process.api_url
    options['public_url'] = process.public_url
    tunnel = PgrokTunnel(options, pgrok_config)
    logger.debug("Creating tunnel with options: {}".format(options))
    _current_tunnels[tunnel.public_url] = tunnel
    return tunnel


def disconnect(public_url, pgrok_config=None):
    """
    Disconnect the ``pgrok`` tunnel for the given URL, if open.

    :param public_url: The public URL of the tunnel to disconnect.
    :type public_url: str
    :param pgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.conf.get_default()`.
    :type pgrok_config: PypgrokConfig, optional
    """
    # TODO: Extend this to support many pgrok process and save each one in _current_process map
    if pgrok_config is None:
        pgrok_config = get_default_config()

    # If pgrok is not running, there are no tunnels to disconnect
    if not _is_process_running(pgrok_config.pgrok_path):
        return

    kill_process(pgrok_config.pgrok_path)
    tunnel = _current_tunnels[public_url]
    logger.info("Disconnecting tunnel: {}".format(tunnel.public_url))
    _current_tunnels.pop(public_url, None)


def get_tunnels(pgrok_config=None):
    """
    Get a list of active ``pgrok`` tunnels for the given config's ``pgrok_path``.

    If ``pgrok`` is not installed at :class:`~pgrok.PypgrokConfig`'s ``pgrok_path``, calling this method
    will first download and install ``pgrok``.

    If ``pgrok`` is not running, calling this method will first start a process with
    :class:`~pgrok.PypgrokConfig`.

    :param pgrok_config: A ``pgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pgrok.get_default_config()`.
    :type pgrok_config: PypgrokConfig, optional
    :return: The active ``pgrok`` tunnels.
    :rtype: list[PgrokTunnel]
    """
    if pgrok_config is None:
        pgrok_config = get_default_config()

    return list(_current_tunnels.values())


def kill(pypgrok_config=None):
    """
    Terminate the ``pgrok`` processes, if running, for the given config's ``pgrok_path``. This method will not
    block, it will just issue a kill request.

    :param pypgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.get_default_config()`.
    :type pypgrok_config: PypgrokConfig, optional
    """
    if pypgrok_config is None:
        pypgrok_config = get_default_config()

    kill_process(pypgrok_config.pgrok_path)
    _current_tunnels.clear()


def get_version(pypgrok_config=None):
    """
    Get a tuple with the ``pgrok`` and ``pypgrok`` versions.

    :param pypgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.get_default_config()`.
    :type pypgrok_config: PypgrokConfig, optional
    :return: A tuple of ``(pgrok_version, pypgrok_version)``.
    :rtype: tuple
    """
    if pypgrok_config is None:
        pypgrok_config = get_default_config()

    ngrok_version = get_process(pypgrok_config.pgrok_path, ["version"])

    return ngrok_version, __version__


def main():
    """
    Entry point for the package's ``console_scripts``. This initializes a call from the command
    line and invokes :func:`~pgrok.pgrok.run`.

    This method is meant for interacting with ``pgrok`` from the command line and is not necessarily
    compatible with non-blocking API methods. For that, use :mod:`~pgrok.pgrok`'s interface methods (like
    :func:`~pgrok.pgrok.connect`), or use :func:`~pgrok.pgrok.get_process`.
    """
    run(sys.argv[1:])

    if len(sys.argv) == 1 or len(sys.argv) == 2 and sys.argv[1].lstrip("-").lstrip("-") == "help":
        print("\nPYpgrok VERSION:\n   {}".format(__version__))
    elif len(sys.argv) == 2 and sys.argv[1].lstrip("-").lstrip("-") in ["v", "version"]:
        print("pypgrok version {}".format(__version__))


if __name__ == "__main__":
    main()

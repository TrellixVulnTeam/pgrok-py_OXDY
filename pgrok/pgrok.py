import logging
import os
import sys
import uuid
import yaml
import time
from pgrok import tools
import subprocess
import atexit
import shlex
from pgrok.exception import PgrokError, PgrokInstallError, PgrokSecurityError

logger = logging.getLogger(__name__)

_current_tunnels = {}
_config_cache = None
_current_processes = {}
__version__ = "5.0.6"

_default_config = {
    "server_addr": "ejemplo.me:4443",
    "tunnels": {
        "pypgrok-default": {
            "proto": {"http": 8080},
            "subdomain": "pypgrok"
        }
    }
}


BIN_DIR = os.path.normpath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "bin"))
DEFAULT_PGROK_PATH = os.path.join(BIN_DIR, tools.get_pgrok_bin())
DEFAULT_PGROK_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".pgrok", "pgrok.yml")


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

        self.api_url = None
        self.logs = []
        self.startup_error = None

        self._tunnel_started = False
        self._client_connected = False
        self._monitor_thread = None

    def __repr__(self):
        return "<PgrokProcess: \"{}\">".format(self.api_url)

    def __str__(self):  # pragma: no cover
        return "PgrokProcess: \"{}\"".format(self.api_url)

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
            self.startup_error = log.err
        else:
            # Log pgrok startup states as they come in
            if "serving web interface" in log.msg and log.addr is not None:
                self.api_url = "http://{}".format(log.addr)
            elif "tunnel established at" in log.msg:
                self._tunnel_started = True
            elif "[client] authenticated with server, client id" in log.msg:
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
        self.logs.append(log)
        if len(self.logs) > self.pgrok_config.max_logs:
            self.logs.pop(0)

        if self.pgrok_config.log_event_callback is not None:
            self.pgrok_config.log_event_callback(log)

        return log


class PgrokLog:
    """An object containing a parsed log from the ``pgrok`` process."""

    def __init__(self, line):
        self.line = line.strip()
        self.t = None
        self.lvl = "NOTSET"
        self.msg = None
        self.err = None
        self.addr = None

        for i in shlex.split(self.line):
            if "=" not in i:
                continue

            key, value = i.split("=", 1)

            if key == "lvl":
                if not value:
                    value = self.lvl

                value = value.upper()
                if value == "CRIT":
                    value = "CRITICAL"
                elif value in ["ERR", "EROR"]:
                    value = "ERROR"
                elif value == "WARN":
                    value = "WARNING"

                if not hasattr(logging, value):
                    value = self.lvl

            setattr(self, key, value)

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
                 region=None,
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
        self.region = region
        self.monitor_thread = monitor_thread
        self.log_event_callback = log_event_callback
        self.startup_timeout = startup_timeout
        self.max_logs = max_logs
        self.request_timeout = request_timeout
        self.start_new_session = start_new_session


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

    def __init__(self, data, pypgrok_config, api_url):
        self.name = data.get("name")
        self.proto = data.get("proto")
        self.uri = data.get("uri")
        self.public_url = data.get("public_url")
        self.addr = data.get("addr")
        self.pypgrok_config = pypgrok_config
        self.api_url = api_url

    def __repr__(self):
        return "<PgrokTunnel: \"{}\" -> \"{}\">".format(self.public_url, self.addr) \
            if getattr(self, "addr", None) else "<pending Tunnel>"

    def __str__(self):  # pragma: no cover
        return "PgrokTunnel: \"{}\" -> \"{}\"".format(self.public_url, self.config["addr"]) \
            if getattr(self, "addr", None) else "<pending Tunnel>"


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
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
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
    if data.get("web_addr", None) is False:
        raise PgrokError("\"web_addr\" cannot be False, as the pgrok API is a dependency for pypgrok")
    elif data.get("log_format") == "json":
        raise PgrokError("\"log_format\" must be \"term\" to be compatible with pypgrok")
    elif data.get("log_level", "info") not in ["info", "debug"]:
        raise PgrokError("\"log_level\" must be \"info\" to be compatible with pypgrok")


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


def _start_process(pyngrok_config, retries=0):
    """
    Start a ``pgrok`` process with no tunnels. This will start the ``pgrok`` web interface, against
    which HTTP requests can be made to create, interact with, and destroy tunnels.

    :param pyngrok_config: The ``pgrok`` configuration to use when interacting with the ``pgrok`` binary.
    :type pyngrok_config: PgrokConfig
    :param retries: The retry attempt index, if ``pgrok`` fails to establish the tunnel.
    :type retries: int, optional
    :return: The ``pgrok`` process.
    :rtype: PgrokProcess
    """
    # TODO: Fix this logic
    if pyngrok_config.config_path is None:
        config_path = pyngrok_config.config_path
    else:
        config_path = DEFAULT_PGROK_CONFIG_PATH

    _validate_path(pyngrok_config.pgrok_path)
    _validate_config(config_path)

    start = [pyngrok_config.pgrok_path, "-log=stdout"]
    logger.info("Starting ngrok with config file: {}".format(config_path))
    start.append("-config={}".format(config_path))
    if pyngrok_config.auth_token:
        logger.info("Overriding default auth token")
        start.append("-authtoken={}".format(pyngrok_config.auth_token))
    start += ["start", "pypgrok_default"]
    popen_kwargs = {"stdout": subprocess.PIPE, "universal_newlines": True}
    if os.name == "posix":
        popen_kwargs.update(start_new_session=pyngrok_config.start_new_session)
    elif pyngrok_config.start_new_session:
        logger.warning("Ignoring start_new_session=True, which requires POSIX")
    proc = subprocess.Popen(start, **popen_kwargs)
    atexit.register(_terminate_process, proc)

    logger.debug("pgrok process starting with PID: {}".format(proc.pid))

    pgrok_process = PgrokProcess(proc, pyngrok_config)
    _current_processes[pyngrok_config.pgrok_path] = pgrok_process

    timeout = time.time() + pyngrok_config.startup_timeout
    while time.time() < timeout:
        line = proc.stdout.readline()
        pgrok_process._log_startup_line(line)

        if pgrok_process.healthy():
            logger.debug("pgrok process has started with API URL: {}".format(pgrok_process.api_url))

            if pyngrok_config.monitor_thread:
                pgrok_process.start_monitor_thread()

            break
        elif pgrok_process.startup_error is not None or \
                pgrok_process.proc.poll() is not None:
            break

    if not pgrok_process.healthy():
        # If the process did not come up in a healthy state, clean up the state
        kill_process(pyngrok_config.pgrok_path)

        if pgrok_process.startup_error is not None:
            if pgrok_process.logs[-1].msg == "failed to reconnect session" and \
                    retries < pyngrok_config.reconnect_session_retries:
                logger.warning("pgrok reset our connection, retrying in 0.5 seconds ...")
                time.sleep(0.5)

                return _start_process(pyngrok_config, retries + 1)
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
    if DEFAULT_PGROK_CONFIG_PATH != config_path and \
            not os.path.exists(DEFAULT_PGROK_CONFIG_PATH):
        install_default_config(DEFAULT_PGROK_CONFIG_PATH, data=_default_config)


def get_pgrok_process(pgrok_config=None):
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

    return _start_process(pgrok_config)


def connect(addr=None, proto=None, name=None, pypgrok_config=None, **options):
    """
    Establish a new ``pgrok`` tunnel for the given protocol to the given port, returning an object representing
    the connected tunnel.

    If a `tunnel definition in pgrok's config file  matches the given ``name``, it will be loaded and used to 
    start the tunnel. When ``name`` is ``None`` and a "pypgrok-default" tunnel definition exists in ``pgrok``'s 
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
    if pypgrok_config is None:
        pypgrok_config = get_default_config()

    if pypgrok_config.config_path is not None:
        config_path = pypgrok_config.config_path
    else:
        config_path = DEFAULT_PGROK_CONFIG_PATH

    if os.path.exists(config_path):
        config = get_pgrok_config(config_path)
    else:
        config = {}

    # If a "pgrok-default" tunnel definition exists in the pgrok config, use that
    tunnel_definitions = config.get("tunnels", {})
    if not name and "pgrok-default" in tunnel_definitions:
        name = "pgrok-default"

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
    config = {
        "name": name,
        "addr": addr,
        "proto": proto
    }
    options.update(config)
    process = get_pgrok_process(pypgrok_config)
    tunnel = PgrokTunnel(config, pypgrok_config, process.api_url)
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
    if pgrok_config is None:
        pgrok_config = get_default_config()

    # If pgrok is not running, there are no tunnels to disconnect
    if not _is_process_running(pgrok_config.pgrok_path):
        return
    # TODO: Check if process with public url is running then destroy it
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


def update(pypgrok_config=None):
    """
    Update ``pgrok`` for the given config's ``pgrok_path``, if an update is available.

    :param pypgrok_config: A ``pypgrok`` configuration to use when interacting with the ``pgrok`` binary,
        overriding :func:`~pypgrok.get_default_config()`.
    :type pgrok_config: PypgrokConfig, optional
    :return: The result from the ``pgrok`` update.
    :rtype: str
    """
    # TODO: Check if new version of pgrok is available for download


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

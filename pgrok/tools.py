import os
import platform
import sys
import platform
import tarfile
import socket
import tempfile
import time
import logging
from http import HTTPStatus
from urllib.request import urlopen

from pgrok.exception import PgrokInstallError, PgrokSecurityError
logger = logging.getLogger(__name__)

_print_progress_enabled = True
PGROK_CDN_URL_PREFIX = "https://github.com/jerson/pgrok/releases/download/v3.2.4/"

PGROK_PLATFORMS = {
    "darwin_x86_64": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_MacOS_x86_64.tar.gz",
    "darwin_x86_64_arm": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_MacOS_arm64.tar.gz",
    "windows_x86_64": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Windows_x86_64.zip",
    "windows_i386": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Windows_i386.zip",
    "linux_x86_64_arm": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Linux_arm64.tar.gz",
    "linux_i386_arm": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Linux_armv7.tar.gz",
    "linux_i386": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Linux_i386.tar.gz",
    "linux_x86_64": PGROK_CDN_URL_PREFIX + "pgrok_3.2.4_Linux_x86_64.tar.gz",
}

DEFAULT_DOWNLOAD_TIMEOUT = 6
DEFAULT_RETRY_COUNT = 0


def get_pgrok_bin():
    """
    Get the ``pgrok`` executable for the current system.

    :return: The name of the ``pgrok`` executable.
    :rtype: str
    """
    system = platform.system().lower()
    if system in ["darwin", "linux", "freebsd"]:
        return "pgrok"
    elif system in ["windows", "cygwin"]:  # pragma: no cover
        return "pgrok.exe"
    else:  # pragma: no cover
        raise PgrokInstallError("\"{}\" is not a supported platform".format(system))


def print_progress(line, progress_enabled=False):
    if progress_enabled:
        sys.stdout.write("{}\r".format(line))
        sys.stdout.flush()


def clear_progress(spaces=100, progress_enabled=False):
    if progress_enabled:
        sys.stdout.write((" " * spaces) + "\r")
        sys.stdout.flush()


def install_pgrok(pgrok_path, **kwargs):
    """
    Download and install the latest ``ngrok`` for the current system, overwriting any existing contents
    at the given path.

    :param ngrok_path: The path to where the ``ngrok`` binary will be downloaded.
    :type ngrok_path: str
    :param kwargs: Remaining ``kwargs`` will be passed to :func:`_download_file`.
    :type kwargs: dict, optional
    """
    logger.debug("Installing pgrok to {}{} ...".format(
        pgrok_path, ", overwriting" if os.path.exists(pgrok_path) else "")
    )

    ngrok_dir = os.path.dirname(pgrok_path)
    os.makedirs(ngrok_dir, exist_ok=True)

    arch = "x86_64" if sys.maxsize > 2 ** 32 else "i386"
    if platform.uname()[4].startswith("arm") or \
            platform.uname()[4].startswith("aarch64"):
        arch += "_arm"
    system = platform.system().lower()
    if "cygwin" in system:
        system = "cygwin"

    plat = system + "_" + arch
    try:
        url = PGROK_PLATFORMS[plat]
        logger.debug("Platform to download: {}".format(plat))
    except KeyError:
        raise PgrokInstallError("\"{}\" is not a supported platform".format(plat))

    try:
        download_path = _download_file(url, **kwargs)
        _install_pgrok_tar(pgrok_path, download_path)
    except Exception as e:
        raise PgrokInstallError("An error occurred while downloading ngrok from {}: {}".format(url, e))


def _download_file(url, retries=0, **kwargs):
    """
    Download a file to a temporary path and emit a status to stdout (if possible) as the download progresses.

    :param url: The URL to download.
    :type url: str
    :param retries: The retry attempt index, if download fails.
    :type retries: int, optional
    :param kwargs: Remaining ``kwargs`` will be passed to :py:func:`urllib.request.urlopen`.
    :type kwargs: dict, optional
    :return: The path to the downloaded temporary file.
    :rtype: str
    """
    kwargs["timeout"] = kwargs.get("timeout", DEFAULT_DOWNLOAD_TIMEOUT)

    if not url.lower().startswith("http"):
        raise PgrokSecurityError("URL must start with \"http\": {}".format(url))

    try:
        print_progress("Downloading pgrok ...", progress_enabled=_print_progress_enabled)
        logger.debug("Download pgrok from {} ...".format(url))
        
        local_filename = url.split("/")[-1]
        response = urlopen(url, **kwargs)
        status_code = response.getcode()

        if status_code != HTTPStatus.OK:
            logger.debug("Response status code: {}".format(status_code))
            return None

        length = response.getheader("Content-Length")
        if length:
            length = int(length)
            chunk_size = max(4096, length // 100)
        else:
            chunk_size = 64 * 1024

        download_path = os.path.join(tempfile.gettempdir(), local_filename)
        with open(download_path, "wb") as f:
            size = 0
            while True:
                buffer = response.read(chunk_size)
                if not buffer:
                    break

                f.write(buffer)
                size += len(buffer)

                if length:
                    percent_done = int((float(size) / float(length)) * 100)
                    print_progress(
                        "Downloading ngrok: {}%".format(percent_done),
                        progress_enabled=_print_progress_enabled
                    )

        clear_progress(progress_enabled=_print_progress_enabled)

        return download_path
    except socket.timeout as e:
        if retries < DEFAULT_RETRY_COUNT:
            logger.warning("ngrok download failed, retrying in 0.5 seconds ...")
            time.sleep(0.5)

            return _download_file(url, retries + 1, **kwargs)
        else:
            raise e


def _install_pgrok_tar(pgrok_path, download_path):
    """
    Extract the ``pgrok`` tar file to the given path.

    :param pgrok_path: The path where ``pgrok`` will be installed.
    :type pgrok_path: str
    :param pgrok_path: The path to the ``pgrok`` tar file to be extracted.
    :type pgrok_path: str
    """
    print_progress("Installing pgrok ... ", progress_enabled=_print_progress_enabled)

    with tarfile.open(download_path, 'r') as tar_ref:
        logger.debug("Extracting ngrok binary from {} to {} ...".format(download_path, pgrok_path))
        tar_ref.extractall(os.path.dirname(pgrok_path))

    os.chmod(pgrok_path, int("777", 8))
    clear_progress(progress_enabled=_print_progress_enabled)

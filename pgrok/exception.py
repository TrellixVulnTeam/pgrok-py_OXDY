
class PgrokBaseError(Exception):
    """
    Raised when a general ``pgrok`` error has occurred.
    """
    pass


class PgrokSecurityError(PgrokBaseError):
    """
    Raised when a ``pgrok`` security error has occurred.
    """
    pass


class PgrokInstallError(PgrokBaseError):
    """
    Raised when an error has occurred while downloading and installing the ``pgrok`` binary.
    """
    pass


class PgrokError(PgrokBaseError):
    """
    Raised when an error occurs interacting directly with the ``pgrok`` binary.

    :var error: A description of the error being thrown.
    :vartype error: str
    :var pgrok_logs: The ``pgrok`` logs, which may be useful for debugging the error.
    :vartype pgrok_logs: list[PgrokLog]
    :var pgrok_error: The error that caused the ``pgrok`` process to fail.
    :vartype pgrok_error: str
    """

    def __init__(self, error, pgrok_logs=None, pgrok_error=None):
        super(PgrokError, self).__init__(error)

        if pgrok_logs is None:
            pgrok_logs = []

        self.pgrok_logs = pgrok_logs
        self.pgrok_error = pgrok_error


class PgrokHTTPError(PgrokError):
    """
    Raised when an error occurs making a request to the ``pgrok`` web interface. The ``body``
    contains the error response received from ``ngrok``.

    :var error: A description of the error being thrown.
    :vartype error: str
    :var url: The request URL that failed.
    :vartype url: str
    :var status_code: The response status code from ``ngrok``.
    :vartype status_code: int
    :var message: The response message from ``ngrok``.
    :vartype message: str
    :var headers: The request headers sent to ``ngrok``.
    :vartype headers: dict[str, str]
    :var body: The response body from ``ngrok``.
    :vartype body: str
    """

    def __init__(self, error, url, status_code, message, headers, body):
        super(PgrokHTTPError, self).__init__(error)

        self.url = url
        self.status_code = status_code
        self.message = message
        self.headers = headers
        self.body = body


class PgrokURLError(PgrokError):
    """
    Raised when an error occurs when trying to initiate an API request.

    :var error: A description of the error being thrown.
    :vartype error: str
    :var reason: The reason for the URL error.
    :vartype reason: str
    """

    def __init__(self, error, reason):
        super(PgrokURLError, self).__init__(error)

        self.reason = reason

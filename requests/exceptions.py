# -*- coding: utf-8 -*-

"""
requests.exceptions
~~~~~~~~~~~~~~~~~~~

This module contains the set of Requests' exceptions.

"""

class RequestException(IOError):
    """There was an ambiguous exception that occurred while handling your
    request."""
    def __init__(self, *args, **kwargs):
        """Initialize RequestException with `request` and `response` objects."""
        response = kwargs.pop('response', None)
        self.response = response
        self.request = kwargs.pop('request', None)
        if (response is not None and not self.request and
                hasattr(response, 'request')):
            self.request = self.response.request
        super(RequestException, self).__init__(*args, **kwargs)

class HTTPError(RequestException):
    """An HTTP error occurred."""

class ConnectionError(RequestException):
    """A Connection error occurred."""

class ProxyError(ConnectionError):
    """A proxy error occurred."""

class SSLError(ConnectionError):
    """An SSL error occurred."""

class Timeout(RequestException):
    """The request timed out.

    Catching this error will catch both
    :exc:`~requests.exceptions.ConnectTimeout` and
    :exc:`~requests.exceptions.ReadTimeout` errors.
    """

class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.
    """

class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time."""

class URLRequired(RequestException):
    """A valid URL is required to make a request."""

class TooManyRedirects(RequestException):
    """Too many redirects."""

class MissingSchema(RequestException, ValueError):
    """The URL schema (e.g. http or https) is missing."""

class InvalidSchema(RequestException, ValueError):
    """The URL schema provided is either invalid or not supported."""

class InvalidURL(RequestException, ValueError):
    """ The URL provided was somehow invalid."""

class InvalidHeader(RequestException, ValueError):
    """The header value provided was somehow invalid."""

class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk."""

class ContentDecodingError(RequestException):
    """Failed to decode response content."""

class FileModeWarning(RequestException, DeprecationWarning):
    """A file was opened in text mode, but Requests determined its binary length."""

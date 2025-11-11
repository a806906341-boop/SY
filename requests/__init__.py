# -*- coding: utf-8 -*-

"""
Requests HTTP Library
~~~~~~~~~~~~~~~~~~~~~

Requests is an HTTP library, written in Python, for human beings.

    >>> import requests
    >>> r = requests.get('https://www.python.org')
    >>> r.status_code
    200
    >>> b'Python is a programming language' in r.content
    True

... or POST:

    >>> payload = dict(key1='value1', key2='value2')
    >>> r = requests.post('https://httpbin.org/post', data=payload)
    >>> print(r.text)
    {
      ...
      "form": {
        "key1": "value1",
        "key2": "value2"
      },
      ...
    }

Enjoy!
"""

from . import utils
from . import packages
from .models import Request, Response, PreparedRequest
from .api import request, get, head, post, patch, put, delete, options
from .sessions import session, Session
from .status_codes import codes
from .exceptions import (
    RequestException, Timeout, URLRequired, TooManyRedirects, HTTPError, 
    ConnectionError, FileModeWarning, ConnectTimeout, ReadTimeout
)

# Set up logging to ``/dev/null`` like a library is supposed to. 
# http://docs.python.org/3.3/howto/logging.html#configuring-logging-for-a-library
import logging
from logging import NullHandler

logging.getLogger(__name__).addHandler(NullHandler())

# FileModeWarnings go off unresolved in versions of Python < 2.7.5
# It's a known bug that we can't do anything about.
# https://github.com/requests/requests/issues/1292
import sys
if (2, 7) <= sys.version_info < (2, 7, 5):
    from .packages.urllib3.exceptions import FileModeWarning
    import warnings
    warnings.simplefilter('ignore', FileModeWarning)

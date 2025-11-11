# -*- coding: utf-8 -*-

"""
requests.models
~~~~~~~~~~~~~~~

This module contains the primary objects that power Requests.

"""

import datetime

# In case with_statement is not available
try:
    from __future__ import with_statement
except ImportError:
    pass

from .hooks import default_hooks
from .structures import CaseInsensitiveDict

from .auth import HTTPBasicAuth
from .cookies import cookiejar_from_dict, get_cookie_header, _basic_cookie_jar
from .packages.urllib3.fields import RequestField
from .packages.urllib3.filepost import encode_multipart_formdata
from .packages.urllib3.util import parse_url
from .exceptions import (
    HTTPError, RequestException, MissingSchema, InvalidURL,
    ChunkedEncodingError, ContentDecodingError)
from .utils import (
    guess_filename, get_auth_from_url, requote_uri, 
    stream_decode_response_unicode, to_key_val_list, parse_header_links, 
    iter_slices, guess_json_utf, super_len, to_native_string)
from .compat import (
    Callable, cookielib, urlunparse, urlsplit, urlencode, str, bytes, is_py2,
    chardet, json, is_py3, basestring)


REDIRECT_STATI = (
    # RFC 2616 (HTTP 1.1)
    301, 302, 303, 307,
    # RFC 6585 (Additional HTTP Status Codes)
    308,
)


class RequestEncodingMixin(object):
    @property
    def path_url(self):
        """Build the path URL to use."""

        url = []

        p = parse_url(self.url)

        path = p.path
        if not path:
            path = '/'

        url.append(path)

        query = p.query
        if query:
            url.append('?')
            url.append(query)

        return ''.join(url)

    @staticmethod
    def _encode_params(data):
        """Encode parameters in a piece of data.

        Will successfully encode parameters when passed as a dict or a list of
        2-tuples. Order is retained if data is a list of 2-tuples but arbitrary
        if parameters are supplied as a dict.
        """

        if isinstance(data, (str, bytes)):
            return data
        elif hasattr(data, 'read'):
            return data
        elif hasattr(data, '__iter__'):
            result = []
            for k, v in to_key_val_list(data):
                if isinstance(v, (str, bytes)) or not hasattr(v, '__iter__'):
                    v = [v]
                for val in v:
                    if val is not None:
                        result.append(
                            (k.encode('utf-8') if isinstance(k, str) else k,
                             val.encode('utf-8') if isinstance(val, str) else val))
            return urlencode(result, doseq=True)
        else:
            return data

    @staticmethod
    def _encode_files(files, data):
        """Build the body for a multipart/form-data request.

        Will successfully encode files when passed as a dict or a list of
        2-tuples. Order is retained if data is a list of 2-tuples.

        """
        if (not files):
            return None

        new_fields = []
        fields = to_key_val_list(data or {})
        files = to_key_val_list(files or {})

        for (k, v) in fields:
            # support for explicit filename
            if isinstance(v, (list, tuple)):
                if len(v) == 2 and isinstance(v[0], basestring):
                    fn, fp = v
                    new_fields.append((k, (fn, fp)))
                else:
                    for val in v:
                        new_fields.append((k, val))
            else:
                new_fields.append((k, v))

        for (k, v) in files:
            # support for explicit filename
            if isinstance(v, (list, tuple)):
                if len(v) == 3:
                    fn, fp, ft = v
                else:
                    fn, fp = v
                    ft = None
            else:
                fn = guess_filename(v) or k
                fp = v
                ft = None

            if isinstance(fp, (str, bytes, bytearray)):
                new_fields.append((k, (fn, fp, ft)))
            else:
                rf = RequestField(name=k, data=fp, filename=fn, headers={'Content-Type': ft})
                new_fields.append(rf.render_headers())

        body, content_type = encode_multipart_formdata(new_fields)

        return body, content_type


class RequestHooksMixin(object):
    def register_hook(self, event, hook):
        """Properly register a hook."""

        if event not in self.hooks:
            raise ValueError('Unsupported event name, received %s' % (event,))

        if isinstance(hook, Callable):
            self.hooks[event].append(hook)
        elif hasattr(hook, '__iter__'):
            self.hooks[event].extend(h for h in hook if isinstance(h, Callable))

    def deregister_hook(self, event, hook):
        """Deregister a previously registered hook.

        Returns True if the hook existed, False if not.
        """

        try:
            self.hooks[event].remove(hook)
            return True
        except ValueError:
            return False


class Request(RequestEncodingMixin, RequestHooksMixin):
    """A user-created :class:`Request <Request>` object.

    Used to prepare a :class:`PreparedRequest <PreparedRequest>`, which is sent to the
    server.

    :param method: HTTP method to use.
    :param url: URL to send.
    :param headers: dictionary of headers to send.
    :param files: dictionary of {filename: fileobject} files to multipart upload.
    :param data: the body to attach to the request. If a dictionary is provided, form-encoding will take place.
    :param params: dictionary of URL parameters to append to the URL.
    :param auth: Auth handler or (user, pass) tuple.
    :param cookies: dictionary or CookieJar of cookies to attach to this request.
    :param hooks: dictionary of callback hooks, for internal usage.

    """
    def __init__(self, 
        method=None, url=None, headers=None, files=None, data=None,
        params=None, auth=None, cookies=None, hooks=None, json=None):

        # Default empty dicts for dict params.
        data = [] if data is None else data
        files = [] if files is None else files
        headers = {} if headers is None else headers
        params = {} if params is None else params
        hooks = {} if hooks is None else hooks

        self.hooks = default_hooks()
        for (k, v) in list(hooks.items()):
            self.register_hook(event=k, hook=v)

        self.method = method
        self.url = url
        self.headers = headers
        self.files = files
        self.data = data
        self.json = json
        self.params = params
        self.auth = auth
        self.cookies = cookies

    def __repr__(self):
        return '<Request [%s]>' % (self.method)

    def prepare(self):
        """Constructs a :class:`PreparedRequest <PreparedRequest>` for transmission and returns it."""
        p = PreparedRequest()
        p.prepare(
            method=self.method,
            url=self.url,
            headers=self.headers,
            files=self.files,
            data=self.data,
            json=self.json,
            params=self.params,
            auth=self.auth,
            cookies=self.cookies,
            hooks=self.hooks,
        )
        return p


class PreparedRequest(RequestEncodingMixin, RequestHooksMixin):
    """The fully mutable :class:`PreparedRequest <PreparedRequest>` object,
    containing the exact bytes that will be sent to the server.

    Generated from either a :class:`Request <Request>` object or created
    directly by user.

    :param method: HTTP method to use.
    :param url: URL to send.
    :param headers: dictionary of headers to send.
    :param files: dictionary of {filename: fileobject} files to multipart upload.
    :param data: the body to attach to the request. If a dictionary is provided, form-encoding will take place.
    :param params: dictionary of URL parameters to append to the URL.
    :param auth: Auth handler or (user, pass) tuple.
    :param cookies: dictionary or CookieJar of cookies to attach to this request.
    :param hooks: dictionary of callback hooks, for internal usage.

    """
    def __init__(self):
        # Default empty dicts for dict params.
        self.method = None
        self.url = None
        self.headers = None
        self.body = None
        self.hooks = default_hooks()
        self._cookies = None

    def prepare(self, 
        method=None, url=None, headers=None, files=None, data=None,
        params=None, auth=None, cookies=None, hooks=None, json=None):
        """Prepares the entire request with the given parameters."""

        self.prepare_method(method)
        self.prepare_url(url, params)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, files, json)
        self.prepare_auth(auth, url)

        # Note that prepare_auth must be last to enable authentication schemes
        # that use the request body (e.g. OAuth1)

        # This MUST be called before prepare_hooks, as the hooks may be used
        # to modify the request before sending.
        self.prepare_hooks(hooks)

    def __repr__(self):
        return '<PreparedRequest [%s]>' % (self.method)

    def copy(self):
        p = PreparedRequest()
        p.method = self.method
        p.url = self.url
        p.headers = self.headers.copy()
        p.body = self.body
        p.hooks = self.hooks
        p._cookies = _basic_cookie_jar(self._cookies)
        p.auth = self.auth
        return p

    def prepare_method(self, method):
        """Prepares the given HTTP method."""
        self.method = method
        if self.method is not None:
            self.method = self.method.upper()

    def prepare_url(self, url, params):
        """Prepares the given HTTP URL."""
        # Support for unicode domain names and paths.
        try:
            url = url.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            pass

        # Don't do any URL preparation for non-HTTP schemes like `mailto`,
        # `data` etc. Without this abstraction of the scheme, we would have to
        # url-quote the whole URL.
        if ':' in url and not url.lower().startswith('http'):
            self.url = url
            return

        # Remove leading whitespaces from url
        url = url.lstrip()

        # Parse the url and make sure we have a scheme
        if not url.startswith('http'):
            raise MissingSchema("Invalid URL %r: No schema supplied. Perhaps you meant http://%s?" % (url, url))

        # Facilitate relative urls
        if url.startswith('//'):
            raise InvalidURL("Invalid URL %r: Relative URLs are not supported." % (url,))

        # Append params to url
        if params:
            enc_params = self._encode_params(params)
            if enc_params:
                if '?' in url:
                    url = '%s&%s' % (url, enc_params)
                else:
                    url = '%s?%s' % (url, enc_params)
        self.url = requote_uri(url)

    def prepare_headers(self, headers):
        """Prepares the given HTTP headers."""

        if headers:
            self.headers = CaseInsensitiveDict((to_native_string(k), v) for k, v in headers.items())
        else:
            self.headers = CaseInsensitiveDict()

    def prepare_body(self, data, files, json=None):
        """Prepares the given HTTP body data."""

        # Check if file, fo, generator, iterator.
        # If not, run through normal process.

        # Nottin' on you.
        body = None
        content_type = None

        if not data and json is not None:
            content_type = 'application/json'
            body = json.dumps(json)
            if not isinstance(body, bytes):
                body = body.encode('utf-8')

        is_stream = all([
            hasattr(data, '__iter__'),
            not isinstance(data, (basestring, list, tuple, dict))
        ])

        if is_stream:
            try:
                self.headers['Transfer-Encoding'] = 'chunked'
            except TypeError:
                self.headers = CaseInsensitiveDict(self.headers)
                self.headers['Transfer-Encoding'] = 'chunked'
        else:
            # Multi-part file uploads.
            if files:
                (body, content_type) = self._encode_files(files, data)
            else:
                if data:
                    body = self._encode_params(data)
                    if isinstance(data, basestring) or hasattr(data, 'read'):
                        content_type = None
                    else:
                        content_type = 'application/x-www-form-urlencoded'

            self.prepare_content_length(body)

            # Add content-type if it wasn't set.
            if content_type and ('content-type' not in self.headers):
                self.headers['Content-Type'] = content_type

        self.body = body


    def prepare_content_length(self, body):
        """Prepares the given HTTP content length."""
        if hasattr(body, 'seek') and hasattr(body, 'tell'):
            self.headers['Content-Length'] = str(super_len(body))
        elif body is not None:
            l = super_len(body)
            if l:
                self.headers['Content-Length'] = str(l)
        elif self.method not in ('GET', 'HEAD') and self.headers.get('Content-Length') is None:
            self.headers['Content-Length'] = '0'


    def prepare_auth(self, auth, url=''):
        """Prepares the given HTTP auth data."""

        # If no Auth is explicitly provided, extract it from the URL.
        if auth is None:
            url_auth = get_auth_from_url(self.url)
            auth = url_auth if any(url_auth) else None

        if auth:
            if isinstance(auth, tuple) and len(auth) == 2:
                # special-case basic_auth
                auth = HTTPBasicAuth(*auth)

            # Allow auth to make its changes.
            r = auth(self)

            # Update self to reflect the auth changes.
            self.__dict__.update(r.__dict__)

            # Re-calculate Content-Length if appropriate.
            self.prepare_content_length(self.body)

        self.auth = auth

    def prepare_cookies(self, cookies):
        """Prepares the given HTTP cookie data.

        This function eventually generates a ``Cookie`` header from the
        given cookies using cookielib. Due to cookielib's design, the header
        will not be regenerated if it already exists, meaning this function
        can only be called once for the life of the
        :class:`PreparedRequest <PreparedRequest>` object. Any subsequent calls to
        this function will not regenerate the cookie header.
        """
        if isinstance(cookies, cookielib.CookieJar):
            self._cookies = cookies
        else:
            self._cookies = cookiejar_from_dict(cookies)

        cookie_header = get_cookie_header(self._cookies, self)
        if cookie_header is not None:
            self.headers['Cookie'] = cookie_header

    def prepare_hooks(self, hooks):
        """Prepares the given hooks."""
        # hooks can be passed as None to the prepare method and to this
        # method. To prevent iterating over None, simply use an empty list
        # if hooks is False-y
        hooks = hooks or []
        for event in hooks:
            self.register_hook(event, hooks[event])


class Response(object):
    """The :class:`Response <Response>` object, which contains a
    server's response to an HTTP request.
    """

    __attrs__ = [
        '_content', 'status_code', 'headers', 'url', 'history',
        'encoding', 'reason', 'cookies', 'elapsed', 'request'
    ]

    def __init__(self):
        self._content = False
        self._content_consumed = False

        #: Integer Code of responded HTTP Status, e.g. 404 or 200.
        self.status_code = None

        #: Case-insensitive Dictionary of Response Headers.
        #: For example, ``headers['content-encoding']`` will return the
        #: value of a ``'Content-Encoding'`` response header.
        self.headers = CaseInsensitiveDict()

        #: File-like object representation of response (for advanced usage).
        self.raw = None

        #: Final URL location of Response.
        self.url = None

        #: Encoding to decode with when accessing r.text.
        self.encoding = None

        #: A list of :class:`Response <Response>` objects from
        #: the history of the Request. Any redirect responses will end
        #: up here. The list is sorted from the oldest to the most recent request.
        self.history = []

        #: Textual reason of responded HTTP Status, e.g. "Not Found" or "OK".
        self.reason = None

        #: A CookieJar of Cookies the server sent back.
        self.cookies = cookiejar_from_dict({})

        #: The amount of time elapsed between sending the request
        #: and the arrival of the response (as a timedelta).
        #: This property specifically measures the time taken between sending the
        #: first byte of the request and finishing parsing the headers.
        self.elapsed = datetime.timedelta(0)

        #: The :class:`PreparedRequest <PreparedRequest>` object to which this
        #: is a response.
        self.request = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)

    @property
    def content(self):
        """Content of the response, in bytes."""

        if self._content is False:
            # Read the contents.
            if self._content_consumed:
                raise RuntimeError(
                    'The content for this response was already consumed')

            if self.status_code == 0:
                self._content = None
            else:
                self._content = b''.join(self.iter_content(10 * 1024)) or b''

        self._content_consumed = True
        return self._content

    @property
    def text(self):
        """Content of the response, in unicode.

        If Response.encoding is None, encoding will be guessed using
        ``chardet``.

        The encoding of the response content is determined based solely on HTTP
        headers, following RFC 2616 to the letter. If you can take advantage of
        non-HTTP knowledge to make a better guess at the encoding, you should
        set ``r.encoding`` appropriately before accessing this property.
        """

        # Try charset from content-type
        content = None
        encoding = self.encoding

        if not self.content:
            return str('')

        # Fallback to auto-detect encoding.
        if self.encoding is None:
            encoding = self.apparent_encoding

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors='replace')
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake. 
            #
            # A TypeError can be raised if encoding is None
            #
            # So we try blindly encoding.
            content = str(self.content, errors='replace')

        return content

    @property
    def json(self, **kwargs):
        """Returns the json-encoded content of a response, if any."""

        if not self.encoding and len(self.content) > 3:
            # No encoding set. JSON RFC 4627 section 3 states we should expect
            # UTF-8, -16 or -32. Detect which one to use; If the detection or
            # decoding fails, fall back to `self.text` (using chardet to make
            # a best guess).
            encoding = guess_json_utf(self.content)
            if encoding is not None:
                try:
                    return json.loads(
                        self.content.decode(encoding),
                        **kwargs
                    )
                except UnicodeDecodeError:
                    # Wrong UTF codec detected; fall back to chardet
                    pass
        return json.loads(self.text, **kwargs)

    @property
    def apparent_encoding(self):
        """The apparent encoding, provided by the chardet library"""
        return chardet.detect(self.content)['encoding']

    def iter_content(self, chunk_size=1, decode_unicode=False):
        """Iterates over the response. When stream=True is set on the
        request, this avoids reading the content at once into memory for
        large responses. The chunk size is the number of bytes it should
        read into memory. This is not necessarily the length of each item
        returned as decoding can take place.

        chunk_size must be of type int.
        """

        def generate():
            # Special case for urllib3.
            if hasattr(self.raw, 'stream'):
                try:
                    for chunk in self.raw.stream(chunk_size, decode_content=True):
                        yield chunk
                except ProtocolError as e:
                    raise ChunkedEncodingError(e)
                except DecodeError as e:
                    raise ContentDecodingError(e)

            else:
                # Standard file-like object.
                while True:
                    chunk = self.raw.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            self._content_consumed = True

        if self._content_consumed and isinstance(self._content, bool):
            raise RuntimeError(
                'The content for this response was already consumed')
        elif chunk_size is not None and not isinstance(chunk_size, int):
            raise TypeError("chunk_size must be an int, not %s." % type(chunk_size))
        # simulate reading small chunks of the content
        reused_chunks = iter_slices(self._content, chunk_size)

        stream_chunks = generate()

        chunks = reused_chunks if self._content_consumed else stream_chunks

        if decode_unicode:
            if self.encoding is None:
                self.encoding = self.apparent_encoding
            return stream_decode_response_unicode(chunks, self)
        return chunks

    def iter_lines(self, chunk_size=512, decode_unicode=None):
        """Iterates over the response data, one line at a time.  When
        stream=True is set on the request, this avoids reading the
        content at once into memory for large responses.

        .. note:: This method is not reentrant safe.
        """

        pending = None

        if decode_unicode is not None:
            decoder = stream_decode_response_unicode(self.iter_content(chunk_size), self)
        else:
            decoder = self.iter_content(chunk_size)

        for chunk in decoder:

            if pending is not None:
                chunk = pending + chunk

            if self.encoding:
                lines = chunk.splitlines()
            else:
                lines = chunk.split(b'\n')

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending

    @property
    def links(self):
        """Returns the parsed header links."""

        l = self.headers.get('link')

        if not l:
            return {}

        return parse_header_links(l)

    def raise_for_status(self):
        """Raises stored :class:`HTTPError`, if one occurred."""

        http_error_msg = ''

        if 400 <= self.status_code < 500:
            http_error_msg = '%s Client Error: %s' % (self.status_code, self.reason)

        elif 500 <= self.status_code < 600:
            http_error_msg = '%s Server Error: %s' % (self.status_code, self.reason)

        if http_error_msg:
            raise HTTPError(http_error_msg, response=self)

    def close(self):
        """Releases the connection back to the pool. Once this method has been
        called the underlying ``raw`` object must not be accessed again.

        *Note: Should not normally need to be called explicitly.*
        """
        if not self._content_consumed:
            self.raw.close()

        return self.raw.release_conn()

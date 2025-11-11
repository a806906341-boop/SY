# -*- coding: utf-8 -*-

"""
requests.status_codes
~~~~~~~~~~~~~~~~~~~~~

This module contains a case-insensitive dictionary of HTTP status codes.
"""

from .structures import CaseInsensitiveDict

# A dictionary of HTTP status codes.
codes = CaseInsensitiveDict()


def _init():
    # The following code is an adaptation of the status code list
    # provided by the http.server module in the Python standard library.
    # The only change is that we are using a case-insensitive dictionary.
    # The original copyright notice is included below.
    #
    # Copyright © 2001-2012 Python Software Foundation; All Rights Reserved
    #
    # Licensed under the Apache License, Version 2.0 (the "License");
    # you may not use this file except in compliance with the License.
    # You may obtain a copy of the License at
    #
    #     http://www.apache.org/licenses/LICENSE-2.0
    #
    # Unless required by applicable law or agreed to in writing, software
    # distributed under the License is distributed on an "AS IS" BASIS,
    # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    # See the License for the specific language governing permissions and
    # limitations under the License.

    codes['continue'] = 100
    codes['switching_protocols'] = 101
    codes['processing'] = 102

    codes['ok'] = 200
    codes['created'] = 201
    codes['accepted'] = 202
    codes['non_authoritative_information'] = 203
    codes['no_content'] = 204
    codes['reset_content'] = 205
    codes['partial_content'] = 206
    codes['multi_status'] = 207
    codes['already_reported'] = 208
    codes['im_used'] = 226

    codes['multiple_choices'] = 300
    codes['moved_permanently'] = 301
    codes['found'] = 302
    codes['see_other'] = 303
    codes['not_modified'] = 304
    codes['use_proxy'] = 305
    codes['switch_proxy'] = 306
    codes['temporary_redirect'] = 307
    codes['permanent_redirect'] = 308

    codes['bad_request'] = 400
    codes['unauthorized'] = 401
    codes['payment_required'] = 402
    codes['forbidden'] = 403
    codes['not_found'] = 404
    codes['method_not_allowed'] = 405
    codes['not_acceptable'] = 406
    codes['proxy_authentication_required'] = 407
    codes['request_timeout'] = 408
    codes['conflict'] = 409
    codes['gone'] = 410
    codes['length_required'] = 411
    codes['precondition_failed'] = 412
    codes['request_entity_too_large'] = 413
    codes['request_uri_too_long'] = 414
    codes['unsupported_media_type'] = 415
    codes['requested_range_not_satisfiable'] = 416
    codes['expectation_failed'] = 417
    codes['im_a_teapot'] = 418
    codes['misdirected_request'] = 421
    codes['unprocessable_entity'] = 422
    codes['locked'] = 423
    codes['failed_dependency'] = 424
    codes['upgrade_required'] = 426
    codes['precondition_required'] = 428
    codes['too_many_requests'] = 429
    codes['request_header_fields_too_large'] = 431
    codes['unavailable_for_legal_reasons'] = 451

    codes['internal_server_error'] = 500
    codes['not_implemented'] = 501
    codes['bad_gateway'] = 502
    codes['service_unavailable'] = 503
    codes['gateway_timeout'] = 504
    codes['http_version_not_supported'] = 505
    codes['variant_also_negotiates'] = 506
    codes['insufficient_storage'] = 507
    codes['loop_detected'] = 508
    codes['not_extended'] = 510
    codes['network_authentication_required'] = 511

_init() # Initialize the dictionary.

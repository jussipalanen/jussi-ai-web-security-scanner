"""HTTP status codes used by the API.

Defined locally rather than imported from Starlette, whose 422 constant was
renamed across versions.
"""

#: Unprocessable Content - the target was rejected by validation.
HTTP_422_UNPROCESSABLE = 422

#: Bad Gateway - the target was valid but could not be reached.
HTTP_502_BAD_GATEWAY = 502

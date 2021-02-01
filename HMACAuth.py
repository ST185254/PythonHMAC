import base64
import hashlib
import hmac
from datetime import datetime
from urllib.parse import urlparse

import requests
from _datetime import timezone


class HMACAuth(requests.auth.AuthBase):

    def __init__(self, enterprise_unit='0'):
        """
        Constructs all necessary attributes for the HMACAuth object.

        :param enterprise_unit: id of the nep enterprise unit the request applies to
        """
        self.enterprise_unit = enterprise_unit
        self.hmac_shared_key = '8cf8750cf3464cd6bc4f749e619b767b'
        self.hmac_secret_key = '584439a70d924a228dce13ef76915c17'
        self.nep_application_key = '8a00840567549da801678588c4360000'

    def __call__(self, request):
        """
        Constructs HMAC to uniquely sign a HTTP authorization request.

        :param request: the HTTP request
        :return: the full credentials string for the HTTP Authorization header
        """
        now = datetime.now(tz=timezone.utc)
        now = datetime(now.year, now.month, now.day, hour=now.hour,
                       minute=now.minute, second=now.second)

        isoDate = now.isoformat(timespec='milliseconds') + 'Z'
        utcDate = now.strftime('%a, %d %b %Y %H:%M:%S GMT')

        # Get the one-time key with the current date string
        key = self.customKey(isoDate)

        # Parse date string from header to a native representation
        parsedUrl = urlparse(request.url)

        # Get data from the request headers to sign in the HMAC string
        request.headers['Date'] = utcDate
        request.headers['Content-Type'] = 'application/json'
        request.headers['Accept'] = 'application/json'
        request.headers['nep-application-key'] = self.nep_application_key
        request.headers['nep-correlation-id'] = '2021-0201'
        request.headers['nep-organization'] = 'mock-customer-restaurant-001'

        if self.enterprise_unit != '0':
            request.headers['nep-enterprise-unit'] = self.enterprise_unit

        # Add the request data to the sign-able content
        self.addAuthorization(request, key)

        return request

    def customKey(self, date):
        """
        Generates a unique one-time key from the secret key and date string.

        :param date: the date string (ISO-8601 format)
        :return: a unique UTF-8 encoded key
        """
        key = self.hmac_secret_key + date
        return key.encode('utf-8')

    def addAuthorization(self, request, key):
        """
        Generates the HMAC signature for a HTTP authorization request.

        :param request: the HTTP request
        :param key: the access key string
        """
        parsedUrl = urlparse(request.url)
        pathAndQuery = parsedUrl.path
        if parsedUrl.query:
            pathAndQuery += '?' + parsedUrl.query

        # HTTP method and path/query are required parameters
        values = [request.method, pathAndQuery, request.headers['Content-Type'], request.headers['nep-application-key']]

        # Add the HTTP header values to the sign-able content

        if 'nep-correlation-id' in request.headers:
            values.append(request.headers['nep-correlation-id'])

        values.append(request.headers['nep-organization'])

        separator = "\n"
        params = separator.join(values)

        # Convert the sign-able content to UTF-8 encoding
        encodedParams = params.encode('utf-8')

        # Calculate the HMAC using the SHA-512 algorithm
        hash = hmac.new(key, encodedParams, hashlib.sha512)
        digest = base64.b64encode(hash.digest()).decode('utf-8')

        # Concatenate the shared key and HMAC strings (UTF-8)
        accessKey = self.hmac_shared_key + ":" + digest

        # Add the signature to the HTTP authorization header
        request.headers['Authorization'] = "AccessKey " + accessKey

# -*- coding: utf-8 -*-
# openpgpwrapper.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


"""
Infrastructure for using OpenPGP keys in Key Manager.
"""


import re

from leap.common.keymanager.errors import (
    KeyNotFound,
    KeyAlreadyExists,
)
from leap.common.keymanager.keys import (
    EncryptionKey,
    KeyTypeWrapper,
)
from leap.common.keymanager.gpg import GPGWrapper


class OpenPGPKey(EncryptionKey):
    """
    Base class for OpenPGP keys.
    """


class OpenPGPWrapper(KeyTypeWrapper):
    """
    A wrapper for OpenPGP keys.
    """

    def __init__(self, gnupghome=None):
        self._gpg = GPGWrapper(gnupghome=gnupghome)

    def _build_key(self, address, result):
        """
        Build an OpenPGPWrapper key for C{address} based on C{result} from
        local storage.

        @param address: The address bound to the key.
        @type address: str
        @param result: Result obtained from GPG storage.
        @type result: dict
        """
        key_data = self._gpg.export_keys(result['fingerprint'], secret=False)
        return OpenPGPKey(
            address,
            key_id=result['keyid'],
            fingerprint=result['fingerprint'],
            key_data=key_data,
            length=result['length'],
            expiry_date=result['expires'],
            validation=None,  # TODO: verify for validation.
        )

    def gen_key(self, address):
        """
        Generate an OpenPGP keypair for C{address}.

        @param address: The address bound to the key.
        @type address: str
        @return: The key bound to C{address}.
        @rtype: OpenPGPKey
        @raise KeyAlreadyExists: If key already exists in local database.
        """
        try:
            self.get_key(address)
            raise KeyAlreadyExists()
        except KeyNotFound:
            pass
        params = self._gpg.gen_key_input(
            key_type='RSA',
            key_length=4096,
            name_real=address,
            name_email=address,
            name_comment='Generated by LEAP Key Manager.')
        self._gpg.gen_key(params)
        return self.get_key(address)

    def get_key(self, address):
        """
        Get key bound to C{address} from local storage.

        @param address: The address bound to the key.
        @type address: str

        @return: The key bound to C{address}.
        @rtype: OpenPGPKey
        @raise KeyNotFound: If the key was not found on local storage.
        """
        m = re.compile('.*<%s>$' % address)
        keys = self._gpg.list_keys(secret=False)

        def bound_to_address(key):
             return bool(filter(lambda u: m.match(u), key['uids']))

        try:
            bound_key = filter(bound_to_address, keys).pop()
            return self._build_key(address, bound_key)
        except IndexError:
            raise KeyNotFound(address)

    def put_key(self, data):
        """
        Put key contained in {data} in local storage.

        @param key: The key data to be stored.
        @type key: str
        """
        self._gpg.import_keys(data)

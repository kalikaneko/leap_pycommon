# -*- coding: utf-8 -*-
# openpgp.py
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
import logging
import os
import re
import shutil
import tempfile

from leap.common.check import leap_assert, leap_assert_type
from leap.common.keymanager import errors

from leap.common.keymanager.keys import (
    EncryptionKey,
    EncryptionScheme,
    is_address,
    keymanager_doc_id,
    build_key_from_dict,
)
from leap.common.keymanager.gpg import GPGWrapper

logger = logging.getLogger(__name__)


#
# gpg wrapper and decorator
#

def unitary_gpgwrapper(key_data=None):
    """
    Returns a unitary gpg wrapper that implements context manager
    protocol.

    @param key_data: ASCII armored key data.
    @type key_data: str

    @return: a GPGWrapper instance
    @rtype: GPGWrapper
    """
    # TODO do here checks on key_data
    return UnitaryGPGWrapper(key_data=key_data)


def with_unitary_gpg(fun):
    """
    Decorator to add a unitary gpg wrapper as context
    to gpg related functions.

    Decorated functions are supposed to return a function whose only
    argument is a gpgwrapper instance.
    """
    def wrapped(*args, **kwargs):
        val = None
        if len(args) == 2:
            key_data = getattr(args[1], 'key_data', None)
        else:
            key_data = None

        with unitary_gpgwrapper(key_data) as gpg:
            val = fun(*args, **kwargs)(gpg)

            # TODO should inspect gpg result here
            # and signal any gpg errors found

            stderr = getattr(val, 'stderr', None)
            if stderr:
                logger.error("%s" % (stderr,))

            if hasattr(val, 'data'):
                val = val.data
        return val
    return wrapped


class UnitaryGPGWrapper(object):
    """
    A context manager returning a temporary GPG wrapper keyring, which
    contains exactly zero or one keys.

    Temporary unitary keyrings allow the to use GPG's facilities for exactly
    one key. This function creates an empty temporary keyring and imports
    C{key_data} if it is not None.
    """
    def __init__(self, key_data=None):
        """
        @param key_data: ASCII armored key data.
        @type key_data: str
        """
        self._gpg = None
        self.key_data = key_data

    def __enter__(self):
        """
        Calls the unitary gpgwrapper initializer

        @return: A GPG wrapper with a unitary keyring.
        @rtype: gnupg.GPG
        """
        self._build_unitary_gpgwrapper()
        return self._gpg

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Ensures the unitary gpgwrapper is properly destroyed.
        """
        # TODO handle exceptions and log here
        self._destroy_unitary_gpgwrapper()

    def _build_unitary_gpgwrapper(self):
        """
        Builds the unitary gpgwrapper.
        """
        self._gpg = GPGWrapper(gnupghome=tempfile.mkdtemp())
        leap_assert(len(self._gpg.list_keys()) is 0, 'Keyring not empty.')
        if self.key_data:
            self._gpg.import_keys(self.key_data)
            leap_assert(
                len(self._gpg.list_keys()) is 1,
                'Unitary keyring has wrong number of keys: %d.'
                % len(self._gpg.list_keys()))

    def _destroy_unitary_gpgwrapper(self):
        """
        Securely erase a unitary keyring.
        """
        # TODO: implement some kind of wiping of data or a more
        # secure way that
        # does not write to disk.
        # --- maybe we could mmap the file?

        try:
            for secret in [True, False]:
                for key in self._gpg.list_keys(secret=secret):
                    self._gpg.delete_keys(
                        key['fingerprint'],
                        secret=secret)
            leap_assert(len(self._gpg.list_keys()) is 0, 'Keyring not empty!')

        except:
            raise

        finally:
            leap_assert(self._gpg.gnupghome != os.path.expanduser('~/.gnupg'),
                        "watch out! Tried to remove default gnupg home!")
            shutil.rmtree(self._gpg.gnupghome)


#
# API functions
#

@with_unitary_gpg
def encrypt_sym(data, passphrase):
    """
    Encrypt C{data} with C{passphrase}.

    @param data: The data to be encrypted.
    @type data: str
    @param passphrase: The passphrase used to encrypt C{data}.
    @type passphrase: str

    @return: The encrypted data.
    @rtype: str
    """
    return lambda gpg: gpg.encrypt(
        data, None, passphrase=passphrase,
        symmetric=True)


@with_unitary_gpg
def decrypt_sym(data, passphrase):
    """
    Decrypt C{data} with C{passphrase}.

    @param data: The data to be decrypted.
    @type data: str
    @param passphrase: The passphrase used to decrypt C{data}.
    @type passphrase: str

    @return: The decrypted data.
    @rtype: str
    """
    return lambda gpg: gpg.decrypt(
        data, passphrase=passphrase)


@with_unitary_gpg
def encrypt_asym(data, key, passphrase=None):
    """
    Encrypt C{data} using public @{key}.

    @param data: The data to be encrypted.
    @type data: str
    @param key: The key used to encrypt.
    @type key: OpenPGPKey

    @return: The encrypted data.
    @rtype: str
    """
    leap_assert(key.private is False, 'Key is not public.')
    return lambda gpg: gpg.encrypt(
        data, key.fingerprint, passphrase=passphrase,
        symmetric=False)


@with_unitary_gpg
def decrypt_asym(data, key, passphrase=None):
    """
    Decrypt C{data} using private @{key}.

    @param data: The data to be decrypted.
    @type data: str
    @param key: The key used to decrypt.
    @type key: OpenPGPKey

    @return: The decrypted data.
    @rtype: str
    """
    leap_assert(key.private is True, 'Key is not private.')
    return lambda gpg: gpg.decrypt(
        data, passphrase=passphrase)


@with_unitary_gpg
def is_encrypted(data):
    """
    Return whether C{data} was encrypted using OpenPGP.

    @param data: The data we want to know about.
    @type data: str

    @return: Whether C{data} was encrypted using this wrapper.
    @rtype: bool
    """
    return lambda gpg: gpg.is_encrypted(data)


@with_unitary_gpg
def is_encrypted_sym(data):
    """
    Return whether C{data} was encrypted using a public OpenPGP key.

    @param data: The data we want to know about.
    @type data: str

    @return: Whether C{data} was encrypted using this wrapper.
    @rtype: bool
    """
    return lambda gpg: gpg.is_encrypted_sym(data)


@with_unitary_gpg
def is_encrypted_asym(data):
    """
    Return whether C{data} was asymmetrically encrypted using OpenPGP.

    @param data: The data we want to know about.
    @type data: str

    @return: Whether C{data} was encrypted using this wrapper.
    @rtype: bool
    """
    return lambda gpg: gpg.is_encrypted_asym(data)


@with_unitary_gpg
def sign(data, key):
    """
    Sign C{data} with C{key}.

    @param data: The data to be signed.
    @type data: str
    @param key: The key to be used to sign.
    @type key: OpenPGPKey

    @return: The ascii-armored signed data.
    @rtype: str
    """
    leap_assert_type(key, OpenPGPKey)
    leap_assert(key.private is True)

    return lambda gpg: gpg.sign(data, keyid=key.key_id)


@with_unitary_gpg
def verify(data, key):
    """
    Verify signed C{data} with C{key}.

    @param data: The data to be verified.
    @type data: str
    @param key: The key to be used on verification.
    @type key: OpenPGPKey

    @return: The ascii-armored signed data.
    @rtype: str
    """
    leap_assert_type(key, OpenPGPKey)
    leap_assert(key.private is False)
    return lambda gpg: gpg.verify(data).valid


#
# Helper functions
#


def _build_key_from_gpg(address, key, key_data):
    """
    Build an OpenPGPKey for C{address} based on C{key} from
    local gpg storage.

    ASCII armored GPG key data has to be queried independently in this
    wrapper, so we receive it in C{key_data}.

    @param address: The address bound to the key.
    @type address: str
    @param key: Key obtained from GPG storage.
    @type key: dict
    @param key_data: Key data obtained from GPG storage.
    @type key_data: str
    @return: An instance of the key.
    @rtype: OpenPGPKey
    """
    return OpenPGPKey(
        address,
        key_id=key['keyid'],
        fingerprint=key['fingerprint'],
        key_data=key_data,
        private=True if key['type'] == 'sec' else False,
        length=key['length'],
        expiry_date=key['expires'],
        validation=None,  # TODO: verify for validation.
    )


#
# The OpenPGP wrapper
#

class OpenPGPKey(EncryptionKey):
    """
    Base class for OpenPGP keys.
    """


class OpenPGPScheme(EncryptionScheme):
    """
    A wrapper for OpenPGP keys.
    """

    def __init__(self, soledad):
        """
        Initialize the OpenPGP wrapper.

        @param soledad: A Soledad instance for key storage.
        @type soledad: leap.soledad.Soledad
        """
        EncryptionScheme.__init__(self, soledad)

    def gen_key(self, address):
        """
        Generate an OpenPGP keypair bound to C{address}.

        @param address: The address bound to the key.
        @type address: str
        @return: The key bound to C{address}.
        @rtype: OpenPGPKey
        @raise KeyAlreadyExists: If key already exists in local database.
        """
        # make sure the key does not already exist
        leap_assert(is_address(address), 'Not an user address: %s' % address)
        try:
            self.get_key(address)
            raise errors.KeyAlreadyExists(address)
        except errors.KeyNotFound:
            pass

        def _gen_key(gpg):
            params = gpg.gen_key_input(
                key_type='RSA',
                key_length=4096,
                name_real=address,
                name_email=address,
                name_comment='Generated by LEAP Key Manager.')
            gpg.gen_key(params)
            pubkeys = gpg.list_keys()
            # assert for new key characteristics
            leap_assert(
                len(pubkeys) is 1,  # a unitary keyring!
                'Keyring has wrong number of keys: %d.' % len(pubkeys))
            key = gpg.list_keys(secret=True).pop()
            leap_assert(
                len(key['uids']) is 1,  # with just one uid!
                'Wrong number of uids for key: %d.' % len(key['uids']))
            leap_assert(
                re.match('.*<%s>$' % address, key['uids'][0]) is not None,
                'Key not correctly bound to address.')
            # insert both public and private keys in storage
            for secret in [True, False]:
                key = gpg.list_keys(secret=secret).pop()
                openpgp_key = _build_key_from_gpg(
                    address, key,
                    gpg.export_keys(key['fingerprint'], secret=secret))
                self.put_key(openpgp_key)

        with unitary_gpgwrapper() as gpg:
            # TODO: inspect result, or use decorator
            _gen_key(gpg)

        return self.get_key(address, private=True)

    def get_key(self, address, private=False):
        """
        Get key bound to C{address} from local storage.

        @param address: The address bound to the key.
        @type address: str
        @param private: Look for a private key instead of a public one?
        @type private: bool

        @return: The key bound to C{address}.
        @rtype: OpenPGPKey
        @raise KeyNotFound: If the key was not found on local storage.
        """
        leap_assert(is_address(address), 'Not an user address: %s' % address)
        doc = self._get_key_doc(address, private)
        if doc is None:
            raise errors.KeyNotFound(address)
        return build_key_from_dict(OpenPGPKey, address, doc.content)

    def put_key_raw(self, data):
        """
        Put key contained in raw C{data} in local storage.

        @param data: The key data to be stored.
        @type data: str
        """
        # TODO: add more checks for correct key data.
        leap_assert(data is not None, 'Data does not represent a key.')

        def _put_key_raw(gpg):

            privkey = None
            pubkey = None

            try:
                privkey = gpg.list_keys(secret=True).pop()
            except IndexError:
                pass
            pubkey = gpg.list_keys(secret=False).pop()  # unitary keyring
            # extract adress from first uid on key
            match = re.match('.*<([\w.-]+@[\w.-]+)>.*', pubkey['uids'].pop())
            leap_assert(match is not None, 'No user address in key data.')
            address = match.group(1)
            if privkey is not None:
                match = re.match(
                    '.*<([\w.-]+@[\w.-]+)>.*', privkey['uids'].pop())
                leap_assert(match is not None, 'No user address in key data.')
                privaddress = match.group(1)
                leap_assert(
                    address == privaddress,
                    'Addresses in pub and priv key differ.')
                leap_assert(
                    pubkey['fingerprint'] == privkey['fingerprint'],
                    'Fingerprints for pub and priv key differ.')
                # insert private key in storage
                openpgp_privkey = _build_key_from_gpg(
                    address, privkey,
                    gpg.export_keys(privkey['fingerprint'], secret=True))
                self.put_key(openpgp_privkey)
            # insert public key in storage
            openpgp_pubkey = _build_key_from_gpg(
                address, pubkey,
                gpg.export_keys(pubkey['fingerprint'], secret=False))
            self.put_key(openpgp_pubkey)

        with unitary_gpgwrapper(data) as gpg:
            # TODO: inspect result, or use decorator
            _put_key_raw(gpg)

    def put_key(self, key):
        """
        Put C{key} in local storage.

        @param key: The key to be stored.
        @type key: OpenPGPKey
        """
        doc = self._get_key_doc(key.address, private=key.private)
        if doc is None:
            self._soledad.create_doc_from_json(
                key.get_json(),
                doc_id=keymanager_doc_id(
                    OpenPGPKey, key.address, key.private))
        else:
            doc.set_json(key.get_json())
            self._soledad.put_doc(doc)

    def _get_key_doc(self, address, private=False):
        """
        Get the document with a key (public, by default) bound to C{address}.

        If C{private} is True, looks for a private key instead of a public.

        @param address: The address bound to the key.
        @type address: str
        @param private: Whether to look for a private key.
        @type private: bool
        @return: The document with the key or None if it does not exist.
        @rtype: leap.soledad.backends.leap_backend.LeapDocument
        """
        return self._soledad.get_doc(
            keymanager_doc_id(OpenPGPKey, address, private))

    def delete_key(self, key):
        """
        Remove C{key} from storage.

        @param key: The key to be removed.
        @type key: EncryptionKey
        """
        leap_assert(key.__class__ is OpenPGPKey, 'Wrong key type.')
        stored_key = self.get_key(key.address, private=key.private)
        if stored_key is None:
            raise errors.KeyNotFound(key)
        if stored_key.__dict__ != key.__dict__:
            raise errors.KeyAttributesDiffer(key)
        doc = self._soledad.get_doc(
            keymanager_doc_id(OpenPGPKey, key.address, key.private))
        self._soledad.delete_doc(doc)

# -*- encoding: utf-8 -*-
"""
tests.test_coring module

"""

import pysodium

def test_cryptoStuff():
    """

    """
    seedl = pysodium.crypto_sign_SEEDBYTES
    assert seedl == 32

    seed = pysodium.randombytes(pysodium.crypto_sign_SEEDBYTES)
    assert  len(seed) == 32
    # seed = (b'J\xeb\x06\xf2BA\xd6/T\xe1\xe2\xe2\x838\x8a\x99L\xd9\xb5(\\I\xccRb\xc8\xd5\xc7Y\x1b\xb6\xf0')


    # Ann's seed
    seed = (b'PTi\x15\xd5\xd3`\xf1u\x15}^r\x9bfH\x02l\xc6\x1b\x1d\x1c\x0b9\xd7{\xc0_\xf2K\x93`')
    assert  len(seed) == 32

    #  try key stretching from 16 bytes using  pysodium.crypto_pwhash()
    saltl = pysodium.crypto_pwhash_SALTBYTES
    assert saltl == 16
    salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)
    assert len(salt) == 16
    #  salt = b'\x19?\xfa\xc7\x8f\x8b\x7f\x8b\xdbS"$\xd7[\x85\x87'

    # algorithm default is argon2id
    seed = pysodium.crypto_pwhash(outlen=32,
                                    passwd="",
                                    salt=salt,
                                    opslimit=pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    memlimit=pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
                                    alg=pysodium.crypto_pwhash_ALG_DEFAULT)

    assert len(seed) == 32
    #  seed = (b'\xa9p\x89\x7f+\x0e\xc4\x9c\xf2\x01r\xafTI\xc0\xfa\xac\xd5\x99\xf8O\x8f=\x843\xa2\xb6e\x9fO\xff\xd0')


    # creates signing/verification key pair
    verkey, sigkey = pysodium.crypto_sign_seed_keypair(seed)
    assert len(verkey) == 32
    assert len(sigkey) == 64
    # sigkey is verkey and seed concatenated. Not sure why libsodium does this
    assert seed == sigkey[:32]
    assert verkey == sigkey[32:]

    # vk = (b'B\xdd\xbb}8V\xa0\xd6lk\xcf\x15\xad9\x1e\xa7\xa1\xfe\xe0p<\xb6\xbex\xb0s\x8d\xd6\xf5\xa5\xe8Q')


    signl =  pysodium.crypto_sign_BYTES
    assert signl == 64

    msg = "The lazy dog jumped over the river"
    msgb = msg.encode("utf-8") # must convert unicode string to bytes in order to sign it
    assert msgb == b'The lazy dog jumped over the river'
    sig = pysodium.crypto_sign_detached(msgb, verkey + seed)  #  sigkey = verkey + seed
    assert len(sig) == 64

    """
    sig = (b'F\x82\x0b\x1b\xacmC\xf0E6&\xb7o\xca\xcau\x9b\xf26R\xf4f\xc4\xcd\x1a \x81\xaf'
           b'\x17\xae\x9d\xf8\xff\x96\xda\x06\x11\xb0\x16.\xb3\xe1N\xbc$\xa0`@'
           b'\x10\xfc'\xe2\n\xc6\x910\x05\x87\xe9\x1a\xa6*\xde\x0c')
    """
    #siga = pysodium.crypto_sign(msg.encode("utf-8"), sk)[:pysodium.crypto_sign_BYTES]
    #assert len(siga) == 64
    #assert sig == siga

    try:  #  verify returns None if valid else raises ValueError
        result = pysodium.crypto_sign_verify_detached(sig, msgb, verkey)
    except Exception as ex:
        assert False
    assert not result
    assert result is None

    sigbad = sig[:-1]
    sigbad += b'A'

    try:  #  verify returns None if valid else raises ValueError
        result = pysodium.crypto_sign_verify_detached(sigbad, msgb, verkey)
    except Exception as ex:
        assert True
        assert isinstance(ex, ValueError)


    pk, sigkey = pysodium.crypto_box_keypair()


    """
    Done Test
    """



"""
  def encrypt(self, plaintext, nonce, encoder=encoding.RawEncoder):
        """
        Encrypts the plaintext message using the given `nonce` and returns
        the ciphertext encoded with the encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you fail
            to do this, you compromise the privacy of the messages encrypted.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext
        :rtype: [:class:`nacl.utils.EncryptedMessage`]
        """
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        ciphertext = libnacl.crypto_box_afternm(
            plaintext,
            nonce,
            self._shared_key,
        )

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def decrypt(self, ciphertext, nonce=None, encoder=encoding.RawEncoder):
        """
        Decrypts the ciphertext using the given nonce and returns the
        plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        plaintext = libnacl.crypto_box_open_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext

"""

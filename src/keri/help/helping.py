# -*- encoding: utf-8 -*-
"""
keri.help.helping module

"""
import os
import shutil
import tempfile
import base64

import pysodium

def cleanupBaseDir(baseDirPath):
    """
    Remove baseDirPath
    """
    if os.path.exists(baseDirPath):
        shutil.rmtree(baseDirPath)


def setupTmpBaseDir(baseDirPath=""):
    """
    Create temporary directory
    """
    if not baseDirPath: # create temp directory at /tmp/keri...test
        baseDirPath = tempfile.mkdtemp(prefix="keri",  suffix="test", dir="/tmp")
    baseDirPath = os.path.abspath(os.path.expanduser(baseDirPath))
    return baseDirPath

def cleanupTmpBaseDir(baseDirPath):
    """
    Remove temporary root of baseDirPath
    Ascend tree to find temporary root directory
    """
    if os.path.exists(baseDirPath):
        while baseDirPath.startswith("/tmp/keri"):
            if baseDirPath.endswith("test"):
                shutil.rmtree(baseDirPath)
                break
            baseDirPath = os.path.dirname(baseDirPath)


def keyToKey64u(key):
    """
    Convert and return bytes key to unicode base64 url-file safe version
    """
    return base64.urlsafe_b64encode(key).decode("utf-8")

def key64uToKey(key64u):
    """
    Convert and return unicode base64 url-file safe key64u to bytes key
    """
    return base64.urlsafe_b64decode(key64u.encode("utf-8"))

def verify(sig, msg, vk):
    """
    Returns True if signature sig of message msg is verified with
    verification key vk Otherwise False
    All of sig, msg, vk are bytes
    """
    try:
        result = pysodium.crypto_sign_verify_detached(sig, msg, vk)
    except Exception as ex:
        return False
    return (True if result else False)

def verify64u(signature, message, verkey):
    """
    Returns True if signature is valid for message with respect to verification
    key verkey

    signature and verkey are encoded as unicode base64 url-file strings
    and message is unicode string as would be the case for a json object

    """
    sig = key64uToKey(signature)
    vk = key64uToKey(verkey)
    msg = message.encode("utf-8")
    return (verify(sig, msg, vk))


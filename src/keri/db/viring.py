# -*- encoding: utf-8 -*-
"""
keri.db.viring module

VIR  Verifiable Issuance(Revocation) Registry

Provides public simple Verificable Credential Issuance/Revocation Registry
A special purpose Verifiable Data Registry (VDR)
"""

from keri.db import dbing

class Issuer(dbing.LMDBer):
    """
    Issuer sets up named sub databases for VIR

    Attributes:
        see superclass LMDBer for inherited attributes

        .virs is named sub DB whose values are VC issuance/revocation state
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed


    Properties:


    """
    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """
        Setup named sub databases.

        Inherited Parameters:
            name is str directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp is boolean, assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname for main database
                If not provided use default .HeadDirpath
            mode is int numeric os dir permissions for database directory
            reopen is boolean, IF True then database will be reopened by this init

        Notes:

        dupsort=True for sub DB means allow unique (key,pair) duplicates at a key.
        Duplicate means that is more than one value at a key but not a redundant
        copies a (key,value) pair per key. In other words the pair (key,value)
        must be unique both key and value in combination.
        Attempting to put the same (key,value) pair a second time does
        not add another copy.

        Duplicates are inserted in lexocographic order by value, insertion order.

        """
        super(Issuer, self).__init__(headDirPath=headDirPath, reopen=reopen, **kwa)


    def reopen(self, **kwa):
        """
        Open sub databases
        """
        super(Issuer, self).reopen(**kwa)

        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.

        self.virs = self.env.open_db(key=b'virs.')


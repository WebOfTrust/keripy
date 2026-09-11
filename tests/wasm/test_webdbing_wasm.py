# -*- encoding: utf-8 -*-
"""
tests.wasm.test_webdbing_wasm module

Browser storage tests run against the current Keripy wheel in Pyodide 314.
"""
import os
from pathlib import Path

import pytest


if os.environ.get("RUN_WASM_TESTS") != "true":
    pytest.skip(
        "WASM tests require RUN_WASM_TESTS=true with a pytest-pyodide runtime",
        allow_module_level=True,
    )

pytest_pyodide = pytest.importorskip("pytest_pyodide")
run_in_pyodide = pytest_pyodide.run_in_pyodide


@run_in_pyodide(pytest_assert_rewrites=False)
async def install_keri(selenium):
    from pathlib import Path
    from importlib import metadata

    import micropip

    # LMDB is native-only; check the remaining requirements after installation.
    await micropip.install([f"emfs:{path}" for path in Path("/wheels").glob("*.whl")],
                           deps=False)
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.markers import default_environment

    environment = default_environment()
    environment["extra"] = ""
    for distribution in metadata.distributions():
        python = distribution.metadata.get("Requires-Python")
        if python:
            assert environment["python_full_version"] in SpecifierSet(python)
        for value in distribution.requires or []:
            requirement = Requirement(value)
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            if requirement.name == "lmdb" and distribution.metadata["Name"] in ("keri", "hio"):
                continue
            assert metadata.version(requirement.name) in requirement.specifier, value


@pytest.fixture
def selenium_keri(selenium):
    from pytest_pyodide.copy_files_to_pyodide import copy_files_to_emscripten_fs

    root = Path(__file__).resolve().parents[2]
    current = list((root / "wheels/current").glob("keri-*.whl"))
    assert len(current) == 1, "Build exactly one Keripy wheel from this checkout"
    dependencies = sorted((root / "wheels/dependencies/wheelhouse").glob("*.whl"))
    assert dependencies, "Prepare the pinned browser dependency wheels"
    assert not any(path.name.startswith("keri-") for path in dependencies)
    files = [(path, f"/wheels/{path.name}") for path in [*dependencies, *current]]
    files.append((root / "tests/db/test_webbasing.py", "/home/pyodide/webbasing_fixtures.py"))
    copy_files_to_emscripten_fs(files, selenium, install_wheels=False)
    install_keri(selenium)
    return selenium


@run_in_pyodide
async def test_webdber_import_and_helpers(selenium_keri):
    """Verify webdbing.py imports and key helpers work in WASM."""
    import sys
    import pyodide
    from keri.db.webdbing import onKey, splitOnKey, MaxON

    assert sys.version_info[:3] == (3, 14, 2)
    assert pyodide.__version__ == "314.0.5"
    assert sys.platform == "emscripten"
    assert MaxON == int("f"*32, 16)

    key = onKey(b"pre", 42)
    top, on = splitOnKey(key)
    assert top == b"pre" and on == 42

    key2 = onKey("strpre", 0)
    assert isinstance(key2, bytes)
    top2, on2 = splitOnKey(key2)
    assert on2 == 0


@run_in_pyodide
async def test_webdber_crud(selenium_keri):
    """Verify WebDBer create, read, update, delete in WASM."""
    from keri.db.webdbing import WebDBer

    class FakeHandle:
        def __init__(self): self._store = {}
        def get(self, key, default=None): return self._store.get(key, default)
        def __setitem__(self, k, v): self._store[k] = v
        def __getitem__(self, k): return self._store[k]
        def __contains__(self, k): return k in self._store
        def keys(self): return self._store.keys()
        async def sync(self): pass

    class FakeBackend:
        def __init__(self): self._handles = {}
        async def __call__(self, ns):
            if ns not in self._handles:
                self._handles[ns] = FakeHandle()
            return self._handles[ns]

    backend = FakeBackend()
    dber = await WebDBer.open(
        name="wasm-crud", stores=["test."],
        storageOpener=backend,
    )
    sdb = dber.env.open_db(b"test.")

    assert dber.putVal(sdb, b"hello", b"world") is True
    assert dber.getVal(sdb, b"hello") == b"world"
    assert dber.setVal(sdb, b"hello", b"earth") is True
    assert dber.getVal(sdb, b"hello") == b"earth"
    assert dber.remVal(sdb, b"hello") is True
    assert dber.getVal(sdb, b"hello") is None


@run_in_pyodide
async def test_webdber_ordinals(selenium_keri):
    """Verify ordinal key operations in WASM."""
    from keri.db.webdbing import WebDBer

    class FakeHandle:
        def __init__(self): self._store = {}
        def get(self, key, default=None): return self._store.get(key, default)
        def __setitem__(self, k, v): self._store[k] = v
        def __getitem__(self, k): return self._store[k]
        def __contains__(self, k): return k in self._store
        def keys(self): return self._store.keys()
        async def sync(self): pass

    class FakeBackend:
        def __init__(self): self._handles = {}
        async def __call__(self, ns):
            if ns not in self._handles:
                self._handles[ns] = FakeHandle()
            return self._handles[ns]

    backend = FakeBackend()
    dber = await WebDBer.open(
        name="wasm-ord", stores=["ords."],
        storageOpener=backend,
    )
    sdb = dber.env.open_db(b"ords.")

    assert dber.appendOnVal(sdb, b"evt", b"first") == 0
    assert dber.appendOnVal(sdb, b"evt", b"second") == 1
    assert dber.appendOnVal(sdb, b"evt", b"third") == 2
    assert dber.getOnVal(sdb, b"evt", on=0) == b"first"
    assert dber.getOnVal(sdb, b"evt", on=1) == b"second"
    assert dber.cntOnAll(sdb, b"evt") == 3


@run_in_pyodide
async def test_webdber_flush(selenium_keri):
    """Verify flush persistence cycle in WASM."""
    from keri.db.webdbing import WebDBer

    class FakeHandle:
        def __init__(self): self._store = {}
        def get(self, key, default=None): return self._store.get(key, default)
        def __setitem__(self, k, v): self._store[k] = v
        def __getitem__(self, k): return self._store[k]
        def __contains__(self, k): return k in self._store
        def keys(self): return self._store.keys()
        async def sync(self): pass

    class FakeBackend:
        def __init__(self): self._handles = {}
        async def __call__(self, ns):
            if ns not in self._handles:
                self._handles[ns] = FakeHandle()
            return self._handles[ns]

    backend = FakeBackend()
    dber = await WebDBer.open(
        name="wasm-flush", stores=["data."],
        storageOpener=backend,
    )
    sdb = dber.env.open_db(b"data.")

    dber.putVal(sdb, b"k1", b"v1")
    dber.putVal(sdb, b"k2", b"v2")
    count = await dber.flush()
    assert count == 1  # one dirty store

    # Reopen from same backend — data persisted
    dber2 = await WebDBer.open(
        name="wasm-flush", stores=["data."],
        storageOpener=backend,
    )
    sdb2 = dber2.env.open_db(b"data.")
    assert dber2.getVal(sdb2, b"k1") == b"v1"
    assert dber2.getVal(sdb2, b"k2") == b"v2"


@run_in_pyodide
async def test_webdber_prefix_iteration(selenium_keri):
    """Verify prefix-scoped iteration in WASM."""
    from keri.db.webdbing import WebDBer

    class FakeHandle:
        def __init__(self): self._store = {}
        def get(self, key, default=None): return self._store.get(key, default)
        def __setitem__(self, k, v): self._store[k] = v
        def __getitem__(self, k): return self._store[k]
        def __contains__(self, k): return k in self._store
        def keys(self): return self._store.keys()
        async def sync(self): pass

    class FakeBackend:
        def __init__(self): self._handles = {}
        async def __call__(self, ns):
            if ns not in self._handles:
                self._handles[ns] = FakeHandle()
            return self._handles[ns]

    backend = FakeBackend()
    dber = await WebDBer.open(
        name="wasm-iter", stores=["recs."],
        storageOpener=backend,
    )
    sdb = dber.env.open_db(b"recs.")

    dber.putVal(sdb, b"alpha.1", b"a1")
    dber.putVal(sdb, b"alpha.2", b"a2")
    dber.putVal(sdb, b"beta.1", b"b1")

    items = list(dber.getTopItemIter(sdb, top=b"alpha."))
    assert len(items) == 2
    assert items[0] == (b"alpha.1", b"a1")
    assert items[1] == (b"alpha.2", b"a2")

    assert dber.cntAll(sdb) == 3
    assert dber.cntTop(sdb, top=b"alpha.") == 2


@run_in_pyodide
async def test_habery_reopen_signing_and_auth_cleanup(selenium_keri):
    """Persist key state and preserve AuthError for the async storage owner."""
    import sys

    import pytest
    from keri import AuthError
    from keri.app.habbing import Habery
    from keri.app.webkeeping import WebKeeper
    from keri.core import Salter
    from keri.db.webbasing import WebBaser
    from webbasing_fixtures import FakeStorageBackend, NullConfiger

    assert "lmdb" not in sys.modules
    assert "hio.core.tcp" not in sys.modules
    backend = FakeStorageBackend()
    correct = Salter(raw=b"0123456789abcdef").signer(transferable=False, temp=True)
    wrong = Salter(raw=b"fedcba9876543210").signer(transferable=False, temp=True)
    salt = Salter(raw=b"abcdefghijklmnop").qb64
    message = b"browser storage signing"

    keeper = WebKeeper(name="wasm-habery", storageOpener=backend.open)
    baser = WebBaser(name="wasm-habery")
    configer = NullConfiger()
    try:
        await keeper.reopen()
        await baser.reopen(storageOpener=backend.open)
        hby = Habery(name="wasm-habery", ks=keeper, db=baser, cf=configer,
                     seed=correct.qb64, aeid=correct.verfer.qb64, salt=salt)
        hab = hby.makeHab(name="alice")
        hab.rotate()
        pre = hab.pre
        assert hab.kever.sn == 1
        assert hab.kever.verfers[0].verify(hab.sign(ser=message)[0].raw, message)
        with pytest.raises(RuntimeError, match="use await aclose"):
            keeper.close()
    finally:
        try:
            await keeper.aclose()
        finally:
            await baser.aclose()
            configer.close()

    # Fresh backend objects must recover persisted state, not live caches.
    keeper = WebKeeper(name="wasm-habery", storageOpener=backend.open)
    baser = WebBaser(name="wasm-habery")
    configer = NullConfiger()
    try:
        await keeper.reopen()
        await baser.reopen(storageOpener=backend.open)
        with pytest.raises(AuthError):
            Habery(name="wasm-habery", ks=keeper, db=baser, cf=configer,
                   seed=wrong.qb64, salt=salt)
        assert keeper.opened
        assert baser.opened
        assert configer.opened
    finally:
        try:
            await keeper.aclose()
        finally:
            await baser.aclose()
            configer.close()

    await keeper.reopen()
    await baser.reopen(storageOpener=backend.open)
    configer = NullConfiger()
    try:
        hby = Habery(name="wasm-habery", ks=keeper, db=baser, cf=configer,
                     seed=correct.qb64, salt=salt)
        hab = hby.habByName("alice")
        assert hab.pre == pre
        assert hab.kever.sn == 1
        assert hab.kever.verfers[0].verify(hab.sign(ser=message)[0].raw, message)
    finally:
        try:
            await keeper.aclose(clear=True)
        finally:
            await baser.aclose(clear=True)
            configer.close()

    await keeper.reopen()
    await baser.reopen(storageOpener=backend.open)
    try:
        assert keeper.gbls.get("aeid") is None
        assert baser.habs.cnt() == 0
    finally:
        try:
            await keeper.aclose(clear=True)
        finally:
            await baser.aclose(clear=True)

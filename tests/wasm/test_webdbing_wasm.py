# -*- encoding: utf-8 -*-
"""
tests.wasm.test_webdbing_wasm module

WASM smoke tests for WebDBer — runs inside Pyodide via pytest-pyodide.
The workflow copies webdbing.py into this directory before running.
"""
import os

import pytest


if os.environ.get("RUN_WASM_TESTS") != "true":
    pytest.skip(
        "WASM tests require RUN_WASM_TESTS=true with a pytest-pyodide runtime",
        allow_module_level=True,
    )

pytest_pyodide = pytest.importorskip("pytest_pyodide")
run_in_pyodide = pytest_pyodide.run_in_pyodide
copy_files_to_pyodide = pytest_pyodide.decorator.copy_files_to_pyodide

WASM_PACKAGES = ["sortedcontainers", "micropip"]


@copy_files_to_pyodide(file_list=[("webdbing.py", "/home/pyodide/webdbing.py")])
@run_in_pyodide(packages=WASM_PACKAGES)
async def test_webdber_import_and_helpers(selenium):
    """Verify webdbing.py imports and key helpers work in WASM."""
    import sys
    import micropip
    await micropip.install("ordered_set")
    sys.path.insert(0, "/home/pyodide")
    from webdbing import WebDBer, onKey, splitOnKey, splitKey, MaxON

    assert MaxON == int("f"*32, 16)

    key = onKey(b"pre", 42)
    top, on = splitOnKey(key)
    assert top == b"pre" and on == 42

    key2 = onKey("strpre", 0)
    assert isinstance(key2, bytes)
    top2, on2 = splitOnKey(key2)
    assert on2 == 0


@copy_files_to_pyodide(file_list=[("webdbing.py", "/home/pyodide/webdbing.py")])
@run_in_pyodide(packages=WASM_PACKAGES)
async def test_webdber_crud(selenium):
    """Verify WebDBer create, read, update, delete in WASM."""
    import sys
    import micropip
    await micropip.install("ordered_set")
    sys.path.insert(0, "/home/pyodide")
    from webdbing import WebDBer

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


@copy_files_to_pyodide(file_list=[("webdbing.py", "/home/pyodide/webdbing.py")])
@run_in_pyodide(packages=WASM_PACKAGES)
async def test_webdber_ordinals(selenium):
    """Verify ordinal key operations in WASM."""
    import sys
    import micropip
    await micropip.install("ordered_set")
    sys.path.insert(0, "/home/pyodide")
    from webdbing import WebDBer

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


@copy_files_to_pyodide(file_list=[("webdbing.py", "/home/pyodide/webdbing.py")])
@run_in_pyodide(packages=WASM_PACKAGES)
async def test_webdber_flush(selenium):
    """Verify flush persistence cycle in WASM."""
    import sys
    import micropip
    await micropip.install("ordered_set")
    sys.path.insert(0, "/home/pyodide")
    from webdbing import WebDBer

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


@copy_files_to_pyodide(file_list=[("webdbing.py", "/home/pyodide/webdbing.py")])
@run_in_pyodide(packages=WASM_PACKAGES)
async def test_webdber_prefix_iteration(selenium):
    """Verify prefix-scoped iteration in WASM."""
    import sys
    import micropip
    await micropip.install("ordered_set")
    sys.path.insert(0, "/home/pyodide")
    from webdbing import WebDBer

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

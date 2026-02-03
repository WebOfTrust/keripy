#!/usr/bin/env python3
"""
Performance benchmark for signature database operations (sigs, wigs)

Purpose: Establish baseline performance before Phase 6 migration to CesrDupSuber

Usage:
    python benchmark_signatures.py

Output:
    Baseline measurements for single/bulk signature operations
"""

import time
import tempfile
import shutil
from contextlib import contextmanager

from keri.core import coring, indexing, signing
from keri.db import dbing, basing


@contextmanager
def timer(name):
    """Simple timing context manager"""
    start = time.perf_counter()
    yield
    elapsed = (time.perf_counter() - start) * 1000  # Convert to milliseconds
    print(f"{name}: {elapsed:.2f} ms")


def setup_test_data(count=3):
    """Create test signatures"""
    # Create a simple signer with raw seed
    raw = b'0123456789abcdef' * 2  # 32 bytes for Ed25519
    signer = signing.Signer(raw=raw, code=coring.MtrDex.Ed25519_Seed)
    
    # Create test signatures
    sigers = []
    for i in range(count):
        # Create different data for each signature
        data = f"test-data-{i}".encode('utf-8')
        siger = signer.sign(ser=data, index=i)
        sigers.append(siger)
    
    return sigers


def benchmark_single_operations(db):
    """Benchmark individual signature operations"""
    print("\n=== Benchmark 1: Single Signature Operations ===")
    
    # Test data
    sigers = setup_test_data(count=3)
    dgkey = dbing.dgKey(pre=b'test-prefix', dig=b'test-digest-123')
    
    # Benchmark putSigs
    with timer("  putSigs (3 signatures)"):
        db.putSigs(dgkey, [siger.qb64b for siger in sigers])
    
    # Benchmark getSigs
    with timer("  getSigs (3 signatures)"):
        sigs = db.getSigs(dgkey)
    
    # Benchmark Siger deserialization
    with timer("  Siger deserialization (3x)"):
        for sig in sigs:
            # Convert memoryview to bytes if needed
            sig_bytes = bytes(sig) if isinstance(sig, memoryview) else sig
            siger = indexing.Siger(qb64b=sig_bytes)
    
    print(f"  Retrieved signatures: {len(sigs)}")


def benchmark_bulk_operations(db):
    """Benchmark bulk signature operations"""
    print("\n=== Benchmark 2: Bulk Operations (100 events) ===")
    
    event_count = 100
    sigers = setup_test_data(count=3)
    sig_bytes = [siger.qb64b for siger in sigers]
    
    # Benchmark bulk writes
    with timer(f"  Write {event_count} events × 3 sigs"):
        for i in range(event_count):
            dgkey = dbing.dgKey(pre=b'bulk-test', dig=f'digest-{i:04d}'.encode())
            db.putSigs(dgkey, sig_bytes)
    
    # Benchmark bulk reads
    with timer(f"  Read {event_count} events × 3 sigs"):
        for i in range(event_count):
            dgkey = dbing.dgKey(pre=b'bulk-test', dig=f'digest-{i:04d}'.encode())
            sigs = db.getSigs(dgkey)
    
    events_per_sec = event_count / ((time.perf_counter()) * 1000)
    print(f"  Throughput: ~{events_per_sec:.0f} events/sec")


def benchmark_witness_operations(db):
    """Benchmark witness signature operations"""
    print("\n=== Benchmark 3: Witness Coordination (10 witnesses) ===")
    
    witness_count = 10
    sigers = setup_test_data(count=witness_count)
    dgkey = dbing.dgKey(pre=b'witness-test', dig=b'witness-digest')
    
    # Benchmark witness signature storage
    with timer(f"  Store {witness_count} witness receipts"):
        db.putWigs(dgkey, [siger.qb64b for siger in sigers])
    
    # Benchmark witness signature retrieval
    with timer(f"  Retrieve {witness_count} witness receipts"):
        wigs = db.getWigs(dgkey)
    
    # Benchmark threshold check (7/10)
    with timer("  Threshold check (7/10)"):
        threshold = 7
        valid = len(wigs) >= threshold
    
    print(f"  Retrieved witnesses: {len(wigs)}, Valid: {valid}")


def benchmark_real_workflow(db):
    """Benchmark realistic event validation workflow"""
    print("\n=== Benchmark 4: Real-World Workflow ===")
    
    # Setup: 3 controller sigs + 5 witness receipts
    sigers = setup_test_data(count=3)
    wigers = setup_test_data(count=5)
    dgkey = dbing.dgKey(pre=b'workflow-test', dig=b'event-digest')
    
    # Full validation cycle
    with timer("  Full event validation (store + retrieve + validate)"):
        # Store signatures
        db.putSigs(dgkey, [s.qb64b for s in sigers])
        db.putWigs(dgkey, [w.qb64b for w in wigers])
        
        # Retrieve
        sigs = db.getSigs(dgkey)
        wigs = db.getWigs(dgkey)
        
        # Deserialize (simulating validation)
        sig_objects = [indexing.Siger(qb64b=bytes(sig) if isinstance(sig, memoryview) else sig) 
                       for sig in sigs]
        wig_objects = [indexing.Siger(qb64b=bytes(wig) if isinstance(wig, memoryview) else wig)
                       for wig in wigs]
        
        # Threshold checks
        sig_valid = len(sig_objects) >= 2  # 2/3 threshold
        wig_valid = len(wig_objects) >= 3  # 3/5 threshold
    
    print(f"  Sigs: {len(sigs)}, Wigs: {len(wigs)}")
    print(f"  Validation: Sigs OK={sig_valid}, Wigs OK={wig_valid}")


def main():
    """Run all benchmarks"""
    print("=" * 60)
    print("Signature Database Performance Benchmark")
    print("=" * 60)
    print("\nPurpose: Establish baseline before Phase 6 migration")
    print("Target: <5% regression acceptable after migration")
    
    # Create database with relative path
    with basing.openDB(name="benchmark", temp=True) as db:
        # Run all benchmarks
        benchmark_single_operations(db)
        benchmark_bulk_operations(db)
        benchmark_witness_operations(db)
        benchmark_real_workflow(db)
        
        print("\n" + "=" * 60)
        print("Baseline measurements complete!")
        print("=" * 60)
        print("\nNext Steps:")
        print("1. Record these measurements in PHASE-6-PREP.md")
        print("2. Proceed with Phase 6 migration")
        print("3. Re-run this benchmark after migration")
        print("4. Compare results (must be <5% regression)")


if __name__ == "__main__":
    main()

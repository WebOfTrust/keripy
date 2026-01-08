# -*- encoding: utf-8 -*-
"""
keri.app.cli.commands.witness.inspect module

Diagnostic command to inspect event databases and identify processing issues.
"""
import argparse
import json

from hio.base import doing

from keri.app.cli.common import existing
from keri.db import dbing
from keri.core import serdering


parser = argparse.ArgumentParser(description='Inspect event databases (.evts, .kels, .fels, .fons)')
parser.set_defaults(handler=lambda args: handler(args))
parser.add_argument('--name', '-n', help='keystore name and file location of KERI keystore', required=True)
parser.add_argument('--base', '-b', help='additional optional prefix to file location of KERI keystore',
                    required=False, default="")
parser.add_argument('--passcode', '-p', help='22 character encryption passcode for keystore (is not saved)',
                    dest="bran", default=None)
parser.add_argument('--prefix', '-pre', help='filter by identifier prefix', default=None)
parser.add_argument('--verbose', '-v', help='show detailed event information', action='store_true', default=False)
parser.add_argument('--aid', '-a', help='show detailed kever info for specific AID', default=None)


def handler(args):
    kwa = dict(args=args)
    return [doing.doify(inspect, **kwa)]


def inspect(tymth, tock=0.0, **opts):
    """Command line inspect handler

    Inspects .evts, .kels, .fels, .fons databases and reports statistics
    and potential issues that could cause event processing failures.
    """
    _ = (yield tock)

    args = opts["args"]
    name = args.name
    base = args.base
    bran = args.bran
    prefix = args.prefix
    verbose = args.verbose
    aid = args.aid

    with existing.existingHby(name=name, base=base, bran=bran) as hby:
        db = hby.db

        # If specific AID requested, show detailed kever info
        if aid:
            print(f"\n=== Detailed inspection for AID: {aid} ===\n")

            if aid in db.kevers:
                kever = db.kevers[aid]
                print(f"Kever loaded: YES")
                print(f"  Sequence Number (sn): {kever.sner.num}")
                print(f"  Last Event SAID: {kever.serder.said}")
                print(f"  Delegated: {kever.delegated}")
                if kever.delegated:
                    print(f"  Delegator: {kever.delegator}")
                print(f"  Witnesses: {kever.wits}")
                print(f"  Witness Threshold (toad): {kever.toader.num}")

                # Check witness receipts for current event
                dgkey = dbing.dgKey(kever.serder.preb, kever.serder.saidb)
                wigs = db.getWigs(dgkey)
                print(f"  Witness Receipts for current event: {len(wigs)}")

                # Check if fully witnessed
                fully_witnessed = len(wigs) >= kever.toader.num
                print(f"  Fully Witnessed: {fully_witnessed}")

                print(f"\n--- Event-by-event witness receipts ---")
                # Show witness receipts for each event in KEL
                for sn, dig in db.getKelItemPreIter(aid.encode('utf-8') if isinstance(aid, str) else aid):
                    dgkey = dbing.dgKey(aid.encode('utf-8') if isinstance(aid, str) else aid, dig)
                    wigs = db.getWigs(dgkey)
                    sigs = db.getSigs(dgkey)

                    # Get event type
                    try:
                        raw = db.getEvt(dgkey)
                        if raw:
                            serder = serdering.SerderKERI(raw=bytes(raw))
                            ilk = serder.ilk
                        else:
                            ilk = "?"
                    except Exception:
                        ilk = "?"

                    status = "✓" if len(wigs) >= kever.toader.num else "✗"
                    print(f"  sn={sn:3d} ilk={ilk:3s} sigs={len(sigs) if sigs else 0} wigs={len(wigs) if wigs else 0}/{kever.toader.num} {status}")

            else:
                print(f"Kever loaded: NO")
                print(f"  AID {aid} not found in kevers")

                # Check if there are any events for this AID
                kel_count = 0
                max_sn = -1
                for sn, dig in db.getKelItemPreIter(aid.encode('utf-8') if isinstance(aid, str) else aid):
                    kel_count += 1
                    max_sn = max(max_sn, sn)

                if kel_count > 0:
                    print(f"  But found {kel_count} events in KEL (max sn={max_sn})")
                    print(f"  This suggests events exist but kever failed to load")
                else:
                    print(f"  No events found in KEL for this AID")

            # Check escrows for this specific AID
            print(f"\n--- Escrows for this AID ---")
            aid_bytes = aid.encode('utf-8') if isinstance(aid, str) else aid

            pse_count = 0
            for key, val in db.getPseItemsNextIter():
                if aid_bytes in bytes(key):
                    pse_count += 1
            print(f"  Partial Signed Escrow (PSE): {pse_count}")

            pwe_count = 0
            for key, val in db.getPweItemIter():
                if aid_bytes in bytes(key):
                    pwe_count += 1
            print(f"  Partial Witnessed Escrow (PWE): {pwe_count}")

            ooe_count = 0
            for key, val in db.getOoeItemIter():
                if aid_bytes in bytes(key):
                    ooe_count += 1
            print(f"  Out of Order Escrow (OOE): {ooe_count}")

            lde_count = 0
            for key, val in db.getLdeItemIter():
                if aid_bytes in bytes(key):
                    lde_count += 1
            print(f"  Likely Duplicitous Escrow (LDE): {lde_count}")

            print()
            return

        report = {
            "summary": {},
            "prefixes": {},
            "issues": []
        }

        # Count total events in .evts
        evts_count = 0
        evts_by_pre = {}
        for key, val in db.getTopItemIter(db.evts):
            evts_count += 1
            # Extract prefix from dgKey (pre.dig format)
            key_str = bytes(key).decode('utf-8')
            if '.' in key_str:
                pre = key_str.rsplit('.', 1)[0]
                if prefix and pre != prefix:
                    continue
                evts_by_pre[pre] = evts_by_pre.get(pre, 0) + 1

        report["summary"]["evts_total"] = evts_count

        # Count entries in .kels (key event log)
        kels_count = 0
        kels_by_pre = {}
        for key, val in db.getTopItemIter(db.kels):
            kels_count += 1
            key_str = bytes(key).decode('utf-8')
            if '.' in key_str:
                pre = key_str.rsplit('.', 1)[0]
                if prefix and pre != prefix:
                    continue
                kels_by_pre[pre] = kels_by_pre.get(pre, 0) + 1

        report["summary"]["kels_total"] = kels_count

        # Count entries in .fels (first seen event log)
        fels_count = 0
        fels_by_pre = {}
        for key, val in db.getTopItemIter(db.fels):
            fels_count += 1
            key_str = bytes(key).decode('utf-8')
            if '.' in key_str:
                pre = key_str.rsplit('.', 1)[0]
                if prefix and pre != prefix:
                    continue
                fels_by_pre[pre] = fels_by_pre.get(pre, 0) + 1

        report["summary"]["fels_total"] = fels_count

        # Count entries in .fons (first seen ordinal number index)
        fons_count = 0
        fons_by_pre = {}
        for keys, val in db.fons.getItemIter():
            fons_count += 1
            if keys:
                pre = keys[0].rsplit('.', 1)[0] if '.' in keys[0] else keys[0]
                if prefix and pre != prefix:
                    continue
                fons_by_pre[pre] = fons_by_pre.get(pre, 0) + 1

        report["summary"]["fons_total"] = fons_count

        # Get all unique prefixes
        all_prefixes = set(evts_by_pre.keys()) | set(kels_by_pre.keys()) | set(fels_by_pre.keys()) | set(fons_by_pre.keys())

        if prefix:
            all_prefixes = {prefix} if prefix in all_prefixes else set()

        # Analyze each prefix
        for pre in sorted(all_prefixes):
            pre_report = {
                "evts": evts_by_pre.get(pre, 0),
                "kels": kels_by_pre.get(pre, 0),
                "fels": fels_by_pre.get(pre, 0),
                "fons": fons_by_pre.get(pre, 0),
            }

            # Check for issues
            issues = []

            # Events in .evts but not in .fels (not first-seen logged)
            if pre_report["evts"] > 0 and pre_report["fels"] == 0:
                issues.append("Events exist but none in first-seen log (.fels)")

            # Events in .evts but not in .kels (not in key event log)
            if pre_report["evts"] > 0 and pre_report["kels"] == 0:
                issues.append("Events exist but none in key event log (.kels)")

            # Mismatch between .fels and .fons
            if pre_report["fels"] != pre_report["fons"]:
                issues.append(f"Mismatch: .fels={pre_report['fels']} vs .fons={pre_report['fons']}")

            # More events than KEL entries could indicate duplicates or escrow
            if pre_report["evts"] > pre_report["kels"] and pre_report["kels"] > 0:
                diff = pre_report["evts"] - pre_report["kels"]
                issues.append(f"More events ({pre_report['evts']}) than KEL entries ({pre_report['kels']}), {diff} may be escrowed/duplicitous")

            if issues:
                pre_report["issues"] = issues
                for issue in issues:
                    report["issues"].append(f"{pre[:16]}...: {issue}")

            report["prefixes"][pre] = pre_report

            # Verbose: show KEL sequence details
            if verbose:
                kel_details = []
                max_sn = -1
                sn_gaps = []
                prev_sn = -1

                for sn, dig in db.getKelItemPreIter(pre.encode('utf-8') if isinstance(pre, str) else pre):
                    if prev_sn >= 0 and sn != prev_sn + 1:
                        sn_gaps.append((prev_sn, sn))
                    prev_sn = sn
                    max_sn = max(max_sn, sn)
                    if len(kel_details) < 10:  # Limit to first 10
                        dig_str = bytes(dig).decode('utf-8') if isinstance(dig, (bytes, memoryview)) else str(dig)
                        kel_details.append({"sn": sn, "dig": dig_str[:24] + "..."})

                pre_report["max_sn"] = max_sn
                if sn_gaps:
                    pre_report["sn_gaps"] = sn_gaps
                    report["issues"].append(f"{pre[:16]}...: Sequence gaps found: {sn_gaps}")
                if verbose and kel_details:
                    pre_report["kel_sample"] = kel_details

                # Check for FEL details
                fel_details = []
                max_fn = -1
                for fn, dig in db.getFelItemPreIter(pre.encode('utf-8') if isinstance(pre, str) else pre):
                    max_fn = max(max_fn, fn)
                    if len(fel_details) < 10:
                        dig_str = bytes(dig).decode('utf-8') if isinstance(dig, (bytes, memoryview)) else str(dig)
                        fel_details.append({"fn": fn, "dig": dig_str[:24] + "..."})

                pre_report["max_fn"] = max_fn
                if verbose and fel_details:
                    pre_report["fel_sample"] = fel_details

        # Add kever information
        report["summary"]["kevers_loaded"] = len(db.kevers)
        report["summary"]["prefixes_count"] = len(all_prefixes)

        # Check escrows
        escrows = {
            "pse": 0,  # Partial Signed Escrow
            "pwe": 0,  # Partial Witnessed Escrow
            "ooe": 0,  # Out of Order Escrow
            "lde": 0,  # Likely Duplicitous Escrow
        }

        # Count PSE entries
        for key, val in db.getPseItemsNextIter():
            escrows["pse"] += 1
            if verbose:
                key_str = bytes(key).decode('utf-8') if isinstance(key, (bytes, memoryview)) else str(key)
                report["issues"].append(f"PSE escrow: {key_str[:40]}...")

        # Count PWE entries
        for key, val in db.getPweItemIter():
            escrows["pwe"] += 1
            if verbose:
                key_str = bytes(key).decode('utf-8') if isinstance(key, (bytes, memoryview)) else str(key)
                report["issues"].append(f"PWE escrow: {key_str[:40]}...")

        # Count OOE entries
        for key, val in db.getOoeItemIter():
            escrows["ooe"] += 1
            if verbose:
                key_str = bytes(key).decode('utf-8') if isinstance(key, (bytes, memoryview)) else str(key)
                report["issues"].append(f"OOE escrow: {key_str[:40]}...")

        # Count LDE entries
        for key, val in db.getLdeItemIter():
            escrows["lde"] += 1
            if verbose:
                key_str = bytes(key).decode('utf-8') if isinstance(key, (bytes, memoryview)) else str(key)
                report["issues"].append(f"LDE escrow: {key_str[:40]}...")

        report["summary"]["escrows"] = escrows
        if any(v > 0 for v in escrows.values()):
            report["issues"].append(f"Escrows found: PSE={escrows['pse']}, PWE={escrows['pwe']}, OOE={escrows['ooe']}, LDE={escrows['lde']}")

        # Check for orphaned events (in .evts but not referenced)
        if verbose:
            # Get all digests from .kels and .fels
            referenced_digs = set()
            for key, val in db.getTopItemIter(db.kels):
                referenced_digs.add(bytes(val).decode('utf-8'))
            for key, val in db.getTopItemIter(db.fels):
                referenced_digs.add(bytes(val).decode('utf-8'))

            orphaned = 0
            for key, val in db.getTopItemIter(db.evts):
                key_str = bytes(key).decode('utf-8')
                if '.' in key_str:
                    dig = key_str.rsplit('.', 1)[1]
                    if dig not in referenced_digs:
                        orphaned += 1

            if orphaned > 0:
                report["summary"]["orphaned_events"] = orphaned
                report["issues"].append(f"Found {orphaned} orphaned events (in .evts but not referenced in .kels/.fels)")

        print(json.dumps(report, indent=2))

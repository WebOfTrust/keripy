# -*- encoding: utf-8 -*-
"""
KERI
keri.metric.metricing module

Prometheus metrics endpoints for KERI escrow monitoring
"""
import falcon


class EscrowEnd:
    """Prometheus metrics endpoint for escrow counts.

    Exposes escrow counts in Prometheus text format for monitoring/alerting.
    """

    def __init__(self, hby, reger):
        """Initialize EscrowEnd.

        Parameters:
            hby (Habery): Habery instance for accessing KEL escrows
            reger (Reger): Registry for accessing TEL escrows
        """
        self.hby = hby
        self.reger = reger

    def on_get(self, _, rep):
        """GET /metrics - Returns Prometheus format metrics.

        Parameters:
            _ (Request): Falcon HTTP request object (unused)
            rep (Response): Falcon HTTP response object
        """
        lines = []

        # Header
        lines.append("# HELP keri_escrow_count Number of items in each escrow type")
        lines.append("# TYPE keri_escrow_count gauge")

        # KEL / Baser escrows
        escrow_counts = [
            ("unverified_receipts", sum(1 for _ in self.hby.db.getUreItemIter())),
            ("verified_receipts", sum(1 for _ in self.hby.db.getVreItemIter())),
            ("out_of_order_events", sum(1 for _ in self.hby.db.getOoeItemIter())),
            ("partially_witnessed_events", sum(1 for _ in self.hby.db.getPweItemIter())),
            ("partially_signed_events", sum(1 for _ in self.hby.db.getPseItemIter())),
            ("likely_duplicitous_events", sum(1 for _ in self.hby.db.getLdeItemIter())),
            ("unverified_event_indexed_couples", sum(1 for _ in self.hby.db.getUweItemIter())),
            ("query_not_found", sum(1 for _ in self.hby.db.qnfs.getItemIter())),
            ("partially_delegated_events", sum(1 for _ in self.hby.db.pdes.getItemIter())),
            ("reply", sum(1 for _ in self.hby.db.rpes.getItemIter())),
            ("failed_oobi", sum(1 for _ in self.hby.db.eoobi.getItemIter())),
            ("group_partial_witness", sum(1 for _ in self.hby.db.gpwe.getItemIter())),
            ("group_delegate", sum(1 for _ in self.hby.db.gdee.getItemIter())),
            ("delegated_partial_witness", sum(1 for _ in self.hby.db.dpwe.getItemIter())),
            ("group_partial_signed", sum(1 for _ in self.hby.db.gpse.getItemIter())),
            ("exchange_partial_signed", sum(1 for _ in self.hby.db.epse.getItemIter())),
            ("delegated_unanchored", sum(1 for _ in self.hby.db.dune.getItemIter())),
        ]

        for name, count in escrow_counts:
            lines.append(f'keri_escrow_count{{type="{name}",layer="kel"}} {count}')

        # TEL / Reger escrows
        tel_escrow_counts = [
            ("out_of_order", sum(1 for _ in self.reger.getOotItemIter())),
            ("partially_witnessed", sum(1 for _ in self.reger.getTweItemIter())),
            ("anchorless", sum(1 for _ in self.reger.getTaeItemIter())),
            ("missing_registry", sum(1 for _ in self.reger.mre.getItemIter())),
            ("broken_chain", sum(1 for _ in self.reger.mce.getItemIter())),
            ("missing_schema", sum(1 for _ in self.reger.mse.getItemIter())),
            ("missing_signature", sum(1 for _ in self.reger.cmse.getItemIter())),
            ("partial_witness", sum(1 for _ in self.reger.tpwe.getItemIter())),
            ("multisig", sum(1 for _ in self.reger.tmse.getItemIter())),
            ("event_dissemination", sum(1 for _ in self.reger.tede.getItemIter())),
        ]

        for name, count in tel_escrow_counts:
            lines.append(f'keri_escrow_count{{type="{name}",layer="tel"}} {count}')

        # Registry transaction escrows
        registry_escrow_counts = [
            ("registry_missing_anchor", sum(1 for _ in self.reger.txnsb.escrowdb.getItemIter(keys=("registry-mae", "")))),
            ("registry_out_of_order", sum(1 for _ in self.reger.txnsb.escrowdb.getItemIter(keys=("registry-ooo", "")))),
            ("credential_missing_registry", sum(1 for _ in self.reger.txnsb.escrowdb.getItemIter(keys=("credential-mre", "")))),
            ("credential_missing_anchor", sum(1 for _ in self.reger.txnsb.escrowdb.getItemIter(keys=("credential-mae", "")))),
            ("credential_out_of_order", sum(1 for _ in self.reger.txnsb.escrowdb.getItemIter(keys=("credential-ooo", "")))),
        ]

        for name, count in registry_escrow_counts:
            lines.append(f'keri_escrow_count{{type="{name}",layer="registry"}} {count}')

        rep.content_type = "text/plain; version=0.0.4; charset=utf-8"
        rep.status = falcon.HTTP_200
        rep.text = "\n".join(lines) + "\n"

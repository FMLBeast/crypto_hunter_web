"""
Enhanced import service with crypto intelligence and LLM orchestration
"""

import os
import json
import re
from typing import Dict, Any, List

from crypto_hunter_web.services.import_service import ImportService
from crypto_hunter_web.services.crypto_intelligence import CryptoIntelligence
from crypto_hunter_web.models import db, AnalysisFile, FileContent

class EnhancedImportService(ImportService):
    """Import service with automatic crypto analysis and LLM orchestration"""

    @staticmethod
    def import_with_crypto_analysis(
        csv_path: str,
        user_id: int,
        analyze_crypto: bool = True,
        use_llm: bool = True,
        offline_mode: bool = False,
        llm_budget: float = 10.0
    ) -> Any:
        """Import with crypto analysis and optional LLM orchestration."""
        # Perform base import
        bulk_import = ImportService.import_files(csv_path, user_id)

        # Get imported files
        imported_files = AnalysisFile.query.filter_by(
            discovered_by=user_id
        ).order_by(AnalysisFile.created_at.desc()) \
         .limit(bulk_import.successful_imports) \
         .all()

        crypto_analysis_count = 0
        llm_analysis_count = 0
        llm_cost_used = 0.0

        for file in imported_files:
            if analyze_crypto and file.filepath and os.path.exists(file.filepath):
                try:
                    # Read preview
                    with open(file.filepath, 'rb') as f:
                        content = f.read(1024 * 1024)

                    # Run crypto intelligence
                    crypto_analysis = CryptoIntelligence.analyze_crypto_content(
                        content, file.filename
                    )

                    # Store or append results
                    file_content = FileContent.query.filter_by(
                        file_id=file.id,
                        content_type='crypto_analysis'
                    ).first()
                    payload = json.dumps(crypto_analysis, indent=2)
                    if not file_content:
                        file_content = FileContent(
                            file_id=file.id,
                            content_type='crypto_analysis',
                            content_text=payload,
                            content_size=len(payload)
                        )
                        db.session.add(file_content)
                    else:
                        existing = {}
                        try:
                            existing = json.loads(file_content.content_text or '{}')
                        except json.JSONDecodeError:
                            pass
                        existing['crypto_analysis'] = crypto_analysis
                        file_content.content_text = json.dumps(existing, indent=2)

                    # Update metadata
                    EnhancedImportService._update_file_metadata(file, crypto_analysis)
                    crypto_analysis_count += 1

                    # Optionally queue LLM
                    if (
                        use_llm and
                        not offline_mode and
                        llm_cost_used < llm_budget and
                        EnhancedImportService._should_use_llm(crypto_analysis, file)
                    ):
                        from crypto_hunter_web.services.llm_crypto_orchestrator import (
                            llm_orchestrated_analysis
                        )
                        est = EnhancedImportService._estimate_llm_cost_for_file(file)
                        if llm_cost_used + est <= llm_budget:
                            llm_orchestrated_analysis.delay(file.id)
                            llm_analysis_count += 1
                            llm_cost_used += est

                except Exception as e:
                    print(f"Crypto analysis failed for {file.filename}: {e}")

        # Commit changes
        db.session.commit()

        # Update import log
        summary = f"Crypto analysis done for {crypto_analysis_count} files."
        if llm_analysis_count:
            summary += f" LLM queued for {llm_analysis_count} files (~${llm_cost_used:.2f})."
        bulk_import.error_log = (bulk_import.error_log or '') + '\n' + summary
        db.session.commit()

        return bulk_import

    @staticmethod
    def import_offline_mode(csv_path: str, user_id: int) -> Any:
        """Import with crypto analysis offline (no APIs)."""
        return EnhancedImportService.import_with_crypto_analysis(
            csv_path, user_id, analyze_crypto=True, use_llm=False, offline_mode=True
        )

    @staticmethod
    def check_api_availability() -> Dict[str, bool]:
        """Check available external APIs."""
        availability = {'llm_service': False, 'ethereum_api': False, 'external_crypto_apis': False}
        try:
            from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis  # noqa
            availability['llm_service'] = True
        except ImportError:
            pass
        try:
            import requests
            r = requests.get('https://api.etherscan.io/api?module=stats&action=ethsupply', timeout=5)
            availability['ethereum_api'] = (r.status_code == 200)
        except:
            pass
        return availability

    @staticmethod
    def import_with_smart_llm_analysis(
        csv_path: str,
        user_id: int,
        max_llm_budget: float = 10.0
    ) -> Any:
        """Selective LLM analysis within budget."""
        if not EnhancedImportService.check_api_availability()['llm_service']:
            return EnhancedImportService.import_offline_mode(csv_path, user_id)

        bulk = EnhancedImportService.import_with_crypto_analysis(
            csv_path, user_id, analyze_crypto=True, use_llm=False
        )
        if bulk.status != 'completed':
            return bulk

        imported = AnalysisFile.query.filter_by(discovered_by=user_id) \
            .order_by(AnalysisFile.created_at.desc()) \
            .limit(bulk.successful_imports).all()

        candidates = []
        for f in imported:
            content = FileContent.query.filter_by(file_id=f.id).first()
            if not content:
                continue
            analysis = json.loads(content.content_text or '{}').get('crypto_analysis', {})
            score = EnhancedImportService._calculate_llm_value_score(analysis, f)
            cost = EnhancedImportService._estimate_llm_cost_for_file(f)
            if score > 6.0:
                candidates.append((f, score / cost, cost))

        candidates.sort(key=lambda x: x[1], reverse=True)
        total_cost = 0.0
        queued = 0
        for f, _, cost in candidates:
            if total_cost + cost <= max_llm_budget:
                from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis  # noqa
                llm_orchestrated_analysis.delay(f.id)
                total_cost += cost
                queued += 1

        bulk.error_log = (bulk.error_log or '') + f"\nSmart LLM queued {queued} files (~${total_cost:.2f})"
        db.session.commit()
        return bulk

    # Utility methods below... ensure they all have correct indentation
    @staticmethod
    def _should_use_llm(crypto_analysis: Dict[str, Any], file: AnalysisFile) -> bool:
        patterns = crypto_analysis.get('crypto_patterns', [])
        if len([p for p in patterns if p.get('confidence', 0) > 0.8]) >= 2:
            return True
        if any(k in crypto_analysis for k in ('private_keys', 'addresses')):
            return True
        if file.priority >= 8:
            return True
        name = file.filename.lower()
        return any(w in name for w in ('flag', 'key', 'secret', 'puzzle', 'ctf'))

    @staticmethod
    def _estimate_llm_cost_for_file(file: AnalysisFile) -> float:
        try:
            with open(file.filepath, 'rb') as f:
                text = f.read(2048).decode('utf-8', errors='ignore')
            length = len(text)
        except:
            length = 512
        return 0.5 * (1 + min(length / 1000, 2.0))

    @staticmethod
    def _calculate_llm_value_score(
        crypto_analysis: Dict[str, Any],
        file: AnalysisFile
    ) -> float:
        score = 3.0
        for p in crypto_analysis.get('crypto_patterns', []):
            score += p.get('confidence', 0)
        if file.priority >= 8:
            score += 2.0
        return min(score, 10.0)

    @staticmethod
    def _update_file_metadata(
        file: AnalysisFile,
        crypto_analysis: Dict[str, Any]
    ) -> None:
        boost = 0
        for p in crypto_analysis.get('crypto_patterns', []):
            if p.get('type') in ('eth_private', 'eth_address'):
                boost += 3
        if boost:
            file.priority = min(10, file.priority + boost)
            file.status = 'crypto_analyzed'
            file.node_color = '#ef4444'

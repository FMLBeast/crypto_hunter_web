"""
Enhanced import service with crypto intelligence and LLM orchestration
"""

import os
import json
import re
from typing import Dict, Any, List
from crypto_hunter_web.services.import_service import ImportService
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
        llm_budget: float = 0.0
    ) -> Any:
        """Import from CSV with optional crypto analysis and LLM orchestration"""

        # First do the base import
        bulk_import = ImportService.import_from_csv(csv_path, user_id)

        if not analyze_crypto:
            return bulk_import

        # Get imported files
        imported_files = AnalysisFile.query.filter_by(
            discovered_by=user_id
        ).order_by(AnalysisFile.created_at.desc()).limit(bulk_import.successful_imports).all()

        crypto_analysis_count = 0
        llm_analysis_count = 0
        llm_cost_used = 0.0

        for file in imported_files:
            if file.filepath and os.path.exists(file.filepath):
                try:
                    # Perform crypto analysis
                    with open(file.filepath, 'rb') as f:
                        content = f.read(1024 * 1024)  # Read first 1MB

                    from crypto_hunter_web.services.crypto_intelligence import CryptoIntelligence
                    crypto_analysis = CryptoIntelligence.analyze_crypto_content(content, file.filename)

                    # Store analysis results in file content
                    file_content = FileContent.query.filter_by(file_id=file.id).first()
                    if not file_content:
                        file_content = FileContent(
                            file_id=file.id,
                            content_type='crypto_analysis',
                            content_text=json.dumps(crypto_analysis, indent=2),
                            content_size=len(json.dumps(crypto_analysis))
                        )
                        db.session.add(file_content)
                    else:
                        # Append crypto analysis to existing content
                        existing_analysis = {}
                        if file_content.content_text:
                            try:
                                existing_analysis = json.loads(file_content.content_text)
                            except:
                                pass

                        existing_analysis['crypto_analysis'] = crypto_analysis
                        file_content.content_text = json.dumps(existing_analysis, indent=2)

                    # Update file metadata based on crypto analysis
                    EnhancedImportService._update_file_metadata(file, crypto_analysis)

                    crypto_analysis_count += 1

                    # Queue LLM analysis for high-value files if enabled and within budget
                    if (use_llm and
                        not offline_mode and
                        llm_cost_used < llm_budget and
                        EnhancedImportService._should_use_llm(crypto_analysis, file)):

                        # Estimate LLM cost for this file
                        estimated_cost = EnhancedImportService._estimate_llm_cost(content[:2048])

                        if llm_cost_used + estimated_cost <= llm_budget:
                            try:
                                # Import here to avoid circular imports
                                from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
                                llm_orchestrated_analysis.delay(file.id)
                                llm_analysis_count += 1
                                llm_cost_used += estimated_cost
                            except ImportError:
                                print("LLM orchestrator not available - continuing with offline analysis")
                            except Exception as e:
                                print(f"LLM analysis failed for {file.filename}: {e}")

                except Exception as e:
                    print(f"Crypto analysis failed for {file.filename}: {e}")
                    continue

        # Commit all changes
        db.session.commit()

        # Update bulk import record with analysis results
        analysis_summary = f"\nCrypto analysis completed for {crypto_analysis_count} files"
        if llm_analysis_count > 0:
            analysis_summary += f"\nLLM analysis queued for {llm_analysis_count} high-value files (${llm_cost_used:.2f} estimated cost)"

        bulk_import.error_log = (bulk_import.error_log or '') + analysis_summary
        db.session.commit()

        return bulk_import

    @staticmethod
    def import_offline_mode(csv_path: str, user_id: int) -> Dict[str, Any]:
        """Import with full offline crypto analysis - no external API calls"""
        return EnhancedImportService.import_with_crypto_analysis(
            csv_path, user_id, analyze_crypto=True, use_llm=False, offline_mode=True
        )

    @staticmethod
    def check_api_availability() -> Dict[str, bool]:
        """Check which APIs are available and funded"""
        availability = {
            'llm_service': False,
            'ethereum_api': False,
            'blockchain_apis': False,
            'external_crypto_apis': False
        }

        # Check LLM service
        try:
            from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
            availability['llm_service'] = True
        except ImportError:
            pass

        # Check Ethereum API (basic connectivity test)
        try:
            import requests
            response = requests.get('https://api.etherscan.io/api?module=stats&action=ethsupply', timeout=5)
            availability['ethereum_api'] = response.status_code == 200
        except:
            pass

        return availability

    @staticmethod
    def get_offline_capabilities() -> Dict[str, Any]:
        """Get list of what works in offline mode"""
        return {
            'crypto_pattern_detection': True,
            'file_analysis': True,
            'hash_validation': True,
            'entropy_analysis': True,
            'encoding_detection': True,
            'cipher_analysis': True,
            'key_format_validation': True,
            'file_relationships': True,
            'content_analysis': True,
            'steganography_detection': True,
            'local_crypto_operations': True,
            'database_operations': True,
            'features_requiring_apis': {
                'llm_analysis': 'Requires funded LLM API',
                'ethereum_balance_checks': 'Requires Etherscan API key',
                'real_time_blockchain_data': 'Requires blockchain API access',
                'advanced_threat_intelligence': 'Requires security API access'
            }
        }

    @staticmethod
    def import_with_smart_llm_analysis(csv_path: str, user_id: int, max_llm_budget: float = 10.0):
        """Smart import with automatic LLM analysis for promising files"""

        # Check API availability first
        api_status = EnhancedImportService.check_api_availability()
        if not api_status['llm_service']:
            print("LLM service not available - falling back to offline analysis")
            return EnhancedImportService.import_offline_mode(csv_path, user_id)

        # First pass: standard import with basic crypto analysis
        bulk_import = EnhancedImportService.import_with_crypto_analysis(
            csv_path, user_id, analyze_crypto=True, use_llm=False
        )

        if bulk_import.status != 'completed':
            return bulk_import

        # Second pass: intelligent LLM analysis selection
        imported_files = AnalysisFile.query.filter_by(
            discovered_by=user_id
        ).order_by(AnalysisFile.priority.desc()).limit(bulk_import.successful_imports).all()

        # Rank files by LLM analysis value
        llm_candidates = []
        for file in imported_files:
            if file.priority >= 7:  # High priority files only
                try:
                    # Get crypto analysis results
                    content = FileContent.query.filter_by(file_id=file.id).first()
                    if content:
                        analysis = json.loads(content.content_text or '{}')
                        crypto_analysis = analysis.get('crypto_analysis', {})

                        value_score = EnhancedImportService._calculate_llm_value_score(crypto_analysis, file)
                        cost_estimate = EnhancedImportService._estimate_llm_cost_for_file(file)

                        if value_score > 6.0:  # Minimum value threshold
                            llm_candidates.append({
                                'file': file,
                                'value_score': value_score,
                                'cost_estimate': cost_estimate,
                                'value_per_dollar': value_score / max(cost_estimate, 0.1)
                            })
                except Exception as e:
                    continue

        # Sort by value per dollar ratio
        llm_candidates.sort(key=lambda x: x['value_per_dollar'], reverse=True)

        # Queue LLM analysis within budget
        total_cost = 0.0
        llm_queued = 0

        for candidate in llm_candidates:
            if total_cost + candidate['cost_estimate'] <= max_llm_budget:
                try:
                    from crypto_hunter_web.services.llm_crypto_orchestrator import llm_orchestrated_analysis
                    llm_orchestrated_analysis.delay(candidate['file'].id)
                    total_cost += candidate['cost_estimate']
                    llm_queued += 1
                except Exception as e:
                    print(f"LLM analysis failed for file {candidate['file'].filename}: {e}")
                    continue

        # Update import record
        llm_summary = f"\nSmart LLM analysis: {llm_queued} files queued, ${total_cost:.2f} estimated cost"
        bulk_import.error_log = (bulk_import.error_log or '') + llm_summary
        db.session.commit()

        return bulk_import

    @staticmethod
    def import_with_enhanced_offline_analysis(csv_path: str, user_id: int) -> Dict[str, Any]:
        """Enhanced offline analysis with maximum local crypto intelligence"""

        # Perform base import
        bulk_import = EnhancedImportService.import_offline_mode(csv_path, user_id)

        if bulk_import.status != 'completed':
            return bulk_import

        # Get imported files for additional offline analysis
        imported_files = AnalysisFile.query.filter_by(
            discovered_by=user_id
        ).order_by(AnalysisFile.priority.desc()).limit(bulk_import.successful_imports).all()

        enhanced_analysis_count = 0

        for file in imported_files:
            if file.filepath and os.path.exists(file.filepath):
                try:
                    # Perform enhanced offline analysis
                    enhanced_results = EnhancedImportService._enhanced_offline_crypto_analysis(file)

                    if enhanced_results:
                        # Update existing analysis
                        content = FileContent.query.filter_by(file_id=file.id).first()
                        if content:
                            existing_analysis = json.loads(content.content_text or '{}')
                            existing_analysis['enhanced_offline_analysis'] = enhanced_results
                            content.content_text = json.dumps(existing_analysis, indent=2)
                            enhanced_analysis_count += 1

                except Exception as e:
                    print(f"Enhanced offline analysis failed for {file.filename}: {e}")
                    continue

        db.session.commit()

        # Update summary
        enhancement_summary = f"\nEnhanced offline analysis completed for {enhanced_analysis_count} files"
        bulk_import.error_log = (bulk_import.error_log or '') + enhancement_summary
        db.session.commit()

        return bulk_import

    @staticmethod
    def _enhanced_offline_crypto_analysis(file: AnalysisFile) -> Dict[str, Any]:
        """Perform enhanced crypto analysis without external APIs"""
        results = {
            'deep_pattern_analysis': {},
            'cross_file_correlations': {},
            'advanced_entropy_analysis': {},
            'local_key_validation': {},
            'cipher_detection_detailed': {}
        }

        try:
            with open(file.filepath, 'rb') as f:
                content = f.read()

            # Deep pattern analysis
            results['deep_pattern_analysis'] = EnhancedImportService._deep_pattern_analysis(content)

            # Advanced entropy analysis
            results['advanced_entropy_analysis'] = EnhancedImportService._advanced_entropy_analysis(content)

            # Local cryptographic validation (no API calls)
            results['local_key_validation'] = EnhancedImportService._local_crypto_validation(content)

            # Enhanced cipher detection
            text_content = content.decode('utf-8', errors='ignore')
            results['cipher_detection_detailed'] = EnhancedImportService._detailed_cipher_analysis(text_content)

        except Exception as e:
            results['error'] = str(e)

        return results

    @staticmethod
    def _deep_pattern_analysis(content: bytes) -> Dict[str, Any]:
        """Perform deep pattern analysis without external APIs"""
        patterns = {
            'repeating_sequences': [],
            'embedded_structures': [],
            'potential_keys': [],
            'encoded_regions': []
        }

        # Find repeating byte sequences
        for length in [4, 8, 16, 32]:
            for i in range(len(content) - length):
                sequence = content[i:i+length]
                if content.count(sequence) > 2:
                    patterns['repeating_sequences'].append({
                        'sequence': sequence.hex(),
                        'length': length,
                        'occurrences': content.count(sequence),
                        'first_offset': i
                    })

        return patterns

    @staticmethod
    def _advanced_entropy_analysis(content: bytes) -> Dict[str, Any]:
        """Advanced entropy analysis for crypto detection"""
        if len(content) == 0:
            return {'entropy': 0, 'analysis': 'empty_file'}

        # Calculate Shannon entropy
        byte_counts = [0] * 256
        for byte in content:
            byte_counts[byte] += 1

        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / len(content)
                entropy -= p * (p.bit_length() - 1)

        # Analyze entropy in chunks
        chunk_size = min(1024, len(content) // 10)
        chunk_entropies = []

        if chunk_size > 0:
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i+chunk_size]
                chunk_entropy = EnhancedImportService._calculate_chunk_entropy(chunk)
                chunk_entropies.append(chunk_entropy)

        return {
            'overall_entropy': entropy,
            'chunk_entropies': chunk_entropies,
            'entropy_variance': max(chunk_entropies) - min(chunk_entropies) if chunk_entropies else 0,
            'likely_encrypted': entropy > 7.5,
            'likely_compressed': entropy > 7.0 and entropy <= 7.5,
            'has_structure': entropy < 6.0
        }

    @staticmethod
    def _calculate_chunk_entropy(chunk: bytes) -> float:
        """Calculate entropy for a chunk of data"""
        if len(chunk) == 0:
            return 0

        byte_counts = [0] * 256
        for byte in chunk:
            byte_counts[byte] += 1

        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / len(chunk)
                entropy -= p * (p.bit_length() - 1)

        return entropy

    @staticmethod
    def _local_crypto_validation(content: bytes) -> Dict[str, Any]:
        """Validate crypto material without external API calls"""
        validation = {
            'potential_private_keys': [],
            'address_formats': [],
            'certificate_structures': [],
            'hash_candidates': []
        }

        text_content = content.decode('utf-8', errors='ignore')

        # Local Ethereum private key validation (format only)
        eth_private_pattern = re.compile(r'\b[0-9a-fA-F]{64}\b')
        for match in eth_private_pattern.finditer(text_content):
            key = match.group(0)
            try:
                # Basic format validation (no API calls)
                key_int = int(key, 16)
                if 0 < key_int < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                    validation['potential_private_keys'].append({
                        'key': key,
                        'format': 'ethereum_private_key',
                        'validation': 'format_valid'
                    })
            except ValueError:
                continue

        return validation

    @staticmethod
    def _detailed_cipher_analysis(text: str) -> Dict[str, Any]:
        """Detailed cipher analysis without external dependencies"""
        analysis = {
            'character_frequency': {},
            'ngram_analysis': {},
            'cipher_indicators': [],
            'potential_encodings': []
        }

        if len(text) < 10:
            return analysis

        # Character frequency analysis
        char_freq = {}
        for char in text.upper():
            if char.isalpha():
                char_freq[char] = char_freq.get(char, 0) + 1

        total_chars = sum(char_freq.values())
        if total_chars > 0:
            analysis['character_frequency'] = {
                char: count / total_chars for char, count in char_freq.items()
            }

        # Simple cipher indicators
        if all(c.isalpha() or c.isspace() for c in text) and len(set(text.upper())) < 15:
            analysis['cipher_indicators'].append('possible_substitution_cipher')

        if re.search(r'^[A-Z\s]+$', text) and len(text) > 50:
            analysis['cipher_indicators'].append('possible_classical_cipher')

        return analysis

    @staticmethod
    def create_llm_analysis_plan(imported_files: List[AnalysisFile], budget: float = 10.0) -> Dict[str, Any]:
        """Create an analysis plan for LLM processing within budget"""

        plan = {
            'total_files': len(imported_files),
            'budget': budget,
            'recommended_files': [],
            'total_estimated_cost': 0.0,
            'analysis_strategy': {}
        }

        # Analyze each file for LLM value
        file_scores = []
        for file in imported_files:
            try:
                content = FileContent.query.filter_by(file_id=file.id).first()
                if content:
                    analysis = json.loads(content.content_text or '{}')
                    crypto_analysis = analysis.get('crypto_analysis', {})

                    value_score = EnhancedImportService._calculate_llm_value_score(crypto_analysis, file)
                    cost_estimate = EnhancedImportService._estimate_llm_cost_for_file(file)

                    file_scores.append({
                        'file_id': file.id,
                        'filename': file.filename,
                        'value_score': value_score,
                        'cost_estimate': cost_estimate,
                        'roi': value_score / max(cost_estimate, 0.1),
                        'crypto_patterns': len(crypto_analysis.get('crypto_patterns', [])),
                        'priority': file.priority
                    })
            except Exception as e:
                continue

        # Sort by ROI and select within budget
        file_scores.sort(key=lambda x: x['roi'], reverse=True)

        running_cost = 0.0
        for file_data in file_scores:
            if running_cost + file_data['cost_estimate'] <= budget and file_data['value_score'] >= 5.0:
                plan['recommended_files'].append(file_data)
                running_cost += file_data['cost_estimate']

        plan['total_estimated_cost'] = running_cost

        # Create strategy recommendations
        high_value_files = [f for f in plan['recommended_files'] if f['value_score'] >= 8.0]
        medium_value_files = [f for f in plan['recommended_files'] if 6.0 <= f['value_score'] < 8.0]

        plan['analysis_strategy'] = {
            'high_priority_first': len(high_value_files),
            'medium_priority_second': len(medium_value_files),
            'estimated_completion_time': len(plan['recommended_files']) * 3,  # 3 minutes per file
            'expected_findings': len(plan['recommended_files']) * 0.7  # 70% expected finding rate
        }

        return plan

    @staticmethod
    def _should_use_llm(crypto_analysis: Dict[str, Any], file: AnalysisFile) -> bool:
        """Determine if file should get LLM analysis"""

        crypto_patterns = crypto_analysis.get('crypto_patterns', [])
        ethereum_analysis = crypto_analysis.get('ethereum_analysis', {})

        # High confidence crypto patterns
        high_confidence_patterns = [p for p in crypto_patterns if p.get('confidence', 0) > 0.8]
        if len(high_confidence_patterns) >= 2:
            return True

        # Ethereum content
        if ethereum_analysis.get('private_keys') or ethereum_analysis.get('addresses'):
            return True

        # Multiple encoding layers
        encoding_detection = crypto_analysis.get('encoding_detection', [])
        if len(encoding_detection) >= 3:
            return True

        # File size and complexity indicators
        if len(crypto_patterns) >= 5:
            return True

        # High priority files (manually marked)
        if file.priority >= 8:
            return True

        # Files with puzzle-related names
        puzzle_keywords = ['flag', 'key', 'secret', 'puzzle', 'challenge', 'ctf', 'crypto']
        if any(keyword in file.filename.lower() for keyword in puzzle_keywords):
            return True

        return False

    @staticmethod
    def _estimate_llm_cost(content_preview: str) -> float:
        """Estimate LLM analysis cost for content"""
        base_cost = 0.50  # Base cost per analysis
        content_factor = min(len(content_preview) / 1000, 2.0)  # Max 2x multiplier
        return base_cost * (1 + content_factor)

    @staticmethod
    def _estimate_llm_cost_for_file(file: AnalysisFile) -> float:
        """Estimate LLM cost for specific file"""
        try:
            if os.path.exists(file.filepath):
                with open(file.filepath, 'rb') as f:
                    preview = f.read(2048).decode('utf-8', errors='ignore')
                return EnhancedImportService._estimate_llm_cost(preview)
        except:
            pass
        return 1.0  # Default estimate

    @staticmethod
    def _calculate_llm_value_score(crypto_analysis: Dict[str, Any], file: AnalysisFile) -> float:
        """Calculate expected value score for LLM analysis"""

        base_score = 3.0
        crypto_patterns = crypto_analysis.get('crypto_patterns', [])
        ethereum_analysis = crypto_analysis.get('ethereum_analysis', {})

        # Boost for crypto patterns
        for pattern in crypto_patterns:
            confidence = pattern.get('confidence', 0)
            if pattern['type'] in ['eth_private', 'eth_address']:
                base_score += confidence * 3
            elif pattern['type'] in ['pem_private', 'bitcoin_address']:
                base_score += confidence * 2
            else:
                base_score += confidence * 1

        # Boost for Ethereum findings
        if ethereum_analysis.get('validated_keys'):
            base_score += 4.0

        # Boost for file characteristics
        if file.priority >= 8:
            base_score += 2.0

        if file.is_root_file:
            base_score += 1.5

        # Boost for promising filenames
        puzzle_keywords = ['flag', 'key', 'secret', 'puzzle', 'wallet', 'private']
        if any(keyword in file.filename.lower() for keyword in puzzle_keywords):
            base_score += 1.0

        return min(base_score, 10.0)  # Cap at 10

    @staticmethod
    def _update_file_metadata(file: AnalysisFile, crypto_analysis: Dict[str, Any]):
        """Update file metadata based on crypto analysis"""

        crypto_patterns = crypto_analysis.get('crypto_patterns', [])
        ethereum_analysis = crypto_analysis.get('ethereum_analysis', {})

        priority_boost = 0

        # High-value crypto patterns boost priority
        for pattern in crypto_patterns:
            if pattern['type'] in ['eth_private', 'eth_address', 'bitcoin_address']:
                priority_boost += 3
            elif pattern['type'] in ['pem_private', 'pgp_block']:
                priority_boost += 2
            elif pattern.get('confidence', 0) > 0.8:
                priority_boost += 1

        # Ethereum findings boost priority
        if ethereum_analysis.get('validated_keys'):
            priority_boost += 4

        # Multiple crypto patterns indicate complexity
        if len(crypto_patterns) >= 5:
            priority_boost += 1

        # Update file priority (max 10)
        file.priority = min(10, file.priority + priority_boost)

        # Update status based on findings
        if priority_boost >= 4:
            file.status = 'high_value_crypto'
        elif priority_boost > 0:
            file.status = 'crypto_analyzed'

        # Update node color for visualization
        if ethereum_analysis.get('validated_keys'):
            file.node_color = '#fbbf24'  # Gold for Ethereum keys
        elif priority_boost >= 3:
            file.node_color = '#ef4444'  # Red for high-value crypto
        elif priority_boost > 0:
            file.node_color = '#3b82f6'  # Blue for crypto content
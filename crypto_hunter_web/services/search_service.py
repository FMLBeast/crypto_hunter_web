# crypto_hunter_web/services/search_service.py - COMPLETE IMPROVED VERSION

import hashlib
import re
from collections import Counter
from typing import List, Dict, Any, Optional

from sqlalchemy import func, or_, text

from crypto_hunter_web.models import AnalysisFile, FileContent
from crypto_hunter_web.models import db


class SearchService:
    """High-performance search service for large file collections (improved version)."""

    # Pre-compiled regex patterns for magic search
    PATTERNS = {
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'base64': re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
        'hex_string': re.compile(r'\b0x[a-fA-F0-9]+\b'),
        'timestamp': re.compile(r'\b\d{10,13}\b'),
        'flag': re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
        'key': re.compile(r'(key|password|pass|secret|token)[\s=:]+[\w\d+/=]+', re.IGNORECASE)
    }

    @staticmethod
    def build_search_index():
        """Build database indexes for search performance (including content)."""
        try:
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_files_filename_trgm 
                    ON analysis_files USING gin(filename gin_trgm_ops);
                CREATE INDEX IF NOT EXISTS idx_files_text_search 
                    ON analysis_files 
                    USING gin(to_tsvector('english', filename || ' ' || COALESCE(file_type, '')));
                CREATE INDEX IF NOT EXISTS idx_files_sha_prefix 
                    ON analysis_files (LEFT(sha256_hash, 8));
                CREATE INDEX IF NOT EXISTS idx_files_size_type 
                    ON analysis_files (file_size, file_type);
                CREATE INDEX IF NOT EXISTS idx_files_status_priority 
                    ON analysis_files (status, priority);
                /* New index for content text search: */
                CREATE INDEX IF NOT EXISTS idx_content_text_search 
                    ON file_contents USING gin(to_tsvector('english', content_text));
                CREATE INDEX IF NOT EXISTS idx_content_bytes_search 
                    ON file_contents USING gin(content_bytes gin_trgm_ops);
            """))
            db.session.commit()
            return True
        except Exception as e:
            print(f"Index creation failed (may already exist): {e}")
            return False

    @staticmethod
    def hyperfast_search(query: str, filters: Dict[str, Any] = None, limit: int = 100) -> Dict[str, Any]:
        """Ultra-fast search with intelligent matching."""
        if not query or len(query.strip()) < 2:
            # No query: just return filtered files (recent/high-priority first)
            return SearchService._get_filtered_files(filters, limit)
        
        query = query.strip()
        # Detect query type for optimized search path
        search_type = SearchService._detect_query_type(query)
        
        if search_type == 'sha':
            return SearchService._search_by_sha(query, limit)
        elif search_type == 'pattern':
            # For pattern-like queries, do a broad content search
            return SearchService._magic_search(query, filters, limit)
        else:
            # Default: filename/type search + content search
            return SearchService._full_text_search(query, filters, limit)

    @staticmethod
    def _full_text_search(query: str, filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Full-text search on filenames, file types, and content with basic relevance ranking."""
        # Base query on AnalysisFile
        base_q = AnalysisFile.query
        
        # Filename and file_type conditions (case-insensitive substring match)
        filename_cond = AnalysisFile.filename.ilike(f'%{query}%')
        filetype_cond = AnalysisFile.file_type.ilike(f'%{query}%')
        
        # Content search condition - FIXED: Use content_bytes instead of content_data
        content_subq = db.session.query(FileContent.file_id).filter(
            or_(
                FileContent.content_text.ilike(f'%{query}%'),
                func.encode(FileContent.content_bytes, 'escape').ilike(f'%{query}%')
            )
        ).subquery()
        
        content_cond = AnalysisFile.id.in_(content_subq)
        
        # Combine all search conditions
        search_cond = or_(filename_cond, filetype_cond, content_cond)
        base_q = base_q.filter(search_cond)
        
        # Apply any additional filters (status, size, etc.)
        base_q = SearchService._apply_filters(base_q, filters)
        
        # Order by relevance: filename matches first, then file type, then content, then by priority and recency
        results = base_q.order_by(
            filename_cond.desc(),
            filetype_cond.desc(),
            AnalysisFile.priority.desc(),
            AnalysisFile.created_at.desc()
        ).limit(limit).all()
        
        return {
            'files': [SearchService._serialize_file(f) for f in results],
            'total': len(results),
            'search_type': 'full_text',
            'query': query
        }

    @staticmethod
    def _magic_search(query: str, filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Deep search for patterns and content within files."""
        results = []
        
        # Search within file content (text and raw bytes) - FIXED: Use content_bytes
        content_q = db.session.query(AnalysisFile).join(FileContent).filter(
            or_(
                FileContent.content_text.ilike(f'%{query}%'),
                func.encode(FileContent.content_bytes, 'escape').ilike(f'%{query}%')
            )
        )
        content_q = SearchService._apply_filters(content_q, filters)  # apply filters to AnalysisFile in the join
        content_results = content_q.limit(max(limit, 10) // 2).all()  # use half of the limit for content matches
        results.extend(content_results)
        
        # If the query itself matches a known pattern type, include files likely related
        for pattern_name, pattern in SearchService.PATTERNS.items():
            if pattern.search(query):
                # e.g., if query looks like an email or hash, gather files with similar context (filename or type hint)
                pat_q = AnalysisFile.query.filter(
                    or_(
                        AnalysisFile.filename.ilike(f'%{pattern_name}%'),
                        AnalysisFile.file_type.ilike(f'%{pattern_name}%')
                    )
                )
                pat_q = SearchService._apply_filters(pat_q, filters)
                pattern_files = pat_q.limit(10).all()
                results.extend(pattern_files)
                # Only use one pattern category for suggestions to avoid too many irrelevant results
                break
        
        # Remove duplicates by file ID and enforce overall limit
        unique_files = list({f.id: f for f in results}.values())[:limit]
        
        return {
            'files': [SearchService._serialize_file(f) for f in unique_files],
            'total': len(unique_files),
            'search_type': 'magic',
            'query': query
        }

    @staticmethod
    def _search_by_sha(prefix: str, limit: int) -> Dict[str, Any]:
        """Optimized search for files by SHA-256 prefix."""
        files = AnalysisFile.query.filter(
            AnalysisFile.sha256_hash.ilike(f'{prefix}%')
        ).limit(limit).all()
        
        return {
            'files': [SearchService._serialize_file(f) for f in files],
            'total': len(files),
            'search_type': 'sha',
            'query': prefix
        }

    @staticmethod
    def _apply_filters(query, filters: Dict[str, Any]):
        """Apply additional filters (file_type, status, size, etc.) to an AnalysisFile query."""
        if not filters:
            return query
        
        if filters.get('file_type'):
            query = query.filter(AnalysisFile.file_type.ilike(f"%{filters['file_type']}%"))
        
        if filters.get('status'):
            query = query.filter(AnalysisFile.status == filters['status'])
        
        if filters.get('is_root') is not None:
            query = query.filter(AnalysisFile.is_root_file == filters['is_root'])
        
        if filters.get('min_size'):
            query = query.filter(AnalysisFile.file_size >= filters['min_size'])
        
        if filters.get('max_size'):
            query = query.filter(AnalysisFile.file_size <= filters['max_size'])
        
        if filters.get('priority_min'):
            query = query.filter(AnalysisFile.priority >= filters['priority_min'])
        
        if filters.get('created_after'):
            query = query.filter(AnalysisFile.created_at >= filters['created_after'])
        
        if filters.get('created_before'):
            query = query.filter(AnalysisFile.created_at <= filters['created_before'])
        
        return query

    @staticmethod
    def _get_filtered_files(filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Return top files that match only the given filters (no query string)."""
        q = AnalysisFile.query
        q = SearchService._apply_filters(q, filters)
        files = q.order_by(AnalysisFile.priority.desc(), AnalysisFile.created_at.desc())\
                 .limit(limit).all()
        
        return {
            'files': [SearchService._serialize_file(f) for f in files],
            'total': len(files),
            'search_type': 'filtered',
            'query': ''
        }

    @staticmethod
    def group_files(group_by: str, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Group files by a category (type, status, size range, priority), applying filters if provided."""
        q = AnalysisFile.query
        q = SearchService._apply_filters(q, filters)  # FIXED: Apply filters to the query
        
        groups = []
        
        if group_by == 'type':
            # Group by file_type (with filters applied)
            for file_type, count in q.with_entities(AnalysisFile.file_type,
                                                   func.count(AnalysisFile.id)).group_by(AnalysisFile.file_type).all():
                groups.append({'key': file_type, 'count': count})
        
        elif group_by == 'status':
            for status, count in q.with_entities(AnalysisFile.status,
                                                func.count(AnalysisFile.id)).group_by(AnalysisFile.status).all():
                groups.append({'key': status, 'count': count})
        
        elif group_by == 'size':
            size_case = func.case([
                (AnalysisFile.file_size < 1024, 'Small (<1KB)'),
                (AnalysisFile.file_size < 1024*1024, 'Medium (<1MB)'),
                (AnalysisFile.file_size < 1024*1024*1024, 'Large (<1GB)')
            ], else_='Very Large (>1GB)').label('size_range')
            
            for size_range, count in q.with_entities(size_case, func.count(AnalysisFile.id)).group_by(size_case).all():
                groups.append({'key': size_range, 'count': count})
        
        elif group_by == 'priority':
            for priority, count in q.with_entities(AnalysisFile.priority,
                                                  func.count(AnalysisFile.id)).group_by(AnalysisFile.priority).all():
                groups.append({'key': priority, 'count': count})
        
        else:
            return {'error': f'Unknown grouping: {group_by}'}
        
        return {'group_by': group_by, 'groups': groups}

    @staticmethod
    def xor_search(sha_list: List[str]) -> Dict[str, Any]:
        """XOR operation on file lists for correlation analysis"""
        if len(sha_list) < 2:
            return {'error': 'XOR requires at least 2 files'}

        # Get all files
        files = {f.sha256_hash: f for f in AnalysisFile.query.filter(
            AnalysisFile.sha256_hash.in_(sha_list)
        ).all()}

        if len(files) != len(sha_list):
            return {'error': 'Some files not found'}

        # Perform XOR correlation analysis
        correlations = SearchService._analyze_xor_correlations(list(files.values()))

        return {
            'files': [SearchService._serialize_file(f) for f in files.values()],
            'correlations': correlations,
            'operation': 'xor'
        }

    @staticmethod
    def _analyze_xor_correlations(files: List[AnalysisFile]) -> Dict[str, Any]:
        """Analyze correlations between files for XOR operation"""
        correlations = {
            'common_patterns': [],
            'size_relationships': [],
            'type_similarities': [],
            'temporal_patterns': []
        }

        # Analyze file sizes
        sizes = [f.file_size for f in files if f.file_size]
        if len(sizes) > 1:
            size_ratios = []
            for i in range(len(sizes)):
                for j in range(i + 1, len(sizes)):
                    ratio = sizes[i] / sizes[j] if sizes[j] != 0 else float('inf')
                    size_ratios.append(ratio)
            correlations['size_relationships'] = size_ratios

        # Analyze file types
        types = [f.file_type for f in files]
        type_counter = Counter(types)
        correlations['type_similarities'] = dict(type_counter)

        # Analyze creation patterns
        dates = [f.created_at for f in files if f.created_at]
        if len(dates) > 1:
            time_diffs = []
            for i in range(len(dates)):
                for j in range(i + 1, len(dates)):
                    diff = abs((dates[i] - dates[j]).total_seconds())
                    time_diffs.append(diff)
            correlations['temporal_patterns'] = time_diffs

        return correlations

    @staticmethod
    def _detect_query_type(query: str) -> str:
        """Detect the type of query for optimization"""
        query = query.strip().lower()
        
        # SHA-256 hash (64 hex chars)
        if re.match(r'^[a-f0-9]{8,64}$', query):
            return 'sha'
        
        # Check for pattern-like queries
        for pattern_name, pattern in SearchService.PATTERNS.items():
            if pattern.search(query):
                return 'pattern'
        
        return 'text'

    @staticmethod
    def _serialize_file(file: AnalysisFile) -> Dict[str, Any]:
        """Convert AnalysisFile object to dictionary for JSON response."""
        return {
            'id': file.id,
            'sha256_hash': file.sha256_hash,
            'filename': file.filename,
            'file_type': file.file_type,
            'file_size': file.file_size,
            'status': file.status,
            'priority': file.priority,
            'is_root_file': file.is_root_file,
            'created_at': file.created_at.isoformat() if file.created_at else None,
            'updated_at': getattr(file, 'updated_at', None) and file.updated_at.isoformat(),
            'findings_count': len(getattr(file, 'findings', [])),
            'content_preview': SearchService._get_content_preview(file.id)
        }

    @staticmethod
    def _get_content_preview(file_id: int) -> Optional[str]:
        """Get a preview of file content for search results"""
        try:
            content = FileContent.query.filter_by(
                file_id=file_id,
                content_type='extracted_text'
            ).first()
            
            if content and content.content_text:
                preview = content.content_text[:200]
                return preview + "..." if len(content.content_text) > 200 else preview
        except Exception:
            pass
        return None


class MetadataGenerator:
    """Generate intelligent metadata for files"""

    @staticmethod
    def generate_file_metadata(file_path: str, file_id: int) -> Dict[str, Any]:
        """Generate comprehensive metadata for a file"""
        metadata = {
            'magic_patterns': [],
            'content_signatures': [],
            'cross_references': [],
            'similarity_matches': [],
            'intelligence_hints': []
        }

        try:
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB for analysis

            # Magic pattern detection
            metadata['magic_patterns'] = MetadataGenerator._detect_magic_patterns(content)

            # Content signatures
            metadata['content_signatures'] = MetadataGenerator._generate_content_signatures(content)

            # Cross-reference with existing files
            metadata['cross_references'] = MetadataGenerator._find_cross_references(content, file_id)

            # Intelligence hints
            metadata['intelligence_hints'] = MetadataGenerator._generate_intelligence_hints(content, metadata)

        except Exception as e:
            metadata['error'] = str(e)

        return metadata

    @staticmethod
    def _detect_magic_patterns(content: bytes) -> List[Dict[str, Any]]:
        """Detect magic patterns in file content"""
        patterns = []

        # Convert to string for pattern matching
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = ''

        # Check for known patterns
        for pattern_name, pattern in SearchService.PATTERNS.items():
            matches = pattern.findall(text_content)
            if matches:
                patterns.append({
                    'type': pattern_name,
                    'matches': matches[:5],  # Limit to first 5 matches
                    'count': len(matches)
                })

        return patterns

    @staticmethod
    def _generate_content_signatures(content: bytes) -> List[Dict[str, Any]]:
        """Generate content signatures for similarity matching"""
        signatures = []

        # File magic bytes
        if len(content) >= 16:
            signatures.append({
                'type': 'magic_bytes',
                'signature': content[:16].hex(),
                'description': 'First 16 bytes'
            })

        # Content hash signatures
        signatures.append({
            'type': 'md5_hash',
            'signature': hashlib.md5(content).hexdigest(),
            'description': 'MD5 hash of content'
        })

        signatures.append({
            'type': 'sha1_hash',
            'signature': hashlib.sha1(content).hexdigest(),
            'description': 'SHA1 hash of content'
        })

        # Entropy calculation
        if content:
            entropy = MetadataGenerator._calculate_entropy(content)
            signatures.append({
                'type': 'entropy',
                'signature': f"{entropy:.4f}",
                'description': 'Shannon entropy'
            })

        return signatures

    @staticmethod
    def _find_cross_references(content: bytes, file_id: int) -> List[Dict[str, Any]]:
        """Find cross-references with other files"""
        cross_refs = []

        try:
            # Look for similar content patterns
            content_hash = hashlib.md5(content).hexdigest()
            
            # Find files with similar content hashes (simplified)
            similar_files = db.session.query(FileContent).filter(
                FileContent.file_id != file_id,
                FileContent.content_text.like(f'%{content_hash}%')
            ).limit(5).all()

            for similar in similar_files:
                cross_refs.append({
                    'type': 'content_similarity',
                    'file_id': similar.file_id,
                    'similarity_score': 0.8  # Simplified score
                })

        except Exception as e:
            cross_refs.append({
                'type': 'error',
                'message': str(e)
            })

        return cross_refs

    @staticmethod
    def _generate_intelligence_hints(content: bytes, metadata: Dict[str, Any]) -> List[str]:
        """Generate intelligence hints based on content analysis"""
        hints = []

        # Check entropy
        if 'content_signatures' in metadata:
            for sig in metadata['content_signatures']:
                if sig['type'] == 'entropy':
                    entropy = float(sig['signature'])
                    if entropy > 7.5:
                        hints.append("High entropy content - possible encryption or compression")
                    elif entropy < 1.0:
                        hints.append("Low entropy content - likely plain text or structured data")

        # Check for crypto patterns
        if 'magic_patterns' in metadata:
            pattern_types = {p['type'] for p in metadata['magic_patterns']}
            if 'base64' in pattern_types:
                hints.append("Contains Base64 encoded data")
            if any(p.startswith('hash_') for p in pattern_types):
                hints.append("Contains cryptographic hashes")
            if 'key' in pattern_types:
                hints.append("May contain cryptographic keys or passwords")

        return hints

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        entropy = 0
        for count in byte_counts:
            if count > 0:
                frequency = count / len(data)
                entropy -= frequency * (frequency.bit_length() - 1)

        return entropy
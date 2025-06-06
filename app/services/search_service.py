"""
Advanced search service with indexing and intelligent correlation
"""

import re
import hashlib
import json
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy import func, or_, and_, text
from app.models import db
from app.models.file import AnalysisFile, FileContent
from app.models.finding import Finding
from app.utils.crypto import calculate_sha256


class SearchService:
    """High-performance search service for large file collections"""

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
        """Build search indexes for performance"""
        try:
            # Create database indexes
            db.session.execute(text("""
                                    CREATE INDEX IF NOT EXISTS idx_files_filename_trgm ON analysis_file USING gin(filename gin_trgm_ops);
                                    CREATE INDEX IF NOT EXISTS idx_files_content_search ON analysis_file USING gin(to_tsvector('english', filename || ' ' || COALESCE (file_type, '')));
                                    CREATE INDEX IF NOT EXISTS idx_files_sha_prefix ON analysis_file (LEFT (sha256_hash, 8));
                                    CREATE INDEX IF NOT EXISTS idx_files_size_type ON analysis_file (file_size, file_type);
                                    CREATE INDEX IF NOT EXISTS idx_files_status_priority ON analysis_file (status, priority);
                                    """))
            db.session.commit()
            return True
        except Exception as e:
            print(f"Index creation failed (may already exist): {e}")
            return False

    @staticmethod
    def hyperfast_search(query: str, filters: Dict[str, Any] = None, limit: int = 100) -> Dict[str, Any]:
        """Ultra-fast search with intelligent matching"""
        if not query or len(query.strip()) < 2:
            return SearchService._get_filtered_files(filters, limit)

        query = query.strip()

        # Detect query type and optimize accordingly
        search_type = SearchService._detect_query_type(query)

        if search_type == 'sha':
            return SearchService._search_by_sha(query, limit)
        elif search_type == 'pattern':
            return SearchService._magic_search(query, filters, limit)
        else:
            return SearchService._full_text_search(query, filters, limit)

    @staticmethod
    def _detect_query_type(query: str) -> str:
        """Detect the type of search query for optimization"""
        if re.match(r'^[a-fA-F0-9]{6,64}$', query):
            return 'sha'
        elif any(pattern in query.lower() for pattern in ['flag{', '0x', 'http', '@']):
            return 'pattern'
        else:
            return 'text'

    @staticmethod
    def _search_by_sha(query: str, limit: int) -> Dict[str, Any]:
        """Optimized SHA hash search"""
        files = AnalysisFile.query.filter(
            AnalysisFile.sha256_hash.ilike(f'{query}%')
        ).limit(limit).all()

        return {
            'files': [SearchService._serialize_file(f) for f in files],
            'total': len(files),
            'search_type': 'sha',
            'query': query
        }

    @staticmethod
    def _full_text_search(query: str, filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Full-text search with ranking"""
        base_query = AnalysisFile.query

        # Build search conditions
        search_conditions = []

        # Filename search (highest priority)
        search_conditions.append(
            AnalysisFile.filename.ilike(f'%{query}%')
        )

        # File type search
        search_conditions.append(
            AnalysisFile.file_type.ilike(f'%{query}%')
        )

        # Combine with OR
        base_query = base_query.filter(or_(*search_conditions))

        # Apply additional filters
        base_query = SearchService._apply_filters(base_query, filters)

        # Order by relevance (filename matches first, then by priority)
        files = base_query.order_by(
            AnalysisFile.filename.ilike(f'%{query}%').desc(),
            AnalysisFile.priority.desc(),
            AnalysisFile.created_at.desc()
        ).limit(limit).all()

        return {
            'files': [SearchService._serialize_file(f) for f in files],
            'total': len(files),
            'search_type': 'full_text',
            'query': query
        }

    @staticmethod
    def _magic_search(query: str, filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Magic search for patterns and content"""
        results = []

        # Search in file content
        content_results = db.session.query(AnalysisFile).join(FileContent).filter(
            or_(
                FileContent.content_text.ilike(f'%{query}%'),
                func.encode(FileContent.content_data, 'escape').ilike(f'%{query}%')
            )
        ).limit(limit // 2).all()

        results.extend(content_results)

        # Pattern matching search
        for pattern_name, pattern in SearchService.PATTERNS.items():
            if pattern.search(query):
                # Find files that might contain this pattern type
                pattern_files = AnalysisFile.query.filter(
                    AnalysisFile.filename.ilike(f'%{pattern_name}%')
                ).limit(10).all()
                results.extend(pattern_files)

        # Remove duplicates
        unique_results = list({f.id: f for f in results}.values())[:limit]

        return {
            'files': [SearchService._serialize_file(f) for f in unique_results],
            'total': len(unique_results),
            'search_type': 'magic',
            'query': query
        }

    @staticmethod
    def _apply_filters(query, filters: Dict[str, Any]):
        """Apply additional filters to query"""
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

        return query

    @staticmethod
    def _get_filtered_files(filters: Dict[str, Any], limit: int) -> Dict[str, Any]:
        """Get files with filters only (no search query)"""
        query = AnalysisFile.query
        query = SearchService._apply_filters(query, filters)

        files = query.order_by(
            AnalysisFile.priority.desc(),
            AnalysisFile.created_at.desc()
        ).limit(limit).all()

        return {
            'files': [SearchService._serialize_file(f) for f in files],
            'total': len(files),
            'search_type': 'filtered',
            'query': ''
        }

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
        dates = [f.created_at for f in files]
        if len(dates) > 1:
            time_diffs = []
            for i in range(len(dates)):
                for j in range(i + 1, len(dates)):
                    diff = abs((dates[i] - dates[j]).total_seconds())
                    time_diffs.append(diff)

            correlations['temporal_patterns'] = time_diffs

        return correlations

    @staticmethod
    def group_files(group_by: str, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Group files by various criteria"""
        query = AnalysisFile.query

        if filters:
            query = SearchService._apply_filters(query, filters)

        if group_by == 'type':
            groups = db.session.query(
                AnalysisFile.file_type,
                func.count(AnalysisFile.id).label('count')
            ).group_by(AnalysisFile.file_type).all()

        elif group_by == 'status':
            groups = db.session.query(
                AnalysisFile.status,
                func.count(AnalysisFile.id).label('count')
            ).group_by(AnalysisFile.status).all()

        elif group_by == 'size':
            # Group by size ranges
            groups = db.session.query(
                func.case([
                    (AnalysisFile.file_size < 1024, 'Small (<1KB)'),
                    (AnalysisFile.file_size < 1024 * 1024, 'Medium (<1MB)'),
                    (AnalysisFile.file_size < 1024 * 1024 * 1024, 'Large (<1GB)'),
                ], else_='Very Large (>1GB)').label('size_range'),
                func.count(AnalysisFile.id).label('count')
            ).group_by('size_range').all()

        elif group_by == 'priority':
            groups = db.session.query(
                AnalysisFile.priority,
                func.count(AnalysisFile.id).label('count')
            ).group_by(AnalysisFile.priority).all()

        else:
            return {'error': f'Unknown grouping: {group_by}'}

        return {
            'groups': [{'key': g[0], 'count': g[1]} for g in groups],
            'group_by': group_by
        }

    @staticmethod
    def _serialize_file(file: AnalysisFile) -> Dict[str, Any]:
        """Serialize file for JSON response"""
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
            'findings_count': len(file.findings) if hasattr(file, 'findings') else 0
        }


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

        # Binary signatures
        if content.startswith(b'\xff\xd8\xff'):
            patterns.append({'type': 'jpeg_signature', 'confidence': 'high'})
        elif content.startswith(b'\x89PNG'):
            patterns.append({'type': 'png_signature', 'confidence': 'high'})
        elif b'PK' in content[:10]:
            patterns.append({'type': 'zip_signature', 'confidence': 'medium'})

        return patterns

    @staticmethod
    def _generate_content_signatures(content: bytes) -> List[Dict[str, Any]]:
        """Generate content-based signatures for similarity matching"""
        signatures = []

        # Byte frequency signature
        if len(content) > 0:
            byte_freq = Counter(content)
            top_bytes = byte_freq.most_common(10)
            signatures.append({
                'type': 'byte_frequency',
                'signature': [{'byte': b, 'count': c} for b, c in top_bytes]
            })

        # Hash signatures at different lengths
        for chunk_size in [256, 1024, 4096]:
            if len(content) >= chunk_size:
                chunk_hash = hashlib.sha256(content[:chunk_size]).hexdigest()
                signatures.append({
                    'type': f'hash_{chunk_size}',
                    'signature': chunk_hash
                })

        return signatures

    @staticmethod
    def _find_cross_references(content: bytes, file_id: int) -> List[Dict[str, Any]]:
        """Find cross-references with existing files"""
        cross_refs = []

        try:
            # Look for similar files by content patterns
            content_hash = hashlib.sha256(content[:1024]).hexdigest()

            # Find files with similar content signatures
            similar_files = AnalysisFile.query.filter(
                AnalysisFile.id != file_id
            ).limit(10).all()

            # This is a simplified version - in practice, you'd store signatures in a separate table
            for similar_file in similar_files:
                if similar_file.filepath and os.path.exists(similar_file.filepath):
                    try:
                        with open(similar_file.filepath, 'rb') as f:
                            similar_content = f.read(1024)

                        similarity = MetadataGenerator._calculate_similarity(content[:1024], similar_content)
                        if similarity > 0.7:  # 70% similarity threshold
                            cross_refs.append({
                                'file_id': similar_file.id,
                                'filename': similar_file.filename,
                                'similarity': similarity,
                                'type': 'content_similarity'
                            })
                    except:
                        continue

        except Exception as e:
            cross_refs.append({'error': str(e)})

        return cross_refs[:5]  # Limit results

    @staticmethod
    def _calculate_similarity(content1: bytes, content2: bytes) -> float:
        """Calculate similarity between two byte sequences"""
        if len(content1) == 0 or len(content2) == 0:
            return 0.0

        # Simple byte-level similarity
        min_len = min(len(content1), len(content2))
        matches = sum(1 for i in range(min_len) if content1[i] == content2[i])

        return matches / min_len

    @staticmethod
    def _generate_intelligence_hints(content: bytes, metadata: Dict[str, Any]) -> List[str]:
        """Generate intelligence hints for investigation"""
        hints = []

        # Check for steganography indicators
        if any(p['type'] in ['base64', 'hex_string'] for p in metadata.get('magic_patterns', [])):
            hints.append("File contains base64/hex data - potential steganography")

        # Check for multiple file signatures
        signatures = [p for p in metadata.get('magic_patterns', []) if 'signature' in p['type']]
        if len(signatures) > 1:
            hints.append("Multiple file signatures detected - possible file concatenation")

        # Check for encryption indicators
        if len(set(content)) > 200:  # High entropy
            hints.append("High entropy detected - possible encryption or compression")

        # Check for flag patterns
        flag_patterns = [p for p in metadata.get('magic_patterns', []) if p['type'] == 'flag']
        if flag_patterns:
            hints.append("Flag patterns detected - likely CTF challenge file")

        return hints
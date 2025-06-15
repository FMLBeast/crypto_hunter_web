#!/usr/bin/env python3
"""
Comprehensive Extractor System

This module provides a comprehensive extraction system for the Crypto Hunter application,
integrating various extraction methods and agents.
"""

import sys
import os
import json
import uuid
from typing import List, Dict, Any
from sqlalchemy import text

# Import agent framework from the new location
from crypto_hunter_web.services.agents.agent_framework import (
    BaseAgent, AgentType, AgentTask, AgentResult, TaskPriority, AgentCapability
)
from crypto_hunter_web import create_app, db
from crypto_hunter_web.models import AnalysisFile, FileStatus
from crypto_hunter_web.services.file_analyzer import FileAnalyzer
from crypto_hunter_web.services.extraction_engine import ExtractionEngine
from crypto_hunter_web.services.crypto_intelligence_service import CryptoIntelligenceService
from crypto_hunter_web.services.extractors import get_extractor


class ComprehensiveExtractorSystem:
    """
    Main class for the comprehensive extractor system.
    Integrates various extraction agents and methods.
    """
    
    def __init__(self):
        """Initialize the comprehensive extractor system"""
        self.app = create_app()
        self.file_analyzer = FileAnalyzer()
        self.extraction_engine = ExtractionEngine()
        self.crypto_service = CryptoIntelligenceService()
        
    def extract(self, file_id: int, methods: List[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive extraction on a file
        
        Args:
            file_id: ID of the file to extract from
            methods: List of extraction methods to use
            
        Returns:
            Dictionary with extraction results
        """
        if methods is None:
            methods = ['zsteg', 'steghide', 'binwalk', 'strings']
            
        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return {
                    'success': False,
                    'error': f"File not found: {file_id}"
                }
            
            extraction_results = {}
            
            # Run each extraction method
            for method in methods:
                try:
                    extractor = get_extractor(method)
                    if extractor:
                        result = extractor.extract(file_record.original_path, {})
                        extraction_results[method] = result
                    else:
                        extraction_results[method] = {
                            'success': False,
                            'error': f"Extractor not found: {method}"
                        }
                except Exception as e:
                    extraction_results[method] = {
                        'success': False,
                        'error': str(e)
                    }
            
            # Count successful extractions
            successful_extractions = sum(1 for r in extraction_results.values() if r.get('success'))
            
            return {
                'success': successful_extractions > 0,
                'file_id': file_id,
                'methods_run': methods,
                'successful_extractions': successful_extractions,
                'results': extraction_results
            }
    
    def analyze(self, file_id: int) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a file
        
        Args:
            file_id: ID of the file to analyze
            
        Returns:
            Dictionary with analysis results
        """
        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return {
                    'success': False,
                    'error': f"File not found: {file_id}"
                }
            
            # Use existing FileAnalyzer
            analysis_result = self.file_analyzer.analyze_file(file_record.original_path)
            
            # Update file record with analysis results
            file_record.status = FileStatus.COMPLETE
            file_record.confidence_score = analysis_result.get('confidence', 0.0)
            file_record.contains_crypto = analysis_result.get('contains_crypto', False)
            file_record.analysis_extra_data = analysis_result.get('metadata', {})
            
            db.session.commit()
            
            return {
                'success': True,
                'file_id': file_id,
                'analysis': analysis_result,
                'entropy': analysis_result.get('entropy'),
                'file_type': analysis_result.get('file_type'),
                'contains_crypto': analysis_result.get('contains_crypto')
            }
    
    def detect_crypto(self, file_id: int) -> Dict[str, Any]:
        """
        Detect cryptographic patterns in a file
        
        Args:
            file_id: ID of the file to analyze
            
        Returns:
            Dictionary with crypto detection results
        """
        with self.app.app_context():
            file_record = AnalysisFile.query.get(file_id)
            if not file_record:
                return {
                    'success': False,
                    'error': f"File not found: {file_id}"
                }
            
            # Use existing crypto intelligence service
            analysis = self.crypto_service.analyze_patterns(file_record.original_path)
            
            return {
                'success': True,
                'file_id': file_id,
                'crypto_analysis': analysis,
                'patterns_found': analysis.get('patterns', []),
                'confidence': analysis.get('confidence', 0.0)
            }


# Factory function to create the system
def create_extractor_system() -> ComprehensiveExtractorSystem:
    """Create and return a new ComprehensiveExtractorSystem instance"""
    return ComprehensiveExtractorSystem()


if __name__ == '__main__':
    # Test the system
    system = create_extractor_system()
    print("Comprehensive Extractor System initialized")
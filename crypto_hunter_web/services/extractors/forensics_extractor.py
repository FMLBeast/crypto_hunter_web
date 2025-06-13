"""
crypto_hunter_web/services/extractors/forensics_extractor.py
Comprehensive forensics extractor
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from .base import BaseExtractor

# Mock ForensicsToolkit for testing purposes
class ForensicsToolkit:
    """Mock ForensicsToolkit class for testing"""

    def __init__(self):
        """Initialize with available tools"""
        self.tools = {
            'strings': 'Basic string extraction',
            'hexdump': 'Hexadecimal dump',
            'binwalk': 'Binary analysis',
            'foremost': 'File carving',
            'exiftool': 'Metadata extraction',
            'steghide': 'Steganography detection',
            'zsteg': 'PNG/BMP steganography detection',
            'stegseek': 'Steganography brute force',
            'bulk-extractor': 'Bulk data extraction'
        }

    def analyze_file_comprehensive(self, file_path, file_type):
        """Mock comprehensive analysis"""
        return {
            'tools_executed': [],
            'confidence_score': 0.5,
            'execution_time': 0.0
        }

    def _is_tool_available(self, tool_name):
        """Mock tool availability check"""
        return False

    def _run_tool_analysis(self, tool_name, file_path, file_type):
        """Mock tool analysis"""
        return None

    def _extract_findings(self, tool_result):
        """Mock findings extraction"""
        return []

logger = logging.getLogger(__name__)

class ForensicsExtractor(BaseExtractor):
    """Comprehensive forensics extractor using the ForensicsToolkit"""

    def _get_tool_name(self):
        return self.method_name

    def extract(self, file_path: str, parameters: Optional[Dict] = None) -> Dict[str, Any]:
        """Extract using comprehensive forensics toolkit"""
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': 'File not found',
                'data': b'',
                'details': '',
                'command_line': '',
                'confidence': 0
            }

        try:
            # Initialize forensics toolkit
            toolkit = ForensicsToolkit()

            # Determine file type
            import magic
            file_type = magic.from_file(file_path, mime=True)

            if self.method_name == 'forensics':
                # Run comprehensive analysis
                results = toolkit.analyze_file_comprehensive(file_path, file_type)

                # Extract all findings and data
                all_data = b''
                all_findings = []

                for tool_result in results.get('tools_executed', []):
                    if tool_result.success:
                        all_data += tool_result.data
                        all_findings.extend(toolkit._extract_findings(tool_result))

                return {
                    'success': len(all_findings) > 0,
                    'data': all_data,
                    'error': '',
                    'details': f"Comprehensive forensics analysis: {len(all_findings)} findings from {len(results.get('tools_executed', []))} tools",
                    'command_line': 'comprehensive_forensics_analysis',
                    'confidence': results.get('confidence_score', 0.0),
                    'metadata': {
                        'findings': all_findings,
                        'tools_executed': len(results.get('tools_executed', [])),
                        'execution_time': results.get('execution_time', 0.0),
                        'full_results': results
                    }
                }

            else:
                # Run specific tool
                if not toolkit._is_tool_available(self.method_name):
                    return {
                        'success': False,
                        'error': f'Tool {self.method_name} not available',
                        'data': b'',
                        'details': f'Tool {self.method_name} is not installed or available',
                        'command_line': '',
                        'confidence': 0
                    }

                # Run the specific tool
                tool_result = toolkit._run_tool_analysis(self.method_name, file_path, file_type)

                if tool_result:
                    findings = toolkit._extract_findings(tool_result)

                    return {
                        'success': tool_result.success,
                        'data': tool_result.data,
                        'error': tool_result.error_message,
                        'details': f"{self.method_name}: {len(findings)} findings" if tool_result.success else f"{self.method_name} failed",
                        'command_line': tool_result.command_line,
                        'confidence': tool_result.confidence,
                        'metadata': {
                            'findings': findings,
                            'execution_time': tool_result.execution_time,
                            'tool_metadata': tool_result.metadata
                        }
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Failed to execute {self.method_name}',
                        'data': b'',
                        'details': f'Tool execution failed for {self.method_name}',
                        'command_line': '',
                        'confidence': 0
                    }

        except Exception as e:
            logger.error(f"Forensics extraction failed for {self.method_name}: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': f'Exception during {self.method_name} extraction',
                'command_line': '',
                'confidence': 0
            }

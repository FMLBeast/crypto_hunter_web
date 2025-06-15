"""
Cryptographic extractors for XOR and AES decryption
"""

from typing import Dict, Any, Optional
import logging
import os

from .base import BaseExtractor
from ..advanced_forensics import CryptographicTools

logger = logging.getLogger(__name__)


class XORDecryptExtractor(BaseExtractor):
    """Extractor for XOR decryption"""

    def __init__(self, method_name="xor_decrypt"):
        super().__init__(method_name)
        self.crypto_tools = CryptographicTools()

    def _get_tool_name(self):
        """Return the name of the underlying tool"""
        return "xor_decrypt"

    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """
        Extract hidden data using XOR decryption

        Args:
            file_path: Path to the file to analyze
            parameters: Dictionary of extraction parameters
                - key: XOR key (string or bytes)
                - output_file: Optional path to save the decrypted data

        Returns:
            Dictionary with:
            - success: Boolean indicating if extraction succeeded
            - data: Extracted binary data (if successful)
            - error: Error message (if failed)
            - details: Additional details about the extraction
            - command_line: Command that was executed
            - confidence: Confidence level (1-10)
        """
        if not parameters:
            parameters = {}

        # Get key from parameters
        key = parameters.get('key', b'')
        if not key:
            return {
                'success': False,
                'error': 'No key provided for XOR decryption',
                'command_line': f'xor_decrypt {file_path}',
                'confidence': 0
            }

        try:
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read()

            # Decrypt data
            decrypted_data = self.crypto_tools.xor_decrypt(data, key)

            # Save to output file if specified
            output_file = parameters.get('output_file')
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                logger.info(f"XOR decrypted data saved to {output_file}")

            # Calculate confidence based on entropy and printable characters
            confidence = self._calculate_confidence(decrypted_data)

            return {
                'success': True,
                'data': decrypted_data,
                'details': f"XOR decryption successful with key: {key}",
                'command_line': f'xor_decrypt {file_path} --key {key}',
                'confidence': confidence
            }

        except Exception as e:
            logger.error(f"XOR decryption failed: {str(e)}")
            return {
                'success': False,
                'error': f"XOR decryption failed: {str(e)}",
                'command_line': f'xor_decrypt {file_path} --key {key}',
                'confidence': 0
            }

    def _calculate_confidence(self, data: bytes) -> int:
        """Calculate confidence score based on data characteristics"""
        if not data:
            return 0

        # Check for printable ASCII characters
        printable_ratio = sum(32 <= b <= 126 for b in data) / len(data)

        # Higher confidence if mostly printable characters
        if printable_ratio > 0.8:
            return 9
        elif printable_ratio > 0.5:
            return 7
        elif printable_ratio > 0.3:
            return 5
        else:
            return 3


class AESDecryptExtractor(BaseExtractor):
    """Extractor for AES decryption with passphrase 'Bodhi tree blossom'"""

    def __init__(self, method_name="aes_decrypt"):
        super().__init__(method_name)
        self.crypto_tools = CryptographicTools()
        self.default_passphrase = 'Bodhi tree blossom'

    def _get_tool_name(self):
        """Return the name of the underlying tool"""
        return "aes_decrypt"

    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """
        Extract hidden data using AES decryption

        Args:
            file_path: Path to the file to analyze
            parameters: Dictionary of extraction parameters
                - passphrase: AES passphrase (default: 'Bodhi tree blossom')
                - mode: AES mode ('CBC', 'ECB')
                - iv: Initialization vector for CBC mode (optional)
                - output_file: Optional path to save the decrypted data

        Returns:
            Dictionary with:
            - success: Boolean indicating if extraction succeeded
            - data: Extracted binary data (if successful)
            - error: Error message (if failed)
            - details: Additional details about the extraction
            - command_line: Command that was executed
            - confidence: Confidence level (1-10)
        """
        if not parameters:
            parameters = {}

        # Get parameters with defaults
        passphrase = parameters.get('passphrase', self.default_passphrase)
        mode = parameters.get('mode', 'CBC')
        iv = parameters.get('iv')

        try:
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read()

            # Decrypt data
            decrypted_data, success = self.crypto_tools.aes_decrypt(data, passphrase, mode, iv)

            if not success:
                return {
                    'success': False,
                    'error': 'AES decryption failed',
                    'command_line': f'aes_decrypt {file_path} --passphrase "{passphrase}" --mode {mode}',
                    'confidence': 0
                }

            # Save to output file if specified
            output_file = parameters.get('output_file')
            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                logger.info(f"AES decrypted data saved to {output_file}")

            # Calculate confidence based on entropy and printable characters
            confidence = self._calculate_confidence(decrypted_data)

            return {
                'success': True,
                'data': decrypted_data,
                'details': f"AES decryption successful with passphrase: '{passphrase}'",
                'command_line': f'aes_decrypt {file_path} --passphrase "{passphrase}" --mode {mode}',
                'confidence': confidence
            }

        except Exception as e:
            logger.error(f"AES decryption failed: {str(e)}")
            return {
                'success': False,
                'error': f"AES decryption failed: {str(e)}",
                'command_line': f'aes_decrypt {file_path} --passphrase "{passphrase}" --mode {mode}',
                'confidence': 0
            }

    def _calculate_confidence(self, data: bytes) -> int:
        """Calculate confidence score based on data characteristics"""
        if not data:
            return 0

        # Check for printable ASCII characters
        printable_ratio = sum(32 <= b <= 126 for b in data) / len(data)

        # Higher confidence if mostly printable characters
        if printable_ratio > 0.8:
            return 9
        elif printable_ratio > 0.5:
            return 7
        elif printable_ratio > 0.3:
            return 5
        else:
            return 3

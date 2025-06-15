#!/usr/bin/env python3
"""
Missing Extractors Integration

This module provides functionality to register and integrate missing extractors
into the Crypto Hunter extraction system.
"""

import logging
from typing import Dict, Any, List

from crypto_hunter_web.services.extractors import register_extractor, get_extractor

logger = logging.getLogger(__name__)


def register_missing_extractors() -> Dict[str, Any]:
    """
    Register any missing extractors that are not already registered in the system.
    
    Returns:
        Dict containing information about the registered extractors
    """
    registered = {}
    
    # List of extractors to ensure are registered
    extractors_to_register = [
        'strings', 'hexdump', 'exiftool', 'foremost', 'binwalk', 
        'zsteg', 'steghide', 'outguess', 'stegdetect'
    ]
    
    for extractor_name in extractors_to_register:
        try:
            # Check if extractor is already registered
            existing = get_extractor(extractor_name)
            if existing:
                logger.info(f"Extractor '{extractor_name}' already registered")
                registered[extractor_name] = {'status': 'already_registered'}
                continue
                
            # Register the extractor based on its type
            if extractor_name == 'strings':
                _register_strings_extractor()
            elif extractor_name == 'hexdump':
                _register_hexdump_extractor()
            elif extractor_name == 'exiftool':
                _register_exiftool_extractor()
            elif extractor_name == 'foremost':
                _register_foremost_extractor()
            elif extractor_name == 'binwalk':
                _register_binwalk_extractor()
            elif extractor_name == 'zsteg':
                _register_zsteg_extractor()
            elif extractor_name == 'steghide':
                _register_steghide_extractor()
            elif extractor_name == 'outguess':
                _register_outguess_extractor()
            elif extractor_name == 'stegdetect':
                _register_stegdetect_extractor()
            
            registered[extractor_name] = {'status': 'registered'}
            logger.info(f"Successfully registered '{extractor_name}' extractor")
            
        except Exception as e:
            logger.error(f"Failed to register '{extractor_name}' extractor: {e}")
            registered[extractor_name] = {'status': 'failed', 'error': str(e)}
    
    return {
        'success': True,
        'registered_extractors': registered,
        'total_registered': sum(1 for r in registered.values() if r['status'] in ['registered', 'already_registered'])
    }


def _register_strings_extractor():
    """Register the strings extractor"""
    from crypto_hunter_web.services.extractors.strings_extractor import StringsExtractor
    register_extractor('strings', StringsExtractor())


def _register_hexdump_extractor():
    """Register the hexdump extractor"""
    from crypto_hunter_web.services.extractors.hexdump_extractor import HexdumpExtractor
    register_extractor('hexdump', HexdumpExtractor())


def _register_exiftool_extractor():
    """Register the exiftool extractor"""
    from crypto_hunter_web.services.extractors.exiftool_extractor import ExifToolExtractor
    register_extractor('exiftool', ExifToolExtractor())


def _register_foremost_extractor():
    """Register the foremost extractor"""
    from crypto_hunter_web.services.extractors.foremost_extractor import ForemostExtractor
    register_extractor('foremost', ForemostExtractor())


def _register_binwalk_extractor():
    """Register the binwalk extractor"""
    from crypto_hunter_web.services.extractors.binwalk_extractor import BinwalkExtractor
    register_extractor('binwalk', BinwalkExtractor())


def _register_zsteg_extractor():
    """Register the zsteg extractor"""
    from crypto_hunter_web.services.extractors.zsteg_extractor import ZstegExtractor
    register_extractor('zsteg', ZstegExtractor())


def _register_steghide_extractor():
    """Register the steghide extractor"""
    from crypto_hunter_web.services.extractors.steghide_extractor import SteghideExtractor
    register_extractor('steghide', SteghideExtractor())


def _register_outguess_extractor():
    """Register the outguess extractor"""
    from crypto_hunter_web.services.extractors.outguess_extractor import OutguessExtractor
    register_extractor('outguess', OutguessExtractor())


def _register_stegdetect_extractor():
    """Register the stegdetect extractor"""
    from crypto_hunter_web.services.extractors.stegdetect_extractor import StegdetectExtractor
    register_extractor('stegdetect', StegdetectExtractor())


if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Register missing extractors
    result = register_missing_extractors()
    print(f"Registered {result['total_registered']} extractors")
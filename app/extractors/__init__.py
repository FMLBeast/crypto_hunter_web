"""
Steganography extractors package
"""

from .base import BaseExtractor
from .zsteg import ZStegExtractor
from .steghide import SteghideExtractor
from .binwalk import BinwalkExtractor
from .custom import CustomExtractor

# Registry of available extractors
EXTRACTORS = {
    'zsteg': ZStegExtractor,
    'zsteg_bitplane_1': ZStegExtractor,
    'zsteg_bitplane_2': ZStegExtractor, 
    'zsteg_bitplane_3': ZStegExtractor,
    'zsteg_bitplane_4': ZStegExtractor,
    'steghide': SteghideExtractor,
    'binwalk': BinwalkExtractor,
    'strings': CustomExtractor,
    'hexdump': CustomExtractor,
    'manual': CustomExtractor
}

def get_extractor(method_name):
    """Get extractor instance for specified method"""
    extractor_class = EXTRACTORS.get(method_name)
    if extractor_class:
        return extractor_class(method_name)
    return None

def list_extractors():
    """List all available extractors"""
    return list(EXTRACTORS.keys())

__all__ = [
    'BaseExtractor',
    'ZStegExtractor', 
    'SteghideExtractor',
    'BinwalkExtractor',
    'CustomExtractor',
    'get_extractor',
    'list_extractors'
]

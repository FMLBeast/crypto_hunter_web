#!/usr/bin/env python3
"""
Advanced Steganography Methods for Crypto Hunter
===============================================

Implements sophisticated steganography techniques that go beyond basic LSB:
- Multi-layered steganography extraction
- Frequency domain analysis (DCT, DWT, FFT)
- Statistical steganography detection
- Advanced bitplane analysis
- Palette-based steganography
- JPEG quantization table analysis
- PNG chunk analysis
- Polyglot file detection
- Metadata steganography
- Advanced pattern recognition
- Machine learning-based detection
- Custom steganography algorithms

These methods are essential for crypto challenges that yield hundreds of thousands
of files through recursive steganographic extraction.
"""

import os
import sys
import numpy as np
import hashlib
import subprocess
import tempfile
import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import struct
import zlib
import base64

# Advanced image processing
try:
    from PIL import Image, ImageChops, ImageStat, ImageFilter
    import cv2
    from scipy.fftpack import dct, idct, fft, ifft
    from scipy import ndimage, signal
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    import matplotlib.pyplot as plt
    HAS_ADVANCED_LIBS = True
except ImportError:
    HAS_ADVANCED_LIBS = False
    logging.warning("Advanced libraries not available - install PIL, opencv-python, scipy, scikit-learn, matplotlib")

# Add project path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_hunter_web.services.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

class MultiLayerSteganographyExtractor(BaseExtractor):
    """Extract data from multiple steganographic layers simultaneously"""
    
    def _get_tool_name(self):
        return 'multilayer_stegano'
    
    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """Extract from multiple steganographic layers"""
        if not HAS_ADVANCED_LIBS:
            return {'success': False, 'error': 'Advanced libraries not available'}
        
        results = {
            'success': False,
            'data': b'',
            'details': 'Multi-layer extraction failed',
            'command_line': f'multilayer_stegano {file_path}',
            'confidence': 0,
            'layers_found': [],
            'extracted_files': []
        }
        
        try:
            output_dir = tempfile.mkdtemp(prefix='multilayer_')
            
            # Load image
            img = Image.open(file_path)
            img_array = np.array(img)
            
            # Extract from multiple layers
            layers = self._extract_all_layers(img_array, output_dir)
            
            # Combine and analyze layers
            combined_data = self._combine_layer_data(layers)
            
            # Try different reconstruction methods
            reconstructed_files = self._reconstruct_hidden_files(combined_data, output_dir)
            
            if reconstructed_files:
                results['success'] = True
                results['confidence'] = 8
                results['details'] = f"Multi-layer extraction found {len(reconstructed_files)} files"
                results['extracted_files'] = reconstructed_files
                results['layers_found'] = list(layers.keys())
            
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Multi-layer extraction failed: {e}")
        
        return results
    
    def _extract_all_layers(self, img_array: np.ndarray, output_dir: str) -> Dict[str, bytes]:
        """Extract data from all possible steganographic layers"""
        layers = {}
        
        if len(img_array.shape) >= 3:
            # Color image processing
            for channel_idx, channel_name in enumerate(['red', 'green', 'blue']):
                if channel_idx < img_array.shape[2]:
                    channel = img_array[:, :, channel_idx]
                    
                    # Extract from different bit planes
                    for bit_plane in range(8):
                        layer_name = f'{channel_name}_bit_{bit_plane}'
                        data = self._extract_bitplane(channel, bit_plane)
                        if data and len(data) > 10:  # Minimum viable data
                            layers[layer_name] = data
                    
                    # Extract from LSB combinations
                    for combo in [(0, 1), (0, 2), (1, 2), (0, 1, 2)]:
                        layer_name = f'{channel_name}_lsb_combo_{"_".join(map(str, combo))}'
                        data = self._extract_lsb_combination(channel, combo)
                        if data and len(data) > 10:
                            layers[layer_name] = data
        else:
            # Grayscale image
            for bit_plane in range(8):
                layer_name = f'gray_bit_{bit_plane}'
                data = self._extract_bitplane(img_array, bit_plane)
                if data and len(data) > 10:
                    layers[layer_name] = data
        
        # Try frequency domain extraction
        freq_data = self._extract_frequency_domain(img_array)
        if freq_data:
            layers['frequency_domain'] = freq_data
        
        # Try statistical extraction
        stat_data = self._extract_statistical_patterns(img_array)
        if stat_data:
            layers['statistical_patterns'] = stat_data
        
        return layers
    
    def _extract_bitplane(self, channel: np.ndarray, bit_plane: int) -> bytes:
        """Extract data from specific bit plane"""
        try:
            # Extract bit plane
            bit_data = (channel >> bit_plane) & 1
            
            # Convert to bytes
            flat_bits = bit_data.flatten()
            
            # Group into bytes
            byte_data = bytearray()
            for i in range(0, len(flat_bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= (flat_bits[i + j] << (7 - j))
                byte_data.append(byte_val)
            
            return bytes(byte_data)
        
        except Exception as e:
            logger.warning(f"Bitplane extraction failed: {e}")
            return b''
    
    def _extract_lsb_combination(self, channel: np.ndarray, bit_positions: Tuple[int, ...]) -> bytes:
        """Extract data from combination of LSB positions"""
        try:
            combined_bits = np.zeros_like(channel, dtype=np.uint8)
            
            for i, bit_pos in enumerate(bit_positions):
                bit_data = (channel >> bit_pos) & 1
                combined_bits |= (bit_data << i)
            
            # Convert to bytes
            flat_data = combined_bits.flatten()
            return flat_data.tobytes()
        
        except Exception as e:
            logger.warning(f"LSB combination extraction failed: {e}")
            return b''
    
    def _extract_frequency_domain(self, img_array: np.ndarray) -> bytes:
        """Extract data from frequency domain"""
        try:
            # Convert to grayscale if needed
            if len(img_array.shape) == 3:
                gray = np.dot(img_array[...,:3], [0.2989, 0.5870, 0.1140])
            else:
                gray = img_array
            
            # Apply DCT
            dct_coeffs = dct(dct(gray, axis=0), axis=1)
            
            # Extract LSBs from DCT coefficients
            int_coeffs = dct_coeffs.astype(np.int32)
            lsb_data = int_coeffs & 1
            
            # Convert to bytes
            flat_data = lsb_data.flatten()
            byte_data = bytearray()
            
            for i in range(0, len(flat_data) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= (flat_data[i + j] << (7 - j))
                byte_data.append(byte_val)
            
            return bytes(byte_data)
        
        except Exception as e:
            logger.warning(f"Frequency domain extraction failed: {e}")
            return b''
    
    def _extract_statistical_patterns(self, img_array: np.ndarray) -> bytes:
        """Extract data based on statistical patterns"""
        try:
            # Look for anomalies in pixel value distributions
            flat_img = img_array.flatten()
            
            # Calculate pixel value histogram
            hist, bins = np.histogram(flat_img, bins=256, range=(0, 256))
            
            # Look for unusual patterns in histogram
            # This is a simplified approach - more sophisticated ML methods could be used
            anomalies = []
            for i in range(1, len(hist) - 1):
                if hist[i] > hist[i-1] * 2 and hist[i] > hist[i+1] * 2:
                    anomalies.append(i)
            
            if anomalies:
                # Extract pixels with anomalous values
                anomaly_data = bytearray()
                for pixel in flat_img:
                    if pixel in anomalies:
                        anomaly_data.append(pixel)
                
                return bytes(anomaly_data)
            
            return b''
        
        except Exception as e:
            logger.warning(f"Statistical pattern extraction failed: {e}")
            return b''
    
    def _combine_layer_data(self, layers: Dict[str, bytes]) -> bytes:
        """Combine data from multiple layers using various strategies"""
        try:
            # Strategy 1: Concatenate all layers
            combined = bytearray()
            for layer_name, data in layers.items():
                combined.extend(data)
            
            # Strategy 2: XOR all layers
            if len(layers) > 1:
                layer_data = list(layers.values())
                xor_result = bytearray(layer_data[0])
                
                for data in layer_data[1:]:
                    min_len = min(len(xor_result), len(data))
                    for i in range(min_len):
                        xor_result[i] ^= data[i]
                
                combined.extend(xor_result)
            
            return bytes(combined)
        
        except Exception as e:
            logger.warning(f"Layer combination failed: {e}")
            return b''
    
    def _reconstruct_hidden_files(self, data: bytes, output_dir: str) -> List[str]:
        """Try to reconstruct hidden files from extracted data"""
        reconstructed_files = []
        
        # Try different reconstruction methods
        methods = [
            self._try_direct_file_extraction,
            self._try_base64_decode,
            self._try_hex_decode,
            self._try_compression_decode,
            self._try_custom_decode
        ]
        
        for i, method in enumerate(methods):
            try:
                result_files = method(data, output_dir, i)
                reconstructed_files.extend(result_files)
            except Exception as e:
                logger.debug(f"Reconstruction method {i} failed: {e}")
        
        return reconstructed_files
    
    def _try_direct_file_extraction(self, data: bytes, output_dir: str, method_id: int) -> List[str]:
        """Try direct file signature detection"""
        files = []
        
        # Common file signatures
        signatures = {
            b'PK\x03\x04': 'zip',
            b'\x89PNG\r\n\x1a\n': 'png',
            b'\xff\xd8\xff': 'jpg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif',
            b'%PDF': 'pdf',
            b'BM': 'bmp',
        }
        
        for signature, ext in signatures.items():
            offset = data.find(signature)
            if offset != -1:
                # Extract potential file
                file_data = data[offset:]
                output_file = os.path.join(output_dir, f'extracted_{method_id}_{ext}_{offset}.{ext}')
                
                with open(output_file, 'wb') as f:
                    f.write(file_data)
                
                files.append(output_file)
        
        return files
    
    def _try_base64_decode(self, data: bytes, output_dir: str, method_id: int) -> List[str]:
        """Try base64 decoding"""
        files = []
        
        try:
            # Convert to string and try base64 decode
            text_data = data.decode('ascii', errors='ignore')
            
            # Look for base64 patterns
            import re
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(base64_pattern, text_data)
            
            for i, match in enumerate(matches[:10]):  # Limit to first 10 matches
                try:
                    decoded = base64.b64decode(match)
                    if len(decoded) > 10:  # Minimum viable file
                        output_file = os.path.join(output_dir, f'base64_decoded_{method_id}_{i}.bin')
                        with open(output_file, 'wb') as f:
                            f.write(decoded)
                        files.append(output_file)
                except:
                    continue
        
        except Exception as e:
            logger.debug(f"Base64 decode failed: {e}")
        
        return files
    
    def _try_hex_decode(self, data: bytes, output_dir: str, method_id: int) -> List[str]:
        """Try hex decoding"""
        files = []
        
        try:
            text_data = data.decode('ascii', errors='ignore')
            
            # Look for hex patterns
            import re
            hex_pattern = r'[0-9a-fA-F]{20,}'
            matches = re.findall(hex_pattern, text_data)
            
            for i, match in enumerate(matches[:10]):
                try:
                    if len(match) % 2 == 0:  # Valid hex length
                        decoded = bytes.fromhex(match)
                        if len(decoded) > 10:
                            output_file = os.path.join(output_dir, f'hex_decoded_{method_id}_{i}.bin')
                            with open(output_file, 'wb') as f:
                                f.write(decoded)
                            files.append(output_file)
                except:
                    continue
        
        except Exception as e:
            logger.debug(f"Hex decode failed: {e}")
        
        return files
    
    def _try_compression_decode(self, data: bytes, output_dir: str, method_id: int) -> List[str]:
        """Try decompression"""
        files = []
        
        # Try different compression methods
        methods = [
            ('zlib', lambda d: zlib.decompress(d)),
            ('gzip', lambda d: zlib.decompress(d, 16 + zlib.MAX_WBITS)),
        ]
        
        for comp_name, decompress_func in methods:
            try:
                decompressed = decompress_func(data)
                if len(decompressed) > len(data):  # Successful decompression usually expands
                    output_file = os.path.join(output_dir, f'{comp_name}_decompressed_{method_id}.bin')
                    with open(output_file, 'wb') as f:
                        f.write(decompressed)
                    files.append(output_file)
            except:
                continue
        
        return files
    
    def _try_custom_decode(self, data: bytes, output_dir: str, method_id: int) -> List[str]:
        """Try custom decoding algorithms"""
        files = []
        
        # XOR with common keys
        xor_keys = [0x42, 0x00, 0xFF, 0xAA, 0x55]
        
        for key in xor_keys:
            try:
                xor_data = bytes(b ^ key for b in data)
                output_file = os.path.join(output_dir, f'xor_decoded_{method_id}_{key:02x}.bin')
                with open(output_file, 'wb') as f:
                    f.write(xor_data)
                files.append(output_file)
            except:
                continue
        
        # Reverse bytes
        try:
            reversed_data = data[::-1]
            output_file = os.path.join(output_dir, f'reversed_{method_id}.bin')
            with open(output_file, 'wb') as f:
                f.write(reversed_data)
            files.append(output_file)
        except:
            pass
        
        return files

class FrequencyDomainAnalyzer(BaseExtractor):
    """Advanced frequency domain steganography analysis"""
    
    def _get_tool_name(self):
        return 'frequency_domain_analyzer'
    
    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """Analyze frequency domain for hidden data"""
        if not HAS_ADVANCED_LIBS:
            return {'success': False, 'error': 'Advanced libraries not available'}
        
        results = {
            'success': False,
            'data': b'',
            'details': 'Frequency domain analysis failed',
            'command_line': f'frequency_analyzer {file_path}',
            'confidence': 0,
            'extracted_files': []
        }
        
        try:
            output_dir = tempfile.mkdtemp(prefix='freq_analysis_')
            
            # Load and process image
            img = Image.open(file_path)
            img_array = np.array(img)
            
            # Perform different frequency domain analyses
            analyses = [
                ('dct', self._analyze_dct),
                ('dwt', self._analyze_dwt),
                ('fft', self._analyze_fft),
                ('jpeg_qtables', self._analyze_jpeg_qtables)
            ]
            
            extracted_files = []
            
            for analysis_name, analysis_func in analyses:
                try:
                    analysis_results = analysis_func(img_array, output_dir, analysis_name)
                    extracted_files.extend(analysis_results)
                except Exception as e:
                    logger.warning(f"{analysis_name} analysis failed: {e}")
            
            if extracted_files:
                results['success'] = True
                results['confidence'] = 7
                results['details'] = f"Frequency domain analysis found {len(extracted_files)} potential files"
                results['extracted_files'] = extracted_files
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _analyze_dct(self, img_array: np.ndarray, output_dir: str, prefix: str) -> List[str]:
        """Analyze DCT coefficients for hidden data"""
        files = []
        
        try:
            # Convert to grayscale if needed
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Apply 2D DCT
            dct_coeffs = cv2.dct(np.float32(gray))
            
            # Analyze different frequency regions
            h, w = dct_coeffs.shape
            
            # Low frequency (top-left)
            low_freq = dct_coeffs[:h//4, :w//4]
            self._extract_from_coefficients(low_freq, output_dir, f'{prefix}_low_freq', files)
            
            # Mid frequency (diagonal band)
            mid_freq = dct_coeffs[h//4:h//2, w//4:w//2]
            self._extract_from_coefficients(mid_freq, output_dir, f'{prefix}_mid_freq', files)
            
            # High frequency (bottom-right)
            high_freq = dct_coeffs[h//2:, w//2:]
            self._extract_from_coefficients(high_freq, output_dir, f'{prefix}_high_freq', files)
        
        except Exception as e:
            logger.warning(f"DCT analysis failed: {e}")
        
        return files
    
    def _analyze_dwt(self, img_array: np.ndarray, output_dir: str, prefix: str) -> List[str]:
        """Analyze DWT coefficients for hidden data"""
        files = []
        
        try:
            import pywt
            
            # Convert to grayscale if needed
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Apply DWT
            coeffs2 = pywt.dwt2(gray, 'haar')
            cA, (cH, cV, cD) = coeffs2
            
            # Extract from different coefficient sets
            coeff_sets = [
                ('approximation', cA),
                ('horizontal', cH),
                ('vertical', cV),
                ('diagonal', cD)
            ]
            
            for coeff_name, coeffs in coeff_sets:
                self._extract_from_coefficients(coeffs, output_dir, f'{prefix}_{coeff_name}', files)
        
        except ImportError:
            logger.warning("PyWavelets not available for DWT analysis")
        except Exception as e:
            logger.warning(f"DWT analysis failed: {e}")
        
        return files
    
    def _analyze_fft(self, img_array: np.ndarray, output_dir: str, prefix: str) -> List[str]:
        """Analyze FFT spectrum for hidden data"""
        files = []
        
        try:
            # Convert to grayscale if needed
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Apply 2D FFT
            f_transform = np.fft.fft2(gray)
            f_shift = np.fft.fftshift(f_transform)
            
            # Extract magnitude and phase
            magnitude = np.abs(f_shift)
            phase = np.angle(f_shift)
            
            # Extract from magnitude and phase
            self._extract_from_coefficients(magnitude, output_dir, f'{prefix}_magnitude', files)
            self._extract_from_coefficients(phase, output_dir, f'{prefix}_phase', files)
        
        except Exception as e:
            logger.warning(f"FFT analysis failed: {e}")
        
        return files
    
    def _analyze_jpeg_qtables(self, img_array: np.ndarray, output_dir: str, prefix: str) -> List[str]:
        """Analyze JPEG quantization tables"""
        files = []
        
        try:
            # This requires access to JPEG file directly
            # Simplified implementation - real version would parse JPEG headers
            
            # Extract quantization patterns from DCT blocks
            if len(img_array.shape) == 3:
                gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
            else:
                gray = img_array
            
            # Divide into 8x8 blocks and analyze DCT
            h, w = gray.shape
            block_size = 8
            
            qtable_data = bytearray()
            
            for i in range(0, h - block_size, block_size):
                for j in range(0, w - block_size, block_size):
                    block = gray[i:i+block_size, j:j+block_size]
                    dct_block = cv2.dct(np.float32(block))
                    
                    # Extract LSBs from quantized coefficients
                    quantized = np.round(dct_block).astype(np.int32)
                    lsbs = quantized & 1
                    
                    # Convert block to bytes
                    qtable_data.extend(lsbs.flatten().astype(np.uint8))
            
            if qtable_data:
                output_file = os.path.join(output_dir, f'{prefix}_qtable.bin')
                with open(output_file, 'wb') as f:
                    f.write(qtable_data)
                files.append(output_file)
        
        except Exception as e:
            logger.warning(f"JPEG quantization table analysis failed: {e}")
        
        return files
    
    def _extract_from_coefficients(self, coeffs: np.ndarray, output_dir: str, filename: str, files: List[str]):
        """Extract data from frequency coefficients"""
        try:
            # Convert coefficients to integers and extract LSBs
            int_coeffs = coeffs.astype(np.int32)
            lsb_data = int_coeffs & 1
            
            # Convert to bytes
            flat_data = lsb_data.flatten()
            byte_data = bytearray()
            
            for i in range(0, len(flat_data) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= (flat_data[i + j] << (7 - j))
                byte_data.append(byte_val)
            
            if len(byte_data) > 10:  # Minimum viable data
                output_file = os.path.join(output_dir, f'{filename}.bin')
                with open(output_file, 'wb') as f:
                    f.write(byte_data)
                files.append(output_file)
        
        except Exception as e:
            logger.debug(f"Coefficient extraction failed for {filename}: {e}")

class PNGChunkAnalyzer(BaseExtractor):
    """Analyze PNG chunks for hidden data"""
    
    def _get_tool_name(self):
        return 'png_chunk_analyzer'
    
    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """Analyze PNG chunks for steganographic content"""
        results = {
            'success': False,
            'data': b'',
            'details': 'PNG chunk analysis failed',
            'command_line': f'png_chunk_analyzer {file_path}',
            'confidence': 0,
            'extracted_files': [],
            'chunks_found': []
        }
        
        try:
            output_dir = tempfile.mkdtemp(prefix='png_chunks_')
            
            with open(file_path, 'rb') as f:
                # Verify PNG signature
                signature = f.read(8)
                if signature != b'\x89PNG\r\n\x1a\n':
                    results['error'] = 'Not a valid PNG file'
                    return results
                
                chunks = []
                extracted_files = []
                
                # Parse PNG chunks
                while True:
                    chunk_data = self._read_png_chunk(f)
                    if not chunk_data:
                        break
                    
                    length, chunk_type, data, crc = chunk_data
                    chunks.append({
                        'type': chunk_type.decode('ascii', errors='ignore'),
                        'length': length,
                        'data_preview': data[:100].hex() if data else '',
                        'crc': crc
                    })
                    
                    # Extract chunk data
                    if data and len(data) > 0:
                        chunk_file = os.path.join(output_dir, f'chunk_{chunk_type.decode("ascii", errors="ignore")}_{len(extracted_files)}.bin')
                        with open(chunk_file, 'wb') as cf:
                            cf.write(data)
                        extracted_files.append(chunk_file)
                    
                    # Check for custom/unknown chunks
                    if chunk_type not in [b'IHDR', b'PLTE', b'IDAT', b'IEND', b'gAMA', b'cHRM', b'sRGB', b'tEXt', b'zTXt', b'iTXt']:
                        logger.info(f"Found custom PNG chunk: {chunk_type}")
                    
                    # Stop at IEND
                    if chunk_type == b'IEND':
                        break
                
                # Analyze IDAT chunks for steganography
                idat_files = self._analyze_idat_chunks(file_path, output_dir)
                extracted_files.extend(idat_files)
                
                # Look for data after IEND
                trailing_data = f.read()
                if trailing_data:
                    trailing_file = os.path.join(output_dir, 'trailing_data.bin')
                    with open(trailing_file, 'wb') as tf:
                        tf.write(trailing_data)
                    extracted_files.append(trailing_file)
                
                if extracted_files:
                    results['success'] = True
                    results['confidence'] = 6
                    results['details'] = f"PNG analysis found {len(chunks)} chunks and extracted {len(extracted_files)} files"
                    results['extracted_files'] = extracted_files
                    results['chunks_found'] = chunks
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _read_png_chunk(self, f) -> Optional[Tuple[int, bytes, bytes, int]]:
        """Read a PNG chunk from file"""
        try:
            # Read chunk length
            length_data = f.read(4)
            if len(length_data) != 4:
                return None
            
            length = struct.unpack('>I', length_data)[0]
            
            # Read chunk type
            chunk_type = f.read(4)
            if len(chunk_type) != 4:
                return None
            
            # Read chunk data
            data = f.read(length) if length > 0 else b''
            
            # Read CRC
            crc_data = f.read(4)
            if len(crc_data) != 4:
                return None
            
            crc = struct.unpack('>I', crc_data)[0]
            
            return length, chunk_type, data, crc
        
        except Exception as e:
            logger.warning(f"Failed to read PNG chunk: {e}")
            return None
    
    def _analyze_idat_chunks(self, file_path: str, output_dir: str) -> List[str]:
        """Analyze IDAT chunks for hidden data"""
        extracted_files = []
        
        try:
            # Use PIL to decompress IDAT data
            img = Image.open(file_path)
            
            # Try to access raw image data
            if hasattr(img, 'im') and hasattr(img.im, 'getpalette'):
                # Analyze palette for hidden data
                palette = img.im.getpalette()
                if palette:
                    palette_file = os.path.join(output_dir, 'palette_data.bin')
                    with open(palette_file, 'wb') as pf:
                        pf.write(palette)
                    extracted_files.append(palette_file)
            
            # Analyze for LSB steganography in uncompressed data
            img_array = np.array(img)
            lsb_file = os.path.join(output_dir, 'idat_lsb_analysis.bin')
            
            # Extract LSBs from all channels
            lsb_data = bytearray()
            if len(img_array.shape) == 3:
                for channel in range(img_array.shape[2]):
                    channel_data = img_array[:, :, channel]
                    lsbs = channel_data & 1
                    lsb_data.extend(lsbs.flatten())
            else:
                lsbs = img_array & 1
                lsb_data.extend(lsbs.flatten())
            
            if lsb_data:
                with open(lsb_file, 'wb') as lf:
                    lf.write(lsb_data)
                extracted_files.append(lsb_file)
        
        except Exception as e:
            logger.warning(f"IDAT analysis failed: {e}")
        
        return extracted_files

class PolyglotFileDetector(BaseExtractor):
    """Detect and analyze polyglot files (files valid as multiple formats)"""
    
    def _get_tool_name(self):
        return 'polyglot_detector'
    
    def extract(self, file_path: str, parameters: Dict = None) -> Dict[str, Any]:
        """Detect polyglot file structures"""
        results = {
            'success': False,
            'data': b'',
            'details': 'Polyglot detection failed',
            'command_line': f'polyglot_detector {file_path}',
            'confidence': 0,
            'extracted_files': [],
            'formats_detected': []
        }
        
        try:
            output_dir = tempfile.mkdtemp(prefix='polyglot_')
            
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for multiple file signatures
            signatures = self._detect_file_signatures(content)
            
            if len(signatures) > 1:
                # Potential polyglot file
                logger.info(f"Polyglot file detected with formats: {[s['format'] for s in signatures]}")
                
                extracted_files = []
                
                # Extract each format
                for i, sig in enumerate(signatures):
                    try:
                        format_data = content[sig['offset']:]
                        format_file = os.path.join(output_dir, f'format_{i}_{sig["format"]}.{sig["ext"]}')
                        
                        with open(format_file, 'wb') as ff:
                            ff.write(format_data)
                        
                        extracted_files.append(format_file)
                    except Exception as e:
                        logger.warning(f"Failed to extract format {sig['format']}: {e}")
                
                # Look for embedded data between formats
                overlays = self._find_overlay_data(content, signatures)
                for i, overlay in enumerate(overlays):
                    overlay_file = os.path.join(output_dir, f'overlay_{i}.bin')
                    with open(overlay_file, 'wb') as of:
                        of.write(overlay)
                    extracted_files.append(overlay_file)
                
                if extracted_files:
                    results['success'] = True
                    results['confidence'] = 8
                    results['details'] = f"Polyglot file with {len(signatures)} formats detected"
                    results['extracted_files'] = extracted_files
                    results['formats_detected'] = [s['format'] for s in signatures]
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _detect_file_signatures(self, content: bytes) -> List[Dict[str, Any]]:
        """Detect file format signatures in content"""
        signatures = []
        
        # File signature database
        sig_db = [
            {'signature': b'PK\x03\x04', 'format': 'ZIP', 'ext': 'zip'},
            {'signature': b'\x89PNG\r\n\x1a\n', 'format': 'PNG', 'ext': 'png'},
            {'signature': b'\xff\xd8\xff', 'format': 'JPEG', 'ext': 'jpg'},
            {'signature': b'GIF87a', 'format': 'GIF87a', 'ext': 'gif'},
            {'signature': b'GIF89a', 'format': 'GIF89a', 'ext': 'gif'},
            {'signature': b'%PDF', 'format': 'PDF', 'ext': 'pdf'},
            {'signature': b'BM', 'format': 'BMP', 'ext': 'bmp'},
            {'signature': b'RIFF', 'format': 'RIFF', 'ext': 'wav'},
            {'signature': b'\x7fELF', 'format': 'ELF', 'ext': 'elf'},
            {'signature': b'MZ', 'format': 'PE', 'ext': 'exe'},
            {'signature': b'Rar!', 'format': 'RAR', 'ext': 'rar'},
            {'signature': b'7z\xbc\xaf\x27\x1c', 'format': '7Z', 'ext': '7z'},
        ]
        
        # Search for signatures
        for sig_info in sig_db:
            signature = sig_info['signature']
            offset = 0
            
            while True:
                pos = content.find(signature, offset)
                if pos == -1:
                    break
                
                signatures.append({
                    'offset': pos,
                    'format': sig_info['format'],
                    'ext': sig_info['ext'],
                    'signature': signature
                })
                
                offset = pos + 1
        
        # Sort by offset
        signatures.sort(key=lambda x: x['offset'])
        
        return signatures
    
    def _find_overlay_data(self, content: bytes, signatures: List[Dict[str, Any]]) -> List[bytes]:
        """Find data between different file format sections"""
        overlays = []
        
        if len(signatures) < 2:
            return overlays
        
        # Find gaps between signatures
        for i in range(len(signatures) - 1):
            start_pos = signatures[i]['offset'] + len(signatures[i]['signature'])
            end_pos = signatures[i + 1]['offset']
            
            if end_pos > start_pos:
                gap_data = content[start_pos:end_pos]
                
                # Only include significant gaps (more than just padding)
                if len(gap_data) > 10 and not all(b == 0 for b in gap_data):
                    overlays.append(gap_data)
        
        return overlays

# Register all advanced steganography extractors
def register_advanced_stegano_extractors():
    """Register advanced steganography extractors"""
    from crypto_hunter_web.services.extractors import EXTRACTORS
    
    advanced_extractors = {
        'multilayer_stegano': MultiLayerSteganographyExtractor,
        'frequency_domain_analyzer': FrequencyDomainAnalyzer,
        'png_chunk_analyzer': PNGChunkAnalyzer,
        'polyglot_detector': PolyglotFileDetector,
    }
    
    EXTRACTORS.update(advanced_extractors)
    
    logger.info(f"Registered {len(advanced_extractors)} advanced steganography extractors")
    
    return advanced_extractors

# Enhanced recommendations for steganographic files
def get_advanced_stegano_recommendations(file_path: str, file_type: str) -> List[str]:
    """Get advanced steganography extraction recommendations"""
    
    recommendations = []
    
    # Always include multilayer analysis for images
    if file_type.startswith('image/'):
        recommendations.extend([
            'multilayer_stegano',
            'frequency_domain_analyzer',
        ])
        
        # PNG-specific analysis
        if file_type == 'image/png':
            recommendations.append('png_chunk_analyzer')
    
    # Always check for polyglot files
    recommendations.append('polyglot_detector')
    
    # Add basic steganography tools
    if file_type.startswith('image/'):
        if file_type == 'image/png':
            recommendations.extend(['zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2'])
        elif file_type == 'image/jpeg':
            recommendations.extend(['steghide', 'stegseek', 'outguess'])
    
    # Add binary analysis for potential embedded files
    recommendations.extend(['binwalk', 'foremost', 'strings'])
    
    return recommendations

if __name__ == '__main__':
    # Test the advanced steganography system
    register_advanced_stegano_extractors()
    
    print("Advanced steganography extractors registered:")
    from crypto_hunter_web.services.extractors import EXTRACTORS
    
    for name in sorted(EXTRACTORS.keys()):
        if any(keyword in name for keyword in ['multilayer', 'frequency', 'png_chunk', 'polyglot']):
            print(f"  - {name}")
    
    # Example usage
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        if os.path.exists(test_file):
            extractor = MultiLayerSteganographyExtractor('multilayer_test')
            result = extractor.extract(test_file)
            print(f"Test result: {result['success']}, files: {len(result.get('extracted_files', []))}")

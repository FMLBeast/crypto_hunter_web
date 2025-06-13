"""
Advanced steganography extractors for XOR bitplanes, combined bitplanes, and DCT extraction
"""

import os
import re
import numpy as np
from PIL import Image
import cv2
from scipy.fftpack import dct, idct
from .base import BaseExtractor

class XORBitplanesExtractor(BaseExtractor):
    """Extractor for XOR operations between bitplanes"""
    
    def _get_tool_name(self):
        return 'xor_bitplanes'
    
    def extract(self, file_path, parameters=None):
        """Extract using XOR between bitplanes"""
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
            # Load image
            img = Image.open(file_path)
            img_array = np.array(img)
            
            # Get parameters
            params = parameters or {}
            bitplane1 = params.get('bitplane1', 1)
            bitplane2 = params.get('bitplane2', 2)
            channel = params.get('channel', 'r')
            
            # Extract bitplanes
            extracted_data = self._extract_xor_bitplanes(img_array, bitplane1, bitplane2, channel)
            
            command_line = f"xor_bitplanes {file_path} --bitplane1 {bitplane1} --bitplane2 {bitplane2} --channel {channel}"
            
            return {
                'success': True,
                'data': extracted_data,
                'error': '',
                'details': f"XOR bitplanes extraction successful, found {len(extracted_data)} bytes",
                'command_line': command_line,
                'confidence': 5,
                'metadata': {
                    'bitplane1': bitplane1,
                    'bitplane2': bitplane2,
                    'channel': channel
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'XOR bitplanes extraction failed',
                'command_line': '',
                'confidence': 0
            }
    
    def _extract_xor_bitplanes(self, img_array, bitplane1, bitplane2, channel):
        """Extract data by XORing two bitplanes"""
        # Get channel index
        channel_idx = {'r': 0, 'g': 1, 'b': 2, 'a': 3}.get(channel.lower(), 0)
        
        # Check if image has enough channels
        if len(img_array.shape) < 3 or img_array.shape[2] <= channel_idx:
            # Grayscale image or not enough channels
            channel_data = img_array
        else:
            # Get specific channel
            channel_data = img_array[:, :, channel_idx]
        
        # Extract bitplanes
        bitplane1_data = (channel_data >> (bitplane1 - 1)) & 1
        bitplane2_data = (channel_data >> (bitplane2 - 1)) & 1
        
        # XOR the bitplanes
        xor_result = np.bitwise_xor(bitplane1_data, bitplane2_data)
        
        # Convert to bytes
        bits = xor_result.flatten()
        bytes_data = bytearray()
        
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                bytes_data.append(byte)
        
        return bytes(bytes_data)


class CombinedBitplanesExtractor(BaseExtractor):
    """Extractor for combining multiple bitplanes"""
    
    def _get_tool_name(self):
        return 'combined_bitplanes'
    
    def extract(self, file_path, parameters=None):
        """Extract by combining multiple bitplanes"""
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
            # Load image
            img = Image.open(file_path)
            img_array = np.array(img)
            
            # Get parameters
            params = parameters or {}
            bitplanes = params.get('bitplanes', [1, 2, 3])
            channel = params.get('channel', 'r')
            combine_method = params.get('combine_method', 'concat')
            
            # Extract combined bitplanes
            extracted_data = self._extract_combined_bitplanes(img_array, bitplanes, channel, combine_method)
            
            command_line = f"combined_bitplanes {file_path} --bitplanes {','.join(map(str, bitplanes))} --channel {channel} --method {combine_method}"
            
            return {
                'success': True,
                'data': extracted_data,
                'error': '',
                'details': f"Combined bitplanes extraction successful, found {len(extracted_data)} bytes",
                'command_line': command_line,
                'confidence': 5,
                'metadata': {
                    'bitplanes': bitplanes,
                    'channel': channel,
                    'combine_method': combine_method
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'Combined bitplanes extraction failed',
                'command_line': '',
                'confidence': 0
            }
    
    def _extract_combined_bitplanes(self, img_array, bitplanes, channel, combine_method):
        """Extract data by combining multiple bitplanes"""
        # Get channel index
        channel_idx = {'r': 0, 'g': 1, 'b': 2, 'a': 3}.get(channel.lower(), 0)
        
        # Check if image has enough channels
        if len(img_array.shape) < 3 or img_array.shape[2] <= channel_idx:
            # Grayscale image or not enough channels
            channel_data = img_array
        else:
            # Get specific channel
            channel_data = img_array[:, :, channel_idx]
        
        # Extract bitplanes
        extracted_bitplanes = []
        for bp in bitplanes:
            bitplane_data = (channel_data >> (bp - 1)) & 1
            extracted_bitplanes.append(bitplane_data)
        
        # Combine bitplanes based on method
        if combine_method == 'concat':
            # Concatenate bitplanes
            combined_bits = np.concatenate([bp.flatten() for bp in extracted_bitplanes])
        elif combine_method == 'interleave':
            # Interleave bitplanes
            combined_bits = np.zeros(len(extracted_bitplanes) * len(extracted_bitplanes[0].flatten()), dtype=np.uint8)
            for i, bp in enumerate(extracted_bitplanes):
                combined_bits[i::len(extracted_bitplanes)] = bp.flatten()
        else:  # Default to OR
            # Bitwise OR of bitplanes
            combined_data = extracted_bitplanes[0]
            for bp in extracted_bitplanes[1:]:
                combined_data = np.bitwise_or(combined_data, bp)
            combined_bits = combined_data.flatten()
        
        # Convert to bytes
        bytes_data = bytearray()
        for i in range(0, len(combined_bits), 8):
            if i + 8 <= len(combined_bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | combined_bits[i + j]
                bytes_data.append(byte)
        
        return bytes(bytes_data)


class DCTExtractor(BaseExtractor):
    """Extractor for DCT-based steganography"""
    
    def _get_tool_name(self):
        return 'dct_extract'
    
    def extract(self, file_path, parameters=None):
        """Extract using DCT coefficients"""
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
            # Load image
            img = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
            if img is None:
                return {
                    'success': False,
                    'error': 'Failed to load image',
                    'data': b'',
                    'details': 'DCT extraction failed - could not load image',
                    'command_line': '',
                    'confidence': 0
                }
            
            # Get parameters
            params = parameters or {}
            block_size = params.get('block_size', 8)
            coefficient = params.get('coefficient', 'lsb')
            
            # Extract DCT coefficients
            extracted_data = self._extract_dct(img, block_size, coefficient)
            
            command_line = f"dct_extract {file_path} --block_size {block_size} --coefficient {coefficient}"
            
            return {
                'success': True,
                'data': extracted_data,
                'error': '',
                'details': f"DCT extraction successful, found {len(extracted_data)} bytes",
                'command_line': command_line,
                'confidence': 6,
                'metadata': {
                    'block_size': block_size,
                    'coefficient': coefficient
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': b'',
                'details': 'DCT extraction failed',
                'command_line': '',
                'confidence': 0
            }
    
    def _extract_dct(self, img, block_size, coefficient):
        """Extract data from DCT coefficients"""
        height, width = img.shape
        
        # Ensure dimensions are multiples of block_size
        img = img[:height - (height % block_size), :width - (width % block_size)]
        height, width = img.shape
        
        # Number of blocks
        num_blocks_h = height // block_size
        num_blocks_w = width // block_size
        
        # Extract bits from DCT coefficients
        bits = []
        
        for i in range(num_blocks_h):
            for j in range(num_blocks_w):
                # Extract block
                block = img[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size]
                
                # Apply DCT
                dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')
                
                # Extract bit based on coefficient
                if coefficient == 'lsb':
                    # LSB of DC coefficient
                    bit = int(abs(dct_block[0, 0]) % 2)
                elif coefficient == 'msb':
                    # MSB of DC coefficient
                    bit = int(abs(dct_block[0, 0]) > 128)
                elif coefficient == 'mid':
                    # Middle frequency coefficient
                    bit = int(abs(dct_block[4, 4]) % 2)
                else:  # Default to AC coefficient
                    # First AC coefficient
                    bit = int(abs(dct_block[0, 1]) % 2)
                
                bits.append(bit)
        
        # Convert bits to bytes
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                bytes_data.append(byte)
        
        return bytes(bytes_data)
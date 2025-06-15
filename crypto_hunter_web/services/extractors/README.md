# Cryptographic Extractors

This directory contains extractors for various cryptographic operations, including XOR and AES decryption.

## XOR Decryption

The `XORDecryptExtractor` allows you to decrypt data that has been XOR encrypted. XOR is a symmetric operation, meaning the same operation is used for both encryption and decryption.

### Usage

```python
from crypto_hunter_web.services.extractors import get_extractor

# Get the XOR decryption extractor
extractor = get_extractor("xor_decrypt")

# Decrypt a file with a specific key
result = extractor.extract("path/to/encrypted/file", {"key": "your_key"})

if result['success']:
    decrypted_data = result['data']
    print(f"Decrypted data: {decrypted_data}")
else:
    print(f"Decryption failed: {result.get('error', 'unknown error')}")
```

### Parameters

- `key`: The key to use for XOR decryption. Can be a string or bytes.
- `output_file`: Optional path to save the decrypted data.

## AES Decryption

The `AESDecryptExtractor` allows you to decrypt data that has been AES encrypted. It uses the passphrase 'Bodhi tree blossom' by default, as specified in the requirements.

### Usage

```python
from crypto_hunter_web.services.extractors import get_extractor

# Get the AES decryption extractor
extractor = get_extractor("aes_decrypt")

# Decrypt a file with the default passphrase ('Bodhi tree blossom')
result = extractor.extract("path/to/encrypted/file")

# Or decrypt with a custom passphrase and mode
result = extractor.extract("path/to/encrypted/file", {
    "passphrase": "custom_passphrase",
    "mode": "CBC"  # or "ECB"
})

if result['success']:
    decrypted_data = result['data']
    print(f"Decrypted data: {decrypted_data}")
else:
    print(f"Decryption failed: {result.get('error', 'unknown error')}")
```

### Parameters

- `passphrase`: The passphrase to use for AES decryption. Default is 'Bodhi tree blossom'.
- `mode`: AES mode to use. Can be 'CBC' or 'ECB'. Default is 'CBC'.
- `iv`: Initialization vector for CBC mode. Optional. If not provided, the first 16 bytes of the SHA-256 hash of the passphrase will be used.
- `output_file`: Optional path to save the decrypted data.

## Requirements

- For AES decryption, the `pycryptodome` library must be installed:

```bash
pip install pycryptodome
```

## Integration with Extraction Workflow

These extractors are integrated into the extraction workflow and can be used with the standard extraction API. They are automatically recommended for appropriate file types.
"""
Crypto analysis API routes
"""

from flask import Blueprint, request, jsonify
from crypto_hunter_web.services.auth_service import AuthService
from crypto_hunter_web.services.crypto_intelligence import CryptoIntelligence, EthereumAnalyzer, CipherAnalyzer
from crypto_hunter_web.utils.decorators import rate_limit
from crypto_hunter_web.utils.validators import validate_sha256

crypto_api_bp = Blueprint('crypto_api', __name__)


@crypto_api_bp.route('/crypto/analyze/<sha>')
@AuthService.login_required
@rate_limit(max_requests=50, window_seconds=300)
def analyze_file_crypto(sha):
    """Analyze file for cryptographic content"""
    if not validate_sha256(sha):
        return jsonify({'error': 'Invalid SHA256'}), 400

    from crypto_hunter_web import AnalysisFile
    file = AnalysisFile.query.filter_by(sha256_hash=sha).first()

    if not file or not os.path.exists(file.filepath):
        return jsonify({'error': 'File not found'}), 404

    try:
        with open(file.filepath, 'rb') as f:
            content = f.read()

        analysis = CryptoIntelligence.analyze_crypto_content(content, file.filename)

        return jsonify({
            'success': True,
            'file': {
                'filename': file.filename,
                'sha256_hash': file.sha256_hash
            },
            'analysis': analysis
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@crypto_api_bp.route('/crypto/ethereum/validate', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=100, window_seconds=300)
def validate_ethereum_key():
    """Validate Ethereum private key and generate address"""
    data = request.json
    private_key = data.get('private_key', '').strip()

    if not private_key:
        return jsonify({'error': 'Private key required'}), 400

    validation = EthereumAnalyzer.validate_private_key(private_key)

    return jsonify({
        'success': True,
        'validation': validation
    })


@crypto_api_bp.route('/crypto/ethereum/balance/<address>')
@AuthService.login_required
@rate_limit(max_requests=50, window_seconds=300)
def check_ethereum_balance(address):
    """Check Ethereum address balance"""
    api_key = request.args.get('api_key', '')

    if not EthereumAnalyzer.validate_address(address):
        return jsonify({'error': 'Invalid Ethereum address'}), 400

    balance_info = EthereumAnalyzer.check_balance(address, api_key)

    return jsonify({
        'success': True,
        'balance_info': balance_info
    })


@crypto_api_bp.route('/crypto/ethereum/vanity', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=10, window_seconds=3600)
def generate_vanity_address():
    """Generate vanity Ethereum address"""
    data = request.json
    prefix = data.get('prefix', '').strip()
    max_attempts = min(data.get('max_attempts', 100000), 1000000)

    if not prefix or len(prefix) > 8:
        return jsonify({'error': 'Prefix must be 1-8 characters'}), 400

    result = EthereumAnalyzer.generate_vanity_address(prefix, max_attempts)

    return jsonify({
        'success': True,
        'result': result
    })


@crypto_api_bp.route('/crypto/cipher/analyze', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=100, window_seconds=300)
def analyze_cipher():
    """Analyze text for classical ciphers"""
    data = request.json
    text = data.get('text', '').strip()
    cipher_type = data.get('cipher_type', 'auto')

    if not text:
        return jsonify({'error': 'Text required'}), 400

    results = {}

    if cipher_type in ['auto', 'caesar']:
        results['caesar'] = CipherAnalyzer.analyze_caesar_cipher(text)

    if cipher_type in ['auto', 'substitution']:
        results['substitution'] = CipherAnalyzer.analyze_substitution_cipher(text)

    if cipher_type in ['auto', 'vigenere']:
        results['vigenere'] = CipherAnalyzer.analyze_vigenere_cipher(text)

    return jsonify({
        'success': True,
        'analysis': results
    })


@crypto_api_bp.route('/crypto/hash/crack', methods=['POST'])
@AuthService.login_required
@rate_limit(max_requests=20, window_seconds=300)
def crack_hash():
    """Attempt to crack hash with wordlist"""
    data = request.json
    target_hash = data.get('hash', '').strip()
    hash_type = data.get('type', 'md5').lower()
    custom_wordlist = data.get('wordlist', [])

    if not target_hash:
        return jsonify({'error': 'Hash required'}), 400

    from crypto_hunter_web.services.crypto_intelligence import AdvancedCryptoAnalyzer
    result = AdvancedCryptoAnalyzer.brute_force_hash(target_hash, hash_type, custom_wordlist)

    return jsonify({
        'success': True,
        'result': result
    })
"""
LLM-orchestrated cryptographic analysis with cost management
"""

import openai
import anthropic
import json
import time
import os
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import tiktoken
from crypto_hunter_web.models import db
from crypto_hunter_web.models import AnalysisFile, FileContent
from crypto_hunter_web.models import Finding, Vector
from crypto_hunter_web.services.celery_app import celery_app


class LLMProvider(Enum):
    OPENAI_GPT4 = "gpt-4-turbo-preview"
    OPENAI_GPT35 = "gpt-3.5-turbo"
    ANTHROPIC_CLAUDE = "claude-3-opus-20240229"
    ANTHROPIC_SONNET = "claude-3-sonnet-20240229"


@dataclass
class LLMCost:
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: datetime


@dataclass
class AnalysisStrategy:
    priority: int
    estimated_cost: float
    expected_value: float
    provider: LLMProvider
    analysis_type: str
    prompt_template: str


class CostManager:
    """Manages LLM API costs and budgets"""

    # Cost per 1K tokens (USD) - Update these with current pricing
    COSTS = {
        LLMProvider.OPENAI_GPT4: {"input": 0.03, "output": 0.06},
        LLMProvider.OPENAI_GPT35: {"input": 0.0015, "output": 0.002},
        LLMProvider.ANTHROPIC_CLAUDE: {"input": 0.015, "output": 0.075},
        LLMProvider.ANTHROPIC_SONNET: {"input": 0.003, "output": 0.015}
    }

    def __init__(self, daily_budget: float = 50.0, hourly_budget: float = 10.0):
        self.daily_budget = daily_budget
        self.hourly_budget = hourly_budget
        self.costs_cache = []

    def estimate_cost(self, provider: LLMProvider, input_text: str, estimated_output: int = 500) -> float:
        """Estimate cost for LLM call"""
        encoding = tiktoken.encoding_for_model(provider.value.replace("claude-", "gpt-4"))
        input_tokens = len(encoding.encode(input_text))

        cost_per_1k = self.COSTS[provider]
        input_cost = (input_tokens / 1000) * cost_per_1k["input"]
        output_cost = (estimated_output / 1000) * cost_per_1k["output"]

        return input_cost + output_cost

    def check_budget(self, estimated_cost: float) -> Tuple[bool, str]:
        """Check if we can afford this operation"""
        current_time = datetime.utcnow()

        # Check hourly budget
        hourly_costs = sum(
            cost.cost_usd for cost in self.costs_cache
            if cost.timestamp > current_time - timedelta(hours=1)
        )

        if hourly_costs + estimated_cost > self.hourly_budget:
            return False, f"Hourly budget exceeded: ${hourly_costs:.3f} + ${estimated_cost:.3f} > ${self.hourly_budget}"

        # Check daily budget
        daily_costs = sum(
            cost.cost_usd for cost in self.costs_cache
            if cost.timestamp > current_time - timedelta(days=1)
        )

        if daily_costs + estimated_cost > self.daily_budget:
            return False, f"Daily budget exceeded: ${daily_costs:.3f} + ${estimated_cost:.3f} > ${self.daily_budget}"

        return True, "Budget OK"

    def record_cost(self, provider: str, model: str, input_tokens: int, output_tokens: int, cost: float):
        """Record actual cost"""
        self.costs_cache.append(LLMCost(
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            timestamp=datetime.utcnow()
        ))

        # Store in database for persistence
        try:
            cost_record = FileContent(
                file_id=0,  # Special ID for cost tracking
                content_type='llm_cost_record',
                content_text=json.dumps({
                    'provider': provider,
                    'model': model,
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'cost_usd': cost,
                    'timestamp': datetime.utcnow().isoformat()
                }),
                created_at=datetime.utcnow()
            )
            db.session.add(cost_record)
            db.session.commit()
        except Exception as e:
            print(f"Failed to store cost record: {e}")


class LLMCryptoOrchestrator:
    """Orchestrates crypto analysis using multiple LLM providers"""

    def __init__(self):
        self.cost_manager = CostManager()

        # Initialize OpenAI client - handle both new and old API versions
        try:
            # Try to use the new OpenAI client (v1.0.0+)
            self.openai_client = openai.OpenAI()
            self.using_openai_v1 = True
        except (AttributeError, TypeError):
            # Fall back to the old API (pre-v1.0.0)
            # Make sure API key is set
            if not openai.api_key and os.environ.get("OPENAI_API_KEY"):
                openai.api_key = os.environ.get("OPENAI_API_KEY")
            self.openai_client = openai
            self.using_openai_v1 = False

        # Initialize Anthropic client
        try:
            # Check if proxies are configured in the environment
            proxies = {}
            if os.environ.get('HTTP_PROXY'):
                proxies['http'] = os.environ.get('HTTP_PROXY')
            if os.environ.get('HTTPS_PROXY'):
                proxies['https'] = os.environ.get('HTTPS_PROXY')

            # Initialize without proxies to avoid errors
            self.anthropic_client = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY'))
            self.anthropic_available = True
        except Exception as e:
            print(f"Warning: Anthropic client initialization failed: {e}")
            self.anthropic_client = None  # Set to None to avoid __del__ errors
            self.anthropic_available = False

        # Cache for LLM responses to avoid repeated calls
        self.response_cache = {}

    def analyze_file_with_llm(self, file_id: int, content_preview: str, existing_analysis: Dict) -> Dict[str, Any]:
        """Orchestrate LLM-guided analysis of a file"""

        # Generate content hash for caching
        content_hash = hashlib.sha256(content_preview.encode()).hexdigest()[:16]
        cache_key = f"llm_analysis_{file_id}_{content_hash}"

        if cache_key in self.response_cache:
            return self.response_cache[cache_key]

        # Determine analysis strategies based on content
        strategies = self._generate_analysis_strategies(content_preview, existing_analysis)

        results = {
            'llm_orchestrated': True,
            'strategies_considered': len(strategies),
            'analysis_results': [],
            'total_cost': 0.0,
            'providers_used': [],
            'recommendations': []
        }

        # Execute strategies in priority order within budget
        for strategy in sorted(strategies, key=lambda s: s.priority, reverse=True):
            can_afford, budget_msg = self.cost_manager.check_budget(strategy.estimated_cost)

            if not can_afford:
                results['budget_limited'] = budget_msg
                break

            try:
                analysis_result = self._execute_llm_strategy(strategy, content_preview, existing_analysis)
                results['analysis_results'].append(analysis_result)
                results['total_cost'] += analysis_result['cost']

                if strategy.provider.value not in results['providers_used']:
                    results['providers_used'].append(strategy.provider.value)

                # Early exit if high-value finding discovered
                if analysis_result.get('confidence_score', 0) > 8:
                    results['early_exit'] = 'High confidence finding discovered'
                    break

            except Exception as e:
                results['errors'] = results.get('errors', [])
                results['errors'].append(f"Strategy {strategy.analysis_type} failed: {str(e)}")

        # Generate final recommendations
        if results['analysis_results']:
            final_recommendations = self._generate_final_recommendations(results['analysis_results'])
            results['recommendations'] = final_recommendations

        # Cache successful results
        self.response_cache[cache_key] = results

        return results

    def _generate_analysis_strategies(self, content_preview: str, existing_analysis: Dict) -> List[AnalysisStrategy]:
        """Generate analysis strategies based on content characteristics"""
        strategies = []

        # Quick pattern analysis to determine strategies
        has_crypto_patterns = bool(existing_analysis.get('crypto_patterns', []))
        has_base64 = 'base64' in content_preview.lower() or any(
            p['type'] == 'base64' for p in existing_analysis.get('crypto_patterns', [])
        )
        has_ethereum = any(
            p['type'] in ['eth_private', 'eth_address']
            for p in existing_analysis.get('crypto_patterns', [])
        )
        content_length = len(content_preview)

        # Check if Anthropic is available
        anthropic_available = hasattr(self, 'anthropic_available') and self.anthropic_available

        # Strategy 1: GPT-4 for complex crypto pattern analysis (high cost, high value)
        if has_crypto_patterns and content_length > 200:
            strategies.append(AnalysisStrategy(
                priority=9,
                estimated_cost=self.cost_manager.estimate_cost(LLMProvider.OPENAI_GPT4, content_preview, 800),
                expected_value=9.0,
                provider=LLMProvider.OPENAI_GPT4,
                analysis_type="complex_crypto_pattern_analysis",
                prompt_template="crypto_pattern_expert"
            ))

        # Strategy 2: Claude for steganography and hidden message analysis (if Anthropic is available)
        if content_length > 100 and anthropic_available:
            strategies.append(AnalysisStrategy(
                priority=8,
                estimated_cost=self.cost_manager.estimate_cost(LLMProvider.ANTHROPIC_SONNET, content_preview, 600),
                expected_value=7.5,
                provider=LLMProvider.ANTHROPIC_SONNET,
                analysis_type="steganography_analysis",
                prompt_template="steganography_expert"
            ))

        # Strategy 3: GPT-3.5 for quick wins and pattern identification (low cost)
        strategies.append(AnalysisStrategy(
            priority=6,
            estimated_cost=self.cost_manager.estimate_cost(LLMProvider.OPENAI_GPT35, content_preview, 400),
            expected_value=6.0,
            provider=LLMProvider.OPENAI_GPT35,
            analysis_type="quick_pattern_scan",
            prompt_template="quick_crypto_scan"
        ))

        # Strategy 4: Claude Opus for Ethereum-specific analysis (if Ethereum patterns found and Anthropic is available)
        if has_ethereum and anthropic_available:
            strategies.append(AnalysisStrategy(
                priority=10,
                estimated_cost=self.cost_manager.estimate_cost(LLMProvider.ANTHROPIC_CLAUDE, content_preview, 700),
                expected_value=9.5,
                provider=LLMProvider.ANTHROPIC_CLAUDE,
                analysis_type="ethereum_deep_analysis",
                prompt_template="ethereum_expert"
            ))

        # Strategy 5: GPT-4 for cipher identification and breaking strategies
        if any(char.isalpha() for char in content_preview) and content_length > 50:
            strategies.append(AnalysisStrategy(
                priority=7,
                estimated_cost=self.cost_manager.estimate_cost(LLMProvider.OPENAI_GPT4, content_preview, 600),
                expected_value=7.0,
                provider=LLMProvider.OPENAI_GPT4,
                analysis_type="cipher_breaking_strategy",
                prompt_template="cipher_expert"
            ))

        return strategies

    def _execute_llm_strategy(self, strategy: AnalysisStrategy, content: str, existing_analysis: Dict) -> Dict[
        str, Any]:
        """Execute a specific LLM analysis strategy"""

        prompt = self._build_prompt(strategy.prompt_template, content, existing_analysis)

        start_time = time.time()

        if strategy.provider in [LLMProvider.OPENAI_GPT4, LLMProvider.OPENAI_GPT35]:
            response = self._call_openai(strategy.provider, prompt)
        else:
            response = self._call_anthropic(strategy.provider, prompt)

        execution_time = time.time() - start_time

        # Parse and structure the response
        parsed_response = self._parse_llm_response(response['content'], strategy.analysis_type)

        return {
            'strategy': strategy.analysis_type,
            'provider': strategy.provider.value,
            'execution_time': execution_time,
            'cost': response['cost'],
            'confidence_score': parsed_response.get('confidence', 5),
            'findings': parsed_response.get('findings', []),
            'recommendations': parsed_response.get('recommendations', []),
            'follow_up_strategies': parsed_response.get('follow_up_strategies', []),
            'raw_response': response['content']
        }

    def _call_openai(self, provider: LLMProvider, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API with cost tracking"""

        try:
            if self.using_openai_v1:
                # New OpenAI API (v1.0.0+)
                response = self.openai_client.chat.completions.create(
                    model=provider.value,
                    messages=[
                        {"role": "system",
                         "content": "You are an expert cryptographic analyst and puzzle solver specializing in CTF challenges, steganography, and blockchain analysis."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.1
                )

                usage = response.usage
                content = response.choices[0].message.content
            else:
                # Old OpenAI API (pre-v1.0.0)
                response = self.openai_client.ChatCompletion.create(
                    model=provider.value,
                    messages=[
                        {"role": "system",
                         "content": "You are an expert cryptographic analyst and puzzle solver specializing in CTF challenges, steganography, and blockchain analysis."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.1
                )

                usage = response['usage']
                content = response['choices'][0]['message']['content']

            cost = self._calculate_openai_cost(
                provider, 
                usage.prompt_tokens if self.using_openai_v1 else usage['prompt_tokens'],
                usage.completion_tokens if self.using_openai_v1 else usage['completion_tokens']
            )

            self.cost_manager.record_cost(
                provider="openai",
                model=provider.value,
                input_tokens=usage.prompt_tokens if self.using_openai_v1 else usage['prompt_tokens'],
                output_tokens=usage.completion_tokens if self.using_openai_v1 else usage['completion_tokens'],
                cost=cost
            )

            return {
                'content': content,
                'cost': cost,
                'tokens': {
                    'input': usage.prompt_tokens if self.using_openai_v1 else usage['prompt_tokens'],
                    'output': usage.completion_tokens if self.using_openai_v1 else usage['completion_tokens']
                }
            }

        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")

    def _call_anthropic(self, provider: LLMProvider, prompt: str) -> Dict[str, Any]:
        """Call Anthropic API with cost tracking"""

        # Check if Anthropic client is available
        if not hasattr(self, 'anthropic_available') or not self.anthropic_available:
            raise Exception("Anthropic client is not available")

        try:
            response = self.anthropic_client.messages.create(
                model=provider.value,
                max_tokens=1000,
                temperature=0.1,
                system="You are an expert cryptographic analyst and puzzle solver specializing in CTF challenges, steganography, and blockchain analysis.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            usage = response.usage
            cost = self._calculate_anthropic_cost(provider, usage.input_tokens, usage.output_tokens)

            self.cost_manager.record_cost(
                provider="anthropic",
                model=provider.value,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cost=cost
            )

            return {
                'content': response.content[0].text,
                'cost': cost,
                'tokens': {
                    'input': usage.input_tokens,
                    'output': usage.output_tokens
                }
            }

        except Exception as e:
            raise Exception(f"Anthropic API error: {str(e)}")

    def _calculate_openai_cost(self, provider: LLMProvider, input_tokens: int, output_tokens: int) -> float:
        """Calculate OpenAI API cost"""
        rates = self.cost_manager.COSTS[provider]
        return (input_tokens / 1000 * rates["input"]) + (output_tokens / 1000 * rates["output"])

    def _calculate_anthropic_cost(self, provider: LLMProvider, input_tokens: int, output_tokens: int) -> float:
        """Calculate Anthropic API cost"""
        rates = self.cost_manager.COSTS[provider]
        return (input_tokens / 1000 * rates["input"]) + (output_tokens / 1000 * rates["output"])

    def _build_prompt(self, template_name: str, content: str, existing_analysis: Dict) -> str:
        """Build specialized prompts for different analysis types"""

        prompts = {
            "crypto_pattern_expert": f"""
Analyze this content for advanced cryptographic patterns and hidden data. Look for:

1. Complex encoding schemes (multi-layer base64, custom encodings)
2. Steganographic patterns in text or data
3. Cryptocurrency-related information (private keys, seed phrases, wallet addresses)
4. Classical cipher patterns (substitution, transposition, polyalphabetic)
5. Modern cryptographic signatures (hashes, certificates, keys)
6. Hidden flags or puzzle solutions

Content to analyze:{content[:2000]}

Existing analysis found:
{json.dumps(existing_analysis.get('crypto_patterns', []), indent=2)}

Provide:
- Confidence score (1-10) for crypto content likelihood
- Specific patterns found with exact locations
- Recommended analysis techniques
- Priority order for follow-up analysis
- Any immediate actionable findings

Format as JSON with sections: confidence, findings, recommendations, follow_up_strategies.
""",

            "steganography_expert": f"""
Analyze this content for steganographic techniques and hidden messages:

Content:{content[:1500]}

Focus on:
1. LSB steganography indicators in data patterns
2. Text-based hiding techniques (whitespace, invisible characters)
3. Frequency analysis anomalies
4. File structure irregularities
5. Encoding layers that might hide data
6. Pattern variations that suggest hidden information

Provide specific extraction methods and tools to use.
""",

            "ethereum_expert": f"""
Deep Ethereum blockchain analysis of this content:

Content:{content[:1500]}

Ethereum patterns detected: {existing_analysis.get('ethereum_analysis', {})}

Analyze for:
1. Private key validation and security
2. Address derivation patterns
3. Smart contract interactions
4. Transaction patterns
5. Wallet seed phrase components
6. Key derivation function hints
7. Vanity address generation clues

Provide actionable steps for key recovery or address generation.
""",

            "cipher_expert": f"""
Classical and modern cipher analysis for this content:

Content:{content[:1500]}

Analyze for:
1. Caesar cipher with optimal shift detection
2. Vigenère cipher with key length analysis
3. Substitution patterns and frequency analysis
4. Modern cipher indicators (AES, RSA patterns)
5. Key derivation hints in surrounding text
6. Cipher mode indicators

Provide specific decryption approaches and parameter recommendations.
""",

            "quick_crypto_scan": f"""
Quick scan for obvious crypto patterns and immediate wins:

Content:{content[:1000]}

Look for:
1. Base64 encoded strings
2. Hex patterns
3. Hash-like strings
4. Common crypto keywords
5. Flag patterns (flag{...})
6. Simple encodings

Provide quick actionable steps and confidence scores.
"""
        }

        return prompts.get(template_name, prompts["quick_crypto_scan"])

    def _parse_llm_response(self, response: str, analysis_type: str) -> Dict[str, Any]:
        """Parse LLM response into structured data"""

        try:
            # Try to parse as JSON first
            if '{' in response and '}' in response:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                json_str = response[json_start:json_end]
                return json.loads(json_str)
        except:
            pass

        # Fallback to text parsing
        parsed = {
            'confidence': 5,
            'findings': [],
            'recommendations': [],
            'follow_up_strategies': []
        }

        # Extract confidence score
        confidence_patterns = [
            r'confidence[:\s]+(\d+)',
            r'score[:\s]+(\d+)',
            r'likelihood[:\s]+(\d+)'
        ]

        for pattern in confidence_patterns:
            import re
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                parsed['confidence'] = min(10, int(match.group(1)))
                break

        # Extract findings
        if 'finding' in response.lower() or 'pattern' in response.lower():
            lines = response.split('\n')
            for line in lines:
                if any(word in line.lower() for word in ['found', 'detected', 'pattern', 'key', 'address']):
                    parsed['findings'].append(line.strip())

        # Extract recommendations
        if 'recommend' in response.lower() or 'suggest' in response.lower():
            lines = response.split('\n')
            for line in lines:
                if any(word in line.lower() for word in ['recommend', 'suggest', 'try', 'use']):
                    parsed['recommendations'].append(line.strip())

        return parsed

    def extract_with_llm(self, file_id: int, content_preview: str, extraction_method: str, parameters: Dict) -> Dict[str, Any]:
        """Use LLM to orchestrate extraction using the specified method

        Args:
            file_id: ID of the file to extract from
            content_preview: Preview of the file content
            extraction_method: Extraction method to use
            parameters: Parameters for the extraction method

        Returns:
            Dictionary with extraction results
        """
        # Generate content hash for caching
        content_hash = hashlib.sha256(content_preview.encode()).hexdigest()[:16]
        cache_key = f"llm_extraction_{file_id}_{extraction_method}_{content_hash}"

        if cache_key in self.response_cache:
            return self.response_cache[cache_key]

        # Create extraction prompt
        extraction_prompt = self._create_extraction_prompt(content_preview, extraction_method, parameters)

        # Use GPT-4 for extraction orchestration (high value task)
        provider = LLMProvider.OPENAI_GPT4
        estimated_cost = self.cost_manager.estimate_cost(provider, extraction_prompt, 800)

        # Check budget
        can_afford, budget_msg = self.cost_manager.check_budget(estimated_cost)
        if not can_afford:
            return {
                'success': False,
                'error': f'Budget limit exceeded: {budget_msg}',
                'extraction_method': extraction_method,
                'llm_orchestrated': True
            }

        try:
            # Get LLM response
            start_time = time.time()
            response_data = self._call_openai(provider, extraction_prompt)
            response = response_data['content']
            processing_time = time.time() - start_time

            # Track cost
            actual_cost = response_data['cost']
            # Cost already recorded in _call_openai

            # Parse extraction guidance
            extraction_guidance = self._parse_extraction_guidance(response, extraction_method)

            # Get the actual extractor
            from crypto_hunter_web.services.extractors import get_extractor
            extractor = get_extractor(extraction_method)

            if not extractor:
                return {
                    'success': False,
                    'error': f'Unknown extraction method: {extraction_method}',
                    'llm_guidance': extraction_guidance,
                    'llm_orchestrated': True,
                    'cost': actual_cost
                }

            # Apply LLM-optimized parameters
            optimized_parameters = {**parameters, **extraction_guidance.get('parameters', {})}

            # Perform extraction with LLM-optimized parameters
            file = AnalysisFile.query.get(file_id)
            result = extractor.extract(file.filepath, optimized_parameters)

            # Enhance result with LLM analysis
            enhanced_result = {
                'success': result.get('success', False),
                'data': result.get('data', b''),
                'error': result.get('error', ''),
                'details': result.get('details', ''),
                'command_line': result.get('command_line', ''),
                'confidence': result.get('confidence', 0),
                'llm_orchestrated': True,
                'llm_guidance': extraction_guidance,
                'extraction_method': extraction_method,
                'optimized_parameters': optimized_parameters,
                'analysis_cost': actual_cost,
                'processing_time': processing_time,
                'provider': provider.value,
                'model_used': 'gpt-4',
                'analysis_results': [{
                    'strategy': 'llm_extraction',
                    'provider': provider.value,
                    'confidence_score': 8.5,
                    'cost': actual_cost,
                    'findings': extraction_guidance.get('findings', []),
                    'recommendations': extraction_guidance.get('recommendations', [])
                }]
            }

            # Cache successful results
            self.response_cache[cache_key] = enhanced_result

            return enhanced_result

        except Exception as e:
            return {
                'success': False,
                'error': f'LLM extraction failed: {str(e)}',
                'extraction_method': extraction_method,
                'llm_orchestrated': True
            }

    def _create_extraction_prompt(self, content_preview: str, extraction_method: str, parameters: Dict) -> str:
        """Create prompt for extraction guidance"""
        return f"""
You are an expert in digital forensics and steganography extraction. Your task is to guide the extraction process 
for a file using the '{extraction_method}' method.

File content preview:
```
{content_preview[:1500]}
```

Current extraction parameters:
```
{json.dumps(parameters, indent=2)}
```

Your task:
1. Analyze the file content preview
2. Determine optimal parameters for the '{extraction_method}' extraction method
3. Provide guidance on how to extract hidden data effectively

Respond with a JSON object containing:
- "analysis": Your analysis of the file content
- "parameters": Optimized parameters for the extraction method
- "findings": List of potential findings based on content analysis
- "recommendations": List of recommendations for further analysis
- "confidence": Confidence score (0-10) that this extraction will succeed

Only respond with valid JSON. Do not include any other text.
"""

    def _parse_extraction_guidance(self, llm_response: str, extraction_method: str) -> Dict:
        """Parse LLM response for extraction guidance"""
        try:
            # Try to parse as JSON
            guidance = json.loads(llm_response)
            return guidance
        except json.JSONDecodeError:
            # If not valid JSON, extract structured information
            guidance = {
                'analysis': 'LLM response parsing failed',
                'parameters': {},
                'findings': [],
                'recommendations': [f'Try manual extraction with {extraction_method}'],
                'confidence': 3.0
            }

            # Try to extract parameters section
            param_match = re.search(r'"parameters"\s*:\s*({[^}]+})', llm_response)
            if param_match:
                try:
                    params_str = param_match.group(1)
                    # Fix common JSON formatting issues
                    params_str = re.sub(r'(\w+):', r'"\1":', params_str)
                    params_str = params_str.replace("'", '"')
                    guidance['parameters'] = json.loads(params_str)
                except:
                    pass

            # Extract findings
            findings_match = re.search(r'"findings"\s*:\s*\[(.*?)\]', llm_response, re.DOTALL)
            if findings_match:
                findings_str = findings_match.group(1)
                guidance['findings'] = [f.strip().strip('"\'') for f in findings_str.split(',') if f.strip()]

            return guidance

    def _generate_final_recommendations(self, analysis_results: List[Dict]) -> List[str]:
        """Generate final recommendations from all analysis results"""

        recommendations = []
        high_confidence_findings = []

        for result in analysis_results:
            if result['confidence_score'] >= 7:
                high_confidence_findings.extend(result['findings'])
                recommendations.extend(result['recommendations'])

        # Deduplicate and prioritize
        unique_recommendations = list(set(recommendations))

        if high_confidence_findings:
            unique_recommendations.insert(0,
                                          f"HIGH PRIORITY: {len(high_confidence_findings)} high-confidence findings detected")

        return unique_recommendations[:10]  # Limit to top 10


# Background Tasks Integration
@celery_app.task(bind=True, max_retries=2)
def llm_orchestrated_analysis(self, file_id: int, extraction_method=None, parameters=None, provider=None, model=None, focus_areas=None, force_reanalysis=False):
    """LLM-orchestrated analysis background task

    Args:
        file_id: ID of the file to analyze
        extraction_method: Optional extraction method to use (for extraction mode)
        parameters: Optional parameters for extraction
        provider: Optional LLM provider to use
        model: Optional LLM model to use
        focus_areas: Optional focus areas for analysis
        force_reanalysis: Whether to force reanalysis
    """

    try:
        file = AnalysisFile.query.get(file_id)
        if not file or not os.path.exists(file.filepath):
            return {'error': 'File not found'}

        self.update_state(state='PROGRESS', meta={'stage': 'reading_file', 'progress': 10})

        # Read file content
        with open(file.filepath, 'rb') as f:
            content = f.read(8192)  # Read first 8KB for LLM analysis

        # Get existing analysis
        existing_content = FileContent.query.filter_by(
            file_id=file_id,
            content_type='crypto_background_complete'
        ).first()

        existing_analysis = {}
        if existing_content:
            try:
                existing_analysis = json.loads(existing_content.content_text or '{}')
            except:
                pass

        self.update_state(state='PROGRESS', meta={'stage': 'llm_analysis', 'progress': 30})

        # Initialize orchestrator
        orchestrator = LLMCryptoOrchestrator()

        # Perform LLM-guided analysis
        content_preview = content.decode('utf-8', errors='ignore')

        # If extraction_method is provided, use extraction mode
        if extraction_method:
            self.update_state(state='PROGRESS', meta={
                'stage': 'llm_extraction', 
                'progress': 40,
                'extraction_method': extraction_method
            })

            # Perform LLM-guided extraction
            llm_results = orchestrator.extract_with_llm(
                file_id, 
                content_preview, 
                extraction_method, 
                parameters or {}
            )
        else:
            # Regular analysis mode
            llm_results = orchestrator.analyze_file_with_llm(
                file_id, 
                content_preview, 
                existing_analysis,
                provider=provider,
                model=model,
                focus_areas=focus_areas
            )

        self.update_state(state='PROGRESS', meta={'stage': 'processing_results', 'progress': 80})

        # Create findings for high-confidence discoveries
        findings_created = 0
        for result in llm_results.get('analysis_results', []):
            if result.get('confidence_score', 0) >= 8:
                create_llm_finding.delay(file_id, result)
                findings_created += 1

        print(f"Queued {findings_created} high-confidence findings for creation")

        # Store LLM analysis results
        storage_success = store_llm_results(file_id, llm_results)

        if not storage_success:
            # Retry storing results if it failed
            print(f"Retrying to store LLM results for file_id: {file_id}")
            storage_success = store_llm_results(file_id, llm_results)

        self.update_state(state='PROGRESS', meta={
            'stage': 'completed', 
            'progress': 100,
            'storage_success': storage_success
        })

        return llm_results

    except Exception as exc:
        self.retry(countdown=300, exc=exc)  # Retry after 5 minutes


@celery_app.task(bind=True, max_retries=3)
def create_llm_finding(self, file_id: int, llm_result: Dict):
    """Create finding from LLM analysis result"""

    try:
        vector = Vector.query.filter_by(name='LLM Crypto Analysis').first()

        if not vector:
            vector = Vector(
                name='LLM Crypto Analysis',
                description='AI-powered cryptographic analysis',
                color='#ff6b6b',
                icon='🤖'
            )
            db.session.add(vector)
            db.session.flush()

        finding = Finding(
            file_id=file_id,
            vector_id=vector.id,
            analyst_id=1,  # System user
            title=f"LLM Discovery - {llm_result['strategy'].replace('_', ' ').title()}",
            description=f"AI analysis using {llm_result['provider']} discovered high-confidence crypto patterns",
            finding_type='llm_analysis',
            confidence_level=llm_result['confidence_score'],
            technical_details=json.dumps(llm_result, indent=2),
            extracted_data='\n'.join(llm_result.get('findings', [])),
            is_breakthrough=llm_result['confidence_score'] >= 9,
            impact_level='high' if llm_result['confidence_score'] >= 8 else 'medium',
            status='verified',
            tools_used=f"LLM: {llm_result['provider']}"
        )

        db.session.add(finding)
        db.session.commit()
        print(f"Successfully created LLM finding for file_id: {file_id}")
        return True

    except Exception as e:
        print(f"Failed to create LLM finding: {e}")
        db.session.rollback()  # Rollback the session on error

        # Retry the task with exponential backoff
        retry_count = self.request.retries
        backoff = 60 * (2 ** retry_count)  # 60s, 120s, 240s
        self.retry(countdown=backoff, exc=e)

        return False


def store_llm_results(file_id: int, results: Dict):
    """Store LLM analysis results"""

    try:
        content = FileContent(
            file_id=file_id,
            content_type='llm_analysis',  # Changed from 'llm_analysis_complete' to match valid types
            content_text=json.dumps(results, indent=2),
            content_size=len(json.dumps(results)),
            created_at=datetime.utcnow()
        )
        db.session.add(content)
        db.session.commit()
        print(f"Successfully stored LLM results for file_id: {file_id}")
        return True

    except Exception as e:
        print(f"Failed to store LLM results: {e}")
        db.session.rollback()  # Rollback the session on error
        return False

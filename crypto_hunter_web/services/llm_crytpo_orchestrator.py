# crypto_hunter_web/services/llm_crypto_orchestrator.py - COMPLETE IMPROVED VERSION

import os
import json
import time
import logging
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

# FIXED: Import the correct API libraries
import openai
import anthropic
import tiktoken

from crypto_hunter_web.models import db, AnalysisFile, FileContent
from crypto_hunter_web.utils.redis_client import redis_client

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """LLM Provider definitions with updated model names"""
    # FIXED: Updated to current model names
    OPENAI_GPT4 = "gpt-4"
    OPENAI_GPT35 = "gpt-3.5-turbo"
    ANTHROPIC_CLAUDE_3_OPUS = "claude-3-opus-20240229"
    ANTHROPIC_CLAUDE_3_SONNET = "claude-3-sonnet-20240229"


class CostManager:
    """Enhanced cost tracking and budget management"""
    
    COST_PER_1K_TOKENS = {
        LLMProvider.OPENAI_GPT4: {'input': 0.03, 'output': 0.06},
        LLMProvider.OPENAI_GPT35: {'input': 0.001, 'output': 0.002},
        LLMProvider.ANTHROPIC_CLAUDE_3_OPUS: {'input': 0.015, 'output': 0.075},
        LLMProvider.ANTHROPIC_CLAUDE_3_SONNET: {'input': 0.003, 'output': 0.015}
    }
    
    def __init__(self):
        self.costs_cache = {}
        self.daily_budget = float(os.getenv('LLM_DAILY_BUDGET', '50.0'))
        self.hourly_budget = float(os.getenv('LLM_HOURLY_BUDGET', '10.0'))
    
    def record_cost(self, provider: str, model: str, input_tokens: int, output_tokens: int, cost: float):
        """Record API usage cost"""
        timestamp = datetime.utcnow()
        cost_record = {
            'timestamp': timestamp.isoformat(),
            'provider': provider,
            'model': model,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'cost': cost
        }
        
        # Store in Redis with expiry
        key = f"llm_cost:{timestamp.strftime('%Y%m%d%H')}"
        redis_client.lpush(key, json.dumps(cost_record))
        redis_client.expire(key, 86400)  # 24 hour expiry
        
        # Update local cache
        hour_key = timestamp.strftime('%Y%m%d%H')
        if hour_key not in self.costs_cache:
            self.costs_cache[hour_key] = []
        self.costs_cache[hour_key].append(cost_record)
        
        logger.info(f"Recorded LLM cost: ${cost:.4f} for {provider}/{model}")
    
    def get_hourly_spend(self, hour: datetime = None) -> float:
        """Get spending for a specific hour"""
        if not hour:
            hour = datetime.utcnow()
        
        hour_key = hour.strftime('%Y%m%d%H')
        
        # Check cache first
        if hour_key in self.costs_cache:
            return sum(record['cost'] for record in self.costs_cache[hour_key])
        
        # Fallback to Redis
        key = f"llm_cost:{hour_key}"
        cost_records = redis_client.lrange(key, 0, -1)
        
        total = 0.0
        for record_json in cost_records:
            try:
                record = json.loads(record_json)
                total += record['cost']
            except:
                continue
        
        return total
    
    def get_daily_spend(self, date: datetime = None) -> float:
        """Get total spending for a day"""
        if not date:
            date = datetime.utcnow()
        
        total = 0.0
        for hour in range(24):
            hour_dt = date.replace(hour=hour, minute=0, second=0, microsecond=0)
            total += self.get_hourly_spend(hour_dt)
        
        return total
    
    def check_budget(self) -> Dict[str, Any]:
        """Check if we're within budget limits"""
        now = datetime.utcnow()
        hourly_spend = self.get_hourly_spend(now)
        daily_spend = self.get_daily_spend(now)
        
        return {
            'hourly_spend': hourly_spend,
            'hourly_budget': self.hourly_budget,
            'hourly_remaining': max(0, self.hourly_budget - hourly_spend),
            'hourly_exceeded': hourly_spend > self.hourly_budget,
            'daily_spend': daily_spend,
            'daily_budget': self.daily_budget,
            'daily_remaining': max(0, self.daily_budget - daily_spend),
            'daily_exceeded': daily_spend > self.daily_budget,
            'can_continue': (hourly_spend < self.hourly_budget and daily_spend < self.daily_budget)
        }


class LLMCryptoOrchestrator:
    """Enhanced LLM orchestrator with fixed API calls and improved cost management"""
    
    def __init__(self):
        self.cost_manager = CostManager()
        
        # FIXED: Set up API keys properly
        openai.api_key = os.getenv('OPENAI_API_KEY')
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        
        # Analysis strategies with improved prompts
        self.strategies = {
            'crypto_identification': {
                'prompt': """Analyze this file content for cryptographic elements. Look for:
1. Encryption algorithms and ciphers
2. Hash functions and their output
3. Key material (private keys, public keys, certificates)
4. Encoded data (Base64, hex, etc.)
5. Cryptographic protocols and implementations

Provide specific findings with confidence levels and actionable recommendations.""",
                'max_tokens': 800,
                'priority': 1
            },
            'pattern_analysis': {
                'prompt': """Examine this content for hidden patterns and relationships:
1. Steganographic content
2. XOR patterns and repeating sequences
3. Data structure patterns
4. File format anomalies
5. Embedded metadata or hidden data

Focus on actionable intelligence and specific locations within the file.""",
                'max_tokens': 600,
                'priority': 2
            },
            'vulnerability_assessment': {
                'prompt': """Assess this content for security vulnerabilities and attack vectors:
1. Weak cryptographic implementations
2. Key management issues
3. Protocol vulnerabilities
4. Implementation flaws
5. Potential exploit opportunities

Provide severity ratings and remediation suggestions.""",
                'max_tokens': 700,
                'priority': 3
            },
            'intelligence_extraction': {
                'prompt': """Extract actionable intelligence from this content:
1. Identify any flags, passwords, or secrets
2. Look for network indicators (IPs, domains, URLs)
3. Find user accounts, email addresses, or identities
4. Discover file paths, system information, or configuration data
5. Identify any CTF-specific clues or puzzle elements

Prioritize immediately actionable findings.""",
                'max_tokens': 600,
                'priority': 4
            }
        }
    
    def analyze_file_with_llm(self, file_id: int, max_cost: float = 5.0) -> Dict[str, Any]:
        """Enhanced file analysis with proper budget control and error handling"""
        try:
            # Check budget first
            budget_check = self.cost_manager.check_budget()
            if not budget_check['can_continue']:
                return {
                    'success': False,
                    'error': 'Budget exceeded',
                    'budget_status': budget_check
                }
            
            # Get file and content
            file = AnalysisFile.query.get(file_id)
            if not file:
                return {'success': False, 'error': 'File not found'}
            
            # Get file content (prefer text, fallback to binary preview)
            content = self._get_file_content_for_analysis(file_id)
            if not content:
                return {'success': False, 'error': 'No analyzable content found'}
            
            # Initialize results
            results = {
                'file_id': file_id,
                'filename': file.filename,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'strategies_completed': [],
                'total_cost': 0.0,
                'budget_limited': False,
                'provider_results': {}
            }
            
            # Select optimal provider based on file characteristics
            provider = self._select_optimal_provider(content, file)
            
            # Execute strategies in priority order
            for strategy_name, strategy_config in sorted(
                self.strategies.items(), 
                key=lambda x: x[1]['priority']
            ):
                # Check budget before each strategy
                budget_check = self.cost_manager.check_budget()
                if not budget_check['can_continue'] or results['total_cost'] >= max_cost:
                    results['budget_limited'] = True
                    break
                
                try:
                    # Execute strategy
                    strategy_result = self._execute_strategy(
                        provider, strategy_name, strategy_config, content, file
                    )
                    
                    if strategy_result['success']:
                        results['strategies_completed'].append(strategy_name)
                        results['provider_results'][strategy_name] = strategy_result
                        results['total_cost'] += strategy_result['cost']
                        
                        logger.info(f"Completed LLM strategy '{strategy_name}' for file {file_id}")
                    else:
                        logger.error(f"Strategy '{strategy_name}' failed: {strategy_result.get('error')}")
                    
                except Exception as e:
                    logger.error(f"Error executing strategy '{strategy_name}': {e}")
                    continue
            
            # Store results
            self._store_llm_results(file_id, results)
            
            results['success'] = True
            return results
            
        except Exception as e:
            logger.error(f"Error in LLM analysis for file {file_id}: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_file_content_for_analysis(self, file_id: int) -> Optional[str]:
        """Get file content optimized for LLM analysis"""
        # Try to get extracted text first
        text_content = FileContent.query.filter_by(
            file_id=file_id, content_type='extracted_text'
        ).first()
        
        if text_content and text_content.content_text:
            # Limit content size for LLM processing
            content = text_content.content_text[:8000]  # ~2K tokens max
            return content
        
        # Fallback to binary content preview
        binary_content = FileContent.query.filter_by(
            file_id=file_id, content_type='raw_binary'
        ).first()
        
        if binary_content and binary_content.content_bytes:
            try:
                # Try to decode as text
                content = binary_content.content_bytes[:4000].decode('utf-8', errors='ignore')
                return content
            except:
                # If decode fails, provide hex representation
                hex_content = binary_content.content_bytes[:2000].hex()
                return f"Binary content (hex): {hex_content}"
        
        return None
    
    def _select_optimal_provider(self, content: str, file: AnalysisFile) -> LLMProvider:
        """Select the optimal LLM provider based on content and file characteristics"""
        # Simple heuristic: use GPT-4 for complex crypto analysis, GPT-3.5 for simpler tasks
        
        crypto_indicators = ['-----BEGIN', 'AES', 'RSA', 'SHA', 'MD5', 'base64', 'cipher']
        crypto_score = sum(1 for indicator in crypto_indicators if indicator.lower() in content.lower())
        
        if crypto_score >= 3 or file.priority >= 8:
            return LLMProvider.OPENAI_GPT4
        else:
            return LLMProvider.OPENAI_GPT35
    
    def _execute_strategy(self, provider: LLMProvider, strategy_name: str, 
                         strategy_config: Dict[str, Any], content: str, 
                         file: AnalysisFile) -> Dict[str, Any]:
        """Execute a single analysis strategy"""
        
        # Prepare the prompt
        full_prompt = f"""File: {file.filename}
File Type: {file.file_type or 'Unknown'}
File Size: {file.file_size} bytes

{strategy_config['prompt']}

Content to analyze:
{content[:4000]}  # Limit content length
"""
        
        # Call the appropriate LLM API
        if provider in [LLMProvider.OPENAI_GPT4, LLMProvider.OPENAI_GPT35]:
            return self._call_openai(provider, full_prompt, strategy_config['max_tokens'])
        else:
            return self._call_anthropic(provider, full_prompt, strategy_config['max_tokens'])
    
    def _call_openai(self, provider: LLMProvider, prompt: str, max_tokens: int) -> Dict[str, Any]:
        """FIXED: Call OpenAI ChatCompletion API with cost tracking."""
        try:
            model_name = provider.value  # e.g., "gpt-4" or "gpt-3.5-turbo"
            
            # FIXED: Use correct OpenAI API call
            response = openai.ChatCompletion.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": "You are an expert cryptographic analyst and puzzle solver specializing in CTF challenges, steganography, and blockchain analysis."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=max_tokens,
                temperature=0.1
            )
            
            # Extract usage and calculate cost
            usage = response["usage"]
            prompt_tokens = usage["prompt_tokens"]
            completion_tokens = usage["completion_tokens"]
            cost = self._calculate_openai_cost(provider, prompt_tokens, completion_tokens)
            
            # Record cost in our CostManager
            self.cost_manager.record_cost(
                provider="openai",
                model=model_name,
                input_tokens=prompt_tokens,
                output_tokens=completion_tokens,
                cost=cost
            )
            
            return {
                "success": True,
                "content": response["choices"][0]["message"]["content"],
                "cost": cost,
                "tokens": {"input": prompt_tokens, "output": completion_tokens},
                "provider": "openai",
                "model": model_name
            }
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return {"success": False, "error": f"OpenAI API error: {e}"}

    def _call_anthropic(self, provider: LLMProvider, prompt: str, max_tokens: int) -> Dict[str, Any]:
        """FIXED: Call Anthropic Claude API with cost tracking."""
        try:
            # FIXED: Use proper Anthropic client initialization
            client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            model_name = provider.value  # e.g., "claude-3-opus-20240229"
            
            # FIXED: Construct the prompt for Claude using proper format
            system_instructions = "You are an expert cryptographic analyst and puzzle solver specializing in CTF challenges, steganography, and blockchain analysis."
            
            # Use Claude's message format
            full_prompt = f"{anthropic.HUMAN_PROMPT} {system_instructions}\n\n{prompt}{anthropic.AI_PROMPT}"
            
            # FIXED: Call the Claude API with correct method
            response = client.completions.create(
                model=model_name,
                prompt=full_prompt,
                max_tokens_to_sample=max_tokens,
                temperature=0.1
            )
            
            assistant_reply = response.completion.strip()
            
            # FIXED: Anthropic doesn't provide usage counts, so estimate tokens using tiktoken
            encoding = tiktoken.encoding_for_model("gpt-4")  # Use GPT-4 encoding as approximation
            input_tokens = len(encoding.encode(full_prompt))
            output_tokens = len(encoding.encode(assistant_reply))
            cost = self._calculate_anthropic_cost(provider, input_tokens, output_tokens)
            
            self.cost_manager.record_cost(
                provider="anthropic",
                model=model_name,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost
            )
            
            return {
                "success": True,
                "content": assistant_reply,
                "cost": cost,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "provider": "anthropic",
                "model": model_name
            }
            
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return {"success": False, "error": f"Anthropic API error: {e}"}

    def _calculate_openai_cost(self, provider: LLMProvider, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for OpenAI API usage"""
        rates = self.cost_manager.COST_PER_1K_TOKENS[provider]
        input_cost = (input_tokens / 1000) * rates['input']
        output_cost = (output_tokens / 1000) * rates['output']
        return input_cost + output_cost

    def _calculate_anthropic_cost(self, provider: LLMProvider, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost for Anthropic API usage"""
        rates = self.cost_manager.COST_PER_1K_TOKENS[provider]
        input_cost = (input_tokens / 1000) * rates['input']
        output_cost = (output_tokens / 1000) * rates['output']
        return input_cost + output_cost

    def _store_llm_results(self, file_id: int, results: Dict[str, Any]):
        """Store LLM analysis results in database"""
        try:
            # Check if results already exist
            existing_content = FileContent.query.filter_by(
                file_id=file_id,
                content_type='llm_analysis_complete'
            ).first()

            if existing_content:
                # Update existing results
                existing_content.content_text = json.dumps(results, indent=2)
                existing_content.content_size = len(json.dumps(results))
                existing_content.extracted_at = datetime.utcnow()
            else:
                # Create new results record
                content = FileContent(
                    file_id=file_id,
                    content_type='llm_analysis_complete',
                    content_text=json.dumps(results, indent=2),
                    content_size=len(json.dumps(results)),
                    extracted_at=datetime.utcnow()
                )
                db.session.add(content)

            db.session.commit()
            logger.info(f"Stored LLM results for file {file_id}")

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error storing LLM results for file {file_id}: {e}")

    def get_cost_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cost statistics"""
        now = datetime.utcnow()
        
        return {
            'current_hour': self.cost_manager.get_hourly_spend(now),
            'current_day': self.cost_manager.get_daily_spend(now),
            'budgets': {
                'hourly': self.cost_manager.hourly_budget,
                'daily': self.cost_manager.daily_budget
            },
            'budget_check': self.cost_manager.check_budget(),
            'last_24_hours': [
                {
                    'hour': (now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00'),
                    'spend': self.cost_manager.get_hourly_spend(now - timedelta(hours=i))
                }
                for i in range(24)
            ]
        }

    def batch_analyze_files(self, file_ids: List[int], max_total_cost: float = 20.0) -> Dict[str, Any]:
        """Analyze multiple files with shared budget"""
        results = {
            'total_files': len(file_ids),
            'completed_files': 0,
            'failed_files': 0,
            'total_cost': 0.0,
            'results': {},
            'budget_exceeded': False
        }
        
        cost_per_file = max_total_cost / len(file_ids) if file_ids else 0
        
        for file_id in file_ids:
            if results['total_cost'] >= max_total_cost:
                results['budget_exceeded'] = True
                break
            
            file_result = self.analyze_file_with_llm(file_id, cost_per_file)
            
            if file_result.get('success'):
                results['completed_files'] += 1
                results['total_cost'] += file_result.get('total_cost', 0)
            else:
                results['failed_files'] += 1
            
            results['results'][file_id] = file_result
        
        return results
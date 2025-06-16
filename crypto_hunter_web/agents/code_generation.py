"""
crypto_hunter_web/agents/code_generation.py
AI-Powered Code Generation Agent using OpenAI/Anthropic APIs
"""

import os
import sys
import uuid
import json
import logging
import subprocess
import tempfile
import ast
import textwrap
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from .base import BaseAgent, AgentTask, AgentResult, AgentType, TaskPriority

logger = logging.getLogger(__name__)


@dataclass
class GeneratedApplication:
    """Represents an AI-generated Python application"""
    app_id: str
    name: str
    description: str
    code: str
    requirements: List[str]
    entry_point: str
    created_at: datetime
    ai_provider: str
    test_results: Optional[Dict[str, Any]] = None
    execution_results: Optional[Dict[str, Any]] = None


class AICodeGenerator:
    """Handles AI API calls for code generation"""

    def __init__(self):
        self.openai_api_key = os.environ.get('OPENAI_API_KEY')
        self.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
        self.preferred_provider = os.environ.get('AI_CODE_PROVIDER', 'openai')  # 'openai' or 'anthropic'

    def generate_code(self, problem_description: str, code_type: str,
                      requirements: List[str] = None, constraints: List[str] = None) -> Dict[str, Any]:
        """Generate code using AI APIs"""

        prompt = self._build_code_prompt(problem_description, code_type, requirements, constraints)

        try:
            if self.preferred_provider == 'anthropic' and self.anthropic_api_key:
                return self._call_anthropic_api(prompt)
            elif self.openai_api_key:
                return self._call_openai_api(prompt)
            else:
                return {"error": "No AI API keys configured", "code": None}
        except Exception as e:
            logger.error(f"AI code generation failed: {e}")
            return {"error": str(e), "code": None}

    def _build_code_prompt(self, problem: str, code_type: str,
                           requirements: List[str] = None, constraints: List[str] = None) -> str:
        """Build a comprehensive prompt for code generation"""

        prompt = f"""
Generate a complete, production-ready Python script for the following problem:

PROBLEM: {problem}
CODE TYPE: {code_type}

REQUIREMENTS:
"""

        if requirements:
            for req in requirements:
                prompt += f"- {req}\n"
        else:
            prompt += "- Create a robust, well-documented solution\n"

        if constraints:
            prompt += "\nCONSTRAINTS:\n"
            for constraint in constraints:
                prompt += f"- {constraint}\n"

        prompt += """
INSTRUCTIONS:
1. Write complete, executable Python code
2. Include comprehensive error handling
3. Add detailed docstrings and comments
4. Use only standard library and common packages (requests, numpy, PIL, cryptography)
5. Include a main entry point function
6. Add input validation and safety checks
7. Make the code modular and reusable
8. Include example usage in the main block

SECURITY REQUIREMENTS:
- No file system access outside of specified directories
- No network access except for specified APIs
- No execution of system commands
- Validate all inputs thoroughly

Please provide ONLY the Python code, no explanations or markdown formatting.
"""

        return prompt

    def _call_openai_api(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API for code generation"""
        headers = {
            'Authorization': f'Bearer {self.openai_api_key}',
            'Content-Type': 'application/json'
        }

        data = {
            'model': 'gpt-4',
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are an expert Python developer specializing in cryptography, steganography, and data analysis. Generate secure, efficient, and well-documented code.'
                },
                {'role': 'user', 'content': prompt}
            ],
            'max_tokens': 4000,
            'temperature': 0.3
        }

        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=data,
            timeout=60
        )

        if response.status_code == 200:
            result = response.json()
            code = result['choices'][0]['message']['content'].strip()
            return {
                "success": True,
                "code": code,
                "provider": "openai",
                "model": "gpt-4",
                "tokens_used": result.get('usage', {}).get('total_tokens', 0)
            }
        else:
            return {
                "success": False,
                "error": f"OpenAI API error: {response.status_code} - {response.text}",
                "code": None
            }

    def _call_anthropic_api(self, prompt: str) -> Dict[str, Any]:
        """Call Anthropic API for code generation"""
        headers = {
            'x-api-key': self.anthropic_api_key,
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01'
        }

        data = {
            'model': 'claude-3-sonnet-20240229',
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': 4000,
            'system': 'You are an expert Python developer specializing in cryptography, steganography, and data analysis. Generate secure, efficient, and well-documented code.'
        }

        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=data,
            timeout=60
        )

        if response.status_code == 200:
            result = response.json()
            code = result['content'][0]['text'].strip()
            return {
                "success": True,
                "code": code,
                "provider": "anthropic",
                "model": "claude-3-sonnet",
                "tokens_used": result.get('usage', {}).get('output_tokens', 0)
            }
        else:
            return {
                "success": False,
                "error": f"Anthropic API error: {response.status_code} - {response.text}",
                "code": None
            }


class CodeExecutor:
    """Safely executes generated code in a controlled environment"""

    def __init__(self):
        self.allowed_imports = {
            'os', 'sys', 'json', 'csv', 'math', 'random', 'datetime', 'time',
            'hashlib', 'base64', 'binascii', 'struct', 'collections', 're',
            'itertools', 'functools', 'operator', 'string', 'textwrap',
            'numpy', 'requests', 'PIL', 'cryptography', 'Crypto', 'statistics'
        }
        self.execution_timeout = 30  # seconds

    def validate_code_safety(self, code: str) -> Dict[str, Any]:
        """Validate that code is safe to execute"""
        try:
            # Parse the code to check for dangerous operations
            tree = ast.parse(code)

            dangerous_nodes = []
            imports = []

            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['exec', 'eval', '__import__', 'open']:
                            if node.func.id == 'open':
                                # Allow limited file operations
                                continue
                            dangerous_nodes.append(f"Dangerous function call: {node.func.id}")

                # Check imports
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                        if alias.name not in self.allowed_imports:
                            dangerous_nodes.append(f"Unsafe import: {alias.name}")

                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    imports.append(module)
                    if module.split('.')[0] not in self.allowed_imports:
                        dangerous_nodes.append(f"Unsafe import from: {module}")

            return {
                "safe": len(dangerous_nodes) == 0,
                "issues": dangerous_nodes,
                "imports": imports,
                "line_count": len(code.split('\n'))
            }

        except SyntaxError as e:
            return {
                "safe": False,
                "issues": [f"Syntax error: {str(e)}"],
                "imports": [],
                "line_count": 0
            }

    def execute_code(self, code: str, function_name: str,
                     args: Tuple = (), kwargs: Dict = None) -> Dict[str, Any]:
        """Execute code safely in a controlled environment"""

        # Validate code safety first
        safety_check = self.validate_code_safety(code)
        if not safety_check["safe"]:
            return {
                "success": False,
                "error": f"Code safety validation failed: {safety_check['issues']}",
                "result": None
            }

        # Create a temporary file for execution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name

        try:
            # Execute in a subprocess for better isolation
            execution_script = f"""
import sys
import json
import traceback
from types import ModuleType

# Load the generated module
sys.path.insert(0, "{os.path.dirname(temp_file_path)}")
module_name = "{os.path.splitext(os.path.basename(temp_file_path))[0]}"

try:
    exec(open("{temp_file_path}").read(), globals())

    # Call the specified function
    if "{function_name}" in globals():
        func = globals()["{function_name}"]
        result = func{args if args else '()'}
        print(json.dumps({{"success": True, "result": result, "error": None}}))
    else:
        available_functions = [name for name in globals() if callable(globals()[name]) and not name.startswith('_')]
        print(json.dumps({{"success": False, "error": f"Function '{function_name}' not found. Available: {{available_functions}}", "result": None}}))

except Exception as e:
    error_info = {{
        "error_type": type(e).__name__,
        "error_message": str(e),
        "traceback": traceback.format_exc()
    }}
    print(json.dumps({{"success": False, "error": error_info, "result": None}}))
"""

            # Execute the script
            result = subprocess.run(
                [sys.executable, '-c', execution_script],
                capture_output=True,
                text=True,
                timeout=self.execution_timeout
            )

            if result.returncode == 0:
                try:
                    execution_result = json.loads(result.stdout.strip())
                    return execution_result
                except json.JSONDecodeError:
                    return {
                        "success": False,
                        "error": f"Failed to parse execution result: {result.stdout}",
                        "result": None
                    }
            else:
                return {
                    "success": False,
                    "error": f"Execution failed with return code {result.returncode}: {result.stderr}",
                    "result": None
                }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Code execution timed out after {self.execution_timeout} seconds",
                "result": None
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "result": None
            }

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except:
                pass


class CodeGenerationAgent(BaseAgent):
    """AI-Powered Code Generation Agent - The Ultimate Problem Solver"""

    def __init__(self):
        super().__init__()
        self.ai_generator = AICodeGenerator()
        self.code_executor = CodeExecutor()
        self.generated_apps: Dict[str, GeneratedApplication] = {}
        self.app_directory = "generated_apps"

        # Ensure app directory exists
        os.makedirs(self.app_directory, exist_ok=True)

        self.capabilities = {
            'ai_powered_code_generation': True,
            'custom_crypto_solvers': True,
            'steganography_detectors': True,
            'file_format_parsers': True,
            'data_analysis_tools': True,
            'automation_scripts': True,
            'cipher_analyzers': True,
            'safe_code_execution': True
        }

    @property
    def agent_type(self) -> AgentType:
        return AgentType.INTELLIGENCE

    @property
    def supported_tasks(self) -> List[str]:
        return [
            'generate_crypto_solver',
            'create_file_parser',
            'build_steganography_detector',
            'develop_cipher_analyzer',
            'generate_data_extractor',
            'create_automation_script',
            'develop_custom_algorithm',
            'generate_analysis_tool',
            'create_decoder_tool',
            'build_validation_script'
        ]

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute AI code generation task"""
        try:
            logger.info(f"AI CodeGeneration Agent executing task: {task.task_type}")

            # Route to appropriate generation method
            if task.task_type == 'generate_crypto_solver':
                return await self._generate_crypto_solver(task)
            elif task.task_type == 'create_file_parser':
                return await self._create_file_parser(task)
            elif task.task_type == 'build_steganography_detector':
                return await self._build_steganography_detector(task)
            elif task.task_type == 'develop_cipher_analyzer':
                return await self._develop_cipher_analyzer(task)
            elif task.task_type == 'generate_data_extractor':
                return await self._generate_data_extractor(task)
            elif task.task_type == 'create_automation_script':
                return await self._create_automation_script(task)
            elif task.task_type == 'develop_custom_algorithm':
                return await self._develop_custom_algorithm(task)
            else:
                return await self._generate_generic_solution(task)

        except Exception as e:
            logger.error(f"AI CodeGeneration Agent error: {e}")
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"AI code generation error: {str(e)}"
            )

    async def _generate_crypto_solver(self, task: AgentTask) -> AgentResult:
        """Generate AI-powered cryptographic solver"""
        problem_description = task.payload.get('problem_description', '')
        cipher_type = task.payload.get('cipher_type', 'unknown')
        sample_data = task.payload.get('sample_data', '')
        hints = task.payload.get('hints', [])

        # Build detailed problem description for AI
        full_problem = f"""
Create a comprehensive cryptographic solver for a {cipher_type} cipher.

Problem Details: {problem_description}

Sample Ciphertext: {sample_data}

Hints: {', '.join(hints)}

The solver should:
1. Analyze the input ciphertext
2. Attempt multiple decryption approaches
3. Score potential solutions based on English language patterns
4. Return the most likely plaintext with confidence scores
5. Include detailed analysis of the decryption process

Create a function called 'solve_cipher' that takes ciphertext as input and returns a dictionary with results.
"""

        # Generate code using AI
        ai_result = self.ai_generator.generate_code(
            problem_description=full_problem,
            code_type="cryptographic_solver",
            requirements=[
                "Handle multiple cipher types automatically",
                "Include frequency analysis capabilities",
                "Provide confidence scoring for solutions",
                "Support both manual and automated key discovery"
            ],
            constraints=[
                "No external network access",
                "Use only standard libraries or numpy/cryptography",
                "Maximum execution time of 30 seconds"
            ]
        )

        if not ai_result.get("success"):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"AI code generation failed: {ai_result.get('error')}"
            )

        # Create application object
        app = GeneratedApplication(
            app_id=f"crypto_solver_{uuid.uuid4().hex[:8]}",
            name=f"AI-Generated {cipher_type.title()} Solver",
            description=f"AI-generated solver for {cipher_type} cipher: {problem_description}",
            code=ai_result["code"],
            requirements=['cryptography', 'numpy'],
            entry_point='solve_cipher',
            created_at=datetime.utcnow(),
            ai_provider=ai_result.get("provider", "unknown")
        )

        # Test the generated code
        test_result = await self._test_generated_code(app, sample_data)
        app.test_results = test_result

        # Save the application
        await self._save_application(app)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=test_result['success'],
            data={
                'app_id': app.app_id,
                'app_name': app.name,
                'description': app.description,
                'code_length': len(app.code),
                'ai_provider': app.ai_provider,
                'test_results': test_result,
                'entry_point': app.entry_point,
                'execution_ready': test_result['success']
            },
            metadata={'generated_app': True, 'cipher_type': cipher_type, 'ai_generated': True}
        )

    async def _create_file_parser(self, task: AgentTask) -> AgentResult:
        """Generate AI-powered file parser"""
        file_format = task.payload.get('file_format', 'unknown')
        file_sample_path = task.payload.get('file_sample_path', '')
        parsing_requirements = task.payload.get('requirements', [])

        problem_description = f"""
Create a comprehensive file parser for {file_format} format files.

Requirements: {', '.join(parsing_requirements)}

The parser should:
1. Read and analyze the file structure
2. Extract all meaningful data sections
3. Handle different variations of the format
4. Provide detailed metadata about the file
5. Return structured data in a standardized format

Create a function called 'parse_file' that takes a file path and returns parsed data.
"""

        ai_result = self.ai_generator.generate_code(
            problem_description=problem_description,
            code_type="file_parser",
            requirements=parsing_requirements + [
                "Robust error handling for malformed files",
                "Support for both binary and text formats",
                "Detailed logging of parsing steps"
            ]
        )

        if not ai_result.get("success"):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"AI file parser generation failed: {ai_result.get('error')}"
            )

        app = GeneratedApplication(
            app_id=f"file_parser_{uuid.uuid4().hex[:8]}",
            name=f"AI-Generated {file_format.upper()} Parser",
            description=f"AI-generated parser for {file_format} files",
            code=ai_result["code"],
            requirements=['struct', 'json'],
            entry_point='parse_file',
            created_at=datetime.utcnow(),
            ai_provider=ai_result.get("provider", "unknown")
        )

        # Test with sample file if provided
        test_result = await self._test_generated_code(app, file_sample_path)
        app.test_results = test_result

        await self._save_application(app)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=test_result['success'],
            data={
                'app_id': app.app_id,
                'app_name': app.name,
                'code_length': len(app.code),
                'ai_provider': app.ai_provider,
                'parsing_capabilities': parsing_requirements,
                'test_results': test_result
            }
        )

    async def _build_steganography_detector(self, task: AgentTask) -> AgentResult:
        """Generate AI-powered steganography detector"""
        detection_method = task.payload.get('detection_method', 'statistical_analysis')
        file_types = task.payload.get('file_types', ['image'])
        sensitivity = task.payload.get('sensitivity', 'medium')

        problem_description = f"""
Create an advanced steganography detection tool using {detection_method}.

Target file types: {', '.join(file_types)}
Detection sensitivity: {sensitivity}

The detector should:
1. Analyze files for steganographic content indicators
2. Use multiple detection algorithms
3. Provide confidence scores for findings
4. Generate detailed analysis reports
5. Support batch processing of files

Create a function called 'detect_steganography' that analyzes a file and returns detection results.
"""

        ai_result = self.ai_generator.generate_code(
            problem_description=problem_description,
            code_type="steganography_detector",
            requirements=[
                "Support for multiple image formats",
                "Statistical analysis capabilities",
                "LSB analysis functionality",
                "Chi-square testing",
                "Entropy analysis"
            ]
        )

        if not ai_result.get("success"):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"AI steganography detector generation failed: {ai_result.get('error')}"
            )

        app = GeneratedApplication(
            app_id=f"stego_detector_{uuid.uuid4().hex[:8]}",
            name=f"AI-Generated Steganography Detector",
            description=f"AI-generated steganography detector using {detection_method}",
            code=ai_result["code"],
            requirements=['PIL', 'numpy', 'scipy'],
            entry_point='detect_steganography',
            created_at=datetime.utcnow(),
            ai_provider=ai_result.get("provider", "unknown")
        )

        test_result = await self._test_generated_code(app)
        app.test_results = test_result

        await self._save_application(app)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=test_result['success'],
            data={
                'app_id': app.app_id,
                'app_name': app.name,
                'detection_method': detection_method,
                'supported_file_types': file_types,
                'ai_provider': app.ai_provider,
                'test_results': test_result
            }
        )

    async def _generate_generic_solution(self, task: AgentTask) -> AgentResult:
        """Generate AI solution for any problem"""
        problem_description = task.payload.get('problem_description', '')
        solution_type = task.payload.get('solution_type', 'analysis_tool')
        requirements = task.payload.get('requirements', [])

        ai_result = self.ai_generator.generate_code(
            problem_description=problem_description,
            code_type=solution_type,
            requirements=requirements
        )

        if not ai_result.get("success"):
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"AI solution generation failed: {ai_result.get('error')}"
            )

        app = GeneratedApplication(
            app_id=f"ai_solution_{uuid.uuid4().hex[:8]}",
            name=f"AI-Generated {solution_type.title()}",
            description=f"AI-generated solution: {problem_description}",
            code=ai_result["code"],
            requirements=[],
            entry_point='main',
            created_at=datetime.utcnow(),
            ai_provider=ai_result.get("provider", "unknown")
        )

        test_result = await self._test_generated_code(app)
        app.test_results = test_result

        await self._save_application(app)

        return AgentResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            success=test_result['success'],
            data={
                'app_id': app.app_id,
                'app_name': app.name,
                'ai_provider': app.ai_provider,
                'test_results': test_result
            }
        )

    async def _test_generated_code(self, app: GeneratedApplication, test_input: str = None) -> Dict[str, Any]:
        """Test the generated code safely"""
        try:
            # First, validate code safety
            safety_check = self.code_executor.validate_code_safety(app.code)

            if not safety_check["safe"]:
                return {
                    "success": False,
                    "error": f"Code safety validation failed: {safety_check['issues']}",
                    "safety_check": safety_check
                }

            # Try to execute the entry point function
            if test_input:
                execution_result = self.code_executor.execute_code(
                    app.code,
                    app.entry_point,
                    args=(test_input,)
                )
            else:
                # Test with minimal input
                execution_result = self.code_executor.execute_code(
                    app.code,
                    app.entry_point,
                    args=("test",)
                )

            return {
                "success": execution_result["success"],
                "execution_result": execution_result,
                "safety_check": safety_check,
                "code_validated": True
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Testing failed: {str(e)}",
                "safety_check": safety_check if 'safety_check' in locals() else None
            }

    async def _save_application(self, app: GeneratedApplication):
        """Save generated application to storage"""
        try:
            # Save to memory registry
            self.generated_apps[app.app_id] = app

            # Save to file system
            app_file = os.path.join(self.app_directory, f"{app.app_id}.py")
            with open(app_file, 'w') as f:
                f.write(f'# {app.name}\n')
                f.write(f'# Generated by AI on {app.created_at}\n')
                f.write(f'# Provider: {app.ai_provider}\n')
                f.write(f'# Description: {app.description}\n\n')
                f.write(app.code)

            # Save metadata
            metadata_file = os.path.join(self.app_directory, f"{app.app_id}_metadata.json")
            with open(metadata_file, 'w') as f:
                metadata = asdict(app)
                metadata['created_at'] = app.created_at.isoformat()
                json.dump(metadata, f, indent=2)

            logger.info(f"Saved AI-generated application {app.app_id} to {app_file}")

        except Exception as e:
            logger.error(f"Failed to save application {app.app_id}: {e}")

    def execute_generated_app(self, app_id: str, input_data: Any = None) -> Dict[str, Any]:
        """Execute a previously generated application"""
        if app_id not in self.generated_apps:
            return {"success": False, "error": f"Application {app_id} not found"}

        app = self.generated_apps[app_id]

        try:
            if input_data is not None:
                result = self.code_executor.execute_code(
                    app.code,
                    app.entry_point,
                    args=(input_data,)
                )
            else:
                result = self.code_executor.execute_code(
                    app.code,
                    app.entry_point
                )

            # Update execution results
            app.execution_results = result

            return {
                "success": result["success"],
                "app_id": app_id,
                "app_name": app.name,
                "result": result["result"],
                "execution_info": {
                    "ai_provider": app.ai_provider,
                    "created_at": app.created_at.isoformat(),
                    "entry_point": app.entry_point
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Execution failed: {str(e)}",
                "app_id": app_id
            }

    def list_generated_apps(self) -> List[Dict[str, Any]]:
        """List all generated applications"""
        return [
            {
                "app_id": app.app_id,
                "name": app.name,
                "description": app.description,
                "ai_provider": app.ai_provider,
                "created_at": app.created_at.isoformat(),
                "entry_point": app.entry_point,
                "test_status": "passed" if app.test_results and app.test_results.get("success") else "failed"
            }
            for app in self.generated_apps.values()
        ]


# Helper functions for integration

def create_code_generation_task(problem_description: str, task_type: str = 'develop_custom_algorithm',
                                **kwargs) -> AgentTask:
    """Helper function to create code generation tasks"""
    return AgentTask(
        task_type=task_type,
        agent_type=AgentType.INTELLIGENCE,
        priority=TaskPriority.HIGH,
        payload={
            'problem_description': problem_description,
            **kwargs
        },
        context={
            'requires_ai_generation': True,
            'max_execution_
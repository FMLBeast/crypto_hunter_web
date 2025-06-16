"""
tests/test_agent_system.py
Comprehensive testing framework for Crypto Hunter agent system
"""

import pytest
import asyncio
import tempfile
import os
import json
import time
from typing import Dict, Any, List
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import uuid

# Import the agent system components
from crypto_hunter_web.agents.base import (
    AgentType, TaskPriority, AgentTask, AgentResult, BaseAgent
)
from crypto_hunter_web.agents.agent_framework import (
    OrchestrationAgent, AgentRegistry, TaskQueue
)
from crypto_hunter_web.agents.specialized_agents import (
    FileAnalysisAgent, SteganographyAgent, CryptographyAgent, IntelligenceAgent
)
from crypto_hunter_web.agents.missing_specialized_agents import (
    RelationshipAgent, PresentationAgent, ValidationAgent
)
from crypto_hunter_web.agents.complete_workflow_templates import (
    register_complete_workflow_templates, get_workflow_recommendations
)
from crypto_hunter_web.services.complete_agent_system import CompleteAgentSystem
from crypto_hunter_web.config.agent_config import AgentConfigManager, CompleteAgentConfig


class TestAgentBase:
    """Test cases for base agent functionality"""
    
    def setup_method(self):
        """Setup for each test method"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_files = self._create_test_files()
    
    def teardown_method(self):
        """Cleanup after each test method"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_files(self) -> Dict[str, str]:
        """Create test files for agent testing"""
        test_files = {}
        
        # Create a test image file
        image_path = os.path.join(self.temp_dir, "test_image.png")
        with open(image_path, "wb") as f:
            # Write minimal PNG header
            f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82')
        test_files['image'] = image_path
        
        # Create a test text file with potential cipher
        text_path = os.path.join(self.temp_dir, "test_cipher.txt")
        with open(text_path, "w") as f:
            f.write("Uryyb Jbeyq")  # ROT13 encoded "Hello World"
        test_files['cipher'] = text_path
        
        # Create a test binary file
        binary_path = os.path.join(self.temp_dir, "test_binary.bin")
        with open(binary_path, "wb") as f:
            f.write(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f')
        test_files['binary'] = binary_path
        
        return test_files
    
    def test_agent_task_creation(self):
        """Test agent task creation and serialization"""
        task = AgentTask(
            task_type="test_task",
            agent_type=AgentType.FILE_ANALYSIS,
            priority=TaskPriority.HIGH,
            payload={"file_path": self.test_files['image']},
            context={"test": True}
        )
        
        assert task.task_type == "test_task"
        assert task.agent_type == AgentType.FILE_ANALYSIS
        assert task.priority == TaskPriority.HIGH
        assert task.payload["file_path"] == self.test_files['image']
        
        # Test serialization
        task_dict = task.to_dict()
        assert isinstance(task_dict, dict)
        assert task_dict['task_type'] == "test_task"
        assert task_dict['agent_type'] == "file_analysis"
    
    def test_agent_result_creation(self):
        """Test agent result creation"""
        result = AgentResult(
            task_id="test_task_123",
            agent_id="test_agent",
            success=True,
            output_data={"findings": ["test_finding"]},
            confidence_score=0.85
        )
        
        assert result.success is True
        assert result.confidence_score == 0.85
        assert result.output_data["findings"] == ["test_finding"]


class TestFileAnalysisAgent:
    """Test cases for File Analysis Agent"""
    
    def setup_method(self):
        self.agent = FileAnalysisAgent()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_file_analysis_basic(self):
        """Test basic file analysis functionality"""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World!")
        
        task = AgentTask(
            task_type="analyze_file",
            payload={"file_path": test_file, "action": "basic"}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "file_path" in result.output_data
        assert "file_size" in result.output_data
        assert "file_type" in result.output_data
        assert result.output_data["file_size"] > 0
    
    @pytest.mark.asyncio
    async def test_file_analysis_nonexistent_file(self):
        """Test file analysis with non-existent file"""
        task = AgentTask(
            task_type="analyze_file",
            payload={"file_path": "/nonexistent/file.txt"}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is False
        assert "not found" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_file_entropy_calculation(self):
        """Test entropy calculation for files"""
        # Create file with known entropy characteristics
        low_entropy_file = os.path.join(self.temp_dir, "low_entropy.txt")
        with open(low_entropy_file, "w") as f:
            f.write("A" * 1000)  # Low entropy
        
        high_entropy_file = os.path.join(self.temp_dir, "high_entropy.bin")
        with open(high_entropy_file, "wb") as f:
            import random
            f.write(bytes([random.randint(0, 255) for _ in range(1000)]))  # High entropy
        
        # Test low entropy file
        task1 = AgentTask(
            task_type="analyze_file",
            payload={"file_path": low_entropy_file}
        )
        result1 = await self.agent.execute(task1)
        
        # Test high entropy file
        task2 = AgentTask(
            task_type="analyze_file",
            payload={"file_path": high_entropy_file}
        )
        result2 = await self.agent.execute(task2)
        
        assert result1.success is True
        assert result2.success is True
        
        # High entropy file should have higher entropy score
        if "entropy" in result1.output_data and "entropy" in result2.output_data:
            assert result2.output_data["entropy"] > result1.output_data["entropy"]


class TestSteganographyAgent:
    """Test cases for Steganography Agent"""
    
    def setup_method(self):
        self.agent = SteganographyAgent()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_steganography_task_types(self):
        """Test different steganography task types"""
        # Create test image
        test_image = os.path.join(self.temp_dir, "test.png")
        with open(test_image, "wb") as f:
            f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82')
        
        # Test basic extraction
        task = AgentTask(
            task_type="basic_extraction",
            payload={"file_path": test_image}
        )
        
        result = await self.agent.execute(task)
        
        # Should complete even if no hidden data found
        assert result.success is True
        assert "extractions" in result.output_data
    
    @pytest.mark.asyncio
    async def test_invalid_task_type(self):
        """Test invalid task type handling"""
        task = AgentTask(
            task_type="invalid_task",
            payload={"file_path": "test.png"}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is False
        assert "unknown task type" in result.error_message.lower()


class TestCryptographyAgent:
    """Test cases for Cryptography Agent"""
    
    def setup_method(self):
        self.agent = CryptographyAgent()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_caesar_cipher_detection(self):
        """Test Caesar cipher detection and solving"""
        # Create file with Caesar cipher
        cipher_file = os.path.join(self.temp_dir, "caesar.txt")
        with open(cipher_file, "w") as f:
            f.write("Uryyb Jbeyq")  # "Hello World" with ROT13
        
        task = AgentTask(
            task_type="detect_cipher_type",
            payload={"file_path": cipher_file}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "detected_ciphers" in result.output_data
    
    @pytest.mark.asyncio
    async def test_pattern_analysis(self):
        """Test pattern analysis functionality"""
        # Create file with various patterns
        pattern_file = os.path.join(self.temp_dir, "patterns.txt")
        with open(pattern_file, "w") as f:
            f.write("SGVsbG8gV29ybGQ=")  # Base64 encoded "Hello World"
        
        task = AgentTask(
            task_type="analyze_patterns",
            payload={"file_path": pattern_file}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "patterns" in result.output_data


class TestIntelligenceAgent:
    """Test cases for Intelligence Agent"""
    
    def setup_method(self):
        self.agent = IntelligenceAgent()
    
    @pytest.mark.asyncio
    async def test_finding_synthesis(self):
        """Test finding synthesis functionality"""
        mock_findings = [
            {"type": "pattern", "content": "base64", "confidence": 0.8},
            {"type": "extraction", "content": "hidden_text", "confidence": 0.9},
            {"type": "cipher", "content": "caesar", "confidence": 0.7}
        ]
        
        task = AgentTask(
            task_type="synthesize_findings",
            payload={"findings": mock_findings}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "synthesis" in result.output_data
        assert "confidence_score" in result.output_data
    
    @pytest.mark.asyncio
    async def test_hypothesis_generation(self):
        """Test hypothesis generation"""
        mock_context = {
            "file_count": 3,
            "extraction_chains": 2,
            "cipher_types": ["caesar", "base64"]
        }
        
        task = AgentTask(
            task_type="generate_hypotheses",
            payload={"context": mock_context}
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "hypotheses" in result.output_data


class TestRelationshipAgent:
    """Test cases for Relationship Agent"""
    
    def setup_method(self):
        self.agent = RelationshipAgent()
    
    @pytest.mark.asyncio
    async def test_file_similarity_calculation(self):
        """Test file similarity calculation"""
        # Mock file objects for testing
        mock_files = [
            Mock(id=1, filename="file1.txt", file_content=Mock(raw_content=b"Hello World")),
            Mock(id=2, filename="file2.txt", file_content=Mock(raw_content=b"Hello Universe")),
            Mock(id=3, filename="file3.txt", file_content=Mock(raw_content=b"Completely different content"))
        ]
        
        similarity_matrix = await self.agent._calculate_similarity_matrix(mock_files)
        
        assert similarity_matrix.shape == (3, 3)
        assert similarity_matrix[0, 0] == 1.0  # Self-similarity
        assert similarity_matrix[0, 1] > similarity_matrix[0, 2]  # file1 more similar to file2 than file3


class TestValidationAgent:
    """Test cases for Validation Agent"""
    
    def setup_method(self):
        self.agent = ValidationAgent()
    
    @pytest.mark.asyncio
    async def test_solution_validation(self):
        """Test solution validation"""
        task = AgentTask(
            task_type="validate_solution",
            payload={
                "solution": "flag{test_solution}",
                "expected_format": "flag",
                "criteria": {
                    "min_length": 5,
                    "contains": ["flag"]
                }
            }
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "is_valid" in result.output_data
        assert "confidence" in result.output_data
        assert "validation_checks" in result.output_data
    
    @pytest.mark.asyncio
    async def test_cipher_solution_validation(self):
        """Test cipher solution validation"""
        task = AgentTask(
            task_type="validate_cipher_solution",
            payload={
                "ciphertext": "URYYB JBEYQ",
                "plaintext": "HELLO WORLD",
                "cipher_type": "caesar",
                "key": "13"
            }
        )
        
        result = await self.agent.execute(task)
        
        assert result.success is True
        assert "valid" in result.output_data
        assert "confidence" in result.output_data


class TestOrchestrationEngine:
    """Test cases for Orchestration Engine"""
    
    def setup_method(self):
        self.orchestrator = OrchestrationAgent()
        self.agent_registry = AgentRegistry()
        self.task_queue = TaskQueue()
    
    @pytest.mark.asyncio
    async def test_agent_registration(self):
        """Test agent registration"""
        test_agent = FileAnalysisAgent()
        
        self.orchestrator.register_agent(test_agent)
        
        assert test_agent.agent_id in self.orchestrator.agents
        assert self.orchestrator.agents[test_agent.agent_id] == test_agent
    
    @pytest.mark.asyncio
    async def test_task_execution(self):
        """Test task execution through orchestrator"""
        # Register test agent
        test_agent = FileAnalysisAgent()
        self.orchestrator.register_agent(test_agent)
        
        # Create test file
        temp_dir = tempfile.mkdtemp()
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Test content")
        
        try:
            # Create and execute task
            task = AgentTask(
                task_type="analyze_file",
                agent_type=AgentType.FILE_ANALYSIS,
                payload={"file_path": test_file}
            )
            
            result = await self.orchestrator.execute_task(task)
            
            assert result.success is True
            
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestWorkflowTemplates:
    """Test cases for Workflow Templates"""
    
    def setup_method(self):
        self.orchestrator = OrchestrationAgent()
        register_complete_workflow_templates(self.orchestrator)
    
    def test_workflow_registration(self):
        """Test that all workflow templates are registered"""
        expected_workflows = [
            "file_analysis",
            "steganography_deep_scan",
            "crypto_challenge",
            "quick_analysis",
            "collaborative_puzzle_solving",
            "forensic_investigation",
            "ml_enhanced_analysis"
        ]
        
        for workflow_name in expected_workflows:
            assert workflow_name in self.orchestrator.workflow_templates
    
    def test_workflow_recommendations(self):
        """Test workflow recommendation system"""
        file_types = ["image/png", "text/plain"]
        context = {
            "file_count": 2,
            "has_images": True,
            "suspected_cipher": True
        }
        
        recommendations = get_workflow_recommendations(file_types, context)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert "quick_analysis" in recommendations  # Should always be recommended


class TestCompleteAgentSystem:
    """Test cases for Complete Agent System"""
    
    def setup_method(self):
        self.system = CompleteAgentSystem()
    
    @pytest.mark.asyncio
    async def test_system_initialization(self):
        """Test complete system initialization"""
        # Mock the app context and database
        with patch('crypto_hunter_web.extensions.db'):
            success = self.system.initialize()
            
            assert success is True
            assert self.system.initialized is True
            assert len(self.system.agents) > 0
    
    def test_system_status(self):
        """Test system status reporting"""
        # Initialize with mocked components
        with patch('crypto_hunter_web.extensions.db'):
            self.system.initialize()
            
            status = self.system.get_system_status()
            
            assert isinstance(status, dict)
            assert "initialized" in status
            assert "agents" in status
            assert "orchestrator" in status


class TestAgentConfiguration:
    """Test cases for Agent Configuration System"""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = AgentConfigManager(self.temp_dir)
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_default_config_loading(self):
        """Test default configuration loading"""
        config = self.config_manager.load_config()
        
        assert isinstance(config, CompleteAgentConfig)
        assert config.config_version == "1.0"
        assert config.resources.max_memory_mb > 0
        assert config.security.sandbox_mode is not None
    
    def test_environment_config_override(self):
        """Test environment variable configuration override"""
        # Set environment variable
        os.environ['AGENT_MAX_MEMORY_MB'] = '2048'
        
        try:
            config = self.config_manager.load_config()
            assert config.resources.max_memory_mb == 2048
        finally:
            # Clean up
            if 'AGENT_MAX_MEMORY_MB' in os.environ:
                del os.environ['AGENT_MAX_MEMORY_MB']
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Test valid configuration
        valid_config = CompleteAgentConfig()
        self.config_manager._validate_config(valid_config)  # Should not raise
        
        # Test invalid configuration
        invalid_config = CompleteAgentConfig()
        invalid_config.resources.max_memory_mb = 50  # Too low
        
        with pytest.raises(ValueError):
            self.config_manager._validate_config(invalid_config)


class TestIntegrationScenarios:
    """Integration test scenarios"""
    
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.system = CompleteAgentSystem()
    
    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_complete_file_analysis_workflow(self):
        """Test complete file analysis workflow"""
        # Create test files
        test_files = self._create_comprehensive_test_files()
        
        # Mock database and initialize system
        with patch('crypto_hunter_web.extensions.db'), \
             patch('crypto_hunter_web.models.analysis_file.AnalysisFile') as mock_file:
            
            # Mock file object
            mock_file.query.get.return_value = Mock(
                id=1,
                file_path=test_files['complex_file'],
                session_id='test_session'
            )
            
            # Initialize system
            self.system.initialize()
            
            # Start analysis workflow
            workflow_id = await self.system.analyze_file(
                file_id=1,
                workflow_name="file_analysis"
            )
            
            assert workflow_id is not None
            assert isinstance(workflow_id, str)
    
    def _create_comprehensive_test_files(self) -> Dict[str, str]:
        """Create comprehensive test files for integration testing"""
        test_files = {}
        
        # Create file with multiple layers
        complex_file = os.path.join(self.temp_dir, "complex.png")
        with open(complex_file, "wb") as f:
            # PNG header + potential steganographic content
            f.write(b'\x89PNG\r\n\x1a\n')
            f.write(b'HIDDEN_DATA: SGVsbG8gV29ybGQ=')  # Base64 encoded data
            f.write(b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde')
        test_files['complex_file'] = complex_file
        
        return test_files
    
    @pytest.mark.asyncio
    async def test_multi_agent_collaboration(self):
        """Test multiple agents working together"""
        # This would test the complete workflow with multiple agents
        # interacting and sharing results
        pass
    
    def test_error_handling_and_recovery(self):
        """Test system behavior under error conditions"""
        # Test various error scenarios and recovery mechanisms
        pass


# Performance and load testing
class TestPerformance:
    """Performance test cases"""
    
    @pytest.mark.asyncio
    async def test_concurrent_agent_execution(self):
        """Test concurrent execution of multiple agents"""
        agents = [
            FileAnalysisAgent(),
            SteganographyAgent(),
            CryptographyAgent()
        ]
        
        # Create test tasks
        tasks = []
        for i, agent in enumerate(agents):
            task = AgentTask(
                task_type="test_task",
                payload={"test_data": f"data_{i}"}
            )
            tasks.append((agent, task))
        
        # Execute tasks concurrently
        start_time = time.time()
        
        async def execute_agent_task(agent, task):
            # Mock execution for performance testing
            await asyncio.sleep(0.1)  # Simulate work
            return AgentResult(
                task_id=task.task_id,
                agent_id=agent.agent_id,
                success=True
            )
        
        results = await asyncio.gather(*[
            execute_agent_task(agent, task) for agent, task in tasks
        ])
        
        execution_time = time.time() - start_time
        
        assert len(results) == len(agents)
        assert all(result.success for result in results)
        assert execution_time < 1.0  # Should complete quickly in parallel
    
    def test_memory_usage(self):
        """Test memory usage under load"""
        # Test memory consumption during heavy operations
        pass
    
    def test_scalability(self):
        """Test system scalability with increasing load"""
        # Test how system performs with increasing number of files/tasks
        pass


# Utility functions for testing
def create_mock_database_session():
    """Create mock database session for testing"""
    mock_session = Mock()
    mock_session.query.return_value = Mock()
    mock_session.commit.return_value = None
    mock_session.rollback.return_value = None
    return mock_session


def create_mock_file_objects(count: int = 3) -> List[Mock]:
    """Create mock file objects for testing"""
    files = []
    for i in range(count):
        file_obj = Mock()
        file_obj.id = i + 1
        file_obj.filename = f"test_file_{i+1}.txt"
        file_obj.file_type = "text/plain"
        file_obj.file_size = 1000 + i * 100
        file_obj.session_id = "test_session"
        files.append(file_obj)
    return files


# Test runner configuration
if __name__ == "__main__":
    # Run tests with coverage
    pytest.main([
        __file__,
        "-v",
        "--cov=crypto_hunter_web.agents",
        "--cov=crypto_hunter_web.services.complete_agent_system",
        "--cov=crypto_hunter_web.config.agent_config",
        "--cov-report=html",
        "--cov-report=term-missing"
    ])
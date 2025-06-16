"""
crypto_hunter_web/agents/complete_workflow_templates.py
Complete workflow template definitions for Crypto Hunter orchestration
"""

from typing import Dict, Any, List, Optional
from crypto_hunter_web.agents.base import AgentType
from crypto_hunter_web.agents.orchestration import WorkflowTemplate, WorkflowStep

def register_complete_workflow_templates(engine) -> None:
    """Register all complete workflow templates with the orchestration engine"""
    
    # 1. Complete File Analysis Workflow
    file_analysis = WorkflowTemplate(
        name="file_analysis",
        description="Complete file analysis workflow with parallel processing"
    )
    
    file_analysis.add_step(WorkflowStep(
        step_name="initial_analysis",
        agent_type=AgentType.FILE_ANALYSIS,
        task_type="analyze_file",
        conditions={},
        dependencies=[],
        timeout=120
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="steganography_scan",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="extract_hidden_data",
        conditions={"file_type": ["image/*", "audio/*"]},
        dependencies=["initial_analysis"],
        parallel=True,
        timeout=300
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="crypto_analysis",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="analyze_crypto_patterns",
        conditions={},
        dependencies=["initial_analysis"],
        parallel=True,
        timeout=180
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="relationship_analysis",
        agent_type=AgentType.RELATIONSHIP,
        task_type="analyze_file_relationships",
        conditions={},
        dependencies=["initial_analysis"],
        parallel=True,
        timeout=240
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="intelligence_synthesis",
        agent_type=AgentType.INTELLIGENCE,
        task_type="synthesize_findings",
        conditions={},
        dependencies=["steganography_scan", "crypto_analysis", "relationship_analysis"],
        timeout=300
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="validation",
        agent_type=AgentType.VALIDATION,
        task_type="cross_validate_findings",
        conditions={},
        dependencies=["intelligence_synthesis"],
        timeout=120
    ))
    
    file_analysis.add_step(WorkflowStep(
        step_name="presentation",
        agent_type=AgentType.PRESENTATION,
        task_type="format_analysis_report",
        conditions={},
        dependencies=["validation"],
        timeout=60
    ))
    
    engine.register_workflow(file_analysis)
    
    # 2. Steganography Deep Scan Workflow
    stego_deep = WorkflowTemplate(
        name="steganography_deep_scan",
        description="Comprehensive steganographic analysis with multiple extraction methods"
    )
    
    stego_deep.add_step(WorkflowStep(
        step_name="basic_stegano",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="basic_extraction",
        conditions={},
        dependencies=[],
        timeout=180
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="advanced_stegano",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="advanced_extraction",
        conditions={},
        dependencies=["basic_stegano"],
        timeout=600
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="frequency_analysis",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="frequency_domain_analysis",
        conditions={"file_type": ["image/*"]},
        dependencies=["basic_stegano"],
        parallel=True,
        timeout=300
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="bit_plane_analysis",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="bit_plane_analysis",
        conditions={"file_type": ["image/*"]},
        dependencies=["basic_stegano"],
        parallel=True,
        timeout=240
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="polyglot_detection",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="polyglot_analysis",
        conditions={},
        dependencies=["basic_stegano"],
        parallel=True,
        timeout=180
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="stego_intelligence",
        agent_type=AgentType.INTELLIGENCE,
        task_type="correlate_stego_findings",
        conditions={},
        dependencies=["advanced_stegano", "frequency_analysis", "bit_plane_analysis", "polyglot_detection"],
        timeout=240
    ))
    
    stego_deep.add_step(WorkflowStep(
        step_name="stego_validation",
        agent_type=AgentType.VALIDATION,
        task_type="verify_extraction",
        conditions={},
        dependencies=["stego_intelligence"],
        timeout=120
    ))
    
    engine.register_workflow(stego_deep)
    
    # 3. Crypto Challenge Workflow
    crypto_challenge = WorkflowTemplate(
        name="crypto_challenge",
        description="Comprehensive cryptographic challenge solving workflow"
    )
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="cipher_detection",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="detect_cipher_type",
        conditions={},
        dependencies=[],
        timeout=120
    ))
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="pattern_analysis",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="analyze_patterns",
        conditions={},
        dependencies=["cipher_detection"],
        parallel=True,
        timeout=300
    ))
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="frequency_analysis",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="frequency_analysis",
        conditions={},
        dependencies=["cipher_detection"],
        parallel=True,
        timeout=240
    ))
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="key_search",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="brute_force_keys",
        conditions={"cipher_type": ["caesar", "substitution", "vigenere"]},
        dependencies=["pattern_analysis", "frequency_analysis"],
        timeout=900
    ))
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="crypto_intelligence",
        agent_type=AgentType.INTELLIGENCE,
        task_type="crypto_hypothesis_generation",
        conditions={},
        dependencies=["key_search"],
        timeout=300
    ))
    
    crypto_challenge.add_step(WorkflowStep(
        step_name="solution_validation",
        agent_type=AgentType.VALIDATION,
        task_type="validate_cipher_solution",
        conditions={},
        dependencies=["crypto_intelligence"],
        timeout=180
    ))
    
    engine.register_workflow(crypto_challenge)
    
    # 4. Quick Analysis Workflow
    quick_analysis = WorkflowTemplate(
        name="quick_analysis",
        description="Fast initial analysis for rapid puzzle assessment"
    )
    
    quick_analysis.add_step(WorkflowStep(
        step_name="rapid_file_scan",
        agent_type=AgentType.FILE_ANALYSIS,
        task_type="quick_scan",
        conditions={},
        dependencies=[],
        timeout=30
    ))
    
    quick_analysis.add_step(WorkflowStep(
        step_name="rapid_stego_check",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="quick_stego_scan",
        conditions={"file_type": ["image/*", "audio/*"]},
        dependencies=["rapid_file_scan"],
        parallel=True,
        timeout=60
    ))
    
    quick_analysis.add_step(WorkflowStep(
        step_name="rapid_crypto_check",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="quick_crypto_scan",
        conditions={},
        dependencies=["rapid_file_scan"],
        parallel=True,
        timeout=45
    ))
    
    quick_analysis.add_step(WorkflowStep(
        step_name="quick_summary",
        agent_type=AgentType.PRESENTATION,
        task_type="create_summary_dashboard",
        conditions={},
        dependencies=["rapid_stego_check", "rapid_crypto_check"],
        timeout=30
    ))
    
    engine.register_workflow(quick_analysis)
    
    # 5. Collaborative Puzzle Solving Workflow
    collaborative = WorkflowTemplate(
        name="collaborative_puzzle_solving",
        description="Team-based puzzle solving with real-time collaboration"
    )
    
    collaborative.add_step(WorkflowStep(
        step_name="initial_assessment",
        agent_type=AgentType.FILE_ANALYSIS,
        task_type="collaborative_analysis",
        conditions={},
        dependencies=[],
        timeout=120
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="parallel_extraction",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="collaborative_extraction",
        conditions={},
        dependencies=["initial_assessment"],
        parallel=True,
        timeout=300
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="parallel_cryptanalysis",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="collaborative_crypto_analysis",
        conditions={},
        dependencies=["initial_assessment"],
        parallel=True,
        timeout=300
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="relationship_mapping",
        agent_type=AgentType.RELATIONSHIP,
        task_type="build_relationship_graph",
        conditions={},
        dependencies=["parallel_extraction", "parallel_cryptanalysis"],
        timeout=180
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="team_intelligence",
        agent_type=AgentType.INTELLIGENCE,
        task_type="collaborative_synthesis",
        conditions={},
        dependencies=["relationship_mapping"],
        timeout=240
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="collaborative_validation",
        agent_type=AgentType.VALIDATION,
        task_type="team_validation",
        conditions={},
        dependencies=["team_intelligence"],
        timeout=180
    ))
    
    collaborative.add_step(WorkflowStep(
        step_name="team_presentation",
        agent_type=AgentType.PRESENTATION,
        task_type="collaborative_report",
        conditions={},
        dependencies=["collaborative_validation"],
        timeout=120
    ))
    
    engine.register_workflow(collaborative)
    
    # 6. Forensic Investigation Workflow
    forensic = WorkflowTemplate(
        name="forensic_investigation",
        description="Comprehensive forensic analysis workflow"
    )
    
    forensic.add_step(WorkflowStep(
        step_name="evidence_cataloging",
        agent_type=AgentType.FILE_ANALYSIS,
        task_type="forensic_cataloging",
        conditions={},
        dependencies=[],
        timeout=180
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="timeline_analysis",
        agent_type=AgentType.RELATIONSHIP,
        task_type="analyze_extraction_chains",
        conditions={},
        dependencies=["evidence_cataloging"],
        timeout=240
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="deep_extraction",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="forensic_extraction",
        conditions={},
        dependencies=["evidence_cataloging"],
        parallel=True,
        timeout=600
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="cryptographic_evidence",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="forensic_crypto_analysis",
        conditions={},
        dependencies=["evidence_cataloging"],
        parallel=True,
        timeout=600
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="evidence_correlation",
        agent_type=AgentType.INTELLIGENCE,
        task_type="forensic_correlation",
        conditions={},
        dependencies=["timeline_analysis", "deep_extraction", "cryptographic_evidence"],
        timeout=360
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="chain_of_custody",
        agent_type=AgentType.VALIDATION,
        task_type="validate_evidence_chain",
        conditions={},
        dependencies=["evidence_correlation"],
        timeout=240
    ))
    
    forensic.add_step(WorkflowStep(
        step_name="forensic_report",
        agent_type=AgentType.PRESENTATION,
        task_type="generate_forensic_report",
        conditions={},
        dependencies=["chain_of_custody"],
        timeout=300
    ))
    
    engine.register_workflow(forensic)
    
    # 7. Machine Learning Enhanced Workflow
    ml_enhanced = WorkflowTemplate(
        name="ml_enhanced_analysis",
        description="Machine learning enhanced puzzle solving"
    )
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="ml_preprocessing",
        agent_type=AgentType.FILE_ANALYSIS,
        task_type="ml_feature_extraction",
        conditions={},
        dependencies=[],
        timeout=120
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="pattern_recognition",
        agent_type=AgentType.INTELLIGENCE,
        task_type="ml_pattern_recognition",
        conditions={},
        dependencies=["ml_preprocessing"],
        timeout=300
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="ml_stego_detection",
        agent_type=AgentType.STEGANOGRAPHY,
        task_type="ml_stego_detection",
        conditions={"file_type": ["image/*"]},
        dependencies=["pattern_recognition"],
        parallel=True,
        timeout=240
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="ml_crypto_classification",
        agent_type=AgentType.CRYPTOGRAPHY,
        task_type="ml_cipher_classification",
        conditions={},
        dependencies=["pattern_recognition"],
        parallel=True,
        timeout=240
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="ml_relationship_inference",
        agent_type=AgentType.RELATIONSHIP,
        task_type="ml_relationship_prediction",
        conditions={},
        dependencies=["pattern_recognition"],
        parallel=True,
        timeout=300
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="ml_synthesis",
        agent_type=AgentType.INTELLIGENCE,
        task_type="ml_result_synthesis",
        conditions={},
        dependencies=["ml_stego_detection", "ml_crypto_classification", "ml_relationship_inference"],
        timeout=240
    ))
    
    ml_enhanced.add_step(WorkflowStep(
        step_name="confidence_scoring",
        agent_type=AgentType.VALIDATION,
        task_type="ml_confidence_validation",
        conditions={},
        dependencies=["ml_synthesis"],
        timeout=120
    ))
    
    engine.register_workflow(ml_enhanced)


def get_workflow_recommendations(file_types: List[str], session_context: Dict[str, Any]) -> List[str]:
    """Get recommended workflows based on file types and session context"""
    recommendations = []
    
    # Always recommend quick analysis first
    recommendations.append("quick_analysis")
    
    # Check for specific file types
    has_images = any("image" in ft for ft in file_types)
    has_audio = any("audio" in ft for ft in file_types)
    has_text = any("text" in ft for ft in file_types)
    
    if has_images or has_audio:
        recommendations.append("steganography_deep_scan")
    
    if has_text or session_context.get("suspected_cipher", False):
        recommendations.append("crypto_challenge")
    
    # For comprehensive analysis
    if len(file_types) > 1:
        recommendations.append("file_analysis")
    
    # Check for collaboration mode
    if session_context.get("team_mode", False):
        recommendations.append("collaborative_puzzle_solving")
    
    # Check for forensic requirements
    if session_context.get("forensic_mode", False):
        recommendations.append("forensic_investigation")
    
    # Check for ML enhancement preference
    if session_context.get("ml_enhanced", False):
        recommendations.append("ml_enhanced_analysis")
    
    return recommendations


def get_workflow_metadata() -> Dict[str, Dict[str, Any]]:
    """Get metadata for all available workflows"""
    return {
        "file_analysis": {
            "name": "Complete File Analysis",
            "description": "Comprehensive analysis with all agents",
            "estimated_time": "5-10 minutes",
            "complexity": "high",
            "best_for": ["complex puzzles", "multiple files", "unknown content"],
            "agents_used": ["file_analysis", "steganography", "cryptography", "relationship", "intelligence", "validation", "presentation"]
        },
        "steganography_deep_scan": {
            "name": "Deep Steganographic Analysis",
            "description": "Comprehensive steganography extraction",
            "estimated_time": "10-20 minutes",
            "complexity": "high",
            "best_for": ["image files", "audio files", "suspected hidden data"],
            "agents_used": ["steganography", "intelligence", "validation"]
        },
        "crypto_challenge": {
            "name": "Cryptographic Challenge",
            "description": "Comprehensive cipher solving",
            "estimated_time": "5-15 minutes",
            "complexity": "high",
            "best_for": ["encrypted text", "cipher challenges", "cryptographic puzzles"],
            "agents_used": ["cryptography", "intelligence", "validation"]
        },
        "quick_analysis": {
            "name": "Quick Analysis",
            "description": "Fast initial assessment",
            "estimated_time": "1-2 minutes",
            "complexity": "low",
            "best_for": ["initial assessment", "time constraints", "simple files"],
            "agents_used": ["file_analysis", "steganography", "cryptography", "presentation"]
        },
        "collaborative_puzzle_solving": {
            "name": "Team Collaboration",
            "description": "Team-based puzzle solving",
            "estimated_time": "varies",
            "complexity": "medium",
            "best_for": ["team challenges", "complex puzzles", "collaborative work"],
            "agents_used": ["all agents with collaboration features"]
        },
        "forensic_investigation": {
            "name": "Forensic Investigation",
            "description": "Comprehensive forensic analysis",
            "estimated_time": "15-30 minutes",
            "complexity": "very high",
            "best_for": ["forensic challenges", "evidence analysis", "chain of custody"],
            "agents_used": ["all agents with forensic capabilities"]
        },
        "ml_enhanced_analysis": {
            "name": "ML Enhanced Analysis",
            "description": "Machine learning powered analysis",
            "estimated_time": "10-20 minutes",
            "complexity": "high",
            "best_for": ["pattern recognition", "complex relationships", "advanced analysis"],
            "agents_used": ["all agents with ML capabilities"]
        }
    }


# Workflow execution utilities
class WorkflowExecutionUtils:
    """Utilities for workflow execution and monitoring"""
    
    @staticmethod
    def estimate_execution_time(workflow_name: str, file_count: int = 1, file_sizes: List[int] = None) -> int:
        """Estimate workflow execution time in seconds"""
        base_times = {
            "quick_analysis": 60,
            "file_analysis": 300,
            "steganography_deep_scan": 600,
            "crypto_challenge": 450,
            "collaborative_puzzle_solving": 600,
            "forensic_investigation": 1200,
            "ml_enhanced_analysis": 800
        }
        
        base_time = base_times.get(workflow_name, 300)
        
        # Scale with file count
        time_multiplier = min(3.0, 1.0 + (file_count - 1) * 0.2)
        
        # Scale with file sizes if provided
        if file_sizes:
            avg_size_mb = sum(file_sizes) / len(file_sizes) / (1024 * 1024)
            size_multiplier = min(2.0, 1.0 + avg_size_mb * 0.1)
            time_multiplier *= size_multiplier
        
        return int(base_time * time_multiplier)
    
    @staticmethod
    def get_workflow_dependencies(workflow_name: str) -> List[str]:
        """Get list of required services/tools for a workflow"""
        dependencies = {
            "steganography_deep_scan": ["zsteg", "steghide", "binwalk", "exiftool"],
            "crypto_challenge": ["python-crypto", "frequency-analysis", "pattern-matching"],
            "forensic_investigation": ["exiftool", "binwalk", "volatility", "sleuthkit"],
            "ml_enhanced_analysis": ["scikit-learn", "tensorflow", "opencv"]
        }
        
        return dependencies.get(workflow_name, ["python", "postgresql"])
    
    @staticmethod
    def validate_workflow_prerequisites(workflow_name: str, session_context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate that prerequisites for workflow execution are met"""
        issues = []
        
        # Check file types for steganography workflows
        if "steganography" in workflow_name:
            file_types = session_context.get("file_types", [])
            if not any("image" in ft or "audio" in ft for ft in file_types):
                issues.append("Steganography workflow requires image or audio files")
        
        # Check for crypto workflows
        if "crypto" in workflow_name:
            has_text_content = session_context.get("has_text_content", False)
            if not has_text_content:
                issues.append("Cryptography workflow requires text content")
        
        # Check for collaborative workflows
        if "collaborative" in workflow_name:
            team_size = session_context.get("team_size", 1)
            if team_size < 2:
                issues.append("Collaborative workflow requires multiple team members")
        
        # Check system resources
        memory_available = session_context.get("memory_available_mb", 1000)
        if workflow_name in ["ml_enhanced_analysis", "forensic_investigation"] and memory_available < 2000:
            issues.append(f"Workflow {workflow_name} requires at least 2GB memory")
        
        return len(issues) == 0, issues
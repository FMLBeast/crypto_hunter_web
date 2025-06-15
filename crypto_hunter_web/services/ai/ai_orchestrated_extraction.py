#!/usr/bin/env python3
"""
AI Orchestrated Multi-Agent Extraction System
==============================================

This replaces the monolithic extraction script with an intelligent multi-agent system.
The orchestrator coordinates specialized agents to extract, analyze, and synthesize findings.

Features:
- Intelligent task prioritization
- Agent-based specialized extraction
- Cross-agent correlation analysis
- AI-powered synthesis and recommendations
- Real-time progress tracking
- Database integration with relationship mapping

Usage:
    python ai_orchestrated_extraction.py input_file.png
    python ai_orchestrated_extraction.py --analysis-only input_file.png
    python ai_orchestrated_extraction.py --deep-intelligence input_file.png
"""

import os
import sys
import time
import uuid
import asyncio
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(project_root)

# Import the agent framework and specialized agents
from crypto_hunter_web.services.agents.agent_framework import (
    OrchestrationAgent, AgentTask, TaskPriority, AgentCapability,
    orchestrator
)
from crypto_hunter_web.services.agents.specialized_agents import (
    FileAnalysisAgent, SteganographyAgent, CryptographyAgent, 
    IntelligenceAgent
)
from crypto_hunter_web.services.database.fixed_db_integration import PostgreSQLDatabaseIntegrator

class AIOrchestrator:
    """
    Main AI orchestration system that coordinates all agents
    """
    
    def __init__(self, output_dir: str = "./ai_extractions"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize orchestrator and agents
        self.orchestrator = orchestrator
        self._initialize_agents()
        
        # Database integration
        self.db_integrator = PostgreSQLDatabaseIntegrator()
        
        # Execution tracking
        self.session_id = str(uuid.uuid4())
        self.execution_start_time = None
        self.task_results: Dict[str, Any] = {}
        
        logger.info(f"🧠 AI Orchestrator initialized with session ID: {self.session_id}")

    def _initialize_agents(self):
        """Initialize and register all specialized agents"""
        # Create agent instances
        file_agent = FileAnalysisAgent()
        stego_agent = SteganographyAgent()
        crypto_agent = CryptographyAgent()
        intelligence_agent = IntelligenceAgent()
        
        # Register with orchestrator
        self.orchestrator.register_agent(file_agent)
        self.orchestrator.register_agent(stego_agent)
        self.orchestrator.register_agent(crypto_agent)
        self.orchestrator.register_agent(intelligence_agent)
        
        # Start orchestrator processing
        self.orchestrator.start_processing()
        
        logger.info("🤖 All agents registered and orchestrator started")

    async def extract_and_analyze(self, file_path: str, analysis_mode: str = "comprehensive") -> Dict[str, Any]:
        """
        Main extraction and analysis workflow
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")
        
        self.execution_start_time = time.time()
        
        logger.info(f"🚀 Starting AI orchestrated analysis")
        logger.info(f"📂 Input file: {file_path}")
        logger.info(f"🎯 Analysis mode: {analysis_mode}")
        logger.info(f"📁 Output directory: {self.output_dir}")
        
        # Create session output directory
        session_dir = self.output_dir / f"session_{self.session_id[:8]}"
        session_dir.mkdir(exist_ok=True)
        
        try:
            # Phase 1: File Analysis (Foundation)
            logger.info("\n📊 Phase 1: Foundational File Analysis")
            analysis_task_id = await self._submit_file_analysis(file_path, analysis_mode)
            
            # Phase 2: Parallel Extraction (Steganography + Cryptography)
            logger.info("\n🔍 Phase 2: Parallel Specialized Extraction")
            stego_task_id, crypto_task_id = await self._submit_parallel_extraction(
                file_path, analysis_task_id
            )
            
            # Phase 3: Wait for completion and collect results
            logger.info("\n⏳ Phase 3: Waiting for agent completion...")
            agent_results = await self._wait_for_completion([
                analysis_task_id, stego_task_id, crypto_task_id
            ], timeout=600)  # 10 minute timeout
            
            # Phase 4: Intelligence Synthesis
            logger.info("\n🧠 Phase 4: AI Intelligence Synthesis")
            synthesis_result = await self._synthesize_intelligence(agent_results)
            
            # Phase 5: Generate comprehensive report
            logger.info("\n📋 Phase 5: Generating Comprehensive Report")
            final_report = await self._generate_final_report(
                file_path, agent_results, synthesis_result, session_dir
            )
            
            # Phase 6: Database integration
            logger.info("\n💾 Phase 6: Database Integration")
            db_file_id = await self._integrate_with_database(file_path, final_report)
            
            execution_time = time.time() - self.execution_start_time
            
            # Update final report with metadata
            final_report.update({
                'session_id': self.session_id,
                'execution_time_seconds': execution_time,
                'output_directory': str(session_dir),
                'database_file_id': db_file_id,
                'orchestrator_status': self.orchestrator.get_status()
            })
            
            # Save final report
            report_file = session_dir / "ai_analysis_report.json"
            with open(report_file, 'w') as f:
                json.dump(final_report, f, indent=2, default=str)
            
            self._print_final_summary(final_report)
            
            return final_report
            
        except Exception as e:
            logger.error(f"💥 AI orchestration failed: {e}")
            raise
        finally:
            # Cleanup
            self.orchestrator.stop_processing()

    async def _submit_file_analysis(self, file_path: str, analysis_mode: str) -> str:
        """Submit file analysis task"""
        task_id = str(uuid.uuid4())
        
        task = AgentTask(
            task_id=task_id,
            agent_type="file_analysis",
            input_data={
                'file_path': file_path,
                'action': 'full_analysis' if analysis_mode == 'deep' else 'analyze'
            },
            priority=TaskPriority.HIGH,
            metadata={'required_capabilities': ['file_analysis']}
        )
        
        await self.orchestrator.submit_task(task)
        logger.info(f"  📝 Submitted file analysis task: {task_id}")
        return task_id

    async def _submit_parallel_extraction(self, file_path: str, dependency_task_id: str) -> tuple:
        """Submit parallel steganography and cryptography tasks"""
        stego_task_id = str(uuid.uuid4())
        crypto_task_id = str(uuid.uuid4())
        
        # Steganography extraction task
        stego_task = AgentTask(
            task_id=stego_task_id,
            agent_type="steganography",
            input_data={
                'file_path': file_path,
                'action': 'extract',
                'methods': ['zsteg', 'steghide', 'binwalk', 'foremost', 'strings']
            },
            priority=TaskPriority.HIGH,
            dependencies=[dependency_task_id],
            metadata={'required_capabilities': ['steganography']}
        )
        
        # Cryptography analysis task
        crypto_task = AgentTask(
            task_id=crypto_task_id,
            agent_type="cryptography",
            input_data={
                'file_path': file_path,
                'action': 'analyze'
            },
            priority=TaskPriority.HIGH,
            dependencies=[dependency_task_id],
            metadata={'required_capabilities': ['cryptography']}
        )
        
        await self.orchestrator.submit_task(stego_task)
        await self.orchestrator.submit_task(crypto_task)
        
        logger.info(f"  🔐 Submitted steganography task: {stego_task_id}")
        logger.info(f"  🔢 Submitted cryptography task: {crypto_task_id}")
        
        return stego_task_id, crypto_task_id

    async def _wait_for_completion(self, task_ids: List[str], timeout: int = 300) -> List[Dict]:
        """Wait for all tasks to complete and return results"""
        start_time = time.time()
        completed_results = []
        
        while len(completed_results) < len(task_ids):
            if time.time() - start_time > timeout:
                logger.warning(f"⚠️  Timeout waiting for tasks after {timeout}s")
                break
            
            # Check for completed tasks
            for task_id in task_ids:
                if task_id not in [r.get('task_id') for r in completed_results]:
                    if task_id in self.orchestrator.completed_tasks:
                        result = self.orchestrator.completed_tasks[task_id]
                        completed_results.append({
                            'task_id': task_id,
                            'agent_id': result.agent_id,
                            'success': result.success,
                            'output_data': result.output_data,
                            'confidence': result.confidence,
                            'execution_time': result.execution_time,
                            'error_message': result.error_message
                        })
                        logger.info(f"  ✅ Task completed: {task_id} by {result.agent_id}")
            
            await asyncio.sleep(0.5)  # Check every 500ms
        
        logger.info(f"📊 Collected {len(completed_results)} results from {len(task_ids)} tasks")
        return completed_results

    async def _synthesize_intelligence(self, agent_results: List[Dict]) -> Dict[str, Any]:
        """Use IntelligenceAgent to synthesize findings"""
        synthesis_task_id = str(uuid.uuid4())
        
        synthesis_task = AgentTask(
            task_id=synthesis_task_id,
            agent_type="intelligence",
            input_data={
                'agent_results': agent_results,
                'synthesis_type': 'comprehensive'
            },
            priority=TaskPriority.CRITICAL,
            metadata={'required_capabilities': ['intelligence']}
        )
        
        await self.orchestrator.submit_task(synthesis_task)
        
        # Wait for synthesis completion
        synthesis_results = await self._wait_for_completion([synthesis_task_id], timeout=120)
        
        if synthesis_results and synthesis_results[0]['success']:
            logger.info("  🧠 Intelligence synthesis completed successfully")
            return synthesis_results[0]['output_data']
        else:
            logger.warning("  ⚠️  Intelligence synthesis failed or incomplete")
            return {'error': 'Synthesis failed'}

    async def _generate_final_report(self, file_path: str, agent_results: List[Dict], 
                                   synthesis: Dict[str, Any], session_dir: Path) -> Dict[str, Any]:
        """Generate comprehensive final report"""
        report = {
            'metadata': {
                'input_file': file_path,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'session_id': self.session_id,
                'agent_framework_version': '1.0.0'
            },
            'agent_results': agent_results,
            'intelligence_synthesis': synthesis,
            'performance_metrics': self._calculate_performance_metrics(agent_results),
            'recommendations': synthesis.get('recommendations', []),
            'threat_assessment': synthesis.get('threat_assessment', {}),
            'extracted_files': self._collect_extracted_files(agent_results, session_dir),
            'confidence_scores': self._analyze_confidence_scores(agent_results, synthesis)
        }
        
        return report

    async def _integrate_with_database(self, file_path: str, report: Dict[str, Any]) -> Optional[int]:
        """Integrate results with database"""
        try:
            # Convert report to format expected by database integrator
            db_results = {
                'extraction_results': [],
                'duration_seconds': report.get('execution_time_seconds', 0),
                'tree_stats': {
                    'total_files': len(report.get('extracted_files', [])),
                    'total_size_bytes': sum(
                        os.path.getsize(f) for f in report.get('extracted_files', []) 
                        if os.path.exists(f)
                    ),
                    'methods': {}
                }
            }
            
            # Convert agent results to extraction results format
            for result in report.get('agent_results', []):
                if result.get('success') and result.get('agent_id') == 'steganography_extractor':
                    output_data = result.get('output_data', {})
                    extraction_methods = output_data.get('extraction_results', [])
                    db_results['extraction_results'].extend(extraction_methods)
            
            # Store in database
            db_file_id = self.db_integrator.store_extraction_results(
                file_path, db_results, user_id=1
            )
            
            if db_file_id:
                logger.info(f"  💾 Results stored in database with file ID: {db_file_id}")
            
            return db_file_id
            
        except Exception as e:
            logger.error(f"  ❌ Database integration failed: {e}")
            return None

    def _calculate_performance_metrics(self, agent_results: List[Dict]) -> Dict[str, Any]:
        """Calculate performance metrics"""
        total_execution_time = sum(r.get('execution_time', 0) for r in agent_results)
        successful_agents = len([r for r in agent_results if r.get('success', False)])
        average_confidence = sum(r.get('confidence', 0) for r in agent_results) / len(agent_results) if agent_results else 0
        
        return {
            'total_execution_time': total_execution_time,
            'successful_agents': successful_agents,
            'total_agents': len(agent_results),
            'success_rate': successful_agents / len(agent_results) if agent_results else 0,
            'average_confidence': average_confidence,
            'parallel_efficiency': self._calculate_parallel_efficiency(agent_results)
        }

    def _calculate_parallel_efficiency(self, agent_results: List[Dict]) -> float:
        """Calculate how well parallel execution worked"""
        if len(agent_results) < 2:
            return 1.0
        
        total_sequential_time = sum(r.get('execution_time', 0) for r in agent_results)
        actual_wall_time = time.time() - self.execution_start_time
        
        if actual_wall_time > 0:
            return min(total_sequential_time / actual_wall_time, len(agent_results))
        return 1.0

    def _collect_extracted_files(self, agent_results: List[Dict], session_dir: Path) -> List[str]:
        """Collect all extracted files from all agents"""
        extracted_files = []
        
        for result in agent_results:
            if result.get('success'):
                output_data = result.get('output_data', {})
                
                # From steganography agent
                if 'extracted_files' in output_data:
                    extracted_files.extend(output_data['extracted_files'])
                
                # From extraction results
                if 'extraction_results' in output_data:
                    for extraction in output_data['extraction_results']:
                        extracted_files.extend(extraction.get('extracted_files', []))
        
        # Filter to only existing files
        return [f for f in extracted_files if os.path.exists(f)]

    def _analyze_confidence_scores(self, agent_results: List[Dict], synthesis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze confidence scores across all components"""
        agent_confidences = [r.get('confidence', 0) for r in agent_results]
        synthesis_confidence = synthesis.get('confidence', 0) if 'confidence' in synthesis else 0
        
        return {
            'agent_scores': {
                result.get('agent_id', 'unknown'): result.get('confidence', 0)
                for result in agent_results
            },
            'synthesis_score': synthesis_confidence,
            'overall_average': (sum(agent_confidences) + synthesis_confidence) / (len(agent_confidences) + 1) if agent_confidences else 0,
            'highest_confidence_agent': max(agent_results, key=lambda x: x.get('confidence', 0)).get('agent_id', 'none') if agent_results else 'none'
        }

    def _print_final_summary(self, report: Dict[str, Any]):
        """Print comprehensive final summary"""
        print("\n" + "=" * 80)
        print("🎉 AI ORCHESTRATED EXTRACTION COMPLETED")
        print("=" * 80)
        
        # Basic metrics
        metrics = report.get('performance_metrics', {})
        print(f"📊 Performance Summary:")
        print(f"   ⏱️  Total execution time: {metrics.get('total_execution_time', 0):.2f}s")
        print(f"   🤖 Successful agents: {metrics.get('successful_agents', 0)}/{metrics.get('total_agents', 0)}")
        print(f"   📈 Success rate: {metrics.get('success_rate', 0):.1%}")
        print(f"   🎯 Average confidence: {metrics.get('average_confidence', 0):.2f}")
        print(f"   ⚡ Parallel efficiency: {metrics.get('parallel_efficiency', 0):.1f}x")
        
        # Findings summary
        synthesis = report.get('intelligence_synthesis', {})
        key_findings = synthesis.get('key_findings', [])
        correlations = synthesis.get('cross_agent_correlations', [])
        
        print(f"\n🔍 Discovery Summary:")
        print(f"   📋 Key findings: {len(key_findings)}")
        print(f"   🔗 Cross-agent correlations: {len(correlations)}")
        print(f"   📁 Total extracted files: {len(report.get('extracted_files', []))}")
        
        # Top findings
        if key_findings:
            print(f"\n🏆 Top Findings:")
            for i, finding in enumerate(key_findings[:3], 1):
                print(f"   {i}. {finding.get('details', 'Unknown finding')} (confidence: {finding.get('confidence', 0):.2f})")
        
        # Recommendations
        recommendations = synthesis.get('recommendations', [])
        if recommendations:
            print(f"\n💡 AI Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. {rec}")
        
        # Threat assessment
        threat = synthesis.get('threat_assessment', {})
        if threat:
            threat_level = threat.get('threat_level', 'unknown')
            print(f"\n🚨 Threat Assessment: {threat_level.upper()}")
            if threat.get('indicators'):
                print(f"   📍 Indicators: {', '.join(threat['indicators'])}")
        
        # Output locations
        print(f"\n📂 Output Locations:")
        print(f"   📁 Session directory: {report.get('output_directory', 'N/A')}")
        print(f"   💾 Database file ID: {report.get('database_file_id', 'N/A')}")
        print(f"   📋 Report file: {report.get('output_directory', 'N/A')}/ai_analysis_report.json")
        
        print("=" * 80)


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AI Orchestrated Multi-Agent Crypto Hunter')
    parser.add_argument('input_file', help='Input file to analyze')
    parser.add_argument('--output-dir', default='./ai_extractions', help='Output directory')
    parser.add_argument('--analysis-mode', choices=['quick', 'comprehensive', 'deep'], 
                       default='comprehensive', help='Analysis depth')
    parser.add_argument('--timeout', type=int, default=600, help='Maximum execution time in seconds')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print(f"❌ Input file not found: {args.input_file}")
        return 1
    
    try:
        # Initialize AI orchestrator
        ai_orchestrator = AIOrchestrator(output_dir=args.output_dir)
        
        # Run extraction and analysis
        result = await ai_orchestrator.extract_and_analyze(
            args.input_file, 
            analysis_mode=args.analysis_mode
        )
        
        print(f"\n✅ AI orchestrated analysis completed successfully!")
        print(f"📊 Session ID: {result['session_id']}")
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
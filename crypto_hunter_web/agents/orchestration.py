"""
crypto_hunter_web/agents/orchestration.py
Agent orchestration engine for intelligent task coordination
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
import json

from .base import (
    BaseAgent, AgentTask, AgentResult, AgentType, TaskPriority, TaskStatus,
    agent_registry, task_queue
)

logger = logging.getLogger(__name__)


@dataclass
class WorkflowStep:
    """Definition of a workflow step"""
    step_name: str
    agent_type: AgentType
    task_type: str
    conditions: Dict[str, Any]
    dependencies: List[str]
    parallel: bool = False
    optional: bool = False
    timeout_seconds: int = 300


class WorkflowTemplate:
    """Template for multi-agent workflows"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.steps: List[WorkflowStep] = []
        self.global_conditions: Dict[str, Any] = {}
    
    def add_step(self, step: WorkflowStep):
        """Add a step to the workflow"""
        self.steps.append(step)
    
    def validate(self) -> bool:
        """Validate workflow dependencies"""
        step_names = {step.step_name for step in self.steps}
        
        for step in self.steps:
            for dep in step.dependencies:
                if dep not in step_names:
                    logger.error(f"Workflow {self.name}: Step {step.step_name} depends on unknown step {dep}")
                    return False
        
        return True


class OrchestrationEngine:
    """Main orchestration engine for agent coordination"""
    
    def __init__(self):
        self.active_workflows: Dict[str, 'WorkflowExecution'] = {}
        self.workflow_templates: Dict[str, WorkflowTemplate] = {}
        self.running = False
        self.max_concurrent_workflows = 10
        self.task_timeout = 600
        
        # Register built-in workflow templates
        self._register_builtin_workflows()
    
    def _register_builtin_workflows(self):
        """Register built-in workflow templates"""
        
        # File Analysis Workflow
        file_analysis = WorkflowTemplate(
            name="file_analysis",
            description="Complete file analysis workflow"
        )
        
        file_analysis.add_step(WorkflowStep(
            step_name="initial_analysis",
            agent_type=AgentType.FILE_ANALYSIS,
            task_type="analyze_file",
            conditions={},
            dependencies=[]
        ))
        
        file_analysis.add_step(WorkflowStep(
            step_name="steganography_scan",
            agent_type=AgentType.STEGANOGRAPHY,
            task_type="extract_hidden_data",
            conditions={"file_type": ["image/*", "audio/*"]},
            dependencies=["initial_analysis"],
            parallel=True
        ))
        
        file_analysis.add_step(WorkflowStep(
            step_name="crypto_analysis",
            agent_type=AgentType.CRYPTOGRAPHY,
            task_type="analyze_crypto_patterns",
            conditions={},
            dependencies=["initial_analysis"],
            parallel=True
        ))
        
        file_analysis.add_step(WorkflowStep(
            step_name="relationship_analysis",
            agent_type=AgentType.RELATIONSHIP,
            task_type="find_relationships",
            conditions={},
            dependencies=["initial_analysis", "steganography_scan", "crypto_analysis"]
        ))
        
        file_analysis.add_step(WorkflowStep(
            step_name="intelligence_synthesis",
            agent_type=AgentType.INTELLIGENCE,
            task_type="synthesize_findings",
            conditions={},
            dependencies=["relationship_analysis"]
        ))
        
        self.workflow_templates["file_analysis"] = file_analysis
        
        # Steganography Deep Scan Workflow
        stego_deep = WorkflowTemplate(
            name="steganography_deep_scan",
            description="Deep steganography analysis"
        )
        
        stego_deep.add_step(WorkflowStep(
            step_name="basic_stegano",
            agent_type=AgentType.STEGANOGRAPHY,
            task_type="run_basic_extractors",
            conditions={},
            dependencies=[]
        ))
        
        stego_deep.add_step(WorkflowStep(
            step_name="advanced_stegano",
            agent_type=AgentType.STEGANOGRAPHY,
            task_type="run_advanced_extractors",
            conditions={},
            dependencies=["basic_stegano"]
        ))
        
        stego_deep.add_step(WorkflowStep(
            step_name="frequency_analysis",
            agent_type=AgentType.STEGANOGRAPHY,
            task_type="frequency_domain_analysis",
            conditions={"file_type": ["image/*"]},
            dependencies=["basic_stegano"],
            parallel=True
        ))
        
        self.workflow_templates["steganography_deep_scan"] = stego_deep
        
        # Crypto Challenge Workflow
        crypto_challenge = WorkflowTemplate(
            name="crypto_challenge",
            description="Complete cryptographic challenge analysis"
        )
        
        crypto_challenge.add_step(WorkflowStep(
            step_name="cipher_detection",
            agent_type=AgentType.CRYPTOGRAPHY,
            task_type="detect_ciphers",
            conditions={},
            dependencies=[]
        ))
        
        crypto_challenge.add_step(WorkflowStep(
            step_name="pattern_analysis",
            agent_type=AgentType.CRYPTOGRAPHY,
            task_type="analyze_patterns",
            conditions={},
            dependencies=["cipher_detection"],
            parallel=True
        ))
        
        crypto_challenge.add_step(WorkflowStep(
            step_name="frequency_analysis",
            agent_type=AgentType.CRYPTOGRAPHY,
            task_type="frequency_analysis",
            conditions={},
            dependencies=["cipher_detection"],
            parallel=True
        ))
        
        crypto_challenge.add_step(WorkflowStep(
            step_name="decryption_attempts",
            agent_type=AgentType.CRYPTOGRAPHY,
            task_type="attempt_decryption",
            conditions={},
            dependencies=["pattern_analysis", "frequency_analysis"]
        ))
        
        self.workflow_templates["crypto_challenge"] = crypto_challenge
        
        logger.info(f"Registered {len(self.workflow_templates)} workflow templates")
    
    def register_workflow_template(self, template: WorkflowTemplate) -> bool:
        """Register a new workflow template"""
        if not template.validate():
            return False
        
        self.workflow_templates[template.name] = template
        logger.info(f"Registered workflow template: {template.name}")
        return True
    
    async def execute_workflow(self, 
                             workflow_name: str, 
                             initial_data: Dict[str, Any],
                             session_id: Optional[str] = None) -> str:
        """Execute a workflow and return workflow ID"""
        
        if workflow_name not in self.workflow_templates:
            raise ValueError(f"Unknown workflow: {workflow_name}")
        
        if len(self.active_workflows) >= self.max_concurrent_workflows:
            raise RuntimeError("Maximum concurrent workflows reached")
        
        template = self.workflow_templates[workflow_name]
        workflow_execution = WorkflowExecution(template, initial_data, session_id)
        
        self.active_workflows[workflow_execution.workflow_id] = workflow_execution
        
        # Start workflow execution
        asyncio.create_task(self._execute_workflow_async(workflow_execution))
        
        logger.info(f"Started workflow {workflow_name} with ID {workflow_execution.workflow_id}")
        return workflow_execution.workflow_id
    
    async def _execute_workflow_async(self, workflow: 'WorkflowExecution'):
        """Execute workflow asynchronously"""
        try:
            await workflow.execute()
        except Exception as e:
            logger.exception(f"Workflow {workflow.workflow_id} failed: {e}")
            workflow.status = TaskStatus.FAILED
            workflow.error = str(e)
        finally:
            # Clean up completed workflow after delay
            await asyncio.sleep(300)  # Keep results for 5 minutes
            self.active_workflows.pop(workflow.workflow_id, None)
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow execution status"""
        workflow = self.active_workflows.get(workflow_id)
        if workflow:
            return workflow.get_status()
        return None
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel a running workflow"""
        workflow = self.active_workflows.get(workflow_id)
        if workflow:
            workflow.cancel()
            return True
        return False
    
    async def start(self):
        """Start the orchestration engine"""
        self.running = True
        logger.info("Orchestration engine started")
        
        # Start task processing loop
        asyncio.create_task(self._process_tasks_loop())
    
    async def stop(self):
        """Stop the orchestration engine"""
        self.running = False
        logger.info("Orchestration engine stopped")
    
    async def _process_tasks_loop(self):
        """Main task processing loop"""
        while self.running:
            try:
                # Get next task from queue
                task = task_queue.get_next_task()
                
                if task:
                    # Find available agent
                    agent = agent_registry.find_available_agent(task)
                    
                    if agent:
                        # Mark task as running
                        task_queue.mark_running(task)
                        
                        # Execute task
                        asyncio.create_task(self._execute_task_with_agent(agent, task))
                    else:
                        # No available agent, put task back in queue
                        task_queue.add_task(task)
                
                # Sleep briefly to prevent busy waiting
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.exception(f"Error in task processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _execute_task_with_agent(self, agent: BaseAgent, task: AgentTask):
        """Execute task with specific agent"""
        try:
            result = await agent.process_task(task)
            task_queue.complete_task(result)
            
            # Queue any follow-up tasks
            for next_task in result.next_tasks:
                task_queue.add_task(next_task)
                
        except Exception as e:
            logger.exception(f"Error executing task {task.task_id} with agent {agent.agent_id}: {e}")
            
            # Create error result
            error_result = AgentResult(
                task_id=task.task_id,
                agent_id=agent.agent_id,
                success=False,
                error=str(e)
            )
            task_queue.complete_task(error_result)


class WorkflowExecution:
    """Manages execution of a specific workflow instance"""
    
    def __init__(self, template: WorkflowTemplate, initial_data: Dict[str, Any], session_id: Optional[str] = None):
        self.workflow_id = f"wf_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{hash(str(initial_data)) % 10000:04d}"
        self.template = template
        self.initial_data = initial_data
        self.session_id = session_id
        self.status = TaskStatus.PENDING
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None
        
        # Step execution tracking
        self.step_results: Dict[str, AgentResult] = {}
        self.completed_steps: Set[str] = set()
        self.running_steps: Set[str] = set()
        self.failed_steps: Set[str] = set()
        
        # Data passing between steps
        self.workflow_data: Dict[str, Any] = initial_data.copy()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current workflow status"""
        return {
            'workflow_id': self.workflow_id,
            'template_name': self.template.name,
            'status': self.status.value,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error': self.error,
            'total_steps': len(self.template.steps),
            'completed_steps': len(self.completed_steps),
            'running_steps': len(self.running_steps),
            'failed_steps': len(self.failed_steps),
            'session_id': self.session_id,
            'step_results': {
                step_name: result.to_dict() 
                for step_name, result in self.step_results.items()
            }
        }
    
    async def execute(self):
        """Execute the workflow"""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.utcnow()
        
        try:
            # Execute steps according to dependencies
            await self._execute_steps()
            
            if self.failed_steps:
                self.status = TaskStatus.FAILED
                self.error = f"Failed steps: {', '.join(self.failed_steps)}"
            else:
                self.status = TaskStatus.COMPLETED
                
        except Exception as e:
            self.status = TaskStatus.FAILED
            self.error = str(e)
            raise
        finally:
            self.completed_at = datetime.utcnow()
    
    async def _execute_steps(self):
        """Execute workflow steps respecting dependencies"""
        remaining_steps = set(step.step_name for step in self.template.steps)
        
        while remaining_steps:
            # Find steps that can be executed (dependencies met)
            ready_steps = []
            
            for step in self.template.steps:
                if step.step_name not in remaining_steps:
                    continue
                
                # Check if dependencies are met
                dependencies_met = all(
                    dep in self.completed_steps 
                    for dep in step.dependencies
                )
                
                if dependencies_met and self._check_step_conditions(step):
                    ready_steps.append(step)
            
            if not ready_steps:
                # No more steps can be executed
                if self.running_steps:
                    # Wait for running steps to complete
                    await asyncio.sleep(0.5)
                    continue
                else:
                    # Deadlock or completion
                    break
            
            # Execute ready steps
            tasks = []
            for step in ready_steps:
                if step.parallel:
                    tasks.append(self._execute_step(step))
                else:
                    await self._execute_step(step)
                
                remaining_steps.discard(step.step_name)
            
            # Wait for parallel tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    def _check_step_conditions(self, step: WorkflowStep) -> bool:
        """Check if step conditions are met"""
        for condition_key, condition_value in step.conditions.items():
            if condition_key not in self.workflow_data:
                if not step.optional:
                    return False
                continue
            
            data_value = self.workflow_data[condition_key]
            
            if isinstance(condition_value, list):
                # Check if data_value matches any pattern in list
                matched = False
                for pattern in condition_value:
                    if isinstance(pattern, str) and pattern.endswith('/*'):
                        # Wildcard match
                        prefix = pattern[:-2]
                        if str(data_value).startswith(prefix):
                            matched = True
                            break
                    elif data_value == pattern:
                        matched = True
                        break
                
                if not matched:
                    return False
            elif data_value != condition_value:
                return False
        
        return True
    
    async def _execute_step(self, step: WorkflowStep):
        """Execute a single workflow step"""
        step_name = step.step_name
        self.running_steps.add(step_name)
        
        try:
            # Create task for this step
            task = AgentTask(
                task_type=step.task_type,
                agent_type=step.agent_type,
                priority=TaskPriority.NORMAL,
                payload=self.workflow_data.copy(),
                context={
                    'workflow_id': self.workflow_id,
                    'step_name': step_name,
                    'session_id': self.session_id
                },
                timeout_seconds=step.timeout_seconds
            )
            
            # Find and execute with agent
            agent = agent_registry.find_available_agent(task)
            if not agent:
                raise RuntimeError(f"No available agent for step {step_name}")
            
            result = await agent.process_task(task)
            
            # Store result
            self.step_results[step_name] = result
            
            if result.success:
                self.completed_steps.add(step_name)
                
                # Merge result data into workflow data
                if result.data:
                    self.workflow_data.update(result.data)
                
                logger.info(f"Workflow {self.workflow_id} completed step {step_name}")
            else:
                self.failed_steps.add(step_name)
                logger.error(f"Workflow {self.workflow_id} step {step_name} failed: {result.error}")
                
        except Exception as e:
            self.failed_steps.add(step_name)
            logger.exception(f"Workflow {self.workflow_id} step {step_name} exception: {e}")
        finally:
            self.running_steps.discard(step_name)
    
    def cancel(self):
        """Cancel workflow execution"""
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.utcnow()


# Global orchestration engine instance
orchestration_engine = OrchestrationEngine()

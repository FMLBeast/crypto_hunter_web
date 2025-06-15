"""
crypto_hunter_web/agents/base.py
Core agent framework for Crypto Hunter multi-agent architecture
"""

import asyncio
import uuid
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Union, Callable
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class AgentType(Enum):
    """Agent type classifications"""
    ORCHESTRATION = "orchestration"
    FILE_ANALYSIS = "file_analysis"
    STEGANOGRAPHY = "steganography"
    CRYPTOGRAPHY = "cryptography"
    INTELLIGENCE = "intelligence"
    RELATIONSHIP = "relationship"
    PRESENTATION = "presentation"
    VALIDATION = "validation"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class AgentTask:
    """Task definition for agent execution"""
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = ""
    agent_type: AgentType = AgentType.FILE_ANALYSIS
    priority: TaskPriority = TaskPriority.NORMAL
    payload: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    timeout_seconds: int = 300
    retries: int = 0
    max_retries: int = 3
    parent_task_id: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        return {
            'task_id': self.task_id,
            'task_type': self.task_type,
            'agent_type': self.agent_type.value,
            'priority': self.priority.value,
            'payload': self.payload,
            'context': self.context,
            'created_at': self.created_at.isoformat(),
            'timeout_seconds': self.timeout_seconds,
            'retries': self.retries,
            'max_retries': self.max_retries,
            'parent_task_id': self.parent_task_id,
            'session_id': self.session_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentTask':
        """Create task from dictionary"""
        data = data.copy()
        data['agent_type'] = AgentType(data['agent_type'])
        data['priority'] = TaskPriority(data['priority'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        return cls(**data)


@dataclass
class AgentResult:
    """Result from agent task execution"""
    task_id: str
    agent_id: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    next_tasks: List[AgentTask] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'task_id': self.task_id,
            'agent_id': self.agent_id,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'warnings': self.warnings,
            'execution_time': self.execution_time,
            'metadata': self.metadata,
            'next_tasks': [task.to_dict() for task in self.next_tasks],
            'completed_at': self.completed_at.isoformat()
        }


class BaseAgent(ABC):
    """Base class for all Crypto Hunter agents"""
    
    def __init__(self, agent_id: Optional[str] = None):
        self.agent_id = agent_id or f"{self.agent_type.value}_{uuid.uuid4().hex[:8]}"
        self.status = "initialized"
        self.active_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: List[str] = []
        self.error_count = 0
        self.last_heartbeat = datetime.utcnow()
        self.max_concurrent_tasks = 5
        self.capabilities: Dict[str, Any] = {}
        
    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """Return the agent type"""
        pass
    
    @property
    @abstractmethod
    def supported_tasks(self) -> List[str]:
        """Return list of supported task types"""
        pass
    
    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a task and return result"""
        pass
    
    def can_handle_task(self, task: AgentTask) -> bool:
        """Check if agent can handle the given task"""
        return (
            task.agent_type == self.agent_type and
            task.task_type in self.supported_tasks and
            len(self.active_tasks) < self.max_concurrent_tasks
        )
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process a task with error handling and logging"""
        start_time = time.time()
        
        try:
            # Add to active tasks
            self.active_tasks[task.task_id] = task
            
            logger.info(f"Agent {self.agent_id} starting task {task.task_id} ({task.task_type})")
            
            # Execute the task
            result = await self.execute_task(task)
            result.execution_time = time.time() - start_time
            
            # Handle success
            if result.success:
                logger.info(f"Agent {self.agent_id} completed task {task.task_id} in {result.execution_time:.2f}s")
                self.completed_tasks.append(task.task_id)
            else:
                logger.error(f"Agent {self.agent_id} failed task {task.task_id}: {result.error}")
                self.error_count += 1
                
        except asyncio.TimeoutError:
            result = AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Task timeout after {task.timeout_seconds}s",
                execution_time=time.time() - start_time
            )
            self.error_count += 1
            
        except Exception as e:
            result = AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                success=False,
                error=f"Unexpected error: {str(e)}",
                execution_time=time.time() - start_time
            )
            self.error_count += 1
            logger.exception(f"Agent {self.agent_id} task {task.task_id} failed with exception")
            
        finally:
            # Remove from active tasks
            self.active_tasks.pop(task.task_id, None)
            self.last_heartbeat = datetime.utcnow()
            
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status information"""
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type.value,
            'status': self.status,
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.completed_tasks),
            'error_count': self.error_count,
            'last_heartbeat': self.last_heartbeat.isoformat(),
            'capabilities': self.capabilities,
            'supported_tasks': self.supported_tasks
        }
    
    def reset_error_count(self):
        """Reset error counter"""
        self.error_count = 0


class AgentRegistry:
    """Registry for managing agent instances"""
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_types: Dict[AgentType, List[BaseAgent]] = {
            agent_type: [] for agent_type in AgentType
        }
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent instance"""
        self.agents[agent.agent_id] = agent
        self.agent_types[agent.agent_type].append(agent)
        logger.info(f"Registered agent {agent.agent_id} of type {agent.agent_type.value}")
    
    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            agent = self.agents.pop(agent_id)
            self.agent_types[agent.agent_type].remove(agent)
            logger.info(f"Unregistered agent {agent_id}")
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """Get all agents of a specific type"""
        return self.agent_types.get(agent_type, [])
    
    def find_available_agent(self, task: AgentTask) -> Optional[BaseAgent]:
        """Find an available agent that can handle the task"""
        candidates = self.get_agents_by_type(task.agent_type)
        
        for agent in candidates:
            if agent.can_handle_task(task):
                return agent
        
        return None
    
    def get_all_agents_status(self) -> Dict[str, Any]:
        """Get status of all registered agents"""
        return {
            agent_id: agent.get_status() 
            for agent_id, agent in self.agents.items()
        }


# Global agent registry
agent_registry = AgentRegistry()


class TaskQueue:
    """Priority queue for agent tasks"""
    
    def __init__(self):
        self.tasks: List[AgentTask] = []
        self.running_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentResult] = {}
        self.failed_tasks: Dict[str, AgentResult] = {}
    
    def add_task(self, task: AgentTask):
        """Add task to queue"""
        # Insert task based on priority
        priority_value = task.priority.value
        inserted = False
        
        for i, existing_task in enumerate(self.tasks):
            if existing_task.priority.value > priority_value:
                self.tasks.insert(i, task)
                inserted = True
                break
        
        if not inserted:
            self.tasks.append(task)
        
        logger.info(f"Added task {task.task_id} to queue with priority {task.priority.value}")
    
    def get_next_task(self) -> Optional[AgentTask]:
        """Get next task from queue"""
        if self.tasks:
            return self.tasks.pop(0)
        return None
    
    def mark_running(self, task: AgentTask):
        """Mark task as running"""
        self.running_tasks[task.task_id] = task
    
    def complete_task(self, result: AgentResult):
        """Mark task as completed"""
        task_id = result.task_id
        
        if task_id in self.running_tasks:
            del self.running_tasks[task_id]
        
        if result.success:
            self.completed_tasks[task_id] = result
        else:
            self.failed_tasks[task_id] = result
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get queue status"""
        return {
            'pending_tasks': len(self.tasks),
            'running_tasks': len(self.running_tasks),
            'completed_tasks': len(self.completed_tasks),
            'failed_tasks': len(self.failed_tasks)
        }


# Global task queue
task_queue = TaskQueue()

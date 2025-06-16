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
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    def find_available_agent(self, task: AgentTask) -> Optional[BaseAgent]:
        """Find an available agent that can handle the task"""
        candidates = self.agent_types.get(task.agent_type, [])
        
        for agent in candidates:
            if len(agent.active_tasks) < agent.max_concurrent_tasks:
                return agent
        
        return None


class TaskQueue:
    """Priority queue for agent tasks"""
    
    def __init__(self):
        self.tasks: List[AgentTask] = []
        self.running_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentResult] = {}
    
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


# Global instances
agent_registry = AgentRegistry()
task_queue = TaskQueue()

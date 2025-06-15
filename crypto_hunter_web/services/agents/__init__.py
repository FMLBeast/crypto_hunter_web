"""
Agent Framework Package

This package provides the agent-based architecture for the Crypto Hunter application.
"""

from .agent_framework import (
    AgentStatus, TaskPriority, AgentCapability, AgentTask, AgentResult,
    AgentExecution, BaseAgent, OrchestrationAgent
)

__all__ = [
    'AgentStatus', 'TaskPriority', 'AgentCapability', 'AgentTask', 'AgentResult',
    'AgentExecution', 'BaseAgent', 'OrchestrationAgent'
]
# Minimal agent base
class AgentType:
    FILE_ANALYSIS = "file_analysis"

class BaseAgent:
    def __init__(self):
        self.agent_id = "basic_agent"

agent_registry = object()  # Placeholder
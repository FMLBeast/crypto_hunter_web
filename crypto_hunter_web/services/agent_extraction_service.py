# Minimal agent service
def create_agent_tables():
    pass

class AgentExtractionService:
    def __init__(self):
        self.initialized = False
    
    def initialize(self):
        self.initialized = True

agent_extraction_service = AgentExtractionService()
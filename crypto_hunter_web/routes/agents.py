from flask import Blueprint, request, jsonify, current_app
from crypto_hunter_web.services.agent_integration import agent_integration_service
from crypto_hunter_web.agents.base import AgentTask, AgentType, TaskPriority
import asyncio

agents_bp = Blueprint('agents', __name__, url_prefix='/api/agents')

@agents_bp.route('/status', methods=['GET'])
def get_agent_status():
    """Get agent system status"""
    try:
        from crypto_hunter_web.agents.base import agent_registry
        return jsonify({
            'success': True,
            'agents_registered': len(agent_registry.agents),
            'agent_types': [agent.agent_type.value for agent in agent_registry.agents.values()],
            'system_status': 'operational'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@agents_bp.route('/analyze', methods=['POST'])
def start_agent_analysis():
    """Start multi-agent analysis"""
    try:
        data = request.get_json()
        
        # Create analysis task
        task = AgentTask(
            task_type=data.get('task_type', 'generate_hypotheses'),
            agent_type=AgentType(data.get('agent_type', 'intelligence')),
            priority=TaskPriority.NORMAL,
            payload=data.get('payload', {}),
            context=data.get('context', {})
        )
        
        # For now, return task created (async execution would be added later)
        return jsonify({
            'success': True,
            'task_id': task.task_id,
            'message': 'Analysis task created',
            'task_type': task.task_type,
            'agent_type': task.agent_type.value
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@agents_bp.route('/test', methods=['POST'])
def test_agents():
    """Test agent functionality"""
    try:
        # Test intelligence agent
        from crypto_hunter_web.agents.base import agent_registry
        from crypto_hunter_web.agents.specialized import IntelligenceAgent
        
        # Make sure intelligence agent is registered
        intel_agent = None
        for agent in agent_registry.agents.values():
            if agent.agent_type == AgentType.INTELLIGENCE:
                intel_agent = agent
                break
        
        if not intel_agent:
            intel_agent = IntelligenceAgent()
            agent_registry.register_agent(intel_agent)
        
        # Create test task
        task = AgentTask(
            task_type='generate_hypotheses',
            agent_type=AgentType.INTELLIGENCE,
            payload={
                'file_type': 'image/png',
                'entropy': 7.8,
                'findings': ['high_entropy', 'steganography_indicators']
            }
        )
        
        # Execute synchronously for API response
        import asyncio
        async def run_test():
            return await intel_agent.execute_task(task)
        
        result = asyncio.run(run_test())
        
        return jsonify({
            'success': result.success,
            'agent_id': result.agent_id,
            'data': result.data,
            'execution_time': result.execution_time
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

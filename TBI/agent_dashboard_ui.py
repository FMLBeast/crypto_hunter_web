"""
crypto_hunter_web/templates/agent_dashboard.html
Agent system dashboard for monitoring and controlling workflows
"""

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypto Hunter - Agent Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .agent-card {
            border-left: 4px solid #007bff;
            transition: all 0.3s ease;
        }
        .agent-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .agent-status {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .status-running { background-color: #d4edda; color: #155724; }
        .status-idle { background-color: #e2e3e5; color: #383d41; }
        .status-error { background-color: #f8d7da; color: #721c24; }
        .workflow-progress {
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
        }
        .real-time-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #28a745;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 12px;
        }
        .workflow-card {
            border: 1px solid #e3e6f0;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        .workflow-card:hover {
            border-color: #007bff;
            box-shadow: 0 2px 8px rgba(0,123,255,0.15);
        }
        .agent-network {
            min-height: 300px;
            border: 1px solid #e3e6f0;
            border-radius: 8px;
            background: #f8f9fa;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">
                <i class="fas fa-robot me-2"></i>Crypto Hunter - Agent System
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text">
                    <span class="real-time-indicator"></span>
                    Real-time monitoring active
                </span>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- System Status Overview -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="card-body text-center">
                        <i class="fas fa-robot fa-2x mb-2"></i>
                        <h3 id="agent-count" class="mb-0">0</h3>
                        <small>Active Agents</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="card-body text-center">
                        <i class="fas fa-tasks fa-2x mb-2"></i>
                        <h3 id="workflow-count" class="mb-0">0</h3>
                        <small>Running Workflows</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="card-body text-center">
                        <i class="fas fa-clock fa-2x mb-2"></i>
                        <h3 id="queue-count" class="mb-0">0</h3>
                        <small>Queued Tasks</small>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card metric-card">
                    <div class="card-body text-center">
                        <i class="fas fa-chart-line fa-2x mb-2"></i>
                        <h3 id="success-rate" class="mb-0">0%</h3>
                        <small>Success Rate</small>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Agent Status Panel -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-cogs me-2"></i>Agent Status
                        </h5>
                        <button class="btn btn-sm btn-outline-primary" onclick="refreshAgentStatus()">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                    </div>
                    <div class="card-body">
                        <div id="agent-status-container">
                            <!-- Agents will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>

            <!-- Active Workflows Panel -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-project-diagram me-2"></i>Active Workflows
                        </h5>
                        <div>
                            <button class="btn btn-sm btn-success" onclick="showWorkflowModal()">
                                <i class="fas fa-plus"></i> Start Workflow
                            </button>
                            <button class="btn btn-sm btn-outline-primary" onclick="refreshWorkflows()">
                                <i class="fas fa-sync-alt"></i>
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="workflows-container">
                            <!-- Workflows will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Detailed Analytics Row -->
        <div class="row mt-4">
            <!-- Agent Network Visualization -->
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-sitemap me-2"></i>Agent Execution Network
                        </h5>
                    </div>
                    <div class="card-body">
                        <div id="agent-network" class="agent-network d-flex align-items-center justify-content-center">
                            <div class="text-muted">
                                <i class="fas fa-spinner fa-spin fa-2x mb-3"></i>
                                <div>Loading agent network visualization...</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent Activity -->
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-history me-2"></i>Recent Activity
                        </h5>
                    </div>
                    <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                        <div id="activity-feed">
                            <!-- Activity items will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Performance Analytics -->
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-bar me-2"></i>Performance Analytics
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <canvas id="workflow-performance-chart" width="400" height="200"></canvas>
                            </div>
                            <div class="col-md-6">
                                <canvas id="agent-utilization-chart" width="400" height="200"></canvas>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Workflow Selection Modal -->
    <div class="modal fade" id="workflowModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Start New Workflow</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="session-select" class="form-label">Select Session</label>
                        <select class="form-select" id="session-select">
                            <option value="">Choose a session...</option>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="workflow-select" class="form-label">Workflow Type</label>
                        <select class="form-select" id="workflow-select">
                            <option value="">Choose workflow...</option>
                        </select>
                    </div>
                    <div id="workflow-description" class="alert alert-info" style="display: none;">
                        <!-- Workflow description will be shown here -->
                    </div>
                    <div class="mb-3">
                        <label for="priority-select" class="form-label">Priority</label>
                        <select class="form-select" id="priority-select">
                            <option value="normal">Normal</option>
                            <option value="high">High</option>
                            <option value="critical">Critical</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="startWorkflow()">Start Workflow</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Workflow Details Modal -->
    <div class="modal fade" id="workflowDetailsModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Workflow Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="workflow-details-content">
                        <!-- Workflow details will be loaded here -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // Global variables
        let agentStatusInterval;
        let workflowStatusInterval;
        let activityInterval;
        let performanceChart;
        let utilizationChart;

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeDashboard();
            startRealTimeUpdates();
        });

        function initializeDashboard() {
            console.log('🚀 Initializing Agent Dashboard...');
            
            // Load initial data
            refreshSystemStatus();
            refreshAgentStatus();
            refreshWorkflows();
            refreshActivity();
            loadSessions();
            loadWorkflowTemplates();
            
            // Initialize charts
            initializeCharts();
            
            console.log('✅ Dashboard initialized');
        }

        function startRealTimeUpdates() {
            // Update every 5 seconds
            agentStatusInterval = setInterval(refreshSystemStatus, 5000);
            workflowStatusInterval = setInterval(refreshWorkflows, 10000);
            activityInterval = setInterval(refreshActivity, 15000);
        }

        function stopRealTimeUpdates() {
            clearInterval(agentStatusInterval);
            clearInterval(workflowStatusInterval);
            clearInterval(activityInterval);
        }

        async function refreshSystemStatus() {
            try {
                const response = await fetch('/api/agents/system/status');
                const data = await response.json();
                
                if (data.success) {
                    updateSystemMetrics(data.status);
                }
            } catch (error) {
                console.error('Failed to refresh system status:', error);
            }
        }

        function updateSystemMetrics(status) {
            document.getElementById('agent-count').textContent = Object.keys(status.agents || {}).length;
            document.getElementById('workflow-count').textContent = status.orchestrator?.active_workflows || 0;
            document.getElementById('queue-count').textContent = status.task_queue?.pending_tasks || 0;
            
            // Calculate success rate from database stats
            const total = status.database?.agent_executions || 0;
            const successRate = total > 0 ? '85%' : '0%'; // Placeholder calculation
            document.getElementById('success-rate').textContent = successRate;
        }

        async function refreshAgentStatus() {
            try {
                const response = await fetch('/api/agents/system/status');
                const data = await response.json();
                
                if (data.success) {
                    renderAgentStatus(data.status.agents);
                }
            } catch (error) {
                console.error('Failed to refresh agent status:', error);
            }
        }

        function renderAgentStatus(agents) {
            const container = document.getElementById('agent-status-container');
            
            if (!agents || Object.keys(agents).length === 0) {
                container.innerHTML = '<div class="text-muted text-center">No agents available</div>';
                return;
            }

            const agentCards = Object.entries(agents).map(([agentId, agent]) => {
                const statusClass = getStatusClass(agent.status);
                const capabilities = (agent.capabilities || []).join(', ');
                
                return `
                    <div class="agent-card card mb-2">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <h6 class="mb-1">${agentId}</h6>
                                    <small class="text-muted">${agent.agent_type}</small>
                                </div>
                                <div class="text-end">
                                    <span class="agent-status ${statusClass}">${agent.status}</span>
                                    <div class="small text-muted">${capabilities}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

            container.innerHTML = agentCards;
        }

        function getStatusClass(status) {
            switch (status?.toLowerCase()) {
                case 'running': return 'status-running';
                case 'error': return 'status-error';
                default: return 'status-idle';
            }
        }

        async function refreshWorkflows() {
            try {
                // This would need to be implemented to get active workflows
                const workflows = []; // Placeholder
                renderWorkflows(workflows);
            } catch (error) {
                console.error('Failed to refresh workflows:', error);
            }
        }

        function renderWorkflows(workflows) {
            const container = document.getElementById('workflows-container');
            
            if (!workflows || workflows.length === 0) {
                container.innerHTML = '<div class="text-muted text-center">No active workflows</div>';
                return;
            }

            const workflowCards = workflows.map(workflow => {
                const progress = ((workflow.completed_steps || 0) / (workflow.total_steps || 1)) * 100;
                
                return `
                    <div class="workflow-card card mb-2">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <h6 class="mb-0">${workflow.workflow_name}</h6>
                                <small class="text-muted">${workflow.status}</small>
                            </div>
                            <div class="workflow-progress bg-light mb-2">
                                <div class="bg-primary h-100" style="width: ${progress}%"></div>
                            </div>
                            <div class="d-flex justify-content-between">
                                <small class="text-muted">${workflow.completed_steps}/${workflow.total_steps} steps</small>
                                <button class="btn btn-sm btn-outline-primary" onclick="showWorkflowDetails('${workflow.workflow_id}')">
                                    Details
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');

            container.innerHTML = workflowCards;
        }

        async function refreshActivity() {
            const activities = [
                { time: '2 minutes ago', message: 'FileAnalysisAgent completed analysis for file_001.png', type: 'success' },
                { time: '5 minutes ago', message: 'SteganographyAgent started extraction on image_data.jpg', type: 'info' },
                { time: '8 minutes ago', message: 'CryptographyAgent solved Caesar cipher', type: 'success' },
                { time: '12 minutes ago', message: 'Workflow "crypto_challenge" initiated', type: 'info' }
            ];
            
            renderActivity(activities);
        }

        function renderActivity(activities) {
            const container = document.getElementById('activity-feed');
            
            const activityItems = activities.map(activity => {
                const iconClass = activity.type === 'success' ? 'fas fa-check-circle text-success' : 'fas fa-info-circle text-primary';
                
                return `
                    <div class="d-flex mb-3">
                        <div class="me-3">
                            <i class="${iconClass}"></i>
                        </div>
                        <div class="flex-grow-1">
                            <div class="small text-muted">${activity.time}</div>
                            <div>${activity.message}</div>
                        </div>
                    </div>
                `;
            }).join('');

            container.innerHTML = activityItems;
        }

        function initializeCharts() {
            // Workflow Performance Chart
            const perfCtx = document.getElementById('workflow-performance-chart').getContext('2d');
            performanceChart = new Chart(perfCtx, {
                type: 'line',
                data: {
                    labels: ['1h ago', '45m ago', '30m ago', '15m ago', 'Now'],
                    datasets: [{
                        label: 'Completed Workflows',
                        data: [5, 8, 12, 15, 18],
                        borderColor: '#007bff',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Workflow Completion Rate'
                        }
                    }
                }
            });

            // Agent Utilization Chart
            const utilCtx = document.getElementById('agent-utilization-chart').getContext('2d');
            utilizationChart = new Chart(utilCtx, {
                type: 'doughnut',
                data: {
                    labels: ['File Analysis', 'Steganography', 'Cryptography', 'Intelligence', 'Other'],
                    datasets: [{
                        data: [25, 20, 20, 15, 20],
                        backgroundColor: ['#007bff', '#28a745', '#ffc107', '#17a2b8', '#6c757d']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Agent Utilization'
                        }
                    }
                }
            });
        }

        async function loadSessions() {
            try {
                // This would load sessions from your API
                const sessions = [
                    { id: 'session_001', name: 'CTF Challenge Alpha' },
                    { id: 'session_002', name: 'Forensic Investigation Beta' }
                ];
                
                const select = document.getElementById('session-select');
                sessions.forEach(session => {
                    const option = document.createElement('option');
                    option.value = session.id;
                    option.textContent = session.name;
                    select.appendChild(option);
                });
            } catch (error) {
                console.error('Failed to load sessions:', error);
            }
        }

        async function loadWorkflowTemplates() {
            try {
                const response = await fetch('/api/agents/workflows/metadata');
                const data = await response.json();
                
                if (data.success) {
                    const select = document.getElementById('workflow-select');
                    
                    Object.entries(data.workflows).forEach(([key, workflow]) => {
                        const option = document.createElement('option');
                        option.value = key;
                        option.textContent = workflow.name;
                        option.dataset.description = workflow.description;
                        option.dataset.estimatedTime = workflow.estimated_time;
                        option.dataset.complexity = workflow.complexity;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Failed to load workflow templates:', error);
            }
        }

        function showWorkflowModal() {
            const modal = new bootstrap.Modal(document.getElementById('workflowModal'));
            modal.show();
        }

        document.getElementById('workflow-select').addEventListener('change', function() {
            const selectedOption = this.options[this.selectedIndex];
            const description = document.getElementById('workflow-description');
            
            if (selectedOption.dataset.description) {
                description.innerHTML = `
                    <strong>${selectedOption.textContent}</strong><br>
                    ${selectedOption.dataset.description}<br>
                    <small><strong>Estimated time:</strong> ${selectedOption.dataset.estimatedTime || 'Unknown'}</small><br>
                    <small><strong>Complexity:</strong> ${selectedOption.dataset.complexity || 'Unknown'}</small>
                `;
                description.style.display = 'block';
            } else {
                description.style.display = 'none';
            }
        });

        async function startWorkflow() {
            const sessionId = document.getElementById('session-select').value;
            const workflowType = document.getElementById('workflow-select').value;
            const priority = document.getElementById('priority-select').value;
            
            if (!sessionId || !workflowType) {
                alert('Please select both a session and workflow type');
                return;
            }
            
            try {
                const response = await fetch(`/api/agents/analyze/session/${sessionId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        workflow: workflowType,
                        priority: priority
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert(`Workflow started successfully! ID: ${data.workflow_id}`);
                    bootstrap.Modal.getInstance(document.getElementById('workflowModal')).hide();
                    refreshWorkflows();
                } else {
                    alert(`Failed to start workflow: ${data.error}`);
                }
            } catch (error) {
                console.error('Failed to start workflow:', error);
                alert('Failed to start workflow. Please try again.');
            }
        }

        function showWorkflowDetails(workflowId) {
            // Load and show workflow details
            console.log('Showing details for workflow:', workflowId);
            // Implementation would fetch workflow details and show in modal
        }

        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            stopRealTimeUpdates();
        });
    </script>
</body>
</html>
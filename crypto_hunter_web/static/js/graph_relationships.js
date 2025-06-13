// Functions for managing file relationships in the graph

/**
 * Derive relationships from filenames
 * This function calls the API endpoint to automatically derive relationships
 * between files based on their filenames.
 */
function deriveRelationships() {
    // Show loading indicator
    showNotification('Deriving relationships from filenames...', 'info');

    // Call the API endpoint
    fetch('/api/graph/derive-relationships', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification(`Successfully derived ${data.results.relationships_created} relationships`, 'success');
            // Reload the graph after a short delay
            setTimeout(() => {
                location.reload();
            }, 2000);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    })
    .catch(error => {
        console.error('Error deriving relationships:', error);
        showNotification('Failed to derive relationships', 'error');
    });
}

/**
 * Show a notification message
 * @param {string} message - The message to display
 * @param {string} type - The type of notification (info, success, error, warning)
 */
function showNotification(message, type = 'info') {
    // Check if notification container exists
    let container = document.getElementById('notification-container');
    if (!container) {
        // Create container if it doesn't exist
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.style.padding = '12px 16px';
    notification.style.marginBottom = '10px';
    notification.style.borderRadius = '4px';
    notification.style.boxShadow = '0 2px 4px rgba(0,0,0,0.1)';
    notification.style.transition = 'all 0.3s ease';

    // Set background color based on type
    if (type === 'success') {
        notification.style.backgroundColor = '#10B981';
        notification.style.color = 'white';
    } else if (type === 'error') {
        notification.style.backgroundColor = '#EF4444';
        notification.style.color = 'white';
    } else if (type === 'warning') {
        notification.style.backgroundColor = '#F59E0B';
        notification.style.color = 'white';
    } else {
        notification.style.backgroundColor = '#3B82F6';
        notification.style.color = 'white';
    }

    notification.textContent = message;

    // Add to container
    container.appendChild(notification);

    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            container.removeChild(notification);
        }, 300);
    }, 5000);
}

/**
 * Get CSRF token from meta tag
 * @returns {string} CSRF token
 */
function getCSRFToken() {
    const tokenMeta = document.querySelector('meta[name="csrf-token"]');
    return tokenMeta ? tokenMeta.getAttribute('content') : '';
}

/**
 * Show modal for manually defining a relationship between files
 */
function showManualRelationshipModal() {
    // Create modal if it doesn't exist
    let modal = document.getElementById('relationship-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'relationship-modal';
        modal.className = 'fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50';
        modal.style.display = 'none';

        modal.innerHTML = `
            <div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">
                <h3 class="text-lg font-medium mb-4">Define Relationship</h3>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Parent File</label>
                        <select id="parent-file" class="mt-1 block w-full border-gray-300 rounded-md">
                            <!-- Populated by JavaScript -->
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Child File</label>
                        <select id="child-file" class="mt-1 block w-full border-gray-300 rounded-md">
                            <!-- Populated by JavaScript -->
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">Relationship Type</label>
                        <select id="relationship-type" class="mt-1 block w-full border-gray-300 rounded-md">
                            <option value="zsteg">zsteg extraction</option>
                            <option value="steghide">steghide extraction</option>
                            <option value="binwalk">binwalk extraction</option>
                            <option value="strings">strings extraction</option>
                            <option value="manual">manual extraction</option>
                        </select>
                    </div>
                </div>
                <div class="mt-6 flex justify-end space-x-3">
                    <button onclick="closeRelationshipModal()" class="px-4 py-2 text-gray-600 border border-gray-300 rounded-md">
                        Cancel
                    </button>
                    <button onclick="createRelationship()" class="px-4 py-2 bg-blue-600 text-white rounded-md">
                        Create Relationship
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    // Populate file selectors
    const parentSelect = document.getElementById('parent-file');
    const childSelect = document.getElementById('child-file');

    parentSelect.innerHTML = '';
    childSelect.innerHTML = '';

    // Add files to selectors
    if (typeof graphData !== 'undefined' && graphData.nodes) {
        graphData.nodes.forEach(node => {
            parentSelect.innerHTML += `<option value="${node.id}">${node.filename || node.id}</option>`;
            childSelect.innerHTML += `<option value="${node.id}">${node.filename || node.id}</option>`;
        });
    }

    // Show modal
    modal.style.display = 'flex';
}

/**
 * Close the manual relationship modal
 */
function closeRelationshipModal() {
    const modal = document.getElementById('relationship-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Create a manual relationship between files
 */
function createRelationship() {
    const parentId = document.getElementById('parent-file').value;
    const childId = document.getElementById('child-file').value;
    const relationshipType = document.getElementById('relationship-type').value;

    if (parentId === childId) {
        showNotification('Parent and child files must be different', 'error');
        return;
    }

    // Call API to create relationship
    fetch('/api/graph/create-relationship', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({
            parent_sha: parentId,
            child_sha: childId,
            relationship_type: relationshipType
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Relationship created successfully', 'success');
            closeRelationshipModal();
            // Reload the graph after a short delay
            setTimeout(() => {
                location.reload();
            }, 2000);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    })
    .catch(error => {
        console.error('Error creating relationship:', error);
        showNotification('Failed to create relationship', 'error');
    });
}

// Add a button to the Quick Actions section when the document is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Find the Quick Actions container
    const quickActionsHeadings = document.querySelectorAll('h3.text-lg.font-medium');
    let quickActionsContainer = null;

    // Find the heading with "Quick Actions" text
    for (const heading of quickActionsHeadings) {
        if (heading.textContent.trim() === 'Quick Actions') {
            // Find the container that holds the buttons
            const parentDiv = heading.closest('.bg-white.rounded-lg.shadow');
            if (parentDiv) {
                quickActionsContainer = parentDiv.querySelector('.p-4.space-y-3');
                break;
            }
        }
    }

    if (quickActionsContainer) {
        // Create the Auto-Derive Relationships button
        const deriveButton = document.createElement('button');
        deriveButton.className = 'w-full text-left px-3 py-2 text-sm bg-yellow-50 hover:bg-yellow-100 text-yellow-700 rounded';
        deriveButton.onclick = deriveRelationships;
        deriveButton.innerHTML = '<i class="fas fa-project-diagram mr-2"></i>Auto-Derive Relationships';

        // Create the Define Manual Relationship button
        const manualButton = document.createElement('button');
        manualButton.className = 'w-full text-left px-3 py-2 text-sm bg-indigo-50 hover:bg-indigo-100 text-indigo-700 rounded';
        manualButton.onclick = showManualRelationshipModal;
        manualButton.innerHTML = '<i class="fas fa-link mr-2"></i>Define Manual Relationship';

        // Add buttons to container
        quickActionsContainer.appendChild(deriveButton);
        quickActionsContainer.appendChild(manualButton);
    } else {
        console.error('Could not find Quick Actions container');
    }
});

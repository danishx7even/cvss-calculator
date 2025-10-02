// Global variables
let currentVersion = '3.1';
let currentMetrics = {};

// Initialize on page load
$(document).ready(function() {
    // Version selection handler
    $('input[name="version"]').change(function() {
        currentVersion = $(this).val();
        switchMetricsDisplay(currentVersion);
        updateVectorString();
    });

    // Metric selection handler
    $('.btn-check').change(function() {
        if ($(this).attr('name') !== 'version') {
            updateVectorString();
        }
    });

    // Initial vector string
    updateVectorString();
});

// Switch between CVSS2 and CVSS3 metrics display
function switchMetricsDisplay(version) {
    if (version === '2.0') {
        $('#cvss3-metrics').hide();
        $('#cvss2-metrics').show();
    } else {
        $('#cvss3-metrics').show();
        $('#cvss2-metrics').hide();
    }
}

// Update vector string based on selected metrics
function updateVectorString() {
    let vectorString = '';
    
    if (currentVersion === '2.0') {
        // CVSS2 format
        const metrics = ['AV', 'AC', 'Au', 'C', 'I', 'A'];
        let values = [];
        
        metrics.forEach(metric => {
            const value = $(`input[name="cvss2_${metric}"]:checked`).val();
            if (value) {
                values.push(`${metric}:${value}`);
            }
        });
        
        vectorString = values.join('/');
    } else {
        // CVSS3 format
        const metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        let values = [];
        
        // Add version prefix
        if (currentVersion === '3.1') {
            values.push('CVSS:3.1');
        } else {
            values.push('CVSS:3.0');
        }
        
        metrics.forEach(metric => {
            const value = $(`input[name="cvss3_${metric}"]:checked`).val();
            if (value) {
                values.push(`${metric}:${value}`);
            }
        });
        
        vectorString = values.join('/');
    }
    
    $('#vector-string').val(vectorString);
}

// Calculate CVSS Score
function calculateScore() {
    const vectorString = $('#vector-string').val();
    
    if (!vectorString) {
        showAlert('Please select metrics to calculate score', 'warning');
        return;
    }
    
    // Show loading state
    const btn = $('.btn-primary');
    const originalText = btn.html();
    btn.html('<span class="loading"></span> Calculating...');
    btn.prop('disabled', true);
    
    // Make API call
    $.ajax({
        url: '/calculate',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            version: currentVersion,
            vector_string: vectorString
        }),
        success: function(response) {
            if (response.success) {
                updateScoreDisplay(response);
                showAlert('Score calculated successfully!', 'success');
            } else {
                showAlert('Error calculating score: ' + response.error, 'danger');
            }
        },
        error: function(xhr) {
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Unknown error occurred';
            showAlert('Error: ' + error, 'danger');
        },
        complete: function() {
            // Restore button state
            btn.html(originalText);
            btn.prop('disabled', false);
        }
    });
}

// Update score display
function updateScoreDisplay(data) {
    // Update main score
    $('.score-value').text(data.base_score.toFixed(1));
    
    // Update severity badge
    const severityBadge = $('.severity-badge .badge');
    severityBadge.removeClass('bg-info bg-success bg-warning bg-danger bg-critical');
    
    if (data.severity_class === 'critical') {
        severityBadge.addClass('bg-critical');
    } else {
        severityBadge.addClass('bg-' + data.severity_class);
    }
    severityBadge.text(data.severity);
    
    // Update score details
    $('#base-score').text(data.base_score.toFixed(1));
    $('#impact-score').text(data.scores.impact ? data.scores.impact.toFixed(1) : '-');
    $('#exploitability-score').text(data.scores.exploitability ? data.scores.exploitability.toFixed(1) : '-');
    
    // Animate score circle
    $('.score-circle').addClass('animate__animated animate__pulse');
    setTimeout(() => {
        $('.score-circle').removeClass('animate__animated animate__pulse');
    }, 1000);
}

// Copy vector string to clipboard
function copyToClipboard() {
    const vectorString = $('#vector-string').val();
    
    if (!vectorString) {
        showAlert('No vector string to copy', 'warning');
        return;
    }
    
    navigator.clipboard.writeText(vectorString).then(function() {
        showAlert('Vector string copied to clipboard!', 'success');
    }, function() {
        showAlert('Failed to copy to clipboard', 'danger');
    });
}

// Show alert message
function showAlert(message, type) {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    $('#alert-container').append(alertHtml);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        $('.alert').first().alert('close');
    }, 5000);
}

// Get icon for alert type
function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

// Parse vector string (for importing)
function parseVectorString() {
    const vectorString = prompt('Enter CVSS vector string:');
    
    if (!vectorString) {
        return;
    }
    
    $.ajax({
        url: '/parse_vector',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            version: currentVersion,
            vector_string: vectorString
        }),
        success: function(response) {
            if (response.success) {
                // Update UI with parsed values
                for (const [key, value] of Object.entries(response.components)) {
                    if (currentVersion === '2.0') {
                        $(`#cvss2_${key}_${value}`).prop('checked', true);
                    } else {
                        $(`#cvss3_${key}_${value}`).prop('checked', true);
                    }
                }
                updateVectorString();
                showAlert('Vector string parsed successfully!', 'success');
            }
        },
        error: function(xhr) {
            const error = xhr.responseJSON ? xhr.responseJSON.error : 'Invalid vector string';
            showAlert('Error: ' + error, 'danger');
        }
    });
}

// Keyboard shortcuts
$(document).keydown(function(e) {
    // Ctrl+Enter to calculate
    if (e.ctrlKey && e.keyCode === 13) {
        calculateScore();
    }
    // Ctrl+C to copy vector
    if (e.ctrlKey && e.keyCode === 67 && !window.getSelection().toString()) {
        copyToClipboard();
    }
});
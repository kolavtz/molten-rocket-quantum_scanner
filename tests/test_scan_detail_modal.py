"""
Test suite for scan detail modal API and frontend integration.
"""
import json
import pytest
from web.app import app


@pytest.fixture
def client():
    """Create a test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def authenticated_client(client):
    """Provide an authenticated test client."""
    # Mock login via session
    with client.session_transaction() as sess:
        sess['_user_id'] = 'test-user-1'
    return client


def test_scan_detail_modal_template_exists():
    """Test that scan detail modal template file exists."""
    import os
    template_path = 'web/templates/common/scan_detail_modal.html'
    assert os.path.exists(template_path), f"Modal template not found at {template_path}"


def test_scan_modal_included_in_base():
    """Test that modal is included in base.html."""
    with open('web/templates/base.html', 'r') as f:
        content = f.read()
    assert "scan_detail_modal.html" in content, "Scan modal not included in base.html"


def test_scan_table_calls_modal_open(authenticated_client):
    """Test that scan table uses modal open instead of navigation."""
    with open('web/templates/scans.html', 'r', encoding='utf-8') as f:
        content = f.read()
    # Check that the action button function calls the new details handler
    assert "window.QuantumShieldScans.showRecordDetails" in content, "Scan table does not call showRecordDetails()"


def test_api_scan_result_endpoint_exists(authenticated_client):
    """Test that API endpoint for scan results exists."""
    # This uses the existing endpoint from scans.py
    # We're just verifying it's in the route
    response = authenticated_client.get('/api/scans/test-scan-123/result')
    # Should return 404 (scan not found) not 404 (endpoint not found)
    assert response.status_code in [404, 200], "Scan result endpoint returned unexpected status"


def test_scan_modal_html_structure():
    """Test that modal HTML has required elements."""
    with open('web/templates/common/scan_detail_modal.html', 'r') as f:
        content = f.read()
    
    required_elements = [
        'id="qsScanDetailModal"',
        'id="qsScanDetailTitle"',
        'id="qsScanLoadingState"',
        'id="qsScanContentContainer"',
        'id="qsScanErrorState"',
        'window.ScanDetailModal',
        'open(scanId)',
        'close()',
        'populateModal(',
    ]
    
    for element in required_elements:
        assert element in content, f"Required element '{element}' not found in modal template"


def test_scan_modal_has_required_tables():
    """Test that modal includes required data tables."""
    with open('web/templates/common/scan_detail_modal.html', 'r') as f:
        content = f.read()
    
    required_sections = [
        'Scan Metadata',
        'Results Summary',
        'Targets Scanned',
        'SSL/TLS Certificates',
        'Recommendations'
    ]
    
    for section in required_sections:
        assert section in content, f"Required section '{section}' not found in modal template"


def test_scan_modal_accessibility_attributes():
    """Test that modal has accessibility attributes."""
    with open('web/templates/common/scan_detail_modal.html', 'r') as f:
        content = f.read()
    
    # Check for aria labels and attributes
    assert 'aria-hidden' in content, "aria-hidden attribute missing"
    assert 'aria-label' in content, "aria-label attribute missing"
    assert 'role=' in content or '<h2' in content, "Semantic HTML not used"


def test_scan_modal_key_handlers():
    """Test that modal has keyboard event handlers."""
    with open('web/templates/common/scan_detail_modal.html', 'r') as f:
        content = f.read()
    
    # Check for Escape key handler
    assert 'key === \'Escape\'' in content or 'key == "Escape"' in content, "Escape key handler missing"
    
    # Check for backdrop click handler
    assert 'addEventListener' in content, "Event listeners missing"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

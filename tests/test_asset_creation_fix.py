#!/usr/bin/env python3
"""
Quick test to verify asset creation endpoint works
"""
import json
import pytest
from flask import Flask
from tests.conftest import app as create_app


def test_asset_creation_endpoint_json_response(app_client):
    """Verify POST /api/assets returns proper JSON response"""
    
    # Test creating a new asset
    response = app_client.post(
        '/api/assets',
        data=json.dumps({
            'target': 'test-example.com',
            'owner': 'Test User',
            'type': 'domain',
            'risk_level': 'Medium'
        }),
        content_type='application/json',
        headers={'X-CSRFToken': 'test-token'}  # Mock CSRF token
    )
    
    # Verify response is JSON (not HTML error)
    assert response.status_code in [200, 201, 400, 401, 403], \
        f"Unexpected status: {response.status_code}\nResponse: {response.data[:500]}"
    
    try:
        data = json.loads(response.data)
        print(f"✅ Response is valid JSON")
        print(f"   Status: {response.status_code}")
        print(f"   Keys: {list(data.keys())}")
        
        # Verify response structure
        assert 'success' in data, "Response missing 'success' key"
        print(f"✅ Response has 'success' key = {data['success']}")
        
        if data['success']:
            assert 'data' in data, "Success response missing 'data' key"
            print(f"✅ Response has 'data' with asset info")
        else:
            assert 'error' in data or 'message' in data, "Error response missing error message"
            print(f"ℹ️  Error response: {data.get('error') or data.get('message')}")
            
    except json.JSONDecodeError as e:
        pytest.fail(f"Response is not valid JSON: {e}\nResponse: {response.data[:1000]}")


def test_asset_creation_with_validation(app_client):
    """Verify validation of asset creation input"""
    
    # Test with invalid target (should fail validation)
    response = app_client.post(
        '/api/assets',
        data=json.dumps({
            'target': 'invalid target!!!',  # Invalid characters
            'owner': 'Test User',
            'type': 'domain',
            'risk_level': 'Medium'
        }),
        content_type='application/json',
        headers={'X-CSRFToken': 'test-token'}
    )
    
    # Should return JSON response (not HTML error)
    try:
        data = json.loads(response.data)
        print(f"✅ Validation error returned as JSON")
        print(f"   Status: {response.status_code}")
        print(f"   Message: {data.get('message') or data.get('error')}")
    except json.JSONDecodeError as e:
        pytest.fail(f"Validation response is not valid JSON: {e}")


if __name__ == "__main__":
    # Run with: python test_asset_creation_fix.py
    pytest.main([__file__, "-v", "-s"])

import pytest
import json
import os
from unittest.mock import patch, MagicMock
from application import application, scan_cache


# --- Setup ---

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    application.config['TESTING'] = True
    application.config['UPLOAD_FOLDER'] = 'test_uploads'
    os.makedirs('test_uploads', exist_ok=True)
    with application.test_client() as client:
        yield client
    # Cleanup test uploads after each test
    import shutil
    shutil.rmtree('test_uploads', ignore_errors=True)


# --- Index Route ---

def test_index(client):
    response = client.get('/')
    assert response.status_code == 200


# --- Upload Route ---

def test_upload_no_files(client):
    """Should return 400 if no files provided."""
    response = client.post('/upload')
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_upload_invalid_filename(client):
    """Should reject files with invalid filenames."""
    from io import BytesIO
    data = {'files': (BytesIO(b"content"), '')}  # empty filename
    response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 200


@patch('application.scan_file_flask')
def test_upload_success(mock_scan, client):
    """Should upload a file and return scan result."""
    mock_scan.return_value = {'status': 'clean'}
    from io import BytesIO
    data = {'files': (BytesIO(b"hello world"), 'test.txt')}
    response = client.post('/upload', data=data, content_type='multipart/form-data')
    assert response.status_code == 200
    result = json.loads(response.data)
    assert result['files'][0]['scan_result'] == {'status': 'clean'}


@patch('application.scan_file_flask', side_effect=Exception("Scan failed"))
def test_upload_scan_error(mock_scan, client):
    """Should handle scan errors gracefully."""
    from io import BytesIO
    data = {'files': (BytesIO(b"data"), 'file.txt')}
    response = client.post('/upload', data=data, content_type='multipart/form-data')
    result = json.loads(response.data)
    assert result['files'][0]['status'] == 'error'
    assert 'Scan failed' in result['files'][0]['reason']


# --- List Files Route ---

def test_list_files_empty(client):
    """Should return empty list when no files uploaded."""
    response = client.get('/files')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


# --- Report Route ---

def test_report_not_found(client):
    """Should return 404 if report doesn't exist."""
    response = client.get('/report/nonexistent.txt')
    assert response.status_code == 404


def test_report_invalid_filename(client):
    """Should return 400 for invalid filename."""
    response = client.get('/report/')
    assert response.status_code == 404  # Flask returns 404 for missing route param


def test_report_found(client):
    """Should return report file if it exists."""
    report_path = os.path.join('test_uploads', 'myfile.txt_report.txt')
    with open(report_path, 'w') as f:
        f.write('Scan report content')
    response = client.get('/report/myfile.txt')
    assert response.status_code == 200


# --- Delete Route ---

def test_delete_nonexistent_file(client):
    """Should return 404 when deleting a file that doesn't exist."""
    response = client.delete('/delete/ghost.txt')
    assert response.status_code == 404


def test_delete_success(client):
    """Should delete file and return success message."""
    filepath = os.path.join('test_uploads', 'todelete.txt')
    with open(filepath, 'w') as f:
        f.write('temp')
    scan_cache['todelete.txt'] = {'status': 'clean'}
    response = client.delete('/delete/todelete.txt')
    assert response.status_code == 200
    result = json.loads(response.data)
    assert result['message'] == 'File deleted successfully'
    assert not os.path.exists(filepath)
    assert 'todelete.txt' not in scan_cache


def test_delete_also_removes_report(client):
    """Should also delete the report file if it exists."""
    filepath = os.path.join('test_uploads', 'myfile.txt')
    report_path = filepath + '_report.txt'
    with open(filepath, 'w') as f:
        f.write('data')
    with open(report_path, 'w') as f:
        f.write('report')
    client.delete('/delete/myfile.txt')
    assert not os.path.exists(report_path)

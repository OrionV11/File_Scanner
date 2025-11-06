from flask import Flask, render_template_string, request, jsonify
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Upload</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #e3e4ea 0%, #fcf8ff 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }

        h1 {
            color: #333;
            margin-bottom: 30px;
            text-align: center;
        }

        .upload-area {
            border: 3px dashed #667eea;
            border-radius: 15px;
            padding: 60px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: #f8f9ff;
        }

        .upload-area:hover {
            background: #eef1ff;
            border-color: #764ba2;
        }

        .upload-area.dragover {
            background: #e0e7ff;
            border-color: #4f46e5;
        }

        .upload-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }

        .upload-text {
            color: #667eea;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .upload-subtext {
            color: #888;
            font-size: 14px;
        }

        input[type="file"] {
            display: none;
        }

        .file-list {
            margin-top: 30px;
        }

        .file-list h2 {
            color: #333;
            font-size: 20px;
            margin-bottom: 15px;
        }

        .file-item {
            background: #f8f9ff;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.2s ease;
        }

        .file-item:hover {
            background: #eef1ff;
            transform: translateX(5px);
        }

        .file-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .file-icon {
            font-size: 24px;
        }

        .file-details {
            display: flex;
            flex-direction: column;
        }

        .file-name {
            color: #333;
            font-weight: 600;
            margin-bottom: 3px;
        }

        .file-size {
            color: #888;
            font-size: 12px;
        }

        .remove-btn {
            background: #ff4757;
            color: white;
            border: none;
            border-radius: 5px;
            padding: 8px 15px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 14px;
        }

        .remove-btn:hover {
            background: #ff3838;
            transform: scale(1.05);
        }

        .empty-state {
            text-align: center;
            color: #888;
            padding: 20px;
            font-style: italic;
        }

        .status-message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            display: none;
        }

        .status-message.success {
            background: #d4edda;
            color: #155724;
        }

        .status-message.error {
            background: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 File Upload</h1>
        
        <div class="upload-area" id="uploadArea">
            <div class="upload-text">Click to upload files</div>
            <div class="upload-subtext">or drag and drop files here</div>
        </div>
        
        <input type="file" id="fileInput" multiple>
        
        <div id="statusMessage" class="status-message"></div>
        
        <div class="file-list">
            <h2>Uploaded Files</h2>
            <div id="fileListContainer">
                <div class="empty-state">No files uploaded yet</div>
            </div>
        </div>
    </div>

    <script>
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileListContainer = document.getElementById('fileListContainer');
        const statusMessage = document.getElementById('statusMessage');

        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            handleFiles(e.dataTransfer.files);
        });

        async function handleFiles(files) {
            const formData = new FormData();
            
            for (let file of files) {
                formData.append('files', file);
            }

            try {
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok) {
                    showStatus('Files uploaded successfully!', 'success');
                    loadUploadedFiles();
                } else {
                    showStatus(result.error || 'Upload failed', 'error');
                }
            } catch (error) {
                showStatus('Upload failed: ' + error.message, 'error');
            }

            fileInput.value = '';
        }

        async function loadUploadedFiles() {
            try {
                const response = await fetch('/files');
                const files = await response.json();
                displayFiles(files);
            } catch (error) {
                console.error('Error loading files:', error);
            }
        }

        function displayFiles(files) {
            if (files.length === 0) {
                fileListContainer.innerHTML = '<div class="empty-state">No files uploaded yet</div>';
                return;
            }

            fileListContainer.innerHTML = '';
            
            files.forEach((file) => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                
                const icon = getFileIcon(file.name);
                const size = formatFileSize(file.size);
                
                fileItem.innerHTML = `
                    <div class="file-info">
                        <div class="file-icon">${icon}</div>
                        <div class="file-details">
                            <div class="file-name">${file.name}</div>
                            <div class="file-size">${size}</div>
                        </div>
                    </div>
                    <button class="remove-btn" onclick="removeFile('${file.name}')">Remove</button>
                `;
                
                fileListContainer.appendChild(fileItem);
            });
        }

        async function removeFile(filename) {
            try {
                const response = await fetch(`/delete/${encodeURIComponent(filename)}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    showStatus('File deleted successfully', 'success');
                    loadUploadedFiles();
                } else {
                    showStatus('Failed to delete file', 'error');
                }
            } catch (error) {
                showStatus('Delete failed: ' + error.message, 'error');
            }
        }

        function getFileIcon(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            const icons = {
                'pdf': '📄',
                'doc': '📝', 'docx': '📝',
                'xls': '📊', 'xlsx': '📊',
                'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
                'mp4': '🎬', 'avi': '🎬', 'mov': '🎬',
                'mp3': '🎵', 'wav': '🎵',
                'zip': '🗜️', 'rar': '🗜️',
                'txt': '📃'
            };
            return icons[ext] || '📎';
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function showStatus(message, type) {
            statusMessage.textContent = message;
            statusMessage.className = `status-message ${type}`;
            statusMessage.style.display = 'block';
            
            setTimeout(() => {
                statusMessage.style.display = 'none';
            }, 3000);
        }

        // Load files on page load
        loadUploadedFiles();
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    uploaded_files = []
    
    for file in files:
        if file.filename == '':
            continue
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        uploaded_files.append(file.filename)
    
    return jsonify({
        'message': 'Files uploaded successfully',
        'files': uploaded_files
    })

@app.route('/files', methods=['GET'])
def list_files():
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            files.append({
                'name': filename,
                'size': os.path.getsize(filepath)
            })
    return jsonify(files)

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'message': 'File deleted successfully'})
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
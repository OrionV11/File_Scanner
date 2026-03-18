from flask import Flask, render_template, request, jsonify, url_for, redirect, session
import os
from scanner.scanner_core import scan_file_flask
from functools import wraps
import uuid
from werkzeug.utils import secure_filename

application = Flask(__name__)
application.config['UPLOAD_FOLDER'] = 'uploads'
application.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)
application.secret_key = 'anything'


@application.route('/')
def index():
    return render_template('index.html')


@application.route('/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400

    files = request.files.getlist('files')
    uploaded_files = []

    for file in files:
        if not file or file.filename == '':
            continue


    
        original_name = file.filename
        safe_name = secure_filename(original_name)

        if not safe_name:
            uploaded_files.append({
                "filename": original_name,
                "status": "rejected",
                "reason": "Invalid filename"
            })
            continue

        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], unique_name)

        try:
            file.save(filepath)

            # Run scanner
            scan_result = scan_file_flask(filepath)
            print("SCAN RESULT:", scan_result, flush=True)

            uploaded_files.append({
                "filename": original_name,
                "stored_as": unique_name,
                "scan_result": scan_result
            })

        except Exception as e:
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass

            uploaded_files.append({
                "filename": original_name,
                "status": "error",
                "reason": str(e)
            })

    return jsonify({
        'message': 'Files uploaded successfully',
        'files': uploaded_files
    })


@application.route('/files', methods=['GET'])
def list_files():
    files = []
    for filename in os.listdir(application.config['UPLOAD_FOLDER']):
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            files.append({
                'name': filename,
                'size': os.path.getsize(filepath)
            })
    return jsonify(files)

@application.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        safe_name = secure_filename(filename)
        if not safe_name:
            return jsonify({'error': 'Invalid filename'}), 400

        filepath = os.path.join(application.config['UPLOAD_FOLDER'], safe_name)

        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'message': 'File deleted successfully'})

        return jsonify({'error': 'File not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    application.run()

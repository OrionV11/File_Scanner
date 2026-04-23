from flask import Flask, render_template, request, jsonify, url_for, redirect, session, send_file
import os
from scanner.scanner_core import scan_file_flask
import uuid
import secrets
import shutil
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
load_dotenv()

application = Flask(__name__)
application.config['UPLOAD_FOLDER'] = 'uploads'
application.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
application.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# In-memory scan cache — stores scan results by stored filename
scan_cache = {}

# Create uploads folder if it doesn't exist
os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)


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

            scan_result = scan_file_flask(filepath)
            print("SCAN RESULT:", scan_result, flush=True)

            # Quarantining high-risk files
            stats = scan_result.get('last_analysis_stats', {}) if isinstance(scan_result, dict) else {}
            malicious = stats.get('malicious', 0)

            quarantined = False
            reason = None

            local_infected = scan_result.get('local_scan') == 'infected'

            if malicious > 10 or local_infected:
                quarantine_path = os.path.join(QUARANTINE_FOLDER, unique_name)
                shutil.move(filepath, quarantine_path)
                
                report_src = filepath + '_report.txt'
                if os.path.exists(report_src):
                    shutil.move(report_src, os.path.join(QUARANTINE_FOLDER, unique_name +'_report.txt'))

                quarantined = True
                if local_infected and malicious > 10:
                     reason = f'Local scan infected + VT malicious detections: {malicious}'
                elif local_infected:
                     reason = 'Local scan: infected'
                else:
                     reason = f'High risk (malicious detections: {malicious})'
            
            # Cache scan result by stored filename
            scan_cache[unique_name] = scan_result
            uploaded_files.append({
                "filename": original_name,
                "stored_as": unique_name,
                "scan_result": scan_result,
                "quarantined": quarantined,
                "reason": reason
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
        if filename.endswith('_report.txt'):
            continue
        filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            files.append({
                'name': filename,
                'size': os.path.getsize(filepath),
                'scan': scan_cache.get(filename, {})
            })
    return jsonify(files)


@application.route('/report/<filename>', methods=['GET'])
def view_report(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        return jsonify({'error': 'Invalid filename'}), 400

    for folder in [application.config['UPLOAD_FOLDER'], QUARANTINE_FOLDER]:
        report_path = os.path.join(folder, safe_name + '_report.txt')
        if os.path.exists(report_path):
            return send_file(report_path, as_attachment=False, mimetype='text/plain')

    return jsonify({'error': 'Report not found'}), 404

@application.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        safe_name = secure_filename(filename)
        if not safe_name:
            return jsonify({'error': 'Invalid filename'}), 400

        filepath = os.path.join(application.config['UPLOAD_FOLDER'], safe_name)

        # Remove from scan cache
        scan_cache.pop(safe_name, None)

        # Delete report if it exists
        report_path = filepath + '_report.txt'
        if os.path.exists(report_path):
            os.remove(report_path)

        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'message': 'File deleted successfully'})

        return jsonify({'error': 'File not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

QUARANTINE_FOLDER = 'quarantine'
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

@application.route('/quarantine', methods=['GET'])
def get_quarantine():
    files = [
        f for f in os.listdir(QUARANTINE_FOLDER)
        if os.path.isfile(os.path.join(QUARANTINE_FOLDER, f))
        and not f.endswith('_report.txt')  
    ]
    return jsonify(files)

@application.route('/recover/<filename>', methods=['POST'])
def recover_file(filename):
    safe = secure_filename(filename)
    src = os.path.join(QUARANTINE_FOLDER, safe)
    dst = os.path.join(application.config['UPLOAD_FOLDER'], safe)
    if os.path.exists(src):
        shutil.move(src, dst)
        # Move report back too
        report_src = os.path.join(QUARANTINE_FOLDER, safe + '_report.txt')
        if os.path.exists(report_src):
            shutil.move(report_src, os.path.join(application.config['UPLOAD_FOLDER'], safe + '_report.txt'))
        # Restore scan cache entry if missing
        if safe not in scan_cache:
            scan_cache[safe] = {'local_scan': 'recovered', 'signatures': [], 'virustotal': {}}
        return jsonify({'success': True, 'message': f'Recovered {filename}'})
    return jsonify({'error': 'File not found'}), 404

@application.route('/quarantine/delete/<filename>', methods=['DELETE'])
def delete_quarantined(filename):
    path = os.path.join(QUARANTINE_FOLDER, secure_filename(filename))
    if os.path.exists(path):
        os.remove(path)
        return jsonify({'success': True, 'message': f'Deleted {filename}'})
    return jsonify({'error': 'File not found'}), 404

if __name__ == '__main__':
    application.run(debug=True)

from flask import Flask, render_template, request, jsonify, url_for, redirect, session
import os
from functools import wraps

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.secret_key = 'anything'

# Database for development, use an actual database in production
USERS = {
    'admin': 'password123',
    'user': 'demo123'
}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required  # ← ADD THIS
def index():
    return render_template('index.html', username=session['username'])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in USERS and USERS[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    if 'username' in session:
        return redirect(url_for('index'))

    return render_template('login.html', error=None)


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/upload', methods=['POST'])
@login_required  # ← ADD THIS
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
@login_required  # ← ADD THIS
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
@login_required  # ← ADD THIS
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
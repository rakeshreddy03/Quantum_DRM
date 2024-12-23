from flask import Flask, request, jsonify, session, redirect, url_for, send_file, render_template
from cryptography.fernet import Fernet, InvalidToken
import os
from flask_mysqldb import MySQL
import MySQLdb
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'
KEY_FILE = 'key.key'  # File to store the encryption key

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'drm_db'

mysql = MySQL(app)


class RLWE:
    def keygen(self):
        return Fernet.generate_key(), Fernet.generate_key()  # Dummy keys

    def encrypt(self, plaintext, public_key):
        return plaintext  # Replace with actual encryption logic

    def decrypt(self, ciphertext, secret_key):
        return ciphertext  # Replace with actual decryption logic

# License Server Class for Authentication and Role Management
class LicenseServer:
    def __init__(self):
        self.rlwe = RLWE()
        self.encryption_key = self.load_key()  # Load the encryption key from the file

        # If no key exists, generate a new one and save it
        if not self.encryption_key:
            self.encryption_key = Fernet.generate_key()
            self.save_key(self.encryption_key)

    def authenticate_user(self, username, password):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
        account = cursor.fetchone()
        cursor.close()
        if account:
            session['username'] = account['username']
            session['role'] = account['role']  # Store user role
            return account['subscription']  # Return user subscription level
        return None

    def provide_decryption_key(self, subscription):
        if subscription == 'premium':
            return self.encryption_key  # Provide key for premium users
        elif subscription == 'basic':
            return None  # Basic users might only stream content without full decryption access
        return None

    def save_key(self, key):
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)

    def load_key(self):
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, 'rb') as key_file:
                return key_file.read()
        return None

# Content Encryption/Decryption Functions
def encrypt_content(content_data, key):
    fernet = Fernet(key)
    return fernet.encrypt(content_data)

def decrypt_content(encrypted_data, key):
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_data)
    except InvalidToken:
        print("Decryption failed: Invalid token or corrupted data")
        return None

# Initialize License Server
license_server = LicenseServer()

# Home Route
@app.route('/')
def home():
    return render_template('home.html')

# Route for User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        subscription = license_server.authenticate_user(username, password)
        
        if subscription:
            session['subscription'] = subscription
            return redirect(url_for('dashboard'))
        return "Login Failed", 403
    return render_template('login.html')

# Route for User Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        subscription = request.form['subscription']  # basic or premium
        
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO users (username, password, subscription, role) VALUES (%s, %s, %s, %s)', 
                       (username, password, subscription, 'user'))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('login'))

    return render_template('signup.html')

# Route for Provider Login
@app.route('/provider', methods=['GET', 'POST'])
def provider():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM providers WHERE username = %s AND password = %s', (username, password))
        account = cursor.fetchone()
        cursor.close()
        if account:
            session['provider_name'] = account['username']
            return redirect(url_for('upload_mp3'))
        return "Provider Login Failed", 403
    return render_template('provider.html')

# Route for Provider Signup
@app.route('/provider_signup', methods=['GET', 'POST'])
def provider_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO providers (username, password) VALUES (%s, %s)', 
                       (username, password))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('provider'))

    return render_template('provider_signup.html')

# Dashboard Route
# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    subscription = session.get('subscription')
    
    # Get folders for each provider
    provider_files = {}
    providers = [d for d in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'], d))]
    
    # Get uploaded files for each provider
    for provider in providers:
        provider_folder = os.path.join(app.config['UPLOAD_FOLDER'], provider)
        provider_files[provider] = []
        for song_file in os.listdir(provider_folder):
            if song_file.endswith('.mp3.enc'):
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT visibility FROM songs WHERE provider_username = %s AND filename = %s',
                               (provider, song_file[:-4]))  
                visibility = cursor.fetchone()
                if visibility:
                    # Filter songs based on user subscription
                    if subscription == 'premium' or visibility['visibility'] == 'basic':
                        provider_files[provider].append({
                            'filename': song_file[:-4], 
                            'visibility': visibility['visibility']
                        })
                cursor.close()

    return render_template('dashboard.html', username=session['username'], subscription=subscription, provider_files=provider_files)

# Route for MP3 File Upload (Provider Side)
@app.route('/upload_mp3', methods=['GET', 'POST'])
def upload_mp3():
    if 'provider_name' not in session:
        return "Unauthorized", 403
    
    provider_name = session['provider_name']

    if request.method == 'POST':
        file = request.files['file']
        visibility = request.form.get('visibility')  # Get visibility option
        
        if not file or not file.filename.endswith('.mp3'):
            return "Invalid file type, only MP3 allowed", 400
        
        # Create a folder for the provider if it doesn't exist
        provider_folder = os.path.join(app.config['UPLOAD_FOLDER'], provider_name)
        os.makedirs(provider_folder, exist_ok=True)

        # Save the uploaded file in the provider's folder
        file_path = os.path.join(provider_folder, file.filename)
        file.save(file_path)
        
        # Encrypt the MP3 file with a quantum-secure key
        with open(file_path, 'rb') as f:
            encrypted_content = encrypt_content(f.read(), license_server.encryption_key)
        
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_content)

        os.remove(file_path)  # Delete the unencrypted file after encryption

        # Save song information to the database
        cursor = mysql.connection.cursor()
        cursor.execute('INSERT INTO songs (provider_username, filename, visibility) VALUES (%s, %s, %s)',
                       (provider_name, file.filename, visibility))
        mysql.connection.commit()
        cursor.close()

        return "MP3 uploaded and encrypted successfully!"

    # Fetch the list of uploaded songs for the provider
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT filename, visibility FROM songs WHERE provider_username = %s', (provider_name,))
    uploaded_songs = cursor.fetchall()
    cursor.close()

    return render_template('upload.html', uploaded_songs=uploaded_songs)

# Route for Deleting a Song (Provider Side)
@app.route('/delete_song/<filename>', methods=['POST'])
def delete_song(filename):
    if 'provider_name' not in session:
        return "Unauthorized", 403
    
    provider_name = session['provider_name']
    
    # Verify that the song belongs to the logged-in provider
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM songs WHERE provider_username = %s AND filename = %s', 
                   (provider_name, filename))
    song = cursor.fetchone()
    
    if not song:
        cursor.close()
        return "Song not found or unauthorized", 404

    # Delete the song record from the database
    cursor.execute('DELETE FROM songs WHERE provider_username = %s AND filename = %s', 
                   (provider_name, filename))
    mysql.connection.commit()
    cursor.close()

    # Delete the encrypted file from the filesystem
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], provider_name, filename + '.enc')
    if os.path.exists(encrypted_file_path):
        os.remove(encrypted_file_path)

    return "Song deleted successfully!"
    
# Route for Downloading MP3 (User Access)
@app.route('/download_mp3/<filename>', methods=['GET'])
def download_mp3(filename):
    if 'username' not in session:
        return "Unauthorized", 403

    subscription = session.get('subscription')
    if not subscription:
        return "Unauthorized", 403

    # Retrieve provider name from the song database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT provider_username FROM songs WHERE filename = %s', (filename,))
    result = cursor.fetchone()
    cursor.close()

    if not result:
        return "File not found", 404

    provider_username = result['provider_username']
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], provider_username, filename + '.enc')
    
    if not os.path.exists(encrypted_file_path):
        return "File not found", 404

    # Provide the decryption key based on the subscription level
    key = license_server.provide_decryption_key(subscription)
    if not key:
        return "Upgrade to premium to download content", 403

    # Decrypt and send the MP3 file
    with open(encrypted_file_path, 'rb') as ef:
        encrypted_content = ef.read()
        decrypted_content = decrypt_content(encrypted_content, key)

    if decrypted_content is None:
        return "Failed to download: Invalid key", 403

    # Fix here: Use download_name instead of attachment_filename
    return send_file(io.BytesIO(decrypted_content), download_name=f"{filename}.mp3", as_attachment=True)

# Route for Streaming MP3 (User Access)
@app.route('/stream_mp3/<filename>', methods=['GET'])
def stream_mp3(filename):
    if 'username' not in session:
        return "Unauthorized", 403

    subscription = session.get('subscription')
    if not subscription:
        return "Unauthorized", 403

    # Retrieve provider name from the song database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT provider_username FROM songs WHERE filename = %s', (filename,))
    result = cursor.fetchone()
    cursor.close()

    if not result:
        return "File not found", 404

    provider_username = result['provider_username']
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], provider_username, filename + '.enc')
    
    if not os.path.exists(encrypted_file_path):
        return "File not found", 404

    # Provide the decryption key based on the subscription level
    key = license_server.provide_decryption_key(subscription)
    if not key:
        return "Upgrade to premium to stream content", 403

    # Decrypt and send the MP3 file for streaming
    with open(encrypted_file_path, 'rb') as ef:
        encrypted_content = ef.read()
        decrypted_content = decrypt_content(encrypted_content, key)

    if decrypted_content is None:
        return "Failed to stream: Invalid key", 403

    return send_file(io.BytesIO(decrypted_content), mimetype='audio/mp3')

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
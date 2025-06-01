import mysql.connector
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, make_response, g
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import random
import base64
from functools import wraps
from PIL import Image, ImageDraw, ImageFont
import io
from datetime import datetime, date
# --- Configuration for Flask ---
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_should_be_changed')

# --- Configuration for file uploads ---
UPLOAD_FOLDER = os.path.join('static', 'uploads')
CERTIFICATE_FOLDER = os.path.join('static', 'certificates')
PRESCRIPTION_FOLDER = os.path.join('static', 'prescriptions') # New folder for prescriptions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_DOCUMENT_EXTENSIONS = {'pdf'} # For prescriptions

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CERTIFICATE_FOLDER'] = CERTIFICATE_FOLDER
app.config['PRESCRIPTION_FOLDER'] = PRESCRIPTION_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 MB limit

# Create upload and certificate folders if they don't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(CERTIFICATE_FOLDER):
    os.makedirs(CERTIFICATE_FOLDER)
if not os.path.exists(PRESCRIPTION_FOLDER): # Create prescriptions folder
    os.makedirs(PRESCRIPTION_FOLDER)

# Function to check if the file extension is allowed for images
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to check if the file extension is allowed for documents (PDFs)
def allowed_document_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_DOCUMENT_EXTENSIONS

# Configure Flask-Mail (USE ENVIRONMENT VARIABLES IN PRODUCTION!)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'givehubdonation@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'fmyd alnh hhli hhuc')
mail = Mail(app)

# Database Connection (using Flask's g object for per-request connection)
def get_db_connection():
    try:
        return mysql.connector.connect(
            host="localhost",
            user="root",
            password="Password",  # Replace with your actual MySQL password
            database="finl_gh"
        )
    except mysql.connector.Error as err:
        print(f"[DB ERROR] Connection failed: {err}")
        raise

# Register b64encode filter if you intend to display images from database as base64
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''

# Helper function to check if user is logged in
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedin' not in session:
            flash('You need to be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if 'loggedin' not in session or session.get('role') != role_name:
                flash(f'Access denied. You must be a {role_name} to view this page.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrap
    return decorator

admin_required = role_required('Admin')
medical_store_required = role_required('Medical Store')
ngo_required = role_required('NGO')
donor_required = role_required('Donor')
central_hub_required = role_required('Central Hub') # New role decorator

# --- Helper Functions for Certificates ---
def generate_certificate(donor_name, donation_id):
    try:
        width, height = 800, 600
        img = Image.new('RGB', (width, height), color = '#e0f7fa')
        d = ImageDraw.Draw(img)

        try:
            # Using a system-wide font for better compatibility, or provide path
            # On Windows, try "arial.ttf". On Linux, you might need to install 'ttf-mscorefonts-installer'
            # For a more robust solution, bundle fonts with your app and use their paths
            font_title = ImageFont.truetype("arial.ttf", 48)
            font_subtitle = ImageFont.truetype("arial.ttf", 30)
            font_body = ImageFont.truetype("arial.ttf", 24)
            font_signature = ImageFont.truetype("arial.ttf", 28)
        except IOError:
            print("Warning: Arial font not found, using default PIL font. Certificates may not look as intended.")
            font_title = ImageFont.load_default()
            font_subtitle = ImageFont.load_default()
            font_body = ImageFont.load_default()
            font_signature = ImageFont.load_default()

        title_text = "Certificate of Appreciation"
        # Use textbbox to get bounding box and calculate width/height
        title_bbox = d.textbbox((0, 0), title_text, font=font_title)
        title_width = title_bbox[2] - title_bbox[0]
        # title_height = title_bbox[3] - title_bbox[1] # You don't use height for centering in this specific line
        d.text(((width - title_width) / 2, 50), title_text, fill=(0, 102, 102), font=font_title)

        presented_to_text = "PRESENTED TO"
        presented_to_bbox = d.textbbox((0, 0), presented_to_text, font=font_subtitle)
        presented_to_width = presented_to_bbox[2] - presented_to_bbox[0]
        d.text(((width - presented_to_width) / 2, 150), presented_to_text, fill=(51, 51, 51), font=font_subtitle)

        donor_text = donor_name.upper()
        donor_bbox = d.textbbox((0, 0), donor_text, font=font_title)
        donor_width = donor_bbox[2] - donor_bbox[0]
        d.text(((width - donor_width) / 2, 200), donor_text, fill=(0, 102, 102), font=font_title)

        body_line1 = "For your generous contribution of medicines,"
        body_line2 = "which will significantly help those in need"
        body_line3 = "through GiveHub's humanitarian efforts."
        
        body_line1_bbox = d.textbbox((0, 0), body_line1, font=font_body)
        body_line1_w = body_line1_bbox[2] - body_line1_bbox[0]
        
        body_line2_bbox = d.textbbox((0, 0), body_line2, font=font_body)
        body_line2_w = body_line2_bbox[2] - body_line2_bbox[0]
        
        body_line3_bbox = d.textbbox((0, 0), body_line3, font=font_body)
        body_line3_w = body_line3_bbox[2] - body_line3_bbox[0]

        d.text(((width - body_line1_w) / 2, 300), body_line1, fill=(0, 0, 0), font=font_body)
        d.text(((width - body_line2_w) / 2, 340), body_line2, fill=(0, 0, 0), font=font_body)
        d.text(((width - body_line3_w) / 2, 380), body_line3, fill=(0, 0, 0), font=font_body)

        date_text = f"Date: {datetime.now().strftime('%B %d, %Y')}"
        d.text((50, height - 100), date_text, fill=(51, 51, 51), font=font_body)

        signature_text = "The GiveHub Team"
        signature_bbox = d.textbbox((0, 0), signature_text, font=font_signature)
        signature_width = signature_bbox[2] - signature_bbox[0]
        d.text((width - signature_width - 50, height - 100), signature_text, fill=(0, 102, 102), font=font_signature)

        d.rectangle([20, 20, width - 20, height - 20], outline=(0, 102, 102), width=5)

        certificate_filename = f"certificate_{donation_id}.jpeg"
        # Ensure app.config['CERTIFICATE_FOLDER'] is correctly configured
        certificate_path = os.path.join(app.config['CERTIFICATE_FOLDER'], certificate_filename)
        img.save(certificate_path, "JPEG")
        return certificate_path
    except Exception as e:
        print(f"Error generating certificate for donation {donation_id}: {e}")
        import traceback
        traceback.print_exc()
        return None

def send_certificate_email(recipient_email, donor_name, certificate_path):
    try:
        msg = Message("Thank You for Your Generous Donation to GiveHub!",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[recipient_email])
        msg.body = f"""Dear {donor_name},

Thank you so much for your generous donation to GiveHub! Your contribution of medicines is greatly appreciated and will help those in need through our trusted NGO partners.

We are pleased to inform you that your donation has been successfully approved and processed by our medical store partners, and collected by GiveHub.

Attached is a Certificate of Appreciation for your support.

Warm regards,
The GiveHub Team"""

        if certificate_path and os.path.exists(certificate_path):
            with app.open_resource(certificate_path) as cert_file:
                msg.attach(os.path.basename(certificate_path), "image/jpeg", cert_file.read())
        else:
            print(f"Warning: Certificate file not found for {donor_name} at {certificate_path}. Email sent without attachment.")

        mail.send(msg)
        print(f"Certificate email sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"Error sending certificate email to {recipient_email}: {e}")
        import traceback
        traceback.print_exc()
        return False


# --- Routes ---

@app.route('/')
def index():
    session.pop('_flashed_messages', None)
    return render_template('index.html')

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/donation', methods=['GET', 'POST'])
@login_required
@donor_required
def donation():
    medical_stores = []
    form_data = {}

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id, name FROM medical_stores WHERE approved = TRUE")
            medical_stores = cur.fetchall()
    except Exception as e:
        flash(f"Error fetching medical stores: {e}", 'danger')

    if request.method == 'POST':
        form_data = request.form.to_dict()
        donor_name = request.form.get('donor_name')
        contact_number = request.form.get('contact_number')
        donor_email = request.form.get('email')
        address = request.form.get('address')
        medical_store_id_str = request.form.get('medical_store_id')
        num_meds_str = request.form.get('num_medicines')

        if not all([donor_name, contact_number, donor_email, address, medical_store_id_str, num_meds_str]):
            flash('All fields are required.', 'danger')
            return render_template('donation.html', form_data=form_data, medical_stores=medical_stores)

        try:
            num_meds = int(num_meds_str)
            medical_store_id = int(medical_store_id_str)
            if num_meds < 1:
                raise ValueError
        except ValueError:
            flash('Invalid number of medicines or medical store.', 'danger')
            return render_template('donation.html', form_data=form_data, medical_stores=medical_stores)

        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                conn.start_transaction()

                # Insert into donations table
                cur.execute("""
                    INSERT INTO donations (donor_name, contact_number, email, address, medical_store_id, status, medical_store_status, central_hub_status)
                    VALUES (%s, %s, %s, %s, %s, 'Pending', 'Assigned to Medical Store', 'Awaiting MS Receipt')
                """, (donor_name, contact_number, donor_email, address, medical_store_id))
                donation_id = cur.lastrowid

                # Insert individual medicine details into donation_medicines
                for i in range(num_meds):
                    name = request.form.get(f'medicine_name_{i}')
                    qty_str = request.form.get(f'quantity_{i}')
                    expiry_str = request.form.get(f'expiry_date_{i}')
                    image = request.files.get(f'image_{i}')

                    if not all([name, qty_str, expiry_str]):
                        flash(f'All medicine details for medicine {i+1} are required.', 'danger')
                        conn.rollback()
                        return render_template('donation.html', form_data=form_data, medical_stores=medical_stores)
                    
                    try:
                        qty = int(qty_str)
                        if qty < 1:
                            raise ValueError
                        expiry = datetime.strptime(expiry_str, '%Y-%m-%d').date() # Store as date
                    except ValueError:
                        flash(f'Invalid quantity or expiry date for medicine {i+1}.', 'danger')
                        conn.rollback()
                        return render_template('donation.html', form_data=form_data, medical_stores=medical_stores)

                    image_filename = None
                    if image and allowed_file(image.filename):
                        image_filename = secure_filename(f"donation_{donation_id}_med_{i}_{random.randint(1000,9999)}_{image.filename}")
                        image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                    
                    cur.execute("""
                        INSERT INTO donation_medicines (donation_id, medicine_name, quantity, expiry_date, image_filename)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (donation_id, name, qty, expiry, image_filename))

                conn.commit()
                flash('Donation submitted successfully. It is now awaiting review by the medical store.', 'success')
                return redirect(url_for('index'))
        except Exception as e:
            flash(f"Database error during donation submission: {e}", 'danger')
            if conn.is_connected():
                conn.rollback() # Rollback transaction on error
            return render_template('donation.html', form_data=form_data, medical_stores=medical_stores)

    return render_template('donation.html', medical_stores=medical_stores, form_data=form_data)


@app.route('/request', methods=['GET', 'POST'])
@login_required
@ngo_required
def request_medicine():
    if request.method == 'POST':
        num_meds_str = request.form.get('num_medicines')
        num_beneficiaries_str = request.form.get('num_beneficiaries')
        requester_name = request.form.get('name')
        contact_number = request.form.get('contactNumber', '')
        address = request.form.get('location')

        if not all([num_meds_str, num_beneficiaries_str, requester_name, address]):
            flash('All fields are required.', 'danger')
            return render_template('request.html', form_data=request.form)

        try:
            num_meds = int(num_meds_str)
            num_beneficiaries = int(num_beneficiaries_str)
            if num_meds < 1 or num_beneficiaries < 1:
                raise ValueError
        except ValueError:
            flash('Invalid numbers entered.', 'danger')
            return render_template('request.html', form_data=request.form)

        requester_id = session.get('id')

        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                conn.start_transaction()

                cur.execute("""
                    INSERT INTO requests (num_beneficiaries, requester_name, contact_number, address, status, requester_id)
                    VALUES (%s, %s, %s, %s, 'Pending', %s)
                """, (num_beneficiaries, requester_name, contact_number, address, requester_id))
                request_id = cur.lastrowid

                for i in range(num_meds):
                    name = request.form.get(f'request_medicine_name_{i}')
                    qty_str = request.form.get(f'request_quantity_{i}')

                    if not all([name, qty_str]):
                        flash(f'All medicine details for requested medicine {i+1} are required.', 'danger')
                        conn.rollback()
                        return render_template('request.html', form_data=request.form)

                    try:
                        qty = int(qty_str)
                        if qty < 1:
                            raise ValueError
                    except ValueError:
                        flash(f'Invalid quantity for requested medicine {i+1}.', 'danger')
                        conn.rollback()
                        return render_template('request.html', form_data=request.form)

                    cur.execute("""
    INSERT INTO request_medicines (request_id, medicine, quantity)  # Changed 'medicine_name' to 'medicine'
    VALUES (%s, %s, %s)
""", (request_id, name, qty)) # 'name' is the medicine name from the form, 'qty' is the quantity

                for i in range(num_beneficiaries):
                    bname = request.form.get(f'beneficiary_name_{i}')
                    age_str = request.form.get(f'beneficiary_age_{i}')
                    sex = request.form.get(f'beneficiary_sex_{i}')
                    doc = request.files.get(f'doctor_letter_{i}')
                    doc_path = None

                    if not all([bname, age_str, sex]):
                        flash(f'All beneficiary details for beneficiary {i+1} are required.', 'danger')
                        conn.rollback()
                        return render_template('request.html', form_data=request.form)
                    
                    try:
                        age = int(age_str)
                        if age < 0:
                            raise ValueError
                    except ValueError:
                        flash(f'Invalid age for beneficiary {i+1}.', 'danger')
                        conn.rollback()
                        return render_template('request.html', form_data=request.form)

                    if doc and allowed_document_file(doc.filename):
                        fname = secure_filename(doc.filename)
                        doc_path = f"prescription_{request_id}_{i}_{random.randint(1000,9999)}_{fname}"
                        doc.save(os.path.join(app.config['PRESCRIPTION_FOLDER'], doc_path))
                    else:
                        flash(f'Doctor letter (PDF) is required for beneficiary {i+1}.', 'danger')
                        conn.rollback()
                        return render_template('request.html', form_data=request.form)

                    cur.execute("""
                        INSERT INTO request_beneficiaries (request_id, beneficiary_name, age, sex, doctor_prescription_path)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (request_id, bname, age, sex, doc_path))

                conn.commit()
                flash('Request submitted successfully. It is now awaiting review by the Central Hub.', 'success')
                return redirect(url_for('index'))
        except Exception as e:
            flash(f"Request error: {e}", 'danger')
            if conn.is_connected():
                conn.rollback()
            return render_template('request.html', form_data=request.form)

    return render_template('request.html', form_data=request.form if request.method == 'POST' else {})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Both email and password are required.', 'danger')
            return render_template('login.html', form_data={'email': email})

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute('SELECT id, name, email, password, role FROM users WHERE email = %s', (email,))
                user = cursor.fetchone()

                if user and check_password_hash(user['password'], password):
                    # Check if Medical Store or NGO is approved
                    if user['role'] == 'Medical Store':
                        cursor.execute("SELECT approved FROM medical_stores WHERE user_id = %s", (user['id'],))
                        store_status = cursor.fetchone()
                        if not store_status or not store_status['approved']:
                            flash('Your Medical Store account is pending admin approval. Please wait for activation.', 'warning')
                            return render_template('login.html', form_data={'email': email})
                    elif user['role'] == 'NGO':
                        cursor.execute("SELECT approved FROM ngos WHERE user_id = %s", (user['id'],))
                        ngo_status = cursor.fetchone()
                        if not ngo_status or not ngo_status['approved']:
                            flash('Your NGO account is pending admin approval. Please wait for activation.', 'warning')
                            return render_template('login.html', form_data={'email': email})

                    session['loggedin'] = True
                    session['user_id'] = user['id']
                    session['name'] = user['name']
                    session['email'] = user['email']
                    session['role'] = user['role']
                    flash('Logged in successfully!', 'success')

                    if session['role'] == 'Admin':
                        return redirect(url_for('admin_dashboard'))
                    elif session['role'] == 'Medical Store':
                        return redirect(url_for('medical_store_dashboard'))
                    elif session['role'] == 'Donor':
                        return redirect(url_for('donation'))
                    elif session['role'] == 'NGO':
                        return redirect(url_for('request_medicine'))
                    elif session['role'] == 'Central Hub': # New redirection for Central Hub
                        return redirect(url_for('central_hub_dashboard'))
                    else:
                        return redirect(url_for('index'))
                else:
                    flash('Incorrect email or password.', 'danger')
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", 'danger')
            print(f"MySQL Error in login route: {err}")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", 'danger')
            print(f"Unexpected error in login route: {e}")

    return render_template('login.html', form_data={})

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html', form_data={
            'name': '', 'email': '', 'password': '', 'role': '',
            'ms_contact': '', 'ms_address': '',
            'ngo_contact': '', 'ngo_address': '', 'registration_number': ''
        })

    step = request.form.get('step')

    # Prepare form_data dictionary to always pass back for re-population
    # Initialize with default empty values
    form_data = {
        'name': request.form.get('name', ''),
        'email': request.form.get('email', ''),
        'password': request.form.get('password', ''), # Password usually not repopulated for security
        'role': request.form.get('role', ''),
        'ms_contact': request.form.get('ms_contact', ''),
        'ms_address': request.form.get('ms_address', ''),
        'ngo_contact': request.form.get('ngo_contact', ''),
        'ngo_address': request.form.get('ngo_address', ''),
        'registration_number': request.form.get('registration_number', '')
    }

    if step == 'send_otp':
        name = form_data['name']
        email = form_data['email']
        password = form_data['password']
        role = form_data['role']

        # Initialize contact/address for database storage, will be set based on role
        contact_to_store = None
        address_to_store = None
        reg_num_to_store = None

        if not all([name, email, password, role]):
            flash('All required fields (Name, Email, Password, Role) must be filled.', 'danger')
            return render_template('register.html', form_data=form_data)

        allowed_roles = ['Donor', 'NGO', 'Medical Store', 'Central Hub']
        if role not in allowed_roles:
            flash('Invalid role selected.', 'danger')
            return render_template('register.html', form_data=form_data)

        # Validate and set role-specific fields
        if role == 'Medical Store':
            contact_to_store = form_data['ms_contact']
            address_to_store = form_data['ms_address']
            if not all([contact_to_store, address_to_store]):
                flash('Contact Number and Address are required for Medical Store registration.', 'danger')
                return render_template('register.html', form_data=form_data)
        elif role == 'NGO':
            contact_to_store = form_data['ngo_contact']
            address_to_store = form_data['ngo_address']
            reg_num_to_store = form_data['registration_number']
            if not all([contact_to_store, address_to_store, reg_num_to_store]):
                flash('Contact Number, Address, and Registration Number are required for NGO registration.', 'danger')
                return render_template('register.html', form_data=form_data)
        # For Donor and Central Hub, contact_to_store, address_to_store, reg_num_to_store remain None

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM users WHERE email = %s', (email,))
                existing_user = cursor.fetchone()

            if existing_user:
                flash('An account with this email already exists. Please login or use forgot password.', 'danger')
                return render_template('register.html', form_data=form_data)

            otp = str(random.randint(100000, 999999))
            session['temp_user'] = {
                'name': name,
                'email': email,
                'password': password, # Store password temporarily (hashed later)
                'role': role,
                'contact': contact_to_store,
                'address': address_to_store,
                'registration_number': reg_num_to_store # Store the validated reg_num
            }
            session['otp'] = otp
            session['otp_timestamp'] = datetime.now().timestamp()

            msg = Message("Your OTP for GiveHub Registration",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f"Hello {name},\n\nYour One-Time Password (OTP) for GiveHub registration is: {otp}\n\nPlease use this OTP to complete your registration.\n\nThis OTP is valid for 5 minutes.\n\nThank you,\nThe GiveHub Team"
            mail.send(msg)
            flash('An OTP has been sent to your email address. Please check your inbox (and spam folder).', 'info')
            return render_template('register.html', show_otp=True, email=email, form_data=form_data)
        except Exception as e:
            flash(f'Failed to send OTP: {str(e)}. Please check your mail configuration and try again.', 'danger')
            print(f"Error sending OTP: {e}")
            return render_template('register.html', form_data=form_data)

    elif step == 'verify_otp':
        user_otp = request.form['otp']

        otp_timestamp = session.get('otp_timestamp')
        if otp_timestamp and (datetime.now().timestamp() - otp_timestamp) > 300:
            flash('OTP has expired. Please restart the registration process.', 'danger')
            session.pop('temp_user', None)
            session.pop('otp', None)
            session.pop('otp_timestamp', None)
            return render_template('register.html', form_data={})

        if user_otp == session.get('otp'):
            user_data = session.get('temp_user')
            if user_data:
                try:
                    hashed_password = generate_password_hash(user_data['password'])
                    user_role = user_data['role']
                    contact_number = user_data.get('contact') # This now holds the *correct* contact for the role
                    store_address = user_data.get('address')  # This now holds the *correct* address for the role
                    ngo_registration_number = user_data.get('registration_number')

                    with get_db_connection() as conn:
                        cursor = conn.cursor()
                        conn.start_transaction()

                        cursor.execute('INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)',
                                       (user_data['name'], user_data['email'], hashed_password, user_role))
                        user_id = cursor.lastrowid

                        if user_role == 'Medical Store':
                            cursor.execute(
                                "INSERT INTO medical_stores (user_id, name, email, contact_number, address, approved) VALUES (%s, %s, %s, %s, %s, %s)",
                                (user_id, user_data['name'], user_data['email'], contact_number, store_address, False)
                            )
                            flash_message = 'Medical Store application submitted! It will be active after admin approval.'
                        elif user_role == 'NGO':
                            cursor.execute(
                                "INSERT INTO ngos (user_id, name, email, contact_person, contact_number, address, registration_number, approved) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                                (user_id, user_data['name'], user_data['email'], user_data['name'], contact_number, store_address, ngo_registration_number, False)
                            )
                            flash_message = 'NGO application submitted! It will be active after admin approval.'
                        elif user_role == 'Central Hub':
                            flash_message = 'Central Hub account created successfully! You can now log in.'
                        else: # Donor
                            flash_message = 'Registration successful! You can now log in.'

                        conn.commit()

                    session.pop('temp_user', None)
                    session.pop('otp', None)
                    session.pop('otp_timestamp', None)
                    flash(flash_message, 'success')
                    return redirect(url_for('login'))

                except mysql.connector.Error as err:
                    if conn:
                        conn.rollback()
                    flash(f'An error occurred during registration: {err}', 'danger')
                    # Pass the original user data back to the template if an error occurs
                    return render_template('register.html', show_otp=True, email=user_data['email'], form_data=user_data)
                except Exception as e:
                    if conn:
                        conn.rollback()
                    flash(f'An unexpected error occurred during registration: {e}', 'danger')
                    # Pass the original user data back to the template if an error occurs
                    return render_template('register.html', show_otp=True, email=user_data['email'], form_data=user_data)
            else:
                flash('Session data missing. Please restart the registration process.', 'danger')
                return render_template('register.html', form_data={})
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            # If OTP is invalid, retrieve temp_user from session to repopulate fields
            # Also need to re-create the form_data for rendering
            if 'temp_user' in session:
                temp_user_data = session.get('temp_user')
                form_data['name'] = temp_user_data.get('name', '')
                form_data['email'] = temp_user_data.get('email', '')
                form_data['role'] = temp_user_data.get('role', '')
                # Repopulate specific fields based on role stored in temp_user
                if temp_user_data.get('role') == 'Medical Store':
                    form_data['ms_contact'] = temp_user_data.get('contact', '')
                    form_data['ms_address'] = temp_user_data.get('address', '')
                elif temp_user_data.get('role') == 'NGO':
                    form_data['ngo_contact'] = temp_user_data.get('contact', '')
                    form_data['ngo_address'] = temp_user_data.get('address', '')
                    form_data['registration_number'] = temp_user_data.get('registration_number', '')

            return render_template('register.html', show_otp=True, email=session.get('temp_user', {}).get('email'), form_data=form_data)
    # This line is for GET request, should return empty form_data as handled above
    return render_template('register.html', form_data={})

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_or_reset_password():
    if request.method == 'POST':
        step = request.form.get('step')

        if step == 'send_otp':
            email = request.form['email']
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT id, name FROM users WHERE email = %s', (email,))
                    user = cursor.fetchone()

                if user:
                    otp = str(random.randint(100000, 999999))
                    session['reset_email'] = email
                    session['reset_otp'] = otp
                    session['reset_otp_timestamp'] = datetime.now().timestamp()

                    msg = Message("Your OTP to Reset GiveHub Password",
                                  sender=app.config['MAIL_USERNAME'],
                                  recipients=[email])
                    msg.body = f"Hello {user[1]},\n\nYour One-Time Password (OTP) to reset your GiveHub password is: {otp}\n\nPlease use this OTP to set your new password.\n\nThis OTP is valid for 5 minutes.\n\nThank you,\nThe GiveHub Team"
                    mail.send(msg)
                    flash('An OTP has been sent to your email address for password reset. Please check your inbox (and spam folder).', 'info')
                    return render_template('reset_password.html', step='verify_otp', email=email)
                else:
                    flash('Email not found. Please enter a registered email address.', 'danger')
                    return render_template('reset_password.html', step='send_otp', email=email)
            except Exception as e:
                flash(f'Failed to send OTP: {str(e)}. Please check your mail configuration and try again.', 'danger')
                return render_template('reset_password.html', step='send_otp', error='Failed to send OTP.')

        elif step == 'verify_otp':
            user_otp = request.form['otp']
            reset_email = session.get('reset_email')
            stored_otp = session.get('reset_otp')
            otp_timestamp = session.get('reset_otp_timestamp')

            if not reset_email or not stored_otp or not otp_timestamp:
                flash('Password reset session expired or invalid. Please start over.', 'danger')
                return redirect(url_for('forgot_or_reset_password'))

            if (datetime.now().timestamp() - otp_timestamp) > 300: # 5 minutes expiry
                flash('OTP has expired. Please request a new one.', 'danger')
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                session.pop('reset_otp_timestamp', None)
                return render_template('reset_password.html', step='send_otp', email=reset_email)

            if user_otp == stored_otp:
                flash('OTP verified successfully. You can now set your new password.', 'success')
                return render_template('reset_password.html', step='set_password', email=reset_email)
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return render_template('reset_password.html', step='verify_otp', email=reset_email)

        elif step == 'set_password':
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            reset_email = session.get('reset_email')

            if not reset_email:
                flash('Password reset session expired or invalid. Please start over.', 'danger')
                return redirect(url_for('forgot_or_reset_password'))

            if new_password != confirm_password:
                flash('New password and confirm password do not match.', 'danger')
                return render_template('reset_password.html', step='set_password', email=reset_email)
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('reset_password.html', step='set_password', email=reset_email)


            try:
                hashed_password = generate_password_hash(new_password)
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET password = %s WHERE email = %s', (hashed_password, reset_email))
                    conn.commit()
                
                flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
                # Clear all reset-related session data
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                session.pop('reset_otp_timestamp', None)
                return redirect(url_for('login'))
            except Exception as e:
                flash(f'Failed to reset password: {str(e)}', 'danger')
                return render_template('reset_password.html', step='set_password', email=reset_email)
    
    return render_template('reset_password.html', step='send_otp')


# --- Admin Dashboard and Functions ---
@app.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    pending_medical_stores = []
    pending_ngos = []
    all_donations = []
    all_requests = []
    
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            
            # Fetch pending Medical Stores
            cur.execute("SELECT ms.*, u.email FROM medical_stores ms JOIN users u ON ms.user_id = u.id WHERE ms.approved = FALSE")
            pending_medical_stores = cur.fetchall()

            # Fetch pending NGOs
            cur.execute("SELECT n.*, u.email FROM ngos n JOIN users u ON n.user_id = u.id WHERE n.approved = FALSE")
            pending_ngos = cur.fetchall()

            # Fetch all donations
            cur.execute("""
                SELECT d.*, ms.name AS medical_store_name 
                FROM donations d 
                LEFT JOIN medical_stores ms ON d.medical_store_id = ms.id
                ORDER BY d.created_at DESC
            """)
            all_donations = cur.fetchall()

            # Fetch all requests
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, ms.name AS medical_store_name
                FROM requests r 
                JOIN users u ON r.requester_id = u.id
                LEFT JOIN medical_stores ms ON r.medical_store_id = ms.id
                ORDER BY r.created_at DESC
            """)
            all_requests = cur.fetchall()

    except Exception as e:
        flash(f"Error fetching data for admin dashboard: {e}", 'danger')

    return render_template('admin_dashboard.html', 
                           pending_medical_stores=pending_medical_stores,
                           pending_ngos=pending_ngos,
                           all_donations=all_donations,
                           all_requests=all_requests)

@app.route('/admin_approve_medical_store/<int:store_id>', methods=['POST'])
@admin_required
def admin_approve_medical_store(store_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE medical_stores SET approved = TRUE WHERE id = %s", (store_id,))
            conn.commit()
            flash('Medical Store approved successfully!', 'success')
    except Exception as e:
        flash(f"Error approving medical store: {e}", 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_reject_medical_store/<int:store_id>', methods=['POST'])
@admin_required
def admin_reject_medical_store(store_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Optionally, you might want to delete the user account associated with it
            cur.execute("DELETE FROM medical_stores WHERE id = %s", (store_id,))
            # Consider also deleting the user from 'users' table if no other roles
            flash('Medical Store application rejected and removed.', 'info')
            conn.commit()
    except Exception as e:
        flash(f"Error rejecting medical store: {e}", 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_approve_ngo/<int:ngo_id>', methods=['POST'])
@admin_required
def admin_approve_ngo(ngo_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE ngos SET approved = TRUE WHERE id = %s", (ngo_id,))
            conn.commit()
            flash('NGO approved successfully!', 'success')
    except Exception as e:
        flash(f"Error approving NGO: {e}", 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_reject_ngo/<int:ngo_id>', methods=['POST'])
@admin_required
def admin_reject_ngo(ngo_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Optionally, you might want to delete the user account associated with it
            cur.execute("DELETE FROM ngos WHERE id = %s", (ngo_id,))
            # Consider also deleting the user from 'users' table if no other roles
            flash('NGO application rejected and removed.', 'info')
            conn.commit()
    except Exception as e:
        flash(f"Error rejecting NGO: {e}", 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_view_donation_details/<int:donation_id>')
@admin_required
def admin_view_donation_details(donation_id):
    donation = None
    medicines = []
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT d.*, ms.name AS medical_store_name, ms.contact_number AS ms_contact, ms.address AS ms_address
                FROM donations d
                LEFT JOIN medical_stores ms ON d.medical_store_id = ms.id
                WHERE d.id = %s
            """, (donation_id,))
            donation = cur.fetchone()

            if donation:
                cur.execute("SELECT * FROM donation_medicines WHERE donation_id = %s", (donation_id,))
                medicines = cur.fetchall()
            else:
                flash("Donation not found.", "danger")
                return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f"Error fetching donation details: {e}", "danger")
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_donation_details.html', donation=donation, medicines=medicines)

@app.route('/admin_view_request_details/<int:request_id>')
@admin_required
def admin_view_request_details(request_id):
    request_data = None
    medicines = []
    beneficiaries = []
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email, ms.name AS medical_store_name
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                LEFT JOIN medical_stores ms ON r.medical_store_id = ms.id
                WHERE r.id = %s
            """, (request_id,))
            request_data = cur.fetchone()

            if request_data:
                cur.execute("SELECT * FROM request_medicines WHERE request_id = %s", (request_id,))
                medicines = cur.fetchall()
                cur.execute("SELECT * FROM request_beneficiaries WHERE request_id = %s", (request_id,))
                beneficiaries = cur.fetchall()
            else:
                flash("Request not found.", "danger")
                return redirect(url_for('admin_dashboard'))
    except Exception as e:
        flash(f"Error fetching request details: {e}", "danger")
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_request_details.html', request_data=request_data, medicines=medicines, beneficiaries=beneficiaries)

# In your app.py

@app.route('/add_ngo', methods=['GET', 'POST'])
@login_required
@admin_required
def add_ngo():
    if request.method == 'POST':
        # Handle form submission for adding a new NGO
        ngo_name = request.form['name']
        ngo_email = request.form['email']
        # ... other NGO details
        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                # Assuming you also need to create a user account for the NGO
                # First, create a user and get their ID
                cur.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s)",
                            (ngo_email, generate_password_hash("default_password"), 'ngo')) # Use a proper password generation
                user_id = cur.lastrowid

                cur.execute("INSERT INTO ngos (user_id, name, contact_person, contact_number, address, registration_number, approved) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                            (user_id, ngo_name, request.form.get('contact_person'), request.form.get('contact_number'), request.form.get('address'), request.form.get('registration_number'), True)) # Assuming admin adds approved NGOs
                conn.commit()
                flash('NGO added successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f"Error adding NGO: {e}", 'danger')
            # Handle potential rollback here if necessary
    return render_template('add_ngo.html') # Create this template

# --- Central Hub Dashboard and Functions ---
@app.route('/central_hub_dashboard')
@login_required
@central_hub_required
def central_hub_dashboard():
    assigned_donations = []
    pending_requests = []
    approved_requests = []
    medical_stores = []
    central_inventory = [] # New list for inventory

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)

            # Donations awaiting Central Hub receipt from Medical Stores
            cur.execute("""
                SELECT d.*, dm.medicine_name, dm.quantity, dm.batch_no, dm.expiry_date,
                       ms.name AS medical_store_name, ms.contact_number AS ms_contact, ms.address AS ms_address
                FROM donations d
                JOIN donation_medicines dm ON d.id = dm.donation_id -- <--- ADD THIS JOIN
                JOIN medical_stores ms ON d.medical_store_id = ms.id
                WHERE d.medical_store_status = 'Received by MS' AND d.central_hub_status = 'Awaiting CH Receipt'
                ORDER BY d.created_at DESC
            """)
            assigned_donations = cur.fetchall()

            # Requests pending Central Hub approval
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                WHERE r.status = 'Pending'
                ORDER BY r.created_at DESC
            """)
            pending_requests = cur.fetchall()

            # Requests approved by Central Hub, awaiting Medical Store assignment/fulfillment
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email, ms.name AS medical_store_name
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                LEFT JOIN medical_stores ms ON r.medical_store_id = ms.id
                WHERE r.status = 'Approved by CH' OR r.status = 'Assigned to MS'
                ORDER BY r.created_at DESC
            """)
            approved_requests = cur.fetchall()

            # Fetch approved medical stores for assigning requests
            cur.execute("SELECT id, name FROM medical_stores WHERE approved = TRUE")
            medical_stores = cur.fetchall()

            # NEW: Fetch Central Hub Inventory, ordered by expiry date (FEFO)
            cur.execute("""
                SELECT
                    ci.id AS inventory_id,
                    ci.medicine_name,
                    ci.batch_no,
                    ci.quantity,
                    ci.expiry_date,
                    ci.unit_price,
                    ci.current_location,
                    ci.received_at
                FROM
                    central_inventory ci
                WHERE
                    ci.quantity > 0 AND ci.expiry_date > CURDATE()
                ORDER BY
                    ci.expiry_date ASC, ci.received_at ASC
            """)
            central_inventory = cur.fetchall()

    except Exception as e:
        flash(f"Error fetching Central Hub data: {e}", 'danger')

    return render_template('central_hub_dashboard.html',
                            assigned_donations=assigned_donations,
                            pending_requests=pending_requests,
                            approved_requests=approved_requests,
                            medical_stores=medical_stores,
                            central_inventory=central_inventory) # Pass inventory data

@app.route('/central_hub_confirm_donation/<int:donation_id>', methods=['POST'])
@central_hub_required
def central_hub_confirm_donation(donation_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            conn.start_transaction()

            # Get donor email and name for certificate
            # Fetch basic donation info from 'donations' table
            cur.execute("SELECT donor_name, email FROM donations WHERE id = %s", (donation_id,))
            donation_header_info = cur.fetchone()

            if not donation_header_info:
                flash("Donation not found.", "danger")
                conn.rollback()
                return redirect(url_for('central_hub_dashboard'))

            donor_name = donation_header_info['donor_name']
            donor_email = donation_header_info['email']
            
            # Fetch ALL medicines associated with this donation from 'donation_medicines' table
            cur.execute("SELECT medicine_name, quantity, expiry_date, batch_no FROM donation_medicines WHERE donation_id = %s", (donation_id,))
            donated_medicines = cur.fetchall()

            if not donated_medicines:
                flash("No medicines found for this donation. Cannot confirm.", "danger")
                conn.rollback()
                return redirect(url_for('central_hub_dashboard'))

            # Update donation status in the 'donations' table
            cur.execute("""
                UPDATE donations SET
                status = 'Collected by CH',
                central_hub_status = 'Central Hub Received'
                WHERE id = %s
            """, (donation_id,))

            # Add confirmed donation medicines to central_inventory (one by one if multiple)
            for med in donated_medicines:
                # Ensure medicine_name is not None before insertion
                if not med['medicine_name']:
                    raise ValueError(f"Medicine name is missing for donation ID {donation_id}. Cannot proceed.")
                
                cur.execute("""
                    INSERT INTO central_inventory (medicine_name, quantity, batch_no, expiry_date, current_location, received_at)
                    VALUES (%s, %s, %s, %s, 'Central Hub', NOW())
                """, (med['medicine_name'], med['quantity'], med.get('batch_no'), med['expiry_date'])) # Use .get for batch_no as it might be null

            # Generate and send certificate
            certificate_path = generate_certificate(donor_name, donation_id)
            if certificate_path:
                cur.execute("UPDATE donations SET certificate_path = %s WHERE id = %s", (certificate_path, donation_id))
                send_certificate_email(donor_email, donor_name, certificate_path)
                flash('Donation confirmed and certificate sent to donor. Inventory updated.', 'success')
            else:
                flash('Donation confirmed, but failed to generate/send certificate. Check server logs. Inventory updated.', 'warning')

            conn.commit()
    except ValueError as ve: # Catch specific validation errors
        flash(f"Data error: {ve}", 'danger')
        if conn.is_connected():
            conn.rollback()
    except Exception as e:
        flash(f"Error confirming donation: {e}", 'danger')
        if conn.is_connected():
            conn.rollback()
    return redirect(url_for('central_hub_dashboard'))

@app.route('/central_hub_approve_request/<int:request_id>', methods=['POST'])
@central_hub_required
def central_hub_approve_request(request_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE requests SET status = 'Approved by CH' WHERE id = %s", (request_id,))
            conn.commit()
            flash('Request approved by Central Hub. Now assign it to a Medical Store.', 'success')
    except Exception as e:
        flash(f"Error approving request: {e}", 'danger')
    return redirect(url_for('central_hub_dashboard'))

@app.route('/central_hub_reject_request/<int:request_id>', methods=['POST'])
@central_hub_required
def central_hub_reject_request(request_id):
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE requests SET status = 'Rejected by CH' WHERE id = %s", (request_id,))
            conn.commit()
            flash('Request rejected by Central Hub.', 'info')
    except Exception as e:
        flash(f"Error rejecting request: {e}", 'danger')
    return redirect(url_for('central_hub_dashboard'))

@app.route('/central_hub_assign_request/<int:request_id>', methods=['POST'])
@central_hub_required
def central_hub_assign_request(request_id):
    medical_store_id = request.form.get('medical_store_id')
    if not medical_store_id:
        flash('Please select a Medical Store.', 'danger')
        return redirect(url_for('central_hub_dashboard'))

    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE requests SET medical_store_id = %s, status = 'Assigned to MS'
                WHERE id = %s
            """, (medical_store_id, request_id))
            conn.commit()
            flash(f'Request assigned to Medical Store ID {medical_store_id}.', 'success')
    except Exception as e:
        flash(f"Error assigning request: {e}", 'danger')
    return redirect(url_for('central_hub_dashboard'))

# NEW: Route for issuing medicine
@app.route('/central_hub_issue_medicine', methods=['POST'])
@central_hub_required
def central_hub_issue_medicine():
    request_id = request.form.get('request_id')
    medicine_name = request.form.get('medicine_name')
    quantity_to_issue = int(request.form.get('quantity_to_issue', 0))

    if not request_id or not medicine_name or quantity_to_issue <= 0:
        flash("Invalid input for issuing medicine.", "danger")
        return redirect(url_for('central_hub_dashboard'))

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            conn.start_transaction()

            # 1. Check if the request is approved and not yet fulfilled
            cur.execute("SELECT * FROM requests WHERE id = %s AND (status = 'Approved by CH' OR status = 'Assigned to MS')", (request_id,))
            req_data = cur.fetchone()
            if not req_data:
                flash(f"Request {request_id} is not in a state to issue medicine or does not exist.", "danger")
                conn.rollback()
                return redirect(url_for('central_hub_dashboard'))

            # 2. Get available inventory for the requested medicine, ordered by expiry date (FEFO)
            cur.execute("""
                SELECT id, quantity, expiry_date
                FROM central_inventory
                WHERE medicine_name = %s AND quantity > 0 AND expiry_date > CURDATE()
                ORDER BY expiry_date ASC, received_at ASC
            """, (medicine_name,))
            available_batches = cur.fetchall()

            total_available = sum(batch['quantity'] for batch in available_batches)

            if total_available < quantity_to_issue:
                flash(f"Insufficient stock for {medicine_name}. Available: {total_available}, Requested: {quantity_to_issue}.", "danger")
                conn.rollback()
                return redirect(url_for('central_hub_dashboard'))

            issued_quantity_count = 0
            for batch in available_batches:
                if issued_quantity_count >= quantity_to_issue:
                    break # Already issued enough

                quantity_from_batch = min(batch['quantity'], quantity_to_issue - issued_quantity_count)

                # Update the inventory for the current batch
                cur.execute("UPDATE central_inventory SET quantity = quantity - %s WHERE id = %s",
                            (quantity_from_batch, batch['id']))

                # Record the issue (you might want a separate 'issue_log' table)
                # For simplicity, we'll assume updating request status for now.
                # A more robust system would track issued medicines per request in detail.

                issued_quantity_count += quantity_from_batch

            # Update the request status if fully fulfilled, or partially fulfilled
            if issued_quantity_count == quantity_to_issue:
                cur.execute("UPDATE requests SET status = 'Fulfilled by CH' WHERE id = %s", (request_id,))
                flash(f"Successfully issued {issued_quantity_count} units of {medicine_name} for Request ID {request_id}.", "success")
            else:
                # This scenario should ideally not happen if total_available was checked
                # but good to have a fallback or more granular tracking for partial issues.
                flash(f"Partially issued {issued_quantity_count} units of {medicine_name} for Request ID {request_id}. Remaining to issue: {quantity_to_issue - issued_quantity_count}.", "warning")
                # You might update request status to 'Partially Fulfilled' here

            conn.commit()

    except Exception as e:
        flash(f"Error issuing medicine: {e}", 'danger')
        if conn.is_connected():
            conn.rollback()
    return redirect(url_for('central_hub_dashboard'))


@app.route('/central_hub_view_request_details/<int:request_id>')
@central_hub_required
def central_hub_view_request_details(request_id):
    request_data = None
    medicines = []
    beneficiaries = []
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email, ms.name AS medical_store_name
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                LEFT JOIN medical_stores ms ON r.medical_store_id = ms.id
                WHERE r.id = %s
            """, (request_id,))
            request_data = cur.fetchone()

            if request_data:
                cur.execute("SELECT * FROM request_medicines WHERE request_id = %s", (request_id,))
                medicines = cur.fetchall()
                cur.execute("SELECT * FROM request_beneficiaries WHERE request_id = %s", (request_id,))
                beneficiaries = cur.fetchall()
            else:
                flash("Request not found.", "danger")
                return redirect(url_for('central_hub_dashboard'))
    except Exception as e:
        flash(f"Error fetching request details: {e}", "danger")
        return redirect(url_for('central_hub_dashboard'))

    return render_template('central_hub_request_details.html', request_data=request_data, medicines=medicines, beneficiaries=beneficiaries)
# Medical store dashb
@app.route('/medical_store_dashboard')
@login_required
@medical_store_required
def medical_store_dashboard():
    medical_store_id = None
    assigned_donations = []
    stock_medicines = []
    assigned_requests = []

    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],)) # Use session['user_id']
            ms_info = cur.fetchone()
            if ms_info:
                medical_store_id = ms_info['id']
            else:
                flash('Medical Store profile not found.', 'danger')
                return redirect(url_for('index'))

            # Donations assigned to this medical store for initial receipt/verification
            cur.execute("""
                SELECT d.*, dm.medicine_name, dm.quantity, dm.expiry_date, dm.image_filename
                FROM donations d
                JOIN donation_medicines dm ON d.id = dm.donation_id
                WHERE d.medical_store_id = %s AND d.medical_store_status = 'Assigned to Medical Store'
                ORDER BY d.created_at DESC
            """, (medical_store_id,))
            assigned_donations = cur.fetchall()

            # Current stock of medicines - Group by medicine_name and expiry_date, order by expiry_date (FEFO)
            cur.execute("""
                SELECT medicine_name, SUM(quantity) as total_quantity, expiry_date
                FROM medical_store_stock
                WHERE medical_store_id = %s AND quantity > 0 AND expiry_date > CURDATE()
                GROUP BY medicine_name, expiry_date
                ORDER BY expiry_date ASC, medicine_name ASC
            """, (medical_store_id,))
            stock_medicines = cur.fetchall()

            # Requests assigned to this medical store for fulfillment
            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                WHERE r.medical_store_id = %s AND r.status = 'Assigned to MS'
                ORDER BY r.created_at DESC
            """, (medical_store_id,))
            assigned_requests = cur.fetchall()


    except Exception as e:
        flash(f"Error fetching Medical Store data: {e}", 'danger')

    return render_template('medical_store_dashboard.html',
                            assigned_donations=assigned_donations,
                            stock_medicines=stock_medicines,
                            assigned_requests=assigned_requests)

@app.route('/medical_store_confirm_donation_receipt/<int:donation_id>', methods=['POST'])
@medical_store_required
def medical_store_confirm_donation_receipt(donation_id):
    # Retrieve form data
    received_medicine_name = request.form.get('received_medicine_name')
    batch_no = request.form.get('batch_no')
    received_quantity = request.form.get('received_quantity')
    unit_price = request.form.get('unit_price')
    expiry_date_str = request.form.get('expiry_date') # Keep as string for now

    if not received_medicine_name or not batch_no or not received_quantity or not expiry_date_str:
        flash('Missing required fields (Medicine Name, Batch No, Quantity, Expiry Date).', 'danger')
        return redirect(url_for('medical_store_dashboard'))

    try:
        received_quantity = int(received_quantity)
        if received_quantity <= 0:
            raise ValueError("Quantity must be positive.")
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
        if expiry_date < date.today():
            flash('Expiry date cannot be in the past.', 'danger')
            return redirect(url_for('medical_store_dashboard'))

        unit_price = float(unit_price) if unit_price else None # Handle optional price

    except ValueError as e:
        flash(f"Invalid input: {e}", "danger")
        return redirect(url_for('medical_store_dashboard'))


    medical_store_id = None
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            conn.start_transaction()

            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],)) # Use session['user_id']
            ms_info = cur.fetchone()
            if not ms_info:
                flash('Medical Store profile not found.', 'danger')
                conn.rollback()
                return redirect(url_for('medical_store_dashboard'))
            medical_store_id = ms_info[0]

            # Check if the donation is indeed assigned to this medical store
            cur.execute("SELECT medical_store_id FROM donations WHERE id = %s", (donation_id,))
            donation_ms_id = cur.fetchone()
            if not donation_ms_id or donation_ms_id[0] != medical_store_id:
                flash('Access denied or donation not assigned to your store.', 'danger')
                conn.rollback()
                return redirect(url_for('medical_store_dashboard'))

            # Update donation status
            cur.execute("""
                UPDATE donations SET
                status = 'Approved by MS',
                medical_store_status = 'Received by MS',
                central_hub_status = 'Awaiting CH Receipt'
                WHERE id = %s
            """, (donation_id,))

            # Add medicines from this donation to the medical store's stock
            # IMPORTANT: Now inserting the actual received data from the form
            cur.execute("""
                INSERT INTO medical_store_stock (medical_store_id, medicine_name, quantity, batch_no, expiry_date, unit_price)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (medical_store_id, received_medicine_name, received_quantity, batch_no, expiry_date, unit_price))

            conn.commit()
            flash('Donation receipt confirmed and medicines added to stock with batch and price details. Central Hub will be notified.', 'success')
    except Exception as e:
        flash(f"Error confirming donation receipt: {e}", 'danger')
        if conn.is_connected():
            conn.rollback()
    return redirect(url_for('medical_store_dashboard'))

# --- Other existing routes (medical_store_reject_donation, medical_store_fulfill_request, etc.) ---
# Ensure these still exist and are correctly implemented in your app.py

@app.route('/medical_store_reject_donation/<int:donation_id>', methods=['POST'])
@medical_store_required
def medical_store_reject_donation(donation_id):
    medical_store_id = None
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],))
            ms_info = cur.fetchone()
            if not ms_info:
                flash('Medical Store profile not found.', 'danger')
                return redirect(url_for('medical_store_dashboard'))
            medical_store_id = ms_info[0]

            cur.execute("SELECT medical_store_id FROM donations WHERE id = %s", (donation_id,))
            donation_ms_id = cur.fetchone()
            if not donation_ms_id or donation_ms_id[0] != medical_store_id:
                flash('Access denied or donation not assigned to your store.', 'danger')
                return redirect(url_for('medical_store_dashboard'))

            cur.execute("""
                UPDATE donations SET
                status = 'Rejected by MS',
                medical_store_status = 'Rejected by MS',
                central_hub_status = 'MS Rejected'
                WHERE id = %s
            """, (donation_id,))
            conn.commit()
            flash('Donation rejected. Donor and Central Hub will be notified.', 'info')
    except Exception as e:
        flash(f"Error rejecting donation: {e}", 'danger')
    return redirect(url_for('medical_store_dashboard'))

@app.route('/medical_store_fulfill_request/<int:request_id>', methods=['POST'])
@medical_store_required
def medical_store_fulfill_request(request_id):
    medical_store_id = None
    try:
        with get_db_connection() as conn:
            cur = conn.cursor()
            conn.start_transaction()

            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],))
            ms_info = cur.fetchone()
            if not ms_info:
                flash('Medical Store profile not found.', 'danger')
                conn.rollback()
                return redirect(url_for('medical_store_dashboard'))
            medical_store_id = ms_info[0]

            # Check if the request is indeed assigned to this medical store
            cur.execute("SELECT medical_store_id FROM requests WHERE id = %s", (request_id,))
            request_ms_id = cur.fetchone()
            if not request_ms_id or request_ms_id[0] != medical_store_id:
                flash('Access denied or request not assigned to your store.', 'danger')
                conn.rollback()
                return redirect(url_for('medical_store_dashboard'))

            # Get requested medicines
            cur.execute("SELECT medicine_name, quantity FROM request_medicines WHERE request_id = %s", (request_id,))
            requested_medicines = cur.fetchall()

            # Check stock and deduct (FEFO logic applied in ORDER BY)
            for med_name, requested_qty in requested_medicines:
                cur.execute("""
                    SELECT id, quantity FROM medical_store_stock
                    WHERE medical_store_id = %s AND medicine_name = %s AND quantity > 0 AND expiry_date > CURDATE()
                    ORDER BY expiry_date ASC, received_at ASC
                """, (medical_store_id, med_name))
                available_batches = cur.fetchall() # Renamed from available_stock for clarity

                total_available_qty = sum(batch[1] for batch in available_batches) # Sum of quantity from each batch

                if total_available_qty < requested_qty:
                    flash(f'Insufficient stock for {med_name}. Cannot fulfill request. Available: {total_available_qty}, Requested: {requested_qty}.', 'danger')
                    conn.rollback()
                    return redirect(url_for('medical_store_dashboard'))

                current_deducted_qty = 0
                for stock_id, stock_qty in available_batches:
                    if current_deducted_qty >= requested_qty:
                        break # Enough stock already deducted

                    needed_from_this_batch = min(requested_qty - current_deducted_qty, stock_qty)

                    if needed_from_this_batch > 0:
                        new_stock_qty = stock_qty - needed_from_this_batch
                        cur.execute("UPDATE medical_store_stock SET quantity = %s WHERE id = %s", (new_stock_qty, stock_id))
                        current_deducted_qty += needed_from_this_batch

            # Update request status
            cur.execute("UPDATE requests SET status = 'Fulfilled by MS' WHERE id = %s", (request_id,))
            conn.commit()
            flash('Request fulfilled successfully and stock updated!', 'success')
    except Exception as e:
        flash(f"Error fulfilling request: {e}", 'danger')
        if conn.is_connected():
            conn.rollback()
    return redirect(url_for('medical_store_dashboard'))


@app.route('/medical_store_view_donation_details/<int:donation_id>')
@medical_store_required
def medical_store_view_donation_details(donation_id):
    donation = None
    medicines = []
    medical_store_id = None
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],))
            ms_info = cur.fetchone()
            if ms_info:
                medical_store_id = ms_info['id']
            else:
                flash('Medical Store profile not found.', 'danger')
                return redirect(url_for('medical_store_dashboard'))

            cur.execute("""
                SELECT d.*
                FROM donations d
                WHERE d.id = %s AND d.medical_store_id = %s
            """, (donation_id, medical_store_id))
            donation = cur.fetchone()

            if donation:
                cur.execute("SELECT * FROM donation_medicines WHERE donation_id = %s", (donation_id,))
                medicines = cur.fetchall()
            else:
                flash("Donation not found or not assigned to your store.", "danger")
                return redirect(url_for('medical_store_dashboard'))
    except Exception as e:
        flash(f"Error fetching donation details: {e}", "danger")
        return redirect(url_for('medical_store_dashboard'))

    return render_template('medical_store_donation_details.html', donation=donation, medicines=medicines)

@app.route('/medical_store_view_request_details/<int:request_id>')
@medical_store_required
def medical_store_view_request_details(request_id):
    request_data = None
    medicines = []
    beneficiaries = []
    medical_store_id = None
    try:
        with get_db_connection() as conn:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT id FROM medical_stores WHERE user_id = %s", (session['user_id'],))
            ms_info = cur.fetchone()
            if ms_info:
                medical_store_id = ms_info['id']
            else:
                flash('Medical Store profile not found.', 'danger')
                return redirect(url_for('medical_store_dashboard'))

            cur.execute("""
                SELECT r.*, u.name AS ngo_name, u.email AS ngo_email
                FROM requests r
                JOIN users u ON r.requester_id = u.id
                WHERE r.id = %s AND r.medical_store_id = %s
            """, (request_id, medical_store_id))
            request_data = cur.fetchone()

            if request_data:
                cur.execute("SELECT * FROM request_medicines WHERE request_id = %s", (request_id,))
                medicines = cur.fetchall()
                cur.execute("SELECT * FROM request_beneficiaries WHERE request_id = %s", (request_id,))
                beneficiaries = cur.fetchall()
            else:
                flash("Request not found or not assigned to your store.", "danger")
                return redirect(url_for('medical_store_dashboard'))
    except Exception as e:
        flash(f"Error fetching request details: {e}", "danger")
        return redirect(url_for('medical_store_dashboard'))

    return render_template('medical_store_request_details.html', request_data=request_data, medicines=medicines, beneficiaries=beneficiaries)


@app.route('/static/prescriptions/<filename>')
def uploaded_prescription(filename):
    return send_from_directory(app.config['PRESCRIPTION_FOLDER'], filename)

@app.route('/static/certificates/<filename>')
def uploaded_certificate(filename):
    return send_from_directory(app.config['CERTIFICATE_FOLDER'], filename)

@app.route('/static/uploads/<filename>')
def uploaded_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['PRESCRIPTION_FOLDER'], exist_ok=True)
    os.makedirs(app.config['CERTIFICATE_FOLDER'], exist_ok=True)
    app.run(debug=True, host='0.0.0.0')
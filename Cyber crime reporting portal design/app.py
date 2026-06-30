"""
CyberSafe India — Cyber Crime Reporting Portal
Main Flask Application
"""
import os
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_from_directory
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from werkzeug.utils import secure_filename

from database import db, User, Complaint, Alert, Statistic, init_db

# ─── App Configuration ───────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersafe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'mp4', 'mp3'}

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    """Decorator for admin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ─── Public Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    """Main portal page"""
    stats = Statistic.query.first()
    alerts = Alert.query.filter_by(is_active=True).order_by(Alert.created_at.desc()).all()
    recent_cases = Complaint.query.order_by(Complaint.created_at.desc()).limit(5).all()
    return render_template('index.html', stats=stats, alerts=alerts, recent_cases=recent_cases)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not all([name, email, phone, password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        user = User(name=name, email=email, phone=phone, is_verified=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            flash(f'Welcome back, {user.name}!', 'success')
            next_page = request.args.get('next')
            if user.role == 'admin':
                return redirect(next_page or url_for('admin_dashboard'))
            return redirect(next_page or url_for('dashboard'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


# ─── Complaint Routes ────────────────────────────────────────────────

@app.route('/complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    """File a new complaint"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        mobile = request.form.get('mobile', '').strip()
        email = request.form.get('email', '').strip()
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        amount_lost = request.form.get('amount_lost', 0)

        if not all([name, mobile, category, description]):
            flash('Please fill all required fields.', 'danger')
            return render_template('complaint.html')

        # Handle file upload
        evidence_filename = None
        if 'evidence' in request.files:
            file = request.files['evidence']
            if file and file.filename and allowed_file(file.filename):
                evidence_filename = secure_filename(f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], evidence_filename))

        # Generate unique case ID
        case_id = Complaint.generate_case_id()
        while Complaint.query.filter_by(case_id=case_id).first():
            case_id = Complaint.generate_case_id()

        complaint = Complaint(
            case_id=case_id,
            user_id=current_user.id,
            name=name,
            mobile=mobile,
            email=email,
            category=category,
            description=description,
            evidence_file=evidence_filename,
            amount_lost=float(amount_lost) if amount_lost else 0.0,
            status='Submitted',
            priority='Medium'
        )
        db.session.add(complaint)

        # Update statistics
        stats = Statistic.query.first()
        if stats:
            stats.total_reports += 1
            stats.updated_at = datetime.utcnow()

        db.session.commit()

        flash(f'Complaint filed successfully! Your Case ID: {case_id}', 'success')
        return redirect(url_for('track_case', case_id=case_id))

    return render_template('complaint.html')


@app.route('/track')
def track_case():
    """Track case status"""
    case_id = request.args.get('case_id', '').strip()
    complaint = None
    if case_id:
        complaint = Complaint.query.filter_by(case_id=case_id).first()
        if not complaint:
            flash('Case not found. Please check the Case ID.', 'warning')
    return render_template('track_case.html', complaint=complaint, case_id=case_id)


@app.route('/awareness')
def awareness():
    """Cyber awareness tips page"""
    return render_template('awareness.html')


# ─── User Dashboard ──────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('dashboard.html', complaints=complaints)


# ─── Admin Routes ────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    total_complaints = Complaint.query.count()
    pending = Complaint.query.filter_by(status='Submitted').count()
    investigating = Complaint.query.filter_by(status='Investigating').count()
    resolved = Complaint.query.filter_by(status='Resolved').count()
    recent = Complaint.query.order_by(Complaint.created_at.desc()).limit(20).all()
    stats = Statistic.query.first()
    return render_template('admin_dashboard.html',
                           total=total_complaints,
                           pending=pending,
                           investigating=investigating,
                           resolved=resolved,
                           recent=recent,
                           stats=stats)


@app.route('/admin/update_case/<int:complaint_id>', methods=['POST'])
@login_required
@admin_required
def update_case(complaint_id):
    """Admin update case status"""
    complaint = Complaint.query.get_or_404(complaint_id)
    new_status = request.form.get('status', complaint.status)
    notes = request.form.get('notes', '')
    priority = request.form.get('priority', complaint.priority)
    amount_recovered = request.form.get('amount_recovered', complaint.amount_recovered)

    complaint.status = new_status
    complaint.priority = priority
    complaint.officer_notes = notes
    complaint.amount_recovered = float(amount_recovered) if amount_recovered else 0.0
    complaint.updated_at = datetime.utcnow()

    # Update stats if resolved
    if new_status == 'Resolved':
        stats = Statistic.query.first()
        if stats:
            total = Complaint.query.count()
            resolved_count = Complaint.query.filter_by(status='Resolved').count()
            stats.resolution_rate = round((resolved_count / total) * 100, 1) if total > 0 else 0
            stats.amount_recovered += float(amount_recovered) if amount_recovered else 0

    db.session.commit()
    flash(f'Case {complaint.case_id} updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


# ─── API Routes ──────────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    """Get live statistics"""
    stats = Statistic.query.first()
    if stats:
        return jsonify({
            'total_reports': stats.total_reports,
            'amount_recovered': stats.amount_recovered,
            'resolution_rate': stats.resolution_rate
        })
    return jsonify({'total_reports': 0, 'amount_recovered': 0, 'resolution_rate': 0})


@app.route('/api/alerts')
def api_alerts():
    """Get live alerts"""
    alerts = Alert.query.filter_by(is_active=True).order_by(Alert.created_at.desc()).all()
    return jsonify([{'message': a.message, 'type': a.alert_type} for a in alerts])


@app.route('/api/track/<case_id>')
def api_track(case_id):
    """API to track case"""
    complaint = Complaint.query.filter_by(case_id=case_id).first()
    if complaint:
        return jsonify({
            'found': True,
            'case_id': complaint.case_id,
            'category': complaint.category,
            'status': complaint.status,
            'priority': complaint.priority,
            'created_at': complaint.created_at.strftime('%d %b %Y, %I:%M %p'),
            'updated_at': complaint.updated_at.strftime('%d %b %Y, %I:%M %p'),
            'officer_notes': complaint.officer_notes or 'No updates yet.'
        })
    return jsonify({'found': False})


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ─── Error Handlers ──────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


# ─── Run ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db(app)
    app.run(debug=True, port=5000)

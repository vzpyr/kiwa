import os
import uuid
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, send_file, abort, session, request, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from dotenv import load_dotenv
from config import Config
from models import db, User, File
from forms import LoginForm, RegistrationForm, UploadForm, FilePasswordForm, ForgotPasswordForm, ResetPasswordForm

# Load environment variables from .env file
load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    db.init_app(app)
    
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    limiter.init_app(app)
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'please log in to access this page.'
    
    from flask_mail import Mail
    mail = Mail()
    mail.init_app(app)
    
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = RegistrationForm()
        if form.validate_on_submit():
            if hasattr(form, 'recaptcha') and form.recaptcha.data:
                if not form.recaptcha.validate(form):
                    form.recaptcha.errors.append('reCAPTCHA validation failed. Please try again.')
                    return render_template('register.html', form=form)
            
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                form.username.errors.append('username already exists.')
                return render_template('register.html', form=form)
                
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                form.email.errors.append('email already registered.')
                return render_template('register.html', form=form)
            
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            
            flash('registration successful!', 'success')
            return redirect(url_for('login'))
        
        return render_template('register.html', form=form)
    
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = LoginForm()
        if form.validate_on_submit():
            if hasattr(form, 'recaptcha') and form.recaptcha.data:
                if not form.recaptcha.validate(form):
                    form.recaptcha.errors.append('reCAPTCHA validation failed. Please try again.')
                    return render_template('login.html', form=form)
            
            user = User.query.filter_by(username=form.username.data).first()
            if not user:
                user = User.query.filter_by(email=form.username.data).first()
            
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('invalid username or password.', 'error')
        
        return render_template('login.html', form=form)
    
    
    @app.route('/forgot-password', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def forgot_password():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = ForgotPasswordForm()
        if form.validate_on_submit():
            if hasattr(form, 'recaptcha') and form.recaptcha.data:
                if not form.recaptcha.validate(form):
                    form.recaptcha.errors.append('reCAPTCHA validation failed. Please try again.')
                    return render_template('forgot_password.html', form=form)
            
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                token = secrets.token_urlsafe(32)
                user.password_reset_token = token
                user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                
                from flask_mail import Message
                mail = current_app.extensions['mail']
                msg = Message(
                    subject='kiwa password reset',
                    recipients=[user.email],
                    body=f'''to reset your password, click the following link:
{url_for('reset_password', token=token, _external=True)}

this link will expire in 1 hour.

if you did not request a password reset, please ignore this email.
'''
                )
                try:
                    mail.send(msg)
                    flash('a password reset link has been sent to your email.', 'info')
                except Exception as e:
                    flash('unable to send email. please contact support.', 'error')
                    current_app.logger.error(f'Failed to send email: {str(e)}')
            else:
                flash('a password reset link has been sent to your email.', 'info')
            
            return redirect(url_for('login'))
        
        return render_template('forgot_password.html', form=form)
    
    
    @app.route('/reset-password/<token>', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def reset_password(token):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        user = User.query.filter_by(password_reset_token=token).first()
        if not user or not user.password_reset_expires or user.password_reset_expires < datetime.utcnow():
            flash('invalid or expired reset token.', 'error')
            return redirect(url_for('login'))
        
        form = ResetPasswordForm()
        if form.validate_on_submit():
            user.set_password(form.password.data)
            user.password_reset_token = None
            user.password_reset_expires = None
            db.session.commit()
            
            flash('your password has been reset successfully.', 'success')
            return redirect(url_for('login'))
        
        return render_template('reset_password.html', form=form)
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('you have been logged out.', 'info')
        return redirect(url_for('index'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        user_files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
        
        total_files = File.query.count()
        user_files_count = len(user_files)
        
        from datetime import datetime, timedelta
        two_weeks_ago = datetime.utcnow() - timedelta(weeks=2)
        
        recent_files = File.query.filter(File.upload_date >= two_weeks_ago).all()
        
        download_data = []
        for i in range(14):
            date = (datetime.utcnow() - timedelta(days=13-i)).date()
            daily_downloads = sum(
                file.download_count for file in recent_files 
                if file.upload_date.date() == date
            )
            download_data.append({
                'date': date.strftime('%Y-%m-%d'),
                'downloads': daily_downloads
            })
        
        if total_files > 0:
            user_file_percentage = (user_files_count / total_files) * 100
        else:
            user_file_percentage = 0
        
        upload_form = UploadForm()
        return render_template('dashboard.html', 
                             files=user_files, 
                             upload_form=upload_form,
                             user_files_count=user_files_count,
                             total_files=total_files,
                             download_data=download_data,
                             user_file_percentage=user_file_percentage)
    
    @app.route('/upload', methods=['POST'])
    @login_required
    def upload_file():
        form = UploadForm()
        if form.validate_on_submit():
            uploaded_file = form.file.data
            filename = secure_filename(uploaded_file.filename)
            
            uploaded_file.seek(0, 2)
            file_size = uploaded_file.tell()
            uploaded_file.seek(0)
            
            if file_size > app.config['MAX_FILE_SIZE']:
                flash('file size exceeds limit.', 'error')
                return redirect(url_for('dashboard'))
            
            file_extension = os.path.splitext(filename)[1]
            unique_filename = str(uuid.uuid4()) + file_extension
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            uploaded_file.save(file_path)
            
            file_record = File(
                user_id=current_user.id,
                original_filename=filename,
                stored_filename=unique_filename,
                file_size=file_size
            )
            
            if form.expiry_time.data != 'never':
                if form.expiry_time.data == '1h':
                    file_record.expiry_date = datetime.utcnow() + timedelta(hours=1)
                elif form.expiry_time.data == '1d':
                    file_record.expiry_date = datetime.utcnow() + timedelta(days=1)
                elif form.expiry_time.data == '1w':
                    file_record.expiry_date = datetime.utcnow() + timedelta(weeks=1)
                elif form.expiry_time.data == '1m':
                    file_record.expiry_date = datetime.utcnow() + timedelta(days=30)
            
            if form.download_limit.data != '0':
                file_record.download_limit = int(form.download_limit.data)
            
            if form.password.data:
                file_record.set_password(form.password.data)
            
            db.session.add(file_record)
            db.session.commit()
            
            flash('file uploaded successfully!', 'success')
        else:
            if form.file.errors:
                flash(f'file upload error: {", ".join(form.file.errors)}', 'error')
            else:
                flash('error uploading file.', 'error')
            
        return redirect(url_for('dashboard'))
    
    @app.route('/file/<int:file_id>', methods=['GET', 'POST'])
    def file_detail(file_id):
        file = File.query.get_or_404(file_id)
        
        if not file.is_active or file.is_expired():
            flash('file not found.', 'error')
            abort(404)
            
        if file.password_hash:
            form = FilePasswordForm()
            if form.validate_on_submit():
                if file.check_password(form.password.data):
                    session[f'file_access_{file_id}'] = True
                    return render_template('download.html', file=file, password_protected=False)
                else:
                    flash('incorrect password.', 'error')
            return render_template('download.html', file=file, form=form, password_protected=True)
            
        return render_template('download.html', file=file, password_protected=False)
    
    @app.route('/download/<int:file_id>')
    def download_file(file_id):
        file = File.query.get_or_404(file_id)
        
        if not file.is_active or file.is_expired():
            flash('file not found.', 'error')
            abort(404)
            
        if file.password_hash and not session.get(f'file_access_{file_id}'):
            flash('password required to download this file.', 'error')
            return redirect(url_for('file_detail', file_id=file_id))
        
        file.download_count += 1
        db.session.commit()
        
        if file.is_expired():
            db.session.commit()
            flash('file has expired.', 'error')
            abort(404)
        
        return send_file(file.get_file_path(), as_attachment=True, download_name=file.original_filename)
    
    @app.route('/preview/<int:file_id>')
    def preview_file(file_id):
        file = File.query.get_or_404(file_id)
        
        if not file.is_active or file.is_expired():
            flash('file not found.', 'error')
            abort(404)
            
        if file.password_hash and not session.get(f'file_access_{file_id}'):
            flash('password required to preview this file.', 'error')
            return redirect(url_for('file_detail', file_id=file_id))
        
        return send_file(file.get_file_path())
    
    @app.route('/delete/<int:file_id>')
    @login_required
    def delete_file(file_id):
        file = File.query.get_or_404(file_id)
        
        if file.user_id != current_user.id:
            flash('you do not have permission to delete this file.', 'error')
            return redirect(url_for('dashboard'))
        
        try:
            os.remove(file.get_file_path())
        except OSError:
            pass
        
        db.session.delete(file)
        db.session.commit()
        
        flash('file deleted successfully.', 'success')
        return redirect(url_for('dashboard'))
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500
    
    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(error):
        flash('file size exceeds limit.', 'error')
        return redirect(url_for('dashboard'))
    
    with app.app_context():
        db.create_all()
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
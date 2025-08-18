import os
import magic
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

DevelopmentConfig = os.environ.get('FLASK_DEBUG') == '1' or os.environ.get('FLASK_ENV') == 'development'

BLACKLISTED_MIME_TYPES = {
    # executables
    'application/x-msdownload',
    'application/vnd.microsoft.portable-executable',
    'application/x-dosexec',
    'application/x-mach-binary',
    'application/x-elf',
    'application/x-sharedlib',
    
    # scripts
    'text/x-python',
    'text/x-perl',
    'text/x-ruby',
    'text/x-php',
    'application/x-sh',
    'application/x-csh',
    'application/javascript',
    'application/x-javascript',
}

BLACKLISTED_EXTENSIONS = {
    '.exe', '.dll', '.com', '.bat', '.msi', '.scr', '.pif', '.application', '.gadget', '.msp', '.mst',
    '.sh', '.bash', '.csh', '.ksh', '.pl', '.py', '.rb', '.php', '.js', '.vbs', '.wsf', '.jar', '.class',
    '.cmd', '.ps1', '.app', '.command', '.dmg'
}

class LoginForm(FlaskForm):
    username = StringField('username or email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    remember_me = BooleanField('remember me')
    
    if not DevelopmentConfig:
        recaptcha = RecaptchaField()
    
    submit = SubmitField('login')


class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[
        DataRequired(), 
        Length(min=3, max=20)
    ])
    email = StringField('email', validators=[
        DataRequired(), 
        Email()
    ])
    password = PasswordField('password', validators=[
        DataRequired(), 
        Length(min=6)
    ])
    password2 = PasswordField('confirm password', validators=[
        DataRequired(), 
        EqualTo('password')
    ])
    
    if not DevelopmentConfig:
        recaptcha = RecaptchaField()
    
    submit = SubmitField('register')


class UploadForm(FlaskForm):
    file = FileField('file', validators=[FileRequired()])
    
    def validate_file(self, field):
        if field.data:
            filename = field.data.filename.lower()
            if any(filename.endswith(ext) for ext in BLACKLISTED_EXTENSIONS):
                raise ValidationError('file extension not allowed.')
            
            try:
                mime = magic.from_buffer(field.data.read(1024), mime=True)
                field.data.seek(0)
                
                if mime in BLACKLISTED_MIME_TYPES:
                    raise ValidationError('file type not allowed.')
            except Exception:
                import traceback
                traceback.print_exc()
                raise ValidationError('unable to verify file type.')
    
    expiry_time = SelectField('expiry time', choices=[
        ('1h', '1 hour'),
        ('1d', '1 day'),
        ('1w', '1 week'),
        ('1m', '1 month'),
        ('never', 'never')
    ], default='1w')
    download_limit = SelectField('download limit', choices=[
        ('1', '1 download'),
        ('5', '5 downloads'),
        ('10', '10 downloads'),
        ('25', '25 downloads'),
        ('50', '50 downloads'),
        ('0', 'unlimited')
    ], default='0')
    password = PasswordField('password (optional)')
    submit = SubmitField('upload')


class FilePasswordForm(FlaskForm):
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('access file')


class ForgotPasswordForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    
    if not DevelopmentConfig:
        recaptcha = RecaptchaField()
    
    submit = SubmitField('send reset link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('new password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('confirm new password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('reset password')
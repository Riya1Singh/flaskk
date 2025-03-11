from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer



app = Flask(__name__)
app.secret_key = 'supersecretmre'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a strong random key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Change this
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Change this (use an App Password for security)
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # Token generator



#User model


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

#Load user

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create Database Tables

with app.app_context():
    db.create_all()


#Landing page route

@app.route('/')
def landing():
    return render_template('landing.html')

#Login page route

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))  # Redirect to a protected route
        else:
            flash("Invalid credentials. Please try again.", "danger")
    
    return render_template('login.html')


#Register page route


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered! Please login.", "danger")
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Generate email verification link
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)

        # Send email
        msg = Message("Confirm Your Email", recipients=[email])
        msg.body = f"Click the link to verify your email: {confirm_url}"
        mail.send(msg)

        flash("Registration successful! Please check your email to verify your account.", "info")
        return redirect(url_for('login'))

    return render_template('register.html')



#route for email confirmation

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # Valid for 1 hour
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email verified! You can now log in.", "success")
            return redirect(url_for('login'))
    except:
        flash("The confirmation link is invalid or has expired.", "danger")
        return redirect(url_for('register'))
    


#route for sending password reset emails

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send password reset email
            msg = Message("Reset Your Password", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)

            flash("Password reset link has been sent to your email.", "info")
        else:
            flash("No account found with that email.", "danger")

    return render_template('forgot_password.html')




#route to rest the password

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # Valid for 1 hour
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Invalid or expired token.", "danger")
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            new_password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()

            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for('login'))

        return render_template('reset_password.html')

    except:
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))




#Protected dashboard route

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome, {current_user.username}! This is your dashboard."

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))





@app.route('/')
def index():
    flash('Welcome to the Flask App', 'info')
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
from flask import Flask, render_template, flash, redirect, url_for, session, request
from models import db, User, SecurityQuestion
from forms import RegistrationForm, LoginForm, SecurityQuestionsForm, SecurityQuestionVerificationForm
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Required for CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/auth.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Auth startup')

# Initialize the database
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def homepage():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        if User.query.filter_by(email=form.email.data).first():
            app.logger.warning(f'Registration attempt with existing email: {form.email.data}')
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=form.username.data).first():
            app.logger.warning(f'Registration attempt with existing username: {form.username.data}')
            flash('Username already taken!', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        
        app.logger.info(f'New user registered: {form.username.data} ({form.email.data})')
        flash('Registration successful!', 'success')
        return redirect(url_for('security_questions'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # Get current browser agent
            current_browser_agent = request.headers.get('User-Agent')
            
            # Check if browser agent has changed
            if user.browser_agent and user.browser_agent != current_browser_agent:
                app.logger.warning(f'Browser agent changed for user {user.username}. Old: {user.browser_agent}, New: {current_browser_agent}')
                session['pending_user_email'] = user.email
                flash('New browser detected. Please verify your security questions.', 'warning')
                return redirect(url_for('verify_security_question'))
            
            # Check if user has reached 3 failed attempts
            if user.login_attempts >= 3:
                # Store user email in session for verification
                session['pending_user_email'] = user.email
                app.logger.warning(f'User {user.username} requires security verification after {user.login_attempts} failed attempts')
                flash('Too many failed attempts. Please verify your security questions.', 'error')
                return redirect(url_for('verify_security_question'))
            
            # Save browser agent
            user.update_browser_agent(current_browser_agent)
            
            # Successful login
            session['user_id'] = user.id
            session['username'] = user.username
            user.reset_login_attempts()
            app.logger.info(f'User logged in: {user.username} from {current_browser_agent}')
            flash('Login successful!', 'success')
            return redirect(url_for('homepage'))
        else:
            if user:
                user.increment_login_attempts()
                app.logger.warning(f'Failed login attempt for user {user.username}. Attempts: {user.login_attempts}')
                if user.login_attempts >= 3:
                    session['pending_user_email'] = user.email
                    flash('Too many failed attempts. Please verify your security questions.', 'error')
                    return redirect(url_for('verify_security_question'))
            else:
                app.logger.warning(f'Failed login attempt for non-existent email: {form.email.data}')
            flash('Invalid email or password!', 'error')
    return render_template('login.html', form=form)

@app.route('/verify-security-question', methods=['GET', 'POST'])
def verify_security_question():
    if 'pending_user_email' not in session:
        app.logger.warning('Security verification attempt without pending user email')
        flash('Please login first', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['pending_user_email']).first()
    if not user:
        session.pop('pending_user_email', None)
        app.logger.error(f'Security verification attempt for non-existent user: {session["pending_user_email"]}')
        flash('User not found', 'error')
        return redirect(url_for('login'))

    # Get all security questions for the user
    security_questions = SecurityQuestion.query.filter_by(user_id=user.id).order_by(SecurityQuestion.question_number).all()
    if not security_questions or len(security_questions) != 3:
        session.pop('pending_user_email', None)
        app.logger.error(f'Security questions not found for user: {user.username}')
        flash('Security questions not found', 'error')
        return redirect(url_for('login'))

    form = SecurityQuestionVerificationForm()
    if form.validate_on_submit():
        # Verify all three questions and answers
        all_verified = True
        for i, stored_question in enumerate(security_questions, 1):
            input_question = getattr(form, f'question{i}').data
            input_answer = getattr(form, f'answer{i}').data
            
            # Verify using bcrypt's checkpw
            if not (stored_question.verify_text(input_question, stored_question.question) and 
                   stored_question.verify_text(input_answer, stored_question.answer)):
                all_verified = False
                app.logger.warning(f'Failed security verification for user: {user.username}')
                break

        if all_verified:
            user.reset_login_attempts()
            session['user_id'] = user.id
            session['username'] = user.username
            session.pop('pending_user_email', None)
            app.logger.info(f'Security verification successful for user: {user.username}')
            flash('Security questions verified successfully!', 'success')
            return redirect(url_for('homepage'))
        else:
            flash('One or more questions/answers are incorrect!', 'error')

    return render_template('verify_security_question.html', form=form)

@app.route('/security-questions', methods=['GET', 'POST'])
def security_questions():
    form = SecurityQuestionsForm()
    if form.validate_on_submit():
        # Get the most recently registered user
        user = User.query.order_by(User.id.desc()).first()
        if not user:
            flash('Please register first!', 'error')
            return redirect(url_for('register'))
        
        # Save security questions
        questions = [
            (form.question1.data, form.answer1.data, 1),
            (form.question2.data, form.answer2.data, 2),
            (form.question3.data, form.answer3.data, 3)
        ]
        
        for question, answer, number in questions:
            security_question = SecurityQuestion(
                user_id=user.id,
                question_number=number
            )
            # Encrypt question and answer before saving
            security_question.set_question(question)
            security_question.set_answer(answer)
            db.session.add(security_question)
        
        db.session.commit()
        flash('Security questions saved successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('security_questions.html', form=form)

@app.route('/logout')
def logout():
    if 'username' in session:
        app.logger.info(f'User logged out: {session["username"]}')
    session.clear()
    flash('You have been logged out successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20, message='Username must be between 3 and 20 characters')
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired()
    ])
    submit = SubmitField('Login')

class SecurityQuestionsForm(FlaskForm):
    question1 = StringField('Security Question 1', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer1 = StringField('Answer 1', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    question2 = StringField('Security Question 2', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer2 = StringField('Answer 2', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    question3 = StringField('Security Question 3', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer3 = StringField('Answer 3', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    submit = SubmitField('Save Security Questions')

class SecurityQuestionVerificationForm(FlaskForm):
    question1 = StringField('Security Question 1', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer1 = StringField('Answer 1', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    question2 = StringField('Security Question 2', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer2 = StringField('Answer 2', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    question3 = StringField('Security Question 3', validators=[
        DataRequired(),
        Length(min=10, message='Question must be at least 10 characters long')
    ])
    answer3 = StringField('Answer 3', validators=[
        DataRequired(),
        Length(min=2, message='Answer must be at least 2 characters long')
    ])

    submit = SubmitField('Verify Security Questions')

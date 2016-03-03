from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, validators, TextField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
import main

class RegistrationForm(Form):
    firstName = StringField('First Name')
    lastName = StringField('Last Name')
    major = StringField('Major')
    classYear = StringField('Class Year (ex. 2018)')
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    idNumber = StringField('Student ID', validators=[Required()])
    #idNumber = StringField('Student ID', validators=[Required(),validators.Length(min=9, max=9), validators.NumberRange(min=100000000, max=999999999,message="Your student ID must be a 9-digit number.")])
    private = SelectField('Would you like to allow other students to view your photos?', validators=[Required()],
                          coerce=int, choices=[(1, "No"), (2, "Yes")], default=1)
    submit = SubmitField('Register')

    def validate_email(self, field):
        from main import User
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        from main import User
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already registered.')

    def validate_idNumber(self, field):
        from main import User
        if User.query.filter_by(idNumber=field.data).first():
            raise ValidationError('Student ID already registered.')

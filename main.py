'''
Authors: Caitlin Wormsley, Lisa Famularo, Sabrina Knight
Final Project for Advanced Web Programming at Ithaca College
Fall 2015
Used the code from chapter 5a from the book "Flask Web Development: Developing Web Applications
    by Miguel Grinberg as a base for this project
'''



import os

from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory, session
from flask.ext.script import Manager
from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from flask.ext.sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, login_required
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, validators, TextField
from wtforms.validators import Required

#from app.main.forms import RegistrationForm
import app.main.forms

basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/pics')
ALLOWED_EXTENSIONS = set(['png', 'jpg'])

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:///' + os.path.join(basedir, 'TraditionsChallenge.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

manager = Manager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
admin = Admin(app)


class User(db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(64))
    username = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(64), index=True)
    firstName = db.Column(db.String(64), index=True)
    lastName = db.Column(db.String(64), index=True)
    classYear = db.Column(db.Integer)
    major = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    idNumber = db.Column(db.Integer, unique=True)
    private = db.Column(db.Integer)
    numComplete = db.Column(db.Integer)

    def check_password(self, password):
        match=False
        if password == self.password:
            match=True
        return match

    def is_authenticated(self):
        return True

class Challenge(db.Model):
    __tablename__ = 'Challenge'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, index=True)

class UserToChallenge(db.Model):
    __tablename__ = 'UserToChallenge'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Integer)
    #changed below line to db.String
    photo = db.Column(db.String)
    description = db.Column(db.String(128), index=True)
    userid = db.Column(db.Integer, db.ForeignKey('User.id'))
    challengeid = db.Column(db.Integer, db.ForeignKey('Challenge.id'))

class Prize(db.Model):
    __tablename__ = 'Prize'
    id = db.Column(db.Integer, primary_key=True)
    prizeName = db.Column(db.String(64), unique=True, index=True)
    numChallengesNeeded = db.Column(db.Integer)

class UserToPrize(db.Model):
    __tablename__ = 'UserToPrize'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.Integer)
    userid = db.Column(db.Integer, db.ForeignKey('User.id'))
    prizeid = db.Column(db.Integer, db.ForeignKey('Prize.id'))

@app.errorhandler(404)
def page_not_found(e):
    print (e)
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/', methods=['GET', 'POST'])
def ictraditions():

    challengeList = []
    for a in Challenge.query.order_by('id'):
        challengeList.append(a.name)

    return render_template('ictraditions.html', challengeList=challengeList)

def checkForLogin():
    isIn = False
    if 'isLoggedIn' in session and session['isLoggedIn'] == True:
        isIn = True
    return isIn

def checkForAdminLogin():
    isAdminIn = False
    if 'isAdminLoggedIn' in session and session['isAdminLoggedIn'] == True:
        isAdminIn = True
    return isAdminIn

@app.route('/home.html', methods=['GET', 'POST'])
#@login_required
def home():
    challengeList = []
    user1 = User.query.filter_by(id=session['user_id']).first()
    numComplete = user1.numComplete
    for a in Challenge.query.order_by('id'):
        challengeList.append(a.name)
    if request.method == 'POST':
        file = request.files['file']
        ##########
        desc = request.form['description']
        challenge = request.form['challenge']
        if file and allowed_file(file.filename):
            filename = file.filename
            #this changes the filename to the username followed by the challenge number
            type = filename[-4:]
            currentUserId = session['user_id']
            currUser = User.query.filter_by(id = currentUserId).first()
            newName = currUser.username + str(challenge) + type
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], newName))
            userToChallenge = UserToChallenge(status = 0,
                                              photo = newName,
                                              description = desc,
                                              userid = currentUserId,
                                              challengeid = challenge)
            db.session.add(userToChallenge)
            db.session.commit()
            flash('Your photo has been uploaded successfully.')
            #return redirect(url_for('uploaded_file',filename=filename))
        else:
            flash('Not a valid file type. Only jpg and png allowed.')

    statusList=[-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1]
    for a in UserToChallenge.query.filter_by(userid = session['user_id']):
        statusList[a.challengeid-1]=a.status

    isIn=checkForLogin()
    return render_template('home.html', challengeList = challengeList, isLoggedIn=isIn, numComplete=numComplete, statusList=statusList)

@app.route('/register.html', methods=['GET', 'POST'])
def register():
    from app.main.forms import RegistrationForm
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(role='Student',
                    email=form.email.data,
                    username=form.username.data,
                    password=form.password.data,
                    idNumber=form.idNumber.data,
                    private=form.private.data,
                    firstName = form.firstName.data,
                    lastName = form.lastName.data,
                    classYear = form.classYear.data,
                    major = form.major.data,
                    numComplete = 0)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created. You may now login!')
        challengeList=[]
        for a in Challenge.query.order_by('id'):
            challengeList.append(a.name)
        return render_template('ictraditions.html', challengeList=challengeList)
    return render_template('register.html', form=form)


@app.route('/community.html', methods=['GET', 'POST'])
def community():
    challengeList=[]
    for a in Challenge.query.order_by('id'):
        challengeList.append(a.name)
    #PICTURE GRID
    isIn=checkForLogin()
    isAdminIn = checkForAdminLogin()
    print("isIn")
    print(isIn)
    print("isAdminIn")
    print(isAdminIn)
    if isIn or isAdminIn:
        loggedIn = True


    userList = []
    userNameList = []
    photoList = []
    descriptionList = []
    tempList = []
    tempUserList = []
    tempChallList = []
    challengePicList = []

    #queries the databse for all users who allow pics to be public
    for a in User.query.filter_by(private = 2):
        userList.append(a.id)

    #queries database for all userids
    for a in UserToChallenge.query.order_by('userid'):
        #if a UserToChallenge entry has a public user then append the photo, description to approproate lists
        if a.userid in userList:
            photoList.append(a.photo)
            descriptionList.append(a.description)
            tempUserList.append(a.userid)
            tempChallList.append(a.challengeid)
    for b in tempUserList:
        for c in User.query.filter_by(id=b):
            userNameList.append(c.username)
    for d in tempChallList:
        for e in Challenge.query.filter_by(id=d):
          challengePicList.append(e.name)
    #photoList, descriptionList, userNameList, challengePicList = getAllPhotos()
    print(userNameList)
    print(challengePicList)

    photoListSearch = []
    descriptionListSearch = []
    userNameListSearch = []
    challengePicListSearch=[]
    if request.method == 'POST':
        buttonType = request.form['submit']
        userToSearchBy = request.form['text']
        challenge = request.form['challenge']
        if buttonType == "Clear Search":
            photoList = []
            descriptionList = []
            #photoList, descriptionList, userNameList, challengePicList = getAllPhotos()
            for a in User.query.filter_by(private = 2):
                userList.append(a.id)
                #userNameList.append(a.username)
            for a in UserToChallenge.query.order_by('userid'):
                if a.userid in userList:
                    photoList.append(a.photo)
                    descriptionList.append(a.description)
                    tempList.append(a.userid)
                    for b in tempList:
                        for c in User.query.filter_by(id=b):
                            userNameList.append(c.username)
            return render_template('community.html', isLoggedIn=loggedIn, isAdminLoggedIn=isAdminIn, userNameList=userNameList, photoList=photoList, descriptionList=descriptionList, challengeList=challengeList, challengePicList=challengePicList)
        elif buttonType =="Submit":
            photoListSearch, descriptionListSearch, userNameListSearch, challengePicListSearch = searchByChallenge(challenge)
            if (photoListSearch == []):
                flash("No public images for this challenge")
            return render_template('community.html', isLoggedIn=loggedIn, isAdminLoggedIn=isAdminIn, userNameList=userNameListSearch, photoList=photoListSearch, descriptionList=descriptionListSearch, challengeList=challengeList, challengePicList=challengePicListSearch)
        else:
            photoListSearch, descriptionListSearch, userNameListSearch, challengePicListSearch = searchByName(userToSearchBy)
            if (photoListSearch == []):
                flash("No public images for this user")
            return render_template('community.html', isLoggedIn=loggedIn,isAdminLoggedIn=isAdminIn, userNameList=userNameListSearch, photoList=photoListSearch, descriptionList=descriptionListSearch, challengeList=challengeList, challengePicList=challengePicListSearch)
    return render_template('community.html', isLoggedIn=loggedIn, isAdminLoggedIn=isAdminIn, userNameList=userNameList, photoList=photoList, descriptionList=descriptionList, challengeList=challengeList, challengePicList=challengePicList)




def searchByName(searchTerm):
    userListSearch = []
    photoListSearch = []
    descriptionListSearch = []
    userNameListSearch = []
    tempUserList=[]
    tempChallList=[]
    challengePicListSearch = []
    for a in User.query.filter_by(username = searchTerm):
        if a.private ==2:
            userListSearch.append(a.id)
    for a in UserToChallenge.query.order_by('userid'):
        if a.userid in userListSearch:
            photoListSearch.append(a.photo)
            descriptionListSearch.append(a.description)
            tempUserList.append(a.userid)
            tempChallList.append(a.challengeid)
    for b in tempUserList:
        for c in User.query.filter_by(id=b):
            userNameListSearch.append(c.username)
    for d in tempChallList:
        for e in Challenge.query.filter_by(id=d):
          challengePicListSearch.append(e.name)
    return (photoListSearch, descriptionListSearch, userNameListSearch, challengePicListSearch)

def searchByChallenge(searchTerm):
    print(searchTerm)
    userListSearch = []
    photoListSearch = []
    descriptionListSearch = []
    userNameListSearch = []
    tempUserList=[]
    tempChallList=[]
    challengePicListSearch=[]
    for a in User.query.filter_by(private = 2):
        userListSearch.append(a.id)
    for a in UserToChallenge.query.filter_by(challengeid = searchTerm):
        if a.userid in userListSearch:
            photoListSearch.append(a.photo)
            descriptionListSearch.append(a.description)
            tempUserList.append(a.userid)
            tempChallList.append(a.challengeid)
    for b in tempUserList:
        for c in User.query.filter_by(id=b):
            userNameListSearch.append(c.username)
    for d in tempChallList:
        for e in Challenge.query.filter_by(id=d):
          challengePicListSearch.append(e.name)
    print('test')
    print(tempChallList)
    print(challengePicListSearch)
    return (photoListSearch, descriptionListSearch, userNameListSearch, challengePicListSearch)



@app.route('/calendar.html', methods=['GET', 'POST'])
def calendar():
    isIn=checkForLogin()
    isAdminIn = checkForAdminLogin()
    if isIn or isAdminIn:
        loggedIn = True
    return render_template('calendar.html', isLoggedIn=loggedIn, isAdminLoggedIn=isAdminIn)


class ChangePrivacyForm(Form):
    newPrivate = SelectField('Would you like to change the privacy setting of your photos?', validators=[Required()],
                          coerce=int, choices=[(1, "Private"), (2, "Public")])
    submit = SubmitField('Update')

@app.route('/settings.html', methods=['GET', 'POST'])
def settings():
    form = ChangePrivacyForm()
    if form.validate_on_submit():
        currentUserId = session['user_id']
        for a in User.query.filter_by(id = currentUserId):
            a.private = form.newPrivate.data
        flash('Your privacy settings have been updated.')
        isIn=checkForLogin()
        return redirect(url_for('settings'))
        #return redirect('settings.html',isLoggedIn=isIn, form=form)
    isIn=checkForLogin()
    return render_template('settings.html', isLoggedIn=isIn, form=form)

@app.route('/prizeReview.html', methods=['GET', 'POST'])
def prizeReview():
    #the .order_by('role') is sort of cheating.. i don't know how to use order_by or filter_by correctly
    #it's displaying the usernames right now, if we want first+last names, we have to change something

    prize1List = []
    for a in User.query.order_by('role'):
        if 5 <= a.numComplete:
            prize1List.append(a.username)

    prize2List = []
    for a in User.query.order_by('role'):
        if 10 <= a.numComplete:
            prize2List.append(a.username)

    prize3List = []
    for a in User.query.order_by('role'):
        if 15 <= a.numComplete:
            prize3List.append(a.username)

    isAdminIn = checkForAdminLogin()
    return render_template('prizeReview.html', prize1List=prize1List, prize2List=prize2List, prize3List=prize3List, isAdminLoggedIn=isAdminIn)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

#LOGIN

class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])
    submit = SubmitField('Login')

    def __init__(self, *args, **kwargs):
        Form.__init__(self, *args, **kwargs)
        self.user = None

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        user = User.query.filter_by(username=self.username.data).first()
        if user is None:
            self.username.errors.append('Unknown username')
            return False

        if not user.check_password(self.password.data):
            self.password.errors.append('Invalid password')
            return False

        self.user = user
        return True

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.id

@app.route('/login.html', methods=['GET', 'POST'])
def login():
    session['isLoggedIn'] = False
    session['isAdminLoggedIn'] = False
    form = LoginForm()
    if form.validate_on_submit():
        session['user_id'] = form.user.id

        for a in User.query.filter_by(username=form.user.username):
            if a.role == 'Student':
                session['isLoggedIn'] = True
                return redirect(url_for('home'))
            if a.role == 'Admin':
                session['isAdminLoggedIn'] = True
                return redirect(url_for('adminHome'))

    return render_template('login.html', form=form)

@app.route('/logout.html')
def logout():
    session['isLoggedIn'] = False
    session['isAdminLoggedIn'] = False
    return render_template('ictraditions.html')

#ADMIN

admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Challenge, db.session))
admin.add_view(ModelView(UserToChallenge, db.session))
admin.add_view(ModelView(Prize, db.session))
admin.add_view(ModelView(UserToPrize, db.session))

@app.route('/admin/index')
def admin():
    return render_template('admin/index.html')

@app.route('/adminHome.html', methods=['GET', 'POST'])
def adminHome():
    isAdminIn = checkForAdminLogin()
    #photoList will be the photos that are pending that the admin needs to approve
    photoList = []
    descriptionList=[]
    challengeNameList=[]
    userNameList=[]
    for a in UserToChallenge.query.order_by('status'):
        if a.status == 0:
            photoList.append(a.photo)
            descriptionList.append(a.description)
            userNameList.append(User.query.filter_by(id=a.userid).first().username)
            challengeNameList.append(Challenge.query.filter_by(id=a.challengeid).first().name)
    if request.method == 'POST':
        if request.form['submit']:
            buttonString = request.form['submit']
            approveOrDeny = buttonString.split(":")[0]
            if(approveOrDeny == "Approve"):
                photoName = buttonString.split(" ")[1]
                for a in UserToChallenge.query.filter_by(photo=photoName):
                    if a.photo == photoName:
                        a.status = 1
                        for b in User.query.filter_by(id = a.userid):
                            b.numComplete = b.numComplete +1
                        db.session.commit()
                        index = photoList.index(a.photo)
                        photoList.remove(a.photo)
                        userNameList.remove(userNameList[index])
                        descriptionList.remove(descriptionList[index])
                        challengeNameList.remove(challengeNameList[index])
                        return render_template('adminHome.html', isAdminLoggedIn=isAdminIn, photoList = photoList, userNameList=userNameList, challengeNameList=challengeNameList, descriptionList=descriptionList)
            elif(approveOrDeny == "Deny"):
                photoLong = request.form['submit']
                photoName = photoLong.split(" ")[1]
                for a in UserToChallenge.query.filter_by(photo=photoName):
                    if a.photo == photoName:
                        a.status = 2
                        db.session.commit()
                        index = photoList.index(a.photo)
                        print(descriptionList)
                        photoList.remove(a.photo)
                        userNameList.remove(userNameList[index])
                        descriptionList.remove(descriptionList[index])
                        challengeNameList.remove(challengeNameList[index])
                        print(descriptionList)
                        return render_template('adminHome.html', isAdminLoggedIn=isAdminIn, photoList = photoList, userNameList=userNameList, challengeNameList=challengeNameList, descriptionList=descriptionList)
        else:
           print("error")
    return render_template('adminHome.html', isAdminLoggedIn=isAdminIn, photoList = photoList, userNameList=userNameList, challengeNameList=challengeNameList, descriptionList=descriptionList)

if __name__ == '__main__':
    db.create_all()
    manager.run()

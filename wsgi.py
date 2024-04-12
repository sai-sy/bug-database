from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

#Create flask instance
app = Flask(__name__)
app.config['SECRET_KEY']='REPLACE THIS FOR PRODUCTION'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///bugs.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# MODELS
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(200))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bugs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(200))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    #author = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.Column(db.String(200))

    def __repr__(self):
        return '<Title %r>' % self.title
    
app.app_context().push()
db.create_all()

# ROUTES
@app.route('/')
def index():
    return redirect("/bugs")

@app.route('/user')
def user():
    id = current_user.id
    return render_template("user.html")

# ROUTES /user
@app.route('/user/update/<int:id>', methods=["GET","POST"])
@login_required
def user_update(id):
    form = UserForm()
    user_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        try: 
            db.session.commit()
            flash("user updated successfully")
            return render_template("user_update.html", form=form, user_to_update=user_to_update)
        except:
            flash("Error: problem")
            return render_template("user_update.html", form=form, user_to_update=user_to_update)
    else:
        return render_template("user_update.html", form=form, user_to_update=user_to_update)

@app.route("/user/signup", methods=['GET', 'POST'])
def user_signup():
    form=UserForm()
    email=None
    our_users = Users.query.order_by(Users.date_added)
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data)
            user = Users(name=form.name.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash('User added successfuly')
        email = form.email.data
        form.name.data = ''
        form.email.data = ''
        form.password_hash.data = ''
        form.password_hash2.data = ''
        login_user(user)
        return redirect(url_for('index'))
        
    return render_template('user_signup.html', form=form, email=email, our_users=our_users)

@app.route("/user/login", methods=['GET', 'POST'])
def user_login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    email = None
    password = None
    user_to_check: Users = None
    passed = None
    form = LoginForm()

    if form.validate_on_submit():
        print('validated')
        password = form.password_hash.data
        form.password_hash.data = ''
        user_to_check = Users.query.filter_by(email=form.email.data).first()
        form.email.data  = ''
        if user_to_check:
            print('user exists')
            if check_password_hash(user_to_check.password_hash, password):
                print('correct pass')
                login_user(user_to_check)
                return redirect("/")
        else:
            email = None
            password = None
            user_to_check: Users = None
            passed = None
            form = LoginForm()
            flash("WRONG LOGIN INFO")

    return render_template('user_login.html', email=email, password=password,passed=passed, user_to_check=user_to_check, form=form)

@app.route("/user/logout", methods=['GET','POST'])
@login_required
def user_logout():
    logout_user()
    return redirect(url_for('user_logout'))

#ROUTES /bugs
@app.route("/bugs/add", methods=['GET','POST'])
@login_required
def bugs_add():
    form = BugForm()

    if form.validate_on_submit():
        print('here')
        bug = Bugs(title=form.title.data, author=form.author.data, description=form.description.data)
        print(bug)
        form.title.data = ''
        form.description.data = ''
        form.author.data = ''

        db.session.add(bug)
        db.session.commit()

        flash("Bug Submitted Successfully")

    return render_template("bugs_add.html", form=form)

@app.route("/bugs")
@login_required
def bugs():
    bugs = Bugs.query.order_by(Bugs.date_added)
    return render_template("bugs.html", bugs=bugs)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

# FORMS
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Submit")
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message="Passwords must match")])
    submit = SubmitField("Submit")
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Submit")
    
class BugForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Submit")
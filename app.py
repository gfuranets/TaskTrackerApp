from flask import Flask, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import PickleType
from sqlalchemy.ext.mutable import MutableDict
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, NumberRange
from flask_bcrypt import Bcrypt

from flask_migrate import Migrate


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '123'
db = SQLAlchemy(app)

bcrypt = Bcrypt(app) # necessary for password hashing

migrate = Migrate(app, db) # necessary for updating DB

""" Ensure an account control system """
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

""" Define a user structure in the DB """
""" Use UserMixin to fill all the required fields for the User class """
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    tasks = db.Column(MutableDict.as_mutable(PickleType), nullable=True)


class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), 
                                         Length(min = 4, max = 20)],
                                         render_kw = {'placeholder': 'Username'})
    
    password = PasswordField(validators = [InputRequired(),
                                          Length(min = 4, max = 20)],
                                          render_kw = {'placeholder': 'Password'})
    
    submit = SubmitField('Register')

    """ Prevent user from creating accounts with identical usernames """
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username = username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username is already taken")

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), 
                                         Length(min = 4, max = 20)],
                                         render_kw = {'placeholder': 'Username'})
    
    password = PasswordField(validators = [InputRequired(),
                                          Length(min = 4, max = 100)], # max is smaller than the DB value due to hashing (max 20 original, 80 encrypted)
                                          render_kw = {'placeholder': 'Password'})
    
    submit = SubmitField('Login')

class CreateForm(FlaskForm):
    task = StringField(validators = [Length(min = 1, max = 60)],
                                    render_kw = {'placeholder': 'Task'})
    
    amount = IntegerField(validators = [NumberRange(min = 1, max = 1e5)],
                                        render_kw = {'placeholder': 'Amount'})
    
    submit = SubmitField('Create')

class DeleteForm(FlaskForm):
    task = StringField(validators = [InputRequired(),
                                    Length(min = 1, max = 20)],
                                    render_kw = {'placeholder': 'Task'})
    
    submit = SubmitField('Delete')

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username = form.username.data, password = hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect('/')

    return render_template('signup.html', form = form)


@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()

    # First the program checks for a username in the DB, then hashes the input password and checks with the DB password
    # If passwords match the user is redirected to logged in homepage
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first() # Find a user with such username
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data): # compare input password and DB password
                login_user(user) # user has enter his account
                return redirect('/indexLogged')

    return render_template('login.html', form = form)

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect('/index')

@app.route('/indexLogged')
@login_required
def indexLogged():
    tasks = current_user.tasks if current_user.tasks else {}
    return render_template('indexLogged.html', tasks = tasks)

@app.route('/create', methods = ['GET', 'POST'])
@login_required
def create():
    form = CreateForm()

    if form.validate_on_submit():
        # Acquire data from form
        task = form.task.data
        amount = form.amount.data

        # Access the user's task dict
        user_id = current_user.id
        user = User.query.get(user_id)

        # Check whether there is a dict
        if user.tasks is None:
            user.tasks = MutableDict() # needed for further changing

        # Change the task dict
        user.tasks.update({task: [0, amount]})
        db.session.commit()

        return redirect('/indexLogged')

    return render_template('create.html', form = form)

@app.route('/delete', methods = ['GET', 'POST'])
@login_required
def delete():
    form = DeleteForm()
    tasks = current_user.tasks if current_user.tasks else {}

    if form.validate_on_submit():
        user_id = current_user.id 
        user = User.query.get(user_id)

        if user.tasks != {}:
            if form.task.data in user.tasks:
                user.tasks.pop(form.task.data)

        db.session.commit()
        return redirect('/indexLogged')

    return render_template('delete.html', form = form, tasks = tasks)

@app.route('/increase', methods = ['POST'])
@login_required
def increase():
    task = request.form.get('task')
    current_progress = int(request.form.get('current_progress'))
    max_progress = int(request.form.get('max_progress'))
    added_progress = int(request.form.get('added_progress'))

    if added_progress > 0 and added_progress <= max_progress - current_progress:
        user = User.query.get(current_user.id)
        user.tasks[task][0] += added_progress

        db.session.commit()

    return redirect('/indexLogged')

@app.route('/decrease', methods = ['POST'])
@login_required
def decrease():
    task = request.form.get('task')
    current_progress = int(request.form.get('current_progress'))
    removed_progress = int(request.form.get('removed_progress'))

    if removed_progress > 0 and removed_progress >= current_progress:
        user = User.query.get(current_user.id)
        user.tasks[task][0] -= removed_progress

        db.session.commit()

    return redirect('/indexLogged')

@app.route('/statistics.html')
@login_required
def statistics():
    return render_template('statistics.html')

if __name__ == '__main__':
    app.run(debug = True)
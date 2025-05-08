from flask import Flask, render_template, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import PickleType
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm.attributes import flag_modified

from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, NumberRange
from flask_bcrypt import Bcrypt

from flask_migrate import Migrate

from datetime import datetime, date
import io
import base64
import matplotlib.pyplot as plt
from functools import wraps
from flask import make_response

from dotenv import load_dotenv
import os

load_dotenv() 
print("SECRET_KEY =", os.getenv('SECRET_KEY'))


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

""" Prevent repeated authentification error """
def nocache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_view

""" Upgrade task progress daily """
def check_and_update_day(user):
    today = str(date.today())

    if user.stats is None:
        user.stats = MutableDict()

    if today not in user.stats:
        user.stats[today] = {}

    if user.tasks:
        for task, (progress, total) in user.tasks.items():
            percent = round((progress / total) * 100) if total > 0 else 0
            user.stats[today][task] = percent

    user.last_updated = today
    flag_modified(user, 'stats')
    flag_modified(user, 'last_updated')
    db.session.commit()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    tasks = db.Column(MutableDict.as_mutable(PickleType), nullable=True)
    stats = db.Column(MutableDict.as_mutable(PickleType), nullable=True)
    last_updated = db.Column(db.String(10), nullable=True)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={'placeholder': 'Password'})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username is already taken')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={'placeholder': 'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=100)],
                             render_kw={'placeholder': 'Password'})
    submit = SubmitField('Login')


class CreateForm(FlaskForm):
    task = StringField(validators=[Length(min=1, max=60)],
                       render_kw={'placeholder': 'Task'})
    amount = IntegerField(validators=[NumberRange(min=1, max=1e5)],
                          render_kw={'placeholder': 'Amount'})
    submit = SubmitField('Create')


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect('/')

    return render_template('signup.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect('/indexLogged')

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
@nocache
def logout():
    logout_user()
    return redirect('/index')


@app.route('/indexLogged', methods=['GET', 'POST'])
@login_required
@nocache
def indexLogged():
    tasks = current_user.tasks if current_user.tasks else {}
    return render_template('indexLogged.html', tasks=tasks)


@app.route('/create', methods=['POST', 'GET'])
@login_required
@nocache
def create():
    form = CreateForm()

    if form.validate_on_submit():
        task = form.task.data
        amount = form.amount.data

        if current_user.tasks is None:
            current_user.tasks = MutableDict()

        current_user.tasks.update({task: [0, amount]})
        db.session.commit()

        return redirect('/indexLogged')

    return render_template('create.html', form=form)


@app.route('/delete', methods=['POST'])
@login_required
@nocache
def delete():
    task = request.form.get('task')

    if current_user.tasks and task in current_user.tasks:
        # Remove from tasks
        current_user.tasks.pop(task)
        flag_modified(current_user, 'tasks')

        # Remove from stats
        if current_user.stats:
            for day in current_user.stats:
                if task in current_user.stats[day]:
                    current_user.stats[day].pop(task)
            flag_modified(current_user, 'stats')

        db.session.commit()

    return redirect('/indexLogged')

 d

@app.route('/increase', methods=['POST'])
@login_required
@nocache
def increase():
    task = request.form.get('task')
    added_progress = int(request.form.get('added_progress'))

    if added_progress > 0:
        current_user.tasks[task][0] += added_progress
        flag_modified(current_user, 'tasks')
        db.session.commit()

    return redirect('/indexLogged')


@app.route('/decrease', methods=['POST'])
@login_required
@nocache
def decrease():
    task = request.form.get('task')
    current_progress = int(request.form.get('current_progress'))
    removed_progress = int(request.form.get('removed_progress'))

    if removed_progress > 0:
        if removed_progress <= current_progress:
            current_user.tasks[task][0] -= removed_progress
        else:
            current_user.tasks[task][0] = 0

        flag_modified(current_user, 'tasks')
        db.session.commit()

    return redirect('/indexLogged')


@app.route('/statistics')
@login_required
@nocache
def statistics():
    check_and_update_day(current_user)
    stats = current_user.stats or {}

    task_progress = {}
    for day, day_stats in stats.items():
        for task, value in day_stats.items():
            if task not in task_progress:
                task_progress[task] = []
            task_progress[task].append((day, value))

    plt.switch_backend('agg')
    plt.figure(figsize=(10, 6))

    for task, data in task_progress.items():
        data.sort(key=lambda x: x[0])
        dates = [str(d) for d, _ in data]
        values = [float(v) for _, v in data]
        plt.plot(dates, values, marker='o', label=task)

    plt.xlabel('Date')
    plt.ylabel('Progress (%)')
    plt.title('Percentual task progresses')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.close()

    return render_template('statistics.html', plot_url=image_base64, tasks=current_user.tasks)

if __name__ == '__main__':
    app.run(debug = True)

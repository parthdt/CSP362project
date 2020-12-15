from flask import Flask, render_template, redirect, flash, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, DecimalField
from wtforms.validators import InputRequired, Email, Length, NumberRange
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dbms.db'
app.config['SECRET_KEY'] = 'DBMSPROJECT'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(69), unique=True)

    def __repr__(self):
        return '<Name {}, Username {}, Password Hash {}, Email {}>'.format(self.name,self.username,self.password,self.email) 

class Criminal(db.Model):
    __tablename__ = "criminals"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    crimes = db.Column(db.String(100))
    status = db.Column(db.Integer)

    def __repr__(self):
        return '<Name {}, Crimes {}, Status Code {}>'.format(self.name,self.crimes,self.status)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class SignupForm(FlaskForm):
    name = StringField('name', validators=[InputRequired(), Length(min=4, max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=69)])

class AddCriminalForm(FlaskForm):
    name = StringField('name', validators=[InputRequired(), Length(min=10, max=50)])
    crimes = StringField('crimes', validators=[InputRequired(), Length(min=0, max=100)])
    status = DecimalField('status', validators=[NumberRange(min=0, max=2, message='Status Code should be between 0 to 2')])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password,form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Username or Password! Try Again.')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/signup', methods = ['GET','POST'])
def signup():

    form = SignupForm()
    if form.validate_on_submit():
        hashedPW = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username = form.username.data, name = form.name.data, password = hashedPW, email = form.email.data)
        db.session.add(new_user)
        db.session.commit()
        flash('New User Created')
        return redirect(url_for('login'))
    return render_template('signup.html',form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name = current_user.name)

@app.route('/viewRecords')
@login_required
def view_records():
    criminals = Criminal.query.all()
    if not criminals:
        flash('Database empty!')
    return render_template('viewRecords.html', criminals = criminals)

@app.route('/addRecords', methods = ['GET','POST'])
@login_required
def add_records():
    form = AddCriminalForm()
    if form.validate_on_submit():
        new_criminal = Criminal(name = form.name.data, crimes = form.crimes.data, status = int(form.status.data))
        db.session.add(new_criminal)
        db.session.commit()
        flash('Criminal record added.')
        return redirect(url_for('add_records'))
    return render_template('addRecords.html', form = form, action="addRecords", button = "Add")

@app.route('/deleteRecords/<int:id>', methods=['POST'])
@login_required
def delete_records(id):
    criminal = Criminal.query.get_or_404(id)
    db.session.delete(criminal)
    db.session.commit()
    flash('Item deleted.')
    return redirect(url_for('view_records'))

@app.route('/editRecords/<int:id>', methods=['POST'])
@login_required
def edit_records(id):
    criminal = Criminal.query.get_or_404(id)
    form = AddCriminalForm(obj=criminal)
    if form.validate_on_submit():
        criminal.name = form.name.data
        criminal.crimes = form.crimes.data
        criminal.status = int(form.status.data)
        db.session.commit()
        flash('Criminal record edited.')
        return redirect(url_for('view_records'))
    return render_template('addRecords.html', form = form, action="editRecords/"+str(criminal.id), button = "Edit")
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been successfully logged out!')
    return render_template('home.html')

if __name__ == "__main__":
    app.run(debug=True)
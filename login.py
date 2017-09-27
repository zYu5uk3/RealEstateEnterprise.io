from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template ,redirect ,url_for ,abort ,Markup ,request ,session ,flash ,Response ,Blueprint
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm 
from wtforms import StringField ,ValidationError ,PasswordField, BooleanField, SubmitField, TextAreaField ,DateField ,TextField, IntegerField, validators, DateTimeField
from wtforms.validators import Required, Length, EqualTo, DataRequired, Email, Regexp
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    login_required
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message as MailMessage
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from itsdangerous import URLSafeTimedSerializer
import SocketServer
import os
from datetime import datetime
from flask_moment import Moment








#App Config
app = Flask(__name__)
#Date Config
datetime.utcnow()


#Secruity
app.config['SECRET_KEY'] = 'i bet you cant guess this password'            
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'

#Email Server
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['FLASKY_ADMIN'] = 'FLASKY_ADMIN'
app.config['FLASKY_MAIL_SENDER'] = 'Flasky Admin <mikeygod755@gmail.com>' 
app.config['FLASKY_MAIL_SUBJECT_PREFIX'] = '[Flask-Email]'


#App Config 
db = SQLAlchemy(app)
lm = LoginManager(app)
mail = Mail(app)
manager = Manager(app)
bcrypt = Bcrypt(app)
bootstrap = Bootstrap(app)


lm.login_view = 'login'
lm.login_message_category = "danger"

#################################################################################################################
#################################################################################################################
######Forms######################################################################################################
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[Required(), Length(1, 16)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Login')

class SignUpForm(FlaskForm):
    name = TextField('Name', validators = [Required(), Length(max=45)])
    city = TextField('City', validators = [Required(), Length(1,16)])
    dob = TextAreaField('DOB(YYYY/MM/DD)', validators = [Required(), Length(max=30)])
    zipcode = IntegerField('Zipcode', validators = [Required()])
    state = TextField('State', validators = [Required(), Length(1,16)])
    address = TextAreaField('Address', validators = [Required(), Length(max=30)])
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[
    Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                      'Usernames must have only letters, '
                                      'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', 
                              message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')
    remember_me = BooleanField('Remember me')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')




class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class PostForm(FlaskForm):
    body = TextAreaField("Whats on your mind?", validators=[Required()])
    submit = SubmitField('Submit')


class SearchForm(FlaskForm):
    city = TextField('City', validators = [Required(), Length(1,16)])
    property_type = TextField('Property Type', validators = [Required(), Length(1,16)])
    bedrooms = TextAreaField('Bedrooms', validators = [Required(), Length(max=30)])
    budget = TextField('Budget', validators=[Required(), Length(max=30)])
    square_feet = TextField('Square Feet', validators=[Required(), Length(max=30)])
    feature = TextField('Feature', validators=[Required(), Length(max=30)])
    search = SubmitField('Search')


########################################################################################################
########################################################################################################
########################################################################################################
##BLOG ENTITES

class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))



    def __repr__(self):
        return '<Post %r>' % (self.body)

#################################################################################################################
#################################################################################################################
######Entities###################################################################################################
class User(UserMixin, db.Model):

    __tablename__ = 'users'


    id = db.Column('id', db.Integer, primary_key=True)

    #Register/Login
    username = db.Column('username', db.String(16))
    password_hash = db.Column(db.String(64))
    password = db.Column('password',db.String(64))
    password2 = db.Column('password2',db.String(64))
    city = db.Column('city', db.String(16))
    dob = db.Column('dob', db.String(16))
    zipcode = db.Column('zipcode',db.Integer)
    state = db.Column('state', db.String(16))
    address = db.Column('address', db.String(30))
    email = db.Column('email', db.String(25))
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
  

   



    #Profile
    name = db.Column('name', db.String(16))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())

    #Posts
    posts = db.relationship('Post', backref = 'users',lazy='dynamic')


    #UserLogin
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def register(username, password):
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    #Login/Register
    def __init__(self ,username ,password2 ,password ,name ,city ,dob ,zipcode
        ,state ,address ,email ,confirmed ,confirmed_on=None):

        self.username = username
        self.password = bcrypt.generate_password_hash(password)
        self.password2 = password2
        self.email = email
        self.name = name
        self.city = city
        self.dob = dob
        self.zipcode = zipcode
        self.state = state
        self.address = address
        self.confirmed=confirmed
        self.confirmed_on=confirmed_on



##########################################################################################################################
##########################################################################################################################
######Search Listings Entities Database Whoosh############################################################################
class Property(db.Model):

    __tablename__ = 'properties' 

    

    id = db.Column(db.Integer , primary_key = True)
    city = db.Column(db.String(16))
    property_add_id = db.Column(db.Integer)
    property_date = db.Column(db.String(16))
    number_of_rooms = db.Column(db.Integer)
    property_type = db.Column(db.String(16))
    area_size = db.Column(db.Integer)
    per_unit_price = db.Column(db.Integer)
    
    property_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    def __repr__(self):
        return '<Room %r>'.format(self.id)


class address(db.Model):

    __tablename__ = 'addresses'

    id = db.Column(db.Integer, primary_key = True)
    city = db.Column(db.String(16))
    post_property_for = db.Column(db.String(24))
    zipcode = db.Column(db.Integer)
    plot_num = db.Column(db.Integer)
    property_name = db.Column(db.String(16))
    floor_num = db.Column(db.Integer)
    area_name = db.Column(db.String(16))
    state = db.Column(db.String(16))
    country = db.Column(db.String(16))

    def __repr__(self):
       return '<Address %r>' .format(self.id) 


class buyer(db.Model):

    __tablename__ = 'buyers'

    buyer_id = db.Column(db.Integer, primary_key=True)
    min_budget = db.Column(db.Integer)
    max_budget = db.Column(db.Integer)
    max_area = db.Column(db.Integer)
    min_area = db.Column(db.Integer)
    city = db.Column(db.String(24))
    

    def __repr__(self):
       return '<Buyer %r>'.format(self.id)


class seller(db.Model):

    __tablename__ = 'sellers'

    seller_id = db.Column(db.Integer, primary_key=True)
    property_id = db.Column(db.Integer)
    post_property_for = db.Column(db.String(24))

    def __repr__(self):
       return '<Seller %r>'.format(self.seller_id)


class feature(db.Model):

    __tablename__ = 'features'

    feature_id = db.Column(db.Integer, primary_key=True)
    feature_name = db.Column(db.String(24))

    def __repr__(self):
       return '<Feature %r>'.format(self.feature_id)


class room(db.Model):

    __tablename__ = 'rooms'

    room_id = db.Column(db.Integer, primary_key = True)
    image = db.Column(db.String(50))
    area = db.Column(db.Integer)
    room_name = db.Column(db.String(16))

    def __repr__(self):
        return '<Room %r>'.format(self.room_id)

##################################################################################################################
##################################################################################################################
#Routing#######################################################################################################




@app.route('/search/<username>', methods=['POST', 'GET'])
def search(username):
  form = SearchForm()
  user = User.query.filter_by(username = username).first()
  posts = [
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'},
        {'author': user, 'body' : 'City:XXXXXX, Property Type:XXXXX, Bedrooms:XX, Budge:XXX, SquareFeet:XXXXX, Feature:XXXX'}        
       ] 
  return render_template('searchlistings.html', user=user, form = form, posts =posts)

@app.route('/blog/<username>', methods=['GET', 'POST'])
def blog(username):
    form = PostForm()
    user = User.query.filter_by(username = username).first()
    if user == None:
        return redirect(url_for('index'))
    posts = [
        {'author': user, 'body' : 'What are some tips on finding an affordable home?'},
        {'author': user, 'body' : 'What are some esstential features that we have to take in mind?'},
        {'author': user, 'body' : 'Any afforable homes in the Pharr area?'},
        {'author': user, 'body' : 'What are tips on getting a loan for a home?'},
        {'author': user, 'body' : 'Are there any bad neighborhoods I should avoid in the Edinburg area?'},
        {'author': user, 'body' : 'Selling a home by ridge road and I road in Pharr?, click profile for details?'},
        {'author': user, 'body' : 'Looking for a home where is located to a early college high school'},
        {'author': user, 'body' : 'What are the tips in order to evaluate your home ?'}
    ]   
    return render_template('blog.html', user = user , form = form, posts =posts)

@app.route('/user/<username>')
def user(username):
    form = PostForm()
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    posts = [
        {'author': user, 'body' : 'What are some tips on finding an affordable home?'},
        {'author': user, 'body' : 'What are some esstential features that we have to take in mind?'},
        {'author': user, 'body' : 'Any afforable homes in the Pharr area?'},
        {'author': user, 'body' : 'What are tips on getting a loan for a home?'},
        {'author': user, 'body' : 'Are there any bad neighborhoods I should avoid in the Edinburg area?'},
        {'author': user, 'body' : 'Selling a home by ridge road and I road in Pharr?, click profile for details?'},
        {'author': user, 'body' : 'Looking for a home where is located to a early college high school'},
        {'author': user, 'body' : 'What are the tips in order to evaluate your home ?'}
    ]   
    return render_template('profile.html', user=user ,form = form , posts= posts)


@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('index'))


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():                                
        user = User.query.filter_by(username=form.username.data).first()
        if user is None :
            user.verify_password(form.password.data)
            user.last_seen =user.current_logged_in
            return redirect(url_for('index', **request.args))
        login_user(user, form.remember_me.data)
        return redirect(request.args.get('next') or url_for('index'))
    return render_template('login.html', form=form)

@app.route('/signup', methods = ['GET', 'POST'])
def register():

    form = SignUpForm()

    if form.validate_on_submit():

        user = User(username = form.username.data,
                    password = form.password.data,
                    password2 = form.password2.data,
                    name = form.name.data,
                    email = form.email.data,
                    address = form.address.data,
                    state = form.state.data,
                    city = form.city.data,
                    zipcode = form.city.data,
                    dob = form.dob.data,
                    confirmed=False)

        db.session.add(user)
        db.session.commit()

        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('confirm.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, html)

        
        login_user(user,form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/edit_profile')
def edit():
    form = EditProfileForm()
    return render_template('edit-profile.html', form = form)

############################################################################################################
############################################################################################################
####Error Rendering

############################################################################################################
############################################################################################################
##Rendering

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def homepage():
    return render_template('base.html')


@app.route('/gallery')
def gallery():
    return render_template('gallery.html')  

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


###############################################################################################################
###############################################################################################################
##Email Notification

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    msg = MailMessage(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['FLASKY_MAIL_SENDER']
    )
    mail.send(msg)

###############################################################################################################
###############################################################################################################
###############################################################################################################

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
   
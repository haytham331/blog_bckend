
import os
from flask import Flask,make_response,render_template,redirect,url_for,jsonify,g,current_app,request,session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from flask_login import login_user,UserMixin,LoginManager,login_required
from werkzeug.security import generate_password_hash,check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

basedir = os.path.abspath(os.path.dirname(__file__))

# SQLite
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# CORS
CORS(app,supports_credentials=True)
@app.after_request
def after_request(resp):
	resp = make_response(resp)
	resp.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
	resp.headers['Access-Control-Allow-Methods'] = 'GET,POST'
	resp.headers['Access-Control-Allow-Headers'] = 'content-type,token'
	return resp

# Http auth
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username_token,password):
	username_token = request.headers.get('Token')
	if username_token == '':
		return False
	else:
		g.currnet_user = User.verify_auth_token(username_token)
		g.token_used = True
		return g.currnet_user is not None

@auth.error_handler
def auth_error():
	return unauthorized('Invalid credentials')

# Routes
@app.route('/login',methods=['POST'])
def login():
	json = request.get_json()
	user = User.query.filter_by(username = json['username']).first()
	if user.verify_password(json['password']):
		g.currnet_user = user
		token = user.generate_auth_token(expiration=3600)
		return token
	return "wrong password"

@app.route('/register',methods=['POST'])
def register():
	json = request.get_json()
	email = json['username'] + '@email.com'
	user = User(email=email,username=json['username'],password=json['password'])
	db.session.add(user)
	db.session.commit()
	return "200 OK register"


@app.route('/postlist')
def article():
	ptemp = Post.query.all()
	return jsonify({
			'posts': [post.to_json() for post in ptemp],
		})

@auth.login_required
@app.route('/creatpost',methods=['POST'])
def new_post():
	json = request.get_json()
	newpost = Post(title=json['title'],content=json['content'])
	db.session.add(newpost)
	db.session.commit()
	return "200 OK"

def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    return response

# ORM
class User(UserMixin,db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64),unique=True,index=True)
	username = db.Column(db.String(64),unique=True,index=True)
	password_hash = db.Column(db.String(128))

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self,password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self,password):
		return check_password_hash(self.password_hash,password)

	def generate_auth_token(self,expiration):
		s = Serializer(current_app.config['SECRET_KEY'],expires_in = expiration)
		return  s.dumps({'id':self.id}).decode('utf-8')

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
		except:
			return None
		return User.query.get(data['id'])

class Post(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(64),unique=True,index=True)
	content = db.Column(db.String(64))

	def to_json(self):
		json_post = {
			'title': self.title,
			'content': self.content,
		}
		return json_post

if __name__ == '__main__':
	db.drop_all()
	db.create_all()
	app.run()
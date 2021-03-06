#
#
#-----------------------------------import begin--------------------------------------------
import os
from flask import Flask,make_response,render_template,redirect,url_for,jsonify
from flask import g,current_app,request,session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth

from flask_login import login_user,UserMixin,LoginManager,login_required
from werkzeug.security import generate_password_hash,check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
# login_manager = LoginManager()
# login_manager.login_view = 'auth.login'

#-----------------------------------import end--------------------------------------------
#
#
#
#-----------------------------------config begin--------------------------------------------
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir,'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# login_manager.init_app(app)

CORS(app,supports_credentials=True)
#-----------------------------------config end--------------------------------------------
#
#
#
#-----------------------------------hook begin--------------------------------------------
@app.after_request
def after_request(resp):
	resp = make_response(resp)
	resp.headers['Access-Control-Allow-Origin'] = 'http://127.0.0.1:8080'
	resp.headers['Access-Control-Allow-Methods'] = 'GET,POST'
	# resp.headers['Access-Control-Allow-Credentials'] = 'true'
	# resp.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type,token'
	resp.headers['Access-Control-Allow-Headers'] = 'content-type,token'
	# resp.headers['Access-Control-Allow-Headers'] = 'token'
	return resp
#-----------------------------------hook end--------------------------------------------
#
#
#
#
#-----------------------------------auth begin--------------------------------------------
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username_token,password):
	print("auth vertify pw")
	print("vertify token:",request.headers.get('Token'))
	username_token = request.headers.get('Token')
	if username_token == '':
		return False
	if password == '':
		g.currnet_user = User.verify_auth_token(username_token)
		g.token_used = True
		print(g)
		return g.currnet_user is not None
	user = User.query.filter_by(username = username_token).first()
	if not user:
		return False
	g.currnet_user = user
	g.token_used = False
	return user.verify_password(password)

@auth.error_handler
def auth_error():
	print("navigator : auth_error")
	return unauthorized('Invalid credentials')


# @auth.verify_token
# def verify_token(token):
# 	verify_password(token,'')

#-----------------------------------auth  end--------------------------------------------
#
#
#
#
#
#-----------------------------------hooker begin--------------------------------------------
# @auth.login_required

@app.before_request
def before_request():
	if(request.method == 'POST' or request.method == 'GET'):
		noNeedLoginPath = ['/login','/register']
		# if request.path not in noNeedLoginPath:
		print(request.headers)
			# print(request.headers.get('Token'))
			# token = request.headers.get('Token')
			# get_pw(token)

#-----------------------------------  end  --------------------------------------------
#
#
#
#
#-----------------------------------router begin--------------------------------------------
@app.route('/')
def index():
	return "200 OK"

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

# @auth.login_required
@app.route('/postlist')
def article():
	ptemp = Post.query.all()
	print(ptemp)
	for i in ptemp:
		print(i)
		print(i.to_json())
	return jsonify({
			'posts': [post.to_json() for post in ptemp],
		})

@app.route('/getpost')
def getpost():
	postId = request.args.get('id')
	print(postId)
	postDetail = Post.query.filter_by(id = postId).first()
	return jsonify(postDetail.to_json())


@auth.login_required
@app.route('/creatpost',methods=['POST'])
def new_post():
	json = request.get_json()
	newpost = Post(title=json['title'],content=json['content'])
	db.session.add(newpost)
	db.session.commit()
	return "200 OK"

@app.route('/tokens',methods=['POST'])
def get_token():
	if g.currnet_user.is_anonymous or g.token_used:
		return unauthorized('Invalid credentials')
	return jsonify({'token':g.currnet_user.generate_auth_token(expiration=3600),'expiration':3600})

#-----------------------------------end--------------------------------------------
#
#
#
#-----------------------------------error begin--------------------------------------------
def forbidden(message):
	response = jsonify({'error':'forbidden','message':message})
	response.status_code = 403
	return response

def unauthorized(message):
    response = jsonify({'error': 'unauthorized', 'message': message})
    response.status_code = 401
    return response

def bad_request(message):
    response = jsonify({'error': 'bad request', 'message': message})
    response.status_code = 400
    return response

@app.errorhandler(404)
def page_not_found(e):
	if request.accept_mimetypes.accept_json:
		response = jsonify({'error':'not found'})
		response.status_code = 404
		return response
	return '404',404
#-----------------------------------error  end  --------------------------------------------
#
#
#
#-----------------------------------Data Base begin--------------------------------------------
class User(UserMixin,db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(64),unique=True,index=True)
	username = db.Column(db.String(64),unique=True,index=True)
	password_hash = db.Column(db.String(128))

	# article = db.relationship('Article',secondary=user_article,back_populates='users')

	@property
	def password(self):
		raise AttributeError('password is not a readable attribute')

	@password.setter
	def password(self,password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self,password):
		print("User vertify pw")
		return check_password_hash(self.password_hash,password)

	def generate_auth_token(self,expiration):
		s = Serializer(current_app.config['SECRET_KEY'],expires_in = expiration)
		return  s.dumps({'id':self.id}).decode('utf-8')

	@staticmethod
	def verify_auth_token(token):
		s = Serializer(current_app.config['SECRET_KEY'])
		try:
			data = s.loads(token)
			print("what have I get?: ",User.query.get(data['id']))
		except:
			return None
		return User.query.get(data['id'])

	def __repr__(self):
		return '<User %r>' % self.username


class Post(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(64),unique=True,index=True)
	content = db.Column(db.String(64))

	def __repr__(self):
		return '<Post %r>' % self.title

	def to_json(self):
		json_post = {
			'id':self.id,
			'title': self.title,
			'content': self.content,
		}
		return json_post



#-----------------------------------end----------------------------------------------------
#
#
#
#------------------------------------------------------------------------
if __name__ == '__main__':
	db.drop_all()
	db.create_all()
	temp1 = Post(title='title1',content='content1')
	db.session.add(temp1)
	db.session.commit()
	app.run()
	






























































































# class Article(db.Model):
# 	__tablename__ = 'articles'
# 	id = db.Column(db.Integer, primary_key=True)
# 	name = db.Column(db.String(64),unique=True,index=True)
# 	title = db.Column(db.String(64))
# 	author =  db.Column(db.String(64))
# 	date = db.Column(db.DateTime)
# 	content = db.Column(db.String(64))

# 	user = db.relationship('User',secondary=user_article,back_populates='articles')

# 	def __repr__(self):
# 		return '<Article %r>' % self.name




# class Role(db.Model):
# 	__tablename__ = 'roles'
# 	id = db.Column(db.Integer, primary_key=True)
# 	name = db.Column(db.String(64),unique=True)

# 	def __repr__(self):
# 		return '<Role %r>' % self.name


# user_article = db.Table(
# 	'association',
# 	db.Column('user_id',db.Integer,db.ForeignKey('users.id')),
# 	db.Column('article_id',db.Integer,db.ForeignKey('articles.id'))
# 	)


# class User(UserMixin, db.Model):
# 	__tablename__ = 'users'
# 	id = db.Column(db.Integer, primary_key=True)
# 	email = db.Column(db.String(64),unique=True,index=True)
# 	username = db.Column(db.String(64),unique=True,index=True)
# 	password_hash = db.Column(db.String(128))

	# article = db.relationship('Article',secondary=user_article,back_populates='users')

	# @property
	# def password(self):
	# 	raise AttributeError('password is not a readable attribute')
	
	# @password.setter
	# def password(self,password):
	# 	self.password_hash = generate_password_hash(password)

	# def verify_password(self,password):
	# 	return check_password_hash(self.password_hash,password)

	# def __repr__(self):
	# 	return '<User %r>' % self.username



# @login_manager.user_loader
# def load_user(user_id):
# 	return user.query.get(int(user_id))








# 1 - n
# class Person(db.Model):
# 	__tablename__ = 'people'
# 	name = db.Column(db.String(20),primary_key=True)
# 	age = db.Column(db.Integer)
# 	birth = db.Column(db.Date)
# 	phone = db.Column(db.String(11),unique=True)


# 	def __repr__(self):
# 			return '<Person %r>' % self.name

# class Car(db.Model):
# 	__tablename__ = 'cars'
# 	name = db.Column(db.String(10),primary_key=True)
# 	price = db.Column(db.Float)

# 	def __repr__(self):
# 			return '<Car %r>' % self.name

# 1 -1 


# n - n

# association_table = db.Table(
# 	'association', 
# 	db.Column('customer_id', db.Integer, db.ForeignKey('customer.id')),
#     db.Column('product_id', db.Integer, db.ForeignKey('product.id'))
# )


# class Customer(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     name = db.Column(db.String(10))
#     work = db.Column(db.String(20))

#     products = db.relationship('Product', secondary=association_table, back_populates='customers')

#     def __repr__(self):
#         return '姓名：{name} 公司：{work}'.format(name=self.name, work=self.work)


# class Product(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     name = db.Column(db.String(10))
#     price = db.Column(db.Float)

#     customers = db.relationship('Customer', secondary=association_table, back_populates='products')

#     def __repr__(self):
#         return '产品类型：{name} 单价：{price}'.format(name=self.name, price=self.price)


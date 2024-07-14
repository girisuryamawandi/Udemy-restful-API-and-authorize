import json
from flask import Flask, jsonify, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from authlib.integrations.flask_client import OAuth
from functools import wraps
import requests
import logging
from flask_caching import Cache
from flask_compress import Compress
#from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

#from flask_httpauth import HTTPBasicAuth
#from werkzeug.security import generate_password_hash, check_password_hash

cache = Cache()
compress = Compress()

app = Flask(__name__)
cache.init_app(app)
compress.init_app(app)
#auth = HTTPBasicAuth()
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key

# OAuth configuration
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id='your_id',
    client_secret='your_secret',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    client_kwargs={'scope': 'user:email'}
)

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
#login_manager.login_view = 'login'

usersOauth = {}

class User(UserMixin):
    def __init__(self, id, name, email):    
        self.id = id
        self.name = name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    return usersOauth.get(user_id)

#@app.route("/")
#def index():
#    return 'Hello!'

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = github.authorize_access_token()
    resp = github.get('user', token=token)
    profile = resp.json()
    user_id = str(profile['id'])
    if user_id not in usersOauth:
        usersOauth[user_id] = User(id=user_id, name=profile['name'], email=profile['email'])
    login_user(usersOauth[user_id])
    return redirect('/')

#@app.route('/logout')
#@login_required
#def logout():
#    logout_user()
#    return redirect('/')

def verify_github_token(token):
    logging.debug(f"Verifying token: {token}")
    headers = {'Authorization': f'token {token}'}
    response = requests.get('https://api.github.com/user', headers=headers)
    logging.debug(f"GitHub token verification response: {response.status_code}, {response.text}")
    if response.status_code == 200:
        return True, response.json()
    else:
        return False, None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        logging.debug(f"Token from session: {token}")
        if not token:
            auth_header = request.headers.get('Authorization')
            logging.debug(f"Authorization header: {auth_header}")
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        logging.debug(f"Final token: {token}")
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        is_valid, user_info = verify_github_token(token)
        if not is_valid:
            return jsonify({'message': 'Token is invalid!'}), 401

        user_id = str(user_info['id'])
        if user_id not in usersOauth:
            usersOauth[user_id] = User(id=user_id, name=user_info.get('name'), email=user_info.get('email'))
        login_user(usersOauth[user_id], remember=True)
        return f(*args, **kwargs)
    return decorated

#usersBasic = {
#
#    "HR": generate_password_hash("HR123"),
#    "Test": generate_password_hash("Test123")
#}


#@auth.verify_password
#def verify_password(username, password):
#    if username in usersBasic and check_password_hash(usersBasic.get(username), password):
#       return username
    
#users = [
#    {'username':'HR', 'password':'HR123'},
#    {'username':'Test', 'password':'Test123'},
#]

#@app.route('/get-token', methods=['Post'])
#def getToken():
#    username = request.json.get('username', None)
#    password = request.json.get('password', None)
#    user = next((u for u in users if u['username'] == username and u['password'] == password), None)
#    if user is None:
#        return jsonify({'msg': 'Wrong credentials'}), 401
    
 #   access_token = create_access_token(identity=username)
 #   return jsonify(access_token=access_token)

employees = [
    {'id': 1, 'name': 'Max'},
    {'id': 2, 'name': 'Peter'},
    {'id': 3, 'name': 'John'}
]

nextEmployeeId = 4

@app.route('/employees', methods=['GET'])
@token_required
@login_required
@cache.cached(timeout=300)
#@jwt_required()
def get_employees():
    return jsonify(employees)

@app.route('/employees/<int:id>', methods=['GET'])
#@auth.login_required
def get_employee_by_id(id: int):
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error': 'Employee does not exist'}), 404
    return jsonify(employee)

def get_employee(id):
    return next((e for e in employees if e['id'] == id), None)

def employee_is_valid(employee):
    return len(employee) == 1 and 'name' in employee

@app.route('/employees', methods=['POST'])
def create_employee():
    global nextEmployeeId
    employee = json.loads(request.data)
    if not employee_is_valid(employee):
        return jsonify({'error': 'Invalid employee properties.'}), 400
    
    employee['id'] = nextEmployeeId
    nextEmployeeId += 1
    employees.append(employee)

    return '', 201, {'location': f'/employees/{employee["id"]}'}

@app.route('/employees/<int:id>', methods=["PUT"])
def update_employee(id: int):
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error': 'Employee does not exist'}), 404
    
    update_employee = json.loads(request.data)
    if not employee_is_valid(update_employee):
        return jsonify({'error': 'Invalid employee properties.'}), 400
    employee.update(update_employee)
    return jsonify(employee)

@app.route('/employees/<int:id>', methods=['DELETE'])
@token_required
@login_required
def delete_employee(id: int):
    global employees
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error': 'Employee does not exist'}), 404

    employees = [e for e in employees if e['id'] !=  id]
    return jsonify(employee), 200

if __name__ == '__main__':
    app.run(port=5000) 
     
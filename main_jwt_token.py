import json
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'access_key'
jwt = JWTManager(app)


users = [
   {'username':'HR', 'password':'HR123'},
   {'username':'Test', 'password':'Test123'},
]


@app.route('/get-token', methods=['Post'])
def getToken():
    print(request.data)
    # print(request.json())
    print('masuk')
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = next((u for u in users if u['username'] == username and u['password'] == password), None)
    if user is None:
       return jsonify({'msg': 'Wrong credentials'}), 401
    
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

employeers  = [
    {'id' : 1, 'name' : 'Max'},
    {'id' : 2, 'name' : 'Peter'},
    {'id' : 3, 'name' : 'John'},
]

nextEmployeeId = 4

def get_employee(id):
	return next((e for e in employeers if e['id'] == id),None)

def employee_is_valid(employee):
    for key in employee.keys():
        if key != 'name':
            return False
        return True

@app.route('/employees',methods=['GET'])
@jwt_required()
def get_employees():
    return jsonify(employeers)

@app.route('/employees/<int:id>',methods=['GET'])
def get_employee_by_id(id:int):
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error':'Employee does not exit'}), 404 
    return jsonify(employee)
    
@app.route('/employees',methods=['POST'])
def create_employee():
    global nextEmployeeId
    print(request.data)
    employee = json.loads(request.data)
    if not employee_is_valid(employee):
        return jsonify({'error':'Invalid employee properties'}), 404
    employee['id'] = nextEmployeeId
    employeers.append(employee)
    nextEmployeeId += 1
    
    return jsonify(employee), 201, {'location': f"/employees/{employee['id']}"}

@app.route('/employees/<int:id>',methods=['PUT'])
def update_employee(id):
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error':'Employee does not exit'}), 404 
    
    employee = json.loads(request.data)
    employee["id"] = id
    if not employee_is_valid(employee):
        return jsonify({'error':'Invalid employee properties'}), 404
    employeers[int(id)-1] = employee
    return jsonify(employee)

@app.route('/employees/<int:id>',methods=['DELETE'])
def delete_employee(id):
    employee = get_employee(id)
    if employee is None:
        return jsonify({'error':'Employee does not exit'}), 404 
    employees = next(e for e in employeers if e['id'] == id)
    employeers.remove(employees)
    return f"id : {employees['id']}, name : {employees['name']} is deleted"

if __name__ == '__main__':
    app.run(port=5000)
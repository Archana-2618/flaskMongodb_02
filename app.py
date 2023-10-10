from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson import ObjectId

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mydatabase'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'message': 'Email already exists'}), 400
    mongo.db.users.insert_one({
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': hashed_password
    })
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        user = mongo.db.users.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({'error': 'Invalid email or password'}), 401
    except:
        return jsonify({'error': 'Somthing went wrong'}), 404

@app.route('/template', methods=['POST'])
@jwt_required()
def create_template():
    current_user = get_jwt_identity()
    data = request.get_json()
    template_name = data.get('template_name')
    subject = data.get('subject')
    body = data.get('body')
    template_collection = mongo.db.templates
    template_collection.insert_one({
        'user': current_user,
        'template_name': template_name,
        'subject': subject,
        'body': body
    })
    message={'message': 'Template created successfully'}
    data={
        'user': current_user,
        'template_name': template_name,
        'subject': subject,
        'body': body
    }
    return jsonify(message,data), 201

@app.route('/template', methods=['GET'])
@jwt_required()
def get_all_templates():
    current_user = get_jwt_identity()
    template_collection = mongo.db.templates
    templates = template_collection.find({'user': current_user}, {'_id': 0})
    return jsonify(list(templates)), 200


@app.route('/template/<template_id>', methods=['GET'])
@jwt_required()
def get_single_template(template_id):
    current_user = get_jwt_identity()
    try:
        if ObjectId.is_valid(template_id):
            template_object_id = ObjectId(template_id)
            template = mongo.db.templates.find_one({'_id': template_object_id, 'user': current_user}, {'_id': 0})
            if template:
                return jsonify(template), 200
            else:
                return jsonify({'error': 'Template not found'}), 404
        else:
            return jsonify({'error': 'Invalid template_id'}), 400

    except Exception as e:
        return jsonify({'error': 'Invalid template_id'}), 400


@app.route('/template/<template_id>', methods=['PUT'])
@jwt_required()
def update_template(template_id):
    current_user = get_jwt_identity()
    data = request.get_json()

    try:
        if ObjectId.is_valid(template_id):
            template_object_id = ObjectId(template_id)
            template = mongo.db.templates.find_one({'_id': template_object_id, 'user': current_user})
            if not template:
                return jsonify({'error': 'Template not found'}), 404
            mongo.db.templates.update_one({'_id': template_object_id}, {'$set': data})
            return jsonify({'message': 'Template updated successfully'}), 200
        else:
            return jsonify({'error': 'Invalid template_id'}), 400
    except Exception as e:
        return jsonify({'error': 'Invalid template_id'}), 400

@app.route('/template/<template_id>', methods=['DELETE'])
@jwt_required()
def delete_template(template_id):
    current_user = get_jwt_identity()

    try:
        if ObjectId.is_valid(template_id):
            template_object_id = ObjectId(template_id)
            template = mongo.db.templates.find_one({'_id': template_object_id, 'user': current_user})
            if not template:
                return jsonify({'error': 'Template not found'}), 404
            mongo.db.templates.delete_one({'_id': template_object_id})

            return jsonify({'message': 'Template deleted successfully'}), 200
        else:
            return jsonify({'error': 'Invalid template_id'}), 400

    except Exception as e:
        return jsonify({'error': 'Invalid template_id'}), 400

if __name__ == '__main__':
    app.run(debug=True)

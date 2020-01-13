from flask import Flask, jsonify, request, json
from flask_cors import CORS
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flaskext.mysql import MySQL
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import pymysql


app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'secret'

dbServerName = "127.0.0.1"

dbUser = "root"

dbPassword = ""

dbName = "image_compression"

charSet = "utf8mb4"

cusrorType = pymysql.cursors.DictCursor

# mysql = MySQL()
# mysql.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# connection = mysql.connect()
# cur = connection.cursor()
connectionObject= pymysql.connect(host=dbServerName, user=dbUser, password=dbPassword, db=dbName, charset=charSet,cursorclass=cusrorType)
cur = connectionObject.cursor()

CORS(app)


@app.route('/users/register', methods=['POST'])
def register():
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.utcnow()
    print("first name:",first_name);
    print("Beforeinsert--------->")
    cur.execute("INSERT INTO users (first_name, last_name, email, password, created) VALUES ('" +
                str(first_name) + "', '" +
                str(last_name) + "', '" +
                str(email) + "', '" +
                str(password) + "', '" +
                str(created) + "')")

    connectionObject.commit()
    result = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': password,
        'created': created
    }
    print("Result=====", result)
    return jsonify({'result': result})


@app.route('/users/login', methods=['POST'])
def login():
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""

    cur.execute("SELECT * FROM users where email = '" + str(email) + "'")
    rv = cur.fetchone()
    print("Password --------", password)
    if bcrypt.check_password_hash(rv['password'], password):
        access_token = create_access_token(
            identity={'first_name': rv['first_name'], 'last_name': rv['last_name'], 'email': rv['email']})
        result = jsonify({"token": access_token})
    else:
        result = jsonify({"error": "Invalid username and password"})

    return result

if __name__ == '__main__':
    app.run(debug=True)





from app import app
from app import db, login_manager

from flask import Flask, jsonify, g
from flask import request
import time
import sqlite3
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS
from flask_login import LoginManager
from flask_crontab import Crontab

import jwt
from flask_login import current_user, login_user
from app.models import User, Raspberry


import datetime

import subprocess
import sys

import json



auth = HTTPBasicAuth()
CORS(app)
crontab = Crontab(app)


DATABASE = '/home/ec2-user/webapp/temperatures.db'


raspberry_address = app.config['RASP_ADDRESS']
raspberry_port = app.config['RASP_PORT']
raspberry_workspace = "/home/pi/Desktop/TemperatureConnected/"
temperatures_db_password = app.config['TEMPERATURES_DB_PASSWORD']



#global target_fridge_temp
#target_fridge_temp = 10

def ssh_to_raspberry(command):
    ssh = subprocess.Popen(["ssh", "%s" % raspberry_address, "-p", raspberry_port, command],
                           shell=False,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    result = b"".join([line.decode() for line in ssh.stdout.readlines()])
    error = b"".join([line.decode() for line in ssh.stderr.readlines()])
    return result, error

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def sauvegardeDansDb(temperature_blue, temperature_green, temperature_yellow, date, db):
    temperature_average = (temperature_blue + temperature_green + temperature_yellow) / 3
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("INSERT INTO temperatures(date,  temperature_blue, temperature_green, temperature_yellow, temperature_average) VALUES (?, ?, ?, ?, ?)", (date, temperature_blue, temperature_green, temperature_yellow, temperature_average))
    conn.commit()
    conn.close()


def request_temperature():
    command = "python " + raspberry_workspace + "TemperatureIntoTxt.py"
    ssh = subprocess.Popen(["ssh", "%s" % raspberry_address, "-p", raspberry_port, command],
                           shell=False,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    if result == []:
        error = ssh.stderr.readlines()
        print("ERROR: %s" % error )
        rasp = Raspberry.query.filter_by(id=1).first()
        rasp.set_status({"error" : "can't do ssh TemperatureIntoTxt.py"})
        db.session.commit()
        return False
    else:
        return True

def send_target_temperature_to_rasp(temp):
    command = "echo " + str(temp) + " > " + raspberry_workspace + "TargetTemperature.txt"

    result, error = ssh_to_raspberry(command)
    print("ssh incubator", result, error)
    if len(error) > 0:
        #error_message = "".join([line.decode() for line in error])
        print("ERROR: %s" % error)
        set_rasp_status({"error" : error})
        return False
    else:
        return True


def encode_auth_token(user_id):
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=0),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        return e


def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), algorithms=["HS256"])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

def check_authorisation(request):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        print(auth_header)
        auth_token = auth_header.split(" ")[1]
        resp = decode_auth_token(auth_token)
        if isinstance(resp, int):
            return True
        else:
            return False
    else:
        #return jsonify({'message':'Failed'}), 401
        return False

def set_rasp_status(json_status):
    rasp = Raspberry.query.filter_by(id=1).first()
    rasp.set_status(json_status)
    db.session.commit()
    sys.stdout.flush()

@app.route('/temperatures/v2.0', methods=['GET'])
def get_temperatures():
    c = get_db().cursor()
    c.row_factory = dict_factory
    c.execute('''SELECT * FROM temperatures''')
    return jsonify(c.fetchall())

@app.route('/temperatures/v2.0', methods=['POST'])
@auth.login_required
def insert_temperature():
    if not request.json:
        abort(400)
    sauvegardeDansDb(request.json['temperature_blue'], request.json['temperature_green'], request.json['temperature_yellow'], request.json['date'], DATABASE)
    return jsonify({"ok": "good"}), 201
    

@app.route('/temperatures/select/v2.0', methods=['GET'])
def get_temperatures_select():
    start = request.args.get('start')
    end = request.args.get('end')
    if start is None:
        return get_temperatures()
    c = get_db().cursor()
    c.row_factory = dict_factory
    c.execute('SELECT * FROM temperatures WHERE date BETWEEN ? AND ?', (start, end))
    return jsonify(c.fetchall())


@app.route('/set_fridge_temperature', methods=['GET', 'POST'])
def set_fridge_temperature():
    auth = check_authorisation(request)
    if not auth:
        return jsonify({'message':'Authentification error'}), 401
    if request.method == 'GET':
        return jsonify(value = target_fridge_temp), 200
    elif request.method == 'POST':
        data = request.get_json()
        value = data['value']
        rasp = Raspberry.query.filter_by(id=1).first()
        rasp.target_temperature = float(value)
        db.session.commit()
        r = send_target_temperature_to_rasp(rasp.target_temperature)
        if not r:
            return  jsonify(success = False), 401
        return jsonify(success = True, new_target_temperature = rasp.target_temperature), 200


@app.route('/check_global_state', methods=['GET'])
def check_global_state():
    rasp = Raspberry.query.filter_by(id=1).first()
    authentification = check_authorisation(request)
    return jsonify(authentification = authentification, raspberry_status = rasp.get_status(), target_temperature = rasp.target_temperature), 200

@app.route('/incubator', methods=['GET'])
def incubator():
    print("incubator")
    authentification = check_authorisation(request)
    if not authentification:
        return jsonify(message = "require identification"), 401
    rasp = Raspberry.query.filter_by(id=1).first()
    status = rasp.get_status()
    command = "tmux ls"

    # TODO: change logic if multiples tmux sessions
    result, error = ssh_to_raspberry(command)
    print("ssh incubator", result, error)
    if len(error) > 0:
        error_message = error
        print("error_message", error_message)
        if error_message == "no server running on /tmp/tmux-1000/default\n":
            is_incubator_running = False
        else:
            set_rasp_status({"error" : error_message})
            return jsonify(status), 501
    if len(result) == 0:
        is_incubator_running = False
    elif "incubator" in str(result[0]):
        is_incubator_running = True

    status = {}
    status["is_incubator_running"] = is_incubator_running
    switch = request.args.get('switch')
    if switch is not None:
        if switch == "true":
            print("swith on")
            command = "tmux new-session -d -s incubator 'python " + raspberry_workspace + "TemperatureHandler.py'"
            print("command", command)
            result, error = ssh_to_raspberry(command)
            print("result, error", result, error)
            status["is_incubator_running"] = True
        elif switch == "false":
            print("switch off")
            command = "tmux kill-session -t incubator"
            result, error = ssh_to_raspberry(command)
            print("result, error", result, error)
            command = "python " + raspberry_workspace + "shutdown_everything.py"
            result, error = ssh_to_raspberry(command)
            print("result, error", result, error)
            status["is_incubator_running"] = False
    status["result"] = result
    status["error"] = error
    set_rasp_status(status)


    return jsonify(status), 200



@app.route('/login', methods=['POST'])
def login():
    json = request.get_json()
    username = json['username']
    password = json['password']
    user = User.query.filter_by(username=json['username']).first()
    if user is None or not user.check_password(json['password']):
        print('Invalid username or password')
        return jsonify({"error" : "Invalid username or password"}), 401
    token = encode_auth_token(user.id)
    print("token encoded |" + str(token) + "|")
    #print(type(token))
    return jsonify({"token" : str(token)})


@auth.login_required
def insert_temperature():
    if not request.json:
        abort(400)
    sauvegardeDansDb(request.json['temperature_blue'], request.json['temperature_green'], request.json['temperature_yellow'], request.json['date'], DATABASE)
    return jsonify({"ok": "good"}), 201


@auth.get_password
def get_password(username):
    if username == 'rasp':
        return temperatures_db_password
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

#@crontab.job(minute="0")
#def my_scheduled_job():
#    output = request_temperature()









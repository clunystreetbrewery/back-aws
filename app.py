#!/home/ec2-user/webapp/flask/bin/python
from flask import Flask, jsonify, g
from flask import request
import time
import sqlite3
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()


app = Flask(__name__)

DATABASE = '/home/ec2-user/webapp/temperatures.db'

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


@app.route('/temperatures/v2.0', methods=['GET'])
def get_temperatures():
    c = get_db().cursor()
    c.row_factory = dict_factory
    c.execute('''SELECT * FROM temperatures''')
    return jsonify(c.fetchall())

@app.route('/temperatures/select/v2.0', methods=['GET'])
def get_temperatures_select():
    if not request.json:
        return get_temperatures()
    print(request.json)
    start = request.json["start"]
    end = request.json["end"]
    c = get_db().cursor()
    c.row_factory = dict_factory
    c.execute('SELECT * FROM temperatures WHERE date BETWEEN ? AND ?', (start, end))
    #c.execute('''SELECT * FROM temperatures''')
    return jsonify(c.fetchall())

@app.route('/temperatures/v2.0', methods=['POST'])
@auth.login_required
def insert_temperature():
    if not request.json:
        abort(400)
    sauvegardeDansDb(request.json['temperature_blue'], request.json['temperature_green'], request.json['temperature_yellow'], request.json['date'], DATABASE)
    return jsonify({"ok": "good"}), 201

@auth.get_password
def get_password(username):
    if username == 'rasp':
        return 'apiipa'
    return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


if __name__ == '__main__':
    app.run(host= '0.0.0.0', port=6789, debug=True)

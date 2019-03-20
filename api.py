#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from werkzeug.utils import secure_filename
from flask import render_template

#logging


def apiLog(line):
    #if not os.path.exists('apiLog.log'):
    line =[str(w) for w in line]
    flog  = open('apiLog.log','a')
    import datetime 
    now = datetime.datetime.now()
    time = str(now)

    row = [time]
    row.extend(line)
    flog.write('\t'.join(row)+'\n')
    flog.close()




# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/api/upload',methods=['GET','POST'])
@auth.login_required
def upload():
    if request.method == 'POST':
        f = request.files['file']
        filename = secure_filename(f.filename)
        #f.save(os.path.join('app/static',filename))
        f.save('static/'+str(filename))
        print ('remote_addr:',request.remote_addr)
        print ('username:',g.user.username)
        line = [ g.user.username,'api/upload',request.remote_addr,str(filename)]
        apiLog(line)
        return 'ok'
    else:
        return 'method should be post'

from flask import send_file, send_from_directory
import os
from flask import make_response


@app.route("/")
def index():
    #cmd = '$curl -u miguel:python -i -X POST -F "file=@filename.pdf" http://pdf.simplified.org.cn:3000/api/vbeta'
    return render_template('index.html')
    #return '<h2>Hello! Welcome to use PDFPARSER~</h2>'+cmd


@app.route("/api/download/<filename>", methods=['GET'])
def download_file(filename):
    directory = 'static'
    response = make_response(send_from_directory(directory, filename, as_attachment=True))
    response.headers["Content-Disposition"] = "attachment; filename={}".format(filename.encode().decode('latin-1'))
    return response

import sys
sys.path.append('..')
from pdfparser1207 import Parser


@app.route('/api/vbeta',methods=['GET','POST'])
@auth.login_required
def run():
    if request.method == 'POST':
        f = request.files['file']
        filename = secure_filename(f.filename)
        f.save('static/'+str(filename))
        print ('remote_addr:',request.remote_addr)
        print ('username:',g.user.username)
        line = [ g.user.username,'api/vbeta',request.remote_addr,str(filename)]
        apiLog(line)
        directory ='static'
        result = Parser('static/'+str(filename )) 
        result.to_csv(directory)
        filename  = filename[:-4]+'.csv'
        response = make_response(send_from_directory(directory, filename, as_attachment=True))
        response.headers["Content-Disposition"] = "attachment; filename={}".format(filename.encode().decode('latin-1'))
        return response
    else:
        return 'method should be post'



if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    if not os.path.exists('static'):
        os.mkdir('static')
    app.run(host='0.0.0.0',port=3000)

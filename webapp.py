#!/home/ec2-user/webapp/flask/bin/python
from app import app


if __name__ == '__main__':
    #app.run(host= '0.0.0.0', port=6789, debug=True,ssl_context=('cert.pem', 'key.pem'))
    #app.run(host= '0.0.0.0',port=6789, debug=True)
    app.run(host= '0.0.0.0', debug=True)
    #app.run(port=443, ssl_context='adhoc')
    #app.run(ssl_context=('cert.pem', 'key.pem'))

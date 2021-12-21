from flask import Flask
from flask import render_template
from flask import request,redirect,session
from flask.helpers import url_for
import subprocess

import os

TIMEOUT = 1
MAX_TTL = 50
DEFAULT_OUTPUT_DIR = "./tracevis_data/"

app = Flask(__name__)
app.secret_key = 'the random string'
@app.route('/',methods = ['GET', 'POST'])
def index():
    
    if request.method == 'GET':
        name = 'Rosalia'
        return render_template('index.html', title='Welcome', username=name)
    if request.method == 'POST':
        
        url= request.form.get('url')
        
        
        return redirect(url_for('process')) 
    
@app.route('/process',methods = ['GET', 'POST'])
def process():
    if request.method=="POST":
        url= request.form.get('url')
        temp_return= run_command('sudo python3 ./tracevis.py --dns --domain1 %s --domain2 %s'% (url, url))
        x=str(temp_return).rsplit('/', 1)[-1]
        size=len(x)
        z=x[:size - 3]
        y= 'tracevis_data/'+z
        return render_template(y)
        #return render_template('proccess.html')
   
def run_command(command):
    return subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read()


app.run(host='0.0.0.0', port=5000)
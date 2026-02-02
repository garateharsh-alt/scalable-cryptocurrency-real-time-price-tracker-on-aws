import os
import boto3
import requests
import decimal
import io
import base64
import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from botocore.exceptions import ClientError

# --- INITIALIZATION ---
application = Flask(__name__)
application.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')

# --- AWS DYNAMODB SETUP ---
# Elastic Beanstalk uses its IAM Role to authenticate automatically in the cloud.
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

DYNAMODB_TABLE_USERS = 'Users'
DYNAMODB_TABLE_MARKET_PRICES = 'MarketPrices'
DYNAMODB_TABLE_WATCHLIST = 'Watchlist'

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username, password):
        self.id = username
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(username):
    table = dynamodb.Table(DYNAMODB_TABLE_USERS)
    try:
        response = table.get_item(Key={'username': username})
        item = response.get('Item')
        if item:
            return User(item['username'], item['password'])
    except ClientError:
        return None

# --- CHART GENERATION ---
def create_chart(sparkline_data):
    try:
        plt.figure(figsize=(5, 2))
        data = eval(sparkline_data) if isinstance(sparkline_data, str) else sparkline_data
        plt.plot(data, color='#0d6efd')
        plt.axis('off')
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', bbox_inches='tight', pad_inches=0, transparent=True)
        buffer.seek(0)
        image = base64.b64encode(buffer.getvalue()).decode('utf-8')
        plt.close()
        return f'<img src="data:image/png;base64,{image}" alt="7d chart" width="100">'
    except:
        return ""

# --- ROUTES ---
@application.route('/')
def index():
    return render_template('index.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        table = dynamodb.Table(DYNAMODB_TABLE_USERS)
        table.put_item(Item={
            'username': request.form['username'],
            'email': request.form['email'],
            'password': generate_password_hash(request.form['password'])
        })
        return redirect(url_for('login'))
    return render_template('register.html')

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        table = dynamodb.Table(DYNAMODB_TABLE_USERS)
        response = table.get_item(Key={'username': request.form['username']})
        user_data = response.get('Item')
        if user_data and check_password
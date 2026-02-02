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
        if user_data and check_password_hash(user_data['password'], request.form['password']):
            login_user(User(user_data['username'], user_data['password']))
            return redirect(url_for('get_crypto_data'))
        flash('Invalid username or password')
    return render_template('login.html')

@application.route('/prices')
@login_required
def get_crypto_data():
    api_url = "https://api.coingecko.com/api/v3/coins/markets"
    params = {"vs_currency": "usd", "order": "market_cap_desc", "per_page": 10, "sparkline": 'true'}
    try:
        response = requests.get(api_url, params=params)
        data = response.json()
        table = dynamodb.Table(DYNAMODB_TABLE_MARKET_PRICES)
        
        for coin in data:
            table.put_item(Item={
                'symbol': coin['symbol'],
                'name': coin['name'],
                'current_price': decimal.Decimal(str(coin['current_price'])),
                'sparkline_7d': str(coin['sparkline_in_7d']['price']),
                'market_cap_rank': coin['market_cap_rank']
            })

        db_items = table.scan()['Items']
        db_items.sort(key=lambda x: int(x['market_cap_rank']))
        charts = {c['symbol']: create_chart(c['sparkline_7d']) for c in db_items}
        return render_template('trading.html', cryptos=db_items, charts=charts)
    except Exception as e:
        return f"Error: {str(e)}"

@application.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    data = request.get_json()
    table = dynamodb.Table(DYNAMODB_TABLE_WATCHLIST)
    table.put_item(Item={
        'user_id': current_user.username,
        'crypto_symbol': data.get('symbol')
    })
    return jsonify({'message': 'Added to Watchlist!'}), 200

@application.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5000)
import os
import requests
import io
import base64
import decimal
import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, current_user, UserMixin, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

# --- INITIALIZATION [cite: 491-496] ---
application = Flask(__name__)
application.config['SECRET_KEY'] = 'your_secret_key_here'

# Local Database setup (To replace DynamoDB for local run) [cite: 255]
basedir = os.path.abspath(os.path.dirname(__file__))
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'crypto_tracker.db')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(application)

# --- MODELS (Based on PDF Data Structures [cite: 27-45, 951, 959]) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class MarketPrice(db.Model):
    symbol = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(50))
    current_price = db.Column(db.Float)
    sparkline_7d = db.Column(db.Text) 

class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    crypto_symbol = db.Column(db.String(10))

# --- LOGIN MANAGER [cite: 455-463] ---
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- CHART GENERATION  ---
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
        # Registration logic [cite: 281-297]
        hashed_pw = generate_password_hash(request.form['password'])
        new_user = User(username=request.form['username'], email=request.form['email'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Login logic 
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('get_crypto_data'))
    return render_template('login.html')

@application.route('/prices')
@login_required
def get_crypto_data():
    # API integration [cite: 430-444]
    api_url = "https://api.coingecko.com/api/v3/coins/markets"
    params = {"vs_currency": "usd", "order": "market_cap_desc", "per_page": 10, "sparkline": 'true'}
    try:
        response = requests.get(api_url, params=params)
        data = response.json()
        for coin in data:
            existing = MarketPrice.query.filter_by(symbol=coin['symbol']).first()
            if existing:
                existing.current_price = coin['current_price']
                existing.sparkline_7d = str(coin['sparkline_in_7d']['price'])
            else:
                db.session.add(MarketPrice(
                    symbol=coin['symbol'], name=coin['name'],
                    current_price=coin['current_price'], sparkline_7d=str(coin['sparkline_in_7d']['price'])
                ))
        db.session.commit()
        prices = MarketPrice.query.all()
        charts = {p.symbol: create_chart(p.sparkline_7d) for p in prices}
        return render_template('trading.html', cryptos=prices, charts=charts)
    except Exception as e:
        return f"Error: {str(e)}"

@application.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    # Watchlist Logic [cite: 341-363]
    data = request.get_json()
    symbol = data.get('symbol')
    existing = Watchlist.query.filter_by(user_id=current_user.id, crypto_symbol=symbol).first()
    if existing:
        return jsonify({'message': 'Already in watchlist'}), 400
    db.session.add(Watchlist(user_id=current_user.id, crypto_symbol=symbol))
    db.session.commit()
    return jsonify({'message': 'Added to Watchlist!'}), 200

@application.route('/watchlist')
@login_required
def watchlist():
    # Retrieve user's watchlist [cite: 374-387]
    user_watchlist = Watchlist.query.filter_by(user_id=current_user.id).all()
    cryptos_details = []
    charts = {}
    for item in user_watchlist:
        coin = MarketPrice.query.filter_by(symbol=item.crypto_symbol).first()
        if coin:
            cryptos_details.append(coin)
            charts[coin.symbol] = create_chart(coin.sparkline_7d)
    return render_template('watchlist.html', cryptos=cryptos_details, charts=charts)

@application.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with application.app_context():
        db.create_all()
    application.run(host='0.0.0.0', port=5000, debug=True)
from flask import Flask, render_template, request, redirect, session, url_for
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from google_auth_oauthlib.flow import Flow
import os
import pathlib
from cachecontrol import CacheControl
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import google
import requests
from functools import wraps
import razorpay
import json
import datetime

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
razorpay_client = razorpay.Client(auth=("rzp_test_hWbjKqDDxaZkwG", "D9nchXbolV0vmXGiQCrD1Z0O"))

db = SQLAlchemy(app)
migrate = Migrate(app, db)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "196848239339-2atsc3954jpv7us696evaqvcb478d0rv.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add the is_admin column

class Good(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Membership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Rec(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    date_of_payment = db.Column(db.DateTime)
    total_amount = db.Column(db.Float)
    selected_products = db.Column(db.String(255))
    selected_services = db.Column(db.String(255))
    selected_membership=db.Column(db.String(255))

    def __init__(self, username, date_of_payment, total_amount, selected_products, selected_services, selected_membership):
        self.username = username
        self.date_of_payment = date_of_payment
        self.total_amount = total_amount
        self.selected_products = selected_products
        self.selected_services = selected_services
        self.selected_membership = selected_membership

class Bill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    date_of_payment = db.Column(db.DateTime, nullable=False)
    selected_items = db.Column(db.Text, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)

    def __init__(self, username, date_of_payment, total_amount, selected_items):
        self.username = username
        self.date_of_payment = date_of_payment
        self.total_amount = total_amount
        self.selected_items=selected_items

class TotalAmountServices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_amount = db.Column(db.Float, nullable=False)

class TotalAmountProducts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_amount = db.Column(db.Float, nullable=False)

class TotalAmountMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    total_amount = db.Column(db.Float, nullable=False)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return 'Authentication required'
        else:
            return function(*args, **kwargs)

    return wrapper

def admin_login_is_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return 'Authentication required'
        else:
            username = session['username']
            admin = User.query.filter_by(username=username, is_admin=True).first()
            if admin:
                return function(*args, **kwargs)
            else:
                return redirect('/dashboard')  # Redirect to regular user dashboard

    return wrapper

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('homepage.html')

@app.route('/intro')
def intro():
    return render_template('intro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template('error.html')

    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = User.query.filter_by(username=username, is_admin=True).first()
        if admin and check_password_hash(admin.password, password):
            session['username'] = username
            return redirect('/admin/dashboard')  
        else:
            return 'Invalid admin credentials'

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
@admin_login_is_required
def admin_dashboard():
    if 'username' in session:
        username = session['username']
        admin = User.query.filter_by(username=username, is_admin=True).first()
        if admin:
            goods = Good.query.all()
            return render_template('admin_dashboard.html', username=username, goods=goods)
        else:
            return redirect('/dashboard')  # Redirect to regular user dashboard

    return redirect('/admin/login')
      


@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the admin user already exists
        admin = User.query.filter_by(username=username, is_admin=True).first()
        if admin:
            return 'Admin user already exists'

        # Create a new admin user
        admin_user = User(username=username, password=generate_password_hash(password), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()

        return 'Admin user created successfully'

    return render_template('create_admin.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return 'Username already exists'

        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')


@app.route('/dashboard')

def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/existingusers')
def existing_users():
    users = User.query.all()
    return render_template('existing_users.html', users=users)


@app.route('/gmaillogin')
def glogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        return "Authorization error"

    credentials = flow.credentials
    request_session = requests.Session()
    cached_session = CacheControl(request_session)
    token_request = google_requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["username"] = session["name"]
    email = id_info.get("email")

    return redirect("/dashboard")

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_login_is_required
def add_good():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        new_good = Good(name=name, description=description, price=price)
        db.session.add(new_good)
        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('add_good.html')

@app.route('/edit-good/<int:good_id>', methods=['GET', 'POST'])
@admin_login_is_required
def edit_good(good_id):
    good = Good.query.get_or_404(good_id)

    if request.method == 'POST':
        good.name = request.form['name']
        good.description = request.form['description']
        good.price = request.form['price']

        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('edit_good.html', good=good)

@app.route('/delete-good/<int:good_id>', methods=['POST'])
@admin_login_is_required
def delete_good(good_id):
    good = Good.query.get_or_404(good_id)
    db.session.delete(good)
    db.session.commit()

    return redirect('/admin/dashboard')

@app.route('/admin/view-products')
def view_products():
    products = Good.query.all()

    return render_template('view_products.html', products=products)

@app.route('/shop-products', methods=['GET', 'POST'])
def shop_products():
    if request.method == 'POST':
        selected_product_ids = request.form.getlist('selected_products')
        selected_products = Good.query.filter(Good.id.in_(selected_product_ids)).all()
        total_amount = sum(product.price for product in selected_products)
        products = Good.query.all()
        
        
        return render_template('shop_products.html', products=products, selected_products=selected_products, total_amount=total_amount)

    products = Good.query.all()
    return render_template('shop_products.html', products=products)

@app.route('/shop-membership', methods=['GET', 'POST'])
def shop_membership():
    if request.method == 'POST':
        selected_membership_ids = request.form.getlist('selected_membership')
        selected_memberships = Membership.query.filter(Membership.id.in_(selected_membership_ids)).all()
        total_amount = sum(membership.price for membership in selected_memberships)
        memberships = Membership.query.all()
        
        return render_template('shop_membership.html', memberships=memberships, selected_memberships=selected_memberships, total_amount=total_amount)

    memberships = Membership.query.all()
    return render_template('shop_membership.html', memberships=memberships)


@app.route('/shop-products/checkout', methods=['GET', 'POST'])
def checkout_products():
    if request.method == 'POST':
        selected_product_ids = request.form.getlist('selected_products')
        selected_products = Good.query.filter(Good.id.in_(selected_product_ids)).all()
        total_amount_products = sum(product.price for product in selected_products)
        
        # Create a list of selected products
        selected_items = [f'{product.name} - ₹{product.price}' for product in selected_products]
        selected_items_str = '<br>'.join(selected_items)
        
        # Store the serialized products and total amount in the session
        session['selected_products'] = selected_items_str
        session['total_amount_products'] = total_amount_products
        
        return render_template('checkout_products.html', selected_products=selected_products, total_amount_products=total_amount_products)
    
    else:
        return "Invalid request method"


@app.route('/shop-membership/checkout', methods=['GET', 'POST'])
def checkout_membership():
    if request.method == 'POST':
        selected_membership_ids = request.form.getlist('selected_memberships')
        selected_memberships = Membership.query.filter(Membership.id.in_(selected_membership_ids)).all()
        total_amount_membership = sum(membership.price for membership in selected_memberships)

        # Create a list of selected memberships
        selected_items = [f'{membership.name} - ₹{membership.price}' for membership in selected_memberships]
        selected_items_str = '<br>'.join(selected_items)

        # Store the serialized memberships and total amount in the session
        session['selected_memberships'] = selected_items_str
        session['total_amount_membership'] = total_amount_membership

        return render_template('checkout_membership.html', selected_memberships=selected_memberships, total_amount_membership=total_amount_membership)

    else:
        return "Invalid request method"


@app.route('/admin/receipts')
@admin_login_is_required
def admin_receipts():
    receipts = Bill.query.all()  # Assuming you have a Receipt model and want to retrieve all receipts
    
    return render_template('admin_receipts.html', receipts=receipts)


@app.route('/admin/add-service', methods=['GET', 'POST'])
@admin_login_is_required
def add_service():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        new_service = Service(name=name, description=description, price=price)
        db.session.add(new_service)
        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('add_service.html')

@app.route('/edit-service/<int:service_id>', methods=['GET', 'POST'])
@admin_login_is_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)

    if request.method == 'POST':
        service.name = request.form['name']
        service.description = request.form['description']
        service.price = request.form['price']

        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('edit_service.html', service=service)

@app.route('/delete-service/<int:service_id>', methods=['POST'])
@admin_login_is_required
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()

    return redirect('/admin/dashboard')

@app.route('/admin/view-membership')
def view_membership():
    memberships =Membership.query.all()

    return render_template('view_memberships.html', memberships=memberships)

@app.route('/admin/view-services')
def view_services():
    services = Service.query.all()

    return render_template('view_services.html', services=services)

@app.route('/shop-services', methods=['GET', 'POST'])
def shop_services():
    if request.method == 'POST':
        selected_service_ids = request.form.getlist('selected_services')
        selected_services = Service.query.filter(Service.id.in_(selected_service_ids)).all()
        total_amount = sum(service.price for service in selected_services)
        services = Service.query.all()
        return render_template('shop_services.html', services=services, selected_services=selected_services, total_amount=total_amount)

    services = Service.query.all()
    return render_template('shop_services.html', services=services)

import json

import json

@app.route('/shop-services/checkout', methods=['GET', 'POST'])
def checkout_services():
    if request.method == 'POST':
        selected_service_ids = request.form.getlist('selected_services')
        selected_services = Service.query.filter(Service.id.in_(selected_service_ids)).all()
        total_amount_services = sum(service.price for service in selected_services)
        
        # Create a list of dictionaries with required service information
        selected = [f'{service.name} - ₹{service.price}' for service in selected_services]
        selected_items_str = ', '.join(selected)
        
        
        # Store the serialized services and total amount in the session
        session['selected_services'] = selected_items_str
        session['total_amount_services'] = total_amount_services
        
        return render_template('checkout_services.html', selected_services=selected_services, total_amount_services=total_amount_services)
    else:
        return "Invalid request method"







@app.route('/admin/add-membership', methods=['GET', 'POST'])
@admin_login_is_required
def add_membership():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']

        new_membership = Membership(name=name, description=description, price=price)
        db.session.add(new_membership)
        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('add_membership.html')

@app.route('/edit-membership/<int:membership_id>', methods=['GET', 'POST'])
@admin_login_is_required
def edit_membership(membership_id):
    membership = Membership.query.get_or_404(membership_id)

    if request.method == 'POST':
        membership.name = request.form['name']
        membership.description = request.form['description']
        membership.price = request.form['price']

        db.session.commit()

        return redirect('/admin/dashboard')

    return render_template('edit_membership.html', membership=membership)

@app.route('/delete-membership/<int:membership_id>', methods=['POST'])
@admin_login_is_required
def delete_membership(membership_id):
    membership = Membership.query.get_or_404(membership_id)
    db.session.delete(membership)
    db.session.commit()

    return redirect('/admin/dashboard')

@app.route('/admin/view-memberships')
def view_memberships():
    memberships = Membership.query.all()

    return render_template('view_memberships.html', memberships=memberships)

@app.route('/shop-memberships', methods=['GET', 'POST'])
def shop_memberships():
    if request.method == 'POST':
        selected_membership_ids = request.form.getlist('selected_memberships')
        selected_memberships = Membership.query.filter(Membership.id.in_(selected_membership_ids)).all()
        total_amount = sum(membership.price for membership in selected_memberships)
        memberships = Membership.query.all()
        return render_template('shop_memberships.html', memberships=memberships, selected_memberships=selected_memberships, total_amount=total_amount)

    memberships = Membership.query.all()
    return render_template('shop_memberships.html', memberships=memberships)





@app.route('/shop-products/checkout/razor', methods=['GET', 'POST'])
def app_create():
    if request.method == 'POST':
        total_amount_products = session.get('total_amount_products')
        if total_amount_products:
            total_amount = float(total_amount_products) * 100  # Multiply by 100
            return render_template('rrr.html', total_amount=total_amount)
        else:
            return "Invalid total_amount value"

    return render_template('rrr.html')

@app.route('/shop-services/checkout/razor', methods=['GET', 'POST'])
def app_create1():
    if request.method == 'POST':
        total_amount_services = session.get('total_amount_services')
        if total_amount_services:
            total_amount = float(total_amount_services) * 100  # Multiply by 100
            return render_template('rrr1.html', total_amount=total_amount)
        else:
            return "Invalid total_amount_services value"

    return render_template('rrr1.html')

@app.route('/shop-membership/checkout/razor', methods=['GET', 'POST'])
def app_create2():
    if request.method == 'POST':
        total_amount_membership = session.get('total_amount_membership')
        if total_amount_membership:
            total_amount = float(total_amount_membership) * 100  # Multiply by 100
            return render_template('rrr2.html', total_amount=total_amount)
        else:
            return "Invalid total_amount_memberships value"

    return render_template('rrr2.html')


import ast

@app.route('/shop-products/checkout/charge', methods=['POST'])
def charge():
    # Extract data from the request
    username = session.get('username')
    date_of_payment_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_of_payment = datetime.datetime.strptime(date_of_payment_str, '%Y-%m-%d %H:%M:%S')
    total_amount = session.get('total_amount_products')
    selected_items = session.get('selected_products')

    # Update total_amount_products in the TotalAmountProducts table
    total_amount_products = TotalAmountProducts.query.first()
    if total_amount_products:
        total_amount_products.total_amount += total_amount
    else:
        total_amount_products = TotalAmountProducts(total_amount=total_amount)
    db.session.add(total_amount_products)
    db.session.commit()

    receipt = Bill(username=username, date_of_payment=date_of_payment, total_amount=total_amount,
                  selected_items=selected_items)
    db.session.add(receipt)
    db.session.commit()

    return render_template('receipt.html', username=username, date_of_payment=date_of_payment,
                           selected_items=selected_items, total_amount_products=total_amount)

@app.route('/shop-membership/checkout/charge', methods=['POST'])
def charge2():
    # Extract data from the request
    username = session.get('username')
    date_of_payment_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_of_payment = datetime.datetime.strptime(date_of_payment_str, '%Y-%m-%d %H:%M:%S')
    total_amount = session.get('total_amount_membership')
    selected_items = session.get('selected_memberships')

    total_amount_membership = TotalAmountMembership.query.first()
    if total_amount_membership:
        total_amount_membership.total_amount += total_amount
    else:
        total_amount_membership = TotalAmountMembership(total_amount=total_amount)
    db.session.add(total_amount_membership)
    db.session.commit()
    
    receipt = Bill(username=username, date_of_payment=date_of_payment, total_amount=total_amount,
                  selected_items=selected_items)
    db.session.add(receipt)
    db.session.commit()

    return render_template('receipt2.html', username=username, date_of_payment=date_of_payment,
                           selected_items=selected_items, total_amount_membership=total_amount)


@app.route('/shop-services/checkout/charge', methods=['POST'])
def charge1():
    # Extract data from the request
    username = session.get('username')
    date_of_payment_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    date_of_payment = datetime.datetime.strptime(date_of_payment_str, '%Y-%m-%d %H:%M:%S')
    total_amount = session.get('total_amount_services')
    selected_items = session.get('selected_services')

    # Update total_amount_services in the TotalAmountServices table
    total_amount_services = TotalAmountServices.query.first()
    if total_amount_services:
        total_amount_services.total_amount += total_amount
    else:
        total_amount_services = TotalAmountServices(total_amount=total_amount)
    db.session.add(total_amount_services)
    db.session.commit()

    receipt = Bill(username=username, date_of_payment=date_of_payment, total_amount=total_amount,
                  selected_items=selected_items)
    db.session.add(receipt)
    db.session.commit()
    
    return render_template('receipt1.html', username=username, date_of_payment=date_of_payment,
                           selected_items=selected_items, total_amount_services=total_amount)


@app.route('/admin/revenue')
def admin_revenue():
    total_revenue_products = TotalAmountProducts.query.first()
    total_revenue_services = TotalAmountServices.query.first()
    total_revenue_membership = TotalAmountMembership.query.first()
    total_revenue_combined = 0

    if total_revenue_products:
        total_revenue_combined += total_revenue_products.total_amount

    if total_revenue_services:
        total_revenue_combined += total_revenue_services.total_amount

    if total_revenue_membership:
        total_revenue_combined += total_revenue_membership.total_amount

    return render_template('admin_revenue.html', total_revenue_products=total_revenue_products,
                           total_revenue_services=total_revenue_services,
                           total_revenue_membership=total_revenue_membership,
                           total_revenue_combined=total_revenue_combined)





if __name__ == '__main__':
    app.run(debug=True)

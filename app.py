from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
    flash
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from flask_migrate import Migrate
import re

import pandas as pd


app = Flask(__name__)
app.jinja_env.globals.update(
    timedelta=timedelta
)
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = \
    os.getenv('DATABASE_URL')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['SESSION_COOKIE_SECURE'] = False

app.config['REMEMBER_COOKIE_HTTPONLY'] = True


db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# LOGIN MANAGER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def valid_password(password):

    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"\d", password):
        return False

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False

    return True

# USER MODEL

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default='employee'
    )

    restaurant_id = db.Column(
        db.Integer,
        db.ForeignKey('restaurant.id')
    )


# INGREDIENT MODEL

class Ingredient(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    ingredient_name = db.Column(db.String(100))
    category = db.Column(db.String(100))
    quantity = db.Column(db.Float)
    price = db.Column(db.Float)
    purchase_date = db.Column(db.String(50))
    supplier = db.Column(db.String(100))
    used = db.Column(db.String(10))
    expiry_date = db.Column(db.String(50))

    restaurant_id = db.Column(
        db.Integer,
        db.ForeignKey('restaurant.id')
    )

# Restaurant Model
class Restaurant(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100))

    location = db.Column(db.String(100))

class ActivityLog(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    action = db.Column(
        db.String(300)
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    restaurant_id = db.Column(
        db.Integer,
        db.ForeignKey('restaurant.id')
    )

@app.route('/delete-log/<int:id>')
@login_required
def delete_log(id):

    # Only admins can delete logs

    if current_user.role != 'admin':

        flash('Access Denied')

        return redirect('/')

    log = ActivityLog.query.filter_by(
        id=id
    ).first_or_404()

    db.session.delete(log)

    db.session.commit()

    flash('Activity deleted')

    return redirect('/')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# LOGIN PAGE
@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(
            username=username

        ).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            return redirect('/')

        else:

            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        restaurant_name = request.form['restaurant_name']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation

        # Validation

        if password != confirm_password:
            flash('Passwords do not match')

            return redirect('/signup')

        if not valid_password(password):
            flash(
                'Password must contain uppercase, lowercase, number, special character, and be at least 8 characters long'
            )

            return redirect('/signup')
        existing_restaurant = Restaurant.query.filter_by(
            name=restaurant_name
        ).first()

        if existing_restaurant:
            flash('Restaurant already exists')
            return redirect('/signup')

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            flash('Username already exists')
            return redirect('/signup')

        # Create restaurant

        new_restaurant = Restaurant(
            name=restaurant_name
        )

        db.session.add(new_restaurant)
        db.session.commit()

        # Create admin user

        hashed_password = generate_password_hash(password)

        admin_user = User(

            username=username,

            password=hashed_password,

            role='admin',

            restaurant_id=new_restaurant.id
        )

        db.session.add(admin_user)
        db.session.commit()

        flash('Restaurant account created')

        return redirect('/login')

    return render_template('signup.html')

@app.route('/create-user', methods=['GET', 'POST'])
@login_required
def create_user():

    if current_user.role != 'admin':
        flash('Access Denied')

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if not valid_password(password):
            flash(
                'Password must contain uppercase, lowercase, number, special character, and be at least 8 characters long'
            )

            return redirect('/create-user')


        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return 'User already exists'

        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            password=hashed_password,
            role=role,
            restaurant_id=current_user.restaurant_id
        )

        db.session.add(new_user)
        db.session.commit()

        return redirect('/')

    return render_template('create_user.html')

# LOGOUT

@app.route('/logout')
@login_required
def logout():

    logout_user()

    return redirect('/login')


# HOME PAGE

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():

    if request.method == 'POST':

        new_ingredient = Ingredient(
            ingredient_name=request.form['ingredient_name'],
            category=request.form['category'],
            quantity=float(request.form['quantity']),
            price=float(request.form['price']),
            purchase_date=request.form['purchase_date'],
            supplier=request.form['supplier'],
            used=request.form['used'],
            restaurant_id = current_user.restaurant_id,
            expiry_date=request.form['expiry_date'],
        )

        db.session.add(new_ingredient)

        log = ActivityLog(

            action=f'{current_user.username} added {new_ingredient.ingredient_name}',

            restaurant_id=current_user.restaurant_id
        )

        db.session.add(log)

        db.session.commit()

        return redirect('/')

    ingredients_query = Ingredient.query.filter_by(
        restaurant_id=current_user.restaurant_id
    )

    total_items = ingredients_query.count()

    total_cost = db.session.query(
        db.func.sum(Ingredient.price)
    ).filter_by(
        restaurant_id=current_user.restaurant_id
    ).scalar()

    used_items = ingredients_query.filter_by(
        used='Yes'
    ).count()

    unused_items = ingredients_query.filter_by(
        used='No'
    ).count()

    if total_cost is None:
        total_cost = 0

    category_data = db.session.query(
        Ingredient.category,
        db.func.sum(Ingredient.price)
    ).filter_by(
        restaurant_id=current_user.restaurant_id
    ).group_by(
        Ingredient.category
    ).all()

    categories = [item[0] for item in category_data]
    category_totals = [float(item[1]) for item in category_data]

    low_stock_items = Ingredient.query.filter(
        Ingredient.restaurant_id == current_user.restaurant_id,
        Ingredient.quantity <= 5

    ).all()

    expiring_items = []

    expired_items = []

    ingredients = Ingredient.query.filter_by(
        restaurant_id=current_user.restaurant_id
    ).all()

    today = datetime.today().date()

    for item in ingredients:

        if item.expiry_date:

            expiry = datetime.strptime(
                item.expiry_date,
                '%Y-%m-%d'
            ).date()

            days_left = (expiry - today).days

            if days_left < 0:

                expired_items.append({
                    'name': item.ingredient_name,
                    'days': abs(days_left)
                })

            elif days_left <= 3:

                expiring_items.append({
                    'name': item.ingredient_name,
                    'days': days_left
                })

    logs = ActivityLog.query.filter_by(

        restaurant_id=current_user.restaurant_id

    ).order_by(

        ActivityLog.timestamp.desc()

    ).limit(5).all()

    return render_template(
        'index.html',
        total_items=total_items,
        total_cost=total_cost,
        used_items=used_items,
        unused_items=unused_items,
        categories=categories,
        category_totals=category_totals,
        low_stock_items = low_stock_items,
        expiring_items=expiring_items,
        expired_items=expired_items,
        logs=logs

    )


# RECORDS PAGE + SEARCH

@app.route('/records')
@login_required
def records():

    search = request.args.get('search')

    ingredients = Ingredient.query.filter_by(
        restaurant_id=current_user.restaurant_id
    )

    if search:

        ingredients = ingredients.filter(
            Ingredient.ingredient_name.ilike(f'%{search}%')
        )

    ingredients = ingredients.all()

    return render_template(
        'records.html',
        ingredients=ingredients
    )


# EDIT RECORD

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):

    ingredient = Ingredient.query.filter_by(
        id=id,
        restaurant_id=current_user.restaurant_id
    ).first_or_404()

    if request.method == 'POST':

        ingredient.ingredient_name = request.form['ingredient_name']
        ingredient.category = request.form['category']
        ingredient.quantity = float(request.form['quantity'])
        ingredient.price = float(request.form['price'])
        ingredient.purchase_date = request.form['purchase_date']
        ingredient.supplier = request.form['supplier']
        ingredient.used = request.form['used']
        ingredient.expiry_date = request.form['expiry_date']

        log = ActivityLog(

            action=f'{current_user.username} edited {ingredient.ingredient_name}',

            restaurant_id=current_user.restaurant_id
        )

        db.session.add(log)

        db.session.commit()

        return redirect('/records')

    return render_template(
        'edit.html',
        ingredient=ingredient
    )


# DELETE RECORD

@app.route('/delete/<int:id>')
@login_required
def delete(id):

    # Only admins can delete

    if current_user.role != 'admin':
        return 'Access Denied'

    ingredient = Ingredient.query.filter_by(
                    id=id,
                    restaurant_id=current_user.restaurant_id
                ).first_or_404()

    log = ActivityLog(

        action=f'{current_user.username} deleted {ingredient.ingredient_name}',

        restaurant_id=current_user.restaurant_id
    )

    db.session.add(log)

    db.session.delete(ingredient)
    db.session.commit()

    return redirect('/records')


# EXPORT CSV

@app.route('/export')
@login_required
def export():

    ingredients = Ingredient.query.filter_by(
                      restaurant_id=current_user.restaurant_id
                    ).all()
    #ingredients = Ingredient.query.all()

    data = []

    for item in ingredients:

        data.append({
            'Ingredient': item.ingredient_name,
            'Category': item.category,
            'Quantity': item.quantity,
            'Price': item.price,
            'Purchase Date': item.purchase_date,
            'Supplier': item.supplier,
            'Used': item.used
        })

    df = pd.DataFrame(data)

    file_name = 'restaurant_data.csv'

    df.to_csv(file_name, index=False)

    return send_file(file_name, as_attachment=True)


if __name__ == '__main__':

    with app.app_context():
            db.create_all()

    app.run(debug=True)


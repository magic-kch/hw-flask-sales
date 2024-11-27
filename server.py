import flask
from flask import request, jsonify
from flask.views import MethodView
from models import User, Session, Product
from sqlalchemy.exc import IntegrityError
import flask_bcrypt
from pydantic import ValidationError
from schema import CreateUser, UpdateUser, CreateProduct, UpdateProduct
import base64


app = flask.Flask(__name__)
bcrypt = flask_bcrypt.Bcrypt(app)


def validate_json(json_data: dict, schema_class):
    try:
        schema_object = schema_class(**json_data)
        json_data_validated = schema_object.dict(exclude_unset=True)
        return json_data_validated
    except ValidationError as err:
        errors = err.errors()
        for error in errors:
            error.pop('ctx', None)
        raise HttpError(400, errors)

def hash_password(password: str):
    password_bytes = password.encode('utf-8')
    return bcrypt.generate_password_hash(password_bytes).decode('utf-8')


class HttpError(Exception):
    def __init__(self, status_code: int, err_message: str | dict | list):
        self.status_code = status_code
        self.err_message = err_message

@app.errorhandler(HttpError)
def error_handler(error):
    http_response = jsonify({'error': error.err_message})
    http_response.status_code = error.status_code
    return http_response

@app.before_request
def before_request():
    session = Session()
    request.session = session


@app.after_request
def after_request(response: flask.Response):
    request.session.close()
    return response

def get_user_by_id(user_id: int):
    user = request.session.get(User, user_id)
    if user is None:
        raise HttpError(404, 'user not found')
    return user

def add_user(user: User):
    request.session.add(user)
    try:
        request.session.commit()
    except IntegrityError:
        raise HttpError(409, 'user already exists')

def get_product_by_id(product_id: int):
    product = request.session.get(Product, product_id)
    if product is None:
        raise HttpError(404, 'product not found')
    return product

def auth_check(auth_header):
    if not auth_header:
        raise HttpError(401, 'Login or password not provided')
    if auth_header:
        decoded_auth_header = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
        name, password = decoded_auth_header.split(':')
        user = request.session.query(User).filter_by(name=name).first()
        print(user.password)
        if not user or not bcrypt.check_password_hash(user.password, password):
            raise HttpError(401, 'login or password is incorrect')
    return user

class UserView(MethodView):
    def get(self, user_id: int):
        user = get_user_by_id(user_id)
        return jsonify(user.dict)

    def post(self):
        json_data = validate_json(request.json, CreateUser)
        json_data['password'] = hash_password(json_data['password'])
        user = User(**json_data)
        add_user(user)
        return jsonify(user.id_dict)

    def patch(self, user_id: int):
        auth_header = request.headers.get('Authorization')
        user = auth_check(auth_header)
        if user_id != user.id:
            raise HttpError(403, 'Forbidden')

        json_data = validate_json(request.json, UpdateUser)
        if "password" in json_data:
            json_data['password'] = hash_password(json_data['password'])
        # user = get_user_by_id(user_id)
        for key, value in json_data.items():
            setattr(user, key, value)
        add_user(user)
        return jsonify(user.id_dict)

    def delete(self, user_id: int):
        auth_header = request.headers.get('Authorization')
        user = auth_check(auth_header)
        if user_id != user.id:
            raise HttpError(403, 'Forbidden')
        # user = get_user_by_id(user_id)
        request.session.delete(user)
        request.session.commit()
        return jsonify({'status': 'deleted'})
    

class ProductView(MethodView):
    def get(self, product_id: int):
        product = get_product_by_id(product_id)
        return jsonify(product.dict)


    def post(self):
        auth_header = request.headers.get('Authorization')
        user = auth_check(auth_header)

        json_data = validate_json(request.json, CreateProduct)
        product = Product(**json_data)
        product.owner_id = user.id
        request.session.add(product)
        request.session.commit()
        return jsonify(product.id_dict)

    def patch(self, product_id: int):
        auth_header = request.headers.get('Authorization')
        user = auth_check(auth_header)

        json_data = validate_json(request.json, UpdateProduct)

        product = get_product_by_id(product_id)

        if product.owner_id != user.id:
            raise HttpError(403, 'Forbidden')
        for key, value in json_data.items():
            setattr(product, key, value)
        request.session.add(product)
        request.session.commit()
        return jsonify(product.id_dict)

    def delete(self, product_id: int):
        auth_header = request.headers.get('Authorization')
        user = auth_check(auth_header)

        json_data = validate_json(request.json, UpdateProduct)


        if json_data.get('owner_id') != user.id:
            raise HttpError(403, 'Forbidden')

        product = get_product_by_id(product_id)
        request.session.delete(product)
        request.session.commit()
        return jsonify({'status': 'deleted'})

class UserViewAll(MethodView):
    def get(self):
        users = request.session.query(User).all()
        return jsonify([user.dict for user in users])
    

class ProductViewAll(MethodView):
    def get(self):
        products = request.session.query(Product).all()
        if not products:
            return jsonify({"error": "No products found"}), 404
        return jsonify([product.dict for product in products])


class ProductViewRetrieve(MethodView):
    def get(self, user_id: int):
        products = request.session.query(Product).filter_by(owner_id=user_id).all()
        if not products:
            return jsonify({"error": "No products found"}), 404
        return jsonify([product.dict for product in products])

product_view_retrieve = ProductViewRetrieve.as_view('products_retrieve')
product_view_all = ProductViewAll.as_view('products_all')
product_view = ProductView.as_view('products')
user_view = UserView.as_view('users')
user_view_all = UserViewAll.as_view('users_all')

app.add_url_rule(
    '/product/<int:product_id>/',
    view_func=product_view,
    methods=['GET', 'PATCH', 'DELETE']
)

app.add_url_rule(
    '/product/',
    view_func=product_view,
    methods=['POST']
)

app.add_url_rule(
    '/',
    view_func=product_view_all,
    methods=['GET']
)

app.add_url_rule(
    '/users/',
    view_func=user_view_all,
    methods=['GET']
)

app.add_url_rule(
    '/user/<int:user_id>/',
    view_func=user_view,
    methods=['GET', 'PATCH', 'DELETE'])

app.add_url_rule(
    '/user/',
    view_func=user_view,
    methods=['POST'])

app.add_url_rule(
    '/user/<int:user_id>/products/',
    view_func=product_view_retrieve,
    methods=['GET']
)

app.run(host='0.0.0.0', port=5000)
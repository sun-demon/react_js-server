from flask import (Flask, session, request, jsonify, make_response)
import re
import hashlib
import json
from base64 import b64encode
import os


app = Flask(__name__)

users_filepath = 'files/users.json'
news_filepath = 'files/news.json'
app = Flask(__name__, template_folder='templates')
app.secret_key = b'_5#y3L"F4Q8z\n\xec]/'


class User:
    def __init__(self, login_: str, email: str, password: str):
        validate_login(login_)
        validate_email(email)
        validate_password(password)
        self.login = login_
        self.email = email
        self.hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

class Newpaper:
    def __init__(self, login_: str, text: str):
        self.login = login_
        self.text = text

class LoginException(Exception):
    def __init__(self, message):
        super().__init__(message)

class EmailException(Exception):
    def __init__(self, message):
        super().__init__(message)

class PasswordException(Exception):
    def __init__(self, message):
        super().__init__(message)


def has_space(value: str) -> bool:
    return re.search(r'\s', value) is not None

def validate_login(login_: str) -> None:
    MAX_LOGIN_LENGTH = 20
    if login_ == '':
        raise LoginException('Пустое поле')
    elif has_space(login_):
        raise LoginException('Есть пробельные символы')
    elif len(login_) > MAX_LOGIN_LENGTH:
        raise LoginException(f'Длина имени больше {MAX_LOGIN_LENGTH}')

def validate_email(email: str) -> None:
    if not re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email):
        raise EmailException('Неверный формат')

def validate_password(password: str) -> None:
    MIN_PASSWORD_LENGTH = 8
    has_digit = re.search(r'\d', password) is not None
    has_uppercase = re.search(r'[A-Z]', password) is not None
    has_lowercase = re.search(r'[a-z]', password) is not None
    if has_space(password):
        raise PasswordException('Есть пробельные символы')
    elif len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordException(f'Длина пароля меньше {MIN_PASSWORD_LENGTH} символов')
    elif not has_digit:
        raise PasswordException('Нет цифр')
    elif not has_uppercase:
        raise PasswordException('Нет заглавных латинских букв')
    elif not has_lowercase:
        raise PasswordException('Нет строчных латинских букв')

def get_news():
    news = list()
    with open(news_filepath, encoding='utf-8') as f:
        news = list(json.loads(f.read()))
    return news;

def login_user(filepath: str, the_user: User):
    users = []
    with open(filepath, encoding='utf-8') as f:
        users = json.loads(f.read())
    for user in users:
        if user['login'] == the_user.login:
            if user['hash'] == the_user.hash:
                salt = b64encode(os.urandom(256)).decode('utf-8')
                session['login'] = the_user.login
                session['salt'] = salt
                result = jsonify({'title': 'news', 'username': the_user.login, 'news': get_news()})
                response = make_response(result)
                response.set_cookie('salt', salt, max_age=15 * 60)
                return response
            else:
                raise PasswordException('Неверный пароль')
    raise LoginException('Неверное имя пользователя')


def register_user(filepath: str, new_user: User):
    users = list()
    with open(filepath, encoding='utf-8') as f:
        users = list(json.loads(f.read()))
    for user in users:
        if user['login'] == new_user.login:
            raise LoginException('Этот логин уже занят')
        if user['email'] == new_user.email:
            raise EmailException('Эта почта уже занята')
    users.append({'login': new_user.login, 'email': new_user.email, 'hash': new_user.hash})
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(json.dumps(users, indent=4))
    salt = b64encode(os.urandom(256)).decode('utf-8')
    session['login'] = user['login']
    session['salt'] = salt
    result = jsonify({'title': 'news', 'username': new_user.login, 'news': get_news()})
    response = make_response(result)
    response.set_cookie('salt', salt, max_age=15 * 60)
    return response


@app.route('/')
@app.route('/index')
@app.route('/news')
def index():
    if session.new or 'salt' not in session or request.cookies.get('salt', None) != session['salt']:
        return {'title': 'login', 'username': '', 'news': []}
    else:
        return {'title': 'news', 'username': session.get('login', None), 'news': get_news()}


@app.route('/add-new', methods=['POST'])
def add_new():
    if session.new or 'salt' not in session or request.cookies.get('salt', None) != session['salt']:
        return {'title': 'login', 'username': '', 'news': []}
    else:
        news = get_news()
        news.append({'login': session.get('login', None), 'text': request.form.get('text', None)})
        with open(news_filepath, 'w', encoding='utf-8') as f:
            f.write(json.dumps(news, indent=4))
        return {'title': 'news', 'username': session.get('login', None), 'news': news}


@app.route('/login', methods=['POST'])
def login():
    try:
        user = User(request.form.get('login', None), 'example@gmail.com', request.form.get('password', None))
        return login_user(users_filepath, user)
    except (LoginException, PasswordException) as err:
        exception_type = 'login' if isinstance(err, LoginException) else 'password'
        return make_response(dict({'error': {
            'class': exception_type,
            'message': str(err)
        }}, ), 401)


@app.route('/register', methods=['POST'])
def register():
    try:
        new_user = User(request.form.get('login', None), request.form.get('email', None),
                        request.form.get('password', None))
        return register_user(users_filepath, new_user)
    except (LoginException, EmailException, PasswordException) as err:
        exception_type = 'login'
        if isinstance(err, EmailException):
            exception_type = 'email'
        elif isinstance(err, PasswordException):
            exception_type = 'password'
        return make_response(dict({'error': {
            'class': exception_type,
            'message': str(err)
        }}, ), 401)


if __name__ == '__main__':
    app.run(debug=True)

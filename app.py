from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'secret-123'

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

bcrypt = Bcrypt(app)

# Dummy user database
users = {
    "user@example.com": {
        "password": bcrypt.generate_password_hash("password123").decode('utf-8')
    }
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.get(email)

        if user and bcrypt.check_password_hash(user['password'], password):
            login_user(User(email))
            return redirect(url_for('home'))
        else:
            flash('Email atau password salah!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email in users:
            flash('Email sudah terdaftar!')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users[email] = {'password': hashed_password}
        flash('Registrasi berhasil! Silakan login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

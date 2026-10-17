from flask import Flask, request, make_response
import sqlite3

app = Flask(__name__)


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# --- Weakness 1: Reflected XSS ---
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f'<h2>Search results for: {query}</h2><p>No results found.</p>'


# --- Weakness 2: SQL Injection ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = sqlite3.connect(':memory:')
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (username TEXT, password TEXT)")
        cur.execute("INSERT INTO users VALUES ('admin', 'admin123')")
        query = "SELECT * FROM users WHERE username=? AND password=?"
        try:
            cur.execute(query, (username, password))
            result = cur.fetchall()
            if result:
                return "Login successful!"
            return "Invalid credentials."
        except Exception as e:
            return f"Database error: {e}"
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit">Login</button>
        </form>
    '''


# --- Weakness 3: Cookie now improved (but still http, not https) ---
@app.route('/')
def home():
    resp = make_response('<h1>Welcome to Vulnerable Test App</h1><p><a href="/search?q=test">Search</a> | <a href="/login">Login</a></p>')
    resp.set_cookie('session_id', '12345', secure=False, httponly=True, samesite='Lax')
    return resp


if __name__ == '__main__':
    app.run(port=5001, debug=True)
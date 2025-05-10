from typing import Union
from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

db = {
    "testuser": {
        "username": "testuser",
        "password": "securepassword", 
        "token": "testtoken"
    }
}

def get_current_user(token: str = Depends(oauth2_scheme)):
    for user in db.values():
        if user["token"] == token:
            return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.post("/register/")
def register_user(username: str = Form(...), password: str = Form(...)):
    if username in db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )
    db[username] = {
        "username": username,
        "password": password,  
        "token": f"{username}_token" 
    }
    return {"message": f"User {username} registered successfully!"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": user["token"], "token_type": "bearer"}

@app.get("/", response_class=HTMLResponse)
def read_root():
    return """
    <html>
        <head>
            <title>User Form</title>
        </head>
        <body>
            <h1>Register or Login</h1>
            <form action="/register/" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password">
                <button type="submit">Register</button>
            </form>
            <br>
            <form action="/token" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """

@app.get("/protected/")
def protected_route(user: dict = Depends(get_current_user)):
    return {"message": f"Hello, {user['username']}! This is a protected route."}


@app.get("/dangerous/")
def dangerous(cmd: str): # injection risc
    result = subprocess.check_output(cmd, shell=True)
    return {"output": result.decode()}

@app.get("/hardcoded-secret/")
def hardcoded_secret():
    secret = "super_secret_password"
    return {"secret": secret}

if __name__ == "__main__":
    import subprocess

    subprocess.run(
        ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
    )
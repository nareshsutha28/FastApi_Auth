import uvicorn
from fastapi import FastAPI, Header, HTTPException,Depends, Request
from decouple import config
from app.utils import verify_token, signJWT,db_connection, check_user_by_email_pass,check_user_by_email,check_for_valid_token, blacklist_token
from app.model import UserSchema, UserLoginSchema, UserDelSchema
# import bcrypt
from passlib.context import CryptContext

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.get("/")
def greet(x_token: bool = Depends(verify_token)):
    return {"hello": "world!"}


@app.post("/add_user")
def signup(user: UserSchema):
    hashPass = pwd_context.hash(user.password)
    sql_query = '''
    INSERT INTO public."User" (username, password, email)
    VALUES (%s, %s, %s)
    ''' 
    data = db_connection(sql_query, (user.username, hashPass, user.email))
    return signJWT(user.email)


@app.get("/get_users")
def greet(x_token: bool = Depends(verify_token)):
    return userList


@app.post("/login")
def user_login(user: UserLoginSchema):
    if check_user_by_email_pass(user):
        return signJWT(user.email)
    return {
        "error": "Wrong login details!"
    }


@app.post("/del_user")
def del_user(user: UserDelSchema , x_token: bool = Depends(verify_token)):
    if check_user_by_email(user):
        sql_query = ''' DELETE FROM public."User" WHERE email=%s ''' 
        db_connection(sql_query, (user.email,))
        
        return {"success": "User deleted"}
    return {
        "error": "Email Is Does Not Exists!"
    }


@app.get("/logout")
def del_user(payload: str = Depends(check_for_valid_token)):
    try: 
        blacklist_token(payload["access_token"])
        return {"message": "Token has been revoked"}
    except Exception as e: 
        return{"Error": e}

# Create an endpoint that requires token authentication
@app.get("/protected")
async def protected_route(payload: str = Depends(check_for_valid_token)):

    if not payload["user"]:
        raise HTTPException(status_code=401, detail="User not found")
    username = payload["user"]
    return {"message": f"Hello {username} ! This is a protected route."}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
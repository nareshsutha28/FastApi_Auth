from decouple import config
from fastapi import Header, HTTPException, Request
from app.model import UserSchema, UserLoginSchema, UserDelSchema
from passlib.context import CryptContext
import psycopg2
import time
import jwt


# admin token
ACCESS_TOKEN = config("access_token")

JWT_SECRET = config("jwt_secret")
JWT_ALGORITHM = config("algorithm")

# database credetials 
HOSTNAME = config("db_host")
DATABASE = config("database")
USERNAME = config("username")
PASSWORD = config("password")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# varify admin access token        
def verify_token(req: Request):
        token = req.headers.get("x-token")
        if token != ACCESS_TOKEN:
            raise HTTPException(
                status_code=401,
                detail="Unauthorized"
            )
        return True


# varify user access token for protected view
def check_for_valid_token(req: Request):
    try:
        access_token = req.headers.get("authorization")
        access_token = access_token.split(" ")[1]
        sql_query = '''select token from public."Blacklisted_token" where token=%s '''
        black_listed_token = db_connection(sql_query , (access_token,))
        print(black_listed_token)
        if black_listed_token != None:
            raise HTTPException(status_code=401, detail="Token has been blacklisted.")

        payload = jwt.decode(access_token, JWT_SECRET, algorithm=JWT_ALGORITHM)
        username: str = payload.get("email_id")
        if username is None:
            raise HTTPException(status_code=401, detail="Token validation failed")
        return {"access_token":access_token, "user":username }
    
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# add token to blacklist
def blacklist_token(token):
    sql_query = '''INSERT into public."Blacklisted_token" (token) values (%s) ON CONFLICT (token) DO NOTHING;''' 
    db_connection(sql_query, (token,))



# token_response
def token_response(token: str):
    return {
        "access_token": token
    }


# send response in jwt token 
def signJWT(email_id: str):
    payload = {
        "email_id": email_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token_response(token)


# execute db query with conncetion
def db_connection(sql_query, data_list=None):
    try:
        connection = psycopg2.connect(
            dbname=DATABASE,
            user=USERNAME,
            password = PASSWORD,
            host=HOSTNAME
        )
        cursor = connection.cursor()

        if data_list != None: 
            cursor.execute(sql_query, data_list)
        else: 
            cursor.execute(sql_query)

        connection.commit()

        try: 
            rows = cursor.fetchall()
            if rows: 
                return rows 
        except: 
            return {"success" : "data updated successfully"}

    except Exception as e :
        raise HTTPException(status_code=502, detail=str(e))


# varify user for signin 
def check_user_by_email_pass(data: UserLoginSchema):
    sql_query = '''SELECT * FROM public."User" WHERE email=%s '''
    result = db_connection(sql_query , (data.email,) )
    print(result)
    stored_hashed_password = result[0][2]
    if result != None: 
        if pwd_context.verify(data.password, stored_hashed_password):
            return True
        
    return False
    


# varify user for deletion of user if user exist
def check_user_by_email(data: UserDelSchema):
    sql_query = ''' SELECT * FROM public."User" WHERE email=%s '''
    result = db_connection(sql_query , (data.email,) )
    if result == None:
        return False
    return True





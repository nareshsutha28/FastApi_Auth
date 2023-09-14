from pydantic import BaseModel, Field, EmailStr



class UserSchema(BaseModel):
    username: str = Field(...)
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "Name": "Joe Doe",
                "email": "joe@xyz.com",
                "password": "any"
            }
        }


class UserLoginSchema(BaseModel):
    email: EmailStr = Field(...)
    password: str = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "email": "joe@xyz.com",
                "password": "any"
            }
        }


class UserDelSchema(BaseModel):
    email: EmailStr = Field(...)

    class Config:
        schema_extra = {
            "example": {
                "email": "joe@xyz.com",
            }
        }

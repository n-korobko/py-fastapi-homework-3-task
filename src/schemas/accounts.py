from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserModelBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserModelBase):
    password: str


class UserRegistrationResponseSchema(UserModelBase):
    model_config = ConfigDict(from_attributes=True)
    id: int


class UserActivationRequestSchema(UserModelBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserModelBase):
    pass


class PasswordResetCompleteRequestSchema(UserModelBase):
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

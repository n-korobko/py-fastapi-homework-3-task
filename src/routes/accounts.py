from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_data: UserRegistrationRequestSchema,
    db: Session = Depends(get_db),
):
    existing_user = db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    ).scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = db.execute(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        ).scalar_one()

        user = UserModel(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            is_active=False,
            group=group,
        )

        db.add(user)
        db.flush()

        activation_token = ActivationTokenModel(
            user_id=cast(int, user.id)
        )
        db.add(activation_token)

        db.commit()
        db.refresh(user)

        return UserRegistrationResponseSchema(
            id=user.id,
            email=user.email,
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
def activate_user(
    data: UserActivationRequestSchema,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(UserModel).where(UserModel.email == data.email)
    ).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active.",
        )

    token = db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token,
        )
    ).scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.delete(token)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    db.delete(token)
    db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
def password_reset_request(
    data: PasswordResetRequestSchema,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(UserModel).where(UserModel.email == data.email)
    ).scalar_one_or_none()

    if user and user.is_active:
        db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        reset_token = PasswordResetTokenModel(
            user_id=cast(int, user.id)
        )
        db.add(reset_token)
        db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(UserModel).where(UserModel.email == data.email)
    ).scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    token = db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == data.token,
        )
    ).scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.delete(token)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    try:
        user.hashed_password = hash_password(data.password)
        db.delete(token)
        db.commit()

        return MessageResponseSchema(
            message="Password reset successfully."
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def login(
    data: UserLoginRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = db.execute(
        select(UserModel).where(UserModel.email == data.email)
    ).scalar_one_or_none()

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token(user.id)
        refresh_token = jwt_manager.create_refresh_token(user.id)

        RefreshTokenModel.create(
            db=db,
            token=refresh_token,
            user_id=cast(int, user.id),
            days=settings.LOGIN_TIME_DAYS,
        )

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except BaseSecurityError:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    refresh_token = db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    ).scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found.",
        )

    user = db.execute(
        select(UserModel).where(
            UserModel.id == payload["user_id"]
        )
    ).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(user.id)

    return TokenRefreshResponseSchema(
        access_token=access_token
    )

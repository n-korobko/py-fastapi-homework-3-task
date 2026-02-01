from datetime import datetime, timezone
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )
        if not group:
            raise HTTPException(
                status_code=500,
                detail="An error occurred during user creation.",
            )

        try:
            user = UserModel.create(
                email=user_data.email,
                raw_password=user_data.password,
                group_id=group.id,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail=str(e),
            )

        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)

        return UserRegistrationResponseSchema(
            id=user.id,
            email=user.email,
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    data: UserActivationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(joinedload(UserModel.activation_token))
    )

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

    token = user.activation_token
    if not token or token.token != data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during activation.",
        )

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(joinedload(UserModel.password_reset_token))
    )

    if not user or not user.is_active:
        return message

    try:
        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.flush()

        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during password reset request.",
        )

    return message


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(joinedload(UserModel.password_reset_token))
    )

    if not user or not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    token = user.password_reset_token
    if not token or token.token != data.token:
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    try:
        user.password = data.password
        await db.delete(token)
        await db.flush()
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def login_user(
        user_data: UserLoginRequestSchema,
        db: Annotated[AsyncSession, Depends(get_db)],
        jwt_manager: Annotated[
            JWTAuthManagerInterface, Depends(get_jwt_auth_manager)
        ],
        settings: Annotated[BaseAppSettings, Depends(get_settings)],
) -> UserLoginResponseSchema:
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    token_data = {
        "sub": str(db_user.id),
        "user_id": db_user.id,
        "email": user_data.email,
    }

    try:
        access_token = jwt_manager.create_access_token(data=token_data)
        refresh_token = jwt_manager.create_refresh_token(data=token_data)

        db_refresh_token = RefreshTokenModel.create(
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
            user_id=db_user.id
        )
        db.add(db_refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
    jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired.",
        )

    token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found.",
        )

    user = await db.scalar(
        select(UserModel).where(UserModel.id == payload["user_id"])
    )
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    token_data = {
        "sub": str(user.id),
        "user_id": user.id,
        "email": user.email,
    }

    access_token = jwt_manager.create_access_token(token_data)

    return TokenRefreshResponseSchema(
        access_token=access_token
    )

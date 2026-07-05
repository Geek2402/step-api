import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_admin
from app.core.security import hash_password
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.audit_service import log_event

router = APIRouter(prefix="/users", tags=["users"])


def _check_self_or_admin(target_id: uuid.UUID, user: User) -> None:
    if not user.is_admin and user.id != target_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès non autorisé à cet utilisateur")


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur introuvable")
    return target


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Un compte existe déjà avec cet email")

    user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_event(db, "user", "user_registered", actor_id=user.id)
    return user


@router.get("/me", response_model=UserRead)
async def me(user: User = Depends(get_current_user)):
    return user


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    _check_self_or_admin(user_id, user)
    return await _get_user_or_404(user_id, db)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _check_self_or_admin(user_id, user)
    target = await _get_user_or_404(user_id, db)

    if payload.email is not None and payload.email != target.email:
        existing = await db.execute(select(User).where(User.email == payload.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status.HTTP_409_CONFLICT, "Un compte existe déjà avec cet email")
        target.email = payload.email
    if payload.first_name is not None:
        target.first_name = payload.first_name
    if payload.last_name is not None:
        target.last_name = payload.last_name
    if payload.password is not None:
        target.password_hash = hash_password(payload.password)

    await db.commit()
    await db.refresh(target)
    await log_event(db, "user", "user_updated", actor_id=user.id, metadata={"target_user_id": str(target.id)})
    return target


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    _check_self_or_admin(user_id, user)
    target = await _get_user_or_404(user_id, db)
    await db.delete(target)
    await db.commit()
    await log_event(db, "user", "user_deleted", actor_id=user.id, metadata={"target_user_id": str(target.id)})


@router.post("/{user_id}/activate", response_model=UserRead)
async def activate_user(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    target = await _get_user_or_404(user_id, db)
    target.is_active = True
    await db.commit()
    await db.refresh(target)
    await log_event(db, "user", "user_activated", actor_id=admin.id, metadata={"target_user_id": str(target.id)})
    return target


@router.post("/{user_id}/deactivate", response_model=UserRead)
async def deactivate_user(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    target = await _get_user_or_404(user_id, db)
    target.is_active = False
    await db.commit()
    await db.refresh(target)
    await log_event(db, "user", "user_deactivated", actor_id=admin.id, metadata={"target_user_id": str(target.id)})
    return target


@router.post("/{user_id}/promote-admin", response_model=UserRead)
async def promote_admin(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    target = await _get_user_or_404(user_id, db)
    target.is_admin = True
    await db.commit()
    await db.refresh(target)
    await log_event(db, "user", "user_promoted_admin", actor_id=admin.id, metadata={"target_user_id": str(target.id)})
    return target


@router.post("/{user_id}/demote-admin", response_model=UserRead)
async def demote_admin(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    target = await _get_user_or_404(user_id, db)
    target.is_admin = False
    await db.commit()
    await db.refresh(target)
    await log_event(db, "user", "user_demoted_admin", actor_id=admin.id, metadata={"target_user_id": str(target.id)})
    return target
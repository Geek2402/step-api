import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_admin
from app.core.security import hash_password
from app.db.session import get_db
from app.models.enums import ActorType, AuditEventType
from app.models.user import User
from app.schemas.pagination import DEFAULT_LIMIT, MAX_LIMIT, Page
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.audit_service import log_event

router = APIRouter(prefix="/users", tags=["users"])


async def _check_self_or_admin(target_id: uuid.UUID, user: User, db: AsyncSession, action: str) -> None:
    if not user.is_admin and user.id != target_id:
        await log_event(
            db, ActorType.USER, AuditEventType.ACCESS_DENIED, actor_id=user.id,
            metadata={"reason": "not_self_or_admin", "target_user_id": str(target_id), "action": action},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Access to this user is not authorized")


async def _get_user_or_404(user_id: uuid.UUID, db: AsyncSession) -> User:
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return target


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED, summary="Register a new User account")
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    """Creates a new User (dev/admin) account with email, password, first and last name.

    Public endpoint, no authentication required. The account is created active but unverified;
    it becomes verified on first successful login (see `/users/auth/login` + `/verify-otp`).

    Errors: 409 if an account already exists with this email.
    """
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "An account already exists with this email")

    user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_event(db, ActorType.USER, AuditEventType.USER_REGISTERED, actor_id=user.id)
    return user


@router.get("/me", response_model=UserRead, summary="Get the current authenticated User's profile")
async def me(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Returns the profile of the User identified by the JWT in the `Authorization` header.

    Requires a valid User JWT. Logs a `USER_READ` audit event (self-read).
    """
    await log_event(
        db, ActorType.USER, AuditEventType.USER_READ, actor_id=user.id,
        metadata={"target_user_id": str(user.id), "self": True},
    )
    return user


@router.get("", response_model=Page[UserRead], summary="List all User accounts (admin only)")
async def list_users(
    search: str | None = Query(default=None, description="Search by last name, first name, or email"),
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Returns a paginated list of every User account on the platform.

    Admin only. Supports an optional case-insensitive partial-match `search` across first
    name, last name, and email. Paginated via `limit` (default 20, max 100) and `offset`;
    the response envelope includes `total` for the unpaginated match count. Logs a
    `USER_LIST` audit event.

    Errors: 403 if the caller is not an admin.
    """
    filters = []
    if search:
        pattern = f"%{search}%"
        filters.append(
            or_(User.first_name.ilike(pattern), User.last_name.ilike(pattern), User.email.ilike(pattern))
        )

    count_query = select(func.count()).select_from(User).where(*filters)
    query = select(User).where(*filters)

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(query.order_by(User.created_at).limit(limit).offset(offset))
    await log_event(db, ActorType.USER, AuditEventType.USER_LIST, actor_id=admin.id)
    return Page(items=result.scalars().all(), total=total, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=UserRead, summary="Get a User by id (self or admin)")
async def get_user(
    user_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Returns the profile of the User with the given id.

    Restricted to the User themselves or an admin. Logs a `USER_READ` audit event
    (`self` flag reflects whether the caller viewed their own profile).

    Errors: 403 if the caller is neither the target User nor an admin; 404 if the id
    does not exist.
    """
    await _check_self_or_admin(user_id, user, db, "get_user")
    target = await _get_user_or_404(user_id, db)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_READ, actor_id=user.id,
        metadata={"target_user_id": str(target.id), "self": user.id == target.id},
    )
    return target


@router.patch("/{user_id}", response_model=UserRead, summary="Update a User's profile (self or admin)")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Partially updates a User's email, first name, last name, and/or password.

    Restricted to the User themselves or an admin. Only the fields provided in the request
    body are changed; omitted fields are left untouched. Logs a `USER_UPDATED` audit event.

    Errors: 403 if the caller is neither the target User nor an admin; 404 if the id does not
    exist; 409 if the new email is already used by another account.
    """
    await _check_self_or_admin(user_id, user, db, "update_user")
    target = await _get_user_or_404(user_id, db)

    if payload.email is not None and payload.email != target.email:
        existing = await db.execute(select(User).where(User.email == payload.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status.HTTP_409_CONFLICT, "An account already exists with this email")
        target.email = payload.email
    if payload.first_name is not None:
        target.first_name = payload.first_name
    if payload.last_name is not None:
        target.last_name = payload.last_name
    if payload.password is not None:
        target.password_hash = hash_password(payload.password)

    await db.commit()
    await db.refresh(target)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_UPDATED, actor_id=user.id,
        metadata={"target_user_id": str(target.id)},
    )
    return target


@router.delete(
    "/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a User account (self or admin)"
)
async def delete_user(
    user_id: uuid.UUID, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Permanently deletes the User account with the given id.

    Restricted to the User themselves or an admin. This is a hard delete, not a deactivation —
    it cannot be undone. Logs a `USER_DELETED` audit event before returning 204 with no body.

    Errors: 403 if the caller is neither the target User nor an admin; 404 if the id does not
    exist.
    """
    await _check_self_or_admin(user_id, user, db, "delete_user")
    target = await _get_user_or_404(user_id, db)
    await db.delete(target)
    await db.commit()
    await log_event(
        db, ActorType.USER, AuditEventType.USER_DELETED, actor_id=user.id,
        metadata={"target_user_id": str(target.id)},
    )


@router.post("/{user_id}/activate", response_model=UserRead, summary="Reactivate a disabled User account (admin only)")
async def activate_user(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    """Sets `is_active` back to true on the target User, restoring their ability to log in.

    Admin only. Logs a `USER_ACTIVATED` audit event.

    Errors: 403 if the caller is not an admin; 404 if the id does not exist.
    """
    target = await _get_user_or_404(user_id, db)
    target.is_active = True
    await db.commit()
    await db.refresh(target)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_ACTIVATED, actor_id=admin.id,
        metadata={"target_user_id": str(target.id)},
    )
    return target


@router.post("/{user_id}/deactivate", response_model=UserRead, summary="Disable a User account (admin only)")
async def deactivate_user(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    """Sets `is_active` to false on the target User, immediately preventing them from logging in
    (existing JWTs remain valid until they naturally expire — this does not blacklist tokens).

    Admin only. Logs a `USER_DEACTIVATED` audit event.

    Errors: 403 if the caller is not an admin; 404 if the id does not exist.
    """
    target = await _get_user_or_404(user_id, db)
    target.is_active = False
    await db.commit()
    await db.refresh(target)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_DEACTIVATED, actor_id=admin.id,
        metadata={"target_user_id": str(target.id)},
    )
    return target


@router.post("/{user_id}/promote-admin", response_model=UserRead, summary="Grant admin rights to a User (admin only)")
async def promote_admin(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    """Sets `is_admin` to true on the target User, granting them full administrative access
    (unrestricted read/write on all Users, Apps, and audit logs).

    Admin only. Logs a `USER_PROMOTED_ADMIN` audit event.

    Errors: 403 if the caller is not an admin; 404 if the id does not exist.
    """
    target = await _get_user_or_404(user_id, db)
    target.is_admin = True
    await db.commit()
    await db.refresh(target)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_PROMOTED_ADMIN, actor_id=admin.id,
        metadata={"target_user_id": str(target.id)},
    )
    return target


@router.post("/{user_id}/demote-admin", response_model=UserRead, summary="Revoke admin rights from a User (admin only)")
async def demote_admin(
    user_id: uuid.UUID, admin: User = Depends(require_admin), db: AsyncSession = Depends(get_db)
):
    """Sets `is_admin` to false on the target User, reverting them to standard access.

    Admin only — note this includes the ability to demote yourself, so take care not to
    leave the platform without any administrator. Logs a `USER_DEMOTED_ADMIN` audit event.

    Errors: 403 if the caller is not an admin; 404 if the id does not exist.
    """
    target = await _get_user_or_404(user_id, db)
    target.is_admin = False
    await db.commit()
    await db.refresh(target)
    await log_event(
        db, ActorType.USER, AuditEventType.USER_DEMOTED_ADMIN, actor_id=admin.id,
        metadata={"target_user_id": str(target.id)},
    )
    return target

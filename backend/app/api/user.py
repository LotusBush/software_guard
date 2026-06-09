from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from ..core.database import get_db
from ..core.deps import require_admin
from ..core.security import get_password_hash
from ..models.user import User, UserRole
from ..models.audit import AuditLog
from ..schemas.user import UserResponse, UserCreate

router = APIRouter(prefix="/users", tags=["用户管理"])


class UserUpdate(BaseModel):
    role: UserRole
    is_active: bool
    email: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    password: str


@router.get("", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """获取用户列表（仅管理员）"""
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """创建用户（仅管理员）"""
    # 检查用户名是否存在
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="用户名已存在")

    # 检查邮箱是否存在
    if user_data.email:
        existing_email = db.query(User).filter(User.email == user_data.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="邮箱已被注册")

    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        hashed_password=hashed_password,
        email=user_data.email,
        role=UserRole.USER  # 默认为普通用户
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """更新用户（仅管理员）"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    # 不允许修改自己的角色
    if user.id == current_user.id and user_data.role != user.role:
        raise HTTPException(status_code=400, detail="不能修改自己的角色")

    # 邮箱校验
    if user_data.email is not None:
        if user_data.email.strip():
            existing = db.query(User).filter(
                User.email == user_data.email.strip(), User.id != user_id
            ).first()
            if existing:
                raise HTTPException(status_code=400, detail="邮箱已被其他用户使用")
            user.email = user_data.email.strip()
        else:
            user.email = None

    user.role = user_data.role
    user.is_active = user_data.is_active
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    db.refresh(user)

    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """删除用户（仅管理员）"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    # 不允许删除自己
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="不能删除自己")

    db.delete(user)
    db.commit()


@router.put("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    data: ResetPasswordRequest,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """管理员重置用户密码"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if getattr(user, 'auth_source', 'local') != 'local':
        raise HTTPException(status_code=400, detail="LDAP 用户请通过域控修改密码")

    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="密码至少6位")

    user.hashed_password = get_password_hash(data.password)
    user.token_version = (user.token_version or 0) + 1

    audit = AuditLog(
        user_id=current_user.id,
        action="reset_password",
        resource_type="user",
        resource_id=user.id,
        details={"target_username": user.username},
        ip_address=request.client.host if request.client else None
    )
    db.add(audit)
    db.commit()

    return {"message": "密码重置成功"}

import os
import secrets
import warnings
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # 应用配置
    APP_NAME: str = "Software Guard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # 数据库配置
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/software_guard"

    # JWT 配置 - 如果未设置环境变量则自动生成随机密钥
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # 文件存储配置
    STORAGE_PATH: str = "storage"
    MAX_UPLOAD_SIZE: int = 3 * 1024 * 1024 * 1024  # 3GB

    # 首次运行创建管理员账号
    FIRST_ADMIN_USERNAME: str = "admin"
    FIRST_ADMIN_PASSWORD: str = "admin123"
    FIRST_ADMIN_EMAIL: str = "admin@company.com"

    # 是否允许开放注册（默认关闭）
    ALLOW_REGISTRATION: bool = False

    # CORS 允许的前端域名（逗号分隔，如 http://localhost:5173,http://localhost:3000）
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    class Config:
        env_file = ".env"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.SECRET_KEY or self.SECRET_KEY == "your-secret-key-change-in-production":
            self.SECRET_KEY = secrets.token_urlsafe(32)
            warnings.warn(
                "SECURITY WARNING: SECRET_KEY 未设置，已自动生成随机密钥。"
                "请在 .env 中设置固定的 SECRET_KEY 以确保服务重启后 token 仍然有效。",
                stacklevel=2
            )
        if self.FIRST_ADMIN_PASSWORD == "admin123":
            warnings.warn(
                "SECURITY WARNING: 管理员密码仍为默认值 'admin123'，请通过环境变量 FIRST_ADMIN_PASSWORD 修改。",
                stacklevel=2
            )


settings = Settings()


# 默认允许上传的文件扩展名（数据库未配置时使用）
DEFAULT_ALLOWED_UPLOAD_EXTENSIONS = {
    ".exe", ".msi", ".zip", ".rar", ".7z",
    ".dmg", ".pkg", ".deb", ".rpm",
    ".tar", ".gz", ".bz2", ".xz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".iso", ".img",
}


def get_allowed_upload_extensions(db=None) -> set:
    """获取允许上传的文件扩展名：优先读数据库配置，否则用默认值"""
    if db:
        from ..models.config import Config
        row = db.query(Config).filter(Config.key == "allowed_upload_extensions").first()
        if row and row.value.strip():
            exts = {ext.strip().lower() for ext in row.value.split(",") if ext.strip()}
            if exts:
                return exts
    return DEFAULT_ALLOWED_UPLOAD_EXTENSIONS


def get_max_upload_size(db=None) -> int:
    """获取最大上传大小：优先读数据库配置，否则用环境变量"""
    if db:
        from ..models.config import Config
        row = db.query(Config).filter(Config.key == "max_upload_size").first()
        if row:
            return int(row.value)
    return settings.MAX_UPLOAD_SIZE


def get_storage_path(db=None) -> str:
    """获取存储路径：优先读数据库配置，否则用环境变量，始终返回绝对路径"""
    if db:
        from ..models.config import Config
        row = db.query(Config).filter(Config.key == "storage_path").first()
        if row and row.value.strip():
            path = os.path.abspath(row.value.strip())
            os.makedirs(path, exist_ok=True)
            return path
    path = os.path.abspath(settings.STORAGE_PATH)
    os.makedirs(path, exist_ok=True)
    return path

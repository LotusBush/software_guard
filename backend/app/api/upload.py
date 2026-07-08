import uuid
import os
import math
import hashlib
import shutil
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
import aiofiles

from ..core.database import get_db
from ..core.deps import require_ops
from ..core.config import settings, get_max_upload_size, get_storage_path, get_allowed_upload_extensions
from ..core.validators import sanitize_filename, validate_path_within_dir
from ..models.user import User
from ..models.software import Software, SoftwareVersion
from ..models.upload import UploadSession
from ..schemas.upload import (
    UploadInitRequest, UploadInitResponse,
    UploadChunkResponse, UploadCompleteResponse
)

router = APIRouter(prefix="/upload", tags=["分块上传"])


@router.post("/init", response_model=UploadInitResponse)
async def init_upload(
    data: UploadInitRequest,
    current_user: User = Depends(require_ops),
    db: Session = Depends(get_db)
):
    """初始化分块上传会话"""
    software = db.query(Software).filter(Software.id == data.software_id).first()
    if not software:
        raise HTTPException(status_code=404, detail="软件不存在")

    # 检查文件扩展名
    allowed_extensions = get_allowed_upload_extensions(db)
    file_ext = os.path.splitext(data.file_name)[1].lower() if data.file_name else ''
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"不支持的文件类型: {file_ext}，允许的类型: {', '.join(sorted(allowed_extensions))}"
        )

    max_size = get_max_upload_size(db)
    if data.file_size > max_size:
        gb = max_size / (1024 ** 3)
        raise HTTPException(status_code=400, detail=f"文件大小超过限制（最大 {gb:.1f}GB）")

    expected_chunks = math.ceil(data.file_size / data.chunk_size)
    if data.total_chunks != expected_chunks:
        raise HTTPException(status_code=400, detail="分片数量不匹配")

    session_id = uuid.uuid4().hex
    storage_path = get_storage_path(db)
    temp_dir = os.path.join(storage_path, "uploads_temp", session_id)
    os.makedirs(temp_dir, exist_ok=True)

    session = UploadSession(
        id=session_id,
        software_id=data.software_id,
        file_name=data.file_name,
        file_size=data.file_size,
        file_hash=data.file_hash,
        chunk_size=data.chunk_size,
        total_chunks=data.total_chunks,
        uploader_id=current_user.id,
        version=data.version,
        release_notes=data.release_notes,
        temp_dir=temp_dir,
        status="pending"
    )
    db.add(session)
    db.commit()

    return UploadInitResponse(
        session_id=session_id,
        chunk_size=data.chunk_size,
        total_chunks=data.total_chunks
    )


@router.put("/{session_id}/chunk/{chunk_index}", response_model=UploadChunkResponse)
async def upload_chunk(
    session_id: str,
    chunk_index: int,
    chunk: UploadFile = File(...),
    current_user: User = Depends(require_ops),
    db: Session = Depends(get_db)
):
    """上传单个分片"""
    session = db.query(UploadSession).filter(UploadSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="上传会话不存在")
    if session.status not in ("pending", "uploading"):
        raise HTTPException(status_code=400, detail="上传会话状态异常")
    if session.uploader_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权操作此上传会话")
    if chunk_index < 0 or chunk_index >= session.total_chunks:
        raise HTTPException(status_code=400, detail="分片索引无效")

    content = await chunk.read()
    # 最后一个分片可以小于 chunk_size，其余必须接近 chunk_size
    if chunk_index < session.total_chunks - 1:
        if len(content) > session.chunk_size * 1.1:
            raise HTTPException(status_code=400, detail="分片大小异常")

    chunk_path = os.path.join(session.temp_dir, str(chunk_index))
    async with aiofiles.open(chunk_path, "wb") as f:
        await f.write(content)

    session.uploaded_chunks += 1
    session.status = "uploading"
    db.commit()

    return UploadChunkResponse(
        session_id=session_id,
        chunk_index=chunk_index,
        uploaded_chunks=session.uploaded_chunks,
        total_chunks=session.total_chunks
    )


@router.post("/{session_id}/complete", response_model=UploadCompleteResponse)
async def complete_upload(
    session_id: str,
    current_user: User = Depends(require_ops),
    db: Session = Depends(get_db)
):
    """完成上传，合并分片并创建版本记录"""
    session = db.query(UploadSession).filter(UploadSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="上传会话不存在")
    if session.status != "uploading":
        raise HTTPException(status_code=400, detail="上传会话状态异常")
    if session.uploader_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权操作此上传会话")
    if session.uploaded_chunks != session.total_chunks:
        raise HTTPException(
            status_code=400,
            detail=f"分片未全部上传完成（{session.uploaded_chunks}/{session.total_chunks}）"
        )

    # 合并分片
    safe_filename = sanitize_filename(session.file_name)
    storage_path = get_storage_path(db)
    software_dir = os.path.join(storage_path, str(session.software_id))
    os.makedirs(software_dir, exist_ok=True)
    final_path = validate_path_within_dir(os.path.join(software_dir, safe_filename), storage_path)

    sha256_hash = hashlib.sha256()
    total_size = 0
    async with aiofiles.open(final_path, "wb") as out_f:
        for i in range(session.total_chunks):
            chunk_path = os.path.join(session.temp_dir, str(i))
            if not os.path.exists(chunk_path):
                os.remove(final_path)
                raise HTTPException(status_code=400, detail=f"分片 {i} 缺失")
            async with aiofiles.open(chunk_path, "rb") as in_f:
                while True:
                    block = await in_f.read(1024 * 1024)
                    if not block:
                        break
                    sha256_hash.update(block)
                    total_size += len(block)
                    await out_f.write(block)

    computed_hash = sha256_hash.hexdigest()
    if computed_hash != session.file_hash:
        os.remove(final_path)
        session.status = "failed"
        db.commit()
        raise HTTPException(status_code=400, detail="文件校验失败，哈希不匹配")

    # 创建版本记录
    version = SoftwareVersion(
        software_id=session.software_id,
        version=session.version,
        file_path=final_path,
        file_name=safe_filename,
        file_size=total_size,
        file_hash=computed_hash,
        uploader_id=current_user.id,
        release_notes=session.release_notes
    )
    db.add(version)
    session.status = "completed"
    db.commit()
    db.refresh(version)

    # 清理临时文件
    shutil.rmtree(session.temp_dir, ignore_errors=True)

    return UploadCompleteResponse(
        session_id=session_id,
        version_id=version.id,
        file_name=safe_filename,
        file_size=total_size,
        file_hash=computed_hash
    )


@router.post("/{session_id}/cancel")
async def cancel_upload(
    session_id: str,
    current_user: User = Depends(require_ops),
    db: Session = Depends(get_db)
):
    """取消上传并清理临时文件"""
    session = db.query(UploadSession).filter(UploadSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="上传会话不存在")
    if session.status == "completed":
        raise HTTPException(status_code=400, detail="上传已完成，无法取消")

    shutil.rmtree(session.temp_dir, ignore_errors=True)
    session.status = "cancelled"
    db.commit()

    return {"message": "上传已取消"}

import uuid
from enum import (
    Enum,
)

from sqlalchemy import (
    TIMESTAMP,
    Column,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import (
    UUID,
)
from sqlalchemy.ext.declarative import (
    declarative_base,
)

Base = declarative_base()


class AuthType(Enum):
    CREDENTIAL = 1
    TOKEN = 2


class Authentication(Base):
    __tablename__ = "authentication"
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    auth_type = Column(Integer)
    auth_uuid = Column(String)
    user_uuid = Column(String)
    user_id = Column(String)
    token = Column(String)
    role_code = Column(Integer, ForeignKey("roles.code"))
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)

    def __repr__(self):
        return (
            "<Authentication(uuid='{}', auth_type='{}',"
            "auth_uuid={}, created_at={}, updated_at={})>".format(  # pragma: no cover
                self.uuid, AuthType(self.auth_type), self.auth_uuid, self.created_at, self.updated_at
            )
        )


class Role(Base):
    __tablename__ = "roles"
    code = Column(Integer, primary_key=True)
    role_name = Column(String)
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)

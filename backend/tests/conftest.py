import os
import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.db.session import get_db, Base
from backend.app.db.models import InvestigationModel, EvidenceItemModel
from backend.app.routes import investigations

import tempfile

test_db_fd, test_db_path = tempfile.mkstemp(suffix=".db")
os.close(test_db_fd) # Close it so SQLite can open it

engine = create_engine(f"sqlite:///{test_db_path}", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function", autouse=True)
def setup_test_db():
    """Create fresh database tables for each test."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="function", autouse=True)
def isolated_api(db_session, tmp_path, monkeypatch):
    """Override database and uploads directory for API tests."""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    
    # Isolate uploads directory to a temporary path
    test_uploads_dir = tmp_path / "uploads"
    test_uploads_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(investigations, "UPLOADS_DIR", test_uploads_dir)
    
    yield
    
    app.dependency_overrides.clear()
